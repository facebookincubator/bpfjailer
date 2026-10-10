// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/PodVars.h"

#include <sys/mman.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <vector>

#include "bpfj/enforce/ArenaMap.h"
#include "bpfj/enforce/RoleId.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/bpf/types_str_map.h"
#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kArenaMap = "bpfj_heap_arena";

std::mutex& openMutex() noexcept {
  static std::mutex mutex;
  return mutex;
}

std::array<std::size_t, arena::kSlotCount>& openCounts() noexcept {
  static std::array<std::size_t, arena::kSlotCount> counts{};
  return counts;
}

std::size_t slotIndex(std::uint64_t extra) noexcept {
  return static_cast<std::size_t>(
      (extra - arena::kWindowBase) / arena::kSlotSize);
}

[[nodiscard]] Expected<const void*> lookupStringMap(
    const struct bpfj_str_map* index,
    std::string_view key,
    std::string_view description) noexcept {
  if (index == nullptr || index->capacity == 0) {
    return nullptr;
  }

  __u32 off = bpfj_str_map_hash(
      key.data(),
      static_cast<__u32>(key.size()),
      index->capacity,
      BPFJ_STR_MAP_MAX_STR_LEN);
  for (std::size_t attempt = 0; attempt < BPFJ_STR_MAP_MAX_ATTEMPTS;
       ++attempt) {
    const auto& entry = index->vec[off];
    if (entry.key == nullptr) {
      return nullptr;
    }
    if (entry.key_len == key.size() &&
        std::memcmp(entry.key, key.data(), key.size()) == 0) {
      return entry.val;
    }
    if (++off == index->capacity) {
      off = 0;
    }
  }
  return makeUnexpected(makeError(
      std::errc::no_space_on_device,
      description,
      " index exceeded its probe limit"));
}

} // namespace

[[nodiscard]] std::uint32_t varCatalogAllocSize(
    std::span<const std::string> names) noexcept {
  std::uint32_t size = bpfj_var_align_up(
      offsetof(struct bpfj_var_catalog, names) +
      sizeof(struct bpfj_var_name*) * names.size());
  for (const auto& name : names) {
    size += bpfj_var_align_up(
        offsetof(struct bpfj_var_name, str) + static_cast<__u32>(name.size()) +
        1);
  }
  return size;
}

[[nodiscard]] const struct bpfj_str_map* readRolePoliciesPointer(
    const PodArena& arena) noexcept {
  const auto* ctrl = arena.ctrl();
  return ctrl == nullptr
      ? nullptr
      : static_cast<const struct bpfj_str_map*>(ctrl->role_policies);
}

struct PublishedVarCatalog {
  struct bpfj_var_catalog* catalog = nullptr;
  PublishedVarNames names;
};

[[nodiscard]] Expected<PublishedVarCatalog> publishVarNames(
    PodArena& arena,
    std::span<const std::string> names) noexcept {
  if (names.empty()) {
    return PublishedVarCatalog{};
  }

  auto blob = arena.alloc(varCatalogAllocSize(names));
  if (!blob) {
    return makeUnexpected(blob.error());
  }

  auto* catalog = static_cast<struct bpfj_var_catalog*>(*blob);
  *catalog = {};
  catalog->count = static_cast<__u32>(names.size());
  auto* publishedNames = bpfj_var_catalog_names_mut(catalog);
  PublishedVarNames byName;

  std::uint32_t nameOff = bpfj_var_align_up(
      offsetof(struct bpfj_var_catalog, names) +
      sizeof(struct bpfj_var_name*) * names.size());
  for (std::size_t i = 0; i < names.size(); ++i) {
    const auto& name = names[i];
    auto* stored = reinterpret_cast<struct bpfj_var_name*>(
        static_cast<char*>(*blob) + nameOff);
    stored->id = static_cast<__u32>(i + 1);
    stored->len = static_cast<__u32>(name.size());
    std::memcpy(stored->str, name.data(), name.size());
    stored->str[name.size()] = '\0';
    publishedNames[i] = stored;
    byName.emplace(name, stored);
    nameOff += bpfj_var_align_up(
        offsetof(struct bpfj_var_name, str) + stored->len + 1);
  }

  return PublishedVarCatalog{.catalog = catalog, .names = std::move(byName)};
}

[[nodiscard]] Expected<const struct bpfj_role_set*> publishRoleSet(
    PodArena& arena,
    const PublishedRolePolicies& policies,
    const std::vector<std::string>& roles) noexcept {
  const std::uint32_t size = static_cast<std::uint32_t>(
      offsetof(struct bpfj_role_set, policies) +
      roles.size() * sizeof(struct bpfj_role_policy*));
  auto blob = arena.alloc(size);
  if (!blob) {
    return makeUnexpected(blob.error());
  }

  auto* set = static_cast<struct bpfj_role_set*>(*blob);
  set->count = static_cast<__u32>(roles.size());
  for (std::size_t i = 0; i < roles.size(); ++i) {
    const auto policy = policies.find(roles[i]);
    if (policy == policies.end()) {
      (void)arena.free(set);
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "role list names unknown role ",
          roles[i]));
    }
    set->policies[i] = policy->second;
  }
  return set;
}

Expected<PublishedPolicyGraph> publishPolicyGraph(
    PodArena& arena,
    const Policy& policy) noexcept {
  if (arena.ctrl()->role_policies != nullptr ||
      arena.ctrl()->var_catalog != nullptr) {
    return makeUnexpected(makeError(
        std::errc::file_exists, "the arena policy graph is already set"));
  }

  PublishedRolePolicies publishedPolicies;
  for (const auto& [name, source] : policy.roles) {
    auto id = makeRoleId(name);
    if (!id) {
      return makeUnexpected(id.error());
    }
    auto blob = arena.alloc(sizeof(struct bpfj_role_policy));
    if (!blob) {
      return makeUnexpected(blob.error());
    }
    auto* out = static_cast<struct bpfj_role_policy*>(*blob);
    *out = {};
    out->role_id = *id;
    out->min_seq = source.minSeq;
    out->flags = (source.overrideStacked ? BPFJ_POLICY_OVERRIDE_STACKED : 0) |
        (source.unprivEnroll ? BPFJ_POLICY_UNPRIV_ENROLL : 0) |
        (source.untrackedBpf ? BPFJ_POLICY_BPF_UNTRACKED : 0) |
        (source.hasMinSeq ? BPFJ_POLICY_HAS_MIN_SEQ : 0) |
        (source.lkmAny ? BPFJ_POLICY_LKM_ANY : 0) |
        (source.fsAny ? BPFJ_POLICY_FS_ANY : 0) |
        (source.verityAny ? BPFJ_POLICY_VERITY_ANY : 0) |
        BPFJ_POLICY_HAS_UMOUNT |
        (source.umountAny ? BPFJ_POLICY_UMOUNT_ANY : 0) |
        (source.mountAny ? BPFJ_POLICY_MOUNT_ANY : 0) |
        (source.execAny ? BPFJ_POLICY_EXEC_ANY : 0);
    out->bpf_mode = static_cast<__u8>(source.bpfMode);
    out->mq_sysv_mode = static_cast<__u8>(source.mqSysvMode);
    out->mq_posix_mode = static_cast<__u8>(source.mqPosixMode);
    out->shm_sysv_mode = static_cast<__u8>(source.shmSysvMode);
    out->shm_posix_mode = static_cast<__u8>(source.shmPosixMode);
    out->kill_mode = static_cast<__u8>(source.killMode);
    out->ptrace_mode = static_cast<__u8>(source.ptraceMode);
    out->proc_mode = static_cast<__u8>(source.procMode);
    out->keyring_mode = static_cast<__u8>(source.keyringMode);
    out->enroll_mode = static_cast<__u8>(source.enrollMode);
    publishedPolicies.emplace(name, out);
  }

  for (const auto& [name, source] : policy.roles) {
    auto* out = publishedPolicies.at(name);
    const struct {
      enum bpfj_policy_gate gate;
      AccessMode mode;
      const std::vector<std::string>* roles;
    } sets[] = {
        {BPFJ_POLICY_GATE_BPF, source.bpfMode, &source.bpf},
        {BPFJ_POLICY_GATE_KILL, source.killMode, &source.kill},
        {BPFJ_POLICY_GATE_PTRACE, source.ptraceMode, &source.ptrace},
        {BPFJ_POLICY_GATE_PROC, source.procMode, &source.proc},
        {BPFJ_POLICY_GATE_KEYRING, source.keyringMode, &source.keyring},
        {BPFJ_POLICY_GATE_ENROLL, source.enrollMode, &source.enroll},
        {BPFJ_POLICY_GATE_MQ_SYSV, source.mqSysvMode, &source.mqSysv},
        {BPFJ_POLICY_GATE_MQ_POSIX, source.mqPosixMode, &source.mqPosix},
        {BPFJ_POLICY_GATE_SHM_SYSV, source.shmSysvMode, &source.shmSysv},
        {BPFJ_POLICY_GATE_SHM_POSIX, source.shmPosixMode, &source.shmPosix},
    };
    for (const auto& set : sets) {
      if (set.mode != AccessMode::Roles) {
        continue;
      }
      auto published = publishRoleSet(arena, publishedPolicies, *set.roles);
      if (!published) {
        return makeUnexpected(published.error());
      }
      out->gates[set.gate] = *published;
    }
  }

  auto vars = publishVarNames(arena, policy.vars);
  if (!vars) {
    return makeUnexpected(vars.error());
  }
  arena.ctrl()->var_catalog = vars->catalog;
  arena.ctrl()->runtime_versions = BPFJ_RUNTIME_VERSIONS;
  return PublishedPolicyGraph{
      .rolePolicies = std::move(publishedPolicies),
      .varNames = std::move(vars->names),
  };
}

Expected<const struct bpfj_str_map*> readRolePolicies(
    const PodArena& arena) noexcept {
  if (!arena.valid()) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "role policy read needs an open arena"));
  }
  return readRolePoliciesPointer(arena);
}

Expected<const struct bpfj_role_policy*> lookupRolePolicy(
    const struct bpfj_str_map* policies,
    const struct bpfj_role_id& role) noexcept {
  const std::size_t len = ::strnlen(role.id, ROLE_ID_LEN);
  if (len == ROLE_ID_LEN) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument, "role id is not null terminated"));
  }
  return lookupRolePolicy(policies, std::string_view(role.id, len));
}

Expected<const struct bpfj_role_policy*> lookupRolePolicy(
    const struct bpfj_str_map* policies,
    std::string_view role) noexcept {
  auto id = makeRoleId(std::string(role));
  if (!id) {
    return makeUnexpected(id.error());
  }
  auto found = lookupStringMap(policies, role, "role policy");
  if (!found) {
    return makeUnexpected(found.error());
  }
  return static_cast<const struct bpfj_role_policy*>(*found);
}

Expected<const struct bpfj_var_catalog*> readVarCatalog(
    const PodArena& arena) noexcept {
  const auto* ctrl = arena.ctrl();
  if (ctrl == nullptr) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "variable catalog read needs an open arena"));
  }

  return static_cast<const struct bpfj_var_catalog*>(ctrl->var_catalog);
}

Expected<ResolvedPolicyVar> lookupVar(
    const struct bpfj_var_catalog* catalog,
    std::string_view name) noexcept {
  if (name.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "a variable name is empty"));
  }

  auto found = lookupStringMap(
      catalog == nullptr ? nullptr : catalog->by_name, name, "variable name");
  if (!found) {
    return makeUnexpected(found.error());
  }
  if (*found != nullptr) {
    const auto* published = static_cast<const struct bpfj_var_name*>(*found);
    return ResolvedPolicyVar{.id = published->id, .name = published};
  }

  return makeUnexpected(makeError(
      std::errc::invalid_argument,
      "no variable named ",
      name,
      " is published in this jail"));
}

struct bpfj_heap_control* PodArena::ctrl() noexcept {
  return reinterpret_cast<struct bpfj_heap_control*>(base_);
}

const struct bpfj_heap_control* PodArena::ctrl() const noexcept {
  return reinterpret_cast<const struct bpfj_heap_control*>(base_);
}

PodArena::~PodArena() noexcept {
  reset();
}

PodArena::PodArena(PodArena&& other) noexcept
    : owner_{std::move(other.owner_)},
      heapSyscall_{std::move(other.heapSyscall_)},
      base_{other.base_},
      mapExtra_{other.mapExtra_} {
  other.base_ = nullptr;
  other.mapExtra_ = 0;
}

PodArena& PodArena::operator=(PodArena&& other) noexcept {
  if (this != &other) {
    reset();
    owner_ = std::move(other.owner_);
    heapSyscall_ = std::move(other.heapSyscall_);
    base_ = other.base_;
    mapExtra_ = other.mapExtra_;
    other.base_ = nullptr;
    other.mapExtra_ = 0;
  }
  return *this;
}

Expected<PodArena> PodArena::open(const PinConfig& cfg) noexcept {
  if (auto res = arena::ensureWindowReserved(); !res) {
    return makeUnexpected(res.error());
  }

  auto fd = pins::openPinnedMap(cfg, kArenaMap);
  if (!fd) {
    return makeUnexpected(fd.error());
  }
  auto heapSyscall = pins::openPinnedProgram(cfg, kHeapSyscallProgram);
  if (!heapSyscall) {
    return makeUnexpected(heapSyscall.error());
  }

  auto extra = arena::pinnedMapExtra(*fd);
  if (!extra) {
    return makeUnexpected(extra.error());
  }

  const std::size_t index = slotIndex(*extra);
  {
    std::lock_guard<std::mutex> guard(openMutex());
    if (openCounts()[index] == 0) {
      void* const mapped = ::mmap(
          reinterpret_cast<void*>(*extra),
          arena::kSlotSize,
          PROT_READ | PROT_WRITE,
          MAP_SHARED | MAP_FIXED,
          fd->get(),
          0);
      if (mapped == MAP_FAILED) {
        return makeUnexpected(
            makeErrnoError("failed to mmap pinned arena at fixed address"));
      }
    }
    ++openCounts()[index];
  }

  PodArena arena;
  arena.owner_ = std::shared_ptr<void>(
      reinterpret_cast<void*>(*extra), [extra = *extra](void*) {
        std::lock_guard<std::mutex> guard(openMutex());
        auto& counts = openCounts();
        const std::size_t slot = slotIndex(extra);
        if (counts[slot] == 0) {
          return;
        }
        --counts[slot];
        if (counts[slot] == 0) {
          (void)::munmap(reinterpret_cast<void*>(extra), arena::kSlotSize);
          (void)arena::restorePlaceholder(extra);
        }
      });
  arena.heapSyscall_ = std::move(*heapSyscall);
  arena.base_ = reinterpret_cast<void*>(*extra);
  arena.mapExtra_ = *extra;
  return arena;
}

Expected<void*> PodArena::alloc(std::uint32_t size) noexcept {
  const long offset = heap::allocOffset(heapSyscall_.get(), base_, size);
  if (offset <= BPFJ_HEAP_NULL) {
    return makeUnexpected(
        makeError(std::errc::not_enough_memory, "failed to allocate pod vars"));
  }

  void* const ptr = heap::offsetToPtr(base_, static_cast<__u32>(offset));
  if (ptr == nullptr) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "pod vars allocation lies outside the arena"));
  }
  return ptr;
}

Expected<> PodArena::free(void* ptr) noexcept {
  const long res =
      heap::freeOffset(heapSyscall_.get(), heap::ptrToOffset(base_, ptr));
  if (res != 0) {
    return makeUnexpected(
        makeError(std::errc(-res), "failed to free pod vars from arena"));
  }
  return unit;
}

void PodArena::reset() noexcept {
  owner_.reset();
  heapSyscall_ = Fd{};
  base_ = nullptr;
  mapExtra_ = 0;
}

} // namespace bpfjailer
