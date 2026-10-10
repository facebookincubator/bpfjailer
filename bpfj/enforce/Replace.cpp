// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/Replace.h"

#include <bpf/bpf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/syscall.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "bpfj/enforce/BpfEnforcer.h"
#include "bpfj/enforce/ExecEnforcer.h"
#include "bpfj/enforce/FsEnforcer.h"
#include "bpfj/enforce/Jailer.h"
#include "bpfj/enforce/KillEnforcer.h"
#include "bpfj/enforce/LkmEnforcer.h"
#include "bpfj/enforce/MountEnforcer.h"
#include "bpfj/enforce/MqEnforcer.h"
#include "bpfj/enforce/PodVars.h"
// For bpfj_pod and bpfj_uuid: Pods.h is where C++ pulls the shared ABI header
// in, with the pedantic warning silenced around it.
#include "bpfj/enforce/Pods.h"
#include "bpfj/enforce/ProcEnforcer.h"
#include "bpfj/enforce/PtraceEnforcer.h"
#include "bpfj/enforce/ShmEnforcer.h"
#include "bpfj/enforce/UnixEnforcer.h"
#include "bpfj/enforce/UnprivRoles.h"
#include "bpfj/enforce/VerityEnforcer.h"
#include "bpfj/enforce/bpf/replace.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/Lock.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer {

namespace {

namespace fs = std::filesystem;

constexpr std::string_view kTaskMap = "bpfj_task_map";
constexpr std::string_view kOldTaskMap = "bpfj_old_task_map";
constexpr std::string_view kGenerationControl = "bpfj_generation_control";
constexpr std::string_view kReplaceFrozenMap = "bpfj_replace_frozen";
constexpr std::string_view kActiveEnrollsMap = "bpfj_active_enrolls";
constexpr std::string_view kMapOwners = "bpfj_bpf_map_owners";
constexpr std::string_view kProgOwners = "bpfj_bpf_prog_owners";
constexpr std::string_view kOwnerVersion = "bpfj_bpf_owner_version";
constexpr std::string_view kMqSysvOwners = "bpfj_mq_sysv_owners";
constexpr std::string_view kMqPosixOwners = "bpfj_mq_posix_owners";
constexpr std::string_view kMqPosixPending = "bpfj_mq_posix_pending";
constexpr std::string_view kMqSysvOwnerVersion = "bpfj_mq_sysv_owner_version";
constexpr std::string_view kMqPosixOwnerVersion = "bpfj_mq_posix_owner_version";
constexpr std::string_view kShmSysvOwners = "bpfj_shm_sysv_owners";
constexpr std::string_view kShmPosixOwners = "bpfj_shm_posix_owners";
constexpr std::string_view kShmPosixPending = "bpfj_shm_posix_pending";
constexpr std::string_view kShmSysvOwnerVersion = "bpfj_shm_sysv_owner_version";
constexpr std::string_view kShmPosixOwnerVersion =
    "bpfj_shm_posix_owner_version";
constexpr std::string_view kShmPosixMounts = "bpfj_shm_posix_mounts";
constexpr std::string_view kShmPosixDevices = "bpfj_shm_posix_devices";

struct BpfOwnerV2 {
  struct bpfj_role_id role;
  std::uint32_t id;
  const struct bpfj_role_policy* policy;
};

static_assert(sizeof(BpfOwnerV2) == 32);

// The tree the replacement is built in, beside the one being replaced.
constexpr std::string_view kNewSuffix = "-new";

[[nodiscard]] Expected<> exchangePinTrees(
    const PinConfig& active,
    const PinConfig& replacement) noexcept {
  if (::syscall(
          SYS_renameat2,
          AT_FDCWD,
          active.root().c_str(),
          AT_FDCWD,
          replacement.root().c_str(),
          RENAME_EXCHANGE) != 0) {
    return makeUnexpected(makeErrnoError(
        "failed to atomically exchange ",
        active.root(),
        " and ",
        replacement.root()));
  }
  return unit;
}

[[nodiscard]] Expected<Fd> acquireReplaceLease(const PinConfig& cfg) noexcept {
  Fd fd(::open(cfg.bpffsPath.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (!fd.hasFd()) {
    return makeUnexpected(
        makeErrnoError("failed to open bpffs for replacement locking"));
  }

  if (::flock(fd.get(), LOCK_EX | LOCK_NB) == 0) {
    return fd;
  }
  if (errno == EWOULDBLOCK) {
    return makeUnexpected(makeError(
        std::errc::device_or_resource_busy,
        "another jailer replacement is already running on ",
        cfg.bpffsPath));
  }
  return makeUnexpected(
      makeErrnoError("failed to lock bpffs for jailer replacement"));
}

[[nodiscard]] Expected<std::uint32_t> treeGeneration(
    const PinConfig& cfg) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  const std::uint32_t generation = arena->ctrl()->generation;
  if (generation == 0) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running jailer predates generation-controlled replacement; "
        "detach and attach to upgrade"));
  }
  return generation;
}

[[nodiscard]] Expected<struct bpfj_generation_control> readGenerationControl(
    const Fd& fd) noexcept {
  const std::uint32_t zero = 0;
  struct bpfj_generation_control control{};
  if (::bpf_map_lookup_elem(fd.get(), &zero, &control) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to read the active jailer generation"));
  }
  if (control.version != BPFJ_GENERATION_CONTROL_VERSION ||
      control.active_generation == 0) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running jailer has an incompatible generation control"));
  }
  return control;
}

struct ReplacePodValue {
  struct bpfj_pod* pod = nullptr;
};

struct ReplacePodKey {
  struct bpfj_pod* oldPod = nullptr;
};

struct SnapshotVar {
  struct bpfj_replace_var_snapshot header{};
  std::vector<unsigned char> value;
};

struct SnapshotPod {
  struct bpfj_replace_pod_snapshot header{};
  struct bpfj_pod_id pod_id{};
  std::vector<SnapshotVar> vars;
};

[[nodiscard]] bool sameSnapshot(
    const SnapshotPod& lhs,
    const SnapshotPod& rhs) noexcept {
  if (std::memcmp(&lhs.header, &rhs.header, sizeof(lhs.header)) != 0 ||
      std::memcmp(&lhs.pod_id, &rhs.pod_id, sizeof(lhs.pod_id)) != 0 ||
      lhs.vars.size() != rhs.vars.size()) {
    return false;
  }
  for (std::size_t i = 0; i < lhs.vars.size(); ++i) {
    if (std::memcmp(
            &lhs.vars[i].header,
            &rhs.vars[i].header,
            sizeof(lhs.vars[i].header)) != 0 ||
        lhs.vars[i].value != rhs.vars[i].value) {
      return false;
    }
  }
  return true;
}

template <typename T>
[[nodiscard]] bool readSnapshotField(
    const std::vector<char>& bytes,
    std::size_t& at,
    T& out) noexcept {
  if (at > bytes.size() || bytes.size() - at < sizeof(T)) {
    return false;
  }
  std::memcpy(&out, bytes.data() + at, sizeof(T));
  at += sizeof(T);
  return true;
}

[[nodiscard]] Expected<std::vector<SnapshotPod>> parseSnapshots(
    const std::vector<char>& bytes) noexcept {
  std::map<std::uint64_t, SnapshotPod> unique;
  std::size_t at = 0;
  while (at < bytes.size()) {
    SnapshotPod pod;
    if (!readSnapshotField(bytes, at, pod.header) ||
        pod.header.magic != BPFJ_REPLACE_SNAPSHOT_MAGIC ||
        pod.header.version != BPFJ_REPLACE_SNAPSHOT_VERSION ||
        pod.header.old_pod == 0 || pod.header.var_count > BPFJ_OSS_VAR_MAX ||
        !readSnapshotField(bytes, at, pod.pod_id)) {
      return makeUnexpected(makeError(
          std::errc::state_not_recoverable,
          "replace iterator emitted an invalid pod snapshot"));
    }
    if (std::memchr(
            pod.header.role_id.id, '\0', sizeof(pod.header.role_id.id)) ==
            nullptr ||
        std::memchr(pod.pod_id.id, '\0', sizeof(pod.pod_id.id)) == nullptr) {
      return makeUnexpected(makeError(
          std::errc::state_not_recoverable,
          "replace iterator emitted an unterminated pod identity"));
    }

    pod.vars.reserve(pod.header.var_count);
    for (std::uint8_t i = 0; i < pod.header.var_count; ++i) {
      SnapshotVar var;
      if (!readSnapshotField(bytes, at, var.header) || var.header.id == 0 ||
          var.header.reserved != 0) {
        return makeUnexpected(makeError(
            std::errc::state_not_recoverable,
            "replace iterator emitted an invalid variable snapshot"));
      }
      const std::uint32_t payloadSize = var.header.type == BPFJ_VAR_TYPE_STR
          ? static_cast<std::uint32_t>(var.header.size) + 1
          : var.header.type == BPFJ_VAR_TYPE_VSOCK_ADDR
          ? static_cast<std::uint32_t>(sizeof(struct vsock_address))
          : static_cast<std::uint32_t>(BPFJ_OSS_VAR_VAL_LEN + 1);
      if (payloadSize > BPFJ_OSS_VAR_VAL_LEN || at > bytes.size() ||
          bytes.size() - at < payloadSize) {
        return makeUnexpected(makeError(
            std::errc::state_not_recoverable,
            "replace iterator emitted an invalid variable payload"));
      }
      var.value.assign(bytes.begin() + at, bytes.begin() + at + payloadSize);
      at += payloadSize;
      pod.vars.push_back(std::move(var));
    }

    auto [stored, inserted] = unique.emplace(pod.header.old_pod, pod);
    if (!inserted && !sameSnapshot(stored->second, pod)) {
      return makeUnexpected(makeError(
          std::errc::state_not_recoverable,
          "one old arena address identified two different pods"));
    }
  }

  std::vector<SnapshotPod> snapshots;
  snapshots.reserve(unique.size());
  for (auto& [pointer, pod] : unique) {
    (void)pointer;
    snapshots.push_back(std::move(pod));
  }
  return snapshots;
}

[[nodiscard]] Expected<ResolvedPolicyVar> translatedVar(
    std::uint32_t oldId,
    const struct bpfj_var_catalog* oldCatalog,
    const struct bpfj_var_catalog* newCatalog) noexcept {
  const struct bpfj_var_name* oldName = nullptr;
  if (oldCatalog != nullptr && oldId > 0 && oldId <= oldCatalog->count) {
    const auto* names = bpfj_var_catalog_names(oldCatalog);
    oldName = names[oldId - 1];
    if (oldName != nullptr && oldName->id != oldId) {
      oldName = nullptr;
    }
  }
  if (oldName == nullptr) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "pod variable id ",
        std::to_string(oldId),
        " has no published name"));
  }

  const std::string_view name(oldName->str, oldName->len);
  auto translated = lookupVar(newCatalog, name);
  if (!translated) {
    return makeUnexpected(makeError(
        translated.error().code(),
        "pod carries variable '",
        name,
        "', which the new policy does not declare in vars"));
  }

  return translated;
}

/// @brief Copy `src`'s arena-backed vars into a freshly allocated flat pod,
/// translating ids by name so a new policy can renumber the allowlist without
/// changing what a running pod means.
[[nodiscard]] Expected<struct bpfj_pod*> translatePod(
    const SnapshotPod& src,
    PodArena& newArena,
    const struct bpfj_var_catalog* oldVars,
    const struct bpfj_var_catalog* newVars,
    const struct bpfj_str_map* newPolicies) noexcept {
  const std::size_t count = src.vars.size();
  std::uint32_t blobSize = bpfj_var_align_up(sizeof(struct bpfj_pod));
  blobSize += bpfj_var_align_up(sizeof(struct bpfj_var) * count);
  for (const auto& var : src.vars) {
    blobSize += bpfj_var_align_up(static_cast<std::uint32_t>(var.value.size()));
  }

  auto blob = newArena.alloc(blobSize);
  if (!blob) {
    return makeUnexpected(blob.error());
  }

  auto* dst = static_cast<struct bpfj_pod*>(*blob);
  *dst = {};
  dst->role_id = src.header.role_id;
  dst->pod_id = src.pod_id;
  dst->uuid = src.header.uuid;
  dst->creation_time_ns = src.header.creation_time_ns;
  dst->gc_removal_attempts = src.header.gc_removal_attempts;
  dst->enrollment_source = src.header.enrollment_source;
  auto rolePolicy = lookupRolePolicy(newPolicies, src.header.role_id);
  if (!rolePolicy || !*rolePolicy) {
    (void)newArena.free(*blob);
    if (!rolePolicy) {
      return makeUnexpected(rolePolicy.error());
    }
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "pod ",
        uuidToString(src.header.uuid),
        " has role missing from the new policy"));
  }
  dst->policy = *rolePolicy;
  dst->refs = 0;
  bpfj_var_array_init(&dst->var_array);
  if (count == 0) {
    return dst;
  }

  auto* outVars = reinterpret_cast<struct bpfj_var*>(
      static_cast<unsigned char*>(*blob) +
      bpfj_var_align_up(sizeof(struct bpfj_pod)));
  std::uint32_t valueOff = bpfj_var_align_up(sizeof(struct bpfj_pod)) +
      bpfj_var_align_up(sizeof(struct bpfj_var) * count);
  for (std::size_t i = 0; i < count; ++i) {
    const auto& oldVar = src.vars[i];
    auto translated = translatedVar(oldVar.header.id, oldVars, newVars);
    if (!translated) {
      (void)newArena.free(*blob);
      return makeUnexpected(makeError(
          translated.error().code(),
          "pod ",
          uuidToString(src.header.uuid),
          ": ",
          translated.error().message()));
    }

    const std::uint32_t payloadSize =
        static_cast<std::uint32_t>(oldVar.value.size());
    outVars[i] = {
        .id = translated->id,
        .type = oldVar.header.type,
        .size = oldVar.header.size,
        .reserved = oldVar.header.reserved,
        .name = translated->name,
        .val = static_cast<unsigned char*>(*blob) + valueOff,
    };
    std::memcpy(outVars[i].val, oldVar.value.data(), payloadSize);
    valueOff += bpfj_var_align_up(payloadSize);
  }

  dst->var_array.vars = outVars;
  dst->var_array.count = static_cast<__u8>(count);
  return dst;
}

/// @brief Copy the old tree's pods into the new arena, less its base role,
/// which Jailer::load has already remade and reseeded. Refs are zeroed on the
/// way across and counted back up by the backfill iterator. Variables cross by
/// name (see translatePod()), and the backfill finds the translated pod again
/// by the old pod pointer value so it never has to dereference the old arena.
[[nodiscard]] Expected<std::size_t> copyPods(
    const PinConfig& oldCfg,
    const PinConfig& newCfg,
    const std::vector<SnapshotPod>& snapshots,
    int replacePodsMapFd) noexcept {
  auto oldArena = PodArena::open(oldCfg);
  if (!oldArena) {
    return makeUnexpected(oldArena.error());
  }
  auto oldVars = readVarCatalog(*oldArena);
  if (!oldVars) {
    return makeUnexpected(oldVars.error());
  }
  auto newArena = PodArena::open(newCfg);
  if (!newArena) {
    return makeUnexpected(newArena.error());
  }
  std::vector<void*> newPods;
  auto rollbackPods = makeGuard([&] {
    for (void* const pod : newPods) {
      (void)newArena->free(pod);
    }
  });
  auto newVars = readVarCatalog(*newArena);
  if (!newVars) {
    return makeUnexpected(newVars.error());
  }
  auto newPolicies = readRolePolicies(*newArena);
  if (!newPolicies || !*newPolicies) {
    return !newPolicies
        ? makeUnexpected(newPolicies.error())
        : makeUnexpected(makeError(
              std::errc::bad_address, "the new arena has no role policy map"));
  }
  if (newArena->ctrl()->runtime_versions == 0) {
    return makeUnexpected(makeError(
        std::errc::bad_address, "the new arena has no runtime versions"));
  }
  std::size_t copied = 0;
  for (const auto& pod : snapshots) {
    struct bpfj_pod* newPod = nullptr;
    if (pod.header.enrollment_source != BPFJ_ENROLL_BASE_ROLE) {
      auto translated =
          translatePod(pod, *newArena, *oldVars, *newVars, *newPolicies);
      if (!translated) {
        return makeUnexpected(translated.error());
      }
      newPod = *translated;
      newPods.push_back(newPod);
    }

    const ReplacePodKey key{
        .oldPod = reinterpret_cast<struct bpfj_pod*>(pod.header.old_pod)};
    const ReplacePodValue entry{.pod = newPod};
    if (::bpf_map_update_elem(replacePodsMapFd, &key, &entry, BPF_ANY) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to record a carried pod for backfill"));
    }
    if (newPod != nullptr) {
      ++copied;
    }
  }

  rollbackPods.dismiss();
  return copied;
}

// BPF object ownership records are carried across the way the pods are: a
// pinned object is held by its pin rather than anyone's fd, so bpf_enforce's
// seeding walk cannot see the jailer's own maps, and a rebuilt tree would read
// as "nothing is owned".

/// @brief Whether the old tree has a bpf_enforce in it at all; the tests bring
/// enforcers up one at a time, so partial trees are not hypothetical.
[[nodiscard]] bool tracksOwnership(const PinConfig& cfg) noexcept {
  std::error_code ec;
  return fs::exists(fs::path(cfg.mapPath(kMapOwners)), ec);
}

/// @brief Carry one owner map's records into the new tree's copy.
[[nodiscard]] Expected<std::size_t> copyOwnerMap(
    int from,
    int to,
    const struct bpfj_str_map* policies,
    std::uint32_t sourceVersion) noexcept {
  // Same guard as copyPods(), and the free hook deletes from this map, so a
  // restarted walk is not hypothetical here.
  std::set<std::uint64_t> seen;

  std::size_t copied = 0;
  std::uint64_t curr = 0;
  std::uint64_t next = 0;
  const void* cursor = nullptr;
  while (::bpf_map_get_next_key(from, cursor, &next) == 0) {
    if (!seen.insert(next).second) {
      break;
    }

    struct bpfj_bpf_owner owner{};
    bool found = false;
    if (sourceVersion == 2) {
      BpfOwnerV2 legacy{};
      found = ::bpf_map_lookup_elem(from, &next, &legacy) == 0;
      if (found) {
        owner.role = legacy.role;
        owner.id = legacy.id;
        // v2 had no pod identity. Leave the UUID zero as an explicit legacy
        // marker; the BPF gate preserves v2's same-role access for only these
        // records rather than pretending they belong to an arbitrary pod.
      }
    } else {
      found = ::bpf_map_lookup_elem(from, &next, &owner) == 0;
    }
    if (found) {
      auto policy = lookupRolePolicy(policies, owner.role);
      if (!policy) {
        return makeUnexpected(policy.error());
      }
      if (!*policy) {
        return makeUnexpected(makeError(
            std::errc::invalid_argument,
            "BPF owner has a role missing from the new policy"));
      }
      owner.policy = *policy;
      if (::bpf_map_update_elem(to, &next, &owner, BPF_ANY) != 0) {
        return makeUnexpected(
            makeErrnoError("failed to copy a BPF ownership record across"));
      }
      ++copied;
    }

    curr = next;
    cursor = &curr;
  }

  return copied;
}

/// @brief Carry both owner maps into the new tree, whose own objects the live
/// enforcer's create hook already recorded in the old map. Runs before the old
/// tree is unloaded, so the new tree's bpf_map_free hook prunes the records for
/// the objects that unload frees.
[[nodiscard]] Expected<std::size_t> copyBpfOwners(
    const PinConfig& oldCfg,
    const PinConfig& newCfg,
    std::uint32_t sourceVersion) noexcept {
  if (!tracksOwnership(oldCfg)) {
    return std::size_t{0};
  }

  std::size_t copied = 0;
  auto arena = PodArena::open(newCfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies || !*policies) {
    return !policies
        ? makeUnexpected(policies.error())
        : makeUnexpected(makeError(
              std::errc::bad_address, "the new arena has no role policy map"));
  }
  for (const auto& name : {kMapOwners, kProgOwners}) {
    auto from = pins::openPinnedMap(oldCfg, name);
    if (!from) {
      return makeUnexpected(from.error());
    }

    auto to = pins::openPinnedMap(newCfg, name);
    if (!to) {
      return makeUnexpected(to.error());
    }

    auto one = copyOwnerMap(from->get(), to->get(), *policies, sourceVersion);
    if (!one) {
      return makeUnexpected(one.error());
    }
    copied += *one;
  }

  return copied;
}

[[nodiscard]] bool hasPinnedMap(
    const PinConfig& cfg,
    std::string_view name) noexcept {
  std::error_code ec;
  return fs::exists(fs::path(cfg.mapPath(name)), ec);
}

[[nodiscard]] bool hasVersionedOwnerState(const PinConfig& cfg) noexcept {
  for (const auto name :
       {kMapOwners,
        kMqSysvOwners,
        kMqPosixOwners,
        kShmSysvOwners,
        kShmPosixOwners}) {
    if (hasPinnedMap(cfg, name)) {
      return true;
    }
  }
  return false;
}

struct MutationJournal {
  PodArena arena;
  struct bpfj_mutation_journal* journal = nullptr;
  std::uint64_t replayed = 0;
};

[[nodiscard]] Expected<> lockJournal(
    struct bpfj_mutation_journal& journal,
    std::optional<lock::Guard>& guard) noexcept {
  using namespace std::chrono_literals;
  guard.emplace(journal.lock, 5s);
  if (!guard->owns()) {
    return makeUnexpected(makeError(
        std::errc::timed_out, "timed out taking the ownership journal lock"));
  }
  return unit;
}

[[nodiscard]] Expected<MutationJournal> startMutationJournal(
    const PinConfig& cfg) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }

  auto* ctrl = arena->ctrl();
  auto* journal =
      static_cast<struct bpfj_mutation_journal*>(ctrl->mutation_journal);
  if (journal == nullptr) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running jailer lacks a persistent ownership journal; detach and "
        "attach to upgrade"));
  }

  std::optional<lock::Guard> guard;
  if (auto res = lockJournal(*journal, guard); !res) {
    return makeUnexpected(res.error());
  }
  const bool compatibleCapacity =
      journal->entries.capacity == BPFJ_MUTATION_JOURNAL_CAPACITY ||
      journal->entries.capacity == BPFJ_MUTATION_JOURNAL_LEGACY_CAPACITY;
  if (!compatibleCapacity ||
      journal->entries.elem_size != sizeof(struct bpfj_mutation_record) ||
      journal->entries.buf == nullptr) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running arena has an incompatible ownership journal"));
  }
  journal->entries.size = 0;
  journal->next = 0;
  journal->consumed = 0;
  journal->failure = BPFJ_MUTATION_JOURNAL_OK;
  journal->state = BPFJ_MUTATION_JOURNAL_RECORDING;
  return MutationJournal{.arena = std::move(*arena), .journal = journal};
}

void disableMutationJournal(MutationJournal& owner) noexcept {
  if (owner.journal == nullptr) {
    return;
  }
  using namespace std::chrono_literals;
  lock::Guard guard{owner.journal->lock, 5s};
  if (guard.owns()) {
    owner.journal->state = BPFJ_MUTATION_JOURNAL_OFF;
  }
}

struct MutationReplayMaps {
  PodArena arena;
  const struct bpfj_str_map* policies = nullptr;
  std::map<std::uint8_t, Fd> maps;
};

[[nodiscard]] Expected<MutationReplayMaps> openMutationReplayMaps(
    const PinConfig& cfg) noexcept {
  MutationReplayMaps out;
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies || !*policies) {
    return !policies ? makeUnexpected(policies.error())
                     : makeUnexpected(makeError(
                           std::errc::bad_address,
                           "the replacement arena has no role policy map"));
  }
  out.arena = std::move(*arena);
  out.policies = *policies;

  const std::pair<std::uint8_t, std::string_view> names[] = {
      {BPFJ_MUTATION_BPF_MAP_OWNER, kMapOwners},
      {BPFJ_MUTATION_BPF_PROG_OWNER, kProgOwners},
      {BPFJ_MUTATION_MQ_SYSV_OWNER, kMqSysvOwners},
      {BPFJ_MUTATION_MQ_POSIX_OWNER, kMqPosixOwners},
      {BPFJ_MUTATION_MQ_POSIX_PENDING, kMqPosixPending},
      {BPFJ_MUTATION_SHM_SYSV_OWNER, kShmSysvOwners},
      {BPFJ_MUTATION_SHM_POSIX_OWNER, kShmPosixOwners},
      {BPFJ_MUTATION_SHM_POSIX_PENDING, kShmPosixPending},
  };
  for (const auto& [domain, name] : names) {
    auto map = pins::openPinnedMap(cfg, name);
    if (!map) {
      return makeUnexpected(map.error());
    }
    out.maps.emplace(domain, std::move(*map));
  }
  return out;
}

[[nodiscard]] Expected<const struct bpfj_role_policy*> replayPolicy(
    const MutationReplayMaps& maps,
    const struct bpfj_mutation_record& record) noexcept {
  auto policy = lookupRolePolicy(maps.policies, record.role);
  if (!policy) {
    return makeUnexpected(policy.error());
  }
  if (!*policy) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "ownership journal names a role missing from the new policy"));
  }
  return *policy;
}

[[nodiscard]] Expected<> replayMutation(
    const MutationReplayMaps& maps,
    const struct bpfj_mutation_record& record) noexcept {
  const auto found = maps.maps.find(record.domain);
  if (found == maps.maps.end()) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "ownership journal has an unknown domain"));
  }
  const int fd = found->second.get();
  if (record.operation == BPFJ_MUTATION_DELETE) {
    if (::bpf_map_delete_elem(fd, record.key) != 0 && errno != ENOENT) {
      return makeUnexpected(
          makeErrnoError("failed to replay an ownership deletion"));
    }
    return unit;
  }
  if (record.operation != BPFJ_MUTATION_UPSERT) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "ownership journal has an unknown operation"));
  }

  const struct bpfj_role_policy* policy = nullptr;
  if (record.owned) {
    auto translated = replayPolicy(maps, record);
    if (!translated) {
      return makeUnexpected(translated.error());
    }
    policy = *translated;
  }

  int result = -1;
  switch (record.domain) {
    case BPFJ_MUTATION_BPF_MAP_OWNER:
    case BPFJ_MUTATION_BPF_PROG_OWNER: {
      const struct bpfj_bpf_owner owner = {
          .role = record.role,
          .id = record.object_id,
          .pod = record.pod,
          .policy = policy,
      };
      result = ::bpf_map_update_elem(fd, record.key, &owner, BPF_ANY);
      break;
    }
    case BPFJ_MUTATION_MQ_SYSV_OWNER:
    case BPFJ_MUTATION_MQ_POSIX_OWNER: {
      const struct bpfj_mq_owner owner = {
          .role = record.role,
          .pod = record.pod,
          .policy = policy,
      };
      result = ::bpf_map_update_elem(fd, record.key, &owner, BPF_ANY);
      break;
    }
    case BPFJ_MUTATION_MQ_POSIX_PENDING: {
      const struct bpfj_mq_pending_owner pending = {
          .owner =
              {
                  .role = record.role,
                  .pod = record.pod,
                  .policy = policy,
              },
          .owned = record.owned,
      };
      result = ::bpf_map_update_elem(fd, record.key, &pending, BPF_ANY);
      break;
    }
    case BPFJ_MUTATION_SHM_SYSV_OWNER:
    case BPFJ_MUTATION_SHM_POSIX_OWNER: {
      const struct bpfj_shm_owner owner = {
          .role = record.role,
          .pod = record.pod,
          .policy = policy,
      };
      result = ::bpf_map_update_elem(fd, record.key, &owner, BPF_ANY);
      break;
    }
    case BPFJ_MUTATION_SHM_POSIX_PENDING: {
      const struct bpfj_shm_pending_owner pending = {
          .owner =
              {
                  .role = record.role,
                  .pod = record.pod,
                  .policy = policy,
              },
          .owned = record.owned,
      };
      result = ::bpf_map_update_elem(fd, record.key, &pending, BPF_ANY);
      break;
    }
    default:
      break;
  }
  if (result != 0) {
    return makeUnexpected(makeErrnoError("failed to replay ownership state"));
  }
  return unit;
}

[[nodiscard]] Expected<std::uint64_t> journalEndLocked(
    const MutationJournal& owner) noexcept {
  const auto failure =
      __atomic_load_n(&owner.journal->failure, __ATOMIC_ACQUIRE);
  if (failure == BPFJ_MUTATION_JOURNAL_FULL) {
    std::array<std::uint32_t, BPFJ_MUTATION_SHM_POSIX_PENDING + 1> domains{};
    const auto* records = static_cast<const struct bpfj_mutation_record*>(
        owner.journal->entries.buf);
    for (std::uint32_t i = 0; i < owner.journal->entries.capacity; ++i) {
      if (records[i].committed != 0 && records[i].domain < domains.size()) {
        ++domains[records[i].domain];
      }
    }
    return makeUnexpected(makeError(
        std::errc::no_buffer_space,
        "ownership mutation journal exhausted its capacity during "
        "replacement (BPF maps ",
        std::to_string(domains[BPFJ_MUTATION_BPF_MAP_OWNER]),
        ", BPF programs ",
        std::to_string(domains[BPFJ_MUTATION_BPF_PROG_OWNER]),
        ", MQ ",
        std::to_string(
            domains[BPFJ_MUTATION_MQ_SYSV_OWNER] +
            domains[BPFJ_MUTATION_MQ_POSIX_OWNER] +
            domains[BPFJ_MUTATION_MQ_POSIX_PENDING]),
        ", SHM ",
        std::to_string(
            domains[BPFJ_MUTATION_SHM_SYSV_OWNER] +
            domains[BPFJ_MUTATION_SHM_POSIX_OWNER] +
            domains[BPFJ_MUTATION_SHM_POSIX_PENDING]),
        ")"));
  }
  if (failure == BPFJ_MUTATION_JOURNAL_CONTENDED) {
    return makeUnexpected(makeError(
        std::errc::device_or_resource_busy,
        "an ownership mutation could not acquire the replacement journal "
        "lock"));
  }
  if (failure != BPFJ_MUTATION_JOURNAL_OK) {
    return makeUnexpected(makeError(
        std::errc::state_not_recoverable,
        "ownership mutation journal has an unknown failure state"));
  }
  const std::uint64_t end =
      __atomic_load_n(&owner.journal->next, __ATOMIC_ACQUIRE);
  const std::uint64_t consumed =
      __atomic_load_n(&owner.journal->consumed, __ATOMIC_ACQUIRE);
  if (end - consumed > owner.journal->entries.capacity) {
    return makeUnexpected(makeError(
        std::errc::no_buffer_space,
        "ownership mutation journal exceeded its capacity"));
  }
  return end;
}

[[nodiscard]] Expected<std::uint64_t> journalEnd(
    MutationJournal& owner) noexcept {
  return journalEndLocked(owner);
}

[[nodiscard]] Expected<> publishJournalReplay(MutationJournal& owner) noexcept {
  __atomic_store_n(&owner.journal->consumed, owner.replayed, __ATOMIC_RELEASE);
  return unit;
}

[[nodiscard]] Expected<std::size_t> replayMutationJournal(
    MutationJournal& owner,
    const MutationReplayMaps& maps,
    std::uint64_t end) noexcept {
  auto* records =
      static_cast<struct bpfj_mutation_record*>(owner.journal->entries.buf);
  std::size_t applied = 0;
  while (owner.replayed < end) {
    auto& record = records[owner.replayed % owner.journal->entries.capacity];
    if (record.committed == 0) {
      return makeUnexpected(makeError(
          std::errc::state_not_recoverable,
          "ownership journal contains an uncommitted record"));
    }
    if (auto res = replayMutation(maps, record); !res) {
      return makeUnexpected(res.error());
    }
    ++owner.replayed;
    ++applied;
    if ((applied & 0xffU) == 0) {
      if (auto res = publishJournalReplay(owner); !res) {
        return makeUnexpected(res.error());
      }
    }
  }
  if (auto res = publishJournalReplay(owner); !res) {
    return makeUnexpected(res.error());
  }
  return applied;
}

[[nodiscard]] Expected<std::uint32_t> readRuntimeVersions(
    const PinConfig& cfg) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  if (arena->ctrl()->runtime_versions == 0) {
    return makeUnexpected(makeError(
        std::errc::bad_address,
        "the running jailer has no arena runtime versions"));
  }
  return arena->ctrl()->runtime_versions;
}

/// Refuse task-storage or pod records this build cannot read. Zero denotes the
/// immediate predecessor, which used these layouts but had not published a
/// membership version in the remaining byte of the runtime-version word.
[[nodiscard]] Expected<> checkMembershipVersion(
    const PinConfig& cfg,
    std::uint32_t versions) noexcept {
  if (!hasPinnedMap(cfg, kTaskMap)) {
    return unit;
  }

  std::uint32_t version =
      (versions >> BPFJ_MEMBERSHIP_VERSION_SHIFT) & BPFJ_RUNTIME_VERSION_MASK;
  if (version == 0) {
    version = BPFJ_MEMBERSHIP_VERSION;
  }
  if (version != BPFJ_MEMBERSHIP_VERSION) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running jailer persists task membership in layout v",
        std::to_string(version),
        ", and this build reads v",
        std::to_string(BPFJ_MEMBERSHIP_VERSION),
        "; detach and attach to upgrade"));
  }
  return unit;
}

[[nodiscard]] Expected<std::uint32_t> readLegacyOwnerVersion(
    const PinConfig& cfg,
    std::string_view versionMap,
    std::string_view what) noexcept {
  auto map = pins::openPinnedMap(cfg, versionMap);
  if (!map) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running jailer records ",
        what,
        " without an arena or legacy layout version; detach and "
        "attach to upgrade"));
  }

  const std::uint32_t slot = 0;
  std::uint32_t version = 0;
  if (::bpf_map_lookup_elem(map->get(), &slot, &version) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to read the legacy ", what, " version"));
  }
  return version;
}

/// Refuse records this build cannot read. A zero arena field denotes the
/// predecessor that still published one-entry version maps; accepting those
/// maps here provides a one-way replace path while new trees create none.
[[nodiscard]] Expected<> checkOwnerVersion(
    const PinConfig& cfg,
    std::uint32_t versions,
    std::string_view owners,
    std::string_view versionMap,
    std::uint32_t shift,
    std::uint32_t expected,
    std::string_view what) noexcept {
  if (!hasPinnedMap(cfg, owners)) {
    return unit;
  }

  std::uint32_t version = (versions >> shift) & BPFJ_RUNTIME_VERSION_MASK;
  if (version == 0) {
    auto legacy = readLegacyOwnerVersion(cfg, versionMap, what);
    if (!legacy) {
      return makeUnexpected(legacy.error());
    }
    version = *legacy;
  }

  if (version != expected) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "the running jailer records ",
        what,
        " in layout v",
        std::to_string(version),
        ", and this build reads v",
        std::to_string(expected),
        "; detach and attach to upgrade"));
  }
  return unit;
}

/// Copy a map without baking its key shape into replacement. This is used for
/// both the pointer-keyed System V map and the (device,inode)-keyed POSIX map.
[[nodiscard]] Expected<std::size_t> copyRawMap(
    int from,
    int to,
    std::string_view what,
    const struct bpfj_str_map* policies = nullptr,
    std::size_t policyOffset = 0,
    std::optional<std::size_t> ownedOffset = std::nullopt) noexcept {
  static_assert(offsetof(struct bpfj_mq_owner, role) == 0);
  static_assert(offsetof(struct bpfj_shm_owner, role) == 0);
  struct bpf_map_info info{};
  std::uint32_t infoSize = sizeof(info);
  if (::bpf_obj_get_info_by_fd(from, &info, &infoSize) != 0) {
    return makeUnexpected(makeErrnoError("failed to inspect ", what));
  }

  std::vector<unsigned char> current(info.key_size);
  std::vector<unsigned char> next(info.key_size);
  std::vector<unsigned char> value(info.value_size);
  std::set<std::vector<unsigned char>> seen;
  const void* cursor = nullptr;
  std::size_t copied = 0;
  const std::size_t maxAttempts =
      static_cast<std::size_t>(info.max_entries) * 2 + 1;
  for (std::size_t attempt = 0; attempt < maxAttempts; ++attempt) {
    if (::bpf_map_get_next_key(from, cursor, next.data()) != 0) {
      return copied;
    }
    const bool firstVisit = seen.insert(next).second;
    if (firstVisit &&
        ::bpf_map_lookup_elem(from, next.data(), value.data()) == 0) {
      const bool owned = !ownedOffset ||
          (*ownedOffset < value.size() && value[*ownedOffset] != 0);
      if (policies != nullptr && owned) {
        struct bpfj_role_id role{};
        std::memcpy(&role, value.data(), sizeof(role));
        auto policy = lookupRolePolicy(policies, role);
        if (!policy) {
          return makeUnexpected(policy.error());
        }
        if (!*policy) {
          return makeUnexpected(makeError(
              std::errc::invalid_argument,
              what,
              " has an owner role missing from the new policy"));
        }
        if (value.size() < policyOffset + sizeof(*policy)) {
          return makeUnexpected(makeError(
              std::errc::invalid_argument,
              what,
              " has an unexpected owner value size"));
        }
        std::memcpy(value.data() + policyOffset, &*policy, sizeof(*policy));
      }
      if (::bpf_map_update_elem(to, next.data(), value.data(), BPF_ANY) != 0) {
        return makeUnexpected(makeErrnoError("failed to copy ", what));
      }
      ++copied;
    }
    current = next;
    cursor = current.data();
  }
  return makeUnexpected(makeError(
      std::errc::resource_unavailable_try_again,
      what,
      " kept changing while it was copied"));
}

[[nodiscard]] Expected<std::size_t> copyMqOwners(
    const PinConfig& oldCfg,
    const PinConfig& newCfg) noexcept {
  std::size_t copied = 0;
  auto arena = PodArena::open(newCfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies || !*policies) {
    return !policies
        ? makeUnexpected(policies.error())
        : makeUnexpected(makeError(
              std::errc::bad_address, "the new arena has no role policy map"));
  }
  for (const auto name : {kMqSysvOwners, kMqPosixOwners}) {
    if (!hasPinnedMap(oldCfg, name)) {
      continue;
    }
    auto from = pins::openPinnedMap(oldCfg, name);
    auto to = pins::openPinnedMap(newCfg, name);
    if (!from) {
      return makeUnexpected(from.error());
    }
    if (!to) {
      return makeUnexpected(to.error());
    }
    auto one = copyRawMap(
        from->get(),
        to->get(),
        name,
        *policies,
        offsetof(struct bpfj_mq_owner, policy));
    if (!one) {
      return makeUnexpected(one.error());
    }
    copied += *one;
  }
  return copied;
}

[[nodiscard]] Expected<std::size_t> copyShmState(
    const PinConfig& oldCfg,
    const PinConfig& newCfg) noexcept {
  std::size_t copied = 0;
  auto arena = PodArena::open(newCfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies || !*policies) {
    return !policies
        ? makeUnexpected(policies.error())
        : makeUnexpected(makeError(
              std::errc::bad_address, "the new arena has no role policy map"));
  }
  for (const auto name :
       {kShmSysvOwners, kShmPosixOwners, kShmPosixMounts, kShmPosixDevices}) {
    if (!hasPinnedMap(oldCfg, name)) {
      continue;
    }
    auto from = pins::openPinnedMap(oldCfg, name);
    auto to = pins::openPinnedMap(newCfg, name);
    if (!from) {
      return makeUnexpected(from.error());
    }
    if (!to) {
      return makeUnexpected(to.error());
    }
    const bool hasOwner = name == kShmSysvOwners || name == kShmPosixOwners;
    auto one = copyRawMap(
        from->get(),
        to->get(),
        name,
        hasOwner ? *policies : nullptr,
        offsetof(struct bpfj_shm_owner, policy));
    if (!one) {
      return makeUnexpected(one.error());
    }
    copied += *one;
  }
  return copied;
}

[[nodiscard]] Expected<> copyPendingOwnership(
    const PinConfig& oldCfg,
    const PinConfig& newCfg) noexcept {
  auto arena = PodArena::open(newCfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto policies = readRolePolicies(*arena);
  if (!policies || !*policies) {
    return !policies
        ? makeUnexpected(policies.error())
        : makeUnexpected(makeError(
              std::errc::bad_address, "the new arena has no role policy map"));
  }

  const struct {
    std::string_view name;
    std::size_t policyOffset;
    std::size_t ownedOffset;
  } pendingMaps[] = {
      {kMqPosixPending,
       offsetof(struct bpfj_mq_pending_owner, owner) +
           offsetof(struct bpfj_mq_owner, policy),
       offsetof(struct bpfj_mq_pending_owner, owned)},
      {kShmPosixPending,
       offsetof(struct bpfj_shm_pending_owner, owner) +
           offsetof(struct bpfj_shm_owner, policy),
       offsetof(struct bpfj_shm_pending_owner, owned)},
  };
  for (const auto& pending : pendingMaps) {
    if (!hasPinnedMap(oldCfg, pending.name)) {
      continue;
    }
    auto from = pins::openPinnedMap(oldCfg, pending.name);
    auto to = pins::openPinnedMap(newCfg, pending.name);
    if (!from) {
      return makeUnexpected(from.error());
    }
    if (!to) {
      return makeUnexpected(to.error());
    }
    auto copied = copyRawMap(
        from->get(),
        to->get(),
        pending.name,
        *policies,
        pending.policyOffset,
        pending.ownedOffset);
    if (!copied) {
      return makeUnexpected(copied.error());
    }
  }
  return unit;
}

/// @brief Read one of the iterator's single-slot counters.
[[nodiscard]] Expected<std::size_t> readCounter(
    struct bpf_map* map,
    std::string_view what) noexcept {
  const std::uint32_t zero = 0;
  std::uint64_t value = 0;
  if (::bpf_map_lookup_elem(::bpf_map__fd(map), &zero, &value) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to read the backfill ", what, " count"));
  }

  return static_cast<std::size_t>(value);
}

/// Snapshot every pod named by every task, threads included. This skeleton is
/// deliberately bound to the old arena: the iterator copies each pod while
/// its task-storage reference is live, so userspace never follows an old arena
/// pointer after the task can release it.
[[nodiscard]] Expected<std::vector<SnapshotPod>> snapshotPods(
    const PinConfig& oldCfg) noexcept {
  auto created = bpfj::libbpf::BpfSkel<replace_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  if (auto res = pins::pinSharedMaps(skel, oldCfg.mapDir()); !res) {
    return makeUnexpected(res.error());
  }
  if (auto res =
          pins::pinMapAt(skel, kOldTaskMap, oldCfg.mapPath(kTaskMap), {});
      !res) {
    return makeUnexpected(res.error());
  }
  if (auto res = skel.load(); !res) {
    return makeUnexpected(res.error());
  }
  if (auto res = heap::init(created.value()); !res) {
    return makeUnexpected(res.error());
  }
  if (auto res = skel.attach(); !res) {
    return makeUnexpected(res.error());
  }

  bpfj::libbpf::BpfLink link(skel.links().bpfj_replace_snapshot);
  auto bytes = link.iter();
  if (!bytes) {
    return makeUnexpected(bytes.error());
  }

  auto incompatible =
      readCounter(skel.maps().bpfj_replace_incompatible, "snapshot layout");
  if (!incompatible) {
    return makeUnexpected(incompatible.error());
  }
  if (*incompatible != 0) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "snapshot found ",
        std::to_string(*incompatible),
        " invalid task-storage or pod record(s)"));
  }
  auto failed = readCounter(skel.maps().bpfj_replace_failed, "snapshot write");
  if (!failed) {
    return makeUnexpected(failed.error());
  }
  if (*failed != 0) {
    return makeUnexpected(makeError(
        std::errc::io_error,
        "snapshot could not emit ",
        std::to_string(*failed),
        " pod record(s)"));
  }
  return parseSnapshots(*bytes);
}

[[nodiscard]] Expected<> setReplaceFrozen(
    const PinConfig& cfg,
    bool frozen) noexcept {
  auto map = pins::openPinnedMap(cfg, kReplaceFrozenMap);
  if (!map) {
    return makeUnexpected(map.error());
  }

  const std::uint32_t slot = 0;
  const std::uint8_t value = frozen ? 1 : 0;
  if (::bpf_map_update_elem(map->get(), &slot, &value, BPF_ANY) != 0) {
    return makeUnexpected(makeErrnoError(
        "failed to ",
        frozen ? "freeze" : "thaw",
        " enrollments in ",
        cfg.root()));
  }

  return unit;
}

[[nodiscard]] Expected<> clearMutationJournal(const PinConfig& cfg) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }
  auto* journal = static_cast<struct bpfj_mutation_journal*>(
      arena->ctrl()->mutation_journal);
  if (journal) {
    std::optional<lock::Guard> guard;
    if (auto res = lockJournal(*journal, guard); !res) {
      return makeUnexpected(res.error());
    }
    journal->state = BPFJ_MUTATION_JOURNAL_OFF;
  }
  return unit;
}

[[nodiscard]] Expected<> recoverInterruptedCutover(
    const PinConfig& cfg,
    const PinConfig& newCfg) noexcept {
  std::error_code ec;
  if (!fs::exists(fs::path(cfg.root()), ec) ||
      !fs::exists(fs::path(newCfg.root()), ec)) {
    return unit;
  }

  auto control = pins::openPinnedMap(cfg, kGenerationControl);
  if (!control) {
    // A pre-generation tree cannot have reached this implementation's atomic
    // exchange. Leave normal compatibility handling to buildAndSwap().
    return unit;
  }
  auto active = readGenerationControl(*control);
  if (!active) {
    return makeUnexpected(active.error());
  }
  auto canonicalGeneration = treeGeneration(cfg);
  if (!canonicalGeneration) {
    return makeUnexpected(canonicalGeneration.error());
  }

  if (active->active_generation != *canonicalGeneration) {
    auto peerGeneration = treeGeneration(newCfg);
    if (!peerGeneration) {
      return makeUnexpected(peerGeneration.error());
    }
    if (active->active_generation != *peerGeneration) {
      return makeUnexpected(makeError(
          std::errc::state_not_recoverable,
          "neither replacement pin tree contains the enforcing generation"));
    }
    if (auto res = exchangePinTrees(cfg, newCfg); !res) {
      return makeUnexpected(res.error());
    }
  }

  // The enforcing tree is canonical again. A pre-activation crash can leave
  // its enrollment gate frozen and journal recording; neither state is useful
  // once the passive peer is discarded.
  if (auto res = clearMutationJournal(cfg); !res) {
    return makeUnexpected(res.error());
  }
  if (auto res = setReplaceFrozen(cfg, false); !res) {
    return makeUnexpected(res.error());
  }
  if (auto res = Jailer::unload(newCfg); !res) {
    return makeUnexpected(res.error());
  }
  return unit;
}

[[nodiscard]] bool pidIsAlive(std::uint32_t pid) noexcept {
  return ::kill(static_cast<pid_t>(pid), 0) == 0 || errno != ESRCH;
}

[[nodiscard]] Expected<> waitForActiveEnrollsToDrain(
    const PinConfig& cfg) noexcept {
  auto map = pins::openPinnedMap(cfg, kActiveEnrollsMap);
  if (!map) {
    return makeUnexpected(map.error());
  }

  using namespace std::chrono_literals;
  constexpr auto kTimeout = 5s;
  const auto deadline = std::chrono::steady_clock::now() + kTimeout;

  while (true) {
    std::uint32_t pid = 0;
    if (::bpf_map_get_next_key(map->get(), nullptr, &pid) != 0) {
      if (errno == ENOENT) {
        return unit;
      }

      return makeUnexpected(makeErrnoError(
          "failed to read the in-flight enrollments from ", cfg.root()));
    }

    if (!pidIsAlive(pid)) {
      (void)::bpf_map_delete_elem(map->get(), &pid);
      continue;
    }

    if (std::chrono::steady_clock::now() >= deadline) {
      return makeUnexpected(makeError(
          std::errc::timed_out,
          "timed out waiting for pid ",
          std::to_string(pid),
          " to finish enrolling while replacing the jailer"));
    }

    std::this_thread::sleep_for(1ms);
  }
}

struct BackfillStats {
  std::size_t pods = 0;
  std::size_t tasks = 0;
};

/// @brief Migrate each task's membership into the new tree's task map, through
/// an iterator loaded, run and dropped rather than pinned.
[[nodiscard]] Expected<BackfillStats> backfillTasks(
    const PinConfig& oldCfg,
    const PinConfig& newCfg) noexcept {
  auto snapshots = snapshotPods(oldCfg);
  if (!snapshots) {
    return makeUnexpected(snapshots.error());
  }

  auto created = bpfj::libbpf::BpfSkel<replace_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  // The membership being migrated into, adopted from the tree just built.
  if (auto res = pins::pinSharedMaps(skel, newCfg.mapDir()); !res) {
    return makeUnexpected(res.error());
  }

  // And the one being migrated off, under the program's second name for it;
  // both definitions must match or libbpf refuses the adoption.
  if (auto res =
          pins::pinMapAt(skel, kOldTaskMap, oldCfg.mapPath(kTaskMap), {});
      !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = skel.load(); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = heap::init(created.value()); !res) {
    return makeUnexpected(res.error());
  }

  auto pods = copyPods(
      oldCfg, newCfg, *snapshots, ::bpf_map__fd(skel.maps().bpfj_replace_pods));
  if (!pods) {
    return makeUnexpected(pods.error());
  }

  if (auto res = skel.attach(); !res) {
    return makeUnexpected(res.error());
  }

  // Reading to EOF is what runs the iterator over every task; it emits nothing.
  bpfj::libbpf::BpfLink link(skel.links().bpfj_replace_backfill);
  if (auto res = link.iter(); !res) {
    return makeUnexpected(res.error());
  }

  auto failed = readCounter(skel.maps().bpfj_replace_failed, "failure");
  if (!failed) {
    return makeUnexpected(failed.error());
  }

  auto incompatible =
      readCounter(skel.maps().bpfj_replace_incompatible, "incompatible");
  if (!incompatible) {
    return makeUnexpected(incompatible.error());
  }
  if (*incompatible != 0) {
    return makeUnexpected(makeError(
        std::errc::not_supported,
        "backfill found ",
        std::to_string(*incompatible),
        " task-storage entry or entries with an incompatible layout"));
  }

  auto unmapped = readCounter(skel.maps().bpfj_replace_unmapped, "unmapped");
  if (!unmapped) {
    return makeUnexpected(unmapped.error());
  }
  if (*unmapped != 0) {
    return makeUnexpected(makeError(
        std::errc::state_not_recoverable,
        "backfill found ",
        std::to_string(*unmapped),
        " persisted pod reference(s) without a translation"));
  }

  if (*failed != 0) {
    // Swapping now would promote a jailer that silently lost part of the jail,
    // leaving those tasks running unjailed.
    return makeUnexpected(makeError(
        std::errc::not_enough_memory,
        "backfill could not migrate ",
        std::to_string(*failed),
        " task(s)"));
  }

  auto migrated = readCounter(skel.maps().bpfj_replace_migrated, "migrated");
  if (!migrated) {
    return makeUnexpected(migrated.error());
  }

  return BackfillStats{.pods = *pods, .tasks = *migrated};
}

/// @brief Everything between building the new tree and it becoming the live
/// one, so that a failure anywhere in it is one thing to take back.
[[nodiscard]] Expected<ReplaceStats> buildAndSwap(
    const PinConfig& cfg,
    const PinConfig& newCfg,
    const Policy& policy) noexcept {
  std::error_code ec;
  const bool hasOld = fs::exists(fs::path(cfg.root()), ec);
  std::uint32_t bpfOwnerVersion = BPFJ_BPF_OWNER_VERSION;
  std::optional<Fd> generationControl;
  std::uint32_t oldGeneration = 0;

  // Before anything is built, so the only cost of refusing is the parse.
  if (hasOld && hasVersionedOwnerState(cfg)) {
    auto control = pins::openPinnedMap(cfg, kGenerationControl);
    if (!control) {
      return makeUnexpected(makeError(
          std::errc::not_supported,
          "the running jailer predates generation-controlled replacement; "
          "detach and attach to upgrade"));
    }
    generationControl.emplace(std::move(*control));
    auto generation = treeGeneration(cfg);
    if (!generation) {
      return makeUnexpected(generation.error());
    }
    oldGeneration = *generation;
    auto active = readGenerationControl(*generationControl);
    if (!active) {
      return makeUnexpected(active.error());
    }
    if (active->active_generation != oldGeneration) {
      return makeUnexpected(makeError(
          std::errc::state_not_recoverable,
          "the active pin tree is not the enforcing jailer generation"));
    }

    auto versions = readRuntimeVersions(cfg);
    if (!versions) {
      return makeUnexpected(versions.error());
    }
    if (auto res = checkMembershipVersion(cfg, *versions); !res) {
      return makeUnexpected(res.error());
    }
    if (hasPinnedMap(cfg, kMapOwners)) {
      bpfOwnerVersion = (*versions >> BPFJ_BPF_OWNER_VERSION_SHIFT) &
          BPFJ_RUNTIME_VERSION_MASK;
      if (bpfOwnerVersion == 0) {
        auto legacy =
            readLegacyOwnerVersion(cfg, kOwnerVersion, "BPF ownership");
        if (!legacy) {
          return makeUnexpected(legacy.error());
        }
        bpfOwnerVersion = *legacy;
      }
      if (bpfOwnerVersion != 2 && bpfOwnerVersion != BPFJ_BPF_OWNER_VERSION) {
        return makeUnexpected(makeError(
            std::errc::not_supported,
            "the running jailer records BPF ownership in layout v",
            std::to_string(bpfOwnerVersion),
            ", and this build reads v2 or v",
            std::to_string(BPFJ_BPF_OWNER_VERSION),
            "; detach and attach to upgrade"));
      }
    }
    if (auto res = checkOwnerVersion(
            cfg,
            *versions,
            kMqSysvOwners,
            kMqSysvOwnerVersion,
            BPFJ_MQ_OWNER_VERSION_SHIFT,
            BPFJ_MQ_OWNER_VERSION,
            "System V message-queue ownership");
        !res) {
      return makeUnexpected(res.error());
    }
    if (auto res = checkOwnerVersion(
            cfg,
            *versions,
            kMqPosixOwners,
            kMqPosixOwnerVersion,
            BPFJ_MQ_OWNER_VERSION_SHIFT,
            BPFJ_MQ_OWNER_VERSION,
            "POSIX message-queue ownership");
        !res) {
      return makeUnexpected(res.error());
    }
    if (auto res = checkOwnerVersion(
            cfg,
            *versions,
            kShmSysvOwners,
            kShmSysvOwnerVersion,
            BPFJ_SHM_OWNER_VERSION_SHIFT,
            BPFJ_SHM_OWNER_VERSION,
            "System V shared-memory ownership");
        !res) {
      return makeUnexpected(res.error());
    }
    if (auto res = checkOwnerVersion(
            cfg,
            *versions,
            kShmPosixOwners,
            kShmPosixOwnerVersion,
            BPFJ_SHM_OWNER_VERSION_SHIFT,
            BPFJ_SHM_OWNER_VERSION,
            "POSIX shared-memory ownership");
        !res) {
      return makeUnexpected(res.error());
    }
  }

  std::optional<MutationJournal> mutationJournal;
  auto stopJournal = makeGuard([&] {
    if (mutationJournal) {
      disableMutationJournal(*mutationJournal);
    }
  });

  // Destructive, which clears a tree left by a run that died before its swap,
  // and seeds the new base role onto every task before the backfill merges the
  // old membership on top.
  auto scratchMaps = Jailer::load(
      newCfg,
      policy,
      hasOld,
      generationControl ? &*generationControl : nullptr);
  if (!scratchMaps) {
    return makeUnexpected(scratchMaps.error());
  }

  if (auto res = VerityEnforcer::load(newCfg, policy, *scratchMaps); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = ExecEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = KillEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = PtraceEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = ProcEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = LkmEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = MqEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = ShmEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = FsEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = UnixEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = MountEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  // Last, as in `attach`: this one can deny bpf(2), and everything above still
  // needs the syscall to pin its links.
  if (auto res = BpfEnforcer::load(newCfg, policy); !res) {
    return makeUnexpected(res.error());
  }

  ReplaceStats stats;

  if (hasOld) {
    // Earlier mutations are already represented by the source maps. Record
    // only the membership backfill and ownership snapshot leading to cutover,
    // rather than filling the bounded ring while new programs are loaded.
    auto started = startMutationJournal(cfg);
    if (!started) {
      return makeUnexpected(started.error());
    }
    mutationJournal.emplace(std::move(*started));

    // Fork and exec enrollment are mirrored by both attached trees; what can
    // still diverge here is a userspace enrollment through the old pins.
    if (auto res = setReplaceFrozen(cfg, true); !res) {
      return makeUnexpected(res.error());
    }
    auto thaw = makeGuard([&] { (void)setReplaceFrozen(cfg, false); });

    if (auto res = waitForActiveEnrollsToDrain(cfg); !res) {
      return makeUnexpected(res.error());
    }

    auto backfill = backfillTasks(cfg, newCfg);
    if (!backfill) {
      return makeUnexpected(backfill.error());
    }
    stats.pods = backfill->pods;
    stats.tasks = backfill->tasks;

    // Before the unload below, so the new tree's free hook prunes the records
    // for the objects that unload is about to free.
    auto owners = copyBpfOwners(cfg, newCfg, bpfOwnerVersion);
    if (!owners) {
      return makeUnexpected(owners.error());
    }
    stats.owners = *owners;

    auto mqOwners = copyMqOwners(cfg, newCfg);
    if (!mqOwners) {
      return makeUnexpected(mqOwners.error());
    }
    stats.owners += *mqOwners;

    auto shmState = copyShmState(cfg, newCfg);
    if (!shmState) {
      return makeUnexpected(shmState.error());
    }
    stats.owners += *shmState;

    if (auto res = copyPendingOwnership(cfg, newCfg); !res) {
      return makeUnexpected(res.error());
    }

    auto replayMaps = openMutationReplayMaps(newCfg);
    if (!replayMaps) {
      return makeUnexpected(replayMaps.error());
    }
    auto initialEnd = journalEnd(*mutationJournal);
    if (!initialEnd) {
      return makeUnexpected(initialEnd.error());
    }
    if (auto replayed =
            replayMutationJournal(*mutationJournal, *replayMaps, *initialEnd);
        !replayed) {
      return makeUnexpected(replayed.error());
    }

    auto newGeneration = treeGeneration(newCfg);
    if (!newGeneration) {
      return makeUnexpected(newGeneration.error());
    }

    auto cutoverCreated = bpfj::libbpf::BpfSkel<replace_bpf>::create();
    if (!cutoverCreated) {
      return makeUnexpected(cutoverCreated.error());
    }
    auto& cutoverSkel = *cutoverCreated.value();
    if (auto res = pins::pinSharedMaps(cutoverSkel, cfg.mapDir()); !res) {
      return makeUnexpected(res.error());
    }
    if (auto res =
            pins::pinMapAt(cutoverSkel, kOldTaskMap, cfg.mapPath(kTaskMap), {});
        !res) {
      return makeUnexpected(res.error());
    }
    if (auto res = cutoverSkel.load(); !res) {
      return makeUnexpected(res.error());
    }
    if (auto res = heap::init(cutoverCreated.value()); !res) {
      return makeUnexpected(res.error());
    }
    if (auto res = cutoverSkel.attach(); !res) {
      return makeUnexpected(res.error());
    }
    bpfj::libbpf::BpfLink cutoverLink(cutoverSkel.links().bpfj_replace_cutover);
    const int cutoverCommandFd =
        ::bpf_map__fd(cutoverSkel.maps().bpfj_replace_cutover_command);

    // Keep the old generation authoritative across the exchange. Both trees
    // are frozen, and every FD used for replay remains valid after its pin
    // moves, so this only changes which complete tree clients will find.
    if (auto res = exchangePinTrees(cfg, newCfg); !res) {
      return makeUnexpected(res.error());
    }
    bool exchanged = true;
    auto restorePins = makeGuard([&] {
      if (exchanged) {
        (void)exchangePinTrees(cfg, newCfg);
      }
    });

    // Replay without holding the lock, then ask the transient iterator to
    // commit only if the tail is still empty. It takes the journal lock and
    // switches the generation entirely in BPF context, so no userspace holder
    // can be descheduled while ownership mutations wait behind it.
    while (true) {
      auto finalEnd = journalEnd(*mutationJournal);
      if (!finalEnd) {
        return makeUnexpected(finalEnd.error());
      }
      if (auto replayed =
              replayMutationJournal(*mutationJournal, *replayMaps, *finalEnd);
          !replayed) {
        return makeUnexpected(replayed.error());
      }

      const std::uint32_t zero = 0;
      struct bpfj_replace_cutover_command command = {
          .replayed = mutationJournal->replayed,
          .generation = *newGeneration,
          .result = -EINPROGRESS,
      };
      if (::bpf_map_update_elem(cutoverCommandFd, &zero, &command, BPF_ANY) !=
          0) {
        return makeUnexpected(
            makeErrnoError("failed to prepare the replacement cutover"));
      }
      if (auto res = cutoverLink.iter(); !res) {
        return makeUnexpected(res.error());
      }
      if (::bpf_map_lookup_elem(cutoverCommandFd, &zero, &command) != 0) {
        return makeUnexpected(
            makeErrnoError("failed to read the replacement cutover result"));
      }
      if (command.result == 1) {
        break;
      }
      if (command.result == -EBUSY) {
        continue;
      }
      if (command.result < 0) {
        return makeUnexpected(makeError(
            std::error_code(-command.result, std::generic_category()),
            "the replacement cutover iterator failed"));
      }
    }

    exchanged = false;
    restorePins.dismiss();
    disableMutationJournal(*mutationJournal);
    stopJournal.dismiss();
    thaw.dismiss();

    if (auto res = setReplaceFrozen(cfg, false); !res) {
      // The new policy is attached at the active path but remains frozen. Do
      // not exchange it back after ownership has been copied; leave a
      // fail-closed tree for a retry to repair.
      return makeUnexpected(res.error());
    }

    // Through unload(), rather than remove_all(), for the old tree's keyrings.
    if (auto res = Jailer::unload(newCfg); !res) {
      return makeUnexpected(res.error());
    }
  } else {
    // With no prior tree there is nothing to exchange or preserve.
    fs::rename(newCfg.root(), cfg.root(), ec);
    if (ec) {
      return makeUnexpected(
          makeError(ec, "failed to move ", newCfg.root(), " to ", cfg.root()));
    }
  }

  return stats;
}

} // namespace

Expected<ReplaceStats> replaceJailer(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  auto lease = acquireReplaceLease(cfg);
  if (!lease) {
    return makeUnexpected(lease.error());
  }

  PinConfig newCfg = cfg;
  newCfg.pinDir = cfg.pinDir + std::string(kNewSuffix);

  if (auto recovered = recoverInterruptedCutover(cfg, newCfg); !recovered) {
    return makeUnexpected(recovered.error());
  }

  auto res = buildAndSwap(cfg, newCfg, policy);
  if (!res) {
    // The half-built tree is all this created, and unload() takes its keyrings
    // with it; removing only the pins would strand them in the user keyring.
    (void)Jailer::unload(newCfg);
  }

  return res;
}

} // namespace bpfjailer
