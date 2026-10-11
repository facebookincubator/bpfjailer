// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/Jailer.h"

#include <bpf/bpf.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

// Ahead of the skeleton, in its own block so the formatter keeps it there: the
// generated rodata struct only forward-declares `struct bpfj_uuid`.
#include "bpfj/enforce/ArenaMap.h"
#include "bpfj/enforce/Pods.h"
#include "bpfj/enforce/RoleId.h"

// For unload(), which disarms the fs-verity keyrings before removing the map
// that names them; the one enforcer with state the pin tree does not own.
#include "bpfj/enforce/VerityEnforcer.h"

#include "bpfj/enforce/bpf/jailer.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/lib/StrMap.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/match/bpf/types_mount.h" // @manual

namespace bpfjailer {

namespace {

namespace fs = std::filesystem;

constexpr std::string_view kGenerationControl = "bpfj_generation_control";

/// @brief The encoded base role id, validated in userspace before load so BPF
/// can copy it straight into a prebuilt or fallback-allocated base-role pod.
[[nodiscard]] Expected<struct bpfj_role_id> makeBaseRoleId(
    const std::string& role) noexcept {
  auto roleId = makeRoleId(role);
  if (!roleId) {
    return makeUnexpected(makeError(
        roleId.error().code(), "base-role: ", roleId.error().message()));
  }
  return *roleId;
}

[[nodiscard]] Expected<> initializeMutationJournal(
    const PinConfig& cfg) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }

  auto* ctrl = arena->ctrl();
  if (ctrl->mutation_journal != nullptr) {
    return makeUnexpected(makeError(
        std::errc::file_exists,
        "the arena ownership journal is already initialized"));
  }

  auto journalMem = arena->alloc(sizeof(struct bpfj_mutation_journal));
  if (!journalMem) {
    return makeUnexpected(journalMem.error());
  }
  auto* journal = static_cast<struct bpfj_mutation_journal*>(*journalMem);

  constexpr std::uint32_t kRecordsSize =
      BPFJ_MUTATION_JOURNAL_CAPACITY * sizeof(struct bpfj_mutation_record);
  auto records = arena->alloc(kRecordsSize);
  if (!records) {
    (void)arena->free(journal);
    return makeUnexpected(records.error());
  }

  lock::init(journal->lock);
  journal->state = BPFJ_MUTATION_JOURNAL_OFF;
  journal->failure = BPFJ_MUTATION_JOURNAL_OK;
  journal->next = 0;
  journal->consumed = 0;
  journal->entries.buf = *records;
  journal->entries.elem_size = sizeof(struct bpfj_mutation_record);
  journal->entries.size = 0;
  journal->entries.capacity = BPFJ_MUTATION_JOURNAL_CAPACITY;
  journal->entries._pad = 0;
  ctrl->mutation_journal = journal;
  return unit;
}

/// @brief Build the one pod the base-role seeding walk names on every task.
[[nodiscard]] Expected<std::pair<PodArena, struct bpfj_pod*>> makeBaseRolePod(
    const PinConfig& cfg,
    const struct bpfj_role_id& roleId) noexcept {
  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }

  auto blob = arena->alloc(sizeof(struct bpfj_pod));
  if (!blob) {
    return makeUnexpected(blob.error());
  }

  auto* pod = static_cast<struct bpfj_pod*>(*blob);
  *pod = {};
  pod->role_id = roleId;
  auto policies = readRolePolicies(*arena);
  if (!policies) {
    (void)arena->free(pod);
    return makeUnexpected(policies.error());
  }
  auto rolePolicy = lookupRolePolicy(*policies, roleId);
  if (!rolePolicy || !*rolePolicy) {
    (void)arena->free(pod);
    if (!rolePolicy) {
      return makeUnexpected(rolePolicy.error());
    }
    return makeUnexpected(makeError(
        std::errc::invalid_argument, "base role is missing from policy"));
  }
  pod->policy = *rolePolicy;
  auto uuid = makeUuid4();
  if (!uuid) {
    (void)arena->free(pod);
    return makeUnexpected(uuid.error());
  }
  pod->uuid = *uuid;
  pod->enrollment_source = BPFJ_ENROLL_BASE_ROLE;
  bpfj_var_array_init(&pod->var_array);

  auto nowNs = monotonicNs();
  if (!nowNs) {
    (void)arena->free(pod);
    return makeUnexpected(nowNs.error());
  }
  pod->creation_time_ns = *nowNs;

  return std::pair{std::move(*arena), pod};
}

} // namespace

Expected<ScratchMapFds> Jailer::load(
    const PinConfig& cfg,
    const Policy& policy,
    bool replacementFrozen,
    const Fd* generationControl) noexcept {
  // Before makeTree rather than inside it: the links going is what detaches
  // whatever was running, so removing only the map pins would leave those
  // programs attached to unreachable maps.
  if (auto res = unload(cfg); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = pins::makeTree(cfg); !res) {
    return makeUnexpected(res.error());
  }

  // The selector is the only map shared across replacement generations. All
  // policy, membership and ownership state remains in the generation's tree.
  if (generationControl != nullptr &&
      ::bpf_obj_pin(
          generationControl->get(), cfg.mapPath(kGenerationControl).c_str()) !=
          0) {
    return makeUnexpected(
        makeErrnoError("failed to pin the replacement generation control"));
  }

  using Skel = bpfj::libbpf::BpfSkel<jailer_bpf>;
  auto created = Skel::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  // One path from the binary's own xattr, plus optionally the base role.
  skel.rodata().bpfj_enroll_from_xattr = 1;

  // Before load(), since rodata is frozen there.
  const bool hasBaseRole = !policy.baseRole.empty();
  std::optional<struct bpfj_role_id> baseRoleId;
  if (hasBaseRole) {
    auto parsedBaseRoleId = makeBaseRoleId(policy.baseRole);
    if (!parsedBaseRoleId) {
      return makeUnexpected(parsedBaseRoleId.error());
    }
    baseRoleId = *parsedBaseRoleId;
    skel.rodata().bpfj_base_role_enabled = 1;
    skel.rodata().bpfj_base_role_id = *baseRoleId;
  }

  if (auto res = pins::pinSharedMaps(skel, cfg.mapDir()); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = skel.load(); !res) {
    return makeUnexpected(res.error());
  }

  auto scratchMaps = ScratchMapFds::duplicateFrom(skel);
  if (!scratchMaps) {
    return makeUnexpected(scratchMaps.error());
  }

  if (auto res = heap::init(created.value()); !res) {
    return makeUnexpected(res.error());
  }
  if (auto res = pins::pinProgram(
          skel.progs().bpfj_heap_syscall, cfg, kHeapSyscallProgram);
      !res) {
    return makeUnexpected(res.error());
  }

  auto* const heapControl = skel.bss().bpfj_heap_ctrl;
  if (heapControl->mount_cache == nullptr) {
    heapControl->mount_cache =
        heap::alloc<struct bpfj_mount_cache>(created.value());
    if (heapControl->mount_cache == nullptr) {
      return makeUnexpected(makeError(
          std::errc::not_enough_memory,
          "shared mount cache allocation failed"));
    }
  }

  auto generation = arena::generationForMapExtra(
      reinterpret_cast<std::uintptr_t>(heapControl));
  if (!generation) {
    return makeUnexpected(generation.error());
  }
  heapControl->generation = *generation;

  if (auto res = initializeMutationJournal(cfg); !res) {
    return makeUnexpected(res.error());
  }

  const std::uint32_t generationSlot = 0;
  struct bpfj_generation_control control{};
  const int generationFd = ::bpf_map__fd(skel.maps().bpfj_generation_control);
  if (generationControl != nullptr) {
    if (::bpf_map_lookup_elem(generationFd, &generationSlot, &control) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to read the active jailer generation"));
    }
    if (control.version != BPFJ_GENERATION_CONTROL_VERSION ||
        control.active_generation == 0 ||
        control.active_generation == *generation) {
      return makeUnexpected(makeError(
          std::errc::not_supported,
          "the running jailer has an incompatible generation control"));
    }
  } else {
    control = {
        .version = BPFJ_GENERATION_CONTROL_VERSION,
        .active_generation = *generation,
    };
    if (::bpf_map_update_elem(
            generationFd, &generationSlot, &control, BPF_ANY) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to activate the initial jailer generation"));
    }
  }

  auto policyArena = PodArena::open(cfg);
  if (!policyArena) {
    return makeUnexpected(policyArena.error());
  }
  auto publishedGraph = publishPolicyGraph(*policyArena, policy);
  if (!publishedGraph) {
    return makeUnexpected(publishedGraph.error());
  }

  StrMap<Skel> roleMap(
      created.value(), skel.bss().bpfj_heap_ctrl->role_policies, false);
  if (auto res = roleMap.init(publishedGraph->rolePolicies); !res) {
    return makeUnexpected(res.error());
  }

  auto* varCatalog = static_cast<struct bpfj_var_catalog*>(
      skel.bss().bpfj_heap_ctrl->var_catalog);
  if (varCatalog != nullptr) {
    StrMap<Skel> varMap(created.value(), varCatalog->by_name, false);
    if (auto res = varMap.init(publishedGraph->varNames); !res) {
      return makeUnexpected(res.error());
    }
  }

  if (replacementFrozen) {
    const std::uint32_t zero = 0;
    const std::uint8_t frozen = 1;
    if (::bpf_map_update_elem(
            ::bpf_map__fd(skel.maps().bpfj_replace_frozen),
            &zero,
            &frozen,
            BPF_ANY) != 0) {
      return makeUnexpected(
          makeErrnoError("failed to freeze the replacement jailer"));
    }
  }

  std::optional<PodArena> baseRoleArena;
  struct bpfj_pod* baseRolePod = nullptr;
  auto freeBaseRolePod = makeGuard([&] {
    if (baseRoleArena && baseRolePod) {
      (void)baseRoleArena->free(baseRolePod);
    }
  });
  if (baseRoleId) {
    auto pod = makeBaseRolePod(cfg, *baseRoleId);
    if (!pod) {
      return makeUnexpected(pod.error());
    }
    baseRoleArena = std::move(pod->first);
    baseRolePod = pod->second;
    skel.bss().bpfj_base_role_pod = baseRolePod;
  }

  if (auto res = skel.attach(); !res) {
    return makeUnexpected(res.error());
  }

  // After attach, so anything forked from here on is covered by
  // bpfj_jailer_fork whether or not the walk reaches it. Unpinned, the walk
  // being over once this returns.
  if (hasBaseRole) {
    bpfj::libbpf::BpfLink seed(skel.links().bpfj_jailer_seed_base_role);
    if (auto res = seed.iter(); !res) {
      return makeUnexpected(res.error());
    }
    freeBaseRolePod.dismiss();
  }

  // An attached link that is not pinned dies with this process, and for
  // bpfj_jailer_free that means pods created and never released.
  const auto linkDir = cfg.linkDir();
  if (auto res = pins::pinLink(
          skel.links().bpfj_jailer_fork, "bpfj_jailer_fork", linkDir);
      !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = pins::pinLink(
          skel.links().bpfj_jailer_exec, "bpfj_jailer_exec", linkDir);
      !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = pins::pinLink(
          skel.links().bpfj_jailer_free, "bpfj_jailer_free", linkDir);
      !res) {
    return makeUnexpected(res.error());
  }

  return std::move(*scratchMaps);
}

Expected<> Jailer::unload(const PinConfig& cfg) noexcept {
  if (auto res = pins::checkBpffs(cfg.bpffsPath); !res) {
    return res;
  }

  const fs::path root = cfg.root();

  std::error_code ec;
  if (!fs::exists(root, ec)) {
    return unit;
  }

  // The fs-verity keyrings live in the kernel's keyring subsystem, so
  // removing the pins below would strand them. Disarmed first, the map naming
  // them being one of the pins about to go, and released once they are gone.
  auto serials = VerityEnforcer::disarm(cfg);
  if (!serials) {
    return makeUnexpected(serials.error());
  }

  // Removing a pinned link drops its last reference, detaching the program.
  fs::remove_all(root, ec);

  // Even if the removal failed, disarm() took these out of the map.
  VerityEnforcer::release(*serials);

  if (ec) {
    return makeUnexpected(
        makeError(ec, "failed to remove pin tree ", root.string()));
  }

  return unit;
}

} // namespace bpfjailer
