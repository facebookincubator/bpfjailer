// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/types.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bpfj/enforce/Jailer.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/err/Error.h"

// report_event's union holds an anonymous struct, ordinary C11 but an
// extension in ISO C++; RoleId.h silences it the same way.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#include "bpfj/enforce/bpf/types.h"
#pragma GCC diagnostic pop

namespace bpfjailer {

/// @brief Which tasks of the target an enrollment has to reach.
enum class Threads {
  /// @brief The thread group leader alone, written through its pidfd, for a
  /// caller enrolling itself immediately before an exec -- de_thread() is
  /// about to destroy the other threads.
  LeaderOnly,

  /// @brief One thread named by its tid, using PIDFD_THREAD and a task
  /// iterator narrowed to that tid.
  SingleThread,

  /// @brief Every thread of the process, through the jailer's enroll
  /// iterator, for a process already running: each thread is checked against
  /// its own task entry, and pidfd_open() only accepts a leader.
  All,
};

/// @brief Put `pid` in a new pod named by `roleId` and `podId`, through the
/// pinned maps rather than loading anything. `roleId` must exist in the
/// running policy, and each of the at most BPFJ_OSS_VAR_MAX `vars` must be one
/// that policy declares; attach publishes both lookups in the arena.
/// @return The uuid of the pod that was created.
[[nodiscard]] Expected<bpfj_uuid> enrollPod(
    const PinConfig& cfg,
    std::string_view roleId,
    std::string_view podId,
    std::span<const PodVar> vars,
    pid_t pid,
    Threads threads) noexcept;

/// @brief The pods `pid` belongs to; empty for an unjailed task, which is not
/// an error.
[[nodiscard]] Expected<std::vector<bpfj_pod>> listPods(
    const PinConfig& cfg,
    pid_t pid) noexcept;

/// @brief A pod and the running processes enrolled in it.
struct PodMembers {
  bpfj_pod pod;
  std::vector<pid_t> pids;
};

/// @brief Every pod the jailer holds, each with the pids enrolled in it,
/// oldest first. Membership is stored task -> pods and task storage cannot be
/// enumerated from userspace, so the reverse is reconstructed by walking
/// /proc and deduplicating the pod pointers found there.
[[nodiscard]] Expected<std::vector<PodMembers>> listAllPods(
    const PinConfig& cfg) noexcept;

/// @brief A pod uuid as the canonical 8-4-4-4-12 hex string.
[[nodiscard]] std::string uuidToString(const bpfj_uuid& uuid) noexcept;

/// @brief A random version 4 uuid, matching the BPF-side pod stamps.
[[nodiscard]] Expected<bpfj_uuid> makeUuid4() noexcept;

/// @brief The clock bpfj_pod::creation_time_ns is measured against, the
/// jailer stamping a pod with bpf_ktime_get_ns().
[[nodiscard]] Expected<std::int64_t> monotonicNs() noexcept;

} // namespace bpfjailer
