// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/Pods.h"

#include "bpfj/enforce/ShmEnforcer.h"

#include <bpf/bpf.h>
#include <dirent.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>

#include "bpfj/enforce/bpf/enroll.skel.h"
#include "bpfj/lib/Fd.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/libbpf-cpp/BpfLink.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

namespace {

constexpr std::string_view kTaskMap = "bpfj_task_map";
constexpr std::string_view kReplaceFrozenMap = "bpfj_replace_frozen";
constexpr std::string_view kActiveEnrollsMap = "bpfj_active_enrolls";
// PIDFD_THREAD is the O_EXCL bit, without including conflicting kernel fcntl.
constexpr unsigned int kPidFdThread = O_EXCL;

using pins::openPinnedMap;

struct ActiveEnroll {
  Fd map;
  std::uint32_t pid = 0;
};

struct ResolvedPodVar {
  std::uint32_t id = 0;
  const struct bpfj_var_name* name = nullptr;
  std::string_view value;
};

// Task storage is keyed by pidfd at the syscall boundary; PIDFD_THREAD is
// required when the target is not a thread group leader.
[[nodiscard]] Expected<Fd> openPidFd(
    pid_t pid,
    unsigned int flags = 0) noexcept {
  const int fd = static_cast<int>(::syscall(SYS_pidfd_open, pid, flags));
  if (fd < 0) {
    return makeUnexpected(
        makeErrnoError("failed to open pidfd for pid ", std::to_string(pid)));
  }

  return Fd(fd);
}

[[nodiscard]] Expected<bpfj_uuid> makeUuid4Impl() noexcept {
  bpfj_uuid uuid{};
  if (::getrandom(uuid.uuid, sizeof(uuid.uuid), 0) !=
      static_cast<ssize_t>(sizeof(uuid.uuid))) {
    return makeUnexpected(makeErrnoError("failed to generate a pod uuid"));
  }

  // Version 4, variant 1, matching bpfj_make_uuid4() on the BPF side.
  uuid.uuid[6] = (uuid.uuid[6] & 0x0f) | 0x40;
  uuid.uuid[8] = (uuid.uuid[8] & 0x3f) | 0x80;

  return uuid;
}

[[nodiscard]] Expected<> checkNotFrozen(const PinConfig& cfg) noexcept {
  auto frozen = openPinnedMap(cfg, kReplaceFrozenMap);
  if (!frozen) {
    return makeUnexpected(frozen.error());
  }

  const std::uint32_t slot = 0;
  std::uint8_t value = 0;
  if (::bpf_map_lookup_elem(frozen->get(), &slot, &value) != 0) {
    return makeUnexpected(makeErrnoError(
        "failed to read the replace state from ",
        cfg.mapPath(kReplaceFrozenMap)));
  }

  if (value != 0) {
    return makeUnexpected(makeError(
        std::errc::device_or_resource_busy,
        "jailer replace is in progress; retry the enrollment once it finishes"));
  }

  return unit;
}

[[nodiscard]] Expected<ActiveEnroll> registerActiveEnroll(
    const PinConfig& cfg) noexcept {
  auto active = openPinnedMap(cfg, kActiveEnrollsMap);
  if (!active) {
    return makeUnexpected(active.error());
  }

  const std::uint32_t pid = static_cast<std::uint32_t>(::getpid());
  constexpr std::uint8_t kInFlight = 1;
  if (::bpf_map_update_elem(active->get(), &pid, &kInFlight, BPF_NOEXIST) !=
      0) {
    if (errno == EEXIST) {
      return makeUnexpected(makeError(
          std::errc::device_or_resource_busy,
          "pid ",
          std::to_string(pid),
          " already has an enrollment in flight"));
    }

    return makeUnexpected(makeErrnoError(
        "failed to register an in-flight enrollment for pid ",
        std::to_string(pid)));
  }

  return ActiveEnroll{.map = std::move(*active), .pid = pid};
}

template <std::size_t N>
[[nodiscard]] Expected<>
setId(char (&dst)[N], std::string_view src, std::string_view what) noexcept {
  if (src.size() >= N) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        what,
        " must be at most ",
        std::to_string(N - 1),
        " characters"));
  }

  std::memcpy(dst, src.data(), src.size());
  dst[src.size()] = '\0';

  return unit;
}

/// @brief Add `uuid` to the selected task or tasks through a task iterator
/// loaded, run and thrown away. The target, pod, thread mode and caller are
/// compiled into that object rather than passed through a map, so two
/// enrollments can run at once and the BPF side can drop the caller's in-flight
/// marker before a self-enrollment loses bpf(2).
[[nodiscard]] Expected<std::uint32_t> enrollTasks(
    const PinConfig& cfg,
    pid_t pid,
    struct bpfj_pod* pod,
    Threads threads,
    std::uint32_t callerPid) noexcept {
  auto created = bpfj::libbpf::BpfSkel<enroll_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();

  // Before load(), which is when rodata is frozen.
  skel.rodata().bpfj_enroll_tgid = pid;
  skel.rodata().bpfj_enroll_tid = threads == Threads::SingleThread ? pid : 0;
  skel.rodata().bpfj_enroll_caller_pid = static_cast<pid_t>(callerPid);
  skel.rodata().bpfj_enroll_all_threads = threads == Threads::All ? 1 : 0;
  skel.bss().bpfj_enroll_pod = pod;

  // Adopted from the jailer's pins, so this writes the running jailer's state
  // rather than a private copy.
  if (auto res = pins::pinSharedMaps(skel, cfg.mapDir()); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = skel.load(); !res) {
    return makeUnexpected(res.error());
  }

  if (auto res = heap::init(created.value()); !res) {
    return makeUnexpected(res.error());
  }

  // By hand rather than skel.attach(), so link_info can narrow the walk to one
  // process or one thread.
  auto prog = skel.getProg("bpfj_enroll_threads");
  if (!prog) {
    return makeUnexpected(makeError(
        std::errc::no_such_file_or_directory, "no enroll iterator program"));
  }

  union bpf_iter_link_info linfo{};
  if (threads == Threads::SingleThread) {
    linfo.task.tid = static_cast<__u32>(pid);
  } else {
    linfo.task.pid = static_cast<__u32>(pid);
  }

  LIBBPF_OPTS(bpf_iter_attach_opts, opts);
  opts.link_info = &linfo;
  opts.link_info_len = sizeof(linfo);

  auto link = prog->attachIter(&opts);
  if (!link) {
    return makeUnexpected(link.error());
  }

  // Deliberately unpinned: the walk is over by the time this returns.
  if (auto res = link->iter(); !res) {
    return makeUnexpected(res.error());
  }

  return skel.bss().bpfj_enroll_count;
}

/// @brief Resolve `vars` against `varMap` and write them into `dst`, all of
/// them before any is written, so a request naming one unpublished variable
/// is refused whole.
[[nodiscard]] Expected<std::vector<ResolvedPodVar>> resolveVars(
    std::span<const PodVar> vars,
    const struct bpfj_var_catalog* catalog) noexcept {
  if (vars.size() > BPFJ_OSS_VAR_MAX) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "a pod holds at most ",
        std::to_string(BPFJ_OSS_VAR_MAX),
        " variables, got ",
        std::to_string(vars.size())));
  }

  std::vector<ResolvedPodVar> resolved;
  resolved.reserve(vars.size());
  for (const PodVar& var : vars) {
    auto policyVar = lookupVar(catalog, var.name);
    if (!policyVar) {
      return makeUnexpected(policyVar.error());
    }

    for (const auto& existing : resolved) {
      if (existing.id == policyVar->id) {
        return makeUnexpected(makeError(
            std::errc::invalid_argument,
            "variable ",
            var.name,
            " is set twice"));
      }
    }

    // StrVarParser's cap, restated so an oversized value is named as the
    // problem rather than silently truncated into the pod.
    if (var.value.size() > BPFJ_OSS_VAR_VAL_LEN - 2) {
      return makeUnexpected(makeError(
          std::errc::value_too_large,
          "value of variable ",
          var.name,
          " must be at most ",
          std::to_string(BPFJ_OSS_VAR_VAL_LEN - 2),
          " characters"));
    }

    resolved.push_back(
        ResolvedPodVar{
            .id = policyVar->id,
            .name = policyVar->name,
            .value = var.value,
        });
  }

  return resolved;
}

[[nodiscard]] std::uint32_t podAllocSize(
    std::span<const ResolvedPodVar> vars) noexcept {
  std::uint32_t size = bpfj_var_align_up(sizeof(struct bpfj_pod));
  size += bpfj_var_align_up(sizeof(struct bpfj_var) * vars.size());
  for (const auto& var : vars) {
    size += bpfj_var_align_up(static_cast<__u32>(var.value.size()) + 1);
  }
  return size;
}

[[nodiscard]] Expected<struct bpfj_pod*> makePod(
    PodArena& arena,
    const struct bpfj_role_policy* rolePolicy,
    std::string_view roleId,
    std::string_view podId,
    std::span<const ResolvedPodVar> vars,
    unsigned char source) noexcept {
  auto blob = arena.alloc(podAllocSize(vars));
  if (!blob) {
    return makeUnexpected(blob.error());
  }

  auto* pod = static_cast<struct bpfj_pod*>(*blob);
  *pod = {};
  if (auto res = setId(pod->role_id.id, roleId, "role"); !res) {
    (void)arena.free(*blob);
    return makeUnexpected(res.error());
  }
  pod->policy = rolePolicy;

  if (auto res = setId(pod->pod_id.id, podId, "pod id"); !res) {
    (void)arena.free(*blob);
    return makeUnexpected(res.error());
  }

  auto uuid = makeUuid4Impl();
  if (!uuid) {
    (void)arena.free(*blob);
    return makeUnexpected(uuid.error());
  }
  pod->uuid = *uuid;

  auto now = monotonicNs();
  if (!now) {
    (void)arena.free(*blob);
    return makeUnexpected(now.error());
  }
  pod->creation_time_ns = *now;
  pod->enrollment_source = source;
  bpfj_var_array_init(&pod->var_array);

  if (vars.empty()) {
    return pod;
  }

  auto* staged = reinterpret_cast<struct bpfj_var*>(
      static_cast<unsigned char*>(*blob) +
      bpfj_var_align_up(sizeof(struct bpfj_pod)));
  std::uint32_t valueOff = bpfj_var_align_up(sizeof(struct bpfj_pod)) +
      bpfj_var_align_up(sizeof(struct bpfj_var) * vars.size());
  for (std::size_t i = 0; i < vars.size(); ++i) {
    const auto& var = vars[i];
    staged[i] = {
        .id = var.id,
        .type = BPFJ_VAR_TYPE_STR,
        .size = static_cast<__u8>(var.value.size()),
        .reserved = 0,
        .name = var.name,
        .val = static_cast<unsigned char*>(*blob) + valueOff,
    };

    auto* value = static_cast<unsigned char*>(staged[i].val);
    std::memcpy(value, var.value.data(), var.value.size());
    value[var.value.size()] = '\0';
    valueOff += bpfj_var_align_up(static_cast<__u32>(var.value.size()) + 1);
  }

  pod->var_array.vars = staged;
  pod->var_array.count = static_cast<__u8>(vars.size());
  return pod;
}

/// @brief Read `pid`'s jail membership; an unjailed task reads back as an
/// empty bpfj_pid_data rather than an error.
[[nodiscard]] Expected<bpfj_pid_data>
readPidData(const Fd& taskMap, const Fd& pidFd, pid_t pid) noexcept {
  bpfj_pid_data pidData{};
  const int key = pidFd.get();
  if (::bpf_map_lookup_elem(taskMap.get(), &key, &pidData) == 0) {
    return pidData;
  }

  if (errno != ENOENT) {
    return makeUnexpected(makeErrnoError(
        "failed to read jail membership of pid ", std::to_string(pid)));
  }

  return bpfj_pid_data{.version = BPFJ_PID_DATA_VERSION};
}

/// @brief The thread group ids /proc currently lists.
[[nodiscard]] Expected<std::vector<pid_t>> runningPids() noexcept {
  DIR* dir = ::opendir("/proc");
  if (dir == nullptr) {
    return makeUnexpected(makeErrnoError("failed to open /proc"));
  }

  std::vector<pid_t> pids;
  while (const struct dirent* entry = ::readdir(dir)) {
    // /proc holds one numeric directory per thread group, alongside named
    // entries that are not processes.
    char* end = nullptr;
    const long value = std::strtol(entry->d_name, &end, 10);
    if (end == entry->d_name || *end != '\0' || value <= 0) {
      continue;
    }

    pids.push_back(static_cast<pid_t>(value));
  }

  ::closedir(dir);

  return pids;
}

} // namespace

Expected<bpfj_uuid> makeUuid4() noexcept {
  return makeUuid4Impl();
}

Expected<bpfj_uuid> enrollPod(
    const PinConfig& cfg,
    std::string_view roleId,
    std::string_view podId,
    std::span<const PodVar> vars,
    pid_t pid,
    Threads threads) noexcept {
  auto active = registerActiveEnroll(cfg);
  if (!active) {
    return makeUnexpected(active.error());
  }
  auto release = makeGuard(
      [&] { (void)::bpf_map_delete_elem(active->map.get(), &active->pid); });

  if (auto res = checkNotFrozen(cfg); !res) {
    return makeUnexpected(res.error());
  }

  auto taskMap = openPinnedMap(cfg, kTaskMap);
  if (!taskMap) {
    return makeUnexpected(taskMap.error());
  }

  auto pidFd =
      openPidFd(pid, threads == Threads::SingleThread ? kPidFdThread : 0);
  if (!pidFd) {
    return makeUnexpected(pidFd.error());
  }

  auto pidData = readPidData(*taskMap, *pidFd, pid);
  if (!pidData) {
    return makeUnexpected(pidData.error());
  }

  // Before the pod is created, so a refused enrollment leaves no unreferenced
  // pod behind.
  if (pidData->num_pods >= BPFJ_MAX_POD_PER_PID) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "pid ",
        std::to_string(pid),
        " is already in the maximum of ",
        std::to_string(BPFJ_MAX_POD_PER_PID),
        " pods"));
  }

  auto openedArena = PodArena::open(cfg);
  if (!openedArena) {
    return makeUnexpected(openedArena.error());
  }
  auto arena = std::move(*openedArena);

  std::vector<ResolvedPodVar> resolved;
  if (!vars.empty()) {
    auto catalog = readVarCatalog(arena);
    if (!catalog) {
      return makeUnexpected(catalog.error());
    }

    auto read = resolveVars(vars, *catalog);
    if (!read) {
      return makeUnexpected(read.error());
    }
    resolved = std::move(*read);
  }

  auto policies = readRolePolicies(arena);
  if (!policies) {
    return makeUnexpected(policies.error());
  }
  auto rolePolicy = lookupRolePolicy(*policies, roleId);
  if (!rolePolicy) {
    return makeUnexpected(rolePolicy.error());
  }
  if (!*rolePolicy) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "role ",
        roleId,
        " is not in the running policy"));
  }

  auto pod = makePod(
      arena,
      *rolePolicy,
      roleId,
      podId,
      resolved,
      static_cast<unsigned char>(BPFJ_ENROLL_CLIENT));
  if (!pod) {
    return makeUnexpected(pod.error());
  }

  // The iterator takes one reference per task it enrolls and leaves the pod
  // owned by nobody if it reaches none.
  (*pod)->refs = 0;

  // Publish the target's /dev/shm mount before it acquires the role. This is
  // a no-op when the SHM enforcer is not attached.
  if (auto res = registerPosixShmMount(cfg, pid); !res) {
    (void)arena.free(*pod);
    return makeUnexpected(res.error());
  }

  auto enrolled = enrollTasks(
      cfg, pid, *pod, threads, static_cast<std::uint32_t>(::getpid()));
  if (!enrolled) {
    (void)arena.free(*pod);
    return makeUnexpected(enrolled.error());
  }

  if (*enrolled == 0) {
    (void)arena.free(*pod);
    return makeUnexpected(makeError(
        std::errc::no_such_process,
        "no task of pid ",
        std::to_string(pid),
        " could be enrolled"));
  }

  release.dismiss();
  return (*pod)->uuid;
}

Expected<std::vector<bpfj_pod>> listPods(
    const PinConfig& cfg,
    pid_t pid) noexcept {
  auto taskMap = openPinnedMap(cfg, kTaskMap);
  if (!taskMap) {
    return makeUnexpected(taskMap.error());
  }

  auto pidFd = openPidFd(pid);
  if (!pidFd) {
    return makeUnexpected(pidFd.error());
  }

  auto pidData = readPidData(*taskMap, *pidFd, pid);
  if (!pidData) {
    return makeUnexpected(pidData.error());
  }

  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }

  // Clamped, since num_pods comes from a map BPF writes concurrently and
  // nothing else bounds the read of the pod pointer array.
  const std::uint8_t count =
      std::min<std::uint8_t>(pidData->num_pods, BPFJ_MAX_POD_PER_PID);

  std::vector<bpfj_pod> pods;
  pods.reserve(count);
  for (std::uint8_t i = 0; i < count; ++i) {
    const auto* pod = pidData->pods[i];
    if (pod == nullptr) {
      continue;
    }
    pods.push_back(*pod);
  }

  return pods;
}

Expected<std::vector<PodMembers>> listAllPods(const PinConfig& cfg) noexcept {
  auto taskMap = openPinnedMap(cfg, kTaskMap);
  if (!taskMap) {
    return makeUnexpected(taskMap.error());
  }

  auto arena = PodArena::open(cfg);
  if (!arena) {
    return makeUnexpected(arena.error());
  }

  std::vector<PodMembers> members;
  std::map<std::uintptr_t, std::size_t> index;

  auto pids = runningPids();
  if (!pids) {
    return makeUnexpected(pids.error());
  }

  for (const pid_t pid : *pids) {
    auto pidFd = openPidFd(pid);
    if (!pidFd) {
      // Exited between /proc and here, which contributes nothing either way.
      continue;
    }

    auto pidData = readPidData(*taskMap, *pidFd, pid);
    if (!pidData) {
      continue;
    }

    const std::uint8_t count =
        std::min<std::uint8_t>(pidData->num_pods, BPFJ_MAX_POD_PER_PID);
    for (std::uint8_t i = 0; i < count; ++i) {
      const auto* pod = pidData->pods[i];
      if (pod == nullptr) {
        continue;
      }

      const auto key = reinterpret_cast<std::uintptr_t>(pod);
      auto [entry, inserted] = index.emplace(key, members.size());
      if (inserted) {
        members.push_back(PodMembers{.pod = *pod, .pids = {}});
      }
      members[entry->second].pids.push_back(pid);
    }
  }

  // /proc order means nothing and changes between runs. Oldest first is stable.
  std::sort(
      members.begin(), members.end(), [](const auto& lhs, const auto& rhs) {
        if (lhs.pod.creation_time_ns != rhs.pod.creation_time_ns) {
          return lhs.pod.creation_time_ns < rhs.pod.creation_time_ns;
        }
        return std::memcmp(
                   lhs.pod.uuid.uuid,
                   rhs.pod.uuid.uuid,
                   sizeof(lhs.pod.uuid.uuid)) < 0;
      });

  return members;
}

std::string uuidToString(const bpfj_uuid& uuid) noexcept {
  static constexpr char kHex[] = "0123456789abcdef";

  std::string out;
  out.reserve(POD_UUID_LEN - 1);
  for (std::size_t i = 0; i < BPFJ_UUID_BYTES; ++i) {
    if (i == 4 || i == 6 || i == 8 || i == 10) {
      out.push_back('-');
    }

    out.push_back(kHex[uuid.uuid[i] >> 4]);
    out.push_back(kHex[uuid.uuid[i] & 0x0f]);
  }

  return out;
}

Expected<std::int64_t> monotonicNs() noexcept {
  struct timespec ts{};
  if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return makeUnexpected(makeErrnoError("failed to read CLOCK_MONOTONIC"));
  }

  return static_cast<std::int64_t>(ts.tv_sec) * 1'000'000'000 + ts.tv_nsec;
}

} // namespace bpfjailer
