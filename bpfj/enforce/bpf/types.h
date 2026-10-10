// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/fsverity/bpf/types_fsverity.h"
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/lib/bpf/types_lock.h"
#include "bpfj/lib/bpf/types_role.h"
#include "bpfj/lib/bpf/types_uuid.h"
#include "bpfj/var/bpf/types_var.h"

// OSS task storage holds arena pointers rather than embedded pods.
#undef BPFJ_MAX_POD_PER_PID
#define BPFJ_MAX_POD_PER_PID BPFJ_OSS_MAX_POD_PER_PID

// The types the open source jailer needs, and nothing else; the internal tree
// keeps its own, much larger one at bpfjailer/enforce/bpf/types.h, and what is
// shared is what this header includes. The pod layout is now OSS-specific: pod
// variables live in the shared arena and the pod carries only arena pointers.

// Sized for long service/tenant identity strings (255 chars plus NUL). Never
// put a bpfj_pod_id on the BPF stack -- even at 64 bytes it pushed the
// internal scan chain past the 512-byte budget.
#define POD_ID_LEN 256

// Versioning
#define BPFJ_PID_DATA_VERSION 4

// The persisted task-storage and arena-pod layouts replaced as one unit.
// Bump this whenever either bpfj_pid_data or bpfj_pod changes shape or
// meaning.
#define BPFJ_MEMBERSHIP_VERSION 3

// The layout of the bpfj_bpf_owner records below, which a replace reads
// through the running tree's pin to decide whether it can carry them across;
// bump it whenever bpfj_bpf_owner changes shape. Pin adoption does not cover
// this: it catches a change of size but not a reordering, and the replace
// copies between two maps rather than adopting one.
#define BPFJ_BPF_OWNER_VERSION 3

// Layout of both message-queue ownership maps. The maps have distinct keys,
// but intentionally share this value and version so replacement can validate
// and carry both atomically.
#define BPFJ_MQ_OWNER_VERSION 2

// Layout of both shared-memory ownership maps and the POSIX mount classifier.
#define BPFJ_SHM_OWNER_VERSION 2

// The one control map intentionally shared by the two trees during replace.
// Mutable enforcement state remains generation-local and is copied instead.
#define BPFJ_GENERATION_CONTROL_VERSION 1

#if BPFJ_BPF_OWNER_VERSION > 255 || BPFJ_MQ_OWNER_VERSION > 255 || \
    BPFJ_SHM_OWNER_VERSION > 255 || BPFJ_MEMBERSHIP_VERSION > 255
#error "arena runtime versions are packed into 8-bit fields"
#endif

#define BPFJ_BPF_OWNER_VERSION_SHIFT 0
#define BPFJ_MQ_OWNER_VERSION_SHIFT 8
#define BPFJ_SHM_OWNER_VERSION_SHIFT 16
#define BPFJ_MEMBERSHIP_VERSION_SHIFT 24
#define BPFJ_RUNTIME_VERSION_MASK 0xffU
#define BPFJ_RUNTIME_VERSIONS                                        \
  (((__u32)BPFJ_BPF_OWNER_VERSION << BPFJ_BPF_OWNER_VERSION_SHIFT) | \
   ((__u32)BPFJ_MQ_OWNER_VERSION << BPFJ_MQ_OWNER_VERSION_SHIFT) |   \
   ((__u32)BPFJ_SHM_OWNER_VERSION << BPFJ_SHM_OWNER_VERSION_SHIFT) | \
   ((__u32)BPFJ_MEMBERSHIP_VERSION << BPFJ_MEMBERSHIP_VERSION_SHIFT))

#define BPFJ_EXEC_POLICY_XATTR "user.bpfj.policy.exec"

// How a pod came to exist, numbered to match the internal tree's.
#define BPFJ_ENROLL_UNKNOWN 0
#define BPFJ_ENROLL_CLIENT 1
#define BPFJ_ENROLL_EXE 2
#define BPFJ_ENROLL_EXE_SCAN 3
#define BPFJ_ENROLL_CGROUP 4
#define BPFJ_ENROLL_CGROUP_SCAN 5
#define BPFJ_ENROLL_XATTR 6
#define BPFJ_ENROLL_DBUS 7
#define BPFJ_ENROLL_FFC_TCP 8
#define BPFJ_ENROLL_FFC_UDS 9
#define BPFJ_ENROLL_BASE_ROLE 10
#define BPFJ_ENROLL_FFC_PTY 11

enum bpfj_event_type {
  BPFJ_EVENT_UNKNOWN = 0,
  BPFJ_EVENT_JAILER = 1,
  BPFJ_EVENT_ENROLL = 2,
  BPFJ_EVENT_VERITY = 3,
  BPFJ_EVENT_KILL = 4,
  BPFJ_EVENT_PTRACE = 5,
  BPFJ_EVENT_BPF = 6,
  BPFJ_EVENT_LKM = 7,
  BPFJ_EVENT_FS = 8,
  BPFJ_EVENT_UNIX = 9,
  BPFJ_EVENT_MOUNT = 10,
  BPFJ_EVENT_PROC = 11,
  BPFJ_EVENT_EXEC = 12,
};

struct bpfj_role_id {
  // null terminated. String role id.
  char id[ROLE_ID_LEN];
};

struct bpfj_generation_control {
  __u32 version;
  __u32 active_generation;
};

enum bpfj_policy_gate {
  BPFJ_POLICY_GATE_BPF = 0,
  BPFJ_POLICY_GATE_KILL = 1,
  BPFJ_POLICY_GATE_PTRACE = 2,
  BPFJ_POLICY_GATE_KEYRING = 3,
  BPFJ_POLICY_GATE_ENROLL = 4,
  BPFJ_POLICY_GATE_MQ_SYSV = 5,
  BPFJ_POLICY_GATE_MQ_POSIX = 6,
  BPFJ_POLICY_GATE_SHM_SYSV = 7,
  BPFJ_POLICY_GATE_SHM_POSIX = 8,
  BPFJ_POLICY_GATE_PROC = 9,
  BPFJ_POLICY_GATE_COUNT = 10,
};

enum bpfj_policy_mode {
  BPFJ_POLICY_DENY = 0,
  BPFJ_POLICY_POD = 1,
  BPFJ_POLICY_ROLES = 2,
  BPFJ_POLICY_ANY = 3,
};

#define BPFJ_POLICY_OVERRIDE_STACKED (1U << 0)
#define BPFJ_POLICY_UNPRIV_ENROLL (1U << 1)
#define BPFJ_POLICY_BPF_UNTRACKED (1U << 2)
#define BPFJ_POLICY_HAS_MIN_SEQ (1U << 3)
#define BPFJ_POLICY_LKM_ANY (1U << 4)
#define BPFJ_POLICY_FS_ANY (1U << 5)
#define BPFJ_POLICY_VERITY_ANY (1U << 6)
#define BPFJ_POLICY_HAS_UMOUNT (1U << 7)
#define BPFJ_POLICY_UMOUNT_ANY (1U << 8)
#define BPFJ_POLICY_EXEC_ANY (1U << 9)
#define BPFJ_POLICY_MOUNT_ANY (1U << 10)

struct bpfj_role_policy;
struct bpfj_glob_map;
struct bpfj_file_matcher;

// A role list used only with BPFJ_POLICY_ROLES. An empty set permits the
// actor's own pod but no additional role. Entries point directly at shared
// policies, avoiding role-name resolution in enforcement paths.
struct bpfj_role_set {
  __u32 count;
  const struct bpfj_role_policy __arena* policies[1];
};

// One role's contiguous accept range in a shared compiled IPC glob matcher.
struct bpfj_ipc_pattern_set {
  const struct bpfj_glob_map __arena* map;
  __u32 first_accept;
  __u32 num_accepts;
};

// Policy shared by every pod carrying one role, with sparse arena allocations
// so memory grows with what was configured rather than the square of roles.
struct bpfj_role_policy {
  struct bpfj_role_id role_id;
  __u32 flags;
  __u32 key_serial;
  __u64 min_seq;
  __u8 bpf_mode;
  __u8 mq_sysv_mode;
  __u8 mq_posix_mode;
  __u8 shm_sysv_mode;
  __u8 shm_posix_mode;
  __u8 kill_mode;
  __u8 ptrace_mode;
  __u8 proc_mode;
  __u8 keyring_mode;
  __u8 enroll_mode;
  const struct bpfj_ipc_pattern_set __arena* mq_posix_patterns;
  const struct bpfj_ipc_pattern_set __arena* shm_posix_patterns;
  struct bpfj_file_matcher __arena* fs_matcher;
  struct bpfj_file_matcher __arena* mount_matcher;
  struct bpfj_file_matcher __arena* unix_path_matcher;
  struct bpfj_glob_map __arena* unix_bind_abstract;
  struct bpfj_glob_map __arena* unix_connect_abstract;
  struct bpfj_glob_map __arena* unix_dgram_abstract;
  struct bpfj_file_matcher __arena* exec_matcher;
  const struct bpfj_role_set __arena* gates[BPFJ_POLICY_GATE_COUNT];
  struct bpfj_file_matcher __arena* umount_matcher;
};

struct bpfj_role_policy_ref {
  const struct bpfj_role_policy __arena* policy;
};

struct bpfj_pod_id {
  // null terminated. String pod id.
  char id[POD_ID_LEN];
};

struct bpfj_pod {
  struct bpfj_role_id role_id;
  struct bpfj_pod_id pod_id;
  struct bpfj_uuid uuid;
  struct bpfj_var_array var_array;

  // Number of processes referencing this pod
  __s64 refs;

  // bpf_ktime_get_ns() at enrollment, so CLOCK_MONOTONIC.
  __s64 creation_time_ns;

  // How many attempts before we decide a pod is stale
  __u16 gc_removal_attempts;
  __u8 enrollment_source;
  const struct bpfj_role_policy __arena* policy;
};

struct bpfj_event {
  enum bpfj_event_type type;
  struct bpfj_pod pod;
  __u32 pid;
  __u32 tid;
  __u64 timestamp_ns;
};

// Which role owns a BPF map or program, keyed in bpfj_bpf_map_owners and
// bpfj_bpf_prog_owners by the object's kernel address. The id cannot be the
// key -- bpf_map_put() zeroes map->id before queueing the work that runs the
// free hook -- so it is carried in the value for userspace instead. Here
// rather than in bpf_enforce.bpf.c because a replace carries these records
// between two trees' maps and so needs the layout from C++ too.
struct bpfj_bpf_owner {
  struct bpfj_role_id role;
  __u32 id;
  struct bpfj_uuid pod;
  const struct bpfj_role_policy __arena* policy;
};

struct bpfj_mq_owner {
  struct bpfj_role_id role;
  struct bpfj_uuid pod;
  const struct bpfj_role_policy __arena* policy;
};

struct bpfj_mq_pending_owner {
  struct bpfj_mq_owner owner;
  __u8 owned;
};

// mqueuefs inode identity. s_dev separates mounts/filesystems and i_ino names
// the queue within one of them; unlike an fd, the pair survives close/open.
struct bpfj_posix_mq_key {
  __u64 dev;
  __u64 ino;
};

struct bpfj_shm_owner {
  struct bpfj_role_id role;
  struct bpfj_uuid pod;
  const struct bpfj_role_policy __arena* policy;
};

struct bpfj_shm_pending_owner {
  struct bpfj_shm_owner owner;
  __u8 owned;
};

struct bpfj_posix_shm_key {
  __u64 dev;
  __u64 ino;
};

// A mount id is unique only within its mount namespace.
struct bpfj_shm_mount_key {
  __u64 namespace_ino;
  __u64 mount_id;
};

#define BPFJ_MUTATION_JOURNAL_CAPACITY 4096U
#define BPFJ_MUTATION_JOURNAL_LEGACY_CAPACITY 65536U

enum bpfj_mutation_journal_state {
  BPFJ_MUTATION_JOURNAL_OFF = 0,
  BPFJ_MUTATION_JOURNAL_RECORDING = 1,
  BPFJ_MUTATION_JOURNAL_CLOSING = 2,
};

enum bpfj_mutation_journal_failure {
  BPFJ_MUTATION_JOURNAL_OK = 0,
  BPFJ_MUTATION_JOURNAL_FULL = 1,
  BPFJ_MUTATION_JOURNAL_CONTENDED = 2,
};

enum bpfj_mutation_domain {
  BPFJ_MUTATION_BPF_MAP_OWNER = 1,
  BPFJ_MUTATION_BPF_PROG_OWNER = 2,
  BPFJ_MUTATION_MQ_SYSV_OWNER = 3,
  BPFJ_MUTATION_MQ_POSIX_OWNER = 4,
  BPFJ_MUTATION_MQ_POSIX_PENDING = 5,
  BPFJ_MUTATION_SHM_SYSV_OWNER = 6,
  BPFJ_MUTATION_SHM_POSIX_OWNER = 7,
  BPFJ_MUTATION_SHM_POSIX_PENDING = 8,
};

enum bpfj_mutation_operation {
  BPFJ_MUTATION_UPSERT = 1,
  BPFJ_MUTATION_DELETE = 2,
};

// Stable ownership data only. Policy pointers are resolved against the new
// arena while replaying the journal.
struct bpfj_mutation_record {
  __u32 committed;
  __u8 domain;
  __u8 operation;
  __u8 owned;
  __u8 reserved;
  __u64 key[2];
  __u32 object_id;
  struct bpfj_role_id role;
  struct bpfj_uuid pod;
};

// A bounded MPSC ring during replacement. The vec is fully reserved before
// RECORDING is published; BPF writers never grow or free its buffer.
struct bpfj_mutation_journal {
  struct bpfj_lock lock;
  __u32 state;
  __u32 failure;
  __u64 next;
  __u64 consumed;
  struct bpfj_vec entries;
};

struct bpfj_replace_cutover_command {
  __u64 replayed;
  __u32 generation;
  __s32 result;
};

struct bpfj_pid_data {
  __s8 version;
  __u8 num_pods;
  __u32 flags; // currently unused
  __u64 reserved; // currently unused
  struct bpfj_pod __arena* pods[BPFJ_MAX_POD_PER_PID];
};

// Binary records emitted by the replace discovery iterator. The fixed header
// is followed by one bpfj_pod_id and then var_count pairs of
// bpfj_replace_var_snapshot plus that variable's payload bytes.
#define BPFJ_REPLACE_SNAPSHOT_MAGIC 0x42504a52U
#define BPFJ_REPLACE_SNAPSHOT_VERSION 2U

struct bpfj_replace_pod_snapshot {
  __u32 magic;
  __u16 version;
  __u8 var_count;
  __u8 enrollment_source;
  __u64 old_pod;
  struct bpfj_role_id role_id;
  struct bpfj_uuid uuid;
  __s64 creation_time_ns;
  __u16 gc_removal_attempts;
  __u8 reserved[6];
};

struct bpfj_replace_var_snapshot {
  __u32 id;
  __u8 type;
  __u8 size;
  __u16 reserved;
};

// Pinned so widening a member is a compile error rather than a silent change
// to the task-storage records shared by every BPF object in the jail.
#ifdef __cplusplus
#define BPFJ_POD_STATIC_ASSERT(condition) static_assert(condition)
#else
#define BPFJ_POD_STATIC_ASSERT(condition) \
  _Static_assert(condition, "pod layout is shared through pinned jail maps")
#endif

BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_var) == 24);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_var_array) == 16);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_pod) == 336);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_pid_data) == 80);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_replace_pod_snapshot) == 64);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_replace_var_snapshot) == 8);

// Same reasoning for the records a replace copies between two trees; a change
// this catches is one BPFJ_BPF_OWNER_VERSION has to be bumped for.
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_bpf_owner) == 48);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_mq_owner) == 40);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_posix_mq_key) == 16);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_shm_owner) == 40);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_posix_shm_key) == 16);
BPFJ_POD_STATIC_ASSERT(sizeof(struct bpfj_shm_mount_key) == 16);

#undef BPFJ_POD_STATIC_ASSERT
