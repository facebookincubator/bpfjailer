// Copyright (c) Meta Platforms, Inc. and affiliates.

// The open source jailer: a jailed task's pods are inherited by its children,
// a binary carrying the policy xattr enrolls itself on exec, and pods live as
// long as some task names them. The rest -- cgroup and exe-path enrollment,
// pod GC, Fork-follows-Connect taint -- is still in
// bpfjailer/enforce/bpf/jailer.bpf.c, ported a feature at a time.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/lib/bpf/scratch.h"
#include "bpfj/lib/bpf/uuid.h"

#define PF_KTHREAD 0x00200000 /* Kernel thread */

extern int bpf_get_file_xattr(struct file*, const char*, struct bpf_dynptr*)
    __weak __ksym;

volatile const unsigned char bpfj_enroll_from_xattr = 0;

// The base role's id, published through rodata, and an optional userspace-made
// pod the seeding iterator can point every task at.
volatile const unsigned char bpfj_base_role_enabled = 0;
volatile const struct bpfj_role_id bpfj_base_role_id;
struct bpfj_pod __arena* bpfj_base_role_pod;

_Static_assert(
    BPFJ_MAX_POD_PER_PID <= 8,
    "the rollback masks below are a single byte");

// The trailing `lsm_ret` is the verdict the hook has collected so far;
// ignoring it would turn another module's denial into an allow. It only is the
// return value at the hook's real arity, so every argument ahead of it has to
// be declared even where it is unused.
SEC("lsm.s/task_alloc")
int BPF_PROG(
    bpfj_jailer_fork,
    struct task_struct* child,
    unsigned long clone_flags,
    int lsm_ret) {
  if (lsm_ret) {
    // The clone is being refused, so there is no child to put in a pod.
    return lsm_ret;
  }

  // Threads are cloned like any other task, each carrying its own entry.
  (void)clone_flags;

  struct task_struct* parent = bpf_get_current_task_btf();

  struct bpfj_pid_data* pid_data = bpfj_get_task_pid_data(parent);
  if (!pid_data) {
    // Parent isn't jailed, so the child isn't either.
    return 0;
  }

  if (bpfj_replacement_is_frozen()) {
    BPFJ_LOG_ERR(EBUSY, "Fork blocked while replacing the jailer");
    return -EBUSY;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  // Taken now because creating the child's entry can invalidate the parent's
  // map value pointer, which the rollback below still needs.
  struct bpfj_pod __arena* pods[BPFJ_MAX_POD_PER_PID];
  __builtin_memcpy(pods, pid_data->pods, sizeof(pods));

  // Before the child's entry exists, or the parent could exit in between and
  // free a pod the child names.
  __u8 incremented = 0;
  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    struct bpfj_pod __arena* pod = pods[i];
    if (!pod) {
      BPFJ_LOG_ERR(
          ENOENT, "Pod %d named by pid %d is missing on fork", i, parent->tgid);
      continue;
    }

    bpfj_pod_refs_inc(pod);
    incremented |= (__u8)(1 << i);
  }

  // Seeding with the parent's value is the clone.
  struct bpfj_pid_data* child_pid_data =
      bpfj_set_pid_data_in(&bpfj_task_map, child, pid_data);
  if (!child_pid_data) {
    // Release only what this call took, so a failed clone is reference
    // neutral; a leak here pins the pod for the life of the host.
    for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
      if (!(incremented & (__u8)(1 << i))) {
        continue;
      }

      struct bpfj_pod __arena* pod = pods[i];
      if (pod) {
        bpfj_pod_refs_dec(pod);
      }
    }

    // Allow the fork rather than deny it, as the internal jailer does.
    BPFJ_LOG_ERR(
        ENOMEM, "Failed to clone pod data on fork for pid %d", parent->tgid);
  } else {
    struct bpfj_event* ev = bpfj_event_reserve(
        BPFJ_EVENT_JAILER, bpfj_get_primary_pod(pid_data), child);
    bpfj_event_submit(ev);
  }

  return 0;
}

SEC("lsm.s/bprm_creds_from_file")
int BPF_PROG(
    bpfj_jailer_exec,
    struct linux_binprm* bprm,
    struct file* file,
    int lsm_ret) {
  if (lsm_ret) {
    // The exec is being refused, so there is nothing to enroll.
    return lsm_ret;
  }

  if (!bpfj_generation_is_active()) {
    return 0;
  }

  if (!bpfj_enroll_from_xattr) {
    return 0;
  }

  BPFJ_SCRATCH_GUARD(struct bpfj_role_id, role_id);
  if (!role_id) {
    BPFJ_LOG_ERR(ENOMEM, "No scratch slot to read an xattr role id");
    return -ENOMEM;
  }

  struct bpf_dynptr role_id_ptr;
  bpf_dynptr_from_mem(role_id, sizeof(*role_id), 0, &role_id_ptr);
  if (bpf_get_file_xattr(file, BPFJ_EXEC_POLICY_XATTR, &role_id_ptr) < 0) {
    // No policy xattr, so this binary does not enroll.
    return 0;
  }

  // A replace snapshots every old-arena pod before backfilling task storage.
  // Refuse an exec that would allocate a new pod between those two operations;
  // allowing the binary through without its xattr role would be a bypass.
  if (bpfj_replacement_is_frozen()) {
    BPFJ_LOG_ERR(EBUSY, "Exec enrollment blocked while replacing the jailer");
    return -EBUSY;
  }

  const struct bpfj_role_policy __arena* policy = bpfj_policy_lookup(role_id);
  if (!policy) {
    BPFJ_LOG_ERR(EINVAL, "Role id %s from xattr is not in policy", role_id->id);
    return -EINVAL;
  }

  if (!bpfj_gate_enroll_allowed(bpfj_get_current_pid_data(), policy)) {
    BPFJ_LOG_ERR(EACCES, "Current roles forbid xattr enrollment into %s",
                 role_id->id);
    return -EACCES;
  }

  // Only binaries that actually carry the xattr need a pod allocation.
  BPFJ_HEAP_ALLOC_GUARD(struct bpfj_pod, pod);
  if (!pod) {
    // Denied, not allowed through. Every check after this reads the roles on
    // the task, so a binary that failed to pick up the role its xattr names
    // runs without that role's restrictions and without its signature
    // requirement -- which is the bypass the xattr exists to close. The pool
    // is finite where the per-CPU array it replaced was not, so this is
    // reachable, and sizing it is the other half of the answer.
    BPFJ_LOG_ERR(ENOMEM, "No scratch slot to enroll from xattr, denying exec");
    return -ENOMEM;
  }

  __builtin_memset(pod, 0, sizeof(*pod));
  pod->var_array.count = 0;
  pod->var_array.vars = NULL;
  __builtin_memcpy(&pod->role_id, role_id, sizeof(pod->role_id));
  pod->policy = policy;

  struct bpfj_uuid uuid = {};
  bpfj_make_uuid4(&uuid);
  __builtin_memcpy(&pod->uuid, &uuid, sizeof(pod->uuid));
  pod->enrollment_source = BPFJ_ENROLL_XATTR;
  pod->refs = 1;
  pod->creation_time_ns = bpf_ktime_get_ns();

  // Only the calling thread, de_thread being about to kill the others.
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data =
      bpfj_set_pid_data_in(&bpfj_task_map, task, NULL);
  if (!pid_data) {
    BPFJ_LOG_ERR(
        ENOMEM, "Failed to get pid data to enroll from xattr, denying exec");
    return -ENOMEM;
  }

  // The pod holds one reference for this entry, so a refusal takes it too.
  if (!bpfj_pid_data_add_pod(pid_data, pod)) {
    BPFJ_LOG_ERR(E2BIG, "Too many pods to enroll from xattr, denying exec");
    return -E2BIG;
  }
  pod_heap_guard = NULL;

  BPFJ_LOG("Enrolled role id %s from xattr", role_id->id);
  struct bpfj_event* ev = bpfj_event_reserve(BPFJ_EVENT_JAILER, pod, task);
  bpfj_event_submit(ev);

  return 0;
}

// Put every process already running into the base role's pod, the enrollment
// hooks only seeing a process at fork or exec. Driven from userspace right
// after attach, and anything forked later inherits through bpfj_jailer_fork.
//
// Sleepable, because seeding allocates task storage: a non-sleepable iterator
// allocates under kmalloc_nolock and can fail on trylock contention alone,
// silently leaving a process out of the base role.
SEC("iter.s/task")
int bpfj_jailer_seed_base_role(struct bpf_iter__task* ctx) {
  struct task_struct* task = ctx->task;
  if (!task) {
    // The final call of the walk carries no task.
    return 0;
  }

  if (!bpfj_base_role_enabled) {
    return 0;
  }

  // Threads included, each being checked against its own entry, but not kernel
  // threads: they mostly never exit, so they would hold references forever.
  if (task->flags & PF_KTHREAD) {
    return 0;
  }

  if (bpfj_heap_enabled) {
    bpfj_heap_use_arena();
  }

  // Before the task entry is created, so a missing pod leaves no empty entry
  // behind on an unjailed task.
  struct bpfj_pod __arena* pod = bpfj_base_role_pod;
  if (!pod) {
    BPFJ_HEAP_ALLOC_GUARD(struct bpfj_pod, new_pod);
    if (!new_pod) {
      BPFJ_LOG_ERR(
          ENOMEM, "Base role skipped for pid %d: no pod memory", task->tgid);
      return 0;
    }

    __builtin_memset(new_pod, 0, sizeof(*new_pod));
    struct bpfj_role_id role_id = {};
    __builtin_memcpy(
        &role_id, (const void*)&bpfj_base_role_id, sizeof(role_id));
    __builtin_memcpy(&new_pod->role_id, &role_id, sizeof(new_pod->role_id));
    new_pod->policy = bpfj_policy_lookup(&role_id);
    if (!new_pod->policy) {
      return 0;
    }
    struct bpfj_uuid uuid = {};
    bpfj_make_uuid4(&uuid);
    __builtin_memcpy(&new_pod->uuid, &uuid, sizeof(new_pod->uuid));
    new_pod->enrollment_source = BPFJ_ENROLL_BASE_ROLE;
    new_pod->creation_time_ns = bpf_ktime_get_ns();
    new_pod->var_array.count = 0;
    new_pod->var_array.vars = NULL;

    bpfj_base_role_pod = new_pod;
    new_pod_heap_guard = NULL;
    pod = new_pod;
  }
  if (!pod) {
    BPFJ_LOG_ERR(
        ENOENT, "Base role skipped for pid %d: pod missing", task->tgid);
    return 0;
  }

  struct bpfj_pid_data* pid_data =
      bpfj_set_pid_data_in(&bpfj_task_map, task, NULL);
  if (!pid_data) {
    BPFJ_LOG_ERR(
        ENOMEM, "Base role skipped for pid %d: no task storage", task->tgid);
    return 0;
  }

  // Already named, or no room for another. Either way nothing is owed.
  if (!bpfj_pid_data_add_pod(pid_data, pod)) {
    return 0;
  }

  bpfj_pod_refs_inc(pod);
  struct bpfj_event* ev = bpfj_event_reserve(BPFJ_EVENT_JAILER, pod, task);
  bpfj_event_submit(ev);

  return 0;
}

// Where a pod's last reference goes back. Non-sleepable, everything here being
// a read, an atomic and a delete rather than a task-storage allocation.
SEC("lsm/task_free")
int BPF_PROG(bpfj_jailer_free, struct task_struct* task) {
  struct bpfj_pid_data* pid_data = bpfj_get_task_pid_data(task);
  if (!pid_data) {
    // Not jailed, so it owns nothing.
    return 0;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  struct bpfj_pod __arena* pods[BPFJ_MAX_POD_PER_PID];
  __builtin_memcpy(pods, pid_data->pods, sizeof(pods));

  // The entry goes first, so nothing observes a task still naming pods whose
  // references are already dropped.
  bpf_task_storage_delete(&bpfj_task_map, task);

  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    struct bpfj_pod __arena* pod = pods[i];
    if (!pod) {
      BPFJ_LOG_ERR(
          ENOENT, "Pod %d named by pid %d is missing on exit", i, task->tgid);
      continue;
    }

    bpfj_pod_refs_dec(pod);
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
