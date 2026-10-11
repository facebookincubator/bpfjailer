// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types_mount_enforce.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/lib/bpf/scratch.h"
#include "bpfj/match/bpf/file_match_cached.h"
#include "bpfj/match/bpf/glob_var_bindings.h"

#define MS_REMOUNT 32
#define MS_MOVE 8192
#define BPFJ_REMOUNT_RELAY_NS (100ULL * 1000 * 1000)

struct bpfj_mount_cache __arena* bpfj_mount_cache;

struct bpfj_remount_relay {
  __u64 sb;
  __u64 root;
  __u64 type;
  __u64 dev;
  __u64 magic;
  __u64 when;
};

struct bpfj_mount_scratch {
  struct bpfj_role_id role;
  struct bpfj_uuid uuid;
  char type[BPFJ_MOUNT_FS_TYPE_LEN];
  bool has_type;
};

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);
  __type(value, struct bpfj_remount_relay);
} bpfj_remount_relays SEC(".maps");

static __noinline int bpfj_mount_deny(
    struct bpfj_pod __arena* pod,
    struct task_struct* task,
    const struct bpfj_role_id* role,
    const char* operation) {
  struct bpfj_event* event = bpfj_event_reserve(BPFJ_EVENT_MOUNT, pod, task);
  bpfj_event_submit(event);
  BPFJ_LOG("Denied %s for role %s", operation, role->id);
  return -EACCES;
}

// Keep scratch-pool iteration out of the already-deep path matcher call
// chain. The claimed slot remains live in the caller until its cleanup runs.
static __noinline struct bpfj_mount_scratch* bpfj_mount_scratch_claim(
    __u32* slot) {
  return bpfj_scratch_alloc(sizeof(struct bpfj_mount_scratch), slot);
}

// GLOBAL function: select the best mount rule independently while returning
// only its scalar index to the caller.
__noinline long bpfj_mount_best_match(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    long count) {
  __s32 best_pos = -1;
  __u8 best_specificity = 0;
  long best_index = -1;
  __u32 i;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }
    struct bpfj_mount_path_entry* entry =
        BPFJ_FILE_MATCH_CACHED_LOOKUP(state, i);
    if (!entry) {
      continue;
    }
    const __s32 pos = BPFJ_FILE_MATCH_CACHED_GET_POS(state, i);
    if (pos > best_pos ||
        (pos == best_pos && entry->specificity > best_specificity) ||
        (pos == best_pos && entry->specificity == best_specificity &&
         !entry->types)) {
      best_pos = pos;
      best_specificity = entry->specificity;
      best_index = i;
    }
  }
  return best_index;
}

static __always_inline bool bpfj_mount_match_allowed(
    struct bpfj_file_match_cached_state __arena* state,
    long count,
    struct bpfj_mount_scratch* scratch) {
  const long best_index = bpfj_mount_best_match(state, count);
  if (best_index < 0) {
    return false;
  }
  struct bpfj_mount_path_entry* best =
      BPFJ_FILE_MATCH_CACHED_LOOKUP(state, best_index);
  if (best == NULL) {
    return false;
  }
  if (best->any_type) {
    return true;
  }
  if (!best->types || !scratch->has_type) {
    return false;
  }

  void __arena* found = NULL;
  return bpfj_str_map_lookup_strlen(
             best->types, scratch->type, sizeof(scratch->type), &found) == 0;
}

static __noinline bool bpfj_umount_match_allowed(
    struct bpfj_file_match_cached_state __arena* state,
    long count) {
  __s32 best_pos = -1;
  __u8 best_specificity = 0;
  struct bpfj_umount_path_entry* best = NULL;
  __u32 i;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }
    struct bpfj_umount_path_entry* entry =
        BPFJ_FILE_MATCH_CACHED_LOOKUP(state, i);
    if (!entry) {
      continue;
    }
    const __s32 pos = BPFJ_FILE_MATCH_CACHED_GET_POS(state, i);
    if (pos > best_pos ||
        (pos == best_pos && entry->specificity > best_specificity) ||
        (pos == best_pos && entry->specificity == best_specificity &&
         !entry->allowed)) {
      best_pos = pos;
      best_specificity = entry->specificity;
      best = entry;
    }
  }
  return best && best->allowed;
}

static __always_inline int bpfj_mount_enforce_path(
    uintptr_t dentry,
    uintptr_t type) {
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data || !dentry) {
    return 0;
  }

  __attribute__((cleanup(bpfj_scratch_release))) __u32 scratch_guard =
      BPFJ_SCRATCH_NONE;
  struct bpfj_mount_scratch* scratch = bpfj_mount_scratch_claim(&scratch_guard);
  if (!scratch) {
    return -EACCES;
  }
  __builtin_memset(scratch->type, 0, sizeof(scratch->type));
  scratch->has_type = type &&
      bpf_probe_read_kernel_str(
          scratch->type, sizeof(scratch->type), (const void*)type) > 0;

  BPFJ_FILE_MATCH_CACHED_ALLOC(state);
  if (!state) {
    return -EACCES;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    bpfj_pod_read_role_id(&scratch->role, pod);
    bpfj_pod_read_uuid(&scratch->uuid, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy) {
      return bpfj_mount_deny(pod, task, &scratch->role, "mount");
    }
    if (policy->flags & BPFJ_POLICY_MOUNT_ANY) {
      if (bpfj_is_override(pod)) {
        break;
      }
      continue;
    }
    struct bpfj_file_matcher __arena* matcher = policy->mount_matcher;
    if (!matcher) {
      return bpfj_mount_deny(pod, task, &scratch->role, "mount");
    }
    const long count = BPFJ_FILE_MATCH_CACHED(
        state,
        matcher,
        bpfj_mount_cache,
        dentry,
        &scratch->uuid,
        bpfj_file_match_cached_bind_var_array,
        &pod->var_array);
    if (count == -EXDEV) {
      if (bpfj_is_override(pod)) {
        break;
      }
      continue;
    }
    if (count < 0) {
      if (count != -E2BIG) {
        BPFJ_LOG_ERR(-count, "mount destination path match failed");
      }
      return bpfj_mount_deny(pod, task, &scratch->role, "mount");
    }
    if (count == 0 || !bpfj_mount_match_allowed(state, count, scratch)) {
      return bpfj_mount_deny(pod, task, &scratch->role, "mount");
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

static __always_inline int bpfj_mount_enforce_any(
    __u32 flag,
    const char* operation) {
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data) {
    return 0;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    struct bpfj_role_id role = {};
    bpfj_pod_read_role_id(&role, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy || !(policy->flags & flag)) {
      return bpfj_mount_deny(pod, task, &role, operation);
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

enum bpfj_umount_operation {
  BPFJ_UMOUNT_OPERATION_UMOUNT,
  BPFJ_UMOUNT_OPERATION_MOVE,
  BPFJ_UMOUNT_OPERATION_PIVOT,
};

static __always_inline int bpfj_mount_enforce_umount_path(
    uintptr_t dentry,
    enum bpfj_umount_operation operation_id) {
  if (!dentry) {
    return 0;
  }
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data) {
    return 0;
  }

  __attribute__((cleanup(bpfj_scratch_release))) __u32 scratch_guard =
      BPFJ_SCRATCH_NONE;
  struct bpfj_mount_scratch* scratch = bpfj_mount_scratch_claim(&scratch_guard);
  if (!scratch) {
    return -EACCES;
  }
  const char* operation = operation_id == BPFJ_UMOUNT_OPERATION_MOVE
      ? "move mount source"
      : operation_id == BPFJ_UMOUNT_OPERATION_PIVOT ? "pivot old root"
                                                    : "umount";
  BPFJ_FILE_MATCH_CACHED_ALLOC(state);
  if (!state) {
    return -EACCES;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    bpfj_pod_read_role_id(&scratch->role, pod);
    bpfj_pod_read_uuid(&scratch->uuid, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy) {
      return bpfj_mount_deny(pod, task, &scratch->role, operation);
    }
    if (policy->flags & BPFJ_POLICY_UMOUNT_ANY) {
      if (bpfj_is_override(pod)) {
        break;
      }
      continue;
    }
    struct bpfj_file_matcher __arena* matcher = policy->umount_matcher;
    if (!matcher) {
      return bpfj_mount_deny(pod, task, &scratch->role, operation);
    }
    const long count = BPFJ_FILE_MATCH_CACHED(
        state,
        matcher,
        bpfj_mount_cache,
        dentry,
        &scratch->uuid,
        bpfj_file_match_cached_bind_var_array,
        &pod->var_array);
    if (count == -EXDEV) {
      if (bpfj_is_override(pod)) {
        break;
      }
      continue;
    }
    if (count < 0) {
      if (count != -E2BIG) {
        BPFJ_LOG_ERR(-count, "umount path match failed");
      }
      return bpfj_mount_deny(pod, task, &scratch->role, operation);
    }
    if (count == 0 || !bpfj_umount_match_allowed(state, count)) {
      return bpfj_mount_deny(pod, task, &scratch->role, operation);
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

static __always_inline const char* bpfj_mount_path_type(
    const struct path* path) {
  if (!path) {
    return NULL;
  }
  return bpf_core_cast((path), typeof(*(path)))->mnt->mnt_sb->s_type->name;
}

// A remount path names the mounted root. Match the covered mountpoint instead,
// which is the destination the policy author wrote and remains visible in the
// host mount snapshot used by file_match_cached.
static __always_inline struct dentry* bpfj_mountpoint(
    struct vfsmount* vfsmount,
    struct dentry* fallback) {
  if (!vfsmount) {
    return NULL;
  }
  const long offset = bpf_core_field_offset(struct mount, mnt);
  struct mount* mount = bpf_core_cast((void*)vfsmount - offset, struct mount);
  struct mount* parent = bpf_core_cast(mount->mnt_parent, struct mount);
  if (parent && parent != mount) {
    return bpf_core_cast(mount->mnt_mountpoint, struct dentry);
  }
  return fallback;
}

static __always_inline bool bpfj_mount_is_attached(struct vfsmount* vfsmount) {
  if (!vfsmount) {
    return false;
  }
  const long offset = bpf_core_field_offset(struct mount, mnt);
  struct mount* mount = bpf_core_cast((void*)vfsmount - offset, struct mount);
  struct mount* parent = bpf_core_cast(mount->mnt_parent, struct mount);
  return parent && parent != mount;
}

static __always_inline int bpfj_mount_enforce_result(int result) {
  barrier_var(result);
  if (result > 0 || result < -4095) {
    return -EACCES;
  }
  return result;
}

static __always_inline struct dentry* bpfj_mount_destination(
    const struct path* path) {
  if (!path) {
    return NULL;
  }
  const struct path* core_path = bpf_core_cast(path, struct path);
  struct vfsmount* vfsmount = bpf_core_cast(core_path->mnt, struct vfsmount);
  if (!vfsmount) {
    return NULL;
  }
  return bpfj_mountpoint(
      vfsmount, bpf_core_cast((path), typeof(*(path)))->dentry);
}

SEC("lsm/sb_mount")
int BPF_PROG(
    bpfj_mount_new,
    const char* dev_name,
    const struct path* path,
    const char* type,
    unsigned long flags,
    void* data,
    int lsm_ret) {
  if (lsm_ret || !path || (flags & MS_REMOUNT)) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_result(bpfj_mount_enforce_path(
      bpfj_ptr_to_scalar(bpf_core_cast((path), typeof(*(path)))->dentry),
      (uintptr_t)type));
}

SEC("lsm/sb_mount")
int BPF_PROG(
    bpfj_mount_remount,
    const char* dev_name,
    const struct path* path,
    const char* type,
    unsigned long flags,
    void* data,
    int lsm_ret) {
  if (lsm_ret || !path || !(flags & MS_REMOUNT)) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_result(bpfj_mount_enforce_path(
      bpfj_ptr_to_scalar(bpfj_mount_destination(path)),
      (uintptr_t)bpfj_mount_path_type(path)));
}

SEC("lsm/sb_mount")
int BPF_PROG(
    bpfj_mount_move_source,
    const char* dev_name,
    const struct path* path,
    const char* type,
    unsigned long flags,
    void* data,
    int lsm_ret) {
  return lsm_ret || !(flags & MS_MOVE)
      ? lsm_ret
      : bpfj_mount_enforce_any(BPFJ_POLICY_UMOUNT_ANY, "move mount source");
}

SEC("lsm/sb_mount")
int BPF_PROG(
    bpfj_mount_remount_relay,
    const char* dev_name,
    const struct path* path,
    const char* type,
    unsigned long flags,
    void* data,
    int lsm_ret) {
  if (lsm_ret || !(flags & MS_REMOUNT) || !path) {
    return lsm_ret;
  }

  struct super_block* sb = bpf_core_cast((path), typeof(*(path)))->mnt->mnt_sb;
  if (!sb) {
    return 0;
  }
  const __u64 pid_tgid = bpf_get_current_pid_tgid();
  const struct bpfj_remount_relay relay = {
      .sb = (__u64)sb,
      .root = (__u64)bpf_core_cast((sb), typeof(*(sb)))->s_root,
      .type = (__u64)bpf_core_cast((sb), typeof(*(sb)))->s_type,
      .dev = bpf_core_cast((sb), typeof(*(sb)))->s_dev,
      .magic = bpf_core_cast((sb), typeof(*(sb)))->s_magic,
      .when = bpf_ktime_get_ns(),
  };
  bpf_map_update_elem(&bpfj_remount_relays, &pid_tgid, &relay, BPF_ANY);
  return 0;
}

SEC("lsm/sb_remount")
int BPF_PROG(
    bpfj_remount,
    struct super_block* sb,
    void* mnt_opts,
    int lsm_ret) {
  if (lsm_ret || !sb) {
    return lsm_ret;
  }
  const __u64 pid_tgid = bpf_get_current_pid_tgid();
  struct bpfj_remount_relay* relay =
      bpf_map_lookup_elem(&bpfj_remount_relays, &pid_tgid);
  const bool allowed = relay && relay->sb == (__u64)sb &&
      relay->root == (__u64)bpf_core_cast((sb), typeof(*(sb)))->s_root &&
      relay->type == (__u64)bpf_core_cast((sb), typeof(*(sb)))->s_type &&
      relay->dev == bpf_core_cast((sb), typeof(*(sb)))->s_dev &&
      relay->magic == bpf_core_cast((sb), typeof(*(sb)))->s_magic &&
      bpf_ktime_get_ns() - relay->when < BPFJ_REMOUNT_RELAY_NS;
  bpf_map_delete_elem(&bpfj_remount_relays, &pid_tgid);
  if (allowed) {
    return 0;
  }
  return bpfj_mount_enforce_any(BPFJ_POLICY_MOUNT_ANY, "remount");
}

SEC("lsm/sb_umount")
int BPF_PROG(bpfj_umount, struct vfsmount* mnt, int flags, int lsm_ret) {
  if (lsm_ret || !mnt) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_result(bpfj_mount_enforce_umount_path(
      bpfj_ptr_to_scalar(
          bpfj_mountpoint(mnt, bpf_core_cast(mnt->mnt_root, struct dentry))),
      BPFJ_UMOUNT_OPERATION_UMOUNT));
}

SEC("lsm/move_mount")
int BPF_PROG(
    bpfj_move_mount_destination,
    const struct path* from_path,
    const struct path* to_path,
    int lsm_ret) {
  if (lsm_ret || !from_path || !to_path) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_result(bpfj_mount_enforce_path(
      bpfj_ptr_to_scalar(bpf_core_cast((to_path), typeof(*(to_path)))->dentry),
      (uintptr_t)bpfj_mount_path_type(from_path)));
}

SEC("lsm/move_mount")
int BPF_PROG(
    bpfj_move_mount_source,
    const struct path* from_path,
    const struct path* to_path,
    int lsm_ret) {
  if (lsm_ret || !from_path) {
    return lsm_ret;
  }
  struct vfsmount* source = bpf_core_cast(from_path->mnt, struct vfsmount);
  if (!bpfj_mount_is_attached(source)) {
    return 0;
  }
  return bpfj_mount_enforce_result(bpfj_mount_enforce_umount_path(
      bpfj_ptr_to_scalar(bpfj_mount_destination(from_path)),
      BPFJ_UMOUNT_OPERATION_MOVE));
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(
    bpfj_pivot_root_new,
    const struct path* old_path,
    const struct path* new_path,
    int lsm_ret) {
  if (lsm_ret || !new_path) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_result(bpfj_mount_enforce_path(
      bpfj_ptr_to_scalar(bpfj_mount_destination(new_path)),
      (uintptr_t)bpfj_mount_path_type(new_path)));
}

SEC("lsm/sb_pivotroot")
int BPF_PROG(
    bpfj_pivot_root_old,
    const struct path* old_path,
    const struct path* new_path,
    int lsm_ret) {
  if (lsm_ret || !old_path) {
    return lsm_ret;
  }
  return bpfj_mount_enforce_result(bpfj_mount_enforce_umount_path(
      bpfj_ptr_to_scalar(bpfj_mount_destination(old_path)),
      BPFJ_UMOUNT_OPERATION_PIVOT));
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
