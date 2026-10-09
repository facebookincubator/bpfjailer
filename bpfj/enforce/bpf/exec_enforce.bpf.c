// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types_exec.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/match/bpf/file_match_cached.h"
#include "bpfj/match/bpf/glob_var_bindings.h"

#define PROT_EXEC 0x4
#define VM_EXEC 0x4
#define S_ISUID 0004000
#define S_ISGID 0002000

struct bpfj_dyn_lru __arena* bpfj_exec_match_lru;
struct bpfj_mount_cache __arena bpfj_exec_mount_cache;

// GLOBAL function: verify path-entry selection independently from the policy
// walk while returning only the scalar decision supported by BPF subprograms.
__noinline bool bpfj_exec_match_allowed(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    __u32 wanted,
    long count) {
  __s32 best_pos = -1;
  __u8 best_specificity = 0;
  struct bpfj_exec_path_entry* best = NULL;
  __u32 i;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }
    struct bpfj_exec_path_entry* entry =
        BPFJ_FILE_MATCH_CACHED_LOOKUP(state, i);
    if (!entry) {
      continue;
    }
    const __s32 pos = BPFJ_FILE_MATCH_CACHED_GET_POS(state, i);
    const bool denied = (entry->flags & wanted) != wanted;
    const bool best_denied = best && (best->flags & wanted) != wanted;
    if (pos > best_pos ||
        (pos == best_pos && entry->specificity > best_specificity) ||
        (pos == best_pos && entry->specificity == best_specificity && denied &&
         !best_denied)) {
      best_pos = pos;
      best_specificity = entry->specificity;
      best = entry;
    }
  }
  return best != NULL && (best->flags & wanted) == wanted;
}

// The pod loop is unrolled because file_match_cached uses bpf_for internally.
static __always_inline int bpfj_exec_enforce(uintptr_t dentry, __u32 wanted) {
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data || !dentry) {
    return 0;
  }

  BPFJ_FILE_MATCH_CACHED_ALLOC(state);
  if (!state) {
    return -EACCES;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods) {
      continue;
    }

    void* pod_pointer = (void*)pid_data->pods[index];
    if (!pod_pointer) {
      continue;
    }
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;

    struct bpfj_role_id role = {};
    struct bpfj_uuid uuid = {};
    bpfj_pod_read_role_id(&role, pod);
    bpfj_pod_read_uuid(&uuid, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    struct bpfj_file_matcher __arena* matcher =
        policy ? policy->exec_matcher : NULL;
    bool allowed = policy && (policy->flags & BPFJ_POLICY_EXEC_ANY);
    if (matcher && !allowed) {
      long count = BPFJ_FILE_MATCH_CACHED(
          state,
          matcher,
          &bpfj_exec_mount_cache,
          dentry,
          &uuid,
          bpfj_file_match_cached_bind_var_array,
          &pod->var_array);
      allowed = count > 0 && bpfj_exec_match_allowed(state, wanted, count);
      if (count < 0 && count != -EXDEV) {
        BPFJ_LOG_ERR(-count, "exec path match failed");
      }
    }
    if (!allowed) {
      struct bpfj_event* event = bpfj_event_reserve(BPFJ_EVENT_EXEC, pod, task);
      bpfj_event_submit(event);
      BPFJ_LOG("Denied executable code for role %s", role.id);
      return -EACCES;
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

// This is the first exec hook after jailer.bpf.c's bprm_creds_from_file, so a
// role claimed by this executable's xattr participates in the check.
SEC("lsm/bprm_check_security")
int BPF_PROG(bpfj_exec_bprm_check, struct linux_binprm* bprm, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  struct file* file = bprm->file;
  if (!file) {
    return 0;
  }
  struct inode* inode = bpf_core_cast((file), typeof(*(file)))->f_inode;
  if (!inode) {
    return 0;
  }

  __u32 wanted = BPFJ_EXEC_ALLOW_EXEC;
  const umode_t mode = bpf_core_cast((inode), typeof(*(inode)))->i_mode;
  if (mode & (S_ISUID | S_ISGID)) {
    wanted |= BPFJ_EXEC_ALLOW_SETUID;
  }
  return bpfj_exec_enforce(
      bpfj_ptr_to_scalar(bpf_core_cast((file), typeof(*(file)))->f_path.dentry),
      wanted);
}

static __always_inline bool bpfj_exec_is_kernel_exec(void) {
  struct task_struct* task = bpf_get_current_task_btf();
  return task && BPF_CORE_READ_BITFIELD_PROBED(task, in_execve);
}

SEC("lsm/mmap_file")
int BPF_PROG(
    bpfj_exec_mmap_file,
    struct file* file,
    unsigned long reqprot,
    unsigned long prot,
    unsigned long flags,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  if (!file || !(prot & PROT_EXEC) || bpfj_exec_is_kernel_exec()) {
    return 0;
  }
  return bpfj_exec_enforce(
      bpfj_ptr_to_scalar(bpf_core_cast((file), typeof(*(file)))->f_path.dentry),
      BPFJ_EXEC_ALLOW_SHARED_OBJECT);
}

SEC("lsm/file_mprotect")
int BPF_PROG(
    bpfj_exec_file_mprotect,
    struct vm_area_struct* vma,
    unsigned long reqprot,
    unsigned long prot,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  if (!vma || !(prot & PROT_EXEC) ||
      (bpf_core_cast((vma), typeof(*(vma)))->vm_flags & VM_EXEC) ||
      bpfj_exec_is_kernel_exec()) {
    return 0;
  }
  struct file* file = bpf_core_cast((vma), typeof(*(vma)))->vm_file;
  if (!file) {
    return 0;
  }
  return bpfj_exec_enforce(
      bpfj_ptr_to_scalar(bpf_core_cast((file), typeof(*(file)))->f_path.dentry),
      BPFJ_EXEC_ALLOW_SHARED_OBJECT);
}

SEC("lsm/inode_rename")
int BPF_PROG(
    bpfj_exec_inode_rename,
    struct inode* old_dir,
    struct dentry* old_dentry,
    struct inode* new_dir,
    struct dentry* new_dentry,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  return BPFJ_FILE_MATCH_CACHED_INVALIDATE_ON_RENAME(
      bpfj_exec_match_lru, old_dentry);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
