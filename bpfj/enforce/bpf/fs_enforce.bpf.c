// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types_fs.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/match/bpf/file_match_cached.h"
#include "bpfj/match/bpf/glob_var_bindings.h"

#define FMODE_READ BPFJ_FS_MODE_READ
#define FMODE_WRITE BPFJ_FS_MODE_WRITE

// Each role policy points directly at its matcher while all roles share the
// inode cache and PID 1 mount snapshot.
struct bpfj_mount_cache __arena* bpfj_fs_mount_cache;

static __always_inline bool bpfj_fs_mode_allowed(__u32 granted, __u32 wanted) {
  if ((wanted & FMODE_WRITE) && !(granted & FMODE_WRITE)) {
    return false;
  }
  if ((wanted & FMODE_READ) && !(granted & FMODE_READ)) {
    return false;
  }
  return true;
}

static __noinline bool bpfj_fs_match_allowed(
    struct bpfj_file_match_cached_state __arena* state,
    __u32 wanted,
    long count) {
  __s32 bestPos = -1;
  struct bpfj_fs_path_entry* best = NULL;
  __u32 i;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }
    struct bpfj_fs_path_entry* entry = BPFJ_FILE_MATCH_CACHED_LOOKUP(state, i);
    if (!entry) {
      continue;
    }
    const __s32 pos = BPFJ_FILE_MATCH_CACHED_GET_POS(state, i);
    if (pos > bestPos) {
      bestPos = pos;
      best = entry;
    }
  }
  return best != NULL && bpfj_fs_mode_allowed(best->mode, wanted);
}

// Inlined to avoid adding a ninth frame to the mount and glob walk. The pod
// loop is ordinarily one iteration and is unrolled rather than expressed with
// bpf_for: file_match_cached itself uses bpf_for and those iterators must never
// be nested.
static __always_inline int bpfj_fs_enforce(uintptr_t dentry, __u32 wanted) {
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pidData = bpfj_get_current_pid_data();
  if (!task || !pidData || !dentry) {
    return 0;
  }

  BPFJ_FILE_MATCH_CACHED_ALLOC(state);
  if (!state) {
    return 0;
  }

  __u32 numPods = pidData->num_pods;
  if (numPods > BPFJ_MAX_POD_PER_PID) {
    numPods = BPFJ_MAX_POD_PER_PID;
  }

  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= numPods) {
      continue;
    }

    void* podPointer = (void*)pidData->pods[index];
    if (!podPointer) {
      continue;
    }
    barrier_var(podPointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)podPointer;

    struct bpfj_role_id role = {};
    struct bpfj_uuid uuid = {};
    bpfj_pod_read_role_id(&role, pod);
    bpfj_pod_read_uuid(&uuid, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    struct bpfj_file_matcher __arena* matcher =
        policy ? policy->fs_matcher : NULL;
    bool allowed = policy && (policy->flags & BPFJ_POLICY_FS_ANY);
    if (matcher) {
      long count = BPFJ_FILE_MATCH_CACHED(
          state,
          matcher,
          bpfj_fs_mount_cache,
          dentry,
          &uuid,
          bpfj_file_match_cached_bind_var_array,
          &pod->var_array);
      if (count == -E2BIG) {
        struct bpfj_event* event = bpfj_event_reserve(BPFJ_EVENT_FS, pod, task);
        bpfj_event_submit(event);
        BPFJ_LOG("Denied filesystem access: path exceeds matcher limit");
        return -EACCES;
      }
      allowed = count > 0 && bpfj_fs_match_allowed(state, wanted, count);
      if (count < 0 && count != -EXDEV) {
        BPFJ_LOG_ERR(-count, "filesystem path match failed");
      }
    }
    if (!allowed) {
      struct bpfj_event* event = bpfj_event_reserve(BPFJ_EVENT_FS, pod, task);
      bpfj_event_submit(event);
      BPFJ_LOG("Denied filesystem access for role %s", role.id);
      return -EACCES;
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

#define BPFJ_FS_CHECK(_dentry, _mode) \
  bpfj_fs_enforce(bpfj_ptr_to_scalar(_dentry), _mode)

SEC("lsm/file_open")
int BPF_PROG(bpfj_fs_file_open, struct file* file, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  return BPFJ_FS_CHECK(
      bpf_core_cast((file), typeof(*(file)))->f_path.dentry,
      bpf_core_cast((file), typeof(*(file)))->f_mode &
          (FMODE_READ | FMODE_WRITE));
}

SEC("lsm/inode_unlink")
int BPF_PROG(
    bpfj_fs_inode_unlink,
    struct inode* dir,
    struct dentry* dentry,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  int ret = BPFJ_FS_CHECK(dentry, FMODE_WRITE);
  if (ret) {
    return ret;
  }
  return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(
    bpfj_fs_inode_link,
    struct dentry* old_dentry,
    struct inode* dir,
    struct dentry* new_dentry,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  int ret = BPFJ_FS_CHECK(new_dentry, FMODE_WRITE);
  if (ret) {
    return ret;
  }
  return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(
    bpfj_fs_inode_link_source,
    struct dentry* old_dentry,
    struct inode* dir,
    struct dentry* new_dentry,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : BPFJ_FS_CHECK(old_dentry, FMODE_WRITE);
}

SEC("lsm/inode_create")
int BPF_PROG(
    bpfj_fs_inode_create,
    struct inode* dir,
    struct dentry* dentry,
    umode_t mode,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : BPFJ_FS_CHECK(dentry, FMODE_WRITE);
}

SEC("lsm/inode_mknod")
int BPF_PROG(
    bpfj_fs_inode_mknod,
    struct inode* dir,
    struct dentry* dentry,
    umode_t mode,
    dev_t dev,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : BPFJ_FS_CHECK(dentry, FMODE_WRITE);
}

SEC("lsm/inode_rename")
int BPF_PROG(
    bpfj_fs_inode_rename,
    struct inode* old_dir,
    struct dentry* old_dentry,
    struct inode* new_dir,
    struct dentry* new_dentry,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  int ret = BPFJ_FS_CHECK(old_dentry, FMODE_WRITE);
  if (ret) {
    return ret;
  }

  return 0;
}

SEC("lsm/inode_rename")
int BPF_PROG(
    bpfj_fs_inode_rename_destination,
    struct inode* old_dir,
    struct dentry* old_dentry,
    struct inode* new_dir,
    struct dentry* new_dentry,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  int ret = BPFJ_FS_CHECK(
      bpf_core_cast((new_dentry), typeof(*(new_dentry)))->d_parent,
      FMODE_WRITE);
  if (ret) {
    return ret;
  }

  return 0;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(
    bpfj_fs_inode_rmdir,
    struct inode* dir,
    struct dentry* dentry,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  int ret = BPFJ_FS_CHECK(dentry, FMODE_WRITE);
  if (ret) {
    return ret;
  }
  return 0;
}

SEC("lsm/inode_mkdir")
int BPF_PROG(
    bpfj_fs_inode_mkdir,
    struct inode* dir,
    struct dentry* dentry,
    umode_t mode,
    int lsm_ret) {
  return lsm_ret
      ? lsm_ret
      : BPFJ_FS_CHECK(
            bpf_core_cast((dentry), typeof(*(dentry)))->d_parent, FMODE_WRITE);
}

SEC("lsm/inode_setattr")
int BPF_PROG(
    bpfj_fs_inode_setattr,
    struct mnt_idmap* idmap,
    struct dentry* dentry,
    struct iattr* attr,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : BPFJ_FS_CHECK(dentry, FMODE_WRITE);
}

SEC("lsm/inode_getattr")
int BPF_PROG(bpfj_fs_inode_getattr, const struct path* path, int lsm_ret) {
  return lsm_ret
      ? lsm_ret
      : BPFJ_FS_CHECK(
            bpf_core_cast((path), typeof(*(path)))->dentry, FMODE_READ);
}

SEC("lsm/inode_setxattr")
int BPF_PROG(
    bpfj_fs_inode_setxattr,
    struct mnt_idmap* idmap,
    struct dentry* dentry,
    const char* name,
    const void* value,
    size_t size,
    int flags,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : BPFJ_FS_CHECK(dentry, FMODE_WRITE);
}

SEC("lsm/inode_getxattr")
int BPF_PROG(
    bpfj_fs_inode_getxattr,
    struct dentry* dentry,
    const char* name,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : BPFJ_FS_CHECK(dentry, FMODE_READ);
}

SEC("lsm/inode_listxattr")
int BPF_PROG(bpfj_fs_inode_listxattr, struct dentry* dentry, int lsm_ret) {
  return lsm_ret ? lsm_ret : BPFJ_FS_CHECK(dentry, FMODE_READ);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(
    bpfj_fs_inode_removexattr,
    struct mnt_idmap* idmap,
    struct dentry* dentry,
    const char* name,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : BPFJ_FS_CHECK(dentry, FMODE_WRITE);
}

SEC("lsm/inode_symlink")
int BPF_PROG(
    bpfj_fs_inode_symlink,
    struct inode* dir,
    struct dentry* dentry,
    const char* old_name,
    int lsm_ret) {
  return lsm_ret
      ? lsm_ret
      : BPFJ_FS_CHECK(
            bpf_core_cast((dentry), typeof(*(dentry)))->d_parent, FMODE_WRITE);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
