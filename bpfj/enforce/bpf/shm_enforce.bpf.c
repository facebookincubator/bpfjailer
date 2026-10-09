// Copyright (c) Meta Platforms, Inc. and affiliates.

// System V shared memory is checked at lookup, control, and attach. POSIX
// shared memory is ordinary tmpfs reached through a registered /dev/shm
// mount, so file acquisition, descriptor receipt, mapping, permission checks,
// protection upgrades, truncation, and unlink are all gated.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/mutation_journal.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/shm_gate.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

#define BPFJ_TMPFS_MAGIC 0x01021994
// PROT_READ, PROT_WRITE, and PROT_EXEC use the same low bits as VM_READ,
// VM_WRITE, and VM_EXEC. vmlinux.h does not carry the preprocessor macros.
#define BPFJ_VM_ACCESS_FLAGS 7UL

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u64);
  __type(value, struct bpfj_shm_owner);
} bpfj_shm_sysv_owners SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_posix_shm_key);
  __type(value, struct bpfj_shm_owner);
} bpfj_shm_posix_owners SEC(".maps");

// Pin the inode-to-owner handoff so replacement preserves an allocation whose
// file_open has not resolved its persistent key yet.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);
  __type(value, struct bpfj_shm_pending_owner);
} bpfj_shm_posix_pending SEC(".maps");

// Published by userspace for every enrolled mount namespace. The value is the
// mount's device number, making a stale or reused mount id fail closed.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, struct bpfj_shm_mount_key);
  __type(value, __u64);
} bpfj_shm_posix_mounts SEC(".maps");

// inode_alloc_security has no mount argument, so creation filtering uses the
// device half of the classifier and file_open confirms the exact mount.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 4096);
  __type(key, __u64);
  __type(value, __u8);
} bpfj_shm_posix_devices SEC(".maps");

static __always_inline int bpfj_shm_deny(const char* kind) {
  BPFJ_LOG("Denied %s shared memory access", kind);
  return -EPERM;
}

static __always_inline int bpfj_shm_sysv_check(struct kern_ipc_perm* shp) {
  if (!shp) {
    return 0;
  }

  const __u64 key = (__u64)shp;
  const struct bpfj_shm_owner* owner =
      bpf_map_lookup_elem(&bpfj_shm_sysv_owners, &key);
  return bpfj_shm_allowed(
             BPFJ_POLICY_GATE_SHM_SYSV,
             bpfj_get_current_pid_data(),
             owner,
             NULL)
      ? 0
      : bpfj_shm_deny("System V");
}

SEC("lsm/shm_alloc_security")
int BPF_PROG(bpfj_shm_sysv_alloc, struct kern_ipc_perm* shp, int lsm_ret) {
  if (lsm_ret || !shp) {
    return lsm_ret;
  }

  struct bpfj_shm_owner owner = {};
  const bool owned = bpfj_shm_current_owner(&owner);
  if (!bpfj_shm_allowed(
          BPFJ_POLICY_GATE_SHM_SYSV,
          bpfj_get_current_pid_data(),
          owned ? &owner : NULL,
          NULL)) {
    return bpfj_shm_deny("System V");
  }

  if (owned) {
    BPFJ_MUTATION_TRANSACTION(transaction);
    const int active = bpfj_mutation_begin(&transaction);
    if (active <= 0) {
      return active;
    }
    const __u64 key = (__u64)shp;
    if (bpf_map_update_elem(&bpfj_shm_sysv_owners, &key, &owner, BPF_NOEXIST) !=
        0) {
      return -ENOMEM;
    }
    bpfj_mutation_shm_owner(
        &transaction,
        BPFJ_MUTATION_SHM_SYSV_OWNER,
        BPFJ_MUTATION_UPSERT,
        key,
        0,
        &owner,
        1);
  }
  return 0;
}

SEC("lsm/shm_free_security")
int BPF_PROG(bpfj_shm_sysv_free, struct kern_ipc_perm* shp) {
  if (!shp) {
    return 0;
  }
  const __u64 key = (__u64)shp;
  if (!bpf_map_lookup_elem(&bpfj_shm_sysv_owners, &key)) {
    return 0;
  }
  BPFJ_MUTATION_TRANSACTION(transaction);
  if (bpfj_mutation_begin(&transaction) <= 0) {
    return 0;
  }
  bpf_map_delete_elem(&bpfj_shm_sysv_owners, &key);
  bpfj_mutation_shm_owner(
      &transaction,
      BPFJ_MUTATION_SHM_SYSV_OWNER,
      BPFJ_MUTATION_DELETE,
      key,
      0,
      NULL,
      0);
  return 0;
}

SEC("lsm/shm_associate")
int BPF_PROG(
    bpfj_shm_sysv_associate,
    struct kern_ipc_perm* shp,
    int shmflg,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_shm_sysv_check(shp);
}

SEC("lsm/shm_shmctl")
int BPF_PROG(
    bpfj_shm_sysv_ctl,
    struct kern_ipc_perm* shp,
    int cmd,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_shm_sysv_check(shp);
}

SEC("lsm/shm_shmat")
int BPF_PROG(
    bpfj_shm_sysv_attach,
    struct kern_ipc_perm* shp,
    char* shmaddr,
    int shmflg,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_shm_sysv_check(shp);
}

static __always_inline bool bpfj_posix_shm_key_from_inode(
    struct inode* inode,
    struct bpfj_posix_shm_key* key) {
  struct super_block* sb =
      inode ? bpf_core_cast((inode), typeof(*(inode)))->i_sb : NULL;
  if (!sb || bpf_core_cast((sb), typeof(*(sb)))->s_magic != BPFJ_TMPFS_MAGIC) {
    return false;
  }
  key->dev = bpf_core_cast((sb), typeof(*(sb)))->s_dev;
  key->ino = bpf_core_cast((inode), typeof(*(inode)))->i_ino;
  return key->ino != 0;
}

// inode_alloc_security runs before the VFS has necessarily assigned i_ino.
// The superblock and device are already stable, and file_open later confirms
// the exact registered mount before promoting the pending owner to {dev, ino}.
static __always_inline bool bpfj_posix_shm_registered_device(
    struct inode* inode) {
  struct super_block* sb =
      inode ? bpf_core_cast((inode), typeof(*(inode)))->i_sb : NULL;
  if (!sb || bpf_core_cast((sb), typeof(*(sb)))->s_magic != BPFJ_TMPFS_MAGIC) {
    return false;
  }

  const __u64 dev = bpf_core_cast((sb), typeof(*(sb)))->s_dev;
  return bpf_map_lookup_elem(&bpfj_shm_posix_devices, &dev) != NULL;
}

static __always_inline bool bpfj_posix_shm_key_from_file(
    struct file* file,
    struct bpfj_posix_shm_key* key) {
  return file &&
      bpfj_posix_shm_key_from_inode(
             bpf_core_cast((file), typeof(*(file)))->f_inode, key);
}

static __always_inline bool bpfj_posix_shm_mount_registered(
    struct vfsmount* vfsmnt,
    __u64 dev) {
  if (!vfsmnt) {
    return false;
  }

  struct task_struct* task = bpf_get_current_task_btf();
  struct nsproxy* nsproxy =
      task ? bpf_core_cast((task), typeof(*(task)))->nsproxy : NULL;
  struct mnt_namespace* ns =
      nsproxy ? bpf_core_cast((nsproxy), typeof(*(nsproxy)))->mnt_ns : NULL;
  if (!ns) {
    return false;
  }

  struct mount* mount = container_of(vfsmnt, struct mount, mnt);
  struct bpfj_shm_mount_key key = {
      .namespace_ino = bpf_core_cast((ns), typeof(*(ns)))->ns.inum,
      .mount_id = bpf_core_cast((mount), typeof(*(mount)))->mnt_id,
  };
  const __u64* registered_dev =
      bpf_map_lookup_elem(&bpfj_shm_posix_mounts, &key);
  return registered_dev && *registered_dev == dev;
}

static __always_inline int bpfj_posix_shm_check(
    struct file* file,
    bool require_registered_mount) {
  struct bpfj_posix_shm_key key = {};
  if (!bpfj_posix_shm_key_from_file(file, &key)) {
    return 0;
  }

  const struct bpfj_shm_owner* owner =
      bpf_map_lookup_elem(&bpfj_shm_posix_owners, &key);
  if (!owner && require_registered_mount) {
    struct vfsmount* mnt = bpf_core_cast((file), typeof(*(file)))->f_path.mnt;
    if (!bpfj_posix_shm_mount_registered(mnt, key.dev)) {
      return 0;
    }
  } else if (!owner) {
    return 0;
  }

  struct dentry* dentry =
      file ? bpf_core_cast((file), typeof(*(file)))->f_path.dentry : NULL;
  const struct qstr* name = dentry ? &dentry->d_name : NULL;
  return bpfj_shm_allowed(
             BPFJ_POLICY_GATE_SHM_POSIX,
             bpfj_get_current_pid_data(),
             owner,
             name)
      ? 0
      : bpfj_shm_deny("POSIX");
}

SEC("lsm/inode_alloc_security")
int BPF_PROG(bpfj_shm_posix_alloc, struct inode* inode, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!bpfj_posix_shm_registered_device(inode)) {
    return 0;
  }

  struct bpfj_shm_pending_owner pending = {};
  pending.owned = bpfj_shm_current_owner(&pending.owner);
  if (!bpfj_shm_allowed(
          BPFJ_POLICY_GATE_SHM_POSIX,
          bpfj_get_current_pid_data(),
          pending.owned ? &pending.owner : NULL,
          NULL)) {
    return bpfj_shm_deny("POSIX");
  }
  if (!pending.owned) {
    return 0;
  }

  const __u64 key = (__u64)inode;
  BPFJ_MUTATION_TRANSACTION(transaction);
  const int active = bpfj_mutation_begin(&transaction);
  if (active <= 0) {
    return active;
  }
  if (bpf_map_update_elem(&bpfj_shm_posix_pending, &key, &pending, BPF_ANY) !=
      0) {
    return -ENOMEM;
  }
  bpfj_mutation_shm_owner(
      &transaction,
      BPFJ_MUTATION_SHM_POSIX_PENDING,
      BPFJ_MUTATION_UPSERT,
      key,
      0,
      &pending.owner,
      pending.owned);
  return 0;
}

SEC("lsm/file_open")
int BPF_PROG(bpfj_shm_posix_open, struct file* file, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  struct bpfj_posix_shm_key object = {};
  if (!bpfj_posix_shm_key_from_file(file, &object)) {
    return 0;
  }

  const struct bpfj_shm_owner* owner =
      bpf_map_lookup_elem(&bpfj_shm_posix_owners, &object);
  if (owner) {
    return bpfj_posix_shm_check(file, false);
  }

  struct vfsmount* mnt = bpf_core_cast((file), typeof(*(file)))->f_path.mnt;
  if (!bpfj_posix_shm_mount_registered(mnt, object.dev)) {
    return 0;
  }

  struct inode* inode = bpf_core_cast((file), typeof(*(file)))->f_inode;
  const __u64 pending_key = (__u64)inode;
  const struct bpfj_shm_pending_owner* pending =
      bpf_map_lookup_elem(&bpfj_shm_posix_pending, &pending_key);
  if (!pending) {
    return bpfj_posix_shm_check(file, true);
  }

  struct dentry* dentry = bpf_core_cast((file), typeof(*(file)))->f_path.dentry;
  const struct qstr* name = dentry ? &dentry->d_name : NULL;
  if (!bpfj_shm_allowed(
          BPFJ_POLICY_GATE_SHM_POSIX,
          bpfj_get_current_pid_data(),
          pending->owned ? &pending->owner : NULL,
          name)) {
    return bpfj_shm_deny("POSIX");
  }

  BPFJ_MUTATION_TRANSACTION(transaction);
  const int active = bpfj_mutation_begin(&transaction);
  if (active <= 0) {
    return active;
  }

  if (pending->owned &&
      bpf_map_update_elem(
          &bpfj_shm_posix_owners, &object, &pending->owner, BPF_ANY) != 0) {
    return -ENOMEM;
  }
  bpfj_mutation_shm_owner(
      &transaction,
      BPFJ_MUTATION_SHM_POSIX_OWNER,
      BPFJ_MUTATION_UPSERT,
      object.dev,
      object.ino,
      &pending->owner,
      pending->owned);
  bpf_map_delete_elem(&bpfj_shm_posix_pending, &pending_key);
  bpfj_mutation_shm_owner(
      &transaction,
      BPFJ_MUTATION_SHM_POSIX_PENDING,
      BPFJ_MUTATION_DELETE,
      pending_key,
      0,
      NULL,
      0);
  return 0;
}

SEC("lsm/file_receive")
int BPF_PROG(bpfj_shm_posix_receive_fd, struct file* file, int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_posix_shm_check(file, true);
}

SEC("lsm/file_permission")
int BPF_PROG(
    bpfj_shm_posix_permission,
    struct file* file,
    int mask,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_posix_shm_check(file, false);
}

SEC("lsm/mmap_file")
int BPF_PROG(
    bpfj_shm_posix_mmap,
    struct file* file,
    unsigned long reqprot,
    unsigned long prot,
    unsigned long flags,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_posix_shm_check(file, true);
}

SEC("lsm/file_mprotect")
int BPF_PROG(
    bpfj_shm_posix_mprotect,
    struct vm_area_struct* vma,
    unsigned long reqprot,
    unsigned long prot,
    int lsm_ret) {
  if (lsm_ret || !vma ||
      !(prot & ~bpf_core_cast((vma), typeof(*(vma)))->vm_flags &
        BPFJ_VM_ACCESS_FLAGS)) {
    return lsm_ret;
  }
  struct file* file =
      vma ? bpf_core_cast((vma), typeof(*(vma)))->vm_file : NULL;
  return bpfj_posix_shm_check(file, true);
}

static __always_inline int bpfj_posix_shm_path_check(
    const struct path* path,
    struct dentry* dentry) {
  struct inode* inode =
      dentry ? bpf_core_cast((dentry), typeof(*(dentry)))->d_inode : NULL;
  struct bpfj_posix_shm_key object = {};
  if (!bpfj_posix_shm_key_from_inode(inode, &object)) {
    return 0;
  }

  const struct bpfj_shm_owner* owner =
      bpf_map_lookup_elem(&bpfj_shm_posix_owners, &object);
  struct vfsmount* mnt =
      path ? bpf_core_cast((path), typeof(*(path)))->mnt : NULL;
  if (!owner && !bpfj_posix_shm_mount_registered(mnt, object.dev)) {
    return 0;
  }

  const struct qstr* name = dentry ? &dentry->d_name : NULL;
  return bpfj_shm_allowed(
             BPFJ_POLICY_GATE_SHM_POSIX,
             bpfj_get_current_pid_data(),
             owner,
             name)
      ? 0
      : bpfj_shm_deny("POSIX");
}

SEC("lsm/path_unlink")
int BPF_PROG(
    bpfj_shm_posix_unlink,
    const struct path* dir,
    struct dentry* dentry,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }
  const int ret = bpfj_posix_shm_path_check(dir, dentry);
  return ret;
}

SEC("lsm/path_truncate")
int BPF_PROG(bpfj_shm_posix_truncate, const struct path* path, int lsm_ret) {
  struct dentry* dentry =
      path ? bpf_core_cast((path), typeof(*(path)))->dentry : NULL;
  return lsm_ret ? lsm_ret : bpfj_posix_shm_path_check(path, dentry);
}

SEC("lsm/file_truncate")
int BPF_PROG(bpfj_shm_posix_file_truncate, struct file* file, int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_posix_shm_check(file, true);
}

SEC("lsm/inode_free_security")
int BPF_PROG(bpfj_shm_posix_free, struct inode* inode) {
  if (!inode) {
    return 0;
  }
  const __u64 pending_key = (__u64)inode;
  const bool pending =
      bpf_map_lookup_elem(&bpfj_shm_posix_pending, &pending_key) != NULL;
  struct bpfj_posix_shm_key key = {};
  const bool owned = bpf_core_cast((inode), typeof(*(inode)))->i_nlink == 0 &&
      bpfj_posix_shm_key_from_inode(inode, &key) &&
      bpf_map_lookup_elem(&bpfj_shm_posix_owners, &key) != NULL;
  if (!pending && !owned) {
    return 0;
  }

  BPFJ_MUTATION_TRANSACTION(transaction);
  if (bpfj_mutation_begin(&transaction) <= 0) {
    return 0;
  }
  if (pending) {
    bpf_map_delete_elem(&bpfj_shm_posix_pending, &pending_key);
    bpfj_mutation_shm_owner(
        &transaction,
        BPFJ_MUTATION_SHM_POSIX_PENDING,
        BPFJ_MUTATION_DELETE,
        pending_key,
        0,
        NULL,
        0);
  }

  if (owned) {
    bpf_map_delete_elem(&bpfj_shm_posix_owners, &key);
    bpfj_mutation_shm_owner(
        &transaction,
        BPFJ_MUTATION_SHM_POSIX_OWNER,
        BPFJ_MUTATION_DELETE,
        key.dev,
        key.ino,
        NULL,
        0);
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
