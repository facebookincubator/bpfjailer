// Copyright (c) Meta Platforms, Inc. and affiliates.

// System V message queues name kernel objects with integer ids that can be
// copied freely, so every operation is checked. POSIX queues are file-backed:
// file_open gates mq_open(), file_receive gates SCM_RIGHTS acquisition, and
// possession of an already-authorized descriptor remains the capability.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/mq_gate.h"
#include "bpfj/enforce/bpf/mutation_journal.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

#define BPFJ_MQUEUE_MAGIC 0x19800202

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u64);
  __type(value, struct bpfj_mq_owner);
} bpfj_mq_sysv_owners SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, struct bpfj_posix_mq_key);
  __type(value, struct bpfj_mq_owner);
} bpfj_mq_posix_owners SEC(".maps");

// Pin the inode-to-owner handoff so replacement preserves an allocation whose
// file_open has not resolved its persistent key yet.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 16384);
  __type(key, __u64);
  __type(value, struct bpfj_mq_pending_owner);
} bpfj_mq_posix_pending SEC(".maps");

static __always_inline int bpfj_mq_deny(const char* kind) {
  BPFJ_LOG("Denied %s message queue access", kind);
  return -EPERM;
}

static __always_inline int bpfj_mq_sysv_check(
    struct kern_ipc_perm* msq,
    struct task_struct* actor) {
  if (!msq) {
    return 0;
  }

  const __u64 key = (__u64)msq;
  const struct bpfj_mq_owner* owner =
      bpf_map_lookup_elem(&bpfj_mq_sysv_owners, &key);
  struct bpfj_pid_data* pid_data =
      actor ? bpfj_get_task_pid_data(actor) : bpfj_get_current_pid_data();
  return bpfj_mq_allowed(BPFJ_POLICY_GATE_MQ_SYSV, pid_data, owner, NULL)
      ? 0
      : bpfj_mq_deny("System V");
}

SEC("lsm/msg_queue_alloc_security")
int BPF_PROG(bpfj_mq_sysv_alloc, struct kern_ipc_perm* msq, int lsm_ret) {
  if (lsm_ret || !msq) {
    return lsm_ret;
  }

  struct bpfj_mq_owner owner = {};
  const bool owned = bpfj_mq_current_owner(&owner);
  if (!bpfj_mq_allowed(
          BPFJ_POLICY_GATE_MQ_SYSV,
          bpfj_get_current_pid_data(),
          owned ? &owner : NULL,
          NULL)) {
    return bpfj_mq_deny("System V");
  }

  if (owned) {
    BPFJ_MUTATION_TRANSACTION(transaction);
    const int active = bpfj_mutation_begin(&transaction);
    if (active <= 0) {
      return active;
    }
    const __u64 key = (__u64)msq;
    if (bpf_map_update_elem(&bpfj_mq_sysv_owners, &key, &owner, BPF_NOEXIST) !=
        0) {
      return -ENOMEM;
    }
    bpfj_mutation_mq_owner(
        &transaction,
        BPFJ_MUTATION_MQ_SYSV_OWNER,
        BPFJ_MUTATION_UPSERT,
        key,
        0,
        &owner,
        1);
  }
  return 0;
}

SEC("lsm/msg_queue_free_security")
int BPF_PROG(bpfj_mq_sysv_free, struct kern_ipc_perm* msq) {
  if (!msq) {
    return 0;
  }
  const __u64 key = (__u64)msq;
  if (!bpf_map_lookup_elem(&bpfj_mq_sysv_owners, &key)) {
    return 0;
  }
  BPFJ_MUTATION_TRANSACTION(transaction);
  if (bpfj_mutation_begin(&transaction) <= 0) {
    return 0;
  }
  bpf_map_delete_elem(&bpfj_mq_sysv_owners, &key);
  bpfj_mutation_mq_owner(
      &transaction,
      BPFJ_MUTATION_MQ_SYSV_OWNER,
      BPFJ_MUTATION_DELETE,
      key,
      0,
      NULL,
      0);
  return 0;
}

SEC("lsm/msg_queue_associate")
int BPF_PROG(
    bpfj_mq_sysv_associate,
    struct kern_ipc_perm* msq,
    int msqflg,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_sysv_check(msq, NULL);
}

SEC("lsm/msg_queue_msgctl")
int BPF_PROG(
    bpfj_mq_sysv_msgctl,
    struct kern_ipc_perm* msq,
    int cmd,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_sysv_check(msq, NULL);
}

SEC("lsm/msg_queue_msgsnd")
int BPF_PROG(
    bpfj_mq_sysv_send,
    struct kern_ipc_perm* msq,
    struct msg_msg* msg,
    int msqflg,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_sysv_check(msq, NULL);
}

SEC("lsm/msg_queue_msgrcv")
int BPF_PROG(
    bpfj_mq_sysv_receive,
    struct kern_ipc_perm* msq,
    struct msg_msg* msg,
    struct task_struct* target,
    long type,
    int mode,
    int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_sysv_check(msq, target);
}

static __always_inline bool bpfj_posix_mq_key(
    struct file* file,
    struct bpfj_posix_mq_key* key) {
  struct inode* inode =
      file ? bpf_core_cast((file), typeof(*(file)))->f_inode : NULL;
  struct super_block* sb =
      inode ? bpf_core_cast((inode), typeof(*(inode)))->i_sb : NULL;
  if (!sb || bpf_core_cast((sb), typeof(*(sb)))->s_magic != BPFJ_MQUEUE_MAGIC) {
    return false;
  }

  key->dev = bpf_core_cast((sb), typeof(*(sb)))->s_dev;
  key->ino = bpf_core_cast((inode), typeof(*(inode)))->i_ino;
  return key->ino != 0;
}

static __always_inline bool bpfj_is_mqueue_inode(struct inode* inode) {
  struct super_block* sb =
      inode ? bpf_core_cast((inode), typeof(*(inode)))->i_sb : NULL;
  return sb && bpf_core_cast((sb), typeof(*(sb)))->s_magic == BPFJ_MQUEUE_MAGIC;
}

SEC("lsm/inode_alloc_security")
int BPF_PROG(bpfj_mq_posix_alloc, struct inode* inode, int lsm_ret) {
  if (lsm_ret || !bpfj_is_mqueue_inode(inode)) {
    return lsm_ret;
  }

  struct bpfj_mq_pending_owner pending = {};
  pending.owned = bpfj_mq_current_owner(&pending.owner);
  if (!bpfj_mq_allowed(
          BPFJ_POLICY_GATE_MQ_POSIX,
          bpfj_get_current_pid_data(),
          pending.owned ? &pending.owner : NULL,
          NULL)) {
    return bpfj_mq_deny("POSIX");
  }

  const __u64 key = (__u64)inode;
  BPFJ_MUTATION_TRANSACTION(transaction);
  const int active = bpfj_mutation_begin(&transaction);
  if (active <= 0) {
    return active;
  }
  if (bpf_map_update_elem(&bpfj_mq_posix_pending, &key, &pending, BPF_ANY) !=
      0) {
    return -ENOMEM;
  }
  bpfj_mutation_mq_owner(
      &transaction,
      BPFJ_MUTATION_MQ_POSIX_PENDING,
      BPFJ_MUTATION_UPSERT,
      key,
      0,
      &pending.owner,
      pending.owned);
  return 0;
}

static __always_inline int bpfj_mq_posix_check(struct file* file) {
  struct bpfj_posix_mq_key key = {};
  if (!bpfj_posix_mq_key(file, &key)) {
    return 0;
  }

  const struct bpfj_mq_owner* owner =
      bpf_map_lookup_elem(&bpfj_mq_posix_owners, &key);
  struct dentry* dentry =
      file ? bpf_core_cast((file), typeof(*(file)))->f_path.dentry : NULL;
  const struct qstr* name = dentry ? &dentry->d_name : NULL;
  return bpfj_mq_allowed(
             BPFJ_POLICY_GATE_MQ_POSIX,
             bpfj_get_current_pid_data(),
             owner,
             name)
      ? 0
      : bpfj_mq_deny("POSIX");
}

SEC("lsm/file_open")
int BPF_PROG(bpfj_mq_posix_open, struct file* file, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  struct bpfj_posix_mq_key key = {};
  if (!bpfj_posix_mq_key(file, &key)) {
    return 0;
  }

  struct inode* inode = bpf_core_cast((file), typeof(*(file)))->f_inode;
  const __u64 pending_key = (__u64)inode;
  const struct bpfj_mq_pending_owner* pending =
      bpf_map_lookup_elem(&bpfj_mq_posix_pending, &pending_key);
  if (!pending) {
    return bpfj_mq_posix_check(file);
  }

  struct dentry* dentry = bpf_core_cast((file), typeof(*(file)))->f_path.dentry;
  const struct qstr* name = dentry ? &dentry->d_name : NULL;
  if (!bpfj_mq_allowed(
          BPFJ_POLICY_GATE_MQ_POSIX,
          bpfj_get_current_pid_data(),
          pending->owned ? &pending->owner : NULL,
          name)) {
    return bpfj_mq_deny("POSIX");
  }

  BPFJ_MUTATION_TRANSACTION(transaction);
  const int active = bpfj_mutation_begin(&transaction);
  if (active <= 0) {
    return active;
  }

  if (pending->owned &&
      bpf_map_update_elem(
          &bpfj_mq_posix_owners, &key, &pending->owner, BPF_ANY) != 0) {
    return -ENOMEM;
  }
  bpfj_mutation_mq_owner(
      &transaction,
      BPFJ_MUTATION_MQ_POSIX_OWNER,
      BPFJ_MUTATION_UPSERT,
      key.dev,
      key.ino,
      &pending->owner,
      pending->owned);
  bpf_map_delete_elem(&bpfj_mq_posix_pending, &pending_key);
  bpfj_mutation_mq_owner(
      &transaction,
      BPFJ_MUTATION_MQ_POSIX_PENDING,
      BPFJ_MUTATION_DELETE,
      pending_key,
      0,
      NULL,
      0);
  return 0;
}

SEC("lsm/file_receive")
int BPF_PROG(bpfj_mq_posix_receive_fd, struct file* file, int lsm_ret) {
  return lsm_ret ? lsm_ret : bpfj_mq_posix_check(file);
}

SEC("lsm/inode_free_security")
int BPF_PROG(bpfj_mq_posix_free, struct inode* inode) {
  const __u64 pending_key = (__u64)inode;
  const bool pending =
      bpf_map_lookup_elem(&bpfj_mq_posix_pending, &pending_key) != NULL;
  const bool mqueue = bpfj_is_mqueue_inode(inode);
  struct super_block* sb =
      inode ? bpf_core_cast((inode), typeof(*(inode)))->i_sb : NULL;
  const bool unlinked =
      mqueue && sb && bpf_core_cast((inode), typeof(*(inode)))->i_nlink == 0;
  const struct bpfj_posix_mq_key key = {
      .dev = unlinked ? bpf_core_cast((sb), typeof(*(sb)))->s_dev : 0,
      .ino = unlinked ? bpf_core_cast((inode), typeof(*(inode)))->i_ino : 0,
  };
  const bool owned =
      key.ino != 0 && bpf_map_lookup_elem(&bpfj_mq_posix_owners, &key) != NULL;
  if (!pending && !owned) {
    return 0;
  }

  BPFJ_MUTATION_TRANSACTION(transaction);
  if (bpfj_mutation_begin(&transaction) <= 0) {
    return 0;
  }
  if (pending) {
    bpf_map_delete_elem(&bpfj_mq_posix_pending, &pending_key);
    bpfj_mutation_mq_owner(
        &transaction,
        BPFJ_MUTATION_MQ_POSIX_PENDING,
        BPFJ_MUTATION_DELETE,
        pending_key,
        0,
        NULL,
        0);
  }

  if (owned) {
    bpf_map_delete_elem(&bpfj_mq_posix_owners, &key);
    bpfj_mutation_mq_owner(
        &transaction,
        BPFJ_MUTATION_MQ_POSIX_OWNER,
        BPFJ_MUTATION_DELETE,
        key.dev,
        key.ino,
        NULL,
        0);
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
