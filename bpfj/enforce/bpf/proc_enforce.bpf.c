// Copyright (c) Meta Platforms, Inc. and affiliates.

// Proc paths name tasks in the pid namespace mounted at that proc superblock,
// so the numeric path component must be resolved there rather than as a host
// pid before the ordinary actor-to-target role gate is applied.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/role_gate.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/kfuncs.h"
#include "bpfj/lib/bpf/logging_bpf.h"

extern const void proc_sops __ksym;

#define BPFJ_PROC_MAX_DEPTH 16

// This mirrors find_pid_ns() through the namespace's IDR and turns the result
// back into a referenced task through the root-namespace pid kfunc.
static struct task_struct* bpfj_task_from_pid_ns(
    pid_t pid,
    struct pid_namespace* ns) {
  if (ns->level == 0) {
    return bpf_task_from_pid(pid);
  }

  unsigned long idr_base = bpf_core_cast((ns), typeof(*(ns)))->idr.idr_base;
  if ((unsigned long)pid < idr_base) {
    return NULL;
  }
  unsigned long index = (unsigned long)pid - idr_base;
  void* entry = bpf_core_cast((ns), typeof(*(ns)))->idr.idr_rt.xa_head;

  int i;
  bpf_for(i, 0, 4) {
    if (!entry) {
      break;
    }
    if (((unsigned long)entry & 3) != 2 || (unsigned long)entry <= 4096) {
      break;
    }

    struct xa_node* node = (struct xa_node*)((unsigned long)entry & ~3UL);
    unsigned char shift;
    bpf_probe_read_kernel(&shift, sizeof(shift), &node->shift);
    unsigned int offset = (index >> shift) & 63;
    bpf_probe_read_kernel(&entry, sizeof(entry), node->slots + offset);
  }

  if (!entry || ((unsigned long)entry & 3)) {
    return NULL;
  }

  struct pid* pid_entry = (struct pid*)entry;
  int root_pid = 0;
  bpf_probe_read_kernel(&root_pid, sizeof(root_pid), &pid_entry->numbers[0].nr);
  return bpf_task_from_pid(root_pid);
}

// The proc superblock yields the namespace as a scalar, so this restores BTF
// trust only after reading the level without dereferencing the scalar.
static __noinline struct task_struct* bpfj_proc_task_from_ns_pid(
    pid_t pid,
    __u64 ns_ptr) {
  if (!ns_ptr) {
    return bpf_task_from_pid(pid);
  }

  __u32 level = 0;
  bpf_probe_read_kernel(
      &level,
      sizeof(level),
      (void*)ns_ptr + offsetof(struct pid_namespace, level));
  if (level == 0) {
    return bpf_task_from_pid(pid);
  }

  struct pid_namespace* ns = bpf_core_cast((void*)ns_ptr, struct pid_namespace);
  return bpfj_task_from_pid_ns(pid, ns);
}

// Find the numeric child of the proc mount root even when the opened file is
// below /proc/<pid>/task/<tid>.
static __noinline long bpfj_proc_pid_from_dentry(__u64 dentry_ptr) {
  uintptr_t current = dentry_ptr;
  uintptr_t pid_dentry = 0;

  __u32 depth;
  bpf_for(depth, 0, BPFJ_PROC_MAX_DEPTH) {
    struct dentry* parent = NULL;
    bpf_probe_read_kernel(
        &parent,
        sizeof(parent),
        (void*)current + offsetof(struct dentry, d_parent));
    if (!parent) {
      break;
    }

    struct dentry* grandparent = NULL;
    bpf_probe_read_kernel(&grandparent, sizeof(grandparent), &parent->d_parent);
    if (parent == grandparent) {
      pid_dentry = current;
      break;
    }
    current = (uintptr_t)parent;
  }

  if (!pid_dentry) {
    return 0;
  }

  const unsigned char* name_ptr = NULL;
  bpf_probe_read_kernel(
      &name_ptr,
      sizeof(name_ptr),
      (void*)pid_dentry + offsetof(struct dentry, d_name) +
          offsetof(struct qstr, name));
  char name[16] = {};
  long len = bpf_probe_read_kernel_str(name, sizeof(name), name_ptr);
  if (len <= 1) {
    return 0;
  }

  long pid = 0;
  if (bpf_strtol(name, len < sizeof(name) ? len : sizeof(name), 10, &pid) < 0 ||
      pid <= 0) {
    return 0;
  }
  return pid;
}

// The trailing return value preserves a denial made by an earlier LSM.
SEC("lsm/file_open")
int BPF_PROG(bpfj_proc_file_open, struct file* file, int lsm_ret) {
  if (lsm_ret || !file) {
    return lsm_ret;
  }

  struct inode* inode = bpf_core_cast((file), typeof(*(file)))->f_inode;
  struct super_block* sb =
      inode ? bpf_core_cast((inode), typeof(*(inode)))->i_sb : NULL;
  const struct super_operations* sops =
      sb ? bpf_core_cast((sb), typeof(*(sb)))->s_op : NULL;
  if (sops != (const struct super_operations*)&proc_sops) {
    return 0;
  }

  struct dentry* dentry = bpf_core_cast((file), typeof(*(file)))->f_path.dentry;
  long pid = dentry ? bpfj_proc_pid_from_dentry((__u64)dentry) : 0;
  if (pid <= 0) {
    return 0;
  }

  // Since Linux 5.6 s_fs_info points at proc_fs_info, whose first member is
  // the pid namespace pointer.
  void* proc_fs_info = bpf_core_cast((sb), typeof(*(sb)))->s_fs_info;
  __u64 pid_ns_ptr = 0;
  if (proc_fs_info) {
    bpf_probe_read_kernel(&pid_ns_ptr, sizeof(pid_ns_ptr), proc_fs_info);
  }

  struct task_struct* target =
      bpfj_proc_task_from_ns_pid((pid_t)pid, pid_ns_ptr);
  struct bpfj_pid_data* actor_data = bpfj_get_current_pid_data();
  struct bpfj_pid_data* target_data = bpfj_get_task_pid_data(target);
  bool allowed =
      bpfj_gate_allowed(BPFJ_POLICY_GATE_PROC, actor_data, target_data);
  if (target) {
    bpf_task_release(target);
  }
  if (allowed) {
    return 0;
  }

  struct bpfj_event* ev = bpfj_event_reserve_current(BPFJ_EVENT_PROC);
  bpfj_event_submit(ev);
  BPFJ_LOG("Denied proc access to pid %ld", pid);
  return -EPERM;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
