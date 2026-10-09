// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpfj/match/bpf/mount.h"

long ret;
long first_ret;
long second_ret;
__u32 final_size;
__u64 first_parent;
__u64 first_mountpoint;
__u64 second_parent;
__u64 second_mountpoint;

SEC("syscall")
int bpfj_mount_snapshot_test(void* ctx) {
  (void)ctx;
  bpfj_heap_use_arena();

  const __u32 map_bytes = bpfj_const_map_allocation_size(
      3, sizeof(__u64), sizeof(struct bpfj_mount_snapshot_value));
  const __u32 bytes =
      (__u32) __builtin_offsetof(struct bpfj_mount_snapshot, roots) + map_bytes;
  struct bpfj_mount_snapshot __arena* snapshot = BPFJ_HEAP_ALLOC(bytes);
  if (!snapshot) {
    return -ENOMEM;
  }
  ret = bpfj_const_map_init(
      &snapshot->roots,
      3,
      sizeof(__u64),
      sizeof(struct bpfj_mount_snapshot_value));
  if (ret < 0) {
    BPFJ_HEAP_FREE(snapshot);
    return 0;
  }
  struct bpfj_mount_fallback __arena* fallback =
      BPFJ_HEAP_ALLOC(sizeof(*fallback));
  if (!fallback) {
    BPFJ_HEAP_FREE(snapshot);
    return -ENOMEM;
  }

  ret = bpfj_mount_snapshot_insert(snapshot, 0x100, 20, 200, 20);
  if (ret == 0) {
    ret = bpfj_mount_snapshot_insert(snapshot, 0x100, 30, 300, 30);
  }
  if (ret == 0) {
    ret = bpfj_mount_snapshot_insert(snapshot, 0x100, 10, 100, 10);
  }
  if (ret == 0) {
    ret = bpfj_mount_snapshot_insert(snapshot, 0x200, 40, 400, 40);
  }
  if (ret == 0) {
    ret = bpfj_const_map_seal(&snapshot->roots);
  }

  if (ret == 0) {
    first_ret = bpfj_mount_find_parent(snapshot, 0x100, fallback);
    first_parent = fallback->parent_vfsmount;
    first_mountpoint = fallback->mountpoint;
    second_ret = bpfj_mount_find_parent(snapshot, 0x200, fallback);
    second_parent = fallback->parent_vfsmount;
    second_mountpoint = fallback->mountpoint;
    final_size = snapshot->roots.size;
  }

  BPFJ_HEAP_FREE(fallback);
  BPFJ_HEAP_FREE(snapshot);
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
