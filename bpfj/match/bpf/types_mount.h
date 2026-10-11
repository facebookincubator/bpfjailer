#pragma once

#include "bpfj/lib/bpf/types_const_map.h"
#include "bpfj/lib/bpf/types_lock.h"
#include "bpfj/lib/bpf/types_shared_ptr.h"

#define BPFJ_MOUNT_MAX_LOAD_RETRIES 4
#define BPFJ_MOUNT_MAX_TREE_BREADTH 128
#define BPFJ_MOUNT_MAX_MOUNTS 1048576
#define BPFJ_MOUNT_OLD_MAX_TREE_BREADTH 32
#define BPFJ_MOUNT_OLD_MAX_MOUNTS 512

struct bpfj_mount_key {
  struct dentry* dentry;
};

struct bpfj_mount_lock {
  __u64 ns_ino;
  __u32 seqlock;
};

struct bpfj_mount_val {
  struct mount* mount;
};

// The canonical transition for one root dentry. During construction duplicate
// roots retain the transition with the lowest mount ID, excluding later bind
// aliases from path walks.
struct bpfj_mount_snapshot_value {
  __u64 parent_vfsmount;
  __u64 mountpoint;
  __u64 mount_id;
};

struct bpfj_mount_snapshot {
  __u64 mount_generation;
  struct bpfj_const_map roots;
};

// Stable storage supplied by the caller. The shared pointer lets a generation
// be replaced while a path walk still holds the previous immutable snapshot.
struct bpfj_mount_cache {
  struct bpfj_lock lock;
  __u32 reserved;
  __u64 ns_ino;
  struct bpfj_shared_ptr snapshot;
};

// The namespace selected by one policy walk.
struct bpfj_mount_descriptor {
  __u64 ns_ino;
  __u64 namespace_addr;
  __u64 mount_generation;
};

struct bpfj_mount_fallback {
  __u64 parent_vfsmount;
  __u64 mountpoint;
};
