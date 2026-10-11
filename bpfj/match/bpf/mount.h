#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/const_map.h"
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/lock.h"
#include "bpfj/lib/bpf/shared_ptr.h"
#include "bpfj/match/bpf/matcher_state.h"
#include "bpfj/match/bpf/types_mount.h"

extern const void mount_lock __ksym;

// The global mount lock protects the mount tree while it is changing. It is
// only a consistency sequence for snapshot construction. Cache generations
// come from the root mount namespace's own event counter.
__noinline u32 bpfj_mount_seqcount() {
  return BPF_CORE_READ(
      ((const seqlock_t*)&mount_lock), seqcount.seqcount.sequence);
}

static __always_inline uintptr_t bpfj_ptr_to_scalar(const void* ptr) {
  uintptr_t out = 0;
  bpf_probe_read_kernel(&out, sizeof(out), &ptr);
  return out;
}

static __always_inline void bpfj_mount_task_cleanup(struct task_struct** task) {
  if (task && *task) {
    bpf_task_release(*task);
  }
}

static __noinline __u64 bpfj_mount_root_generation(void) {
  struct bpfj_matcher_state* state = bpfj_matcher_state_get();
  uintptr_t namespace_addr = state ? state->init_mount_namespace : 0;
  struct mnt_namespace* ns = namespace_addr
      ? bpf_core_cast((void*)namespace_addr, struct mnt_namespace)
      : NULL;
  if (ns) {
    return ns->event;
  }

  __attribute((cleanup(bpfj_mount_task_cleanup))) struct task_struct* task =
      bpf_task_from_pid(1);
  if (!task) {
    return 0;
  }
  struct task_struct* init_task = bpf_core_cast(task, struct task_struct);
  struct nsproxy* nsproxy = init_task->nsproxy;
  if (!nsproxy) {
    return 0;
  }
  ns = bpf_core_cast(nsproxy, struct nsproxy)->mnt_ns;
  if (!ns) {
    return 0;
  }
  if (state) {
    __sync_val_compare_and_swap(&state->init_mount_namespace, 0, (uintptr_t)ns);
  }
  return ns->event;
}

static __always_inline long bpfj_mount_snapshot_insert(
    struct bpfj_mount_snapshot __arena* snapshot,
    __u64 root,
    __u64 parent_vfsmount,
    __u64 mountpoint,
    __u64 mount_id) {
  if (!root) {
    return -EINVAL;
  }
  long plan = bpfj_const_map_insert_u64(&snapshot->roots, root);
  if (plan < 0) {
    return plan;
  }

  struct bpfj_mount_snapshot_value __arena* value = bpfj_const_map_value_at(
      &snapshot->roots, BPFJ_CONST_MAP_PLAN_INDEX(plan));
  if (!value) {
    return -EFAULT;
  }
  if (BPFJ_CONST_MAP_PLAN_KIND(plan) == BPFJ_CONST_MAP_INSERTED ||
      mount_id < value->mount_id) {
    value->parent_vfsmount = parent_vfsmount;
    value->mountpoint = mountpoint;
    value->mount_id = mount_id;
  }
  return 0;
}

__noinline long bpfj_mount_snapshot_visit(
    struct bpfj_mount_snapshot __arena* snapshot __arg_arena,
    struct rb_node * __arena * nodes __arg_arena,
    int depth) {
  int pos = depth - 1;
  struct rb_node* node = nodes[pos--];
  struct mount* mount = container_of(node, struct mount, mnt_node);
  struct rb_node* right = BPF_CORE_READ(node, rb_right);
  struct rb_node* left = BPF_CORE_READ(node, rb_left);

  if (right) {
    ++pos;
    barrier_var(pos);
    if (pos >= 0 && pos < BPFJ_MOUNT_MAX_TREE_BREADTH) {
      nodes[pos] = right;
    }
  }
  if (pos >= BPFJ_MOUNT_MAX_TREE_BREADTH) {
    return -E2BIG;
  }
  if (left) {
    ++pos;
    barrier_var(pos);
    if (pos >= 0 && pos < BPFJ_MOUNT_MAX_TREE_BREADTH) {
      nodes[pos] = left;
    }
  }
  if (pos >= BPFJ_MOUNT_MAX_TREE_BREADTH) {
    return -E2BIG;
  }

  struct mount* parent = BPF_CORE_READ(mount, mnt_parent);
  long ret = bpfj_mount_snapshot_insert(
      snapshot,
      (uintptr_t)BPF_CORE_READ(mount, mnt.mnt_root),
      parent ? (uintptr_t)&parent->mnt : 0,
      (uintptr_t)BPF_CORE_READ(mount, mnt_mountpoint),
      BPF_CORE_READ(mount, mnt_id_unique));
  return ret < 0 ? ret : pos + 1;
}

static __noinline long bpfj_mount_snapshot_build(
    uintptr_t namespace_i,
    __u64 mount_generation,
    __u32 mount_sequence,
    struct bpfj_shared_ptr* out) {
  struct mnt_namespace* ns = (struct mnt_namespace*)namespace_i;
  __u32 mounts = BPF_CORE_READ(ns, nr_mounts);
  if (mounts > BPFJ_MOUNT_MAX_MOUNTS) {
    return -E2BIG;
  }

  __u32 map_bytes = bpfj_const_map_allocation_size(
      mounts, sizeof(__u64), sizeof(struct bpfj_mount_snapshot_value));
  if (map_bytes == 0 ||
      map_bytes > BPFJ_HEAP_MAX_ARENA_SIZE -
              (__u32) __builtin_offsetof(struct bpfj_mount_snapshot, roots)) {
    return -E2BIG;
  }
  __u32 bytes =
      (__u32) __builtin_offsetof(struct bpfj_mount_snapshot, roots) + map_bytes;

  *out = bpfj_shared_ptr_make(bytes);
  if (!bpfj_shared_ptr_valid(*out)) {
    return -ENOMEM;
  }
  struct bpfj_mount_snapshot __arena* snapshot = out->buf;
  snapshot->mount_generation = mount_generation;
  long ret = bpfj_const_map_init(
      &snapshot->roots,
      mounts,
      sizeof(__u64),
      sizeof(struct bpfj_mount_snapshot_value));
  if (ret < 0) {
    bpfj_shared_ptr_release(out);
    return ret;
  }

  __attribute((cleanup(bpfj_heap_free_ptr))) void __arena* stack_buf =
      BPFJ_HEAP_ALLOC(sizeof(struct rb_node*) * BPFJ_MOUNT_MAX_TREE_BREADTH);
  if (!stack_buf) {
    bpfj_shared_ptr_release(out);
    return -ENOMEM;
  }
  struct rb_node* __arena* nodes = stack_buf;
  nodes[0] = BPF_CORE_READ(ns, mounts.rb_node);
  long depth = nodes[0] ? 1 : 0;
  __u32 visited = 0;
  __u32 i = 0;
  bpf_for(i, 0, BPFJ_MOUNT_MAX_MOUNTS) {
    if (depth <= 0 || depth > BPFJ_MOUNT_MAX_TREE_BREADTH) {
      break;
    }
    depth = bpfj_mount_snapshot_visit(snapshot, nodes, (int)depth);
    if (depth < 0) {
      break;
    }
    ++visited;
  }

  ret = depth < 0 ? depth : 0;
  // A concurrent mount-tree update can change both the traversal shape and
  // nr_mounts. Retry any result from a stale generation, including apparent
  // breadth overflow, rather than reporting a permanent policy error.
  if ((mount_sequence & 1) != 0 || mount_sequence != bpfj_mount_seqcount() ||
      mount_generation != BPF_CORE_READ(ns, event)) {
    ret = -EBUSY;
  } else if (ret == 0 && visited != mounts) {
    ret = -EIO;
  }
  if (ret == 0) {
    ret = bpfj_const_map_seal(&snapshot->roots);
  }
  if (ret < 0) {
    bpfj_shared_ptr_release(out);
    return ret;
  }
  return 0;
}

// Resolve the target namespace and acquire an immutable snapshot from the
// caller-owned cache, replacing a stale generation without disturbing walks
// that still hold it.
__noinline long bpfj_mount_load(
    struct bpfj_mount_cache __arena* cache __arg_arena,
    pid_t pid,
    struct bpfj_mount_descriptor __arena* descriptor __arg_arena,
    struct bpfj_shared_ptr __arena* out __arg_arena) {
  descriptor->ns_ino = 0;
  descriptor->namespace_addr = 0;
  descriptor->mount_generation = 0;
  out->buf = NULL;
  out->refcount = NULL;
  if (!cache) {
    return -EINVAL;
  }

  __attribute((cleanup(bpfj_mount_task_cleanup))) struct task_struct* task =
      bpf_task_from_pid(pid);
  if (!task) {
    return -ESRCH;
  }
  struct mnt_namespace* ns = BPF_CORE_READ(task, nsproxy, mnt_ns);
  if (!ns) {
    return -ESRCH;
  }

  __u64 ns_ino = BPF_CORE_READ(ns, ns.inum);
  __u64 generation = BPF_CORE_READ(ns, event);
  {
    BPFJ_LOCK_GUARD(guard, &cache->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(guard)) {
      return -EBUSY;
    }
    struct bpfj_mount_snapshot __arena* snapshot = cache->snapshot.buf;
    if (cache->ns_ino == ns_ino && snapshot &&
        snapshot->mount_generation == generation &&
        generation == BPF_CORE_READ(ns, event)) {
      struct bpfj_shared_ptr acquired =
          bpfj_shared_ptr_acquire_arena(&cache->snapshot);
      out->buf = acquired.buf;
      out->refcount = acquired.refcount;
      descriptor->ns_ino = ns_ino;
      descriptor->mount_generation = generation;
      descriptor->namespace_addr = (uintptr_t)ns;
      return (long)ns_ino;
    }
  }

  struct bpfj_shared_ptr built = {0};
  __u32 mount_sequence = bpfj_mount_seqcount();
  long ret = bpfj_mount_snapshot_build(
      (uintptr_t)ns, generation, mount_sequence, &built);
  if (ret < 0) {
    return ret;
  }
  if (generation != BPF_CORE_READ(ns, event)) {
    bpfj_shared_ptr_release(&built);
    return -EBUSY;
  }

  struct bpfj_shared_ptr retired = {0};
  {
    BPFJ_LOCK_GUARD(guard, &cache->lock);
    if (!BPFJ_LOCK_IS_ACQUIRED(guard)) {
      bpfj_shared_ptr_release(&built);
      return -EBUSY;
    }
    struct bpfj_mount_snapshot __arena* current = cache->snapshot.buf;
    if (generation != BPF_CORE_READ(ns, event)) {
      bpfj_shared_ptr_release(&built);
      return -EBUSY;
    }
    if (cache->ns_ino == ns_ino && current &&
        current->mount_generation == generation) {
      struct bpfj_shared_ptr acquired =
          bpfj_shared_ptr_acquire_arena(&cache->snapshot);
      out->buf = acquired.buf;
      out->refcount = acquired.refcount;
    } else {
      retired = bpfj_shared_ptr_take_arena(&cache->snapshot);
      cache->ns_ino = ns_ino;
      cache->snapshot.buf = built.buf;
      cache->snapshot.refcount = built.refcount;
      built.buf = NULL;
      built.refcount = NULL;
      struct bpfj_shared_ptr acquired =
          bpfj_shared_ptr_acquire_arena(&cache->snapshot);
      out->buf = acquired.buf;
      out->refcount = acquired.refcount;
    }
  }
  bpfj_shared_ptr_release(&retired);
  bpfj_shared_ptr_release(&built);

  descriptor->ns_ino = ns_ino;
  descriptor->mount_generation = generation;
  descriptor->namespace_addr = (uintptr_t)ns;
  return (long)ns_ino;
}

// Lookup the canonical transition for a true filesystem or subvolume root.
static __always_inline long bpfj_mount_find_parent(
    struct bpfj_mount_snapshot __arena* snapshot __arg_arena,
    uintptr_t root_i,
    struct bpfj_mount_fallback __arena* out __arg_arena) {
  out->parent_vfsmount = 0;
  out->mountpoint = 0;
  if (!snapshot || !root_i) {
    return -EINVAL;
  }

  long index = bpfj_const_map_lookup_u64(&snapshot->roots, root_i);
  if (index < 0) {
    return index;
  }
  struct bpfj_mount_snapshot_value __arena* value =
      bpfj_const_map_value_at(&snapshot->roots, (__u32)index);
  if (!value) {
    return -EFAULT;
  }
  out->parent_vfsmount = value->parent_vfsmount;
  out->mountpoint = value->mountpoint;
  return 0;
}
