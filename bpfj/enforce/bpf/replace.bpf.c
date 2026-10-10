// Copyright (c) Meta Platforms, Inc. and affiliates.

// The backfill half of `bpfjctl replace`. Userspace copies the pods, but task
// storage answers get_next_key with ENOTSUPP, so a task iterator is the only
// way to reach every task's entry. It runs after the new jailer seeded its
// base role, and merges the old membership into that rather than replacing
// it, a base role being a floor rather than an alternative.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/lock.h"
#include "bpfj/lib/bpf/types_heap.h"

// The task map of the jailer being replaced, a second definition of maps.h's
// bpfj_task_map that must stay identical to it; libbpf compares the two before
// adopting, so drift fails the load.
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct bpfj_pid_data);
} bpfj_old_task_map SEC(".maps");

struct bpfj_replace_pod {
  struct bpfj_pod __arena* pod;
};

struct bpfj_replace_pod_key {
  struct bpfj_pod __arena* old_pod;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __uint(max_entries, 1048576);
  __type(key, struct bpfj_replace_pod_key);
  __type(value, struct bpfj_replace_pod);
} bpfj_replace_pods SEC(".maps");

// Tasks that came across with their whole membership intact.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_replace_migrated SEC(".maps");

// Tasks that did not, because the entry could not be allocated or the
// membership did not fit; a non-zero count fails the replace.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_replace_failed SEC(".maps");

// Persisted pod references for which userspace supplied no translation.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_replace_unmapped SEC(".maps");

// Task-storage entries whose persisted value layout this build cannot read.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u64);
} bpfj_replace_incompatible SEC(".maps");

static __always_inline void bpfj_replace_count(void* counter) {
  const __u32 zero = 0;
  __u64* n = bpf_map_lookup_elem(counter, &zero);
  if (n) {
    __sync_fetch_and_add(n, 1);
  }
}

static __always_inline bool bpfj_replace_var_valid(
    const struct bpfj_var __arena* var) {
  if (!var || !var->val || var->id == 0) {
    return false;
  }
  if (var->type == BPFJ_VAR_TYPE_STR) {
    if (var->size >= BPFJ_OSS_VAR_VAL_LEN) {
      return false;
    }
    const char __arena* value = var->val;
    return value[var->size] == '\0';
  }
  return var->type == BPFJ_VAR_TYPE_VSOCK_ADDR &&
      var->size == sizeof(struct vsock_address);
}

static __always_inline bool
bpfj_replace_seq_write(struct seq_file* seq, const void* data, __u32 size) {
  if (bpf_seq_write(seq, data, size) == 0) {
    return true;
  }
  bpfj_replace_count(&bpfj_replace_failed);
  return false;
}

struct bpfj_replace_snapshot_scratch {
  struct bpfj_pod_id pod_id;
  unsigned char value[BPFJ_OSS_VAR_VAL_LEN];
};

// This object and its iterator are private to one replace invocation, so one
// ordinary map value is enough to bridge arena bytes into bpf_seq_write().
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bpfj_replace_snapshot_scratch);
} bpfj_replace_snapshot_scratch SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bpfj_replace_cutover_command);
} bpfj_replace_cutover_command SEC(".maps");

// Invoked once at EOF. The old journal lock makes an empty tail and the
// generation switch one kernel-side linearization point, without exposing a
// userspace lock holder to BPF's bounded acquisition path.
SEC("iter.s/task")
int bpfj_replace_cutover(struct bpf_iter__task* ctx) {
  if (ctx->task) {
    return 0;
  }

  const __u32 zero = 0;
  struct bpfj_replace_cutover_command* command =
      bpf_map_lookup_elem(&bpfj_replace_cutover_command, &zero);
  if (!command) {
    return 0;
  }
  command->result = -EINVAL;

  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  struct bpfj_mutation_journal __arena* journal =
      ctrl ? ctrl->mutation_journal : NULL;
  if (!journal) {
    return 0;
  }

  unsigned long flags;
  if (bpfj_lock_acquire(&journal->lock, &flags)) {
    command->result = -EBUSY;
    return 0;
  }

  if (journal->state != BPFJ_MUTATION_JOURNAL_RECORDING) {
    command->result = -EINVAL;
  } else if (journal->failure == BPFJ_MUTATION_JOURNAL_FULL) {
    command->result = -ENOBUFS;
  } else if (journal->failure == BPFJ_MUTATION_JOURNAL_CONTENDED) {
    command->result = -EDEADLK;
  } else if (journal->failure != BPFJ_MUTATION_JOURNAL_OK) {
    command->result = -EIO;
  } else if (journal->next != command->replayed) {
    command->result = 0;
  } else {
    struct bpfj_generation_control* generation =
        bpf_map_lookup_elem(&bpfj_generation_control, &zero);
    if (!generation || generation->version != BPFJ_GENERATION_CONTROL_VERSION ||
        command->generation == 0) {
      command->result = -EINVAL;
    } else {
      // Publish the new authority first. An old writer that already observed
      // RECORDING is blocked on this lock and rechecks the generation after
      // acquiring it; a writer observing the new generation is passive.
      generation->active_generation = command->generation;
      journal->state = BPFJ_MUTATION_JOURNAL_CLOSING;
      command->result = 1;
    }
  }
  bpfj_lock_release(&journal->lock, &flags);
  return 0;
}

// Snapshot every task-storage pod while the iterator holds the task alive.
// Userspace deduplicates records by old_pod and never dereferences an arena
// pointer after this callback returns.
SEC("iter.s/task")
int bpfj_replace_snapshot(struct bpf_iter__task* ctx) {
  struct task_struct* task = ctx->task;
  if (!task) {
    return 0;
  }

  struct bpfj_pid_data* old = bpfj_get_pid_data_from(&bpfj_task_map, task);
  if (!old) {
    return 0;
  }
  if (old->version != BPFJ_PID_DATA_VERSION ||
      old->num_pods > BPFJ_MAX_POD_PER_PID) {
    bpfj_replace_count(&bpfj_replace_incompatible);
    return 0;
  }

  bpfj_heap_use_arena();
  const __u32 zero = 0;
  struct bpfj_replace_snapshot_scratch* snapshot_scratch =
      bpf_map_lookup_elem(&bpfj_replace_snapshot_scratch, &zero);
  if (!snapshot_scratch) {
    bpfj_replace_count(&bpfj_replace_failed);
    return 0;
  }

  __u32 num_pods = old->num_pods;
  barrier_var(num_pods);
  int i;
  bpf_for(i, 0, BPFJ_MAX_POD_PER_PID) {
    if (i >= num_pods) {
      break;
    }
    struct bpfj_pod __arena* pod = old->pods[i];
    if (!pod || pod->var_array.count > BPFJ_OSS_VAR_MAX ||
        (pod->var_array.count != 0 && !pod->var_array.vars)) {
      bpfj_replace_count(&bpfj_replace_incompatible);
      continue;
    }

    bool valid = true;
    __u32 var_count = pod->var_array.count;
    barrier_var(var_count);
    int at;
    bpf_for(at, 0, BPFJ_OSS_VAR_MAX) {
      if (at >= var_count) {
        break;
      }
      const struct bpfj_var __arena* var = pod->var_array.vars + at;
      if (!bpfj_replace_var_valid(var)) {
        valid = false;
        break;
      }
    }
    if (!valid) {
      bpfj_replace_count(&bpfj_replace_incompatible);
      continue;
    }

    struct bpfj_replace_pod_snapshot snapshot = {
        .magic = BPFJ_REPLACE_SNAPSHOT_MAGIC,
        .version = BPFJ_REPLACE_SNAPSHOT_VERSION,
        .var_count = pod->var_array.count,
        .enrollment_source = pod->enrollment_source,
        .old_pod = (__u64)(unsigned long)pod,
        .creation_time_ns = pod->creation_time_ns,
        .gc_removal_attempts = pod->gc_removal_attempts,
    };
    __builtin_memcpy(
        &snapshot.role_id, &pod->role_id, sizeof(snapshot.role_id));
    __builtin_memcpy(&snapshot.uuid, &pod->uuid, sizeof(snapshot.uuid));
    __builtin_memcpy(
        &snapshot_scratch->pod_id, &pod->pod_id, sizeof(pod->pod_id));

    struct seq_file* seq = ctx->meta->seq;
    if (!bpfj_replace_seq_write(seq, &snapshot, sizeof(snapshot)) ||
        !bpfj_replace_seq_write(
            seq, &snapshot_scratch->pod_id, sizeof(pod->pod_id))) {
      return 0;
    }

    bpf_for(at, 0, BPFJ_OSS_VAR_MAX) {
      if (at >= var_count) {
        break;
      }
      const struct bpfj_var __arena* var = pod->var_array.vars + at;
      struct bpfj_replace_var_snapshot var_snapshot = {
          .id = var->id,
          .type = var->type,
          .size = var->size,
          .reserved = var->reserved,
      };
      __u32 payload_size = var->type == BPFJ_VAR_TYPE_STR
          ? (__u32)var->size + 1
          : sizeof(struct vsock_address);
      barrier_var(payload_size);
      if (payload_size > sizeof(snapshot_scratch->value)) {
        bpfj_replace_count(&bpfj_replace_incompatible);
        return 0;
      }
      const unsigned char __arena* value = var->val;
      int n;
      bpf_for(n, 0, BPFJ_OSS_VAR_VAL_LEN) {
        if (n >= payload_size) {
          break;
        }
        snapshot_scratch->value[n] = value[n];
      }
      if (!bpfj_replace_seq_write(seq, &var_snapshot, sizeof(var_snapshot)) ||
          !bpfj_replace_seq_write(seq, snapshot_scratch->value, payload_size)) {
        return 0;
      }
    }
  }
  return 0;
}

/// Whether `pid_data` already names `pod`.
static __always_inline bool bpfj_replace_holds(
    struct bpfj_pid_data* pid_data,
    struct bpfj_pod __arena* pod) {
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  barrier_var(num_pods);

  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    if (bpfj_pod_ptr_cmp(pid_data->pods[i], pod) == 0) {
      return true;
    }
  }

  return false;
}

/// Add `pod` to `pid_data` and take a reference on it.
/// @return false if there was no room, the caller's cue to fail the replace
///         rather than let the task through with a narrower jail.
static __always_inline bool bpfj_replace_add(
    struct bpfj_pid_data* pid_data,
    struct bpfj_pod __arena* pod) {
  __u32 slot = pid_data->num_pods;
  if (slot >= BPFJ_MAX_POD_PER_PID) {
    return false;
  }
  barrier_var(slot);
  pid_data->pods[slot] = pod;
  pid_data->num_pods = slot + 1;

  // After the write, so the reference is only taken once the entry naming
  // the pod is holding it.
  bpfj_pod_refs_inc(pod);
  return true;
}

// Sleepable so creating a task storage entry allocates with GFP_KERNEL; a
// non-sleepable iterator uses kmalloc_nolock, which can fail on trylock
// contention alone and leave a task unjailed.
SEC("iter.s/task")
int bpfj_replace_backfill(struct bpf_iter__task* ctx) {
  struct task_struct* task = ctx->task;
  if (!task) {
    // The final call of the walk carries no task.
    return 0;
  }

  struct bpfj_pid_data* old = bpfj_get_pid_data_from(&bpfj_old_task_map, task);
  if (!old) {
    return 0;
  }

  if (old->version != BPFJ_PID_DATA_VERSION) {
    bpfj_replace_count(&bpfj_replace_incompatible);
    bpfj_replace_count(&bpfj_replace_failed);
    return 0;
  }

  // Usually already there holding the base role this tree seeded, and
  // created empty for a task the new base role does not cover.
  struct bpfj_pid_data* new_data =
      bpfj_set_pid_data_in(&bpfj_task_map, task, NULL);
  if (!new_data) {
    bpfj_replace_count(&bpfj_replace_failed);
    return 0;
  }

  if (old->num_pods > BPFJ_MAX_POD_PER_PID ||
      new_data->num_pods > BPFJ_MAX_POD_PER_PID) {
    bpfj_replace_count(&bpfj_replace_incompatible);
    bpfj_replace_count(&bpfj_replace_failed);
    return 0;
  }
  __u32 num_pods = old->num_pods;
  barrier_var(num_pods);

  bool lost = false;
  __u32 needed = 0;
  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    struct bpfj_pod __arena* old_pod = old->pods[i];
    if (!old_pod) {
      bpfj_replace_count(&bpfj_replace_incompatible);
      lost = true;
      continue;
    }

    for (int before = 0; before < BPFJ_MAX_POD_PER_PID; ++before) {
      if (before >= i) {
        break;
      }
      if (bpfj_pod_ptr_cmp(old->pods[before], old_pod) == 0) {
        bpfj_replace_count(&bpfj_replace_incompatible);
        lost = true;
      }
    }

    struct bpfj_replace_pod_key key = {.old_pod = old_pod};
    struct bpfj_replace_pod* translated =
        bpf_map_lookup_elem(&bpfj_replace_pods, &key);
    if (!translated) {
      bpfj_replace_count(&bpfj_replace_unmapped);
      lost = true;
      continue;
    }
    // Userspace records the old base-role pod as an intentional tombstone:
    // the new tree has already seeded its replacement.
    if (!translated->pod) {
      continue;
    }

    if (bpfj_replace_holds(new_data, translated->pod)) {
      continue;
    }
    ++needed;
  }

  if (needed > BPFJ_MAX_POD_PER_PID - new_data->num_pods) {
    lost = true;
  }
  if (lost) {
    bpfj_replace_count(&bpfj_replace_failed);
    return 0;
  }

  // A second pass makes migration transactional per task: no partial
  // membership is published when validation above found an unmapped pod.
  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }
    struct bpfj_replace_pod_key key = {.old_pod = old->pods[i]};
    struct bpfj_replace_pod* translated =
        bpf_map_lookup_elem(&bpfj_replace_pods, &key);
    if (!translated || !translated->pod ||
        bpfj_replace_holds(new_data, translated->pod)) {
      continue;
    }
    if (!bpfj_replace_add(new_data, translated->pod)) {
      bpfj_replace_count(&bpfj_replace_failed);
      return 0;
    }
  }

  bpfj_replace_count(&bpfj_replace_migrated);
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
