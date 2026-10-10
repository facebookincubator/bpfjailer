// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/str_map.h"
#include "bpfj/var/bpf/types_var.h"

// The jail membership maps, shared by every BPF object in the open source
// jailer. Each including object gets its own definition and the pin is what
// joins them, so a definition that drifts fails pin adoption rather than
// silently splitting the jail in two. These layouts must also match
// bpfjailer/enforce/bpf/maps.h, the ABI the internal tree shares.

// Which pods a task belongs to. Every task carries its own entry, threads
// included, unlike the internal jailer's leader-only model
// (bpf_enforcer_constraints.md), so a thread that execs keeps its entry through
// de_thread() and the task carrying the jail never dies under the survivor.
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct bpfj_pid_data);
} bpfj_task_map SEC(".maps");

// A replace gives both trees this one control map. Their task, policy and
// ownership maps remain separate; the active generation is only the atomic
// authority switch after those maps have been populated.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bpfj_generation_control);
} bpfj_generation_control SEC(".maps");

static __always_inline bool bpfj_generation_is_active(void) {
  if (!bpfj_heap_enabled) {
    return false;
  }
  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  if (!ctrl || ctrl->generation == 0) {
    return false;
  }

  const __u32 zero = 0;
  const struct bpfj_generation_control* control =
      bpf_map_lookup_elem(&bpfj_generation_control, &zero);
  return control && control->version == BPFJ_GENERATION_CONTROL_VERSION &&
      control->active_generation == ctrl->generation;
}

// A userspace-only flag raised while `replace` is copying membership out of
// this tree, so bpfjctl enroll, wrap and bpfjsrv refuse to add pods the new
// tree would miss. A one-slot array rather than rodata because the tree being
// replaced and the tree replacing it can disagree.
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u8);
} bpfj_replace_frozen SEC(".maps");

static __always_inline bool bpfj_replacement_is_frozen(void) {
  const __u32 zero = 0;
  const __u8* frozen = bpf_map_lookup_elem(&bpfj_replace_frozen, &zero);
  return frozen && *frozen != 0;
}

// Userspace enrollments currently in flight, keyed by their process id. A
// replace raises bpfj_replace_frozen and then waits for this map to empty, so
// an enrollment already past the flag check still finishes before the copy.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u8);
} bpfj_active_enrolls SEC(".maps");

// Structured enforcer events for bpfjlog, shared host-wide through the pin.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1);
} bpfj_event_map SEC(".maps");

// bpfj_heap_arena / bpfj_heap_ctrl come from bpfj/lib/bpf/heap.h. Role
// policies and variable names are immutable arena graphs rooted there.

// A pod is owned by the task-map entries that name it, one reference per pod
// pointer, so it outlives its enroller for as long as some descendant is still
// jailed.
// Nothing else removes a pod, and several CPUs write the counter at once.

static __always_inline void bpfj_pod_refs_inc(struct bpfj_pod __arena* pod) {
  __sync_fetch_and_add(&pod->refs, 1);
}

static __always_inline void bpfj_pod_refs_dec(struct bpfj_pod __arena* pod) {
  // The pre-subtraction value, so 1 is the last reference; re-reading
  // pod->refs would let two concurrent putters both decide they were last.
  if (__sync_fetch_and_sub(&pod->refs, 1) <= 1) {
    if (bpfj_heap_enabled) {
      BPFJ_HEAP_FREE(pod);
    }
  }
}

/// Whether two pod pointers name the same pod. Zero when they do, as memcmp.
static __always_inline int bpfj_pod_ptr_cmp(
    const struct bpfj_pod __arena* a,
    const struct bpfj_pod __arena* b) {
  return a != b;
}

static __always_inline const struct bpfj_role_policy __arena*
bpfj_policy_lookup(const struct bpfj_role_id* role_id) {
  if (!role_id || !bpfj_heap_enabled) {
    return NULL;
  }
  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  const struct bpfj_str_map __arena* policies = ctrl->role_policies;
  void __arena* policy = NULL;
  if (bpfj_str_map_lookup_strlen(policies, role_id->id, ROLE_ID_LEN, &policy) !=
      0) {
    return NULL;
  }
  return (const struct bpfj_role_policy __arena*)policy;
}

struct bpfj_role_set_search {
  const struct bpfj_role_set __arena* set;
  const struct bpfj_role_policy __arena* policy;
  __u8 found;
};

static long bpfj_role_set_search_cb(__u32 index, void* data) {
  struct bpfj_role_set_search* search = data;
  if (search->set->policies[index] == search->policy) {
    search->found = 1;
    return 1;
  }
  return 0;
}

static __always_inline bool bpfj_role_set_contains(
    const struct bpfj_role_set __arena* set,
    const struct bpfj_role_policy __arena* policy) {
  if (!set || !policy) {
    return false;
  }
  struct bpfj_role_set_search search = {
      .set = set,
      .policy = policy,
  };
  bpf_loop(set->count, bpfj_role_set_search_cb, &search, 0);
  return search.found;
}

static __always_inline const struct bpfj_role_policy __arena* bpfj_pod_policy(
    const struct bpfj_pod __arena* pod) {
  return pod ? pod->policy : NULL;
}

static __always_inline void bpfj_pod_read_role_id(
    struct bpfj_role_id* out,
    const struct bpfj_pod __arena* pod) {
  __builtin_memcpy(out, &pod->role_id, sizeof(*out));
}

static __always_inline void bpfj_pod_read_uuid(
    struct bpfj_uuid* out,
    const struct bpfj_pod __arena* pod) {
  __builtin_memcpy(out, &pod->uuid, sizeof(*out));
}

/// @brief Whether `role_id` terminates a pod-stack walk, so the roles stacked
/// under it get no say. bpfj_pid_data::pods runs oldest first with the base
/// role at slot 0, so actor walks run backwards and break on the first
/// override role; the walk over a target's roles, bpfj_gate_covers(), ignores
/// the flag, or a target could shed a restriction by holding one.
static __always_inline bool bpfj_is_override(
    const struct bpfj_pod __arena* pod) {
  const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
  return policy && (policy->flags & BPFJ_POLICY_OVERRIDE_STACKED);
}

/// @brief `task`'s jail membership, or NULL if it is not jailed; `task` must be
/// a trusted pointer, the current task or a hook argument.
static __always_inline struct bpfj_pid_data* bpfj_get_task_pid_data(
    struct task_struct* task) {
  if (!task || !bpfj_generation_is_active()) {
    return NULL;
  }

  if (bpfj_heap_enabled) {
    bpfj_heap_use_arena();
  }
  return bpf_task_storage_get(&bpfj_task_map, task, NULL, 0);
}

/// Name `pod` in `pid_data`, if it does not already and there is room. Returns
/// whether the entry changed, which is exactly when the caller owes the pod a
/// reference -- taken after this call, since one taken first and handed back
/// on a refusal would free the pod under its creator.
static __always_inline bool bpfj_pid_data_add_pod(
    struct bpfj_pid_data* pid_data,
    struct bpfj_pod __arena* pod) {
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  // A second naming would take a reference nothing ever gives back.
  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }
    if (bpfj_pod_ptr_cmp(pid_data->pods[i], pod) == 0) {
      return false;
    }
  }

  if (num_pods >= BPFJ_MAX_POD_PER_PID) {
    return false;
  }

  // The mask alone is not enough: clang drops the check as redundant, but the
  // verifier does not always carry the range this far, so barrier_var makes
  // the index opaque and keeps the check below in the object.
  __u32 slot = num_pods & (BPFJ_MAX_POD_PER_PID - 1);
  barrier_var(slot);
  if (slot >= BPFJ_MAX_POD_PER_PID) {
    return false;
  }

  pid_data->version = BPFJ_PID_DATA_VERSION;
  pid_data->pods[slot] = pod;
  pid_data->num_pods = num_pods + 1;
  return true;
}

/// The calling task's jail membership, or NULL if it is not jailed.
static __always_inline struct bpfj_pid_data* bpfj_get_current_pid_data(void) {
  return bpfj_get_task_pid_data(bpf_get_current_task_btf());
}

/// @brief The newest pod named by `pid_data`, or NULL when it names none or
/// the pod itself has already disappeared.
static __always_inline struct bpfj_pod __arena* bpfj_get_primary_pod(
    struct bpfj_pid_data* pid_data) {
  if (!pid_data || pid_data->num_pods == 0) {
    return NULL;
  }

  __u32 index = pid_data->num_pods - 1;
  if (index >= BPFJ_MAX_POD_PER_PID) {
    index = BPFJ_MAX_POD_PER_PID - 1;
  }

  return pid_data->pods[index];
}

/// @brief Reserve one structured event in the shared ring buffer and seed its
/// common fields. Returns NULL if the ring buffer is full or no pod is known.
static __always_inline struct bpfj_event* bpfj_event_reserve(
    enum bpfj_event_type type,
    struct bpfj_pod __arena* pod,
    struct task_struct* task) {
  if (!pod || !task) {
    return NULL;
  }

  struct bpfj_event* ev = bpf_ringbuf_reserve(&bpfj_event_map, sizeof(*ev), 0);
  if (!ev) {
    return NULL;
  }

  ev->type = type;
  __builtin_memcpy(&ev->pod, pod, sizeof(*pod));
  ev->pid = task->tgid;
  ev->tid = task->pid;
  ev->timestamp_ns = bpf_ktime_get_ns();
  return ev;
}

/// @brief Reserve an event for the calling task's newest pod.
static __always_inline struct bpfj_event* bpfj_event_reserve_current(
    enum bpfj_event_type type) {
  struct task_struct* task = bpf_get_current_task_btf();
  return bpfj_event_reserve(
      type, bpfj_get_primary_pod(bpfj_get_current_pid_data()), task);
}

static __always_inline void bpfj_event_submit(struct bpfj_event* ev) {
  if (ev) {
    bpf_ringbuf_submit(ev, BPF_RB_FORCE_WAKEUP);
  }
}

/// @brief Release the reference `pid_data` holds on each pod it names, leaving
/// the entry alone for the caller to delete or overwrite.
static __always_inline void bpfj_put_pid_data_refs(
    struct bpfj_pid_data* pid_data) {
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    struct bpfj_pod __arena* pod = pid_data->pods[i];
    if (pod) {
      bpfj_pod_refs_dec(pod);
    }
  }
}

/// @brief bpfj_get_task_pid_data against a caller-named task map, for
/// `replace`, which reaches the tree it is building and the one it is
/// migrating off at once. __always_inline is what makes the map argument
/// legal, the verifier wanting it resolved where it is used.
static __always_inline struct bpfj_pid_data* bpfj_get_pid_data_from(
    void* task_map,
    struct task_struct* task) {
  if (bpfj_heap_enabled) {
    bpfj_heap_use_arena();
  }
  return bpf_task_storage_get(task_map, task, NULL, 0);
}

/// @brief Create `task`'s entry in `task_map`, seeded with `init` or zeroed if
/// it is NULL.
/// @return The stored copy, or NULL if the allocation failed.
static __always_inline struct bpfj_pid_data* bpfj_set_pid_data_in(
    void* task_map,
    struct task_struct* task,
    struct bpfj_pid_data* init) {
  if (bpfj_heap_enabled) {
    bpfj_heap_use_arena();
  }
  return bpf_task_storage_get(
      task_map, task, init, BPF_LOCAL_STORAGE_GET_F_CREATE);
}
