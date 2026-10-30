// Copyright (c) Meta Platforms, Inc. and affiliates.

// BPF object ownership. CAP_BPF is all or nothing, so every map and program a
// permitted role creates is recorded with its role and pod. Missing policy
// denies bpf(2); pod, role-list and any modes progressively widen access.
// `untracked-bpf: true` leaves created objects unowned, which a permissive base
// role needs to avoid claiming every BPF object on the host.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/mutation_journal.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging_bpf.h"

// Userspace flips this through the mmap-backed BSS only after the syscall
// link is pinned. Until then the program must not deny the bpf(2) calls that
// make its own attachment persistent.
bool bpfj_bpf_enforcing;

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, __u8);
} bpfj_bpf_loader_tasks SEC(".maps");

static __always_inline bool bpfj_bpf_is_loader(void) {
  struct task_struct* current = bpf_get_current_task_btf();
  return bpf_task_storage_get(&bpfj_bpf_loader_tasks, current, NULL, 0) != NULL;
}

extern void bpf_prog_fops __ksym;
extern void bpf_map_fops __ksym;

// Keyed on the kernel address of the object rather than its id; see struct
// bpfj_bpf_owner in types.h. A replace carries both maps across, since the
// seeding walk below only sees objects some task holds an fd to and a pinned
// map is held by its pin. Arena runtime metadata records whether a replace
// can carry the records across.
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u64);
  __type(value, struct bpfj_bpf_owner);
} bpfj_bpf_map_owners SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1);
  __type(key, __u64);
  __type(value, struct bpfj_bpf_owner);
} bpfj_bpf_prog_owners SEC(".maps");

/// Whether every role the caller holds permits bpf(2).
static __always_inline bool bpfj_bpf_syscall_allowed(
    struct bpfj_pid_data* pid_data) {
  if (!pid_data) {
    // Not jailed, so no policy applies.
    return true;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  if (num_pods == 0) {
    return false;
  }

  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod __arena* pod = pid_data->pods[i];
    if (!pod) {
      continue;
    }

    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy || policy->bpf_mode == BPFJ_POLICY_DENY) {
      return false;
    }

    if (bpfj_is_override(pod)) {
      break;
    }
  }

  return true;
}

/// The role and pod that own what this caller creates, or NULL if nothing
/// should be recorded.
static __always_inline bool bpfj_bpf_owning_role(
    struct bpfj_pid_data* pid_data,
    struct bpfj_bpf_owner* out) {
  if (!pid_data) {
    return false;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }

  // Newest role first, so a specific role owns what it creates rather than the
  // base role every process on the host also holds.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod __arena* pod = pid_data->pods[i];
    if (!pod) {
      continue;
    }

    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy) {
      return false;
    }
    if (policy->bpf_mode != BPFJ_POLICY_DENY &&
        !(policy->flags & BPFJ_POLICY_BPF_UNTRACKED)) {
      __builtin_memcpy(
          &out->role,
          (const struct bpfj_role_id*)&policy->role_id,
          sizeof(out->role));
      bpfj_pod_read_uuid(&out->pod, pod);
      out->policy = policy;
      return true;
    }

    if (bpfj_is_override(pod)) {
      break;
    }
  }

  return false;
}

/// Whether every role the caller holds may open an object owned by `owner`.
static __always_inline bool bpfj_bpf_uuid_equal(
    const struct bpfj_uuid* a,
    const struct bpfj_uuid* b) {
  const __u64* aw = (const __u64*)a->uuid;
  const __u64* bw = (const __u64*)b->uuid;
  return aw[0] == bw[0] && aw[1] == bw[1];
}

static __always_inline bool bpfj_bpf_uuid_is_zero(
    const struct bpfj_uuid* uuid) {
  const __u64* words = (const __u64*)uuid->uuid;
  return words[0] == 0 && words[1] == 0;
}

static __always_inline bool bpfj_bpf_access_allowed(
    struct bpfj_pid_data* pid_data,
    const struct bpfj_bpf_owner* owner) {
  if (!pid_data) {
    return true;
  }

  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  if (num_pods == 0) {
    return false;
  }

  bool granted = false;
  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod __arena* pod = pid_data->pods[i];
    if (!pod) {
      continue;
    }

    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy) {
      return false;
    }
    if (policy->bpf_mode == BPFJ_POLICY_DENY) {
      return false;
    }
    if (!owner && (policy->flags & BPFJ_POLICY_BPF_UNTRACKED)) {
      // The fd for an object created by an untracked role is checked after
      // the create hook deliberately left it unowned. Preserve that role's
      // ability to use unowned objects without letting it reach jailed ones.
      granted = true;
      if (bpfj_is_override(pod)) {
        break;
      }
      continue;
    }
    if (owner && policy->bpf_mode == BPFJ_POLICY_ANY &&
        (policy->flags & BPFJ_POLICY_BPF_UNTRACKED)) {
      // An untracked permissive base role may operate on host-owned objects,
      // but abstains from the gate for objects a jailed role owns. Otherwise
      // it would make every narrower role stacked above it ineffective.
      if (bpfj_is_override(pod)) {
        break;
      }
      continue;
    }
    if (policy->bpf_mode != BPFJ_POLICY_ANY) {
      struct bpfj_uuid actor_pod = {};
      bpfj_pod_read_uuid(&actor_pod, pod);
      // Owner v2 predated pod UUIDs. Replacement marks those records with the
      // impossible all-zero UUID; retain their former same-role semantics
      // because the original pod identity cannot be reconstructed. New v3
      // records always carry a real UUID and remain strictly pod-scoped.
      const bool same_pod = owner &&
          (bpfj_bpf_uuid_equal(&actor_pod, &owner->pod) ||
           (bpfj_bpf_uuid_is_zero(&owner->pod) && owner->policy == policy));
      const bool named_role = owner && policy->bpf_mode == BPFJ_POLICY_ROLES &&
          bpfj_role_set_contains(policy->gates[BPFJ_POLICY_GATE_BPF],
                                 owner->policy);
      if (!same_pod && !named_role) {
        return false;
      }
    }
    granted = true;

    if (bpfj_is_override(pod)) {
      break;
    }
  }

  return granted;
}

/// Take ownership of a newly created object on behalf of its creator. Only
/// from the create hooks, since bpf_map_new_fd also runs for a GET_FD_BY_ID
/// and an open of a pin; the id is unassigned here, so the first fd fills it
/// in.
static __always_inline int
bpfj_bpf_take_ownership(void* owners, __u8 domain, __u64 addr) {
  struct bpfj_bpf_owner record = {};
  if (!bpfj_bpf_owning_role(bpfj_get_current_pid_data(), &record)) {
    // Unjailed, denied, or explicitly untracked. Nothing to record.
    return 0;
  }

  BPFJ_MUTATION_TRANSACTION(transaction);
  const int active = bpfj_mutation_begin(&transaction);
  if (active <= 0) {
    return active;
  }

  if (bpf_map_update_elem(owners, &addr, &record, BPF_NOEXIST) < 0) {
    // Loud, because the object stays unowned and so openable by anyone.
    BPFJ_LOG_ERR(ENOSPC, "No room to record the owner of a new BPF object");
    return 0;
  }
  bpfj_mutation_bpf_owner(
      &transaction, domain, BPFJ_MUTATION_UPSERT, addr, &record);
  return 0;
}

/// @brief Check an fd being created for an object against the caller's policy.
static __always_inline int
bpfj_bpf_check_object(void* owners, __u8 domain, __u64 addr, __u32 id) {
  if (bpfj_bpf_is_loader()) {
    return 0;
  }

  struct bpfj_bpf_owner* owner = bpf_map_lookup_elem(owners, &addr);
  if (!bpfj_bpf_access_allowed(bpfj_get_current_pid_data(), owner)) {
    struct bpfj_event* ev = bpfj_event_reserve_current(BPFJ_EVENT_BPF);
    bpfj_event_submit(ev);
    if (owner) {
      BPFJ_LOG("Denied BPF object %u owned by %s", id, owner->role.id);
    } else {
      BPFJ_LOG("Denied unowned BPF object %u", id);
    }
    return -EPERM;
  }

  // bpf-any deliberately reaches objects the jailer did not see created.
  if (!owner) {
    return 0;
  }

  // The id exists by the first fd, so record it for userspace.
  if (owner->id == 0) {
    BPFJ_MUTATION_TRANSACTION(transaction);
    const int active = bpfj_mutation_begin(&transaction);
    if (active <= 0) {
      return active;
    }
    owner->id = id;
    bpfj_mutation_bpf_owner(
        &transaction, domain, BPFJ_MUTATION_UPSERT, addr, owner);
  }

  return 0;
}

// Every program below that can refuse takes a trailing `lsm_ret`, the verdict
// the hook has collected so far, and returns early when it is set; ignoring it
// would turn another module's denial into an allow. It only is the return
// value at the hook's real arity, so every argument ahead of it has to be
// declared even where it is unused.
SEC("lsm/bpf")
int BPF_PROG(
    bpfj_bpf_syscall,
    int cmd,
    union bpf_attr* attr,
    unsigned int size,
    bool kernel,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!bpfj_bpf_enforcing) {
    return 0;
  }

  // The trusted process which attached this policy remains able to operate
  // the pinned control-plane maps even when the base role denies bpf(2).
  if (bpfj_bpf_is_loader()) {
    return 0;
  }

  if (bpfj_bpf_syscall_allowed(bpfj_get_current_pid_data())) {
    return 0;
  }

  struct bpfj_event* ev = bpfj_event_reserve_current(BPFJ_EVENT_BPF);
  bpfj_event_submit(ev);
  BPFJ_LOG("Denied bpf(2) cmd %d", cmd);
  return -EPERM;
}

// The only place ownership is taken. The id is not allocated until after this
// returns, so only the address is usable.
SEC("lsm/bpf_map_create")
int BPF_PROG(
    bpfj_bpf_map_created,
    struct bpf_map* map,
    union bpf_attr* attr,
    struct bpf_token* token,
    bool kernel,
    int lsm_ret) {
  if (lsm_ret) {
    // The creation is being refused, so there will be no object to own.
    return lsm_ret;
  }

  if (map) {
    return bpfj_bpf_take_ownership(
        &bpfj_bpf_map_owners, BPFJ_MUTATION_BPF_MAP_OWNER, (__u64)map);
  }
  return 0;
}

SEC("lsm/bpf_prog_load")
int BPF_PROG(
    bpfj_bpf_prog_loaded,
    struct bpf_prog* prog,
    union bpf_attr* attr,
    struct bpf_token* token,
    bool kernel,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (prog) {
    return bpfj_bpf_take_ownership(
        &bpfj_bpf_prog_owners, BPFJ_MUTATION_BPF_PROG_OWNER, (__u64)prog);
  }
  return 0;
}

SEC("lsm/bpf_map")
int BPF_PROG(
    bpfj_bpf_map_check,
    struct bpf_map* map,
    fmode_t fmode,
    int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!map) {
    return 0;
  }

  return bpfj_bpf_check_object(
      &bpfj_bpf_map_owners, BPFJ_MUTATION_BPF_MAP_OWNER, (__u64)map, map->id);
}

// No fmode here, unlike bpf_map: security_bpf_prog() takes the program alone.
SEC("lsm/bpf_prog")
int BPF_PROG(bpfj_bpf_prog_check, struct bpf_prog* prog, int lsm_ret) {
  if (lsm_ret) {
    return lsm_ret;
  }

  if (!prog || !prog->aux) {
    return 0;
  }

  return bpfj_bpf_check_object(
      &bpfj_bpf_prog_owners,
      BPFJ_MUTATION_BPF_PROG_OWNER,
      (__u64)prog,
      prog->aux->id);
}

// Cleanup. Both hooks return void, so there is nothing to decide here.

static __always_inline void
bpfj_bpf_forget(void* owners, __u8 domain, __u64 addr) {
  if (!bpf_map_lookup_elem(owners, &addr)) {
    return;
  }
  BPFJ_MUTATION_TRANSACTION(transaction);
  if (bpfj_mutation_begin(&transaction) <= 0) {
    return;
  }
  bpf_map_delete_elem(owners, &addr);
  bpfj_mutation_bpf_owner(
      &transaction, domain, BPFJ_MUTATION_DELETE, addr, NULL);
}

SEC("lsm/bpf_map_free")
int BPF_PROG(bpfj_bpf_map_free, struct bpf_map* map) {
  bpfj_bpf_forget(
      &bpfj_bpf_map_owners, BPFJ_MUTATION_BPF_MAP_OWNER, (__u64)map);
  return 0;
}

SEC("lsm/bpf_prog_free")
int BPF_PROG(bpfj_bpf_prog_free, struct bpf_prog* prog) {
  bpfj_bpf_forget(
      &bpfj_bpf_prog_owners, BPFJ_MUTATION_BPF_PROG_OWNER, (__u64)prog);
  return 0;
}

// Record what is already open: the hooks above only see an object as its fd is
// created, so this walks every open file on the host once at load. First
// writer wins, the creator not being recoverable after the fact.
SEC("iter/task_file")
int bpfj_bpf_seed_owners(struct bpf_iter__task_file* ctx) {
  struct task_struct* task = ctx->task;
  struct file* file = ctx->file;
  if (!task || !file) {
    return 0;
  }

  // A process's jail lives on its thread-group leader.
  if (task->pid != task->tgid) {
    return 0;
  }

  struct bpfj_pid_data* pid_data = bpfj_get_task_pid_data(task);
  struct bpfj_bpf_owner record = {};
  if (!bpfj_bpf_owning_role(pid_data, &record)) {
    return 0;
  }

  if (file->f_op == &bpf_map_fops) {
    struct bpf_map* map = bpf_core_cast(file->private_data, struct bpf_map);
    if (map) {
      const __u64 addr = (__u64)map;
      record.id = map->id;
      bpf_map_update_elem(&bpfj_bpf_map_owners, &addr, &record, BPF_NOEXIST);
    }
  } else if (file->f_op == &bpf_prog_fops) {
    struct bpf_prog* prog = bpf_core_cast(file->private_data, struct bpf_prog);
    if (prog && prog->aux) {
      const __u64 addr = (__u64)prog;
      record.id = prog->aux->id;
      bpf_map_update_elem(&bpfj_bpf_prog_owners, &addr, &record, BPF_NOEXIST);
    }
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
