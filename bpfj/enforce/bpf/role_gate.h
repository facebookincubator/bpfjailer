// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// May a process in these roles act on a process in those roles? The signal
// enforcer asks it of `kill`, the ptrace enforcer of `ptrace`, and the proc
// enforcer of `proc`, with each role's arena policy carrying its mode and
// optional target-role set.
//
// Which gives a role four states:
//
//   option absent  may not act at all
//   *-pod          may act only inside its own pod
//   *-roles [a,b]  that, and on a process whose roles are all in {a, b}
//   *-any           unrestricted
//
// Acting inside the restricting role's *own* pod is always allowed, a pod
// being one jail instance -- not any pod the two share, since a base role puts
// the whole host in one and the list would then never deny anything.
//
// Where the actor holds several roles, every one has to permit, walking newest
// first and stopping after the first override role. The target is read the
// other way round, every role it holds having to be listed, or
// picking up a listed role alongside the one protecting it is an escalation --
// which is also why a restricted actor cannot reach a target in no pod at all.

#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types.h"

static __always_inline __u32
bpfj_gate_num_pods(const struct bpfj_pid_data* pid_data) {
  const __u32 num_pods = pid_data->num_pods;
  return num_pods > BPFJ_MAX_POD_PER_PID ? BPFJ_MAX_POD_PER_PID : num_pods;
}

static __always_inline __u8 bpfj_gate_mode(
    const struct bpfj_role_policy __arena* policy,
    enum bpfj_policy_gate gate) {
  if (gate == BPFJ_POLICY_GATE_KILL) {
    return policy->kill_mode;
  }
  if (gate == BPFJ_POLICY_GATE_PTRACE) {
    return policy->ptrace_mode;
  }
  if (gate == BPFJ_POLICY_GATE_PROC) {
    return policy->proc_mode;
  }
  if (gate == BPFJ_POLICY_GATE_KEYRING) {
    return policy->keyring_mode;
  }
  if (gate == BPFJ_POLICY_GATE_ENROLL) {
    return policy->enroll_mode;
  }
  return BPFJ_POLICY_DENY;
}

/// Whether `pid_data` names `pod`.
static __always_inline bool bpfj_gate_in_pod(
    struct bpfj_pid_data* pid_data,
    struct bpfj_pod __arena* pod) {
  const __u32 num_pods = bpfj_gate_num_pods(pid_data);

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

/// Whether `actor_role`'s list names every role the target holds. Deliberately
/// does not stop on bpfj_is_override(): every role here has to be covered, and
/// breaking early would let a target escape a gate by holding an override
/// role.
static __always_inline bool bpfj_gate_covers(
    enum bpfj_policy_gate gate,
    const struct bpfj_role_policy __arena* actor_policy,
    struct bpfj_pid_data* target) {
  const __u32 num_pods = bpfj_gate_num_pods(target);
  if (num_pods == 0) {
    return false;
  }

  for (int i = 0; i < BPFJ_MAX_POD_PER_PID; ++i) {
    if (i >= num_pods) {
      break;
    }

    struct bpfj_pod __arena* pod = target->pods[i];
    if (!pod) {
      return false;
    }

    if (!bpfj_role_set_contains(
            actor_policy->gates[gate], bpfj_pod_policy(pod))) {
      return false;
    }
  }

  return true;
}

/// Whether the actor may act on something `owner` owns, under the gate
/// `roles`/`access`. The object form of bpfj_gate_allowed(): the target
/// belongs to exactly one role, so naming that role is the whole test and the
/// own-pod exemption becomes an own-role one.
static __always_inline bool bpfj_gate_allowed_owner(
    enum bpfj_policy_gate gate,
    struct bpfj_pid_data* actor,
    const struct bpfj_role_policy __arena* owner) {
  if (!actor) {
    return true;
  }

  const __u32 num_pods = bpfj_gate_num_pods(actor);
  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod __arena* pod = actor->pods[i];
    if (!pod) {
      continue;
    }

    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy) {
      return false;
    }
    const __u8 mode = bpfj_gate_mode(policy, gate);
    if (mode == BPFJ_POLICY_DENY) {
      return false;
    }
    const struct bpfj_role_set __arena* set = policy->gates[gate];
    if (mode == BPFJ_POLICY_POD && policy != owner) {
      return false;
    }
    if (mode == BPFJ_POLICY_ROLES && policy != owner &&
        !bpfj_role_set_contains(set, owner)) {
      return false;
    }

    // Checked for every pod: an override role's answer ends the walk.
    if (bpfj_is_override(pod)) {
      break;
    }
  }

  return true;
}

/// Whether any role the actor holds is narrower than unrestricted.
static __always_inline bool bpfj_gate_restricted(
    enum bpfj_policy_gate gate,
    struct bpfj_pid_data* actor) {
  const __u32 num_pods = bpfj_gate_num_pods(actor);

  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod __arena* pod = actor->pods[i];
    if (!pod) {
      continue;
    }

    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy) {
      return true;
    }
    if (bpfj_gate_mode(policy, gate) != BPFJ_POLICY_ANY) {
      return true;
    }

    if (bpfj_is_override(pod)) {
      break;
    }
  }

  return false;
}

/// Whether the actor may act on the target, under the gate `roles`/`access`.
/// Either side may be NULL, meaning a process the jailer knows nothing about:
/// no policy applies to such an actor, and such a target is reachable only by
/// an unrestricted one.
static __always_inline bool bpfj_gate_allowed(
    enum bpfj_policy_gate gate,
    struct bpfj_pid_data* actor,
    struct bpfj_pid_data* target) {
  if (!actor) {
    return true;
  }

  // Answered here rather than inside the walk below: clang hoists the address
  // of the target's uuids out of that loop, above a nested null test, and the
  // verifier rejects arithmetic on an unchecked pointer.
  if (!target) {
    return !bpfj_gate_restricted(gate, actor);
  }

  const __u32 num_pods = bpfj_gate_num_pods(actor);
  // Newest role first, down to the base. See bpfj_is_override() in maps.h.
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }

    struct bpfj_pod __arena* pod = actor->pods[i];
    if (!pod) {
      continue;
    }

    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    if (!policy) {
      return false;
    }
    const __u8 mode = bpfj_gate_mode(policy, gate);
    if (mode == BPFJ_POLICY_DENY) {
      return false;
    }
    if (mode == BPFJ_POLICY_POD && !bpfj_gate_in_pod(target, pod)) {
      return false;
    }
    if (mode == BPFJ_POLICY_ROLES && !bpfj_gate_in_pod(target, pod) &&
        !bpfj_gate_covers(gate, policy, target)) {
      return false;
    }

    // As above: an override role's answer ends the walk.
    if (bpfj_is_override(pod)) {
      break;
    }
  }

  return true;
}

/// Whether the actor's existing roles permit acquiring the target role.
static __always_inline bool
bpfj_gate_enroll_allowed(struct bpfj_pid_data *actor,
                         const struct bpfj_role_policy __arena *target) {
  if (!target) {
    return false;
  }
  if (!actor) {
    return true;
  }

  const __u32 num_pods = bpfj_gate_num_pods(actor);
  for (int i = BPFJ_MAX_POD_PER_PID - 1; i >= 0; --i) {
    if (i >= num_pods) {
      continue;
    }
    struct bpfj_pod __arena *pod = actor->pods[i];
    const struct bpfj_role_policy __arena *policy = bpfj_pod_policy(pod);
    if (!policy) {
      return false;
    }
    if (policy->enroll_mode != BPFJ_POLICY_ANY &&
        (policy->enroll_mode != BPFJ_POLICY_ROLES ||
         !bpfj_role_set_contains(policy->gates[BPFJ_POLICY_GATE_ENROLL],
                                 target))) {
      return false;
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return true;
}
