// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/bpf_core_read.h>

#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/glob_map.h"
#include "bpfj/lib/bpf/heap.h"

#define BPFJ_IPC_GLOB_RUNS 4

struct bpfj_glob_run __arena* bpfj_ipc_glob_run0;
struct bpfj_glob_run __arena* bpfj_ipc_glob_run1;
struct bpfj_glob_run __arena* bpfj_ipc_glob_run2;
struct bpfj_glob_run __arena* bpfj_ipc_glob_run3;
__u64 bpfj_ipc_glob_claimed;

static void bpfj_ipc_glob_release(__u32* slot) {
  if (*slot < BPFJ_IPC_GLOB_RUNS) {
    __sync_fetch_and_and(&bpfj_ipc_glob_claimed, ~(1ULL << *slot));
  }
}

static __always_inline struct bpfj_glob_run __arena* bpfj_ipc_glob_claim(
    __u32* slot) {
  *slot = BPFJ_IPC_GLOB_RUNS;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_IPC_GLOB_RUNS) {
    __u64 bit = 1ULL << i;
    if ((__sync_fetch_and_or(&bpfj_ipc_glob_claimed, bit) & bit) == 0) {
      *slot = i;
      if (i == 0) {
        return bpfj_ipc_glob_run0;
      }
      if (i == 1) {
        return bpfj_ipc_glob_run1;
      }
      if (i == 2) {
        return bpfj_ipc_glob_run2;
      }
      return bpfj_ipc_glob_run3;
    }
  }
  return NULL;
}

__noinline bool bpfj_ipc_glob_bindings_complete(
    const struct bpfj_glob_run __arena* run __arg_arena) {
  u32 wanted = run->map->num_vars;
  u32 bound = run->bindings.count;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_BINDINGS) {
    if (i >= wanted) {
      break;
    }
    bool found = false;
    u32 j = 0;
    bpf_for(j, 0, BPFJ_GLOB_MAP_MAX_BINDINGS) {
      if (j >= bound) {
        break;
      }
      if (run->bindings.b[j].key == run->map->var_keys[i]) {
        found = true;
        break;
      }
    }
    if (!found) {
      return false;
    }
  }
  return true;
}

static __always_inline uintptr_t bpfj_ipc_ptr_to_scalar(const void* ptr) {
  uintptr_t out = 0;
  bpf_probe_read_kernel(&out, sizeof(out), &ptr);
  return out;
}

__noinline int bpfj_ipc_glob_bind_pod(
    struct bpfj_glob_run __arena* run __arg_arena,
    const struct bpfj_glob_map __arena* map __arg_arena,
    const struct bpfj_pod __arena* pod __arg_arena) {
  run->map = map;
  run->bindings.count = 0;
  if (pod == NULL || map == NULL) {
    return 0;
  }

  u32 count = pod->var_array.count;
  struct bpfj_var __arena* vars = pod->var_array.vars;
  if (count > BPFJ_VAR_MAX) {
    count = BPFJ_VAR_MAX;
  }
  u32 v = 0;
  bpf_for(v, 0, BPFJ_VAR_MAX) {
    if (v >= count || vars == NULL) {
      break;
    }
    struct bpfj_var __arena* var = vars + v;
    if (var->type != BPFJ_VAR_TYPE_STR ||
        !bpfj_glob_map_wants_key(map, var->id)) {
      continue;
    }

    u32 at = run->bindings.count;
    if (at >= BPFJ_GLOB_MAP_MAX_BINDINGS) {
      break;
    }
    struct bpfj_glob_binding __arena* binding = &run->bindings.b[at];
    binding->key = var->id;
    binding->len = var->size;
    if (var->size <= BPFJ_GLOB_MAP_MAX_VAR_LEN && var->val != NULL) {
      const char __arena* value = var->val;
      u32 k = 0;
      bpf_for(k, 0, BPFJ_GLOB_MAP_MAX_VAR_LEN) {
        if (k >= var->size) {
          break;
        }
        binding->val[k] = value[k];
      }
    }
    run->bindings.count = at + 1;
  }
  return 0;
}

// GLOBAL function: keep the matcher outside the gate's policy branches. Older
// verifiers otherwise explore the product of those branches and every bounded
// glob loop.
__noinline bool bpfj_ipc_glob_matches_global(
    const struct bpfj_ipc_pattern_set __arena* patterns __arg_arena,
    const struct bpfj_pod __arena* pod __arg_arena,
    u32 len,
    u64 chars) {
  if (patterns == NULL || patterns->map == NULL || pod == NULL || chars == 0 ||
      patterns->num_accepts == 0) {
    return false;
  }

  if (len > BPFJ_GLOB_MAP_MAX_STR_LEN) {
    return false;
  }

  __attribute__((cleanup(bpfj_ipc_glob_release))) __u32 run_slot =
      BPFJ_IPC_GLOB_RUNS;
  struct bpfj_glob_run __arena* run = bpfj_ipc_glob_claim(&run_slot);
  if (run == NULL) {
    return false;
  }
  bpfj_ipc_glob_bind_pod(run, patterns->map, pod);
  if (!bpfj_ipc_glob_bindings_complete(run) ||
      bpfj_glob_run_read_kernel(run, len, chars) < 0 ||
      bpfj_glob_eval_state(run) < 0) {
    return false;
  }

  __u64 best = 0;
  bool matched = false;
  __u32 offset;
  bpf_for(offset, 0, BPFJ_GLOB_MAP_MAX_ACCEPTS) {
    if (offset >= patterns->num_accepts) {
      break;
    }
    const __u32 accept = patterns->first_accept + offset;
    if (accept >= run->map->num_accepts ||
        !bpfj_glob_state_has_accept(run, accept)) {
      continue;
    }
    const __u64 value = run->map->accept_val[accept];
    if (!matched || (value >> 1) > (best >> 1) ||
        ((value >> 1) == (best >> 1) && (value & 1) == 0)) {
      matched = true;
      best = value;
    }
  }
  return matched && (best & 1) != 0;
}

static __always_inline bool bpfj_ipc_glob_matches(
    const struct bpfj_ipc_pattern_set __arena* patterns,
    const struct bpfj_pod __arena* pod,
    const struct qstr* name) {
  if (name == NULL) {
    return false;
  }
  u32 len = bpf_core_cast((name), typeof(*(name)))->len;
  const unsigned char* chars = bpf_core_cast((name), typeof(*(name)))->name;
  return bpfj_ipc_glob_matches_global(
      patterns, pod, len, bpfj_ipc_ptr_to_scalar(chars));
}
