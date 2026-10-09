// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpfj/lib/bpf/const_map.h"

#define CONST_MAP_TEST_MAX_SEED 32

const volatile __u32 max_entries = 8;
const volatile __u32 key_size = sizeof(__u64);
const volatile __u32 val_size = sizeof(__u64);
const volatile __u64 seed_keys[CONST_MAP_TEST_MAX_SEED];
const volatile __u64 seed_key_tails[CONST_MAP_TEST_MAX_SEED];
const volatile __u64 seed_vals[CONST_MAP_TEST_MAX_SEED];
const volatile __u32 seed_count = 0;
const volatile __u64 lookup_key = 0;
const volatile __u64 lookup_key_tail = 0;
const volatile __u64 missing_key = 0;

volatile long ret = 0;
volatile long lookup_ret = 0;
volatile long missing_ret = 0;
volatile long lookup_before_seal_ret = 0;
volatile long insert_after_seal_ret = 0;
volatile __u64 lookup_val = 0;
volatile __u32 inserted = 0;
volatile __u32 duplicates = 0;
volatile __u32 final_size = 0;
volatile __u32 final_capacity = 0;
volatile __u32 final_probe_limit = 0;
volatile __u64 used_before = 0;
volatile __u64 used_while_live = 0;
volatile __u64 used_after = 0;

static __always_inline __u64 __arena* test_key(__u64 first, __u64 tail) {
  __u64 __arena* key = BPFJ_HEAP_ALLOC(key_size);
  if (!key) {
    return NULL;
  }
  key[0] = first;
  __u32 i = 0;
  bpf_for(i, 1, key_size / (__u32)sizeof(__u64)) {
    key[i] = tail;
  }
  return key;
}

static __noinline long test_insert(
    struct bpfj_const_map __arena* map __arg_arena,
    __u64 first,
    __u64 tail,
    __u64 val) {
  long plan = 0;
  if (key_size == sizeof(__u64)) {
    plan = bpfj_const_map_insert_u64(map, first);
  } else {
    __u64 __arena* key = test_key(first, tail);
    if (!key) {
      return -ENOMEM;
    }
    plan = bpfj_const_map_insert(map, key);
    BPFJ_HEAP_FREE(key);
  }
  if (plan < 0) {
    return plan;
  }

  __u32 index = BPFJ_CONST_MAP_PLAN_INDEX(plan);
  __u64 __arena* stored = bpfj_const_map_value_at(map, index);
  if (!stored) {
    return -EFAULT;
  }
  *stored = val;
  if (BPFJ_CONST_MAP_PLAN_KIND(plan) == BPFJ_CONST_MAP_INSERTED) {
    ++inserted;
  } else {
    ++duplicates;
  }
  return 0;
}

static __noinline long test_lookup(
    struct bpfj_const_map __arena* map __arg_arena,
    __u64 first,
    __u64 tail,
    __u64* out __arg_nonnull) {
  long index = 0;
  if (key_size == sizeof(__u64)) {
    index = bpfj_const_map_lookup_u64(map, first);
  } else {
    __u64 __arena* key = test_key(first, tail);
    if (!key) {
      return -ENOMEM;
    }
    index = bpfj_const_map_lookup(map, key);
    BPFJ_HEAP_FREE(key);
  }
  if (index < 0) {
    return index;
  }

  __u64 __arena* val = bpfj_const_map_value_at(map, (__u32)index);
  if (!val) {
    return -EFAULT;
  }
  *out = *val;
  return 0;
}

SEC("syscall")
int test_const_map(void* ctx) {
  (void)ctx;

  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  used_before = ctrl->current_used;

  __u32 bytes = bpfj_const_map_allocation_size(max_entries, key_size, val_size);
  if (bytes == 0) {
    ret = -EINVAL;
    return 0;
  }
  long map_off = bpfj_heap_alloc(bytes);
  if (map_off <= 0) {
    ret = map_off < 0 ? map_off : -ENOMEM;
    return 0;
  }
  struct bpfj_const_map __arena* map =
      (struct bpfj_const_map __arena*)(bpfj_heap_ptr() + map_off);

  ret = bpfj_const_map_init(map, max_entries, key_size, val_size);
  if (ret < 0) {
    BPFJ_HEAP_FREE(map);
    return 0;
  }

  lookup_before_seal_ret = bpfj_const_map_lookup_u64(map, lookup_key);

  __u32 i = 0;
  bpf_for(i, 0, CONST_MAP_TEST_MAX_SEED) {
    if (i >= seed_count) {
      break;
    }
    ret = test_insert(map, seed_keys[i], seed_key_tails[i], seed_vals[i]);
    if (ret < 0) {
      break;
    }
  }
  if (ret < 0) {
    BPFJ_HEAP_FREE(map);
    return 0;
  }

  ret = bpfj_const_map_seal(map);
  if (ret < 0) {
    BPFJ_HEAP_FREE(map);
    return 0;
  }

  __u64 found = 0;
  lookup_ret = test_lookup(map, lookup_key, lookup_key_tail, &found);
  lookup_val = found;
  __u64 ignored = 0;
  missing_ret = test_lookup(map, missing_key, 0, &ignored);
  insert_after_seal_ret = bpfj_const_map_insert_u64(map, lookup_key);
  final_size = map->size;
  final_capacity = map->capacity;
  final_probe_limit = map->probe_limit;
  used_while_live = ctrl->current_used;

  BPFJ_HEAP_FREE(map);
  used_after = ctrl->current_used;
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
