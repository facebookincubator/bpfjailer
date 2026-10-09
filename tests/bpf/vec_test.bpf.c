// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/vec.h"

// Enough to watch the buffer double several times over from
// BPFJ_VEC_MIN_CAPACITY.
#define VEC_TEST_MAX 64

// Reported rather than restated on the userspace side: vec.h is a BPF-only
// header, so the test has no way to include the constant it is asserting on.
const volatile __u32 min_capacity = BPFJ_VEC_MIN_CAPACITY;

// Reserve to this before pushing anything; 0 skips the call. A reserve past
// what doubling would give is how the round-up path gets exercised.
const volatile __u32 reserve_to = 0;
const volatile __u32 push_count = 0;
// Push through bpfj_vec_push_back (copy from a local) rather than
// bpfj_vec_emplace_back (write the slot directly). Both are covered; they take
// different routes into the arena.
const volatile bool use_push_back = true;
const volatile __u32 clear_after = 0; // 1 = clear once the pushes are done
const volatile __u32 pop_after = 0; // elements to pop once the pushes are done

// First failing operation, 0 if every one succeeded.
volatile long ret = 0;

volatile __u32 capacity_when_empty = 0;
volatile bool buf_null_when_empty = false;
volatile __u32 capacity_after_reserve = 0;
volatile __u32 final_size = 0;
volatile __u32 final_capacity = 0;
// at() one past the last element, which must not hand back a slot.
volatile bool at_past_end_null = false;

// Every element read back after all the growth, so a copy the reallocation
// dropped or misplaced shows up as a wrong value rather than as a size that
// happens to match.
volatile __u64 values[VEC_TEST_MAX];
volatile __u32 values_read = 0;

// Arena bytes in use with the vec header allocated but the vec still empty, and
// again after destroy. An empty vec owns nothing, so the two have to agree.
volatile __u64 used_when_empty = 0;
volatile __u64 used_after_destroy = 0;

static __u64 vec_test_value(__u32 i) {
  return ((__u64)i * 0x9e3779b9ULL) + 1;
}

SEC("syscall")
int test_vec(void* ctx) {
  (void)ctx;

  bpfj_heap_use_arena();

  // The header is the caller's allocation, not the vec's, so it is taken before
  // the baseline reading: what a destroyed vec must give back is everything
  // above this line.
  BPFJ_HEAP_ALLOC_GUARD(struct bpfj_vec, vec);
  if (!vec) {
    ret = -ENOMEM;
    return 0;
  }

  bpfj_vec_init(vec, sizeof(__u64));

  capacity_when_empty = bpfj_vec_capacity(vec);
  buf_null_when_empty = vec->buf == NULL;
  used_when_empty = bpfj_heap_get_ctrl()->current_used;

  if (reserve_to != 0) {
    long res = bpfj_vec_reserve(vec, reserve_to);
    if (res < 0) {
      ret = res;
      bpfj_vec_destroy(vec);
      return 0;
    }
  }
  capacity_after_reserve = bpfj_vec_capacity(vec);

  __u32 i = 0;
  if (use_push_back) {
    // Unrolled rather than a bpf_for, because BPFJ_VEC_PUSH_BACK expands its
    // copy inline and that copy's iterator must not end up nested inside one of
    // ours. That is the whole point of this branch, so the usual advice to
    // prefer bpf_for is the thing being tested against here.
    // @lint-ignore BPFCLINT unrolled-for-loop
#pragma unroll
    for (__u32 j = 0; j < VEC_TEST_MAX; ++j) {
      if (j >= push_count) {
        break;
      }

      __u64 v = vec_test_value(j);
      long res = BPFJ_VEC_PUSH_BACK(vec, &v);
      if (res < 0) {
        ret = res;
        break;
      }
    }
  } else {
    // From inside a bpf_for, which is the case emplace_back exists for: it has
    // no iterator of its own, and the growth path's lives in reserve's frame,
    // so nothing nests.
    bpf_for(i, 0, VEC_TEST_MAX) {
      if (i >= push_count) {
        break;
      }

      __u64 __arena* slot = bpfj_vec_emplace_back(vec);
      if (slot == NULL) {
        ret = -ENOMEM;
        break;
      }
      *slot = vec_test_value(i);
    }
  }

  if (ret != 0) {
    bpfj_vec_destroy(vec);
    return 0;
  }

  if (clear_after != 0) {
    bpfj_vec_clear(vec);
  }

  bpf_for(i, 0, VEC_TEST_MAX) {
    if (i >= pop_after) {
      break;
    }
    bpfj_vec_pop_back(vec);
  }

  final_size = bpfj_vec_size(vec);
  final_capacity = bpfj_vec_capacity(vec);
  at_past_end_null = bpfj_vec_at(vec, final_size) == NULL;

  __u32 read = 0;
  bpf_for(i, 0, VEC_TEST_MAX) {
    if (i >= final_size) {
      break;
    }
    __u64 __arena* slot = bpfj_vec_at(vec, i);
    if (slot == NULL) {
      ret = -EFAULT;
      break;
    }
    values[i & (VEC_TEST_MAX - 1)] = *slot;
    read = i + 1;
  }
  values_read = read;

  bpfj_vec_destroy(vec);
  used_after_destroy = bpfj_heap_get_ctrl()->current_used;

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
