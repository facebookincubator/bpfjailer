// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpfj/lib/bpf/heap.h"

// ---------------------------------------------------------------------------
// Shared globals (only one program runs per test load)
// ---------------------------------------------------------------------------

volatile int init_ret = 0;
volatile int done = 0;

// ---------------------------------------------------------------------------
// test_heap_init result globals
// ---------------------------------------------------------------------------

volatile __u32 init_arena_size = 0;
volatile __u64 init_total_alloc = 0;
volatile __u64 init_total_free = 0;
volatile __u64 init_current_used = 0;
volatile __u32 init_fl_bitmap = 0;

// ---------------------------------------------------------------------------
// test_heap_alloc result globals
// ---------------------------------------------------------------------------

volatile __u32 alloc_small = 0;
volatile __u32 alloc_medium = 0;
volatile __u32 alloc_large = 0;
volatile long alloc_zero = 0;
volatile __u64 alloc_total = 0;
volatile __u64 alloc_used = 0;

// ---------------------------------------------------------------------------
// test_heap_free result globals
// ---------------------------------------------------------------------------

volatile __u32 free_alloc1_off = 0;
volatile __u32 free_alloc2_off = 0;
volatile __u32 free_alloc3_off = 0;
volatile __u64 free_used_after_alloc = 0;
volatile __u64 free_used_after_free1 = 0;
volatile __u64 free_used_after_free2 = 0;
volatile __u64 free_used_after_free3 = 0;
volatile __u64 free_total_alloc_count = 0;
volatile __u64 free_total_free_count = 0;

// ---------------------------------------------------------------------------
// test_heap_reuse result globals
// ---------------------------------------------------------------------------

volatile __u32 reuse_first_alloc = 0;
volatile __u32 reuse_second_alloc = 0;
volatile int reuse_reused = 0;
volatile __u64 reuse_used_before_free = 0;
volatile __u64 reuse_used_after_free = 0;
volatile __u64 reuse_used_after_realloc = 0;

// ---------------------------------------------------------------------------
// test_heap_multi result globals
// ---------------------------------------------------------------------------

#define MULTI_NUM_ALLOCS 8

volatile __u32 multi_offsets[MULTI_NUM_ALLOCS] = {};
volatile int multi_all_nonzero = 0;
volatile int multi_all_unique = 0;
volatile __u64 multi_used_after_alloc = 0;
volatile __u64 multi_used_after_free_half = 0;
volatile __u64 multi_used_after_free_all = 0;
volatile __u64 multi_total_alloc_count = 0;
volatile __u64 multi_total_free_count = 0;

// ---------------------------------------------------------------------------
// test_heap_exhaust result globals
// ---------------------------------------------------------------------------

#define EXHAUST_MAX_ALLOCS 64

volatile __u32 exhaust_success_count = 0;
volatile __u64 exhaust_peak_used = 0;
volatile __u64 exhaust_used_after_free_all = 0;
volatile __u32 exhaust_recovery_alloc = 0;
volatile __u64 exhaust_total_alloc_count = 0;
volatile __u64 exhaust_total_free_count = 0;
volatile __u32 exhaust_offsets[EXHAUST_MAX_ALLOCS] = {};

// ---------------------------------------------------------------------------
// test_heap_minsize result globals
// ---------------------------------------------------------------------------

volatile __u32 minsize_alloc_1 = 0;
volatile __u32 minsize_alloc_24 = 0;
volatile __u32 minsize_alloc_25 = 0;
volatile __u64 minsize_used_after_alloc = 0;
volatile __u64 minsize_used_after_free = 0;

// ---------------------------------------------------------------------------
// test_heap_large result globals
// ---------------------------------------------------------------------------

volatile __u32 large_alloc_off = 0;
volatile __u64 large_used_after_alloc = 0;
volatile __u64 large_used_after_free = 0;
volatile __u32 large_realloc_off = 0;
volatile __u64 large_realloc_used = 0;

// ---------------------------------------------------------------------------
// test_heap_free_null result globals
// ---------------------------------------------------------------------------

volatile __u64 fnull_total_free_after_null = 0;
volatile __u64 fnull_used_after_null = 0;
volatile __u64 fnull_total_free_after_small = 0;
volatile __u64 fnull_used_after_small = 0;

// ---------------------------------------------------------------------------
// test_heap_coalesce_all result globals
// ---------------------------------------------------------------------------

volatile __u32 coal_alloc1 = 0;
volatile __u32 coal_alloc2 = 0;
volatile __u32 coal_alloc3 = 0;
volatile __u64 coal_used_after_alloc = 0;
volatile __u64 coal_used_after_free_all = 0;
volatile __u32 coal_large_alloc_off = 0;
volatile __u64 coal_total_alloc_count = 0;
volatile __u64 coal_total_free_count = 0;

// ---------------------------------------------------------------------------
// test_heap_alignment result globals
// ---------------------------------------------------------------------------

#define ALIGN_NUM_ALLOCS 8

volatile __u32 align_offsets[ALIGN_NUM_ALLOCS] = {};
volatile int align_all_aligned = 0;
volatile int align_all_nonzero = 0;
volatile __u64 align_used_after_free = 0;

// ---------------------------------------------------------------------------
// test_heap_double result globals
// ---------------------------------------------------------------------------

#define DOUBLE_MAX_ALLOCS 8

volatile __u32 double_exhaust_count = 0;
volatile long double_ret = 0;
volatile __u32 double_post_alloc = 0;
volatile __u32 double_new_arena_size = 0;
volatile __u64 double_used_after_free_all = 0;
volatile __u32 double_offsets[DOUBLE_MAX_ALLOCS] = {};

// ---------------------------------------------------------------------------
// test_heap_interleaved result globals
// ---------------------------------------------------------------------------

#define ILEAVE_NUM_STEPS 8

volatile __u64 ileave_used[ILEAVE_NUM_STEPS] = {};
volatile __u64 ileave_total_alloc_count = 0;
volatile __u64 ileave_total_free_count = 0;
volatile __u32 ileave_off_a = 0;
volatile __u32 ileave_off_b = 0;
volatile __u32 ileave_off_c = 0;
volatile __u32 ileave_off_d = 0;

// ---------------------------------------------------------------------------
// test_heap_split_exact result globals
// ---------------------------------------------------------------------------

volatile __u64 split_used_no_split = 0;
volatile __u64 split_used_with_split = 0;
volatile __u32 split_no_split_off = 0;
volatile __u32 split_split_off = 0;

// ---------------------------------------------------------------------------
// test_heap_userspace_init result globals
// ---------------------------------------------------------------------------

volatile int usinit_was_initialized = 0;
volatile __u32 usinit_alloc_off = 0;
volatile __u64 usinit_used_after_alloc = 0;
volatile __u64 usinit_used_after_free = 0;
volatile __u64 usinit_total_alloc = 0;
volatile __u64 usinit_total_free = 0;

// ---------------------------------------------------------------------------
// test_heap_calloc result globals
// ---------------------------------------------------------------------------

volatile __u32 calloc_off = 0;
volatile int calloc_all_zero = 0;
volatile __u64 calloc_used_after_alloc = 0;
volatile __u64 calloc_used_after_free = 0;

// ---------------------------------------------------------------------------
// test_heap_realloc result globals
// ---------------------------------------------------------------------------

volatile __u32 realloc_orig_off = 0;
volatile __u32 realloc_grown_off = 0;
volatile __u32 realloc_shrunk_off = 0;
volatile __u32 realloc_null_alloc_off = 0;
volatile long realloc_free_ret = 0;
volatile int realloc_data_preserved = 0;
volatile __u64 realloc_used_after_free_all = 0;

// ---------------------------------------------------------------------------
// test_heap_coalesce_forward result globals
// ---------------------------------------------------------------------------

#define CFWD_MAX_ALLOCS 8

volatile __u32 cfwd_exhaust_count = 0;
volatile __u32 cfwd_offsets[CFWD_MAX_ALLOCS] = {};
volatile __u32 cfwd_merged_alloc = 0;
volatile __u64 cfwd_used_after_free_all = 0;

// ---------------------------------------------------------------------------
// test_heap_coalesce_backward result globals
// ---------------------------------------------------------------------------

#define CBWD_MAX_ALLOCS 8

volatile __u32 cbwd_exhaust_count = 0;
volatile __u32 cbwd_offsets[CBWD_MAX_ALLOCS] = {};
volatile __u32 cbwd_merged_alloc = 0;
volatile __u64 cbwd_used_after_free_all = 0;

// ---------------------------------------------------------------------------
// test_heap_userspace_alloc result globals
// ---------------------------------------------------------------------------

#define USALLOC_NUM_BLOCKS 4
#define USALLOC_MAGIC_BASE 0xDEADBEEF42ULL

volatile __u32 usalloc_offsets[USALLOC_NUM_BLOCKS] = {};
volatile __u32 usalloc_count = 0;
volatile int usalloc_was_initialized = 0;
volatile int usalloc_values_ok = 0;
volatile __u64 usalloc_used_seen_by_bpf = 0;
volatile __u32 usalloc_bpf_alloc_off = 0;
volatile __u64 usalloc_used_after_bpf_alloc = 0;
volatile int usalloc_bpf_free_ok = 0;
volatile __u64 usalloc_used_after_bpf_free_all = 0;

// ===========================================================================
// Programs
// ===========================================================================

SEC("syscall")
int test_heap_init(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  init_arena_size = ctrl->arena_size;
  init_total_alloc = ctrl->total_alloc;
  init_total_free = ctrl->total_free;
  init_current_used = ctrl->current_used;
  init_fl_bitmap = ctrl->fl_bitmap;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_alloc(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  alloc_zero = bpfj_heap_alloc(0);
  alloc_small = bpfj_heap_alloc(16);
  alloc_medium = bpfj_heap_alloc(256);
  alloc_large = bpfj_heap_alloc(4096);

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  alloc_total = ctrl->total_alloc;
  alloc_used = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_free(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  free_alloc1_off = bpfj_heap_alloc(64);
  free_alloc2_off = bpfj_heap_alloc(64);
  free_alloc3_off = bpfj_heap_alloc(64);

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  free_used_after_alloc = ctrl->current_used;

  bpfj_heap_free(free_alloc2_off);
  free_used_after_free1 = ctrl->current_used;

  bpfj_heap_free(free_alloc1_off);
  free_used_after_free2 = ctrl->current_used;

  bpfj_heap_free(free_alloc3_off);
  free_used_after_free3 = ctrl->current_used;
  free_total_alloc_count = ctrl->total_alloc;
  free_total_free_count = ctrl->total_free;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_reuse(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  reuse_first_alloc = bpfj_heap_alloc(128);
  reuse_used_before_free = ctrl->current_used;

  bpfj_heap_free(reuse_first_alloc);
  reuse_used_after_free = ctrl->current_used;

  reuse_second_alloc = bpfj_heap_alloc(128);
  reuse_used_after_realloc = ctrl->current_used;

  reuse_reused = (reuse_first_alloc == reuse_second_alloc) ? 1 : 0;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_multi(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  __u32 sizes[MULTI_NUM_ALLOCS] = {32, 64, 128, 256, 512, 1024, 48, 96};
  int i;

  multi_all_nonzero = 1;
  for (i = 0; i < MULTI_NUM_ALLOCS; i++) {
    multi_offsets[i] = bpfj_heap_alloc(sizes[i]);
    if (multi_offsets[i] == 0)
      multi_all_nonzero = 0;
  }

  multi_all_unique = 1;
  for (i = 0; i < MULTI_NUM_ALLOCS; i++) {
    int j;
    for (j = i + 1; j < MULTI_NUM_ALLOCS; j++) {
      if (multi_offsets[i] == multi_offsets[j] && multi_offsets[i] != 0)
        multi_all_unique = 0;
    }
  }

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  multi_used_after_alloc = ctrl->current_used;

  for (i = 0; i < MULTI_NUM_ALLOCS; i += 2)
    bpfj_heap_free(multi_offsets[i]);
  multi_used_after_free_half = ctrl->current_used;

  for (i = 1; i < MULTI_NUM_ALLOCS; i += 2)
    bpfj_heap_free(multi_offsets[i]);
  multi_used_after_free_all = ctrl->current_used;
  multi_total_alloc_count = ctrl->total_alloc;
  multi_total_free_count = ctrl->total_free;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_exhaust(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  __u32 count = 0;
  int i;
  for (i = 0; i < EXHAUST_MAX_ALLOCS; i++) {
    long off = bpfj_heap_alloc(8192);
    if (off <= 0)
      break;
    exhaust_offsets[i] = off;
    count++;
  }
  exhaust_success_count = count;

  exhaust_peak_used = ctrl->current_used;

  for (i = 0; i < EXHAUST_MAX_ALLOCS; i++) {
    if (exhaust_offsets[i] != 0)
      bpfj_heap_free(exhaust_offsets[i]);
  }

  exhaust_used_after_free_all = ctrl->current_used;

  exhaust_recovery_alloc = bpfj_heap_alloc(8192);

  exhaust_total_alloc_count = ctrl->total_alloc;
  exhaust_total_free_count = ctrl->total_free;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_minsize(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  minsize_alloc_1 = bpfj_heap_alloc(1);
  minsize_alloc_24 = bpfj_heap_alloc(24);
  minsize_alloc_25 = bpfj_heap_alloc(25);

  minsize_used_after_alloc = ctrl->current_used;

  bpfj_heap_free(minsize_alloc_1);
  bpfj_heap_free(minsize_alloc_24);
  bpfj_heap_free(minsize_alloc_25);

  minsize_used_after_free = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_large(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  large_alloc_off = bpfj_heap_alloc(200000);

  large_used_after_alloc = ctrl->current_used;

  bpfj_heap_free(large_alloc_off);

  large_used_after_free = ctrl->current_used;

  large_realloc_off = bpfj_heap_alloc(200000);

  large_realloc_used = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_free_null(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  bpfj_heap_free(0);

  fnull_total_free_after_null = ctrl->total_free;
  fnull_used_after_null = ctrl->current_used;

  bpfj_heap_free(4);

  fnull_total_free_after_small = ctrl->total_free;
  fnull_used_after_small = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_coalesce_all(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  coal_alloc1 = bpfj_heap_alloc(64);
  coal_alloc2 = bpfj_heap_alloc(64);
  coal_alloc3 = bpfj_heap_alloc(64);

  coal_used_after_alloc = ctrl->current_used;

  bpfj_heap_free(coal_alloc1);
  bpfj_heap_free(coal_alloc3);
  bpfj_heap_free(coal_alloc2);

  coal_used_after_free_all = ctrl->current_used;

  coal_large_alloc_off = bpfj_heap_alloc(192);

  coal_total_alloc_count = ctrl->total_alloc;
  coal_total_free_count = ctrl->total_free;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_alignment(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  __u32 sizes[ALIGN_NUM_ALLOCS] = {1, 3, 7, 9, 13, 31, 33, 100};
  int i;

  align_all_nonzero = 1;
  for (i = 0; i < ALIGN_NUM_ALLOCS; i++) {
    align_offsets[i] = bpfj_heap_alloc(sizes[i]);
    if (align_offsets[i] == 0)
      align_all_nonzero = 0;
  }

  align_all_aligned = 1;
  for (i = 0; i < ALIGN_NUM_ALLOCS; i++) {
    if (align_offsets[i] != 0 && (align_offsets[i] % BPFJ_HEAP_ALIGN) != 0)
      align_all_aligned = 0;
  }

  for (i = 0; i < ALIGN_NUM_ALLOCS; i++)
    bpfj_heap_free(align_offsets[i]);

  align_used_after_free = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_double(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  __u32 count = 0;
  int i;
  for (i = 0; i < DOUBLE_MAX_ALLOCS; i++) {
    __u32 off = bpfj_heap_alloc(50000);
    if (off == 0)
      break;
    double_offsets[i] = off;
    count++;
  }
  double_exhaust_count = count;

  double_ret = bpfj_arena_double();

  double_new_arena_size = ctrl->arena_size;

  double_post_alloc = bpfj_heap_alloc(50000);

  for (i = 0; i < DOUBLE_MAX_ALLOCS; i++) {
    if (double_offsets[i] != 0)
      bpfj_heap_free(double_offsets[i]);
  }
  if (double_post_alloc != 0)
    bpfj_heap_free(double_post_alloc);

  double_used_after_free_all = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_interleaved(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  ileave_off_a = bpfj_heap_alloc(64);
  ileave_used[0] = ctrl->current_used;

  ileave_off_b = bpfj_heap_alloc(64);
  ileave_used[1] = ctrl->current_used;

  bpfj_heap_free(ileave_off_a);
  ileave_used[2] = ctrl->current_used;

  ileave_off_c = bpfj_heap_alloc(64);
  ileave_used[3] = ctrl->current_used;

  ileave_off_d = bpfj_heap_alloc(64);
  ileave_used[4] = ctrl->current_used;

  bpfj_heap_free(ileave_off_c);
  ileave_used[5] = ctrl->current_used;

  bpfj_heap_free(ileave_off_b);
  ileave_used[6] = ctrl->current_used;

  bpfj_heap_free(ileave_off_d);
  ileave_used[7] = ctrl->current_used;

  ileave_total_alloc_count = ctrl->total_alloc;
  ileave_total_free_count = ctrl->total_free;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_split_exact(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  // Phase 1: exact-fit (no split possible)
  __u32 off1 = bpfj_heap_alloc(24);
  bpfj_heap_free(off1);
  split_no_split_off = bpfj_heap_alloc(24);
  split_used_no_split = ctrl->current_used;
  bpfj_heap_free(split_no_split_off);

  // Phase 2: split should occur
  __u32 big = bpfj_heap_alloc(8192);
  bpfj_heap_free(big);
  split_split_off = bpfj_heap_alloc(24);
  split_used_with_split = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_userspace_init(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  // Record whether userspace already initialized the heap.
  usinit_was_initialized = bpfj_heap_get_ctrl()->arena_size != 0;

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  usinit_alloc_off = bpfj_heap_alloc(128);
  usinit_used_after_alloc = ctrl->current_used;

  bpfj_heap_free(usinit_alloc_off);
  usinit_used_after_free = ctrl->current_used;
  usinit_total_alloc = ctrl->total_alloc;
  usinit_total_free = ctrl->total_free;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_calloc(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  calloc_off = bpfj_heap_calloc(256);

  if (calloc_off != BPFJ_HEAP_NULL) {
    calloc_used_after_alloc = ctrl->current_used;

    // Verify all 256 bytes are zero (check 8 bytes at a time).
    void __arena* base = (void __arena*)ctrl;
    calloc_all_zero = 1;
    int i;
    for (i = 0; i < 32; i++) { // 256 / 8 = 32 iterations
      __u32 off = calloc_off + (__u32)i * 8;
      off = off & (BPFJ_HEAP_MAX_ARENA_SIZE - 1);
      __u64 __arena* p = (__u64 __arena*)((char __arena*)base + off);
      if (*p != 0)
        calloc_all_zero = 0;
    }

    bpfj_heap_free(calloc_off);
    calloc_used_after_free = ctrl->current_used;
  }

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_realloc(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  void __arena* base = (void __arena*)ctrl;

  // Test 1: realloc(NULL, 64) == alloc(64)
  realloc_null_alloc_off = bpfj_heap_realloc(BPFJ_HEAP_NULL, 64);
  if (realloc_null_alloc_off == BPFJ_HEAP_NULL) {
    done = 1;
    return 0;
  }

  // Write marker bytes (0xAA) to the first 64 bytes (8 words).
  int i;
  for (i = 0; i < 8; i++) { // 64 / 8 = 8 iterations
    __u32 off = realloc_null_alloc_off + (__u32)i * 8;
    off = off & (BPFJ_HEAP_MAX_ARENA_SIZE - 1);
    __u64 __arena* p = (__u64 __arena*)((char __arena*)base + off);
    *p = 0xAAAAAAAAAAAAAAAAULL;
  }

  // Test 2: realloc(off, 128) — grow
  realloc_grown_off = bpfj_heap_realloc(realloc_null_alloc_off, 128);
  if (realloc_grown_off != BPFJ_HEAP_NULL) {
    // Verify first 64 bytes are still 0xAA.
    realloc_data_preserved = 1;
    for (i = 0; i < 8; i++) {
      __u32 off = realloc_grown_off + (__u32)i * 8;
      off = off & (BPFJ_HEAP_MAX_ARENA_SIZE - 1);
      __u64 __arena* p = (__u64 __arena*)((char __arena*)base + off);
      if (*p != 0xAAAAAAAAAAAAAAAAULL)
        realloc_data_preserved = 0;
    }

    // Test 3: realloc(off, 32) — shrink
    realloc_shrunk_off = bpfj_heap_realloc(realloc_grown_off, 32);

    if (realloc_shrunk_off != BPFJ_HEAP_NULL) {
      // Test 4: realloc(off, 0) — free
      realloc_free_ret = bpfj_heap_realloc(realloc_shrunk_off, 0);
    }
  }

  realloc_used_after_free_all = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_coalesce_forward(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  // Exhaust the heap with 50000-byte blocks.
  __u32 count = 0;
  int i;
  for (i = 0; i < CFWD_MAX_ALLOCS; i++) {
    __u32 off = bpfj_heap_alloc(50000);
    if (off == 0)
      break;
    cfwd_offsets[i] = off;
    count++;
  }
  cfwd_exhaust_count = count;

  // Forward coalescing test: free block[3] first (C), then block[2] (B).
  // When B is freed, its next physical neighbor C is already free,
  // so bpfj_heap_merge_next should merge B+C into one block.
  if (count > 3) {
    bpfj_heap_free(cfwd_offsets[3]);
    bpfj_heap_free(cfwd_offsets[2]);

    // Attempt allocation that requires merged B+C space.
    // Neither B nor C alone (~50008 bytes) is large enough.
    // Use 90000 (not 100000) to avoid TLSF bucket boundary effects.
    cfwd_merged_alloc = bpfj_heap_alloc(90000);

    // Free the merged alloc if it succeeded.
    if (cfwd_merged_alloc != 0)
      bpfj_heap_free(cfwd_merged_alloc);
  }

  // Free remaining blocks.
  for (i = 0; i < CFWD_MAX_ALLOCS; i++) {
    if (i == 2 || i == 3)
      continue; // already freed
    if (cfwd_offsets[i] != 0)
      bpfj_heap_free(cfwd_offsets[i]);
  }

  cfwd_used_after_free_all = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_coalesce_backward(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  // Exhaust the heap with 50000-byte blocks.
  __u32 count = 0;
  int i;
  for (i = 0; i < CBWD_MAX_ALLOCS; i++) {
    __u32 off = bpfj_heap_alloc(50000);
    if (off == 0)
      break;
    cbwd_offsets[i] = off;
    count++;
  }
  cbwd_exhaust_count = count;

  // Backward coalescing test: free block[2] first (B), then block[3] (C).
  // When C is freed, its PREV_FREE flag is set (B is free),
  // so bpfj_heap_merge_prev should merge C into B.
  if (count > 3) {
    bpfj_heap_free(cbwd_offsets[2]);
    bpfj_heap_free(cbwd_offsets[3]);

    // Attempt allocation that requires merged B+C space.
    // Use 90000 (not 100000) to avoid TLSF bucket boundary effects.
    cbwd_merged_alloc = bpfj_heap_alloc(90000);

    // Free the merged alloc if it succeeded.
    if (cbwd_merged_alloc != 0)
      bpfj_heap_free(cbwd_merged_alloc);
  }

  // Free remaining blocks.
  for (i = 0; i < CBWD_MAX_ALLOCS; i++) {
    if (i == 2 || i == 3)
      continue; // already freed
    if (cbwd_offsets[i] != 0)
      bpfj_heap_free(cbwd_offsets[i]);
  }

  cbwd_used_after_free_all = ctrl->current_used;

  done = 1;
  return 0;
}

SEC("syscall")
int test_heap_userspace_alloc(void* ctx) {
  if (done)
    return 0;

  bpfj_heap_use_arena();

  usalloc_was_initialized = bpfj_heap_get_ctrl()->arena_size != 0;

  init_ret = 0;

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  void __arena* base = (void __arena*)ctrl;

  usalloc_used_seen_by_bpf = ctrl->current_used;

  // Verify values written by userspace at each offset
  usalloc_values_ok = 1;
  __u32 count = usalloc_count;
  int i;
  for (i = 0; i < USALLOC_NUM_BLOCKS; i++) {
    if ((__u32)i >= count)
      break;
    __u32 off = usalloc_offsets[i];
    if (off == 0) {
      usalloc_values_ok = 0;
      continue;
    }
    off = off & (BPFJ_HEAP_MAX_ARENA_SIZE - 1);
    __u64 __arena* p = (__u64 __arena*)((char __arena*)base + off);
    if (*p != USALLOC_MAGIC_BASE + (__u64)i)
      usalloc_values_ok = 0;
  }

  // Allocate from BPF side (proves shared heap works)
  usalloc_bpf_alloc_off = bpfj_heap_alloc(64);
  usalloc_used_after_bpf_alloc = ctrl->current_used;

  // Free the BPF allocation
  if (usalloc_bpf_alloc_off != 0)
    bpfj_heap_free(usalloc_bpf_alloc_off);

  // Free userspace allocations from BPF
  usalloc_bpf_free_ok = 1;
  for (i = 0; i < USALLOC_NUM_BLOCKS; i++) {
    if ((__u32)i >= count)
      break;
    if (usalloc_offsets[i] != 0) {
      long ret = bpfj_heap_free(usalloc_offsets[i]);
      if (ret < 0)
        usalloc_bpf_free_ok = 0;
    }
  }

  usalloc_used_after_bpf_free_all = ctrl->current_used;

  done = 1;
  return 0;
}

int _version SEC("version") = 1;
char _license[] SEC("license") = "Dual MIT/GPL";
