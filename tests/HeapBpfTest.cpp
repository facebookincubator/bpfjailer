// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cstddef>
#include <cstring>
#include <functional>
#include <memory>

#include "bpfj/lib/Heap.h"
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/heap_bpf_test.skel.h"

using namespace bpfjailer;

// Disable all BPF programs in the skeleton, then enable only the given one.
template <typename SkelType>
void enableOnly(
    bpfj::libbpf::BpfSkel<SkelType>& obj,
    struct bpf_program* prog) {
  struct bpf_program* p;
  bpf_object__for_each_program(p, obj.obj().get()) {
    bpf_program__set_autoload(p, false);
  }
  bpf_program__set_autoload(prog, true);
  if constexpr (requires { obj.progs().bpfj_heap_syscall; }) {
    bpf_program__set_autoload(obj.progs().bpfj_heap_syscall, true);
  }
}

// Load only the requested test program and the heap growth helper, initialize
// its arena, then invoke the test directly with BPF_PROG_RUN.
template <typename SkelType>
std::shared_ptr<bpfj::libbpf::BpfSkel<SkelType>> runHeapTest(
    std::shared_ptr<bpfj::libbpf::BpfSkel<SkelType>>& obj,
    const std::function<void()>& preLoadConfig = nullptr,
    const std::function<void()>& preAttachConfig = nullptr) {
  auto created = bpfj::libbpf::BpfSkel<SkelType>::create();
  ASSERT_OK(created);
  obj = *created;

  if (preLoadConfig) {
    preLoadConfig();
  }

  ASSERT_OK(obj->load());
  ASSERT_OK(heap::init(obj));

  if (preAttachConfig) {
    preAttachConfig();
  }

  struct bpf_program* testProgram = nullptr;
  struct bpf_program* program = nullptr;
  bpf_object__for_each_program(program, obj->obj().get()) {
    if (bpf_program__fd(program) >= 0 &&
        std::strcmp(bpf_program__name(program), "bpfj_heap_syscall") != 0) {
      ASSERT(testProgram == nullptr);
      testProgram = program;
    }
  }
  ASSERT(testProgram != nullptr);

  LIBBPF_OPTS(bpf_test_run_opts, opts);
  ASSERT_EQ(bpf_prog_test_run_opts(bpf_program__fd(testProgram), &opts), 0);
  ASSERT_EQ(static_cast<int>(opts.retval), 0);

  return obj;
}

// ---------------------------------------------------------------------------
// Test: heap init
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestInit) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_init); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  ASSERT_EQ(
      obj->bss().init_arena_size, BPFJ_HEAP_INIT_PAGES * BPFJ_HEAP_PAGE_SIZE);
  ASSERT_EQ(obj->bss().init_total_alloc, 0U);
  ASSERT_EQ(obj->bss().init_total_free, 0U);
  ASSERT_EQ(obj->bss().init_current_used, 0U);
  ASSERT_NE(obj->bss().init_fl_bitmap, 0U);
}

// ---------------------------------------------------------------------------
// Test: heap alloc
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestAlloc) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_alloc); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Zero-size alloc should return 0
  ASSERT_EQ(obj->bss().alloc_zero, -EINVAL);

  // All real allocations should succeed (non-zero offset)
  ASSERT_NE(obj->bss().alloc_small, 0U);
  ASSERT_NE(obj->bss().alloc_medium, 0U);
  ASSERT_NE(obj->bss().alloc_large, 0U);

  // Offsets should be different
  ASSERT_NE(obj->bss().alloc_small, obj->bss().alloc_medium);
  ASSERT_NE(obj->bss().alloc_small, obj->bss().alloc_large);
  ASSERT_NE(obj->bss().alloc_medium, obj->bss().alloc_large);

  // Should have 3 allocations
  ASSERT_EQ(obj->bss().alloc_total, 3U);

  // current_used should be > 0
  ASSERT_GT(obj->bss().alloc_used, 0U);
}

// ---------------------------------------------------------------------------
// Test: heap free and coalescing
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestFree) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_free); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // All allocations should succeed
  ASSERT_NE(obj->bss().free_alloc1_off, 0U);
  ASSERT_NE(obj->bss().free_alloc2_off, 0U);
  ASSERT_NE(obj->bss().free_alloc3_off, 0U);

  // After allocating 3 blocks, used > 0
  ASSERT_GT(obj->bss().free_used_after_alloc, 0U);

  // After freeing one block, used should decrease
  ASSERT_LT(obj->bss().free_used_after_free1, obj->bss().free_used_after_alloc);

  // After freeing two blocks, used should decrease more
  ASSERT_LT(obj->bss().free_used_after_free2, obj->bss().free_used_after_free1);

  // After freeing all, used should be 0
  ASSERT_EQ(obj->bss().free_used_after_free3, 0U);

  // Counters
  ASSERT_EQ(obj->bss().free_total_alloc_count, 3U);
  ASSERT_EQ(obj->bss().free_total_free_count, 3U);
}

// ---------------------------------------------------------------------------
// Test: heap block reuse
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestReuse) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_reuse); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Both allocations should succeed
  ASSERT_NE(obj->bss().reuse_first_alloc, 0U);
  ASSERT_NE(obj->bss().reuse_second_alloc, 0U);

  // The freed block should be reused for the same-size allocation
  ASSERT_EQ(obj->bss().reuse_reused, 1);

  // Used before and after realloc should be the same
  ASSERT_EQ(
      obj->bss().reuse_used_before_free, obj->bss().reuse_used_after_realloc);

  // Used after free should be 0
  ASSERT_EQ(obj->bss().reuse_used_after_free, 0U);
}

// ---------------------------------------------------------------------------
// Test: multiple alloc/free cycles with data integrity
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestMulti) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_multi); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // All allocations should succeed
  ASSERT_EQ(obj->bss().multi_all_nonzero, 1);

  // All offsets should be unique
  ASSERT_EQ(obj->bss().multi_all_unique, 1);

  // After allocating 8 blocks, used > 0
  ASSERT_GT(obj->bss().multi_used_after_alloc, 0U);

  // After freeing half, used should decrease
  ASSERT_LT(
      obj->bss().multi_used_after_free_half, obj->bss().multi_used_after_alloc);

  // After freeing all, used should be 0
  ASSERT_EQ(obj->bss().multi_used_after_free_all, 0U);

  // Counters
  ASSERT_EQ(obj->bss().multi_total_alloc_count, 8U);
  ASSERT_EQ(obj->bss().multi_total_free_count, 8U);
}

// ---------------------------------------------------------------------------
// Test: heap exhaustion and recovery
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestAllocExhaust) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_exhaust); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Should have allocated at least 1 block before exhaustion
  ASSERT_GT(obj->bss().exhaust_success_count, 0U);

  // Peak used should be > 0
  ASSERT_GT(obj->bss().exhaust_peak_used, 0U);

  // After freeing everything, used should be 0
  ASSERT_EQ(obj->bss().exhaust_used_after_free_all, 0U);

  // Recovery alloc should succeed (allocator still functional)
  ASSERT_NE(obj->bss().exhaust_recovery_alloc, 0U);

  // total_alloc should equal success_count + 1 (recovery alloc)
  ASSERT_EQ(
      obj->bss().exhaust_total_alloc_count,
      obj->bss().exhaust_success_count + 1U);
}

// ---------------------------------------------------------------------------
// Test: minimum size allocations
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestAllocMinSize) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_minsize); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // All allocations should succeed
  ASSERT_NE(obj->bss().minsize_alloc_1, 0U);
  ASSERT_NE(obj->bss().minsize_alloc_24, 0U);
  ASSERT_NE(obj->bss().minsize_alloc_25, 0U);

  // All offsets should be distinct
  ASSERT_NE(obj->bss().minsize_alloc_1, obj->bss().minsize_alloc_24);
  ASSERT_NE(obj->bss().minsize_alloc_1, obj->bss().minsize_alloc_25);
  ASSERT_NE(obj->bss().minsize_alloc_24, obj->bss().minsize_alloc_25);

  // Each block is at least MIN_BLOCK_SIZE (32), so used >= 3*32
  ASSERT_GE(obj->bss().minsize_used_after_alloc, 3U * BPFJ_HEAP_MIN_BLOCK_SIZE);

  // After freeing all, used should be 0
  ASSERT_EQ(obj->bss().minsize_used_after_free, 0U);
}

// ---------------------------------------------------------------------------
// Test: large allocation
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestAllocLarge) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_large); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Large alloc should succeed
  ASSERT_NE(obj->bss().large_alloc_off, 0U);
  ASSERT_GT(obj->bss().large_used_after_alloc, 0U);

  // After free, used should be 0
  ASSERT_EQ(obj->bss().large_used_after_free, 0U);

  // Re-alloc should succeed (proves coalesce restored the free block)
  ASSERT_NE(obj->bss().large_realloc_off, 0U);
  ASSERT_GT(obj->bss().large_realloc_used, 0U);
}

// ---------------------------------------------------------------------------
// Test: free of null/invalid offsets
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestFreeNull) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_free_null); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // free(0) should be a no-op
  ASSERT_EQ(obj->bss().fnull_total_free_after_null, 0U);
  ASSERT_EQ(obj->bss().fnull_used_after_null, 0U);

  // free(4) should be a no-op (offset too small)
  ASSERT_EQ(obj->bss().fnull_total_free_after_small, 0U);
  ASSERT_EQ(obj->bss().fnull_used_after_small, 0U);
}

// ---------------------------------------------------------------------------
// Test: three-way coalescing
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestCoalesceAll) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_coalesce_all); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // All 3 allocations should succeed
  ASSERT_NE(obj->bss().coal_alloc1, 0U);
  ASSERT_NE(obj->bss().coal_alloc2, 0U);
  ASSERT_NE(obj->bss().coal_alloc3, 0U);

  ASSERT_GT(obj->bss().coal_used_after_alloc, 0U);

  // After freeing all 3, used should be 0
  ASSERT_EQ(obj->bss().coal_used_after_free_all, 0U);

  // 192-byte alloc should succeed (coalesced block is large enough)
  ASSERT_NE(obj->bss().coal_large_alloc_off, 0U);

  // Counters
  ASSERT_EQ(obj->bss().coal_total_alloc_count, 4U); // 3 + 1
  ASSERT_EQ(obj->bss().coal_total_free_count, 3U);
}

// ---------------------------------------------------------------------------
// Test: allocation alignment
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestAllocAlignment) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_alignment); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // All allocations should succeed
  ASSERT_EQ(obj->bss().align_all_nonzero, 1);

  // All offsets should be 8-byte aligned
  ASSERT_EQ(obj->bss().align_all_aligned, 1);

  // After freeing all, used should be 0
  ASSERT_EQ(obj->bss().align_used_after_free, 0U);
}

// ---------------------------------------------------------------------------
// Test: heap double
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestDouble) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_double); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Should have exhausted after some allocs
  ASSERT_GT(obj->bss().double_exhaust_count, 0U);

  // Double should succeed
  ASSERT_EQ(obj->bss().double_ret, 0);

  // Arena should have grown
  ASSERT_GT(
      obj->bss().double_new_arena_size,
      BPFJ_HEAP_INIT_PAGES * BPFJ_HEAP_PAGE_SIZE);

  // Post-double alloc should succeed
  ASSERT_NE(obj->bss().double_post_alloc, 0U);

  // After freeing everything, used should be 0
  ASSERT_EQ(obj->bss().double_used_after_free_all, 0U);
}

// ---------------------------------------------------------------------------
// Test: interleaved alloc/free pattern
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestAllocFreeInterleaved) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_interleaved); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // All allocs should succeed
  ASSERT_NE(obj->bss().ileave_off_a, 0U);
  ASSERT_NE(obj->bss().ileave_off_b, 0U);
  ASSERT_NE(obj->bss().ileave_off_c, 0U);
  ASSERT_NE(obj->bss().ileave_off_d, 0U);

  // ileave_used[0] after alloc A > 0
  ASSERT_GT(obj->bss().ileave_used[0], 0U);
  // ileave_used[1] after alloc B > ileave_used[0]
  ASSERT_GT(obj->bss().ileave_used[1], obj->bss().ileave_used[0]);
  // ileave_used[2] after free A < ileave_used[1]
  ASSERT_LT(obj->bss().ileave_used[2], obj->bss().ileave_used[1]);

  // Final used (after free D) should be 0
  ASSERT_EQ(obj->bss().ileave_used[7], 0U);

  // Counters
  ASSERT_EQ(obj->bss().ileave_total_alloc_count, 4U);
  ASSERT_EQ(obj->bss().ileave_total_free_count, 4U);
}

// ---------------------------------------------------------------------------
// Test: split boundary (exact fit vs. split)
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestSplitExact) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_split_exact); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Both allocs should succeed
  ASSERT_NE(obj->bss().split_no_split_off, 0U);
  ASSERT_NE(obj->bss().split_split_off, 0U);

  // No-split case: exact-fit block, used should be exactly 32
  // (24 bytes + 8 byte header = 32, which is MIN_BLOCK_SIZE)
  ASSERT_EQ(obj->bss().split_used_no_split, 32U);

  // Split case: alloc from large block, used should also be 32
  // (not the full large block size, because split occurred)
  ASSERT_EQ(obj->bss().split_used_with_split, 32U);
}

// ---------------------------------------------------------------------------
// Test: userspace heap initialization
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestUserspaceInit) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_userspace_init); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().done, 1);

  // Userspace should have initialized the arena before BPF ran
  ASSERT_EQ(obj->bss().usinit_was_initialized, 1);

  ASSERT_EQ(obj->bss().init_ret, 0);

  // Alloc should succeed
  ASSERT_NE(obj->bss().usinit_alloc_off, 0U);

  // After alloc, used > 0
  ASSERT_GT(obj->bss().usinit_used_after_alloc, 0U);

  // After free, used should be 0
  ASSERT_EQ(obj->bss().usinit_used_after_free, 0U);

  // Counters
  ASSERT_EQ(obj->bss().usinit_total_alloc, 1U);
  ASSERT_EQ(obj->bss().usinit_total_free, 1U);
}

// ---------------------------------------------------------------------------
// Test: calloc (zeroed allocation)
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestCalloc) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_calloc); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Calloc should succeed
  ASSERT_NE(obj->bss().calloc_off, 0U);

  // All 256 bytes should be zero
  ASSERT_EQ(obj->bss().calloc_all_zero, 1);

  // After alloc, used > 0
  ASSERT_GT(obj->bss().calloc_used_after_alloc, 0U);

  // After free, used should be 0
  ASSERT_EQ(obj->bss().calloc_used_after_free, 0U);
}

// ---------------------------------------------------------------------------
// Test: realloc (resize allocation)
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestRealloc) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj, [&]() { enableOnly(*obj, obj->progs().test_heap_realloc); });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // realloc(NULL, 64) should succeed (equivalent to alloc)
  ASSERT_NE(obj->bss().realloc_null_alloc_off, 0U);

  // realloc grow should succeed
  ASSERT_NE(obj->bss().realloc_grown_off, 0U);

  // Data should be preserved after grow
  ASSERT_EQ(obj->bss().realloc_data_preserved, 1);

  // realloc shrink should succeed
  ASSERT_NE(obj->bss().realloc_shrunk_off, 0U);

  // realloc(off, 0) should free and return 0
  ASSERT_EQ(obj->bss().realloc_free_ret, 0);

  // After all operations, used should be 0
  ASSERT_EQ(obj->bss().realloc_used_after_free_all, 0U);
}

// ---------------------------------------------------------------------------
// Test: forward coalescing (merge_next)
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestCoalesceForward) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(obj, [&]() {
    enableOnly(*obj, obj->progs().test_heap_coalesce_forward);
  });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Need at least 4 blocks for the test
  ASSERT_GT(obj->bss().cfwd_exhaust_count, 3U);

  // The 90000-byte allocation must succeed, proving blocks were merged
  ASSERT_NE(obj->bss().cfwd_merged_alloc, 0U);

  // After freeing everything, used should be 0
  ASSERT_EQ(obj->bss().cfwd_used_after_free_all, 0U);
}

// ---------------------------------------------------------------------------
// Test: backward coalescing (merge_prev)
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestCoalesceBackward) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(obj, [&]() {
    enableOnly(*obj, obj->progs().test_heap_coalesce_backward);
  });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().init_ret, 0);
  ASSERT_EQ(obj->bss().done, 1);

  // Need at least 4 blocks for the test
  ASSERT_GT(obj->bss().cbwd_exhaust_count, 3U);

  // The 90000-byte allocation must succeed, proving blocks were merged
  ASSERT_NE(obj->bss().cbwd_merged_alloc, 0U);

  // After freeing everything, used should be 0
  ASSERT_EQ(obj->bss().cbwd_used_after_free_all, 0U);
}

// ---------------------------------------------------------------------------
// Test: userspace alloc, fill values, read from BPF
// ---------------------------------------------------------------------------

TEST(HeapBpf, TestUserspaceAllocReadFromBpf) {
  std::shared_ptr<bpfj::libbpf::BpfSkel<heap_bpf_test_bpf>> obj;

  auto handler = runHeapTest(
      obj,
      [&]() { enableOnly(*obj, obj->progs().test_heap_userspace_alloc); },
      [&]() {
        void* arena = bpfjailer::heap::base(obj);

        // Allocate 4 blocks from userspace and write magic values
        for (__u32 i = 0; i < 4; i++) {
          auto off = bpfjailer::heap::allocOffset(obj, 64);
          if (off == BPFJ_HEAP_NULL) {
            return;
          }
          obj->bss().usalloc_offsets[i] = static_cast<__u32>(off);

          auto* p = reinterpret_cast<__u64*>(
              bpfjailer::heap::offsetToPtr(arena, static_cast<__u32>(off)));
          *p = 0xDEADBEEF42ULL + i;
        }
        obj->bss().usalloc_count = 4;
      });
  ASSERT_NE(handler, nullptr);

  ASSERT_EQ(obj->bss().done, 1);

  // Userspace should have initialized the arena before BPF ran
  ASSERT_EQ(obj->bss().usalloc_was_initialized, 1);

  ASSERT_EQ(obj->bss().init_ret, 0);

  // BPF should have seen allocated memory
  ASSERT_GT(obj->bss().usalloc_used_seen_by_bpf, 0U);

  // BPF should have read the magic values written by userspace
  ASSERT_EQ(obj->bss().usalloc_values_ok, 1);

  // BPF should be able to allocate from the same heap
  ASSERT_NE(obj->bss().usalloc_bpf_alloc_off, 0U);

  // BPF should be able to free userspace-allocated blocks
  ASSERT_EQ(obj->bss().usalloc_bpf_free_ok, 1);

  // After freeing everything, used should be 0
  ASSERT_EQ(obj->bss().usalloc_used_after_bpf_free_all, 0U);
}
