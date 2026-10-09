// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cstdint>
#include <vector>

#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/vec_test.skel.h"

using namespace bpfjailer;

namespace {

// What the BPF side pushed at index i. Recomputed here rather than read back
// from the implementation, so a growth that dropped or reordered an element
// fails instead of agreeing with itself.
__u64 valueAt(__u32 i) {
  return (static_cast<__u64>(i) * 0x9e3779b9ULL) + 1;
}

// Mirrors BPFJ_VEC_MIN_CAPACITY for scripting a run; every run asserts the BPF
// side agrees, so the two cannot drift apart silently.
constexpr __u32 kMinCapacity = 4;

struct VecConfig {
  __u32 reserveTo = 0;
  __u32 pushCount = 0;
  bool usePushBack = true;
  bool clearAfter = false;
  __u32 popAfter = 0;
};

struct VecResult {
  long ret = 0;
  __u32 capacityWhenEmpty = 0;
  bool bufNullWhenEmpty = false;
  __u32 capacityAfterReserve = 0;
  __u32 finalSize = 0;
  __u32 finalCapacity = 0;
  bool atPastEndNull = false;
  __u32 valuesRead = 0;
  std::vector<__u64> values;
  __u32 minCapacity = 0;
  __u64 usedWhenEmpty = 0;
  __u64 usedAfterDestroy = 0;
};

// Drives one scripted run of the vec through prog_test_run.
void runVec(const VecConfig& cfg, VecResult& out) {
  using Skel = bpfj::libbpf::BpfSkel<vec_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;

  skel->rodata().reserve_to = cfg.reserveTo;
  skel->rodata().push_count = cfg.pushCount;
  skel->rodata().use_push_back = cfg.usePushBack;
  skel->rodata().clear_after = cfg.clearAfter ? 1 : 0;
  skel->rodata().pop_after = cfg.popAfter;

  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  LIBBPF_OPTS(bpf_test_run_opts, opts);
  const int fd = bpf_program__fd(skel->progs().test_vec);
  ASSERT(fd >= 0);
  ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
  ASSERT_EQ(static_cast<int>(opts.retval), 0);

  out.minCapacity = skel->rodata().min_capacity;
  out.ret = skel->bss().ret;
  out.capacityWhenEmpty = skel->bss().capacity_when_empty;
  out.bufNullWhenEmpty = skel->bss().buf_null_when_empty;
  out.capacityAfterReserve = skel->bss().capacity_after_reserve;
  out.finalSize = skel->bss().final_size;
  out.finalCapacity = skel->bss().final_capacity;
  out.atPastEndNull = skel->bss().at_past_end_null;
  out.valuesRead = skel->bss().values_read;
  out.usedWhenEmpty = skel->bss().used_when_empty;
  out.usedAfterDestroy = skel->bss().used_after_destroy;

  out.values.clear();
  for (__u32 i = 0; i < out.valuesRead; ++i) {
    out.values.push_back(skel->bss().values[i]);
  }

  // Every run destroys the vec, so every run has to give back everything it
  // took. Checked here rather than in one test, because it is the property most
  // likely to break and least likely to be noticed.
  ASSERT_EQ(out.usedAfterDestroy, out.usedWhenEmpty);
  ASSERT_EQ(out.minCapacity, kMinCapacity);
}

std::vector<__u64> expectedValues(__u32 n) {
  std::vector<__u64> out;
  out.reserve(n);
  for (__u32 i = 0; i < n; ++i) {
    out.push_back(valueAt(i));
  }
  return out;
}

} // namespace

TEST(Vec, TestEmptyOwnsNothing) {
  VecResult out;
  runVec({}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_TRUE(out.bufNullWhenEmpty);
  ASSERT_EQ(out.capacityWhenEmpty, 0U);
  ASSERT_EQ(out.finalSize, 0U);
  ASSERT_TRUE(out.atPastEndNull);
}

TEST(Vec, TestFirstPushAllocatesMinimum) {
  VecResult out;
  runVec({.pushCount = 1}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.finalSize, 1U);
  ASSERT_EQ(out.finalCapacity, out.minCapacity);
  ASSERT(out.values == expectedValues(1));
}

TEST(Vec, TestFillingCapacityDoesNotGrow) {
  VecResult out;
  runVec({.pushCount = kMinCapacity}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.finalCapacity, out.minCapacity);
  ASSERT(out.values == expectedValues(kMinCapacity));
}

TEST(Vec, TestPushPastCapacityDoubles) {
  VecResult out;
  runVec({.pushCount = kMinCapacity + 1}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.finalCapacity, out.minCapacity * 2);
  ASSERT(out.values == expectedValues(kMinCapacity + 1));
}

TEST(Vec, TestContentsSurviveRepeatedGrowth) {
  // 33 pushes from a capacity of 4 is four reallocations, so every element has
  // been copied forward several times by the end.
  VecResult out;
  runVec({.pushCount = 33}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.finalSize, 33U);
  ASSERT_EQ(out.finalCapacity, 64U);
  ASSERT(out.values == expectedValues(33));
}

TEST(Vec, TestEmplaceBackWritesTheSlot) {
  // Same script through the emplace path, which is what a caller inside a
  // bpf_for uses.
  VecResult out;
  runVec({.pushCount = 33, .usePushBack = false}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.finalSize, 33U);
  ASSERT(out.values == expectedValues(33));
}

TEST(Vec, TestReserveJumpsStraightToFit) {
  VecResult out;
  runVec({.reserveTo = 40, .pushCount = 40}, out);

  ASSERT_EQ(out.ret, 0);
  // Rounded up to a power of two in one step, not reached by doubling from 4.
  ASSERT_EQ(out.capacityAfterReserve, 64U);
  ASSERT_EQ(out.finalCapacity, 64U);
  ASSERT(out.values == expectedValues(40));
}

TEST(Vec, TestReserveWithinCapacityIsANoOp) {
  VecResult out;
  runVec({.reserveTo = 2, .pushCount = 2}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.capacityAfterReserve, out.minCapacity);
  ASSERT_EQ(out.finalCapacity, out.minCapacity);
}

TEST(Vec, TestClearKeepsCapacity) {
  VecResult out;
  runVec({.pushCount = 10, .clearAfter = true}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.finalSize, 0U);
  ASSERT_EQ(out.finalCapacity, 16U);
  ASSERT_EQ(out.valuesRead, 0U);
  ASSERT_TRUE(out.atPastEndNull);
}

TEST(Vec, TestPopBackShortensWithoutDisturbingTheRest) {
  VecResult out;
  runVec({.pushCount = 10, .popAfter = 3}, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.finalSize, 7U);
  ASSERT_EQ(out.finalCapacity, 16U);
  ASSERT(out.values == expectedValues(7));
  ASSERT_TRUE(out.atPastEndNull);
}
