// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cstring>
#include <memory>
#include <unordered_map>
#include <vector>

#include "bpfj/lib/PerfMap.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/perf_map_test.skel.h"

using namespace bpfjailer;

namespace {

void runPerfMapLookup(
    __u64 needle,
    const std::unordered_map<__u64, __u64>& entries,
    long& out_ret,
    __u64& out_val) {
  using Skel = bpfj::libbpf::BpfSkel<perf_map_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;

  skel->rodata().lookup_key = needle;

  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  // init() allocates the header on the arena and records its pointer in
  // skel.bss().map, which is how the BPF program finds it.
  PerfMap perfMap{skel, skel->bss().map};
  ASSERT_OK(perfMap.init(entries));

  const auto cleanup = makeGuard([&] {
    perfMap.destroy();
    ASSERT_EQ(heap::currentUsed(skel), 0U);
  });

  LIBBPF_OPTS(bpf_test_run_opts, opts);
  const int fd = bpf_program__fd(skel->progs().test_perf_map_lookup);
  ASSERT(fd >= 0);
  ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
  ASSERT_EQ(static_cast<int>(opts.retval), 0);

  out_ret = skel->bss().ret;
  out_val = skel->bss().val;
}

} // namespace

TEST(PerfMap, TestMatch) {
  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup(1, {{1, 100}, {2, 200}, {3, 300}}, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 100);
}

TEST(PerfMap, TestMiss) {
  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup(99, {{1, 100}, {2, 200}, {3, 300}}, ret, val);
  ASSERT_EQ(ret, -ENOENT);
  ASSERT_EQ(val, 0);
}

TEST(PerfMap, TestMatchDifferentKey) {
  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup(3, {{1, 100}, {2, 200}, {3, 300}}, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 300);
}

TEST(PerfMap, TestSingleEntry) {
  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup(42, {{42, 12345}}, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 12345);
}

TEST(PerfMap, TestMissOnSingleEntry) {
  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup(43, {{42, 12345}}, ret, val);
  ASSERT_EQ(ret, -ENOENT);
}

TEST(PerfMap, TestLargerMap) {
  std::unordered_map<__u64, __u64> entries;
  for (__u64 i = 0; i < 50; ++i) {
    entries[(i * 7) + 1] = i + 1;
  }

  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup((15 * 7) + 1, entries, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 16);
}

TEST(PerfMap, TestLargerMapMiss) {
  std::unordered_map<__u64, __u64> entries;
  for (__u64 i = 0; i < 50; ++i) {
    entries[(i * 7) + 1] = i + 1;
  }

  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup(9999, entries, ret, val);
  ASSERT_EQ(ret, -ENOENT);
}

TEST(PerfMap, TestEmptyMap) {
  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup(1, {}, ret, val);
  ASSERT_EQ(ret, -ENOENT);
}

TEST(PerfMap, TestZeroKey) {
  long ret = 0;
  __u64 val = 0;
  runPerfMapLookup(0, {{0, 777}}, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 777);
}

TEST(PerfMap, TestMaxU64Key) {
  long ret = 0;
  __u64 val = 0;
  __u64 maxKey = UINT64_MAX;
  runPerfMapLookup(maxKey, {{maxKey, 42}}, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 42);
}

TEST(PerfMap, TestDestroy) {
  using Skel = bpfj::libbpf::BpfSkel<perf_map_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;
  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  PerfMap perfMap{skel, skel->bss().map};
  std::unordered_map<__u64, __u64> entries = {{1, 10}, {2, 20}};
  auto res = perfMap.init(entries);
  ASSERT_TRUE(res);

  ASSERT_NE(skel->bss().map, nullptr);
  ASSERT_NE(skel->bss().map->seeds, nullptr);
  ASSERT_NE(skel->bss().map->slots, nullptr);

  // destroy() owns the header too, so it releases every byte it allocated and
  // leaves the caller's slot empty.
  perfMap.destroy();
  ASSERT_EQ(skel->bss().map, nullptr);
  ASSERT_EQ(heap::currentUsed(skel), 0U);
}

TEST(PerfMap, TestFailedInitUnwindsItself) {
  // init() publishes the header before it can know the tables will fit, so
  // every failure after that point has to hand it back: a caller that gives up
  // on a failed init() does not call destroy() (FileMatchCached's inner nodes
  // maps just return the error), and the destructor aborts on a slot that is
  // still set. Note there is no destroy() call below -- that is the point.
  //
  // The failure is forced by asking for more slot table than the arena can hold
  // at any size, which fails after the header is already allocated.
  using Skel = bpfj::libbpf::BpfSkel<perf_map_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;
  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  // init() over-provisions to 2 slots per key, so this many keys needs more
  // than the whole arena for the slot table alone. A vector of pairs rather
  // than a hash map keeps the setup cheap; init() only sizes and iterates it.
  const std::size_t numKeys =
      (BPFJ_HEAP_MAX_ARENA_SIZE / (2 * sizeof(struct bpfj_perf_map_slot))) + 1;
  std::vector<std::pair<__u64, __u64>> entries;
  entries.reserve(numKeys);
  for (std::size_t i = 0; i < numKeys; ++i) {
    entries.emplace_back(static_cast<__u64>(i) + 1, i);
  }

  {
    PerfMap perfMap{skel, skel->bss().map};
    auto res = perfMap.init(entries);
    ASSERT_FALSE(res);
    ASSERT_EQ(skel->bss().map, nullptr);
    ASSERT_EQ(heap::currentUsed(skel), 0U);
  }
}

// A minimal perfect-hash table (num_slots == num_keys, load factor 1.0) cannot
// be constructed once the key set is large enough: the greedy displacement in
// init() runs out of slots for the last buckets and fails with "Failed to find
// perfect hash for bucket". On twshared that made the entire FS2 enforcer fail
// to load. The table must over-provision slots (load factor ~0.5). Guard that
// invariant directly so a revert to a minimal table is caught deterministically
// — independent of the pseudo-random placement outcome.
TEST(PerfMap, TestLargePolicyOverProvisionsSlots) {
  using Skel = bpfj::libbpf::BpfSkel<perf_map_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;
  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  std::unordered_map<__u64, __u64> entries;
  for (__u64 i = 0; i < 512; ++i) {
    entries[(i * 2654435761ULL) + 1] = i + 1;
  }

  PerfMap perfMap{skel, skel->bss().map};
  auto res = perfMap.init(entries);
  ASSERT_TRUE(res);

  ASSERT_NE(skel->bss().map, nullptr);
  ASSERT_EQ(skel->bss().map->num_buckets, entries.size());
  ASSERT_GE(skel->bss().map->num_slots, 2U * skel->bss().map->num_buckets);

  perfMap.destroy();
}

// Functional check that a large policy (well past the sizes that fail to build
// with a minimal table) constructs and every sampled key round-trips through
// the real BPF lookup: present keys resolve to their values, absent keys miss.
TEST(PerfMap, TestLargePolicyRoundTrip) {
  constexpr __u64 kNumEntries = 4096;
  std::unordered_map<__u64, __u64> entries;
  entries.reserve(kNumEntries);
  for (__u64 i = 0; i < kNumEntries; ++i) {
    entries[(i * 2654435761ULL) + 1] = i + 1000;
  }

  for (__u64 i : {0ULL, 2048ULL, 4095ULL}) {
    long ret = 0;
    __u64 val = 0;
    runPerfMapLookup((i * 2654435761ULL) + 1, entries, ret, val);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(val, i + 1000);
  }

  // Keys 2 and 3 are absent (the only small key is 1, from i == 0).
  for (__u64 missKey : {2ULL, 3ULL}) {
    long ret = 0;
    __u64 val = 0;
    runPerfMapLookup(missKey, entries, ret, val);
    ASSERT_EQ(ret, -ENOENT);
  }
}
