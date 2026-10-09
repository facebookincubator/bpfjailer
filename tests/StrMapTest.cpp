// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cstring>
#include <unordered_map>
#include <vector>

#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/lib/StrMap.h"
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/str_map_test.skel.h"

using namespace bpfjailer;

namespace {

constexpr std::string_view kStr1 = "str1";
constexpr std::string_view kStr2 = "str2";
constexpr std::string_view kStr3 = "str3";
constexpr std::string_view kStr4 = "str4";

// The arena is mmap'd behind the sanitizer's back, so writes to it need the
// attribute to land -- same as the accessors in StrMap.h.
__attribute__((no_sanitize("address"))) void writePayload(
    __u64* block,
    __u64 payload) {
  *block = payload;
}

// `entries` maps each key to the payload its block holds, not to the entry
// value itself: the value is an arena pointer now, so every key gets a block
// and the BPF side reports what it read through the pointer it looked up.
void runStrMapLookup(
    std::string_view needle,
    const std::unordered_map<std::string_view, std::size_t>& entries,
    long& out_ret,
    __u64& out_val) {
  using Skel = bpfj::libbpf::BpfSkel<str_map_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;

  ASSERT(needle.size() <= sizeof(skel->rodata().to_match));
  std::memcpy(skel->rodata().to_match, needle.data(), needle.size());
  skel->rodata().to_match_size = needle.size();

  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  std::unordered_map<std::string_view, void*> blocks;
  std::vector<__u64*> allocated;
  for (auto&& [key, payload] : entries) {
    auto* block = heap::alloc<__u64>(skel);
    ASSERT_NE(block, nullptr);
    writePayload(block, payload);
    blocks.emplace(key, block);
    allocated.push_back(block);
  }

  // init() allocates the header on the arena and records its pointer in
  // skel.bss().map, which is how the BPF program finds it.
  StrMap strMap{skel, skel->bss().map};
  ASSERT_OK(strMap.init(blocks));

  const auto cleanup = makeGuard([&] {
    strMap.destroy();
    // The map holds the blocks but does not own them, so they come back here.
    for (auto* block : allocated) {
      heap::free(skel, block);
    }
    ASSERT_EQ(heap::currentUsed(skel), 0U);
  });

  LIBBPF_OPTS(bpf_test_run_opts, opts);
  const int fd = bpf_program__fd(skel->progs().test_str_match);
  ASSERT(fd >= 0);
  ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
  ASSERT_EQ(static_cast<int>(opts.retval), 0);

  out_ret = skel->bss().ret;
  out_val = skel->bss().val;
}

} // namespace

TEST(StrMap, TestFailedInitUnwindsItself) {
  // init() publishes the header before it allocates the entry vector, so a
  // failure after that has to hand the header back: a caller that gives up on a
  // failed init() does not call destroy() (FileMatchCached's inner data maps
  // just return the error), and the destructor aborts on a slot that is still
  // set. Note there is no destroy() call below -- that is the point.
  using Skel = bpfj::libbpf::BpfSkel<str_map_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;
  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  // Entries are 24 bytes apiece, so this vector cannot fit the arena at any
  // size and the allocation fails once the header is already in the slot.
  const std::size_t capacity =
      (BPFJ_HEAP_MAX_ARENA_SIZE / sizeof(struct bpfj_str_map_entry)) + 1;
  {
    StrMap strMap{skel, skel->bss().map};
    const auto res = strMap.init(capacity);
    ASSERT_FALSE(res);
    ASSERT_EQ(skel->bss().map, nullptr);
    ASSERT_EQ(heap::currentUsed(skel), 0U);
  }

  // A successful init() after a failed one still works, and still frees. A
  // real block, because an entry's value is an arena pointer; the map does not
  // own it, so it is freed separately once the map is gone.
  auto* block = heap::alloc<__u64>(skel);
  ASSERT_NE(block, nullptr);

  StrMap strMap{skel, skel->bss().map};
  ASSERT_OK(
      strMap.init(std::unordered_map<std::string_view, void*>{{kStr1, block}}));
  strMap.destroy();
  heap::free(skel, block);
  ASSERT_EQ(heap::currentUsed(skel), 0U);
}

TEST(StrMap, TestMatch) {
  long ret = 0;
  __u64 val = 0;
  runStrMapLookup(kStr1, {{kStr1, 1}, {kStr2, 2}, {kStr3, 3}}, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 1);
}

TEST(StrMap, TestMiss) {
  long ret = 0;
  __u64 val = 0;
  runStrMapLookup(kStr4, {{kStr1, 1}, {kStr2, 2}, {kStr3, 3}}, ret, val);
  ASSERT_EQ(ret, -ENOENT);
  ASSERT_EQ(val, 0);
}

TEST(StrMap, TestMatchDifferentKey) {
  long ret = 0;
  __u64 val = 0;
  runStrMapLookup(kStr3, {{kStr1, 1}, {kStr2, 2}, {kStr3, 3}}, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 3);
}

TEST(StrMap, TestSingleEntry) {
  long ret = 0;
  __u64 val = 0;
  runStrMapLookup(kStr1, {{kStr1, 42}}, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 42);
}

TEST(StrMap, TestMissEmptyPrefix) {
  long ret = 0;
  __u64 val = 0;
  runStrMapLookup("st", {{kStr1, 1}, {kStr2, 2}}, ret, val);
  ASSERT_EQ(ret, -ENOENT);
}

TEST(StrMap, TestLargerMap) {
  std::unordered_map<std::string_view, std::size_t> entries;
  std::vector<std::string> keys;
  for (int i = 0; i < 30; ++i) {
    keys.push_back("key_" + std::to_string(i));
  }
  for (int i = 0; i < 30; ++i) {
    entries.emplace(std::string_view(keys[i]), i + 1);
  }

  long ret = 0;
  __u64 val = 0;
  runStrMapLookup("key_15", entries, ret, val);
  ASSERT_EQ(ret, 0);
  ASSERT_EQ(val, 16);
}
