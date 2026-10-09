// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <vector>

#include "bpfj/lib/Heap.h"
#include "bpfj/lib/bpf/types_dyn_map.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/dyn_map_test.skel.h"

using namespace bpfjailer;

namespace {

enum {
  OP_LOOKUP = 0,
  OP_INSERT = 1,
  OP_DELETE = 2,
  OP_DESTROY = 3,
  OP_INSERT_SHARED = 4,
  OP_DELETE_IF_UNIQUE = 5,
  OP_INSERT_FIXED = 6,
};

// One userspace-seeded entry. `tail` fills every key word after the first, so a
// map running wider than one word can hold keys that agree on their first word
// and differ later.
struct DynMapSeed {
  __u64 key = 0;
  __u64 tail = 0;
  __u64 val = 0;
};

struct DynMapConfig {
  __u32 op = OP_LOOKUP;
  __u64 key = 0;
  __u64 key_tail = 0;
  __u64 val = 0;
  __u64 key2 = 0; // secondary lookup (verify a rehash survivor)
  __u64 key2_tail = 0;
  __u32 init_capacity = BPFJ_DYN_MAP_MIN_CAPACITY;
  __u32 key_size = sizeof(__u64);
  __u32 val_size = sizeof(__u64);
  // Hold a reference to `key`'s value across the op (see dyn_map_test.bpf.c).
  bool hold_ref = false;
  std::vector<DynMapSeed> seed;
  // If non-zero, seed into a buffer of exactly this capacity (rather than
  // auto-sizing) so the map can be primed near its load-factor threshold.
  __u32 seed_capacity = 0;
};

struct DynMapResult {
  long ret = 0;
  long seed_ret = 0; // first failing seed insert, 0 if the map seeded cleanly
  long lookup_ret = 0;
  __u64 lookup_val = 0;
  long lookup2_ret = 0;
  __u64 lookup2_val = 0;
  __u32 pre_capacity = 0;
  __u32 final_capacity = 0;
  __u32 final_size = 0;
  __u32 final_tombstones = 0;
  __u32 seeds_found = 0;
  // Arena bytes one key block plus one value block costs, what the reference
  // count the map puts on a value costs, and the bytes in use either side of
  // the op. See the same names in dyn_map_test.bpf.c.
  __u64 entry_bytes = 0;
  __u64 refcount_bytes = 0;
  __u64 used_at_start = 0;
  __u64 header_bytes = 0;
  __u64 used_before = 0;
  __u64 used_after = 0;
  // The reference insert_shared returned or hold_ref kept, read after the op.
  __u32 ref_use_count = 0;
  __u64 ref_val = 0;
};

void runDynMap(const DynMapConfig& cfg, DynMapResult& out) {
  using Skel = bpfj::libbpf::BpfSkel<dyn_map_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;

  skel->rodata().op = cfg.op;
  skel->rodata().key = cfg.key;
  skel->rodata().key_tail = cfg.key_tail;
  skel->rodata().val = cfg.val;
  skel->rodata().key2 = cfg.key2;
  skel->rodata().key2_tail = cfg.key2_tail;
  skel->rodata().init_key_size = cfg.key_size;
  skel->rodata().init_val_size = cfg.val_size;
  skel->rodata().hold_ref = cfg.hold_ref;
  // A non-zero seed_capacity primes the map's buffer at exactly that capacity
  // (see DynMapConfig); otherwise fall back to the explicit init_capacity.
  skel->rodata().init_capacity =
      cfg.seed_capacity ? cfg.seed_capacity : cfg.init_capacity;

  const std::size_t kMaxSeed =
      sizeof(skel->rodata().seed_keys) / sizeof(skel->rodata().seed_keys[0]);
  ASSERT_LE(cfg.seed.size(), kMaxSeed);
  std::size_t i = 0;
  for (auto&& seed : cfg.seed) {
    skel->rodata().seed_keys[i] = seed.key;
    skel->rodata().seed_key_tails[i] = seed.tail;
    skel->rodata().seed_vals[i] = seed.val;
    ++i;
  }
  skel->rodata().seed_count = static_cast<__u32>(i);

  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  LIBBPF_OPTS(bpf_test_run_opts, opts);
  const int fd = bpf_program__fd(skel->progs().test_dyn_map);
  ASSERT(fd >= 0);
  ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
  ASSERT_EQ(static_cast<int>(opts.retval), 0);

  out.ret = skel->bss().ret;
  out.seed_ret = skel->bss().seed_ret;
  out.lookup_ret = skel->bss().lookup_ret;
  out.lookup_val = skel->bss().lookup_val;
  out.lookup2_ret = skel->bss().lookup2_ret;
  out.lookup2_val = skel->bss().lookup2_val;
  out.pre_capacity = skel->bss().pre_capacity;
  out.final_capacity = skel->bss().final_capacity;
  out.final_size = skel->bss().final_size;
  out.final_tombstones = skel->bss().final_tombstones;
  out.seeds_found = skel->bss().seeds_found;
  out.entry_bytes = skel->bss().entry_bytes;
  out.refcount_bytes = skel->bss().refcount_bytes;
  out.used_at_start = skel->bss().used_at_start;
  out.header_bytes = skel->bss().header_bytes;
  out.used_before = skel->bss().used_before;
  out.used_after = skel->bss().used_after;
  out.ref_use_count = skel->bss().ref_use_count;
  out.ref_val = skel->bss().ref_val;

  // A half-seeded map makes every later expectation lie about the thing it
  // meant to check, so fail here on the setup instead.
  ASSERT_EQ(out.seed_ret, 0);
}

} // namespace

TEST(DynMap, SeededLookupHit) {
  DynMapConfig cfg;
  cfg.op = OP_LOOKUP;
  cfg.key = 2;
  cfg.seed = {
      {.key = 1, .val = 10}, {.key = 2, .val = 20}, {.key = 3, .val = 30}};

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 20);
}

TEST(DynMap, SeededLookupMiss) {
  DynMapConfig cfg;
  cfg.op = OP_LOOKUP;
  cfg.key = 99;
  cfg.seed = {
      {.key = 1, .val = 10}, {.key = 2, .val = 20}, {.key = 3, .val = 30}};

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.lookup_ret, -ENOENT);
}

TEST(DynMap, ZeroKeyIsValid) {
  // An all-zero key is legal; the explicit slot state must distinguish it from
  // empty.
  DynMapConfig cfg;
  cfg.op = OP_LOOKUP;
  cfg.key = 0;
  cfg.seed = {{.key = 0, .val = 42}, {.key = 1, .val = 10}};

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 42);
}

TEST(DynMap, MultiWordKeysCompareEveryWord) {
  // Two keys that agree on their first word and differ in their second. A hash
  // or a compare that stopped at the first word would either collide them or
  // hand back the wrong entry -- and the near miss below would hit.
  DynMapConfig cfg;
  cfg.key_size = 2 * sizeof(__u64);
  cfg.op = OP_LOOKUP;
  cfg.seed = {
      {.key = 5, .tail = 1, .val = 10},
      {.key = 5, .tail = 2, .val = 20},
  };
  cfg.key = 5;
  cfg.key_tail = 2;
  cfg.key2 = 5;
  cfg.key2_tail = 3; // same first word as both entries, stored by neither

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 20);
  ASSERT_EQ(out.lookup2_ret, -ENOENT);
  ASSERT_EQ(out.final_size, 2U);
}

TEST(DynMap, InitRejectsEntrySizesItCannotHandle) {
  // Keys are hashed and compared a __u64 at a time, so a width that is not a
  // whole number of words would leave a tail nothing ever looks at -- two keys
  // differing only there would alias. A zero-width value has no block to hold.
  DynMapConfig partialKey;
  partialKey.key_size = sizeof(__u64) + 1;
  DynMapResult out;
  runDynMap(partialKey, out);
  ASSERT_EQ(out.ret, -EINVAL);

  DynMapConfig emptyKey;
  emptyKey.key_size = 0;
  runDynMap(emptyKey, out);
  ASSERT_EQ(out.ret, -EINVAL);

  DynMapConfig emptyVal;
  emptyVal.val_size = 0;
  runDynMap(emptyVal, out);
  ASSERT_EQ(out.ret, -EINVAL);

  DynMapConfig wideKey;
  wideKey.key_size = 4 * sizeof(__u64);
  runDynMap(wideKey, out);
  ASSERT_EQ(out.ret, 0);
}

TEST(DynMap, BpfInsertThenLookup) {
  DynMapConfig cfg;
  cfg.init_capacity = 8;
  cfg.op = OP_INSERT;
  cfg.key = 5;
  cfg.val = 55;

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 55);
  ASSERT_EQ(out.final_size, 1U);

  // The map stored the blocks it was handed rather than copying them, so the
  // only thing an insert into spare capacity allocates is the reference count
  // it puts on the value.
  ASSERT_EQ(out.used_after - out.used_before, out.refcount_bytes);
}

TEST(DynMap, InsertReplacingAKeyReleasesTheDuplicate) {
  // Re-inserting a live key keeps the key already stored and overwrites the
  // value, leaving the duplicate key and the displaced value for the map to
  // release: one entry's worth of arena goes back.
  DynMapConfig cfg;
  cfg.op = OP_INSERT;
  cfg.seed = {{.key = 5, .val = 55}};
  cfg.key = 5;
  cfg.val = 66;

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 66);
  ASSERT_EQ(out.final_size, 1U);
  ASSERT_EQ(out.used_before - out.used_after, out.entry_bytes);
}

TEST(DynMap, BpfDeleteRemovesKey) {
  DynMapConfig cfg;
  cfg.op = OP_DELETE;
  cfg.key = 7;
  cfg.seed = {{.key = 7, .val = 77}, {.key = 8, .val = 88}};

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookup_ret, -ENOENT);
  ASSERT_EQ(out.final_tombstones, 1U);

  // The tombstone holds nothing, so the entry's blocks are released with it
  // rather than waiting for the grow-rehash that reclaims the slot: both blocks
  // and the reference count the map had on the value.
  ASSERT_EQ(
      out.used_before - out.used_after, out.entry_bytes + out.refcount_bytes);
}

// The reference comes back on the value the map stored, shared with the map
// rather than a copy: two holders, one block.
TEST(DynMap, InsertSharedHandsBackAReferenceToTheStoredValue) {
  DynMapConfig cfg;
  cfg.op = OP_INSERT_SHARED;
  cfg.key = 5;
  cfg.val = 55;

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.ref_val, 55U);
  ASSERT_EQ(out.ref_use_count, 2U);
  ASSERT_EQ(out.lookup_val, 55U);
  ASSERT_EQ(out.used_after - out.used_before, out.refcount_bytes);
}

TEST(DynMap, DeleteIfUniqueDeletesAnEntryOnlyTheMapHolds) {
  DynMapConfig cfg;
  cfg.op = OP_DELETE_IF_UNIQUE;
  cfg.key = 7;
  cfg.seed = {{.key = 7, .val = 77}};

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookup_ret, -ENOENT);
  ASSERT_EQ(
      out.used_before - out.used_after, out.entry_bytes + out.refcount_bytes);
}

// Held elsewhere, the entry stays indexed and nothing is freed.
TEST(DynMap, DeleteIfUniqueLeavesAnEntryHeldElsewhere) {
  DynMapConfig cfg;
  cfg.op = OP_DELETE_IF_UNIQUE;
  cfg.key = 7;
  cfg.hold_ref = true;
  cfg.seed = {{.key = 7, .val = 77}};

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 1);
  ASSERT_EQ(out.ref_use_count, 2U);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 77U);
  ASSERT_EQ(out.used_after, out.used_before);
}

TEST(DynMap, DeleteIfUniqueOfAMissingKey) {
  DynMapConfig cfg;
  cfg.op = OP_DELETE_IF_UNIQUE;
  cfg.key = 9;
  cfg.seed = {{.key = 7, .val = 77}};

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, -ENOENT);
}

// The same threshold InsertTriggersResizeAndPreservesEntries grows at: the
// fixed insert stores the entry in the 8 slots there are.
TEST(DynMap, InsertFixedNeverGrows) {
  DynMapConfig cfg;
  cfg.seed = {
      {.key = 0, .val = 1000},
      {.key = 1, .val = 1001},
      {.key = 2, .val = 1002},
      {.key = 3, .val = 1003},
      {.key = 4, .val = 1004},
      {.key = 5, .val = 1005},
  };
  cfg.seed_capacity = 8;
  cfg.op = OP_INSERT_FIXED;
  cfg.key = 6;
  cfg.val = 1006;

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 1006U);
  ASSERT_EQ(out.final_size, 7U);
  ASSERT_EQ(out.final_capacity, 8U);
}

TEST(DynMap, InsertTriggersResizeAndPreservesEntries) {
  // Prime an 8-slot map to its 3/4 load-factor threshold (6 entries), then a
  // single BPF insert forces a grow-rehash to 16 slots. Confirm the new key is
  // findable in the grown buffer and a seeded key survived the rehash.
  DynMapConfig cfg;
  cfg.seed = {
      {.key = 0, .val = 1000},
      {.key = 1, .val = 1001},
      {.key = 2, .val = 1002},
      {.key = 3, .val = 1003},
      {.key = 4, .val = 1004},
      {.key = 5, .val = 1005},
  };
  cfg.seed_capacity = 8;
  cfg.op = OP_INSERT;
  cfg.key = 6;
  cfg.val = 1006;
  cfg.key2 = 3; // seeded entry that must survive the rehash

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 1006); // new key present in grown buffer
  ASSERT_EQ(out.lookup2_ret, 0);
  ASSERT_EQ(out.lookup2_val, 1003); // seeded key survived rehash
  ASSERT_EQ(out.final_size, 7U);
  ASSERT_EQ(out.final_capacity, 16U); // 8 -> 16
  ASSERT_EQ(out.final_tombstones, 0U); // grow reclaims tombstones
}

TEST(DynMap, UpdateAtThresholdSucceeds) {
  // Same 8-slot map at the same 3/4 threshold as the test above, but the insert
  // overwrites a key that is already there. An update adds no entry, so it must
  // not be gated on a grow: at BPFJ_DYN_MAP_MAX_CAPACITY the grow can only fail
  // with -ENOMEM, which would turn a plain overwrite into a spurious failure.
  //
  // The single-threaded map skipped the grow outright, and this asserted the
  // capacity had not moved. A trylocked map cannot tell an update from an
  // insert without a probe it has no stack for (see bpfj_dyn_map_insert), so
  // here the rehash still runs and only its failure is ignored. What survives
  // is the part that matters: the overwrite lands, and adds nothing.
  DynMapConfig cfg;
  cfg.seed = {
      {.key = 0, .val = 1000},
      {.key = 1, .val = 1001},
      {.key = 2, .val = 1002},
      {.key = 3, .val = 1003},
      {.key = 4, .val = 1004},
      {.key = 5, .val = 1005},
  };
  cfg.seed_capacity = 8;
  cfg.op = OP_INSERT;
  cfg.key = 3; // already seeded
  cfg.val = 7777; // overwrite its value

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 7777);
  ASSERT_EQ(out.final_size, 6U); // the overwrite added no entry
}

TEST(DynMap, LargeResizePreservesEntries) {
  // Prime a 256-slot map to its 3/4 threshold (192 entries), then one BPF
  // insert forces a grow to 512 slots -- past the old 256-slot cap -- rehashing
  // all 192 entries. Confirm the map grows large and entries survive.
  DynMapConfig cfg;
  cfg.seed_capacity = 256;
  for (__u64 k = 0; k < 192; ++k) {
    cfg.seed.push_back({.key = k, .val = k + 1000});
  }
  cfg.op = OP_INSERT;
  cfg.key = 1000;
  cfg.val = 9999;
  cfg.key2 = 100; // seeded entry that must survive the 192-entry rehash

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookup_ret, 0);
  ASSERT_EQ(out.lookup_val, 9999); // new key present in grown buffer
  ASSERT_EQ(out.lookup2_ret, 0);
  ASSERT_EQ(out.lookup2_val, 1100); // seeded key survived rehash
  ASSERT_EQ(out.final_size, 193U);
  ASSERT_EQ(out.final_capacity, 512U); // 256 -> 512, past the old cap
}

TEST(DynMap, GrowFreesOldBuffer) {
  // Prime an 8-slot map to its 3/4 load-factor threshold, then let one insert
  // force the grow to 16 slots. The slot buffer is not refcounted, so grow owns
  // the buffer it replaces: arena usage must move by the difference between the
  // two buffers, not by the whole new one.
  DynMapConfig cfg;
  cfg.seed = {
      {.key = 0, .val = 1000},
      {.key = 1, .val = 1001},
      {.key = 2, .val = 1002},
      {.key = 3, .val = 1003},
      {.key = 4, .val = 1004},
      {.key = 5, .val = 1005},
  };
  cfg.seed_capacity = 8;
  cfg.op = OP_INSERT;
  cfg.key = 6;
  cfg.val = 1006;
  cfg.key2 = 3; // seeded entry that must survive the rehash

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.pre_capacity, 8U);
  ASSERT_EQ(out.final_capacity, 16U);
  ASSERT_EQ(out.lookup_val, 1006); // new key present in grown buffer
  ASSERT_EQ(out.lookup2_val, 1003); // seeded key survived rehash

  // Releasing the old buffer leaves only the size difference behind; leaking it
  // would charge the whole 16-slot buffer plus its block header. The entries
  // themselves are moved, not copied, so none of them enters this — only the
  // reference count the insert that triggered the grow put on its value.
  const __u64 slot = sizeof(struct bpfj_dyn_map_slot);
  ASSERT_EQ(
      out.used_after - out.used_before, (16 - 8) * slot + out.refcount_bytes);
}

TEST(DynMap, GrowKeepsEveryEntry) {
  // Fill a map far past its threshold so it resizes more than once, then look
  // up every entry that went in. A resize moves them all, and the checks above
  // only ask after one or two -- an entry it drops, or files under a home a
  // later lookup does not probe from, is invisible to them.
  DynMapConfig cfg;
  cfg.init_capacity = 8;
  for (__u64 k = 0; k < 100; ++k) {
    cfg.seed.push_back({.key = (k * 7) + 1, .val = k + 500});
  }
  cfg.op = OP_LOOKUP;
  cfg.key = 8; // seeded (k=1)

  DynMapResult out;
  runDynMap(cfg, out);
  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.final_size, 100U);
  ASSERT_GT(out.final_capacity, 8U);
  ASSERT_EQ(out.seeds_found, 100U);
}

TEST(DynMap, DestroyReleasesEverythingAfterAGrow) {
  // Tear down a map that has resized. What it holds by then reached its buffer
  // by being moved there rather than inserted into it, and the buffer it was
  // moved out of is gone -- so this is the case where releasing the wrong one,
  // or one of them twice, does not show up in a smaller test.
  DynMapConfig cfg;
  cfg.init_capacity = 8;
  for (__u64 k = 0; k < 100; ++k) {
    cfg.seed.push_back({.key = (k * 7) + 1, .val = k + 500});
  }
  cfg.op = OP_DESTROY;

  DynMapResult out;
  runDynMap(cfg, out);

  // The header block is the caller's -- destroy does not free what it did not
  // allocate -- so everything the map took should be back and nothing else.
  ASSERT_EQ(out.used_after - out.used_at_start, out.header_bytes);
}
