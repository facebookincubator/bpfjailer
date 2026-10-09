// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstddef>
#include <memory>
#include <vector>

#include "bpfj/lib/DynLru.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/bpf/types_dyn_lru.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/dyn_lru_test.skel.h"

using namespace bpfjailer;

namespace {

using Skel = bpfj::libbpf::BpfSkel<dyn_lru_test_bpf>;

// The capacity every scripted test initializes the map with. Small enough that
// a script under BPFJ_DYN_LRU_TEST_MAX_INS instructions can overflow it.
constexpr __u32 kCapacity = 8;

// Distinguishable per-key payloads prove that a lookup returns the value stored
// under K and not merely some live entry.
constexpr __u64 kValueBase = 0xA000;

// The test's scratch key, direct value and reference count are the only
// per-insert blocks.
constexpr double kMaxAllocsPerEvictingInsert = 3.0;

constexpr __u64 valueFor(__u64 key) {
  return kValueBase + key;
}

lru_ins insertOp(__u64 key) {
  return {.ins = LRU_INSERT, .key = key, .val = valueFor(key)};
}

lru_ins lookupOp(__u64 key) {
  return {.ins = LRU_LOOKUP, .key = key, .val = 0};
}

struct LruResult {
  // Indexed in lockstep with the script.
  std::vector<long> rets;
  std::vector<__u64> vals;
  std::vector<__u32> sizes;
  __u32 finalSize = 0;
  // Arena bytes still in use once the script has run.
  __u32 heapUsed = 0;
  // Arena allocations the script itself made, measured across the run rather
  // than from process start so the map's own setup is not counted.
  __u64 heapAllocs = 0;
};

// Load the skeleton and initialize the arena heap, without attaching. Enough
// for the userspace half of DynLru; scripted tests go through runLru.
void loadSkel(std::shared_ptr<Skel>& out) {
  auto created = Skel::create();
  ASSERT_OK(created);
  out = *created;
  ASSERT_OK(out->load());
  ASSERT_OK(heap::init(out));
}

// Run `script` against a freshly initialized LRU of `capacity` entries. The BPF
// program is triggered directly through BPF_PROG_RUN.
void runLru(
    __u32 capacity,
    const std::vector<lru_ins>& script,
    LruResult& out) {
  ASSERT_LE(script.size(), std::size_t{BPFJ_DYN_LRU_TEST_MAX_INS});

  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;

  for (std::size_t i = 0; i < script.size(); ++i) {
    skel->rodata().ins[i] = script[i];
  }

  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  DynLru lru(skel, skel->bss().map);
  ASSERT_OK(lru.init(capacity, BPFJ_DYN_LRU_TEST_KEY_SIZE));

  // Taken after init, so the delta below covers only what the scripted
  // operations allocated.
  const auto before = heap::readStats(skel);
  ASSERT(before.has_value());

  LIBBPF_OPTS(bpf_test_run_opts, opts);
  const int fd = bpf_program__fd(skel->progs().test_dyn_lru);
  ASSERT(fd >= 0);
  ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
  ASSERT_EQ(static_cast<int>(opts.retval), 0);

  out.rets.assign(script.size(), 0);
  out.vals.assign(script.size(), 0);
  out.sizes.assign(script.size(), 0);
  for (std::size_t i = 0; i < script.size(); ++i) {
    out.rets[i] = skel->bss().rets[i];
    out.vals[i] = skel->bss().vals[i];
    out.sizes[i] = skel->bss().sizes[i];
  }
  out.finalSize = skel->bss().final_size;
  out.heapUsed = heap::currentUsed(skel);

  const auto after = heap::readStats(skel);
  ASSERT(after.has_value());
  out.heapAllocs = after->totalAlloc - before->totalAlloc;
}

// Assert that instruction `idx` was a lookup that hit and handed back the map
// stored under `key`.
void expectHit(const LruResult& out, std::size_t idx, __u64 key) {
  ASSERT_EQ(out.rets[idx], 0);
  ASSERT_EQ(out.vals[idx], valueFor(key));
}

void expectMiss(const LruResult& out, std::size_t idx) {
  ASSERT_EQ(out.rets[idx], -ENOENT);
}

// Whether instruction `idx` was a lookup that hit, checking on the way that a
// hit handed back the map stored under `key` rather than some other key's.
//
// For the eviction tests, which can say how many entries survive but not which:
// the victim is whichever entry the clock hand reaches with no credit left (see
// bpfj_dyn_lru_evict), and that is index order, not insertion order.
bool hitFor(const LruResult& out, std::size_t idx, __u64 key) {
  if (out.rets[idx] == -ENOENT) {
    return false;
  }
  ASSERT_EQ(out.rets[idx], 0);
  ASSERT_EQ(out.vals[idx], valueFor(key));
  return true;
}

// How many of keys [0, count) instruction `firstLookup + k` found.
std::size_t
residentCount(const LruResult& out, std::size_t firstLookup, __u64 count) {
  std::size_t resident = 0;
  for (__u64 k = 0; k < count; ++k) {
    resident += hitFor(out, firstLookup + k, k) ? 1 : 0;
  }
  return resident;
}

// A script that fills the map to capacity: keys 0..capacity-1.
std::vector<lru_ins> fillScript(__u64 capacity) {
  std::vector<lru_ins> script;
  script.reserve(capacity);
  for (__u64 k = 0; k < capacity; ++k) {
    script.push_back(insertOp(k));
  }
  return script;
}

} // namespace

TEST(DynLru, InsertThenLookupReturnsTheStoredValue) {
  const std::vector<lru_ins> script = {insertOp(42), lookupOp(42)};

  LruResult out;
  runLru(kCapacity, script, out);

  ASSERT_EQ(out.rets[0], 0);
  expectHit(out, 1, 42);
  ASSERT_EQ(out.finalSize, 1U);
}

TEST(DynLru, LookupOfAbsentKeyMisses) {
  const std::vector<lru_ins> script = {insertOp(42), lookupOp(43)};

  LruResult out;
  runLru(kCapacity, script, out);

  expectMiss(out, 1);
}

TEST(DynLru, LookupOnEmptyMapMisses) {
  const std::vector<lru_ins> script = {lookupOp(1)};

  LruResult out;
  runLru(kCapacity, script, out);

  expectMiss(out, 0);
  ASSERT_EQ(out.finalSize, 0U);
}

TEST(DynLru, ZeroKeyIsValid) {
  // 0 is a legal key, so an empty index slot cannot double as the "no such key"
  // sentinel the way a zero key would.
  const std::vector<lru_ins> script = {
      insertOp(0), insertOp(1), lookupOp(0), lookupOp(1)};

  LruResult out;
  runLru(kCapacity, script, out);

  expectHit(out, 2, 0);
  expectHit(out, 3, 1);
  ASSERT_EQ(out.finalSize, 2U);
}

TEST(DynLru, DistinctKeysDoNotAliasEachOther) {
  // Fill every slot, then read all of them back. Each key must return its own
  // value, which only holds if the probe walk resolves collisions correctly.
  std::vector<lru_ins> script = fillScript(kCapacity);
  const std::size_t firstLookup = script.size();
  for (__u64 k = 0; k < kCapacity; ++k) {
    script.push_back(lookupOp(k));
  }

  LruResult out;
  runLru(kCapacity, script, out);

  for (__u64 k = 0; k < kCapacity; ++k) {
    ASSERT_EQ(out.rets[k], 0);
    expectHit(out, firstLookup + k, k);
  }
  ASSERT_EQ(out.finalSize, kCapacity);
}

TEST(DynLru, UpperKeyBitsContributeToTheHash) {
  // The index uses a power-of-two mask. Without an avalanche step, multiply
  // and XOR preserve the independence of the low bits, placing all of these
  // keys in one bucket and exhausting the 16-slot probe window.
  constexpr __u32 kWideCapacity = 32;
  constexpr __u64 kKeys = BPFJ_DYN_LRU_MAX_PROBES + 1;
  std::vector<lru_ins> script;
  script.reserve(kKeys);
  for (__u64 k = 0; k < kKeys; ++k) {
    script.push_back(insertOp(k << 32));
  }

  LruResult out;
  runLru(kWideCapacity, script, out);

  for (std::size_t i = 0; i < script.size(); ++i) {
    ASSERT_EQ(out.rets[i], 0);
  }
  ASSERT_EQ(out.finalSize, kKeys);
}

TEST(DynLru, ReinsertingAKeyReplacesItWithoutGrowing) {
  // Re-inserting a live key is an update, not a second entry: the map must
  // still hold one entry, and it must be the newer value.
  std::vector<lru_ins> script = {insertOp(7)};
  script.push_back({.ins = LRU_INSERT, .key = 7, .val = valueFor(7) + 1});
  script.push_back(lookupOp(7));

  LruResult out;
  runLru(kCapacity, script, out);

  ASSERT_EQ(out.rets[1], 0);
  ASSERT_EQ(out.rets[2], 0);
  ASSERT_EQ(out.vals[2], valueFor(7) + 1);
  ASSERT_EQ(out.finalSize, 1U);
}

TEST(DynLru, InsertingPastCapacityEvictsExactlyOneEntry) {
  // Fill the map, then insert one more. The map is fixed size, so the new key
  // has to cost exactly one resident entry -- and never itself, which is the
  // invariant bpfj_dyn_lru_evict's `skip` carries now that there is no recency
  // list putting a new entry out of the victim's reach.
  //
  // Which of the eight goes is the clock hand's business and not asserted here:
  // an untouched entry outranks nothing, so the sweep takes the first one it
  // reaches in index order.
  std::vector<lru_ins> script = fillScript(kCapacity);
  const std::size_t overflow = script.size();
  script.push_back(insertOp(kCapacity));
  const std::size_t firstLookup = script.size();
  for (__u64 k = 0; k <= kCapacity; ++k) {
    script.push_back(lookupOp(k));
  }

  LruResult out;
  runLru(kCapacity, script, out);

  ASSERT_EQ(out.rets[overflow], 0);
  ASSERT_TRUE(hitFor(out, firstLookup + kCapacity, kCapacity));
  ASSERT_EQ(residentCount(out, firstLookup, kCapacity), kCapacity - 1);
  ASSERT_EQ(out.finalSize, kCapacity);
}

TEST(DynLru, LookupProtectsAnEntryFromTheNextEviction) {
  // A hit credits the entry it found up to BPFJ_DYN_LRU_REF_LOOKUP where a
  // plain insert only grants BPFJ_DYN_LRU_REF_INSERT, so the entry touched just
  // before an overflowing insert outranks every untouched one and survives the
  // sweep that insert triggers. That credit is the whole of what replaced
  // moving the entry to the head of a recency list -- and what lets a lookup
  // run without the map-wide lock.
  std::vector<lru_ins> script = fillScript(kCapacity);
  script.push_back(lookupOp(0)); // credit key 0 above the rest
  script.push_back(insertOp(kCapacity)); // overflows, so something is evicted
  const std::size_t firstLookup = script.size();
  for (__u64 k = 0; k <= kCapacity; ++k) {
    script.push_back(lookupOp(k));
  }

  LruResult out;
  runLru(kCapacity, script, out);

  ASSERT_TRUE(hitFor(out, firstLookup, 0));
  ASSERT_TRUE(hitFor(out, firstLookup + kCapacity, kCapacity));
  ASSERT_EQ(residentCount(out, firstLookup, kCapacity + 1), kCapacity);
  ASSERT_EQ(out.finalSize, kCapacity);
}

TEST(DynLru, ChurnBeyondCapacityStaysAtCapacity) {
  // Insert 2x capacity distinct keys with no lookups in between, then read all
  // of them back. The map must never exceed capacity, must end full, and every
  // key still resident must hand back its own map.
  //
  // That last part is what the churn is really for: every eviction leaves the
  // slot it emptied behind, and a slot wrongly reset to EMPTY rather than
  // tombstoned would cut a live key off its probe chain -- which shows up here
  // as a survivor count short of capacity, since the entry is still counted in
  // `size` but no longer reachable.
  constexpr __u64 kChurn = __u64{2} * kCapacity;
  std::vector<lru_ins> script;
  script.reserve(2 * kChurn);
  for (__u64 k = 0; k < kChurn; ++k) {
    script.push_back(insertOp(k));
  }
  const std::size_t firstLookup = script.size();
  for (__u64 k = 0; k < kChurn; ++k) {
    script.push_back(lookupOp(k));
  }

  LruResult out;
  runLru(kCapacity, script, out);

  for (std::size_t i = 0; i < kChurn; ++i) {
    ASSERT_EQ(out.rets[i], 0);
    ASSERT_LE(out.sizes[i], kCapacity);
  }
  ASSERT_EQ(residentCount(out, firstLookup, kChurn), kCapacity);
  ASSERT_TRUE(hitFor(out, firstLookup + kChurn - 1, kChurn - 1));
  ASSERT_EQ(out.finalSize, kCapacity);
}

TEST(DynLru, EvictionReclaimsTheEvictedEntry) {
  // A fixed-size LRU must run in bounded memory: once the map is full, further
  // inserts evict, and an eviction has to give the entry's value back
  // to the arena. Compare against what filling the map cost in the first place
  // rather than against a hardcoded footprint.
  LruResult empty;
  runLru(kCapacity, {}, empty);

  LruResult full;
  runLru(kCapacity, fillScript(kCapacity), full);

  constexpr __u64 kChurn = __u64{2} * kCapacity;
  std::vector<lru_ins> churn;
  churn.reserve(kChurn);
  for (__u64 k = 0; k < kChurn; ++k) {
    churn.push_back(insertOp(k));
  }
  LruResult churned;
  runLru(kCapacity, churn, churned);

  ASSERT_GT(full.heapUsed, empty.heapUsed);
  const __u32 costOfFilling = full.heapUsed - empty.heapUsed;

  // The second `kCapacity` inserts all evict, so they must not cost anything
  // like another full map's worth of arena.
  ASSERT_LE(churned.heapUsed, full.heapUsed + costOfFilling / 2);
}

TEST(DynLru, InitRejectsCapacityOutOfRange) {
  std::shared_ptr<Skel> skel;
  loadSkel(skel);

  DynLru zero(skel, skel->bss().map);
  ASSERT_FALSE(zero.init(0, BPFJ_DYN_LRU_TEST_KEY_SIZE));

  DynLru tooLarge(skel, skel->bss().map);
  ASSERT_FALSE(
      tooLarge.init(BPFJ_DYN_LRU_MAX_CAPACITY + 1, BPFJ_DYN_LRU_TEST_KEY_SIZE));

  DynLru inRange(skel, skel->bss().map);
  ASSERT_TRUE(inRange.init(kCapacity, BPFJ_DYN_LRU_TEST_KEY_SIZE));
}

TEST(DynLru, InitRejectsAKeySizeThatIsNotWholeWords) {
  // BPF hashes, compares and copies a key one __u64 at a time, so a width that
  // is not a whole number of words would leave a tail it never looks at — two
  // keys differing only there would alias.
  std::shared_ptr<Skel> skel;
  loadSkel(skel);

  DynLru empty(skel, skel->bss().map);
  ASSERT_FALSE(empty.init(kCapacity, 0));

  DynLru partial(skel, skel->bss().map);
  ASSERT_FALSE(partial.init(kCapacity, sizeof(__u64) + 1));

  DynLru wide(skel, skel->bss().map);
  ASSERT_TRUE(wide.init(kCapacity, 4 * sizeof(__u64)));
}

TEST(DynLru, InitRoundsCapacityUpToAPowerOfTwo) {
  // Slot selection masks with arr_size - 1, so the index must be sized to a
  // power of two even when the caller asks for something else.
  std::shared_ptr<Skel> skel;
  loadSkel(skel);

  DynLru lru(skel, skel->bss().map);
  ASSERT_TRUE(lru.init(9, BPFJ_DYN_LRU_TEST_KEY_SIZE));

  const auto* hdr = skel->bss().map;
  ASSERT_NE(hdr, nullptr);
  ASSERT_EQ(hdr->capacity, 16U);
  ASSERT_EQ(hdr->arr_size & (hdr->arr_size - 1), 0U);
  ASSERT_GE(hdr->arr_size, hdr->capacity);
  ASSERT_EQ(hdr->size, 0U);
}

TEST(DynLru, EvictingInsertsDoNotAllocatePerEntry) {
  // The entry and its key buffer come from a pool sized once at init, so an
  // insert's only arena allocation is the reference count on its value. Every
  // allocation goes through the arena-wide heap lock, which the whole jailer
  // shares, so this is what keeps a churning cache off it.
  //
  // Measured as the marginal cost of the evicting half of a churn rather than
  // as an absolute. Filling the map and then churning it cost the same per
  // insert except for what eviction and re-insertion add, so the difference
  // isolates this map's own traffic.
  LruResult filled;
  runLru(kCapacity, fillScript(kCapacity), filled);

  constexpr __u64 kChurn = __u64{2} * kCapacity;
  std::vector<lru_ins> churn;
  churn.reserve(kChurn);
  for (__u64 k = 0; k < kChurn; ++k) {
    churn.push_back(insertOp(k));
  }
  LruResult churned;
  runLru(kCapacity, churn, churned);

  ASSERT_GE(churned.heapAllocs, filled.heapAllocs);
  const double perEvictingInsert =
      static_cast<double>(churned.heapAllocs - filled.heapAllocs) / kCapacity;

  // Tight enough that allocating an entry or key buffer per insert breaks it.
  ASSERT_LE(perEvictingInsert, kMaxAllocsPerEvictingInsert);
}
