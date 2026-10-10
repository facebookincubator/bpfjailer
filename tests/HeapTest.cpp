// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <chrono>
#include <thread>
#include <vector>

#include "bpfj/enforce/ArenaMap.h"
#include "bpfj/enforce/Jailer.h"
#include "bpfj/enforce/Pins.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/lib/Heap.h"

namespace heap = bpfjailer::heap;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::loadJailer;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

struct FakeRodata {
  bool bpfj_heap_enabled{true};
};

struct FakeBss {
  bpfj_heap_control* bpfj_heap_ctrl{nullptr};
};

struct FakeSkel {
  FakeRodata rodata_;
  FakeBss bss_;

  FakeRodata& rodata() {
    return rodata_;
  }

  FakeBss& bss() {
    return bss_;
  }
};

void initControl(bpfj_heap_control& ctrl, __u32 arenaSize) {
  ctrl.arena_size = arenaSize;
  ctrl.current_used = 4096;
  ctrl.total_alloc = 10;
  ctrl.total_free = 3;
}

} // namespace

TEST(Heap, AllocFreeReturnsToBaseline) {
  const auto cfg = bpfjailer::test::testPins();
  const auto policy = bpfjailer::test::policyOf("[roles]");
  ASSERT_OK(bpfjailer::Jailer::load(cfg, policy));
  auto arena = bpfjailer::PodArena::open(cfg);
  ASSERT(arena);
  const __u64 initialUsed = arena->ctrl()->current_used;

  auto first = arena->alloc(64);
  auto second = arena->alloc(128);
  ASSERT_OK(first);
  ASSERT_OK(second);
  ASSERT(*first != *second);
  ASSERT(arena->ctrl()->current_used > initialUsed);

  ASSERT_OK(arena->free(*first));
  ASSERT_OK(arena->free(*second));
  ASSERT_EQ(arena->ctrl()->current_used, initialUsed);
  ASSERT_OK(bpfjailer::Jailer::unload(cfg));
  ASSERT(!bpfjailer::test::exists(
      cfg.programPath(bpfjailer::kHeapSyscallProgram)));
}

TEST(Heap, ReusesAFreedBlock) {
  const auto cfg = bpfjailer::test::testPins();
  const auto policy = bpfjailer::test::policyOf("[roles]");
  ASSERT_OK(bpfjailer::Jailer::load(cfg, policy));
  auto arena = bpfjailer::PodArena::open(cfg);
  ASSERT(arena);
  const __u64 initialUsed = arena->ctrl()->current_used;

  auto first = arena->alloc(64);
  ASSERT_OK(first);
  ASSERT_OK(arena->free(*first));

  auto reused = arena->alloc(64);
  ASSERT_OK(reused);
  ASSERT_EQ(*reused, *first);
  ASSERT_OK(arena->free(*reused));
  ASSERT_EQ(arena->ctrl()->current_used, initialUsed);
  ASSERT_OK(bpfjailer::Jailer::unload(cfg));
}

TEST(Heap, BpfGrowMakesLaterAllocsSucceed) {
  const auto cfg = bpfjailer::test::testPins();
  const auto policy = bpfjailer::test::policyOf("[roles]");
  ASSERT_OK(bpfjailer::Jailer::load(cfg, policy));
  auto arena = bpfjailer::PodArena::open(cfg);
  ASSERT(arena);

  const __u32 initSize = arena->ctrl()->arena_size;
  const __u64 initialUsed = arena->ctrl()->current_used;
  std::vector<void*> allocations;
  constexpr __u32 kChunk = 64 * 1024;

  for (int i = 0; i < 16; ++i) {
    auto allocation = arena->alloc(kChunk);
    ASSERT_OK(allocation);
    allocations.push_back(*allocation);
  }

  ASSERT(arena->ctrl()->arena_size > initSize);

  for (void* allocation : allocations) {
    ASSERT_OK(arena->free(allocation));
  }
  ASSERT_EQ(arena->ctrl()->current_used, initialUsed);
  ASSERT_OK(bpfjailer::Jailer::unload(cfg));
}

TEST(Heap, ReadStatsReturnsInitializedCounters) {
  bpfj_heap_control ctrl{};
  initControl(ctrl, 8192);
  FakeSkel skel;
  skel.bss_.bpfj_heap_ctrl = &ctrl;
  FakeSkel* obj = &skel;

  const auto stats = heap::readStats(obj);
  ASSERT(stats.has_value());
  ASSERT_EQ(stats->arenaSize, 8192U);
  ASSERT_EQ(stats->currentUsed, 4096U);
  ASSERT_EQ(stats->totalAlloc, 10U);
  ASSERT_EQ(stats->totalFree, 3U);
}

TEST(Heap, ReadStatsReturnsEmptyWhenHeapIsDisabled) {
  bpfj_heap_control ctrl{};
  initControl(ctrl, 8192);
  FakeSkel skel;
  skel.rodata_.bpfj_heap_enabled = false;
  skel.bss_.bpfj_heap_ctrl = &ctrl;
  FakeSkel* obj = &skel;

  ASSERT(!heap::readStats(obj).has_value());
}

TEST(Heap, ReadStatsReturnsEmptyBeforeInitialization) {
  FakeSkel skel;
  FakeSkel* obj = &skel;

  ASSERT(!heap::readStats(obj).has_value());
}

TEST(Heap, ReadStatsReturnsEmptyForAnEmptyArena) {
  bpfj_heap_control ctrl{};
  initControl(ctrl, 0);
  FakeSkel skel;
  skel.bss_.bpfj_heap_ctrl = &ctrl;
  FakeSkel* obj = &skel;

  ASSERT(!heap::readStats(obj).has_value());
}

TEST(Heap, LastPodReferenceReturnsAllocationToArena) {
  loadJailer(policyOf(R"toml([roles]

[roles.svc]
)toml"));

  auto arena = bpfjailer::PodArena::open(testPins());
  ASSERT(arena.hasValue());
  const auto used = [&] {
    return __atomic_load_n(&arena->ctrl()->current_used, __ATOMIC_ACQUIRE);
  };
  const auto usedBefore = used();

  {
    Child actor;
    enroll("svc", actor.pid());
    ASSERT(used() > usedBefore);
    ASSERT_EQ(actor.run(), 0);
  }

  using namespace std::chrono_literals;
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (used() != usedBefore && std::chrono::steady_clock::now() < deadline) {
    std::this_thread::yield();
  }
  ASSERT_EQ(used(), usedBefore);
}

TEST(ArenaMap, IndependentPinTreesUseDifferentSlots) {
  const auto policy = bpfjailer::test::policyOf(R"toml([roles]

[roles.svc]
)toml");
  const auto first = bpfjailer::test::testPins();
  ASSERT_OK(bpfjailer::Jailer::load(first, policy));

  auto second = first;
  second.pinDir += "-independent";
  ASSERT_OK(bpfjailer::Jailer::load(second, policy));

  auto firstMap = bpfjailer::pins::openPinnedMap(first, "bpfj_heap_arena");
  ASSERT(firstMap);
  auto secondMap = bpfjailer::pins::openPinnedMap(second, "bpfj_heap_arena");
  ASSERT(secondMap);

  auto firstExtra = bpfjailer::arena::pinnedMapExtra(*firstMap);
  ASSERT_OK(firstExtra);
  auto secondExtra = bpfjailer::arena::pinnedMapExtra(*secondMap);
  ASSERT_OK(secondExtra);
  ASSERT(*firstExtra != *secondExtra);
}
