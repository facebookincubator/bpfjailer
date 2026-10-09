// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <vector>

#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/const_map_test.skel.h"

using namespace bpfjailer;

namespace {

struct Seed {
  __u64 key;
  __u64 tail;
  __u64 val;
};

struct Config {
  __u32 maxEntries = 8;
  __u32 keySize = sizeof(__u64);
  __u64 lookupKey = 0;
  __u64 lookupTail = 0;
  __u64 missingKey = ~0ULL;
  std::vector<Seed> seed;
};

struct Result {
  long ret;
  long lookupRet;
  long missingRet;
  long lookupBeforeSealRet;
  long insertAfterSealRet;
  __u64 lookupVal;
  __u32 inserted;
  __u32 duplicates;
  __u32 size;
  __u32 capacity;
  __u32 probeLimit;
  __u64 usedBefore;
  __u64 usedWhileLive;
  __u64 usedAfter;
};

void runConstMap(const Config& cfg, Result& out) {
  using Skel = bpfj::libbpf::BpfSkel<const_map_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;

  skel->rodata().max_entries = cfg.maxEntries;
  skel->rodata().key_size = cfg.keySize;
  skel->rodata().lookup_key = cfg.lookupKey;
  skel->rodata().lookup_key_tail = cfg.lookupTail;
  skel->rodata().missing_key = cfg.missingKey;

  const auto maxSeed =
      sizeof(skel->rodata().seed_keys) / sizeof(skel->rodata().seed_keys[0]);
  ASSERT_LE(cfg.seed.size(), maxSeed);
  for (std::size_t i = 0; i < cfg.seed.size(); ++i) {
    skel->rodata().seed_keys[i] = cfg.seed[i].key;
    skel->rodata().seed_key_tails[i] = cfg.seed[i].tail;
    skel->rodata().seed_vals[i] = cfg.seed[i].val;
  }
  skel->rodata().seed_count = static_cast<__u32>(cfg.seed.size());

  ASSERT_OK(skel->load());
  ASSERT_OK(heap::init(skel));

  LIBBPF_OPTS(bpf_test_run_opts, opts);
  const int fd = bpf_program__fd(skel->progs().test_const_map);
  ASSERT(fd >= 0);
  ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
  ASSERT_EQ(static_cast<int>(opts.retval), 0);

  out = {
      .ret = skel->bss().ret,
      .lookupRet = skel->bss().lookup_ret,
      .missingRet = skel->bss().missing_ret,
      .lookupBeforeSealRet = skel->bss().lookup_before_seal_ret,
      .insertAfterSealRet = skel->bss().insert_after_seal_ret,
      .lookupVal = skel->bss().lookup_val,
      .inserted = skel->bss().inserted,
      .duplicates = skel->bss().duplicates,
      .size = skel->bss().final_size,
      .capacity = skel->bss().final_capacity,
      .probeLimit = skel->bss().final_probe_limit,
      .usedBefore = skel->bss().used_before,
      .usedWhileLive = skel->bss().used_while_live,
      .usedAfter = skel->bss().used_after,
  };
}

} // namespace

TEST(ConstMap, FindsASealedEntryAndMissesAnAbsentOne) {
  Config cfg{
      .lookupKey = 22,
      .seed =
          {{.key = 11, .tail = 0, .val = 110},
           {.key = 22, .tail = 0, .val = 220},
           {.key = 33, .tail = 0, .val = 330}},
  };
  Result out{};
  runConstMap(cfg, out);

  ASSERT_EQ(out.ret, 0);
  ASSERT_EQ(out.lookupRet, 0);
  ASSERT_EQ(out.lookupVal, 220);
  ASSERT_EQ(out.missingRet, -ENOENT);
  ASSERT_EQ(out.size, 3);
  ASSERT_EQ(out.capacity, 32);
}

TEST(ConstMap, DuplicateKeyReusesTheDenseEntry) {
  Config cfg{
      .lookupKey = 7,
      .seed =
          {{.key = 7, .tail = 0, .val = 70}, {.key = 7, .tail = 0, .val = 71}},
  };
  Result out{};
  runConstMap(cfg, out);

  ASSERT_EQ(out.lookupVal, 71);
  ASSERT_EQ(out.inserted, 1);
  ASSERT_EQ(out.duplicates, 1);
  ASSERT_EQ(out.size, 1);
}

TEST(ConstMap, MultiwordKeysCompareEveryWord) {
  Config cfg{
      .keySize = 2 * sizeof(__u64),
      .lookupKey = 5,
      .lookupTail = 2,
      .seed =
          {{.key = 5, .tail = 1, .val = 51}, {.key = 5, .tail = 2, .val = 52}},
  };
  Result out{};
  runConstMap(cfg, out);

  ASSERT_EQ(out.lookupRet, 0);
  ASSERT_EQ(out.lookupVal, 52);
  ASSERT_EQ(out.size, 2);
}

TEST(ConstMap, ConstructionAndLookupPhasesDoNotOverlap) {
  Config cfg{
      .lookupKey = 1,
      .seed = {{.key = 1, .tail = 0, .val = 10}},
  };
  Result out{};
  runConstMap(cfg, out);

  ASSERT_EQ(out.lookupBeforeSealRet, -EPERM);
  ASSERT_EQ(out.insertAfterSealRet, -EPERM);
}

TEST(ConstMap, CollisionChainsRemainSearchable) {
  Config cfg{
      .maxEntries = 4,
      .lookupKey = 24,
      .seed =
          {{.key = 4, .tail = 0, .val = 40},
           {.key = 7, .tail = 0, .val = 70},
           {.key = 11, .tail = 0, .val = 110},
           {.key = 24, .tail = 0, .val = 240}},
  };
  Result out{};
  runConstMap(cfg, out);

  ASSERT_EQ(out.lookupRet, 0);
  ASSERT_EQ(out.lookupVal, 240);
  ASSERT_GT(out.probeLimit, 1);
}

TEST(ConstMap, FreeingTheSlabReturnsAllMapMemory) {
  Config cfg{
      .lookupKey = 1,
      .seed = {{.key = 1, .tail = 0, .val = 10}},
  };
  Result out{};
  runConstMap(cfg, out);

  ASSERT_GT(out.usedWhileLive, out.usedBefore);
  ASSERT_EQ(out.usedAfter, out.usedBefore);
}
