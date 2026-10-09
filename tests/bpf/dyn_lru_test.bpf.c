// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpfj/lib/bpf/dyn_lru.h"
#include "bpfj/lib/bpf/heap.h"

volatile struct bpfj_dyn_lru __arena* map;

const volatile struct lru_ins ins[BPFJ_DYN_LRU_TEST_MAX_INS];

// Per-instruction results, indexed in lockstep with `ins`.
volatile long rets[BPFJ_DYN_LRU_TEST_MAX_INS];
// LRU_LOOKUP: the value read from the returned arena block, so the test can
// tell which entry came back. Left at 0 when the lookup missed.
volatile __u64 vals[BPFJ_DYN_LRU_TEST_MAX_INS];
volatile __u32 sizes[BPFJ_DYN_LRU_TEST_MAX_INS];

volatile __u32 final_size;

// The two instruction bodies below are global subprograms, not static helpers,
// so the verifier checks each once in isolation. Inlined into the script loop
// they explode the state search and the program fails to load with -E2BIG. For
// the same reason they write their own results into the arrays above rather
// than taking out-parameters.

// Insert a fresh arena value under LRU key `key`.
long lru_test_insert(
    struct bpfj_dyn_lru __arena* lru __arg_arena,
    __u64 key,
    __u64 val) {
  // The LRU takes arena pointers for keys and copies what it is given, so the
  // scripted scalar is staged into a scratch block that lives only as long as
  // the call.
  BPFJ_HEAP_ALLOC_GUARD(__u64, key_buf);
  if (!key_buf) {
    return -ENOMEM;
  }
  *key_buf = key;

  __u64 __arena* stored = BPFJ_HEAP_ALLOC(sizeof(*stored));
  if (!stored) {
    return -ENOMEM;
  }
  *stored = val;
  return bpfj_dyn_lru_insert(lru, key_buf, stored);
}

// Look `key` up and record the returned value.
long lru_test_lookup(
    struct bpfj_dyn_lru __arena* lru __arg_arena,
    __u64 key,
    __u32 idx) {
  if (idx >= BPFJ_DYN_LRU_TEST_MAX_INS) {
    return -EINVAL;
  }

  // Staged into the arena for the same reason as in lru_test_insert.
  BPFJ_HEAP_ALLOC_GUARD(__u64, key_buf);
  if (!key_buf) {
    return -ENOMEM;
  }
  *key_buf = key;

  BPFJ_DYN_LRU_LOOKUP_GUARD(found);
  long ret = BPFJ_DYN_LRU_LOOKUP(found, lru, key_buf);
  if (ret == 0) {
    vals[idx] = *(__u64 __arena*)found.buf;
  }
  return ret;
}

SEC("syscall")
int test_dyn_lru(void* ctx) {
  bpfj_heap_use_arena();

  struct bpfj_dyn_lru __arena* lru = (struct bpfj_dyn_lru __arena*)map;

  // A real loop rather than an unrolled one: duplicating a 32-step script's
  // body per iteration also overruns the verifier's budget.
  __u32 i = 0;
  bpf_for(i, 0, BPFJ_DYN_LRU_TEST_MAX_INS) {
    enum lru_ins_type kind = ins[i].ins;
    if (kind == LRU_NONE) {
      break;
    }

    __u64 key = ins[i].key;

    if (kind == LRU_INSERT) {
      rets[i] = lru_test_insert(lru, key, ins[i].val);
    } else if (kind == LRU_LOOKUP) {
      rets[i] = lru_test_lookup(lru, key, i);
    }

    sizes[i] = lru->size;
  }

  final_size = lru->size;

  return 0;
}

int _version SEC("version") = 1;
char _license[] SEC("license") = "Dual MIT/GPL";
