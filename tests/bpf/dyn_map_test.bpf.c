// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpfj/lib/bpf/dyn_map.h"
#include "bpfj/lib/bpf/heap.h"

enum {
  OP_LOOKUP = 0,
  OP_INSERT = 1,
  OP_DELETE = 2,
  OP_DESTROY = 3,
  OP_INSERT_SHARED = 4,
  OP_DELETE_IF_UNIQUE = 5,
  OP_INSERT_FIXED = 6,
};

const volatile __u32 op = OP_LOOKUP;
const volatile __u64 key = 0;
const volatile __u64 key_tail = 0; // filler words of `key`; see test_key
const volatile __u64 val = 0;
const volatile __u64 key2 =
    0; // secondary lookup (e.g. verify a rehash survivor)
const volatile __u64 key2_tail = 0;
const volatile __u32 init_capacity = BPFJ_DYN_MAP_MIN_CAPACITY;
const volatile __u32 init_key_size = (__u32)sizeof(__u64);
const volatile __u32 init_val_size = (__u32)sizeof(__u64);
// Hold a reference to `key`'s value across the op, as a pod set holds one to a
// pod the index also names.
const volatile bool hold_ref = false;

volatile long ret = 0;
// First failing seed insert, 0 if the map seeded cleanly. A partially seeded
// map would otherwise surface as a confusing wrong-value assertion rather than
// the setup failure it is.
volatile long seed_ret = 0;
volatile long lookup_ret = 0;
volatile __u64 lookup_val = 0;
volatile long lookup2_ret = 0;
volatile __u64 lookup2_val = 0;
volatile __u32 pre_capacity = 0;
volatile __u32 final_capacity = 0;
volatile __u32 final_size = 0;
volatile __u32 final_tombstones = 0;

// The reference insert_shared handed back, or the one hold_ref kept: its use
// count and value once the op is done, before it is released.
volatile __u32 ref_use_count = 0;
volatile __u64 ref_val = 0;

// Arena bytes in use before the map was made, so a test can see everything it
// took come back.
volatile __u64 used_at_start = 0;

// What the map's header block costs, measured the same way as entry_bytes. It
// is the caller's allocation, not the map's, so it is what a torn-down map is
// expected to leave behind.
volatile __u64 header_bytes = 0;

// How many of the seeded entries are still findable, with the value they were
// seeded with, once the op is done. A resize moves every entry, and a lookup of
// one or two keys does not notice one it dropped or filed under the wrong home.
volatile __u32 seeds_found = 0;

// What one key block plus one value block costs in the arena, block headers
// included. Measured rather than computed so a test can say "the map released
// the entry it took" without restating the allocator's accounting.
volatile __u64 entry_bytes = 0;

// What the reference count the map puts on a value costs, measured the same
// way. An insert allocates one of these of its own, on top of the two blocks it
// is handed, and a delete gives it back.
volatile __u64 refcount_bytes = 0;

// Arena bytes in use either side of the op. The key and value the op is given
// are staged before the first of these is read, so the difference is what the
// map itself allocated or released, not what the driver did to ask it.
volatile __u64 used_before = 0;
volatile __u64 used_after = 0;

// Sized for the largest seeded test (LargeResizePreservesEntries seeds 192).
#define DYN_MAP_TEST_MAX_SEED 256
const volatile __u64 seed_keys[DYN_MAP_TEST_MAX_SEED];
const volatile __u64 seed_key_tails[DYN_MAP_TEST_MAX_SEED];
const volatile __u64 seed_vals[DYN_MAP_TEST_MAX_SEED];
const volatile __u32 seed_count = 0;

// The scripted keys are single scalars, so a map running wider than one word
// gets {key, tail, tail, ...}. That gives the hash and the compare more than
// one word to look at while the script itself stays scalar.
static __always_inline __u64 __arena* test_key(__u64 k, __u64 tail) {
  __u64 __arena* buf = BPFJ_HEAP_ALLOC(init_key_size);
  if (!buf) {
    return NULL;
  }

  buf[0] = k;
  __u32 i = 0;
  bpf_for(i, 1, bpfj_dyn_map_key_words(init_key_size)) {
    buf[i] = tail;
  }
  return buf;
}

static __always_inline void __arena* test_val(__u64 v) {
  __u64 __arena* buf = BPFJ_HEAP_ALLOC(init_val_size);
  if (!buf) {
    return NULL;
  }

  *buf = v;
  return buf;
}

// Stage one seeded entry and hand it to the map.
//
// A global subprogram rather than the body of the seeding loop below: the
// verifier walks a loop body into the path it is checking once per step, and
// 256 steps of staging a key, a value and an insert is enough on its own to
// pass the point where it gives up ("the sequence of jumps is too complex").
long test_seed(
    struct bpfj_dyn_map __arena* map __arg_arena,
    __u64 k,
    __u64 tail,
    __u64 v) {
  __u64 __arena* seed_key = test_key(k, tail);
  void __arena* seed_val = test_val(v);
  if (!seed_key || !seed_val) {
    bpfj_dyn_map_free_entry(seed_key, seed_val);
    return -ENOMEM;
  }

  // The map owns both blocks from here, so a failed seed leaks nothing.
  return bpfj_dyn_map_insert(map, seed_key, seed_val);
}

// Look `k` up and report both the outcome and the value behind it. The map
// takes no interest in the key, so the scratch key goes back to the heap here;
// the reference it hands back on the value is dropped once the value is read.
static __always_inline long
test_lookup(struct bpfj_dyn_map __arena* map, __u64 k, __u64 tail, __u64* out) {
  __u64 __arena* probe = test_key(k, tail);
  if (!probe) {
    return -ENOMEM;
  }

  struct bpfj_shared_ptr found = {0};
  long lookup = bpfj_dyn_map_lookup(map, probe, &found);
  if (lookup == 0) {
    *out = *(__u64 __arena*)found.buf;
    bpfj_shared_ptr_release(&found);
  }

  BPFJ_HEAP_FREE(probe);
  return lookup;
}

// Whether one seeded entry is still there with the value it was seeded with. A
// global subprogram for the same reason as test_seed.
long test_check_seed(
    struct bpfj_dyn_map __arena* map __arg_arena,
    __u64 k,
    __u64 tail,
    __u64 v) {
  __u64 found = 0;
  long ret = test_lookup(map, k, tail, &found);
  return ret == 0 && found == v;
}

SEC("syscall")
int test_dyn_map(void* ctx) {
  bpfj_heap_use_arena();
  used_at_start = bpfj_heap_get_ctrl()->current_used;
  // Offset 0 is the arena base, so an unchecked failure here would hand
  // bpfj_dyn_map_init the heap control struct to initialize over.
  long map_off = bpfj_heap_alloc(sizeof(struct bpfj_dyn_map));
  if (map_off <= 0) {
    ret = map_off < 0 ? map_off : -ENOMEM;
    return 0;
  }
  __arena struct bpfj_dyn_map* map = bpfj_dyn_map_at((__u32)map_off);
  header_bytes = bpfj_heap_get_ctrl()->current_used - used_at_start;

  ret = bpfj_dyn_map_init(map, init_capacity, init_key_size, init_val_size);
  if (ret < 0) {
    return 0;
  }

  __u32 si = 0;
  long sret = 0;
  bpf_for(si, 0, DYN_MAP_TEST_MAX_SEED) {
    if (si >= seed_count) {
      break;
    }

    sret = test_seed(map, seed_keys[si], seed_key_tails[si], seed_vals[si]);
    if (sret < 0) {
      break;
    }
  }
  seed_ret = sret;
  if (sret < 0) {
    return 0;
  }

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  __u64 staged = ctrl->current_used;

  __u64 __arena* op_key = test_key(key, key_tail);
  void __arena* op_val = test_val(val);
  if (!op_key || !op_val) {
    bpfj_dyn_map_free_entry(op_key, op_val);
    ret = -ENOMEM;
    return 0;
  }
  entry_bytes = ctrl->current_used - staged;

  // The count the map will put on the value: allocated and given straight back,
  // so it costs the bracket below nothing but tells the test what one is worth.
  __u64 staged_rc = ctrl->current_used;
  long rc_probe = bpfj_heap_alloc(sizeof(__u32));
  if (rc_probe > 0) {
    refcount_bytes = ctrl->current_used - staged_rc;
    bpfj_heap_free((__u32)rc_probe);
  }

  // Only the ops that hand an entry to the map keep what was staged; the rest
  // release the value now and the key once the op is done with it, so neither
  // shows up inside the bracket below.
  bool op_takes_entry =
      op == OP_INSERT || op == OP_INSERT_SHARED || op == OP_INSERT_FIXED;
  if (!op_takes_entry) {
    BPFJ_HEAP_FREE(op_val);
    op_val = NULL;
  }
  if (op == OP_DESTROY) {
    // Nothing to key, and holding it would show up as something the teardown
    // failed to give back.
    BPFJ_HEAP_FREE(op_key);
    op_key = NULL;
  }

  // Taken before the bracket: the lookup stages a probe key of its own.
  struct bpfj_shared_ptr ref = {0};
  if (hold_ref && op_key) {
    bpfj_dyn_map_lookup(map, op_key, &ref);
  }

  pre_capacity = map->capacity;
  used_before = ctrl->current_used;

  if (op == OP_INSERT) {
    ret = bpfj_dyn_map_insert(map, op_key, op_val);
  } else if (op == OP_DELETE) {
    ret = bpfj_dyn_map_delete(map, op_key);
  } else if (op == OP_DESTROY) {
    bpfj_dyn_map_destroy(map);
  } else if (op == OP_INSERT_SHARED) {
    ret = bpfj_dyn_map_insert_shared(map, op_key, op_val, &ref);
  } else if (op == OP_DELETE_IF_UNIQUE) {
    ret = bpfj_dyn_map_delete_if_unique(map, op_key);
  } else if (op == OP_INSERT_FIXED) {
    ret = bpfj_dyn_map_insert_fixed(map, op_key, op_val);
  }

  used_after = ctrl->current_used;

  if (ref.refcount) {
    ref_use_count = *ref.refcount;
    ref_val = *(__u64 __arena*)ref.buf;
    bpfj_shared_ptr_release(&ref);
  }

  if (!op_takes_entry && op_key) {
    BPFJ_HEAP_FREE(op_key);
  }

  __u64 found = 0;
  lookup_ret = test_lookup(map, key, key_tail, &found);
  lookup_val = found;

  __u64 found2 = 0;
  lookup2_ret = test_lookup(map, key2, key2_tail, &found2);
  lookup2_val = found2;

  __u32 ci = 0;
  bpf_for(ci, 0, DYN_MAP_TEST_MAX_SEED) {
    if (ci >= seed_count || op == OP_DESTROY) {
      break; // nothing to look up in a map that has been torn down
    }
    if (test_check_seed(
            map, seed_keys[ci], seed_key_tails[ci], seed_vals[ci])) {
      __sync_fetch_and_add(&seeds_found, 1);
    }
  }

  final_capacity = map->capacity;
  final_size = map->size;
  final_tombstones = map->tombstones;
  return 0;
}

int _version SEC("version") = 1;
char _license[] SEC("license") = "Dual MIT/GPL";
