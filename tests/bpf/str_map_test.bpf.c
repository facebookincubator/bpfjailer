// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/str_map.h"

const volatile char to_match[64];
const volatile __u32 to_match_size = 0;

// The string table, allocated on the arena by userspace, which publishes the
// pointer here after the skeleton is loaded.
struct bpfj_str_map __arena* map;
volatile long ret = 0;
// The payload found *through* the entry's value, not the value itself: the
// value is an arena pointer, and reading the block it addresses is what proves
// BPF got a pointer it can use rather than one that merely survived the trip.
volatile __u64 val = 0;

SEC("syscall")
int test_str_match(void* ctx) {
  (void)ctx;

  bpfj_heap_use_arena();

  char search[64] = {};
  u32 sz = to_match_size;
  if (sz > sizeof(search)) {
    sz = sizeof(search);
  }
  u32 j = 0;
  bpf_for(j, 0, 64) {
    if (j >= sz) {
      break;
    }
    search[j] = to_match[j];
  }

  void __arena* out = NULL;
  ret = bpfj_str_map_lookup(map, search, sz, &out);
  if (out) {
    val = *(__u64 __arena*)out;
  }

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
