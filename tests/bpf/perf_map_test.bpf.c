// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/perf_map.h"

const volatile __u64 lookup_key = 0;

// The perfect-hash table, allocated on the arena by userspace, which publishes
// the pointer here after the skeleton is loaded.
struct bpfj_perf_map __arena* map;
volatile long ret = 0;
volatile __u64 val = 0;

SEC("syscall")
int test_perf_map_lookup(void* ctx) {
  (void)ctx;

  bpfj_heap_use_arena();

  ret = bpfj_perf_map_lookup(map, lookup_key, (u64*)&val);

  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
