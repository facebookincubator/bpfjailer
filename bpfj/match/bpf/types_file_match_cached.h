// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

#pragma once

#include "bpfj/lib/bpf/types_glob_map.h"
#include "bpfj/lib/bpf/types_perf_map.h"
#include "bpfj/lib/bpf/types_str_map.h"
#include "bpfj/match/bpf/types_file_match.h"
#include "bpfj/match/bpf/types_matcher_state.h"

#define BPFJ_FILE_MATCH_CACHED_CACHE_SIZE 8192
#define BPFJ_FILE_MATCH_CACHED_STATS_SLOTS 256
#define BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES 64

__inline __attribute__((always_inline)) __u64
bpfj_file_match_cached_bloom_hash(__u64 dentry) {
  __u64 hash = dentry;
  hash ^= hash >> 33;
  hash *= 0xff51afd7ed558ccdULL;
  hash ^= hash >> 33;
  return hash;
}

struct bpfj_file_match_cached_stats {
  __u64 hit;
  __u64 miss;
  __u64 busy;
  __u64 invalid;
  __u64 insert_exists;
  __u64 insert_busy;
  __u64 insert_error;
  __u64 reserved;
};

struct bpfj_file_match_cached_entry {
  __u64 rename_generation;
  __u64 ancestry_bloom[2];
  __u32 iter_count;
  __u32 dentry_count;
  __u64 dentries[BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES];
  struct bpfj_file_match_node nodes[BPFJ_FILE_MATCH_MAX_ITERS];
};

struct bpfj_file_matcher {
  // Maps a path component (a single dentry name) to the set of pattern nodes it
  // matches. A single bit-parallel glob NFA replaces the former literal
  // names_map, the per-node globs_perf_map, and the var_id_to_node_perf_map:
  // every distinct component pattern (literal, '*'/'?' wildcard, or ${VAR}
  // variable, bare or with a trailing pattern) is one glob pattern whose value
  // is the packed bpfj_file_match_indexes for that component. The compiled
  // header lives on the arena (userspace's GlobMap owns it), so this is just a
  // pointer to it.
  struct bpfj_glob_map __arena* glob_map;
  // Both headers live on the arena too (userspace's PerfMap owns them), so
  // these are just pointers. NULL when the policy has no such nodes at all.
  struct bpfj_perf_map __arena* nodes_perf_map;
  struct bpfj_perf_map __arena* initializer_perf_map;
  // Per path_id data: data_entry_count entries of data_entry_size bytes each,
  // flat, in one block. This used to be an array of str_maps keyed by role id,
  // because one matcher served every role and the same path could carry a
  // different entry per role. A matcher belongs to one role now, so a path has
  // exactly one entry and the path_id is the index -- no probe, no key, and no
  // per-entry allocation.
  void __arena* data_vec;
  // Number of components in each path, with zero reserved for `/`, so the
  // root-to-leaf matcher can retain completed ancestor rules.
  __u32 __arena* path_depths;
  __u64 cache_cookie;
  // Bytes per entry, and how many of them data_vec holds. The size is whatever
  // the owning userspace matcher's value type is; BPF only ever hands the entry
  // back to a caller that knows what it is.
  __u32 data_entry_size;
  __u32 data_entry_count;
  // Packed bpfj_file_match_indexes for an explicit `/` policy. Root matching
  // bypasses the glob engine so an unbound variable cannot match as empty.
  __u64 root_indexes;
  __u32 has_root;
  struct bpfj_file_match_cached_pattern_str __arena*
      pattern_strs; // arena ptr to pattern_str[]
  __u32 num_pattern_strs;
  // Non-zero when at least one of this role's paths asks for a signature.
  //
  // bpfj_fs2_file_post_open_sig works out what to verify from the cache entry
  // the path match left behind, and a cache miss leaves it with no answer. For
  // a role that signs nothing that is fine -- there was nothing to check. For a
  // role that does, it is the difference between checking a signature and
  // silently not, so the miss has to deny, and this is how that half knows
  // which case it is in without a match of its own.
  __u32 has_signed_paths;
};
