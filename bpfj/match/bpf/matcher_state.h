#pragma once

#include <errno.h>
#include "bpfj/match/bpf/types_matcher_state.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct bpfj_matcher_state);
} bpfj_file_match_state SEC(".maps");

static __always_inline struct bpfj_matcher_state* bpfj_matcher_state_get(void) {
  const __u32 zero = 0;
  return bpf_map_lookup_elem(&bpfj_file_match_state, &zero);
}

static __always_inline struct bpfj_file_match_cached_rename_journal*
bpfj_file_match_cached_get_rename_journal(void) {
  struct bpfj_matcher_state* state = bpfj_matcher_state_get();
  return state != NULL ? &state->rename_journal : NULL;
}

static __always_inline long bpfj_file_match_cached_invalidate_dentry(
    uintptr_t dentry) {
  struct bpfj_file_match_cached_rename_journal* journal =
      bpfj_file_match_cached_get_rename_journal();
  if (journal == NULL) {
    return -ENOMEM;
  }
  __u64 generation = __sync_fetch_and_add(&journal->generation, 1) + 1;
  struct bpfj_file_match_cached_rename_record* record =
      &journal->records
           [generation & (BPFJ_FILE_MATCH_CACHED_RENAME_JOURNAL_SIZE - 1)];
  __sync_lock_test_and_set(&record->generation, ~generation);
  record->dentry = dentry;
  __sync_lock_test_and_set(&record->generation, generation);
  return 0;
}
