// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#endif

#define BPFJ_FILE_MATCH_CACHED_RENAME_JOURNAL_SIZE 64

struct bpfj_file_match_cached_rename_record {
  __u64 generation;
  __u64 dentry;
};

struct bpfj_file_match_cached_rename_journal {
  __u64 generation;
  struct bpfj_file_match_cached_rename_record
      records[BPFJ_FILE_MATCH_CACHED_RENAME_JOURNAL_SIZE];
};

struct bpfj_matcher_state {
  // This journal invalidates caches for every matcher and enforcer.
  struct bpfj_file_match_cached_rename_journal rename_journal;
  // PID 1's mount namespace is permanent, so cache its address.
  __u64 init_mount_namespace;
};
