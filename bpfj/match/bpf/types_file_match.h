#pragma once

#include "bpfj/lib/bpf/types_uuid.h"
#include "bpfj/match/bpf/types_file.h"

#define BPFJ_FILE_MATCH_NAME_LEN 256
#define BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN 1024
#define BPFJ_FILE_MATCH_MAX_ITERS 64
#define BPFJ_FILE_MATCH_MAX_INITIALIZER_NODES 64

struct __attribute__((packed)) bpfj_file_match_name {
  char name[BPFJ_FILE_MATCH_NAME_LEN];
};

struct __attribute__((packed)) bpfj_file_match_node {
  __s32 path_id;
  __s32 pos;
};

struct __attribute__((packed)) bpfj_file_match_indexes {
  __s32 nodes_id;
  __s32 initializer_nodes_id;
};

struct bpfj_file_match_cached_pattern_str {
  char pattern[BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN];
};

struct bpfj_file_match_cached_key {
  __u64 ino;
  __u64 subvol;
  struct bpfj_uuid uuid;
  __u64 matcher;
  __u64 mount_generation;
  __u32 dev;
  __u32 reserved;
};
