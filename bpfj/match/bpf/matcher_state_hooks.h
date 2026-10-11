// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpfj/match/bpf/matcher_state.h"

static __always_inline void bpfj_matcher_state_invalidate(
    struct dentry* dentry) {
  bpfj_file_match_cached_invalidate_dentry((uintptr_t)dentry);
}

static __always_inline void bpfj_matcher_state_invalidate_rename(
    struct dentry* old_dentry,
    struct dentry* new_dentry) {
  bpfj_matcher_state_invalidate(old_dentry);
  if (new_dentry != old_dentry) {
    bpfj_matcher_state_invalidate(new_dentry);
  }
}

SEC("lsm/inode_unlink")
int BPF_PROG(
    bpfj_matcher_state_inode_unlink,
    struct inode* dir,
    struct dentry* dentry,
    int lsm_ret) {
  bpfj_matcher_state_invalidate(dentry);
  return lsm_ret;
}

SEC("lsm/inode_link")
int BPF_PROG(
    bpfj_matcher_state_inode_link,
    struct dentry* old_dentry,
    struct inode* dir,
    struct dentry* new_dentry,
    int lsm_ret) {
  bpfj_matcher_state_invalidate(old_dentry);
  return lsm_ret;
}

SEC("lsm/inode_rename")
int BPF_PROG(
    bpfj_matcher_state_inode_rename,
    struct inode* old_dir,
    struct dentry* old_dentry,
    struct inode* new_dir,
    struct dentry* new_dentry,
    int lsm_ret) {
  bpfj_matcher_state_invalidate_rename(old_dentry, new_dentry);
  return lsm_ret;
}

SEC("lsm/inode_rmdir")
int BPF_PROG(
    bpfj_matcher_state_inode_rmdir,
    struct inode* dir,
    struct dentry* dentry,
    int lsm_ret) {
  bpfj_matcher_state_invalidate(dentry);
  return lsm_ret;
}

// Close the interval between each pre-operation LSM hook and the filesystem
// mutation. An enforcer or concurrent walk in that interval can repopulate
// stale topology after the first invalidation. Both ends are required even
// though that consumes two journal generations: filtering by the mutating task
// is unsafe because an unenrolled task can move a path used by an enrolled one.
SEC("fexit/vfs_unlink")
int BPF_PROG(
    bpfj_matcher_state_vfs_unlink,
    struct mnt_idmap* idmap,
    struct inode* dir,
    struct dentry* dentry,
    struct inode** delegated_inode,
    int ret) {
  if (ret == 0) {
    bpfj_matcher_state_invalidate(dentry);
  }
  return 0;
}

SEC("fexit/vfs_link")
int BPF_PROG(
    bpfj_matcher_state_vfs_link,
    struct dentry* old_dentry,
    struct mnt_idmap* idmap,
    struct inode* dir,
    struct dentry* new_dentry,
    struct inode** delegated_inode,
    int ret) {
  if (ret == 0) {
    bpfj_matcher_state_invalidate(old_dentry);
  }
  return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(bpfj_matcher_state_vfs_rename, struct renamedata* data, int ret) {
  if (ret == 0 && data != NULL) {
    struct renamedata* rename = bpf_core_cast(data, struct renamedata);
    bpfj_matcher_state_invalidate_rename(
        rename->old_dentry, rename->new_dentry);
  }
  return 0;
}

SEC("fexit/vfs_rmdir")
int BPF_PROG(
    bpfj_matcher_state_vfs_rmdir,
    struct mnt_idmap* idmap,
    struct inode* dir,
    struct dentry* dentry,
    int ret) {
  if (ret == 0) {
    bpfj_matcher_state_invalidate(dentry);
  }
  return 0;
}
