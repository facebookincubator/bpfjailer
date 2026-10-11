// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/MatcherState.h"

#include <string_view>
#include <utility>

#include "bpfj/enforce/bpf/matcher_state.skel.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"

namespace bpfjailer {

Expected<> MatcherState::load(const PinConfig& cfg) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  auto created = bpfj::libbpf::BpfSkel<matcher_state_bpf>::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto& skel = *created.value();
  if (auto res = pins::pinMap(
          skel, "bpfj_file_match_state", cfg.mapDir(), std::nullopt);
      !res) {
    return res;
  }
  if (auto res = skel.load(); !res) {
    return res;
  }
  if (auto res = skel.attach(); !res) {
    return res;
  }

  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_matcher_state_inode_unlink,
       "bpfj_matcher_state_inode_unlink"},
      {skel.links().bpfj_matcher_state_inode_link,
       "bpfj_matcher_state_inode_link"},
      {skel.links().bpfj_matcher_state_inode_rename,
       "bpfj_matcher_state_inode_rename"},
      {skel.links().bpfj_matcher_state_inode_rmdir,
       "bpfj_matcher_state_inode_rmdir"},
      {skel.links().bpfj_matcher_state_vfs_unlink,
       "bpfj_matcher_state_vfs_unlink"},
      {skel.links().bpfj_matcher_state_vfs_link, "bpfj_matcher_state_vfs_link"},
      {skel.links().bpfj_matcher_state_vfs_rename,
       "bpfj_matcher_state_vfs_rename"},
      {skel.links().bpfj_matcher_state_vfs_rmdir,
       "bpfj_matcher_state_vfs_rmdir"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, cfg.linkDir()); !res) {
      return res;
    }
  }
  return unit;
}

} // namespace bpfjailer
