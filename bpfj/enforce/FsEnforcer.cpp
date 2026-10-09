// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/FsEnforcer.h"

#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/bpf/types.h" // @manual
#include "bpfj/enforce/bpf/types_fs.h" // @manual
#include "bpfj/match/bpf/types_mount.h" // @manual

// The generated skeleton embeds bpfj_mount_cache by value.
#include "bpfj/enforce/bpf/fs_enforce.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/match/FileMatchCached.h"

namespace bpfjailer {

namespace {

[[nodiscard]] __u32 toMode(FileMode mode) noexcept {
  switch (mode) {
    case FileMode::ReadOnly:
      return BPFJ_FS_MODE_READ;
    case FileMode::ReadWrite:
      return BPFJ_FS_MODE_READ | BPFJ_FS_MODE_WRITE;
    case FileMode::None:
      return 0;
  }
  return 0;
}

} // namespace

Expected<> FsEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  using Skel = bpfj::libbpf::BpfSkel<fs_enforce_bpf>;
  using Matcher = FileMatchCached<fs_enforce_bpf>;
  auto created = Skel::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto obj = created.value();
  auto& skel = *obj;

  const auto mapDir = cfg.mapDir();
  if (auto res = pins::pinSharedMaps(skel, mapDir); !res) {
    return res;
  }
  if (auto res = skel.load(); !res) {
    return res;
  }
  if (auto res = heap::init(obj); !res) {
    return res;
  }

  auto matchLru =
      std::make_shared<Matcher::Lru>(obj, skel.bss().bpfj_fs_match_lru);
  std::unordered_map<std::string, __u32> variableIds;
  for (std::size_t i = 0; i < policy.vars.size(); ++i) {
    variableIds.emplace(policy.vars[i], static_cast<__u32>(i + 1));
  }
  GlobKeyResolver resolveVariable =
      [ids = std::move(variableIds)](
          std::string_view name) -> err::Expected<__u32> {
    const auto found = ids.find(std::string(name));
    if (found == ids.end()) {
      return err::Error(
          std::errc::invalid_argument,
          "filesystem path references undeclared variable '" +
              std::string(name) + "'");
    }
    return found->second;
  };
  std::vector<std::unique_ptr<Matcher>> matchers;
  auto* publishedPolicies = static_cast<struct bpfj_str_map*>(
      skel.bss().bpfj_heap_ctrl->role_policies);

  for (const auto& [name, role] : policy.roles) {
    if (role.paths.empty()) {
      continue;
    }
    std::map<std::string, struct bpfj_fs_path_entry> paths;
    for (const auto& [path, mode] : role.paths) {
      paths.emplace(path, bpfj_fs_path_entry{.mode = toMode(mode)});
    }

    auto foundPolicy = lookupRolePolicy(publishedPolicies, name);
    if (!foundPolicy) {
      return makeUnexpected(foundPolicy.error());
    }
    if (*foundPolicy == nullptr) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "filesystem role is missing from the published role map: ",
          name));
    }
    auto* rolePolicy = const_cast<struct bpfj_role_policy*>(*foundPolicy);
    auto matcher = std::make_unique<Matcher>();
    if (auto res = matcher->init(
            obj,
            resolveVariable,
            Matcher::SharedMaps{.match = matchLru},
            rolePolicy->fs_matcher,
            paths);
        !res) {
      return res.error();
    }
    matchers.push_back(std::move(matcher));
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }

  const auto linkDir = cfg.linkDir();
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_fs_file_open, "bpfj_fs_file_open"},
      {skel.links().bpfj_fs_inode_unlink, "bpfj_fs_inode_unlink"},
      {skel.links().bpfj_fs_inode_link, "bpfj_fs_inode_link"},
      {skel.links().bpfj_fs_inode_link_source, "bpfj_fs_inode_link_source"},
      {skel.links().bpfj_fs_inode_create, "bpfj_fs_inode_create"},
      {skel.links().bpfj_fs_inode_mknod, "bpfj_fs_inode_mknod"},
      {skel.links().bpfj_fs_inode_rename, "bpfj_fs_inode_rename"},
      {skel.links().bpfj_fs_inode_rename_destination,
       "bpfj_fs_inode_rename_destination"},
      {skel.links().bpfj_fs_inode_rmdir, "bpfj_fs_inode_rmdir"},
      {skel.links().bpfj_fs_inode_mkdir, "bpfj_fs_inode_mkdir"},
      {skel.links().bpfj_fs_inode_setattr, "bpfj_fs_inode_setattr"},
      {skel.links().bpfj_fs_inode_getattr, "bpfj_fs_inode_getattr"},
      {skel.links().bpfj_fs_inode_setxattr, "bpfj_fs_inode_setxattr"},
      {skel.links().bpfj_fs_inode_getxattr, "bpfj_fs_inode_getxattr"},
      {skel.links().bpfj_fs_inode_listxattr, "bpfj_fs_inode_listxattr"},
      {skel.links().bpfj_fs_inode_removexattr, "bpfj_fs_inode_removexattr"},
      {skel.links().bpfj_fs_inode_symlink, "bpfj_fs_inode_symlink"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }

  for (auto& matcher : matchers) {
    matcher->release();
  }
  matchLru->release();
  return unit;
}

} // namespace bpfjailer
