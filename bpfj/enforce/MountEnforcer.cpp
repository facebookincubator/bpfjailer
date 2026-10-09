// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/MountEnforcer.h"

#include <bpf/libbpf.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/enforce/bpf/types_mount_enforce.h" // @manual
#include "bpfj/match/bpf/types_mount.h" // @manual

// The generated skeleton embeds bpfj_mount_cache by value.
#include "bpfj/enforce/bpf/mount_enforce.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/StrMap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/match/FileMatchCached.h"

namespace bpfjailer {

namespace {

[[nodiscard]] std::uint8_t pathSpecificity(std::string_view path) noexcept {
  std::uint8_t specificity = 0;
  std::size_t begin = 0;
  while (begin < path.size()) {
    while (begin < path.size() && path[begin] == '/') {
      ++begin;
    }
    const auto end = path.find('/', begin);
    const auto component = path.substr(
        begin,
        end == std::string_view::npos ? path.size() - begin : end - begin);
    if (!component.empty() && component != "*") {
      if (specificity != std::numeric_limits<std::uint8_t>::max()) {
        ++specificity;
      }
    }
    if (end == std::string_view::npos) {
      break;
    }
    begin = end + 1;
  }
  return specificity;
}

} // namespace

Expected<> MountEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (policy.roles.empty()) {
    return unit;
  }
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  using Skel = bpfj::libbpf::BpfSkel<mount_enforce_bpf>;
  using Matcher = FileMatchCached<mount_enforce_bpf>;
  auto created = Skel::create();
  if (!created) {
    return makeUnexpected(created.error());
  }
  auto obj = created.value();
  auto& skel = *obj;
  if (auto res = pins::pinSharedMaps(skel, cfg.mapDir()); !res) {
    return res;
  }
  if (auto res = skel.load(); !res) {
    return res;
  }
  if (auto res = heap::init(obj); !res) {
    return res;
  }

  std::unordered_map<std::string, __u32> variableIds;
  for (std::size_t i = 0; i < policy.vars.size(); ++i) {
    variableIds.emplace(policy.vars[i], static_cast<__u32>(i + 1));
  }
  const GlobKeyResolver resolveVariable =
      [ids = std::move(variableIds)](
          std::string_view name) -> err::Expected<__u32> {
    const auto found = ids.find(std::string(name));
    if (found == ids.end()) {
      return err::Error(
          std::errc::invalid_argument,
          "mount path references undeclared variable '" + std::string(name) +
              "'");
    }
    return found->second;
  };

  auto matchLru =
      std::make_shared<Matcher::Lru>(obj, skel.bss().bpfj_mount_match_lru);
  std::vector<std::unique_ptr<Matcher>> matchers;
  auto* publishedPolicies = static_cast<struct bpfj_str_map*>(
      skel.bss().bpfj_heap_ctrl->role_policies);

  for (const auto& [name, role] : policy.roles) {
    if (role.mount.empty() && role.umount.empty()) {
      continue;
    }

    auto foundPolicy = lookupRolePolicy(publishedPolicies, name);
    if (!foundPolicy) {
      return makeUnexpected(foundPolicy.error());
    }
    if (*foundPolicy == nullptr) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "mount role is missing from the published role map: ",
          name));
    }
    auto* rolePolicy = const_cast<struct bpfj_role_policy*>(*foundPolicy);

    if (!role.mount.empty()) {
      std::map<std::string, struct bpfj_mount_path_entry> paths;
      for (const auto& [path, types] : role.mount) {
        struct bpfj_str_map* typeSet = nullptr;
        const bool anyType =
            std::find(types.begin(), types.end(), "ANY") != types.end();
        if (!types.empty() && !anyType) {
          std::map<std::string, void*> allowedTypes;
          for (const auto& type : types) {
            allowedTypes.emplace(type, rolePolicy);
          }
          StrMap<Skel> publishedTypes{obj, typeSet, false};
          if (auto res = publishedTypes.init(allowedTypes); !res) {
            return res.error();
          }
        }
        const std::string compiledPath = path == "/" ? "/*" : path;
        paths.emplace(
            compiledPath,
            bpfj_mount_path_entry{
                .types = typeSet,
                .specificity = pathSpecificity(path),
                .any_type = static_cast<__u8>(anyType),
            });
      }

      auto matcher = std::make_unique<Matcher>();
      if (auto res = matcher->init(
              obj,
              resolveVariable,
              Matcher::SharedMaps{.match = matchLru},
              rolePolicy->mount_matcher,
              paths);
          !res) {
        return res.error();
      }
      matchers.push_back(std::move(matcher));
    }

    if (!role.umount.empty()) {
      std::map<std::string, struct bpfj_umount_path_entry> paths;
      for (const auto& [path, allowed] : role.umount) {
        paths.emplace(
            path == "/" ? "/*" : path,
            bpfj_umount_path_entry{
                .allowed = static_cast<__u8>(allowed),
                .specificity = pathSpecificity(path),
            });
      }
      auto matcher = std::make_unique<Matcher>();
      if (auto res = matcher->init(
              obj,
              resolveVariable,
              Matcher::SharedMaps{.match = matchLru},
              rolePolicy->umount_matcher,
              paths);
          !res) {
        return res.error();
      }
      matchers.push_back(std::move(matcher));
    }
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }

  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_mount_new, "bpfj_mount_new"},
      {skel.links().bpfj_mount_remount, "bpfj_mount_remount"},
      {skel.links().bpfj_mount_move_source, "bpfj_mount_move_source"},
      {skel.links().bpfj_mount_remount_relay, "bpfj_mount_remount_relay"},
      {skel.links().bpfj_remount, "bpfj_remount"},
      {skel.links().bpfj_umount, "bpfj_umount"},
      {skel.links().bpfj_move_mount_destination, "bpfj_move_mount_destination"},
      {skel.links().bpfj_move_mount_source, "bpfj_move_mount_source"},
      {skel.links().bpfj_pivot_root_new, "bpfj_pivot_root_new"},
      {skel.links().bpfj_pivot_root_old, "bpfj_pivot_root_old"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, cfg.linkDir()); !res) {
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
