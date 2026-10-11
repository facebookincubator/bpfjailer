// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/ExecEnforcer.h"

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
#include "bpfj/enforce/bpf/types.h" // @manual
#include "bpfj/enforce/bpf/types_exec.h" // @manual
#include "bpfj/match/bpf/types_mount.h" // @manual

#include "bpfj/enforce/bpf/exec_enforce.skel.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/match/FileMatchCached.h"

namespace bpfjailer {

namespace {

[[nodiscard]] __u32 toFlags(const ExecPathPolicy& policy) noexcept {
  return (policy.allowExec ? BPFJ_EXEC_ALLOW_EXEC : 0) |
      (policy.allowSetuid ? BPFJ_EXEC_ALLOW_SETUID : 0) |
      (policy.allowSharedObject ? BPFJ_EXEC_ALLOW_SHARED_OBJECT : 0);
}

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
    if (!component.empty() && component != "*" &&
        specificity != std::numeric_limits<std::uint8_t>::max()) {
      ++specificity;
    }
    if (end == std::string_view::npos) {
      break;
    }
    begin = end + 1;
  }
  return specificity;
}

} // namespace

Expected<> ExecEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  using Skel = bpfj::libbpf::BpfSkel<exec_enforce_bpf>;
  using Matcher = FileMatchCached<exec_enforce_bpf>;
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
  skel.bss().bpfj_exec_mount_cache = skel.bss().bpfj_heap_ctrl->mount_cache;
  if (skel.bss().bpfj_exec_mount_cache == nullptr) {
    return makeUnexpected(makeError(
        std::errc::state_not_recoverable,
        "shared mount cache is not initialized"));
  }

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
          "exec path references undeclared variable '" + std::string(name) +
              "'");
    }
    return found->second;
  };

  std::vector<std::unique_ptr<Matcher>> matchers;
  auto* publishedPolicies = static_cast<struct bpfj_str_map*>(
      skel.bss().bpfj_heap_ctrl->role_policies);
  for (const auto& [name, role] : policy.roles) {
    if (role.execPaths.empty()) {
      continue;
    }
    std::map<std::string, struct bpfj_exec_path_entry> paths;
    for (const auto& [path, permissions] : role.execPaths) {
      paths.emplace(
          path,
          bpfj_exec_path_entry{
              .flags = toFlags(permissions),
              .specificity = pathSpecificity(path),
          });
    }

    auto foundPolicy = lookupRolePolicy(publishedPolicies, name);
    if (!foundPolicy) {
      return makeUnexpected(foundPolicy.error());
    }
    if (*foundPolicy == nullptr) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "exec role is missing from the published role map: ",
          name));
    }
    auto* rolePolicy = const_cast<struct bpfj_role_policy*>(*foundPolicy);
    auto matcher = std::make_unique<Matcher>();
    if (auto res = matcher->init(
            obj, resolveVariable, rolePolicy->exec_matcher, paths);
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
      {skel.links().bpfj_exec_bprm_check, "bpfj_exec_bprm_check"},
      {skel.links().bpfj_exec_mmap_file, "bpfj_exec_mmap_file"},
      {skel.links().bpfj_exec_file_mprotect, "bpfj_exec_file_mprotect"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, linkDir); !res) {
      return res;
    }
  }

  for (auto& matcher : matchers) {
    matcher->release();
  }
  return unit;
}

} // namespace bpfjailer
