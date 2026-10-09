// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/UnixEnforcer.h"

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
#include "bpfj/enforce/bpf/types_unix.h" // @manual
#include "bpfj/match/bpf/types_mount.h" // @manual

// The generated skeleton embeds bpfj_mount_cache by value.
#include "bpfj/enforce/bpf/unix_enforce.skel.h"
#include "bpfj/lib/GlobMap.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/match/FileMatchCached.h"

namespace bpfjailer {

namespace {

using Rules = std::map<std::string, bool>;

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

[[nodiscard]] std::uint64_t abstractPriority(
    std::string_view pattern,
    bool allowed) noexcept {
  std::uint32_t specific = 0;
  for (std::size_t i = 0; i < pattern.size(); ++i) {
    if (pattern[i] == '\\' && i + 1 < pattern.size()) {
      ++specific;
      ++i;
      continue;
    }
    if (pattern[i] == '*' || pattern[i] == '?') {
      continue;
    }
    if (pattern[i] == '$' && i + 1 < pattern.size() && pattern[i + 1] == '{') {
      const auto close = pattern.find('}', i + 2);
      if (close != std::string_view::npos) {
        ++specific;
        i = close;
        continue;
      }
    }
    ++specific;
  }
  const auto length = std::min<std::size_t>(pattern.size(), 0xffff);
  const std::uint64_t priority =
      (static_cast<std::uint64_t>(specific) << 16) | length;
  return (priority << 1) | static_cast<std::uint64_t>(allowed);
}

template <typename EntryMap>
void addPathRules(
    EntryMap& paths,
    const Rules& rules,
    enum bpfj_unix_operation operation) {
  for (const auto& [path, allowed] : rules) {
    if (path.front() == '@') {
      continue;
    }
    const std::string compiledPath = path == "/" ? "/*" : path;
    auto it = paths
                  .try_emplace(
                      compiledPath,
                      bpfj_unix_path_entry{
                          .allowed = {-1, -1, -1},
                          .specificity = pathSpecificity(path),
                      })
                  .first;
    it->second.allowed[operation] = allowed ? 1 : 0;
  }
}

template <typename Skel>
Expected<> compileAbstract(
    const std::shared_ptr<Skel>& obj,
    const GlobKeyResolver& resolveVariable,
    const Rules& rules,
    struct bpfj_glob_map*& slot) {
  std::vector<std::pair<std::string, std::uint64_t>> patterns;
  for (const auto& [pattern, allowed] : rules) {
    if (pattern.front() == '@') {
      patterns.emplace_back(pattern, abstractPriority(pattern, allowed));
    }
  }
  if (patterns.empty()) {
    return unit;
  }

  GlobMap<Skel> glob(obj, slot, false);
  if (auto res = glob.init(resolveVariable, std::move(patterns)); !res) {
    return res.error();
  }
  return unit;
}

} // namespace

Expected<> UnixEnforcer::load(
    const PinConfig& cfg,
    const Policy& policy) noexcept {
  if (policy.roles.empty()) {
    return unit;
  }
  if (auto res = pins::makeTree(cfg); !res) {
    return res;
  }

  using Skel = bpfj::libbpf::BpfSkel<unix_enforce_bpf>;
  using Matcher = FileMatchCached<unix_enforce_bpf>;
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
          "Unix socket rule references undeclared variable '" +
              std::string(name) + "'");
    }
    return found->second;
  };

  std::vector<std::unique_ptr<Matcher>> matchers;
  bool hasAbstract = false;
  auto* publishedPolicies = static_cast<struct bpfj_str_map*>(
      skel.bss().bpfj_heap_ctrl->role_policies);

  for (const auto& [name, role] : policy.roles) {
    auto foundPolicy = lookupRolePolicy(publishedPolicies, name);
    if (!foundPolicy) {
      return makeUnexpected(foundPolicy.error());
    }
    if (*foundPolicy == nullptr) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "Unix role is missing from the published role map: ",
          name));
    }
    auto* rolePolicy = const_cast<struct bpfj_role_policy*>(*foundPolicy);

    std::map<std::string, struct bpfj_unix_path_entry> paths;
    addPathRules(paths, role.unixBind, BPFJ_UNIX_BIND);
    addPathRules(paths, role.unixConnect, BPFJ_UNIX_CONNECT);
    addPathRules(paths, role.unixDgram, BPFJ_UNIX_DGRAM);
    if (!paths.empty()) {
      auto matcher = std::make_unique<Matcher>();
      if (auto res = matcher->init(
              obj,
              resolveVariable,
              Matcher::SharedMaps{},
              rolePolicy->unix_path_matcher,
              paths);
          !res) {
        return res.error();
      }
      matchers.push_back(std::move(matcher));
    }

    if (auto res = compileAbstract(
            obj,
            resolveVariable,
            role.unixBind,
            rolePolicy->unix_bind_abstract);
        !res) {
      return res;
    }
    if (auto res = compileAbstract(
            obj,
            resolveVariable,
            role.unixConnect,
            rolePolicy->unix_connect_abstract);
        !res) {
      return res;
    }
    if (auto res = compileAbstract(
            obj,
            resolveVariable,
            role.unixDgram,
            rolePolicy->unix_dgram_abstract);
        !res) {
      return res;
    }
    hasAbstract |= rolePolicy->unix_bind_abstract != nullptr ||
        rolePolicy->unix_connect_abstract != nullptr ||
        rolePolicy->unix_dgram_abstract != nullptr;
  }

  if (hasAbstract) {
    struct bpfj_glob_run** runs[] = {
        &skel.bss().bpfj_ipc_glob_run0,
        &skel.bss().bpfj_ipc_glob_run1,
        &skel.bss().bpfj_ipc_glob_run2,
        &skel.bss().bpfj_ipc_glob_run3,
    };
    for (auto** run : runs) {
      *run = heap::alloc<struct bpfj_glob_run>(obj);
      if (*run == nullptr) {
        return makeUnexpected(makeError(
            std::errc::not_enough_memory,
            "failed to reserve Unix socket glob matcher run"));
      }
      bpfj_glob_run_init(*run);
    }
  }

  if (auto res = skel.attach(); !res) {
    return res;
  }
  const std::pair<struct bpf_link*, std::string_view> links[] = {
      {skel.links().bpfj_unix_path_bind, "bpfj_unix_path_bind"},
      {skel.links().bpfj_unix_abstract_bind, "bpfj_unix_abstract_bind"},
      {skel.links().bpfj_unix_abstract_connect, "bpfj_unix_abstract_connect"},
      {skel.links().bpfj_unix_stream_connect, "bpfj_unix_stream_connect"},
      {skel.links().bpfj_unix_dgram_send_path, "bpfj_unix_dgram_send_path"},
      {skel.links().bpfj_unix_dgram_send_abstract,
       "bpfj_unix_dgram_send_abstract"},
  };
  for (const auto& [link, name] : links) {
    if (auto res = pins::pinLink(link, name, cfg.linkDir()); !res) {
      return res;
    }
  }
  for (auto& matcher : matchers) {
    matcher->release();
  }
  return unit;
}

} // namespace bpfjailer
