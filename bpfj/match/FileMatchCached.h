// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "bpfj/err/Error.h"
#include "bpfj/lib/GlobMap.h"
#include "bpfj/lib/Heap.h"
#include "bpfj/lib/PerfMap.h"
#include "bpfj/lib/ScopeGuard.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "bpfj/match/bpf/types_file_match.h"
#include "bpfj/match/bpf/types_file_match_cached.h"

namespace bpfjailer {

namespace detail {

__attribute__((no_sanitize("address"))) inline void
fileMatchArenaWrite(void* destination, const void* source, std::size_t size) {
  std::memcpy(destination, source, size);
}

__attribute__((no_sanitize("address"))) inline void fileMatchArenaZero(
    void* destination,
    std::size_t size) {
  std::memset(destination, 0, size);
}

inline std::string fileMatchGlobEscape(std::string_view value) {
  std::string out;
  out.reserve(value.size());
  for (const char c : value) {
    if (c == '\\' || c == '*' || c == '?' || c == '$') {
      out.push_back('\\');
    }
    out.push_back(c);
  }
  return out;
}

inline std::uint64_t fileMatchCacheCookie() {
  std::random_device entropy;
  std::uint64_t cookie =
      (static_cast<std::uint64_t>(entropy()) << 32) | entropy();
  return cookie != 0 ? cookie : 1;
}

inline std::string fileMatchVarSuffix(std::string_view suffix) {
  std::string out;
  out.reserve(suffix.size());
  for (const char c : suffix) {
    if (c == '\\' || c == '$') {
      out.push_back('\\');
    }
    out.push_back(c);
  }
  return out;
}

inline std::string fileMatchComponentPattern(
    std::string_view component,
    bool variablesEnabled) {
  if (component == "*") {
    return "*";
  }
  // GlobMap's public variable syntax is ${NAME}. Preserve that spelling while
  // escaping only the optional trailing glob suffix. An unterminated
  // reference is deliberately passed through so GlobMap reports its precise
  // compile error.
  if (variablesEnabled && component.starts_with("${")) {
    const auto end = component.find('}', 2);
    if (end == std::string_view::npos) {
      return std::string(component);
    }
    return std::string(component.substr(0, end + 1)) +
        fileMatchVarSuffix(component.substr(end + 1));
  }
  if (component == "\\*") {
    return "\\*";
  }
  if (component.starts_with("\\$")) {
    component.remove_prefix(1);
  }
  return fileMatchGlobEscape(component);
}

inline std::vector<std::string_view> fileMatchComponents(
    std::string_view path) {
  if (path == "/") {
    return {std::string_view{}};
  }

  std::vector<std::string_view> components;
  std::size_t begin = 0;
  while (begin <= path.size()) {
    const auto end = path.find('/', begin);
    const auto component = path.substr(
        begin,
        end == std::string_view::npos ? path.size() - begin : end - begin);
    if (!component.empty()) {
      components.push_back(component);
    }
    if (end == std::string_view::npos) {
      break;
    }
    begin = end + 1;
  }
  return components;
}

struct FileMatchNodeLess {
  bool operator()(
      const struct bpfj_file_match_node& lhs,
      const struct bpfj_file_match_node& rhs) const {
    return lhs.path_id < rhs.path_id ||
        (lhs.path_id == rhs.path_id && lhs.pos < rhs.pos);
  }
};

} // namespace detail

// Builds the arena-resident matcher consumed by file_match_cached.h. One
// instance belongs to one role. Multiple instances may share one Lru, so a
// rename invalidates all role matches for an inode at once.
template <typename Skeleton>
class FileMatchCached {
 private:
  using Skel = bpfj::libbpf::BpfSkel<Skeleton>;
  using NodeSet =
      std::set<struct bpfj_file_match_node, detail::FileMatchNodeLess>;

 public:
  FileMatchCached() = default;
  ~FileMatchCached() {
    if (!released_) {
      destroy();
    }
  }

  FileMatchCached(const FileMatchCached&) = delete;
  FileMatchCached& operator=(const FileMatchCached&) = delete;
  FileMatchCached(FileMatchCached&&) = delete;
  FileMatchCached& operator=(FileMatchCached&&) = delete;

  // Hand the published blocks to a pinned arena map. Container destructors
  // remain non-owning; the pin now determines their lifetime.
  void release() noexcept {
    released_ = true;
  }

  template <typename Paths>
  Expected<> init(
      std::shared_ptr<Skel> skel,
      GlobKeyResolver resolveKey,
      struct bpfj_file_matcher*& matcherSlot,
      const Paths& paths) {
    if (matcher_ != nullptr) {
      return Error(
          std::errc::operation_in_progress, "matcher already initialized");
    }

    obj_ = std::move(skel);
    matcherSlot_ = &matcherSlot;

    if (auto res = heap::init(obj_); !res) {
      return res.error();
    }

    auto cleanup = makeGuard([this] { destroy(); });
    matcher_ = heap::alloc<struct bpfj_file_matcher>(obj_);
    if (matcher_ == nullptr) {
      return Error(std::errc::not_enough_memory, "matcher allocation failed");
    }
    detail::fileMatchArenaZero(matcher_, sizeof(*matcher_));
    *matcherSlot_ = matcher_;

    matcher_->cache_cookie = detail::fileMatchCacheCookie();

    if (auto res = compile(std::move(resolveKey), paths); !res) {
      return res.error();
    }

    cleanup.dismiss();
    return unit;
  }

  void destroy() {
    heap::free(obj_, dataVec_);
    dataVec_ = nullptr;
    heap::free(obj_, pathDepths_);
    pathDepths_ = nullptr;

    if (initMap_) {
      initMap_->destroy();
      initMap_.reset();
    }
    for (auto& map : nodeMaps_) {
      map.destroy();
    }
    nodeMaps_.clear();
    innerHeaders_.clear();
    if (nodesMap_) {
      nodesMap_->destroy();
      nodesMap_.reset();
    }
    if (globMap_) {
      globMap_->destroy();
      globMap_.reset();
    }
    for (auto* values : initializerValues_) {
      heap::free(obj_, values);
    }
    initializerValues_.clear();

    if (matcher_ != nullptr) {
      heap::free(obj_, matcher_);
      matcher_ = nullptr;
    }
    if (matcherSlot_ != nullptr) {
      *matcherSlot_ = nullptr;
      matcherSlot_ = nullptr;
    }
    obj_.reset();
  }

 private:
  template <typename Paths>
  Expected<> compile(GlobKeyResolver resolveKey, const Paths& paths) {
    using Value = typename Paths::mapped_type;
    if (paths.size() >
        static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max())) {
      return Error(std::errc::argument_list_too_long, "too many path patterns");
    }

    std::map<std::string, struct bpfj_file_match_indexes> patterns;
    std::map<std::int32_t, NodeSet> matchNodes;
    std::map<std::int32_t, std::vector<std::int32_t>> initializers;
    std::map<std::int32_t, Value> values;
    std::vector<__u32> pathDepths;
    std::int32_t nextNode = 0;
    std::int32_t nextInitializer = 0;
    std::int32_t pathId = 0;

    for (const auto& [path, value] : paths) {
      auto components = detail::fileMatchComponents(path);
      pathDepths.push_back(path == "/" ? 0 : components.size());
      for (std::size_t pos = 0; pos < components.size(); ++pos) {
        if (pos > static_cast<std::size_t>(
                      std::numeric_limits<std::int32_t>::max())) {
          return Error(
              std::errc::argument_list_too_long,
              "path has too many components");
        }
        auto pattern = detail::fileMatchComponentPattern(
            components[pos], static_cast<bool>(resolveKey));
        auto [it, inserted] = patterns.emplace(
            std::move(pattern), bpfj_file_match_indexes{-1, -1});
        if (inserted) {
          it->second.nodes_id = nextNode++;
        }

        if (pos == 0) {
          if (it->second.initializer_nodes_id < 0) {
            it->second.initializer_nodes_id = nextInitializer++;
          }
          initializers[it->second.initializer_nodes_id].push_back(pathId);
        } else {
          matchNodes[it->second.nodes_id].insert(
              bpfj_file_match_node{
                  .path_id = pathId,
                  .pos = static_cast<std::int32_t>(pos),
              });
        }
      }
      values.emplace(pathId++, value);
    }

    if (const auto root = patterns.find(""); root != patterns.end()) {
      std::memcpy(&matcher_->root_indexes, &root->second, sizeof(root->second));
      matcher_->has_root = 1;
    }

    if (auto res = initGlob(std::move(resolveKey), patterns); !res) {
      return res.error();
    }
    if (auto res = initNodes(matchNodes); !res) {
      return res.error();
    }
    if (auto res = initInitializers(initializers); !res) {
      return res.error();
    }
    if (auto res = initPathDepths(pathDepths); !res) {
      return res.error();
    }
    return initValues(values);
  }

  Expected<> initPathDepths(const std::vector<__u32>& pathDepths) {
    if (pathDepths.empty()) {
      return unit;
    }
    auto* depths = heap::allocArray<__u32>(obj_, pathDepths.size());
    if (depths == nullptr) {
      return Error(
          std::errc::not_enough_memory, "path depth allocation failed");
    }
    pathDepths_ = depths;
    detail::fileMatchArenaWrite(
        depths, pathDepths.data(), pathDepths.size() * sizeof(pathDepths[0]));
    matcher_->path_depths = depths;
    return unit;
  }

  Expected<> initGlob(
      GlobKeyResolver resolveKey,
      const std::map<std::string, struct bpfj_file_match_indexes>& patterns) {
    std::map<std::string, __u64> entries;
    for (const auto& [pattern, indexes] : patterns) {
      __u64 packed = 0;
      std::memcpy(&packed, &indexes, sizeof(indexes));
      entries.emplace(pattern, packed);
    }
    globMap_.emplace(obj_, matcher_->glob_map, false);
    return globMap_->init(std::move(resolveKey), std::move(entries));
  }

  Expected<> initNodes(const std::map<std::int32_t, NodeSet>& matchNodes) {
    if (matchNodes.empty()) {
      return unit;
    }

    std::map<__u64, __u64> outer;
    for (const auto& [nodeId, nodes] : matchNodes) {
      std::map<__u64, __u64> inner;
      for (const auto& node : nodes) {
        __u64 key = 0;
        std::memcpy(&key, &node, sizeof(node));
        inner.emplace(key, 1);
      }
      innerHeaders_.push_back(nullptr);
      PerfMap<Skel> map{obj_, innerHeaders_.back(), false};
      if (auto res = map.init(inner); !res) {
        return res.error();
      }
      outer.emplace(static_cast<__u64>(nodeId), map.offset());
      nodeMaps_.push_back(std::move(map));
    }
    nodesMap_.emplace(obj_, matcher_->nodes_perf_map, false);
    return nodesMap_->init(outer);
  }

  Expected<> initInitializers(
      const std::map<std::int32_t, std::vector<std::int32_t>>& initializers) {
    if (initializers.empty()) {
      return unit;
    }

    std::map<__u64, __u64> entries;
    for (const auto& [initializerId, paths] : initializers) {
      auto* values = heap::allocArray<std::int32_t>(obj_, paths.size() + 1);
      if (values == nullptr) {
        return Error(
            std::errc::not_enough_memory, "initializer allocation failed");
      }
      initializerValues_.push_back(values);
      detail::fileMatchArenaWrite(
          values, paths.data(), paths.size() * sizeof(paths.front()));
      const std::int32_t sentinel = -1;
      detail::fileMatchArenaWrite(
          &values[paths.size()], &sentinel, sizeof(sentinel));
      entries.emplace(
          static_cast<__u64>(initializerId),
          static_cast<__u64>(heap::ptrToOffset(heap::base(obj_), values)));
    }
    initMap_.emplace(obj_, matcher_->initializer_perf_map, false);
    return initMap_->init(entries);
  }

  template <typename Value>
  Expected<> initValues(const std::map<std::int32_t, Value>& values) {
    static_assert(std::is_trivially_copyable_v<Value>);
    if (values.empty()) {
      return unit;
    }
    auto* data = heap::allocArray<Value>(obj_, values.size());
    if (data == nullptr) {
      return Error(std::errc::not_enough_memory, "path data allocation failed");
    }
    dataVec_ = data;
    for (const auto& [pathId, value] : values) {
      detail::fileMatchArenaWrite(&data[pathId], &value, sizeof(value));
    }
    matcher_->data_vec = data;
    matcher_->data_entry_size = sizeof(Value);
    matcher_->data_entry_count = values.size();
    return unit;
  }

  std::shared_ptr<Skel> obj_;
  struct bpfj_file_matcher** matcherSlot_ = nullptr;
  struct bpfj_file_matcher* matcher_ = nullptr;
  std::optional<GlobMap<Skel>> globMap_;
  std::optional<PerfMap<Skel>> nodesMap_;
  std::deque<struct bpfj_perf_map*> innerHeaders_;
  std::vector<PerfMap<Skel>> nodeMaps_;
  std::optional<PerfMap<Skel>> initMap_;
  std::vector<std::int32_t*> initializerValues_;
  void* dataVec_ = nullptr;
  __u32* pathDepths_ = nullptr;
  bool released_ = false;
};

} // namespace bpfjailer
