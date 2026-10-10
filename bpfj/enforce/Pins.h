// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

#include "bpfj/err/Error.h"
#include "bpfj/lib/Fd.h"
#include "bpfj/libbpf-cpp/BpfSkelBase.h"

namespace bpfjailer {

inline constexpr std::string_view kHeapSyscallProgram = "bpfj_heap_syscall";

/// @brief Where the jailer's programs and maps are pinned: `bpffsPath` names
/// the bpffs mount and `pinDir` a directory beneath it, together one
/// self-contained tree that can be torn down without a manifest.
struct PinConfig {
  std::string bpffsPath = "/sys/fs/bpf";
  std::string pinDir = "bpfj-pins";

  /// @brief The pin tree root, `bpffsPath/pinDir`.
  [[nodiscard]] std::string root() const noexcept;

  /// @brief Where maps are pinned, shared by every BPF object.
  [[nodiscard]] std::filesystem::path mapDir() const noexcept;

  /// @brief Where the map named `name` is pinned, the one place the layout
  /// beneath the root is spelled out.
  [[nodiscard]] std::string mapPath(std::string_view name) const noexcept;

  /// @brief Where attached links are pinned, one per program.
  [[nodiscard]] std::filesystem::path linkDir() const noexcept;

  /// @brief Where callable, unattached programs are pinned.
  [[nodiscard]] std::filesystem::path programDir() const noexcept;

  [[nodiscard]] std::string programPath(std::string_view name) const noexcept;
};

/// @brief The pin tree operations the jailer and its enforcers share. Every
/// BPF object comes up the same way -- point its copy of the shared maps at
/// the same pins, load, attach, pin the links -- and the first object loaded
/// creates those maps while the rest adopt them, which is what makes them one
/// jail.
namespace pins {

/// @brief Create the pin tree described by `cfg`. Idempotent, so a second
/// object brought up after the first converges rather than failing.
[[nodiscard]] Expected<> makeTree(const PinConfig& cfg) noexcept;

/// @brief Reject a path that is not a bpffs mount. The tree is removed by path
/// on unload, so a mistyped `bpffsPath` would delete real files.
[[nodiscard]] Expected<> checkBpffs(const std::string& path) noexcept;

/// @brief Pin `link` as `dir/name`; the link is borrowed, and the pin is what
/// keeps the program attached past this process.
[[nodiscard]] Expected<> pinLink(
    struct bpf_link* link,
    std::string_view name,
    const std::filesystem::path& dir) noexcept;

[[nodiscard]] Expected<> pinProgram(
    struct bpf_program* program,
    const PinConfig& cfg,
    std::string_view name) noexcept;

/// @brief Point `skel`'s map `name` at `mapDir/name`, resizing it first. Must
/// run before load(), since libbpf creates the pin as part of map creation and
/// adopts an existing pin rather than creating a second map.
[[nodiscard]] Expected<> pinMap(
    bpfj::libbpf::BpfSkelBase& skel,
    std::string_view name,
    const std::filesystem::path& mapDir,
    std::optional<std::uint32_t> maxEntries = std::nullopt) noexcept;

/// @brief Point `skel`'s map `name` at `pinPath`, resizing it first. The
/// general form of pinMap(), for `replace`, which adopts the old tree's
/// bpfj_task_map into a second definition to reach both jailers' membership.
[[nodiscard]] Expected<> pinMapAt(
    bpfj::libbpf::BpfSkelBase& skel,
    std::string_view name,
    const std::filesystem::path& pinPath,
    std::optional<std::uint32_t> maxEntries = std::nullopt) noexcept;

/// @brief Pin the jail membership maps that every BPF object declares; every
/// skeleton has to agree on the pin path and on max_entries, or the second to
/// load fails adoption rather than sharing the map.
[[nodiscard]] Expected<> pinSharedMaps(
    bpfj::libbpf::BpfSkelBase& skel,
    const std::filesystem::path& mapDir) noexcept;

/// @brief Open the map pinned as `name` under `cfg`, the only way into a
/// running jail for a process that did not load it. Fails when nothing is
/// pinned there, which is what a command run against no jailer sees.
[[nodiscard]] Expected<Fd> openPinnedMap(
    const PinConfig& cfg,
    std::string_view name) noexcept;

[[nodiscard]] Expected<Fd> openPinnedProgram(
    const PinConfig& cfg,
    std::string_view name) noexcept;

} // namespace pins
} // namespace bpfjailer
