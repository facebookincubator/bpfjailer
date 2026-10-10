// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/enforce/Pins.h"

#include <bpf/bpf.h>
#include <linux/magic.h>
#include <sys/stat.h>
#include <sys/statfs.h>

#include <array>

#include "bpfj/enforce/ArenaMap.h"
#include "bpfj/libbpf-cpp/BpfLink.h"

namespace bpfjailer {

namespace {

namespace fs = std::filesystem;

// The jail membership every BPF object declares: the per-task membership, the
// arena their pod payloads and policy graph live in, and the shared
// event/log ring buffers.
constexpr std::array<std::string_view, 7> kSharedMapNames = {
    "bpfj_task_map",
    "bpfj_generation_control",
    "bpfj_heap_arena",
    "bpfj_replace_frozen",
    "bpfj_active_enrolls",
    "bpfj_event_map",
    "bpfj_log_map",
};

// logging_bpf.h measures the ring buffer in 4 KiB pages and the closed source
// jailer uses 64 of them for bpfj_log_map.
constexpr std::uint32_t kBpfEventMapEntries = 512 * 4096;
constexpr std::uint32_t kBpfLogMapEntries = 64 * 4096;

[[nodiscard]] bool isOptionalSharedMap(std::string_view name) noexcept {
  // Programs that neither allocate arena state nor emit BPF logs do not
  // declare these maps. They still share the maps when present, but absence
  // must not make pinning an otherwise independent enforcer fail.
  return name == "bpfj_heap_arena" || name == "bpfj_log_map";
}

// 0700 because the tree exposes the jail membership of every task on the host.
[[nodiscard]] Expected<> makeDir(const fs::path& path) noexcept {
  if (::mkdir(path.c_str(), S_IRWXU) != 0 && errno != EEXIST) {
    return makeUnexpected(makeErrnoError("failed to create ", path.string()));
  }

  return unit;
}

} // namespace

std::string PinConfig::root() const noexcept {
  return (fs::path(bpffsPath) / pinDir).string();
}

fs::path PinConfig::mapDir() const noexcept {
  return fs::path(root()) / "maps";
}

std::string PinConfig::mapPath(std::string_view name) const noexcept {
  return (mapDir() / name).string();
}

fs::path PinConfig::linkDir() const noexcept {
  return fs::path(root()) / "links";
}

fs::path PinConfig::programDir() const noexcept {
  return fs::path(root()) / "programs";
}

std::string PinConfig::programPath(std::string_view name) const noexcept {
  return (programDir() / name).string();
}

namespace pins {

Expected<> checkBpffs(const std::string& path) noexcept {
  struct statfs sfs{};
  if (::statfs(path.c_str(), &sfs) != 0) {
    return makeUnexpected(makeErrnoError("failed to stat ", path));
  }

  if (sfs.f_type != BPF_FS_MAGIC) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, path, " is not a bpffs mount"));
  }

  return unit;
}

Expected<> makeTree(const PinConfig& cfg) noexcept {
  if (auto res = checkBpffs(cfg.bpffsPath); !res) {
    return res;
  }

  for (const auto& dir :
       {fs::path(cfg.root()), cfg.mapDir(), cfg.linkDir(), cfg.programDir()}) {
    if (auto res = makeDir(dir); !res) {
      return res;
    }
  }

  return unit;
}

Expected<> pinLink(
    struct bpf_link* link,
    std::string_view name,
    const fs::path& dir) noexcept {
  if (!link) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument, "program ", name, " did not attach"));
  }

  bpfj::libbpf::BpfLink wrapped(link);
  return wrapped.pin((dir / name).c_str());
}

Expected<> pinProgram(
    struct bpf_program* program,
    const PinConfig& cfg,
    std::string_view name) noexcept {
  if (!program || ::bpf_program__fd(program) < 0) {
    return makeUnexpected(makeError(
        std::errc::not_supported, "program ", name, " is not loaded"));
  }
  if (::bpf_program__pin(program, cfg.programPath(name).c_str()) != 0) {
    return makeUnexpected(makeErrnoError("failed to pin program ", name));
  }
  return unit;
}

Expected<> pinMapAt(
    bpfj::libbpf::BpfSkelBase& skel,
    std::string_view name,
    const fs::path& pinPath,
    std::optional<std::uint32_t> maxEntries) noexcept {
  auto map = skel.getMap(name.data());
  if (!map) {
    return makeUnexpected(
        makeError(std::errc::no_such_file_or_directory, "no map named ", name));
  }

  if (maxEntries) {
    if (auto res = map->setMaxEntries(*maxEntries); !res) {
      return res;
    }
  }

  return map->setPinPath(pinPath.c_str());
}

Expected<> pinMap(
    bpfj::libbpf::BpfSkelBase& skel,
    std::string_view name,
    const fs::path& mapDir,
    std::optional<std::uint32_t> maxEntries) noexcept {
  return pinMapAt(skel, name, mapDir / name, maxEntries);
}

Expected<Fd> openPinnedMap(
    const PinConfig& cfg,
    std::string_view name) noexcept {
  const std::string path = cfg.mapPath(name);
  const int fd = ::bpf_obj_get(path.c_str());
  if (fd < 0) {
    return makeUnexpected(makeErrnoError("failed to open pinned map ", path));
  }

  return Fd(fd);
}

Expected<Fd> openPinnedProgram(
    const PinConfig& cfg,
    std::string_view name) noexcept {
  const std::string path = cfg.programPath(name);
  const int fd = ::bpf_obj_get(path.c_str());
  if (fd < 0) {
    return makeUnexpected(
        makeErrnoError("failed to open pinned program ", path));
  }

  return Fd(fd);
}

Expected<> pinSharedMaps(
    bpfj::libbpf::BpfSkelBase& skel,
    const fs::path& mapDir) noexcept {
  if (auto res = arena::prepareMap(skel, mapDir); !res) {
    return res;
  }

  for (const auto& name : kSharedMapNames) {
    const auto maxEntries = name == "bpfj_event_map"
        ? std::optional<std::uint32_t>(kBpfEventMapEntries)
        : name == "bpfj_log_map"
        ? std::optional<std::uint32_t>(kBpfLogMapEntries)
        : std::nullopt;

    if (auto res = pinMap(skel, name, mapDir, maxEntries); !res) {
      if (isOptionalSharedMap(name) &&
          res.error().code() == std::errc::no_such_file_or_directory) {
        continue;
      }
      return res;
    }
  }

  return unit;
}

} // namespace pins
} // namespace bpfjailer
