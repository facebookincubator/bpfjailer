// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "bpfj/enforce/FsEnforcer.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/Pods.h"
#include "bpfj/match/bpf/types_file_match_cached.h"
#include "bpfj/match/bpf/types_matcher_state.h"

using bpfjailer::FsEnforcer;
using bpfjailer::Policy;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

class Fixture {
 public:
  Fixture() {
    char path[] = "/tmp/bpfj-fs-test-XXXXXX";
    ASSERT(::mkdtemp(path) != nullptr);
    dir_ = path;
    file_ = dir_ + "/data";
    const int fd = ::open(file_.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    ASSERT(fd >= 0);
    ASSERT_EQ(::write(fd, "data", 4), 4);
    ASSERT_EQ(::close(fd), 0);
  }

  ~Fixture() {
    (void)::unlink((dir_ + "/renamed").c_str());
    (void)::unlink((dir_ + "/new").c_str());
    (void)::unlink(file_.c_str());
    (void)::rmdir(dir_.c_str());
  }

  const std::string& dir() const {
    return dir_;
  }

  const std::string& file() const {
    return file_;
  }

 private:
  std::string dir_;
  std::string file_;
};

void attach(const std::string& paths) {
  const Policy policy = policyOf("[roles.svc]\n" + paths);
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));
}

[[nodiscard]] std::string rule(
    const std::string& path,
    std::optional<std::string_view> access) {
  std::string result = "[[roles.svc.paths]]\npath = \"" + path + "\"\n";
  if (!access.has_value()) {
    return result + "allow = false\n";
  }
  return result + "allow = true\naccess = \"" + std::string(*access) + "\"\n";
}

[[nodiscard]] int openErrno(const std::string& path, int flags) {
  errno = 0;
  const int fd = ::open(path.c_str(), flags | O_CLOEXEC);
  if (fd < 0) {
    return errno;
  }
  ::close(fd);
  return 0;
}

[[nodiscard]] std::vector<struct bpfj_file_match_cached_key>
exactCacheKeysForInode(ino_t ino) {
  auto map =
      bpfjailer::pins::openPinnedMap(testPins(), "bpfj_file_match_exact_cache");
  ASSERT(map);

  std::vector<struct bpfj_file_match_cached_key> matches;
  struct bpfj_file_match_cached_key current{};
  struct bpfj_file_match_cached_key next{};
  const void* previous = nullptr;
  while (::bpf_map_get_next_key(map->get(), previous, &next) == 0) {
    if (next.ino == static_cast<__u64>(ino)) {
      matches.push_back(next);
    }
    current = next;
    previous = &current;
  }
  return matches;
}

[[nodiscard]] struct bpfj_file_match_cached_entry exactCacheEntry(
    const struct bpfj_file_match_cached_key& key) {
  auto map =
      bpfjailer::pins::openPinnedMap(testPins(), "bpfj_file_match_exact_cache");
  ASSERT(map);
  struct bpfj_file_match_cached_entry entry{};
  ASSERT_EQ(::bpf_map_lookup_elem(map->get(), &key, &entry), 0);
  return entry;
}

[[nodiscard]] struct bpfj_matcher_state matcherState() {
  auto map =
      bpfjailer::pins::openPinnedMap(testPins(), "bpfj_file_match_state");
  ASSERT(map);
  const __u32 zero = 0;
  struct bpfj_matcher_state state{};
  ASSERT_EQ(::bpf_map_lookup_elem(map->get(), &zero, &state), 0);
  return state;
}

} // namespace

TEST(FsEnforcer, LoadPinsEveryHook) {
  Fixture fixture;
  attach(rule(fixture.file(), "read-only"));

  ASSERT(linkPinned("bpfj_fs_file_open"));
  ASSERT(linkPinned("bpfj_fs_inode_rename"));
  ASSERT(linkPinned("bpfj_fs_inode_rename_destination"));
  ASSERT(linkPinned("bpfj_fs_inode_link_source"));
  ASSERT(!linkPinned("bpfj_fs_file_ioctl"));
  ASSERT(!linkPinned("bpfj_fs_file_truncate"));

  auto arena = bpfjailer::PodArena::open(testPins());
  ASSERT(arena);
  auto policies = bpfjailer::readRolePolicies(*arena);
  ASSERT_OK(policies);
  ASSERT(*policies);
  auto policy = bpfjailer::lookupRolePolicy(*policies, "svc");
  ASSERT_OK(policy);
  ASSERT(*policy);
  ASSERT((*policy)->fs_matcher != nullptr);
}

TEST(FsEnforcer, MissingFilesystemPolicyDeniesAccess) {
  Fixture fixture;
  const Policy policy = policyOf(R"toml([roles]

[roles.svc]
)toml");
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));

  Child actor([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, FsAnyAllowsAccess) {
  Fixture fixture;
  const Policy policy = policyOf(R"toml([roles]

[roles.svc]
fs-any = true
)toml");
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));

  Child actor([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(FsEnforcer, OverrideStackedBoundsTheActorPolicyWalk) {
  Fixture fixture;
  const Policy policy = policyOf(
      "[[roles.denied.paths]]\npath = \"" + fixture.file() +
      "\"\nallow = false\n"
      "[roles.override]\noverride-stacked = true\n"
      "[[roles.override.paths]]\npath = \"" +
      fixture.file() +
      "\"\nallow = true\naccess = \"read-only\"\n"
      "[[roles.top.paths]]\npath = \"" +
      fixture.file() + "\"\nallow = false\n");
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));

  Child allowed([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("denied", allowed.pid());
  enroll("override", allowed.pid());
  ASSERT_EQ(allowed.run(), 0);

  Child denied([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("denied", denied.pid());
  enroll("override", denied.pid());
  enroll("top", denied.pid());
  ASSERT_EQ(denied.run(), EACCES);
}

TEST(FsEnforcer, UnenrolledFilesystemTrafficDoesNotUseTheHeap) {
  Fixture fixture;
  attach(rule(fixture.file(), std::nullopt));

  auto arena = bpfjailer::PodArena::open(testPins());
  ASSERT(arena.hasValue());
  const auto allocsBefore = arena->ctrl()->total_alloc;
  const auto freesBefore = arena->ctrl()->total_free;
  const auto usedBefore = arena->ctrl()->current_used;

  for (int i = 0; i < 100; ++i) {
    ASSERT_EQ(openErrno(fixture.file(), O_RDONLY), 0);
  }

  ASSERT_EQ(arena->ctrl()->total_alloc, allocsBefore);
  ASSERT_EQ(arena->ctrl()->total_free, freesBefore);
  ASSERT_EQ(arena->ctrl()->current_used, usedBefore);
}

TEST(FsEnforcer, ReadOnlyAllowsReadsAndDeniesWrites) {
  Fixture fixture;
  attach(rule(fixture.file(), "read-only"));

  Child actor([&] {
    const int readError = openErrno(fixture.file(), O_RDONLY);
    return readError != 0 ? readError : openErrno(fixture.file(), O_WRONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, DeniedRuleDeniesReads) {
  Fixture fixture;
  attach(rule(fixture.file(), std::nullopt));

  Child actor([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, PolicyPathDoesNotMatchTheSameSuffixBelowAnotherDirectory) {
  Fixture fixture;
  const std::string suffix = fixture.file().substr(std::string("/tmp").size());
  attach(rule(suffix, "read-only"));

  Child actor([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, ReadWriteAllowsWrites) {
  Fixture fixture;
  attach(rule(fixture.file(), "read-write"));

  Child actor([&] { return openErrno(fixture.file(), O_WRONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(FsEnforcer, LongestPathWins) {
  Fixture fixture;
  attach(rule(fixture.dir(), std::nullopt) + rule(fixture.file(), "read-only"));

  Child actor([&] {
    const int readError = openErrno(fixture.file(), O_RDONLY);
    return readError != 0 ? readError : openErrno(fixture.file(), O_WRONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, RootPolicyAppliesToDescendants) {
  Fixture fixture;
  attach(rule("/", std::nullopt));

  Child actor([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, SpecificPathOverridesRootPolicy) {
  Fixture fixture;
  attach(rule("/", std::nullopt) + rule(fixture.file(), "read-only"));

  Child actor([&] {
    const int readError = openErrno(fixture.file(), O_RDONLY);
    return readError != 0 ? readError : openErrno(fixture.file(), O_WRONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, UnboundVariableDoesNotMatchAtRootTransition) {
  Fixture fixture;
  const Policy policy = policyOf(
      "vars = [\"USER\"]\n[roles.svc]\n" + rule(fixture.dir(), "read-only") +
      rule(fixture.dir() + "/$USER", std::nullopt));
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));

  Child actor([&] { return openErrno(fixture.file(), O_RDONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);
}

TEST(FsEnforcer, HardLinkAliasesDoNotShareCachedPolicy) {
  Fixture fixture;
  const std::string alias = fixture.dir() + "/renamed";
  ASSERT_EQ(::link(fixture.file().c_str(), alias.c_str()), 0);
  attach(rule(fixture.file(), "read-write") + rule(alias, std::nullopt));

  Child actor([&] {
    int error = openErrno(fixture.file(), O_RDONLY);
    if (error != 0) {
      return error;
    }
    error = openErrno(fixture.file(), O_RDONLY);
    return error != 0 ? error : openErrno(alias, O_RDONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, NativeExactAndCheckpointCachesPopulate) {
  Fixture fixture;
  const std::string sibling = fixture.dir() + "/new";
  const int fd = ::open(sibling.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::close(fd), 0);
  attach(rule(fixture.dir(), "read-only"));

  ASSERT(bpfjailer::test::pinnedMapIsEmpty("bpfj_file_match_exact_cache"));
  ASSERT(bpfjailer::test::pinnedMapIsEmpty("bpfj_file_match_checkpoint_cache"));

  Child actor([&] {
    int error = openErrno(fixture.file(), O_RDONLY);
    if (error != 0) {
      return error;
    }
    error = openErrno(fixture.file(), O_RDONLY);
    return error != 0 ? error : openErrno(sibling, O_RDONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);

  struct stat first{};
  struct stat second{};
  ASSERT_EQ(::stat(fixture.file().c_str(), &first), 0);
  ASSERT_EQ(::stat(sibling.c_str(), &second), 0);
  ASSERT_EQ(exactCacheKeysForInode(first.st_ino).size(), 1U);
  ASSERT_EQ(exactCacheKeysForInode(second.st_ino).size(), 1U);
  ASSERT(
      !bpfjailer::test::pinnedMapIsEmpty("bpfj_file_match_checkpoint_cache"));
}

TEST(FsEnforcer, PrivateMountNamespaceDoesNotInvalidateTheRootCache) {
  Fixture fixture;
  const std::string mountpoint = fixture.dir() + "/mount";
  ASSERT_EQ(::mkdir(mountpoint.c_str(), 0700), 0);
  attach(rule(fixture.dir(), "read-write"));

  Child actor([&] {
    int error = openErrno(fixture.file(), O_RDONLY);
    if (error != 0) {
      return error;
    }
    if (::mount("tmpfs", mountpoint.c_str(), "tmpfs", 0, nullptr) != 0) {
      return errno;
    }
    error = openErrno(fixture.file(), O_RDONLY);
    const int unmountError = ::umount2(mountpoint.c_str(), MNT_DETACH);
    if (error != 0) {
      return error;
    }
    return unmountError == 0 ? 0 : errno;
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);

  struct stat info{};
  ASSERT_EQ(::stat(fixture.file().c_str(), &info), 0);
  const auto keys = exactCacheKeysForInode(info.st_ino);
  ASSERT_EQ(keys.size(), 1U);
  ASSERT_EQ(::rmdir(mountpoint.c_str()), 0);
}

TEST(FsEnforcer, RenameJournalWrapRefreshesAnExactEntry) {
  Fixture fixture;
  const std::string first = fixture.dir() + "/new";
  const std::string second = fixture.dir() + "/renamed";
  const int fd = ::open(first.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::close(fd), 0);
  attach(rule(fixture.dir(), "read-write"));

  Child actor([&] {
    int error = openErrno(fixture.file(), O_RDONLY);
    if (error != 0) {
      return error;
    }
    for (std::size_t i = 0; i <= BPFJ_FILE_MATCH_CACHED_RENAME_JOURNAL_SIZE / 4;
         ++i) {
      if (::rename(first.c_str(), second.c_str()) != 0 ||
          ::rename(second.c_str(), first.c_str()) != 0) {
        return errno;
      }
    }
    return openErrno(fixture.file(), O_RDONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), 0);

  struct stat info{};
  ASSERT_EQ(::stat(fixture.file().c_str(), &info), 0);
  const auto keys = exactCacheKeysForInode(info.st_ino);
  ASSERT_EQ(keys.size(), 1U);
  const auto entry = exactCacheEntry(keys.front());
  const auto state = matcherState();
  ASSERT_EQ(entry.rename_generation, state.rename_journal.generation);
}

TEST(FsEnforcer, ReadOnlyDirectoryDeniesCreate) {
  Fixture fixture;
  attach(rule(fixture.dir(), "read-only"));

  Child actor(
      [&] { return openErrno(fixture.dir() + "/new", O_CREAT | O_WRONLY); });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, RenameInvalidatesTheCachedPath) {
  Fixture fixture;
  const std::string renamed = fixture.dir() + "/renamed";
  attach(rule(fixture.file(), "read-write") + rule(renamed, std::nullopt));

  Child actor([&] {
    int error = openErrno(fixture.file(), O_RDONLY);
    if (error != 0) {
      return error;
    }
    if (::rename(fixture.file().c_str(), renamed.c_str()) != 0) {
      return errno;
    }
    return openErrno(renamed, O_RDONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);
}

TEST(FsEnforcer, DirectoryRenameInvalidatesCachedDescendants) {
  char rootPath[] = "/tmp/bpfj-fs-dir-rename-test-XXXXXX";
  ASSERT(::mkdtemp(rootPath) != nullptr);
  const std::string root = rootPath;
  const std::string source = root + "/source";
  const std::string sourceSubdir = source + "/subdir";
  const std::string sourceFile = sourceSubdir + "/data";
  const std::string destination = root + "/destination";
  const std::string destinationFile = destination + "/subdir/data";
  ASSERT_EQ(::mkdir(source.c_str(), 0700), 0);
  ASSERT_EQ(::mkdir(sourceSubdir.c_str(), 0700), 0);
  const int fd =
      ::open(sourceFile.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::close(fd), 0);

  attach(rule(root, "read-write") + rule(destinationFile, std::nullopt));

  Child actor([&] {
    int error = openErrno(sourceFile, O_RDONLY);
    if (error != 0) {
      return error;
    }
    // Hit the leaf cache before moving the directory and all of its cached
    // descendants to a path with a different policy.
    error = openErrno(sourceFile, O_RDONLY);
    if (error != 0) {
      return error;
    }
    if (::rename(source.c_str(), destination.c_str()) != 0) {
      return errno;
    }
    return openErrno(destinationFile, O_RDONLY);
  });
  enroll("svc", actor.pid());
  ASSERT_EQ(actor.run(), EACCES);

  ASSERT_EQ(::unlink(destinationFile.c_str()), 0);
  ASSERT_EQ(::rmdir((destination + "/subdir").c_str()), 0);
  ASSERT_EQ(::rmdir(destination.c_str()), 0);
  ASSERT_EQ(::rmdir(root.c_str()), 0);
}

TEST(FsEnforcer, CacheSeparatesPodsWithDifferentVariableBindings) {
  char root[] = "/tmp/bpfj-fs-vars-test-XXXXXX";
  ASSERT(::mkdtemp(root) != nullptr);
  const std::string alice = std::string(root) + "/alice";
  ASSERT_EQ(::mkdir(alice.c_str(), 0700), 0);
  const std::string file = alice + "/data";
  int fd = ::open(file.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::close(fd), 0);

  const Policy policy = policyOf(
      "vars = [\"USER\"]\n[roles.svc]\n" + rule(root, "read-only") +
      rule(std::string(root) + "/${USER}/data", std::nullopt));
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));

  Child alicePod([&] { return openErrno(file, O_RDONLY); });
  const std::array<bpfjailer::PodVar, 1> aliceVars{{{"USER", "alice"}}};
  ASSERT_OK(
      bpfjailer::enrollPod(
          testPins(),
          "svc",
          "alice@meta",
          aliceVars,
          alicePod.pid(),
          bpfjailer::Threads::All));
  ASSERT_EQ(alicePod.run(), EACCES);

  Child bobPod([&] { return openErrno(file, O_RDONLY); });
  const std::array<bpfjailer::PodVar, 1> bobVars{{{"USER", "bob"}}};
  ASSERT_OK(
      bpfjailer::enrollPod(
          testPins(),
          "svc",
          "bob@meta",
          bobVars,
          bobPod.pid(),
          bpfjailer::Threads::All));
  ASSERT_EQ(bobPod.run(), 0);

  ASSERT_EQ(::unlink(file.c_str()), 0);
  ASSERT_EQ(::rmdir(alice.c_str()), 0);
  ASSERT_EQ(::rmdir(root), 0);
}

TEST(FsEnforcer, BareDollarVariableNameIsLiteral) {
  char root[] = "/tmp/bpfj-fs-literal-var-test-XXXXXX";
  ASSERT(::mkdtemp(root) != nullptr);
  const std::string literalDir = std::string(root) + "/$USER";
  const std::string boundDir = std::string(root) + "/alice";
  ASSERT_EQ(::mkdir(literalDir.c_str(), 0700), 0);
  ASSERT_EQ(::mkdir(boundDir.c_str(), 0700), 0);
  const std::string literalFile = literalDir + "/data";
  const std::string boundFile = boundDir + "/data";
  for (const auto& file : {literalFile, boundFile}) {
    int fd = ::open(file.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    ASSERT(fd >= 0);
    ASSERT_EQ(::close(fd), 0);
  }

  const Policy policy = policyOf(
      "vars = [\"USER\"]\n[roles.svc]\n" + rule(root, "read-only") +
      rule(std::string(root) + "/$USER/data", std::nullopt));
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));
  const std::array<bpfjailer::PodVar, 1> vars{{{"USER", "alice"}}};

  Child literalPod([&] { return openErrno(literalFile, O_RDONLY); });
  ASSERT_OK(
      bpfjailer::enrollPod(
          testPins(),
          "svc",
          "literal@meta",
          vars,
          literalPod.pid(),
          bpfjailer::Threads::All));
  ASSERT_EQ(literalPod.run(), EACCES);

  Child boundPod([&] { return openErrno(boundFile, O_RDONLY); });
  ASSERT_OK(
      bpfjailer::enrollPod(
          testPins(),
          "svc",
          "bound@meta",
          vars,
          boundPod.pid(),
          bpfjailer::Threads::All));
  ASSERT_EQ(boundPod.run(), 0);

  ASSERT_EQ(::unlink(literalFile.c_str()), 0);
  ASSERT_EQ(::unlink(boundFile.c_str()), 0);
  ASSERT_EQ(::rmdir(literalDir.c_str()), 0);
  ASSERT_EQ(::rmdir(boundDir.c_str()), 0);
  ASSERT_EQ(::rmdir(root), 0);
}
