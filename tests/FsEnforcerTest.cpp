// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <optional>
#include <string>

#include "bpfj/enforce/FsEnforcer.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/Pods.h"

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
  const int fd = ::open(path.c_str(), flags | O_CLOEXEC, 0600);
  if (fd < 0) {
    return errno;
  }
  ::close(fd);
  return 0;
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
      rule(std::string(root) + "/$USER/data", std::nullopt));
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
