// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <filesystem>
#include <string>

#include "bpfj/enforce/ExecEnforcer.h"
#include "bpfj/enforce/FsEnforcer.h"
#include "bpfj/enforce/PodVars.h"

using bpfjailer::ExecEnforcer;
using bpfjailer::FsEnforcer;
using bpfjailer::PodVar;
using bpfjailer::Policy;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::linkPinned;
using bpfjailer::test::loadJailer;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

constexpr int kRanAndFailed = -1;

[[nodiscard]] std::string truePath() {
  return std::filesystem::canonical("/bin/true").string();
}

[[nodiscard]] std::string uniquePath(const std::string& prefix) {
  std::string dir = "/tmp/" + prefix + "-XXXXXX";
  ASSERT(::mkdtemp(dir.data()) != nullptr);
  return dir + "/file";
}

[[nodiscard]] std::string rule(
    const std::string& role,
    const std::string& path,
    bool allowExec,
    bool allowSetuid,
    bool allowSharedObject) {
  std::string permissions;
  const auto add = [&](std::string_view permission) {
    if (!permissions.empty()) {
      permissions += ", ";
    }
    permissions += "\"" + std::string(permission) + "\"";
  };
  if (allowExec) {
    add("exec");
  }
  if (allowSetuid) {
    add("set-id");
  }
  if (allowSharedObject) {
    add("shared-object");
  }
  std::string result =
      "\n[[roles." + role + ".exec-paths]]\npath = \"" + path + "\"\nallow = ";
  if (permissions.empty()) {
    return result + "false\n";
  }
  return result + "true\npermissions = [" + permissions + "]\n";
}

[[nodiscard]] std::string execPolicy(
    const std::string& executable,
    bool allowExec,
    bool allowSetuid = false,
    bool allowSharedObjects = true) {
  return "[roles.svc]\n" +
      rule("svc", "/usr/lib64/*", false, false, allowSharedObjects) +
      rule("svc", executable, allowExec, allowSetuid, false);
}

void attach(const std::string& toml) {
  const Policy policy = policyOf(toml);
  loadJailer(policy);
  ASSERT_OK(ExecEnforcer::load(testPins(), policy));
}

void attachWithFilesystem(const std::string& toml) {
  const Policy policy = policyOf(toml);
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));
  ASSERT_OK(ExecEnforcer::load(testPins(), policy));
}

[[nodiscard]] int runProgram(const std::string& path) {
  int report[2] = {-1, -1};
  if (::pipe(report) != 0) {
    return errno;
  }

  const pid_t pid = ::fork();
  if (pid < 0) {
    return errno;
  }
  if (pid == 0) {
    ::close(report[0]);
    std::string owned = path;
    char* const argv[] = {owned.data(), nullptr};
    ::execv(owned.c_str(), argv);
    const int failed = errno;
    (void)::write(report[1], &failed, sizeof(failed));
    ::_exit(127);
  }

  ::close(report[1]);
  int failed = 0;
  const ssize_t n = ::read(report[0], &failed, sizeof(failed));
  ::close(report[0]);
  int status = 0;
  (void)::waitpid(pid, &status, 0);
  if (n == static_cast<ssize_t>(sizeof(failed))) {
    return failed;
  }
  return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : kRanAndFailed;
}

[[nodiscard]] std::string copyExecutable(mode_t mode) {
  const std::string path = uniquePath("exec-enforcer-true");
  std::filesystem::copy_file(
      truePath(), path, std::filesystem::copy_options::overwrite_existing);
  ASSERT_EQ(::chmod(path.c_str(), mode), 0);
  return path;
}

[[nodiscard]] int addExecutePermission(const std::string& path) {
  const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    return errno;
  }
  if (::ftruncate(fd, 4096) != 0) {
    const int failed = errno;
    ::close(fd);
    return failed;
  }
  void* mapping = ::mmap(nullptr, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
  ::close(fd);
  if (mapping == MAP_FAILED) {
    return errno;
  }
  const int result = ::mprotect(mapping, 4096, PROT_READ | PROT_EXEC);
  const int failed = result == 0 ? 0 : errno;
  ::munmap(mapping, 4096);
  return failed;
}

} // namespace

TEST(ExecEnforcer, LoadPinsEveryHook) {
  attach("[roles.svc]\n");

  ASSERT(linkPinned("bpfj_exec_bprm_check"));
  ASSERT(linkPinned("bpfj_exec_mmap_file"));
  ASSERT(linkPinned("bpfj_exec_file_mprotect"));
  ASSERT(linkPinned("bpfj_matcher_state_inode_unlink"));
  ASSERT(linkPinned("bpfj_matcher_state_inode_link"));
  ASSERT(linkPinned("bpfj_matcher_state_inode_rename"));
  ASSERT(linkPinned("bpfj_matcher_state_inode_rmdir"));
  ASSERT(linkPinned("bpfj_matcher_state_vfs_unlink"));
  ASSERT(linkPinned("bpfj_matcher_state_vfs_link"));
  ASSERT(linkPinned("bpfj_matcher_state_vfs_rename"));
  ASSERT(linkPinned("bpfj_matcher_state_vfs_rmdir"));
}

TEST(ExecEnforcer, MissingPolicyDeniesExec) {
  const std::string executable = truePath();
  attach("[roles.svc]\n");

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, AllowedDynamicExecutableRuns) {
  const std::string executable = truePath();
  attach(execPolicy(executable, true));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, DeniedExecutableDoesNotRun) {
  const std::string executable = truePath();
  attach(execPolicy(executable, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, DeniedSharedObjectStopsDynamicProgram) {
  const std::string executable = truePath();
  attach(execPolicy(executable, true, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), kRanAndFailed);
}

TEST(ExecEnforcer, SetuidNeedsBothExecPermissions) {
  const std::string executable = copyExecutable(04755);
  attach(execPolicy(executable, true, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, AllowedSetuidExecutableRuns) {
  const std::string executable = copyExecutable(04755);
  attach(execPolicy(executable, true, true));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, FileMprotectNeedsSharedObjectPermission) {
  const std::string path = uniquePath("exec-enforcer-mprotect");
  attach("[roles.svc]\n" + rule("svc", path, false, false, false));

  Child actor([&] { return addExecutePermission(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, SharedObjectPermissionAllowsFileMprotect) {
  const std::string path = uniquePath("exec-enforcer-mprotect");
  attach("[roles.svc]\n" + rule("svc", path, false, false, true));

  Child actor([&] { return addExecutePermission(path); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, UnjailedProcessMayExec) {
  const std::string executable = truePath();
  attach(execPolicy(executable, false));

  Child actor([&] { return runProgram(executable); });

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, AnyAllowsExecutableAndSharedObjects) {
  const std::string executable = truePath();
  attach("[roles.svc]\nany = true\n");

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, ExecAnyAllowsExecutableAndSharedObjects) {
  const std::string executable = truePath();
  attach("[roles.svc]\nexec-any = true\n");

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, ReadOnlyFilesystemDoesNotDecideExecution) {
  const std::string executable = truePath();
  attachWithFilesystem(
      "[[roles.svc.paths]]\npath = \"/\"\nallow = true\n"
      "access = \"read-only\"\n" +
      rule("svc", "/usr/lib64/*", false, false, true) +
      rule("svc", executable, true, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, LongestPathMatchWins) {
  const std::string executable = truePath();
  attach(
      "[roles.svc]\n" + rule("svc", "/usr", false, false, false) +
      rule("svc", "/usr/lib64/*", false, false, true) +
      rule("svc", executable, true, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, MoreSpecificPathWinsAtSameDepth) {
  const std::string executable = truePath();
  attach(
      "[roles.svc]\n" + rule("svc", "/usr/lib64/*", false, false, true) +
      rule("svc", "/usr/bin/*", false, false, false) +
      rule("svc", executable, true, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, BoundVariableComponentIsSpecific) {
  const std::filesystem::path executable = truePath();
  const std::string directory = executable.parent_path().string();
  const std::string program = executable.filename().string();
  attach(
      "vars = [\"PROGRAM\"]\n[roles.svc]\n" +
      rule("svc", "/usr/lib64/*", false, false, true) +
      rule("svc", directory + "/*", false, false, false) +
      rule("svc", directory + "/${PROGRAM}", true, false, false));

  Child actor([&] { return runProgram(executable.string()); });
  const std::array vars{PodVar{.name = "PROGRAM", .value = program}};
  enroll("svc", actor.pid(), vars);

  ASSERT_EQ(actor.run(), 0);
}

TEST(ExecEnforcer, MoreSpecificDenialWinsAtSameDepth) {
  const std::string executable = truePath();
  attach(
      "[roles.svc]\n" + rule("svc", "/usr/lib64/*", false, false, true) +
      rule("svc", "/usr/bin/*", true, false, false) +
      rule("svc", executable, false, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, DenialWinsEquallySpecificTie) {
  const std::string executable = truePath();
  attach(
      "[roles.svc]\n" + rule("svc", "/usr/lib64/*", false, false, true) +
      rule("svc", "/usr/*/true", true, false, false) +
      rule("svc", "/usr/bin/*", false, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("svc", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, EveryStackedRoleMustAllowExec) {
  const std::string executable = truePath();
  attach(
      "[roles.allow]\n[roles.deny]\n" +
      rule("allow", "/usr/lib64/*", false, false, true) +
      rule("allow", executable, true, false, false) +
      rule("deny", "/usr/lib64/*", false, false, true) +
      rule("deny", executable, false, false, false));

  Child actor([&] { return runProgram(executable); });
  enroll("allow", actor.pid());
  enroll("deny", actor.pid());

  ASSERT_EQ(actor.run(), EACCES);
}

TEST(ExecEnforcer, OverrideStackedBoundsTheActorPolicyWalk) {
  const std::string executable = truePath();
  attach(
      "[roles.denied]\n[roles.override]\noverride-stacked = true\n"
      "[roles.top]\n" +
      rule("denied", "/usr/lib64/*", false, false, true) +
      rule("denied", executable, false, false, false) +
      rule("override", "/usr/lib64/*", false, false, true) +
      rule("override", executable, true, false, false) +
      rule("top", "/usr/lib64/*", false, false, true) +
      rule("top", executable, false, false, false));

  Child allowed([&] { return runProgram(executable); });
  enroll("denied", allowed.pid());
  enroll("override", allowed.pid());
  ASSERT_EQ(allowed.run(), 0);

  Child denied([&] { return runProgram(executable); });
  enroll("denied", denied.pid());
  enroll("override", denied.pid());
  enroll("top", denied.pid());
  ASSERT_EQ(denied.run(), EACCES);
}
