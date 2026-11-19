// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/xattr.h>

#include <cerrno>
#include <filesystem>
#include <initializer_list>

#include <string>
#include <string_view>

#include "bpfj/enforce/EnrollGate.h"
#include "bpfj/enforce/Pods.h"

using bpfjailer::enrollPermitted;
using bpfjailer::test::enroll;
using bpfjailer::test::loadJailer;
using bpfjailer::test::mapPinned;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

namespace {

/// @brief Whether this process may add `role`, ending the test on an error.
[[nodiscard]] bool permitted(std::string_view role) {
  auto res = enrollPermitted(testPins(), ::getpid(), role);
  ASSERT_OK(res);
  return *res;
}

} // namespace

TEST(EnrollGate, LoadPinsItsMaps) {
  loadJailer(policyOf(R"toml([roles]

[roles.svc]
)toml"));

  ASSERT(!mapPinned("bpfj_role_policies"));
  ASSERT(!mapPinned("bpfj_enroll_roles"));
  ASSERT(!mapPinned("bpfj_enroll_access"));
}

TEST(EnrollGate, AnUnjailedCallerIsUnrestricted) {
  loadJailer(policyOf(R"toml([roles]

[roles.sandbox]
)toml"));

  ASSERT(permitted("sandbox"));
}

TEST(EnrollGate, ARoleWithNoEnrollKeyIsDenied) {
  loadJailer(policyOf(R"toml([roles]

[roles.svc]

[roles.sandbox]
)toml"));
  enroll("svc", ::getpid());

  ASSERT(!permitted("sandbox"));
  ASSERT(!permitted("svc"));
}

TEST(EnrollGate, AnEmptyListForbidsEvenTheSameRoleAgain) {
  loadJailer(policyOf(R"toml([roles]

[roles.sandbox]
enroll-roles = []

[roles.other]
)toml"));
  enroll("sandbox", ::getpid());

  ASSERT(!permitted("sandbox"));
  ASSERT(!permitted("other"));
}

TEST(EnrollGate, AListPermitsOnlyTheRolesItNames) {
  loadJailer(policyOf(
      R"toml([roles]

[roles.svc]
enroll-roles = ["worker"]

[roles.worker]

[roles.other]
)toml"));
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
  ASSERT(!permitted("other"));
}

TEST(EnrollGate, EveryConfiguredRoleHasToPermit) {
  loadJailer(policyOf(
      R"toml([roles]

[roles.svc]
enroll-roles = ["worker"]

[roles.strict]
enroll-roles = []

[roles.worker]
)toml"));
  enroll("strict", ::getpid());
  enroll("svc", ::getpid());

  ASSERT(!permitted("worker"));
}

TEST(EnrollGate, AnAnyRolePermitsTheNarrowerRoleToAnswer) {
  loadJailer(policyOf(
      R"toml(base-role = "floor"

[roles]

[roles.floor]
enroll-any = true

[roles.svc]
enroll-roles = ["worker"]

[roles.worker]
)toml"));
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
}

TEST(EnrollGate, AnOverrideRoleAnswersForTheRolesUnderIt) {
  loadJailer(policyOf(
      R"toml([roles]

[roles.strict]
enroll-roles = []

[roles.svc]
override-stacked = true
enroll-roles = ["worker"]

[roles.worker]
)toml"));
  enroll("strict", ::getpid());
  enroll("svc", ::getpid());

  ASSERT(permitted("worker"));
}

TEST(EnrollGate, ABaseRoleCanForbidStackingHostWide) {
  loadJailer(policyOf(
      R"toml(base-role = "floor"

[roles]

[roles.floor]
enroll-roles = []

[roles.svc]
)toml"));

  ASSERT(!permitted("svc"));
}

namespace {

void checkExecEnrollment(const std::string &executable,
                         std::initializer_list<std::string_view> roles,
                         int expected, bool hasXattr = true) {
  bpfjailer::test::Child actor([&] {
    int report[2];
    ASSERT_EQ(::pipe2(report, O_CLOEXEC), 0);
    const pid_t pid = ::fork();
    ASSERT(pid >= 0);
    if (pid == 0) {
      ::close(report[0]);
      ::execl(executable.c_str(), executable.c_str(), "30", nullptr);
      const int error = errno;
      (void)::write(report[1], &error, sizeof(error));
      ::_exit(1);
    }
    ::close(report[1]);
    int error = 0;
    const ssize_t count = ::read(report[0], &error, sizeof(error));
    ::close(report[0]);
    ASSERT(count == 0 || count == sizeof(error));
    if (count == 0) {
      auto pods = bpfjailer::listPods(testPins(), pid);
      // Reap the executable before assertions so failures leave no child
      // running.
      (void)::kill(pid, SIGKILL);
      ASSERT_EQ(::waitpid(pid, nullptr, 0), pid);
      ASSERT_OK(pods);
      ASSERT_EQ(pods->size(), roles.size() + (hasXattr ? 1 : 0));
      std::size_t index = 0;
      for (auto role : roles) {
        ASSERT_EQ(std::string((*pods)[index++].role_id.id), std::string(role));
      }
      if (hasXattr) {
        ASSERT_EQ(std::string(pods->back().role_id.id), "worker");
      }
    } else {
      ASSERT_EQ(::waitpid(pid, nullptr, 0), pid);
      auto pods = bpfjailer::listPods(testPins(), ::getpid());
      ASSERT_OK(pods);
      ASSERT_EQ(pods->size(), roles.size());
    }
    return error;
  });
  for (auto role : roles) {
    enroll(role, actor.pid());
  }
  ASSERT_EQ(actor.run(), expected);
}

} // namespace

TEST_EXCLUSIVE(EnrollGate, ExecXattrChecksExistingRoles) {
  const std::string directory = bpfjailer::test::scratchFsPath() +
                                "/exec-enroll-" + std::to_string(::getpid());
  ASSERT(std::filesystem::create_directory(directory));
  const std::string executable = directory + "/sleep";
  ASSERT(std::filesystem::copy_file("/bin/sleep", executable));
  const std::string plain = directory + "/plain";
  ASSERT(std::filesystem::copy_file("/bin/sleep", plain));
  const bpfj_role_id target = {.id = "worker"};
  ASSERT_EQ(::setxattr(executable.c_str(), BPFJ_EXEC_POLICY_XATTR, &target,
                       sizeof(target), 0),
            0);
  loadJailer(policyOf(R"toml(
[roles.allowed]
enroll-roles = ["worker"]
[roles.denied]
enroll-roles = []
[roles.absent]
[roles.other]
enroll-roles = ["allowed"]
[roles.open]
enroll-any = true
[roles.all]
any = true
[roles.override]
override-stacked = true
enroll-roles = ["worker"]
[roles.override-denied]
override-stacked = true
enroll-roles = []
[roles.worker]
enroll-roles = ["worker"]
)toml"));

  checkExecEnrollment(executable, {}, 0);
  checkExecEnrollment(executable, {"allowed"}, 0);
  checkExecEnrollment(executable, {"denied"}, EACCES);
  checkExecEnrollment(executable, {"absent"}, EACCES);
  checkExecEnrollment(executable, {"other"}, EACCES);
  checkExecEnrollment(executable, {"open"}, 0);
  checkExecEnrollment(executable, {"all"}, 0);
  checkExecEnrollment(executable, {"worker"}, 0);
  checkExecEnrollment(executable, {"denied", "allowed"}, EACCES);
  checkExecEnrollment(executable, {"denied", "override"}, 0);
  checkExecEnrollment(executable, {"allowed", "override-denied"}, EACCES);
  checkExecEnrollment(executable, {"denied", "override", "denied"}, EACCES);
  checkExecEnrollment(plain, {"denied"}, 0, false);
  const bpfj_role_id deniedTarget = {.id = "denied"};
  ASSERT_EQ(::setxattr(executable.c_str(), BPFJ_EXEC_POLICY_XATTR,
                      &deniedTarget, sizeof(deniedTarget), 0), 0);
  checkExecEnrollment(executable, {"denied"}, EACCES);
}

TEST_EXCLUSIVE(EnrollGate, BaseRoleForbidsExecXattrEnrollment) {
  const std::string executable = bpfjailer::test::scratchFsPath() +
      "/base-enroll-" + std::to_string(::getpid());
  ASSERT(std::filesystem::copy_file("/bin/sleep", executable));
  const bpfj_role_id target = {.id = "worker"};
  ASSERT_EQ(::setxattr(executable.c_str(), BPFJ_EXEC_POLICY_XATTR,
                      &target, sizeof(target), 0), 0);
  loadJailer(policyOf(R"toml(
base-role = "floor"
[roles.floor]
enroll-roles = []
[roles.worker]
)toml"));
  bpfjailer::test::Child actor([&] {
    ::execl(executable.c_str(), executable.c_str(), "0", nullptr);
    return errno;
  });
  ASSERT_EQ(actor.run(), EACCES);
}
