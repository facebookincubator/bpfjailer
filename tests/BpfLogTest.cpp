// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "bpfj/enforce/FsEnforcer.h"
#include "bpfj/enforce/KillEnforcer.h"
#include "bpfj/enforce/Replace.h"
#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/logging.h"
#include "log/BpfLog.h"
#include "tests/Enforce.h"

namespace {

using bpfjailer::FsEnforcer;
using bpfjailer::KillEnforcer;
using bpfjailer::Policy;
using bpfjailer::replaceJailer;
using bpfjailer::test::bpffsPath;
using bpfjailer::test::Child;
using bpfjailer::test::enroll;
using bpfjailer::test::loadJailer;
using bpfjailer::test::policyOf;
using bpfjailer::test::testPins;

void copyString(char* dst, std::size_t size, const char* src) {
  std::strncpy(dst, src, size);
  dst[size - 1] = '\0';
}

[[nodiscard]] std::string drain(int fd) {
  if (::lseek(fd, 0, SEEK_SET) < 0) {
    return {};
  }

  std::string out;
  char buf[4096];
  for (;;) {
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n <= 0) {
      return out;
    }

    out.append(buf, static_cast<std::size_t>(n));
  }
}

struct BpfjlogProcess {
  pid_t pid = -1;
  int outFd = -1;
  int errFd = -1;

  BpfjlogProcess() = default;
  BpfjlogProcess(const BpfjlogProcess&) = delete;
  BpfjlogProcess& operator=(const BpfjlogProcess&) = delete;

  BpfjlogProcess(BpfjlogProcess&& other) noexcept {
    *this = std::move(other);
  }

  BpfjlogProcess& operator=(BpfjlogProcess&& other) noexcept {
    if (this != &other) {
      pid = other.pid;
      outFd = other.outFd;
      errFd = other.errFd;
      other.pid = -1;
      other.outFd = -1;
      other.errFd = -1;
    }
    return *this;
  }

  ~BpfjlogProcess() {
    if (outFd >= 0) {
      ::close(outFd);
    }
    if (errFd >= 0) {
      ::close(errFd);
    }
  }

  [[nodiscard]] std::string out() const {
    return drain(outFd);
  }

  [[nodiscard]] std::string err() const {
    return drain(errFd);
  }

  [[nodiscard]] int stop() {
    if (pid < 0) {
      return -1;
    }

    ASSERT_EQ(::kill(pid, SIGTERM), 0);
    int status = 0;
    ASSERT_EQ(::waitpid(pid, &status, 0), pid);
    pid = -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
  }
};

[[nodiscard]] BpfjlogProcess spawnBpfjlog(
    const std::vector<std::string>& args) {
  BpfjlogProcess proc;
  proc.outFd = ::memfd_create("bpfjlog-stdout", 0);
  proc.errFd = ::memfd_create("bpfjlog-stderr", 0);
  ASSERT(proc.outFd >= 0);
  ASSERT(proc.errFd >= 0);

  std::vector<std::string> owned;
  owned.reserve(args.size() + 1);
  owned.emplace_back("./build/bpfjlog");
  owned.insert(owned.end(), args.begin(), args.end());

  std::vector<char*> argv;
  argv.reserve(owned.size() + 1);
  for (auto& arg : owned) {
    argv.push_back(arg.data());
  }
  argv.push_back(nullptr);

  proc.pid = ::fork();
  ASSERT(proc.pid >= 0);

  if (proc.pid == 0) {
    ::dup2(proc.outFd, STDOUT_FILENO);
    ::dup2(proc.errFd, STDERR_FILENO);
    ::execvp(argv[0], argv.data());
    ::_exit(127);
  }

  return proc;
}

[[nodiscard]] bool outputContains(
    const BpfjlogProcess& proc,
    std::string_view needle,
    bool stdoutStream) {
  const std::string text = stdoutStream ? proc.out() : proc.err();
  return text.find(needle) != std::string::npos;
}

void waitForOutput(
    const BpfjlogProcess& proc,
    std::string_view needle,
    bool stdoutStream) {
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (std::chrono::steady_clock::now() < deadline) {
    if (outputContains(proc, needle, stdoutStream)) {
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  const std::string text = stdoutStream ? proc.out() : proc.err();
  bpfjailer::test::fail(
      __FILE__,
      __LINE__,
      stdoutStream ? "bpfjlog stdout contained needle"
                   : "bpfjlog stderr contained needle",
      "      missing: " + std::string(needle) + "\n      output was: " + text);
}

void attachKill(const std::string& toml) {
  const Policy policy = policyOf(toml);
  loadJailer(policy);
  ASSERT_OK(KillEnforcer::load(testPins(), policy));
}

void attachFs(const std::string& path) {
  const Policy policy =
      policyOf("[[roles.svc.paths]]\npath = \"" + path + "\"\nallow = false\n");
  loadJailer(policy);
  ASSERT_OK(FsEnforcer::load(testPins(), policy));
}

[[nodiscard]] int signalErrno(pid_t pid) {
  errno = 0;
  return ::kill(pid, 0) == 0 ? 0 : errno;
}

} // namespace

TEST(BpfLog, FormatsStructuredRecords) {
  struct bpfj_log entry{};
  copyString(entry.file, sizeof(entry.file), "heap.h");
  copyString(entry.msg, sizeof(entry.msg), "arena lock timed out");
  entry.line = 47;
  entry.severity = BPFJ_SEV_WARNING;
  entry.code = 16;
  entry.cpu = 3;

  const std::string expected =
      "BPF Message: heap.h:47: sev=warning code=16 cpu=3: arena lock timed out";
  ASSERT_EQ(bpfjailer::log::formatBpfLog(entry), expected);
}

TEST(BpfLog, RejectsShortRecords) {
  char truncated[8]{};
  auto formatted = bpfjailer::log::formatBpfLog(truncated, sizeof(truncated));

  ASSERT(!formatted);
  ASSERT(
      formatted.error().message().find("expected at least") !=
      std::string::npos);
}

TEST(BpfLog, FormatsStructuredEvents) {
  struct bpfj_event entry{};
  copyString(entry.pod.role_id.id, sizeof(entry.pod.role_id.id), "web");
  copyString(entry.pod.pod_id.id, sizeof(entry.pod.pod_id.id), "owner@meta");
  entry.pod.uuid.uuid[0] = 0x12;
  entry.pod.uuid.uuid[1] = 0x34;
  entry.pod.uuid.uuid[2] = 0x56;
  entry.pod.uuid.uuid[3] = 0x78;
  entry.pod.uuid.uuid[4] = 0x9a;
  entry.pod.uuid.uuid[5] = 0xbc;
  entry.pod.uuid.uuid[6] = 0xde;
  entry.pod.uuid.uuid[7] = 0xf0;
  entry.pod.uuid.uuid[8] = 0x11;
  entry.pod.uuid.uuid[9] = 0x22;
  entry.pod.uuid.uuid[10] = 0x33;
  entry.pod.uuid.uuid[11] = 0x44;
  entry.pod.uuid.uuid[12] = 0x55;
  entry.pod.uuid.uuid[13] = 0x66;
  entry.pod.uuid.uuid[14] = 0x77;
  entry.pod.uuid.uuid[15] = 0x88;
  entry.pod.refs = 2;
  entry.pod.creation_time_ns = 42;
  entry.pod.gc_removal_attempts = 3;
  entry.pod.enrollment_source = BPFJ_ENROLL_XATTR;
  entry.type = BPFJ_EVENT_PTRACE;
  entry.pid = 100;
  entry.tid = 101;
  entry.timestamp_ns = 102;

  const std::string expected =
      "event type=ptrace pid=100 tid=101 ts_ns=102 role=web pod_id=owner@meta "
      "uuid=12345678-9abc-def0-1122-334455667788 refs=2 creation_ns=42 "
      "gc_attempts=3 enrollment_source=6";
  ASSERT_EQ(bpfjailer::log::formatBpfEvent(entry), expected);
}

TEST(BpfLog, NamesFilesystemEvents) {
  ASSERT_EQ(bpfjailer::log::eventTypeName(BPFJ_EVENT_FS), "fs");
  ASSERT_EQ(bpfjailer::log::eventTypeName(BPFJ_EVENT_UNIX), "unix");
  ASSERT_EQ(bpfjailer::log::eventTypeName(BPFJ_EVENT_MOUNT), "mount");
  ASSERT_EQ(bpfjailer::log::eventTypeName(BPFJ_EVENT_PROC), "proc");
  ASSERT_EQ(bpfjailer::log::eventTypeName(BPFJ_EVENT_EXEC), "exec");
}

TEST(BpfLog, RejectsShortEventRecords) {
  char truncated[8]{};
  auto formatted = bpfjailer::log::formatBpfEvent(truncated, sizeof(truncated));

  ASSERT(!formatted);
  ASSERT(
      formatted.error().message().find("expected at least") !=
      std::string::npos);
}

TEST(BpfLog, BpfjlogFailsWhenNoMapsArePinned) {
  auto proc = spawnBpfjlog({"--bpffs-path", bpffsPath()});

  int status = 0;
  ASSERT_EQ(::waitpid(proc.pid, &status, 0), proc.pid);
  proc.pid = -1;

  ASSERT(WIFEXITED(status));
  ASSERT_EQ(WEXITSTATUS(status), 1);
  ASSERT(proc.err().find("bpfj_log_map") != std::string::npos);
}

TEST(BpfLog, BpfjlogPrintsDeniedKillToStdoutAndStderr) {
  attachKill(R"toml([roles]

[roles.svc]
kill-roles = []
)toml");
  Child target;
  enroll("svc", ::getpid());
  auto proc = spawnBpfjlog({"--bpffs-path", bpffsPath()});

  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(3);
  while (std::chrono::steady_clock::now() < deadline &&
         (!outputContains(proc, "event type=kill", true) ||
          !outputContains(proc, "Denied signal 0 to pid", false))) {
    ASSERT_EQ(signalErrno(target.pid()), EPERM);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  waitForOutput(proc, "event type=kill", true);
  waitForOutput(proc, "role=svc", true);
  waitForOutput(proc, "Denied signal 0 to pid", false);
  waitForOutput(proc, "kill_enforce.bpf.c", false);
  ASSERT_EQ(proc.stop(), 0);
}

TEST(BpfLog, BpfjlogReattachesAfterReplace) {
  const std::string toml = R"toml([roles]

[roles.svc]
kill-roles = []
)toml";
  attachKill(toml);
  Child before;
  Child after;
  Child beforeActor([pid = before.pid()] { return signalErrno(pid); });
  Child afterActor([pid = after.pid()] { return signalErrno(pid); });
  enroll("svc", beforeActor.pid());
  enroll("svc", afterActor.pid());
  auto proc = spawnBpfjlog({"--bpffs-path", bpffsPath()});

  const std::string beforeNeedle =
      "Denied signal 0 to pid " + std::to_string(before.pid());
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  ASSERT_EQ(beforeActor.run(), EPERM);
  waitForOutput(proc, beforeNeedle, false);

  ASSERT_OK(replaceJailer(testPins(), policyOf(toml)));

  const std::string afterNeedle =
      "Denied signal 0 to pid " + std::to_string(after.pid());
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  ASSERT_EQ(afterActor.run(), EPERM);
  waitForOutput(proc, afterNeedle, false);
  ASSERT_EQ(proc.stop(), 0);
}

TEST(BpfLog, BpfjlogPrintsDeniedFilesystemAccess) {
  char dir[] = "/tmp/bpfj-log-fs-test-XXXXXX";
  ASSERT(::mkdtemp(dir) != nullptr);
  const std::string path = std::string(dir) + "/data";
  int fd = ::open(path.c_str(), O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
  ASSERT(fd >= 0);
  ASSERT_EQ(::close(fd), 0);

  attachFs(path);
  auto proc = spawnBpfjlog({"--bpffs-path", bpffsPath()});
  Child actor([&] {
    errno = 0;
    const int opened = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (opened >= 0) {
      ::close(opened);
      return 0;
    }
    return errno;
  });
  enroll("svc", actor.pid());

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  ASSERT_EQ(actor.run(), EACCES);
  waitForOutput(proc, "event type=fs", true);
  waitForOutput(proc, "role=svc", true);
  ASSERT_EQ(proc.stop(), 0);

  ASSERT_EQ(::unlink(path.c_str()), 0);
  ASSERT_EQ(::rmdir(dir), 0);
}
