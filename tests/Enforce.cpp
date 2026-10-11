// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Enforce.h"
#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <iostream>
#include <thread>

#include "bpfj/enforce/Jailer.h"
#include "bpfj/enforce/MatcherState.h"
#include "bpfj/enforce/Pods.h"

namespace bpfjailer::test {

PinConfig testPins() {
  return PinConfig{.bpffsPath = bpffsPath()};
}

Policy policyOf(const std::string& toml) {
  auto parsed = Policy::parse(toml);
  ASSERT_OK(parsed);
  return *parsed;
}

void loadJailer(const Policy& policy) {
  ASSERT_OK(Jailer::load(testPins(), policy));
  ASSERT_OK(MatcherState::load(testPins()));
}

ScratchMapFds loadJailerWithScratchMaps(const Policy& policy) {
  auto scratchMaps = Jailer::load(testPins(), policy);
  if (!scratchMaps) {
    fail(
        __FILE__,
        __LINE__,
        "Jailer::load(testPins(), policy)",
        "      " + scratchMaps.error().message());
  }
  ASSERT_OK(MatcherState::load(testPins()));
  return std::move(*scratchMaps);
}

bool linkPinned(std::string_view name) {
  return exists(testPins().linkDir() / name);
}

bool mapPinned(std::string_view name) {
  return exists(testPins().mapPath(name));
}

bool pinnedMapIsEmpty(std::string_view name) {
  const int fd = ::bpf_obj_get(testPins().mapPath(name).c_str());
  ASSERT(fd >= 0);

  // The largest key any map here is declared with. get_next_key only writes
  // when there is a key, so an oversized buffer costs nothing and saves knowing
  // each map's key type.
  unsigned char key[256];
  const bool empty = ::bpf_map_get_next_key(fd, nullptr, key) != 0;
  ::close(fd);
  return empty;
}

bool waitForMutationJournal(const PodArena& arena) {
  using namespace std::chrono_literals;
  const auto deadline = std::chrono::steady_clock::now() + 60s;
  do {
    const auto* journal = static_cast<const struct bpfj_mutation_journal*>(
        __atomic_load_n(&arena.ctrl()->mutation_journal, __ATOMIC_ACQUIRE));
    if (journal != nullptr &&
        __atomic_load_n(&journal->state, __ATOMIC_ACQUIRE) ==
            BPFJ_MUTATION_JOURNAL_RECORDING) {
      return true;
    }
    std::this_thread::yield();
  } while (std::chrono::steady_clock::now() < deadline);
  return false;
}

void enroll(std::string_view role, pid_t pid) {
  enroll(role, pid, {});
}

void enroll(std::string_view role, pid_t pid, std::span<const PodVar> vars) {
  auto enrolled =
      enrollPod(testPins(), role, "tester@meta", vars, pid, Threads::All);
  ASSERT_OK(enrolled);
}

Child::Child(std::function<int()> body) : body_(std::move(body)) {
  int goPipe[2] = {-1, -1};
  int resultPipe[2] = {-1, -1};
  ASSERT_EQ(::pipe(goPipe), 0);
  ASSERT_EQ(::pipe(resultPipe), 0);

  // Flushed before the fork, so the child cannot reprint what the test
  // wrote.
  std::cout << std::flush;
  std::cerr << std::flush;

  pid_ = ::fork();
  ASSERT(pid_ >= 0);

  if (pid_ == 0) {
    ::close(goPipe[1]);
    ::close(resultPipe[0]);

    char go = 0;
    if (::read(goPipe[0], &go, 1) == 1) {
      const int result = body_();
      (void)::write(resultPipe[1], &result, sizeof(result));
    }

    // Held open past the answer: a BPF object the body created dies with the
    // process that made it, and the test usually has something else try to open
    // it next.
    char drain = 0;
    while (::read(goPipe[0], &drain, 1) > 0) {
    }

    ::_exit(0);
  }

  ::close(goPipe[0]);
  ::close(resultPipe[1]);
  goFd_ = goPipe[1];
  resultFd_ = resultPipe[0];
}

int Child::run() {
  const char go = 1;
  ASSERT_EQ(::write(goFd_, &go, 1), 1);

  int result = -1;
  ASSERT_EQ(
      ::read(resultFd_, &result, sizeof(result)),
      static_cast<ssize_t>(sizeof(result)));
  return result;
}

Child::~Child() {
  // Closing is what ends the child, which is blocked reading this pipe:
  // signalling it is the very thing the gate tests have taken away.
  ::close(goFd_);
  ::close(resultFd_);

  int status = 0;
  (void)::waitpid(pid_, &status, 0);
}

} // namespace bpfjailer::test
