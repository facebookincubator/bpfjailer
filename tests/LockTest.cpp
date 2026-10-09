// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <chrono>
#include <memory>

#include "bpfj/lib/Heap.h"
#include "bpfj/lib/Lock.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/lock_test.skel.h"

using namespace bpfjailer;
using namespace std::chrono_literals;

namespace {

// Must match lock_test.bpf.c.
constexpr __u32 kCmdNone = 0;
constexpr __u32 kCmdObserve = 1;
constexpr __u32 kCmdLockBumpUnlock = 2;
constexpr __u32 kCmdInit = 3;

// Stands in for whatever the allocator left in a recycled block: bpfj_lock sits
// at the start of its payload, and free() writes next_free/prev_free there.
constexpr __u32 kResidue = 0x0004'0100;

constexpr auto kAcquireTimeout = 5s;

class LockFixture {
 public:
  using Skel = bpfj::libbpf::BpfSkel<lock_test_bpf>;

  LockFixture() {
    auto created = Skel::create();
    ASSERT_OK(created);
    skel_ = *created;
    ASSERT_OK(skel_->load());
    ASSERT_OK(heap::init(skel_));

    lock_ = heap::alloc<bpfj_lock>(skel_);
    ASSERT_NE(lock_, nullptr);
    // Heap blocks are not zeroed on reuse, so a lock is only usable once it has
    // been initialized — do it here rather than leaning on the fact that a
    // freshly grown arena happens to be zero.
    lock::init(*lock_);
    counter_ = heap::alloc<__u64>(skel_, __u64{0});
    ASSERT_NE(counter_, nullptr);

    skel_->bss().test_lock = lock_;
    skel_->bss().counter = counter_;
  }

  void runInBpf(__u32 cmd) {
    const __u32 runsBefore = skel_->bss().runs;

    skel_->bss().cmd = cmd;
    LIBBPF_OPTS(bpf_test_run_opts, opts);
    const int fd = bpf_program__fd(skel_->progs().test_lock_cmd);
    ASSERT(fd >= 0);
    ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
    ASSERT_EQ(static_cast<int>(opts.retval), 0);

    ASSERT_EQ(skel_->bss().cmd, kCmdNone);
    ASSERT_GT(skel_->bss().runs, runsBefore);
  }

  std::shared_ptr<Skel> skel_;
  bpfj_lock* lock_ = nullptr;
  __u64* counter_ = nullptr;
};

} // namespace

// Residue in the lock word wedges the lock: acquire needs an all-zero word, and
// release only clears the locked byte, so nothing else recovers it. init() is
// what makes a lock in reused arena memory usable, from either side.
TEST(Lock, InitRecoversALockFromResidueNeitherSideCanClear) {
  LockFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto*& lock_ = fixture.lock_;
  [[maybe_unused]] auto*& counter_ = fixture.counter_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  lock_->val.store(kResidue, std::memory_order_relaxed);

  ASSERT_FALSE(lock::tryLock(*lock_));
  lock::unlock(*lock_);
  ASSERT_FALSE(lock::tryLock(*lock_));

  lock::init(*lock_);
  ASSERT_FALSE(lock::isLocked(*lock_));
  ASSERT_TRUE(lock::tryLock(*lock_));
  lock::unlock(*lock_);
}

// The BPF-side init clears the same state, so either side can be the one that
// prepares a freshly allocated lock.
TEST(Lock, BpfInitRecoversALockUserspaceCanThenTake) {
  LockFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto*& lock_ = fixture.lock_;
  [[maybe_unused]] auto*& counter_ = fixture.counter_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  lock_->val.store(kResidue, std::memory_order_relaxed);
  ASSERT_FALSE(lock::tryLock(*lock_));

  runInBpf(kCmdInit);

  ASSERT_FALSE(lock::isLocked(*lock_));
  ASSERT_TRUE(lock::tryLock(*lock_));
  lock::unlock(*lock_);

  // And BPF can take what it just initialized.
  runInBpf(kCmdLockBumpUnlock);
  ASSERT_EQ(skel_->bss().locked, 1);
  ASSERT_EQ(*counter_, 1U);
}

// A lock coming out of a recycled heap block is only usable after init().
TEST(Lock, InitMakesARecycledHeapBlockUsable) {
  LockFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto*& lock_ = fixture.lock_;
  [[maybe_unused]] auto*& counter_ = fixture.counter_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  auto* first = heap::alloc<bpfj_lock>(skel_);
  ASSERT_NE(first, nullptr);
  ASSERT_EQ(heap::free(skel_, first), 0);

  auto* reused = static_cast<bpfj_lock*>(heap::alloc(skel_, sizeof(bpfj_lock)));
  ASSERT_EQ(reused, first);

  lock::init(*reused);
  ASSERT_FALSE(lock::isLocked(*reused));
  ASSERT_TRUE(lock::tryLock(*reused));
  lock::unlock(*reused);

  ASSERT_EQ(heap::free(skel_, reused), 0);
}

// A free lock is acquirable exactly once until it is released.
TEST(Lock, TryLockOnFreeLockExcludesFurtherAcquires) {
  LockFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto*& lock_ = fixture.lock_;
  [[maybe_unused]] auto*& counter_ = fixture.counter_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  ASSERT_FALSE(lock::isLocked(*lock_));

  ASSERT_TRUE(lock::tryLock(*lock_));
  ASSERT_TRUE(lock::isLocked(*lock_));
  ASSERT_FALSE(lock::tryLock(*lock_));

  lock::unlock(*lock_);
  ASSERT_FALSE(lock::isLocked(*lock_));
  ASSERT_TRUE(lock::tryLock(*lock_));
  lock::unlock(*lock_);
}

// The two sides address the same arena word: a lock taken in userspace is seen
// as held by BPF, and releasing it is seen too.
TEST(Lock, BpfSeesLockHeldByUserspace) {
  LockFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto*& lock_ = fixture.lock_;
  [[maybe_unused]] auto*& counter_ = fixture.counter_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  ASSERT_TRUE(lock::tryLock(*lock_));

  runInBpf(kCmdObserve);
  ASSERT_EQ(skel_->bss().locked_seen, 1);

  lock::unlock(*lock_);

  runInBpf(kCmdObserve);
  ASSERT_EQ(skel_->bss().locked_seen, 0);
}

// The lock actually excludes: while userspace holds it, BPF cannot take it and
// so cannot enter the critical section. Releasing it lets BPF straight in.
TEST(Lock, UserspaceHeldLockKeepsBpfOutOfTheCriticalSection) {
  LockFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto*& lock_ = fixture.lock_;
  [[maybe_unused]] auto*& counter_ = fixture.counter_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  ASSERT_TRUE(lock::tryLock(*lock_));

  runInBpf(kCmdLockBumpUnlock);
  ASSERT_EQ(skel_->bss().locked, 0);
  ASSERT_EQ(*counter_, 0U);

  // Still ours, and still released cleanly by us rather than by the failed BPF
  // acquire.
  ASSERT_TRUE(lock::isLocked(*lock_));
  lock::unlock(*lock_);

  runInBpf(kCmdLockBumpUnlock);
  ASSERT_EQ(skel_->bss().locked, 1);
  ASSERT_EQ(*counter_, 1U);
}

// Symmetrically, a lock BPF has finished with is handed back in a state
// userspace can acquire — a failed BPF acquire must not leave residue in the
// word either.
TEST(Lock, BpfLeavesLockAcquirableByUserspace) {
  LockFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto*& lock_ = fixture.lock_;
  [[maybe_unused]] auto*& counter_ = fixture.counter_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  runInBpf(kCmdLockBumpUnlock);
  ASSERT_EQ(skel_->bss().locked, 1);
  ASSERT_FALSE(lock::isLocked(*lock_));

  ASSERT_TRUE(lock::tryLock(*lock_));
  // Make BPF fail to acquire, then confirm the word is untouched by that.
  runInBpf(kCmdLockBumpUnlock);
  ASSERT_EQ(skel_->bss().locked, 0);
  lock::unlock(*lock_);

  ASSERT_TRUE(lock::tryLock(*lock_));
  lock::unlock(*lock_);
}

// Both sides mutate the same arena counter under the same lock, handing it back
// and forth. No update may be lost and the lock must survive the round trip.
TEST(Lock, AlternatingCriticalSectionsPreserveTheCounter) {
  LockFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto*& lock_ = fixture.lock_;
  [[maybe_unused]] auto*& counter_ = fixture.counter_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  constexpr __u64 kRounds = 50;

  for (__u64 i = 0; i < kRounds; ++i) {
    {
      lock::Guard guard{*lock_, kAcquireTimeout};
      ASSERT_TRUE(guard.owns());
      *counter_ += 1;
    }

    runInBpf(kCmdLockBumpUnlock);
    ASSERT_EQ(skel_->bss().locked, 1);
  }

  // 'runs' rather than kRounds: an incidental open by this process consumes an
  // armed command, which is still one BPF critical section.
  ASSERT_EQ(*counter_, kRounds + skel_->bss().runs);
  ASSERT_FALSE(lock::isLocked(*lock_));
}
