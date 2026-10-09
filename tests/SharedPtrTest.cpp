// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <memory>

#include "bpfj/lib/Heap.h"
#include "bpfj/lib/SharedPtr.h"
#include "bpfj/lib/bpf/types_heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/shared_ptr_test.skel.h"

using namespace bpfjailer;

namespace {

// Must match shared_ptr_test.bpf.c.
constexpr __u32 kCmdNone = 0;
constexpr __u32 kCmdMake = 1;
constexpr __u32 kCmdAcquire = 2;
constexpr __u32 kCmdReleaseExtra = 3;
constexpr __u32 kCmdReleaseOwner = 4;
constexpr __u32 kCmdGuardMakeAndDrop = 5;

constexpr __u32 kMarker = 0xABCD1234;

class SharedPtrFixture {
 public:
  using Skel = bpfj::libbpf::BpfSkel<shared_ptr_test_bpf>;

  SharedPtrFixture() {
    auto created = Skel::create();
    ASSERT_OK(created);
    skel_ = *created;
    ASSERT_OK(skel_->load());
    ASSERT_OK(heap::init(skel_));
  }

  // Arm a command and trigger the hook. The program clears 'cmd' once it has
  // acted on it, so an incidental open by this process is a no-op.
  void runInBpf(__u32 cmd) {
    const __u32 runsBefore = skel_->bss().runs;

    skel_->bss().cmd = cmd;
    LIBBPF_OPTS(bpf_test_run_opts, opts);
    const int fd = bpf_program__fd(skel_->progs().test_shared_ptr_cmd);
    ASSERT(fd >= 0);
    ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
    ASSERT_EQ(static_cast<int>(opts.retval), 0);

    ASSERT_EQ(skel_->bss().cmd, kCmdNone);
    ASSERT_GT(skel_->bss().runs, runsBefore);
  }

  // Bytes currently in use in the shared arena, read straight from the control
  // structure both worlds map at the same address.
  __u64 heapUsed() {
    const auto* ctrl =
        reinterpret_cast<const bpfj_heap_control*>(heap::base(skel_));
    return ctrl->current_used;
  }

  std::shared_ptr<Skel> skel_;
};

} // namespace

// A freshly made pointer owns one reference to a live, heap-backed buffer.
TEST(SharedPtr, MakeStartsWithOneReferenceAndAllocatesABuffer) {
  SharedPtrFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  [[maybe_unused]] auto heapUsed = [&] { return fixture.heapUsed(); };
  const __u64 baseline = heapUsed();

  runInBpf(kCmdMake);

  ASSERT_EQ(skel_->bss().obs_valid, 1U);
  ASSERT_EQ(skel_->bss().obs_use_count, 1U);
  ASSERT_GT(skel_->bss().obs_heap_used, baseline);
}

// Acquiring an extra reference bumps the count; the buffer written at make time
// is still there behind it.
TEST(SharedPtr, AcquireBumpsTheCountAndKeepsTheBufferAlive) {
  SharedPtrFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  [[maybe_unused]] auto heapUsed = [&] { return fixture.heapUsed(); };
  runInBpf(kCmdMake);

  runInBpf(kCmdAcquire);

  ASSERT_EQ(skel_->bss().obs_use_count, 2U);
  ASSERT_EQ(skel_->bss().obs_buf_val, kMarker);
}

// Releasing one of two references drops the count but does not free: the second
// reference keeps the buffer alive and heap usage unchanged.
TEST(SharedPtr, ReleaseWithReferencesRemainingDoesNotFree) {
  SharedPtrFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  [[maybe_unused]] auto heapUsed = [&] { return fixture.heapUsed(); };
  runInBpf(kCmdMake);
  const __u64 usedWhileHeld = skel_->bss().obs_heap_used;

  runInBpf(kCmdAcquire);

  runInBpf(kCmdReleaseExtra);

  ASSERT_EQ(skel_->bss().obs_use_count, 1U);
  ASSERT_EQ(skel_->bss().obs_buf_val, kMarker);
  ASSERT_EQ(skel_->bss().obs_heap_used, usedWhileHeld);
}

// The release that drops the last reference frees the buffer and its count:
// heap usage returns to the pre-make baseline.
TEST(SharedPtr, LastReleaseFreesTheBuffer) {
  SharedPtrFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  [[maybe_unused]] auto heapUsed = [&] { return fixture.heapUsed(); };
  const __u64 baseline = heapUsed();

  runInBpf(kCmdMake);
  ASSERT_GT(skel_->bss().obs_heap_used, baseline);

  runInBpf(kCmdReleaseOwner);

  ASSERT_EQ(skel_->bss().obs_use_count, 0U);
  ASSERT_EQ(skel_->bss().obs_heap_used, baseline);
}

// A buffer survives an intermediate release and is freed only after the final
// one — the whole make/acquire/release/release lifecycle end to end.
TEST(SharedPtr, BufferOutlivesAnIntermediateReleaseThenIsFreed) {
  SharedPtrFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  [[maybe_unused]] auto heapUsed = [&] { return fixture.heapUsed(); };
  const __u64 baseline = heapUsed();

  runInBpf(kCmdMake);
  runInBpf(kCmdAcquire);
  runInBpf(kCmdReleaseExtra);
  ASSERT_EQ(skel_->bss().obs_use_count, 1U);
  ASSERT_GT(skel_->bss().obs_heap_used, baseline);

  runInBpf(kCmdReleaseOwner);
  ASSERT_EQ(skel_->bss().obs_use_count, 0U);
  ASSERT_EQ(skel_->bss().obs_heap_used, baseline);
}

// The RAII guard releases its reference when the scope ends: a pointer made and
// wrapped inside a scope is freed automatically at scope exit.
TEST(SharedPtr, GuardFreesTheBufferAtScopeExit) {
  SharedPtrFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  [[maybe_unused]] auto heapUsed = [&] { return fixture.heapUsed(); };
  const __u64 baseline = heapUsed();

  runInBpf(kCmdGuardMakeAndDrop);

  ASSERT_EQ(skel_->bss().obs_valid, 1U);
  ASSERT_EQ(skel_->bss().obs_use_count_in_scope, 1U);
  ASSERT_EQ(skel_->bss().obs_heap_used, baseline);
}

// The userspace release hands the buffer to its destructor exactly once, on the
// release that drops the last reference, and the destructor's free plus the
// count's bring the heap back to where it started.
TEST(SharedPtr, UserspaceReleaseRunsTheDestructorOnceAtZero) {
  SharedPtrFixture fixture;
  [[maybe_unused]] auto& skel_ = fixture.skel_;
  [[maybe_unused]] auto runInBpf = [&](const __u32 cmd) {
    fixture.runInBpf(cmd);
  };
  [[maybe_unused]] auto heapUsed = [&] { return fixture.heapUsed(); };
  const __u64 baseline = heapUsed();

  auto owner = shared_ptr::make(skel_, 16);
  ASSERT_TRUE(shared_ptr::valid(owner));
  auto extra = shared_ptr::acquire(owner);

  int destroyed = 0;
  const auto destroy = [&destroyed](auto& skel, void* buf) {
    ++destroyed;
    heap::free(skel, buf);
  };

  shared_ptr::release(skel_, &extra, destroy);
  ASSERT_EQ(destroyed, 0);

  shared_ptr::release(skel_, &owner, destroy);
  ASSERT_EQ(destroyed, 1);
  ASSERT_EQ(heapUsed(), baseline);
}
