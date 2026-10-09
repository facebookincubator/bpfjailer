// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "bpfj/lib/Heap.h"
#include "bpfj/libbpf-cpp/BpfSkel.h"
#include "tests/bpf/mount_snapshot_test.skel.h"

TEST(MountSnapshot, DuplicateRootsKeepTheLowestMountId) {
  using Skel = bpfj::libbpf::BpfSkel<mount_snapshot_test_bpf>;
  auto created = Skel::create();
  ASSERT_OK(created);
  const auto skel = *created;
  ASSERT_OK(skel->load());
  ASSERT_OK(bpfjailer::heap::init(skel));

  LIBBPF_OPTS(bpf_test_run_opts, opts);
  const int fd = bpf_program__fd(skel->progs().bpfj_mount_snapshot_test);
  ASSERT(fd >= 0);
  ASSERT_EQ(bpf_prog_test_run_opts(fd, &opts), 0);
  ASSERT_EQ(static_cast<int>(opts.retval), 0);

  ASSERT_EQ(skel->bss().ret, 0);
  ASSERT_EQ(skel->bss().first_ret, 0);
  ASSERT_EQ(skel->bss().first_parent, 10ULL);
  ASSERT_EQ(skel->bss().first_mountpoint, 100ULL);
  ASSERT_EQ(skel->bss().second_ret, 0);
  ASSERT_EQ(skel->bss().second_parent, 40ULL);
  ASSERT_EQ(skel->bss().second_mountpoint, 400ULL);
  ASSERT_EQ(skel->bss().final_size, 2U);
  ASSERT_EQ(bpfjailer::heap::currentUsed(skel), 0U);
}
