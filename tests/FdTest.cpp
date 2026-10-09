// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "bpfj/lib/Fd.h"
#include "tests/Harness.h"

using namespace bpfjailer;

TEST(FdTest, TestEqualityOperator) {
  Fd a(-1);
  Fd b(-1);
  ASSERT(a == b);

  auto pipes = Fd::pipe();
  ASSERT(pipes);

  auto& readEnd = (*pipes)[0];
  auto& writeEnd = (*pipes)[1];
  ASSERT(!(readEnd == writeEnd));

  auto duped = readEnd.dup();
  ASSERT(duped);
  // Different fd numbers even though they reference the same underlying file.
  ASSERT(!(readEnd == *duped));
}
