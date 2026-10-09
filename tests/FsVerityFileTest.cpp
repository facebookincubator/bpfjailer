// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include "bpfj/fsverity/FsVerityFile.h"
#include "bpfj/lib/ScopeGuard.h"

using namespace bpfjailer;
using bpfjailer::test::scratchFsPath;

TEST(FsVerityFile, MeasuresSha256) {
  auto file = FsVerityFile::create(
      scratchFsPath() + "/measure-256", "foo", FsVerityFile::Sha256{});
  ASSERT_OK(file);
  const auto cleanup = makeGuard([&] { file->unlink(); });

  auto digest = file->measureBase64();
  ASSERT_OK(digest);

  ASSERT_EQ(*digest, "hMc4SzI5J0aROA1wQtw9jBP55gbvVGVE/p40ivsOivU=");
}

TEST(FsVerityFile, MeasuresSha512) {
  auto file = FsVerityFile::create(
      scratchFsPath() + "/measure-512", "foo", FsVerityFile::Sha512{});
  ASSERT_OK(file);
  const auto cleanup = makeGuard([&] { file->unlink(); });

  auto digest = file->measureBase64();
  ASSERT_OK(digest);

  ASSERT_EQ(
      *digest,
      "xjcpsHfTx6emaBFrEgAo3uU5tV6zG4yvB6lfQPP4/GBH6DlCTrznscpmjoeWjYQwj/Ow7uy3hWgnX/3BeL5E0g==");
}
