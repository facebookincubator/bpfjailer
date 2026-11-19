// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// clang-format off
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "bpfj/lib/bpf/kfuncs.h"

// Stream kfuncs are unavailable on the supported 6.16 kernels.
#undef bpf_stream_printk
#include <libarena/common.h>
#include <libarena/buddy.h>
// clang-format on
