// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"

namespace bpfjailer {

/// @brief Owns the rename invalidation hook shared by all file matchers,
/// independent of which policy enforcers are enabled.
class MatcherState {
 public:
  [[nodiscard]] static Expected<> load(const PinConfig& cfg) noexcept;
};

} // namespace bpfjailer
