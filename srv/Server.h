// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/types.h>

#include <string_view>

#include "bpfj/enforce/Pins.h"
#include "bpfj/err/Error.h"
#include "srv/Protocol.h"

namespace bpfjailer::srv {

/// @brief Decode and validate an enrollment request.
[[nodiscard]] Expected<EnrollRequest> decodeRequest(
    std::string_view text) noexcept;

/// @brief Whether `peerPid`, running as `peerUid`, may enroll itself in
/// `role`. Two checks, both required: root may take any role and anyone else
/// only one carrying `unpriv-enroll: true`, the abstract socket having no
/// permissions to lean on; then, for root as well, every role the caller holds
/// that wrote `enroll` has to list `role`. A map that cannot be read is a
/// refusal rather than a fallback.
[[nodiscard]] Expected<> authorizeEnroll(
    std::string_view role,
    pid_t peerPid,
    uid_t peerUid,
    const PinConfig& cfg) noexcept;

/// @brief Serve one connection: read a request, enroll `peerPid`, reply.
/// `peerPid` and `peerUid` both come from the connection's SO_PEERCRED rather
/// than the request, so a client can only enroll itself. A refused request is
/// reported both in the reply and in the return, so an error here does not
/// mean the client went unanswered.
[[nodiscard]] Expected<> serveConnection(
    int connFd,
    pid_t peerPid,
    uid_t peerUid,
    const PinConfig& cfg) noexcept;

} // namespace bpfjailer::srv
