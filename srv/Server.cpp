// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "srv/Server.h"

#include <sys/socket.h>
#include <sys/uio.h>

#include <array>
#include <cstddef>
#include <string>
#include <utility>
#include <vector>

#include "bpfj/enforce/EnrollGate.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/Pods.h"
#include "bpfj/enforce/UnprivRoles.h"
#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer::srv {

namespace {

static_assert(
    kMaxVars == BPFJ_OSS_VAR_MAX,
    "the protocol's variable ceiling has drifted from the pod's");

/// @brief Read one datagram, refusing a truncated one rather than acting on it.
[[nodiscard]] Expected<std::string> readRequest(int connFd) noexcept {
  std::array<char, kMaxMessageBytes> buf{};
  struct iovec iov{.iov_base = buf.data(), .iov_len = buf.size()};
  struct msghdr msg{};
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;

  const ssize_t got = ::recvmsg(connFd, &msg, 0);
  if (got < 0) {
    return makeUnexpected(makeErrnoError("failed to read the request"));
  }

  if ((msg.msg_flags & MSG_TRUNC) != 0) {
    return makeUnexpected(makeError(
        std::errc::message_size,
        "request is over the ",
        std::to_string(kMaxMessageBytes),
        " bytes this protocol carries"));
  }

  if (got == 0) {
    return makeUnexpected(
        makeError(std::errc::protocol_error, "request is empty"));
  }

  return std::string(buf.data(), static_cast<std::size_t>(got));
}

[[nodiscard]] Expected<> writeReply(
    int connFd,
    const std::string& reply) noexcept {
  if (::send(connFd, reply.data(), reply.size(), MSG_NOSIGNAL) !=
      static_cast<ssize_t>(reply.size())) {
    return makeUnexpected(makeErrnoError("failed to send the reply"));
  }

  return unit;
}

[[nodiscard]] ResponseErrorCode responseCodeFor(const Error& error) noexcept {
  if (error.code() == std::make_error_code(std::errc::permission_denied) ||
      error.code() ==
          std::make_error_code(std::errc::operation_not_permitted)) {
    return ResponseErrorCode::PermissionDenied;
  }
  if (error.code() == std::make_error_code(std::errc::invalid_argument) ||
      error.code() == std::make_error_code(std::errc::protocol_error) ||
      error.code() == std::make_error_code(std::errc::message_size) ||
      error.code() == std::make_error_code(std::errc::value_too_large)) {
    return ResponseErrorCode::InvalidRequest;
  }
  return ResponseErrorCode::Internal;
}

[[nodiscard]] Expected<> writeErrorReply(
    int connFd,
    ResponseErrorCode code,
    const Error& error) noexcept {
  auto reply = encodeError(code, error.message());
  if (!reply) {
    return makeUnexpected(reply.error());
  }
  return writeReply(connFd, *reply);
}

/// @brief Enroll `peerPid` as `text` asks, without touching the connection.
[[nodiscard]] Expected<bpfj_uuid> runRequest(
    std::string_view text,
    pid_t peerPid,
    uid_t peerUid,
    const PinConfig& cfg) noexcept {
  auto req = decodeRequest(text);
  if (!req) {
    return makeUnexpected(req.error());
  }

  if (auto res = authorizeEnroll(req->role, peerPid, peerUid, cfg); !res) {
    return makeUnexpected(res.error());
  }

  std::vector<PodVar> vars;
  vars.reserve(req->vars.size());
  for (const auto& [name, value] : req->vars) {
    vars.push_back(PodVar{.name = name, .value = value});
  }

  // Threads::All, the peer being a running process that could have been
  // multithreaded long before it connected.
  return enrollPod(cfg, req->role, req->podId, vars, peerPid, Threads::All);
}

} // namespace

Expected<EnrollRequest> decodeRequest(std::string_view text) noexcept {
  auto message = parseMessage<wire::EnrollRequest>(text);
  if (!message) {
    return makeUnexpected(message.error());
  }

  EnrollRequest req{
      .role = message->role(),
      .podId = message->pod_id(),
  };
  req.vars.reserve(message->variables_size());
  for (const auto& variable : message->variables()) {
    req.vars.emplace_back(variable.name(), variable.value());
  }

  if (auto res = validateRequest(req); !res) {
    return makeUnexpected(res.error());
  }
  return req;
}

Expected<> authorizeEnroll(
    std::string_view role,
    pid_t peerPid,
    uid_t peerUid,
    const PinConfig& cfg) noexcept {
  if (peerUid != 0) {
    auto allowed = unprivEnrollAllowed(cfg, role);
    if (!allowed) {
      return makeUnexpected(allowed.error());
    }

    if (!*allowed) {
      // The same answer whether the role is closed to unprivileged callers
      // or does not exist at all, since which roles a host carries is not for
      // an untrusted caller to enumerate.
      return makeUnexpected(makeError(
          std::errc::permission_denied,
          "role ",
          role,
          " is not open to unprivileged callers"));
    }
  }

  // The caller can still pick up a role by exec between this and enrollPod(),
  // and closing that needs the check made inside the enroll iterator instead.
  auto permitted = enrollPermitted(cfg, peerPid, role);
  if (!permitted) {
    return makeUnexpected(permitted.error());
  }

  if (!*permitted) {
    return makeUnexpected(makeError(
        std::errc::permission_denied,
        "role ",
        role,
        " may not be obtained from the caller's current roles"));
  }

  return unit;
}

Expected<> serveConnection(
    int connFd,
    pid_t peerPid,
    uid_t peerUid,
    const PinConfig& cfg) noexcept {
  auto text = readRequest(connFd);
  if (!text) {
    // Nothing legible arrived, so the client is told only that, and the detail
    // goes to the journal through the return.
    (void)writeErrorReply(
        connFd, ResponseErrorCode::InvalidRequest, text.error());
    return makeUnexpected(text.error());
  }

  auto uuid = runRequest(*text, peerPid, peerUid, cfg);
  if (!uuid) {
    if (auto res = writeErrorReply(
            connFd, responseCodeFor(uuid.error()), uuid.error());
        !res) {
      return makeUnexpected(res.error());
    }

    return makeUnexpected(uuid.error());
  }

  auto reply = encodeOk(uuidToString(*uuid));
  if (!reply) {
    return makeUnexpected(reply.error());
  }
  return writeReply(connFd, *reply);
}

} // namespace bpfjailer::srv
