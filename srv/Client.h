// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "bpfj/err/Error.h"
#include "srv/Protocol.h"

// The client side of bpfjsrv, for a service that wants to jail itself.
//
//   bpfjailer::srv::EnrollRequest req{
//       .role = "worker",
//       .podId = "alice",
//       .vars = {{"vm_uuid", "550e8400-e29b-41d4-a716-446655440000"}},
//   };
//
//   auto uuid = bpfjailer::srv::enroll(req);
//   if (!uuid) {
//     LOG(ERROR) << "could not enroll: " << uuid.error();
//   }
//
// The process that calls enroll() is the process that gets enrolled, bpfjsrv
// reading the pid off the connection with SO_PEERCRED, so there is no way to
// name another task here.
//
// The socket is abstract and reachable by anyone, but the roles are not: root
// may take any role, anyone else only one carrying `unpriv-enroll: true`, and
// either way every role the caller holds that writes `enroll` has to list the
// new one.
//
// Header-only on purpose, so enrolling costs a caller no build edit: nothing
// here reaches outside libc and the header-only bpfj/err.

namespace bpfjailer::srv {

namespace detail {

/// @brief Close-on-scope-exit for the one fd this header owns.
class ClientFd {
 public:
  explicit ClientFd(int fd) noexcept : fd_(fd) {}

  ~ClientFd() noexcept {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }

  ClientFd(const ClientFd&) = delete;
  ClientFd& operator=(const ClientFd&) = delete;
  ClientFd(ClientFd&&) = delete;
  ClientFd& operator=(ClientFd&&) = delete;

  [[nodiscard]] int get() const noexcept {
    return fd_;
  }

 private:
  int fd_ = -1;
};

/// @brief Fill `addr` from `path`, returning the length to pass to connect().
/// The length is the point: an abstract name runs to the length given, so
/// passing sizeof(sockaddr_un) would append 100-odd NUL bytes to the name and
/// fail as ECONNREFUSED, which reads like the service being down.
[[nodiscard]] inline Expected<socklen_t> fillUnixAddr(
    std::string_view path,
    struct sockaddr_un& addr) noexcept {
  addr = {};
  addr.sun_family = AF_UNIX;

  const bool abstract = path.front() == '@';
  const std::string_view name = abstract ? path.substr(1) : path;

  // Abstract names spend a byte on the leading NUL, pathnames on the trailing.
  if (name.empty() || name.size() + 1 > sizeof(addr.sun_path)) {
    return makeUnexpected(makeError(
        std::errc::filename_too_long,
        "socket address must be 1 to ",
        std::to_string(sizeof(addr.sun_path) - 1),
        " characters, got '",
        std::string(path),
        "'"));
  }

  std::memcpy(addr.sun_path + (abstract ? 1 : 0), name.data(), name.size());

  return static_cast<socklen_t>(
      offsetof(struct sockaddr_un, sun_path) + (abstract ? 1 : 0) +
      name.size() + (abstract ? 0 : 1));
}

} // namespace detail

/// @brief Enroll the calling process in a pod, returning the pod uuid.
/// Blocking, and over in one round trip, bpfjsrv being socket activated.
/// Every field has to be a bare scalar (see isBareScalar), and a variable name
/// has to be one the running jail's policy declares in `vars`, which attach
/// publishes as an arena-backed allowlist -- see publishVarNames() in
/// bpfj/enforce/PodVars.h.
[[nodiscard]] inline Expected<std::string> enroll(
    const EnrollRequest& req,
    std::string_view socketPath = kDefaultSocketPath) noexcept {
  auto message = encodeRequest(req);
  if (!message) {
    return makeUnexpected(message.error());
  }

  if (socketPath.empty()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "socket address is empty"));
  }

  struct sockaddr_un addr{};
  auto addrLen = detail::fillUnixAddr(socketPath, addr);
  if (!addrLen) {
    return makeUnexpected(addrLen.error());
  }

  // SOCK_SEQPACKET so the request and the reply each arrive whole, matching
  // the ListenSequentialPacket= in bpfjsrv.socket.
  const detail::ClientFd sock(::socket(AF_UNIX, SOCK_SEQPACKET, 0));
  if (sock.get() < 0) {
    return makeUnexpected(makeErrnoError("failed to create a unix socket"));
  }

  if (::connect(
          sock.get(),
          reinterpret_cast<const struct sockaddr*>(&addr),
          *addrLen) != 0) {
    return makeUnexpected(
        makeErrnoError("failed to connect to ", std::string(socketPath)));
  }

  if (::send(sock.get(), message->data(), message->size(), MSG_NOSIGNAL) !=
      static_cast<ssize_t>(message->size())) {
    return makeUnexpected(makeErrnoError("failed to send the enroll request"));
  }

  std::array<char, kMaxMessageBytes> buf{};
  const ssize_t got = ::recv(sock.get(), buf.data(), buf.size(), 0);
  if (got < 0) {
    return makeUnexpected(makeErrnoError("failed to read the enroll reply"));
  }

  if (got == 0) {
    // A bpfjsrv that could not even compose a reply looks like this.
    return makeUnexpected(makeError(
        std::errc::protocol_error, "bpfjsrv closed the connection unanswered"));
  }

  auto reply = decodeResponse(
      std::string_view(buf.data(), static_cast<std::size_t>(got)));
  if (!reply) {
    return makeUnexpected(reply.error());
  }

  if (!reply->ok) {
    return makeUnexpected(makeError(
        std::errc::operation_not_permitted, "enroll refused: ", reply->error));
  }

  return reply->uuid;
}

} // namespace bpfjailer::srv
