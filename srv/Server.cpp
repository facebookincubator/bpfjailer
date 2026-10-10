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
#include "toml/toml.hpp"

namespace bpfjailer::srv {

namespace {

static_assert(
    kMaxVars == BPFJ_OSS_VAR_MAX,
    "the protocol's variable ceiling has drifted from the pod's");

[[nodiscard]] Expected<std::string> scalarField(
    const toml::table& root,
    std::string_view name) noexcept {
  const auto value = root[name].value<std::string>();
  if (!value) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "missing '", name, "' field"));
  }

  return *value;
}

[[nodiscard]] Expected<std::vector<std::pair<std::string, std::string>>>
varsField(const toml::table& root) noexcept {
  std::vector<std::pair<std::string, std::string>> vars;

  const toml::node* node = root.get(kVarsField);
  if (node == nullptr) {
    return vars;
  }

  const toml::array* entries = node->as_array();
  if (entries == nullptr) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "'",
        kVarsField,
        "' must be a list of key/value pairs"));
  }

  for (const toml::node& entry : *entries) {
    const toml::table* fields = entry.as_table();
    if (fields == nullptr || fields->size() != 2) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "each entry of '",
          kVarsField,
          "' must contain only string 'name' and 'value' fields"));
    }

    const auto name = (*fields)["name"].value<std::string>();
    const auto value = (*fields)["value"].value<std::string>();
    if (!name || !value) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "each entry of '",
          kVarsField,
          "' must contain string 'name' and 'value' fields"));
    }

    vars.emplace_back(*name, *value);
  }

  return vars;
}

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
  try {
    const toml::table root = toml::parse(text);

    auto role = scalarField(root, kRoleField);
    if (!role) {
      return makeUnexpected(role.error());
    }

    auto podId = scalarField(root, kPodIdField);
    if (!podId) {
      return makeUnexpected(podId.error());
    }

    auto vars = varsField(root);
    if (!vars) {
      return makeUnexpected(vars.error());
    }

    EnrollRequest req{
        .role = std::move(*role),
        .podId = std::move(*podId),
        .vars = std::move(*vars),
    };

    // Validated on the way in as well as out: a request that did not come from
    // Client.h is exactly the one worth checking.
    if (auto res = validateRequest(req); !res) {
      return makeUnexpected(res.error());
    }

    return req;
  } catch (const toml::parse_error& e) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "malformed TOML: ", e.what()));
  } catch (const std::exception& e) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "could not parse the request: ",
        e.what()));
  }
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
    (void)writeReply(connFd, encodeError(text.error().message()));
    return makeUnexpected(text.error());
  }

  auto uuid = runRequest(*text, peerPid, peerUid, cfg);
  if (!uuid) {
    if (auto res = writeReply(connFd, encodeError(uuid.error().message()));
        !res) {
      return makeUnexpected(res.error());
    }

    return makeUnexpected(uuid.error());
  }

  return writeReply(connFd, encodeOk(uuidToString(*uuid)));
}

} // namespace bpfjailer::srv
