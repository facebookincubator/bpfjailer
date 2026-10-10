// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include <algorithm>
#include <cstddef>
#include <limits>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "bpfj/err/Error.h"
#include "srv/Protocol.pb.h"

// The bpfjsrv wire format, shared by Client.h and the server. A request and
// its reply are protobuf messages, each carried whole in one SOCK_SEQPACKET
// datagram. Protocol.proto is the source of truth for the wire schema.
//
// No pid appears in the schema: the server takes it from the connection's
// SO_PEERCRED, so a client can only ever enroll itself.

namespace bpfjailer::srv {

inline constexpr std::string_view kDefaultSocketPath = "@bpfj";

// A request is a role, a pod id and at most sixteen short variables, so
// anything approaching this is not a request this protocol can express.
inline constexpr std::size_t kMaxMessageBytes = 4096;
inline constexpr std::size_t kMaxVars = 16;

struct EnrollRequest {
  std::string role;
  std::string podId;
  std::vector<std::pair<std::string, std::string>> vars;
};

enum class ResponseErrorCode {
  Unknown,
  InvalidRequest,
  PermissionDenied,
  Internal,
};

struct EnrollResponse {
  bool ok = false;
  std::string uuid;
  ResponseErrorCode errorCode = ResponseErrorCode::Unknown;
  std::string error;
};

[[nodiscard]] inline bool isProtocolScalar(std::string_view value) noexcept {
  if (value.empty()) {
    return false;
  }

  for (const char c : value) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
        c == '@' || c == '/' || c == '+' || c == '=';
    if (!ok) {
      return false;
    }
  }

  return true;
}

[[nodiscard]] inline Expected<> validateRequest(
    const EnrollRequest& req) noexcept {
  if (!isProtocolScalar(req.role)) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "role must be a non-empty protocol scalar, got '",
        req.role,
        "'"));
  }

  if (!isProtocolScalar(req.podId)) {
    return makeUnexpected(makeError(
        std::errc::invalid_argument,
        "pod-id must be a non-empty protocol scalar, got '",
        req.podId,
        "'"));
  }

  if (req.vars.size() > kMaxVars) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "at most ",
        std::to_string(kMaxVars),
        " variables, got ",
        std::to_string(req.vars.size())));
  }

  for (std::size_t i = 0; i < req.vars.size(); ++i) {
    const auto& [name, value] = req.vars[i];
    if (!isProtocolScalar(name)) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "variable name must be a non-empty protocol scalar, got '",
          name,
          "'"));
    }

    if (!isProtocolScalar(value)) {
      return makeUnexpected(makeError(
          std::errc::invalid_argument,
          "value of variable ",
          name,
          " must be a non-empty protocol scalar, got '",
          value,
          "'"));
    }

    for (std::size_t j = 0; j < i; ++j) {
      if (req.vars[j].first == name) {
        return makeUnexpected(makeError(
            std::errc::invalid_argument, "variable ", name, " is set twice"));
      }
    }
  }

  return unit;
}

[[nodiscard]] inline Expected<std::string> serializeMessage(
    const google::protobuf::MessageLite& message) noexcept {
  std::string out;
  if (!message.SerializeToString(&out)) {
    return makeUnexpected(makeError(
        std::errc::protocol_error, "could not serialize the protobuf message"));
  }

  if (out.size() > kMaxMessageBytes) {
    return makeUnexpected(makeError(
        std::errc::value_too_large,
        "message is ",
        std::to_string(out.size()),
        " bytes, over the ",
        std::to_string(kMaxMessageBytes),
        " this protocol carries"));
  }

  return out;
}

template <typename Message>
[[nodiscard]] inline Expected<Message> parseMessage(
    std::string_view text) noexcept {
  if (text.empty()) {
    return makeUnexpected(
        makeError(std::errc::protocol_error, "protobuf message is empty"));
  }
  if (text.size() > kMaxMessageBytes ||
      text.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
    return makeUnexpected(makeError(
        std::errc::message_size, "protobuf message exceeds the size limit"));
  }

  Message message;
  if (!message.ParseFromArray(text.data(), static_cast<int>(text.size()))) {
    return makeUnexpected(
        makeError(std::errc::protocol_error, "malformed protobuf message"));
  }
  return message;
}

[[nodiscard]] inline Expected<std::string> encodeRequest(
    const EnrollRequest& req) noexcept {
  if (auto res = validateRequest(req); !res) {
    return makeUnexpected(res.error());
  }

  wire::EnrollRequest message;
  message.set_role(req.role);
  message.set_pod_id(req.podId);
  for (const auto& [name, value] : req.vars) {
    auto* variable = message.add_variables();
    variable->set_name(name);
    variable->set_value(value);
  }
  return serializeMessage(message);
}

[[nodiscard]] inline std::string sanitizeMessage(
    std::string_view message) noexcept {
  constexpr std::size_t kMaxErrorBytes = 512;

  std::string out;
  out.reserve(std::min(message.size(), kMaxErrorBytes));
  for (const char c : message.substr(0, kMaxErrorBytes)) {
    out.push_back(c >= 0x20 && c <= 0x7e ? c : ' ');
  }

  return out.empty() ? std::string("unspecified failure") : out;
}

[[nodiscard]] inline Expected<std::string> encodeOk(
    std::string_view uuid) noexcept {
  wire::EnrollResponse response;
  response.mutable_success()->set_uuid(uuid.data(), uuid.size());
  return serializeMessage(response);
}

[[nodiscard]] inline wire::ErrorCode toWireErrorCode(
    ResponseErrorCode code) noexcept {
  switch (code) {
    case ResponseErrorCode::InvalidRequest:
      return wire::ERROR_CODE_INVALID_REQUEST;
    case ResponseErrorCode::PermissionDenied:
      return wire::ERROR_CODE_PERMISSION_DENIED;
    case ResponseErrorCode::Internal:
      return wire::ERROR_CODE_INTERNAL;
    case ResponseErrorCode::Unknown:
      return wire::ERROR_CODE_UNKNOWN;
  }
  return wire::ERROR_CODE_UNKNOWN;
}

[[nodiscard]] inline ResponseErrorCode fromWireErrorCode(
    wire::ErrorCode code) noexcept {
  switch (code) {
    case wire::ERROR_CODE_INVALID_REQUEST:
      return ResponseErrorCode::InvalidRequest;
    case wire::ERROR_CODE_PERMISSION_DENIED:
      return ResponseErrorCode::PermissionDenied;
    case wire::ERROR_CODE_INTERNAL:
      return ResponseErrorCode::Internal;
    case wire::ERROR_CODE_UNKNOWN:
      return ResponseErrorCode::Unknown;
    default:
      return ResponseErrorCode::Unknown;
  }
}

[[nodiscard]] inline Expected<std::string> encodeError(
    ResponseErrorCode code,
    std::string_view message) noexcept {
  wire::EnrollResponse response;
  auto* error = response.mutable_error();
  error->set_code(toWireErrorCode(code));
  error->set_message(sanitizeMessage(message));
  return serializeMessage(response);
}

[[nodiscard]] inline Expected<EnrollResponse> decodeResponse(
    std::string_view text) noexcept {
  auto message = parseMessage<wire::EnrollResponse>(text);
  if (!message) {
    return makeUnexpected(message.error());
  }

  switch (message->result_case()) {
    case wire::EnrollResponse::kSuccess:
      if (message->success().uuid().empty()) {
        return makeUnexpected(makeError(
            std::errc::protocol_error, "reply reported success with no uuid"));
      }
      return EnrollResponse{.ok = true, .uuid = message->success().uuid()};
    case wire::EnrollResponse::kError:
      if (message->error().message().empty()) {
        return makeUnexpected(makeError(
            std::errc::protocol_error,
            "reply reported failure with no error message"));
      }
      return EnrollResponse{
          .ok = false,
          .errorCode = fromWireErrorCode(message->error().code()),
          .error = message->error().message(),
      };
    case wire::EnrollResponse::RESULT_NOT_SET:
      return makeUnexpected(
          makeError(std::errc::protocol_error, "reply has no result"));
  }
  return makeUnexpected(
      makeError(std::errc::protocol_error, "reply has an unknown result"));
}

[[nodiscard]] inline std::errc toErrc(ResponseErrorCode code) noexcept {
  switch (code) {
    case ResponseErrorCode::InvalidRequest:
      return std::errc::invalid_argument;
    case ResponseErrorCode::PermissionDenied:
      return std::errc::permission_denied;
    case ResponseErrorCode::Internal:
    case ResponseErrorCode::Unknown:
      return std::errc::io_error;
  }
  return std::errc::io_error;
}

} // namespace bpfjailer::srv
