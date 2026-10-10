// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <string>

#include "srv/Protocol.h"
#include "srv/Server.h"

using bpfjailer::srv::decodeRequest;
using bpfjailer::srv::decodeResponse;
using bpfjailer::srv::encodeError;
using bpfjailer::srv::encodeOk;
using bpfjailer::srv::encodeRequest;
using bpfjailer::srv::EnrollRequest;
using bpfjailer::srv::ResponseErrorCode;
using bpfjailer::srv::serializeMessage;

TEST(Protocol, RequestRoundTripsThroughSchema) {
  const EnrollRequest request{
      .role = "worker",
      .podId = "alice@example",
      .vars = {{"vm_uuid", "550e8400-e29b-41d4-a716-446655440000"}},
  };

  auto encoded = encodeRequest(request);
  ASSERT_OK(encoded);

  auto decoded = decodeRequest(*encoded);
  ASSERT_OK(decoded);
  ASSERT_EQ(decoded->role, request.role);
  ASSERT_EQ(decoded->podId, request.podId);
  ASSERT(decoded->vars == request.vars);
}

TEST(Protocol, RejectsMalformedProtobuf) {
  const std::string unterminatedVarint(1, static_cast<char>(0x80));
  ASSERT(!decodeRequest(unterminatedVarint));
  ASSERT(!decodeResponse(unterminatedVarint));
}

TEST(Protocol, ErrorReplyCarriesTypedCode) {
  auto encoded =
      encodeError(ResponseErrorCode::PermissionDenied, "role is not available");
  ASSERT_OK(encoded);

  auto decoded = decodeResponse(*encoded);
  ASSERT_OK(decoded);
  ASSERT(!decoded->ok);
  ASSERT(decoded->errorCode == ResponseErrorCode::PermissionDenied);
  ASSERT_EQ(decoded->error, std::string("role is not available"));
}

TEST(Protocol, SuccessReplyCarriesUuid) {
  auto encoded = encodeOk("0f9d4c22-6a1e-4f0b-9c3a-1b2c3d4e5f60");
  ASSERT_OK(encoded);

  auto decoded = decodeResponse(*encoded);
  ASSERT_OK(decoded);
  ASSERT(decoded->ok);
  ASSERT_EQ(decoded->uuid, std::string("0f9d4c22-6a1e-4f0b-9c3a-1b2c3d4e5f60"));
}

TEST(Protocol, RejectsResponseWithoutResult) {
  bpfjailer::srv::wire::EnrollResponse response;
  auto encoded = serializeMessage(response);
  ASSERT_OK(encoded);
  ASSERT(!decodeResponse(*encoded));
}

TEST(Protocol, RejectsSuccessWithoutUuid) {
  bpfjailer::srv::wire::EnrollResponse response;
  response.mutable_success();
  auto encoded = serializeMessage(response);
  ASSERT_OK(encoded);
  ASSERT(!decodeResponse(*encoded));
}
