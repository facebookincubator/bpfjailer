// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "tests/Harness.h"

#include <string>

#include "srv/Protocol.h"
#include "srv/Server.h"

using bpfjailer::srv::decodeRequest;
using bpfjailer::srv::decodeResponse;
using bpfjailer::srv::encodeError;
using bpfjailer::srv::encodeRequest;
using bpfjailer::srv::EnrollRequest;

TEST(Protocol, RequestIsToml) {
  const EnrollRequest request{
      .role = "worker",
      .podId = "alice@example",
      .vars = {{"vm_uuid", "550e8400-e29b-41d4-a716-446655440000"}},
  };

  auto encoded = encodeRequest(request);
  ASSERT_OK(encoded);
  ASSERT_EQ(
      *encoded,
      std::string(
          "role = \"worker\"\n"
          "pod-id = \"alice@example\"\n"
          "vars = [{ name = \"vm_uuid\", value = "
          "\"550e8400-e29b-41d4-a716-446655440000\" }]\n"));

  auto decoded = decodeRequest(*encoded);
  ASSERT_OK(decoded);
  ASSERT_EQ(decoded->role, request.role);
  ASSERT_EQ(decoded->podId, request.podId);
  ASSERT(decoded->vars == request.vars);
}

TEST(Protocol, RejectsLegacyColonSyntax) {
  auto decoded = decodeRequest("role: worker\npod-id: alice\n");
  ASSERT(!decoded);
}

TEST(Protocol, RejectsLegacyUserIdField) {
  auto decoded = decodeRequest("role = \"worker\"\nuser-id = \"alice\"\n");
  ASSERT(!decoded);
}

TEST(Protocol, ErrorReplyEscapesTomlStrings) {
  auto decoded = decodeResponse(encodeError("bad \\\"request\\\""));
  ASSERT_OK(decoded);
  ASSERT(!decoded->ok);
  ASSERT_EQ(decoded->error, std::string("bad \\\"request\\\""));
}
