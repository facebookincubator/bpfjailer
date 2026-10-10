// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <argp.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

#include "srv/Client.h"

const char* argp_program_version = "bpfjclient 0.1";

namespace {

enum ClientOptionKey {
  kSocketKey = 's',
  kVarKey = 'V',
};

struct ClientArgs {
  bpfjailer::srv::EnrollRequest req;
  std::string socketPath{bpfjailer::srv::kDefaultSocketPath};
  char** command = nullptr;
};

constexpr char kDoc[] =
    "Enroll this process in a new pod through bpfjsrv and exec COMMAND"
    "\vThe unprivileged counterpart to `bpfjctl wrap`: same shape, except the "
    "enrollment is done by bpfjsrv over its socket rather than by writing the "
    "jailer's maps here, so this needs no privileges at all.\n"
    "\n"
    "bpfjsrv reads the pid off the connection, so the process enrolled is "
    "always this one, and the command inherits the pod because jail "
    "membership survives exec.\n"
    "\n"
    "ROLE has to carry `unpriv-enroll: true` in the running jailer's policy "
    "unless this is run as root; anything else is refused.";
constexpr char kArgsDoc[] = "ROLE POD_ID -- COMMAND [ARGS...]";

const struct argp_option kOptions[] = {
    {"socket",
     kSocketKey,
     "ADDR",
     0,
     "bpfjsrv address, @name for the abstract namespace (default @bpfj)",
     0},
    {"var",
     kVarKey,
     "NAME=VALUE",
     0,
     "Set a pod variable, repeatable (at most 16)",
     0},
    {},
};

error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto* args = static_cast<ClientArgs*>(state->input);
  switch (key) {
    case kSocketKey:
      args->socketPath = arg;
      return 0;
    case kVarKey: {
      const std::string_view text(arg);
      const auto split = text.find('=');
      if (split == std::string_view::npos || split == 0) {
        argp_error(state, "variable %s is not NAME=VALUE", arg);
        return EINVAL;
      }
      args->req.vars.emplace_back(
          text.substr(0, split), text.substr(split + 1));
      return 0;
    }
    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        args->req.role = arg;
      } else if (state->arg_num == 1) {
        args->req.podId = arg;
      } else {
        // Consuming the rest of the line stops argp reading the command's own
        // flags as bpfjclient's.
        args->command = state->argv + state->next - 1;
        state->next = state->argc;
      }
      return 0;
    case ARGP_KEY_END:
      if (args->command == nullptr) {
        argp_usage(state);
      }
      return 0;
    default:
      return ARGP_ERR_UNKNOWN;
  }
}

const struct argp kArgp = {kOptions, parseOpt, kArgsDoc, kDoc};

} // namespace

int main(int argc, char** argv) {
  ClientArgs args;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &args);

  auto uuid = bpfjailer::srv::enroll(args.req, args.socketPath);
  if (!uuid) {
    std::cerr << "bpfjclient: " << uuid.error() << std::endl;
    return 1;
  }

  ::execvp(args.command[0], args.command);

  // Only reached when the exec failed, by which point the pod exists and is
  // left for `bpfjctl list` to show.
  std::cerr << "bpfjclient: cannot exec " << args.command[0] << ": "
            << std::strerror(errno) << std::endl;
  return 127;
}
