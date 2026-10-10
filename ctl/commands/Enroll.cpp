// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/commands/Enroll.h"

#include <argp.h>
#include <iostream>
#include <string_view>
#include <vector>

#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/Pods.h"
#include "ctl/Options.h"

namespace bpfjailer::ctl {

namespace {

struct EnrollArgs {
  PinConfig pin;
  const char* role = nullptr;
  const char* podId = nullptr;
  const char* pid = nullptr;
  std::vector<PodVar> vars;
};

constexpr char kDoc[] = "Enroll a running process in a new pod";
constexpr char kArgsDoc[] = "ROLE POD_ID PID [NAME=VALUE...]";

// Variables arrive as trailing positionals rather than as a repeated flag so
// the shared pin options stay the whole option table for this command.
error_t parseVar(const char* arg, struct argp_state* state, EnrollArgs& args) {
  const std::string_view text(arg);
  const auto split = text.find('=');
  if (split == std::string_view::npos || split == 0) {
    argp_error(state, "variable %s is not NAME=VALUE", arg);
    return EINVAL;
  }

  args.vars.push_back(
      PodVar{
          .name = std::string(text.substr(0, split)),
          .value = std::string(text.substr(split + 1)),
      });
  return 0;
}

error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto* args = static_cast<EnrollArgs*>(state->input);
  switch (key) {
    case ARGP_KEY_ARG:
      switch (state->arg_num) {
        case 0:
          args->role = arg;
          break;
        case 1:
          args->podId = arg;
          break;
        case 2:
          args->pid = arg;
          break;
        default:
          return parseVar(arg, state, *args);
      }
      return 0;
    case ARGP_KEY_END:
      if (state->arg_num < 3) {
        argp_usage(state);
      }
      return 0;
    default:
      return parsePinOpt(key, arg, args->pin);
  }
}

const struct argp kArgp = {kPinOptions, parseOpt, kArgsDoc, kDoc};

} // namespace

int enrollRun(int argc, char** argv) {
  EnrollArgs args;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &args);

  auto pid = parsePid(args.pid);
  if (!pid) {
    std::cerr << "enroll failed: " << pid.error() << std::endl;
    return 1;
  }

  auto uuid =
      enrollPod(args.pin, args.role, args.podId, args.vars, *pid, Threads::All);
  if (!uuid) {
    std::cerr << "enroll failed: " << uuid.error() << std::endl;
    return 1;
  }

  std::cout << "Enrolled pid " << *pid << " in role " << args.role << ", pod "
            << uuidToString(*uuid) << std::endl;
  return 0;
}

} // namespace bpfjailer::ctl
