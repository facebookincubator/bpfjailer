// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/commands/Attach.h"

#include <argp.h>
#include <iostream>
#include <string_view>

#include "bpfj/enforce/BpfEnforcer.h"
#include "bpfj/enforce/ExecEnforcer.h"
#include "bpfj/enforce/FsEnforcer.h"
#include "bpfj/enforce/Jailer.h"
#include "bpfj/enforce/KillEnforcer.h"
#include "bpfj/enforce/LkmEnforcer.h"
#include "bpfj/enforce/MatcherState.h"
#include "bpfj/enforce/MountEnforcer.h"
#include "bpfj/enforce/MqEnforcer.h"
#include "bpfj/enforce/PodVars.h"
#include "bpfj/enforce/ProcEnforcer.h"
#include "bpfj/enforce/PtraceEnforcer.h"
#include "bpfj/enforce/ShmEnforcer.h"
#include "bpfj/enforce/UnixEnforcer.h"
#include "bpfj/enforce/UnprivRoles.h"
#include "bpfj/enforce/VerityEnforcer.h"
#include "bpfj/policy/Policy.h"
#include "ctl/Options.h"

namespace bpfjailer::ctl {

namespace {

struct AttachArgs {
  PinConfig pin;
  const char* policyPath = nullptr;
};

constexpr char kDoc[] = "Attach and pin the jailer BPF programs";
constexpr char kCompiledDoc[] =
    "Attach and pin the jailer BPF programs, against the compiled-in policy";
constexpr char kArgsDoc[] = "POLICY_PATH";

error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto* args = static_cast<AttachArgs*>(state->input);
  switch (key) {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        args->policyPath = arg;
      } else {
        argp_usage(state);
      }
      return 0;
    case ARGP_KEY_END:
      if (state->arg_num < 1) {
        argp_usage(state);
      }
      return 0;
    default:
      return parsePinOpt(key, arg, args->pin);
  }
}

const struct argp kArgp = {kPinOptions, parseOpt, kArgsDoc, kDoc};

/// @brief Bring up the jailer, its enforcers and its maps against `policy`.
/// @param source what to call the policy in the line this prints.
int attachPolicy(
    const PinConfig& pin,
    const Policy& policy,
    std::string_view source) {
  auto scratchMaps = Jailer::load(pin, policy);
  if (!scratchMaps) {
    std::cerr << "attach failed: " << scratchMaps.error() << std::endl;
    return 1;
  }

  // Before cache-using enforcers, so no rename can occur after a cache is
  // attached but before its invalidation hook is active.
  if (auto res = MatcherState::load(pin); !res) {
    std::cerr << "matcher state load failed: " << res.error() << std::endl;
    return 1;
  }

  // After the jailer, so the membership maps exist for the enforcer to adopt. A
  // failure here leaves the jailer attached, which `bpfjctl unload` clears by
  // removing the pin tree.
  if (auto res = VerityEnforcer::load(pin, policy, *scratchMaps); !res) {
    std::cerr << "fs-verity enforcer load failed: " << res.error() << std::endl;
    return 1;
  }

  if (auto res = ExecEnforcer::load(pin, policy); !res) {
    std::cerr << "exec enforcer load failed: " << res.error() << std::endl;
    return 1;
  }

  if (auto res = KillEnforcer::load(pin, policy); !res) {
    std::cerr << "kill enforcer load failed: " << res.error() << std::endl;
    return 1;
  }

  if (auto res = PtraceEnforcer::load(pin, policy); !res) {
    std::cerr << "ptrace enforcer load failed: " << res.error() << std::endl;
    return 1;
  }

  if (auto res = ProcEnforcer::load(pin, policy); !res) {
    std::cerr << "proc enforcer load failed: " << res.error() << std::endl;
    return 1;
  }

  if (auto res = LkmEnforcer::load(pin, policy); !res) {
    std::cerr << "LKM enforcer load failed: " << res.error() << std::endl;
    return 1;
  }

  if (auto res = MqEnforcer::load(pin, policy); !res) {
    std::cerr << "message-queue enforcer load failed: " << res.error()
              << std::endl;
    return 1;
  }

  if (auto res = ShmEnforcer::load(pin, policy); !res) {
    std::cerr << "shared-memory enforcer load failed: " << res.error()
              << std::endl;
    return 1;
  }

  if (auto res = FsEnforcer::load(pin, policy); !res) {
    std::cerr << "filesystem enforcer load failed: " << res.error()
              << std::endl;
    return 1;
  }

  if (auto res = UnixEnforcer::load(pin, policy); !res) {
    std::cerr << "Unix-socket enforcer load failed: " << res.error()
              << std::endl;
    return 1;
  }

  if (auto res = MountEnforcer::load(pin, policy); !res) {
    std::cerr << "mount enforcer load failed: " << res.error() << std::endl;
    return 1;
  }

  // Last: this can deny bpf(2), and everything above still needs
  // the syscall to pin its links.
  if (auto res = BpfEnforcer::load(pin, policy); !res) {
    std::cerr << "bpf enforcer load failed: " << res.error() << std::endl;
    return 1;
  }

  std::cout << "Jailer attached, pinned under " << pin.root() << ", "
            << policy.roles.size() << " role(s) from " << source;
  if (!policy.baseRole.empty()) {
    std::cout << ", base role " << policy.baseRole;
  }
  std::cout << std::endl;
  return 0;
}

} // namespace

int attachRun(int argc, char** argv) {
  AttachArgs args;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &args);

  // Before anything is attached, so a policy that does not read leaves a
  // command that did nothing rather than a half-loaded jailer.
  auto policy = Policy::parseFile(args.policyPath);
  if (!policy) {
    std::cerr << "policy failed: " << policy.error() << std::endl;
    return 1;
  }

  return attachPolicy(args.pin, *policy, args.policyPath);
}

int attachCompiledRun(int argc, char** argv, std::string_view builtin) {
  PinConfig pin;
  parsePinOnly(argc, argv, kCompiledDoc, pin);

  auto policy = compiledPolicy(builtin);
  if (!policy) {
    std::cerr << "policy failed: " << policy.error() << std::endl;
    return 1;
  }

  return attachPolicy(pin, *policy, kCompiledSource);
}

} // namespace bpfjailer::ctl
