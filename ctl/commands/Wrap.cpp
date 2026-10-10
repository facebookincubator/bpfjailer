// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/commands/Wrap.h"

#include <argp.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>

#include "bpfj/enforce/Pods.h"
#include "bpfj/lib/Privileges.h"
#include "ctl/Options.h"

namespace bpfjailer::ctl {

namespace {

enum WrapOptionKey {
  kUidKey = 'u',
  kGidKey = 'g',
  // Above the character range, so it is a long option with no short form.
  kDropCapKey = 1000,
};

struct WrapArgs {
  PinConfig pin;
  PrivilegeDrop drop;
  const char* role = nullptr;
  const char* podId = nullptr;
  char** command = nullptr;
};

constexpr char kDoc[] =
    "Enroll this process in a new pod and exec COMMAND"
    "\vThe command inherits the pod, because jail membership survives exec.\n"
    "\n"
    "Without --drop-cap the command keeps every capability it was started "
    "with, and CAP_BPF alone is enough to delete its own entry from the "
    "jailer's maps and walk out -- as are CAP_SYS_ADMIN, CAP_SYS_PTRACE and "
    "CAP_SYS_MODULE.\n"
    "\n"
    "--drop-cap is not sufficient on its own. The pin tree is a root-owned "
    "0700 directory, so reaching it is a file permission check rather than a "
    "capability one, and a command left running as root can still unpin the "
    "jailer with no capabilities at all. Pair --drop-cap with a non-root "
    "--uid.\n"
    "\n"
    "--uid and --gid are independent of each other, so --uid on its own "
    "leaves the command in group 0. Changing uid away from root clears the "
    "capability sets but not the bounding set, so an exec can still regain "
    "them; only --drop-cap closes that.";
constexpr char kArgsDoc[] = "ROLE POD_ID -- COMMAND [ARGS...]";

const struct argp_option kOptions[] = {
    {"drop-cap",
     kDropCapKey,
     nullptr,
     0,
     "Give up every capability before the exec, and no_new_privs so it sticks",
     0},
    {"uid", kUidKey, "UID", 0, "Numeric uid to run COMMAND as", 0},
    {"gid", kGidKey, "GID", 0, "Numeric gid to run COMMAND as", 0},
    {"bpffs-path",
     kBpffsPathKey,
     "PATH",
     0,
     "bpffs mount to pin under (default /sys/fs/bpf)",
     0},
    {"pin-dir",
     kPinDirKey,
     "DIR",
     0,
     "Directory under the bpffs mount (default bpfj-pins)",
     0},
    {},
};

[[nodiscard]] Expected<unsigned long> parseId(
    const char* arg,
    std::string_view what) noexcept {
  errno = 0;
  char* end = nullptr;
  const unsigned long value = std::strtoul(arg, &end, 10);
  if (errno != 0 || end == arg || *end != '\0' ||
      value > std::numeric_limits<unsigned int>::max()) {
    return makeUnexpected(
        makeError(std::errc::invalid_argument, "bad ", what, ": ", arg));
  }

  return value;
}

error_t parseOpt(int key, char* arg, struct argp_state* state) {
  auto* args = static_cast<WrapArgs*>(state->input);
  switch (key) {
    case kDropCapKey:
      args->drop.capabilities = true;
      return 0;
    case kUidKey: {
      auto uid = parseId(arg, "uid");
      if (!uid) {
        argp_error(state, "%s", uid.error().what());
      }
      args->drop.uid = static_cast<uid_t>(*uid);
      return 0;
    }
    case kGidKey: {
      auto gid = parseId(arg, "gid");
      if (!gid) {
        argp_error(state, "%s", gid.error().what());
      }
      args->drop.gid = static_cast<gid_t>(*gid);
      return 0;
    }
    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        args->role = arg;
      } else if (state->arg_num == 1) {
        args->podId = arg;
      } else {
        // Everything from here belongs to COMMAND; consuming the rest of the
        // line stops argp reading its flags as bpfjctl's.
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
      return parsePinOpt(key, arg, args->pin);
  }
}

const struct argp kArgp = {kOptions, parseOpt, kArgsDoc, kDoc};

} // namespace

int wrapRun(int argc, char** argv) {
  WrapArgs args;
  argp_parse(&kArgp, argc, argv, 0, nullptr, &args);

  // Enrollment first, since writing the jailer's maps needs the capabilities
  // the drop below gives away. LeaderOnly, since the exec destroys every other
  // thread and the leader's is the only entry that outlives this call.
  auto uuid = enrollPod(
      args.pin, args.role, args.podId, {}, ::getpid(), Threads::LeaderOnly);
  if (!uuid) {
    std::cerr << "wrap failed: " << uuid.error() << std::endl;
    return 1;
  }

  if (auto res = dropPrivileges(args.drop); !res) {
    std::cerr << "wrap failed: " << res.error() << std::endl;
    return 1;
  }

  ::execvp(args.command[0], args.command);

  // Only reached when the exec failed, by which point the pod exists and the
  // capabilities to delete it are gone, so it is left for `list` to show. 127
  // is what a shell reports for a command it could not run.
  std::cerr << "wrap failed: cannot exec " << args.command[0] << ": "
            << std::strerror(errno) << std::endl;
  return 127;
}

} // namespace bpfjailer::ctl
