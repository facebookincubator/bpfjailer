// Copyright (c) Meta Platforms, Inc. and affiliates.

#include "ctl/PodPrinter.h"

#include <algorithm>
#include <cstring>
#include <string_view>

#include "bpfj/var/bpf/types_var.h"

namespace bpfjailer::ctl {

namespace {

const char* enrollmentSourceName(unsigned char source) {
  switch (source) {
    case BPFJ_ENROLL_CLIENT:
      return "client";
    case BPFJ_ENROLL_EXE:
      return "exe";
    case BPFJ_ENROLL_EXE_SCAN:
      return "exe-scan";
    case BPFJ_ENROLL_CGROUP:
      return "cgroup";
    case BPFJ_ENROLL_CGROUP_SCAN:
      return "cgroup-scan";
    case BPFJ_ENROLL_XATTR:
      return "xattr";
    case BPFJ_ENROLL_DBUS:
      return "dbus";
    case BPFJ_ENROLL_FFC_TCP:
      return "ffc-tcp";
    case BPFJ_ENROLL_FFC_UDS:
      return "ffc-uds";
    case BPFJ_ENROLL_BASE_ROLE:
      return "base-role";
    case BPFJ_ENROLL_FFC_PTY:
      return "ffc-pty";
    default:
      return "unknown";
  }
}

// Nothing guarantees a pod's identity strings are terminated: the xattr
// enrollment path fills role_id straight from the xattr, which can fill the
// buffer exactly.
std::string_view boundedId(const char* id, std::size_t size) {
  return {id, ::strnlen(id, size)};
}

void printVars(
    std::ostream& os,
    const bpfj_var_array& vars,
    const void* arenaBase) {
  const auto count = std::min<std::size_t>(vars.count, BPFJ_OSS_VAR_MAX);
  for (std::size_t i = 0; i < count; ++i) {
    const auto* var = bpfj_var_array_at(&vars, static_cast<__u32>(i));
    os << (i == 0 ? "    vars:    " : "             ");
    if (var == nullptr) {
      os << "<unavailable>\n";
      continue;
    }
    if (const char* name = bpfj_var_name_ptr(var); name != nullptr) {
      os << name;
    } else {
      os << "#" << var->id;
    }
    os << "=";

    char value[BPFJ_OSS_VAR_VAL_LEN] = {};
    if (arenaBase == nullptr ||
        bpfj_var_serialize(var, value, sizeof(value)) != 0) {
      os << "<unavailable>\n";
      continue;
    }
    os << boundedId(value, sizeof(value)) << "\n";
  }
}

} // namespace

void printPod(
    std::ostream& os,
    const bpfj_pod& pod,
    std::int64_t nowNs,
    const void* arenaBase) {
  os << "  pod " << uuidToString(pod.uuid) << "\n"
     << "    role:    " << boundedId(pod.role_id.id, ROLE_ID_LEN) << "\n"
     << "    pod id: " << boundedId(pod.pod_id.id, POD_ID_LEN) << "\n"
     << "    source:  " << enrollmentSourceName(pod.enrollment_source) << "\n"
     << "    refs:    " << pod.refs << "\n"
     << "    age:     " << (nowNs - pod.creation_time_ns) / 1'000'000'000
     << "s\n";
  printVars(os, pod.var_array, arenaBase);
}

} // namespace bpfjailer::ctl
