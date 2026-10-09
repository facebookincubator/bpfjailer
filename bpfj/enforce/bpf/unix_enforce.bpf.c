// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <errno.h>

#include "bpfj/enforce/bpf/ipc_glob.h"
#include "bpfj/enforce/bpf/maps.h"
#include "bpfj/enforce/bpf/types_unix.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/match/bpf/file_match_cached.h"
#include "bpfj/match/bpf/glob_var_bindings.h"

#define AF_UNIX 1
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOCK_SEQPACKET 5
#define S_IFMT 0170000
#define S_IFSOCK 0140000

struct bpfj_mount_cache __arena bpfj_unix_mount_cache;

static __noinline bool bpfj_unix_path_allowed(
    struct bpfj_file_match_cached_state __arena* state,
    enum bpfj_unix_operation operation,
    long count) {
  __s32 best_pos = -1;
  __u8 best_specificity = 0;
  __s8 best_allowed = -1;
  __u32 i;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }
    struct bpfj_unix_path_entry* entry =
        BPFJ_FILE_MATCH_CACHED_LOOKUP(state, i);
    if (!entry || entry->allowed[operation] < 0) {
      continue;
    }
    const __s32 pos = BPFJ_FILE_MATCH_CACHED_GET_POS(state, i);
    if (pos > best_pos ||
        (pos == best_pos && entry->specificity > best_specificity) ||
        (pos == best_pos && entry->specificity == best_specificity &&
         entry->allowed[operation] == 0)) {
      best_pos = pos;
      best_specificity = entry->specificity;
      best_allowed = entry->allowed[operation];
    }
  }
  return best_allowed > 0;
}

static __always_inline int bpfj_unix_deny(
    struct bpfj_pod __arena* pod,
    struct task_struct* task,
    const struct bpfj_role_id* role) {
  struct bpfj_event* event = bpfj_event_reserve(BPFJ_EVENT_UNIX, pod, task);
  bpfj_event_submit(event);
  BPFJ_LOG("Denied Unix socket access for role %s", role->id);
  return -EACCES;
}

// An unbound variable must make only patterns that reference it impossible.
// The generic glob matcher treats an absent binding as an empty string, while
// the IPC wrapper rejects the whole map; neither is right for a map that also
// carries a literal default rule. Oversize bindings are the matcher's
// established per-gadget poison value.
static __always_inline void bpfj_unix_poison_missing_bindings(
    struct bpfj_glob_run __arena* run) {
  __u32 wanted = run->map->num_vars;
  __u32 i;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_BINDINGS) {
    if (i >= wanted) {
      break;
    }
    const __u32 key = run->map->var_keys[i];
    if (bpfj_glob_find_binding(&run->bindings, key)) {
      continue;
    }
    const __u32 at = run->bindings.count;
    if (at >= BPFJ_GLOB_MAP_MAX_BINDINGS) {
      break;
    }
    run->bindings.b[at].key = key;
    run->bindings.b[at].len = BPFJ_GLOB_MAP_MAX_VAR_LEN + 1;
    run->bindings.count = at + 1;
  }
}

// Ordinary (unrolled) pod loops call this; the bpf_for here must not be
// textually nested with another iterator.
static __noinline bool bpfj_unix_abstract_allowed(
    const struct bpfj_glob_map __arena* map,
    const struct bpfj_pod __arena* pod,
    const char* name,
    __u32 name_len) {
  if (!map) {
    return true;
  }
  if (!pod || !name || name_len + 1 > BPFJ_GLOB_MAP_MAX_STR_LEN) {
    return false;
  }

  __attribute__((cleanup(bpfj_ipc_glob_release))) __u32 run_slot =
      BPFJ_IPC_GLOB_RUNS;
  struct bpfj_glob_run __arena* run = bpfj_ipc_glob_claim(&run_slot);
  if (!run) {
    return false;
  }
  bpfj_ipc_glob_bind_pod(run, map, pod);
  bpfj_unix_poison_missing_bindings(run);
  char __arena* input = bpfj_glob_run_owned_input(run, name_len + 1);
  if (input == NULL) {
    return false;
  }
  input[0] = '@';
  __u32 at;
  bpf_for(at, 0, BPFJ_GLOB_MAP_MAX_STR_LEN - 1) {
    if (at >= name_len) {
      break;
    }
    char byte = 0;
    if (bpf_probe_read_kernel(&byte, sizeof(byte), name + at) < 0) {
      return false;
    }
    input[at + 1] = byte;
  }
  if (bpfj_glob_eval(run) < 0) {
    return false;
  }

  __u64 best = 0;
  bool matched = false;
  __u32 i;
  bpf_for(i, 0, BPFJ_GLOB_MAP_MAX_ACCEPTS) {
    if (i >= map->num_accepts) {
      break;
    }
    if (!bpfj_glob_state_has_accept(run, i)) {
      continue;
    }
    const __u64 value = map->accept_val[i];
    if (!matched || (value >> 1) > (best >> 1) ||
        ((value >> 1) == (best >> 1) && (value & 1) == 0)) {
      matched = true;
      best = value;
    }
  }
  return !matched || (best & 1) != 0;
}

static __always_inline int bpfj_unix_enforce_path(
    uintptr_t dentry,
    enum bpfj_unix_operation operation) {
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data || !dentry) {
    return 0;
  }

  BPFJ_FILE_MATCH_CACHED_ALLOC(state);
  if (!state) {
    return -EACCES;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    struct bpfj_role_id role = {};
    struct bpfj_uuid uuid = {};
    bpfj_pod_read_role_id(&role, pod);
    bpfj_pod_read_uuid(&uuid, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    struct bpfj_file_matcher __arena* matcher =
        policy ? policy->unix_path_matcher : NULL;
    if (!matcher) {
      return bpfj_unix_deny(pod, task, &role);
    }
    const long count = BPFJ_FILE_MATCH_CACHED(
        state,
        matcher,
        &bpfj_unix_mount_cache,
        dentry,
        &uuid,
        bpfj_file_match_cached_bind_var_array,
        &pod->var_array);
    if (count <= 0 || !bpfj_unix_path_allowed(state, operation, count)) {
      if (count < 0 && count != -EXDEV && count != -E2BIG) {
        BPFJ_LOG_ERR(-count, "Unix socket path match failed");
      }
      return bpfj_unix_deny(pod, task, &role);
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

static __always_inline int bpfj_unix_enforce_abstract(
    enum bpfj_unix_operation operation,
    const char* name,
    __u32 name_len) {
  struct task_struct* task = bpf_get_current_task_btf();
  struct bpfj_pid_data* pid_data = bpfj_get_current_pid_data();
  if (!task || !pid_data || !name) {
    return 0;
  }
  __u32 num_pods = pid_data->num_pods;
  if (num_pods > BPFJ_MAX_POD_PER_PID) {
    num_pods = BPFJ_MAX_POD_PER_PID;
  }
  for (int index = BPFJ_MAX_POD_PER_PID - 1; index >= 0; --index) {
    if (index >= num_pods || !pid_data->pods[index]) {
      continue;
    }
    void* pod_pointer = (void*)pid_data->pods[index];
    barrier_var(pod_pointer);
    struct bpfj_pod __arena* pod =
        (struct bpfj_pod __arena*)(uintptr_t)pod_pointer;
    struct bpfj_role_id role = {};
    bpfj_pod_read_role_id(&role, pod);
    const struct bpfj_role_policy __arena* policy = bpfj_pod_policy(pod);
    const struct bpfj_glob_map __arena* map = NULL;
    if (policy) {
      switch (operation) {
        case BPFJ_UNIX_BIND:
          map = policy->unix_bind_abstract;
          break;
        case BPFJ_UNIX_CONNECT:
          map = policy->unix_connect_abstract;
          break;
        case BPFJ_UNIX_DGRAM:
          map = policy->unix_dgram_abstract;
          break;
        default:
          break;
      }
    }
    if (map && !bpfj_unix_abstract_allowed(map, pod, name, name_len)) {
      return bpfj_unix_deny(pod, task, &role);
    }
    if (bpfj_is_override(pod)) {
      break;
    }
  }
  return 0;
}

static __always_inline int bpfj_unix_sockaddr_abstract(
    enum bpfj_unix_operation operation,
    const struct sockaddr* address,
    int addrlen) {
  const int path_offset = __builtin_offsetof(struct sockaddr_un, sun_path);
  if (!address || addrlen <= path_offset + 1) {
    return 0;
  }
  const char* path = (const char*)address + path_offset;
  char first = 1;
  if (bpf_probe_read_kernel(&first, sizeof(first), path) < 0 || first != '\0') {
    return 0;
  }
  return bpfj_unix_enforce_abstract(
      operation, path + 1, (__u32)(addrlen - path_offset - 1));
}

static __always_inline int bpfj_unix_address_abstract(
    enum bpfj_unix_operation operation,
    const struct unix_address* address) {
  if (!address) {
    return 0;
  }
  const int addrlen = bpf_core_cast((address), typeof(*(address)))->len;
  const struct sockaddr* name = (const struct sockaddr*)&address->name[0];
  return bpfj_unix_sockaddr_abstract(operation, name, addrlen);
}

SEC("lsm/path_mknod")
int BPF_PROG(
    bpfj_unix_path_bind,
    const struct path* dir,
    struct dentry* dentry,
    umode_t mode,
    unsigned int dev,
    int lsm_ret) {
  if (lsm_ret || (mode & S_IFMT) != S_IFSOCK) {
    return lsm_ret;
  }
  return bpfj_unix_enforce_path(bpfj_ptr_to_scalar(dentry), BPFJ_UNIX_BIND);
}

SEC("lsm/socket_bind")
int BPF_PROG(
    bpfj_unix_abstract_bind,
    struct socket* sock,
    struct sockaddr* address,
    int addrlen,
    int lsm_ret) {
  if (lsm_ret || !sock ||
      bpf_core_cast((sock), typeof(*(sock)))->sk->__sk_common.skc_family !=
          AF_UNIX) {
    return lsm_ret;
  }
  return bpfj_unix_sockaddr_abstract(BPFJ_UNIX_BIND, address, addrlen);
}

SEC("lsm/socket_connect")
int BPF_PROG(
    bpfj_unix_abstract_connect,
    struct socket* sock,
    struct sockaddr* address,
    int addrlen,
    int lsm_ret) {
  if (lsm_ret || !sock ||
      bpf_core_cast((sock), typeof(*(sock)))->sk->__sk_common.skc_family !=
          AF_UNIX) {
    return lsm_ret;
  }
  const short type = bpf_core_cast((sock), typeof(*(sock)))->type;
  if (type != SOCK_STREAM && type != SOCK_SEQPACKET) {
    return 0;
  }
  return bpfj_unix_sockaddr_abstract(BPFJ_UNIX_CONNECT, address, addrlen);
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(
    bpfj_unix_stream_connect,
    struct sock* sock,
    struct sock* other,
    struct sock* newsk,
    int lsm_ret) {
  if (lsm_ret || !other) {
    return lsm_ret;
  }
  struct unix_sock* unix_sk = bpf_core_cast(other, struct unix_sock);
  struct dentry* dentry =
      bpf_core_cast((unix_sk), typeof(*(unix_sk)))->path.dentry;
  return dentry
      ? bpfj_unix_enforce_path(bpfj_ptr_to_scalar(dentry), BPFJ_UNIX_CONNECT)
      : 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(
    bpfj_unix_dgram_send_path,
    struct socket* sock,
    struct socket* other,
    int lsm_ret) {
  if (lsm_ret || !sock || !other ||
      bpf_core_cast((sock), typeof(*(sock)))->type != SOCK_DGRAM) {
    return lsm_ret;
  }
  struct sock* other_sk = bpf_core_cast((other), typeof(*(other)))->sk;
  if (!other_sk) {
    return 0;
  }
  struct unix_sock* unix_sk = bpf_core_cast(other_sk, struct unix_sock);
  struct dentry* dentry =
      bpf_core_cast((unix_sk), typeof(*(unix_sk)))->path.dentry;
  if (dentry) {
    return bpfj_unix_enforce_path(bpfj_ptr_to_scalar(dentry), BPFJ_UNIX_DGRAM);
  }
  return 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(
    bpfj_unix_dgram_send_abstract,
    struct socket* sock,
    struct socket* other,
    int lsm_ret) {
  if (lsm_ret || !sock || !other ||
      bpf_core_cast((sock), typeof(*(sock)))->type != SOCK_DGRAM) {
    return lsm_ret;
  }
  struct sock* other_sk = bpf_core_cast((other), typeof(*(other)))->sk;
  if (!other_sk) {
    return 0;
  }
  struct unix_sock* unix_sk = bpf_core_cast(other_sk, struct unix_sock);
  if (bpf_core_cast((unix_sk), typeof(*(unix_sk)))->path.dentry) {
    return 0;
  }
  return bpfj_unix_address_abstract(
      BPFJ_UNIX_DGRAM, bpf_core_cast((unix_sk), typeof(*(unix_sk)))->addr);
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
