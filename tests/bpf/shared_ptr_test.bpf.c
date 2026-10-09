// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/shared_ptr.h"

// Commands userspace asks the program to run on its next file_open. Kept in
// sync with SharedPtrTests.cpp.
#define SP_CMD_NONE 0
#define SP_CMD_MAKE 1
#define SP_CMD_ACQUIRE 2
#define SP_CMD_RELEASE_EXTRA 3
#define SP_CMD_RELEASE_OWNER 4
#define SP_CMD_GUARD_MAKE_AND_DROP 5

#define SP_BUF_SIZE 64
#define SP_MARKER 0xABCD1234

// The pointer under test and an extra reference to it, persisted across the
// per-command file_open triggers. File-local so the {buf, refcount} arena-
// pointer struct stays out of the generated skeleton's public interface;
// userspace only ever reads the scalar observations below.
static struct bpfj_shared_ptr g_owner;
static struct bpfj_shared_ptr g_extra;

volatile __u32 cmd = SP_CMD_NONE;
volatile __u32 runs = 0;

// Observations read back by userspace after each command.
volatile __u32 obs_valid = 0;
volatile __u32 obs_use_count = 0;
volatile __u32 obs_use_count_in_scope = 0;
volatile __u32 obs_buf_val = 0;
volatile __u64 obs_heap_used = 0;

static __always_inline __u32 sp_read_buf(struct bpfj_shared_ptr sp) {
  if (!sp.buf) {
    return 0;
  }
  return *(__u32 __arena*)sp.buf;
}

SEC("syscall")
int test_shared_ptr_cmd(void* ctx) {
  (void)ctx;

  // One action per command: userspace re-arms 'cmd' before each trigger so the
  // program stays inert on the process's incidental file opens.
  __u32 c = cmd;
  if (c == SP_CMD_NONE) {
    return 0;
  }
  cmd = SP_CMD_NONE;

  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();

  if (c == SP_CMD_MAKE) {
    g_owner = bpfj_shared_ptr_make(SP_BUF_SIZE);
    if (bpfj_shared_ptr_valid(g_owner)) {
      *(__u32 __arena*)g_owner.buf = SP_MARKER;
    }
    obs_valid = bpfj_shared_ptr_valid(g_owner);
    obs_use_count = bpfj_shared_ptr_use_count(g_owner);
    obs_heap_used = ctrl->current_used;
  } else if (c == SP_CMD_ACQUIRE) {
    g_extra = bpfj_shared_ptr_acquire(g_owner);
    obs_use_count = bpfj_shared_ptr_use_count(g_owner);
    obs_buf_val = sp_read_buf(g_owner);
  } else if (c == SP_CMD_RELEASE_EXTRA) {
    bpfj_shared_ptr_release(&g_extra);
    obs_use_count = bpfj_shared_ptr_use_count(g_owner);
    obs_buf_val = sp_read_buf(g_owner);
    obs_heap_used = ctrl->current_used;
  } else if (c == SP_CMD_RELEASE_OWNER) {
    bpfj_shared_ptr_release(&g_owner);
    obs_use_count = bpfj_shared_ptr_use_count(g_owner);
    obs_heap_used = ctrl->current_used;
  } else if (c == SP_CMD_GUARD_MAKE_AND_DROP) {
    {
      BPFJ_SHARED_PTR_GUARD(g, bpfj_shared_ptr_make(SP_BUF_SIZE));
      obs_valid = BPFJ_SHARED_PTR_VALID(g);
      obs_use_count_in_scope = bpfj_shared_ptr_use_count(g.ptr);
    }
    // The guard released its reference at scope exit, freeing the buffer, so
    // heap usage returns to what it was before this command.
    obs_heap_used = ctrl->current_used;
  }

  runs++;
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
