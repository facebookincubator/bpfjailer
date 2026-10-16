// Copyright (c) Meta Platforms, Inc. and affiliates.

#include <bpf/vmlinux/vmlinux.h>

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/lock.h"

// Commands userspace asks the program to run on its next file_open. Kept in
// sync with LockTests.cpp.
#define LOCK_CMD_NONE 0
#define LOCK_CMD_OBSERVE 1
#define LOCK_CMD_LOCK_BUMP_UNLOCK 2
#define LOCK_CMD_INIT 3
#define LOCK_CMD_SLOWPATH_ON_HELD_LOCK 4
#define LOCK_CMD_SLOWPATH_ON_FREE_LOCK 5

// Both allocated from the arena heap and published by userspace before attach.
struct bpfj_lock __arena* test_lock;
__u64 __arena* counter;

volatile __u32 cmd = LOCK_CMD_NONE;
volatile __u32 runs = 0;
volatile int locked = 0;
volatile int locked_seen = 0;

SEC("syscall")
int test_lock_cmd(void* ctx) {
  (void)ctx;

  // One action per command: userspace re-arms 'cmd' before each trigger so the
  // program stays inert on the process's incidental file opens.
  __u32 c = cmd;
  if (c == LOCK_CMD_NONE) {
    return 0;
  }
  cmd = LOCK_CMD_NONE;

  bpfj_heap_use_arena();

  if (c == LOCK_CMD_OBSERVE) {
    locked_seen = bpfj_lock_is_locked(test_lock);
  } else if (c == LOCK_CMD_INIT) {
    bpfj_lock_init(test_lock);
  } else if (c == LOCK_CMD_SLOWPATH_ON_HELD_LOCK) {
    // Drive the arena slow path the way the irqsave fast-path failure does.
    // The caller holds the word, so the bounded wait must time out; a timeout
    // must not leave pending residue behind.
    int err = bpfj_arena_spin_lock_slowpath(
        bpfj_lock_qspinlock(test_lock), BPFJ_LOCKED_VAL);
    locked = (err == 0);
    if (!err) {
      *counter += 1;
      bpfj_arena_spin_unlock(bpfj_lock_qspinlock(test_lock));
    }
  } else if (c == LOCK_CMD_SLOWPATH_ON_FREE_LOCK) {
    // Slow path entered with the word free, as the irqsave fast-path failure
    // observes it after losing a race: it must claim the lock.
    int err = bpfj_arena_spin_lock_slowpath(bpfj_lock_qspinlock(test_lock), 0);
    locked = (err == 0);
    if (!err) {
      *counter += 1;
      bpfj_arena_spin_unlock(bpfj_lock_qspinlock(test_lock));
    }
  } else {
    BPFJ_LOCK_GUARD(test_guard, test_lock);
    locked = BPFJ_LOCK_IS_ACQUIRED(test_guard);
    if (locked) {
      *counter += 1;
    }
  }

  runs++;
  return 0;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
