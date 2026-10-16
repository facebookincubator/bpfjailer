// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// A spin lock that lives in the BPF arena, so the same lock word can be taken
// from BPF and from userspace (bpfj/lib/Lock.h). BPF only attempts the lock
// once. Waiting is unsafe against a userspace holder on two counts:
//
//   - it waits with preemption disabled, so a BPF program spinning on a
//     userspace holder parked on the same CPU keeps it from running, and
//   - a bounded queued-lock bail-out can leave pending or queue state behind,
//     which wedges the lock for both sides.
//
// Userspace may wait, since it yields rather than spins and a BPF holder
// always releases before its program returns.
//
// bpf_atomic.h supplies the acquire/release operations over arena memory.
#include <bpf_atomic.h>
#include <errno.h>

#include "bpfj/lib/bpf/kfuncs.h"
#include "bpfj/lib/bpf/types_lock.h"

struct bpfj_arena_spinlock {
  union {
    atomic_t val;
    struct {
      __u8 locked;
      __u8 pending;
      __u16 tail;
    };
    struct {
      __u16 locked_pending;
      __u16 tail_word;
    };
  };
};

#define BPFJ_LOCKED_VAL 1U
#define BPFJ_LOCKED_MASK 0xffU
#define BPFJ_PENDING_VAL 0x100U
#define BPFJ_PENDING_MASK 0xff00U

// Keep the heap's initial 64 KiB backed by arena data. libbpf only exposes and
// backs an arena's initial mapping to the extent described by this section.
__u8 __weak __arena __hidden bpfj_lock_arena_backing[64 * 1024];

_Static_assert(
    sizeof(struct bpfj_arena_spinlock) == sizeof(__u32),
    "struct bpfj_lock must stay a bare 32-bit word");

// The shared struct stores the bare word so types_heap.h can embed it without
// dragging libarena's header into arena-less objects.
static __always_inline struct bpfj_arena_spinlock __arena* bpfj_lock_qspinlock(
    struct bpfj_lock __arena* l) {
  return (struct bpfj_arena_spinlock __arena*)&l->val;
}

static __always_inline int bpfj_arena_spin_trylock(
    struct bpfj_arena_spinlock __arena* lock) {
  int val = atomic_read(&lock->val);
  if (val != 0) {
    return 0;
  }
  return atomic_try_cmpxchg_acquire(&lock->val, &val, BPFJ_LOCKED_VAL);
}

static __always_inline void bpfj_arena_clear_pending(
    struct bpfj_arena_spinlock __arena* lock) {
  WRITE_ONCE(lock->pending, 0);
}

static __always_inline __u32 bpfj_arena_fetch_set_pending(
    struct bpfj_arena_spinlock __arena* lock,
    int* announced) {
  __u32 old = atomic_read(&lock->val);
  do {
    const __u32 next = old | BPFJ_PENDING_VAL;
    cond_break_label(failed);
    if (atomic_try_cmpxchg_acquire(&lock->val, &old, next)) {
      *announced = 1;
      return old;
    }
  } while (true);
failed:
  *announced = 0;
  return old;
}

static __always_inline int bpfj_arena_spin_lock_slowpath(
    struct bpfj_arena_spinlock __arena* lock,
    __u32 val) {
  int announced = 0;
  if (val == BPFJ_PENDING_VAL) {
    int count = 1;
    val = atomic_cond_read_relaxed_label(
        &lock->val, (VAL != BPFJ_PENDING_VAL) || !count--, failed);
  }
  if (val & ~BPFJ_LOCKED_MASK) {
    return -EBUSY;
  }

  val = bpfj_arena_fetch_set_pending(lock, &announced);
  if (!announced) {
    return -EBUSY;
  }
  if (val & ~BPFJ_LOCKED_MASK) {
    if (!(val & BPFJ_PENDING_MASK)) {
      bpfj_arena_clear_pending(lock);
    }
    return -EBUSY;
  }
  if (val & BPFJ_LOCKED_MASK) {
    (void)smp_cond_load_acquire_label(&lock->locked, !VAL, failed);
  }
  WRITE_ONCE(lock->locked_pending, BPFJ_LOCKED_VAL);
  return 0;
failed:
  // Bounded waiting is a transient miss just like observing a held lock. A
  // timeout after announcing must also withdraw the pending bit: left set, it
  // wedges the word for every later acquire on both sides.
  if (announced) {
    bpfj_arena_clear_pending(lock);
  }
  return -EBUSY;
}

static __always_inline void bpfj_arena_spin_unlock(
    struct bpfj_arena_spinlock __arena* lock) {
  smp_store_release(&lock->locked, 0);
}

static __always_inline int bpfj_arena_spin_lock_irqsave(
    struct bpfj_arena_spinlock __arena* lock,
    unsigned long* flags) {
  bpf_local_irq_save(flags);
  bpf_preempt_disable();
  int val = 0;
  if (atomic_try_cmpxchg_acquire(&lock->val, &val, BPFJ_LOCKED_VAL)) {
    return 0;
  }
  const int error = bpfj_arena_spin_lock_slowpath(lock, val);
  if (error != 0) {
    bpf_preempt_enable();
    bpf_local_irq_restore(flags);
  }
  return error;
}

static __always_inline void bpfj_arena_spin_unlock_irqrestore(
    struct bpfj_arena_spinlock __arena* lock,
    unsigned long* flags) {
  bpfj_arena_spin_unlock(lock);
  bpf_preempt_enable();
  bpf_local_irq_restore(flags);
}

// Put a lock into the free state: required before first use, and not safe to
// run concurrently with any user. Acquire only succeeds on an all-zero word,
// and nothing clears the pending bit or tail outside the slow path we do not
// use, so residue -- the allocator's free-list links in a recycled heap block,
// say -- leaves the lock permanently held.
static void bpfj_lock_init(struct bpfj_lock __arena* l) {
  WRITE_ONCE(l->val, 0);
}

// Take the lock if it is free. Returns 1 on success, 0 if it is held. Unlike
// arena_spin_lock() this does not disable preemption, which costs waiters
// latency but cannot deadlock.
static int bpfj_lock_trylock(struct bpfj_lock __arena* l) {
  return bpfj_arena_spin_trylock(bpfj_lock_qspinlock(l));
}

static void bpfj_lock_unlock(struct bpfj_lock __arena* l) {
  bpfj_arena_spin_unlock(bpfj_lock_qspinlock(l));
}

// Whether the lock is currently held, without attempting to take it.
static bool bpfj_lock_is_locked(struct bpfj_lock __arena* l) {
  return READ_ONCE(bpfj_lock_qspinlock(l)->locked) != 0;
}

struct bpfj_lock_guard {
  struct bpfj_lock __arena* lock;
};

// static, so this is not emitted as a global BPF subprog into every including
// object and collide at link time.
static void bpfj_lock_guard_cleanup(struct bpfj_lock_guard* guard) {
  struct bpfj_lock __arena* lock = guard->lock;
  if (lock) {
    bpfj_lock_unlock(lock);
    guard->lock = NULL;
  }
}

// RAII holder for a lock
#define BPFJ_LOCK_GUARD(_name, _lock_ptr)                                    \
  __attribute__((                                                            \
      cleanup(bpfj_lock_guard_cleanup))) struct bpfj_lock_guard _name = {0}; \
  {                                                                          \
    int _ret = bpfj_lock_trylock(_lock_ptr);                                 \
    if (_ret) {                                                              \
      _name.lock = _lock_ptr;                                                \
    }                                                                        \
  }

#define BPFJ_LOCK_IS_ACQUIRED(_name) ((_name).lock ? 1 : 0)

#define BPFJ_LOCK_UNLOCK(_name) bpfj_lock_guard_cleanup(&_name)

#define BPFJ_LOCK_GUARD_RELEASE(_name) _name.lock = NULL

// Bound waiting where bpf_local_irq_save() exists, with a trylock fallback on
// older internal kernels that cannot resolve that kfunc.
#define BPFJ_ARENA_LOCK(_lock, _flags)                    \
  (bpf_ksym_exists(bpf_local_irq_save)                    \
       ? bpfj_arena_spin_lock_irqsave((_lock), &(_flags)) \
       : (bpfj_arena_spin_trylock((_lock)) ? 0 : -EBUSY))

#define BPFJ_ARENA_UNLOCK(_lock, _flags)                     \
  do {                                                       \
    if (bpf_ksym_exists(bpf_local_irq_save)) {               \
      bpfj_arena_spin_unlock_irqrestore((_lock), &(_flags)); \
    } else {                                                 \
      bpfj_arena_spin_unlock((_lock));                       \
    }                                                        \
  } while (0)

// Inline so the arena pointer keeps its type: the verifier does not support
// __arg_arena on static subprograms, while a global lock function cannot
// return with interrupts disabled.
// Static BPF subprogram argument tags are rejected by the verifier, while the
// address-space-qualified pointee preserves the arena cast here without one.
static __always_inline int bpfj_lock_acquire(
    struct bpfj_lock __arena* l,
    unsigned long* flags) {
  return BPFJ_ARENA_LOCK(bpfj_lock_qspinlock(l), *flags);
}

static __always_inline void bpfj_lock_release(
    struct bpfj_lock __arena* l,
    unsigned long* flags) {
  BPFJ_ARENA_UNLOCK(bpfj_lock_qspinlock(l), *flags);
}

struct bpfj_lock_wait_guard {
  struct bpfj_lock __arena* lock;
  unsigned long flags;
  // 1 or 0, a full 8 bytes in its own stack slot: the verifier keeps a stored
  // value exactly only when a whole slot is written at once, and it has to know
  // this on every path to see that exactly the paths that saved the flags
  // restore them. It cannot get that from the lock pointer, an arena pointer it
  // cannot rule out being null.
  long held;
};

#define BPFJ_LOCK_WAIT_HELD(_name) ((_name).held != 0)

static __always_inline void bpfj_lock_wait_guard_cleanup(
    struct bpfj_lock_wait_guard* guard) {
  if (guard->held) {
    bpfj_lock_release(guard->lock, &guard->flags);
    guard->held = 0;
  }
}

// This expands to two statements and must be used in a braced scope.
#define BPFJ_LOCK_WAIT_GUARD(_name, _lock_ptr)                              \
  __attribute__((cleanup(                                                   \
      bpfj_lock_wait_guard_cleanup))) struct bpfj_lock_wait_guard _name = { \
      .lock = (_lock_ptr)};                                                 \
  _name.held = bpfj_lock_acquire(_name.lock, &_name.flags) == 0
