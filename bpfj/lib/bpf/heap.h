// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

// TLSF (Two-Level Segregated Fit) heap allocator over a resizable
// BPF_MAP_TYPE_ARENA. The core logic is in types_heap.h and shared with
// userspace; this file adds the BPF-specific arena map management, locking and
// page allocation. bpfj_arena_double is sleepable-only.

#include <errno.h>
#include "bpfj/lib/bpf/lock.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/lib/bpf/types_heap.h"

#ifndef NUMA_NO_NODE
#define NUMA_NO_NODE (-1)
#endif

// Sized above the heap's ceiling so libbpf's __arena globals land in the
// reserved tail rather than in heap memory (see BPFJ_HEAP_ARENA_MAP_PAGES).
struct {
  __uint(type, BPF_MAP_TYPE_ARENA);
  __uint(map_flags, BPF_F_MMAPABLE);
  __uint(max_entries, BPFJ_HEAP_ARENA_MAP_PAGES);
} bpfj_heap_arena SEC(".maps");

// kfunc declarations for arena page management.
extern void* bpf_arena_alloc_pages(
    void* p__map,
    void* addr__ign,
    u32 page_cnt,
    int node_id,
    u64 flags) __weak __ksym;
extern void bpf_arena_free_pages(void* p__map, void* ptr__ign, u32 page_cnt)
    __weak __ksym;

// Set by userspace heap::init. Arena pointers (AS(1)) support neither ptrtoint
// nor NULL comparison in the verifier, hence the separate flag below.
struct bpfj_heap_control __arena* bpfj_heap_ctrl;

// Feature gate for the BPF arena, which needs kernel 6.9+; set false on older
// kernels, so the verifier prunes every arena-referencing branch.
volatile const bool bpfj_heap_enabled = true;

static __always_inline struct bpfj_heap_control __arena* bpfj_heap_get_ctrl(
    void) {
  return bpfj_heap_ctrl;
}

// Associate the arena map with the current BPF program so the verifier permits
// __arena dereferences; every program using heap pointers must call it. The
// lookup is dead at runtime but the verifier still sees the reference.
#ifdef BPFJ_OSS_BUILD
#define BPFJ_HEAP_USE_ARENA_ATTR __always_inline
#else
#define BPFJ_HEAP_USE_ARENA_ATTR __noinline
#endif
static BPFJ_HEAP_USE_ARENA_ATTR void bpfj_heap_use_arena(void) {
  // Gated on rodata so the reference is dropped where there is no arena.
  if (!bpfj_heap_enabled) {
    return;
  }
  volatile const bool k_false = false;
  if (k_false) {
    const static u32 zero = 0;
    bpf_map_lookup_elem(&bpfj_heap_arena, &zero);
  }
}
#undef BPFJ_HEAP_USE_ARENA_ATTR

__noinline long bpfj_heap_alloc(u32 size);
__noinline long bpfj_heap_free(u32 offset);
__noinline long bpfj_heap_grow(u32 min_bytes);
__noinline long bpfj_heap_grow_preallocated(
    u32 min_bytes,
    u32 expected_arena_size);

// Userspace asks this helper to mutate the heap instead of taking ctrl->lock
// itself. That keeps userspace out of the waiting arena lock path, whose
// timeout semantics are only safe when both the waiter and holder are in BPF.
SEC("syscall")
int bpfj_heap_syscall(void* ctx) {
  struct bpfj_heap_syscall_req req = {};
  __builtin_memcpy(&req, ctx, sizeof(req));

  if (!bpfj_heap_enabled) {
    return -ENOTSUP;
  }

  bpfj_heap_use_arena();

  if (req.op == BPFJ_HEAP_SYSCALL_ALLOC) {
    return (int)bpfj_heap_alloc(req.arg);
  }
  if (req.op == BPFJ_HEAP_SYSCALL_FREE) {
    return (int)bpfj_heap_free(req.arg);
  }
  if (req.op == BPFJ_HEAP_SYSCALL_GROW) {
    if (req.expected_arena_size != 0) {
      return (int)bpfj_heap_grow_preallocated(req.arg, req.expected_arena_size);
    }
    return (int)bpfj_heap_grow(req.arg);
  }
  return -EINVAL;
}

// Public API

// Grow the arena by at least `min_bytes`. Thread safe; sleepable context only.
__noinline long bpfj_heap_grow(u32 min_bytes) {
  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  void __arena* base = (void __arena*)ctrl;

  if (min_bytes == 0) {
    return -EINVAL;
  }

  // Unlocked: only a hint for the recheck below, which holds the lock.
  u32 old_gen = ctrl->grow_gen;
  u32 old_arena_size = ctrl->arena_size;
  if (old_arena_size >= BPFJ_HEAP_MAX_ARENA_SIZE) {
    return -ENOMEM;
  }

  u32 new_block_size = bpfj_heap_growth_size(min_bytes, old_arena_size);
  if (new_block_size == 0) {
    return -ENOMEM;
  }
  u32 pages_needed = new_block_size / BPFJ_HEAP_PAGE_SIZE;
  u64 new_arena_size = (u64)old_arena_size + new_block_size;

  void* ret = bpf_arena_alloc_pages(
      &bpfj_heap_arena,
      (void*)((char __arena*)base + old_arena_size),
      pages_needed,
      NUMA_NO_NODE,
      0);
  if (!ret) {
    // Another grow reaching these pages first is a success for our caller.
    return ctrl->grow_gen != old_gen ? 0 : -ENOMEM;
  }

  // The pages must exist before taking the allocator lock: page allocation is
  // sleepable, while checking the new block into TLSF is a short BPF-only
  // critical section.
  {
    BPFJ_LOCK_WAIT_GUARD(hl, &ctrl->lock);
    if (BPFJ_LOCK_WAIT_HELD(hl) && ctrl->grow_gen == old_gen) {
      ++ctrl->grow_gen;
      ctrl->arena_size = (u32)new_arena_size;

      struct bpfj_heap_block_hdr __arena* new_hdr =
          bpfj_heap_block_at(base, old_arena_size);
      new_hdr->size_and_flags = (u32)new_block_size;
      new_hdr->prev_phys_offset = BPFJ_HEAP_NULL;

      u32 fli, sli;
      bpfj_heap_mapping((u32)new_block_size, &fli, &sli);
      bpfj_heap_insert_free_block(base, ctrl, old_arena_size, fli, sli);
      return 0;
    }
  }

  bpf_arena_free_pages(&bpfj_heap_arena, ret, pages_needed);
  return ctrl->grow_gen != old_gen ? 0 : -EBUSY;
}

// Publish pages userspace prefaulted without taking the shared arena lock in
// userspace. The expected size makes a concurrent completed grow a no-op.
__noinline long bpfj_heap_grow_preallocated(
    u32 min_bytes,
    u32 expected_arena_size) {
  if (min_bytes == 0) {
    return -EINVAL;
  }

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  void __arena* base = (void __arena*)ctrl;

  BPFJ_LOCK_WAIT_GUARD(hl, &ctrl->lock);
  if (!BPFJ_LOCK_WAIT_HELD(hl)) {
    return -EBUSY;
  }
  if (ctrl->arena_size != expected_arena_size) {
    return 0;
  }
  if (expected_arena_size >= BPFJ_HEAP_MAX_ARENA_SIZE) {
    return -ENOMEM;
  }

  u32 new_block_size = bpfj_heap_growth_size(min_bytes, expected_arena_size);
  if (new_block_size == 0) {
    return -ENOMEM;
  }

  ctrl->arena_size = expected_arena_size + new_block_size;
  struct bpfj_heap_block_hdr __arena* new_hdr =
      bpfj_heap_block_at(base, expected_arena_size);
  new_hdr->size_and_flags = new_block_size;
  new_hdr->prev_phys_offset = BPFJ_HEAP_NULL;

  u32 fli, sli;
  bpfj_heap_mapping(new_block_size, &fli, &sli);
  bpfj_heap_insert_free_block(base, ctrl, expected_arena_size, fli, sli);
  ++ctrl->grow_gen;
  return 0;
}

// Double the size of the heap. Thread safe; sleepable context only.
__noinline long bpfj_arena_double() {
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  return bpfj_heap_grow(ctrl->arena_size);
}

static unsigned char __arena* bpfj_heap_ptr() {
  return (unsigned char __arena*)bpfj_heap_ctrl;
}

// Allocate at least `size` bytes, returning the payload's arena offset or 0 on
// failure (including an exhausted pool). Safe in any BPF context.
__noinline long bpfj_heap_alloc(u32 size) {
  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  void __arena* base = (void __arena*)ctrl;

  BPFJ_LOCK_WAIT_GUARD(hl, &ctrl->lock);
  if (!BPFJ_LOCK_WAIT_HELD(hl)) {
    return -EBUSY;
  }

  return bpfj_heap_alloc_impl(base, ctrl, size);
}

// Free a block by the payload offset bpfj_heap_alloc returned.
__noinline long bpfj_heap_free(u32 offset) {
  bpfj_heap_use_arena();
  if (offset == BPFJ_HEAP_NULL) {
    return 0;
  }
  if (offset < sizeof(struct bpfj_heap_block_hdr)) {
    return -EINVAL;
  }

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  void __arena* base = (void __arena*)ctrl;

  BPFJ_LOCK_WAIT_GUARD(hl, &ctrl->lock);
  if (!BPFJ_LOCK_WAIT_HELD(hl)) {
    return -EBUSY;
  }

  return bpfj_heap_free_impl(base, ctrl, offset);
}

// Allocate a zeroed block, returning the payload's arena offset or 0. Inlined
// unlike its siblings, since as a subprogram it would add a frame to every
// allocation chain and the deepest has none to spare.
static __always_inline long bpfj_heap_calloc(u32 size) {
  long off = bpfj_heap_alloc(size);
  if (off <= 0) {
    return off;
  }

  void __arena* base = bpfj_heap_get_ctrl();
  u32 words = (size + 7) / 8;
  u32 i;
  bpf_for(i, 0, words) {
    u32 d = off + i * 8;
    d = bpfj_heap_clamp_off(d);
    *(u64 __arena*)((char __arena*)base + d) = 0;
  }

  return off;
}

__noinline long bpfj_heap_realloc(u32 offset, u32 new_size) {
  bpfj_heap_use_arena();
  if (offset == BPFJ_HEAP_NULL) {
    return bpfj_heap_alloc(new_size);
  }

  if (new_size == 0) {
    long ret = bpfj_heap_free(offset);
    if (ret < 0) {
      BPFJ_LOG_ERR(-ret, "heap: free failed in realloc");
    }
    return BPFJ_HEAP_NULL;
  }

  if (offset < sizeof(struct bpfj_heap_block_hdr)) {
    return -EINVAL;
  }

  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  void __arena* base = (void __arena*)ctrl;
  u32 old_block_off = offset - sizeof(struct bpfj_heap_block_hdr);
  struct bpfj_heap_block_hdr __arena* old_hdr =
      bpfj_heap_block_at(base, old_block_off);
  u32 old_block_size = bpfj_heap_block_size(old_hdr->size_and_flags);
  u32 old_usable = old_block_size - sizeof(struct bpfj_heap_block_hdr);

  long new_off = bpfj_heap_alloc(new_size);
  if (new_off <= 0) {
    return new_off;
  }

  u32 copy_size = old_usable < new_size ? old_usable : new_size;
  u32 words = (copy_size + 7) / 8;
  u32 i;
  bpf_for(i, 0, words) {
    u32 s = offset + i * 8;
    u32 d = new_off + i * 8;
    s = bpfj_heap_clamp_off(s);
    d = bpfj_heap_clamp_off(d);
    u64 val = *(u64 __arena*)((char __arena*)base + s);
    *(u64 __arena*)((char __arena*)base + d) = val;
  }

  long ret = bpfj_heap_free(offset);
  if (ret < 0) {
    BPFJ_LOG_ERR(-ret, "heap: free failed in realloc");
  }
  return new_off;
}

#define BPFJ_HEAP_ALLOC(_size)                                  \
  ({                                                            \
    long _ret = bpfj_heap_alloc(_size);                         \
    if (_ret < 0) {                                             \
      BPFJ_LOG_ERR(-_ret, "Could not alloc");                   \
    }                                                           \
    _ret <= 0 ? NULL : (void __arena*)(bpfj_heap_ptr() + _ret); \
  })

#define BPFJ_HEAP_CALLOC(_size)                                 \
  ({                                                            \
    long _ret = bpfj_heap_calloc(_size);                        \
    if (_ret < 0) {                                             \
      BPFJ_LOG_ERR(-_ret, "Could not alloc");                   \
    }                                                           \
    _ret <= 0 ? NULL : (void __arena*)(bpfj_heap_ptr() + _ret); \
  })

#define BPFJ_HEAP_FREE(_ptr)                                      \
  ({                                                              \
    long _off = (unsigned char __arena*)(_ptr) - bpfj_heap_ptr(); \
    long _ret = bpfj_heap_free(_off);                             \
    if (_ret < 0) {                                               \
      BPFJ_LOG_ERR(-_ret, "Could not free");                      \
    }                                                             \
  })

static void bpfj_heap_free_ptr(void __arena** ptr) {
  if (ptr && *ptr) {
    BPFJ_HEAP_FREE(*ptr);
    *ptr = NULL;
  }
}

// Scoped heap allocation: one _type, freed when _name leaves scope, and NULL
// if the allocation failed. Never BPFJ_HEAP_FREE(_name) or assign to it --
// either leaves the hidden handle owning a block scope exit frees again -- and
// use BPFJ_HEAP_ALLOC for an allocation that must outlive the scope.
#define BPFJ_HEAP_ALLOC_GUARD(_type, _name)                            \
  __attribute__((                                                      \
      cleanup(bpfj_heap_free_ptr))) void __arena* _name##_heap_guard = \
      BPFJ_HEAP_ALLOC(sizeof(_type));                                  \
  _type __arena* _name = _name##_heap_guard

#define BPFJ_HEAP_MAX_PROBE_BYTES 4096

// One chunk of a kernel->arena copy, staged on the stack and small because it
// is charged to the deepest chain there is; 64 does not fit.
#define BPFJ_HEAP_PROBE_CHUNK 32

// We can't read directly from kernel -> arena, so this stages an intermediate
// copy. `src` is an integer because 6.11 rejects the tags a raw kernel pointer
// parameter would need on a global subprogram, and the probe read validates
// the address anyway.
long bpfj_heap_read_kernel(
    void __arena* dst __arg_arena,
    __u32 len,
    __u64 src) {
  // On the stack rather than a per-CPU scratch map: file_open is sleepable, so
  // another task could rewrite a per-CPU slot between the probe read and the
  // copy that drains it.
  unsigned char buf[BPFJ_HEAP_PROBE_CHUNK];
  unsigned char __arena* out = dst;

  len &= (BPFJ_HEAP_MAX_PROBE_BYTES - 1);

  // The probe refills `buf` at each chunk boundary; the mask works because the
  // chunk is a power of two.
  long ret = 0;
  __u32 i = 0;
  bpf_for(i, 0, len) {
    __u32 off = i & (BPFJ_HEAP_PROBE_CHUNK - 1);
    if (off == 0) {
      __u32 n = len - i;
      if (n > BPFJ_HEAP_PROBE_CHUNK) {
        n = BPFJ_HEAP_PROBE_CHUNK;
      }
      ret = bpf_probe_read_kernel(
          buf, n, (const void*)(uintptr_t)(src + (__u64)i));
      if (ret < 0) {
        return ret;
      }
    }

    // Not a memcpy, which clang lowers to a libcall that does not exist for
    // arena memory, and byte-wise because the destination has no alignment.
    out[i & (BPFJ_HEAP_MAX_PROBE_BYTES - 1)] = buf[off];
  }

  return ret;
}

// Copy one arena block over another by hand, __builtin_memcpy lowering to a
// libcall that does not exist for arena memory. Rounds up to whole words,
// which is safe because both ends are 8-byte-granular heap blocks.
static __always_inline void
bpfj_heap_copy_arena(void __arena* dst, const void __arena* src, __u32 size) {
  __u64 __arena* out = dst;
  const __u64 __arena* in = src;
  __u32 words = (size + 7) / 8;
  __u32 i = 0;
  bpf_for(i, 0, words) {
    out[i] = in[i];
  }
}

// Copy into arena memory from a normal buffer, and zero arena memory. Byte-
// wise rather than a struct assignment or __builtin_memset: clang expands a
// small copy inline but drops the arena address space doing so, and these
// write struct *fields*, so rounding a tail up would scribble past them.
static __always_inline void
bpfj_heap_write_arena(void __arena* dst, __u32 len, const void* src) {
  unsigned char __arena* out = dst;
  const unsigned char* in = src;
  __u32 i = 0;
  bpf_for(i, 0, len) {
    out[i] = in[i];
  }
}

static __always_inline void bpfj_heap_zero_arena(void __arena* dst, __u32 len) {
  unsigned char __arena* out = dst;
  __u32 i = 0;
  bpf_for(i, 0, len) {
    out[i] = 0;
  }
}

// Copy out of the arena by hand, the BPF read helpers taking only
// address-space-0 pointers. Inlined with a `len` constant at every call site,
// so the verifier can bound the copy against the destination.
static __always_inline void
bpfj_heap_read_arena(void* dst, __u32 len, const void __arena* src) {
  const unsigned char __arena* in = src;
  unsigned char* out = dst;
  __u32 i = 0;
  bpf_for(i, 0, len) {
    out[i] = in[i];
  }
}
