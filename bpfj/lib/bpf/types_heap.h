// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#include <cerrno>
#include <cstring>
#else
#include <errno.h>
#endif

#include "bpfj/lib/bpf/types_lock.h"

// TLSF Parameters

#define BPFJ_HEAP_SLI_LOG2 4
#define BPFJ_HEAP_SL_INDEX_COUNT (1 << BPFJ_HEAP_SLI_LOG2) // 16
#define BPFJ_HEAP_MIN_BLOCK_SIZE_LOG2 5
#define BPFJ_HEAP_MIN_BLOCK_SIZE (1 << BPFJ_HEAP_MIN_BLOCK_SIZE_LOG2) // 32
#define BPFJ_HEAP_MAX_BLOCK_SIZE_LOG2 25 // 32 MiB
#define BPFJ_HEAP_FL_INDEX_COUNT \
  (BPFJ_HEAP_MAX_BLOCK_SIZE_LOG2 - BPFJ_HEAP_MIN_BLOCK_SIZE_LOG2 + 1) // 21
#define BPFJ_HEAP_ALIGN 8
#define BPFJ_HEAP_ALIGN_MASK (BPFJ_HEAP_ALIGN - 1)

// Arena sizing
#define BPFJ_HEAP_PAGE_SIZE 4096
#define BPFJ_HEAP_INIT_PAGES 64 // 256 KiB initial
#define BPFJ_HEAP_GROW_PAGES 64 // 256 KiB per growth
#define BPFJ_HEAP_MAX_ARENA_PAGES 8192 // 32 MiB max
#define BPFJ_HEAP_MAX_ARENA_SIZE \
  ((__u32)BPFJ_HEAP_MAX_ARENA_PAGES * BPFJ_HEAP_PAGE_SIZE)

#ifdef __cplusplus
static_assert(BPFJ_HEAP_MAX_ARENA_SIZE % BPFJ_HEAP_PAGE_SIZE == 0);
#else
_Static_assert(BPFJ_HEAP_MAX_ARENA_SIZE % BPFJ_HEAP_PAGE_SIZE == 0, "");
#endif

// Pages the arena map carries above the heap's ceiling, reserved for the
// __arena globals libbpf places in the map's last pages -- today just
// libarena's 64 KiB qnodes array -- so a fully grown heap cannot allocate over
// them; heap::init() checks the reservation is still big enough.
// BPFJ_HEAP_MAX_ARENA_SIZE stays a power of two so bpfj_heap_clamp_off can
// mask offsets with it.
#define BPFJ_HEAP_ARENA_GLOBALS_PAGES 32
#define BPFJ_HEAP_ARENA_GLOBALS_SIZE \
  ((__u32)BPFJ_HEAP_ARENA_GLOBALS_PAGES * BPFJ_HEAP_PAGE_SIZE)
#define BPFJ_HEAP_ARENA_MAP_PAGES \
  (BPFJ_HEAP_MAX_ARENA_PAGES + BPFJ_HEAP_ARENA_GLOBALS_PAGES)

// Block flags stored in low 2 bits of size_and_flags
#define BPFJ_HEAP_FLAG_PREV_FREE 0x1
#define BPFJ_HEAP_FLAG_FREE 0x2
#define BPFJ_HEAP_FLAG_MASK 0x3
#define BPFJ_HEAP_SIZE_MASK (~(__u32)BPFJ_HEAP_FLAG_MASK)

// Sentinel value: offset 0 is used by the control structure, so 0 means null.
#define BPFJ_HEAP_NULL 0

// Data Structures (shared between BPF and userspace)

struct bpfj_str_map;
struct bpfj_mount_cache;

// Block header: 8 bytes, precedes every block's payload.
struct bpfj_heap_block_hdr {
  __u32 size_and_flags; // bits[2:31] = block size (incl header), bits[0:1] =
                        // flags
  __u32 prev_phys_offset; // arena offset of previous physical block
};

// Free-list links: overlay the first 8 bytes of a free block's payload area.
struct bpfj_heap_free_links {
  __u32 next_free; // next block in same (FLI,SLI) list
  __u32 prev_free; // prev block in same (FLI,SLI) list
};

// Control structure: lives at arena offset 0.
struct bpfj_heap_control {
  __u32 fl_bitmap; // 1 bit per FL class (21 bits used)
  __u16 sl_bitmap[BPFJ_HEAP_FL_INDEX_COUNT]; // 16 SL bits per FL class
  __u16 _pad; // alignment padding
  __u32 free_heads[BPFJ_HEAP_FL_INDEX_COUNT]
                  [BPFJ_HEAP_SL_INDEX_COUNT]; // free list heads
  __u32 arena_size; // current committed size
  __u64 total_alloc; // stats: total allocations
  __u64 total_free; // stats: total frees
  __u64 current_used; // stats: bytes in use
  struct bpfj_lock lock; // guards every field above and the free lists
  __u32 grow_gen; // bumped by whichever side grows the arena
  __u32 runtime_versions;
  __u32 generation; // stable identity of this arena slot while attached
  void __arena* var_catalog;
  void __arena* mutation_journal;
  struct bpfj_str_map __arena* role_policies;
  struct bpfj_mount_cache __arena* mount_cache;
};

struct bpfj_vec {
  void __arena* buf;
  __u32 elem_size;
  __u32 size;
  __u32 capacity;
  __u32 _pad;
};

enum bpfj_heap_syscall_op {
  BPFJ_HEAP_SYSCALL_ALLOC = 1,
  BPFJ_HEAP_SYSCALL_FREE = 2,
  BPFJ_HEAP_SYSCALL_GROW = 3,
};

// One heap operation request from userspace to the SEC("syscall") helper in
// bpf/heap.h. The helper returns its result in the BPF program retval: a heap
// offset or errno-style negative code for alloc, and 0 or a negative code for
// free.
struct bpfj_heap_syscall_req {
  __u32 op;
  __u32 arg;
  __u32 expected_arena_size;
};

// Platform compatibility (BPF vs. userspace C++)

#ifndef __arena
#ifdef __cplusplus
#define __arena
#else
#define __arena __attribute__((address_space(1)))
#endif
#endif

#ifndef barrier_var
#ifdef __cplusplus
#define barrier_var(x) ((void)(x))
#else
#define barrier_var(x) asm volatile("" : "+r"(x))
#endif
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

// Shared helpers: address arithmetic

static __always_inline __u32 bpfj_heap_clamp_off(__u32 off) {
#ifdef __cplusplus
  off &= (BPFJ_HEAP_MAX_ARENA_SIZE - 1);
#else
  asm volatile("%0 &= %1" : "+r"(off) : "r"(BPFJ_HEAP_MAX_ARENA_SIZE - 1));
#endif
  return off;
}

static __always_inline struct bpfj_heap_block_hdr __arena* bpfj_heap_block_at(
    void __arena* base,
    __u32 off) {
  off = bpfj_heap_clamp_off(off);
  return (struct bpfj_heap_block_hdr __arena*)((char __arena*)base + off);
}

static __always_inline struct bpfj_heap_free_links __arena*
bpfj_heap_free_links_at(void __arena* base, __u32 off) {
  __u32 links_off = off + sizeof(struct bpfj_heap_block_hdr);
  links_off = bpfj_heap_clamp_off(links_off);
  return (struct bpfj_heap_free_links __arena*)((char __arena*)base +
                                                links_off);
}

static __always_inline __u32 bpfj_heap_block_size(__u32 size_and_flags) {
  return size_and_flags & BPFJ_HEAP_SIZE_MASK;
}

static __always_inline int bpfj_heap_block_is_free(__u32 size_and_flags) {
  return (size_and_flags & BPFJ_HEAP_FLAG_FREE) != 0;
}

static __always_inline int bpfj_heap_prev_is_free(__u32 size_and_flags) {
  return (size_and_flags & BPFJ_HEAP_FLAG_PREV_FREE) != 0;
}

static __always_inline __u32
bpfj_heap_next_block_off(__u32 block_off, __u32 block_size) {
  return block_off + block_size;
}

static __always_inline __u32 bpfj_heap_align_up(__u32 size) {
  return (size + BPFJ_HEAP_ALIGN_MASK) & ~BPFJ_HEAP_ALIGN_MASK;
}

static __always_inline __u32 bpfj_heap_adjust_size(__u32 size) {
  size += sizeof(struct bpfj_heap_block_hdr);
  if (size < BPFJ_HEAP_MIN_BLOCK_SIZE) {
    size = BPFJ_HEAP_MIN_BLOCK_SIZE;
  }
  return bpfj_heap_align_up(size);
}

// TLSF index mapping

static __always_inline __u32 bpfj_heap_fls(__u32 x) {
  return 31 - __builtin_clz(x);
}

static __always_inline __u32
bpfj_heap_growth_size(__u32 min_bytes, __u32 arena_size) {
  if (min_bytes == 0 || arena_size >= BPFJ_HEAP_MAX_ARENA_SIZE) {
    return 0;
  }

  __u64 want = bpfj_heap_adjust_size(min_bytes);
  want += (1ULL << (bpfj_heap_fls((__u32)want) - BPFJ_HEAP_SLI_LOG2)) - 1;
  __u64 pages = (want + BPFJ_HEAP_PAGE_SIZE - 1) / BPFJ_HEAP_PAGE_SIZE;
  if (pages < BPFJ_HEAP_GROW_PAGES) {
    pages = BPFJ_HEAP_GROW_PAGES;
  }

  __u64 bytes = pages * BPFJ_HEAP_PAGE_SIZE;
  __u32 remaining = BPFJ_HEAP_MAX_ARENA_SIZE - arena_size;
  return bytes > remaining ? remaining : (__u32)bytes;
}

static __always_inline void
bpfj_heap_mapping(__u32 size, __u32* fli, __u32* sli) {
  if (size < BPFJ_HEAP_MIN_BLOCK_SIZE) {
    *fli = 0;
    *sli = 0;
    return;
  }

  __u32 fl = bpfj_heap_fls(size);
  __u32 fli_val = fl - BPFJ_HEAP_MIN_BLOCK_SIZE_LOG2;
  __u32 sli_val =
      (size >> (fl - BPFJ_HEAP_SLI_LOG2)) & (BPFJ_HEAP_SL_INDEX_COUNT - 1);

  if (fli_val >= BPFJ_HEAP_FL_INDEX_COUNT) {
    fli_val = BPFJ_HEAP_FL_INDEX_COUNT - 1;
    sli_val = BPFJ_HEAP_SL_INDEX_COUNT - 1;
  }

  *fli = fli_val;
  *sli = sli_val;
}

static __always_inline void
bpfj_heap_mapping_search(__u32 size, __u32* fli, __u32* sli) {
  if (size < BPFJ_HEAP_MIN_BLOCK_SIZE) {
    *fli = 0;
    *sli = 0;
    return;
  }

  __u32 fl = bpfj_heap_fls(size);
  __u32 round = (1 << (fl - BPFJ_HEAP_SLI_LOG2)) - 1;
  size += round;

  fl = bpfj_heap_fls(size);
  __u32 fli_val = fl - BPFJ_HEAP_MIN_BLOCK_SIZE_LOG2;
  __u32 sli_val =
      (size >> (fl - BPFJ_HEAP_SLI_LOG2)) & (BPFJ_HEAP_SL_INDEX_COUNT - 1);

  if (fli_val >= BPFJ_HEAP_FL_INDEX_COUNT) {
    fli_val = BPFJ_HEAP_FL_INDEX_COUNT - 1;
    sli_val = BPFJ_HEAP_SL_INDEX_COUNT - 1;
  }

  *fli = fli_val;
  *sli = sli_val;
}

// Free-list operations

static __always_inline void bpfj_heap_remove_free_block(
    void __arena* base,
    struct bpfj_heap_control __arena* ctrl,
    __u32 block_off,
    __u32 fli,
    __u32 sli) {
  if (fli >= BPFJ_HEAP_FL_INDEX_COUNT || sli >= BPFJ_HEAP_SL_INDEX_COUNT) {
    return;
  }
  barrier_var(fli);
  barrier_var(sli);

  struct bpfj_heap_free_links __arena* links =
      bpfj_heap_free_links_at(base, block_off);
  __u32 prev_off = links->prev_free;
  __u32 next_off = links->next_free;

  if (next_off != BPFJ_HEAP_NULL) {
    struct bpfj_heap_free_links __arena* next_links =
        bpfj_heap_free_links_at(base, next_off);
    next_links->prev_free = prev_off;
  }

  if (prev_off != BPFJ_HEAP_NULL) {
    struct bpfj_heap_free_links __arena* prev_links =
        bpfj_heap_free_links_at(base, prev_off);
    prev_links->next_free = next_off;
  } else {
    ctrl->free_heads[fli][sli] = next_off;

    if (next_off == BPFJ_HEAP_NULL) {
      ctrl->sl_bitmap[fli] &= ~((__u16)(1 << sli));
      if (ctrl->sl_bitmap[fli] == 0) {
        ctrl->fl_bitmap &= ~(1U << fli);
      }
    }
  }
}

static __always_inline void bpfj_heap_insert_free_block(
    void __arena* base,
    struct bpfj_heap_control __arena* ctrl,
    __u32 block_off,
    __u32 fli,
    __u32 sli) {
  if (fli >= BPFJ_HEAP_FL_INDEX_COUNT || sli >= BPFJ_HEAP_SL_INDEX_COUNT) {
    return;
  }
  barrier_var(fli);
  barrier_var(sli);

  __u32 old_head = ctrl->free_heads[fli][sli];

  struct bpfj_heap_free_links __arena* links =
      bpfj_heap_free_links_at(base, block_off);
  links->next_free = old_head;
  links->prev_free = BPFJ_HEAP_NULL;

  if (old_head != BPFJ_HEAP_NULL) {
    struct bpfj_heap_free_links __arena* old_head_links =
        bpfj_heap_free_links_at(base, old_head);
    old_head_links->prev_free = block_off;
  }

  ctrl->free_heads[fli][sli] = block_off;

  ctrl->sl_bitmap[fli] |= (__u16)(1 << sli);
  ctrl->fl_bitmap |= (1U << fli);

  struct bpfj_heap_block_hdr __arena* hdr = bpfj_heap_block_at(base, block_off);
  hdr->size_and_flags |= BPFJ_HEAP_FLAG_FREE;

  __u32 blk_size = bpfj_heap_block_size(hdr->size_and_flags);
  __u32 next_off = bpfj_heap_next_block_off(block_off, blk_size);
  if (next_off < ctrl->arena_size) {
    struct bpfj_heap_block_hdr __arena* next_hdr =
        bpfj_heap_block_at(base, next_off);
    next_hdr->size_and_flags |= BPFJ_HEAP_FLAG_PREV_FREE;
    next_hdr->prev_phys_offset = block_off;
  }
}

static __always_inline __u32 bpfj_heap_find_free(
    struct bpfj_heap_control __arena* ctrl,
    __u32* out_fli,
    __u32* out_sli) {
  __u32 fli = *out_fli;
  __u32 sli = *out_sli;

  if (fli >= BPFJ_HEAP_FL_INDEX_COUNT) {
    return BPFJ_HEAP_NULL;
  }
  barrier_var(fli);

  __u32 sl_map = ctrl->sl_bitmap[fli] & (~0U << sli);

  if (sl_map == 0) {
    __u32 fl_map = ctrl->fl_bitmap & (~0U << (fli + 1));
    if (fl_map == 0) {
      return BPFJ_HEAP_NULL;
    }

    fli = __builtin_ctz(fl_map);
    if (fli >= BPFJ_HEAP_FL_INDEX_COUNT) {
      return BPFJ_HEAP_NULL;
    }
    barrier_var(fli);

    sl_map = ctrl->sl_bitmap[fli];
    if (sl_map == 0) {
      return BPFJ_HEAP_NULL;
    }
  }

  sli = __builtin_ctz(sl_map);
  if (sli >= BPFJ_HEAP_SL_INDEX_COUNT) {
    return BPFJ_HEAP_NULL;
  }
  barrier_var(sli);

  *out_fli = fli;
  *out_sli = sli;

  return ctrl->free_heads[fli][sli];
}

// Block splitting

static __always_inline void bpfj_heap_split(
    void __arena* base,
    struct bpfj_heap_control __arena* ctrl,
    __u32 block_off,
    __u32 needed_size) {
  struct bpfj_heap_block_hdr __arena* hdr = bpfj_heap_block_at(base, block_off);
  __u32 full_size = bpfj_heap_block_size(hdr->size_and_flags);

  if (full_size < needed_size + BPFJ_HEAP_MIN_BLOCK_SIZE) {
    return;
  }

  __u32 remainder_size = full_size - needed_size;

  hdr->size_and_flags =
      needed_size | (hdr->size_and_flags & BPFJ_HEAP_FLAG_PREV_FREE);

  __u32 remainder_off = bpfj_heap_next_block_off(block_off, needed_size);
  struct bpfj_heap_block_hdr __arena* rem_hdr =
      bpfj_heap_block_at(base, remainder_off);
  rem_hdr->size_and_flags = remainder_size;
  rem_hdr->prev_phys_offset = block_off;

  __u32 rem_fli;
  __u32 rem_sli;
  bpfj_heap_mapping(remainder_size, &rem_fli, &rem_sli);
  bpfj_heap_insert_free_block(base, ctrl, remainder_off, rem_fli, rem_sli);
}

// Coalescing (used during free)

static __always_inline __u32 bpfj_heap_merge_next(
    void __arena* base,
    struct bpfj_heap_control __arena* ctrl,
    __u32 block_off,
    __u32* block_size) {
  __u32 next_off = bpfj_heap_next_block_off(block_off, *block_size);
  if (next_off >= ctrl->arena_size) {
    return block_off;
  }

  struct bpfj_heap_block_hdr __arena* next_hdr =
      bpfj_heap_block_at(base, next_off);
  if (!bpfj_heap_block_is_free(next_hdr->size_and_flags)) {
    return block_off;
  }

  __u32 next_size = bpfj_heap_block_size(next_hdr->size_and_flags);

  __u32 next_fli;
  __u32 next_sli;
  bpfj_heap_mapping(next_size, &next_fli, &next_sli);
  bpfj_heap_remove_free_block(base, ctrl, next_off, next_fli, next_sli);

  *block_size += next_size;

  return block_off;
}

static __always_inline __u32 bpfj_heap_merge_prev(
    void __arena* base,
    struct bpfj_heap_control __arena* ctrl,
    __u32 block_off,
    __u32* block_size,
    __u32 size_and_flags) {
  if (!bpfj_heap_prev_is_free(size_and_flags)) {
    return block_off;
  }

  struct bpfj_heap_block_hdr __arena* hdr = bpfj_heap_block_at(base, block_off);
  __u32 prev_off = hdr->prev_phys_offset;
  if (prev_off == BPFJ_HEAP_NULL || prev_off >= block_off) {
    return block_off;
  }

  struct bpfj_heap_block_hdr __arena* prev_hdr =
      bpfj_heap_block_at(base, prev_off);
  __u32 prev_size = bpfj_heap_block_size(prev_hdr->size_and_flags);

  __u32 prev_fli;
  __u32 prev_sli;
  bpfj_heap_mapping(prev_size, &prev_fli, &prev_sli);
  bpfj_heap_remove_free_block(base, ctrl, prev_off, prev_fli, prev_sli);

  *block_size += prev_size;

  return prev_off;
}

// Core implementation (no locking, callable from BPF or userspace)

static __always_inline void bpfj_heap_init_arena(
    void __arena* base,
    __u32 arena_size) {
  struct bpfj_heap_control __arena* ctrl =
      (struct bpfj_heap_control __arena*)base;

  if (ctrl->arena_size != 0) {
    // Arena already initialized
    return;
  }

  __u32 ctrl_size = bpfj_heap_align_up(sizeof(struct bpfj_heap_control));

  ctrl->fl_bitmap = 0;
  ctrl->_pad = 0;

  __u32 i;
  for (i = 0; i < BPFJ_HEAP_FL_INDEX_COUNT; i++) {
    ctrl->sl_bitmap[i] = 0;
    __u32 j;
    for (j = 0; j < BPFJ_HEAP_SL_INDEX_COUNT; j++) {
      ctrl->free_heads[i][j] = BPFJ_HEAP_NULL;
    }
  }

  ctrl->arena_size = arena_size;
  ctrl->grow_gen = 0;
  ctrl->runtime_versions = 0;
  ctrl->var_catalog = NULL;
  ctrl->role_policies = NULL;
  ctrl->total_alloc = 0;
  ctrl->total_free = 0;
  ctrl->current_used = 0;

  __u32 free_block_off = ctrl_size;
  __u32 free_block_size = arena_size - ctrl_size;

  struct bpfj_heap_block_hdr __arena* free_hdr =
      bpfj_heap_block_at(base, free_block_off);
  free_hdr->size_and_flags = free_block_size;
  free_hdr->prev_phys_offset = BPFJ_HEAP_NULL;

  __u32 fli;
  __u32 sli;
  bpfj_heap_mapping(free_block_size, &fli, &sli);
  bpfj_heap_insert_free_block(base, ctrl, free_block_off, fli, sli);
}

static __always_inline long bpfj_heap_alloc_impl(
    void __arena* base,
    struct bpfj_heap_control __arena* ctrl,
    __u32 size) {
  if (size == 0 || size > BPFJ_HEAP_MAX_ARENA_SIZE) {
    return -EINVAL;
  }

  __u32 adjusted_size = bpfj_heap_adjust_size(size);

  __u32 fli;
  __u32 sli;
  bpfj_heap_mapping_search(adjusted_size, &fli, &sli);

  __u32 block_off = bpfj_heap_find_free(ctrl, &fli, &sli);
  if (block_off == BPFJ_HEAP_NULL) {
    return -ENOMEM;
  }

  bpfj_heap_remove_free_block(base, ctrl, block_off, fli, sli);
  bpfj_heap_split(base, ctrl, block_off, adjusted_size);

  struct bpfj_heap_block_hdr __arena* hdr = bpfj_heap_block_at(base, block_off);
  hdr->size_and_flags &= ~(__u32)BPFJ_HEAP_FLAG_FREE;

  __u32 blk_size = bpfj_heap_block_size(hdr->size_and_flags);
  __u32 next_off = bpfj_heap_next_block_off(block_off, blk_size);
  if (next_off < ctrl->arena_size) {
    struct bpfj_heap_block_hdr __arena* next_hdr =
        bpfj_heap_block_at(base, next_off);
    next_hdr->size_and_flags &= ~(__u32)BPFJ_HEAP_FLAG_PREV_FREE;
  }

  ctrl->total_alloc++;
  ctrl->current_used += blk_size;

  return block_off + sizeof(struct bpfj_heap_block_hdr);
}

static __always_inline long bpfj_heap_free_impl(
    void __arena* base,
    struct bpfj_heap_control __arena* ctrl,
    __u32 offset) {
  if (offset == BPFJ_HEAP_NULL) {
    return 0;
  }
  if (offset < sizeof(struct bpfj_heap_block_hdr)) {
    return -EINVAL;
  }
  __u32 block_off = offset - sizeof(struct bpfj_heap_block_hdr);

  struct bpfj_heap_block_hdr __arena* hdr = bpfj_heap_block_at(base, block_off);
  __u32 size_and_flags = hdr->size_and_flags;
  __u32 blk_size = bpfj_heap_block_size(size_and_flags);

  if (bpfj_heap_block_is_free(size_and_flags)) {
    return 0;
  }

  ctrl->total_free++;
  ctrl->current_used -= blk_size;

  block_off = bpfj_heap_merge_next(base, ctrl, block_off, &blk_size);
  block_off =
      bpfj_heap_merge_prev(base, ctrl, block_off, &blk_size, size_and_flags);

  hdr = bpfj_heap_block_at(base, block_off);
  hdr->size_and_flags =
      blk_size | (hdr->size_and_flags & BPFJ_HEAP_FLAG_PREV_FREE);

  __u32 fli;
  __u32 sli;
  bpfj_heap_mapping(blk_size, &fli, &sli);
  bpfj_heap_insert_free_block(base, ctrl, block_off, fli, sli);

  return 0;
}
