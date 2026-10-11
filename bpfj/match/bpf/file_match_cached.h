#pragma once

#include <errno.h>
#include "bpfj/lib/bpf/glob_map.h"
#include "bpfj/lib/bpf/heap.h"
#include "bpfj/lib/bpf/logging_bpf.h"
#include "bpfj/lib/bpf/perf_map.h"
#include "bpfj/lib/bpf/scratch.h"
#include "bpfj/lib/bpf/vec.h"
#include "bpfj/match/bpf/matcher_state.h"
#include "bpfj/match/bpf/mount.h"
#include "bpfj/match/bpf/types_file_match.h"
#include "bpfj/match/bpf/types_file_match_cached.h"

#ifndef BPFJ_FILE_MATCH_CACHED_MAX_RECURSION
#define BPFJ_FILE_MATCH_CACHED_MAX_RECURSION 16384
#endif
#define BPFJ_FILE_MATCH_CACHED_BUF_SIZE 4096
#define BPFJ_FILE_MATCH_CACHED_MAX_DIR_DESCENDANTS 128
#define BPFJ_FILE_MATCH_CACHED_CHECKPOINT_SIZE 16384
#define BPFJ_FILE_MATCH_CACHED_MAX_CHECKPOINT_ITERS 32

#define BPFJ_FILE_MATCH_CACHED_MAX_RETRIES 32
#define BPFJ_FILE_MATCH_CACHED_MAX_CHILD_DENTRIES 8

// Linux packs a dentry name's hash and length into qstr::hash_len. Keep this
// header self-contained rather than depending on the closed file walker for
// its stringhash.h compatibility macro.
static __always_inline u32 bpfj_file_hashlen_len(u64 hashlen) {
  return (u32)(hashlen >> 32);
}

#define BTRFS_I(_inode)                                                   \
  _Generic(                                                               \
      _inode,                                                             \
      struct inode*: container_of(_inode, struct btrfs_inode, vfs_inode), \
      const struct inode*: (const struct btrfs_inode*)container_of(       \
          _inode, const struct btrfs_inode, vfs_inode))

#define BTRFS_FIRST_FREE_OBJECTID 256ULL
#define BPFJ_BTRFS_SUPER_MAGIC 0x9123683E

extern const void rename_lock __ksym;
extern const void btrfs_dir_inode_operations __ksym;

// CPU striping avoids one globally contended counter cache line. The kernel can
// migrate a sleepable program because these are ordinary BSS slots.
enum bpfj_file_match_cached_stat {
  BPFJ_FILE_MATCH_CACHED_STAT_HIT,
  BPFJ_FILE_MATCH_CACHED_STAT_MISS,
  BPFJ_FILE_MATCH_CACHED_STAT_BUSY,
  BPFJ_FILE_MATCH_CACHED_STAT_INVALID,
  BPFJ_FILE_MATCH_CACHED_STAT_INSERT_EXISTS,
  BPFJ_FILE_MATCH_CACHED_STAT_INSERT_BUSY,
  BPFJ_FILE_MATCH_CACHED_STAT_INSERT_ERROR,
  BPFJ_FILE_MATCH_CACHED_STAT_RESERVED,
  BPFJ_FILE_MATCH_CACHED_STAT_COUNT,
};

volatile __u64
    bpfj_file_match_cached_cache_stats[BPFJ_FILE_MATCH_CACHED_STATS_SLOTS]
                                      [BPFJ_FILE_MATCH_CACHED_STAT_COUNT];

static __always_inline volatile __u64* bpfj_file_match_cached_stats_for_cpu(
    void) {
  __u32 cpu = bpf_get_smp_processor_id();
  return bpfj_file_match_cached_cache_stats
      [cpu & (BPFJ_FILE_MATCH_CACHED_STATS_SLOTS - 1)];
}

// Public API

// Declares the scope-guarded run state as `_name`, NULL if it could not be
// allocated.
//
// Its own guard rather than BPFJ_HEAP_ALLOC_GUARD's, because the state owns
// vectors: the plain guard frees the struct, which would strand their buffers.
#define BPFJ_FILE_MATCH_CACHED_ALLOC(_name)                          \
  __attribute__((cleanup(bpfj_file_match_cached_state_free))) struct \
      bpfj_file_match_cached_state __arena* _name =                  \
          bpfj_file_match_cached_state_alloc()

#define _BPFJ_FILE_MATCH_CACHED(                                  \
    _name, _matcher, _mount_cache, _dentry, _uuid, _bind, _vars)  \
  ({                                                              \
    long _out = -ENOMEM;                                          \
    if (_name) {                                                  \
      _bind(_name, _matcher, (uintptr_t)(_dentry), _uuid, _vars); \
      _out = bpfj_fmc_run(_matcher, _name, _mount_cache);         \
    }                                                             \
    _out;                                                         \
  })

// Run a cached match against the run state _name, evaluating to the match
// count (or a negative errno).
//
// _name is declared by BPFJ_FILE_MATCH_CACHED_ALLOC, which scope-guards the
// arena allocation: it is freed when that scope ends. The accessors below take
// it explicitly, so they can be used from any function the pointer reaches --
// they no longer have to share a scope with the match itself.
//
// _uuid: pointer to a single struct bpfj_uuid identifying the var bindings.
// _bind: a bind function declared by BPFJ_FILE_MATCH_CACHED_DEFINE_BIND for
//        the caller's var type, which fills in the ${NAME} bindings from
//        _vars.
// _vars: the caller's variables, handed to _bind as is.
#define BPFJ_FILE_MATCH_CACHED(                                  \
    _name, _matcher, _mount_cache, _dentry, _uuid, _bind, _vars) \
  _BPFJ_FILE_MATCH_CACHED(                                       \
      _name, _matcher, _mount_cache, _dentry, _uuid, _bind, _vars)

#define BPFJ_FILE_MATCH_CACHED_GET_POS(_name, _index) \
  ({ bpfj_file_match_cached_pos(_name, _index); })

// The data entry the match at _match_idx landed on, or NULL if the matcher
// carries none for it.
#define BPFJ_FILE_MATCH_CACHED_LOOKUP(_name, _match_idx) \
  ({ bpfj_file_match_cached_lookup(_name, _match_idx); })

// Bounded by the arena scratch, not by sizeof(_buf): the walked path is
// assembled into a pattern_str, so a larger destination would read past it.
#define BPFJ_FILE_MATCH_CACHED_PRINT(_name, _buf)                           \
  ({                                                                        \
    BPFJ_HEAP_ALLOC_GUARD(struct bpfj_file_match_cached_pattern_str, _str); \
    long _ret = -ENOMEM;                                                    \
    if (_str) {                                                             \
      _ret = bpfj_file_match_cached_get_walked_path(_name, _str);           \
      if (_ret == 0) {                                                      \
        bpfj_heap_read_arena(                                               \
            _buf,                                                           \
            sizeof(_buf) < BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN           \
                ? sizeof(_buf)                                              \
                : BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN,                   \
            _str->pattern);                                                 \
      }                                                                     \
    }                                                                       \
    _ret;                                                                   \
  })

// IMPLEMENTATION

// Iterator for traversing the graph.
struct bpfj_file_match_cached_iter {
  struct bpfj_file_match_node node;
  bool is_being_dropped;
  bool was_matched_this_cycle;
};

struct bpfj_file_match_cached_lock {
  __u64 mount_generation;
  __u32 rename_lock;
};

struct bpfj_file_match_cached_checkpoint {
  __u64 rename_generation;
  __u64 ancestry_bloom[2];
  __u32 iter_count;
  __u32 reserved;
  struct bpfj_file_match_node
      nodes[BPFJ_FILE_MATCH_CACHED_MAX_CHECKPOINT_ITERS];
};

struct bpfj_file_match_cached_state {
  // Current matching state, of struct bpfj_file_match_cached_iter. A vec and
  // not iters[BPFJ_FILE_MATCH_MAX_ITERS]: that array was 640 of this struct's
  // ~1336 bytes and a typical match fills a handful of it. The cap survives as
  // the bound on every loop that walks this, and as a ceiling on what a push
  // will add -- it is no longer what the state costs.
  struct bpfj_vec iters;

  // The dentries walked, leaf first, of uintptr_t. Only read to reconstruct the
  // matched path for an event; another 512 bytes as a fixed array.
  struct bpfj_vec saved_dentries;

  // The ${NAME} bindings this match's globs resolve against
  struct bpfj_glob_bindings bindings;

  // The UUID of the pod for caching
  struct bpfj_uuid uuid;

  // The dentry being matched
  struct dentry* leaf;

  // The canonical mount selected from the target namespace. It starts empty:
  // the hook's mount belongs to the caller's namespace and bind aliases must
  // not decide which policy path is matched.
  uintptr_t mount;

  // The matcher
  struct bpfj_file_matcher __arena* matcher;

  // Mount cache for the current match. Retry callbacks can recover it through
  // the run state, keeping their bpf_loop context to one pointer.
  struct bpfj_mount_cache __arena* mount_cache;

  // Namespace whose root bounds the walk. The descriptor is owned by this
  // invocation rather than task storage because these hooks are not sleepable.
  struct bpfj_mount_descriptor mount_descriptor;
  struct bpfj_shared_ptr mount_snapshot;
  struct bpfj_mount_fallback mount_fallback;

  // Scratch for the component NFA, owned by the walk to avoid another
  // allocation on the verifier's deepest path.
  struct bpfj_glob_run glob_run;

  // Current path component. Keep this with the run state for the same reason:
  // allocating it inside the walk adds a heap-cleanup handle to a stack chain
  // that has no verifier headroom.
  struct bpfj_file_match_name name;

  // Sequence counters sampled around a walk. Keeping them in arena scratch
  // saves another stack slot on the same verifier-limited call chain.
  struct bpfj_file_match_cached_lock walk_lock;

  // Arena scratch for constructing native-map keys. Key construction reads
  // kernel objects and therefore cannot write directly into task storage.
  struct bpfj_file_match_cached_key cache_key;

  __u64 rename_generation;
  __u64 ancestry_bloom[2];

  // Output scratch for move_up. Keeping it here avoids an output local in the
  // walk loop, which is part of the verifier's deepest stack chain.
  uintptr_t walk_next;

  // Namespace root for the current walk. It is live across the retry and path
  // loops, so keeping it in the run state avoids a persistent stack spill.
  uintptr_t walk_root;

  // Current dentry in the path walk. It remains live across matcher calls, so
  // arena scratch keeps it out of the retry callback's verifier frame.
  uintptr_t walk_curr;

  // Shared output for the perf-map lookups in process_indexes. Those lookups
  // are sequential, and their former locals kept 24 bytes live in a frame on
  // the same stack-limited chain.
  u64 lookup_value;

  // Result of the bounded retry callback. Keeping it in the run state lets the
  // retry use bpf_loop without a second numeric iterator in the walk frame.
  long retry_result;
  long component_result;
  __u32 walk_depth;
  __u32 checkpoint_depth;
  bool completed_cycle;
  bool has_pending_checkpoint;

  // The most recent directory frontier is staged in arena memory. A short-
  // lived scratch.h slot is claimed only while publishing it to a native map.
  struct bpfj_file_match_cached_key checkpoint_key;
  struct bpfj_file_match_cached_checkpoint pending_checkpoint;
};

// The iters' sizes are the counts now, so there is no separate count to keep in
// step with them.
static __always_inline __u32 bpfj_file_match_cached_count(
    struct bpfj_file_match_cached_state __arena* state) {
  return bpfj_vec_size(&state->iters);
}

static __always_inline struct bpfj_file_match_cached_iter __arena*
bpfj_file_match_cached_iter_at(
    struct bpfj_file_match_cached_state __arena* state,
    __u32 index) {
  return bpfj_vec_at(&state->iters, index);
}

// Whether this matcher caches its matches at all.
//
// A matcher with caching disabled is walked every time. That is not a
// degenerate state -- it is how an enforcer opts out. A cache is not free: it
// holds entries, and it needs a rename hook to retire them, which runs on every
// rename on the host whether or not this enforcer's paths were involved. For
// hooks rare enough that the walk is cheaper than that, not caching is the
// right answer, and then there is nothing to invalidate either.
static __always_inline bool bpfj_file_match_cached_caches(
    struct bpfj_file_match_cached_state __arena* state) {
  return state->matcher != NULL && state->matcher->cache_cookie != 0;
}

static __always_inline bool bpfj_file_match_cached_leaf_cacheable(
    struct bpfj_file_match_cached_state __arena* state) {
  if (!bpfj_file_match_cached_caches(state)) {
    return false;
  }

  struct dentry* leaf = state->leaf;
  struct inode* inode = BPF_CORE_READ(leaf, d_inode);
  if (inode == NULL) {
    return false;
  }

  // Directories use i_nlink for `.` and child directories, not hard-link
  // aliases. Non-directories with any count other than one have no unique path
  // identity, so an inode-based cache key cannot safely represent them.
  umode_t mode = BPF_CORE_READ(inode, i_mode);
  bool is_dir = (mode & 00170000) == 0040000;
  return is_dir || BPF_CORE_READ(inode, i_nlink) == 1;
}

static __always_inline bool bpfj_file_match_cached_is_dir(uintptr_t dentry) {
  struct inode* inode = BPF_CORE_READ((struct dentry*)dentry, d_inode);
  if (inode == NULL) {
    return false;
  }
  return (BPF_CORE_READ(inode, i_mode) & 00170000) == 0040000;
}

// The position the iter at `index` reached, or -1 if there is no such iter.
static __always_inline s32 bpfj_file_match_cached_pos(
    struct bpfj_file_match_cached_state __arena* state,
    __u32 index) {
  if (state == NULL) {
    return -1;
  }

  struct bpfj_file_match_cached_iter __arena* iter =
      bpfj_file_match_cached_iter_at(state, index);
  return iter != NULL ? iter->node.pos : -1;
}

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, BPFJ_FILE_MATCH_CACHED_CACHE_SIZE);
  __type(key, struct bpfj_file_match_cached_key);
  __type(value, struct bpfj_file_match_cached_entry);
} bpfj_file_match_exact_cache SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, BPFJ_FILE_MATCH_CACHED_CHECKPOINT_SIZE);
  __type(key, struct bpfj_file_match_cached_key);
  __type(value, struct bpfj_file_match_cached_checkpoint);
} bpfj_file_match_checkpoint_cache SEC(".maps");

struct bpfj_file_match_cached_validation {
  __u64 generation;
  __u64 current;
  __u64 bloom[2];
  __u32 valid;
};

struct bpfj_file_match_cached_validation_ctx {
  struct bpfj_file_match_cached_validation* validation;
  struct bpfj_file_match_cached_rename_journal* journal;
};

struct bpfj_file_match_cached_native_scratch {
  struct bpfj_file_match_cached_key key;
  struct bpfj_file_match_cached_entry exact;
  struct bpfj_file_match_cached_checkpoint checkpoint;
  struct bpfj_file_match_cached_validation validation;
};

// Allocate a run state with its vectors initialized. __noinline so the
// allocation and initialization sit in a frame of their own: every hook opens
// with this, and a hook's frame is the first one on the chain through
// file_match_cached that is at the verifier's combined-stack limit.
static __noinline void __arena* bpfj_file_match_cached_state_alloc(void) {
  bpfj_heap_use_arena();

  struct bpfj_file_match_cached_state __arena* state =
      BPFJ_HEAP_ALLOC(sizeof(*state));
  if (state == NULL) {
    return NULL;
  }

  bpfj_vec_init(&state->iters, sizeof(struct bpfj_file_match_cached_iter));
  bpfj_vec_init(&state->saved_dentries, sizeof(uintptr_t));
  bpfj_glob_run_init(&state->glob_run);
  state->leaf = NULL;
  state->mount = 0;
  state->matcher = NULL;
  state->mount_cache = NULL;
  state->mount_descriptor.ns_ino = 0;
  state->mount_descriptor.namespace_addr = 0;
  state->mount_descriptor.mount_generation = 0;
  state->mount_snapshot.buf = NULL;
  state->mount_snapshot.refcount = NULL;
  state->mount_fallback.parent_vfsmount = 0;
  state->mount_fallback.mountpoint = 0;
  state->walk_next = 0;
  state->walk_root = 0;
  state->walk_curr = 0;
  state->lookup_value = 0;
  state->rename_generation = 0;
  state->ancestry_bloom[0] = 0;
  state->ancestry_bloom[1] = 0;
  state->retry_result = 0;
  state->component_result = 0;
  state->walk_depth = 0;
  state->checkpoint_depth = 0;
  state->completed_cycle = false;
  state->has_pending_checkpoint = false;
  return state;
}

// The cleanup half of BPFJ_FILE_MATCH_CACHED_ALLOC: the vecs first, then the
// struct they live in.
static void bpfj_file_match_cached_state_free(
    struct bpfj_file_match_cached_state __arena** ptr) {
  if (ptr == NULL || *ptr == NULL) {
    return;
  }

  struct bpfj_file_match_cached_state __arena* state = *ptr;
  bpfj_shared_ptr_release_arena(&state->mount_snapshot);
  bpfj_glob_run_destroy(&state->glob_run);
  bpfj_vec_destroy(&state->iters);
  bpfj_vec_destroy(&state->saved_dentries);
  BPFJ_HEAP_FREE(state);
  *ptr = NULL;
}

static __always_inline void bpfj_file_match_cached_bloom_add(
    __u64 __arena* bloom,
    uintptr_t dentry) {
  __u64 hash = bpfj_file_match_cached_bloom_hash(dentry);
  bloom[(hash >> 6) & 1] |= 1ULL << (hash & 63);
}

static __always_inline bool bpfj_file_match_cached_bloom_contains(
    __u64 bloom0,
    __u64 bloom1,
    uintptr_t dentry) {
  __u64 hash = bpfj_file_match_cached_bloom_hash(dentry);
  __u64 word = ((hash >> 6) & 1) == 0 ? bloom0 : bloom1;
  return (word & (1ULL << (hash & 63))) != 0;
}

static long bpfj_file_match_cached_validate_generation_cb(
    __u32 index,
    void* data) {
  struct bpfj_file_match_cached_validation_ctx* ctx = data;
  struct bpfj_file_match_cached_validation* validation = ctx->validation;
  if (!validation->valid) {
    return 1;
  }

  __u64 expected = validation->generation + index + 1;
  if (expected > validation->current) {
    return 1;
  }

  struct bpfj_file_match_cached_rename_record* record =
      &ctx->journal->records
           [expected & (BPFJ_FILE_MATCH_CACHED_RENAME_JOURNAL_SIZE - 1)];
  __u64 before = *(volatile __u64*)&record->generation;
  barrier();
  __u64 dentry = *(volatile __u64*)&record->dentry;
  barrier();
  __u64 after = *(volatile __u64*)&record->generation;
  if (before != expected || after != before ||
      bpfj_file_match_cached_bloom_contains(
          validation->bloom[0], validation->bloom[1], dentry)) {
    validation->valid = false;
    return 1;
  }
  return 0;
}

// The checkpoint restore frame is on the verifier's deepest matcher path.
// Keep the bounded journal scan in a bpf_loop callback and its state in task
// storage, leaving only the callback context pointer on the BPF stack.
static __always_inline bool bpfj_file_match_cached_generation_valid(
    struct bpfj_file_match_cached_native_scratch* scratch,
    __u64 generation,
    __u64 bloom0,
    __u64 bloom1) {
  struct bpfj_file_match_cached_rename_journal* journal =
      bpfj_file_match_cached_get_rename_journal();
  if (journal == NULL) {
    return false;
  }
  __u64 current = journal->generation;
  if (generation == current) {
    return true;
  }
  if (generation > current ||
      current - generation > BPFJ_FILE_MATCH_CACHED_RENAME_JOURNAL_SIZE) {
    return false;
  }

  scratch->validation.generation = generation;
  scratch->validation.current = current;
  scratch->validation.bloom[0] = bloom0;
  scratch->validation.bloom[1] = bloom1;
  scratch->validation.valid = true;
  struct bpfj_file_match_cached_validation_ctx ctx = {
      .validation = &scratch->validation,
      .journal = journal,
  };
  bpf_loop(
      BPFJ_FILE_MATCH_CACHED_RENAME_JOURNAL_SIZE,
      bpfj_file_match_cached_validate_generation_cb,
      &ctx,
      0);
  return scratch->validation.valid;
}

// __noinline for the same reason as bpfj_mount_seqcount: its BPF_CORE_READ
// scratch would otherwise sit in file_match_cached's frame, which is on the
// deep chain.
__noinline u32 bpfj_file_match_cached_rename_seqcount() {
  return BPF_CORE_READ(
      ((const seqlock_t*)&rename_lock), seqcount.seqcount.sequence);
}

static __always_inline int bpfj_file_match_cached_process_nodes(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    __s32 nodes_id) {
  const struct bpfj_perf_map __arena* nodes_perf_map = matcher->nodes_perf_map;
  u32 i = 0;
  state->lookup_value = 0;
  bool has_nodes =
      bpfj_perf_map_lookup_arena(
          nodes_perf_map, (u64)nodes_id, &state->lookup_value) == 0;

  if (has_nodes) {
    void __arena* base = (void __arena*)bpfj_heap_ctrl;
    u32 hdr_off = bpfj_heap_clamp_off((u32)state->lookup_value);
    __arena const struct bpfj_perf_map* inner_map =
        (__arena const struct bpfj_perf_map*)((char __arena*)base + hdr_off);
    __u32 count = bpfj_file_match_cached_count(state);
    bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
      if (i >= count) {
        break;
      }
      struct bpfj_file_match_cached_iter __arena* iter =
          bpfj_file_match_cached_iter_at(state, i);
      if (iter == NULL) {
        break;
      }
      u64 node_key =
          (u64)(__u32)iter->node.path_id | ((u64)(__u32)iter->node.pos << 32);
      if (bpfj_perf_map_lookup_arena(
              inner_map, node_key, &state->lookup_value) == 0) {
        iter->was_matched_this_cycle = true;
      }
    }
  }
  return 0;
}

static __always_inline int bpfj_file_match_cached_process_initializers(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    __s32 initializer_nodes_id) {
  state->lookup_value = 0;
  if (bpfj_perf_map_lookup_arena(
          matcher->initializer_perf_map,
          (u64)initializer_nodes_id,
          &state->lookup_value) != 0) {
    return 0;
  }

  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_INITIALIZER_NODES) {
    void __arena* base = (void __arena*)bpfj_heap_ctrl;
    u32 elem_off = (u32)state->lookup_value + i * sizeof(s32);
    elem_off = bpfj_heap_clamp_off(elem_off);
    s32 path_id_val = *(__arena const s32*)((char __arena*)base + elem_off);
    if (path_id_val < 0 ||
        bpfj_file_match_cached_count(state) >= BPFJ_FILE_MATCH_MAX_ITERS) {
      break;
    }
    struct bpfj_file_match_cached_iter __arena* mem =
        bpfj_vec_emplace_back(&state->iters);
    if (mem == NULL) {
      break;
    }
    mem->node.path_id = path_id_val;
    mem->node.pos = 0;
    mem->is_being_dropped = false;
    mem->was_matched_this_cycle = true;
  }
  return 0;
}

static __always_inline bool bpfj_file_match_cached_iter_complete(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_iter __arena* iter __arg_arena) {
  s32 path_id = iter->node.path_id;
  if (path_id < 0 || (__u32)path_id >= matcher->data_entry_count ||
      matcher->path_depths == NULL) {
    return false;
  }
  return (__u32)iter->node.pos >= matcher->path_depths[path_id];
}

// Process node matching and initializer logic for one matched component
// pattern, identified by its packed bpfj_file_match_indexes. Keep the two
// independent loops in separate subprograms so their locals do not occupy one
// verifier frame on the already-deep file-open call chain.
static __always_inline int bpfj_file_match_cached_process_indexes(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    __u64 packed_indexes,
    bool allow_initializers) {
  struct bpfj_file_match_indexes indexes;
  __builtin_memcpy(&indexes, &packed_indexes, sizeof(indexes));
  if (indexes.nodes_id < 0) {
    return 0;
  }

  bpfj_file_match_cached_process_nodes(matcher, state, indexes.nodes_id);
  if (allow_initializers && indexes.initializer_nodes_id >= 0) {
    bpfj_file_match_cached_process_initializers(
        matcher, state, indexes.initializer_nodes_id);
  }

  return 0;
}

// Drop the iters marked for purging, keeping the rest in order.
//
// One compacting pass, where the fixed array needed a shift-down per dropped
// iter and a tombstone to mark the new end -- the vec's size is the end, so
// truncating to the survivors is the whole of it.
static __always_inline long bpfj_file_match_cached_purge(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  __u32 count = bpfj_file_match_cached_count(state);
  __u32 kept = 0;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }

    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      break;
    }
    if (iter->is_being_dropped) {
      continue;
    }

    if (kept != i) {
      struct bpfj_file_match_cached_iter __arena* dst =
          bpfj_file_match_cached_iter_at(state, kept);
      if (dst == NULL) {
        break;
      }
      // Field-wise, for the usual reason, and a plain copy rather than a heap
      // helper because this is inside a bpf_for.
      dst->node.path_id = iter->node.path_id;
      dst->node.pos = iter->node.pos;
      dst->was_matched_this_cycle = iter->was_matched_this_cycle;
      dst->is_being_dropped = iter->is_being_dropped;
    }
    ++kept;
  }

  bpfj_vec_truncate(&state->iters, kept);
  return 0;
}

// Finalize iters after all matching for a dentry step: a matched iter advances,
// a completed ancestor remains available, and an unfinished miss is purged.
static __always_inline long bpfj_file_match_cached_finalize(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  __u32 count = bpfj_file_match_cached_count(state);
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }

    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      break;
    }

    if (iter->was_matched_this_cycle) {
      iter->node.pos += 1;
      iter->is_being_dropped = false;
    } else if (!bpfj_file_match_cached_iter_complete(matcher, iter)) {
      iter->is_being_dropped = true;
    }
    iter->was_matched_this_cycle = false;
  }

  return 0;
}

// Finalize pod masks then purge dead iters. Called once per dentry step.
static __always_inline long bpfj_file_match_cached_finalize_and_purge(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  bpfj_file_match_cached_finalize(state->matcher, state);
  bpfj_file_match_cached_purge(state);

  return 0;
}

static __always_inline long bpfj_file_match_cached_purge_incomplete(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  __u32 count = bpfj_file_match_cached_count(state);
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }
    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      break;
    }
    iter->is_being_dropped =
        !bpfj_file_match_cached_iter_complete(state->matcher, iter);
  }
  return bpfj_file_match_cached_purge(state);
}

struct bpfj_file_match_cached_process_ctx {
  struct bpfj_file_match_cached_state __arena* state;
  bool allow_initializers;
};

// Keep the glob result walk outside the matcher call chain. A numeric iterator
// here would remain live while process_indexes runs and push the verifier's
// combined stack over the 512-byte limit.
static long bpfj_file_match_cached_process_cb(__u32 index, void* data) {
  struct bpfj_file_match_cached_process_ctx* ctx = data;
  struct bpfj_file_match_cached_state __arena* state = ctx->state;
  u64 __arena* result = bpfj_glob_map_result_at(&state->glob_run, index);
  if (result == NULL) {
    state->component_result = -ENOMEM;
    return 1;
  }

  state->component_result = bpfj_file_match_cached_process_indexes(
      state->matcher, state, *result, ctx->allow_initializers);
  return state->component_result < 0;
}

// Match a dentry name against every component pattern (literal, '*'/'?'
// wildcard, or ${VAR} variable) via the single glob NFA, then fold each
// matching pattern's nodes/initializers into the active iters. Replaces the
// former three-way lookup (names_map literal, globs_perf_map per-node, and
// var_id_to_node_perf_map per-pod).
// `run` is the walk's run state, bound once in file_match_cached against the
// compiled map and this match's variable bindings. A run bound to a NULL header
// -- nothing compiled -- matches nothing.
static __always_inline long bpfj_file_match_cached_nodes(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    struct bpfj_file_match_name __arena* name __arg_arena,
    long size,
    bool allow_initializers) {
  u64 len = size - 1; // Drop null term
  if (len > BPFJ_FILE_MATCH_NAME_LEN) {
    len = BPFJ_FILE_MATCH_NAME_LEN;
  }

  long n = bpfj_glob_map_lookup(&state->glob_run, name->name, (u32)len);
  if (n < 0) {
    return n;
  }

  struct bpfj_file_match_cached_process_ctx ctx = {
      .state = state,
      .allow_initializers = allow_initializers,
  };
  state->component_result = 0;
  bpf_loop((u32)n, bpfj_file_match_cached_process_cb, &ctx, 0);
  return state->component_result;
}

__noinline long bpfj_file_match_cached_move_up(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    uintptr_t dentry,
    uintptr_t root) {
  state->walk_next = 0;
  if (dentry == root) {
    BPFJ_DBG_LOG("file_match_cached: Reached root");
    return 1;
  }

  struct dentry* parent = BPF_CORE_READ((struct dentry*)dentry, d_parent);
  struct dentry* gparent = BPF_CORE_READ(parent, d_parent);

  uintptr_t curr_mount_vfsmnt = state->mount;
  if (curr_mount_vfsmnt != 0) {
    struct mount* curr_mount =
        container_of((struct vfsmount*)curr_mount_vfsmnt, struct mount, mnt);
    struct mnt_namespace* curr_namespace = BPF_CORE_READ(curr_mount, mnt_ns);
    uintptr_t mount_root =
        (uintptr_t)BPF_CORE_READ((struct vfsmount*)curr_mount_vfsmnt, mnt_root);
    uintptr_t mountpoint = (uintptr_t)BPF_CORE_READ(curr_mount, mnt_mountpoint);
    if ((uintptr_t)curr_namespace == state->mount_descriptor.namespace_addr &&
        mount_root == (uintptr_t)parent) {
      struct mount* parent_mount = BPF_CORE_READ(curr_mount, mnt_parent);
      uintptr_t parent_mount_vfsmnt =
          parent_mount ? (uintptr_t)&parent_mount->mnt : 0;
      if (mountpoint == (uintptr_t)parent) {
        BPFJ_DBG_LOG("file_match_cached: Reached root mount");
        // PID 1 supplies both the namespace and policy root, so its
        // self-parented mount is authoritative even when stacked root mounts
        // give it a different dentry alias.
        if (mountpoint == root || parent_mount == curr_mount) {
          return 1;
        }
        state->mount = parent_mount_vfsmnt;
        state->walk_next = mountpoint;
        return 0;
      }

      bool parent_is_subvol_root =
          BPF_CORE_READ(parent, d_inode, i_op) == &btrfs_dir_inode_operations &&
          BPF_CORE_READ(parent, d_inode, i_ino) == BTRFS_FIRST_FREE_OBJECTID;
      if (parent_is_subvol_root) {
        state->mount = parent_mount_vfsmnt;
        if (mountpoint == root) {
          BPFJ_DBG_LOG("file_match_cached: Reached parent root mount");
          return 1;
        }
        state->walk_next = mountpoint;
        BPFJ_DBG_LOG(
            "file_match_cached: Found mount, moving up to %p",
            state->walk_next);
        return 0;
      }

      if (gparent == parent && mountpoint != 0) {
        state->mount = parent_mount_vfsmnt;
        if (mountpoint == root) {
          BPFJ_DBG_LOG("file_match_cached: Reached parent root mount");
          return 1;
        }
        if (mountpoint == (uintptr_t)parent) {
          BPFJ_DBG_LOG("file_match_cached: Reached root mount");
          if (parent_mount == curr_mount) {
            return 1;
          }
          state->walk_next = mountpoint;
          return 0;
        }

        state->walk_next = mountpoint;
        BPFJ_DBG_LOG(
            "file_match_cached: Crossing same-ns root mount to %p",
            state->walk_next);
        return 0;
      }
    }
  }

  // We skip the root node, because it is not a real node, it is covered by the
  // mount
  if (gparent == parent) {
    BPFJ_DBG_LOG("file_match_cached: Reached dentry root");
    if ((uintptr_t)parent == root) {
      BPFJ_DBG_LOG("file_match_cached: Dentry root is target root, stopping");
      return 1;
    }
    long ret = bpfj_mount_find_parent(
        state->mount_snapshot.buf, (uintptr_t)parent, &state->mount_fallback);
    if (ret == 0) {
      uintptr_t mountpoint = state->mount_fallback.mountpoint;
      state->mount = state->mount_fallback.parent_vfsmount;
      if (mountpoint == root) {
        return 1;
      }
      if (mountpoint == (uintptr_t)parent) {
        state->walk_next = mountpoint;
        return 0;
      }
      state->walk_next = mountpoint;
      return 0;
    }
    if (ret != -ENOENT) {
      return ret;
    }
  } else {
    // If the parent IS the root, stop here instead of returning it as the
    // next dentry to process. The root dentry's name (e.g. a btrfs subvol
    // ID) is not a path component and would spuriously fail to match.
    if ((uintptr_t)parent == root) {
      BPFJ_DBG_LOG("file_match_cached: Parent is root, stopping");
      return 1;
    }
    bool parent_is_subvol_root =
        BPF_CORE_READ(parent, d_inode, i_op) == &btrfs_dir_inode_operations &&
        BPF_CORE_READ(parent, d_inode, i_ino) == BTRFS_FIRST_FREE_OBJECTID;
    if (parent_is_subvol_root) {
      long ret = bpfj_mount_find_parent(
          state->mount_snapshot.buf, (uintptr_t)parent, &state->mount_fallback);
      if (ret == 0) {
        uintptr_t mountpoint = state->mount_fallback.mountpoint;
        state->mount = state->mount_fallback.parent_vfsmount;
        if (mountpoint == root) {
          return 1;
        }
        if (mountpoint != 0 && mountpoint != (uintptr_t)parent) {
          state->walk_next = mountpoint;
          return 0;
        }
      } else if (ret != -ENOENT) {
        return ret;
      }
    }
    BPFJ_DBG_LOG("file_match_cached: Moving up to %p", parent);
    state->walk_next = (uintptr_t)parent;
    return 0;
  }

  // A dentry-tree root that no mount is rooted at: there is nowhere left to
  // climb, and the walk stopped before it could reach `root`. The components
  // gathered so far are a path inside some other namespace's filesystem, not a
  // path in the target namespace, so matching them against the target's policy
  // would compare unrelated paths -- a private-ns tmpfs holding /data/inner
  // would match a rule written for the root ns /data/inner.
  //
  // -EXDEV is the signal v1 gives for exactly this ("not our namespace", see
  // file.h:502 ending the walk and file.h:611 reporting it), and both fs2
  // callers already treat it as benign and allow without logging. Returning the
  // raw -ENOENT instead is what made every containerized open on the fs2 path
  // log "Error matching" and fail open.
  return -EXDEV;
}

__attribute__((noinline)) long bpfj_file_match_cached_save_name(
    struct bpfj_file_match_name __arena* name __arg_arena,
    uintptr_t dentry) {
  if (!dentry) {
    return -EINVAL;
  }

  // TODO this is gross
  void* hash_len_ptr = (unsigned char*)dentry +
      offsetof(struct dentry, d_name) + offsetof(struct qstr, hash_len);
  u64 hash_len = 0;
  bpf_probe_read_kernel(&hash_len, sizeof(hash_len), hash_len_ptr);

  size_t len = bpfj_file_hashlen_len(hash_len) + 1;
  len = len < sizeof(name->name) ? len : sizeof(name->name);

  void* name_dptr = (unsigned char*)dentry + offsetof(struct dentry, d_name) +
      offsetof(struct qstr, name);
  const unsigned char* name_ptr = NULL;
  bpf_probe_read_kernel(&name_ptr, sizeof(name_ptr), name_dptr);
  long ret = bpfj_heap_read_kernel(name->name, len, (__u64)(uintptr_t)name_ptr);
  if (ret < 0) {
    return ret;
  }

  BPFJ_DBG_LOG("file_match_cached: read name=%s", name->name);

  // Check for the root node which has the name "/". It is the only node that
  // can have a slash in the name. We just replace it with an empty name,
  // because having a / in the name is confusing.
  ret = len;
  if (ret == 2 && name->name[0] == '/') {
    --ret;
    name->name[0] = '\0';
  }

  return ret;
}

long bpfj_file_match_cached_init(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  // Clearing keeps both buffers, which is what makes a retry cheap: the
  // capacity the last attempt grew to is still there. It also replaces
  // tombstoning all 64 iter slots, because there is no slot that is not an
  // element any more.
  bpfj_vec_clear(&state->iters);
  bpfj_vec_clear(&state->saved_dentries);
  state->mount = 0;
  bpfj_shared_ptr_release_arena(&state->mount_snapshot);
  state->mount_descriptor.ns_ino = 0;
  state->mount_descriptor.namespace_addr = 0;
  state->mount_descriptor.mount_generation = 0;
  state->mount_fallback.parent_vfsmount = 0;
  state->mount_fallback.mountpoint = 0;
  state->rename_generation = 0;
  state->ancestry_bloom[0] = 0;
  state->ancestry_bloom[1] = 0;
  state->has_pending_checkpoint = false;

  BPFJ_DBG_LOG("file_match_cached: Initialized");

  return 0;
}

__attribute__((noinline)) long bpfj_file_match_cached_get_root(pid_t pid) {
  struct task_struct* task = bpf_task_from_pid(pid);
  if (!task) {
    return 0;
  }

  struct dentry* root = task->fs->root.dentry;
  bpf_task_release(task);

  // Force the verifier to treat pointer as a scalar
  long out = 0;
  bpf_probe_read_kernel(&out, sizeof(out), &root);
  return out;
}

// static __always_inline, not a global subprogram: the run state is written
// field-wise here, and an __arg_arena parameter does not survive the global
// call boundary on 6.11 -- the verifier hands the callee a scalar and rejects
// the first store through it. Inlined, the pointer keeps the provenance it has
// in the caller, which is the frame that allocated it.
static __always_inline long bpfj_file_match_cached_setup(
    struct bpfj_file_match_cached_state __arena* state,
    struct bpfj_uuid* uuid __arg_nonnull) {
  bpfj_heap_use_arena();
  bpfj_heap_zero_arena(&state->bindings, sizeof(state->bindings));

  if (uuid) {
    bpfj_heap_write_arena(&state->uuid, sizeof(state->uuid), uuid);
  } else {
    bpfj_heap_zero_arena(&state->uuid, sizeof(state->uuid));
  }

  return 0;
}

// Bind the run state to a matcher and a dentry, without running the match or
// filling in its variable bindings. BPFJ_FILE_MATCH_CACHED_DEFINE_BIND builds
// the variant that does both, which is what a match needs; this one is for a
// cache check, which evaluates no glob.
//
// Out of line, and split from the match it precedes, purely for stack. Inlined,
// the binding's scratch lands in the caller's frame, and the caller is frame
// one of the chain through file_match_cached that sits at the verifier's
// 512-byte combined limit. This calls nothing, so out of line it is a leaf and
// its frame never joins that chain -- where an out-of-line wrapper around the
// match itself would just move the whole chain a frame deeper.
//
// static, not global: bpfj_file_match_cached_setup has to be inlined into it
// (see the note there about __arg_arena and the global call boundary), and that
// only holds if this keeps the caller's provenance too.
static __noinline void bpfj_file_match_cached_bind(
    struct bpfj_file_match_cached_state __arena* state,
    struct bpfj_file_matcher __arena* matcher,
    uintptr_t dentry,
    struct bpfj_uuid* uuid) {
  bpfj_file_match_cached_setup(state, uuid);
  state->leaf = (struct dentry*)dentry;
  state->matcher = matcher;
}

// Declare `_fn`, bpfj_file_match_cached_bind plus filling in the state's glob
// bindings from a `const _vars_type*` through `_binder`, which takes
// (struct bpfj_glob_bindings __arena* out, const _vars_type* vars). One per var
// type, since BPF cannot call through a pointer.
//
// One call rather than a bind followed by the binder: the hook calling them is
// frame one of the chain at the 512-byte limit, and a second call there costs
// it a spill slot that chain does not have.
#define BPFJ_FILE_MATCH_CACHED_DEFINE_BIND(_fn, _binder, _vars_type) \
  static __noinline void _fn(                                        \
      struct bpfj_file_match_cached_state __arena* state,            \
      struct bpfj_file_matcher __arena* matcher,                     \
      uintptr_t dentry,                                              \
      struct bpfj_uuid* uuid,                                        \
      const _vars_type* vars) {                                      \
    bpfj_file_match_cached_setup(state, uuid);                       \
    _binder(&state->bindings, vars);                                 \
    state->leaf = (struct dentry*)dentry;                            \
    state->matcher = matcher;                                        \
  }

static u64 bpfj_file_match_cached_subvol(struct inode* inode) {
  if (inode == NULL) {
    return 0;
  }
  struct super_block* sb = BPF_CORE_READ(inode, i_sb);
  if (sb == NULL || BPF_CORE_READ(sb, s_magic) != BPFJ_BTRFS_SUPER_MAGIC) {
    return 0;
  }

  struct btrfs_root* root = BPF_CORE_READ(BTRFS_I(inode), root);
  if (!root) {
    return 0;
  }

  return BPF_CORE_READ(root, root_key.objectid);
}

long bpfj_file_match_cached_build_key_for_dentry(
    struct bpfj_file_match_cached_key __arena* key __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    uintptr_t dentry) {
  // Field-wise: a memset of arena memory drops the address space. The key is
  // hashed as raw words, so every byte is explicitly initialized.
  key->ino = 0;
  key->subvol = 0;
  bpfj_heap_copy_arena(&key->uuid, &state->uuid, sizeof(key->uuid));
  key->matcher = state->matcher->cache_cookie;
  key->dev = 0;
  key->reserved = 0;
  if (state->mount_descriptor.namespace_addr != 0) {
    key->mount_generation = state->mount_descriptor.mount_generation;
  } else {
    key->mount_generation = bpfj_mount_root_generation();
  }

  // TODO: remove BPF_CORE_READ
  key->dev = BPF_CORE_READ((struct dentry*)dentry, d_sb, s_dev);
  key->ino = BPF_CORE_READ((struct dentry*)dentry, d_inode, i_ino);
  key->subvol = bpfj_file_match_cached_subvol(
      BPF_CORE_READ((struct dentry*)dentry, d_inode));

  return 0;
}

static __always_inline long bpfj_file_match_cached_build_key(
    struct bpfj_file_match_cached_key __arena* key,
    struct bpfj_file_match_cached_state __arena* state) {
  return bpfj_file_match_cached_build_key_for_dentry(
      key, state, (uintptr_t)state->leaf);
}

// GLOBAL (__noinline), and deliberately not inlined into either caller: the
// five-argument BPF_SNPRINTF below needs a 40-byte argument array on the stack,
// and both callers are folded into file_match_cached, which sits on the
// program's deepest matcher call chain. Out of line, the two arrays live in a
// leaf frame that the mount and glob traversal paths never enter. The key is
// read back from the scratch map rather than passed in, so this needs no
// argument but the label.
//
// Returns a scalar (unused) because a global subprogram must, same as
// bpfj_file_match_cached_process_indexes.
__noinline long bpfj_file_match_cached_log_key(
    struct bpfj_file_match_cached_key __arena* key __arg_arena,
    int saving) {
  if (saving) {
    BPFJ_LOG(
        "file_match_cached: Saving to cache with key: "
        "dev=0x%lu ino=%lu subvol=%lu",
        key->dev,
        key->ino,
        key->subvol);
  } else {
    BPFJ_LOG(
        "file_match_cached: Checking cache with key: "
        "dev=0x%lu ino=%lu subvol=%lu",
        key->dev,
        key->ino,
        key->subvol);
  }

  return 0;
}

long bpfj_file_match_cached_check_file_cache(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  if (!bpfj_file_match_cached_leaf_cacheable(state)) {
    return -ENOENT;
  }

  struct bpfj_file_match_cached_key __arena* key = &state->cache_key;
  long ret = bpfj_file_match_cached_build_key(key, state);
  if (ret < 0) {
    return ret;
  }

  if (bpfj_dbg_mode) {
    bpfj_file_match_cached_log_key(key, false);
  }

  BPFJ_SCRATCH_GUARD(struct bpfj_file_match_cached_native_scratch, scratch);
  if (scratch == NULL) {
    return -ENOMEM;
  }
  long result = -ENOENT;
  bpfj_heap_read_arena(&scratch->key, sizeof(scratch->key), key);
  struct bpfj_file_match_cached_entry* live_entry =
      bpf_map_lookup_elem(&bpfj_file_match_exact_cache, &scratch->key);
  if (live_entry == NULL) {
    volatile __u64* stats = bpfj_file_match_cached_stats_for_cpu();
    __sync_fetch_and_add(&stats[BPFJ_FILE_MATCH_CACHED_STAT_MISS], 1);
    goto out;
  }
  if (bpf_probe_read_kernel(
          &scratch->exact, sizeof(scratch->exact), live_entry) != 0) {
    goto out;
  }
  struct bpfj_file_match_cached_entry* entry = &scratch->exact;

  __u32 iter_count = entry->iter_count;
  __u32 dentry_count = entry->dentry_count;
  if (iter_count > BPFJ_FILE_MATCH_MAX_ITERS ||
      dentry_count > BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES) {
    // Counts come back out of the arena, and every loop that walks these is
    // bounded by the caps, so an entry claiming more than that would be read
    // short. Treat it as a miss rather than as a partial answer.
    volatile __u64* stats = bpfj_file_match_cached_stats_for_cpu();
    __sync_fetch_and_add(&stats[BPFJ_FILE_MATCH_CACHED_STAT_INVALID], 1);
    bpf_map_delete_elem(&bpfj_file_match_exact_cache, &scratch->key);
    goto out;
  }
  if (!bpfj_file_match_cached_generation_valid(
          scratch,
          entry->rename_generation,
          entry->ancestry_bloom[0],
          entry->ancestry_bloom[1])) {
    volatile __u64* stats = bpfj_file_match_cached_stats_for_cpu();
    __sync_fetch_and_add(&stats[BPFJ_FILE_MATCH_CACHED_STAT_INVALID], 1);
    bpf_map_delete_elem(&bpfj_file_match_exact_cache, &scratch->key);
    goto out;
  }
  __u64 mount_generation = bpfj_mount_root_generation();
  if (scratch->key.mount_generation != mount_generation) {
    result = -EBUSY;
    goto out;
  }

  BPFJ_DBG_LOG("file_match_cached: Cache hit: %p", entry);
  volatile __u64* stats = bpfj_file_match_cached_stats_for_cpu();
  __sync_fetch_and_add(&stats[BPFJ_FILE_MATCH_CACHED_STAT_HIT], 1);

  // Only the walk's output. This used to copy the whole run state over itself,
  // which also replaced the matcher, uuid and variable bindings that bind had
  // just put there -- harmless only because the entry was keyed by the uuid
  // whose state it was. Restoring the two vecs leaves the inputs alone.
  bpfj_vec_clear(&state->saved_dentries);
  bpfj_vec_clear(&state->iters);
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES) {
    if (i >= dentry_count) {
      break;
    }
    uintptr_t __arena* dentry = bpfj_vec_emplace_back(&state->saved_dentries);
    if (dentry == NULL) {
      result = -ENOMEM;
      goto out;
    }
    *dentry = entry->dentries[i];
  }
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= iter_count) {
      break;
    }
    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_vec_emplace_back(&state->iters);
    if (iter == NULL) {
      result = -ENOMEM;
      goto out;
    }
    iter->node.path_id = entry->nodes[i].path_id;
    iter->node.pos = entry->nodes[i].pos;
    iter->is_being_dropped = false;
    iter->was_matched_this_cycle = false;
  }

  result = (long)iter_count;

out:
  return result;
}

// The LRU insertion path is the deepest cached-matcher branch. Inline this
// orchestration layer so the allocator remains below the verifier call cap.
static __always_inline long bpfj_file_match_cached_save_file_cache(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  if (!bpfj_file_match_cached_leaf_cacheable(state)) {
    return 0;
  }

  struct bpfj_file_match_cached_key __arena* key = &state->cache_key;
  long ret = bpfj_file_match_cached_build_key(key, state);
  if (ret < 0) {
    return ret;
  }

  if (bpfj_dbg_mode) {
    bpfj_file_match_cached_log_key(key, true);
  }

  __u32 iter_count = bpfj_file_match_cached_count(state);
  __u32 dentry_count = bpfj_vec_size(&state->saved_dentries);
  if (dentry_count > BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES) {
    return 0;
  }

  BPFJ_SCRATCH_GUARD(struct bpfj_file_match_cached_native_scratch, scratch);
  if (scratch == NULL) {
    return -ENOMEM;
  }
  bpfj_heap_read_arena(&scratch->key, sizeof(scratch->key), key);
  struct bpfj_file_match_cached_entry* cached = &scratch->exact;

  cached->rename_generation = state->rename_generation;
  cached->ancestry_bloom[0] = state->ancestry_bloom[0];
  cached->ancestry_bloom[1] = state->ancestry_bloom[1];
  cached->iter_count = iter_count;
  cached->dentry_count = dentry_count;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES) {
    if (i >= dentry_count) {
      break;
    }
    uintptr_t __arena* dentry = bpfj_vec_at(&state->saved_dentries, i);
    if (dentry == NULL) {
      break;
    }
    cached->dentries[i] = *dentry;
  }
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= iter_count) {
      break;
    }
    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      break;
    }
    cached->nodes[i].path_id = iter->node.path_id;
    cached->nodes[i].pos = iter->node.pos;
  }

  // Entries are immutable after publication. Preserve an answer another CPU
  // published while this CPU walked the path.
  long update_ret = bpf_map_update_elem(
      &bpfj_file_match_exact_cache, &scratch->key, cached, BPF_NOEXIST);
  if (update_ret < 0) {
    volatile __u64* stats = bpfj_file_match_cached_stats_for_cpu();
    if (update_ret == -EEXIST) {
      __sync_fetch_and_add(
          &stats[BPFJ_FILE_MATCH_CACHED_STAT_INSERT_EXISTS], 1);
    } else if (update_ret == -EBUSY) {
      __sync_fetch_and_add(&stats[BPFJ_FILE_MATCH_CACHED_STAT_INSERT_BUSY], 1);
    } else {
      __sync_fetch_and_add(&stats[BPFJ_FILE_MATCH_CACHED_STAT_INSERT_ERROR], 1);
    }
  }
  return update_ret;
}

struct bpfj_file_match_cached_save_ctx {
  struct bpfj_file_match_cached_state __arena* state;
};

static long bpfj_file_match_cached_save_file_cache_cb(
    __u32 unused,
    void* data) {
  (void)unused;
  struct bpfj_file_match_cached_save_ctx* ctx = data;
  struct bpfj_file_match_cached_state __arena* state = ctx->state;
  struct bpfj_file_match_cached_rename_journal* journal =
      bpfj_file_match_cached_get_rename_journal();
  if (journal == NULL) {
    return 1;
  }
  state->rename_generation = journal->generation;
  if (state->walk_lock.rename_lock !=
      bpfj_file_match_cached_rename_seqcount()) {
    return 1;
  }
  if (state->has_pending_checkpoint) {
    BPFJ_SCRATCH_GUARD(struct bpfj_file_match_cached_native_scratch, scratch);
    if (scratch != NULL) {
      state->pending_checkpoint.rename_generation = state->rename_generation;
      bpfj_heap_read_arena(
          &scratch->key, sizeof(scratch->key), &state->checkpoint_key);
      bpfj_heap_read_arena(
          &scratch->checkpoint,
          sizeof(scratch->checkpoint),
          &state->pending_checkpoint);
      bpf_map_update_elem(
          &bpfj_file_match_checkpoint_cache,
          &scratch->key,
          &scratch->checkpoint,
          BPF_NOEXIST);
    }
  }
  bpfj_file_match_cached_save_file_cache(state);
  return 1;
}

// Keep debug formatting and its bounded iterator off the verifier-limited
// matcher path. This runs only after the match has completed.
static __noinline long bpfj_file_match_cached_dbg_print(
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  __u32 count = bpfj_file_match_cached_count(state);
  BPFJ_LOG("file_match_cached: Done, found %u matches", count);

  __arena const struct bpfj_file_match_cached_pattern_str* pattern_strs =
      matcher->pattern_strs;
  __u32 num_pattern_strs = matcher->num_pattern_strs;

  if (pattern_strs == NULL || num_pattern_strs == 0) {
    return 0;
  }

  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_MAX_ITERS) {
    if (i >= count) {
      break;
    }

    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      break;
    }
    BPFJ_LOG(
        "file_match_cached: Iter %d,%d", iter->node.path_id, iter->node.pos);

    if ((__u32)iter->node.path_id >= num_pattern_strs) {
      BPFJ_LOG("file_match_cached: Failed to lookup pattern string");
      continue;
    }

    __arena const struct bpfj_file_match_cached_pattern_str* pattern_str =
        pattern_strs + (__u32)iter->node.path_id;

    BPFJ_LOG("file_match_cached: matched pattern: %s", pattern_str->pattern);
  }

  return 0;
}

// Event formatting can sit on top of the matcher's already-deep call chain.
// Keep this inline so callers do not exceed the verifier's eight-frame limit.
static __always_inline long bpfj_file_match_cached_get_walked_path(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    struct bpfj_file_match_cached_pattern_str __arena* str __arg_arena) {
  char __arena* path = str->pattern;

  // Every bound below is the size of `path`, which is a pattern_str and NOT
  // BPFJ_FILE_MATCH_CACHED_BUF_SIZE: the two differ, and bounding a write to
  // the larger one runs off the end of the block and corrupts the arena heap.
  // Masks require a power of two.
  _Static_assert(
      (BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN &
       (BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN - 1)) == 0,
      "pattern_str length must be a power of two to mask against");
  _Static_assert(
      BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN > BPFJ_FILE_MATCH_NAME_LEN,
      "a single component has to fit in the walked-path buffer");

  u32 off = 0;
  u32 i;
  __u32 depth = bpfj_vec_size(&state->saved_dentries);
  BPFJ_DBG_LOG("file_match_cached: Saved dentries depth: %u", depth);
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_SAVED_DENTRIES) {
    if (i >= depth) {
      break;
    }

    // Walked leaf first, so the path is assembled from the far end back.
    uintptr_t __arena* saved =
        bpfj_vec_at(&state->saved_dentries, depth - i - 1);
    if (saved == NULL) {
      break;
    }

    uintptr_t dentry = *saved;
    const unsigned char* name_ptr =
        BPF_CORE_READ((struct dentry*)dentry, d_name.name);
    if (!name_ptr) {
      continue;
    }

    BPFJ_DBG_LOG(
        "file_match_cached: Saved dentry %u name: %s", depth - i - 1, name_ptr);

    u64 hash_len_val = BPF_CORE_READ((struct dentry*)dentry, d_name.hash_len);
    u32 len = bpfj_file_hashlen_len(hash_len_val);
    len &= (BPFJ_FILE_MATCH_NAME_LEN - 1);

    char c = '\0';
    bpf_probe_read_kernel(&c, sizeof(c), name_ptr);
    if (c == '\0' || c == '/') {
      // Skip empty and root names
      continue;
    }

    off &= (BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN - 1);
    if (off >=
        BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN - BPFJ_FILE_MATCH_NAME_LEN) {
      break;
    }
    path[off++] = '/';

    long ret =
        bpfj_heap_read_kernel(path + off, len, (__u64)(uintptr_t)name_ptr);
    if (ret < 0) {
      return ret;
    }

    off += len;
  }

  off &= (BPFJ_FILE_MATCH_CACHED_PATTERN_STR_LEN - 1);
  path[off] = '\0';

  BPFJ_DBG_LOG("file_match_cached: Walked path: %s", path);

  return 0;
}

static __noinline long bpfj_file_match_cached_restore_checkpoint_nodes(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    struct bpfj_file_match_cached_checkpoint* checkpoint) {
  bpfj_vec_clear(&state->iters);
  __u32 count = checkpoint->iter_count;
  u32 j = 0;
  bpf_for(j, 0, BPFJ_FILE_MATCH_CACHED_MAX_CHECKPOINT_ITERS) {
    if (j >= count) {
      break;
    }
    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_vec_emplace_back(&state->iters);
    if (iter == NULL) {
      return -ENOMEM;
    }
    iter->node.path_id = checkpoint->nodes[j].path_id;
    iter->node.pos = checkpoint->nodes[j].pos;
    iter->is_being_dropped = false;
    iter->was_matched_this_cycle = false;
  }
  return 0;
}

static __noinline long bpfj_file_match_cached_restore_checkpoint(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  if (!bpfj_file_match_cached_caches(state)) {
    return 0;
  }
  BPFJ_SCRATCH_GUARD(struct bpfj_file_match_cached_native_scratch, scratch);
  if (scratch == NULL) {
    return 0;
  }

  __u32 depth = bpfj_vec_size(&state->saved_dentries);
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_RECURSION) {
    if (i >= depth) {
      break;
    }
    uintptr_t __arena* saved = bpfj_vec_at(&state->saved_dentries, i);
    if (saved == NULL || !bpfj_file_match_cached_is_dir(*saved)) {
      continue;
    }

    struct bpfj_file_match_cached_key __arena* key = &state->cache_key;
    long ret = bpfj_file_match_cached_build_key_for_dentry(key, state, *saved);
    if (ret < 0) {
      return ret;
    }
    bpfj_heap_read_arena(&scratch->key, sizeof(scratch->key), key);
    struct bpfj_file_match_cached_checkpoint* live_checkpoint =
        bpf_map_lookup_elem(&bpfj_file_match_checkpoint_cache, &scratch->key);
    if (live_checkpoint == NULL) {
      continue;
    }
    if (bpf_probe_read_kernel(
            &scratch->checkpoint,
            sizeof(scratch->checkpoint),
            live_checkpoint) != 0) {
      continue;
    }
    struct bpfj_file_match_cached_checkpoint* checkpoint = &scratch->checkpoint;
    if (checkpoint->iter_count > BPFJ_FILE_MATCH_CACHED_MAX_CHECKPOINT_ITERS ||
        !bpfj_file_match_cached_generation_valid(
            scratch,
            checkpoint->rename_generation,
            checkpoint->ancestry_bloom[0],
            checkpoint->ancestry_bloom[1])) {
      bpf_map_delete_elem(&bpfj_file_match_checkpoint_cache, &scratch->key);
      continue;
    }

    long restore_ret =
        bpfj_file_match_cached_restore_checkpoint_nodes(state, checkpoint);
    if (restore_ret < 0) {
      return restore_ret;
    }
    state->rename_generation = checkpoint->rename_generation;
    state->ancestry_bloom[0] = checkpoint->ancestry_bloom[0];
    state->ancestry_bloom[1] = checkpoint->ancestry_bloom[1];
    return (long)(depth - i);
  }
  return 0;
}

// Stage the most recently matched directory frontier in arena memory.
// Publication happens only after the rename and mount sequence counters are
// stable, avoiding both inconsistent entries and one LRU update per component.
static __noinline long bpfj_file_match_cached_stage_checkpoint(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    uintptr_t dentry) {
  if (!bpfj_file_match_cached_caches(state) ||
      !bpfj_file_match_cached_is_dir(dentry)) {
    return 0;
  }

  __u32 count = bpfj_file_match_cached_count(state);
  if (count > BPFJ_FILE_MATCH_CACHED_MAX_CHECKPOINT_ITERS) {
    return 0;
  }
  struct bpfj_file_match_cached_checkpoint __arena* checkpoint =
      &state->pending_checkpoint;
  checkpoint->rename_generation = state->rename_generation;
  checkpoint->ancestry_bloom[0] = state->ancestry_bloom[0];
  checkpoint->ancestry_bloom[1] = state->ancestry_bloom[1];
  checkpoint->iter_count = count;
  checkpoint->reserved = 0;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_CHECKPOINT_ITERS) {
    if (i >= count) {
      break;
    }
    struct bpfj_file_match_cached_iter __arena* iter =
        bpfj_file_match_cached_iter_at(state, i);
    if (iter == NULL) {
      return 0;
    }
    checkpoint->nodes[i].path_id = iter->node.path_id;
    checkpoint->nodes[i].pos = iter->node.pos;
  }

  struct bpfj_file_match_cached_key __arena* key = &state->checkpoint_key;
  long ret = bpfj_file_match_cached_build_key_for_dentry(key, state, dentry);
  if (ret < 0) {
    return ret;
  }
  state->has_pending_checkpoint = true;
  return 0;
}

static __always_inline long file_match_cached_internal_loop(
    struct bpfj_file_match_cached_state __arena* state __arg_arena) {
  state->walk_curr = (uintptr_t)state->leaf;

  // Bound once: the compiled map and this match's variable bindings are the
  // same for every component. A NULL glob_map -- nothing compiled -- leaves the
  // run matching nothing, exactly as before.
  bpfj_glob_run_bind(
      &state->glob_run, state->matcher->glob_map, &state->bindings);
  bool reached_root = false;
  u32 i = 0;
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_RECURSION) {
    // A self-parented dentry is a filesystem root, not a path component. A
    // namespace may have several whole-filesystem mounts stacked at `/`, so a
    // mount transition can yield another such dentry before reaching `root`.
    // Resolve through it without feeding an empty component to the matcher.
    uintptr_t curr = state->walk_curr;
    struct dentry* curr_parent = BPF_CORE_READ((struct dentry*)curr, d_parent);
    if ((uintptr_t)curr_parent == curr) {
      long ret = bpfj_file_match_cached_move_up(
          state, state->walk_curr, state->walk_root);
      if (ret < 0) {
        return ret;
      }
      if (ret > 0) {
        reached_root = true;
        state->walk_curr = 0;
        break;
      }
      if (state->walk_next == 0) {
        state->walk_curr = 0;
        break;
      }
      state->walk_curr = state->walk_next;
      continue;
    }

    uintptr_t __arena* saved = bpfj_vec_emplace_back(&state->saved_dentries);
    if (saved == NULL) {
      return -ENOMEM;
    }
    *saved = state->walk_curr;

    long ret = bpfj_file_match_cached_move_up(
        state, state->walk_curr, state->walk_root);
    if (ret < 0) {
      return ret;
    }
    if (ret > 0) {
      reached_root = true;
      state->walk_curr = 0;
      break;
    }
    if (state->walk_next == 0) {
      state->walk_curr = 0;
      break;
    }
    state->walk_curr = state->walk_next;
  }

  if (state->walk_curr != 0) {
    return -E2BIG;
  }
  if (!reached_root) {
    return 0;
  }

  // The kernel walk discovers dentries leaf first. Run the matcher over the
  // collected path in the opposite direction. This restores reusable
  // directory frontier state before processing descendants.
  state->walk_depth = bpfj_vec_size(&state->saved_dentries);
  state->component_result = bpfj_file_match_cached_restore_checkpoint(state);
  if (state->component_result < 0) {
    return state->component_result;
  }
  state->checkpoint_depth = (__u32)state->component_result;
  bpf_for(i, 0, BPFJ_FILE_MATCH_CACHED_MAX_RECURSION) {
    if (i < state->checkpoint_depth) {
      continue;
    }
    if (i >= state->walk_depth) {
      break;
    }
    uintptr_t __arena* saved =
        bpfj_vec_at(&state->saved_dentries, state->walk_depth - i - 1);
    if (saved == NULL) {
      return -ENOMEM;
    }
    state->walk_curr = *saved;
    if (bpfj_file_match_cached_caches(state)) {
      bpfj_file_match_cached_bloom_add(state->ancestry_bloom, state->walk_curr);
    }
    long ret = bpfj_file_match_cached_save_name(&state->name, state->walk_curr);
    if (ret < 0) {
      return ret;
    }
    ret = bpfj_file_match_cached_nodes(state, &state->name, ret, i == 0);
    if (ret < 0) {
      return ret;
    }
    bpfj_file_match_cached_finalize_and_purge(state);
    bpfj_file_match_cached_stage_checkpoint(state, state->walk_curr);
  }

  // Discard policy paths that only matched a prefix of the requested path.
  bpfj_file_match_cached_purge_incomplete(state);

  // Add an explicit `/` policy at the selected namespace root without letting
  // an unbound variable glob-match the empty name.
  if (state->matcher->has_root == 0) {
    return 0;
  }
  return bpfj_file_match_cached_process_indexes(
      state->matcher, state, state->matcher->root_indexes, true);
}

struct bpfj_file_match_cached_retry_ctx {
  struct bpfj_file_match_cached_state __arena* state;
};

static long bpfj_file_match_cached_retry_cb(__u32 unused, void* data) {
  (void)unused;
  struct bpfj_file_match_cached_retry_ctx* ctx = data;
  struct bpfj_file_match_cached_state __arena* state = ctx->state;

  bpfj_file_match_cached_init(state);
  long ret = bpfj_mount_load(
      state->mount_cache, 1, &state->mount_descriptor, &state->mount_snapshot);
  if (ret == -EBUSY) {
    return 0;
  }
  if (ret < 0) {
    state->retry_result = ret;
    return 1;
  }
  state->walk_lock.mount_generation = state->mount_descriptor.mount_generation;

  ret = file_match_cached_internal_loop(state);
  if (ret == -EBUSY) {
    return 0;
  }
  if (ret < 0) {
    state->retry_result = ret;
    return 1;
  }

  u32 rename_lock = bpfj_file_match_cached_rename_seqcount();
  __u64 mount_generation = bpfj_mount_root_generation();
  if (state->walk_lock.rename_lock == rename_lock &&
      state->walk_lock.mount_generation == mount_generation) {
    state->retry_result = 0;
    state->completed_cycle = true;
    return 1;
  }
  state->walk_lock.rename_lock = rename_lock;
  return 0;
}

#ifdef BPFJ_FILE_MATCH_CACHED_INLINE_RUN
static __always_inline long bpfj_fmc_run(
#else
__noinline long bpfj_fmc_run(
#endif
    struct bpfj_file_matcher __arena* matcher __arg_arena,
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    struct bpfj_mount_cache __arena* mount_cache __arg_arena) {
  // Negative dentries and multiply-linked non-directories have no unique
  // inode-based path identity. Match them, but neither read nor write the
  // cache.
  //
  // The dentry is read back out of the run state, where bind put it, and it is
  // landed in a local before BPF_CORE_READ touches it: that macro relocates
  // every step of the chain it is given, and the run state is ours, not the
  // kernel's, so there is no BTF for it to relocate against. Same two-step as
  // bpfj_file_match_cached_build_key.
  bool cacheable = bpfj_file_match_cached_leaf_cacheable(state);

  if (cacheable) {
    long count = bpfj_file_match_cached_check_file_cache(state);
    if (count >= 0) {
      return count;
    }
  }

  const pid_t root_pid = 1;
  state->walk_root = (uintptr_t)bpfj_file_match_cached_get_root(root_pid);
  if (!state->walk_root) {
    return -ESRCH;
  }

  state->walk_lock.rename_lock = bpfj_file_match_cached_rename_seqcount();

  // One run state for the whole walk, not one per path component. The heap lock
  // is a trylock that never waits, so a per-component allocation turns heap
  // contention -- from the mount walk, the LRU, or userspace -- into a
  // component that matches nothing, which is indistinguishable downstream from
  // a component that genuinely matched nothing. Hoisted, there is one
  // contention window per walk and one place to report it.
  state->retry_result = -EBUSY;
  state->completed_cycle = false;
  state->mount_cache = mount_cache;
  struct bpfj_file_match_cached_retry_ctx retry_ctx = {
      .state = state,
  };
  bpf_loop(
      BPFJ_FILE_MATCH_CACHED_MAX_RETRIES,
      bpfj_file_match_cached_retry_cb,
      &retry_ctx,
      0);
  if (!state->completed_cycle) {
    return state->retry_result;
  }

  if (bpfj_file_match_cached_caches(state) &&
      (state->has_pending_checkpoint || cacheable)) {
    // The matcher walk already reaches the verifier's call-frame limit. Run
    // cache and checkpoint publication as a one-shot callback so their LRU and
    // heap call graphs are verified independently of the walk's call graph.
    struct bpfj_file_match_cached_save_ctx save_ctx = {.state = state};
    bpf_loop(1, bpfj_file_match_cached_save_file_cache_cb, &save_ctx, 0);
  }

  if (bpfj_dbg_mode) {
    bpfj_file_match_cached_dbg_print(matcher, state);
  }

  return (long)bpfj_file_match_cached_count(state);
}

// The data entry for the path_id the iter at match_idx is sitting on.
//
// This used to be two functions and a string lookup: a global subprogram that
// probed a per-path str_map for the caller's role id, and an inline wrapper
// that staged the key onto the arena for it. Both are gone. A matcher covers
// one role, so its data is a flat array and the path_id is the index -- an
// index check and an add. That is also what let the 64-byte role staging
// buffer come off the run state, which every cache entry carries a copy of.
static __always_inline void* bpfj_file_match_cached_lookup(
    struct bpfj_file_match_cached_state __arena* state __arg_arena,
    u32 match_idx) {
  const struct bpfj_file_matcher __arena* matcher = state->matcher;
  if (matcher == NULL) {
    return NULL;
  }

  void __arena* vec = matcher->data_vec;
  if (vec == NULL) {
    return NULL;
  }

  struct bpfj_file_match_cached_iter __arena* iter =
      bpfj_file_match_cached_iter_at(state, match_idx);
  if (iter == NULL) {
    return NULL;
  }

  s32 path_id = iter->node.path_id;
  u32 count = matcher->data_entry_count;
  u32 size = matcher->data_entry_size;
  if (path_id < 0 || (u32)path_id >= count || size == 0) {
    return NULL;
  }

  // Bounded against the data block, not against the arena.
  //
  // bpfj_heap_clamp_off masks to the arena size, which is the right bound for
  // an offset about to be added to the arena base -- which is what every other
  // use of it here is doing. This offset is added to `vec`, already an interior
  // pointer, so that mask would leave the result anywhere up to a whole arena
  // past the end of the block: it bounds the stride and nothing else.
  //
  // The block is count * size bytes, and both come back out of the arena, so
  // neither is known at verification time and the product is not to be trusted
  // either. Computed in 64 bits so it cannot wrap, and the entry has to fall
  // entirely inside it.
  u64 total = (u64)count * (u64)size;
  u64 off = (u64)(u32)path_id * (u64)size;
  if (total > BPFJ_HEAP_MAX_ARENA_SIZE || off + (u64)size > total) {
    return NULL;
  }
  return (void*)((char __arena*)vec + off);
}
