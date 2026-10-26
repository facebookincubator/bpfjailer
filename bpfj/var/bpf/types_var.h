// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#ifdef __cplusplus
#include <linux/types.h>
#include <cstddef>
#include <cstdio>
#endif

#include <errno.h>

#include "bpfj/lib/bpf/types_heap.h"

struct bpfj_str_map;

#ifdef __cplusplus
#define BPFJ_VAR_INLINE inline
#define BPFJ_VAR_NULL nullptr
#else
#define BPFJ_VAR_INLINE static inline
#define BPFJ_VAR_NULL NULL
#endif

// Sized for a canonical 36-character UUID plus the NUL. In the open source
// tree values live out of line in the arena, so widening this no longer grows
// bpfj_pod; the glob NFA gadget width deliberately does not track it, a
// 39-wide gadget having pushed fs2_enforce over the 6.13 verifier limit.
// Keep the legacy bounds stable for closed layouts that include this header.
#define BPFJ_VAR_VAL_LEN 40
#define BPFJ_VAR_MAX 4
#define BPFJ_OSS_VAR_VAL_LEN 64
#define BPFJ_OSS_VAR_MAX 16

struct vsock_address {
  __u32 cid;
  __u32 port;
};

// Type of the variable
enum bpfj_var_type {
  BPFJ_VAR_TYPE_UNKNOWN = 0,
  BPFJ_VAR_TYPE_STR = 1,
  BPFJ_VAR_TYPE_VSOCK_ADDR = 2,
};

// One policy variable name. Records are sized through the terminating NUL in
// str, and ids are assigned afresh when a policy is loaded.
struct bpfj_var_name {
  __u32 id;
  __u32 len;
  char str[1];
};

// The running jail's variable allowlist. The ID-indexed name pointers and
// variable-sized bpfj_var_name records live in the same allocation; by_name
// points to the arena string map used for name lookup.
struct bpfj_var_catalog {
  struct bpfj_str_map __arena* by_name;
  __u32 count;
  __u32 reserved;
  const struct bpfj_var_name __arena* names[1];
};

BPFJ_VAR_INLINE const struct bpfj_var_name __arena** bpfj_var_catalog_names_mut(
    struct bpfj_var_catalog* catalog) {
  return catalog == BPFJ_VAR_NULL ? BPFJ_VAR_NULL : catalog->names;
}

BPFJ_VAR_INLINE const struct bpfj_var_name __arena* const*
bpfj_var_catalog_names(const struct bpfj_var_catalog* catalog) {
  return catalog == BPFJ_VAR_NULL ? BPFJ_VAR_NULL : catalog->names;
}

// A variable set to a value
struct bpfj_var {
  // Identifies the variable more cheaply than a string name would.
  __u32 id;
  // Type of the variable
  __u8 type;
  // Size of the value
  __u8 size;
  __u16 reserved;
  // Shared allowlist record for this variable's name and current policy id.
  const struct bpfj_var_name __arena* name;
  // Value bytes for this variable, stored in the shared arena.
  void __arena* val;
};

struct bpfj_var_array {
  // Pod-owned flat var blob in the shared arena, beginning with `count`
  // bpfj_var records followed by each value payload.
  struct bpfj_var __arena* vars;
  __u8 count;
  __u8 reserved[7];
};

BPFJ_VAR_INLINE __u32 bpfj_var_align_up(__u32 size) {
  return (size + sizeof(__u32) - 1) & ~((__u32)sizeof(__u32) - 1);
}

BPFJ_VAR_INLINE void bpfj_var_array_init(struct bpfj_var_array* vars) {
  vars->vars = BPFJ_VAR_NULL;
  vars->count = 0;
  __builtin_memset(vars->reserved, 0, sizeof(vars->reserved));
}

BPFJ_VAR_INLINE __u32 bpfj_var_payload_size(const struct bpfj_var* var) {
  switch (var->type) {
    case BPFJ_VAR_TYPE_STR:
      return (__u32)var->size + 1;
    case BPFJ_VAR_TYPE_VSOCK_ADDR:
      return sizeof(struct vsock_address);
    default:
      return var->size;
  }
}

BPFJ_VAR_INLINE struct bpfj_var __arena* bpfj_var_array_at(
    const struct bpfj_var_array* vars,
    __u32 idx) {
  if (vars == BPFJ_VAR_NULL || idx >= vars->count ||
      vars->vars == BPFJ_VAR_NULL) {
    return BPFJ_VAR_NULL;
  }
  return vars->vars + idx;
}

BPFJ_VAR_INLINE const void __arena* bpfj_var_value_ptr(
    const struct bpfj_var* var) {
  if (var == BPFJ_VAR_NULL) {
    return BPFJ_VAR_NULL;
  }
  return var->val;
}

BPFJ_VAR_INLINE const char __arena* bpfj_var_name_ptr(
    const struct bpfj_var* var) {
  if (var == BPFJ_VAR_NULL || var->name == BPFJ_VAR_NULL) {
    return BPFJ_VAR_NULL;
  }
  return var->name->str;
}

BPFJ_VAR_INLINE __u32 bpfj_var_name_len(const struct bpfj_var* var) {
  return var == BPFJ_VAR_NULL || var->name == BPFJ_VAR_NULL ? 0
                                                            : var->name->len;
}

// Get a variable value as a string
BPFJ_VAR_INLINE int
bpfj_var_get_str(const struct bpfj_var* var, char* dest, __u8* size) {
  if (var->type != BPFJ_VAR_TYPE_STR) {
    return -EINVAL;
  }

  __builtin_memset(dest, 0, BPFJ_OSS_VAR_VAL_LEN);
  __builtin_memcpy(dest, bpfj_var_value_ptr(var), var->size + 1);

  if (size) {
    *size = var->size;
  }

  return 0;
}

// Get a variable value as a vsock address
BPFJ_VAR_INLINE int bpfj_var_get_vsock_addr(
    const struct bpfj_var* var,
    struct vsock_address* dest) {
  if (var->type != BPFJ_VAR_TYPE_VSOCK_ADDR) {
    return -EINVAL;
  }

  __builtin_memset(dest, 0, sizeof(struct vsock_address));
  __builtin_memcpy(dest, bpfj_var_value_ptr(var), sizeof(*dest));

  return 0;
}

// Get a variable value as binary data
BPFJ_VAR_INLINE int
bpfj_var_get_bin(const struct bpfj_var* var, unsigned char* dest, __u8* size) {
  __builtin_memset(dest, 0, BPFJ_OSS_VAR_VAL_LEN);
  __builtin_memcpy(dest, bpfj_var_value_ptr(var), var->size);

  if (size) {
    *size = var->size;
  }

  return 0;
}

// Serialize a variable to a string
BPFJ_VAR_INLINE int
bpfj_var_serialize(const struct bpfj_var* var, char* dest, size_t dest_size) {
  switch (var->type) {
    case BPFJ_VAR_TYPE_STR:
      __builtin_memcpy(dest, bpfj_var_value_ptr(var), var->size + 1);
      return 0;
    case BPFJ_VAR_TYPE_VSOCK_ADDR: {
      struct vsock_address addr;
      __builtin_memset(&addr, 0, sizeof(addr));
      __builtin_memcpy(&addr, bpfj_var_value_ptr(var), sizeof(addr));
#ifdef __cplusplus
      snprintf(dest, dest_size, "%u:%u", addr.cid, addr.port);
#else
      BPF_SNPRINTF(dest, dest_size, "%u:%u", addr.cid, addr.port);
#endif
      return 0;
    }
    default:
      return -EINVAL;
  }
}

// Deserialize a variable from a string. Can't be called from bpf
#ifdef __cplusplus
inline int
bpfj_var_deserialize(const char* src, size_t src_size, struct bpfj_var* var) {
  void __arena* dest = var->val;
  if (dest == nullptr) {
    return -EINVAL;
  }

  switch (var->type) {
    case BPFJ_VAR_TYPE_STR:
      if (src_size > BPFJ_OSS_VAR_VAL_LEN - 1) {
        return -ERANGE;
      }

      __builtin_memcpy(dest, src, src_size);
      ((char*)dest)[src_size] = '\0';
      var->size = src_size;

      return 0;
    case BPFJ_VAR_TYPE_VSOCK_ADDR: {
      struct vsock_address addr{};
      if (sscanf(src, "%u:%u", &addr.cid, &addr.port) != 2) {
        return -EINVAL;
      }

      __builtin_memcpy(dest, &addr, sizeof(addr));
      var->size = sizeof(addr);

      return 0;
    }
    default:
      return -EINVAL;
  }
}
#endif

#undef BPFJ_VAR_NULL
#undef BPFJ_VAR_INLINE
