// Copyright (c) Meta Platforms, Inc. and affiliates.

#pragma once

#include "bpfj/enforce/bpf/types.h"
#include "bpfj/lib/bpf/heap.h"

struct bpfj_mutation_transaction {
  struct bpfj_lock_wait_guard lock;
  struct bpfj_mutation_journal __arena* journal;
  __u8 recording;
};

static __always_inline void bpfj_mutation_transaction_cleanup(
    struct bpfj_mutation_transaction* transaction) {
  bpfj_lock_wait_guard_cleanup(&transaction->lock);
}

#define BPFJ_MUTATION_TRANSACTION(_name)                                    \
  __attribute__((cleanup(                                                   \
      bpfj_mutation_transaction_cleanup))) struct bpfj_mutation_transaction \
      _name = {}

// Return 1 when this generation may mutate, 0 when it is passive, and a
// negative errno when replacement serialization failed. The active generation
// is checked again after taking the journal lock, which is the cutover's
// linearization point.
static __always_inline int bpfj_mutation_begin(
    struct bpfj_mutation_transaction* transaction) {
  if (!bpfj_generation_is_active()) {
    return 0;
  }
  if (!bpfj_heap_enabled) {
    return -EINVAL;
  }

  bpfj_heap_use_arena();
  struct bpfj_heap_control __arena* ctrl = bpfj_heap_get_ctrl();
  transaction->journal = ctrl ? ctrl->mutation_journal : NULL;
  if (transaction->journal) {
    transaction->lock.lock = &transaction->journal->lock;
    transaction->lock.held =
        bpfj_lock_acquire(transaction->lock.lock, &transaction->lock.flags) ==
        0;
    if (!transaction->lock.held) {
      transaction->journal->failure = BPFJ_MUTATION_JOURNAL_CONTENDED;
      return -EBUSY;
    }
  }

  if (!bpfj_generation_is_active()) {
    return 0;
  }
  transaction->recording = transaction->journal &&
      transaction->journal->state == BPFJ_MUTATION_JOURNAL_RECORDING;
  return 1;
}

static __always_inline void bpfj_mutation_append(
    struct bpfj_mutation_transaction* transaction,
    __u8 domain,
    __u8 operation,
    __u64 key0,
    __u64 key1,
    const struct bpfj_role_id* role,
    const struct bpfj_uuid* pod,
    __u32 object_id,
    __u8 owned) {
  struct bpfj_mutation_journal __arena* journal = transaction->journal;
  if (!journal) {
    return;
  }

  if (!transaction->recording) {
    return;
  }

  __u64 sequence = journal->next;
  __u64 used = sequence - journal->consumed;
  if (used >= journal->entries.capacity) {
    journal->failure = BPFJ_MUTATION_JOURNAL_FULL;
    return;
  }
  __u32 index = sequence % journal->entries.capacity;
  barrier_var(index);

  struct bpfj_mutation_record __arena* records = journal->entries.buf;
  struct bpfj_mutation_record __arena* record = records + index;
  record->committed = 0;
  record->domain = domain;
  record->operation = operation;
  record->owned = owned;
  record->reserved = 0;
  record->key[0] = key0;
  record->key[1] = key1;
  record->object_id = object_id;
  // `record` is in the arena. bpfj_pod_read_role_id() explains the casts.
  if (role) {
    __builtin_memcpy((struct bpfj_role_id*)&record->role, role, sizeof(*role));
  }
  if (pod) {
    __builtin_memcpy((struct bpfj_uuid*)&record->pod, pod, sizeof(*pod));
  }
  record->committed = 1;
  // Publish the sequence only after the complete record is visible.
  barrier();
  journal->next = sequence + 1;
  journal->entries.size = used + 1;
}

static __always_inline void bpfj_mutation_bpf_owner(
    struct bpfj_mutation_transaction* transaction,
    __u8 domain,
    __u8 operation,
    __u64 key,
    const struct bpfj_bpf_owner* owner) {
  bpfj_mutation_append(
      transaction,
      domain,
      operation,
      key,
      0,
      owner ? &owner->role : NULL,
      owner ? &owner->pod : NULL,
      owner ? owner->id : 0,
      owner != NULL);
}

static __always_inline void bpfj_mutation_mq_owner(
    struct bpfj_mutation_transaction* transaction,
    __u8 domain,
    __u8 operation,
    __u64 key0,
    __u64 key1,
    const struct bpfj_mq_owner* owner,
    __u8 owned) {
  bpfj_mutation_append(
      transaction,
      domain,
      operation,
      key0,
      key1,
      owner ? &owner->role : NULL,
      owner ? &owner->pod : NULL,
      0,
      owned);
}

static __always_inline void bpfj_mutation_shm_owner(
    struct bpfj_mutation_transaction* transaction,
    __u8 domain,
    __u8 operation,
    __u64 key0,
    __u64 key1,
    const struct bpfj_shm_owner* owner,
    __u8 owned) {
  bpfj_mutation_append(
      transaction,
      domain,
      operation,
      key0,
      key1,
      owner ? &owner->role : NULL,
      owner ? &owner->pod : NULL,
      0,
      owned);
}
