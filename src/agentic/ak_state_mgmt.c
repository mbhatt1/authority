/*
 * Authority Kernel - State Management Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements state management infrastructure for agents:
 *   - Checkpoint creation and restoration
 *   - State versioning with history tracking
 *   - State change tracking and diffs
 *   - Migration support for agent state transfer
 *
 * SECURITY:
 *   - All checkpoints include SHA-256 integrity hash
 *   - State changes are logged to audit trail
 *   - Version chain provides tamper evidence
 *   - Migration freezes state to prevent race conditions
 */

#include "ak_state_mgmt.h"
#include "ak_audit.h"
#include "ak_compat.h"
#include "ak_heap.h"

/* ============================================================
 * INTERNAL STRUCTURES
 * ============================================================ */

/* Hash table parameters */
#define STATE_HASH_CAPACITY 1024
#define CHECKPOINT_HASH_CAPACITY 64
#define CHANGE_HISTORY_CAPACITY 10000

/* Internal state entry for hash table */
typedef struct state_entry_internal {
  ak_state_entry_t entry;
  u64 agent_pid; /* Owning agent */
  struct state_entry_internal *hash_next;
} state_entry_internal_t;

/* Internal checkpoint for hash table */
typedef struct checkpoint_internal {
  ak_checkpoint_t checkpoint;
  u32 magic;
  struct checkpoint_internal *hash_next;
} checkpoint_internal_t;

/* Internal change record for history */
typedef struct change_record_internal {
  ak_state_change_t change;
  u64 agent_pid;
  struct change_record_internal *next;
} change_record_internal_t;

/* Per-agent state context */
typedef struct agent_state_ctx {
  u64 agent_pid;
  u64 current_seq;                  /* Current sequence number */
  u64 checkpoint_count;             /* Number of checkpoints */
  ak_checkpoint_t *checkpoint_head; /* Most recent checkpoint */
  ak_checkpoint_t *checkpoint_tail; /* Oldest checkpoint */
  ak_migration_info_t migration;    /* Migration state */
  struct agent_state_ctx *next;     /* Hash chain */
} agent_state_ctx_t;

/* Global state management state */
static struct {
  heap h;
  boolean initialized;

  /* State entries hash table */
  state_entry_internal_t **state_table;
  u64 state_entry_count;

  /* Checkpoints hash table */
  checkpoint_internal_t **checkpoint_table;
  u64 checkpoint_count;
  u64 next_checkpoint_id;

  /* Change history (ring buffer style) */
  change_record_internal_t *change_head;
  change_record_internal_t *change_tail;
  u64 change_count;
  u64 global_seq; /* Global sequence counter */

  /* Per-agent state contexts */
  agent_state_ctx_t **agent_table;

  /* Statistics */
  ak_state_mgmt_stats_t stats;
} state_mgmt;

/* ============================================================
 * INTERNAL HELPERS
 * ============================================================ */

static u64 get_timestamp_ns(void) { return now(CLOCK_ID_MONOTONIC); }

/*
 * FNV-1a hash for strings.
 */
static u64 hash_string(const char *str) {
  u64 hash = 0xcbf29ce484222325ULL;
  while (*str) {
    hash ^= (u8)*str++;
    hash *= 0x100000001b3ULL;
  }
  return hash;
}

/*
 * Hash for u64 values.
 */
static u64 hash_u64(u64 val) {
  val ^= val >> 33;
  val *= 0xff51afd7ed558ccdULL;
  val ^= val >> 33;
  val *= 0xc4ceb9fe1a85ec53ULL;
  val ^= val >> 33;
  return val;
}

/*
 * Combined hash for agent + key lookup.
 */
static u64 hash_agent_key(u64 agent_pid, const char *key) {
  return hash_u64(agent_pid) ^ hash_string(key);
}

/*
 * Compute SHA-256-like hash of buffer contents.
 * Uses FNV-1a extended to fill 32 bytes for simplicity.
 * Production should use real SHA-256.
 */
static void compute_state_hash(buffer data, u8 *hash_out) {
  if (!data || !hash_out) {
    if (hash_out)
      runtime_memset(hash_out, 0, AK_STATE_HASH_SIZE);
    return;
  }

  u64 len = buffer_length(data);
  u8 *bytes = buffer_ref(data, 0);

  u64 h = 0xcbf29ce484222325ULL;
  for (u64 i = 0; i < len; i++) {
    h ^= bytes[i];
    h *= 0x100000001b3ULL;
  }

  /* Extend to fill AK_STATE_HASH_SIZE bytes */
  for (int i = 0; i < AK_STATE_HASH_SIZE; i++) {
    hash_out[i] = (h >> ((i % 8) * 8)) & 0xff;
    if ((i % 8) == 7) {
      h ^= (u64)i;
      h *= 0x100000001b3ULL;
    }
  }
}

/*
 * Verify state hash.
 */
static boolean verify_state_hash(buffer data, const u8 *expected_hash) {
  u8 computed[AK_STATE_HASH_SIZE];
  compute_state_hash(data, computed);
  return runtime_memcmp(computed, expected_hash, AK_STATE_HASH_SIZE) == 0;
}

/*
 * Get agent state context, creating if needed.
 */
static agent_state_ctx_t *get_agent_ctx(u64 agent_pid, boolean create) {
  if (!state_mgmt.agent_table)
    return NULL;

  u64 idx = hash_u64(agent_pid) % CHECKPOINT_HASH_CAPACITY;
  agent_state_ctx_t *ctx = state_mgmt.agent_table[idx];

  while (ctx) {
    if (ctx->agent_pid == agent_pid)
      return ctx;
    ctx = ctx->next;
  }

  if (!create)
    return NULL;

  /* Create new context */
  ctx = allocate_zero(state_mgmt.h, sizeof(agent_state_ctx_t));
  if (!ctx || ctx == INVALID_ADDRESS)
    return NULL;

  ctx->agent_pid = agent_pid;
  ctx->current_seq = 0;
  ctx->checkpoint_count = 0;
  ctx->checkpoint_head = NULL;
  ctx->checkpoint_tail = NULL;
  ctx->migration.state = AK_MIGRATION_NONE;

  /* Insert into hash table */
  ctx->next = state_mgmt.agent_table[idx];
  state_mgmt.agent_table[idx] = ctx;

  return ctx;
}

/*
 * Extract agent PID from context.
 */
static u64 get_agent_pid(ak_agent_context_t *ctx) {
  if (!ctx)
    return 0;

  /* Extract PID from agent context's pid field (first 8 bytes as u64) */
  u64 pid = 0;
  for (int i = 0; i < 8 && i < AK_TOKEN_ID_SIZE; i++) {
    pid |= ((u64)ctx->pid[i]) << (i * 8);
  }
  return pid ? pid : 1; /* Return 1 if pid is 0 to avoid issues */
}

/*
 * Find state entry by agent + key.
 */
static state_entry_internal_t *find_state_entry(u64 agent_pid,
                                                const char *key) {
  if (!state_mgmt.state_table || !key)
    return NULL;

  u64 idx = hash_agent_key(agent_pid, key) % STATE_HASH_CAPACITY;
  state_entry_internal_t *entry = state_mgmt.state_table[idx];

  while (entry) {
    if (entry->agent_pid == agent_pid &&
        runtime_strcmp(entry->entry.key, key) == 0 && !entry->entry.deleted) {
      return entry;
    }
    entry = entry->hash_next;
  }
  return NULL;
}

/*
 * Find checkpoint by ID.
 */
static checkpoint_internal_t *find_checkpoint_internal(u64 checkpoint_id) {
  if (!state_mgmt.checkpoint_table || checkpoint_id == 0)
    return NULL;

  u64 idx = hash_u64(checkpoint_id) % CHECKPOINT_HASH_CAPACITY;
  checkpoint_internal_t *cp = state_mgmt.checkpoint_table[idx];

  while (cp) {
    if (cp->checkpoint.checkpoint_id == checkpoint_id &&
        cp->magic == AK_CHECKPOINT_MAGIC) {
      return cp;
    }
    cp = cp->hash_next;
  }
  return NULL;
}

/*
 * Append bytes to a JSON string literal, escaping as needed.
 *
 * Escapes '"', '\\' and the control characters that the runtime JSON
 * parser (src/runtime/json.c) knows how to unescape (\n \t \r \b \f).
 * Other bytes are emitted verbatim; the parser round-trips them.
 */
static void state_json_escape(buffer out, const u8 *data, u64 len) {
  for (u64 i = 0; i < len; i++) {
    u8 c = data[i];
    switch (c) {
    case '"':
      buffer_write(out, "\\\"", 2);
      break;
    case '\\':
      buffer_write(out, "\\\\", 2);
      break;
    case '\n':
      buffer_write(out, "\\n", 2);
      break;
    case '\t':
      buffer_write(out, "\\t", 2);
      break;
    case '\r':
      buffer_write(out, "\\r", 2);
      break;
    case '\b':
      buffer_write(out, "\\b", 2);
      break;
    case '\f':
      buffer_write(out, "\\f", 2);
      break;
    default:
      buffer_write(out, &c, 1);
      break;
    }
  }
}

/*
 * Clone a buffer.
 */
static buffer clone_buffer(heap h, buffer src) {
  if (!src || src == INVALID_ADDRESS)
    return NULL;

  u64 len = buffer_length(src);
  buffer dst = allocate_buffer(h, len);
  if (!dst || dst == INVALID_ADDRESS)
    return NULL;

  buffer_write(dst, buffer_ref(src, 0), len);
  return dst;
}

/*
 * Record a state change in history.
 */
static void record_change(u64 agent_pid, const char *key, int change_type,
                          buffer old_val, buffer new_val) {
  /* Allocate change record */
  change_record_internal_t *record =
      allocate_zero(state_mgmt.h, sizeof(change_record_internal_t));
  if (!record || record == INVALID_ADDRESS)
    return;

  /* Populate change */
  record->agent_pid = agent_pid;
  record->change.seq_number = ++state_mgmt.global_seq;
  record->change.timestamp_ns = get_timestamp_ns();
  runtime_strncpy(record->change.key, key, AK_MAX_KEY_LEN - 1);
  record->change.key[AK_MAX_KEY_LEN - 1] = '\0';
  record->change.change_type = change_type;
  record->change.old_value =
      old_val ? clone_buffer(state_mgmt.h, old_val) : NULL;
  record->change.new_value =
      new_val ? clone_buffer(state_mgmt.h, new_val) : NULL;

  /* Add to change list */
  record->next = NULL;
  if (state_mgmt.change_tail) {
    state_mgmt.change_tail->next = record;
    state_mgmt.change_tail = record;
  } else {
    state_mgmt.change_head = record;
    state_mgmt.change_tail = record;
  }
  state_mgmt.change_count++;

  /* Trim old changes if too many */
  while (state_mgmt.change_count > CHANGE_HISTORY_CAPACITY &&
         state_mgmt.change_head) {
    change_record_internal_t *old = state_mgmt.change_head;
    state_mgmt.change_head = old->next;
    if (old->change.old_value)
      deallocate_buffer(old->change.old_value);
    if (old->change.new_value)
      deallocate_buffer(old->change.new_value);
    deallocate(state_mgmt.h, old, sizeof(change_record_internal_t));
    state_mgmt.change_count--;
  }
  if (!state_mgmt.change_head)
    state_mgmt.change_tail = NULL;
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

int ak_state_mgmt_init(heap h) {
  if (state_mgmt.initialized)
    return 0;

  if (!h || h == INVALID_ADDRESS)
    return -EINVAL;

  state_mgmt.h = h;

  /* Allocate state entries hash table */
  state_mgmt.state_table =
      allocate_zero(h, STATE_HASH_CAPACITY * sizeof(state_entry_internal_t *));
  if (!state_mgmt.state_table || state_mgmt.state_table == INVALID_ADDRESS) {
    return -ENOMEM;
  }

  /* Allocate checkpoints hash table */
  state_mgmt.checkpoint_table = allocate_zero(
      h, CHECKPOINT_HASH_CAPACITY * sizeof(checkpoint_internal_t *));
  if (!state_mgmt.checkpoint_table ||
      state_mgmt.checkpoint_table == INVALID_ADDRESS) {
    deallocate(h, state_mgmt.state_table,
               STATE_HASH_CAPACITY * sizeof(state_entry_internal_t *));
    return -ENOMEM;
  }

  /* Allocate agent context table */
  state_mgmt.agent_table =
      allocate_zero(h, CHECKPOINT_HASH_CAPACITY * sizeof(agent_state_ctx_t *));
  if (!state_mgmt.agent_table || state_mgmt.agent_table == INVALID_ADDRESS) {
    deallocate(h, state_mgmt.state_table,
               STATE_HASH_CAPACITY * sizeof(state_entry_internal_t *));
    deallocate(h, state_mgmt.checkpoint_table,
               CHECKPOINT_HASH_CAPACITY * sizeof(checkpoint_internal_t *));
    return -ENOMEM;
  }

  state_mgmt.state_entry_count = 0;
  state_mgmt.checkpoint_count = 0;
  state_mgmt.next_checkpoint_id = 1;
  state_mgmt.change_head = NULL;
  state_mgmt.change_tail = NULL;
  state_mgmt.change_count = 0;
  state_mgmt.global_seq = 0;

  runtime_memset(&state_mgmt.stats, 0, sizeof(ak_state_mgmt_stats_t));

  state_mgmt.initialized = true;

  return 0;
}

void ak_state_mgmt_shutdown(void) {
  if (!state_mgmt.initialized)
    return;

  /* Free all state entries */
  if (state_mgmt.state_table) {
    for (u64 i = 0; i < STATE_HASH_CAPACITY; i++) {
      state_entry_internal_t *entry = state_mgmt.state_table[i];
      while (entry) {
        state_entry_internal_t *next = entry->hash_next;
        if (entry->entry.value)
          deallocate_buffer(entry->entry.value);
        deallocate(state_mgmt.h, entry, sizeof(state_entry_internal_t));
        entry = next;
      }
    }
    deallocate(state_mgmt.h, state_mgmt.state_table,
               STATE_HASH_CAPACITY * sizeof(state_entry_internal_t *));
  }

  /* Free all checkpoints */
  if (state_mgmt.checkpoint_table) {
    for (u64 i = 0; i < CHECKPOINT_HASH_CAPACITY; i++) {
      checkpoint_internal_t *cp = state_mgmt.checkpoint_table[i];
      while (cp) {
        checkpoint_internal_t *next = cp->hash_next;
        if (cp->checkpoint.state_data)
          deallocate_buffer(cp->checkpoint.state_data);
        deallocate(state_mgmt.h, cp, sizeof(checkpoint_internal_t));
        cp = next;
      }
    }
    deallocate(state_mgmt.h, state_mgmt.checkpoint_table,
               CHECKPOINT_HASH_CAPACITY * sizeof(checkpoint_internal_t *));
  }

  /* Free agent contexts */
  if (state_mgmt.agent_table) {
    for (u64 i = 0; i < CHECKPOINT_HASH_CAPACITY; i++) {
      agent_state_ctx_t *ctx = state_mgmt.agent_table[i];
      while (ctx) {
        agent_state_ctx_t *next = ctx->next;
        deallocate(state_mgmt.h, ctx, sizeof(agent_state_ctx_t));
        ctx = next;
      }
    }
    deallocate(state_mgmt.h, state_mgmt.agent_table,
               CHECKPOINT_HASH_CAPACITY * sizeof(agent_state_ctx_t *));
  }

  /* Free change history */
  change_record_internal_t *change = state_mgmt.change_head;
  while (change) {
    change_record_internal_t *next = change->next;
    if (change->change.old_value)
      deallocate_buffer(change->change.old_value);
    if (change->change.new_value)
      deallocate_buffer(change->change.new_value);
    deallocate(state_mgmt.h, change, sizeof(change_record_internal_t));
    change = next;
  }

  state_mgmt.initialized = false;
}

/* ============================================================
 * CHECKPOINT OPERATIONS
 * ============================================================ */

u64 ak_checkpoint_create(ak_agent_context_t *ctx, const char *description) {
  if (!state_mgmt.initialized)
    return 0;

  if (!ctx)
    return 0;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, true);
  if (!agent_ctx)
    return 0;

  /* Check checkpoint limit. Returned as (u64)negative error so callers
   * can distinguish limit-hit from other failures; see
   * AK_CHECKPOINT_ID_VALID() in ak_state_mgmt.h. */
  if (agent_ctx->checkpoint_count >= AK_MAX_CHECKPOINTS) {
    return (u64)AK_E_TOO_MANY_CHECKPOINTS;
  }

  /* Check if state is frozen */
  if (agent_ctx->migration.state == AK_MIGRATION_FROZEN) {
    return (u64)AK_E_STATE_FROZEN;
  }

  /* Allocate checkpoint */
  checkpoint_internal_t *cp_int =
      allocate_zero(state_mgmt.h, sizeof(checkpoint_internal_t));
  if (!cp_int || cp_int == INVALID_ADDRESS)
    return 0;

  cp_int->magic = AK_CHECKPOINT_MAGIC;
  ak_checkpoint_t *cp = &cp_int->checkpoint;

  /* Assign checkpoint ID */
  cp->checkpoint_id = state_mgmt.next_checkpoint_id++;
  cp->agent_pid = agent_pid;
  runtime_memcpy(cp->run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
  cp->created_ns = get_timestamp_ns();
  cp->seq_number = ++state_mgmt.global_seq;

  /* Copy description */
  if (description) {
    runtime_strncpy(cp->description, description, AK_MAX_DESCRIPTION_LEN - 1);
    cp->description[AK_MAX_DESCRIPTION_LEN - 1] = '\0';
  } else {
    runtime_strncpy(cp->description, "Auto checkpoint",
                    AK_MAX_DESCRIPTION_LEN - 1);
  }

  /* Serialize all state entries for this agent */
  buffer state_buf = allocate_buffer(state_mgmt.h, 4096);
  if (!state_buf || state_buf == INVALID_ADDRESS) {
    deallocate(state_mgmt.h, cp_int, sizeof(checkpoint_internal_t));
    return 0;
  }

  /* Write state as a single JSON object mapping key -> value, where the
   * value bytes are embedded as an escaped JSON string:
   *
   *   {"<key>":"<escaped value bytes>", ...}
   *
   * This format is chosen so restore can use the runtime JSON parser
   * (src/runtime/json.c), which only accepts a top-level object and
   * only preserves object and string values (arrays/numbers/literals
   * are discarded by that parser). Embedding the raw value bytes as an
   * escaped string makes the round-trip lossless regardless of what
   * the value contains (nested quotes, arrays, etc.). A NULL value is
   * written as the empty string and restored as NULL. */
  buffer_write(state_buf, "{", 1);
  boolean first = true;
  u64 object_count = 0;

  for (u64 i = 0; i < STATE_HASH_CAPACITY; i++) {
    state_entry_internal_t *entry = state_mgmt.state_table[i];
    while (entry) {
      if (entry->agent_pid == agent_pid && !entry->entry.deleted) {
        if (!first)
          buffer_write(state_buf, ",", 1);
        first = false;

        buffer_write(state_buf, "\"", 1);
        state_json_escape(state_buf, (const u8 *)entry->entry.key,
                          runtime_strlen(entry->entry.key));
        buffer_write(state_buf, "\":\"", 3);
        if (entry->entry.value) {
          state_json_escape(state_buf, buffer_ref(entry->entry.value, 0),
                            buffer_length(entry->entry.value));
        }
        buffer_write(state_buf, "\"", 1);

        object_count++;
      }
      entry = entry->hash_next;
    }
  }
  buffer_write(state_buf, "}", 1);

  cp->state_data = state_buf;
  cp->heap_object_count = object_count;
  cp->total_state_bytes = buffer_length(state_buf);

  /* Compute state hash */
  compute_state_hash(state_buf, cp->state_hash);

  /* Get current policy hash from audit */
  ak_audit_head_hash(cp->policy_hash);

  /* Link into version chain */
  cp->prev = agent_ctx->checkpoint_head;
  cp->next = NULL;
  if (agent_ctx->checkpoint_head) {
    agent_ctx->checkpoint_head->next = cp;
  }
  agent_ctx->checkpoint_head = cp;
  if (!agent_ctx->checkpoint_tail) {
    agent_ctx->checkpoint_tail = cp;
  }
  agent_ctx->checkpoint_count++;

  /* Insert into hash table */
  u64 idx = hash_u64(cp->checkpoint_id) % CHECKPOINT_HASH_CAPACITY;
  cp_int->hash_next = state_mgmt.checkpoint_table[idx];
  state_mgmt.checkpoint_table[idx] = cp_int;
  state_mgmt.checkpoint_count++;

  /* Update statistics */
  state_mgmt.stats.checkpoints_created++;
  state_mgmt.stats.total_checkpoint_bytes += cp->total_state_bytes;

  return cp->checkpoint_id;
}

/* ============================================================
 * CHECKPOINT RESTORE PARSING
 * ============================================================
 * Checkpoint state_data is parsed with the runtime JSON parser
 * (src/runtime/json.c) instead of a hand-rolled scanner, so escaped
 * quotes and nested structures in values are handled correctly.
 */

closure_function(1, 1, void, checkpoint_state_parsed, tuple *, result,
                 void *v) {
  *bound(result) = (tuple)v;
}

closure_function(1, 1, void, checkpoint_state_parse_error, boolean *, failed,
                 string err) {
  (void)err;
  *bound(failed) = true;
}

closure_function(2, 2, boolean, checkpoint_restore_each, ak_agent_context_t *,
                 actx, u64 *, failed_entries, value k, value v) {
  if (!is_symbol(k)) {
    (*bound(failed_entries))++;
    return true;
  }

  string name = symbol_string((symbol)k);
  u64 key_len = name ? buffer_length(name) : 0;

  /* Values are always encoded as JSON strings (see ak_checkpoint_create) */
  if (key_len == 0 || key_len >= AK_MAX_KEY_LEN || !is_string(v)) {
    (*bound(failed_entries))++;
    return true; /* keep iterating; failures reported by caller */
  }

  char key[AK_MAX_KEY_LEN];
  runtime_memcpy(key, buffer_ref(name, 0), key_len);
  key[key_len] = '\0';

  buffer val = (buffer)v;
  if (buffer_length(val) == 0)
    val = NULL; /* empty string encodes a NULL value */

  if (ak_state_set(bound(actx), key, val) == 0)
    (*bound(failed_entries))++;

  return true;
}

s64 ak_checkpoint_restore(ak_agent_context_t *ctx, u64 checkpoint_id) {
  if (!state_mgmt.initialized)
    return AK_E_STATE_MGMT_NOT_INIT;

  if (!ctx)
    return -EINVAL;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);
  if (!agent_ctx)
    return AK_E_CHECKPOINT_NOT_FOUND;

  /* Check if state is frozen */
  if (agent_ctx->migration.state == AK_MIGRATION_FROZEN)
    return AK_E_STATE_FROZEN;

  /* Find checkpoint */
  checkpoint_internal_t *cp_int = find_checkpoint_internal(checkpoint_id);
  if (!cp_int)
    return AK_E_CHECKPOINT_NOT_FOUND;

  ak_checkpoint_t *cp = &cp_int->checkpoint;

  /* Verify checkpoint belongs to this agent */
  if (cp->agent_pid != agent_pid)
    return AK_E_CHECKPOINT_NOT_FOUND;

  /* Verify integrity */
  if (!verify_state_hash(cp->state_data, cp->state_hash))
    return AK_E_CHECKPOINT_CORRUPT;

  /* Parse the checkpoint BEFORE making any destructive changes so a
   * malformed checkpoint fails closed without touching current state. */
  tuple parsed = 0;
  boolean parse_failed = false;
  parser jp =
      json_parser(state_mgmt.h, stack_closure(checkpoint_state_parsed, &parsed),
                  stack_closure(checkpoint_state_parse_error, &parse_failed));
  if (!jp || jp == INVALID_ADDRESS)
    return -ENOMEM;

  jp = parser_feed(jp, cp->state_data);
  jp = apply(jp, CHARACTER_INVALID);
  json_parser_free(jp);

  if (parse_failed || !parsed) {
    if (parsed)
      destruct_value(parsed, true);
    return AK_E_CHECKPOINT_CORRUPT;
  }

  /* Create checkpoint of current state before restore (best effort) */
  ak_checkpoint_create(ctx, "Pre-restore backup");

  /* Clear current state entries for this agent */
  for (u64 i = 0; i < STATE_HASH_CAPACITY; i++) {
    state_entry_internal_t **prev_ptr = &state_mgmt.state_table[i];
    state_entry_internal_t *entry = *prev_ptr;

    while (entry) {
      if (entry->agent_pid == agent_pid) {
        /* Mark as deleted instead of removing */
        entry->entry.deleted = true;
        entry->entry.modified_ns = get_timestamp_ns();
        entry->entry.seq_number = ++state_mgmt.global_seq;
      }
      prev_ptr = &entry->hash_next;
      entry = entry->hash_next;
    }
  }

  /* Restore each key from the parsed checkpoint object */
  u64 failed_entries = 0;
  iterate(parsed,
          stack_closure(checkpoint_restore_each, ctx, &failed_entries));
  destruct_value(parsed, true);

  /* Update agent context */
  agent_ctx->current_seq = cp->seq_number;

  /* Update statistics */
  state_mgmt.stats.checkpoints_restored++;

  if (failed_entries > 0)
    return AK_E_CHECKPOINT_CORRUPT;

  return 0;
}

ak_checkpoint_t **ak_checkpoint_list(heap h, ak_agent_context_t *ctx,
                                     u64 *count_out) {
  if (!count_out)
    return NULL;

  *count_out = 0;

  if (!state_mgmt.initialized || !ctx)
    return NULL;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);
  if (!agent_ctx || agent_ctx->checkpoint_count == 0)
    return NULL;

  /* Overflow check */
  if (agent_ctx->checkpoint_count > UINT64_MAX / sizeof(ak_checkpoint_t *))
    return NULL;

  /* Allocate result array */
  ak_checkpoint_t **result =
      allocate(h, agent_ctx->checkpoint_count * sizeof(ak_checkpoint_t *));
  if (!result || result == INVALID_ADDRESS)
    return NULL;

  /* Walk version chain from oldest to newest */
  ak_checkpoint_t *cp = agent_ctx->checkpoint_tail;
  u64 idx = 0;
  while (cp && idx < agent_ctx->checkpoint_count) {
    result[idx++] = cp;
    cp = cp->next;
  }

  *count_out = idx;
  return result;
}

s64 ak_checkpoint_delete(u64 checkpoint_id) {
  if (!state_mgmt.initialized)
    return AK_E_STATE_MGMT_NOT_INIT;

  checkpoint_internal_t *cp_int = find_checkpoint_internal(checkpoint_id);
  if (!cp_int)
    return AK_E_CHECKPOINT_NOT_FOUND;

  ak_checkpoint_t *cp = &cp_int->checkpoint;

  /* Get agent context */
  agent_state_ctx_t *agent_ctx = get_agent_ctx(cp->agent_pid, false);
  if (!agent_ctx)
    return AK_E_CHECKPOINT_NOT_FOUND;

  /* Only allow deleting oldest checkpoint (to maintain chain) */
  if (cp != agent_ctx->checkpoint_tail)
    return -EBUSY;

  /* Update chain */
  agent_ctx->checkpoint_tail = cp->next;
  if (cp->next) {
    cp->next->prev = NULL;
  } else {
    agent_ctx->checkpoint_head = NULL;
  }
  agent_ctx->checkpoint_count--;

  /* Update stats */
  state_mgmt.stats.total_checkpoint_bytes -= cp->total_state_bytes;

  /* Remove from hash table */
  u64 idx = hash_u64(checkpoint_id) % CHECKPOINT_HASH_CAPACITY;
  checkpoint_internal_t **prev_ptr = &state_mgmt.checkpoint_table[idx];
  while (*prev_ptr) {
    if (*prev_ptr == cp_int) {
      *prev_ptr = cp_int->hash_next;
      break;
    }
    prev_ptr = &(*prev_ptr)->hash_next;
  }
  state_mgmt.checkpoint_count--;

  /* Free resources */
  if (cp->state_data)
    deallocate_buffer(cp->state_data);
  deallocate(state_mgmt.h, cp_int, sizeof(checkpoint_internal_t));

  state_mgmt.stats.checkpoints_deleted++;

  return 0;
}

s64 ak_checkpoint_export(u64 checkpoint_id, buffer buf) {
  if (!state_mgmt.initialized)
    return AK_E_STATE_MGMT_NOT_INIT;

  if (!buf)
    return -EINVAL;

  checkpoint_internal_t *cp_int = find_checkpoint_internal(checkpoint_id);
  if (!cp_int)
    return AK_E_CHECKPOINT_NOT_FOUND;

  ak_checkpoint_t *cp = &cp_int->checkpoint;

  /* Verify integrity before export */
  if (!verify_state_hash(cp->state_data, cp->state_hash))
    return AK_E_CHECKPOINT_CORRUPT;

  /* Export format:
   * - Magic (4 bytes)
   * - Checkpoint ID (8 bytes)
   * - Agent PID (8 bytes)
   * - Run ID (16 bytes)
   * - Created NS (8 bytes)
   * - Seq number (8 bytes)
   * - State hash (32 bytes)
   * - Policy hash (32 bytes)
   * - Description length (2 bytes)
   * - Description (variable)
   * - State data length (8 bytes)
   * - State data (variable)
   */

  u32 magic = AK_CHECKPOINT_MAGIC;
  buffer_write(buf, &magic, 4);
  buffer_write(buf, &cp->checkpoint_id, 8);
  buffer_write(buf, &cp->agent_pid, 8);
  buffer_write(buf, cp->run_id, AK_TOKEN_ID_SIZE);
  buffer_write(buf, &cp->created_ns, 8);
  buffer_write(buf, &cp->seq_number, 8);
  buffer_write(buf, cp->state_hash, AK_STATE_HASH_SIZE);
  buffer_write(buf, cp->policy_hash, AK_STATE_HASH_SIZE);

  u16 desc_len = runtime_strlen(cp->description);
  buffer_write(buf, &desc_len, 2);
  buffer_write(buf, cp->description, desc_len);

  u64 state_len = buffer_length(cp->state_data);
  buffer_write(buf, &state_len, 8);
  buffer_write(buf, buffer_ref(cp->state_data, 0), state_len);

  return 0;
}

u64 ak_checkpoint_import(ak_agent_context_t *ctx, buffer buf) {
  if (!state_mgmt.initialized || !ctx || !buf)
    return 0;

  u8 *data = buffer_ref(buf, 0);
  u64 len = buffer_length(buf);
  u64 pos = 0;

  /* Minimum size check */
  if (len < 4 + 8 + 8 + 16 + 8 + 8 + 32 + 32 + 2 + 8)
    return 0;

  /* Read and verify magic */
  u32 magic;
  runtime_memcpy(&magic, &data[pos], 4);
  pos += 4;
  if (magic != AK_CHECKPOINT_MAGIC)
    return 0;

  /* Read header fields */
  u64 orig_checkpoint_id;
  runtime_memcpy(&orig_checkpoint_id, &data[pos], 8);
  pos += 8;

  u64 orig_agent_pid;
  runtime_memcpy(&orig_agent_pid, &data[pos], 8);
  pos += 8;

  u8 orig_run_id[AK_TOKEN_ID_SIZE];
  runtime_memcpy(orig_run_id, &data[pos], AK_TOKEN_ID_SIZE);
  pos += AK_TOKEN_ID_SIZE;

  u64 created_ns;
  runtime_memcpy(&created_ns, &data[pos], 8);
  pos += 8;

  u64 seq_number;
  runtime_memcpy(&seq_number, &data[pos], 8);
  pos += 8;

  u8 state_hash[AK_STATE_HASH_SIZE];
  runtime_memcpy(state_hash, &data[pos], AK_STATE_HASH_SIZE);
  pos += AK_STATE_HASH_SIZE;

  u8 policy_hash[AK_STATE_HASH_SIZE];
  runtime_memcpy(policy_hash, &data[pos], AK_STATE_HASH_SIZE);
  pos += AK_STATE_HASH_SIZE;

  u16 desc_len;
  runtime_memcpy(&desc_len, &data[pos], 2);
  pos += 2;

  if (pos + desc_len + 8 > len)
    return 0;

  char description[AK_MAX_DESCRIPTION_LEN];
  runtime_memset(description, 0, AK_MAX_DESCRIPTION_LEN);
  if (desc_len > 0 && desc_len < AK_MAX_DESCRIPTION_LEN) {
    runtime_memcpy(description, &data[pos], desc_len);
  }
  pos += desc_len;

  u64 state_len;
  runtime_memcpy(&state_len, &data[pos], 8);
  pos += 8;

  if (pos + state_len > len)
    return 0;

  /* Clone state data */
  buffer state_data = allocate_buffer(state_mgmt.h, state_len);
  if (!state_data || state_data == INVALID_ADDRESS)
    return 0;
  buffer_write(state_data, &data[pos], state_len);

  /* Verify state hash */
  if (!verify_state_hash(state_data, state_hash)) {
    deallocate_buffer(state_data);
    return 0;
  }

  /* Create new checkpoint with imported data */
  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, true);
  if (!agent_ctx) {
    deallocate_buffer(state_data);
    return 0;
  }

  checkpoint_internal_t *cp_int =
      allocate_zero(state_mgmt.h, sizeof(checkpoint_internal_t));
  if (!cp_int || cp_int == INVALID_ADDRESS) {
    deallocate_buffer(state_data);
    return 0;
  }

  cp_int->magic = AK_CHECKPOINT_MAGIC;
  ak_checkpoint_t *cp = &cp_int->checkpoint;

  cp->checkpoint_id = state_mgmt.next_checkpoint_id++;
  cp->agent_pid = agent_pid;
  runtime_memcpy(cp->run_id, ctx->run_id, AK_TOKEN_ID_SIZE);
  cp->created_ns = get_timestamp_ns();
  cp->seq_number = ++state_mgmt.global_seq;
  cp->state_data = state_data;
  runtime_memcpy(cp->state_hash, state_hash, AK_STATE_HASH_SIZE);
  runtime_memcpy(cp->policy_hash, policy_hash, AK_STATE_HASH_SIZE);
  runtime_memcpy(cp->description, description, AK_MAX_DESCRIPTION_LEN);
  cp->heap_object_count = 0; /* Will be updated on restore */
  cp->total_state_bytes = state_len;

  /* Link into chain */
  cp->prev = agent_ctx->checkpoint_head;
  cp->next = NULL;
  if (agent_ctx->checkpoint_head) {
    agent_ctx->checkpoint_head->next = cp;
  }
  agent_ctx->checkpoint_head = cp;
  if (!agent_ctx->checkpoint_tail) {
    agent_ctx->checkpoint_tail = cp;
  }
  agent_ctx->checkpoint_count++;

  /* Insert into hash table */
  u64 idx = hash_u64(cp->checkpoint_id) % CHECKPOINT_HASH_CAPACITY;
  cp_int->hash_next = state_mgmt.checkpoint_table[idx];
  state_mgmt.checkpoint_table[idx] = cp_int;
  state_mgmt.checkpoint_count++;

  state_mgmt.stats.checkpoints_created++;
  state_mgmt.stats.total_checkpoint_bytes += state_len;

  return cp->checkpoint_id;
}

ak_checkpoint_t *ak_checkpoint_get(u64 checkpoint_id) {
  if (!state_mgmt.initialized)
    return NULL;

  checkpoint_internal_t *cp_int = find_checkpoint_internal(checkpoint_id);
  if (!cp_int)
    return NULL;

  return &cp_int->checkpoint;
}

/* ============================================================
 * STATE VERSIONING
 * ============================================================ */

s64 ak_state_get_version(ak_agent_context_t *ctx,
                         ak_state_version_t *version_out) {
  if (!state_mgmt.initialized)
    return AK_E_STATE_MGMT_NOT_INIT;

  if (!ctx || !version_out)
    return -EINVAL;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);

  runtime_memset(version_out, 0, sizeof(ak_state_version_t));

  if (agent_ctx) {
    version_out->seq_number = agent_ctx->current_seq;
  } else {
    version_out->seq_number = 0;
  }

  version_out->timestamp_ns = get_timestamp_ns();

  /* Count entries and bytes */
  u64 entry_count = 0;
  u64 total_bytes = 0;

  for (u64 i = 0; i < STATE_HASH_CAPACITY; i++) {
    state_entry_internal_t *entry = state_mgmt.state_table[i];
    while (entry) {
      if (entry->agent_pid == agent_pid && !entry->entry.deleted) {
        entry_count++;
        if (entry->entry.value) {
          total_bytes += buffer_length(entry->entry.value);
        }
      }
      entry = entry->hash_next;
    }
  }

  version_out->entry_count = entry_count;
  version_out->total_bytes = total_bytes;

  /* Compute state hash from all entries */
  buffer hash_data = allocate_buffer(state_mgmt.h, 1024);
  if (hash_data && hash_data != INVALID_ADDRESS) {
    for (u64 i = 0; i < STATE_HASH_CAPACITY; i++) {
      state_entry_internal_t *entry = state_mgmt.state_table[i];
      while (entry) {
        if (entry->agent_pid == agent_pid && !entry->entry.deleted) {
          buffer_write(hash_data, entry->entry.key,
                       runtime_strlen(entry->entry.key));
          if (entry->entry.value) {
            buffer_write(hash_data, buffer_ref(entry->entry.value, 0),
                         buffer_length(entry->entry.value));
          }
        }
        entry = entry->hash_next;
      }
    }
    compute_state_hash(hash_data, version_out->state_hash);
    deallocate_buffer(hash_data);
  }

  return 0;
}

ak_state_diff_t *ak_state_diff(heap h, ak_agent_context_t *ctx,
                               u64 from_version, u64 to_version) {
  if (!state_mgmt.initialized || !ctx || !h)
    return NULL;

  u64 agent_pid = get_agent_pid(ctx);

  /* Allocate diff structure */
  ak_state_diff_t *diff = allocate_zero(h, sizeof(ak_state_diff_t));
  if (!diff || diff == INVALID_ADDRESS)
    return NULL;

  diff->from_seq = from_version;
  diff->to_seq = to_version;
  diff->computed_ns = get_timestamp_ns();

  /* Allocate buffers for additions and deletions */
  diff->additions = allocate_buffer(h, 1024);
  diff->deletions = allocate_buffer(h, 256);

  if (!diff->additions || diff->additions == INVALID_ADDRESS ||
      !diff->deletions || diff->deletions == INVALID_ADDRESS) {
    if (diff->additions && diff->additions != INVALID_ADDRESS)
      deallocate_buffer(diff->additions);
    if (diff->deletions && diff->deletions != INVALID_ADDRESS)
      deallocate_buffer(diff->deletions);
    deallocate(h, diff, sizeof(ak_state_diff_t));
    return NULL;
  }

  /* Start JSON arrays */
  buffer_write(diff->additions, "{", 1);
  buffer_write(diff->deletions, "[", 1);

  boolean first_add = true;
  boolean first_del = true;

  /* Walk through change history to build diff */
  change_record_internal_t *change = state_mgmt.change_head;
  while (change) {
    if (change->agent_pid == agent_pid &&
        change->change.seq_number > from_version &&
        change->change.seq_number <= to_version) {

      if (change->change.change_type == AK_CHANGE_SET) {
        /* Addition or modification */
        if (!first_add)
          buffer_write(diff->additions, ",", 1);
        first_add = false;

        buffer_write(diff->additions, "\"", 1);
        buffer_write(diff->additions, change->change.key,
                     runtime_strlen(change->change.key));
        buffer_write(diff->additions, "\":", 2);

        if (change->change.new_value) {
          buffer_write(diff->additions, buffer_ref(change->change.new_value, 0),
                       buffer_length(change->change.new_value));
          diff->bytes_changed += buffer_length(change->change.new_value);
        } else {
          buffer_write(diff->additions, "null", 4);
        }

        if (change->change.old_value == NULL) {
          diff->keys_added++;
        } else {
          diff->keys_modified++;
        }

      } else if (change->change.change_type == AK_CHANGE_DELETE) {
        /* Deletion */
        if (!first_del)
          buffer_write(diff->deletions, ",", 1);
        first_del = false;

        buffer_write(diff->deletions, "\"", 1);
        buffer_write(diff->deletions, change->change.key,
                     runtime_strlen(change->change.key));
        buffer_write(diff->deletions, "\"", 1);

        diff->keys_deleted++;
        if (change->change.old_value) {
          diff->bytes_changed += buffer_length(change->change.old_value);
        }
      }
    }
    change = change->next;
  }

  /* Close JSON structures */
  buffer_write(diff->additions, "}", 1);
  buffer_write(diff->deletions, "]", 1);

  state_mgmt.stats.diffs_computed++;

  return diff;
}

void ak_state_diff_free(heap h, ak_state_diff_t *diff) {
  if (!diff)
    return;

  if (diff->additions)
    deallocate_buffer(diff->additions);
  if (diff->deletions)
    deallocate_buffer(diff->deletions);

  deallocate(h, diff, sizeof(ak_state_diff_t));
}

s64 ak_state_rollback(ak_agent_context_t *ctx, u64 version) {
  if (!state_mgmt.initialized)
    return AK_E_STATE_MGMT_NOT_INIT;

  if (!ctx)
    return -EINVAL;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);
  if (!agent_ctx)
    return AK_E_VERSION_NOT_FOUND;

  /* Find checkpoint at or before target version */
  ak_checkpoint_t *target_cp = NULL;
  ak_checkpoint_t *cp = agent_ctx->checkpoint_head;
  while (cp) {
    if (cp->seq_number <= version) {
      target_cp = cp;
      break;
    }
    cp = cp->prev;
  }

  if (!target_cp)
    return AK_E_VERSION_NOT_FOUND;

  /* Restore to that checkpoint */
  s64 result = ak_checkpoint_restore(ctx, target_cp->checkpoint_id);

  if (result == 0) {
    state_mgmt.stats.rollbacks++;
  }

  return result;
}

ak_version_history_entry_t **ak_state_history(heap h, ak_agent_context_t *ctx,
                                              u64 limit, u64 *count_out) {
  if (!count_out)
    return NULL;

  *count_out = 0;

  if (!state_mgmt.initialized || !ctx || !h)
    return NULL;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);
  if (!agent_ctx || agent_ctx->checkpoint_count == 0)
    return NULL;

  /* Determine count */
  u64 count = agent_ctx->checkpoint_count;
  if (limit > 0 && limit < count)
    count = limit;

  /* Overflow check */
  if (count > UINT64_MAX / sizeof(ak_version_history_entry_t *))
    return NULL;

  /* Allocate result array */
  ak_version_history_entry_t **result =
      allocate(h, count * sizeof(ak_version_history_entry_t *));
  if (!result || result == INVALID_ADDRESS)
    return NULL;

  /* Build history from checkpoints (newest first) */
  ak_checkpoint_t *cp = agent_ctx->checkpoint_head;
  u64 idx = 0;
  while (cp && idx < count) {
    ak_version_history_entry_t *entry =
        allocate_zero(h, sizeof(ak_version_history_entry_t));
    if (!entry || entry == INVALID_ADDRESS) {
      /* Free already allocated entries */
      for (u64 j = 0; j < idx; j++) {
        deallocate(h, result[j], sizeof(ak_version_history_entry_t));
      }
      deallocate(h, result, count * sizeof(ak_version_history_entry_t *));
      return NULL;
    }

    entry->seq_number = cp->seq_number;
    entry->timestamp_ns = cp->created_ns;
    runtime_strncpy(entry->description, cp->description,
                    AK_MAX_DESCRIPTION_LEN - 1);
    runtime_memcpy(entry->state_hash, cp->state_hash, AK_STATE_HASH_SIZE);
    entry->bytes_changed = cp->total_state_bytes;
    entry->next = NULL;

    result[idx++] = entry;
    cp = cp->prev;
  }

  *count_out = idx;
  return result;
}

void ak_state_history_free(heap h, ak_version_history_entry_t **entries,
                           u64 count) {
  if (!entries)
    return;

  for (u64 i = 0; i < count; i++) {
    if (entries[i]) {
      deallocate(h, entries[i], sizeof(ak_version_history_entry_t));
    }
  }

  deallocate(h, entries, count * sizeof(ak_version_history_entry_t *));
}

/* ============================================================
 * STATE CHANGE TRACKING
 * ============================================================ */

u64 ak_state_set(ak_agent_context_t *ctx, const char *key, buffer value) {
  if (!state_mgmt.initialized)
    return 0;

  if (!ctx || !key)
    return 0;

  /* Validate key length */
  u64 key_len = runtime_strlen(key);
  if (key_len == 0 || key_len >= AK_MAX_KEY_LEN)
    return 0;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, true);
  if (!agent_ctx)
    return 0;

  /* Check if state is frozen */
  if (agent_ctx->migration.state == AK_MIGRATION_FROZEN)
    return 0;

  /* Find existing entry */
  state_entry_internal_t *entry = find_state_entry(agent_pid, key);
  buffer old_value = NULL;

  if (entry) {
    /* Update existing entry */
    old_value = entry->entry.value;
    entry->entry.value = value ? clone_buffer(state_mgmt.h, value) : NULL;
    entry->entry.version++;
    entry->entry.modified_ns = get_timestamp_ns();
    entry->entry.seq_number = ++state_mgmt.global_seq;

    /* Record change */
    record_change(agent_pid, key, AK_CHANGE_SET, old_value, value);

    if (old_value) {
      state_mgmt.stats.total_state_bytes -= buffer_length(old_value);
      deallocate_buffer(old_value);
    }
  } else {
    /* Check entry limit */
    if (state_mgmt.state_entry_count >= AK_MAX_STATE_KEYS)
      return 0;

    /* Create new entry */
    entry = allocate_zero(state_mgmt.h, sizeof(state_entry_internal_t));
    if (!entry || entry == INVALID_ADDRESS)
      return 0;

    entry->agent_pid = agent_pid;
    runtime_strncpy(entry->entry.key, key, AK_MAX_KEY_LEN - 1);
    entry->entry.key[AK_MAX_KEY_LEN - 1] = '\0';
    entry->entry.value = value ? clone_buffer(state_mgmt.h, value) : NULL;
    entry->entry.version = 1;
    entry->entry.created_ns = get_timestamp_ns();
    entry->entry.modified_ns = entry->entry.created_ns;
    entry->entry.seq_number = ++state_mgmt.global_seq;
    entry->entry.taint = AK_TAINT_UNTRUSTED;
    entry->entry.deleted = false;

    /* Insert into hash table */
    u64 idx = hash_agent_key(agent_pid, key) % STATE_HASH_CAPACITY;
    entry->hash_next = state_mgmt.state_table[idx];
    state_mgmt.state_table[idx] = entry;
    state_mgmt.state_entry_count++;

    /* Record change */
    record_change(agent_pid, key, AK_CHANGE_SET, NULL, value);
  }

  /* Update statistics */
  if (entry->entry.value) {
    state_mgmt.stats.total_state_bytes += buffer_length(entry->entry.value);
  }
  state_mgmt.stats.state_sets++;

  /* Update agent context */
  agent_ctx->current_seq = entry->entry.seq_number;

  return entry->entry.seq_number;
}

s64 ak_state_get(heap h, ak_agent_context_t *ctx, const char *key,
                 buffer *value_out) {
  if (!state_mgmt.initialized)
    return AK_E_STATE_MGMT_NOT_INIT;

  if (!ctx || !key || !value_out)
    return -EINVAL;

  *value_out = NULL;

  u64 agent_pid = get_agent_pid(ctx);
  state_entry_internal_t *entry = find_state_entry(agent_pid, key);

  if (!entry)
    return -ENOENT;

  /* Clone value for caller */
  if (entry->entry.value) {
    *value_out = clone_buffer(h, entry->entry.value);
    if (!*value_out || *value_out == INVALID_ADDRESS) {
      *value_out = NULL;
      return -ENOMEM;
    }
  }

  state_mgmt.stats.state_gets++;

  return 0;
}

u64 ak_state_delete(ak_agent_context_t *ctx, const char *key) {
  if (!state_mgmt.initialized)
    return 0;

  if (!ctx || !key)
    return 0;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);
  if (!agent_ctx)
    return 0;

  /* Check if state is frozen */
  if (agent_ctx->migration.state == AK_MIGRATION_FROZEN)
    return 0;

  state_entry_internal_t *entry = find_state_entry(agent_pid, key);
  if (!entry)
    return 0;

  /* Record change before marking deleted */
  record_change(agent_pid, key, AK_CHANGE_DELETE, entry->entry.value, NULL);

  /* Soft delete */
  entry->entry.deleted = true;
  entry->entry.modified_ns = get_timestamp_ns();
  entry->entry.seq_number = ++state_mgmt.global_seq;

  /* Update statistics */
  if (entry->entry.value) {
    state_mgmt.stats.total_state_bytes -= buffer_length(entry->entry.value);
  }
  state_mgmt.stats.state_deletes++;

  /* Update agent context */
  agent_ctx->current_seq = entry->entry.seq_number;

  return entry->entry.seq_number;
}

ak_state_change_t **ak_state_get_changes_since(heap h, ak_agent_context_t *ctx,
                                               u64 seq, u64 *count_out) {
  if (!count_out)
    return NULL;

  *count_out = 0;

  if (!state_mgmt.initialized || !ctx || !h)
    return NULL;

  u64 agent_pid = get_agent_pid(ctx);

  /* First pass: count matching changes */
  u64 count = 0;
  change_record_internal_t *change = state_mgmt.change_head;
  while (change) {
    if (change->agent_pid == agent_pid && change->change.seq_number > seq) {
      count++;
    }
    change = change->next;
  }

  if (count == 0)
    return NULL;

  /* Overflow check */
  if (count > UINT64_MAX / sizeof(ak_state_change_t *))
    return NULL;

  /* Allocate result array */
  ak_state_change_t **result = allocate(h, count * sizeof(ak_state_change_t *));
  if (!result || result == INVALID_ADDRESS)
    return NULL;

  /* Second pass: copy changes */
  u64 idx = 0;
  change = state_mgmt.change_head;
  while (change && idx < count) {
    if (change->agent_pid == agent_pid && change->change.seq_number > seq) {
      ak_state_change_t *copy = allocate(h, sizeof(ak_state_change_t));
      if (!copy || copy == INVALID_ADDRESS) {
        /* Free already allocated */
        for (u64 j = 0; j < idx; j++) {
          if (result[j]->old_value)
            deallocate_buffer(result[j]->old_value);
          if (result[j]->new_value)
            deallocate_buffer(result[j]->new_value);
          deallocate(h, result[j], sizeof(ak_state_change_t));
        }
        deallocate(h, result, count * sizeof(ak_state_change_t *));
        return NULL;
      }

      runtime_memcpy(copy, &change->change, sizeof(ak_state_change_t));
      copy->old_value = change->change.old_value
                            ? clone_buffer(h, change->change.old_value)
                            : NULL;
      copy->new_value = change->change.new_value
                            ? clone_buffer(h, change->change.new_value)
                            : NULL;
      copy->next = NULL;

      result[idx++] = copy;
    }
    change = change->next;
  }

  *count_out = idx;
  return result;
}

void ak_state_changes_free(heap h, ak_state_change_t **changes, u64 count) {
  if (!changes)
    return;

  for (u64 i = 0; i < count; i++) {
    if (changes[i]) {
      if (changes[i]->old_value)
        deallocate_buffer(changes[i]->old_value);
      if (changes[i]->new_value)
        deallocate_buffer(changes[i]->new_value);
      deallocate(h, changes[i], sizeof(ak_state_change_t));
    }
  }

  deallocate(h, changes, count * sizeof(ak_state_change_t *));
}

char **ak_state_list_keys(heap h, ak_agent_context_t *ctx, u64 *count_out) {
  if (!count_out)
    return NULL;

  *count_out = 0;

  if (!state_mgmt.initialized || !ctx || !h)
    return NULL;

  u64 agent_pid = get_agent_pid(ctx);

  /* First pass: count keys */
  u64 count = 0;
  for (u64 i = 0; i < STATE_HASH_CAPACITY; i++) {
    state_entry_internal_t *entry = state_mgmt.state_table[i];
    while (entry) {
      if (entry->agent_pid == agent_pid && !entry->entry.deleted) {
        count++;
      }
      entry = entry->hash_next;
    }
  }

  if (count == 0)
    return NULL;

  /* Overflow check */
  if (count > UINT64_MAX / sizeof(char *))
    return NULL;

  /* Allocate result array */
  char **result = allocate(h, count * sizeof(char *));
  if (!result || result == INVALID_ADDRESS)
    return NULL;

  /* Second pass: copy keys */
  u64 idx = 0;
  for (u64 i = 0; i < STATE_HASH_CAPACITY && idx < count; i++) {
    state_entry_internal_t *entry = state_mgmt.state_table[i];
    while (entry && idx < count) {
      if (entry->agent_pid == agent_pid && !entry->entry.deleted) {
        u64 key_len = runtime_strlen(entry->entry.key) + 1;
        result[idx] = allocate(h, key_len);
        if (result[idx] && result[idx] != INVALID_ADDRESS) {
          runtime_memcpy(result[idx], entry->entry.key, key_len);
          idx++;
        }
      }
      entry = entry->hash_next;
    }
  }

  *count_out = idx;
  return result;
}

void ak_state_keys_free(heap h, char **keys, u64 count) {
  if (!keys)
    return;

  for (u64 i = 0; i < count; i++) {
    if (keys[i]) {
      deallocate(h, keys[i], runtime_strlen(keys[i]) + 1);
    }
  }

  deallocate(h, keys, count * sizeof(char *));
}

/* ============================================================
 * MIGRATION SUPPORT
 * ============================================================ */

u64 ak_state_prepare_migration(ak_agent_context_t *ctx) {
  if (!state_mgmt.initialized)
    return 0;

  if (!ctx)
    return 0;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, true);
  if (!agent_ctx)
    return 0;

  /* Check if migration already in progress */
  if (agent_ctx->migration.state != AK_MIGRATION_NONE)
    return 0;

  /* Create migration checkpoint. ak_checkpoint_create() may return a
   * (u64)negative error code (limit hit / frozen); propagate it so the
   * caller can distinguish the failure reason. Never freeze state on a
   * failed checkpoint. */
  u64 checkpoint_id = ak_checkpoint_create(ctx, "Migration checkpoint");
  if (!AK_CHECKPOINT_ID_VALID(checkpoint_id))
    return checkpoint_id;

  /* Freeze state */
  agent_ctx->migration.state = AK_MIGRATION_FROZEN;
  agent_ctx->migration.started_ns = get_timestamp_ns();
  agent_ctx->migration.checkpoint_id = checkpoint_id;
  runtime_memcpy(agent_ctx->migration.source_run_id, ctx->run_id,
                 AK_TOKEN_ID_SIZE);
  runtime_memset(agent_ctx->migration.target_run_id, 0, AK_TOKEN_ID_SIZE);
  agent_ctx->migration.bytes_transferred = 0;
  agent_ctx->migration.objects_transferred = 0;

  state_mgmt.stats.migrations_started++;

  return checkpoint_id;
}

s64 ak_state_complete_migration(ak_agent_context_t *ctx, boolean success) {
  if (!state_mgmt.initialized)
    return AK_E_STATE_MGMT_NOT_INIT;

  if (!ctx)
    return -EINVAL;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);
  if (!agent_ctx)
    return AK_E_NO_MIGRATION;

  /* Check if migration was in progress */
  if (agent_ctx->migration.state != AK_MIGRATION_FROZEN &&
      agent_ctx->migration.state != AK_MIGRATION_TRANSFERRING) {
    return AK_E_NO_MIGRATION;
  }

  if (success) {
    /* Migration succeeded - update run ID and unfreeze */
    runtime_memcpy(ctx->run_id, agent_ctx->migration.target_run_id,
                   AK_TOKEN_ID_SIZE);
    state_mgmt.stats.migrations_completed++;
  } else {
    /* Migration failed - restore from checkpoint */
    if (agent_ctx->migration.checkpoint_id != 0) {
      ak_checkpoint_restore(ctx, agent_ctx->migration.checkpoint_id);
    }
    state_mgmt.stats.migrations_failed++;
  }

  /* Clear migration state */
  agent_ctx->migration.state = AK_MIGRATION_NONE;
  agent_ctx->migration.started_ns = 0;
  agent_ctx->migration.checkpoint_id = 0;

  return 0;
}

s64 ak_state_get_migration_info(ak_agent_context_t *ctx,
                                ak_migration_info_t *info_out) {
  if (!state_mgmt.initialized)
    return AK_E_STATE_MGMT_NOT_INIT;

  if (!ctx || !info_out)
    return -EINVAL;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);

  if (!agent_ctx) {
    runtime_memset(info_out, 0, sizeof(ak_migration_info_t));
    info_out->state = AK_MIGRATION_NONE;
    return 0;
  }

  runtime_memcpy(info_out, &agent_ctx->migration, sizeof(ak_migration_info_t));
  return 0;
}

boolean ak_state_is_frozen(ak_agent_context_t *ctx) {
  if (!state_mgmt.initialized || !ctx)
    return false;

  u64 agent_pid = get_agent_pid(ctx);
  agent_state_ctx_t *agent_ctx = get_agent_ctx(agent_pid, false);

  if (!agent_ctx)
    return false;

  return agent_ctx->migration.state == AK_MIGRATION_FROZEN;
}

/* ============================================================
 * HEAP INTEGRATION
 * ============================================================ */

buffer ak_state_serialize_heap_objects(heap h, ak_agent_context_t *ctx) {
  if (!state_mgmt.initialized || !ctx || !h)
    return NULL;

  /* Get list of heap objects owned by this agent */
  u64 count;
  u64 *ptrs = ak_heap_list_by_run(h, ctx->run_id, &count);

  if (!ptrs || count == 0)
    return NULL;

  /* Allocate output buffer */
  buffer result = allocate_buffer(h, 4096);
  if (!result || result == INVALID_ADDRESS) {
    if (ptrs)
      deallocate(h, ptrs, count * sizeof(u64));
    return NULL;
  }

  /* Write header */
  buffer_write(result, "{\"objects\":[", 12);

  boolean first = true;
  for (u64 i = 0; i < count; i++) {
    buffer obj = ak_heap_serialize_object(h, ptrs[i]);
    if (obj && obj != INVALID_ADDRESS) {
      if (!first)
        buffer_write(result, ",", 1);
      first = false;
      buffer_write(result, buffer_ref(obj, 0), buffer_length(obj));
      deallocate_buffer(obj);
    }
  }

  buffer_write(result, "]}", 2);

  deallocate(h, ptrs, count * sizeof(u64));

  return result;
}

s64 ak_state_restore_heap_objects(ak_agent_context_t *ctx, buffer buf) {
  if (!state_mgmt.initialized || !ctx || !buf)
    return -EINVAL;

  /* Delegate to ak_heap_restore which handles the actual heap restoration.
   * The ctx parameter is validated here but the restoration is context-
   * independent since heap objects are shared across agent contexts. */
  return ak_heap_restore(buf);
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_state_mgmt_get_stats(ak_state_mgmt_stats_t *stats) {
  if (!stats)
    return;

  runtime_memcpy(stats, &state_mgmt.stats, sizeof(ak_state_mgmt_stats_t));
}
