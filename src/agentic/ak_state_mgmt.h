/*
 * Authority Kernel - State Management (Checkpoint/Restore, Versioning)
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides state management infrastructure for agents:
 *   - Checkpoint creation and restoration
 *   - State versioning with history tracking
 *   - State change tracking and diffs
 *   - Migration support for agent state transfer
 *
 * SECURITY:
 *   - All checkpoints include SHA-256 integrity hash
 *   - State changes are logged to audit trail
 *   - Version chain provides tamper evidence
 */

#ifndef AK_STATE_MGMT_H
#define AK_STATE_MGMT_H

#include "ak_heap.h"
#include "ak_types.h"

/* ============================================================
 * CONSTANTS
 * ============================================================ */

#define AK_CHECKPOINT_MAGIC 0x414B4350 /* "AKCP" */
#define AK_MAX_CHECKPOINTS 256
#define AK_MAX_STATE_KEYS 4096
#define AK_MAX_KEY_LEN 256
#define AK_MAX_DESCRIPTION_LEN 128
#define AK_STATE_HASH_SIZE 32 /* SHA-256 */

/*
 * Checkpoint-ID returning functions (ak_checkpoint_create,
 * ak_checkpoint_import, ak_state_prepare_migration) return:
 *   > 0                 - valid checkpoint ID (IDs are small positive
 *                         monotonic values, always < 2^63)
 *   0                   - generic failure (not initialized, OOM, ...)
 *   (u64)negative AK_E_ - specific failure, e.g.
 *                         (u64)AK_E_TOO_MANY_CHECKPOINTS or
 *                         (u64)AK_E_STATE_FROZEN
 * Use this macro to test for success.
 */
#define AK_CHECKPOINT_ID_VALID(id) ((s64)(id) > 0)

/* ============================================================
 * STATE CHECKPOINT
 * ============================================================
 * Represents a point-in-time snapshot of agent state.
 */

typedef struct ak_checkpoint {
  u64 checkpoint_id;                 /* Unique checkpoint identifier */
  u64 agent_pid;                     /* Owning agent's PID */
  u8 run_id[AK_TOKEN_ID_SIZE];       /* Run ID when checkpoint was created */
  u64 created_ns;                    /* Creation timestamp (nanoseconds) */
  u64 seq_number;                    /* Monotonic sequence number */
  buffer state_data;                 /* Serialized state */
  u8 state_hash[AK_STATE_HASH_SIZE]; /* SHA-256 of state */
  char description[AK_MAX_DESCRIPTION_LEN]; /* Human-readable description */
  struct ak_checkpoint *prev; /* Previous checkpoint in version chain */
  struct ak_checkpoint *next; /* Next checkpoint in version chain */

  /* Metadata for restore */
  u64 heap_object_count;              /* Number of heap objects at checkpoint */
  u64 total_state_bytes;              /* Total bytes in state_data */
  u8 policy_hash[AK_STATE_HASH_SIZE]; /* Policy hash at checkpoint */
} ak_checkpoint_t;

/* ============================================================
 * STATE DIFF
 * ============================================================
 * Represents changes between two state versions.
 */

typedef struct ak_state_diff {
  u64 from_seq;      /* Source sequence number */
  u64 to_seq;        /* Target sequence number */
  buffer additions;  /* New/changed key-value pairs (JSON) */
  buffer deletions;  /* Removed keys (JSON array) */
  u64 bytes_changed; /* Total bytes modified */
  u64 keys_added;    /* Count of new keys */
  u64 keys_modified; /* Count of modified keys */
  u64 keys_deleted;  /* Count of deleted keys */
  u64 computed_ns;   /* When diff was computed */
} ak_state_diff_t;

/* ============================================================
 * STATE KEY-VALUE ENTRY
 * ============================================================
 * Internal structure for tracking state changes.
 */

typedef struct ak_state_entry {
  char key[AK_MAX_KEY_LEN];    /* Key name */
  buffer value;                /* Current value (JSON) */
  u64 version;                 /* Entry version */
  u64 created_ns;              /* When entry was created */
  u64 modified_ns;             /* When entry was last modified */
  u64 seq_number;              /* Sequence when last modified */
  ak_taint_t taint;            /* Taint level of value */
  boolean deleted;             /* Soft-delete flag */
  struct ak_state_entry *next; /* Hash chain */
} ak_state_entry_t;

/* ============================================================
 * STATE CHANGE RECORD
 * ============================================================
 * Tracks individual state modifications for history.
 */

typedef struct ak_state_change {
  u64 seq_number;           /* Sequence number of change */
  u64 timestamp_ns;         /* When change occurred */
  char key[AK_MAX_KEY_LEN]; /* Affected key */
  enum {
    AK_CHANGE_SET,   /* Key was set/updated */
    AK_CHANGE_DELETE /* Key was deleted */
  } change_type;
  buffer old_value;             /* Previous value (NULL for new keys) */
  buffer new_value;             /* New value (NULL for deletes) */
  struct ak_state_change *next; /* Next change in history */
} ak_state_change_t;

/* ============================================================
 * STATE VERSION INFO
 * ============================================================
 */

typedef struct ak_state_version {
  u64 seq_number;                    /* Current sequence number */
  u64 timestamp_ns;                  /* Timestamp of last change */
  u64 entry_count;                   /* Total state entries */
  u64 total_bytes;                   /* Total state size */
  u8 state_hash[AK_STATE_HASH_SIZE]; /* Current state hash */
} ak_state_version_t;

/* ============================================================
 * VERSION HISTORY ENTRY
 * ============================================================
 */

typedef struct ak_version_history_entry {
  u64 seq_number;
  u64 timestamp_ns;
  char description[AK_MAX_DESCRIPTION_LEN];
  u8 state_hash[AK_STATE_HASH_SIZE];
  u64 bytes_changed;
  struct ak_version_history_entry *next;
} ak_version_history_entry_t;

/* ============================================================
 * MIGRATION STATE
 * ============================================================
 */

typedef enum ak_migration_state {
  AK_MIGRATION_NONE = 0,         /* No migration in progress */
  AK_MIGRATION_PREPARING = 1,    /* Preparing for migration */
  AK_MIGRATION_FROZEN = 2,       /* State frozen for transfer */
  AK_MIGRATION_TRANSFERRING = 3, /* State being transferred */
  AK_MIGRATION_COMPLETING = 4,   /* Completing migration */
} ak_migration_state_t;

typedef struct ak_migration_info {
  ak_migration_state_t state;
  u64 started_ns;    /* When migration started */
  u64 checkpoint_id; /* Checkpoint for migration */
  u8 source_run_id[AK_TOKEN_ID_SIZE];
  u8 target_run_id[AK_TOKEN_ID_SIZE];
  u64 bytes_transferred;
  u64 objects_transferred;
} ak_migration_info_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize state management subsystem.
 *
 * Must be called after ak_heap_init().
 *
 * Parameters:
 *   h - Heap for allocations
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
int ak_state_mgmt_init(heap h);

/*
 * Shutdown state management subsystem.
 */
void ak_state_mgmt_shutdown(void);

/* ============================================================
 * CHECKPOINT OPERATIONS
 * ============================================================ */

/*
 * Create a new checkpoint of current agent state.
 *
 * Captures all state entries and heap objects owned by the agent.
 * The checkpoint is added to the version chain.
 *
 * Parameters:
 *   ctx         - Agent context
 *   description - Human-readable description (may be NULL)
 *
 * Returns:
 *   Checkpoint ID (> 0) on success; 0 on generic failure;
 *   (u64)AK_E_TOO_MANY_CHECKPOINTS when the per-agent checkpoint limit
 *   is reached; (u64)AK_E_STATE_FROZEN while state is frozen for
 *   migration. Test with AK_CHECKPOINT_ID_VALID().
 */
u64 ak_checkpoint_create(ak_agent_context_t *ctx, const char *description);

/*
 * Restore agent state from a checkpoint.
 *
 * Rolls back all state to the checkpoint's point-in-time snapshot.
 * The current state is preserved in a new checkpoint before restore.
 *
 * Parameters:
 *   ctx           - Agent context
 *   checkpoint_id - ID of checkpoint to restore
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
s64 ak_checkpoint_restore(ak_agent_context_t *ctx, u64 checkpoint_id);

/*
 * List available checkpoints for an agent.
 *
 * Returns array of checkpoint pointers. Caller must free the array.
 *
 * Parameters:
 *   h         - Heap for allocation
 *   ctx       - Agent context
 *   count_out - Output: number of checkpoints
 *
 * Returns:
 *   Array of checkpoint pointers, or NULL if none
 */
ak_checkpoint_t **ak_checkpoint_list(heap h, ak_agent_context_t *ctx,
                                     u64 *count_out);

/*
 * Delete a checkpoint.
 *
 * Removes the checkpoint and frees associated memory.
 * Cannot delete checkpoints that are part of the current version chain
 * unless they are the oldest.
 *
 * Parameters:
 *   checkpoint_id - ID of checkpoint to delete
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
s64 ak_checkpoint_delete(u64 checkpoint_id);

/*
 * Export a checkpoint for migration/backup.
 *
 * Serializes the checkpoint to a portable format.
 *
 * Parameters:
 *   checkpoint_id - ID of checkpoint to export
 *   buf           - Output buffer for serialized data
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
s64 ak_checkpoint_export(u64 checkpoint_id, buffer buf);

/*
 * Import a checkpoint from serialized data.
 *
 * Creates a new checkpoint from imported data.
 * Verifies integrity hash before accepting.
 *
 * Parameters:
 *   ctx - Agent context to associate with
 *   buf - Buffer containing serialized checkpoint
 *
 * Returns:
 *   New checkpoint ID on success, 0 on failure
 */
u64 ak_checkpoint_import(ak_agent_context_t *ctx, buffer buf);

/*
 * Get checkpoint by ID.
 *
 * Parameters:
 *   checkpoint_id - ID of checkpoint
 *
 * Returns:
 *   Pointer to checkpoint, or NULL if not found
 */
ak_checkpoint_t *ak_checkpoint_get(u64 checkpoint_id);

/* ============================================================
 * STATE VERSIONING
 * ============================================================ */

/*
 * Get current state version information.
 *
 * Parameters:
 *   ctx         - Agent context
 *   version_out - Output: version information
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
s64 ak_state_get_version(ak_agent_context_t *ctx,
                         ak_state_version_t *version_out);

/*
 * Compute diff between two state versions.
 *
 * Returns the changes needed to transform from_version to to_version.
 *
 * Parameters:
 *   h            - Heap for allocations
 *   ctx          - Agent context
 *   from_version - Source version sequence number
 *   to_version   - Target version sequence number
 *
 * Returns:
 *   State diff structure, or NULL on failure
 */
ak_state_diff_t *ak_state_diff(heap h, ak_agent_context_t *ctx,
                               u64 from_version, u64 to_version);

/*
 * Free a state diff structure.
 *
 * Parameters:
 *   h    - Heap used for allocation
 *   diff - Diff to free
 */
void ak_state_diff_free(heap h, ak_state_diff_t *diff);

/*
 * Rollback state to a specific version.
 *
 * Undoes all changes since the specified version.
 * Creates a checkpoint of current state before rollback.
 *
 * Parameters:
 *   ctx     - Agent context
 *   version - Target version sequence number
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
s64 ak_state_rollback(ak_agent_context_t *ctx, u64 version);

/*
 * Get version history for an agent.
 *
 * Returns the most recent 'limit' version history entries.
 *
 * Parameters:
 *   h         - Heap for allocations
 *   ctx       - Agent context
 *   limit     - Maximum entries to return (0 = all)
 *   count_out - Output: actual number of entries
 *
 * Returns:
 *   Array of history entries, or NULL if none
 */
ak_version_history_entry_t **ak_state_history(heap h, ak_agent_context_t *ctx,
                                              u64 limit, u64 *count_out);

/*
 * Free version history array.
 *
 * Parameters:
 *   h       - Heap used for allocation
 *   entries - Array to free
 *   count   - Number of entries
 */
void ak_state_history_free(heap h, ak_version_history_entry_t **entries,
                           u64 count);

/* ============================================================
 * STATE CHANGE TRACKING
 * ============================================================ */

/*
 * Set a state value (tracked).
 *
 * Updates or creates a state entry. The change is recorded
 * for versioning and audit purposes.
 *
 * Parameters:
 *   ctx   - Agent context
 *   key   - Key name (max AK_MAX_KEY_LEN)
 *   value - Value buffer (JSON)
 *
 * Returns:
 *   New version number on success, 0 on failure
 */
u64 ak_state_set(ak_agent_context_t *ctx, const char *key, buffer value);

/*
 * Get a state value.
 *
 * Parameters:
 *   h         - Heap for result allocation
 *   ctx       - Agent context
 *   key       - Key name
 *   value_out - Output: value buffer (caller must free)
 *
 * Returns:
 *   0 on success, -ENOENT if not found, other negative on error
 */
s64 ak_state_get(heap h, ak_agent_context_t *ctx, const char *key,
                 buffer *value_out);

/*
 * Delete a state key (tracked).
 *
 * Soft-deletes the state entry. The deletion is recorded
 * for versioning and can be undone via rollback.
 *
 * Parameters:
 *   ctx - Agent context
 *   key - Key name
 *
 * Returns:
 *   New version number on success, 0 on failure
 */
u64 ak_state_delete(ak_agent_context_t *ctx, const char *key);

/*
 * Get all state changes since a sequence number.
 *
 * Returns changes made after the specified sequence.
 *
 * Parameters:
 *   h         - Heap for allocations
 *   ctx       - Agent context
 *   seq       - Starting sequence number (exclusive)
 *   count_out - Output: number of changes
 *
 * Returns:
 *   Array of change records, or NULL if none
 */
ak_state_change_t **ak_state_get_changes_since(heap h, ak_agent_context_t *ctx,
                                               u64 seq, u64 *count_out);

/*
 * Free state changes array.
 *
 * Parameters:
 *   h       - Heap used for allocation
 *   changes - Array to free
 *   count   - Number of changes
 */
void ak_state_changes_free(heap h, ak_state_change_t **changes, u64 count);

/*
 * List all state keys for an agent.
 *
 * Parameters:
 *   h         - Heap for allocations
 *   ctx       - Agent context
 *   count_out - Output: number of keys
 *
 * Returns:
 *   Array of key strings, or NULL if none
 */
char **ak_state_list_keys(heap h, ak_agent_context_t *ctx, u64 *count_out);

/*
 * Free keys array.
 *
 * Parameters:
 *   h     - Heap used for allocation
 *   keys  - Array to free
 *   count - Number of keys
 */
void ak_state_keys_free(heap h, char **keys, u64 count);

/* ============================================================
 * MIGRATION SUPPORT
 * ============================================================ */

/*
 * Prepare state for migration.
 *
 * Freezes state modifications and creates a migration checkpoint.
 * State can only be read until migration completes.
 *
 * Parameters:
 *   ctx - Agent context
 *
 * Returns:
 *   Migration checkpoint ID (> 0) on success; 0 or a (u64)negative
 *   AK_E_ code on failure (see AK_CHECKPOINT_ID_VALID()). State is NOT
 *   frozen on failure.
 */
u64 ak_state_prepare_migration(ak_agent_context_t *ctx);

/*
 * Complete migration.
 *
 * Resumes normal state operations after migration.
 * If migration failed, restores from pre-migration checkpoint.
 *
 * Parameters:
 *   ctx     - Agent context
 *   success - Whether migration succeeded
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
s64 ak_state_complete_migration(ak_agent_context_t *ctx, boolean success);

/*
 * Get migration status.
 *
 * Parameters:
 *   ctx      - Agent context
 *   info_out - Output: migration information
 *
 * Returns:
 *   0 on success, negative errno on failure
 */
s64 ak_state_get_migration_info(ak_agent_context_t *ctx,
                                ak_migration_info_t *info_out);

/*
 * Check if state is frozen for migration.
 *
 * Parameters:
 *   ctx - Agent context
 *
 * Returns:
 *   true if frozen, false otherwise
 */
boolean ak_state_is_frozen(ak_agent_context_t *ctx);

/* ============================================================
 * HEAP INTEGRATION
 * ============================================================ */

/*
 * Serialize all heap objects owned by an agent.
 *
 * Used for checkpoint creation and migration.
 *
 * Parameters:
 *   h   - Heap for result allocation
 *   ctx - Agent context
 *
 * Returns:
 *   Buffer containing serialized heap objects, or NULL on failure
 */
buffer ak_state_serialize_heap_objects(heap h, ak_agent_context_t *ctx);

/*
 * Restore heap objects from serialized data.
 *
 * Used for checkpoint restore and migration.
 *
 * Parameters:
 *   ctx - Agent context
 *   buf - Buffer containing serialized heap objects
 *
 * Returns:
 *   Number of objects restored, or negative errno on failure
 */
s64 ak_state_restore_heap_objects(ak_agent_context_t *ctx, buffer buf);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_state_mgmt_stats {
  u64 checkpoints_created;
  u64 checkpoints_restored;
  u64 checkpoints_deleted;
  u64 state_sets;
  u64 state_gets;
  u64 state_deletes;
  u64 rollbacks;
  u64 diffs_computed;
  u64 migrations_started;
  u64 migrations_completed;
  u64 migrations_failed;
  u64 total_state_bytes;
  u64 total_checkpoint_bytes;
} ak_state_mgmt_stats_t;

/*
 * Get state management statistics.
 *
 * Parameters:
 *   stats - Output: statistics structure
 */
void ak_state_mgmt_get_stats(ak_state_mgmt_stats_t *stats);

/* ============================================================
 * ERROR CODES
 * ============================================================ */

#define AK_E_STATE_MGMT_NOT_INIT (-4800)
#define AK_E_CHECKPOINT_NOT_FOUND (-4801)
#define AK_E_CHECKPOINT_CORRUPT (-4802)
#define AK_E_STATE_FROZEN (-4803)
#define AK_E_VERSION_NOT_FOUND (-4804)
#define AK_E_KEY_TOO_LONG (-4805)
#define AK_E_TOO_MANY_CHECKPOINTS (-4806)
#define AK_E_TOO_MANY_STATE_KEYS (-4807)
#define AK_E_MIGRATION_IN_PROGRESS (-4808)
#define AK_E_NO_MIGRATION (-4809)

#endif /* AK_STATE_MGMT_H */
