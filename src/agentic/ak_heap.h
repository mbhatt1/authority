/*
 * Authority Kernel - Typed Heap
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Typed, versioned object heap with CAS (Compare-And-Swap) semantics.
 * Provides atomic state management for agent data.
 *
 * SECURITY: All mutations are logged (INV-4 support).
 * Version control prevents lost updates.
 */

#ifndef AK_HEAP_H
#define AK_HEAP_H

#include "ak_types.h"

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/* Initialize typed heap subsystem */
void ak_heap_init(heap h);

/* ============================================================
 * CORE OPERATIONS (ALLOC, READ, WRITE, DELETE)
 * ============================================================ */

/*
 * ALLOC: Create new typed object.
 *
 * Returns: object pointer (ptr) on success, 0 on error.
 *
 * The object is created with:
 *   - version = 1
 *   - taint = AK_TAINT_UNTRUSTED (unless specified)
 *   - owner_run_id = caller's run
 */
u64 ak_heap_alloc(u64 type_hash,   /* Schema type identifier */
                  buffer value,    /* Initial JSON value */
                  u8 *run_id,      /* Owner run */
                  ak_taint_t taint /* Initial taint level */
);

/*
 * READ: Retrieve object.
 *
 * Returns: 0 on success, negative error on failure.
 *
 * Output parameters:
 *   - value_out: JSON value (caller must free)
 *   - version_out: current version
 *   - taint_out: taint level (optional, can be NULL)
 */
s64 ak_heap_read(u64 ptr, buffer *value_out, u64 *version_out,
                 ak_taint_t *taint_out);

/*
 * WRITE: Update object with CAS.
 *
 * The patch is applied ONLY if current version matches expected_version.
 * This provides optimistic concurrency control.
 *
 * Returns:
 *   0              - Success, new_version_out contains new version
 *   AK_E_CONFLICT  - Version mismatch (must re-read and retry)
 *   -ENOENT        - Object not found or deleted
 *   AK_E_SCHEMA_INVALID - Patch result invalid
 */
s64 ak_heap_write(u64 ptr, buffer patch, /* RFC 6902 JSON Patch */
                  u64 expected_version,  /* CAS: must match current */
                  u64 *new_version_out   /* Output: new version after write */
);

/*
 * DELETE: Soft-delete object.
 *
 * Object is marked deleted (tombstone) but retained for audit.
 * Requires version match (CAS).
 *
 * Returns: 0 on success, AK_E_CONFLICT on version mismatch.
 */
s64 ak_heap_delete(u64 ptr, u64 expected_version);

/* ============================================================
 * OBJECT QUERIES
 * ============================================================ */

/*
 * Check if object exists (and is not deleted).
 */
boolean ak_heap_exists(u64 ptr);

/*
 * Get object metadata without value.
 */
typedef struct ak_object_meta {
  u64 ptr;
  u64 type_hash;
  u64 version;
  u64 created_ms;
  u64 modified_ms;
  ak_taint_t taint;
  boolean deleted;
} ak_object_meta_t;

s64 ak_heap_get_meta(u64 ptr, ak_object_meta_t *meta_out);

/*
 * List objects by type.
 */
u64 *ak_heap_list_by_type(heap h, u64 type_hash, u64 *count_out);

/*
 * List objects owned by run.
 */
u64 *ak_heap_list_by_run(heap h, u8 *run_id, u64 *count_out);

/* ============================================================
 * VERSION HISTORY
 * ============================================================ */

/*
 * Get historical version of object.
 */
s64 ak_heap_read_version(u64 ptr, u64 version, buffer *value_out);

/*
 * List all versions of object.
 */
u64 *ak_heap_list_versions(heap h, u64 ptr, u64 *count_out);

/* ============================================================
 * TAINT OPERATIONS
 * ============================================================ */

/*
 * Update taint level of object.
 *
 * SECURITY: Taint is monotonic. This entry point can only keep or raise
 * the taint level (toward AK_TAINT_UNTRUSTED); attempts to downgrade
 * toward trusted return AK_E_TAINT. Downgrades are only possible via
 * ak_heap_set_taint_sanitized() after actual sanitization.
 */
s64 ak_heap_set_taint(u64 ptr, ak_taint_t new_taint, u64 expected_version);

/*
 * Privileged taint update for sanitizers.
 *
 * SECURITY: Allows lowering the taint level (e.g. untrusted ->
 * sanitized_url). Must only be called by kernel sanitizer paths after
 * the value has actually passed through the corresponding sanitizer.
 */
s64 ak_heap_set_taint_sanitized(u64 ptr, ak_taint_t new_taint,
                                u64 expected_version);

/*
 * Get taint level.
 */
ak_taint_t ak_heap_get_taint(u64 ptr);

/* ============================================================
 * SCHEMA VALIDATION
 * ============================================================ */

/*
 * Register schema for type.
 *
 * Schema is JSON Schema (draft-07).
 */
void ak_heap_register_schema(u64 type_hash, buffer schema_json);

/*
 * Validate value against schema.
 */
boolean ak_heap_validate_schema(u64 type_hash, buffer value);

/* ============================================================
 * JSON PATCH (RFC 6902)
 * ============================================================ */

/*
 * Apply JSON Patch to value.
 *
 * The patch must be an RFC 6902 array of operation objects, or a
 * request envelope object with a "patch" member holding that array
 * (as passed through by the AK_SYS_WRITE handler). Supported
 * operations: "add", "replace", "remove", with JSON Pointer (RFC 6901)
 * paths including array indices and "-" append. Unsupported operations
 * (move, copy, test) and malformed patches/paths fail closed.
 *
 * Returns: new value on success, NULL on error.
 * Caller must free returned buffer.
 */
buffer ak_json_patch_apply(heap h, buffer original, buffer patch);

/*
 * Validate JSON Patch syntax (array of objects with "op" and "path").
 */
boolean ak_json_patch_validate(buffer patch);

/*
 * Create JSON Patch from diff.
 *
 * NOT IMPLEMENTED: always returns NULL (no in-tree callers). Do not
 * treat a NULL result as "no changes".
 */
buffer ak_json_patch_diff(heap h, buffer old_value, buffer new_value);

/* ============================================================
 * GARBAGE COLLECTION
 * ============================================================ */

/*
 * Purge old versions (keeping last N).
 *
 * Returns: number of versions purged.
 */
u64 ak_heap_purge_versions(u64 keep_count);

/*
 * Purge deleted objects older than threshold.
 *
 * Returns: number of objects purged.
 */
u64 ak_heap_purge_tombstones(u64 older_than_ms);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_heap_stats {
  u64 object_count;
  u64 deleted_count;
  u64 version_count;
  u64 bytes_used;
  u64 bytes_versions;
} ak_heap_stats_t;

void ak_heap_get_stats(ak_heap_stats_t *stats);

/* ============================================================
 * SNAPSHOT / RESTORE
 * ============================================================ */

/*
 * Create heap snapshot.
 *
 * Returns serialized heap state for replay:
 *   {"version":1,"next_ptr":N,"object_count":N,"objects":[...]}
 * where each entry is the ak_heap_serialize_object() format. Includes
 * tombstones. Caller must free the returned buffer.
 */
buffer ak_heap_snapshot(heap h);

/*
 * Restore heap objects from snapshot.
 *
 * Accepts either a full snapshot (ak_heap_snapshot format) or a single
 * serialized object (ak_heap_serialize_object format). Objects are
 * upserted (merged) into the current heap; existing objects with other
 * pointers are left untouched, so callers may hydrate object by object.
 *
 * Returns 0 on success, negative error on malformed input.
 */
s64 ak_heap_restore(buffer snapshot);

/*
 * Serialize a single heap object.
 *
 * Returns buffer containing serialized object, or NULL on failure.
 */
buffer ak_heap_serialize_object(heap h, u64 ptr);

/* ============================================================
 * TRANSACTION SUPPORT (for BATCH)
 * ============================================================ */

typedef struct ak_heap_txn ak_heap_txn_t;

/*
 * Begin transaction.
 *
 * All operations within transaction are buffered.
 */
ak_heap_txn_t *ak_heap_txn_begin(void);

/*
 * Commit transaction atomically.
 *
 * All buffered operations are applied or none are.
 */
s64 ak_heap_txn_commit(ak_heap_txn_t *txn);

/*
 * Rollback transaction.
 *
 * Discards all buffered operations.
 */
void ak_heap_txn_rollback(ak_heap_txn_t *txn);

/*
 * Transaction-aware versions of core ops.
 */
u64 ak_heap_txn_alloc(ak_heap_txn_t *txn, u64 type_hash, buffer value,
                      u8 *run_id, ak_taint_t taint);
s64 ak_heap_txn_write(ak_heap_txn_t *txn, u64 ptr, buffer patch,
                      u64 expected_version);
s64 ak_heap_txn_delete(ak_heap_txn_t *txn, u64 ptr, u64 expected_version);

#endif /* AK_HEAP_H */
