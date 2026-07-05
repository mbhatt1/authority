/*
 * Authority Kernel - External State Synchronization
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Manages state persistence for ephemeral VMs:
 *   - On boot: Hydrate typed heap from external store
 *   - On AK_COMMIT: Sync dirty objects to external store
 *   - On shutdown: Final sync + anchor emission
 *
 * Backend storage systems:
 *   - VIRTIO (host-side akproxy daemon) - the only functional backend
 *   - S3/Redis/HTTP are defined in the API but FAIL CLOSED: they require
 *     TLS/TCP clients that are not available in the kernel
 *
 * SECURITY:
 *   - Object integrity verified via per-object hashes and merkle roots
 *   - Anchors are hash-chained for tamper-evidence (NOT signed; no
 *     non-repudiation)
 *   - Encryption at rest is NOT implemented in-kernel; delegate to the
 *     host storage daemon or backing store if required
 */

#ifndef AK_STATE_H
#define AK_STATE_H

#include "ak_heap.h"
#include "ak_types.h"

/* ============================================================
 * STORAGE BACKEND CONFIGURATION
 * ============================================================ */

typedef enum ak_storage_backend {
  AK_STORAGE_NONE = 0,   /* In-memory only (ephemeral) */
  AK_STORAGE_S3 = 1,     /* S3-compatible object storage */
  AK_STORAGE_REDIS = 2,  /* Redis/Valkey key-value store */
  AK_STORAGE_HTTP = 3,   /* Custom HTTP API */
  AK_STORAGE_VIRTIO = 4, /* virtio-serial to host storage */
} ak_storage_backend_t;

/* S3 backend configuration */
typedef struct ak_s3_config {
  char endpoint[256];         /* S3 endpoint URL */
  char bucket[64];            /* Bucket name */
  char prefix[64];            /* Key prefix for namespacing */
  char region[32];            /* AWS region */
  char access_key_secret[64]; /* Secret name for access key */
  char secret_key_secret[64]; /* Secret name for secret key */
  boolean use_path_style;     /* Use path-style URLs */
} ak_s3_config_t;

/* Redis backend configuration */
typedef struct ak_redis_config {
  char host[256];
  u16 port;
  char password_secret[64]; /* Secret name for password */
  u32 db_index;
  char key_prefix[64];
} ak_redis_config_t;

/* HTTP backend configuration */
typedef struct ak_http_config {
  char base_url[256];
  char auth_header_secret[64]; /* Secret name for auth header */
  u32 timeout_ms;
} ak_http_config_t;

/* Virtio backend configuration */
typedef struct ak_virtio_config {
  char device_path[64];
} ak_virtio_config_t;

/* Combined storage configuration */
typedef struct ak_storage_config {
  ak_storage_backend_t backend;

  union {
    ak_s3_config_t s3;
    ak_redis_config_t redis;
    ak_http_config_t http;
    ak_virtio_config_t virtio;
  };

  /* Encryption settings */
  boolean encrypt_at_rest;
  char encryption_key_secret[64];

  /* Sync settings */
  u32 sync_interval_ms; /* Auto-sync interval (0 = manual) */
  u32 sync_batch_size;  /* Max objects per sync batch */
  u32 sync_timeout_ms;  /* Sync operation timeout */

  /* Compression settings */
  boolean compression_enabled; /* Enable LZ4 compression for sync */

  /* Retry settings */
  u32 max_retries;
  u32 retry_backoff_ms;
} ak_storage_config_t;

/* ============================================================
 * STATE SNAPSHOT
 * ============================================================
 * Represents a consistent state snapshot for sync.
 */

typedef struct ak_state_snapshot {
  /* Identification */
  u8 snapshot_id[AK_TOKEN_ID_SIZE];
  u64 sequence; /* Monotonic snapshot number */
  u64 timestamp_ms;

  /* Content */
  u8 heap_root_hash[AK_HASH_SIZE]; /* Merkle root of heap */
  u8 log_hash[AK_HASH_SIZE];       /* Latest audit log hash */
  u64 log_sequence;                /* Latest log entry seq */

  /* Objects included */
  u64 object_count;
  u64 total_bytes;

  /* Dirty tracking */
  u64 *dirty_ptrs; /* Array of dirty object ptrs */
  u32 dirty_count;
} ak_state_snapshot_t;

/* ============================================================
 * ANCHOR EMISSION
 * ============================================================
 * Anchors provide tamper-evidence via hash chaining (prev_anchor)
 * and anchoring to the audit log (log_root).
 *
 * HONESTY NOTES:
 *   - heap_root is a merkle root computed over the objects that were
 *     DIRTY at emission time (a delta commitment). It is NOT a
 *     commitment to the full heap state; the kernel has no full-heap
 *     enumeration API. After a fully clean sync it is all zeros.
 *   - signature is all zeros: anchor signing is not implemented, so
 *     anchors do NOT provide non-repudiation.
 */

typedef struct ak_state_anchor {
  u64 timestamp_ms;
  u64 sequence;
  u8 heap_root[AK_HASH_SIZE]; /* Merkle root of dirty set at emission (delta) */
  u8 log_root[AK_HASH_SIZE];
  u8 prev_anchor[AK_HASH_SIZE];
  u8 signature[64]; /* All zeros - Ed25519 signing not implemented */
} ak_state_anchor_t;

/* ============================================================
 * SYNC STATUS
 * ============================================================ */

typedef enum ak_sync_status {
  AK_SYNC_IDLE = 0,
  AK_SYNC_IN_PROGRESS = 1,
  AK_SYNC_COMPLETED = 2,
  AK_SYNC_FAILED = 3,
  AK_SYNC_PARTIAL = 4,    /* Some objects synced */
  AK_SYNC_NO_BACKEND = 5, /* No backend configured: state is in-memory
                             only and was NOT durably persisted */
} ak_sync_status_t;

typedef struct ak_sync_result {
  ak_sync_status_t status;
  u64 objects_synced;
  u64 bytes_synced;
  u64 duration_ms;
  s64 error_code;
  char error_message[256];
} ak_sync_result_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize state sync subsystem.
 */
void ak_state_init(heap h, ak_storage_config_t *config);

/*
 * Shutdown state sync subsystem.
 * Performs final sync before shutdown.
 */
void ak_state_shutdown(void);

/*
 * Update storage configuration.
 */
s64 ak_state_configure(ak_storage_config_t *config);

/* ============================================================
 * HYDRATION (Boot-time state loading)
 * ============================================================ */

/*
 * Hydrate typed heap from external store.
 *
 * Called during kernel initialization to restore state
 * from previous VM instance.
 *
 * Returns:
 *   0 - Success (state loaded)
 *   AK_E_STATE_NOT_FOUND - No previous state
 *   AK_E_STATE_CORRUPT - State verification failed
 */
s64 ak_state_hydrate(ak_heap_t *heap);

/*
 * Verify hydrated state integrity.
 */
boolean ak_state_verify_integrity(void);

/*
 * Get hydration status.
 */
typedef struct ak_hydration_status {
  boolean hydrated;
  u64 objects_loaded;
  u64 bytes_loaded;
  u64 duration_ms;
  u64 source_sequence; /* Sequence of source snapshot */
} ak_hydration_status_t;

void ak_state_get_hydration_status(ak_hydration_status_t *status);

/* ============================================================
 * DIRTY TRACKING
 * ============================================================ */

/*
 * Mark object as dirty (needs sync).
 */
void ak_state_mark_dirty(u64 ptr);

/*
 * Mark object as clean (synced).
 */
void ak_state_mark_clean(u64 ptr);

/*
 * Check if object is dirty.
 */
boolean ak_state_is_dirty(u64 ptr);

/*
 * Get count of dirty objects.
 */
u64 ak_state_dirty_count(void);

/*
 * Get list of dirty object ptrs.
 */
u64 *ak_state_get_dirty_list(u32 *count_out);

/* ============================================================
 * SYNC OPERATIONS
 * ============================================================ */

/*
 * Sync all dirty objects to external store.
 *
 * This is the main sync entry point, called by:
 *   - AK_SYS_COMMIT handler
 *   - Periodic sync timer
 *   - Shutdown sequence
 *
 * Status semantics (truthful reporting):
 *   AK_SYNC_COMPLETED  - every dirty object was persisted by the backend
 *   AK_SYNC_PARTIAL    - some objects persisted; failures remain dirty
 *   AK_SYNC_FAILED     - nothing persisted; all objects remain dirty
 *   AK_SYNC_NO_BACKEND - no backend configured; NOTHING was persisted
 * Objects are only marked clean after the backend acknowledged them.
 */
ak_sync_result_t ak_state_sync(void);

/*
 * Sync specific objects.
 */
ak_sync_result_t ak_state_sync_objects(u64 *ptrs, u32 count);

/*
 * Force immediate sync (blocking).
 */
ak_sync_result_t ak_state_sync_immediate(void);

/*
 * Check if sync is in progress.
 */
boolean ak_state_sync_in_progress(void);

/*
 * Wait for current sync to complete.
 */
ak_sync_result_t ak_state_sync_wait(u32 timeout_ms);

/* ============================================================
 * ANCHOR EMISSION
 * ============================================================ */

/*
 * Emit state anchor to external store.
 *
 * Called:
 *   - After each successful sync
 *   - At periodic intervals
 *   - On graceful shutdown
 */
s64 ak_state_emit_anchor(void);

/*
 * Get latest anchor.
 */
ak_state_anchor_t *ak_state_get_latest_anchor(void);

/*
 * Verify anchor chain integrity.
 */
boolean ak_state_verify_anchor_chain(void);

/* ============================================================
 * BACKEND OPERATIONS
 * ============================================================
 * Low-level storage operations.
 *
 * Only the VIRTIO backend (host-side akproxy daemon) is functional.
 * S3/Redis/HTTP backends FAIL CLOSED: puts/deletes return
 * AK_E_STATE_BACKEND_ERROR and get/list return empty, so no operation
 * ever reports success without actual persistence.
 */

/*
 * Store object to backend.
 * Returns 0 only if the backend acknowledged the write.
 */
s64 ak_backend_put(u64 ptr, buffer value, u8 *hash);

/*
 * Retrieve object from backend.
 * Returns 0 (NULL) if not found, backend unavailable, or the stored
 * record fails integrity verification.
 */
buffer ak_backend_get(u64 ptr);

/*
 * Delete object from backend.
 */
s64 ak_backend_delete(u64 ptr);

/*
 * List all objects (for hydration).
 */
u64 *ak_backend_list(u32 *count_out);

/*
 * Check backend connectivity.
 */
boolean ak_backend_healthy(void);

/* ============================================================
 * SYSCALL HANDLER
 * ============================================================ */

/*
 * Handle state commit (called from ak_handle_commit in ak_syscall.c).
 *
 * Forces sync of dirty state and emits anchor.
 */
ak_response_t *ak_state_handle_commit(ak_agent_context_t *ctx,
                                      ak_request_t *req);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_state_stats {
  u64 syncs_total;
  u64 syncs_successful;
  u64 syncs_failed;
  u64 objects_synced_total;
  u64 bytes_synced_total;
  u64 bytes_compressed; /* Bytes saved by compression */
  u64 anchors_emitted;
  u64 hydrations_total;
  u64 total_sync_time_ms;
} ak_state_stats_t;

void ak_state_get_stats(ak_state_stats_t *stats);

/* ============================================================
 * STATE FILE FORMAT
 * ============================================================
 * The state file uses a binary format for efficient persistence:
 *
 * STATE FILE HEADER (64 bytes):
 *   - Magic:          4 bytes  "AKST"
 *   - Version:        2 bytes  (format version, currently 1)
 *   - Flags:          2 bytes  (compression, encryption flags)
 *   - Object count:   4 bytes  (number of objects in file)
 *   - Reserved:       4 bytes
 *   - Timestamp:      8 bytes  (creation timestamp ms)
 *   - Sequence:       8 bytes  (anchor sequence number)
 *   - Merkle root:   32 bytes  (integrity hash of all objects)
 *
 * OBJECT ENTRY (variable length):
 *   - Ptr:            8 bytes  (object pointer/ID)
 *   - Type hash:      8 bytes  (schema type identifier)
 *   - Version:        8 bytes  (CAS version number)
 *   - Taint:          4 bytes  (taint level)
 *   - Flags:          4 bytes  (deleted, compressed, etc.)
 *   - Data length:    4 bytes  (length of serialized data)
 *   - Hash:          32 bytes  (SHA-256 of data for integrity)
 *   - Data:          variable  (serialized JSON value)
 *
 * ANCHOR CHAIN (appended to end):
 *   - Anchor count:   4 bytes
 *   - Anchors:       variable  (ak_state_anchor_t array)
 *
 * RECOVERY PROCEDURE:
 *   1. Read header, verify magic and version
 *   2. Verify merkle root matches computed root of objects
 *   3. For each object:
 *      a. Verify individual object hash
 *      b. Restore to typed heap
 *   4. Verify anchor chain integrity
 *   5. Resume from latest anchor sequence
 */

/* State file magic number "AKST" */
#define AK_STATE_FILE_MAGIC 0x54534B41

/* State file format version */
#define AK_STATE_FILE_VERSION 1

/* State file flags */
#define AK_STATE_FLAG_COMPRESSED (1 << 0)
#define AK_STATE_FLAG_ENCRYPTED (1 << 1)
#define AK_STATE_FLAG_INCREMENTAL (1 << 2)

/* State file header structure */
typedef struct ak_state_file_header {
  u32 magic;        /* AK_STATE_FILE_MAGIC */
  u16 version;      /* File format version */
  u16 flags;        /* Compression/encryption flags */
  u32 object_count; /* Number of objects */
  u32 reserved;
  u64 timestamp_ms;             /* Creation timestamp */
  u64 sequence;                 /* Anchor sequence number */
  u8 merkle_root[AK_HASH_SIZE]; /* Integrity hash */
} ak_state_file_header_t;

/* Serialized object entry header */
typedef struct ak_state_object_entry {
  u64 ptr;               /* Object pointer/ID */
  u64 type_hash;         /* Schema type identifier */
  u64 version;           /* CAS version number */
  u32 taint;             /* Taint level */
  u32 flags;             /* Object flags */
  u32 data_length;       /* Serialized data length */
  u8 hash[AK_HASH_SIZE]; /* Object data hash */
                         /* Followed by data_length bytes of serialized data */
} ak_state_object_entry_t;

/* Object entry flags */
#define AK_OBJ_FLAG_DELETED (1 << 0)
#define AK_OBJ_FLAG_COMPRESSED (1 << 1)

/* ============================================================
 * LOCAL DISK PERSISTENCE (AK_ENABLE_STATE_SYNC)
 * ============================================================ */

#ifdef AK_ENABLE_STATE_SYNC

/*
 * Write state to local disk file.
 *
 * Serializes all dirty objects (or full state if full_sync is true)
 * to the configured state file path. Uses fsync() to ensure durability.
 *
 * Parameters:
 *   full_sync - If true, write all objects; if false, only dirty objects
 *
 * Returns:
 *   0 on success, negative error code on failure
 */
s64 ak_state_write_to_disk(boolean full_sync);

/*
 * Load state from local disk file.
 *
 * Reads state file, verifies integrity, and restores to typed heap.
 *
 * Returns:
 *   0 on success, negative error code on failure
 */
s64 ak_state_load_from_disk(void);

/*
 * Set the state file path for persistence.
 *
 * Parameters:
 *   path - Path to state file (will be created if doesn't exist)
 *
 * Returns:
 *   0 on success, negative error code on failure
 */
s64 ak_state_set_file_path(const char *path);

/*
 * Get current state file path.
 */
const char *ak_state_get_file_path(void);

/*
 * SHALLOW verification of a state file header (magic and version only).
 *
 * This does NOT verify the merkle root or per-object hashes; full
 * integrity verification is performed by ak_state_load_from_disk(),
 * which fails closed on any hash or merkle mismatch.
 *
 * Parameters:
 *   path - Path to state file
 *
 * Returns:
 *   0 if the header is well-formed, negative error code otherwise
 */
s64 ak_state_verify_file(const char *path);

/* ============================================================
 * REMOTE SYNC PROTOCOL
 * ============================================================
 *
 * The sync protocol supports remote state backends for distributed
 * persistence. Protocol messages use a simple binary format:
 *
 * SYNC REQUEST:
 *   - Command:        1 byte   (PUT=1, GET=2, DELETE=3, LIST=4, SYNC=5)
 *   - Flags:          1 byte   (compression, etc.)
 *   - Sequence:       8 bytes  (for ordering/conflict detection)
 *   - Key length:     2 bytes
 *   - Value length:   4 bytes
 *   - Key:           variable  (object ptr as hex string)
 *   - Value:         variable  (serialized object data)
 *   - Hash:          32 bytes  (integrity)
 *
 * SYNC RESPONSE:
 *   - Status:         1 byte   (OK=0, ERROR=1, CONFLICT=2, NOT_FOUND=3)
 *   - Flags:          1 byte
 *   - Sequence:       8 bytes  (server's sequence for CAS)
 *   - Value length:   4 bytes
 *   - Value:         variable  (for GET responses)
 *   - Error message: variable  (for ERROR responses)
 *
 * CONFLICT RESOLUTION:
 *   - Last-write-wins based on sequence numbers
 *   - Client can request server's current value on conflict
 *   - Merge strategies can be implemented by caller
 */

/* Sync protocol commands */
typedef enum ak_sync_cmd {
  AK_SYNC_CMD_PUT = 1,
  AK_SYNC_CMD_GET = 2,
  AK_SYNC_CMD_DELETE = 3,
  AK_SYNC_CMD_LIST = 4,
  AK_SYNC_CMD_SYNC = 5,  /* Full state sync */
  AK_SYNC_CMD_DELTA = 6, /* Delta/incremental sync */
} ak_sync_cmd_t;

/* Sync protocol status codes */
typedef enum ak_sync_response_status {
  AK_SYNC_STATUS_OK = 0,
  AK_SYNC_STATUS_ERROR = 1,
  AK_SYNC_STATUS_CONFLICT = 2,
  AK_SYNC_STATUS_NOT_FOUND = 3,
  AK_SYNC_STATUS_UNAUTHORIZED = 4,
  AK_SYNC_STATUS_RATE_LIMITED = 5,
} ak_sync_response_status_t;

/* Conflict resolution strategy */
typedef enum ak_conflict_strategy {
  AK_CONFLICT_LAST_WRITE_WINS = 0,
  AK_CONFLICT_FIRST_WRITE_WINS = 1,
  AK_CONFLICT_MERGE = 2,
  AK_CONFLICT_CALLBACK = 3,
} ak_conflict_strategy_t;

/* Sync callback for custom conflict resolution */
typedef buffer (*ak_conflict_resolver_t)(heap h, u64 ptr, buffer local_value,
                                         u64 local_version, buffer remote_value,
                                         u64 remote_version);

/*
 * Configure conflict resolution strategy.
 */
void ak_state_set_conflict_strategy(ak_conflict_strategy_t strategy);

/*
 * Set custom conflict resolver callback.
 */
void ak_state_set_conflict_resolver(ak_conflict_resolver_t resolver);

/*
 * Perform delta sync (only changed objects since last sync).
 *
 * Returns sync result with details of what was synced.
 */
ak_sync_result_t ak_state_delta_sync(void);

/*
 * Get remote state version (for sync decision).
 *
 * Returns remote sequence number, or negative error.
 */
s64 ak_state_get_remote_version(void);

/*
 * Pull changes from remote (download-only sync).
 */
ak_sync_result_t ak_state_pull(void);

/*
 * Push changes to remote (upload-only sync).
 */
ak_sync_result_t ak_state_push(void);

#endif /* AK_ENABLE_STATE_SYNC */

/* ============================================================
 * ERROR CODES
 * ============================================================ */

#define AK_E_STATE_NOT_FOUND (-4700)
#define AK_E_STATE_CORRUPT (-4701)
#define AK_E_STATE_SYNC_FAILED (-4702)
#define AK_E_STATE_BACKEND_ERROR (-4703)
#define AK_E_STATE_ENCRYPTION_ERROR (-4704)
#define AK_E_STATE_TIMEOUT (-4705)
#define AK_E_STATE_CONFLICT (-4706)
#define AK_E_STATE_VERSION_MISMATCH (-4707)
#define AK_E_STATE_FILE_CORRUPT (-4708)
#define AK_E_STATE_MERKLE_MISMATCH (-4709)

#endif /* AK_STATE_H */
