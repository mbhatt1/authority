/*
 * Authority Kernel - Hash-Chained Audit Log
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements INV-4: Log Commitment Invariant
 * "Each committed transition appends a log entry whose hash chain
 *  validates from genesis to head."
 *
 * SECURITY CRITICAL: All state changes MUST be logged before response.
 * The hash chain provides tamper evidence.
 */

#ifndef AK_AUDIT_H
#define AK_AUDIT_H

#include "ak_types.h"

/* ============================================================
 * LOG INITIALIZATION
 * ============================================================ */

/*
 * Initialize audit log subsystem.
 *
 * Creates genesis entry with all-zero prev_hash.
 */
void ak_audit_init(heap h);

/*
 * Load log from persistent storage (crash recovery).
 *
 * Verifies entire hash chain before accepting.
 * Returns: 0 on success, negative on corruption/error.
 */
s64 ak_audit_load(void);

/* ============================================================
 * LOG OPERATIONS
 * ============================================================ */

/*
 * Append entry to audit log.
 *
 * SECURITY: This is SYNCHRONOUS. Returns only after fsync().
 * Response to agent MUST NOT be sent until this returns.
 *
 * The entry's prev_hash and this_hash are computed internally.
 *
 * Returns: log sequence number on success, negative on error.
 */
s64 ak_audit_append(u8 *pid, u8 *run_id, u16 op, u8 *req_hash, u8 *res_hash,
                    u8 *policy_hash);

/*
 * Convenience: append from request/response structures.
 */
s64 ak_audit_append_request(ak_request_t *req, ak_response_t *res,
                            u8 *policy_hash);

/*
 * Query log entries.
 *
 * Returns entries matching filter in [start_seq, end_seq].
 *
 * OWNERSHIP: The returned array is allocated from h; the caller must
 * free the ARRAY itself (deallocate(h, results,
 * sizeof(ak_log_entry_t *) * count)). The ak_log_entry_t pointers it
 * contains are BORROWED - they point into live segment storage owned
 * by the audit log. Callers must NOT free or modify them. Segments
 * are never freed or relocated, so the borrowed pointers remain valid
 * for the lifetime of the kernel.
 */
typedef struct ak_log_query_filter {
  u8 *pid;    /* NULL = any */
  u8 *run_id; /* NULL = any */
  u16 op;     /* 0 = any */
} ak_log_query_filter_t;

ak_log_entry_t **ak_audit_query(heap h, ak_log_query_filter_t *filter,
                                u64 start_seq, u64 end_seq, u64 *count_out);

/*
 * Get current log head sequence number.
 */
u64 ak_audit_head_seq(void);

/*
 * Get current log head hash.
 */
void ak_audit_head_hash(u8 *hash_out);

/* ============================================================
 * LOG VERIFICATION
 * ============================================================
 * CRITICAL for detecting tampering.
 */

/*
 * Verify entire log hash chain.
 *
 * Returns:
 *   0                  - Valid
 *   AK_E_LOG_CORRUPT   - Hash chain broken
 *   Positive value     - Sequence number where corruption detected
 */
s64 ak_audit_verify(void);

/*
 * Verify log segment [start, end].
 *
 * Useful for incremental verification.
 */
s64 ak_audit_verify_range(u64 start_seq, u64 end_seq);

/*
 * Verify single entry against expected previous hash.
 */
boolean ak_audit_verify_entry(ak_log_entry_t *entry, u8 *expected_prev);

/* ============================================================
 * ANCHORING (External Commitments)
 * ============================================================
 * LIMITATION: Anchors are currently UNSIGNED (the signature field is
 * zeroed; no signing key is provisioned) and are held in memory only
 * (ak_audit_post_anchor_remote is a no-op stub). They serve as
 * internal checkpoints of (log_seq, head hash) for consistency
 * checks, but do NOT yet provide externally verifiable tamper
 * evidence, and do NOT prevent log rewrite by an attacker who
 * controls this host. Full anchoring requires signing plus posting
 * to an external service.
 */

/*
 * Emit anchor at current log head.
 *
 * Called automatically every AK_ANCHOR_INTERVAL entries.
 * Also callable manually for important checkpoints.
 */
s64 ak_audit_emit_anchor(void);

/*
 * Get latest anchor.
 */
ak_anchor_t *ak_audit_get_latest_anchor(void);

/*
 * Verify anchor against log.
 */
boolean ak_audit_verify_anchor(ak_anchor_t *anchor);

/*
 * Post anchor to remote service (optional).
 *
 * NOT IMPLEMENTED: currently a no-op stub. Nothing is transmitted and
 * no external commitment is made.
 */
void ak_audit_post_anchor_remote(ak_anchor_t *anchor, const char *url);

/* ============================================================
 * STORAGE
 * ============================================================ */

/*
 * Open the audit log file for persistent storage.
 *
 * MUST be called after filesystem is initialized.
 * Returns 0 on success, negative error code on failure.
 *
 * INV-4 CRITICAL: If this fails, audit log will be in-memory only
 * and INV-4 guarantees are weakened (no crash recovery).
 */
s64 ak_audit_open_storage(void);

/*
 * Flush all pending writes to disk and wait for fsync.
 *
 * Called automatically on append(), but can be called
 * explicitly for checkpointing.
 *
 * INV-4 CRITICAL: This function blocks until fsync completes.
 * Response to agent MUST NOT be sent until this returns.
 */
void ak_audit_sync(void);

/*
 * Get storage statistics.
 */
typedef struct ak_audit_stats {
  u64 entry_count;
  u64 bytes_used;
  u64 anchor_count;
  u64 last_anchor_seq;
  u64 last_sync_ms;
  u64 disk_bytes_written;  /* Total bytes written to disk */
  boolean storage_enabled; /* Whether persistent storage is active */
} ak_audit_stats_t;

void ak_audit_get_stats(ak_audit_stats_t *stats);

/* ============================================================
 * HASH COMPUTATION
 * ============================================================ */

/*
 * Compute hash for log entry.
 *
 * hash = SHA256(prev_hash || canonical(entry_without_hashes))
 */
void ak_audit_compute_entry_hash(ak_log_entry_t *entry, u8 *prev_hash,
                                 u8 *hash_out);

/*
 * Compute hash of request/response for logging.
 */
void ak_audit_hash_request(ak_request_t *req, u8 *hash_out);
void ak_audit_hash_response(ak_response_t *res, u8 *hash_out);

/* ============================================================
 * REPLAY SUPPORT
 * ============================================================ */

/*
 * Create replay bundle from log segment.
 *
 * Bundle contains everything needed to replay a run.
 */
typedef struct ak_replay_bundle {
  u8 run_id[AK_TOKEN_ID_SIZE];
  u64 start_seq;
  u64 end_seq;
  ak_log_entry_t **entries;
  u64 entry_count;
  buffer heap_snapshot; /* Initial heap state */
  u8 policy_hash[AK_HASH_SIZE];
} ak_replay_bundle_t;

ak_replay_bundle_t *ak_audit_create_bundle(heap h, u8 *run_id, u64 start_seq,
                                           u64 end_seq);

void ak_audit_destroy_bundle(heap h, ak_replay_bundle_t *bundle);

/* ============================================================
 * SPECIAL ENTRIES
 * ============================================================ */

/*
 * Log capability revocation.
 */
s64 ak_audit_log_revocation(u8 *tid, const char *reason);

/*
 * Log policy change.
 */
s64 ak_audit_log_policy_change(u8 *old_hash, u8 *new_hash, const char *reason);

/*
 * Log agent lifecycle event.
 */
typedef enum ak_lifecycle_event {
  AK_LIFECYCLE_SPAWN,
  AK_LIFECYCLE_EXIT,
  AK_LIFECYCLE_CRASH,
  AK_LIFECYCLE_TIMEOUT,
} ak_lifecycle_event_t;

s64 ak_audit_log_lifecycle(u8 *agent_id, u8 *run_id,
                           ak_lifecycle_event_t event);

/* ============================================================
 * RING BUFFER - High-frequency data-plane audit events
 * ============================================================
 *
 * Lock-free ring buffer for non-blocking audit of high-frequency
 * events. Uses atomic operations for producer/consumer synchronization.
 * Ring overwrites oldest entries when full (bounded memory).
 */

#define AK_RING_BUFFER_SIZE 4096 /* Must be power of 2 */
#define AK_RING_BUFFER_MASK (AK_RING_BUFFER_SIZE - 1)

/* Compact ring buffer entry for data-plane events */
typedef struct ak_ring_entry {
  u64 seq;                     /* Sequence number */
  u64 ts_ns;                   /* Timestamp (nanoseconds) */
  u8 pid[AK_TOKEN_ID_SIZE];    /* Process/Agent ID */
  u8 run_id[AK_TOKEN_ID_SIZE]; /* Run ID */
  u16 op;                      /* Operation code */
  u8 req_hash[AK_HASH_SIZE];   /* Request hash */
  u8 res_hash[AK_HASH_SIZE];   /* Response hash */
  s64 result_code;             /* Result/errno */
  u32 latency_us;              /* Latency in microseconds */
  u8 flags;                    /* Event flags */
} __attribute__((packed)) ak_ring_entry_t;

/* Ring buffer flags */
#define AK_RING_FLAG_DENIED 0x01   /* Operation was denied */
#define AK_RING_FLAG_TIMEOUT 0x02  /* Operation timed out */
#define AK_RING_FLAG_ERROR 0x04    /* Error occurred */
#define AK_RING_FLAG_OVERFLOW 0x80 /* Ring buffer overflowed */

/*
 * Initialize ring buffer (called from ak_audit_init).
 */
void ak_ring_init(void);

/*
 * Push entry to ring buffer (non-blocking, may overwrite oldest).
 *
 * Returns: sequence number of entry, or 0 if ring not initialized.
 */
u64 ak_ring_push(u8 *pid, u8 *run_id, u16 op, u8 *req_hash, u8 *res_hash,
                 s64 result_code, u32 latency_us, u8 flags);

/*
 * Pop entry from ring buffer (non-blocking).
 *
 * Returns: true if entry was returned, false if ring empty.
 */
boolean ak_ring_pop(ak_ring_entry_t *entry_out);

/*
 * Peek at entry without removing (for batch reads).
 *
 * Returns: true if entry exists at offset from tail.
 */
boolean ak_ring_peek(u64 offset, ak_ring_entry_t *entry_out);

/*
 * Get ring buffer statistics.
 */
typedef struct ak_ring_stats {
  u64 total_pushed;   /* Total entries ever pushed */
  u64 total_popped;   /* Total entries ever popped */
  u64 current_count;  /* Current entries in buffer */
  u64 overflow_count; /* Number of overwrites */
  u64 head_seq;       /* Current head sequence */
  u64 tail_seq;       /* Current tail sequence */
} ak_ring_stats_t;

void ak_ring_get_stats(ak_ring_stats_t *stats);

/*
 * Drain ring buffer to callback (batch processing).
 *
 * Calls callback for each entry, stops if callback returns false.
 * Returns: number of entries processed.
 */
typedef boolean (*ak_ring_drain_cb)(ak_ring_entry_t *entry, void *ctx);
u64 ak_ring_drain(ak_ring_drain_cb cb, void *ctx, u64 max_entries);

#endif /* AK_AUDIT_H */
