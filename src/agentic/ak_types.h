/*
 * Authority Kernel - Core Types
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This file defines the fundamental types for the Authority Kernel,
 * the universal agentic runtime for secure AI agent execution.
 *
 * SECURITY: These types enforce the four invariants:
 *   INV-1: No-Bypass (syscall-only effects)
 *   INV-2: Capability (every effectful op requires valid cap)
 *   INV-3: Budget (admission control)
 *   INV-4: Log Commitment (hash-chained audit)
 */

#ifndef AK_TYPES_H
#define AK_TYPES_H

/* Include runtime.h FIRST to get base types (u64, boolean, etc.)
 * The agentic code primarily needs buffer, heap, and basic types from runtime.
 * This must come before ak_compat.h and ak_assert.h which depend on these types.
 */
#include <runtime.h>
#include "ak_config.h"
#include "ak_compat.h"
#include "ak_assert.h"

/* Base syscall number for AK syscalls */
#define AK_SYS_BASE 1024

/* ============================================================
 * SYSCALL NUMBERS (Reserved: 1024-1100)
 * ============================================================ */

/* Category: STATE - Typed heap operations */
#define AK_SYS_READ 1024   /* Read object from heap */
#define AK_SYS_ALLOC 1025  /* Allocate new typed object */
#define AK_SYS_WRITE 1026  /* Patch object with CAS */
#define AK_SYS_DELETE 1027 /* Soft-delete object */

/* Category: TOOLS - External effect execution.
 * NOTE: numbers must match the SDK ABI (src/agentic/libak.h, README).
 * CALL is 1031 and QUERY is 1028 - do not renumber to be file-sequential. */
#define AK_SYS_CALL 1031  /* Execute tool */
#define AK_SYS_BATCH 1029 /* Atomic batch of operations */

/* Category: AUDIT - Log operations */
#define AK_SYS_COMMIT 1030 /* Force log sync */
#define AK_SYS_QUERY 1028  /* Query audit log */

/* Category: CONTROL - Agent lifecycle and IPC */
#define AK_SYS_SPAWN 1032  /* Create child agent */
#define AK_SYS_SEND 1033   /* Send typed message */
#define AK_SYS_RECV 1034   /* Receive message */
#define AK_SYS_ASSERT 1036 /* Assert predicate (halt on fail); ABI=1036 */

/* Category: OUTPUT - External response */
#define AK_SYS_RESPOND 1035 /* Send response (DLP applied); ABI=1035 */

/* Category: COGNITIVE - LLM gateway */
#define AK_SYS_INFERENCE 1037 /* LLM inference request */

/* Category: BUDGET - Resource consumption tracking */
#define AK_SYS_BUDGET_STATUS 1038    /* Get current budget status */
#define AK_SYS_BUDGET_HISTORY 1039   /* Get historical snapshots */
#define AK_SYS_BUDGET_BREAKDOWN 1040 /* Get detailed breakdown */

/* Category: ASYNC external I/O - enforced issue + non-blocking poll.
 * INFER_ISSUE runs the full enforcement pipeline then issues an async HTTP(S)
 * request to an LLM endpoint (returns a request id without blocking).
 * INFER_POLL retrieves the result (self-scoped; returns -EAGAIN until ready). */
#define AK_SYS_INFER_ISSUE 1041
#define AK_SYS_INFER_POLL 1042

#define AK_SYS_MIN 1024
#define AK_SYS_MAX 1100

/* ============================================================
 * ERROR CODES
 * ============================================================
 * Ranges:
 *   -4000 to -4099: Protocol/schema errors
 *   -4100 to -4199: Capability errors
 *   -4200 to -4299: Policy/flow errors
 *   -4300 to -4399: Resource errors
 *   -4400 to -4499: Execution errors
 */

/* Protocol errors */
#define AK_E_FRAME_TOO_LARGE (-4001)
#define AK_E_SCHEMA_INVALID (-4002)
#define AK_E_SCHEMA_UNKNOWN (-4003)
#define AK_E_JSON_INVALID (-4004)
#define AK_E_FRAME_INCOMPLETE (-4005)

/* Capability errors (INV-2 enforcement) */
#define AK_E_CAP_MISSING (-4100)
#define AK_E_CAP_INVALID (-4101)
#define AK_E_CAP_EXPIRED (-4102)
#define AK_E_CAP_SCOPE (-4103)
#define AK_E_CAP_REVOKED (-4104)
#define AK_E_CAP_RATE (-4105)
#define AK_E_CAP_RUN_MISMATCH (-4106)

/* Policy/flow errors */
#define AK_E_REPLAY (-4200)
#define AK_E_POLICY_DENY (-4201)
#define AK_E_APPROVAL_REQUIRED (-4202)
#define AK_E_TAINT (-4203)
#define AK_E_DLP_BLOCK (-4204)

/* Resource errors (INV-3 enforcement) */
#define AK_E_BUDGET_EXCEEDED (-4300)
#define AK_E_RATE_LIMIT (-4301)
#define AK_E_DEADLINE (-4302)
#define AK_E_QUOTA_EXCEEDED (-4303)

/* Execution errors */
#define AK_E_CONFLICT (-4400) /* CAS version mismatch */
#define AK_E_TOOL_FAIL (-4401)
#define AK_E_TOOL_TIMEOUT (-4402)
#define AK_E_TOOL_NOT_FOUND (-4403)
#define AK_E_LOG_FULL (-4404)
#define AK_E_LOG_CORRUPT (-4405)
#define AK_E_NOT_IMPLEMENTED (-4406) /* Feature not implemented */

/* IPC errors (4500-4599) */
#define AK_E_IPC_INVALID (-4500)   /* Invalid IPC frame */
#define AK_E_SEQ_GAP (-4501)       /* Sequence number gap */
#define AK_E_POLICY_DENIED (-4502) /* Policy denied */
#define AK_E_TIMEOUT (-4503)       /* Operation timeout */

/* Network proxy errors (4550-4599) - for WASM host network operations */
#define AK_E_NET_REQUIRES_PROXY (-4550) /* Operation requires IPC proxy */
#define AK_E_NET_NO_DIRECT (-4551)   /* Direct network access denied from WASM \
                                      */
#define AK_E_NET_URL_INVALID (-4552) /* Invalid URL format */
#define AK_E_NET_HOST_INVALID (-4553)  /* Invalid host/port */
#define AK_E_NET_TLS_REQUIRED (-4554)  /* TLS required but not available */
#define AK_E_NET_PROXY_TIMEOUT (-4555) /* Proxy response timeout */
#define AK_E_NET_PROXY_ERROR (-4556)   /* Proxy returned error */

/* ============================================================
 * FRAME CONSTANTS
 * ============================================================ */

#define AK_MAX_FRAME_SIZE (4 * 1024 * 1024) /* 4MB hard limit */
#define AK_FRAME_HEADER_SIZE 4              /* Big-endian u32 */
#define AK_MIN_FRAME_SIZE 2                 /* Minimum valid JSON "{}" */

/* ============================================================
 * CRYPTOGRAPHIC CONSTANTS
 * ============================================================ */

/* Cryptographic sizes - defined in ak_config.h, with fallback defaults here */
#ifndef AK_HASH_SIZE
#define AK_HASH_SIZE 32 /* SHA-256 */
#endif
#ifndef AK_MAC_SIZE
#define AK_MAC_SIZE 32 /* HMAC-SHA256 */
#endif
#ifndef AK_KEY_SIZE
#define AK_KEY_SIZE 32 /* 256-bit keys */
#endif
#ifndef AK_TOKEN_ID_SIZE
#define AK_TOKEN_ID_SIZE 16 /* 128-bit token IDs */
#endif
/* AK_SIG_SIZE defined in ak_config.h */

/* ============================================================
 * CAPABILITY TYPES
 * ============================================================ */

typedef enum ak_cap_type {
  AK_CAP_NONE = 0,
  AK_CAP_NET = 1,       /* Network access */
  AK_CAP_FS = 2,        /* Filesystem access */
  AK_CAP_TOOL = 3,      /* Tool execution */
  AK_CAP_SECRETS = 4,   /* Secret resolution */
  AK_CAP_SPAWN = 5,     /* Agent spawning */
  AK_CAP_HEAP = 6,      /* Heap object access */
  AK_CAP_INFERENCE = 7, /* LLM access */
  AK_CAP_LLM = 7,       /* Alias for INFERENCE */
  AK_CAP_IPC = 8,       /* Inter-process communication */
  AK_CAP_ANY = 254,     /* Wildcard - matches any type */
  AK_CAP_ADMIN = 255,   /* Administrative (dangerous) */
} ak_cap_type_t;

/* ============================================================
 * TAINT LEVELS (Information Flow Control)
 * ============================================================
 * Lower value = more trusted
 * Propagation: result gets max(input taints)
 */

typedef enum ak_taint {
  AK_TAINT_TRUSTED = 0, /* Kernel-internal only */
  AK_TAINT_SANITIZED_URL = 10,
  AK_TAINT_SANITIZED_PATH = 11,
  AK_TAINT_SANITIZED_SQL = 12,
  AK_TAINT_SANITIZED_CMD = 13,
  AK_TAINT_SANITIZED_HTML = 14,
  AK_TAINT_UNTRUSTED = 100, /* External input default */
} ak_taint_t;

/* ============================================================
 * RESOURCE TYPES (for budget tracking)
 * ============================================================ */

typedef enum ak_resource_type {
  AK_RESOURCE_TOKENS,
  AK_RESOURCE_CALLS,
  AK_RESOURCE_INFERENCE_MS,
  AK_RESOURCE_FILE_BYTES,
  AK_RESOURCE_NETWORK_BYTES,
  AK_RESOURCE_HEAP_BYTES,
  AK_RESOURCE_HEAP_OBJECTS,
  AK_RESOURCE_BLOB_BYTES,
  AK_RESOURCE_WALL_TIME_MS,
  AK_RESOURCE_NET_BYTES_OUT,
  AK_RESOURCE_LLM_TOKENS_IN,
  AK_RESOURCE_LLM_TOKENS_OUT,
  AK_RESOURCE_TOOL_CALLS,
  AK_RESOURCE_COUNT, /* Number of resource types */
} ak_resource_type_t;

/* ============================================================
 * POLICY DECISIONS
 * ============================================================
 * Precedence: DENY > REQUIRE_APPROVAL > ALLOW
 */

typedef enum ak_policy_decision {
  AK_POLICY_DENY = 0, /* Highest precedence */
  AK_POLICY_REQUIRE_APPROVAL = 1,
  AK_POLICY_ALLOW = 2, /* Lowest precedence */
} ak_policy_decision_t;

/* ============================================================
 * FORWARD DECLARATIONS
 * ============================================================ */

typedef struct ak_capability ak_capability_t;
typedef struct ak_object ak_object_t;
typedef struct ak_log_entry ak_log_entry_t;
typedef struct ak_agent_context ak_agent_context_t;
typedef struct ak_request ak_request_t;
typedef struct ak_response ak_response_t;
typedef struct ak_heap ak_heap_t;
typedef struct ak_policy ak_policy_t;
typedef struct ak_channel ak_channel_t;
typedef struct ak_seq_tracker ak_seq_tracker_t;
typedef struct ak_budget ak_budget_bud_t;
typedef struct ak_budget_tracker ak_budget_tracker_t;

/* ============================================================
 * CAPABILITY STRUCTURE
 * ============================================================
 * Unforgeable token granting specific permissions.
 * Integrity protected by HMAC-SHA256.
 */

struct ak_capability {
  /* Type and resource */
  ak_cap_type_t type;
  u8 resource[256]; /* Domain/path pattern */
  u16 resource_len;

  /* Allowed operations */
  u8 methods[8][32]; /* Method names */
  u8 method_count;

  /* Temporal bounds */
  u64 issued_ms;
  u32 ttl_ms;

  /* Rate limiting */
  u32 rate_limit;     /* Max requests */
  u32 rate_window_ms; /* Per window */

  /* Binding */
  u8 run_id[AK_TOKEN_ID_SIZE];
  u8 tid[AK_TOKEN_ID_SIZE]; /* Token ID for revocation */

  /* Key identity */
  u8 kid; /* Which key signed this */

  /* Integrity (MUST be last field) */
  u8 mac[AK_MAC_SIZE];
};

/* ============================================================
 * HEAP OBJECT STRUCTURE
 * ============================================================
 * Typed, versioned objects with CAS semantics.
 */

struct ak_object {
  /* Identity */
  u64 ptr;       /* Unique object ID */
  u64 type_hash; /* Schema type identifier */

  /* Version control (INV-4 support) */
  u64 version; /* Monotonic, starts at 1 */
  u64 created_ms;
  u64 modified_ms;

  /* State */
  buffer value;    /* JSON value */
  boolean deleted; /* Tombstone */

  /* Security */
  ak_taint_t taint;
  u8 owner_run_id[AK_TOKEN_ID_SIZE];

  /* Audit linkage */
  u64 created_log_seq;
  u64 modified_log_seq;
};

/* ============================================================
 * LOG ENTRY STRUCTURE
 * ============================================================
 * Hash-chained audit entry (INV-4).
 */

struct ak_log_entry {
  /* Sequence and time */
  u64 seq;
  u64 ts_ms;

  /* Identity */
  u8 pid[AK_TOKEN_ID_SIZE];
  u8 run_id[AK_TOKEN_ID_SIZE];

  /* Operation */
  u16 op;                    /* Syscall number */
  u8 req_hash[AK_HASH_SIZE]; /* SHA256(canonical(request)) */
  u8 res_hash[AK_HASH_SIZE]; /* SHA256(canonical(response)) */

  /* Chain (tamper-evident) */
  u8 prev_hash[AK_HASH_SIZE];
  u8 this_hash[AK_HASH_SIZE];

  /* Policy state (for replay) */
  u8 policy_hash[AK_HASH_SIZE];
};

/* ============================================================
 * BUDGET STRUCTURE
 * ============================================================
 * Per-run resource limits (INV-3).
 */

typedef struct ak_budget {
  u64 limits[AK_RESOURCE_COUNT];
  u64 used[AK_RESOURCE_COUNT];
} ak_budget_t;

/* Default budget values */
#define AK_DEFAULT_LLM_TOKENS_IN 1000000
#define AK_DEFAULT_LLM_TOKENS_OUT 100000
#define AK_DEFAULT_TOOL_CALLS 100
#define AK_DEFAULT_WALL_TIME_MS 300000
#define AK_DEFAULT_HEAP_OBJECTS 10000
#define AK_DEFAULT_BLOB_BYTES (100 * 1024 * 1024)
#define AK_DEFAULT_NET_BYTES_OUT (10 * 1024 * 1024)

/* ============================================================
 * REQUEST STRUCTURE
 * ============================================================
 * Parsed syscall request.
 */

struct ak_request {
  /* Identity */
  u8 pid[AK_TOKEN_ID_SIZE];
  u8 run_id[AK_TOKEN_ID_SIZE];

  /* Sequencing (INV-2 anti-replay) */
  u64 seq;

  /* Operation */
  u16 op;
  buffer args; /* JSON arguments */

  /* Authorization */
  ak_capability_t *cap; /* May be NULL for cap-free ops */

  /* Security */
  ak_taint_t taint; /* Taint level of request data */

  /* Timing */
  u32 deadline_ms;

  /* Computed */
  u8 hash[AK_HASH_SIZE]; /* For logging */
};

/* ============================================================
 * RESPONSE STRUCTURE
 * ============================================================ */

typedef enum ak_status {
  AK_STATUS_OK = 0,
  AK_STATUS_ERROR = 1,
} ak_status_t;

struct ak_response {
  /* Identity (echo back from request) */
  u8 pid[AK_TOKEN_ID_SIZE];
  u8 run_id[AK_TOKEN_ID_SIZE];
  u64 seq;

  /* Status */
  ak_status_t status;
  s64 error_code;   /* If status == ERROR */
  buffer result;    /* JSON result */
  buffer error_msg; /* Human-readable error */

  /* Usage tracking */
  u64 usage[AK_RESOURCE_COUNT];

  /* Proof (INV-4) */
  u64 log_seq;
  u8 log_hash[AK_HASH_SIZE];

  /* Computed */
  u8 hash[AK_HASH_SIZE];
};

/* ============================================================
 * AGENT CONTEXT
 * ============================================================
 * Per-agent isolation state.
 */

struct ak_agent_context {
  /* Identity */
  u8 pid[AK_TOKEN_ID_SIZE];      /* Process/agent ID */
  u8 agent_id[AK_TOKEN_ID_SIZE]; /* Alias for pid */
  u8 run_id[AK_TOKEN_ID_SIZE];

  /* Memory allocator for this context */
  heap heap;

  /* Capabilities */
  ak_capability_t *root_cap;
  table delegated_caps; /* tid -> ak_capability_t* */

  /* Pending async external request (AK_SYS_INFER_ISSUE/POLL). One in flight
   * per context; opaque ak_https handle, reaped by INFER_POLL. */
  void *infer_handle;

  /* Policy (INV-2, INV-3 enforcement) */
  ak_policy_t *policy;

  /* Isolation (INV-1 support) */
  table allowed_paths; /* Unveil rules */
  table network_rules; /* Firewall rules */

  /* Resources (INV-3) */
  ak_budget_tracker_t *budget;

  /* Sequencing (INV-2 anti-replay) */
  struct ak_seq_tracker *seq_tracker;
  u64 last_seq;

  /* Lifecycle */
  u64 started_ms;
  boolean terminated;

  /* Parent linkage (for delegation) */
  struct ak_agent_context *parent;
};

/* ============================================================
 * VALIDATION PIPELINE RESULT
 * ============================================================ */

typedef struct ak_validation_result {
  boolean valid;
  s64 error_code;
  buffer error_msg;
  u8 stage; /* Which stage failed (1-7) */
} ak_validation_result_t;

/* Pipeline stages */
#define AK_STAGE_PARSE 1
#define AK_STAGE_SCHEMA 2
#define AK_STAGE_SEQUENCE 3
#define AK_STAGE_CAPABILITY 4
#define AK_STAGE_POLICY 5
#define AK_STAGE_BUDGET 6
#define AK_STAGE_TAINT 7

/* ============================================================
 * ANCHOR STRUCTURE (External commitment)
 * ============================================================ */

typedef struct ak_anchor {
  u64 ts_ms;
  u64 log_seq;
  u8 log_hash[AK_HASH_SIZE];
  u8 policy_hash[AK_HASH_SIZE];
  u8 run_id[AK_TOKEN_ID_SIZE];
  u8 signature[AK_SIG_SIZE]; /* Ed25519 signature */
} ak_anchor_t;

/* AK_ANCHOR_INTERVAL defined in ak_config.h */

/* ============================================================
 * GENESIS HASH
 * ============================================================ */

#define AK_GENESIS_HASH                                                        \
  "\x00\x00\x00\x00\x00\x00\x00\x00"                                           \
  "\x00\x00\x00\x00\x00\x00\x00\x00"                                           \
  "\x00\x00\x00\x00\x00\x00\x00\x00"                                           \
  "\x00\x00\x00\x00\x00\x00\x00\x00"

/* ============================================================
 * COMPILE-TIME ASSERTIONS
 * ============================================================
 * Verify critical constants and structure layouts.
 */

/* Verify hash/key sizes are reasonable */
AK_STATIC_ASSERT(AK_HASH_SIZE == 32,
                 "AK_HASH_SIZE must be 32 bytes for SHA-256");
AK_STATIC_ASSERT(AK_MAC_SIZE == 32,
                 "AK_MAC_SIZE must be 32 bytes for HMAC-SHA256");
AK_STATIC_ASSERT(AK_KEY_SIZE == 32, "AK_KEY_SIZE must be 32 bytes");
AK_STATIC_ASSERT(AK_TOKEN_ID_SIZE == 16, "AK_TOKEN_ID_SIZE must be 16 bytes");
AK_STATIC_ASSERT(AK_SIG_SIZE == 64, "AK_SIG_SIZE must be 64 bytes for Ed25519");

/* Verify syscall number ranges */
AK_STATIC_ASSERT(AK_SYS_MIN == 1024, "AK syscalls must start at 1024");
AK_STATIC_ASSERT(AK_SYS_MAX > AK_SYS_MIN,
                 "AK_SYS_MAX must be greater than AK_SYS_MIN");

/* Verify resource type count is bounded */
AK_STATIC_ASSERT(AK_RESOURCE_COUNT <= 16, "Too many resource types");

/* Verify frame size limits */
AK_STATIC_ASSERT(AK_MAX_FRAME_SIZE >= AK_MIN_FRAME_SIZE,
                 "Invalid frame size limits");
AK_STATIC_ASSERT(AK_FRAME_HEADER_SIZE == 4, "Frame header must be 4 bytes");

/* ============================================================
 * INVARIANT DOCUMENTATION
 * ============================================================
 *
 * INV-1: No-Bypass
 *   - All effectful operations MUST go through AK syscalls
 *   - Enforced by: ak_posix_route.c interception
 *   - Checked by: syscall audit in ak_effects.c
 *
 * INV-2: Capability
 *   - Every effectful syscall must carry valid capability
 *   - Enforced by: ak_capability_validate() in syscall path
 *   - Checked by: AK_ASSERT_INV2_HAS_CAP()
 *
 * INV-3: Budget
 *   - Resource usage must not exceed limits
 *   - Enforced by: ak_budget_check() before operation
 *   - Checked by: AK_ASSERT_INV3_BUDGET()
 *
 * INV-4: Log Commitment
 *   - All operations are hash-chained in audit log
 *   - Enforced by: ak_audit_log() after each operation
 *   - Checked by: AK_ASSERT_INV4_LOG_CHAIN()
 */

#endif /* AK_TYPES_H */
