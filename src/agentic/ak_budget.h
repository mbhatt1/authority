/*
 * Authority Kernel - Budget Tracking System
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This module provides enhanced budget tracking with historical snapshots,
 * detailed breakdowns, and consumption monitoring for resource management (INV-3).
 *
 * Features:
 * - Real-time budget status queries
 * - Historical consumption snapshots (ring buffer)
 * - Per-operation breakdown tracking
 * - Budget consumption rate calculation
 */

#ifndef AK_BUDGET_H
#define AK_BUDGET_H

#include "ak_types.h"
#include "ak_compat.h"

/* Configuration constants */
#define AK_BUDGET_HISTORY_SIZE 60     /* Number of historical snapshots (1 minute at 1/sec) */
#define AK_BUDGET_MAX_TOOL_TYPES 32   /* Maximum distinct tool types to track */
#define AK_BUDGET_TOOL_NAME_LEN 64    /* Maximum tool name length */

/* ============================================================
 * LIMIT SEMANTICS (INV-3, fail-closed)
 * ============================================================
 * Budget limits are hard, kernel-enforced caps. For every resource:
 *
 *   limit == 0                   No budget granted. All non-zero
 *                                consumption is DENIED (fail-closed).
 *   limit == AK_BUDGET_UNLIMITED Effectively unlimited (sentinel).
 *   otherwise                    used + amount must not exceed limit.
 *
 * All limit comparisons are overflow-safe: a request whose amount
 * would wrap the u64 running total is treated as over-limit.
 */
#define AK_BUDGET_UNLIMITED ((u64)infinity)

/* ============================================================
 * BUDGET SNAPSHOT STRUCTURE
 * ============================================================
 * A point-in-time snapshot of budget consumption.
 * Used for historical tracking and burn rate calculation.
 */

typedef struct ak_budget_snapshot {
    u64 timestamp_ms;           /* When this snapshot was taken */
    u64 tokens;                 /* Total tokens consumed at this time */
    u64 tool_calls;             /* Total tool calls at this time */
    u64 wall_time_ms;           /* Wall time elapsed (ms) */
    u64 bytes;                  /* Total bytes consumed */
} ak_budget_snapshot_t;

/* ============================================================
 * BUDGET BREAKDOWN STRUCTURE
 * ============================================================
 * Detailed breakdown of budget consumption by operation type.
 */

typedef struct ak_budget_breakdown {
    /* Token consumption by source */
    u64 tokens_inference;       /* Tokens consumed by LLM inference */
    u64 tokens_tool_responses;  /* Tokens in tool response processing */
    
    /* Tool call tracking */
    u32 tool_calls_by_type[AK_BUDGET_MAX_TOOL_TYPES];
    char tool_names[AK_BUDGET_MAX_TOOL_TYPES][AK_BUDGET_TOOL_NAME_LEN];
    u32 tool_type_count;        /* Number of distinct tools tracked */
} ak_budget_breakdown_t;

/* ============================================================
 * BUDGET TRACKER STRUCTURE
 * ============================================================
 * Enhanced budget tracking with historical data and breakdowns.
 */

typedef struct ak_budget_tracker {
    /* Base budget (from ak_types.h) */
    ak_budget_t budget;         /* Current limits and usage */

    /* Concurrency: protects budget limits/usage, snapshots and breakdown.
     * All check/reserve/consume/commit paths take this lock so that
     * admission decisions and usage updates are atomic (no TOCTOU). */
    struct spinlock lock;

    /* Tracking metadata */
    u64 start_timestamp_ms;     /* When tracking started */
    u64 last_update_ms;         /* Last update timestamp */
    u64 last_snapshot_ms;       /* Last snapshot timestamp */
    
    /* Historical snapshots (ring buffer) */
    ak_budget_snapshot_t snapshots[AK_BUDGET_HISTORY_SIZE];
    u32 snapshot_head;          /* Ring buffer head index */
    u32 snapshot_count;         /* Number of snapshots (max AK_BUDGET_HISTORY_SIZE) */
    
    /* Detailed breakdown */
    ak_budget_breakdown_t breakdown;
    
    /* Memory management */
    heap h;
} ak_budget_tracker_t;

/* ============================================================
 * BUDGET STATUS RESULT
 * ============================================================
 * Result structure for budget status queries.
 */

typedef struct ak_budget_status {
    /* Current consumption */
    u64 tokens_used;
    u64 tokens_limit;
    u64 tool_calls_used;
    u64 tool_calls_limit;
    u64 wall_time_ms_used;
    u64 wall_time_ms_limit;
    u64 bytes_used;
    u64 bytes_limit;
    
    /* Metadata */
    u64 last_update_ms;
} ak_budget_status_t;

/* ============================================================
 * FUNCTION PROTOTYPES
 * ============================================================ */

/**
 * Initialize a budget tracker.
 *
 * @param h Heap allocator
 * @return Initialized budget tracker, or NULL on failure
 */
ak_budget_tracker_t *ak_budget_tracker_init(heap h);

/**
 * Destroy a budget tracker and free resources.
 *
 * @param tracker Budget tracker to destroy
 */
void ak_budget_tracker_destroy(ak_budget_tracker_t *tracker);

/**
 * Set budget limits from policy.
 *
 * @param tracker Budget tracker
 * @param resource Resource type
 * @param limit Limit value (0 = deny all, AK_BUDGET_UNLIMITED = no cap)
 */
void ak_budget_set_limit(ak_budget_tracker_t *tracker,
                        ak_resource_type_t resource,
                        u64 limit);

/**
 * Consume budget for a resource.
 *
 * Atomic check-and-consume: takes the tracker lock, verifies the
 * amount fits (overflow-safe, limit==0 denies) and records usage.
 *
 * @param tracker Budget tracker
 * @param resource Resource type
 * @param amount Amount to consume
 * @return 0 on success, AK_E_BUDGET_EXCEEDED on budget exceeded
 */
int ak_budget_consume(ak_budget_tracker_t *tracker,
                     ak_resource_type_t resource,
                     u64 amount);

/**
 * Record detailed breakdown for specific operations.
 *
 * @param tracker Budget tracker
 * @param operation Operation type (e.g., "inference", "tool_call")
 * @param detail Detail string (e.g., tool name)
 * @param amount Amount consumed
 */
void ak_budget_record_operation(ak_budget_tracker_t *tracker,
                                const char *operation,
                                const char *detail,
                                u64 amount);

/**
 * Take a snapshot of current budget state.
 * Should be called periodically (e.g., every second).
 *
 * @param tracker Budget tracker
 */
void ak_budget_snapshot(ak_budget_tracker_t *tracker);

/**
 * Get current budget status.
 *
 * @param tracker Budget tracker
 * @param status Output status structure
 */
void ak_budget_get_status(ak_budget_tracker_t *tracker,
                         ak_budget_status_t *status);

/**
 * Get historical snapshots.
 *
 * @param tracker Budget tracker
 * @param snapshots Output array (caller-allocated)
 * @param max_count Maximum snapshots to retrieve
 * @return Actual number of snapshots returned
 */
u32 ak_budget_get_history(ak_budget_tracker_t *tracker,
                         ak_budget_snapshot_t *snapshots,
                         u32 max_count);

/**
 * Get detailed breakdown of consumption.
 *
 * @param tracker Budget tracker
 * @param breakdown Output breakdown structure
 */
void ak_budget_get_breakdown(ak_budget_tracker_t *tracker,
                            ak_budget_breakdown_t *breakdown);

/**
 * Check if budget is critically low (>90% consumed).
 * A limit of 0 (no budget granted) is always critical;
 * AK_BUDGET_UNLIMITED is never critical.
 *
 * @param tracker Budget tracker
 * @param resource Resource type to check
 * @return true if resource is critically low
 */
boolean ak_budget_is_critical(ak_budget_tracker_t *tracker,
                              ak_resource_type_t resource);

/**
 * Calculate consumption rate (units per second).
 *
 * @param tracker Budget tracker
 * @param resource Resource type
 * @return Consumption rate in units per second (integer), or 0 if cannot
 *         calculate. Integer fixed-point: the kernel is built -mno-sse.
 */
u64 ak_budget_calc_rate(ak_budget_tracker_t *tracker,
                        ak_resource_type_t resource);

/**
 * Format budget status as JSON.
 *
 * @param tracker Budget tracker
 * @param output Output buffer
 */
void ak_budget_format_json(ak_budget_tracker_t *tracker, buffer output);

/**
 * Format budget history as JSON.
 *
 * @param tracker Budget tracker
 * @param count Number of snapshots to include
 * @param output Output buffer
 */
void ak_budget_format_history_json(ak_budget_tracker_t *tracker,
                                   u32 count,
                                   buffer output);

/**
 * Format budget breakdown as JSON.
 *
 * @param tracker Budget tracker
 * @param output Output buffer
 */
void ak_budget_format_breakdown_json(ak_budget_tracker_t *tracker,
                                    buffer output);

/* Forward declaration for compatibility wrapper */
typedef struct ak_policy ak_policy_t;

/**
 * Create budget tracker with policy (compatibility wrapper).
 *
 * Limits for resources covered by the policy budget block are taken
 * from the policy (0 there means denied - fail-closed); resources the
 * policy does not cover keep the AK_DEFAULT_* limits. If policy is
 * NULL, all defaults apply.
 *
 * @param h Heap for allocation
 * @param run_id Run identifier (optional)
 * @param policy Policy with budget limits (optional)
 * @return Allocated budget tracker or NULL on error
 */
ak_budget_tracker_t *ak_budget_create(heap h, u8 *run_id, ak_policy_t *policy);

/**
 * Destroy budget tracker (compatibility wrapper).
 */
void ak_budget_destroy(heap h, ak_budget_tracker_t *tracker);

/**
 * Check if budget is available for resource (advisory only).
 *
 * Overflow-safe; limit==0 denies (fail-closed). NOTE: check followed
 * by commit is NOT atomic - concurrent callers can both pass check.
 * Use ak_budget_reserve() for atomic admission control.
 */
boolean ak_budget_check(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount);

/**
 * Commit resource consumption to budget.
 *
 * Unconditionally records usage (saturating at AK_BUDGET_UNLIMITED;
 * the running total never wraps). Locked, but does not re-check the
 * limit - pair with ak_budget_reserve() for enforced admission.
 */
void ak_budget_commit(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount);

/**
 * Atomically reserve budget for resource (check-and-consume).
 *
 * This is the enforced admission path (INV-3): the limit check and
 * the usage update happen in one critical section, so concurrent
 * callers cannot jointly overshoot the limit. On failure of the
 * subsequent operation, undo with ak_budget_release().
 *
 * @return 0 on success, AK_E_BUDGET_EXCEEDED if it would exceed limit
 */
s64 ak_budget_reserve(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount);

/**
 * Release previously reserved budget (operation failed/cancelled).
 * Clamps at zero; never underflows.
 */
void ak_budget_release(ak_budget_tracker_t *tracker, ak_resource_type_t type, u64 amount);

/* ============================================================
 * BUDGET REQUEST HANDLERS
 * ============================================================ */

/**
 * Handle BUDGET_STATUS request - get current budget consumption.
 */
ak_response_t *ak_handle_budget_status(ak_agent_context_t *ctx, ak_request_t *req);

/**
 * Handle BUDGET_HISTORY request - get historical budget snapshots.
 */
ak_response_t *ak_handle_budget_history(ak_agent_context_t *ctx, ak_request_t *req);

/**
 * Handle BUDGET_BREAKDOWN request - get detailed budget breakdown.
 */
ak_response_t *ak_handle_budget_breakdown(ak_agent_context_t *ctx, ak_request_t *req);

#endif /* AK_BUDGET_H */
