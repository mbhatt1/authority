/*
 * Authority Kernel - Budget Tracking System Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This module implements enhanced budget tracking with historical snapshots,
 * detailed breakdowns, and consumption monitoring (INV-3).
 */

#include "ak_budget.h"
#include "ak_assert.h"
#include "ak_policy.h"
#include <runtime.h>

/* Define missing macros if not already defined */
#ifndef AK_ASSERT_ARG
#if AK_ASSERT_LEVEL > 0
#define AK_ASSERT_ARG(cond) AK_ASSERT(cond)
#else
#define AK_ASSERT_ARG(cond) ((void)0)
#endif
#endif

#ifndef AK_MIN
#define AK_MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

/* Get current timestamp in milliseconds */
static u64 ak_budget_timestamp_ms(void)
{
    return now(CLOCK_ID_MONOTONIC) / MILLION; /* Convert nanoseconds to milliseconds */
}

/*
 * Overflow-safe limit check (INV-3, fail-closed).
 *
 * Returns true iff used + amount fits within limit, without the u64
 * addition being able to wrap: a huge amount cannot make used + amount
 * wrap below limit and slip past enforcement. Semantics:
 *   limit == 0                   -> deny any non-zero amount
 *   limit == AK_BUDGET_UNLIMITED -> effectively unlimited
 *
 * Caller must hold tracker->lock.
 */
static boolean ak_budget_fits(u64 used, u64 limit, u64 amount)
{
    if (used > limit) {
        return false;
    }
    return amount <= limit - used;
}

/* Find tool index in breakdown by name */
static int ak_budget_find_tool(ak_budget_breakdown_t *breakdown, const char *tool_name)
{
    if (!tool_name) return -1;
    bytes tool_len = runtime_strlen(tool_name);
    for (u32 i = 0; i < breakdown->tool_type_count; i++) {
        bytes name_len = runtime_strlen(breakdown->tool_names[i]);
        if (name_len == tool_len && runtime_memcmp(breakdown->tool_names[i], tool_name, tool_len) == 0) {
            return i;
        }
    }
    return -1;
}

/* Add tool to breakdown tracking */
static int ak_budget_add_tool(ak_budget_breakdown_t *breakdown, const char *tool_name)
{
    if (breakdown->tool_type_count >= AK_BUDGET_MAX_TOOL_TYPES) {
        return -1; /* No space for more tools */
    }
    
    u32 idx = breakdown->tool_type_count;
    runtime_memcpy(breakdown->tool_names[idx], tool_name, 
                  AK_MIN(runtime_strlen(tool_name) + 1, AK_BUDGET_TOOL_NAME_LEN));
    breakdown->tool_names[idx][AK_BUDGET_TOOL_NAME_LEN - 1] = '\0';
    breakdown->tool_calls_by_type[idx] = 0;
    breakdown->tool_type_count++;
    
    return idx;
}

ak_budget_tracker_t *ak_budget_tracker_init(heap h)
{
    AK_ASSERT_ARG(h != INVALID_ADDRESS);
    
    ak_budget_tracker_t *tracker = allocate(h, sizeof(ak_budget_tracker_t));
    if (tracker == INVALID_ADDRESS) {
        return NULL;
    }

    runtime_memset((u8*)tracker, 0, sizeof(ak_budget_tracker_t));
    tracker->h = h;
    spin_lock_init(&tracker->lock);
    tracker->start_timestamp_ms = ak_budget_timestamp_ms();
    tracker->last_update_ms = tracker->start_timestamp_ms;
    tracker->last_snapshot_ms = tracker->start_timestamp_ms;
    
    /* Initialize default limits */
    tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_IN] = AK_DEFAULT_LLM_TOKENS_IN;
    tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_OUT] = AK_DEFAULT_LLM_TOKENS_OUT;
    tracker->budget.limits[AK_RESOURCE_TOOL_CALLS] = AK_DEFAULT_TOOL_CALLS;
    tracker->budget.limits[AK_RESOURCE_WALL_TIME_MS] = AK_DEFAULT_WALL_TIME_MS;
    tracker->budget.limits[AK_RESOURCE_HEAP_OBJECTS] = AK_DEFAULT_HEAP_OBJECTS;
    tracker->budget.limits[AK_RESOURCE_BLOB_BYTES] = AK_DEFAULT_BLOB_BYTES;
    tracker->budget.limits[AK_RESOURCE_NET_BYTES_OUT] = AK_DEFAULT_NET_BYTES_OUT;
    
    /* Take initial snapshot */
    ak_budget_snapshot(tracker);
    
    return tracker;
}

void ak_budget_tracker_destroy(ak_budget_tracker_t *tracker)
{
    if (tracker == NULL || tracker == INVALID_ADDRESS) {
        return;
    }

    deallocate(tracker->h, tracker, sizeof(ak_budget_tracker_t));
}

/* Compatibility wrapper for old API that takes policy */
ak_budget_tracker_t *ak_budget_create(heap h, u8 *run_id, ak_policy_t *policy)
{
    (void)run_id;

    ak_budget_tracker_t *tracker = ak_budget_tracker_init(h);
    if (tracker == NULL) {
        return NULL;
    }

    /* Apply per-resource limits from the policy budget block (INV-3).
     * Policy values are applied verbatim: 0 means no budget granted
     * (fail-closed deny), matching the documented limit semantics.
     * Resources the policy does not cover (LLM token split, tool
     * calls, wall time, blob/net bytes) keep the AK_DEFAULT_* limits
     * set by ak_budget_tracker_init(). If policy is NULL, defaults
     * apply across the board.
     * Note: policy->budgets.spawn_count has no ak_resource_type_t
     * counterpart and is enforced elsewhere. */
    if (policy) {
        tracker->budget.limits[AK_RESOURCE_TOKENS] = policy->budgets.tokens;
        tracker->budget.limits[AK_RESOURCE_CALLS] = policy->budgets.calls;
        tracker->budget.limits[AK_RESOURCE_INFERENCE_MS] = policy->budgets.inference_ms;
        tracker->budget.limits[AK_RESOURCE_FILE_BYTES] = policy->budgets.file_bytes;
        tracker->budget.limits[AK_RESOURCE_NETWORK_BYTES] = policy->budgets.network_bytes;
        tracker->budget.limits[AK_RESOURCE_HEAP_OBJECTS] = policy->budgets.heap_objects;
        tracker->budget.limits[AK_RESOURCE_HEAP_BYTES] = policy->budgets.heap_bytes;
    }

    return tracker;
}

void ak_budget_set_limit(ak_budget_tracker_t *tracker,
                        ak_resource_type_t resource,
                        u64 limit)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(resource < AK_RESOURCE_COUNT);

    spin_lock(&tracker->lock);
    tracker->budget.limits[resource] = limit;
    tracker->last_update_ms = ak_budget_timestamp_ms();
    spin_unlock(&tracker->lock);
}

int ak_budget_consume(ak_budget_tracker_t *tracker,
                     ak_resource_type_t resource,
                     u64 amount)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(resource < AK_RESOURCE_COUNT);

    spin_lock(&tracker->lock);

    /* Atomic check-and-consume: overflow-safe, limit==0 denies */
    if (!ak_budget_fits(tracker->budget.used[resource],
                        tracker->budget.limits[resource], amount)) {
        spin_unlock(&tracker->lock);
        return AK_E_BUDGET_EXCEEDED;
    }

    /* Update consumption */
    tracker->budget.used[resource] += amount;
    tracker->last_update_ms = ak_budget_timestamp_ms();

    spin_unlock(&tracker->lock);
    return 0;
}

void ak_budget_record_operation(ak_budget_tracker_t *tracker,
                                const char *operation,
                                const char *detail,
                                u64 amount)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(operation != NULL);

    spin_lock(&tracker->lock);
    tracker->last_update_ms = ak_budget_timestamp_ms();

    /* Track operation-specific details */
    if (runtime_strlen(operation) == 9 && runtime_memcmp(operation, "inference", 9) == 0) {
        tracker->breakdown.tokens_inference += amount;
    } else if (runtime_strlen(operation) == 13 && runtime_memcmp(operation, "tool_response", 13) == 0) {
        tracker->breakdown.tokens_tool_responses += amount;
    } else if (runtime_strlen(operation) == 9 && runtime_memcmp(operation, "tool_call", 9) == 0 && detail != NULL) {
        /* Track tool calls by name */
        int idx = ak_budget_find_tool(&tracker->breakdown, detail);
        if (idx < 0) {
            idx = ak_budget_add_tool(&tracker->breakdown, detail);
        }
        if (idx >= 0) {
            tracker->breakdown.tool_calls_by_type[idx]++;
        }
    }
    spin_unlock(&tracker->lock);
}

void ak_budget_snapshot(ak_budget_tracker_t *tracker)
{
    AK_ASSERT_ARG(tracker != NULL);
    
    u64 now_ms = ak_budget_timestamp_ms();

    spin_lock(&tracker->lock);

    /* Create snapshot */
    ak_budget_snapshot_t snapshot;
    snapshot.timestamp_ms = now_ms;
    snapshot.tokens = tracker->budget.used[AK_RESOURCE_LLM_TOKENS_IN] +
                     tracker->budget.used[AK_RESOURCE_LLM_TOKENS_OUT];
    snapshot.tool_calls = tracker->budget.used[AK_RESOURCE_TOOL_CALLS];
    snapshot.wall_time_ms = now_ms - tracker->start_timestamp_ms;
    snapshot.bytes = tracker->budget.used[AK_RESOURCE_BLOB_BYTES] +
                    tracker->budget.used[AK_RESOURCE_NET_BYTES_OUT];
    
    /* Add to ring buffer */
    tracker->snapshots[tracker->snapshot_head] = snapshot;
    tracker->snapshot_head = (tracker->snapshot_head + 1) % AK_BUDGET_HISTORY_SIZE;
    
    if (tracker->snapshot_count < AK_BUDGET_HISTORY_SIZE) {
        tracker->snapshot_count++;
    }

    tracker->last_snapshot_ms = now_ms;
    spin_unlock(&tracker->lock);
}

void ak_budget_get_status(ak_budget_tracker_t *tracker,
                         ak_budget_status_t *status)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(status != NULL);

    runtime_memset((u8*)status, 0, sizeof(ak_budget_status_t));

    spin_lock(&tracker->lock);

    /* Token consumption (combine input and output) */
    status->tokens_used = tracker->budget.used[AK_RESOURCE_LLM_TOKENS_IN] +
                         tracker->budget.used[AK_RESOURCE_LLM_TOKENS_OUT];
    status->tokens_limit = tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_IN] +
                          tracker->budget.limits[AK_RESOURCE_LLM_TOKENS_OUT];
    
    /* Tool calls */
    status->tool_calls_used = tracker->budget.used[AK_RESOURCE_TOOL_CALLS];
    status->tool_calls_limit = tracker->budget.limits[AK_RESOURCE_TOOL_CALLS];
    
    /* Wall time */
    u64 now_ms = ak_budget_timestamp_ms();
    status->wall_time_ms_used = now_ms - tracker->start_timestamp_ms;
    status->wall_time_ms_limit = tracker->budget.limits[AK_RESOURCE_WALL_TIME_MS];
    
    /* Bytes (combine blob and network) */
    status->bytes_used = tracker->budget.used[AK_RESOURCE_BLOB_BYTES] +
                        tracker->budget.used[AK_RESOURCE_NET_BYTES_OUT];
    status->bytes_limit = tracker->budget.limits[AK_RESOURCE_BLOB_BYTES] +
                         tracker->budget.limits[AK_RESOURCE_NET_BYTES_OUT];
    
    status->last_update_ms = tracker->last_update_ms;

    spin_unlock(&tracker->lock);
}

u32 ak_budget_get_history(ak_budget_tracker_t *tracker,
                         ak_budget_snapshot_t *snapshots,
                         u32 max_count)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(snapshots != NULL);

    spin_lock(&tracker->lock);

    u32 count = AK_MIN(tracker->snapshot_count, max_count);
    if (count == 0) {
        spin_unlock(&tracker->lock);
        return 0;
    }

    /* Copy snapshots in chronological order */
    u32 start_idx;
    if (tracker->snapshot_count < AK_BUDGET_HISTORY_SIZE) {
        /* Haven't wrapped yet */
        start_idx = 0;
    } else {
        /* Wrapped - start from oldest */
        start_idx = tracker->snapshot_head;
    }
    
    for (u32 i = 0; i < count; i++) {
        u32 idx = (start_idx + i) % AK_BUDGET_HISTORY_SIZE;
        snapshots[i] = tracker->snapshots[idx];
    }

    spin_unlock(&tracker->lock);
    return count;
}

void ak_budget_get_breakdown(ak_budget_tracker_t *tracker,
                            ak_budget_breakdown_t *breakdown)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(breakdown != NULL);

    spin_lock(&tracker->lock);
    runtime_memcpy(breakdown, &tracker->breakdown, sizeof(ak_budget_breakdown_t));
    spin_unlock(&tracker->lock);
}

boolean ak_budget_is_critical(ak_budget_tracker_t *tracker,
                              ak_resource_type_t resource)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(resource < AK_RESOURCE_COUNT);

    spin_lock(&tracker->lock);
    u64 limit = tracker->budget.limits[resource];
    u64 used = tracker->budget.used[resource];
    spin_unlock(&tracker->lock);

    if (limit == 0) {
        return true; /* No budget granted - already exhausted (fail-closed) */
    }

    if (used >= limit) {
        return true;
    }

    /* Critical if >90% consumed, i.e. less than 10% headroom left.
     * Computed on the remainder to avoid u64 overflow of used * 100. */
    return (limit - used) < (limit / 10);
}

/*
 * Returns the consumption rate in units per second as an INTEGER.
 * The kernel is built -mno-sse (no floating point), so this uses
 * fixed-point integer math: rate = delta * 1000 / time_span_ms.
 */
u64 ak_budget_calc_rate(ak_budget_tracker_t *tracker,
                        ak_resource_type_t resource)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(resource < AK_RESOURCE_COUNT);

    spin_lock(&tracker->lock);

    if (tracker->snapshot_count < 2) {
        spin_unlock(&tracker->lock);
        return 0; /* Need at least 2 snapshots */
    }

    /* Get oldest and newest snapshots */
    u32 oldest_idx, newest_idx;
    if (tracker->snapshot_count < AK_BUDGET_HISTORY_SIZE) {
        oldest_idx = 0;
        newest_idx = tracker->snapshot_count - 1;
    } else {
        oldest_idx = tracker->snapshot_head;
        newest_idx = (tracker->snapshot_head + AK_BUDGET_HISTORY_SIZE - 1) % AK_BUDGET_HISTORY_SIZE;
    }

    /* Copy under lock; compute after unlock */
    ak_budget_snapshot_t oldest_snap = tracker->snapshots[oldest_idx];
    ak_budget_snapshot_t newest_snap = tracker->snapshots[newest_idx];

    spin_unlock(&tracker->lock);

    ak_budget_snapshot_t *oldest = &oldest_snap;
    ak_budget_snapshot_t *newest = &newest_snap;

    /* Calculate time span in milliseconds */
    u64 time_span_ms = newest->timestamp_ms - oldest->timestamp_ms;
    if (time_span_ms == 0) {
        return 0;
    }

    /* Calculate consumption delta based on resource type */
    u64 delta = 0;
    switch (resource) {
        case AK_RESOURCE_TOKENS:
        case AK_RESOURCE_LLM_TOKENS_IN:
        case AK_RESOURCE_LLM_TOKENS_OUT:
            delta = newest->tokens - oldest->tokens;
            break;
        case AK_RESOURCE_TOOL_CALLS:
            delta = newest->tool_calls - oldest->tool_calls;
            break;
        case AK_RESOURCE_WALL_TIME_MS:
            delta = newest->wall_time_ms - oldest->wall_time_ms;
            break;
        default:
            delta = newest->bytes - oldest->bytes;
            break;
    }
    
    /* rate = delta / (time_span_ms/1000) = delta * 1000 / time_span_ms,
     * computed as fixed-point integer. Guard against delta*1000 overflow. */
    if (delta > (AK_BUDGET_UNLIMITED / 1000))
        return (delta / time_span_ms) * 1000;
    return (delta * 1000) / time_span_ms;
}

void ak_budget_format_json(ak_budget_tracker_t *tracker, buffer output)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(output != NULL);
    
    ak_budget_status_t status;
    ak_budget_get_status(tracker, &status);
    
    bprintf(output, "{");
    bprintf(output, "\"tokens_used\":%lu,", status.tokens_used);
    bprintf(output, "\"tokens_limit\":%lu,", status.tokens_limit);
    bprintf(output, "\"tool_calls_used\":%lu,", status.tool_calls_used);
    bprintf(output, "\"tool_calls_limit\":%lu,", status.tool_calls_limit);
    bprintf(output, "\"wall_time_ms_used\":%lu,", status.wall_time_ms_used);
    bprintf(output, "\"wall_time_ms_limit\":%lu,", status.wall_time_ms_limit);
    bprintf(output, "\"bytes_used\":%lu,", status.bytes_used);
    bprintf(output, "\"bytes_limit\":%lu,", status.bytes_limit);
    bprintf(output, "\"last_update_ms\":%lu", status.last_update_ms);
    bprintf(output, "}");
}

void ak_budget_format_history_json(ak_budget_tracker_t *tracker,
                                   u32 count,
                                   buffer output)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(output != NULL);
    
    ak_budget_snapshot_t snapshots[AK_BUDGET_HISTORY_SIZE];
    u32 actual_count = ak_budget_get_history(tracker, snapshots, count);
    
    bprintf(output, "{\"snapshots\":[");
    
    for (u32 i = 0; i < actual_count; i++) {
        if (i > 0) {
            bprintf(output, ",");
        }
        bprintf(output, "{");
        bprintf(output, "\"timestamp_ms\":%lu,", snapshots[i].timestamp_ms);
        bprintf(output, "\"tokens\":%lu,", snapshots[i].tokens);
        bprintf(output, "\"tool_calls\":%lu,", snapshots[i].tool_calls);
        bprintf(output, "\"wall_time_ms\":%lu,", snapshots[i].wall_time_ms);
        bprintf(output, "\"bytes\":%lu", snapshots[i].bytes);
        bprintf(output, "}");
    }
    
    bprintf(output, "]}");
}

void ak_budget_format_breakdown_json(ak_budget_tracker_t *tracker,
                                    buffer output)
{
    AK_ASSERT_ARG(tracker != NULL);
    AK_ASSERT_ARG(output != NULL);

    /* Copy under the tracker lock; format outside the critical section */
    ak_budget_breakdown_t breakdown_copy;
    ak_budget_get_breakdown(tracker, &breakdown_copy);
    ak_budget_breakdown_t *breakdown = &breakdown_copy;

    bprintf(output, "{");
    
    /* Token breakdown */
    bprintf(output, "\"tokens_by_operation\":{");
    bprintf(output, "\"inference\":%lu,", breakdown->tokens_inference);
    bprintf(output, "\"tool_responses\":%lu", breakdown->tokens_tool_responses);
    bprintf(output, "},");
    
    /* Tool calls breakdown */
    bprintf(output, "\"tool_calls_by_name\":{");
    for (u32 i = 0; i < breakdown->tool_type_count; i++) {
        if (i > 0) {
            bprintf(output, ",");
        }
        bprintf(output, "\"%s\":%u", breakdown->tool_names[i],
               breakdown->tool_calls_by_type[i]);
    }
    bprintf(output, "},");
    
    /* Model breakdown (placeholder for future expansion) */
    bprintf(output, "\"tokens_by_model\":{}");

    bprintf(output, "}");
}

/* ============================================================
 * COMPATIBILITY API (Old budget functions)
 * ============================================================ */

/**
 * Destroy a budget tracker and free resources.
 */
void ak_budget_destroy(heap h, ak_budget_tracker_t *tracker)
{
    if (tracker == NULL || tracker == INVALID_ADDRESS) {
        return;
    }
    deallocate(h, tracker, sizeof(ak_budget_tracker_t));
}

/**
 * Check if a resource budget is available.
 * Returns true if the request fits within budget limits.
 *
 * ADVISORY ONLY: check followed by commit is not atomic; use
 * ak_budget_reserve() for enforced admission control.
 */
boolean ak_budget_check(ak_budget_tracker_t *tracker, ak_resource_type_t type,
                       u64 amount)
{
    if (!tracker) {
        return false;
    }

    if (type >= AK_RESOURCE_COUNT) {
        return false;
    }

    spin_lock(&tracker->lock);
    boolean fits = ak_budget_fits(tracker->budget.used[type],
                                  tracker->budget.limits[type], amount);
    spin_unlock(&tracker->lock);

    return fits;
}

/**
 * Commit a resource budget consumption.
 * Marks the resource as consumed. The running total saturates instead
 * of wrapping so a huge commit cannot reset usage to a small value.
 */
void ak_budget_commit(ak_budget_tracker_t *tracker, ak_resource_type_t type,
                     u64 amount)
{
    if (!tracker || type >= AK_RESOURCE_COUNT) {
        return;
    }

    spin_lock(&tracker->lock);
    u64 used = tracker->budget.used[type];
    if (amount > AK_BUDGET_UNLIMITED - used) {
        tracker->budget.used[type] = AK_BUDGET_UNLIMITED; /* Saturate, never wrap */
    } else {
        tracker->budget.used[type] = used + amount;
    }
    tracker->last_update_ms = ak_budget_timestamp_ms();
    spin_unlock(&tracker->lock);
}

/**
 * Atomically reserve budget (check-and-consume in one critical section).
 * This closes the check/commit TOCTOU window: concurrent callers cannot
 * both pass the limit check and jointly overshoot the budget (INV-3).
 */
s64 ak_budget_reserve(ak_budget_tracker_t *tracker, ak_resource_type_t type,
                      u64 amount)
{
    if (!tracker || type >= AK_RESOURCE_COUNT) {
        return AK_E_BUDGET_EXCEEDED; /* Fail closed */
    }

    spin_lock(&tracker->lock);

    if (!ak_budget_fits(tracker->budget.used[type],
                        tracker->budget.limits[type], amount)) {
        spin_unlock(&tracker->lock);
        return AK_E_BUDGET_EXCEEDED;
    }

    tracker->budget.used[type] += amount;
    tracker->last_update_ms = ak_budget_timestamp_ms();

    spin_unlock(&tracker->lock);
    return 0;
}

/**
 * Release previously reserved budget (operation failed/cancelled).
 * Clamps at zero; never underflows.
 */
void ak_budget_release(ak_budget_tracker_t *tracker, ak_resource_type_t type,
                       u64 amount)
{
    if (!tracker || type >= AK_RESOURCE_COUNT) {
        return;
    }

    spin_lock(&tracker->lock);
    u64 used = tracker->budget.used[type];
    tracker->budget.used[type] = (amount > used) ? 0 : used - amount;
    tracker->last_update_ms = ak_budget_timestamp_ms();
    spin_unlock(&tracker->lock);
}

