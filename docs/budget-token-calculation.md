# Budget Tracking: Token Calculation Explained

## Overview

The Authority kernel tracks consumption across several resource types to enforce hard budget limits. This document explains how usage — including token counts reported by outbound requests — is calculated, tracked, and reported.

Budgets are enforced **before admission**: the policy-and-budget stage of `ak_dispatch()` denies any operation that would push a resource past its declared limit (INV-3).

---

## Where Usage Comes From

Usage is recorded by the kernel as effects execute through the enforcement pipeline.

```c
// In ak_budget.c
int ak_budget_consume(ak_budget_tracker_t *tracker,
                     ak_resource_type_t resource,
                     u64 amount)
{
    u64 limit = tracker->budget.limits[resource];
    u64 used = tracker->budget.used[resource];

    // Deny if consumption would exceed the limit
    if (limit > 0 && used + amount > limit) {
        return AK_E_BUDGET_EXCEEDED;
    }

    // Record consumption and allow
    tracker->budget.used[resource] += amount;
    return 0;
}
```

**Recording flow:**

1. **Outbound request** → `AK_SYS_INFERENCE` (or the async `AK_SYS_INFER_ISSUE` / `AK_SYS_INFER_POLL` pair)
   - The outbound-request handler issues the request on the kernel runloop.
   - When the response returns, its metadata reports token counts.
   - The kernel records `AK_RESOURCE_LLM_TOKENS_IN` (request tokens) and `AK_RESOURCE_LLM_TOKENS_OUT` (response tokens).

2. **Tool execution** → `AK_SYS_CALL`
   - Increments `AK_RESOURCE_TOOL_CALLS`.
   - Records the operation in the breakdown tracker.

3. **Combined token metric**:
   ```c
   status->tokens_used = tracker->budget.used[AK_RESOURCE_LLM_TOKENS_IN] +
                        tracker->budget.used[AK_RESOURCE_LLM_TOKENS_OUT];
   ```

Token counts come from the response metadata of the outbound request. The kernel does not estimate or synthesize token counts.

---

## Token Types and Resources

### Resource Type Mapping

```c
// From ak_types.h
typedef enum {
    AK_RESOURCE_LLM_TOKENS_IN,      // Request tokens
    AK_RESOURCE_LLM_TOKENS_OUT,     // Response tokens
    AK_RESOURCE_TOOL_CALLS,         // Tool execution count
    AK_RESOURCE_WALL_TIME_MS,       // Elapsed time
    AK_RESOURCE_HEAP_BYTES,         // Memory usage
    AK_RESOURCE_NETWORK_BYTES,      // Network I/O
    AK_RESOURCE_FILE_BYTES,         // File I/O
    AK_RESOURCE_BLOB_BYTES,         // Blob storage
    AK_RESOURCE_COUNT
} ak_resource_type_t;
```

### Combined Metrics

**Total tokens:**
```c
tokens_used = tokens_in + tokens_out
```

**Total bytes:**
```c
bytes_used = heap_bytes + network_bytes + file_bytes + blob_bytes
```

---

## Breakdown Tracking

The system tracks consumption by operation type:

```c
// In ak_budget.c
void ak_budget_record_operation(ak_budget_tracker_t *tracker,
                                const char *operation,
                                const char *detail,
                                u64 amount)
{
    if (runtime_strcmp(operation, "inference") == 0) {
        tracker->breakdown.tokens_inference += amount;
    } else if (runtime_strcmp(operation, "tool_response") == 0) {
        tracker->breakdown.tokens_tool_responses += amount;
    } else if (runtime_strcmp(operation, "tool_call") == 0) {
        // Track per-tool statistics
        int idx = ak_budget_find_tool(&tracker->breakdown, detail);
        if (idx >= 0) {
            tracker->breakdown.tool_calls_by_type[idx]++;
        }
    }
}
```

**Operation types:**

1. **inference** — tokens consumed by outbound requests
2. **tool_response** — tokens in tool results
3. **tool_call** — tool execution metadata
4. **ipc** — inter-thread messaging
5. **other** — miscellaneous operations

The breakdown is retrievable via `AK_SYS_BUDGET_BREAKDOWN`.

---

## Historical Tracking

Usage is recorded in time-series snapshots, retrievable via `AK_SYS_BUDGET_HISTORY`:

```c
// Take a snapshot every N seconds or on significant events
void ak_budget_snapshot(ak_budget_tracker_t *tracker)
{
    snapshot.timestamp_ms = now_ms;
    snapshot.tokens = used_tokens_in + used_tokens_out;
    snapshot.tool_calls = used_tool_calls;
    snapshot.wall_time_ms = now_ms - start_time;

    // Store in ring buffer (60 snapshots by default)
    tracker->snapshots[tracker->snapshot_head] = snapshot;
    tracker->snapshot_head = (tracker->snapshot_head + 1) % 60;
}
```

**Snapshot storage:**
- Ring buffer: 60 snapshots (configurable)
- Each snapshot: timestamp + resource usage
- Automatic overflow: oldest replaced by newest

---

## Burn Rate Calculation

Consumption rate is derived from historical snapshots:

```
burn_rate     = total_tokens_used / elapsed_time_seconds
remaining_time = tokens_remaining / burn_rate
```

If the burn rate is effectively zero, remaining runtime is treated as unbounded. Otherwise, remaining budget divided by the current burn rate gives an estimate of time to exhaustion.

---

## Example Token Flows

### Example 1: Single Outbound Request

```
Program issues one outbound request.

1. Request metadata reports:
   - Request tokens:  30
   - Response tokens: 10

2. Budget updated:
   - AK_RESOURCE_LLM_TOKENS_IN  += 30
   - AK_RESOURCE_LLM_TOKENS_OUT += 10
   - Total: 40 tokens
```

### Example 2: Request Plus Tool Call

```
1. Outbound request
   - Request + response: 50 tokens

2. Tool execution
   - AK_RESOURCE_TOOL_CALLS += 1
   - Tool result encoded: 5 tokens (tool_response)

3. Follow-up outbound request
   - Request + response: 60 tokens

4. Total: 115 tokens (50 + 5 + 60), 1 tool call
```

---

## Budget Enforcement

### Check Before Consumption

```c
// In ak_budget.c
int ak_budget_consume(ak_budget_tracker_t *tracker,
                     ak_resource_type_t resource,
                     u64 amount)
{
    u64 limit = tracker->budget.limits[resource];
    u64 used = tracker->budget.used[resource];

    // Deny if it would exceed the limit
    if (limit > 0 && used + amount > limit) {
        return AK_E_BUDGET_EXCEEDED;
    }

    // Allow and record consumption
    tracker->budget.used[resource] += amount;
    return 0;
}
```

A limit of `0` means the resource is unbounded. Any non-zero limit is enforced strictly: the first operation that would cross it returns `AK_E_BUDGET_EXCEEDED` and the effect is never executed.

### Critical Threshold Detection

Budget status (via `AK_SYS_BUDGET_STATUS`) exposes per-resource percentages, so a program can react before exhaustion — for example, treating any resource at or above 90% of its limit as critical.

---

## Summary

**Key points:**

- Usage is tracked per resource (request tokens, response tokens, tool calls, wall time, bytes)
- Token counts come from outbound-request response metadata; the kernel does not estimate them
- Budgets are enforced before admission — consumption never exceeds declared limits (INV-3)
- Historical snapshots enable burn-rate calculation and time-to-exhaustion estimates
- Breakdown tracking identifies high-consumption operations

**For production:**
- Set appropriate headroom in limits (e.g. plan around 80% of the hard cap)
- Monitor actual consumption via `AK_SYS_BUDGET_STATUS` and `AK_SYS_BUDGET_HISTORY`
- Use breakdown data (`AK_SYS_BUDGET_BREAKDOWN`) to find heavy operations
