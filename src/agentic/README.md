# Authority Kernel

The capability-based security subsystem of Authority (a Nanos fork).

## Overview

The Authority Kernel (AK) enforces kernel-level security on the single untrusted
program running in the VM. It implements a capability-based access-control model
with a tamper-evident audit log, so the program operates within strictly defined
boundaries and every operation is provable after the fact.

Authority = Nanos unikernel + Authority Kernel subsystem.

## Security Invariants

The Authority Kernel enforces four invariants inside the syscall dispatch path
(`ak_syscall_handler` → `ak_dispatch`), before any effect executes:

### INV-1: No-Bypass
> The program reaches external effects only through the Authority syscalls (1024+).

VM isolation plus syscall gating ensure no direct hardware or network access
bypasses the kernel.

### INV-2: Capability
> Every effectful syscall must be authorized by a valid, non-revoked capability whose scope subsumes the request.

Authorization is a per-call token (passed in the syscall's `arg5`), a delegated
grant held in the context, or the root context's admin capability.

```c
s64 ak_capability_validate(ak_capability_t *cap, ak_cap_type_t required_type,
                           const char *resource, const char *method, u8 *run_id);
```

### INV-3: Budget
> Admission control rejects operations that would exceed a declared budget.

Budgets are hard, atomic, and overflow-safe.

```c
s64 ak_budget_reserve(ak_budget_tracker_t *tracker,
                      ak_resource_type_t type, u64 amount);
```

### INV-4: Log Commitment
> Each committed operation appends a hash-chained audit entry, made durable before the response is returned.

```c
s64 ak_audit_append(u8 *pid, u8 *run_id, u16 op,
                    u8 *req_hash, u8 *res_hash, u8 *policy_hash);
```

## Enforcement Pipeline

`ak_dispatch()` runs every request through six stages before the effect
executes: (1) request validation, (2) anti-replay, (3) capability check (INV-2),
(4) policy + budget admission (INV-3), (5) execute the handler, (6) append to the
hash-chained audit log and make it durable (INV-4).

## Syscall Interface

| Number | Name | Description |
|--------|------|-------------|
| 1024 | READ | Read object from the typed heap |
| 1025 | ALLOC | Allocate a heap object |
| 1026 | WRITE | Update an object (RFC 6902 JSON Patch, CAS) |
| 1027 | DELETE | Soft-delete an object |
| 1028 | QUERY | Query the audit log |
| 1029 | BATCH | Atomic batch of operations |
| 1030 | COMMIT | Checkpoint the audit log |
| 1031 | CALL | Execute a tool in the WASM sandbox |
| 1032 | SPAWN | Create a child context |
| 1033 | SEND | Send a message |
| 1034 | RECV | Receive messages |
| 1035 | RESPOND | Return a response (DLP applied) |
| 1036 | ASSERT | Record an assertion |
| 1037 | INFERENCE | Invoke an outbound request handler |
| 1038-1040 | BUDGET_STATUS / HISTORY / BREAKDOWN | Budget introspection |
| 1041 | INFER_ISSUE | Issue an outbound HTTP(S) request (non-blocking) |
| 1042 | INFER_POLL | Poll for an issued request's result |

External effects (outbound HTTP, tool calls) use an async issue/poll model: the
kernel enforces the request synchronously on issue, performs the I/O on the
runloop, and the program polls for the result.

## Components

- **Capability system** (`ak_capability.c/.h`) — HMAC-SHA256 tokens, scope
  matching, monotonic key rotation, constant-time verification, revocation.
- **Typed heap** (`ak_heap.c/.h`) — versioned objects with CAS, RFC 6902 JSON
  Patch, transactions for BATCH, taint tracking.
- **Audit log** (`ak_audit.c/.h`) — hash-chained entries, file-header
  persistence, durable-before-response, crash recovery.
- **Policy engine** (`ak_policy.c/.h`) — JSON policy: deny-by-default budgets,
  tool allow/deny, domain rules, taint flow.
- **Budget control** (`ak_budget.c/.h`) — hard, atomic, overflow-safe limits.
- **WASM sandbox** (`ak_wasm.c`, `ak_wasm_interp.c`) — an integer-only bytecode
  interpreter; the kernel is built `-mno-sse`, so float ops are rejected
  fail-closed.
- **Outbound transport** (`ak_transport.c`; klib `ak_https.c`) — async HTTP(S)
  over the network stack.
- **Syscall dispatch** (`ak_syscall.c`) — the enforcement pipeline.

## Building

The Authority sources are compiled into `kernel.elf` by the platform Makefiles
(see `platform/pc/Makefile`, `platform/virt/Makefile`,
`platform/riscv-virt/Makefile`, guarded by `-DCONFIG_AK_ENABLED`). Build the
kernel from the repository root:

```bash
make PLATFORM=pc CROSS_COMPILE=x86_64-elf- kernel
```

`libak` (the userspace helper library and Python SDK glue) is built with the
module Makefile:

```bash
cd src/agentic && make libak
```

## Policy Format (JSON)

```json
{
  "version": "1.0",
  "budgets": { "tokens": 100000, "calls": 50, "inference_ms": 60000, "file_bytes": 10485760 },
  "tools":   { "allow": ["file_read", "http_get"], "deny": ["shell_exec"] },
  "domains": { "allow": ["*.example.com"], "deny": ["*.internal"] },
  "taint":   { "sources": ["user_input"], "sinks": ["shell_exec"], "sanitizers": ["html_escape"] }
}
```

## Security Notes

- **Fail-closed**: unknown capability, missing policy, or taint violation → denied.
- **Timing resistance**: capability MAC comparison is constant-time.
- **Revocation**: keyed on the full 16-byte token id, checked on every use.
- **Audit integrity**: `hash[n] = SHA256(hash[n-1] || entry[n])`; any change to a
  past entry invalidates every subsequent hash.

## License

Apache-2.0
