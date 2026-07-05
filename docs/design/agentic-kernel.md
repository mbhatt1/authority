# The Authority Kernel

**The Security Layer Powering the Authority Unikernel**

## Overview

The Authority kernel (AK) is the security subsystem of **Authority**, a capability-based security unikernel built on Nanos. Authority runs a **single untrusted program** per VM. The Authority kernel implements a capability-based security model with comprehensive audit logging, ensuring the program operates within strictly defined boundaries while maintaining complete auditability.

Authority = Nanos unikernel + Authority kernel subsystem

## Security Invariants

The Authority kernel enforces four fundamental security invariants, all in the syscall dispatcher `ak_dispatch()` (`src/agentic/ak_syscall.c`):

### INV-1: No-Bypass Invariant
> The program reaches external effects only through the Authority syscalls (1024+).

The program is the single workload in the VM. The unikernel boundary ensures no direct hardware or network access bypasses the kernel, and every Authority syscall is routed through `ak_dispatch()`.

### INV-2: Capability Invariant
> Every effectful syscall must carry or resolve a valid, non-revoked capability whose scope subsumes the request.

```c
s64 ak_capability_validate(
    ak_capability_t *cap,
    ak_cap_type_t required_type,
    const char *resource,
    const char *method,
    u8 *run_id
);
```

Authorization resolves from an explicit per-call token, the root context's admin capability, or a delegated grant — otherwise the request is denied.

### INV-3: Budget Invariant
> The sum of in-flight and committed costs never exceeds budget. Budgets are hard, atomic, and overflow-safe.

Admission control prevents resource exhaustion:
```c
s64 ak_budget_reserve(ak_budget_tracker_t *tracker,
                      ak_resource_type_t type, u64 amount);
```

### INV-4: Log Commitment Invariant
> Each committed operation appends a hash-chained audit entry, made durable before the response is returned.

Tamper-evident audit log with a hash chain:
```c
s64 ak_audit_append(u8 *pid, u8 *run_id, u16 op,
                    u8 *req_hash, u8 *res_hash, u8 *policy_hash);
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Untrusted Program                        │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                   Program Code                       │   │
│  │  • Outbound requests   • Tool execution             │   │
│  │  • State management    • Messaging                  │   │
│  └────────────────────────┬────────────────────────────┘   │
│                           │ Authority syscalls (1024-1042)  │
├───────────────────────────┼─────────────────────────────────┤
│                           ▼                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Authority Kernel                        │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
│  │  │Capability│ │  Audit   │ │  Policy  │            │   │
│  │  │  System  │ │   Log    │ │  Engine  │            │   │
│  │  └──────────┘ └──────────┘ └──────────┘            │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐            │   │
│  │  │  Typed   │ │   IPC    │ │ Syscall  │            │   │
│  │  │   Heap   │ │Transport │ │ Dispatch │            │   │
│  │  └──────────┘ └──────────┘ └──────────┘            │   │
│  └─────────────────────────────────────────────────────┘   │
│                    Nanos Kernel                             │
└─────────────────────────────────────────────────────────────┘
```

## Syscall Interface

| Number | Name | Description |
|--------|------|-------------|
| 1024 | READ | Read object from typed heap |
| 1025 | ALLOC | Allocate new heap object |
| 1026 | WRITE | Update object with JSON Patch |
| 1027 | DELETE | Soft-delete object |
| 1028 | QUERY | Query objects by predicate |
| 1029 | BATCH | Atomic batch operations |
| 1030 | COMMIT | Checkpoint audit log |
| 1031 | CALL | Invoke tool in WASM sandbox |
| 1032 | SPAWN | Create child context |
| 1033 | SEND | Send message |
| 1034 | RECV | Receive messages |
| 1035 | RESPOND | Send response to orchestrator |
| 1036 | ASSERT | Record assertion |
| 1037 | INFERENCE | Issue an outbound external request |
| 1038 | BUDGET_STATUS | Current budget status |
| 1039 | BUDGET_HISTORY | Historical budget snapshots |
| 1040 | BUDGET_BREAKDOWN | Detailed budget breakdown |
| 1041 | INFER_ISSUE | Issue an async outbound request |
| 1042 | INFER_POLL | Poll a previously issued request |

The `INFERENCE` / `INFER_ISSUE` / `INFER_POLL` calls are the generic **outbound external-request** mechanism, gated by a capability. External I/O is asynchronous: `INFER_ISSUE` enforces capability, policy, and budget synchronously inside `ak_dispatch()`, then issues the request and returns a handle; `INFER_POLL` reaps the result without blocking, so the runloop drives the transport while the program polls.

## Components

### Capability System (`ak_capability.h/c`)
- HMAC-SHA256 signed tokens
- Scope-based access control
- Key rotation with grace period
- Constant-time verification
- Immediate revocation

### Typed Heap (`ak_heap.h/c`)
- Versioned objects with CAS semantics
- JSON Schema validation
- RFC 6902 JSON Patch support
- Transaction support for BATCH
- Taint tracking

### Audit Log (`ak_audit.h/c`)
- Hash-chained entries
- Crash recovery
- External anchoring
- Replay bundle support

### Policy Engine (`ak_policy.h/c`)
- JSON policy format
- Budget enforcement
- Tool allow/deny lists
- Domain restrictions
- Taint flow rules

### IPC Transport (`ak_ipc.h/c`)
- Framed protocol with CRC-32C
- Sequence-based replay protection
- JSON serialization

### Syscall Dispatcher (`ak_syscall.h/c`)
- Central enforcement point (`ak_dispatch()`)
- Staged validation pipeline
- Per-operation handlers

## Configuration

### Policy Format (JSON)

The compiled policy engine (`ak_policy.c`) parses JSON:

```json
{
  "version": "1.0",
  "budgets": {
    "tokens": 100000,
    "calls": 50,
    "inference_ms": 60000,
    "file_bytes": 10485760
  },
  "tools": {
    "allow": ["file_read", "http_get"],
    "deny": ["shell_exec"]
  },
  "domains": {
    "allow": ["*.github.com"],
    "deny": ["*.internal"]
  }
}
```

## Security Considerations

### Fail-Closed Design
All validation functions default to denial:
- Unknown capability → denied
- Missing policy → denied
- Taint violation → denied

### Timing Attack Resistance
Capability verification uses a constant-time comparison:
```c
static boolean constant_time_compare(u8 *a, u8 *b, u64 len)
{
    u8 result = 0;
    for (u64 i = 0; i < len; i++)
        result |= a[i] ^ b[i];
    return result == 0;
}
```

### Capability Revocation
Revocation is immediate and persistent:
- Stored in the revocation map
- Survives kernel restart
- Logged to the audit trail

### Audit Log Integrity
The hash chain prevents undetected tampering:
```
hash[n] = SHA256(hash[n-1] || entry[n])
```

### Integer-Only Tool Sandbox
The kernel is compiled `-mno-sse` with no hardware float and no soft-float runtime. The WASM tool interpreter is therefore strictly integer-only: it fail-closed rejects any module that declares or uses floating-point types or operations.

## Testing

### Unit Tests
```c
void test_capability_verify(void);
void test_heap_cas_semantics(void);
void test_audit_chain_integrity(void);
void test_policy_evaluation(void);
```

### Integration Tests
```c
void test_full_syscall_pipeline(void);
void test_batch_atomicity(void);
void test_revocation_propagation(void);
```

### Security Tests
```c
void test_replay_detection(void);
void test_capability_forgery(void);
void test_taint_flow_blocking(void);
void test_budget_exhaustion(void);
```

## License

Apache-2.0

## References

- [Authority Documentation](/)
- [Authority Kernel Design](./ak-design.md)
- [Security Invariants](./invariants.md)
- [Threat Model](./ak-threat-model.md)
- [Nanos Unikernel](https://github.com/nanovms/nanos)
- [RFC 6902: JSON Patch](https://tools.ietf.org/html/rfc6902)
- [JSON Schema](https://json-schema.org/)
