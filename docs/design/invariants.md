# Security Invariants

The Authority kernel enforces **four security invariants**. These are not guidelines or best practices - they are cryptographic and architectural guarantees, all enforced in `ak_dispatch()` (`src/agentic/ak_syscall.c`).

---

## INV-1: No-Bypass Invariant

**Statement:** The program reaches external effects only through the Authority syscalls (1024+).

```
For all IO operations O by the program:
    O is external => O passes through ak_dispatch()
```

### Enforcement

- The program is the single workload in the VM (one address space, no other processes)
- Unikernel architecture eliminates bypass vectors
- No raw device access
- Every Authority syscall is routed through `ak_dispatch()`

### Verification

- Static analysis: No effectful paths that skip mediation
- Runtime: Mode=HARD denies raw effectful syscalls

---

## INV-2: Capability Invariant

**Statement:** Every effectful syscall requires a valid, non-revoked capability whose scope subsumes the request.

```
For all syscalls S where effect(S) = true:
    exists capability C such that:
        valid(C) AND NOT revoked(C) AND scope(C) contains resource(S)
```

### Validation Requirements

- HMAC-SHA256 signature verification (constant-time)
- Token ID not in revocation set
- Resource pattern matches request target
- TTL not expired
- Rate limit not exceeded
- Run ID matches current execution

### Error Codes

- `AK_E_CAP_INVALID`: Signature verification failed
- `AK_E_CAP_EXPIRED`: TTL exceeded
- `AK_E_CAP_REVOKED`: Token in revocation set
- `AK_E_CAP_SCOPE`: Resource/method mismatch
- `AK_E_CAP_RUN_ID`: Run ID mismatch
- `AK_E_CAP_RATE`: Rate limit exceeded

---

## INV-3: Budget Invariant

**Statement:** Resource consumption never exceeds declared budgets.

```
For all operations O with cost c:
    let current = sum of completed costs
    let budget = declared limit

    PRE:  current + c <= budget
    POST: current' = current + c

    If PRE fails: reject with E_BUDGET_EXCEEDED
```

### Budget Dimensions

- Outbound request units (tokens)
- Tool calls
- Outbound request time (ms)
- Heap objects / heap bytes
- File I/O (bytes)
- Network I/O (bytes)
- Spawned children

Budget accounting is hard, atomic, and overflow-safe.

### Admission Control

Every expensive operation requires a PRE-ADMISSION budget check:

```c
s64 ak_budget_reserve(ak_budget_tracker_t *tracker,
                      ak_resource_type_t type,
                      u64 amount);
```

If PRE fails, the operation is denied before any state change.

---

## INV-4: Log Commitment Invariant

**Statement:** Every state transition appends a hash-chained audit entry.

```
For all state transitions from S to S':
    exists log entry E such that:
        E.prev_hash = hash(log[n-1])
        E.this_hash = SHA256(E.prev_hash || canonical(E))
        log' = log ++ [E]
        Response sent only after fsync(log)
```

### Hash Chain Structure

```
Entry[0]: prev_hash = zeros, this_hash = SHA256(zeros || E0)
Entry[n]: prev_hash = Entry[n-1].this_hash
          this_hash = SHA256(prev_hash || canonical(En))
```

### Properties

- **Append-only**: No deletions, no modifications
- **Tamper-evident**: Broken chain detected immediately
- **Non-repudiation**: Request hash proves the program's action

### Verification

```c
boolean ak_audit_verify(u64 from_seq, u64 to_seq);
```

Walks the chain from Entry[from_seq] to Entry[to_seq], computing hashes and verifying the chain.

---

## Audit Log Entry Format

```c
struct ak_audit_entry {
    u64 seq;                  // Monotonic sequence number
    u8 pid[16];               // Program/context ID
    u8 run_id[16];            // Execution ID
    u16 op;                   // Operation code
    u64 timestamp_ns;         // Nanosecond timestamp
    u8 req_hash[32];          // SHA-256(request)
    u8 res_hash[32];          // SHA-256(response)
    u8 prev_hash[32];         // Previous entry hash
    u8 this_hash[32];         // SHA-256(prev_hash || entry)
};
```

---

## Anchoring (Optional)

For efficient verification over large ranges, periodic anchors are optional:

```c
struct ak_audit_anchor {
    u64 seq;                  // Anchor sequence
    u8 merkle_root[32];       // Merkle root of entries
    u64 timestamp_ns;
};
```

An anchor at sequence N certifies all entries from the previous anchor to N.

---

## Invariant Enforcement Points

| Invariant | Enforcement Point | Function |
|-----------|-------------------|----------|
| INV-1 | Syscall dispatcher | `ak_dispatch()` |
| INV-2 | Capability stage of dispatch | `ak_validate_capability()` |
| INV-3 | Admission control | `ak_budget_reserve()` |
| INV-4 | Audit append | `ak_audit_append()` |

---

## P0/P1/P2 Roadmap

| Phase | INV-1 | INV-2 | INV-3 | INV-4 |
|-------|-------|-------|-------|-------|
| **P0** | Core | Policy-gated | Token budgets | Ring buffer |
| **P1** | Complete | Revocation | All budgets | Persistent log |
| **P2** | Hardened | Delegation | Fine-grained | External anchoring |

---

## Testing the Invariants

### Unit Tests

- Capability verification with invalid inputs
- Hash chain verification
- Budget admission tests
- Syscall routing verification

### Integration Tests

- Deny-by-default with missing policy
- Allow operations with valid policy
- Budget exhaustion prevents operation
- Audit log integrity across program restarts

### Security Tests

- Capability forgery detection
- Policy bypass attempts
- Audit log tampering detection
- TOCTOU attacks on resource validation

---

## Violation Response

If an invariant violation is detected:

1. **Halt the program** - Stop processing immediately
2. **Revoke all active capabilities** - Prevent further operations
3. **Preserve audit log** - Keep log for forensics
4. **Patch and verify** - Fix the issue and test thoroughly before restart

Severity levels:

| Level | Definition | Response |
|-------|------------|----------|
| P0 | Invariant violation in production | Immediate |
| P1 | Invariant violation in staging | 4 hours |
| P2 | Test failure on invariant | 24 hours |

---

## References

- [Authority Kernel Design](./ak-design.md)
- [Base Contract](./ak-base-contract.md)
- [Threat Model](./ak-threat-model.md)
