# Security Invariants

::: tip Formal Guarantees
These four invariants MUST hold at ALL times. They are not guidelines—they are properties that the implementation MUST preserve.
:::

Authority enforces four foundational security invariants that bound the behavior of the single untrusted program running in the VM. Any violation is a **P0 security incident**.

All four are enforced in the compiled kernel by the syscall dispatcher `ak_dispatch()` (`src/agentic/ak_syscall.c`), which every Authority syscall (numbers 1024+) passes through.

## I. The Four Invariants

### INV-1: No-Bypass Invariant

> **Statement**: The program reaches external effects only through the Authority syscalls (1024+).

#### Enforcement

The program runs as the single workload inside the unikernel, in one address space with no other processes and no direct device access. The only route to an external effect is an Authority syscall, and every such syscall is routed through `ak_dispatch()`.

| Layer | Mechanism | Blocks |
|-------|-----------|--------|
| **VM** | Hypervisor / unikernel boundary | Direct hardware and device access |
| **Address space** | Single program, no child processes | Escaping into another context |
| **Dispatch** | `ak_dispatch()` on syscalls 1024+ | Any effect not carried by a validated request |
| **Unknown syscalls** | Rejected with `-ENOSYS` | Undefined operations |

#### Verification

::: danger Required
Confinement tests MUST pass before the program is allowed to run.
:::

---

### INV-2: Capability Invariant

> **Statement**: Every effectful syscall must carry or resolve a valid, non-revoked capability whose scope subsumes the request.

#### Authorization Model

`ak_validate_capability()` (STAGE 3 of `ak_dispatch()`) resolves authorization three ways, in order, and denies if none applies:

1. **Explicit token** — a per-call capability supplied by the request (in `arg5`). It is validated in full: HMAC-SHA256, revocation check, and scope.
2. **Root context capability** — the single-tenant root context carries an admin capability. It is validated like any other (HMAC + revocation + scope), so a revoked or out-of-scope root capability is still denied.
3. **Delegated grant** — a capability previously granted into the context's delegated store. Allowed only if a still-valid grant subsumes the request.

If none of these authorizes the request, it is denied. There is no ambient authority.

**valid(C)**: HMAC-SHA256 verification passes (constant-time compare).

```c
bool verify_capability(capability_t *cap) {
    // 1. Check HMAC signature
    uint8_t expected_mac[32];
    compute_hmac_sha256(cap->data, cap->len, secret_key, expected_mac);
    if (!constant_time_eq(cap->mac, expected_mac, 32)) return false;

    // 2. Check not revoked
    if (is_revoked(cap->token_id)) return false;

    // 3. Check scope subsumes the request
    return scope_subsumes(cap, request);
}
```

**scope(C) ⊇ resource(S)**:
- Capability type matches the operation type
- Resource pattern matches the target resource
- Methods include the requested method
- TTL not expired
- Rate limit not exceeded

::: warning Strict Enforcement
Capability verification runs before the operation executes. Ambiguous cases are denied.
:::

---

### INV-3: Budget Invariant

> **Statement**: Admission control rejects any operation that would exceed declared run budgets. Budgets are hard, atomic, and overflow-safe.

#### Semantics

```
∀ operation O with cost c:
    let current = Σ(costs of committed operations in run)
    let budget  = declared_budget(run_id, resource_type)

    PRE:  current + c ≤ budget          (overflow-checked)
    POST: current' = current + c        (atomic commit)

    If PRE fails: reject with E_BUDGET_EXCEEDED (no state change)
```

Budget accounting uses overflow-safe arithmetic so a large cost cannot wrap the counter past the limit, and commits are atomic so concurrent operations cannot race past it.

#### Budget Dimensions

The compiled budget tracker accounts for the following declared limits:

| Resource | Field | Enforcement |
|----------|-------|-------------|
| Outbound request units (tokens) | `tokens` | Admission check |
| Tool calls | `calls` / `tool_calls` | Atomic counter |
| Outbound request time (ms) | `inference_ms` | Admission check |
| File I/O bytes | `file_bytes` | Quota |
| Network I/O bytes | `network_bytes` | Quota |
| Spawned children | `spawn_count` | Atomic counter |
| Heap objects | `heap_objects` | Allocator hook |
| Heap bytes | `heap_bytes` | Quota |

::: tip No Soft Limits
Budget checks are hard enforcement only. No warnings, no grace periods—operations are rejected at the limit.
:::

---

### INV-4: Log Commitment Invariant

> **Statement**: Each committed operation appends a hash-chained audit entry, made durable before the response is returned.

#### Definition

```
∀ committed operation with request Q and response R:
    ∃ log entry E such that:
        E.prev_hash = hash(log[n-1])
        E.this_hash = SHA256(E.prev_hash || canonical(E))
        E.req_hash  = SHA256(canonical(Q))
        E.res_hash  = SHA256(canonical(R))

        AND: log' = log ++ [E]
        AND: response returned to the program only AFTER the log is durable
```

`ak_dispatch()` performs the audit append in its final stage (`audit_and_return`) before returning the response, so no response is observed by the program ahead of its log entry.

#### Hash Chain Properties

```mermaid
graph LR
    Genesis[Genesis<br/>all zeros] --> E1[Entry 1<br/>hash₁]
    E1 --> E2[Entry 2<br/>hash₂]
    E2 --> E3[Entry 3<br/>hash₃]
    E3 --> Head[Head<br/>hashₙ]

    style Genesis fill:#27ae60
    style Head fill:#e74c3c
```

- **Append-only**: No deletions, no modifications
- **Tamper-evident**: Any modification breaks the chain
- **Non-repudiation**: The program cannot deny actions (req_hash commits to the request)

#### Verification Algorithm

```python
def verify_chain(log):
    """Verify hash chain from genesis to head"""
    expected_hash = GENESIS_HASH  # All zeros

    for entry in log:
        if entry.prev_hash != expected_hash:
            return False, f"Chain break at entry {entry.seq}"

        canonical = canonicalize(entry)
        computed = sha256(entry.prev_hash + canonical)
        if entry.this_hash != computed:
            return False, f"Hash mismatch at entry {entry.seq}"

        expected_hash = entry.this_hash

    return True, "Chain valid"
```

---

## II. Security Properties

### Property 1: Containment

> Under the adversary classes below, no external effect occurs except through a validated syscall.

**Adversary classes**:
- **Class I**: Arbitrary malicious inputs to the program (crafted data, poisoned inputs)
- **Class II**: A fully compromised program (attacker controls all program logic)
- **Class III**: Escape attempts from the in-kernel tool sandbox

**Argument**:

```
Given: INV-1 (no bypass) + INV-2 (capability required)
Assume: External effect E occurs outside kernel validation

Case 1: E via direct I/O
    → Impossible: single program, no device access (INV-1) ⊥

Case 2: E via syscall without authorization
    → Rejected by capability resolution (INV-2) ⊥

Case 3: E via forged capability
    → HMAC verification fails (INV-2) ⊥

∴ No such E exists.
```

---

### Property 2: Audit Completeness

> Every committed operation produces a log entry whose hash commits to all prior entries.

```
Given: INV-4 (log commitment)

For the log L = [E₀, E₁, ..., Eₙ] at any time:
    ∀ i ∈ [1,n]: Eᵢ.prev_hash = hash(Eᵢ₋₁)

    Any tampering at position k breaks the chain:
        Eₖ'.this_hash ≠ Eₖ₊₁.prev_hash  → detected

∴ The audit trail is complete and tamper-evident.
```

---

### Property 3: Budget Enforcement

> Resource consumption is bounded by declared budgets; over-budget operations are rejected before execution.

```
Given: INV-3 (budget invariant)

∀ run R with budget B:
    Sₙ = Σᵢ₌₁ⁿ Cᵢ (total committed cost after n operations)
    By INV-3: Sₙ + Cₙ₊₁ > B ⟹ operation n+1 rejected
    ∴ Sₙ ≤ B for all n
```

---

## III. The Six Guarantees

| # | Guarantee | Invariant Basis | Enforcement |
|---|-----------|-----------------|-------------|
| **G1** | Containment | INV-1, INV-2 | Confinement + Capabilities |
| **G2** | Least Privilege | INV-2 | Capability scope checking |
| **G3** | Audit | INV-4 | Hash-chained log |
| **G4** | Replay | INV-4 | Deterministic from log |
| **G5** | Bounded Cost | INV-3 | Pre-execution admission |
| **G6** | Injection Resistance | INV-2 + Taint | Capability + taint validation |

---

## IV. Verification Matrix

| Invariant | Test Category | Pass Criteria |
|-----------|---------------|---------------|
| **INV-1** | Confinement | 0 bypass paths |
| **INV-2** | Capability | 0 forgeries, 0 bypasses |
| **INV-3** | Budget | 0 overruns |
| **INV-4** | Audit | 0 undetected tampering |

::: tip Continuous Verification
- Every commit runs invariant tests
- Every change requires security review
:::

---

## V. Zero-Tolerance Policies

### Policy 1: No Security TODOs

**Rule**: Code containing `TODO` comments on security-critical paths MUST NOT be merged.

### Policy 2: No Soft Failures

**Rule**: Security checks MUST hard-fail. No "log and continue" on security violations.

### Policy 3: No Ambient Authority

**Rule**: Every privileged operation MUST resolve an explicit capability.

### Policy 4: No Exception Paths

**Rule**: Security validation MUST occur on ALL code paths, including error handlers.

### Policy 5: Fail Closed

**Rule**: On any ambiguity or error in security validation, DENY.

---

## VI. Incident Response

### If an Invariant Violation Is Detected

1. **IMMEDIATE**: Halt the program
2. **CONTAIN**: Revoke all active capabilities
3. **INVESTIGATE**: Audit log forensics
4. **REMEDIATE**: Patch with an invariant argument
5. **VERIFY**: Full test suite before restart

### Severity Classification

| Severity | Definition | Response Time |
|----------|------------|---------------|
| **P0** | Invariant violation in production | < 1 hour |
| **P1** | Invariant violation in staging | < 4 hours |
| **P2** | Test failure on invariant | < 24 hours |
| **P3** | Potential invariant weakness | < 1 week |

---

*This document is normative. All Authority kernel implementations MUST comply.*
