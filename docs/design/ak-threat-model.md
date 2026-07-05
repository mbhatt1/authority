# Authority Kernel Threat Model

**Version:** 1.0
**Date:** 2026-01-16
**Status:** ACTIVE

---

## 1. Overview

This document defines the threat model for the Authority kernel (AK) deny-by-default security system. Authority runs a **single untrusted program** per VM; the goal is to sandbox that program so it cannot cause external effects outside its granted authority.

---

## 2. Attacker Model

### 2.1 Threat Sources

**Primary: The Untrusted Program**
- Program code that attempts to exceed its authorized capabilities
- A program compromised at runtime by crafted input
- Tools or WASM modules loaded by the program with malicious intent

**Secondary: Malicious External Input**
- Untrusted data from external responses
- Input designed to trigger unintended behavior
- Responses containing malicious payloads

### 2.2 Attacker Capabilities

We assume the attacker can:
- Execute arbitrary code as the program inside the VM
- Make arbitrary syscalls (which are mediated by AK)
- Craft malicious tool inputs/outputs
- Attempt to confuse policy matching through encoding tricks
- Attempt time-of-check to time-of-use (TOCTOU) attacks

### 2.3 Attacker Limitations

We assume the attacker CANNOT:
- Execute code in kernel space
- Modify kernel memory directly
- Bypass CPU protection mechanisms (rings, MMU)
- Access hardware directly (all I/O is virtualized)
- Modify the policy after it's loaded

---

## 3. Security Goals

### 3.1 Non-Bypass (INV-1)

**Goal:** No effectful operation can bypass Authority Kernel mediation.

**Mechanism:**
- Every Authority syscall (1024+) routes through `ak_dispatch()`
- The program is the single workload in the VM; there is no other process or device path
- No direct hardware access
- WASM host calls are capability-gated

### 3.2 Deny-by-Default (INV-DENY)

**Goal:** Any operation not explicitly allowed by policy is denied.

**Mechanism:**
- Policy matching returns DENY if no rule matches
- Missing policy = fail closed
- Empty policy sections = deny that category

### 3.3 Capability Integrity (INV-2)

**Goal:** Capabilities cannot be forged or escalated.

**Mechanism:**
- Capabilities are HMAC-protected
- Kernel controls capability issuance
- Delegation can only attenuate, never escalate
- Revocation is immediate and audited

### 3.4 Budget Enforcement (INV-3)

**Goal:** Resource consumption is bounded and tracked.

**Mechanism:**
- Per-run budget limits (tokens, calls, time, bytes, heap, spawns)
- Pre-admission budget check with overflow-safe, atomic accounting
- Exceeded budget = operation denied

### 3.5 Audit Integrity (INV-4)

**Goal:** All effectful operations are logged and logs are tamper-evident.

**Mechanism:**
- Hash-chained audit entries
- Synchronous logging for control-plane
- Bounded ring buffer for data-plane
- Audit append before response

---

## 4. Attack Vectors and Mitigations

### 4.1 Path Traversal

**Attack:** Use `..` or symbolic links to access files outside allowed paths.

**Mitigation:**
- Canonicalization before policy matching
- Normalize `.` and `..` segments
- Lexical canonicalization (symlinks not resolved in P0)

### 4.2 Encoding Confusion

**Attack:** Use different encodings to confuse policy matching (e.g., %2e%2e for ..)

**Mitigation:**
- Decode before canonicalization
- Single canonical form for all targets
- Bounded buffers prevent overflow

### 4.3 TOCTOU (Time-of-Check to Time-of-Use)

**Attack:** Change target between policy check and actual operation.

**Mitigation:**
- Canonicalize immediately on syscall entry
- Use canonical target for both check and operation
- No user-controlled strings in policy matching

### 4.4 Capability Leakage

**Attack:** Extract or forge capability tokens.

**Mitigation:**
- Capabilities are HMAC-protected
- Keys are kernel-internal only
- Capabilities are bound to run_id
- Rate limiting prevents brute force

### 4.5 Resource Exhaustion

**Attack:** Exhaust system resources to cause denial of service.

**Mitigation:**
- Budget limits on all resource types
- Bounded buffers throughout
- Rate limiting on deny logging
- Ring buffer for data-plane audit

### 4.6 Policy Bypass via Tools

**Attack:** Use tools or WASM to perform operations that bypass AK.

**Mitigation:**
- Tools cannot touch external state directly; their effects route through AK
- The WASM interpreter is integer-only and fail-closed (float declarations/ops rejected)
- WASM host calls are capability-gated
- No ambient authority in the tool sandbox

### 4.7 DNS Rebinding

**Attack:** DNS response changes between resolve and connect.

**Mitigation:**
- Separate `net.dns` and `net.connect` capabilities
- DNS resolution is an effect requiring authorization
- Policy can require IP-based connect authorization

---

## 5. Trust Boundaries

### 5.1 Trusted Components

- Kernel code (including AK)
- Policy file (validated at load time)
- Capability keys (kernel-internal)
- Audit log storage

### 5.2 Untrusted Components

- The program's code
- Tool implementations
- WASM modules
- External responses
- Input data

### 5.3 Boundary Enforcement

Every crossing from untrusted to trusted requires:
1. A request with a canonical target
2. Authorization via `ak_dispatch()` (capability + policy + budget)
3. Audit logging
4. Bounded, validated parameters

---

## 6. Assumptions

### 6.1 Hardware/Hypervisor

- CPU protection mechanisms work correctly
- MMU enforces memory protection
- Hypervisor (if any) is trusted

### 6.2 Kernel

- Kernel code is not compromised
- Kernel memory is protected from userspace

### 6.3 Policy

- Policy is created by trusted administrator
- Policy is not modified after load

### 6.4 Cryptography

- SHA-256 is collision-resistant
- HMAC-SHA256 is unforgeable

---

## 7. Out of Scope

The following are explicitly NOT protected against:

### 7.1 Side Channels

- Timing attacks on policy matching
- Cache-based side channels
- Speculative execution attacks

### 7.2 Physical Attacks

- Physical access to hardware
- Cold boot attacks
- Hardware implants

### 7.3 Policy Errors

- Overly permissive policy configuration
- Missing rules that should be present
- Incorrect pattern specifications

### 7.4 Kernel Vulnerabilities

- Bugs in kernel code itself
- Memory corruption in trusted code

---

## 8. Security Invariant Summary

| ID | Invariant | Description |
|----|-----------|-------------|
| INV-1 | No-Bypass | All effects through mediation |
| INV-2 | Capability | Every effectful op needs valid cap |
| INV-3 | Budget | Resource limits enforced |
| INV-4 | Log Commitment | All ops audited before response |
| INV-DENY | Deny-by-Default | No implicit permissions |
| INV-SINGLE | Single Gate | One authorization function |
| INV-CANONICAL | Canonicalization | Targets normalized before match |
| INV-BOUNDED | Bounded Buffers | All buffers have max sizes |

---

## 9. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-16 | Initial version |
