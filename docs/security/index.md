# Security Overview

Authority is a capability-based security unikernel built on Nanos. It runs a **single untrusted program** per VM and mediates every external effect that program can cause. This section covers:

- [Security Invariants](/security/invariants) - The four foundational guarantees
- [Threat Model](/security/threat-model) - What we protect against

## Defense in Depth

```mermaid
graph TB
    subgraph "Layer 1: VM Isolation"
        VM[Unikernel Boundary]
        HV[Hypervisor]
    end

    subgraph "Layer 2: Capability System"
        CAP[HMAC-SHA256 Tokens]
        REVOKE[Revocation]
    end

    subgraph "Layer 3: Policy Engine"
        DENY[Deny-by-Default]
        RULES[Policy Rules]
    end

    subgraph "Layer 4: Audit System"
        HASH[Hash Chain]
        FSYNC[Durable before respond]
    end

    subgraph "Layer 5: Resource Control"
        BUDGET[Budget Limits]
        RATE[Rate Limiting]
    end

    PROGRAM[Untrusted Program] --> VM
    VM --> CAP
    CAP --> DENY
    DENY --> HASH
    HASH --> BUDGET

    style VM fill:#3498db,color:#fff
    style CAP fill:#e74c3c,color:#fff
    style DENY fill:#9b59b6,color:#fff
    style HASH fill:#2ecc71,color:#fff
    style BUDGET fill:#f39c12,color:#fff
```

## The Four Invariants

```mermaid
graph TB
    subgraph INV1["INV-1: No-Bypass"]
        NB1[All effects through kernel syscalls]
        NB2[No direct hardware access]
        NB3[Single address space, single program]
    end

    subgraph INV2["INV-2: Capability Required"]
        CAP1[HMAC-SHA256 verification]
        CAP2[Scope matching]
        CAP3[Revocation checking]
    end

    subgraph INV3["INV-3: Budget Enforced"]
        BUD1[Pre-admission check]
        BUD2[Atomic decrement]
        BUD3[Hard limits only]
    end

    subgraph INV4["INV-4: Audit Committed"]
        AUD1[Hash chain]
        AUD2[Durable before respond]
        AUD3[Tamper detection]
    end

    INV1 --> G1[Containment]
    INV2 --> G1
    INV2 --> G2[Least Privilege]
    INV3 --> G3[Bounded Cost]
    INV4 --> G4[Complete Audit]

    style INV1 fill:#e74c3c,color:#fff
    style INV2 fill:#3498db,color:#fff
    style INV3 fill:#9b59b6,color:#fff
    style INV4 fill:#2ecc71,color:#fff
```

## Security Philosophy

### Zero-Trust Model

```mermaid
flowchart TD
    REQ[Incoming Request]

    REQ --> Q1{Has Capability?}
    Q1 -->|No| DENY1[DENY]
    Q1 -->|Yes| Q2{Cap Valid?}

    Q2 -->|No| DENY2[DENY]
    Q2 -->|Yes| Q3{Policy Allows?}

    Q3 -->|No| DENY3[DENY]
    Q3 -->|Yes| Q4{Budget OK?}

    Q4 -->|No| DENY4[DENY]
    Q4 -->|Yes| Q5{Taint OK?}

    Q5 -->|No| DENY5[DENY]
    Q5 -->|Yes| ALLOW[ALLOW]

    DENY1 --> LOG1[Log Denial]
    DENY2 --> LOG2[Log Denial]
    DENY3 --> LOG3[Log Denial]
    DENY4 --> LOG4[Log Denial]
    DENY5 --> LOG5[Log Denial]
    ALLOW --> LOG6[Log & Execute]

    style DENY1 fill:#c0392b,color:#fff
    style DENY2 fill:#c0392b,color:#fff
    style DENY3 fill:#c0392b,color:#fff
    style DENY4 fill:#c0392b,color:#fff
    style DENY5 fill:#c0392b,color:#fff
    style ALLOW fill:#27ae60,color:#fff
```

### Fail-Closed Principle

```mermaid
graph LR
    subgraph "Traditional (Fail-Open)"
        T_REQ[Request] --> T_CHECK{Check}
        T_CHECK -->|Pass| T_ALLOW[Allow]
        T_CHECK -->|Fail| T_ALLOW2[Allow Anyway]
        T_CHECK -->|Error| T_ALLOW3[Allow Anyway]
    end

    subgraph "Authority (Fail-Closed)"
        A_REQ[Request] --> A_CHECK{Check}
        A_CHECK -->|Pass| A_ALLOW[Allow]
        A_CHECK -->|Fail| A_DENY[DENY]
        A_CHECK -->|Error| A_DENY2[DENY]
        A_CHECK -->|Unknown| A_DENY3[DENY]
    end

    style T_ALLOW2 fill:#c0392b,color:#fff
    style T_ALLOW3 fill:#c0392b,color:#fff
    style A_DENY fill:#27ae60,color:#fff
    style A_DENY2 fill:#27ae60,color:#fff
    style A_DENY3 fill:#27ae60,color:#fff
```

## Six Security Guarantees

```mermaid
graph TB
    subgraph "Guarantees"
        G1[G1: Containment<br/>No escape from sandbox]
        G2[G2: Least Privilege<br/>Minimal permissions]
        G3[G3: Complete Audit<br/>Every action logged]
        G4[G4: Replay<br/>Reproducible execution]
        G5[G5: Bounded Cost<br/>Resource limits]
        G6[G6: Injection Resistance<br/>Taint tracking]
    end

    subgraph "Invariant Basis"
        INV1[INV-1]
        INV2[INV-2]
        INV3[INV-3]
        INV4[INV-4]
    end

    INV1 --> G1
    INV2 --> G1
    INV2 --> G2
    INV4 --> G3
    INV4 --> G4
    INV3 --> G5
    INV2 --> G6

    style G1 fill:#e74c3c,color:#fff
    style G2 fill:#3498db,color:#fff
    style G3 fill:#2ecc71,color:#fff
    style G4 fill:#9b59b6,color:#fff
    style G5 fill:#f39c12,color:#fff
    style G6 fill:#1abc9c,color:#fff
```

## Capability Verification Flow

```mermaid
sequenceDiagram
    participant Program
    participant Gate as Syscall Dispatch
    participant HMAC as HMAC Verifier
    participant Key as Keyring
    participant Rev as Revocation Map
    participant Scope as Scope Matcher

    Program->>Gate: Request + Capability
    Gate->>HMAC: Verify MAC

    HMAC->>Key: Get signing key
    Key-->>HMAC: key[kid]

    HMAC->>HMAC: Compute expected MAC
    HMAC->>HMAC: Constant-time compare

    alt MAC Invalid
        HMAC-->>Program: E_CAP_INVALID
    end

    Gate->>Rev: Check revocation
    Rev->>Rev: Lookup token ID

    alt Token Revoked
        Rev-->>Program: E_CAP_REVOKED
    end

    Gate->>Scope: Check scope
    Scope->>Scope: Match resource pattern
    Scope->>Scope: Check methods
    Scope->>Scope: Verify TTL
    Scope->>Scope: Check rate limit

    alt Scope Mismatch
        Scope-->>Program: E_CAP_SCOPE
    end

    Gate-->>Program: Capability Valid
```

## Audit Chain Verification

```mermaid
graph LR
    subgraph "Verification Process"
        START[Start at Genesis]
        E1[Entry 1]
        E2[Entry 2]
        E3[Entry 3]
        EN[Entry N]
        VALID[Chain Valid]
        TAMPER[Tampering Detected!]
    end

    START --> E1
    E1 -->|prev_hash matches| E2
    E2 -->|prev_hash matches| E3
    E3 -->|...| EN
    EN --> VALID

    E1 -->|prev_hash mismatch| TAMPER
    E2 -->|prev_hash mismatch| TAMPER
    E3 -->|prev_hash mismatch| TAMPER

    style VALID fill:#27ae60,color:#fff
    style TAMPER fill:#c0392b,color:#fff
```

## Incident Response Flow

```mermaid
stateDiagram-v2
    [*] --> Detected: Invariant Violation

    Detected --> Halt: IMMEDIATE
    Halt --> Revoke: Halt the program
    Revoke --> Investigate: Revoke capabilities

    Investigate --> Forensics: Audit log analysis
    Forensics --> RootCause: Identify cause

    RootCause --> Patch: Develop fix
    Patch --> Proof: Prove invariant preserved

    Proof --> Test: Full test suite
    Test --> Deploy: All tests pass

    Deploy --> [*]: Resume operations

    note right of Halt: P0: < 1 hour
    note right of Investigate: Preserve evidence
    note right of Proof: Invariant argument required
```

## Security Testing Matrix

```mermaid
graph TB
    subgraph "INV-1 Tests"
        T1_1[Effect without syscall attempt]
        T1_2[Unknown/raw syscall blocked]
        T1_3[Direct hardware access blocked]
    end

    subgraph "INV-2 Tests"
        T2_1[Random HMAC forgery]
        T2_2[Expired capability]
        T2_3[Scope violation]
        T2_4[Revoked token use]
    end

    subgraph "INV-3 Tests"
        T3_1[Budget exhaustion]
        T3_2[Concurrent budget race]
        T3_3[Overflow / wraparound]
    end

    subgraph "INV-4 Tests"
        T4_1[Log bit flip]
        T4_2[Entry deletion]
        T4_3[Response before durable log]
    end

    T1_1 --> PASS1[Must FAIL]
    T1_2 --> PASS2[Must FAIL]
    T1_3 --> PASS3[Must FAIL]
    T2_1 --> PASS4[Must REJECT]
    T2_2 --> PASS5[Must REJECT]
    T2_3 --> PASS6[Must REJECT]
    T2_4 --> PASS7[Must REJECT]
    T3_1 --> PASS8[Must BLOCK]
    T3_2 --> PASS9[Must BLOCK]
    T3_3 --> PASS10[Must BLOCK]
    T4_1 --> PASS11[Must DETECT]
    T4_2 --> PASS12[Must DETECT]
    T4_3 --> PASS13[Must NEVER happen]

    style PASS1 fill:#27ae60,color:#fff
    style PASS4 fill:#27ae60,color:#fff
    style PASS8 fill:#27ae60,color:#fff
    style PASS11 fill:#27ae60,color:#fff
```

## Zero-Tolerance Policies

| Policy | Description |
|--------|-------------|
| No Security TODOs | Code with TODO on security paths MUST NOT be merged |
| No Soft Failures | Security checks MUST hard-fail |
| No Ambient Authority | Every privileged operation requires capability |
| No Exception Paths | Security validation on ALL code paths |
| Fail Closed | On ANY ambiguity, DENY |
