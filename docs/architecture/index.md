# Architecture Overview

Authority is a **capability-based security unikernel** — a fork of [Nanos](https://github.com/mbhatt1/nanos) that adds the **Authority Kernel**, a deny-by-default enforcement layer. Each VM runs a **single untrusted program** and the Authority Kernel enforces kernel-level security on every effect it attempts.

## System Stack

```mermaid
graph TB
    subgraph "User Space"
        APP[Untrusted Program]
        LIB[Authority SDK / libc]
    end

    subgraph "Authority Kernel Layer"
        ENTRY["ak_syscall_handler()"]
        DISPATCH["ak_dispatch()"]

        subgraph "Dispatch Pipeline (fixed order)"
            direction LR
            VAL[1 Validate] --> SEQ[2 Anti-Replay]
            SEQ --> CAP[3 Capability]
            CAP --> POLICY[4 Policy + Budget]
            POLICY --> EXEC[5 Execute]
            EXEC --> AUDIT[6 Audit]
        end

        subgraph "Operation Handlers"
            STATE_H[Heap / State]
            TOOL_H[Tool - WASM]
            IPC_H[IPC]
            OUT_H[Outbound Request]
        end
    end

    subgraph "Nanos Kernel"
        VFS[Virtual Filesystem]
        NETSTACK[Network Stack]
        SCHED[Scheduler]
        MEM[Memory Manager]
        VIRTIO[Virtio Drivers]
    end

    subgraph "Hypervisor"
        KVM[KVM/HVF/QEMU]
    end

    APP --> LIB
    LIB --> ENTRY
    ENTRY --> DISPATCH
    DISPATCH --> VAL

    EXEC --> STATE_H
    EXEC --> TOOL_H
    EXEC --> IPC_H
    EXEC --> OUT_H

    AUDIT --> VFS
    OUT_H --> NETSTACK
    VFS --> VIRTIO
    NETSTACK --> VIRTIO
    SCHED --> VIRTIO
    MEM --> VIRTIO
    VIRTIO --> KVM

    style DISPATCH fill:#e74c3c,color:#fff
    style AUDIT fill:#2ecc71,color:#fff
```

## Core Principle: One Dispatch Path

Every Authority syscall (numbers 1024+) is forwarded by the Nanos syscall layer to `ak_syscall_handler()`, which routes it through `ak_dispatch()`. The `ak_handle_*` operation handlers are never invoked directly — the dispatcher's pipeline runs first, every time.

```mermaid
flowchart LR
    subgraph "Entry"
        AK_API["AK Syscalls (1024+)"]
    end

    HANDLER["ak_syscall_handler()"]
    DISPATCH[["ak_dispatch()"]]

    subgraph "Outcomes"
        ALLOW[Execute & Log]
        DENY[Deny & Log]
    end

    AK_API --> HANDLER
    HANDLER --> DISPATCH

    DISPATCH --> ALLOW
    DISPATCH --> DENY

    style DISPATCH fill:#e74c3c,color:#fff
    style DENY fill:#c0392b,color:#fff
    style ALLOW fill:#27ae60,color:#fff
```

- Default is **deny-by-default**: if the pipeline cannot prove an allow, the effect is denied.
- Tool execution, IPC, and outbound requests are ordinary handlers gated by the same pipeline.
- A legacy `ak_effects.c` layer exists in the tree but is **not compiled** into the kernel; the compiled path is the dispatch pipeline described here.

## Request Processing Pipeline

`ak_dispatch()` runs six stages in a fixed order; any failure short-circuits to audit and returns an error before the effect executes.

```mermaid
stateDiagram-v2
    [*] --> Validate: Syscall arrives (1024+)

    Validate --> Replay: pid/run_id/op OK
    Replay --> Capability: Not a replay
    Capability --> Policy: Capability subsumes request
    Policy --> Execute: Policy allows + budget OK
    Execute --> Audit: Effect performed
    Audit --> Respond: Log entry durable (fsync)
    Respond --> [*]: Response returned

    Validate --> Reject: Bad pid/run_id/op
    Replay --> Reject: Duplicate seq
    Capability --> Reject: Missing/invalid/out-of-scope cap
    Policy --> Reject: Policy deny or budget exceeded
    Execute --> Reject: Execution error

    Reject --> Audit: Log denial
    note right of Capability: HMAC + scope + TTL + revocation
    note right of Audit: Must be durable before respond
```

## Key Components

### Component Relationships

```mermaid
graph TB
    subgraph "Policy System"
        POLICY_FILE[Policy File<br/>JSON/TOML]
        POLICY_LOADER[Policy Loader]
        POLICY_EVAL[ak_policy_evaluate]
        PATTERN[Pattern Matcher]
    end

    subgraph "Capability System"
        CAP_TOKEN[Capability Token]
        HMAC[HMAC-SHA256]
        KEYRING[Per-Boot Signing Key]
        REVOKE[Revocation Set]
    end

    subgraph "Audit System"
        LOG_ENTRY[Log Entry]
        HASH_CHAIN[Hash Chain]
        SEGMENT[Segment Log]
        FSYNC[Durable fsync]
    end

    subgraph "Budget System"
        BUDGET_DEF[Budget Definition]
        USAGE[Usage Tracker]
        ADMIT[Admission Control]
    end

    POLICY_FILE --> POLICY_LOADER
    POLICY_LOADER --> POLICY_EVAL
    POLICY_EVAL --> PATTERN

    CAP_TOKEN --> HMAC
    HMAC --> KEYRING
    CAP_TOKEN --> REVOKE

    LOG_ENTRY --> HASH_CHAIN
    HASH_CHAIN --> SEGMENT
    SEGMENT --> FSYNC

    BUDGET_DEF --> ADMIT
    USAGE --> ADMIT

    style HMAC fill:#e74c3c,color:#fff
    style HASH_CHAIN fill:#2ecc71,color:#fff
    style ADMIT fill:#9b59b6,color:#fff
```

### Capability Token Structure

Capabilities are HMAC-signed tokens. The signing key is generated per boot from the Nanos CSPRNG and never leaves the kernel.

```mermaid
graph LR
    subgraph "Capability Token"
        TYPE[Type<br/>Net/FS/Tool/Secrets/...]
        RESOURCE[Resource Pattern<br/>*.example.com]
        METHODS[Methods<br/>GET, POST]
        TTL[TTL]
        RATE[Rate Limit]
        RUN_ID[Run ID]
        MAC[HMAC-SHA256<br/>32 bytes]
    end

    KEY[Per-Boot Signing Key] --> MAC
    TYPE --> MAC
    RESOURCE --> MAC
    METHODS --> MAC
    TTL --> MAC
    RATE --> MAC
    RUN_ID --> MAC

    style MAC fill:#e74c3c,color:#fff
```

### Audit Log Hash Chain

Every dispatched request — allowed or denied — appends an entry, and the response is not returned until the entry is durable.

```mermaid
graph LR
    GENESIS[Genesis<br/>0x00...00]

    E1[Entry 1]
    E2[Entry 2]
    E3[Entry 3]
    EN[Entry N]

    GENESIS -->|prev_hash| E1
    E1 -->|prev_hash| E2
    E2 -->|prev_hash| E3
    E3 -->|...| EN

    subgraph "Entry Structure"
        SEQ[seq: N]
        TS[timestamp]
        OP[operation]
        REQ_H[req_hash]
        RES_H[res_hash]
        PREV[prev_hash]
        THIS[this_hash]
    end

    style GENESIS fill:#95a5a6,color:#fff
    style THIS fill:#2ecc71,color:#fff
```

## Tool Execution and External I/O

- **Tools** invoked via `AK_SYS_CALL` run in an **integer-only WASM subset interpreter** (`ak_wasm_interp.c`). The kernel is built `-mno-sse` with no floating point, so float value types and opcodes are rejected fail-closed. This is a bounded integer-only interpreter, not a full WASM runtime.
- **Outbound network requests** use an async **issue/poll** model (`AK_SYS_INFER_ISSUE` / `AK_SYS_INFER_POLL`): the kernel enforces the pipeline on issue, the Nanos runloop drives the HTTP(S) request, and the program polls for the result. The kernel does not block a thread on external I/O.

## Platform Support

```mermaid
graph TB
    AUTH[Authority]

    subgraph "x86_64"
        X86_KVM[Linux + KVM]
        X86_HVF[macOS + HVF]
        X86_QEMU[QEMU TCG]
    end

    subgraph "ARM64"
        ARM_KVM[Linux + KVM]
        ARM_HVF[macOS + HVF]
        ARM_RPI[Raspberry Pi]
    end

    subgraph "Cloud"
        AWS[AWS EC2/Graviton]
        GCP[Google Cloud]
        AZURE[Azure VMs]
    end

    AUTH --> X86_KVM
    AUTH --> X86_HVF
    AUTH --> X86_QEMU
    AUTH --> ARM_KVM
    AUTH --> ARM_HVF
    AUTH --> ARM_RPI

    X86_KVM --> AWS
    X86_KVM --> GCP
    X86_KVM --> AZURE
    ARM_KVM --> AWS

    style AUTH fill:#e74c3c,color:#fff
```
