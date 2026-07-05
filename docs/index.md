---
layout: home

hero:
  name: Authority
  text: Capability-Based Security Unikernel
  tagline: Kernel-enforced security for a single untrusted program per VM, built on Nanos.
  actions:
    - theme: brand
      text: Get Started
      link: /getting-started/
    - theme: alt
      text: View on GitHub
      link: https://github.com/nanovms/authority-nanos

features:
  - title: Cryptographic Capabilities
    details: Every effectful syscall requires an unforgeable HMAC-SHA256 capability. No ambient authority, no permission guessing, no privilege escalation.
  - title: Tamper-Evident Audit Log
    details: A hash-chained log records every request and result. Any modification breaks the chain and is immediately detectable.
  - title: Deny-by-Default Policy
    details: Filesystem, network, and tool access are denied before execution unless a policy rule and capability explicitly allow them.
  - title: Integer-Only WASM Tool Sandbox
    details: Tools run in an isolated WASM sandbox with explicit capability passing. The kernel is built -mno-sse, so floating-point tools are rejected.
  - title: Single-Process Unikernel
    details: No users, no sudo, no setuid. One program per VM eliminates entire classes of privilege-escalation and container-escape attacks.
  - title: Hard Resource Budgets
    details: Pre-admission budget enforcement bounds tokens, tool calls, wall time, and bytes. Consumption never exceeds declared limits.
---

## System Architecture

```mermaid
graph TB
    subgraph "Untrusted Program"
        APP[Program Code]
        SDK[Authority SDK]
    end

    subgraph "Authority Kernel"
        GATE[ak_syscall_handler → ak_dispatch]

        subgraph "Enforcement Pipeline"
            VAL[Request Validation]
            REPLAY[Anti-Replay]
            CAP[Capability Verifier]
            POLBUD[Policy + Budget]
            AUDIT[Audit Logger]
        end

        subgraph "Handlers"
            FS[Filesystem]
            NET[Network]
            TOOL[WASM Tool]
            OUT[Outbound Request]
        end
    end

    subgraph "Nanos Kernel"
        SYSCALL[Syscall Interface]
        MEM[Memory Manager]
        SCHED[Scheduler]
        DRV[Device Drivers]
    end

    subgraph "Hardware / Hypervisor"
        HV[KVM / HVF / QEMU]
    end

    APP --> SDK
    SDK --> GATE
    GATE --> VAL
    VAL --> REPLAY
    REPLAY --> CAP
    CAP --> POLBUD
    POLBUD --> FS
    POLBUD --> NET
    POLBUD --> TOOL
    POLBUD --> OUT
    FS --> AUDIT
    NET --> AUDIT
    TOOL --> AUDIT
    OUT --> AUDIT

    FS --> SYSCALL
    NET --> SYSCALL
    TOOL --> SYSCALL
    OUT --> SYSCALL

    SYSCALL --> MEM
    SYSCALL --> SCHED
    SYSCALL --> DRV

    DRV --> HV
```

## Request Flow

Every effectful syscall enters through `ak_syscall_handler`, which calls `ak_dispatch()`. `ak_dispatch()` runs a fixed six-stage pipeline before any effect is executed:

```mermaid
sequenceDiagram
    participant Prog as Program
    participant Disp as ak_dispatch
    participant Val as Request Validation
    participant Rep as Anti-Replay
    participant Cap as Capability Check
    participant PB as Policy + Budget
    participant Exec as Executor
    participant Aud as Audit Log

    Prog->>Disp: Syscall (request)
    Disp->>Val: 1. Validate request
    alt Malformed
        Val-->>Prog: E_REQUEST_INVALID
    end
    Val->>Rep: 2. Anti-replay check
    alt Replay detected
        Rep-->>Prog: E_REPLAY
    end
    Rep->>Cap: 3. Verify capability (HMAC-SHA256)
    alt Invalid capability
        Cap-->>Prog: E_CAP_INVALID
    end
    Cap->>PB: 4. Check policy + budget
    alt Policy deny or budget exceeded
        PB-->>Prog: E_POLICY_DENY / E_BUDGET_EXCEEDED
    end
    PB->>Exec: 5. Execute effect
    Exec->>Aud: 6. Append to hash-chained audit log
    Aud->>Aud: fsync()
    Aud-->>Prog: Result
```

## What is Authority?

Authority is a **fork of [Nanos](https://github.com/mbhatt1/nanos)** that adds the **Authority kernel** — a capability-based security layer that runs a single untrusted program per VM and mediates every effect that program performs. It is not a general-purpose OS: one VM runs one program, and the kernel enforces cryptographic authorization, deny-by-default policy, hard budgets, and a tamper-evident audit trail on everything that program does.

```mermaid
graph LR
    subgraph "Standard Nanos"
        N1[Unikernel Core]
        N2[POSIX Syscalls]
        N3[Network Stack]
        N4[Filesystem]
    end

    subgraph "Authority Additions"
        A1[Capability System]
        A2[Policy Engine]
        A3[Audit Logging]
        A4[Budget Control]
        A5[Outbound Request Handler]
        A6[WASM Tool Sandbox]
    end

    N1 --> A1
    N2 --> A2
    N3 --> A5
    N4 --> A3
```

## Security Model

```mermaid
flowchart TB
    subgraph "Four Security Invariants"
        INV1[INV-1: No Bypass<br/>All effects through the kernel]
        INV2[INV-2: Capability Required<br/>HMAC-SHA256 tokens]
        INV3[INV-3: Budget Enforced<br/>Pre-admission control]
        INV4[INV-4: Audit Committed<br/>Hash-chained log]
    end

    subgraph "Security Guarantees"
        G1[Containment]
        G2[Least Privilege]
        G3[Complete Audit]
        G4[Bounded Cost]
    end

    INV1 --> G1
    INV2 --> G1
    INV2 --> G2
    INV4 --> G3
    INV3 --> G4
```

## Quick Example

Create a policy file (`/ak/policy.json`):

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**", "/lib/**"],
    "write": ["/tmp/**"]
  },
  "net": {
    "dns": ["api.example.com"],
    "connect": ["dns:api.example.com:443"]
  },
  "profiles": ["tier1-musl"]
}
```

Build and run:

```bash
authority build myapp -c config.json
authority run myapp
```

## Deployment Options

```mermaid
graph TB
    subgraph "Development"
        DEV[Local Machine]
        QEMU[QEMU/HVF]
    end

    subgraph "Cloud"
        AWS[AWS EC2]
        GCP[Google Cloud]
        AZURE[Azure VMs]
    end

    subgraph "Edge"
        RPI[Raspberry Pi]
        JETSON[NVIDIA Jetson]
    end

    AUTH[Authority Image]

    AUTH --> DEV
    AUTH --> AWS
    AUTH --> GCP
    AUTH --> AZURE
    AUTH --> RPI
    AUTH --> JETSON

    DEV --> QEMU
```

## Project Status

| Component | Status |
|-----------|--------|
| Core Kernel | Stable |
| Authority Kernel | Stable |
| Security Invariants (INV-1 to INV-4) | Enforced |
| Documentation | Active |

See the [roadmap](/guide/roadmap) for upcoming features.
