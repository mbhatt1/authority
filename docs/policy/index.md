# Policy Overview

The Authority kernel uses a **deny-by-default** policy model:

- If no policy is loaded, ALL gated operations are denied
- If a policy is loaded, only explicitly allowed operations succeed
- An unmatched tool or domain = deny

The compiled policy engine is `src/agentic/ak_policy.c`, which parses **JSON**. This page describes the schema that engine actually parses.

## Policy Evaluation Flow

```mermaid
flowchart TD
    REQ[Request] --> LOAD{Policy Loaded?}

    LOAD -->|No| DENY1[DENY<br/>No policy]
    LOAD -->|Yes| MATCH{Rule Match?}

    MATCH -->|No Match| DENY2[DENY<br/>Nothing allows it]
    MATCH -->|Explicit deny| DENY3[DENY<br/>Deny rule]
    MATCH -->|Allow| BUDGET{Budget OK?}

    BUDGET -->|Exceeded| DENY4[DENY<br/>Budget exceeded]
    BUDGET -->|OK| ALLOW[ALLOW]

    style DENY1 fill:#c0392b,color:#fff
    style DENY2 fill:#c0392b,color:#fff
    style DENY3 fill:#c0392b,color:#fff
    style DENY4 fill:#c0392b,color:#fff
    style ALLOW fill:#27ae60,color:#fff
```

## Policy Structure (compiled schema)

```mermaid
graph TB
    subgraph "Policy File"
        VER[version]
        SIG[signature: optional HMAC]

        subgraph TOOLS[Tool Rules]
            T_ALLOW[allow: names]
            T_DENY[deny: names]
        end

        subgraph DOMAINS[Domain Rules]
            D_ALLOW[allow: patterns]
            D_DENY[deny: patterns]
        end

        subgraph TAINT[Taint Rules]
            TA_SRC[sources]
            TA_SINK[sinks]
            TA_SAN[sanitizers]
        end

        subgraph BUDGETS[Budget Limits]
            B_CALLS[calls]
            B_TOKENS[tokens]
            B_TIME[inference_ms]
        end
    end

    style VER fill:#3498db,color:#fff
    style TOOLS fill:#e74c3c,color:#fff
    style DOMAINS fill:#9b59b6,color:#fff
    style TAINT fill:#f39c12,color:#fff
    style BUDGETS fill:#1abc9c,color:#fff
```

## Policy Format

- [JSON Format](/policy/json-format) - The format parsed by the compiled engine
- [TOML Format](/policy/toml-format) - A planned human-friendly alternative (not yet in the kernel build)

## Policy Location

```mermaid
graph LR
    subgraph "Development"
        INITRD[/ak/policy.json<br/>in initrd]
    end

    subgraph "Production"
        EMBED[Embedded in kernel<br/>at compile time]
    end

    subgraph "Runtime"
        LOADER[Policy Loader]
        CACHE[Cached Policy]
    end

    INITRD --> LOADER
    EMBED --> LOADER
    LOADER --> CACHE

    style INITRD fill:#3498db,color:#fff
    style EMBED fill:#e74c3c,color:#fff
    style CACHE fill:#2ecc71,color:#fff
```

### Development (Initrd)

Place your policy at `/ak/policy.json` in the initrd:

```bash
mkdir -p initrd/ak
cp policy.json initrd/ak/policy.json
```

### Production (Embedded)

Compile the policy into the kernel image:

```makefile
CFLAGS += -DCONFIG_AK_EMBEDDED_POLICY=1
```

## Pattern Matching

Tool and domain rules use glob patterns. Deny rules take precedence over allow.

```mermaid
graph TB
    subgraph "Tool Pattern Matching"
        TOOL[http_get]
        P1["http_*"] -->|MATCH| TOOL
        P2["http_get"] -->|MATCH| TOOL
        P3["shell_*"] -->|NO MATCH| TOOL
    end

    subgraph "Domain Pattern Matching"
        DOM[api.github.com]
        N1["api.github.com"] -->|MATCH| DOM
        N2["*.github.com"] -->|MATCH| DOM
        N3["*.internal"] -->|NO MATCH| DOM
    end

    style TOOL fill:#3498db,color:#fff
    style DOM fill:#9b59b6,color:#fff
```

## Quick Reference

### Tool Rules

```json
{
  "tools": {
    "allow": ["http_get", "file_read"],
    "deny": ["shell_exec"]
  }
}
```

### Domain Rules

Domains gate outbound destinations.

```json
{
  "domains": {
    "allow": ["*.github.com", "api.example.com"],
    "deny": ["*.internal"]
  }
}
```

### Budgets

```json
{
  "budgets": {
    "calls": 100,
    "tokens": 100000,
    "inference_ms": 60000,
    "file_bytes": 10485760
  }
}
```

## Budget Enforcement

```mermaid
sequenceDiagram
    participant Program
    participant Gate as ak_dispatch
    participant Budget as Budget Tracker
    participant Op as Operation

    Program->>Gate: Request (cost=10)
    Gate->>Budget: Check budget

    Budget->>Budget: current=90, limit=100
    Budget->>Budget: 90 + 10 <= 100?

    alt Within Budget
        Budget-->>Gate: OK
        Gate->>Op: Execute
        Op-->>Gate: Success
        Gate->>Budget: Commit cost (atomic)
        Gate-->>Program: Success
    else Exceeds Budget
        Budget-->>Gate: E_BUDGET_EXCEEDED
        Gate-->>Program: Error (budget exceeded)
    end
```

## Denial Debugging

```mermaid
sequenceDiagram
    participant Program
    participant AK as Authority Kernel
    participant Console
    participant LastError as Last Error Buffer

    Program->>AK: gated operation
    AK->>AK: No matching allow rule
    AK->>Console: AK DENY ... missing ...
    AK->>LastError: Store denial details
    AK-->>Program: -EACCES

    Program->>AK: syscall(AK_SYS_LAST_ERROR)
    AK->>LastError: Read stored denial
    LastError-->>Program: JSON with details
```

### Last Error Syscall

```c
char buf[1024];
syscall(AK_SYS_LAST_ERROR, buf, sizeof(buf));
// buf contains JSON with denial details
```

## Validation

The parser validates:
- `version` field present
- All patterns are valid strings within bounds
- Numeric budget values parse without overflow
- Trailing garbage after the top-level object is rejected (fail-closed)
- Unknown members are skipped

### Not Yet in the Compiled Engine

Path-level filesystem rules (`fs.read`/`fs.write`), structured network rules (`net.connect`/`net.dns`/`bind`/`listen`), `wasm`, `infer`, and `profiles` sections are **not** parsed by `ak_policy.c`. They belong to the effect layer that is not in the current kernel build. Do not rely on them.
