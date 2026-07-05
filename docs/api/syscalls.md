# Syscalls Reference

Detailed documentation for Authority Kernel syscalls. Every call is routed through `ak_syscall_handler()` into the `ak_dispatch()` pipeline before any effect executes.

## Syscall Categories Overview

```mermaid
graph LR
    subgraph "State (1024-1027)"
        READ[READ<br/>1024]
        ALLOC[ALLOC<br/>1025]
        WRITE[WRITE<br/>1026]
        DELETE[DELETE<br/>1027]
    end

    subgraph "Audit / Batch"
        QUERY[QUERY<br/>1028]
        BATCH[BATCH<br/>1029]
        COMMIT[COMMIT<br/>1030]
    end

    subgraph "Tools"
        CALL[CALL<br/>1031]
    end

    subgraph "Control (1032-1036)"
        SPAWN[SPAWN<br/>1032]
        SEND[SEND<br/>1033]
        RECV[RECV<br/>1034]
        RESPOND[RESPOND<br/>1035]
        ASSERT[ASSERT<br/>1036]
    end

    subgraph "Outbound / Budget (1037-1042)"
        INFER[INFERENCE<br/>1037]
        BUD[BUDGET_*<br/>1038-1040]
        ISSUE[INFER_ISSUE<br/>1041]
        POLL[INFER_POLL<br/>1042]
    end

    style READ fill:#3498db,color:#fff
    style CALL fill:#9b59b6,color:#fff
    style COMMIT fill:#2ecc71,color:#fff
    style SPAWN fill:#e74c3c,color:#fff
    style INFER fill:#f39c12,color:#fff
```

## State Management

```mermaid
stateDiagram-v2
    [*] --> Created: ALLOC

    Created --> Active: Object in use
    Active --> Updated: WRITE (CAS)
    Updated --> Active: New version

    Active --> Deleted: DELETE
    Updated --> Deleted: DELETE

    Deleted --> [*]: Tombstoned

    note right of Active: version increments<br/>on each WRITE

    note right of Updated: CAS ensures<br/>no lost updates
```

### AK_SYS_READ (1024)

Read a heap object by pointer.

**Request:**
```json
{
  "op": "READ",
  "args": {
    "ptr": 12345
  }
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "ptr": 12345,
    "version": 5,
    "value": { ... },
    "taint": 0
  }
}
```

**Errors:**
- `ENOENT` — Object not found
- `E_CAP_SCOPE` — Capability doesn't cover this object

### AK_SYS_ALLOC (1025)

Allocate a new typed heap object.

**Request:**
```json
{
  "op": "ALLOC",
  "args": {
    "type": "State",
    "value": {
      "name": "worker",
      "status": "running"
    }
  }
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "ptr": 12346,
    "version": 1
  }
}
```

**Errors:**
- `E_SCHEMA_INVALID` — Value doesn't match type schema
- `E_BUDGET_EXCEEDED` — Heap object limit reached

### AK_SYS_WRITE (1026)

Update an existing object with CAS semantics.

**Request:**
```json
{
  "op": "WRITE",
  "args": {
    "ptr": 12345,
    "expected_version": 5,
    "patch": [
      { "op": "replace", "path": "/status", "value": "completed" }
    ]
  }
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "version": 6
  }
}
```

**Errors:**
- `E_CONFLICT` — Version mismatch (retry required)
- `E_SCHEMA_INVALID` — Patched value invalid
- `ENOENT` — Object not found

### AK_SYS_DELETE (1027)

Soft-delete an object (sets tombstone flag).

**Request:**
```json
{
  "op": "DELETE",
  "args": {
    "ptr": 12345,
    "expected_version": 6
  }
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "deleted": true
  }
}
```

## Audit and Query

### AK_SYS_QUERY (1028)

Query the audit log.

**Request:**
```json
{
  "op": "QUERY",
  "args": {
    "start_seq": 0,
    "end_seq": 100
  }
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "entries": [
      {
        "seq": 1,
        "op": "ALLOC",
        "req_hash": "...",
        "res_hash": "...",
        "this_hash": "..."
      }
    ],
    "head_seq": 1,
    "count": 1
  }
}
```

### AK_SYS_COMMIT (1030)

Force an immediate audit log commit (fsync). Note: the dispatcher already makes each entry durable before returning; `COMMIT` is an explicit flush point.

**Request:**
```json
{
  "op": "COMMIT"
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "seq": 1234,
    "hash": "abc123..."
  }
}
```

## Batch

### AK_SYS_BATCH (1029)

Execute multiple operations atomically.

**Request:**
```json
{
  "op": "BATCH",
  "args": {
    "operations": [
      { "op": "WRITE", "ptr": 100, "version": 5, "patch": [...] },
      { "op": "WRITE", "ptr": 101, "version": 3, "patch": [...] }
    ]
  }
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "results": [
      { "version": 6 },
      { "version": 4 }
    ]
  }
}
```

**Errors:**
- `E_CONFLICT` — Any operation version mismatch (all rolled back)

## Tools

Tools run in an **integer-only WASM subset interpreter** (`ak_wasm_interp.c`). The kernel is built `-mno-sse`, so float value types and opcodes are rejected fail-closed. Tool execution is gated by the same dispatch pipeline as every other syscall.

```mermaid
sequenceDiagram
    participant App as Program
    participant Dispatch as ak_dispatch
    participant Policy as Policy
    participant WASM as WASM Interpreter
    participant Tool as Tool Module
    participant Audit

    App->>Dispatch: CALL(tool, params) + cap
    Dispatch->>Dispatch: Capability check (INV-2)
    Dispatch->>Policy: Tool allowed?
    Policy-->>Dispatch: Allow/Deny

    alt Tool Allowed
        Dispatch->>WASM: Load module (integer-only)
        WASM->>Tool: Execute function
        Tool-->>WASM: Result
        WASM-->>Dispatch: Result
        Dispatch->>Audit: Log (durable)
        Dispatch-->>App: Success + usage
    else Denied
        Dispatch->>Audit: Log denial (durable)
        Dispatch-->>App: E_POLICY_DENY
    end
```

### AK_SYS_CALL (1031)

Execute a tool in the integer-only WASM interpreter.

**Request:**
```json
{
  "op": "CALL",
  "args": {
    "tool": "parse_record",
    "params": {
      "input": "..."
    }
  }
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "output": { ... }
  },
  "usage": {
    "cpu_ns": 1500000
  }
}
```

**Errors:**
- `E_POLICY_DENY` — Tool not allowed by policy
- `E_CAP_SCOPE` — Capability doesn't cover this tool
- `E_TOOL_FAIL` — Tool execution failed
- `E_WASM_UNSUPPORTED` — Module uses float or unsupported opcodes (rejected fail-closed)
- `E_BUDGET_EXCEEDED` — Tool call budget exhausted

## Control

### AK_SYS_SPAWN (1032)

Create a confined child workload. The child holds only the capabilities delegated to it (attenuation); it never receives the root capability.

### AK_SYS_SEND (1033) / AK_SYS_RECV (1034)

Send and receive typed IPC messages. `RECV` dequeues only from the caller's own inbox. Both require an `AK_CAP_IPC` capability.

### AK_SYS_RESPOND (1035)

Send a response to the outside (DLP applied to the payload).

### AK_SYS_ASSERT (1036)

Assert a predicate; halts the workload on failure.

## Outbound Requests

External network access is capability-gated. `AK_SYS_INFERENCE` is the synchronous-enforcement outbound request handler; for network I/O, the async issue/poll pair is used so the kernel never blocks a thread on the network.

### AK_SYS_INFERENCE (1037)

Submit a capability-gated outbound request. Requires an `AK_CAP_INFERENCE` (alias `AK_CAP_LLM`) capability whose resource pattern covers the destination.

**Request:**
```json
{
  "op": "INFERENCE",
  "args": {
    "endpoint": "https://api.example.com/v1/complete",
    "method": "POST",
    "body": { ... }
  }
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "status": 200,
    "body": { ... }
  },
  "usage": {
    "bytes": 512,
    "latency_ms": 450
  }
}
```

**Errors:**
- `E_POLICY_DENY` — Destination not allowed
- `E_CAP_SCOPE` — Outbound-request capability missing or out of scope
- `E_BUDGET_EXCEEDED` — Budget exhausted

### AK_SYS_INFER_ISSUE (1041) / AK_SYS_INFER_POLL (1042)

Async outbound HTTP(S). The kernel enforces the full pipeline on **issue**, hands the request to the runloop, and the program **polls** for the result. One request may be in flight per context.

```mermaid
sequenceDiagram
    participant App as Program
    participant Dispatch as ak_dispatch
    participant Runloop as Nanos Runloop
    participant Net as Network

    App->>Dispatch: INFER_ISSUE(endpoint) + cap
    Dispatch->>Dispatch: Enforce pipeline (cap, policy, budget)
    Dispatch->>Runloop: Hand off request
    Dispatch-->>App: Accepted

    Runloop->>Net: HTTP(S) request (async)

    loop Until complete
        App->>Dispatch: INFER_POLL
        Dispatch-->>App: -EAGAIN
    end

    Net-->>Runloop: Response
    App->>Dispatch: INFER_POLL
    Dispatch-->>App: Result
```

**Issue request:**
```json
{
  "op": "INFER_ISSUE",
  "args": {
    "endpoint": "https://api.example.com/v1/complete",
    "method": "POST",
    "body": { ... }
  }
}
```

**Poll request:**
```json
{
  "op": "INFER_POLL"
}
```

**Poll response (pending):** returns `-EAGAIN` until the runloop has driven the request to completion.

**Poll response (ready):**
```json
{
  "ok": true,
  "result": {
    "status": 200,
    "body": { ... }
  }
}
```

## Budget Introspection

Read-only views over the hard budget tracked by the kernel.

### AK_SYS_BUDGET_STATUS (1038)

Current budget status.

**Request:**
```json
{
  "op": "BUDGET_STATUS"
}
```

**Response:**
```json
{
  "ok": true,
  "result": {
    "limit": 1000000,
    "used": 42315,
    "in_flight": 0,
    "remaining": 957685
  }
}
```

### AK_SYS_BUDGET_HISTORY (1039)

Historical budget snapshots.

### AK_SYS_BUDGET_BREAKDOWN (1040)

Detailed per-category budget breakdown.
