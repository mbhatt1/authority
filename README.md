# Authority

A capability-based security unikernel, built on [Nanos](https://github.com/nanovms/nanos).

## What This Is

Authority runs a single untrusted program per virtual machine and enforces
kernel-level security on everything that program does. Security is enforced by
the kernel — inside the syscall path, before any effect executes — not by the
application or by configuration.

- **Cryptographic capabilities** — unforgeable HMAC-SHA256 tokens that authorize
  access to a specific resource, bound to a run, time-limited, and revocable.
- **Hash-chained audit log** — an append-only, tamper-evident record of every
  operation, durable before a response is returned.
- **Resource budgets** — hard, kernel-enforced limits on calls, tokens,
  wall-time, and I/O. Admission control rejects work that would exceed them.
- **Deny-by-default policy** — filesystem, network, and tool access controlled
  by an explicit allowlist. Anything not proven allowed is denied.
- **Typed heap** — versioned object storage with compare-and-swap semantics.
- **Sandboxed tool execution** — an integer-only WASM interpreter runs
  bytecode tools in-kernel, gated by capabilities.

The program does not have to cooperate or be trusted for these guarantees to
hold: it runs alone in the VM, with no users, no shell, and no ambient
authority.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                Program (Python, Node.js, native)            │
├─────────────────────────────────────────────────────────────┤
│                    Authority Kernel                         │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │Capability│ │  Audit   │ │  Policy  │ │  Budget  │       │
│  │  System  │ │   Log    │ │  Engine  │ │  Control │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│  │  Typed   │ │ Outbound │ │  WASM    │ │  Syscall │       │
│  │   Heap   │ │ Transport│ │ Sandbox  │ │ Dispatch │       │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
├─────────────────────────────────────────────────────────────┤
│                      Nanos Kernel                           │
└─────────────────────────────────────────────────────────────┘
```

## Enforcement Pipeline

The kernel intercepts the Authority syscalls (numbers 1024+) and runs every
request through a fixed pipeline in `ak_dispatch()` before the effect executes:

1. **Request validation** — structural and identity checks.
2. **Anti-replay** — monotonic sequence enforcement per run.
3. **Capability check** — the request must be authorized by a valid capability
   (a per-call token, a delegated grant, or the root context's authority).
4. **Policy & budget** — deny-by-default policy and hard budget admission.
5. **Execute** — the handler performs the operation.
6. **Audit** — the operation is appended to the hash-chained log and made
   durable before the response is returned.

## Syscall Interface

The kernel implements syscalls in the 1024+ range for the program to
communicate with the Authority layer:

| Number | Name | Description |
|--------|------|-------------|
| 1024 | `AK_SYS_READ` | Read object from the typed heap |
| 1025 | `AK_SYS_ALLOC` | Allocate a heap object |
| 1026 | `AK_SYS_WRITE` | Update an object (CAS semantics) |
| 1027 | `AK_SYS_DELETE` | Delete an object |
| 1028 | `AK_SYS_QUERY` | Query the audit log |
| 1029 | `AK_SYS_BATCH` | Atomic batch of operations |
| 1030 | `AK_SYS_COMMIT` | Checkpoint the audit log |
| 1031 | `AK_SYS_CALL` | Execute a tool in the WASM sandbox |
| 1032 | `AK_SYS_SPAWN` | Create a child context |
| 1033 | `AK_SYS_SEND` | Send a message |
| 1034 | `AK_SYS_RECV` | Receive messages |
| 1035 | `AK_SYS_RESPOND` | Return a response (DLP applied) |
| 1036 | `AK_SYS_ASSERT` | Record an assertion |
| 1037 | `AK_SYS_INFERENCE` | Invoke an outbound request handler |
| 1041 | `AK_SYS_INFER_ISSUE` | Issue an outbound HTTP(S) request (non-blocking) |
| 1042 | `AK_SYS_INFER_POLL` | Poll for an issued request's result |

External effects (outbound HTTP, tool execution) are issued asynchronously and
retrieved by polling: the kernel enforces the request synchronously, performs
the I/O on the runloop, and the program polls for the result. This is the model
that fits the unikernel's cooperative scheduler.

## Policy Format

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
  "tools": {
    "allow": ["http_get", "file_read"],
    "deny": ["shell_exec"]
  },
  "budgets": {
    "tokens": 100000,
    "calls": 50,
    "wall_time_ms": 300000
  }
}
```

## Capability Token

```c
typedef struct ak_capability {
    ak_cap_type_t type;       // NET, FS, TOOL, SECRETS, HEAP, IPC, ...
    char resource[256];       // Pattern: "https://*.example.com/*"
    char methods[8][32];      // Allowed operations
    u64 issued_ms;
    u32 ttl_ms;
    u32 rate_limit;
    u8 run_id[16];            // Bound to a specific run
    u8 mac[32];               // HMAC-SHA256 signature
} ak_capability_t;
```

Capabilities are unforgeable (HMAC), revocable, time-limited, and rate-limited.
The signing key never leaves the kernel.

## Audit Log Entry

```c
typedef struct ak_audit_entry {
    u64 seq;                  // Monotonic sequence number
    u8 pid[16];               // Context ID
    u8 run_id[16];            // Run ID
    u16 op;                   // Operation code
    u8 req_hash[32];          // SHA-256 of the request
    u8 res_hash[32];          // SHA-256 of the response
    u8 prev_hash[32];         // Previous entry hash
    u8 this_hash[32];         // SHA-256(prev_hash || entry)
} ak_audit_entry_t;
```

The hash chain is append-only and tamper-evident: any modification of a past
entry invalidates every hash after it.

## Components

| Component | Files | Description |
|-----------|-------|-------------|
| Capability system | `ak_capability.c/.h` | HMAC-SHA256 tokens, revocation, rate limiting |
| Audit log | `ak_audit.c/.h` | Hash-chained entries, crash recovery |
| Typed heap | `ak_heap.c/.h` | Versioned objects, CAS, taint tracking |
| Policy engine | `ak_policy.c/.h` | JSON/TOML parsing, pattern matching |
| Budget control | `ak_budget.c/.h` | Hard, atomic resource limits |
| WASM sandbox | `ak_wasm.c`, `ak_wasm_interp.c` | Integer-only bytecode interpreter |
| Outbound transport | `ak_transport.c`, `klib/ak_https.c` | Async HTTP(S) over the network stack |
| Syscall dispatch | `ak_syscall.c` | The enforcement pipeline |

## Build

```bash
# Requires a cross toolchain (e.g. x86_64-elf-gcc) and nasm.
make PLATFORM=pc CROSS_COMPILE=x86_64-elf- kernel
# ARM64:
make PLATFORM=virt ARCH=aarch64 CROSS_COMPILE=aarch64-elf- kernel
```

## License

Apache-2.0
