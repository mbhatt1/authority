# Authority Kernel

The Authority Kernel (AK) is the security subsystem that enforces deny-by-default access control on the single untrusted program running inside an Authority VM.

## Design Principles

### 1. One Enforcement Path

Every authority-bearing request enters through the syscall handler and is routed through one dispatcher. User space issues an Authority syscall (numbers 1024+); the Nanos syscall layer (`src/unix/syscall.c`) forwards those calls to `ak_syscall_handler()` (`src/agentic/ak_syscall.c`), which builds a request and hands it to:

```c
ak_response_t *ak_dispatch(ak_agent_context_t *ctx, ak_request_t *req);
```

`ak_dispatch()` runs a fixed, ordered pipeline (below) before any effect executes. The `ak_handle_*` operation handlers are never called directly from the syscall entry point — doing so would bypass capability, policy, budget, and audit enforcement.

> Note: an older `ak_effects.c` layer (with `ak_authorize_and_execute()` and `AK_E_*` effect opcodes) exists in the tree but is **not compiled into the kernel** — it is legacy/dead code and is explicitly excluded from the build in `src/agentic/Makefile`. The compiled enforcement path is `ak_syscall_handler` → `ak_dispatch` → `ak_handle_*`, described here.

### 2. Deny-by-Default

If the pipeline cannot explicitly prove a request is allowed, it is denied:

- No capability of any kind = denied (mandatory confinement)
- No matching policy rule = denied
- Malformed capability token = denied (fail-closed)
- Unknown or out-of-range syscall = denied

### 3. Untrusted by Construction

The program is treated as untrusted. Syscall arguments originate outside the kernel trust boundary (`req.taint = AK_TAINT_UNTRUSTED`), pointers are range-checked before use, and the request's identity (pid, run_id) is stamped by the kernel from the resolved context rather than trusted from user space.

## The Dispatch Pipeline

`ak_dispatch()` executes six stages in a fixed order. Failure at any stage short-circuits to the audit stage and returns an error; the effect never runs.

```
┌──────────────────────────────┐
│ 1. REQUEST VALIDATION        │  ak_validate_request()
│    pid/run_id bind to ctx,   │  fail -> reject
│    op in [1024, 1042]        │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│ 2. ANTI-REPLAY               │  ak_check_replay()
│    monotonic per-run seq;    │  seq <= highest_seen -> AK_E_REPLAY
│    seq tracker per context   │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│ 3. CAPABILITY CHECK (INV-2)  │  ak_validate_capability()
│    per-call token (arg5), OR │  HMAC + scope + TTL + revocation
│    delegated grant, OR       │  no match -> AK_E_CAP_* (deny)
│    root admin capability     │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│ 4. POLICY + BUDGET (INV-3)   │  ak_check_policy()
│    deny-by-default match;    │  AK_E_POLICY_DENIED /
│    hard budget admission     │  AK_E_BUDGET_EXCEEDED
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│ 5. EXECUTE                    │  ak_handle_<op>()
│    perform the effect         │
└──────────────┬───────────────┘
               ↓
┌──────────────────────────────┐
│ 6. AUDIT (INV-4)              │  ak_log_operation()
│    append to hash chain;      │  durable (fsync) BEFORE the
│    make durable before return │  response is returned
└──────────────────────────────┘
```

### Stage 1 — Request validation

`ak_validate_request()` binds the request to the resolved context: the request's `pid` and `run_id` must equal the context's, and the op must be a valid Authority syscall number (1024–1042). Mismatches fail closed (`-EPERM`, `AK_E_CAP_RUN_MISMATCH`, `-EINVAL`).

### Stage 2 — Anti-replay

Each context owns a monotonic sequence tracker (`seq_tracker`), created per run. The kernel pre-increments `last_seq` for each syscall; the tracker rejects any `seq` less than or equal to the highest previously seen value with `AK_E_REPLAY`. This makes replays of a captured request fail closed.

### Stage 3 — Capability check (INV-2)

Authorization is three-way, evaluated in order (`ak_validate_capability()`):

1. **Explicit token** — if the request carries a capability (passed as a serialized token in the syscall's `arg5`), it is fully enforced: HMAC verification, scope/resource/method subsumption, TTL, and revocation. This is how an attenuated child presents a delegated subset of authority.
2. **Ambient root authority** — a context holding a `root_cap` is the single-tenant privileged root. Its `AK_CAP_ADMIN` capability is validated like any other (HMAC + revocation + scope), so a revoked or expired root cap still fails closed. `AK_CAP_ADMIN` subsumes any required type. Checked before the delegated store so root is never accidentally confined.
3. **Delegated grant** — a spawned child context granted capabilities is confined to them: the request is allowed only if a still-valid granted capability subsumes it, otherwise `AK_E_CAP_SCOPE`.
4. **Otherwise** — no token, no ambient authority, no matching grant: `AK_E_CAP_MISSING`. A context with no capability of any kind can perform no effect.

### Stage 4 — Policy + budget admission (INV-3)

`ak_check_policy()` calls `ak_policy_evaluate()` with the loaded policy and the context budget. Policy matching is deny-by-default. Hard budgets are admission-controlled here: the sum of in-flight and committed costs never exceeds the configured budget, and a request that would exceed it is rejected with `AK_E_BUDGET_EXCEEDED` before execution.

### Stage 5 — Execute

Only after stages 1–4 pass does the dispatcher call the matching `ak_handle_<op>()` handler to perform the effect (heap read/write, tool call, outbound request, IPC, etc.).

### Stage 6 — Audit (INV-4)

`ak_log_operation()` appends an entry to the hash-chained audit log for every dispatched request — successes and denials alike. The response is **never** returned before the audit entry is durable: entries are flushed (fsync) before the syscall returns, so the log validates from genesis to head and no committed effect is unlogged.

## Syscall Numbers

Authority syscalls occupy 1024+ (`AK_SYS_BASE`), dispatched by number in `ak_dispatch()`:

```c
/* State */
#define AK_SYS_READ             1024  /* Read heap object */
#define AK_SYS_ALLOC            1025  /* Allocate typed object */
#define AK_SYS_WRITE            1026  /* Patch object (CAS) */
#define AK_SYS_DELETE           1027  /* Soft-delete object */

/* Audit / query */
#define AK_SYS_QUERY            1028  /* Query audit log */

/* Batch */
#define AK_SYS_BATCH            1029  /* Atomic batch of operations */
#define AK_SYS_COMMIT           1030  /* Force audit log commit */

/* Tools */
#define AK_SYS_CALL             1031  /* Execute tool (WASM) */

/* Control */
#define AK_SYS_SPAWN            1032  /* Create child workload */
#define AK_SYS_SEND             1033  /* Send typed IPC message */
#define AK_SYS_RECV             1034  /* Receive IPC message */
#define AK_SYS_RESPOND          1035  /* Send response (DLP applied) */
#define AK_SYS_ASSERT           1036  /* Assert predicate (halt on fail) */

/* Outbound request handler */
#define AK_SYS_INFERENCE        1037  /* Outbound request (gated) */

/* Budget introspection */
#define AK_SYS_BUDGET_STATUS    1038  /* Current budget status */
#define AK_SYS_BUDGET_HISTORY   1039  /* Historical snapshots */
#define AK_SYS_BUDGET_BREAKDOWN 1040  /* Detailed breakdown */

/* Async outbound request */
#define AK_SYS_INFER_ISSUE      1041  /* Issue outbound HTTP(S), non-blocking */
#define AK_SYS_INFER_POLL       1042  /* Poll for outbound result */
```

The dispatcher validates `AK_SYS_BASE <= call <= AK_SYS_INFER_POLL` and rejects anything else with `-ENOSYS`.

## Capabilities

Capabilities are HMAC-signed tokens. The signing key is generated per boot from the Nanos CSPRNG and never leaves the kernel; verification (`ak_capability_validate`) covers the HMAC, the scope (type/resource/method subsumption), TTL, and the revocation set. Capability struct types:

```c
typedef enum {
    AK_CAP_NET       = 1,    /* Network access */
    AK_CAP_FS        = 2,    /* Filesystem access */
    AK_CAP_TOOL      = 3,    /* Tool execution */
    AK_CAP_SECRETS   = 4,    /* Secret resolution */
    AK_CAP_SPAWN     = 5,    /* Child spawning */
    AK_CAP_HEAP      = 6,    /* Heap object access */
    AK_CAP_INFERENCE = 7,    /* Outbound request access */
    AK_CAP_LLM       = 7,    /* Alias for INFERENCE */
    AK_CAP_IPC       = 8,    /* Inter-process communication */
    AK_CAP_ANY       = 254,  /* Wildcard - matches any type */
    AK_CAP_ADMIN     = 255,  /* Administrative (root) */
} ak_cap_type_t;
```

## Tool Execution: Integer-Only WASM

Tools invoked via `AK_SYS_CALL` run in an **integer-only WASM subset interpreter** (`ak_wasm_interp.c`), not a full WASM runtime. The kernel is built `-mno-sse` with no floating point, so `f32`/`f64` value types and float opcodes are rejected fail-closed (`AK_E_WASM_UNSUPPORTED`); unsupported opcodes are likewise rejected rather than approximated. The module is parsed into a bounded, integer-only representation before execution.

## External I/O: Async Issue / Poll

External network requests are **not** synchronous in-kernel blocking calls. They use an issue/poll model (`AK_SYS_INFER_ISSUE` / `AK_SYS_INFER_POLL`, backed by `ak_https_issue`/`ak_https_poll`):

1. **Issue** — the program submits the request; the kernel enforces the full pipeline synchronously and hands the request to the runloop. One request may be in flight per context.
2. **Runloop** — the Nanos runloop drives the HTTP(S) request to completion asynchronously; the kernel does not block a thread on the network.
3. **Poll** — the program polls for the result, receiving `-EAGAIN` until the runloop has produced a response.

## Error Codes

```c
/* Protocol errors: -4000 to -4099 */
#define E_FRAME_TOO_LARGE       (-4001)
#define E_SCHEMA_INVALID        (-4002)

/* Capability errors: -4100 to -4199 */
#define E_CAP_MISSING           (-4100)
#define E_CAP_INVALID           (-4101)
#define E_CAP_EXPIRED           (-4102)
#define E_CAP_SCOPE             (-4103)
#define E_CAP_REVOKED           (-4104)
#define E_CAP_RATE              (-4105)

/* Policy errors: -4200 to -4299 */
#define E_REPLAY                (-4200)
#define E_POLICY_DENY           (-4201)
#define E_APPROVAL_REQUIRED     (-4202)
#define E_TAINT                 (-4203)

/* Resource errors: -4300 to -4399 */
#define E_BUDGET_EXCEEDED       (-4300)
#define E_RATE_LIMIT            (-4301)
```

## Context Structure

Each running program has an Authority Kernel context that carries its identity, sequence tracker, authority, policy, and budget:

```c
typedef struct ak_agent_context {
    u8   pid[AK_TOKEN_ID_SIZE];       /* Program identity */
    u8   run_id[AK_TOKEN_ID_SIZE];    /* Per-run identity */
    u64  last_seq;                    /* Monotonic sequence counter */

    ak_seq_tracker_t   *seq_tracker;  /* Anti-replay state */

    ak_capability_t    *root_cap;     /* Ambient admin cap (root only) */
    table               delegated_caps; /* Confined grants (child contexts) */

    struct ak_policy   *policy;       /* Loaded policy */
    ak_budget_t        *budget;       /* Hard budget state */

    heap                heap;         /* Typed heap for this context */
} ak_agent_context_t;
```

## Security Invariants

The Authority Kernel enforces these invariants across the dispatch pipeline:

| ID | Invariant | Where enforced |
|----|-----------|----------------|
| INV-DENY | Deny-by-default | Capability + policy stages fail closed |
| INV-1 | Single dispatch path | `ak_syscall_handler` → `ak_dispatch` only |
| INV-2 | Capability required | Stage 3: HMAC + scope + TTL + revocation |
| INV-3 | Budget never exceeded | Stage 4: admission control on hard budgets |
| INV-4 | Log commitment | Stage 6: audit durable before response |
| INV-NO-BYPASS | No handler bypass | `ak_handle_*` never called outside dispatch |

See [Security Invariants](/security/invariants) for complete documentation.
