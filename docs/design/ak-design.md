# Authority Kernel (AK) Design Document

**Version:** 1.0
**Status:** ACTIVE

This document defines the shared interfaces, hook points, and ownership boundaries for the deny-by-default Authority kernel.

---

## 1. Architecture Overview

### 1.1 Core Principle: Single Enforcement Gate

Every authority-bearing operation from the untrusted program flows through ONE enforcement point in the compiled kernel: the syscall dispatcher.

```c
ak_response_t *ak_dispatch(ak_agent_context_t *ctx, ak_request_t *req);
```

- `ak_dispatch()` (`src/agentic/ak_syscall.c`) is the enforcement gate for every Authority syscall (1024+).
- Default is **DENY-BY-DEFAULT**: if authorization cannot be resolved, the effect is denied.
- Program primitives (tools, the WASM sandbox, outbound requests) are first-class, capability-gated operations.

::: warning Legacy note
An earlier design routed POSIX syscalls through a `ak_authorize_and_execute()` effect frontend (`ak_effects.c`, `ak_posix_route.c`). Those files are **not compiled into the kernel** (see `platform/pc/Makefile`). The live enforcement path is `ak_dispatch()`.
:::

### 1.2 Dispatch Pipeline

`ak_dispatch()` runs a fixed, staged pipeline. Any stage may deny; denials and commits are both audited:

1. **Request validation** — structural checks, ID binding to the context
2. **Anti-replay** — sequence-based replay rejection
3. **Capability verification (INV-2)** — resolve an explicit token, root capability, or delegated grant
4. **Policy + budget (INV-3)** — policy match and admission control
5. **Execute** — per-operation handler
6. **Audit (INV-4)** — append hash-chained entry, durable before the response is returned

### 1.3 Effect Model

Every effectful operation carries:
- A canonical target (heap object identity, tool identity, outbound destination)
- A trace ID for correlation
- Budget constraints
- Policy-checkable parameters

---

## 2. Concrete Hook Points (Existing Codebase)

### 2.1 Syscall Entry / Dispatcher

| Component | File | Function | Notes |
|-----------|------|----------|-------|
| Main POSIX dispatcher | `src/unix/syscall.c` | `read()`, `write()`, etc. | Routes to fdesc operations |
| AK integration check | `src/unix/syscall.c` | `#ifdef CONFIG_AK_ENABLED` | Conditional include |
| AK syscall handler | `src/agentic/ak_nanos.c` | `ak_syscall_handler()` | Handles syscalls 1024-1042 |
| AK init | `src/agentic/ak_nanos.c` | `ak_nanos_init()` | Called from kernel startup |
| AK dispatch | `src/agentic/ak_syscall.c` | `ak_dispatch()` | Staged validation pipeline |

### 2.2 Process/Thread Structures

| Component | File | Notes |
|-----------|------|-------|
| Thread struct | `src/unix/unix_internal.h` | Per-thread state |
| Process forward decl | `src/unix/unix.h` | `typedef struct process *process` |
| Program context | `src/agentic/ak_types.h` | `struct ak_agent_context` — AK per-context state |
| Current context | `src/agentic/ak_nanos.c` | `__thread ak_agent_context_t *current_context` |

### 2.3 Existing AK Syscall Dispatch

| Component | File | Notes |
|-----------|------|-------|
| Syscall numbers | `src/agentic/ak_types.h` | 1024-1042 defined |
| Handler dispatch | `src/agentic/ak_syscall.c` | Switch on op code |
| Heap operations | `ak_handle_read/alloc/write/delete` | CRUD on typed heap |
| Tool calls | `ak_handle_call` | `AK_SYS_CALL` (1031) |
| Outbound requests | `ak_handle_inference`, `ak_handle_infer_issue/poll` | 1037 / 1041 / 1042 |

### 2.4 Policy & Audit Subsystem

| Component | File | Notes |
|-----------|------|-------|
| Policy structure | `src/agentic/ak_policy.h` | Budget, tool/domain/taint rules |
| Policy load | `src/agentic/ak_policy.c` | JSON parsing (compiled engine) |
| Audit log | `src/agentic/ak_audit.h` | Hash-chained entries |
| Audit append | `ak_audit_append()` | Durable before response |
| Audit verify | `ak_audit_verify()` | Chain verification |

### 2.5 WASM Sandbox / Tool Registry

| Component | File | Notes |
|-----------|------|-------|
| Module struct | `src/agentic/ak_wasm.h` | Bytecode, limits, signature |
| Tool struct | `src/agentic/ak_wasm.h` | Named exports with caps |
| Interpreter | `src/agentic/ak_wasm_interp.c` | Integer-only; rejects float fail-closed |
| Host functions | `src/agentic/ak_wasm_host.c` | Capability-gated host calls |

### 2.6 Canonicalization

| Component | File | Function | Notes |
|-----------|------|----------|-------|
| Path sanitize | `src/agentic/ak_sanitize.h` | `ak_sanitize_path()` | Remove `..`, null bytes |
| URL sanitize | `src/agentic/ak_sanitize.h` | `ak_sanitize_url()` | URL normalization |
| Taint levels | `src/agentic/ak_types.h` | `enum ak_taint` | 0=trusted, 100=untrusted |

::: tip Not in the kernel build
The following exist in `src/agentic/` but are **not** compiled into the kernel (future work / duplicate symbols / unresolved cross-deps): `ak_effects.c`, `ak_posix_route.c`, `ak_policy_v2.c`, `ak_policy_toml.c`, `ak_tool_registry.c`, `ak_agent_ipc.c`, `ak_context.c`, `ak_agentic.c`, and others. Do not treat their features as live.
:::

---

## 3. Security Invariants

1. **INV-DENY**: Deny-by-default is always active after boot
2. **INV-SINGLE**: `ak_dispatch()` is the enforcement gate for Authority syscalls
3. **INV-CANONICAL**: Targets are canonicalized before policy match
4. **INV-BOUNDED**: All buffers have fixed maximum sizes
5. **INV-AUDIT**: Denied operations are logged (rate-limited for high-volume events)
6. **INV-NO-BYPASS**: Tools and the WASM sandbox cannot bypass the kernel for external effects

---

## 4. Test Requirements

### Unit Tests (run on host)
- Pattern matching logic
- JSON policy parsing
- Canonicalization functions
- Decision engine logic

### Integration Tests (run in the unikernel)
- Allow/deny with policy
- Last-deny retrieval

### Smoke Test
- `./tools/smoke.sh` must pass
- Boots the image, runs a test program, verifies deny behavior
