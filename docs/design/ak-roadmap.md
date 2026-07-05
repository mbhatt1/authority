# Authority Kernel Roadmap

**Version:** 1.0
**Date:** 2026-01-16

This document defines the P0/P1/P2 scope gates and completion criteria for the Authority Kernel migration.

---

## Scope Control Philosophy

- **P0**: Minimal viable deny-by-default. Ship it working.
- **P1**: Hardening and polish. Production-ready.
- **P2**: Advanced features. Future expansion.

Each phase has explicit **completion criteria**. No phase is complete until ALL criteria pass.

---

## P0: Minimal Viable Deny-by-Default

### Goal
A working deny-by-default Authority kernel with:
- Core effects enforced
- POSIX compatibility layer
- Program primitives functional
- Actionable deny UX

### P0 Features

| Feature | Description |
|---------|-------------|
| Policy Bootstrap | JSON policy from initrd or embedded |
| Deny-by-Default | Missing policy = fail closed |
| Dispatch Core | `ak_dispatch()` enforcement working |
| Last Deny | Per-thread last denial with suggestion |
| FS Routing | open/openat routed through AK |
| NET Routing | connect routed through AK |
| DNS Effect | `AK_E_NET_DNS_RESOLVE` with policy gate |
| TOOL_CALL Effect | Tool execution gated |
| WASM_INVOKE Effect | WASM execution gated |
| OUTBOUND Effect | Outbound external request gated |
| SOFT Mode | Default routing mode working |
| Smoke Test | `./tools/smoke.sh` passes |

### P0 Completion Criteria

- [ ] **Policy Bootstrap**: JSON policy loads from `/ak/policy.json` in initrd
- [ ] **Fail Closed**: Missing policy = deny-all with clear console message
- [ ] **Dispatch Core**: All P0 effects route through `ak_dispatch()`
- [ ] **Last Deny**: Denied operations populate last_deny with proper information
- [ ] **FS Routing**: `open()` and `openat()` create `AK_E_FS_OPEN` effect
- [ ] **NET Routing**: `connect()` creates `AK_E_NET_CONNECT` effect
- [ ] **DNS Gate**: DNS resolution creates `AK_E_NET_DNS_RESOLVE` effect
- [ ] **Program Effects**: All program effects (tools, WASM, outbound) enforced
- [ ] **Mode**: SOFT mode is default and functional
- [ ] **Unit Tests**: Pattern matching, JSON parsing, canonicalization all pass
- [ ] **Integration Tests**: allow/deny scenarios pass
- [ ] **Smoke Test**: `./tools/smoke.sh` exits 0

### P0 Non-Goals (Explicitly Deferred)

- TOML policy compilation (P1)
- unlink/rename/mkdir routing (P1)
- bind/listen routing (P1)
- PROC_SPAWN effect (P2)
- HARD mode enforcement (P1)
- Performance tuning (P1)

---

## P1: Hardening and Polish

### Goal
Production-ready Authority Kernel with:
- Complete POSIX routing
- HARD mode
- Performance optimizations

### P1 Features

| Feature | Description |
|---------|-------------|
| FS Complete | unlink/rename/mkdir routed |
| NET Complete | bind/listen routed |
| HARD Mode | Raw syscalls denied |
| TOML Compile | Build-time ak.toml → JSON |
| Ring Buffer | Bounded audit ring for data-plane |
| Rate Limiting | Deny log rate limiting |

### P1 Completion Criteria

- [ ] **FS Complete**: unlink, rename, mkdir create appropriate effects
- [ ] **NET Complete**: bind, listen create effects
- [ ] **HARD Mode**: Setting mode=HARD denies raw effectful syscalls
- [ ] **TOML Compile**: `make` automatically compiles ak.toml → embedded policy
- [ ] **Ring Buffer**: Data-plane events use bounded ring
- [ ] **Rate Limiting**: Deny messages rate-limited appropriately
- [ ] **Performance**: Reasonable overhead for policy decisions

---

## P2: Advanced Features

### Goal
Full process model and advanced isolation.

### P2 Features

| Feature | Description |
|---------|-------------|
| PROC_SPAWN | Process creation effect |
| Exec/Fork | Exec and fork interception |
| Streaming | Streaming tool/outbound-request responses |
| Enhanced Sandbox | Stronger WASM isolation |
| Attestation | Policy attestation for remote verification |

---

## Policy Format (P0 JSON)

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**", "/lib/**"],
    "write": ["/tmp/**"]
  },
  "net": {
    "dns": ["*.example.com", "api.github.com"],
    "connect": [
      "dns:api.github.com:443",
      "ip:10.0.0.0/8:5432"
    ]
  },
  "tools": {
    "allow": ["http_get", "file_read"],
    "deny": ["shell_exec"]
  },
  "budgets": {
    "tool_calls": 100,
    "tokens": 100000,
    "wall_time_ms": 300000
  }
}
```

---

## Compatibility Tiers

### Tier 1: Static/musl (Recommended)
- Statically linked binaries
- Simplest policy requirements
- Profile: `tier1-musl`

### Tier 2: Dynamic/glibc
- Dynamically linked binaries
- Requires additional FS permissions for libraries
- Profile: `tier2-glibc`

### Tier 3: Full Linux Compat
- **Out of scope** for P0/P1
- Future consideration
