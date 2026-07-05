# AK Base Contract v1

**Version:** 1.0
**Status:** ACTIVE

This document defines the fundamental security contract between the Authority kernel and the untrusted program it runs.

---

## 1. Core Principle: Deny-by-Default

The Authority kernel operates on a **deny-by-default** principle:

> If authorization cannot be resolved for an operation, it is denied.

There are NO implicit permissions. Every effectful operation requires an explicit, resolvable capability.

---

## 2. Boot Policy Load

### 2.1 Problem Statement

Deny-by-default creates a chicken-and-egg problem:
- Policy must be loaded before the program starts
- But loading policy requires file access
- File access requires policy permission

### 2.2 Solution: Pre-Program Policy Load

The Authority kernel loads policy **before** the untrusted program starts:

1. Kernel boots with minimal internal capabilities
2. **Before** the program starts:
   - Kernel reads policy from initrd `/ak/policy.json`
   - Only kernel-internal reads are allowed
   - No untrusted code executes during this phase
3. Policy is validated and installed
4. The program starts with policy already active

### 2.3 Policy Load Order

1. **Embedded Policy** (compile-time): If `CONFIG_AK_EMBEDDED_POLICY` is set, use the embedded policy blob
2. **Initrd Policy**: Read `/ak/policy.json` from initrd
3. **Fail Closed**: If no policy is found:
   - Deny all operations
   - Print a clear console message with the expected location
   - Do NOT start the program

---

## 3. Effect Categories

Effectful operations are categorized. The following taxonomy describes the effect surface and the capability each requires.

### 3.1 Filesystem Effects

| Effect | Description | Required Cap |
|--------|-------------|--------------|
| `AK_E_FS_OPEN` | Open file for read/write | `fs.read` or `fs.write` |
| `AK_E_FS_UNLINK` | Delete file | `fs.write` |
| `AK_E_FS_RENAME` | Rename/move file | `fs.write` |
| `AK_E_FS_MKDIR` | Create directory | `fs.write` |

### 3.2 Network Effects

| Effect | Description | Required Cap |
|--------|-------------|--------------|
| `AK_E_NET_CONNECT` | Outbound connection | `net.connect` |
| `AK_E_NET_DNS_RESOLVE` | DNS resolution | `net.dns` |
| `AK_E_NET_BIND` | Bind to port | `net.bind` |
| `AK_E_NET_LISTEN` | Listen for connections | `net.listen` |

### 3.3 Program Effects

| Effect | Description | Required Cap |
|--------|-------------|--------------|
| `AK_E_TOOL_CALL` | Execute tool | `tools.call` |
| `AK_E_WASM_INVOKE` | Run WASM module | `wasm.invoke` |
| `AK_E_OUTBOUND` | Outbound external request | `infer.model` |

---

## 4. Deny Response Contract

When an operation is denied, the Authority kernel provides:

### 4.1 Immediate Response

- **errno**: Appropriate POSIX error code (`EACCES`, `EPERM`, `ECONNREFUSED`)
- **Rate-limited log**: One-line denial message

### 4.2 Last Deny Information

Available via `AK_SYS_LAST_ERROR`:

```c
struct ak_last_deny {
    ak_effect_op_t op;           // What was attempted
    char target[512];            // Canonical target
    char missing_cap[64];        // What capability was missing
    char suggested_snippet[512]; // Copy-paste policy fix
    u64 trace_id;                // For correlation
    int errno_equiv;             // POSIX errno
    u64 timestamp_ns;            // When denied
};
```

### 4.3 Suggested Snippet Format

Denials include a copy-pasteable JSON policy fragment (JSON is the compiled policy format). For a denied tool:

```json
{ "tools": { "allow": ["the_denied_tool"] } }
```

---

## 5. Audit Contract

### 5.1 Control-Plane Events

Durable logging for:
- Policy changes
- Tool calls
- WASM invocations
- Outbound requests

### 5.2 Data-Plane Events

Bounded ring buffer for high-volume events, rate-limited (no per-event durability barrier).

### 5.3 Audit Entry Format

```c
struct ak_audit_entry {
    u64 timestamp_ns;
    u64 trace_id;
    ak_effect_op_t op;
    char target[256];
    boolean allowed;
    char reason[64];
};
```

---

## 6. Integration Test Requirements

### 6.1 Deny-by-Default Test

```
GIVEN: Minimal policy (empty tool/domain sections)
WHEN:  The program attempts a gated operation
THEN:
  - Operation denied with EACCES
  - last_deny populated with op, canonical target,
    missing_cap, and a valid suggested_snippet
```

### 6.2 Allow Test

```
GIVEN: Policy allowing the operation
WHEN:  The program performs it
THEN:  Operation succeeds
```

### 6.3 Domain Test

```
GIVEN: Policy with an allowed domain pattern
WHEN:  The program targets a matching domain
THEN:  Resolution/connect authorized

WHEN:  The program targets a non-matching domain
THEN:  Denied; last_deny shows the missing domain authorization
```

---

## 7. Version History

| Version | Changes |
|---------|---------|
| 1.0 | Initial version |
