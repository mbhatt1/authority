# Authority — Frequently Asked Questions

## General

### What is Authority?

Authority is a capability-based security unikernel, built on Nanos. It runs a
single untrusted program per virtual machine and enforces that program's
security in the kernel: every effectful operation must be authorized by a
cryptographic capability, stays within hard resource budgets, passes a
deny-by-default policy, and is recorded in a tamper-evident audit log — before
the effect executes.

### How is Authority different from standard Nanos?

Authority extends Nanos with the **Authority Kernel** subsystem, which adds:

- Capability-based access control with HMAC-SHA256 tokens
- A hash-chained, tamper-evident audit log
- A typed heap with versioned objects and compare-and-swap semantics
- A deny-by-default policy engine (filesystem / network / tool)
- Hard, atomic resource budgets
- An integer-only WASM sandbox for tool execution
- An async outbound-request transport (HTTP/HTTPS over the network stack)

It keeps Nanos's core model: one program per VM, no users, no shell.

### Why run a program under Authority?

When a program performs actions with real-world consequences — writing files,
opening network connections, executing tools — you want the kernel to constrain
it, not trust it. Authority provides cryptographic authorization (not
configuration you hope is correct), a tamper-evident record of everything that
happened, fail-closed defaults, and no privilege escalation surface.

---

## Architecture

### Is 32-bit supported?

No. Authority targets 64-bit architectures (x86_64 and ARM64; RISC-V is in the
source tree).

### Do you support multiple processes?

No — Authority is a single-process unikernel. For multiple workloads, run
multiple VMs, one program each; that provides stronger isolation than processes.

### Do you support multiple threads?

Yes. The single program can be multi-threaded and use multiple cores.

### What platforms are supported?

- **x86_64** — KVM on Linux, HVF on macOS, QEMU/TCG for emulation.
- **ARM64 (aarch64)** — builds and runs; Graviton, Ampere, Raspberry Pi 4.
- **RISC-V 64** — source present; builds on Linux toolchains.

---

## Security

### What are the security invariants?

The kernel enforces four invariants inside the syscall dispatch path
(`ak_syscall_handler` → `ak_dispatch`), before any effect executes:

- **INV-1 (no bypass):** the program reaches external effects only through the
  Authority syscalls (1024+).
- **INV-2 (capability):** every effectful syscall must be authorized by a valid,
  non-revoked capability whose scope subsumes the request.
- **INV-3 (budget):** admission control rejects operations that would exceed a
  declared budget; budgets are hard, atomic, and overflow-safe.
- **INV-4 (log commitment):** each committed operation appends a hash-chained
  audit entry, made durable before the response is returned.

### How do capabilities work?

A capability is an unforgeable HMAC-SHA256 token that grants a specific,
scoped, time-limited, rate-limited authority, bound to a run:

```c
typedef struct ak_capability {
    ak_cap_type_t type;       // NET, FS, TOOL, SECRETS, HEAP, IPC, ...
    u8  resource[256];        // pattern, e.g. "https://*.example.com/*"
    u8  methods[8][32];       // allowed operations
    u64 issued_ms;
    u32 ttl_ms;               // auto-expires
    u32 rate_limit;
    u8  run_id[16];           // bound to a specific run
    u8  mac[32];              // HMAC-SHA256
} ak_capability_t;
```

Authorization for a syscall is a per-call token (passed in the syscall's
`arg5`), a delegated grant held in the context, or the root context's admin
capability. The signing key is generated per boot and never leaves the kernel.
Verification uses constant-time comparison; revocation keys on the full 16-byte
token id and is checked on every use.

### Is the audit log tamper-proof?

The log is tamper-evident: `hash[n] = SHA256(hash[n-1] || entry[n])`. Any change
to a past entry invalidates every subsequent hash. Entries are made durable
before a response is returned (INV-4). The log survives restart via an on-disk
file header and per-entry flush watermark.

### Can the program escape the sandbox?

The unikernel boundary eliminates whole classes of escape (no users, no other
processes, no container runtime). Within that boundary, every Authority syscall
is capability-checked, policy-gated, and budgeted; tool execution runs in an
integer-only WASM interpreter with explicit capability passing; network access
is limited to what a capability permits, through the kernel's network stack, and
is audited. Note the substrate limit: because a unikernel is a single address
space, these guarantees hold for programs confined to the Authority syscall (or
WASM) interface — the model is not a defense against arbitrary native code that
reads kernel memory directly.

---

## Development

### How do I build from source?

```bash
# Requires a cross toolchain (e.g. x86_64-elf-gcc) and nasm.
make PLATFORM=pc CROSS_COMPILE=x86_64-elf- kernel
# ARM64:
make PLATFORM=virt ARCH=aarch64 CROSS_COMPILE=aarch64-elf- kernel
```

Host-side unit tests build under `test/unit`. See `docs/getting-started/`.

### Can I contribute?

Yes — see [CONTRIBUTING.md](CONTRIBUTING.md). For significant changes, open an
issue first.

---

## Comparison

### Authority vs. containers?

| | Authority | Containers |
|---|---|---|
| Isolation | Unikernel (VM-level) | cgroups / namespaces |
| Attack surface | Minimal | Full Linux syscall surface |
| Security model | Capabilities + audit | Users / permissions |
| Audit | Built-in hash chain | DIY |

Use Authority when kernel-enforced authorization and a tamper-evident audit
trail are the point; use containers when ecosystem tooling matters more than
isolation.

---

## Licensing

Apache-2.0. Commercial use, modification, and distribution allowed; patent grant
included; no copyleft.

For security issues, contact the maintainers privately rather than opening a
public issue (see [SECURITY.md](SECURITY.md)).
