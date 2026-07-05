# Frequently Asked Questions

## General Questions

### What is Authority?

Authority is a **fork of [Nanos](https://github.com/mbhatt1/nanos)** that adds the Authority kernel — a capability-based security layer that runs a single untrusted program per VM and enforces kernel-level security on every effect that program performs.

### How is Authority different from standard Nanos?

Authority extends Nanos with:
- Capability-based security with unforgeable HMAC-SHA256 tokens
- A hash-chained, tamper-evident audit log
- A deny-by-default policy engine for filesystem, network, and tool access
- Hard resource budgets enforced before admission
- An integer-only WASM sandbox for tool execution
- A typed heap with versioned objects and CAS semantics
- An outbound-request handler that gates external I/O behind a capability

### Why run an untrusted program on Authority?

**Containment.** A single untrusted program runs in its own VM, and the kernel mediates everything it does:
- Deny-by-default — every effect requires an explicit policy rule and capability
- Complete audit trail for compliance and incident analysis
- Budget enforcement to bound resource and cost consumption
- Fail-closed: unknown operations are denied before execution, not logged after

**Isolation.** The single-process unikernel design eliminates:
- Privilege-escalation attacks (no users, no sudo, no setuid)
- Container-escape vulnerabilities
- Unnecessary attack surface (a minimal syscall set)

## Architecture Questions

### Is 32-bit supported?

No, and there's no intention to add support. Authority focuses on modern 64-bit architectures (x86_64 and ARM64).

### Do you support multiple processes?

No. Authority is a **single-process unikernel** that runs exactly one program per VM. To run more than one workload, deploy multiple VMs.

### Do you support multiple threads?

**Yes.** Authority fully supports multi-threading within the single process.

### What platforms are supported?

**x86_64 (Intel/AMD)**
- Full production support
- KVM acceleration on Linux, HVF on macOS

**ARM64 (aarch64)**
- Full production support
- Raspberry Pi 4, AWS Graviton, Azure Ampere

## Enforcement Questions

### How is every syscall enforced?

Every effectful syscall enters through `ak_syscall_handler`, which calls `ak_dispatch()`. `ak_dispatch()` runs a fixed six-stage pipeline before any effect executes:

1. **Request validation** — the request structure is parsed and validated
2. **Anti-replay** — replayed or stale requests are rejected
3. **Capability** — the HMAC-SHA256 capability is verified
4. **Policy + budget** — the operation is checked against the deny-by-default policy and remaining budgets
5. **Execute** — the effect is performed
6. **Audit** — the request and result are appended to the hash-chained audit log

### How does external I/O work?

Outbound I/O (HTTP requests, tool calls) uses an asynchronous issue/poll model. The program issues a request via `AK_SYS_INFER_ISSUE`, which is enforced synchronously (validation, capability, policy, budget) on the issue path. The actual I/O runs on the kernel runloop (`ak_https_issue`/`ak_https_poll`), and the program later retrieves the result with `AK_SYS_INFER_POLL`. There is no synchronous, in-kernel blocking external I/O.

### What are the syscall numbers?

| Syscall | Number |
|---------|--------|
| `AK_SYS_READ` | 1024 |
| `AK_SYS_ALLOC` | 1025 |
| `AK_SYS_WRITE` | 1026 |
| `AK_SYS_DELETE` | 1027 |
| `AK_SYS_QUERY` | 1028 |
| `AK_SYS_BATCH` | 1029 |
| `AK_SYS_COMMIT` | 1030 |
| `AK_SYS_CALL` | 1031 |
| `AK_SYS_SPAWN` | 1032 |
| `AK_SYS_SEND` | 1033 |
| `AK_SYS_RECV` | 1034 |
| `AK_SYS_RESPOND` | 1035 |
| `AK_SYS_ASSERT` | 1036 |
| `AK_SYS_INFERENCE` | 1037 |
| `AK_SYS_BUDGET_STATUS` | 1038 |
| `AK_SYS_BUDGET_HISTORY` | 1039 |
| `AK_SYS_BUDGET_BREAKDOWN` | 1040 |
| `AK_SYS_INFER_ISSUE` | 1041 |
| `AK_SYS_INFER_POLL` | 1042 |

## Security Questions

### What are the security invariants?

Authority enforces four foundational guarantees:

- **INV-1**: Every external effect occurs through a kernel-mediated syscall
- **INV-2**: Every effectful syscall requires a valid capability
- **INV-3**: Resource consumption never exceeds declared budgets
- **INV-4**: All state changes are logged with hash chaining

### How do capabilities work?

Capabilities are **unforgeable HMAC-SHA256 signed tokens** granting specific permissions:
- Type (Net, FS, Tool, Outbound Request)
- Resource pattern
- Allowed methods
- Time-to-live
- Rate limits

### Are audit logs tamper-proof?

**Yes.** The audit log uses cryptographic hash chaining. Any modification breaks the chain and is immediately detectable.

### Can the program escape the sandbox?

**No.** Multiple layers of isolation apply:
- Unikernel boundary (single-process design)
- Capability enforcement (cryptographic verification on every effect)
- Integer-only WASM sandbox for tools (no direct system access; floats rejected)
- Network isolation (deny-by-default, policy-controlled)

## Deployment Questions

### What hypervisors are supported?

- **KVM** (Linux) — recommended
- **HVF** (macOS) — for local development
- **QEMU** (TCG mode) — software emulation
- **Xen** — experimental
- **Hyper-V** (Windows) — experimental

### How do I deploy to cloud providers?

Use the [authority CLI](https://authority.dev), which supports AWS, GCP, Azure, DigitalOcean, Vultr, and more.

### Can I run on edge devices?

**Yes**, especially ARM devices:
- Raspberry Pi 4
- NVIDIA Jetson
- AWS Graviton edge instances

## Development Questions

### How do I build from source?

```bash
# Clone
git clone https://github.com/nanovms/authority-nanos.git
cd authority-nanos/nanos

# Build for x86_64
make PLATFORM=pc CROSS_COMPILE=x86_64-elf- kernel

# Build for ARM64
make PLATFORM=virt ARCH=aarch64 CROSS_COMPILE=aarch64-elf- kernel
```

### How do I debug a denied operation?

1. **Audit log analysis**: Query the audit log for the run
2. **Last error syscall**: Call `AK_SYS_LAST_ERROR` for denial details
3. **Record mode**: Run with `AK_RECORD=1` to accumulate policy suggestions

### Can I contribute?

**Yes!** See [CONTRIBUTING.md](https://github.com/nanovms/authority-nanos/blob/main/nanos/CONTRIBUTING.md).

Priority areas:
- Security (policy language, formal verification)
- Enforcement pipeline and capability system
- Tools (WASM runtime, policy validators)
- Monitoring (metrics, alerting)

## Licensing & Support

### What license is Authority under?

**Apache License 2.0** (open source)
- Commercial use allowed
- Modification allowed
- Distribution allowed
- Patent grant included

### Where do I get help?

**Community Support** (free):
- [Discussion Forum](https://forums.nanovms.com/)
- [GitHub Issues](https://github.com/nanovms/authority-nanos/issues)

**Commercial Support** (paid):
- 24/7 security incident response
- Priority bug fixes
- Custom policy development
- [Contact NanoVMs](https://nanovms.com/services/subscription)

## More Questions?

- Check the [architecture documentation](/architecture/)
- Read the [security invariants](/security/invariants)
- See the [API reference](/api/)
