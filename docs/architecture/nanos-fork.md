# Fork Relationship

Authority is a **fork of [Nanos](https://github.com/mbhatt1/nanos)** — the original unikernel developed by [NanoVMs](https://nanovms.com).

## What is Nanos?

Nanos is a production-quality unikernel designed to run single applications with minimal overhead:

- **Single-process**: No fork, exec, or multiple users
- **Minimal syscalls**: Only what applications need
- **Fast startup**: Boots in milliseconds
- **Small footprint**: ~20MB base memory
- **Cross-platform**: x86_64 and ARM64

## What Authority Adds

Authority extends Nanos with the **Authority Kernel** subsystem:

| Feature | Nanos | Authority |
|---------|-------|-----------------|
| Unikernel base | Yes | Yes |
| Cross-platform | Yes | Yes |
| Capability-based security | No | Yes |
| Deny-by-default policy | No | Yes |
| Audit logging | No | Yes (hash-chained) |
| Budget enforcement | No | Yes |
| Gated outbound requests | No | Yes |
| Tool sandboxing | No | Yes (integer-only WASM) |

## Repository Structure

```
authority-nanos/
├── nanos/                   # Nanos kernel (with AK additions)
│   └── src/
│       └── agentic/        # Authority Kernel implementation
├── docs/                    # Documentation (this site)
├── IMPLEMENTATION_SPEC.md   # AK technical specification
└── SECURITY_INVARIANTS.md   # Security guarantees
```

## Upstream Compatibility

Authority maintains **full compatibility** with upstream Nanos:

- All existing Nanos applications run unchanged (with `AK_MODE_OFF`)
- Standard ops workflows continue to work
- No breaking changes to the POSIX compatibility layer

## The Authority Kernel Files

The Authority Kernel is implemented in `nanos/src/agentic/`:

```
src/agentic/
├── ak_config.h          # Feature toggles and limits
├── ak_types.h           # Core type definitions
├── ak_syscall.c         # Syscall handler + ak_dispatch() pipeline (1024+)
├── ak_policy.c          # Policy loading and evaluation
├── ak_audit.c           # Hash-chained audit log (durable before response)
├── ak_capability.c      # HMAC token verification (per-boot key)
├── ak_budget.c          # Hard budget admission control
├── ak_wasm_interp.c     # Integer-only WASM subset interpreter
├── ak_inference.c       # Gated outbound request handler (issue/poll)
└── README.md            # Component documentation
```

> `ak_effects.c` also lives in this directory but is **not compiled into the
> kernel** — it is legacy code excluded from the build. The compiled
> enforcement path is `ak_syscall_handler` → `ak_dispatch` in `ak_syscall.c`.

## Build Configuration

The Authority Kernel is enabled by default:

```makefile
# In kernel.mk
CFLAGS += -DCONFIG_AK_ENABLED=1
```

The kernel is built `-mno-sse` (no floating point) so the integer-only WASM
interpreter and the rest of the Authority Kernel remain float-free.

To build without Authority Kernel (pure Nanos):

```bash
make kernel CONFIG_AK_ENABLED=0
```

## Contributing Back to Nanos

Improvements to the core Nanos kernel (not Authority Kernel specific) should be contributed upstream:

1. Identify if the change is AK-specific or general Nanos
2. For general changes, submit PR to [nanovms/nanos](https://github.com/mbhatt1/nanos)
3. For AK-specific changes, submit PR to Authority

## Why Fork?

Forking allows Authority to:

1. **Add capability-based enforcement** that isn't needed for general-purpose unikernels
2. **Keep the security subsystem self-contained** without burdening the main Nanos project
3. **Move fast** on enforcement features while Nanos maintains stability
4. **Stay compatible** by regularly merging upstream changes

## Syncing with Upstream

Authority periodically syncs with upstream Nanos:

```bash
# Add upstream remote
git remote add upstream https://github.com/mbhatt1/nanos.git

# Fetch upstream changes
git fetch upstream

# Merge into authority-nanos
git merge upstream/master
```

Most merges are clean since Authority Kernel code lives in a separate directory (`src/agentic/`).
