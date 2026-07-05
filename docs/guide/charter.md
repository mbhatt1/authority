# Project Charter

## Mission

Authority is a capability-based security unikernel, built on Nanos, that runs a single untrusted program per VM and enforces kernel-level security on every effect that program performs.

## Tenets

These tenets guide Authority's development:

### 1. Security

Authority aims to be a much more secure system than Linux. It achieves this through several approaches:

- **Unikernel architecture** - Single-process design eliminates multi-user complexity and privilege escalation vectors
- **Minimal kernel** - Reduces attack surface by limiting code
- **Capability-based security** - Fine-grained access control with cryptographic tokens
- **Audit logging** - Hash-chained, tamper-evident logs of all operations

### 2. Minimalism (KISS)

Keep It Simple, Stupid. As Authority is not intended to run on bare metal, we strive to keep the core as simple as possible while maintaining security guarantees.

### 3. Performance

Efficiency in both execution and resource usage, without sacrificing security principles.

## Contributions & Project Roles

All contributions must align with this charter:

- Changes should enhance security, simplicity, or performance (in that priority order)
- Security invariants are non-negotiable
- Code should be minimal and maintainable
- Documentation should be clear and comprehensive

For contribution guidelines, see [Contributing](./contributing.md).
