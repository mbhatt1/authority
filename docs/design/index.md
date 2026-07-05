# Design & Specifications

This section contains in-depth design documents, threat models, and technical specifications for the Authority kernel and the Authority unikernel.

## Core Documentation

- **[Authority Kernel Design](./ak-design.md)** - Design of the Authority kernel subsystem
- **[Authority Kernel Base Contract](./ak-base-contract.md)** - The fundamental invariants and API contract
- **[Authority Kernel Overview](./agentic-kernel.md)** - The security layer powering the Authority unikernel

## Security & Threat Modeling

- **[Threat Model](./ak-threat-model.md)** - Threat analysis and mitigations
- **[Security Invariants](./invariants.md)** - The four guarantees Authority enforces

## Development

- **[Authority Kernel Roadmap](./ak-roadmap.md)** - Planned features for the Authority kernel
- **[Bug Checklist](./bug-checklist.md)** - Verification procedures

## Quick Reference

The Authority kernel enforces **four security invariants**, all in `ak_dispatch()` (`src/agentic/ak_syscall.c`):

1. **INV-1: No-Bypass** - The program reaches external effects only through the Authority syscalls (1024+)
2. **INV-2: Capability** - Every effectful syscall resolves a valid, non-revoked capability
3. **INV-3: Budget** - Resource consumption never exceeds declared budgets
4. **INV-4: Log Commitment** - Every committed operation appends a hash-chained audit entry, made durable before the response
