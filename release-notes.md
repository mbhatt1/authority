# Authority v2.0.0

A capability-based security unikernel (Nanos fork) that runs a single untrusted
program per VM and enforces its security in the kernel. This release makes the
enforcement pipeline actually run end-to-end, adds working in-kernel external
I/O, corrects the syscall ABI, and reframes the project away from AI/agent
positioning.

## Breaking changes

- **Syscall numbers corrected.** The kernel and the SDK disagreed on the ABI:
  `CALL`/`QUERY` (1028/1031) and `ASSERT`/`RESPOND` (1035/1036) were swapped, so
  an SDK tool call reached the audit-query handler. The kernel now matches the
  SDK/README numbering (`CALL=1031`, `QUERY=1028`, `RESPOND=1035`, `ASSERT=1036`).
  Rebuild clients against the corrected numbers.
- **Renamed to "Authority"** (was "Authority Nanos"); docs reframed accordingly.

## Enforcement now runs

- The real syscall entry point is routed through the six-stage `ak_dispatch`
  pipeline (validate → anti-replay → capability → policy+budget → execute →
  audit). Previously it bypassed every invariant.
- Socket-layer network enforcement (`ak_net_enforce`) is compiled in and
  fail-closed.
- Fixed memory-safety bugs on the syscall path (uninitialized-response free,
  `ak_handle_query` use-after-free, `ak_handle_delete` argument handling).

## Subsystems fixed

- **Capabilities**: implemented the missing wire parse (was an undefined-symbol
  link break), full 16-byte token-id keying, bounded eviction, monotonic key
  ids, key export/import.
- **Audit log**: file-header persistence, per-entry flush watermark, durable
  before response.
- **Budgets**: hard, atomic, overflow-safe; policy limits wired in.
- **Typed heap**: real RFC-6902 JSON-patch apply (writes now mutate), CAS lock,
  snapshot/restore, taint monotonicity.
- **Policy**: JSON parser, tool/URL/taint enforcement, signature verification.

## New: per-call capability ABI + mandatory confinement

The syscall ABI carries a per-call capability token in `arg5`; the root context
holds an admin capability; a delegated grant store is enforced. Authorization is
four-way and fail-closed (token → root → delegated → deny).

## New: working external I/O

- **Async in-kernel HTTP(S) transport** (`ak_transport`, `klib/ak_https`) over
  the network stack. External I/O is issued non-blocking and retrieved by
  polling, which fits the unikernel's cooperative runloop — live-verified in
  QEMU (HTTP and TLS 1.2 both return real responses).
- **Async inference syscalls** `AK_SYS_INFER_ISSUE` (1041) / `AK_SYS_INFER_POLL`
  (1042): a program issues an enforced outbound request and polls for the
  result. Live-verified end to end (capability + policy + budget + audit, then
  a real response returned).
- **Integer-only WASM tool sandbox** (`ak_wasm_interp`): validates and executes
  an integer bytecode subset; the kernel is built `-mno-sse`, so float/malformed
  modules are rejected fail-closed.

## Build

- The version stamp (`gitversion`) now works in git worktrees, exported
  tarballs, and checkouts without a `.git` (was a hard build failure outside a
  normal clone).
- riscv64 on macOS uses the cross `gcc` (Apple clang has no riscv backend);
  x86_64/aarch64 unchanged.

## Verified

- x86_64 and aarch64 kernels build and link clean; the `ak_https` klib builds
  both.
- 12 host unit-test suites pass.
- Live QEMU boots confirm the enforcement pipeline, typed heap, deny-by-default
  tool policy, hash-chained audit, in-kernel HTTP/HTTPS, and the enforced
  program→endpoint→response round trip.

## Known limitations

- External I/O syscalls are async issue/poll; a synchronous blocking call cannot
  complete in the unikernel's cooperative scheduler.
- TLS to hosts that require TLS 1.3 or SNI needs a fuller mbedTLS than the
  vendored 2.28; TLS 1.2 endpoints work.
- A full riscv64 build on macOS additionally needs a riscv toolchain whose `ld`
  supports `-shared` (for the vdso); Linux CI builds riscv64 end to end.
- The security guarantees hold for programs confined to the syscall (or
  integer-WASM) interface; a single-address-space unikernel is not a defense
  against arbitrary native code that reads kernel memory directly.
