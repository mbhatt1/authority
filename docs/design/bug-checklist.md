# Verification Checklist

This document describes the verification procedures for the Authority kernel and the hardening classes covered by its test suite.

Tracked, individual bug writeups live under [`docs/bugs/`](/bugs/BUG-001-bitmap-heap-overflow). This page is a checklist, not an open-issue tracker.

---

## Hardening Classes Covered

The following defensive properties are enforced in the compiled kernel and exercised by the tests below. They are historical hardening areas, not open defects:

| Area | Property | Verified by |
|------|----------|-------------|
| Integer overflow | Numeric parsing and budget accounting use overflow-safe arithmetic | Fuzz + unit tests |
| Path traversal | Lexical canonicalization; `..` and null bytes rejected before matching | Fuzz + unit tests |
| TOCTOU | Canonical target computed once on entry and reused | Unit tests |
| Bounds | Buffers sized against `AK_MAX_*` constants | ASAN + fuzz |
| Escape sequences | Single canonical form before policy matching | Unit tests |
| Struct validation | Magic fields on critical structures (`AK_CTX_MAGIC`, `AK_CAP_MAGIC`, `AK_REQ_MAGIC`, `AK_POLICY_MAGIC`) | Assertions |

---

## Verification Checklist

### Pre-Merge

- [ ] Unit tests pass at assertion level 3
- [ ] Fuzz targets pass on malformed inputs
- [ ] Integer overflow tests pass
- [ ] Path traversal tests pass
- [ ] TOCTOU tests pass

### Per-Commit

- [ ] `make test` passes
- [ ] `./tools/smoke.sh` passes
- [ ] No new compiler warnings

### Pre-Release

- [ ] Security review completed
- [ ] Threat model reviewed
- [ ] Invariant coverage verified

---

## Testing Infrastructure

### Unit Tests

Location: `test/unit/ak_*.c`

```bash
cd test/unit
make
./bin/ak_capability_test
./bin/ak_audit_test
./bin/ak_policy_test
```

### Integration Tests

Location: `test/runtime/`

```bash
cd test/runtime
make
./ak_integration_test
```

### Fuzzing

Location: `test/fuzz/`

```bash
cd test/fuzz
make fuzz
```

### Smoke Test

```bash
./tools/smoke.sh
```

Verifies the kernel builds, boots to the program, enforces deny-by-default, and exposes last-deny information.

---

## Assertion Levels

| Level | NDEBUG | Description |
|-------|--------|-------------|
| 1 | Yes | Critical only (NULL checks, security invariants) |
| 2 | No | Normal (+ bounds, state validation) |
| 3 | No | Full (+ debug assertions, expensive checks) |

```bash
export AK_ASSERT_LEVEL=3
make test
```

---

## Recommendations

1. **Enable assertions in CI** — run with `AK_ASSERT_LEVEL=3`
2. **Continuous fuzzing** — integrate the fuzz targets into CI
3. **Regular reviews** — schedule a security review each major release
4. **Invariant assertions** — keep `AK_ASSERT_INV*()` calls at enforcement points

---

## References

- [Security Invariants](./invariants.md)
- [Threat Model](./ak-threat-model.md)
- [Authority Kernel Design](./ak-design.md)
