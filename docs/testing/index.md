# Testing Documentation

This section documents the testing infrastructure for Authority.

## Overview

Authority uses a testing strategy covering:

- **Unit Tests** - Test individual components in isolation
- **Integration Tests** - Test system behavior across components
- **Fuzzing Tests** - Fuzz test API boundaries and policy parsing
- **Runtime Tests** - Test kernel behavior in actual unikernel
- **Smoke Tests** - Basic sanity checks that kernel boots and runs

## Quick Links

- **[Fuzz Testing](./fuzz-testing.md)** - Fuzzing infrastructure and corpus
- **[Runtime Testing](./runtime-testing.md)** - Running tests in the unikernel

## Running Tests

### Unit Tests
```bash
cd test/unit
make && make test
```

### Fuzz Tests
```bash
cd test/fuzz
make fuzz
```

### Runtime Tests
```bash
cd test/runtime
make && make test
```

### Smoke Test
```bash
./tools/smoke.sh
```

## Test Coverage

All security-critical code has:
- Unit tests for edge cases
- Fuzzing for API boundaries
- Integration tests for real-world scenarios
- Assertion checks at invariant enforcement points

See [Bug Checklist](/design/bug-checklist.md) for known issues and verification procedures.
