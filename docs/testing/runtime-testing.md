# Runtime Testing

This page documents runtime testing for Authority in the unikernel.

## Overview

Runtime tests verify kernel behavior when running in actual unikernel environments. These tests complement unit tests and fuzzing by testing real system interactions.

## Test Categories

### Unit Tests

Location: `test/unit/`

Individual component testing:
- Capability verification
- Audit log operations
- Policy parsing and matching
- Budget tracking
- Pattern canonicalization

```bash
cd test/unit
make
make test
```

### Integration Tests

Location: `test/runtime/`

System-level testing:
- Full syscall pipelines
- Allow/deny scenarios with policy
- Deny-by-default enforcement
- Mode switching (OFF/SOFT/HARD)
- Last deny retrieval
- Boot sequence verification

```bash
cd test/runtime
make
make test
```

### Smoke Test

The smoke test verifies basic kernel functionality:

```bash
./tools/smoke.sh
```

This test:
- Builds the kernel
- Creates a test image with minimal policy
- Boots the kernel
- Verifies deny-by-default is active
- Checks that last_deny information is available

## Running Tests

### All Tests

```bash
# Run all tests
make -C test/unit test
make -C test/runtime test
./tools/smoke.sh
```

### Specific Test

```bash
# Run capability test
./output/test/unit/bin/ak_capability_test

# Run audit test
./output/test/unit/bin/ak_audit_test

# Run policy test
./output/test/unit/bin/ak_policy_test
```

### With Assertions Enabled

```bash
# Run with maximum assertion checking
AK_ASSERT_LEVEL=3 make -C test/unit test
```

## Test Coverage

All security-critical code areas are tested:

| Component | Unit Tests | Integration | Fuzzing |
|-----------|-----------|-------------|---------|
| Capability System | ✓ | ✓ | - |
| Audit Log | ✓ | ✓ | - |
| Policy Engine | ✓ | ✓ | ✓ |
| Path Canonicalization | ✓ | ✓ | ✓ |
| Effects Authorization | ✓ | ✓ | - |
| Budget Tracking | ✓ | ✓ | - |

## Interpreting Test Results

### Success Output

```
All tests passed: 510/510
```

### Failure Output

```
FAILED: test_capability_verify (seed=12345)
  Expected: VALID_SIGNATURE
  Got: INVALID_SIGNATURE
  Details: HMAC verification failed
```

### Assertion Failures

If assertions are enabled (Level 2+):

```
ASSERTION FAILED: ak_effects.c:142
  Condition: ctx != NULL
  Message: Context must be non-NULL
```

## Writing New Tests

### Unit Test Template

```c
#include "ak_test.h"

void test_my_feature(void) {
    // PRECONDITION: Set up test environment
    heap h = heap_allocate(100 * MB);
    ASSERT_NOT_NULL(h);

    // ACTION: Execute code under test
    int result = my_function(arg);

    // ASSERTION: Verify results
    ASSERT_EQUAL(result, EXPECTED_VALUE);

    // CLEANUP
    heap_deallocate(h);
}

int main(void) {
    RUN_TEST(test_my_feature);
    return 0;
}
```

### Integration Test Template

> Note: the effect API below (`ak_effect_req_t` / `ak_authorize_and_execute`,
> and `ak_policy_v2`) is the legacy request frontend and is **not compiled into
> the kernel**. The enforced path is `ak_syscall_handler` → `ak_dispatch`, which
> runs the six-stage pipeline (validate, anti-replay, capability, policy+budget,
> execute, audit). The example is retained to illustrate policy-decision testing.

```c
#include "ak_integration.h"

void test_full_flow(void) {
    // Load policy
    ak_policy_v2_t *policy = load_test_policy();
    ASSERT_NOT_NULL(policy);

    // Create request
    ak_effect_req_t req = {
        .op = AK_E_FS_OPEN,
        .target = "/allowed/file.txt"
    };

    // Make decision
    ak_decision_t decision;
    ak_authorize_and_execute(&req, &decision);

    // Verify
    ASSERT_TRUE(decision.allow);
}
```

## CI/CD Integration

### GitHub Actions Example

```yaml
test:
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v2
    - name: Run unit tests
      run: cd test/unit && make && make test
    - name: Run integration tests
      run: cd test/runtime && make && make test
    - name: Run smoke test
      run: ./tools/smoke.sh
    - name: Run fuzz tests
      run: cd test/fuzz && make && ./fuzz_json_parser corpus/json/ -max_total_time=60
```

## Performance Testing

Basic performance testing:

```bash
# Measure policy matching latency
./output/test/unit/bin/ak_perf_test

# Profile kernel with trace
make TRACE=1 -C test/unit test
```

## Debugging Failed Tests

### Enable Debug Output

```bash
DEBUG=1 make -C test/unit test
```

### Run Under GDB

```bash
gdb ./output/test/unit/bin/ak_capability_test
```

### Enable Core Dumps

```bash
ulimit -c unlimited
./output/test/unit/bin/ak_capability_test
gdb ./output/test/unit/bin/ak_capability_test core
```

## References

- [Bug Checklist](/design/bug-checklist.md) - Known issues and fixes
- [Fuzz Testing](/testing/fuzz-testing.md) - Fuzzing infrastructure
- [Testing Overview](/testing/) - All testing resources
