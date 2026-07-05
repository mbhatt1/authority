# Fuzz Testing

This page documents the fuzzing infrastructure for Authority.

## Overview

Fuzzing is critical for security-sensitive code like the Authority kernel, where input parsing bugs could lead to:
- Policy bypass vulnerabilities
- Path traversal attacks
- Denial of service
- Memory corruption

## Fuzz Targets

### 1. JSON Policy Parser

**Target:** `fuzz_json_parser.c`

Tests the JSON policy parsing logic with:
- Malformed JSON
- Truncated input
- Deeply nested structures
- Large arrays/strings
- Special characters and escape sequences

### 2. Pattern Matching

**Target:** `fuzz_pattern_match.c`

Tests the glob pattern matcher with:
- Pathological patterns (many `*` characters)
- Unicode and special characters
- Edge cases like empty patterns
- ReDoS-style attack patterns

### 3. Path Canonicalization

**Target:** `fuzz_path_canonicalize.c`

Tests path and sockaddr canonicalization with:
- Path traversal attempts (`../../../etc/passwd`)
- Null byte injection
- Double slashes
- Mixed `.` and `..` components
- Very long paths

## Building

```bash
# Build all fuzz targets
cd test/fuzz
make

# Build specific target
make fuzz_json_parser

# Build standalone debug versions (no fuzzer)
make standalone
```

Requirements:
- clang with libFuzzer support
- AddressSanitizer and UndefinedBehaviorSanitizer

## Running

### Quick Start

```bash
# Run fuzzer for 60 seconds
./fuzz_json_parser corpus/json/ -max_total_time=60

# Run with multiple jobs
./fuzz_json_parser corpus/json/ -jobs=4 -workers=4

# Run with specific seed
./fuzz_json_parser corpus/json/ -seed=12345
```

### Coverage-Guided Fuzzing

```bash
# Run with coverage
./fuzz_json_parser corpus/json/ -max_total_time=300 -use_cmp=1
```

## Corpus Management

### Initial Seeds

The `corpus/` directory contains seed inputs:
- `corpus/json/` - JSON policy examples
- `corpus/pattern/` - Pattern matching test cases
- `corpus/path/` - Path canonicalization inputs

### Generating Corpus

```bash
make corpus
```

### Minimizing Corpus

```bash
make minimize
```

## Interpreting Results

### Crash Files

If a crash is found, a file like `crash-<hash>` is created. To reproduce:

```bash
./fuzz_json_parser crash-abc123
```

### Leak Files

Memory leaks are recorded in `leak-<hash>` files.

### Timeout Files

Inputs causing timeouts are saved as `timeout-<hash>`.

## What Fuzzing Catches

The fuzz targets detect:

1. **Memory Safety Issues**
   - Buffer overflows
   - Use-after-free
   - Uninitialized memory reads

2. **Logic Bugs**
   - Incorrect parsing
   - Pattern matching bypasses
   - Path traversal vulnerabilities

3. **Resource Exhaustion**
   - Exponential backtracking (ReDoS)
   - Excessive memory allocation
   - Infinite loops

## CI Integration

Add to your CI pipeline:

```yaml
fuzz_test:
  script:
    - cd test/fuzz
    - make
    - make corpus
    - ./fuzz_json_parser corpus/json/ -max_total_time=30
    - ./fuzz_pattern_match corpus/pattern/ -max_total_time=30
    - ./fuzz_path_canonicalize corpus/path/ -max_total_time=30
  artifacts:
    paths:
      - test/fuzz/crash-*
      - test/fuzz/leak-*
    when: on_failure
```

## References

- [Bug Checklist](/design/bug-checklist.md) - Known issues found via fuzzing
- [Testing Documentation](/testing/) - All testing resources
