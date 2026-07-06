# Build Scripts and Utilities

This page documents build scripts and automation utilities for Authority development.

## Overview

The `scripts/` directory contains utility scripts for code formatting, building, and development automation.

## Code Formatting

### apply-format

Automatically formats code according to the project's style guide.

#### Installation

```bash
# macOS
brew install clang-format-hooks

# Linux
apt-get install apply-format
```

#### Usage

Format modified files:
```bash
scripts/apply-format
```

This reformats only the code that `git diff` would show and prints the diff to the terminal.

#### Options

For more options, see the [clang-format-hooks documentation](https://github.com/barisione/clang-format-hooks)

#### Applying Changes

To apply the formatting changes:

```bash
scripts/apply-format >> changes.patch
git apply changes.patch
```

Or apply interactively:

```bash
scripts/apply-format | git apply
```

## Common Development Tasks

### Build with Tracing

```bash
make TRACE=ftrace TARGET=<target> run
```

### Run Tests

```bash
make -C test/unit test
make -C test/runtime test
./tools/smoke.sh
```

### Run Fuzz Tests

```bash
cd test/fuzz
make
./fuzz_json_parser corpus/json/ -max_total_time=60
```

### Clean Build

```bash
make clean && make PLATFORM=pc
```

## Policy Compilation

Policy TOML files are automatically compiled to JSON at build time:

```bash
# Build compiles ak.toml -> policy.json
make PLATFORM=pc
```

## Release Management

Release process steps:

1. Create [GitHub release](https://github.com/mbhatt1/authority/releases)
2. Build on both Linux and macOS
3. Update version files
4. Run release script:
   ```bash
   ./release.sh
   ```

See [Release Notes](/guide/release-notes.md) for detailed process.

## Smoke Test

Basic verification that kernel boots and denies unpermitted operations:

```bash
./tools/smoke.sh
```

This:
- Builds the kernel
- Creates test image with minimal policy
- Boots and verifies deny-by-default
- Checks last_deny information

## References

- [Testing Documentation](/testing/) - Test infrastructure
- [Trace Utilities](/tools/trace-utilities.md) - Performance analysis tools
- [Contributing Guide](/guide/contributing.md) - Code contribution standards
