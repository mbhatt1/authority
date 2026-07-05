# Tools & Utilities

This section documents tools and utilities for developing and debugging Authority.

## Overview

Authority includes several tools to help with development, testing, and debugging.

## Quick Links

- **[Trace Utilities](./trace-utilities.md)** - Kernel tracing and analysis tools
- **[Scripts](./scripts.md)** - Build and automation scripts

## Available Tools

### Trace Utilities (`tools/trace-utilities/`)

Tools for analyzing kernel trace logs:
- Parse and decode trace records
- Filter trace events by type
- Generate flame graphs
- Analyze timing information

### Build Scripts (`scripts/`)

Automation scripts for development:
- Build configuration helpers
- Testing utilities
- Release management
- Policy compilation

### Release Tools

Release management utilities:
- Changelog generation
- Version bumping
- Binary packaging

## Getting Started

1. Start with [Trace Utilities](./trace-utilities.md) for debugging kernel behavior
2. Review [Scripts](./scripts.md) for build automation
3. Check `Makefile` for common development commands

## Contributing Tools

When adding new tools:
1. Document in the appropriate section
2. Add usage examples
3. Update the `tools/` README
4. Consider adding to CI/CD pipeline
