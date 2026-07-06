# Authority Python SDK

The Authority SDK for writing programs that run under Authority, a
capability-based security unikernel. Every operation goes through the kernel,
where it is checked against the caller's cryptographic capability, evaluated
against a deny-by-default policy and hard resource budgets, and recorded in a
tamper-evident audit log.

## Installation

```bash
pip install authority-nanos
```

## Quick Start

```python
from authority_nanos import AuthorityKernel

# Simulation mode - works without a kernel
with AuthorityKernel(simulate=True) as ak:
    # Allocate a typed object
    handle = ak.alloc("counter", b'{"value": 0}')

    # Read it back
    data = ak.read(handle)
    print(data)  # b'{"value": 0}'

    # Update with JSON Patch
    ak.write(handle, b'[{"op": "replace", "path": "/value", "value": 42}]')

# Real mode - requires a running kernel
with AuthorityKernel() as ak:
    # Same API, but operations go through the kernel
    handle = ak.alloc("counter", b'{"value": 0}')
```

## Features

- **Simulation Mode**: Develop and test against the API without running the kernel
- **Typed Heap**: Allocate, read, write, and delete versioned typed objects
- **Authorization**: Capability-checked, policy-controlled access to resources
- **Tool Execution**: Run integer-only WASM tools in a sandbox
- **Outbound Requests**: Issue capability-gated external requests, charged against the budget
- **Budget Queries**: Read the kernel's hard resource budgets (tokens, tool calls, wall time, bytes)
- **Audit Log**: Read the tamper-evident, hash-chained audit trail

## Documentation

- [Getting Started](https://mbhatt1.github.io/authority/getting-started/)
- [API Reference](https://mbhatt1.github.io/authority/api/)
- [Security Model](https://mbhatt1.github.io/authority/security/)

## License

Apache 2.0
