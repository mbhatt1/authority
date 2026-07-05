# Authority Python SDK Examples

This directory contains example scripts demonstrating the Authority Python SDK. Each example is a small program that runs under Authority and exercises one part of the kernel's API.

## Quick Start

All examples run in **simulation mode by default** - no kernel build or setup required.

```bash
# Install the SDK
pip install authority-nanos

# Run any example immediately
python3 examples/00_hello_world.py
python3 examples/01_heap_operations.py
```

## Simulation Mode vs Real Kernel

### Simulation Mode (Default)

Examples run in simulation mode by default, which:

- **Works out of the box** - No kernel build, no configuration
- **Full API coverage** - All SDK methods work correctly
- **In-memory implementation** - Heap, audit log, and authorization are all simulated
- **Good for learning** - Understand the API without infrastructure setup
- **CI-friendly** - Tests run anywhere Python runs

```bash
# These run in simulation mode
python3 examples/00_hello_world.py
python3 examples/01_heap_operations.py
```

### Real Kernel Mode

To run against the actual Authority kernel, use the `--real` or `--kernel` flag:

```bash
# Run with real kernel
python3 examples/01_heap_operations.py --real
python3 examples/02_authorization.py --kernel
```

Requirements for real kernel mode:
- Built Authority kernel (`make -j$(nproc)`)
- `libak` available in the library path
- Kernel running or accessible

## Examples

### 0. Hello World (`00_hello_world.py`)

The simplest possible example: allocates one object, reads it, prints success.
Under 30 lines of code with clear comments.

```bash
python3 examples/00_hello_world.py
```

### 1. Basic Heap Operations (`01_heap_operations.py`)

Demonstrates typed-heap memory management with allocation, reading, and modification:

- **Allocate**: Create typed objects in the kernel's heap
- **Read**: Retrieve object data
- **Write**: Modify objects using JSON Patch (RFC 6902)
- **Delete**: Free allocated objects

```bash
python3 examples/01_heap_operations.py
```

### 2. Authorization and Policy (`02_authorization.py`)

Demonstrates capability-based authorization checks:

- **Check authorization** for protected operations
- **File I/O** gated by policy
- **Outbound requests** gated by policy
- **Simulate denials** for testing the deny-by-default path

```bash
python3 examples/02_authorization.py
```

### 3. WASM Tool Execution (`03_tool_execution.py`)

Demonstrates sandboxed execution of WASM tools. Tool execution is integer-only
(the WASM sandbox is built with `-mno-sse`):

- **Execute WASM tools** in an isolated sandbox
- **Pass arguments** to tools via JSON
- **Receive results** with capability-based access control
- Built-in simulated tools: `add`, `concat`

```bash
python3 examples/03_tool_execution.py
```

### 4. Outbound Requests (`04_inference.py`)

Demonstrates a capability-gated outbound request. External effects are mediated
by the kernel: the request is only issued if policy and the caller's capability
permit it, and it is subject to the resource budget.

- **Issue an outbound request** through the kernel
- **Policy enforcement** on the request target
- **Simulated responses** in simulation mode

```bash
python3 examples/04_inference.py
```

### 5. Audit Logging (`05_audit_logging.py`)

Demonstrates the tamper-evident audit log:

- **Read audit entries** - Append-only, hash-chained records
- **Query the log** - Filter by event type, actor, timestamp
- **Custom events** - Record application-specific events
- Fully functional in simulation mode

```bash
python3 examples/05_audit_logging.py
```

## What Simulation Mode Does

In simulation mode, the SDK uses an in-memory implementation:

| Feature | Simulation Behavior |
|---------|---------------------|
| Heap (alloc/read/write/delete) | Full implementation with versioning |
| Authorization | Default allow-all, configurable denials |
| Tool calls | Simulated `add` and `concat` tools |
| Outbound requests | Returns simulated responses |
| Audit log | In-memory, queryable log |
| File I/O | Passes through to the real filesystem |

### Configuring Simulation Behavior

In simulation mode, you can test policy denials:

```python
with AuthorityKernel(simulate=True) as ak:
    # Deny specific operations
    ak.deny_operation("write")
    ak.deny_target("/etc/shadow")

    # Check authorization (will fail)
    if not ak.authorize("read", "/etc/shadow"):
        print("Access denied as expected")

    # Reset to allow all
    ak.allow_all()
```

## Running Examples

### Using run_example.sh

The helper script runs examples with the correct setup:

```bash
# Run in simulation mode (default)
./examples/run_example.sh 0
./examples/run_example.sh 1

# Run all examples
./examples/run_example.sh all

# Run with real kernel
./examples/run_example.sh 1 --real
```

### Direct Python Execution

```bash
# Install SDK first
pip install authority-nanos

# Or install from source
pip install -e sdk/python/

# Run examples
python3 examples/00_hello_world.py
python3 examples/01_heap_operations.py --real  # For real kernel
```

## Expected Output

### Simulation Mode Output

```
=== Heap Operations Example (SIMULATION mode) ===

[+] Connected to Authority kernel
[+] Allocated counter with handle: Handle(id=1, version=0)
[+] Read counter: {'value': 0, 'name': 'counter'}
[+] Updated counter to version: 1
[+] Updated counter: {'value': 42, 'name': 'counter'}
[+] Deleted counter handle

[+] All heap operations completed successfully!
```

### Real Kernel Output

```
=== Heap Operations Example (REAL KERNEL mode) ===

[+] Connected to Authority kernel
[+] Allocated counter with handle: Handle(id=0x7f2a8c0000, version=0)
...
```

## Error Handling

Examples demonstrate common error-handling patterns:

- **AuthorityKernelError**: Base exception for kernel errors
- **OperationDeniedError**: Policy denied the operation
- **NotFoundError**: Resource not found
- **InvalidArgumentError**: Bad argument to a syscall

## Troubleshooting

### "ModuleNotFoundError: No module named 'authority_nanos'"

Install the SDK:
```bash
pip install authority-nanos
# or
pip install -e sdk/python/
```

### "libak.so not found" (Real Kernel Mode Only)

Build the kernel and set the library path:
```bash
make -j$(nproc)
export LD_LIBRARY_PATH=output/platform/pc/lib:$LD_LIBRARY_PATH
```

### "Operation denied" (Real Kernel Mode)

Check the policy configuration and capability grants.

## Documentation

For more details, see:
- [Python SDK Documentation](../docs/guide/python-sdk.md)
- [API Reference](../docs/api/index.md)
- [Architecture Guide](../docs/architecture/index.md)
- [Security Model](../docs/security/index.md)

## License

Examples are provided under the same license as Authority (Apache 2.0).
