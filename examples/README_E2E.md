# Authority Examples - End-to-End Guide

This guide covers both **host-side** and **kernel-side** Python execution with Authority.

## Architecture

Authority has two execution modes.

### 1. Host-Side Execution (SDK Examples)

Python code runs on the **host machine** (macOS/Linux) and makes syscalls to the Authority kernel:

```
Host Machine (macOS/Linux)
+-------------------------+
|  Python Example Code    |
|  (examples/01-05.py)    |
|                         |
|  Authority Python SDK   |
|  (ctypes bindings)      |
+------------+------------+
             | Syscalls (1024-1042)
             v
+-------------------------+
| Authority Kernel        |
| (Nanos-based unikernel) |
|                         |
| - libak                 |
| - Policy Engine         |
| - Capabilities          |
+-------------------------+
```

**Use case**: Run and audit a workload against the kernel from the host, enforcing policy at the kernel level.

### 2. Kernel-Side Execution (Unikernel Examples)

Python code is compiled **into** the kernel image and executes directly inside the unikernel:

```
Nanos Unikernel (QEMU/KVM)
+-------------------------+
|  Program                |
|  (running inside)       |
|                         |
|  Kernel                 |
|  - Python Runtime       |
|  - File System          |
|  - Network Stack        |
|  - Authority Kernel     |
+-------------------------+
```

**Use case**: Deploy a single isolated program with minimal overhead.

---

## Part 1: Host-Side Examples (Ready Now)

### Setup

```bash
# Build libak
make -j$(nproc)

# Run examples with the helper script
./examples/run_example.sh 1  # Heap operations
./examples/run_example.sh 2  # Authorization
./examples/run_example.sh 3  # Tool execution
./examples/run_example.sh 4  # Outbound requests
./examples/run_example.sh 5  # Audit logging
```

### Available Examples

1. **01_heap_operations.py** - Typed-heap memory management with JSON Patch
2. **02_authorization.py** - Capability-based authorization
3. **03_tool_execution.py** - WASM tool sandboxing (integer-only)
4. **04_inference.py** - Capability-gated outbound requests
5. **05_audit_logging.py** - Tamper-evident audit log

### Example: Heap Operations

```python
from authority_nanos import AuthorityKernel
import json

with AuthorityKernel() as ak:
    # Allocate a counter object
    handle = ak.alloc("counter", b'{"value": 0}')

    # Read it back
    data = ak.read(handle)
    counter = json.loads(data.decode('utf-8'))
    print(f"Counter: {counter}")

    # Update with JSON Patch
    patch = b'[{"op": "replace", "path": "/value", "value": 42}]'
    new_version = ak.write(handle, patch)

    # Clean up
    ak.delete(handle)
```

**When this works**: Requires the Authority kernel to be running and reachable.

---

## Part 2: Kernel-Side Examples (Unikernel)

### Option A: Using the `ops` Tool (Recommended)

Install `ops`:
```bash
curl https://ops.city/get.sh -sSfL | sh
```

### Create a Kernel-Side Python Application

```bash
mkdir -p kernel-examples/hello-auth
cd kernel-examples/hello-auth
```

Create `main.py`:
```python
#!/usr/bin/env python3
"""
Authority Python program.
Runs inside the unikernel with direct libak access.
"""

import sys
import json

print("Python running inside the Authority unikernel")

# Basic runtime info
print(f"Python version: {sys.version}")
print(f"Platform: {sys.platform}")

# JSON round-trip
data = {
    "kernel": "Authority",
    "language": "Python",
    "execution": "inside-unikernel",
    "status": "ok"
}
print(f"Data: {json.dumps(data, indent=2)}")

# Filesystem (if mounted)
try:
    with open("/proc/cmdline", "r") as f:
        cmdline = f.read()
        print(f"Kernel cmdline: {cmdline}")
except Exception:
    print("Filesystem not available")

print("Unikernel execution complete")
sys.exit(0)
```

Create `config.json`:
```json
{
  "Args": ["main.py"],
  "ManifestPassthrough": {
    "expected_exit_code": ["0"],
    "debug_exit": "t"
  }
}
```

### Run Inside the Kernel

```bash
# Verify the kernel image exists
ls -lh ../../../output/platform/pc/bin/kernel.img

# Run Python inside the kernel
ops run main.py -c config.json
```

### Option B: Using the Authority SDK Inside the Kernel

Create `auth_app.py`:
```python
#!/usr/bin/env python3
"""
Authority program using libak syscalls.
"""

import sys
sys.path.insert(0, '/lib/python')

# Inside the kernel, libak is directly available
try:
    from authority_nanos import AuthorityKernel, AuthorityKernelError

    print("Authority SDK loaded inside the unikernel")

    # Create context (syscalls go directly to the kernel)
    with AuthorityKernel() as ak:
        print("Connected to the Authority kernel")

        # Allocate an object in the kernel heap
        handle = ak.alloc("test", b'{"msg": "hello from inside"}')
        print(f"Allocated handle: {handle}")

        # Read back
        data = ak.read(handle)
        print(f"Read: {data.decode()}")

        # Clean up
        ak.delete(handle)
        print("Deleted handle")

except AuthorityKernelError as e:
    print(f"Kernel error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

print("Application complete")
sys.exit(0)
```

---

## Part 3: End-to-End Test

Create `test_e2e.sh`:
```bash
#!/bin/bash
set -e

echo "Authority End-to-End Test"
echo ""

# 1. Build kernel with Python support
echo "1. Building kernel with Python support..."
make PLATFORM=pc -j$(nproc) kernel > /dev/null
echo "   Kernel built"
echo ""

# 2. Run host-side examples
echo "2. Testing host-side SDK examples..."
for i in 1 2 3 4 5; do
    echo "   Example $i..."
    ./examples/run_example.sh $i 2>&1 | grep -E "\[+\]|\[-\]" | head -3
done
echo "   Host-side examples tested"
echo ""

# 3. Run kernel-side application (requires ops)
if command -v ops &> /dev/null; then
    echo "3. Testing kernel-side Python application..."
    cd kernel-examples/hello-auth
    ops run main.py -c config.json 2>&1 | grep "complete"
    cd ../..
    echo "   Kernel-side application tested"
else
    echo "3. ops tool not found - skipping kernel-side test"
    echo "   Install with: curl https://ops.city/get.sh -sSfL | sh"
fi

echo ""
echo "End-to-End Test Complete"
```

Run it:
```bash
chmod +x test_e2e.sh
./test_e2e.sh
```

---

## Verification

### Host-Side Verification

```bash
# Check the SDK loads
python3 << 'EOF'
import sys
sys.path.insert(0, 'sdk/python')
from authority_nanos import AuthorityKernel
print("SDK imports successfully")
EOF

# Check the libak binary
file output/platform/pc/lib/libak.dylib
# Output: Mach-O 64-bit dynamically linked shared library
```

### Kernel-Side Verification

```bash
# Verify the kernel image
file output/platform/pc/bin/kernel.img
# Output: ELF 64-bit LSB executable

# Run with QEMU directly
qemu-system-x86_64 \
  -m 2G \
  -kernel output/platform/pc/bin/kernel.img \
  -append "main=hello.py" \
  -display none \
  -serial stdio
```

---

## Troubleshooting

### Host-Side Issues

**Problem**: `Could not load libak.so`
- **Solution**: Ensure libak was built: `make -j$(nproc)`
- **Solution**: Set `LIBAK_PATH`: `export LIBAK_PATH=/path/to/libak.dylib`

**Problem**: `SIGSYS` (Bad system call)
- **Cause**: The Authority kernel is not reachable from this host
- **Info**: Expected when no kernel is running; the examples work when the kernel is present

### Kernel-Side Issues

**Problem**: `ops: command not found`
- **Solution**: Install the ops tool: `curl https://ops.city/get.sh -sSfL | sh`

**Problem**: Kernel does not boot
- **Solution**: Check the kernel log: `qemu-system-x86_64 ... -serial stdio`
- **Solution**: Verify Python support in the kernel image

---

## Architecture Summary

| Aspect | Host-Side | Kernel-Side |
|--------|-----------|-------------|
| **Location** | macOS/Linux | Nanos unikernel |
| **SDK** | Python + ctypes bindings | Python 3.x builtin |
| **Syscalls** | 1024-1042 via IPC | Direct kernel integration |
| **Isolation** | Process isolation | Kernel isolation |
| **Use Case** | Control host workloads | Deploy an isolated program |
| **Launch** | `python examples/01.py` | `ops run app.py` |

---

## Next Steps

1. **Test host examples**: `./examples/run_example.sh 1`
2. **Install ops**: `curl https://ops.city/get.sh -sSfL | sh`
3. **Run a kernel example**: `cd kernel-examples/hello-auth && ops run main.py -c config.json`
4. **Deploy**: Package kernel images with the Authority kernel for production

---

## References

- [ops Tool Documentation](https://ops.city/)
- [Nanos Unikernel Project](https://github.com/nanovms/nanos)
- [Python SDK Guide](../docs/guide/python-sdk.md)
