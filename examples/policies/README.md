# Authority Policy Files

This directory contains a policy file for each of the Authority SDK examples. A
policy is deny-by-default: an operation is only permitted if the policy explicitly
allows it and the caller holds a capability for it.

## Policy Files

| Policy File | Example | Description |
|-------------|---------|-------------|
| `01_heap_policy.json` | `01_heap_operations.py` | Heap operations (alloc, read, write, delete) with budgets |
| `02_authorization_policy.json` | `02_authorization.py` | File read and outbound-request authorization |
| `03_tool_policy.json` | `03_tool_execution.py` | Tool execution (add, concat, file_read) |
| `04_inference_policy.json` | `04_inference.py` | Capability-gated outbound requests |
| `05_audit_policy.json` | `05_audit_logging.py` | Audit log access |

## Policy Loading

The minops tool detects and loads a policy file based on the script name.
For example, running `01_heap_operations.py` auto-loads `01_heap_policy.json`.

Manual override:
```bash
minops run examples/01_heap_operations.py -p examples/policies/01_heap_policy.json
```

## Policy JSON Format

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/usr/**", "/lib/**"],
    "write": ["/tmp/**"]
  },
  "net": {
    "dns": ["api.example.com"],
    "connect": ["dns:api.example.com:443"]
  },
  "tools": {
    "allow": ["add", "concat"],
    "deny": ["shell_exec"]
  },
  "infer": {
    "models": ["default"],
    "max_tokens": 100000
  },
  "budgets": {
    "heap_objects": 1000,
    "heap_bytes": 10485760,
    "tool_calls": 100,
    "tokens": 100000,
    "wall_time_ms": 60000
  }
}
```

The `infer` section gates capability-controlled outbound requests: `models` is
the allowlist of request targets and `max_tokens` caps the accounting budget per
request. The `budgets` section sets the hard resource limits the kernel enforces.

## How Policy Is Enforced

Every syscall enters the kernel through `ak_syscall_handler`, which calls
`ak_dispatch`. `ak_dispatch` runs six stages in order:

1. **validate** - check request shape and arguments
2. **anti-replay** - reject duplicate or replayed requests
3. **capability** - verify the caller's HMAC capability authorizes the operation
4. **policy + budget** - evaluate this policy and the resource budgets
5. **execute** - perform the operation
6. **audit** - append a hash-chained entry to the tamper-evident audit log

Policy files are consumed at stage 4. If a policy rule denies an operation, or a
budget is exhausted, the request is rejected before execution.
