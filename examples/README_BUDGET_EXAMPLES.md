# Budget Tracking Examples

Authority enforces hard resource budgets in the kernel. Every workload runs
against fixed limits on tokens, tool calls, wall-clock time, and bytes; when a
limit is reached the kernel denies further consuming operations. These examples
show how to read and monitor that budget from a program using the Authority SDK.

Budget dimensions:

- **tokens** - accounting unit charged by capability-gated outbound requests
- **tool_calls** - number of sandboxed WASM tool invocations
- **wall_time** - elapsed wall-clock time
- **bytes** - heap and I/O byte accounting

## Primary Example

### 01_budget_tracking_unified.py

Issues capability-gated outbound requests and records the usage each request
reports back against the kernel's token budget. When a response includes usage
metadata, the exact reported counts are recorded; if usage metadata is missing,
the example fails fast rather than estimating, so budget accounting stays exact.

**Features:**
- Records the usage reported by each outbound request
- Explicit error handling when a response omits usage metadata
- Detailed breakdown of consumption by operation
- Budget-limit enforcement with critical warnings

**Demonstrations:**
1. Basic budget monitoring around outbound requests
2. Budget-limit enforcement (intentionally low limit)
3. Consumption comparison between a large and a small request

---

## Budget Tracking API

### Core Classes

#### `BudgetTracker`
Main interface for reading budget state, exposed as `ak.budget`:

```python
from authority_nanos import AuthorityKernel

with AuthorityKernel() as ak:
    # Get current status
    status = ak.budget.get_status()
    print(f"Tokens: {status.tokens_used} / {status.tokens_limit}")

    # Get history
    history = ak.budget.get_history(count=60)

    # Get breakdown
    breakdown = ak.budget.get_breakdown()

    # Estimate remaining time
    remaining = ak.budget.estimate_remaining_runtime()

    # Print formatted status
    ak.budget.print_status(detailed=True)
```

#### `BudgetStatus`
Current budget state:
- `tokens_used`, `tokens_limit`, `tokens_percent`, `tokens_remaining`
- `tool_calls_used`, `tool_calls_limit`, `tool_calls_percent`
- `wall_time_used`, `wall_time_limit`, `wall_time_percent`
- `bytes_used`, `bytes_limit`, `bytes_percent`
- `is_any_critical` - True if any resource is above 90%

#### `BudgetSnapshot`
Historical point-in-time data:
- `timestamp` - When the snapshot was taken
- `tokens` - Total tokens at that time
- `tool_calls` - Total tool calls
- `wall_time_ms` - Elapsed time in milliseconds

#### `BudgetBreakdown`
Detailed consumption analysis:
- `tokens_by_operation` - Dict of operation type -> token count
- `tool_calls_by_name` - Dict of tool name -> call count
- `top_token_consumers(n)` - Top N token-consuming operations
- `top_tools(n)` - Top N most-called tools

---

## Common Patterns

### 1. Basic Monitoring

```python
with AuthorityKernel() as ak:
    # Do work...

    # Check status
    status = ak.budget.get_status()
    if status.is_any_critical:
        print("WARNING: Budget critical!")
```

### 2. Continuous Monitoring

```python
def monitor_loop(ak, interval=1.0):
    while True:
        status = ak.budget.get_status(force_refresh=True)
        if status.tokens_percent > 90:
            alert("Token budget critical!")
        time.sleep(interval)
```

### 3. Budget Alerts

```python
class BudgetMonitor:
    def __init__(self, kernel, warn=75, critical=90):
        self.kernel = kernel
        self.warn_threshold = warn
        self.critical_threshold = critical

    def check(self):
        status = self.kernel.budget.get_status()
        if status.tokens_percent >= self.critical_threshold:
            return "CRITICAL"
        elif status.tokens_percent >= self.warn_threshold:
            return "WARNING"
        return "OK"
```

### 4. Historical Analysis

```python
# Get last hour of snapshots
history = ak.budget.get_history(count=60)

# Calculate burn rate
if len(history) >= 2:
    first, last = history[0], history[-1]
    elapsed_sec = (last.timestamp - first.timestamp).total_seconds()
    token_rate = (last.tokens - first.tokens) / elapsed_sec
    print(f"Burn rate: {token_rate:.1f} tokens/sec")
```

### 5. Detailed Reporting

```python
breakdown = ak.budget.get_breakdown()

print("Top Token Consumers:")
for operation, tokens in breakdown.top_token_consumers(5):
    print(f"  {operation}: {tokens:,} tokens")

print("\nTop Tools:")
for tool, calls in breakdown.top_tools(5):
    print(f"  {tool}: {calls} calls")
```

---

## Environment Setup

### Real Kernel Mode

1. Build the Authority kernel:
   ```bash
   make -j$(nproc)
   ```

2. Set the library path:
   ```bash
   export LD_LIBRARY_PATH=/path/to/libak:$LD_LIBRARY_PATH
   ```

3. Run with the real kernel.

### Simulation Mode

Budget tracking is fully functional in simulation mode (`simulate=True`) with no
kernel build required, which is convenient for developing and testing budget
logic.

---

## Accounting Accuracy

The kernel charges the budget from the usage actually reported to it. When an
outbound request returns usage metadata, the exact reported counts are recorded:

```python
# Record the usage the response reports; do not estimate.
if usage is None:
    raise RuntimeError("Cannot track usage accurately without response metadata")

tokens_used = usage.total_tokens
```

Recording reported usage (rather than estimating) keeps budget accounting exact,
which matters when budgets are used for hard enforcement or cost accounting.

---

## Integration with Your Code

### Minimal Integration

```python
from authority_nanos import AuthorityKernel

with AuthorityKernel() as ak:
    # Your program logic here

    # Check budget periodically
    if ak.budget.get_status().is_any_critical:
        print("Budget critical - stopping")
```

### Full Integration

```python
from authority_nanos import AuthorityKernel

class MyWorkload:
    def __init__(self):
        self.kernel = AuthorityKernel()
        self.kernel.init()

    def run(self):
        while True:
            # Do work
            self.process_task()

            # Monitor budget
            status = self.kernel.budget.get_status()
            if status.is_any_critical:
                self.handle_budget_critical()
                break

            # Log progress
            if self.should_log():
                self.kernel.budget.print_status()

    def handle_budget_critical(self):
        print("Budget exhausted!")
        breakdown = self.kernel.budget.get_breakdown()
        print("Top consumers:")
        for op, tokens in breakdown.top_token_consumers(3):
            print(f"  {op}: {tokens:,} tokens")
```

---

## Troubleshooting

### "libak not found"
- Build the kernel first: `make -j$(nproc)`
- Set the library path: `export LD_LIBRARY_PATH=/path/to/libak:$LD_LIBRARY_PATH`

### "Response missing usage metadata"
- This is intentional fail-fast behavior
- The response did not include usage counts, so exact accounting is not possible
- Check the request path and that the endpoint reports usage

### "No budget data"
- Budget tracking starts after the first operation
- Call `ak.budget.get_status()` to force an update

---

## Development/Testing Examples

The following examples (08-10) exist for development and testing only. They use
simulation or estimation and are not suitable for exact accounting:

- `08_budget_tracking.py` - Simulation mode, fixed usage estimates
- `09_langchain_budget_demo.py` - Simulated integration
- `10_langchain_gemini_budget.py` - Has estimation fallbacks

For exact accounting, use example 01.

---

## Next Steps

1. Run example 01 to see budget tracking around outbound requests
2. Integrate budget queries into your program
3. Set appropriate budget limits in your policy file
4. Monitor and optimize consumption

For more information, see:
- Main README: `../README.md`
- Python SDK docs: `../sdk/python/README.md`
- Policy examples: `./policies/`
