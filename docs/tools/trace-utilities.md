# Trace Utilities

This page documents the kernel tracing and analysis tools for Authority.

## Overview

Authority implements a tracing mechanism inspired by [Linux' ftrace](https://www.kernel.org/doc/Documentation/trace/ftrace.txt). Trace utilities help you analyze kernel behavior and identify performance bottlenecks.

## Enabling Tracing

To enable tracing, build nanos by specifying `TRACE=ftrace`:

```bash
make clean && make TRACE=ftrace TARGET=<target> run
```

The resulting kernel will collect timing data on all kernel function calls.

## Collecting Trace Data

Once your application is running, access trace data via HTTP:

```bash
wget localhost:9090/ftrace/trace
```

This creates a `trace` file that looks like:

```
# tracer: function_graph
#
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
 0)               |  mcache_alloc() {
 0) ! 207.666 us  |    runtime_memcpy();
 0)   0.071 us    |    runtime_memcpy();
 0)   0.077 us    |    objcache_allocate();
 0) ! 208.173 us  |  }
 0)   0.093 us    |  install_fallback_fault_handler();
 ...
```

## Trace Options

### Tracer Selection

#### function_graph
The function_graph tracer interposes all function entries and return paths, allowing the kernel to collect entry and exit times for all function calls. This is the default tracer and creates trace files with entry/exit timing.

#### function
The function tracer only interposes function entries. It creates less overhead but provides less detailed timing information.

### Trace Data Consumption

Trace data is stored in an in-memory ring buffer (64MB by default). Once full, subsequent function calls are not traced.

**Destructive query** (removes data from buffer):
```bash
wget localhost:9090/ftrace/trace_pipe
```

**Non-destructive query** (keeps data in buffer):
```bash
wget localhost:9090/ftrace/trace
```

## Trace Parsing Tools

### parse-trace.py

Parses function_graph trace files and generates CSV:

```bash
./tools/trace-utilities/parse-trace.py <trace_file>
```

Output: `trace.csv`

### runtime-breakdown.py

Generates a bar graph showing function latencies:

```bash
./tools/trace-utilities/runtime-breakdown.py trace.csv
```

Requirements: `pandas` and `plotly` Python packages

```bash
pip install pandas plotly
```

Output: Interactive HTML graph showing:
- Function self-time (function time minus called functions)
- Total time per function across all invocations
- Toggleable function filtering

## Workflow Example

1. **Build with tracing:**
   ```bash
   make TRACE=ftrace TARGET=myapp run
   ```

2. **Collect trace data:**
   ```bash
   wget localhost:9090/ftrace/trace
   ```

3. **Parse trace:**
   ```bash
   ./tools/trace-utilities/parse-trace.py trace
   ```

4. **Analyze results:**
   ```bash
   ./tools/trace-utilities/runtime-breakdown.py trace.csv
   ```

5. **View graph** in your default browser

## Performance Considerations

- **Ring buffer size**: Default 64MB, fills quickly with many functions
- **Overhead**: function_graph adds measurable overhead to all function calls
- **Use cases**: Identify bottlenecks, understand call patterns, debug timing issues

## Tips

- Use `trace_pipe` to stream data and avoid buffer overflow
- Focus on specific functions by filtering in the parsing scripts
- Compare before/after traces to measure optimization impact
- Disable tracing for production builds

## References

- [Testing Documentation](/testing/) - Other debugging tools
- [Nanos Documentation](https://nanovms.gitbook.io/ops/)
