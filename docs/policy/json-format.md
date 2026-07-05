# JSON Policy Format

JSON is the policy format parsed by the compiled policy engine (`src/agentic/ak_policy.c`). This page documents the schema that engine actually parses.

## Complete Example

```json
{
  "version": "1.0",

  "tools": {
    "allow": [
      "http_get",
      "http_post",
      "file_read"
    ],
    "deny": [
      "shell_exec",
      "file_write_raw"
    ]
  },

  "domains": {
    "allow": [
      "api.github.com",
      "*.googleapis.com"
    ],
    "deny": [
      "*.internal"
    ]
  },

  "taint": {
    "sources": ["external_response"],
    "sinks": ["outbound_request"],
    "sanitizers": ["validate_json"]
  },

  "budgets": {
    "tokens": 100000,
    "calls": 100,
    "inference_ms": 60000,
    "file_bytes": 10485760,
    "network_bytes": 104857600,
    "spawn_count": 8,
    "heap_objects": 10000,
    "heap_bytes": 104857600
  }
}
```

## Section Reference

### version (required)

```json
{ "version": "1.0" }
```

### tools

Controls tool execution via `AK_SYS_CALL`.

```json
{
  "tools": {
    "allow": ["tool_name", "prefix_*"],
    "deny": ["dangerous_tool"]
  }
}
```

**Matching:**

| Pattern | Matches |
|---------|---------|
| `tool_name` | Exact match |
| `prefix_*` | Prefix match |
| `*` | Any tool (dangerous!) |

**Precedence:** deny rules take precedence over allow. An unmatched tool is denied.

### domains

Controls outbound destinations.

```json
{
  "domains": {
    "allow": ["api.github.com", "*.googleapis.com"],
    "deny": ["*.internal"]
  }
}
```

| Pattern | Matches |
|---------|---------|
| `example.com` | Exact domain |
| `*.example.com` | Subdomains |
| `*` | Any domain (dangerous!) |

An unmatched domain is denied.

### taint

Declares taint sources, sinks, and sanitizers for taint-flow tracking.

```json
{
  "taint": {
    "sources": ["external_response"],
    "sinks": ["outbound_request", "file_write"],
    "sanitizers": ["validate_json"]
  }
}
```

### budgets

Resource limits for the run. Unknown numeric keys are ignored; `calls` and `tool_calls` are aliases.

```json
{
  "budgets": {
    "tokens": 100000,
    "calls": 100,
    "inference_ms": 60000,
    "file_bytes": 10485760,
    "network_bytes": 104857600,
    "spawn_count": 8,
    "heap_objects": 10000,
    "heap_bytes": 104857600
  }
}
```

| Budget | Description |
|--------|-------------|
| `tokens` | Outbound-request units |
| `calls` / `tool_calls` | Max tool invocations |
| `inference_ms` | Max outbound-request time (ms) |
| `file_bytes` | Max file I/O bytes |
| `network_bytes` | Max network I/O bytes |
| `spawn_count` | Max spawned children |
| `heap_objects` | Max heap objects |
| `heap_bytes` | Max heap bytes |

### signature (optional)

A hex-encoded HMAC-SHA256 tag (64 hex chars for the 32-byte MAC, or 128 hex chars for the full field). When present and verified against the signing key, `signature_verified` is set; unsigned policies are never treated as verified.

```json
{ "signature": "<64 or 128 hex chars>" }
```

## Common Patterns

### Restricted Program

```json
{
  "version": "1.0",
  "tools": {
    "allow": ["http_get", "file_read"],
    "deny": ["shell_exec"]
  },
  "domains": {
    "allow": ["api.example.com"]
  },
  "budgets": {
    "calls": 50,
    "tokens": 100000
  }
}
```

### Outbound-Only Program

```json
{
  "version": "1.0",
  "domains": {
    "allow": ["api.example.com", "*.cdn.example.com"]
  },
  "budgets": {
    "tokens": 100000,
    "inference_ms": 60000
  }
}
```

## Not Parsed by the Compiled Engine

Older drafts referenced `fs`, `net`, `wasm`, `infer`, and `profiles` sections. `ak_policy.c` does **not** parse these; they belong to the effect layer that is not in the current kernel build. Use `tools`, `domains`, `taint`, and `budgets`.
