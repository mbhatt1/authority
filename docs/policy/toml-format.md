# TOML Policy Format

::: warning Planned — not in the kernel build
A TOML policy format is planned as a human-friendly authoring format. The TOML compiler (`ak_policy_toml.c`) is **not** compiled into the current kernel. Use the [JSON format](/policy/json-format), which the compiled engine parses.
:::

## Overview

TOML would provide a more human-friendly way to author the same schema the [JSON engine](/policy/json-format) parses (`tools`, `domains`, `taint`, `budgets`):

```toml
version = "1.0"

[tools]
allow = ["http_get", "http_post", "file_read"]
deny = ["shell_exec"]

[domains]
allow = ["api.github.com", "*.googleapis.com"]
deny = ["*.internal"]

[taint]
sources = ["external_response"]
sinks = ["outbound_request"]
sanitizers = ["validate_json"]

[budgets]
calls = 100
tokens = 100000
inference_ms = 60000
```

## Benefits over JSON

| Feature | JSON | TOML |
|---------|------|------|
| Comments | No | Yes (`#`) |
| Trailing commas | No | Yes |
| Readability | Moderate | High |

## Example with Comments

```toml
version = "1.0"

# Tool permissions
[tools]
allow = [
    "http_get",   # Read-only HTTP
    "file_read",  # Read files within policy
]
deny = [
    "shell_exec", # Never allow shell execution
]

# Outbound destinations
[domains]
allow = [
    "api.github.com",
    "api.example.com",
]

# Resource budgets
[budgets]
calls = 100
tokens = 100_000        # Underscore for readability
inference_ms = 60_000
```

## Intended Compilation

A TOML policy would be compiled to JSON at build time and embedded or placed in the initrd:

```makefile
policy.json: ak.toml
	$(TOOLS)/ak-compile $< $@

INITRD_FILES += /ak/policy.json:policy.json
```

## Current Status

TOML support is not yet compiled into the kernel. For now, use the JSON format, which provides the full functionality of the current policy engine.
