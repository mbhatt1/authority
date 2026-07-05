# Quick Start

**Run an untrusted program under kernel-enforced, capability-based security.**

Authority runs a single untrusted program per VM and mediates every effect it performs. This guide shows you how to build and run a program with a deny-by-default policy and a tamper-evident audit trail.

## Getting Started Workflow

```mermaid
flowchart LR
    subgraph "1. Create Policy"
        POLICY["policy.json"]
    end

    subgraph "2. Build"
        INITRD[Add to initrd]
        BUILD[authority build]
    end

    subgraph "3. Run"
        RUN[authority run]
        APP[Program Runs]
    end

    subgraph "4. Debug"
        DENY[Denial Messages]
        FIX[Update Policy]
    end

    POLICY --> INITRD
    INITRD --> BUILD
    BUILD --> RUN
    RUN --> APP
    APP --> DENY
    DENY --> FIX
    FIX --> POLICY
```

## Prerequisites

Before you begin, ensure you have:

- [authority CLI](https://authority.dev) installed
- A compiled application (Go, Rust, C, etc.)
- Basic familiarity with unikernels

## 1. Create a Policy File

Create `/ak/policy.json` in your initrd:

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**", "/lib/**"],
    "write": ["/tmp/**"]
  },
  "net": {
    "dns": ["api.example.com"],
    "connect": ["dns:api.example.com:443"]
  },
  "profiles": ["tier1-musl"]
}
```

## 2. Build Your Image

```bash
# Include policy in initrd
mkdir -p initrd/ak
cp policy.json initrd/ak/policy.json

# Build with authority CLI
authority build myapp -c config.json
```

## 3. Run

```bash
authority run myapp
```

## 4. Debug Denials

When an operation is denied, you'll see a helpful message:

```
AK DENY FS_OPEN /etc/secret missing fs.read. Fix: read = ["/etc/secret"]
```

### Programmatic Access

```c
// Get last denial info
char buf[1024];
syscall(AK_SYS_LAST_ERROR, buf, sizeof(buf));
// buf contains JSON with details
```

## 5. Common Patterns

```mermaid
graph TB
    subgraph "Web Application"
        WEB_FS["fs.read: /app/**, /etc/ssl/**<br/>fs.write: /tmp/**, /app/logs/**"]
        WEB_NET["net: bind/listen :8080<br/>connect: *:443, *:80"]
    end

    subgraph "Database Client"
        DB_FS["fs.read: /app/**"]
        DB_NET["net.dns: db.internal<br/>net.connect: :5432"]
    end

    subgraph "Outbound-Request Program"
        OB_FS["fs.read: /app/**<br/>fs.write: /app/workspace/**"]
        OB_NET["net: api.example.com:443"]
        OB_TOOLS["tools.allow: http_get<br/>tools.deny: shell_exec"]
        OB_BUDGET["budgets: 50 tool calls, 100k tokens"]
    end
```

### Web Application

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**", "/etc/ssl/**"],
    "write": ["/tmp/**", "/app/logs/**"]
  },
  "net": {
    "dns": ["*"],
    "connect": ["dns:*:443", "dns:*:80"],
    "bind": ["ip:0.0.0.0:8080"],
    "listen": ["ip:0.0.0.0:8080"]
  },
  "profiles": ["tier1-musl"]
}
```

### Database Client

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**"]
  },
  "net": {
    "dns": ["db.internal"],
    "connect": ["dns:db.internal:5432"]
  },
  "profiles": ["tier1-musl"]
}
```

### Outbound-Request Program

A program that makes gated outbound requests and calls sandboxed tools, with hard budgets:

```json
{
  "version": "1.0",
  "fs": {
    "read": ["/app/**"],
    "write": ["/app/workspace/**"]
  },
  "net": {
    "dns": ["api.example.com"],
    "connect": ["dns:api.example.com:443"]
  },
  "tools": {
    "allow": ["http_get", "file_read"],
    "deny": ["shell_exec"]
  },
  "budgets": {
    "tool_calls": 50,
    "tokens": 100000
  },
  "profiles": ["tier1-musl"]
}
```

## 6. Troubleshooting

### No policy found

```
AK: FATAL - No policy found
AK: Expected policy at: /ak/policy.json (initrd)
```

**Fix:** Ensure `/ak/policy.json` is in your initrd.

### Operation denied

Check the console message and add the suggested rule to your policy.

### Missing capability

The denial message shows exactly which capability is needed:
- `fs.read` - Add path to `fs.read` array
- `fs.write` - Add path to `fs.write` array
- `net.dns` - Add domain to `net.dns` array
- `net.connect` - Add target to `net.connect` array

## Next Steps

- [Installation Guide](/getting-started/installation) - Detailed setup instructions
- [First Program](/getting-started/first-agent) - Build and run your first program
- [Policy Reference](/policy/) - Complete policy documentation
- [Security Model](/security/) - Understand the threat model
