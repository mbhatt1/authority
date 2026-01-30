# @authority/nanos - Node.js SDK

Capability-based security for AI agents running on Authority Nanos.

## Overview

Authority Nanos is a purpose-built unikernel for securing autonomous AI agents with:

- **Cryptographic Capabilities**: HMAC-signed tokens for every operation
- **Immutable Audit Trail**: Hash-chained append-only log
- **Budget Enforcement**: Hard kernel limits on tokens, tool calls, wall time
- **Tool Sandboxing**: WASM execution with capability gating
- **Zero Ambient Authority**: No inherited permissions, everything requires explicit capability

This SDK provides a Node.js/TypeScript API to interact with the Authority Kernel.

## Installation

```bash
npm install @authority/nanos
```

## Quick Start

```typescript
import { AuthorityKernel } from '@authority/nanos';

// Create and initialize kernel
await using ak = new AuthorityKernel();
await ak.init();

// Allocate object in typed heap
const handle = await ak.alloc('counter', { value: 0 });

// Read it back
const data = await ak.read(handle);
console.log(new TextDecoder().decode(data));

// Update with JSON Patch
await ak.write(handle, [
  { op: 'replace', path: '/value', value: 42 }
]);

// Delete when done
await ak.delete(handle);
```

## Core Features

### Typed Heap

Store and manage versioned objects with compare-and-swap semantics:

```typescript
const handle = await ak.alloc('conversation', {
  messages: [],
  context: 'default'
});

const data = await ak.read(handle);
const obj = JSON.parse(new TextDecoder().decode(data));

// Update with JSON Patch (RFC 6902)
const newVersion = await ak.write(handle, [
  { op: 'add', path: '/messages/-', value: { role: 'user', content: 'Hello' } }
]);
```

### Authorization

Check if operations are permitted by policy:

```typescript
// Simple boolean check
if (await ak.authorize('read', '/etc/passwd')) {
  const contents = await ak.fileRead('/etc/passwd');
}

// Get detailed authorization info
const details = await ak.authorizeDetails('write', '/tmp/file.txt');
console.log(details);
// {
//   operation: 'write',
//   target: '/tmp/file.txt',
//   authorized: true,
//   ttlMs: 3600000
// }
```

### LLM Inference

Make LLM calls through the Authority gateway (budget-enforced):

```typescript
const response = await ak.inference({
  model: 'gpt-4',
  messages: [
    { role: 'system', content: 'You are helpful' },
    { role: 'user', content: 'What is 2+2?' }
  ],
  max_tokens: 100,
  temperature: 0.7
});

const result = JSON.parse(new TextDecoder().decode(response));
console.log(result.choices[0].message.content);
```

### File I/O

Read and write files (controlled by policy):

```typescript
// Read
const contents = await ak.fileRead('/etc/hostname');
console.log(new TextDecoder().decode(contents));

// Write
await ak.fileWrite('/tmp/output.txt', 'Hello, World!');
```

### Audit Logging

Log events to the immutable audit trail:

```typescript
await ak.auditLog('user_action', {
  action: 'login',
  username: 'alice',
  timestamp: Date.now()
});

// Query audit log
const result = await ak.auditQuery({
  event_type: 'user_action',
  limit: 100
});

console.log(result.entries);
```

### Budget Tracking

Monitor resource consumption:

```typescript
const status = await ak.getBudgetStatus();
console.log(status);
// {
//   tokens: { used: 500, limit: 1000000, remaining: 999500 },
//   wallTime: { used: 1234, limit: 300000, remaining: 298766 },
//   toolCalls: { used: 3, limit: 100, remaining: 97 },
//   objects: { used: 5, limit: 10000, remaining: 9995 }
// }
```

## Error Handling

The SDK provides typed error classes for different scenarios:

```typescript
import {
  AuthorityKernelError,
  OperationDeniedError,
  CapabilityError,
  BudgetExceededError,
  InvalidArgumentError,
  NotFoundError,
} from '@authority/nanos';

try {
  await ak.fileRead('/etc/shadow');
} catch (err) {
  if (err instanceof OperationDeniedError) {
    console.log('Access denied by policy');
  } else if (err instanceof BudgetExceededError) {
    console.log('Budget exhausted');
  } else if (err instanceof AuthorityKernelError) {
    console.log('Kernel error:', err.code, err.message);
  }
}
```

## Configuration

### Initialization Options

```typescript
const ak = new AuthorityKernel({
  // Path to libak library (auto-detected if not provided)
  libakPath: '/usr/local/lib/libak.so',

  // Enable debug logging
  debug: true,

  // Syscall timeout in milliseconds
  syscallTimeout: 30000,

  // Max size for single heap object (bytes)
  maxObjectSize: 10 * 1024 * 1024,

  // Max response size for LLM inference (bytes)
  maxInferenceSize: 100 * 1024 * 1024
});

await ak.init();
// ... use kernel
await ak.shutdown();
```

### Environment Variables

- `LIBAK_PATH`: Override library path (default: auto-detect)

## Running with minops

Use the `minops` tool to run Node.js applications in the Authority Nanos unikernel:

```bash
minops run app.js -p policy.json --allow-llm -m 512
```

Where:
- `app.js`: Your Node.js application
- `policy.json`: Security policy file
- `--allow-llm`: Allow common LLM API endpoints
- `-m 512`: Allocate 512MB memory

## Examples

See the `examples/` directory for complete working examples:

- `01-heap-operations.ts` - Typed heap basic operations
- `02-authorization.ts` - Authorization checks
- `03-tool-execution.ts` - Tool execution and sandboxing

Run examples:

```bash
npx ts-node examples/01-heap-operations.ts
```

## Testing

Run unit tests:

```bash
npm test
```

With coverage:

```bash
npm run test:coverage
```

Watch mode:

```bash
npm run test:watch
```

## API Reference

### AuthorityKernel class

#### Methods

- `init(): Promise<void>` - Initialize kernel
- `shutdown(): Promise<void>` - Shutdown kernel
- `alloc(typeName: string, initialValue: any): Promise<Handle>` - Allocate heap object
- `read(handle: Handle): Promise<Buffer>` - Read heap object
- `write(handle: Handle, patch: JsonPatchOp[]): Promise<number>` - Update heap object
- `delete(handle: Handle): Promise<void>` - Delete heap object
- `authorize(operation: string, target: string): Promise<boolean>` - Check authorization
- `authorizeDetails(operation: string, target: string): Promise<AuthorizationDetails>` - Get auth details
- `fileRead(path: string, maxSize?: number): Promise<Buffer>` - Read file
- `fileWrite(path: string, data: Buffer | string): Promise<void>` - Write file
- `inference(request: InferenceRequest): Promise<Buffer>` - LLM inference
- `auditLog(eventType: string, details?: any): Promise<void>` - Write audit log
- `auditQuery(query?: any): Promise<AuditQueryResult>` - Query audit log
- `getBudgetStatus(): Promise<BudgetStatus>` - Get resource budget status
- `getLastDenial(): Promise<DenialInfo | null>` - Get last denial info
- `toolCall(toolName: string, args: any): Promise<Buffer>` - Execute WASM tool

### Error Classes

- `AuthorityKernelError` - Base error class
- `OperationDeniedError` - Operation denied by policy
- `CapabilityError` - Capability-related error
- `BudgetExceededError` - Budget limit exceeded
- `InvalidArgumentError` - Invalid argument provided
- `NotFoundError` - Resource not found
- `BufferOverflowError` - Buffer overflow
- `TimeoutError` - Operation timeout
- `OutOfMemoryError` - Out of memory
- `TaintViolationError` - Taint violation

### Types

See `src/types.ts` for complete type definitions:

- `Handle` - Reference to heap object
- `InferenceRequest` - LLM request parameters
- `AuthorizationDetails` - Authorization decision details
- `BudgetStatus` - Resource budget information
- `AuditEntry` - Audit log entry
- `DenialInfo` - Denial information

## Performance

- **Syscall overhead**: ~5-10μs per call
- **Memory usage**: ~30MB baseline (Node.js/V8)
- **Event throughput**: 1000+ ops/sec
- **Audit log**: Hash-chain with tamper detection

## Security Considerations

1. **Never hardcode credentials** - Use policies and capabilities
2. **Validate all inputs** - Check authorization before operations
3. **Monitor budget** - Prevent resource exhaustion
4. **Review audit logs** - Detect anomalies
5. **Use strong policies** - Apply principle of least privilege

## Development

### Building

```bash
npm run build
```

### Linting

```bash
npm run lint
```

### Formatting

```bash
npm run format
```

### Generating Docs

```bash
npm run docs
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

Apache License 2.0

## Support

- **Documentation**: [Authority Nanos Docs](https://github.com/authority-systems/nanos)
- **Issues**: [GitHub Issues](https://github.com/authority-systems/nanos/issues)
- **Discussions**: [GitHub Discussions](https://github.com/authority-systems/nanos/discussions)

## Changelog

### 0.1.0 (Initial Release)

- Core AuthorityKernel class with async/await API
- Typed heap operations (alloc, read, write, delete)
- Authorization and policy enforcement
- File I/O operations
- LLM inference gateway
- Audit logging and queries
- Budget tracking
- Comprehensive error handling
- Full TypeScript support
- Unit tests
