/**
 * Authority Nanos SDK for Node.js
 * Capability-based security for AI agents
 *
 * @example
 * ```typescript
 * import { AuthorityKernel } from '@authority/nanos';
 *
 * await using ak = new AuthorityKernel();
 * await ak.init();
 *
 * const handle = await ak.alloc('counter', { value: 0 });
 * const data = await ak.read(handle);
 * ```
 */

// Core class
export { AuthorityKernel } from './kernel';

// Types
export type {
  Handle,
  InferenceRequest,
  ToolResult,
  AuthorizationDetails,
  DenialInfo,
  BudgetStatus,
  AuditEntry,
  AuditQueryResult,
  Capability,
  FileAccessRequest,
  HttpRequest,
  HttpResponse,
  PolicyConstraint,
  AuthorityKernelOptions,
} from './types';

// Enums
export {
  Syscall,
  ErrorCode,
  CapabilityType,
} from './types';

// Error classes
export {
  AuthorityKernelError,
  OperationDeniedError,
  CapabilityError,
  BudgetExceededError,
  InvalidArgumentError,
  NotFoundError,
  BufferOverflowError,
  TimeoutError,
  OutOfMemoryError,
  TaintViolationError,
  LibakError,
  createError,
} from './errors';

// SDK info
export const SDK_VERSION = '0.1.0';

/**
 * Get SDK information
 */
export function getSdkInfo() {
  return {
    version: SDK_VERSION,
    name: '@authority/nanos',
    description: 'Authority Nanos SDK for Node.js',
  };
}
