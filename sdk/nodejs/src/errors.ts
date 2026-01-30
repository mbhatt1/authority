/**
 * Error classes for Authority Kernel
 */

/**
 * Base error class for Authority Kernel errors
 */
export class AuthorityKernelError extends Error {
  constructor(
    public code: number,
    message: string,
    public context: string = '',
  ) {
    super(`[${code}] ${message}${context ? ` (${context})` : ''}`);
    this.name = 'AuthorityKernelError';
    Object.setPrototypeOf(this, AuthorityKernelError.prototype);
  }
}

/**
 * Operation was denied by policy
 */
export class OperationDeniedError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'OperationDeniedError';
    Object.setPrototypeOf(this, OperationDeniedError.prototype);
  }
}

/**
 * Capability-related error (invalid, expired, revoked)
 */
export class CapabilityError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'CapabilityError';
    Object.setPrototypeOf(this, CapabilityError.prototype);
  }
}

/**
 * Budget was exceeded
 */
export class BudgetExceededError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'BudgetExceededError';
    Object.setPrototypeOf(this, BudgetExceededError.prototype);
  }
}

/**
 * Invalid argument provided
 */
export class InvalidArgumentError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'InvalidArgumentError';
    Object.setPrototypeOf(this, InvalidArgumentError.prototype);
  }
}

/**
 * Resource not found
 */
export class NotFoundError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'NotFoundError';
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

/**
 * Buffer overflow or out of bounds
 */
export class BufferOverflowError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'BufferOverflowError';
    Object.setPrototypeOf(this, BufferOverflowError.prototype);
  }
}

/**
 * Operation timeout
 */
export class TimeoutError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'TimeoutError';
    Object.setPrototypeOf(this, TimeoutError.prototype);
  }
}

/**
 * Out of memory
 */
export class OutOfMemoryError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'OutOfMemoryError';
    Object.setPrototypeOf(this, OutOfMemoryError.prototype);
  }
}

/**
 * Taint violation (untrusted data flowing to sensitive sink)
 */
export class TaintViolationError extends AuthorityKernelError {
  constructor(code: number, message: string, context?: string) {
    super(code, message, context);
    this.name = 'TaintViolationError';
    Object.setPrototypeOf(this, TaintViolationError.prototype);
  }
}

/**
 * libak library error
 */
export class LibakError extends AuthorityKernelError {
  constructor(message: string, code?: number, context?: string) {
    super(code ?? -999, message, context);
    this.name = 'LibakError';
    Object.setPrototypeOf(this, LibakError.prototype);
  }
}

/**
 * Convert error code to appropriate error class
 */
export function createError(
  code: number,
  message: string,
  context: string = '',
): AuthorityKernelError {
  switch (code) {
    case -1:
      return new OperationDeniedError(code, message, context);
    case -2:
    case -3:
    case -4:
      return new CapabilityError(code, message, context);
    case -5:
      return new BudgetExceededError(code, message, context);
    case -6:
      return new OutOfMemoryError(code, message, context);
    case -7:
      return new InvalidArgumentError(code, message, context);
    case -8:
      return new NotFoundError(code, message, context);
    case -9:
    case -13:
      return new BufferOverflowError(code, message, context);
    case -10:
      return new TimeoutError(code, message, context);
    case -12:
      return new TaintViolationError(code, message, context);
    default:
      return new AuthorityKernelError(code, message, context);
  }
}
