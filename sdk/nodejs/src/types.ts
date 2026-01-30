/**
 * TypeScript type definitions for Authority Nanos SDK
 */

// ============================================================================
// ENUMS
// ============================================================================

export enum Syscall {
  READ = 1024,
  ALLOC = 1025,
  WRITE = 1026,
  DELETE = 1027,
  QUERY = 1028,
  BATCH = 1029,
  COMMIT = 1030,
  CALL = 1031,
  SPAWN = 1032,
  SEND = 1033,
  RECV = 1034,
  RESPOND = 1035,
  ASSERT = 1036,
  INFERENCE = 1037,
}

export enum ErrorCode {
  OK = 0,
  DENIED = -1,
  CAP_INVALID = -2,
  CAP_EXPIRED = -3,
  CAP_REVOKED = -4,
  BUDGET = -5,
  NOMEM = -6,
  INVAL = -7,
  NOENT = -8,
  OVERFLOW = -9,
  TIMEOUT = -10,
  DENIED_BY_POLICY = -11,
  TAINT_VIOLATION = -12,
  OUT_OF_BOUNDS = -13,
}

export enum CapabilityType {
  NET = 1,
  FS = 2,
  TOOL = 3,
  SECRETS = 4,
  INFERENCE = 5,
}

// ============================================================================
// CORE TYPES
// ============================================================================

/**
 * Handle to a typed heap object
 */
export interface Handle {
  id: bigint;
  version: number;
}

/**
 * LLM inference request
 */
export interface InferenceRequest {
  model: string;
  messages?: Array<{ role: string; content: string }>;
  prompt?: string;
  max_tokens?: number;
  temperature?: number;
  stop?: string[];
  [key: string]: any;
}

/**
 * Tool execution result
 */
export interface ToolResult {
  status: 'success' | 'error';
  output: any;
  error?: string;
  duration_ms?: number;
}

/**
 * Authorization decision details
 */
export interface AuthorizationDetails {
  operation: string;
  target: string;
  authorized: boolean;
  capabilityName?: string;
  ttlMs?: number;
  reason?: string;
  suggestion?: string;
}

/**
 * Information about denied operation
 */
export interface DenialInfo {
  reason: string;
  capabilityRequired?: string;
  operation?: string;
  target?: string;
  suggestion?: string;
  timestamp?: number;
}

/**
 * Budget status
 */
export interface BudgetStatus {
  tokens: {
    used: number;
    limit: number;
    remaining: number;
  };
  wallTime: {
    used: number;
    limit: number;
    remaining: number;
  };
  toolCalls: {
    used: number;
    limit: number;
    remaining: number;
  };
  objects: {
    used: number;
    limit: number;
    remaining: number;
  };
}

/**
 * Audit log entry
 */
export interface AuditEntry {
  seq: number;
  timestamp: number;
  eventType: string;
  operationId: string;
  details: Record<string, any>;
  prevHash: string;
  thisHash: string;
}

/**
 * Audit query result
 */
export interface AuditQueryResult {
  entries: AuditEntry[];
  total: number;
  hasMore: boolean;
}

/**
 * Capability token
 */
export interface Capability {
  type: CapabilityType;
  resource: string;
  methods: string[];
  issuedMs: number;
  ttlMs: number;
  rateLimit?: number;
  runId?: string;
}

/**
 * File access request
 */
export interface FileAccessRequest {
  operation: 'read' | 'write' | 'delete';
  path: string;
  maxSize?: number;
}

/**
 * HTTP request
 */
export interface HttpRequest {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  url: string;
  headers?: Record<string, string>;
  body?: Uint8Array | string;
  timeout?: number;
  maxResponseSize?: number;
}

/**
 * HTTP response
 */
export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

/**
 * Async iterator support for resources
 */
export interface AsyncDisposable {
  [Symbol.asyncDispose](): Promise<void>;
}

/**
 * Raw JSON Patch operation (RFC 6902)
 */
export interface JsonPatchOp {
  op: 'add' | 'remove' | 'replace' | 'move' | 'copy' | 'test';
  path: string;
  value?: any;
  from?: string;
}

/**
 * Batch operation group
 */
export interface BatchOperation {
  operations: Array<{
    op: 'alloc' | 'read' | 'write' | 'delete';
    handle?: Handle;
    typeName?: string;
    data?: any;
    patch?: JsonPatchOp[];
  }>;
  atomic?: boolean;
}

/**
 * Policy constraint
 */
export interface PolicyConstraint {
  version: string;
  fs?: {
    read?: string[];
    write?: string[];
    delete?: string[];
  };
  net?: {
    dns?: string[];
    connect?: string[];
    deny?: string[];
  };
  tools?: {
    allow?: string[];
    deny?: string[];
    require_approval?: string[];
  };
  budgets?: {
    llm_input_tokens?: number;
    llm_output_tokens?: number;
    tool_calls?: number;
    wall_time_ms?: number;
    heap_objects?: number;
  };
}

// ============================================================================
// INITIALIZATION OPTIONS
// ============================================================================

export interface AuthorityKernelOptions {
  /**
   * Path to libak library (auto-detected if not provided)
   */
  libakPath?: string;

  /**
   * Enable debug logging
   */
  debug?: boolean;

  /**
   * Timeout for syscalls (ms)
   */
  syscallTimeout?: number;

  /**
   * Max size for single heap object
   */
  maxObjectSize?: number;

  /**
   * Max response size for LLM inference
   */
  maxInferenceSize?: number;
}

// ============================================================================
// CALLBACK TYPES
// ============================================================================

/**
 * Callback for budget exhaustion
 */
export type BudgetExhaustedCallback = (
  resourceType: keyof BudgetStatus,
  remaining: number,
) => void;

/**
 * Callback for policy violations
 */
export type PolicyViolationCallback = (
  operation: string,
  target: string,
  reason: string,
) => void;

/**
 * Callback for audit events
 */
export type AuditCallback = (entry: AuditEntry) => void;
