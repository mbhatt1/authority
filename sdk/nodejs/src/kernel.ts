/**
 * AuthorityKernel - Main class for Authority Nanos SDK
 * Provides async/await API for all Authority syscalls
 */

import ref from 'ref-napi';
import {
  loadLibak,
  getErrorMessage,
  objectToBuffer,
  bufferToObject,
  ErrorCodes,
  Handle as CHandle,
  AuthorizationDetails as CAuthorizationDetails,
} from './syscalls';
import { createError, AuthorityKernelError } from './errors';
import {
  Handle,
  InferenceRequest,
  AuthorityKernelOptions,
  AuthorizationDetails,
  DenialInfo,
  BudgetStatus,
  AuditEntry,
  AuditQueryResult,
  FileAccessRequest,
  HttpRequest,
  HttpResponse,
  JsonPatchOp,
  AsyncDisposable,
} from './types';

/**
 * Main Authority Kernel class
 * Provides Promise-based async API for all syscalls
 */
export class AuthorityKernel implements AsyncDisposable {
  private libak: any;
  private initialized = false;
  private lastDenialInfo: DenialInfo | null = null;
  private readBufferPool: Buffer[] = [];
  private options: Omit<Required<AuthorityKernelOptions>, 'libakPath'> & { libakPath?: string };

  constructor(options: AuthorityKernelOptions = {}) {
    this.options = {
      libakPath: options.libakPath,
      debug: options.debug ?? false,
      syscallTimeout: options.syscallTimeout ?? 30000,
      maxObjectSize: options.maxObjectSize ?? 10 * 1024 * 1024, // 10MB
      maxInferenceSize: options.maxInferenceSize ?? 100 * 1024 * 1024, // 100MB
    };

    try {
      this.libak = loadLibak(this.options.libakPath);
    } catch (err) {
      throw new AuthorityKernelError(
        -999,
        'Failed to load libak library',
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  /**
   * Initialize the kernel
   */
  async init(): Promise<void> {
    if (this.initialized) {
      return;
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const err = this.libak.ak_init();
      if (err !== 0) {
        throw createError(err, 'Failed to initialize Authority Kernel');
      }
      this.initialized = true;
    });
  }

  /**
   * Shutdown the kernel
   */
  async shutdown(): Promise<void> {
    if (!this.initialized) {
      return;
    }

    try {
      this.libak.ak_shutdown();
      this.initialized = false;
    } catch (err) {
      if (this.options.debug) {
        console.error('Error during shutdown:', err);
      }
    }

    // Clear buffer pool
    this.readBufferPool = [];
  }

  /**
   * Support for async dispose (await using)
   */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.shutdown();
  }

  // ==========================================================================
  // TYPED HEAP OPERATIONS
  // ==========================================================================

  /**
   * Allocate a new object in the typed heap
   */
  async alloc(typeName: string, initialValue: any): Promise<Handle> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const valueBytes = objectToBuffer(initialValue);

      if (valueBytes.length > this.options.maxObjectSize) {
        throw createError(
          ErrorCodes.OVERFLOW,
          `Object size exceeds limit: ${valueBytes.length} > ${this.options.maxObjectSize}`,
        );
      }

      const handle = ref.alloc(CHandle);
      const err = this.libak.ak_alloc(
        typeName,
        valueBytes,
        valueBytes.length,
        handle,
      );

      if (err !== 0) {
        this.updateDenialInfo(err);
        throw createError(err, 'Failed to allocate object', typeName);
      }

      return handle.deref();
    });
  }

  /**
   * Read object from typed heap
   */
  async read(handle: Handle): Promise<Buffer> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const buffer = this.getReadBuffer(this.options.maxObjectSize);
      const outLen = ref.alloc('uint64');

      const cHandle = this.createCHandle(handle);
      const err = this.libak.ak_read(cHandle, buffer, buffer.length, outLen);

      if (err !== 0) {
        this.returnReadBuffer(buffer);
        this.updateDenialInfo(err);
        throw createError(err, 'Failed to read object', `handle=${handle.id}`);
      }

      const len = Number(outLen.deref());
      const result = buffer.slice(0, len);
      this.returnReadBuffer(buffer);

      return result;
    });
  }

  /**
   * Write to object with JSON Patch
   */
  async write(
    handle: Handle,
    patch: JsonPatchOp[] | any[],
    expectedVersion?: number,
  ): Promise<number> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const patchBytes = objectToBuffer(patch);

      if (patchBytes.length > this.options.maxObjectSize) {
        throw createError(
          ErrorCodes.OVERFLOW,
          `Patch size exceeds limit: ${patchBytes.length}`,
        );
      }

      const newVersion = ref.alloc('uint32');
      const cHandle = this.createCHandle(handle);

      const err = this.libak.ak_write(
        cHandle,
        patchBytes,
        patchBytes.length,
        expectedVersion ?? 0,
        newVersion,
      );

      if (err !== 0) {
        this.updateDenialInfo(err);
        throw createError(err, 'Failed to write object', `handle=${handle.id}`);
      }

      return newVersion.deref();
    });
  }

  /**
   * Delete object from typed heap
   */
  async delete(handle: Handle): Promise<void> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const cHandle = this.createCHandle(handle);
      const err = this.libak.ak_delete(cHandle);

      if (err !== 0) {
        this.updateDenialInfo(err);
        throw createError(err, 'Failed to delete object', `handle=${handle.id}`);
      }
    });
  }

  // ==========================================================================
  // TOOL EXECUTION
  // ==========================================================================

  /**
   * Call a WASM tool
   */
  async toolCall(toolName: string, args: any): Promise<Buffer> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout * 2, async () => {
      const argsBytes = objectToBuffer(args);
      const resultBuffer = this.getReadBuffer(this.options.maxObjectSize);
      const outLen = ref.alloc('uint64');

      const err = this.libak.ak_call_tool(
        toolName,
        argsBytes,
        argsBytes.length,
        resultBuffer,
        resultBuffer.length,
        outLen,
      );

      if (err !== 0) {
        this.returnReadBuffer(resultBuffer);
        this.updateDenialInfo(err);
        throw createError(err, 'Tool execution failed', toolName);
      }

      const len = Number(outLen.deref());
      const result = resultBuffer.slice(0, len);
      this.returnReadBuffer(resultBuffer);

      return result;
    });
  }

  // ==========================================================================
  // AUTHORIZATION
  // ==========================================================================

  /**
   * Check if operation is authorized
   */
  async authorize(operation: string, target: string): Promise<boolean> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const details = await this.authorizeDetails(operation, target);
      return details.authorized;
    });
  }

  /**
   * Get detailed authorization info
   */
  async authorizeDetails(
    operation: string,
    target: string,
  ): Promise<AuthorizationDetails> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const details = ref.alloc(CAuthorizationDetails);
      const err = this.libak.ak_authorize(operation, target, details);

      if (err !== 0) {
        this.updateDenialInfo(err);
        throw createError(
          err,
          'Authorization check failed',
          `${operation}:${target}`,
        );
      }

      const authDetails = details.deref();
      return {
        operation: operation,
        target: target,
        authorized: authDetails.authorized,
        capabilityName: authDetails.reason ? undefined : 'required',
        ttlMs: authDetails.ttl_ms ?? undefined,
        reason: authDetails.reason ? authDetails.reason.toString() : undefined,
      };
    });
  }

  /**
   * Get last denial info
   */
  async getLastDenial(): Promise<DenialInfo | null> {
    return this.lastDenialInfo;
  }

  // ==========================================================================
  // FILE I/O
  // ==========================================================================

  /**
   * Read file
   */
  async fileRead(path: string, maxSize?: number): Promise<Buffer> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    const maxLen = maxSize ?? this.options.maxObjectSize;

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const buffer = this.getReadBuffer(maxLen);
      const outLen = ref.alloc('uint64');

      const err = this.libak.ak_file_read(path, buffer, buffer.length, outLen);

      if (err !== 0) {
        this.returnReadBuffer(buffer);
        this.updateDenialInfo(err);
        throw createError(err, 'Failed to read file', path);
      }

      const len = Number(outLen.deref());
      const result = buffer.slice(0, len);
      this.returnReadBuffer(buffer);

      return result;
    });
  }

  /**
   * Write file
   */
  async fileWrite(path: string, data: Buffer | Uint8Array | string): Promise<void> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const buffer = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);

      if (buffer.length > this.options.maxObjectSize) {
        throw createError(ErrorCodes.OVERFLOW, 'File data too large', path);
      }

      const err = this.libak.ak_file_write(path, buffer, buffer.length);

      if (err !== 0) {
        this.updateDenialInfo(err);
        throw createError(err, 'Failed to write file', path);
      }
    });
  }

  // ==========================================================================
  // LLM INFERENCE
  // ==========================================================================

  /**
   * LLM inference through Authority gateway
   */
  async inference(request: InferenceRequest | Buffer): Promise<Buffer> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout * 10, async () => {
      const requestBytes =
        request instanceof Buffer ? request : objectToBuffer(request);

      if (requestBytes.length > this.options.maxInferenceSize) {
        throw createError(
          ErrorCodes.OVERFLOW,
          'Inference request too large',
        );
      }

      const resultBuffer = this.getReadBuffer(this.options.maxInferenceSize);
      const outLen = ref.alloc('uint64');

      const err = this.libak.ak_inference(
        requestBytes,
        requestBytes.length,
        resultBuffer,
        resultBuffer.length,
        outLen,
      );

      if (err !== 0) {
        this.returnReadBuffer(resultBuffer);
        this.updateDenialInfo(err);
        throw createError(err, 'Inference failed');
      }

      const len = Number(outLen.deref());
      const result = resultBuffer.slice(0, len);
      this.returnReadBuffer(resultBuffer);

      return result;
    });
  }

  // ==========================================================================
  // AUDIT LOGGING
  // ==========================================================================

  /**
   * Write audit log entry
   */
  async auditLog(eventType: string, details?: any): Promise<void> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const detailsBytes = details ? objectToBuffer(details) : Buffer.alloc(0);

      const err = this.libak.ak_audit_log(eventType, detailsBytes, detailsBytes.length);

      if (err !== 0) {
        throw createError(err, 'Failed to write audit log', eventType);
      }
    });
  }

  /**
   * Query audit log
   */
  async auditQuery(query?: any): Promise<AuditQueryResult> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const queryBytes = query ? objectToBuffer(query) : Buffer.alloc(0);
      const resultBuffer = this.getReadBuffer(this.options.maxObjectSize);
      const outLen = ref.alloc('uint64');

      const err = this.libak.ak_audit_query(
        queryBytes,
        queryBytes.length,
        resultBuffer,
        resultBuffer.length,
        outLen,
      );

      if (err !== 0) {
        this.returnReadBuffer(resultBuffer);
        throw createError(err, 'Audit query failed');
      }

      const len = Number(outLen.deref());
      const result = bufferToObject(resultBuffer.slice(0, len));
      this.returnReadBuffer(resultBuffer);

      return result as AuditQueryResult;
    });
  }

  // ==========================================================================
  // BUDGET TRACKING
  // ==========================================================================

  /**
   * Get budget status
   */
  async getBudgetStatus(): Promise<BudgetStatus> {
    if (!this.initialized) {
      throw new AuthorityKernelError(0, 'Kernel not initialized');
    }

    return this.withTimeout(this.options.syscallTimeout, async () => {
      const resultBuffer = Buffer.alloc(4096);
      const outLen = ref.alloc('uint64');

      const err = this.libak.ak_get_budget_status(
        resultBuffer,
        resultBuffer.length,
        outLen,
      );

      if (err !== 0) {
        throw createError(err, 'Failed to get budget status');
      }

      const len = Number(outLen.deref());
      return bufferToObject(resultBuffer.slice(0, len)) as BudgetStatus;
    });
  }

  // ==========================================================================
  // PRIVATE HELPERS
  // ==========================================================================

  private withTimeout<T>(timeoutMs: number, fn: () => Promise<T>): Promise<T> {
    return Promise.race([
      fn(),
      new Promise<T>((_, reject) =>
        setTimeout(
          () => reject(new AuthorityKernelError(
            ErrorCodes.TIMEOUT,
            'Syscall timeout',
            `${timeoutMs}ms`,
          )),
          timeoutMs,
        ),
      ),
    ]);
  }

  private createCHandle(handle: Handle): any {
    const cHandle = ref.alloc(CHandle);
    cHandle.id = handle.id;
    cHandle.version = handle.version;
    return cHandle;
  }

  private getReadBuffer(size: number): Buffer {
    const existing = this.readBufferPool.pop();
    if (existing && existing.length >= size) {
      return existing;
    }
    return Buffer.alloc(size);
  }

  private returnReadBuffer(buffer: Buffer): void {
    if (this.readBufferPool.length < 10) {
      this.readBufferPool.push(buffer);
    }
  }

  private updateDenialInfo(code: number): void {
    if (code < 0) {
      this.lastDenialInfo = {
        reason: getErrorMessage(code),
      };
    }
  }
}

export { AuthorityKernelError };
