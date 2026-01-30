/**
 * Low-level FFI bindings to libak.so/libak.dylib
 * Maps C functions directly using ffi-napi
 */

import ffi from 'ffi-napi';
import ref from 'ref-napi';
import StructType from 'ref-struct-di';
import ArrayType from 'ref-array-di';
import * as os from 'os';
import * as path from 'path';
import * as fs from 'fs';

const Struct = StructType(ref);
const Array = ArrayType(ref);

// ============================================================================
// C STRUCT DEFINITIONS (matching libak.h)
// ============================================================================

export const Handle = Struct({
  id: ref.types.uint64,
  version: ref.types.uint32,
  _padding: ref.types.uint32,
});

export const ToolCall = Struct({
  tool_name: Array(ref.types.char, 128),
  args_json: ref.refType(ref.types.uint8),
  args_len: ref.types.uint32,
  timeout_ms: ref.types.uint32,
});

export const InferenceRequest = Struct({
  model: Array(ref.types.char, 128),
  prompt: ref.refType(ref.types.uint8),
  prompt_len: ref.types.uint32,
  max_tokens: ref.types.uint32,
  temperature: ref.types.double,
});

export const CapabilityToken = Struct({
  type: ref.types.uint8,
  resource: Array(ref.types.char, 256),
  methods: Array(Array(ref.types.char, 32), 8),
  issued_ms: ref.types.uint64,
  ttl_ms: ref.types.uint32,
  rate_limit: ref.types.uint32,
  run_id: Array(ref.types.uint8, 16),
  mac: Array(ref.types.uint8, 32),
});

export const AuthorizationDetails = Struct({
  operation: ref.types.uint32,
  target: Array(ref.types.char, 256),
  authorized: ref.types.bool,
  ttl_ms: ref.types.uint32,
  reason: Array(ref.types.char, 256),
});

// ============================================================================
// LIBAK LOADER
// ============================================================================

let cachedLib: any = null;
let cachedPath: string | null = null;

/**
 * Load libak from standard locations
 */
export function loadLibak(explicitPath?: string): any {
  if (cachedLib && !explicitPath) {
    return cachedLib;
  }

  const searchPaths = getSearchPaths(explicitPath);

  for (const libPath of searchPaths) {
    try {
      const lib = ffi.Library(libPath, getLibakInterface());
      cachedLib = lib;
      cachedPath = libPath;
      return lib;
    } catch (err) {
      continue;
    }
  }

  throw new Error(
    `Could not load libak from any standard location. Searched: ${searchPaths.join(', ')}. ` +
      `Set LIBAK_PATH environment variable to specify custom location.`
  );
}

/**
 * Get search paths for libak library
 */
function getSearchPaths(explicitPath?: string): string[] {
  const platform = os.platform();
  const arch = os.arch();
  const filename = platform === 'darwin' ? 'libak.dylib' : 'libak.so';

  const paths: string[] = [];

  // 1. Explicit path
  if (explicitPath) {
    paths.push(explicitPath);
  }

  // 2. Environment variable
  if (process.env.LIBAK_PATH) {
    paths.push(process.env.LIBAK_PATH);
  }

  // 3. Bundled in package (platform-specific)
  const packageDir = path.join(__dirname, '..');
  const platformTag = `${platform}_${arch}`;
  paths.push(
    path.join(packageDir, '_binaries', platformTag, filename),
    path.join(packageDir, '_libak', filename),
  );

  // 4. System library paths
  if (platform === 'darwin') {
    paths.push(
      `/usr/local/lib/${filename}`,
      `/opt/local/lib/${filename}`,
      `/usr/local/opt/libak/lib/${filename}`,
    );
  } else if (platform === 'linux') {
    paths.push(
      `/usr/local/lib/${filename}`,
      `/usr/lib/${filename}`,
      `/usr/lib/${arch}-linux-gnu/${filename}`,
    );
  }

  // Filter to existing paths
  return paths.filter(p => {
    try {
      return fs.existsSync(p);
    } catch {
      return false;
    }
  });
}

/**
 * Get FFI interface definition for libak
 */
function getLibakInterface(): any {
  return {
    // Initialization
    ak_init: ['int64', []],
    ak_shutdown: ['void', []],

    // Typed heap operations
    ak_alloc: [
      'int64',
      [
        ref.types.CString, // type_name
        ref.refType(ref.types.uint8), // data
        ref.types.uint64, // data_len
        ref.refType(Handle), // out_handle
      ],
    ],

    ak_read: [
      'int64',
      [
        Handle, // handle
        ref.refType(ref.types.uint8), // out_data
        ref.types.uint64, // max_len
        ref.refType(ref.types.uint64), // out_len
      ],
    ],

    ak_write: [
      'int64',
      [
        Handle, // handle
        ref.refType(ref.types.uint8), // patch_data (JSON Patch)
        ref.types.uint64, // patch_len
        ref.types.uint32, // expected_version
        ref.refType(ref.types.uint32), // out_new_version
      ],
    ],

    ak_delete: [
      'int64',
      [Handle], // handle
    ],

    // Tool execution
    ak_call_tool: [
      'int64',
      [
        ref.types.CString, // tool_name
        ref.refType(ref.types.uint8), // args_json
        ref.types.uint64, // args_len
        ref.refType(ref.types.uint8), // out_result
        ref.types.uint64, // max_result_len
        ref.refType(ref.types.uint64), // out_result_len
      ],
    ],

    // Authorization
    ak_authorize: [
      'int64',
      [
        ref.types.CString, // operation
        ref.types.CString, // target
        ref.refType(AuthorizationDetails), // out_details
      ],
    ],

    // File I/O
    ak_file_read: [
      'int64',
      [
        ref.types.CString, // path
        ref.refType(ref.types.uint8), // out_data
        ref.types.uint64, // max_len
        ref.refType(ref.types.uint64), // out_len
      ],
    ],

    ak_file_write: [
      'int64',
      [
        ref.types.CString, // path
        ref.refType(ref.types.uint8), // data
        ref.types.uint64, // len
      ],
    ],

    // LLM inference
    ak_inference: [
      'int64',
      [
        ref.refType(ref.types.uint8), // request_json
        ref.types.uint64, // request_len
        ref.refType(ref.types.uint8), // out_response
        ref.types.uint64, // max_response_len
        ref.refType(ref.types.uint64), // out_response_len
      ],
    ],

    // Audit logging
    ak_audit_log: [
      'int64',
      [
        ref.types.CString, // event_type
        ref.refType(ref.types.uint8), // details_json
        ref.types.uint64, // details_len
      ],
    ],

    ak_audit_query: [
      'int64',
      [
        ref.refType(ref.types.uint8), // query_json
        ref.types.uint64, // query_len
        ref.refType(ref.types.uint8), // out_results
        ref.types.uint64, // max_results_len
        ref.refType(ref.types.uint64), // out_results_len
      ],
    ],

    // Error handling
    ak_strerror: ['CString', ['int64']], // errno -> error message
    ak_is_fatal: ['bool', ['int64']], // is error fatal

    // Budget tracking
    ak_get_budget_status: [
      'int64',
      [
        ref.refType(ref.types.uint8), // out_json
        ref.types.uint64, // max_len
        ref.refType(ref.types.uint64), // out_len
      ],
    ],

    // Utility
    ak_version: ['CString', []],
  };
}

// ============================================================================
// ERROR CODE DEFINITIONS
// ============================================================================

export const ErrorCodes = {
  OK: 0,
  DENIED: -1,
  CAP_INVALID: -2,
  CAP_EXPIRED: -3,
  CAP_REVOKED: -4,
  BUDGET: -5,
  NOMEM: -6,
  INVAL: -7,
  NOENT: -8,
  OVERFLOW: -9,
  TIMEOUT: -10,
  DENIED_BY_POLICY: -11,
  TAINT_VIOLATION: -12,
  OUT_OF_BOUNDS: -13,
} as const;

/**
 * Convert error code to human-readable message
 */
export function getErrorMessage(code: number): string {
  try {
    const lib = loadLibak();
    return lib.ak_strerror(code);
  } catch {
    // Fallback if libak not available
    switch (code) {
      case ErrorCodes.DENIED:
        return 'Operation denied by policy';
      case ErrorCodes.CAP_INVALID:
        return 'Invalid capability';
      case ErrorCodes.CAP_EXPIRED:
        return 'Capability expired';
      case ErrorCodes.CAP_REVOKED:
        return 'Capability revoked';
      case ErrorCodes.BUDGET:
        return 'Budget exceeded';
      case ErrorCodes.NOMEM:
        return 'Out of memory';
      case ErrorCodes.INVAL:
        return 'Invalid argument';
      case ErrorCodes.NOENT:
        return 'Not found';
      case ErrorCodes.OVERFLOW:
        return 'Buffer overflow';
      case ErrorCodes.TIMEOUT:
        return 'Operation timeout';
      case ErrorCodes.DENIED_BY_POLICY:
        return 'Denied by policy';
      case ErrorCodes.TAINT_VIOLATION:
        return 'Taint violation';
      case ErrorCodes.OUT_OF_BOUNDS:
        return 'Out of bounds';
      default:
        return `Unknown error code: ${code}`;
    }
  }
}

/**
 * Check if error is fatal (should stop execution)
 */
export function isFatalError(code: number): boolean {
  return code < -10 || code === ErrorCodes.NOMEM || code === ErrorCodes.OVERFLOW;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Convert JavaScript object to buffer
 */
export function objectToBuffer(obj: any): Buffer {
  const json = JSON.stringify(obj);
  return Buffer.from(json, 'utf-8');
}

/**
 * Convert buffer to JavaScript object
 */
export function bufferToObject<T = any>(buf: Buffer): T {
  return JSON.parse(buf.toString('utf-8')) as T;
}

/**
 * Get libak version
 */
export function getLibakVersion(): string {
  try {
    const lib = loadLibak();
    return lib.ak_version();
  } catch (err) {
    return 'unknown';
  }
}
