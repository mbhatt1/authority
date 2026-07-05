/*
 * Authority Kernel - WASM Runtime Interface
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides a capability-gated WASM sandbox for tool execution.
 * The WASM runtime (wasm3) lives in userspace; the kernel provides:
 *   - Capability validation for host functions
 *   - Tool registry and dispatch
 *   - Resource limits and sandboxing
 *
 * SECURITY CRITICAL: All host functions are capability-gated.
 */

#ifndef AK_WASM_H
#define AK_WASM_H

#include "ak_capability.h"
#include "ak_types.h"

/* ============================================================
 * WASM MODULE REPRESENTATION
 * ============================================================ */

/* Module load sources */
typedef enum ak_wasm_source {
  AK_WASM_SOURCE_EMBEDDED, /* Built into supervisor binary */
  AK_WASM_SOURCE_NETWORK,  /* Fetched from trusted URL */
  AK_WASM_SOURCE_HEAP,     /* Loaded from typed heap */
} ak_wasm_source_t;

/* Module metadata */
typedef struct ak_wasm_module {
  /* Identity */
  u8 module_id[AK_TOKEN_ID_SIZE];
  char name[64];
  u8 hash[AK_HASH_SIZE]; /* SHA256 of WASM bytecode */

  /* Source tracking */
  ak_wasm_source_t source;
  char source_url[256]; /* If loaded from network */

  /* Bytecode */
  buffer bytecode;
  u64 bytecode_len;

  /* Exports */
  char **export_names;
  u32 export_count;

  /* Required capabilities */
  ak_cap_type_t required_caps[8];
  u32 required_cap_count;

  /* Resource limits for this module */
  u64 max_memory;       /* Max linear memory (bytes) */
  u64 max_stack;        /* Max stack depth */
  u64 max_instructions; /* Instruction limit (gas) */
  u64 max_runtime_ms;   /* Wall-clock timeout */

  /* Trust level */
  boolean verified;  /* Signature verified */
  boolean sandboxed; /* Runs in restricted mode */

  /* Signature (if verified) */
  u8 signature[64];   /* Ed25519 signature of bytecode */
  u8 signing_key[32]; /* Ed25519 public key that signed */

  /* Lifecycle */
  u64 loaded_ms;
  u64 last_used_ms;
  u64 invocation_count;
} ak_wasm_module_t;

/* ============================================================
 * TOOL REGISTRY
 * ============================================================
 * Tools are named WASM exports that agents can invoke via AK_SYS_CALL.
 */

/* Tool descriptor */
typedef struct ak_tool {
  char name[64];         /* Tool name (e.g., "http_get") */
  char description[256]; /* Human-readable description */

  /* Module reference */
  ak_wasm_module_t *module;
  char export_name[64]; /* Function to call in module */

  /* Capability requirements */
  ak_cap_type_t cap_type; /* Required capability type */
  char cap_resource[256]; /* Resource pattern (e.g., "*.github.com") */
  char *cap_methods[8];   /* Allowed methods */
  u32 cap_method_count;

  /* Argument schema (JSON Schema) */
  buffer input_schema;
  buffer output_schema;

  /* Rate limiting */
  u32 default_rate_limit;
  u32 default_rate_window_ms;

  /* Audit classification */
  boolean log_args;   /* Log full arguments */
  boolean log_result; /* Log full result */
  boolean sensitive;  /* Contains credentials/PII */
} ak_tool_t;

/* ============================================================
 * EXECUTION CONTEXT
 * ============================================================
 * Per-invocation state for WASM execution.
 */

typedef enum ak_wasm_exec_state {
  AK_WASM_STATE_INIT,
  AK_WASM_STATE_RUNNING,
  AK_WASM_STATE_SUSPENDED, /* Awaiting host call */
  AK_WASM_STATE_COMPLETED,
  AK_WASM_STATE_FAILED,
  AK_WASM_STATE_TIMEOUT,
  AK_WASM_STATE_OOM,
} ak_wasm_exec_state_t;

/* Suspension reason for async operations */
typedef enum ak_wasm_suspend_reason {
  AK_WASM_SUSPEND_NONE = 0,
  AK_WASM_SUSPEND_HOST_CALL, /* Waiting for async host function */
  AK_WASM_SUSPEND_APPROVAL,  /* Waiting for human approval */
  AK_WASM_SUSPEND_RESOURCE,  /* Waiting for resource availability */
  AK_WASM_SUSPEND_IO,        /* Waiting for I/O completion */
} ak_wasm_suspend_reason_t;

/* Suspension state (saved when context is suspended) */
typedef struct ak_wasm_suspension {
  ak_wasm_suspend_reason_t reason;
  u64 suspend_time_ms;
  void *resume_data; /* Data to pass on resume */
  u64 resume_data_len;
  void *resume_callback; /* Called when resume data is available (closure) */
  u64 timeout_ms;        /* 0 = no timeout */
  u64 approval_id;       /* If waiting for approval */
} ak_wasm_suspension_t;

typedef struct ak_wasm_exec_ctx {
  /* Identity */
  u8 exec_id[AK_TOKEN_ID_SIZE];

  /* Agent context (for capability checks) */
  ak_agent_context_t *agent;

  /* Module and tool */
  ak_wasm_module_t *module;
  ak_tool_t *tool;

  /* Capability for this invocation */
  ak_capability_t *cap;

  /* Input/Output */
  buffer input;
  buffer output;
  s64 result_code;

  /* State */
  ak_wasm_exec_state_t state;

  /* Suspension (if state == AK_WASM_STATE_SUSPENDED) */
  ak_wasm_suspension_t suspension;

  /* Resource tracking */
  u64 instructions_used;
  u64 memory_used;
  u64 start_ms;
  u64 elapsed_ms;

  /* Host call stack (for nested calls) */
  struct ak_wasm_exec_ctx *parent;
  u32 depth;

  /* Error info */
  char error_msg[256];
} ak_wasm_exec_ctx_t;

/* ============================================================
 * HOST FUNCTION ABI
 * ============================================================
 * Host functions that WASM modules can call.
 * Each is capability-gated via ak_capability_validate().
 */

/* Host function signature */
typedef s64 (*ak_host_fn_t)(ak_wasm_exec_ctx_t *ctx, buffer args,
                            buffer *result);

/* Host function registration */
typedef struct ak_host_fn_entry {
  char name[64];          /* Function name in WASM */
  ak_host_fn_t fn;        /* Implementation */
  ak_cap_type_t cap_type; /* Required capability type */
  boolean async_capable;  /* Can suspend execution */
} ak_host_fn_entry_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize WASM subsystem.
 *
 * Sets up:
 *   - Module registry
 *   - Tool registry
 *   - Host function bindings
 */
void ak_wasm_init(heap h);

/*
 * Shutdown WASM subsystem.
 */
void ak_wasm_shutdown(void);

/* ============================================================
 * MODULE MANAGEMENT
 * ============================================================ */

/*
 * Load WASM module from bytecode.
 *
 * Validates:
 *   - WASM binary format
 *   - No disallowed imports
 *   - Resource limits within bounds
 *
 * Returns NULL on validation failure.
 */
ak_wasm_module_t *ak_wasm_module_load(heap h, const char *name, buffer bytecode,
                                      ak_wasm_source_t source,
                                      const char *source_url);

/*
 * Load module with Ed25519 signature verification.
 *
 * SECURITY: The public_key must be in the trusted key set.
 * Verified modules may have additional privileges.
 *
 * @param signature   64-byte Ed25519 signature of bytecode
 * @param public_key  32-byte Ed25519 public key
 * Returns NULL if signature verification fails.
 */
ak_wasm_module_t *
ak_wasm_module_load_verified(heap h, const char *name, buffer bytecode,
                             ak_wasm_source_t source, const char *source_url,
                             const u8 *signature, const u8 *public_key);

/*
 * Load module from network URL.
 *
 * NOT SUPPORTED: There is no in-kernel HTTP client, so network fetch of
 * AK_WASM_SOURCE_NETWORK modules cannot be performed. The AK_CAP_NET
 * capability is still validated for the URL, but this function ALWAYS
 * returns NULL (fail-closed). Modules must be loaded from local bytecode
 * via ak_wasm_module_load()/ak_wasm_module_load_verified().
 */
ak_wasm_module_t *ak_wasm_module_fetch(heap h, const char *name,
                                       const char *url,
                                       ak_capability_t *net_cap);

/*
 * Unload module and free resources.
 */
void ak_wasm_module_unload(heap h, ak_wasm_module_t *module);

/*
 * Get module by name.
 */
ak_wasm_module_t *ak_wasm_module_get(const char *name);

/*
 * Get module by hash (for verification).
 */
ak_wasm_module_t *ak_wasm_module_get_by_hash(u8 *hash);

/* ============================================================
 * TOOL REGISTRY
 * ============================================================ */

/*
 * Register a tool (callable via AK_SYS_CALL).
 *
 * SECURITY: Tool inherits module's trust level.
 */
s64 ak_tool_register(heap h, const char *name, ak_wasm_module_t *module,
                     const char *export_name, ak_cap_type_t cap_type,
                     const char *cap_resource);

/*
 * Unregister tool.
 */
void ak_tool_unregister(const char *name);

/*
 * Get tool by name.
 */
ak_tool_t *ak_tool_get(const char *name);

/*
 * List all registered tools.
 */
ak_tool_t **ak_tool_list(u32 *count_out);

/* ============================================================
 * TOOL EXECUTION
 * ============================================================
 * Entry point for AK_SYS_CALL handler.
 */

/*
 * Execute tool by name.
 *
 * Pipeline:
 *   1. Look up tool
 *   2. Validate capability (INV-2)
 *   3. Check budget (INV-3)
 *   4. Create execution context
 *   5. Run WASM with resource limits
 *   6. Capture result
 *   7. Log to audit (INV-4)
 *
 * Returns result or error code.
 */
ak_response_t *ak_wasm_execute_tool(ak_agent_context_t *agent,
                                    const char *tool_name, buffer args,
                                    ak_capability_t *cap);

/*
 * Create execution context (for advanced use).
 */
ak_wasm_exec_ctx_t *ak_wasm_exec_create(heap h, ak_agent_context_t *agent,
                                        ak_tool_t *tool, ak_capability_t *cap);

/*
 * Run execution to completion.
 *
 * SUBSTRATE: the kernel is compiled -mno-sse (no hardware float, no
 * soft-float runtime) and no full WASM interpreter is linked in, so a
 * complete WASM interpreter (which the spec's mandatory f32/f64 types
 * require) cannot run here. This executes a strict, bounded, INTEGER-ONLY
 * WASM subset via ak_wasm_interp_run() (see ak_wasm_interp.h):
 *   - Modules that declare/use float types or opcodes, or anything outside
 *     the supported integer subset, are REJECTED fail-closed
 *     (AK_E_WASM_UNSUPPORTED) - never mis-executed.
 *   - A validating, integer-only module is genuinely interpreted; on real
 *     completion the context is marked COMPLETED with real output and
 *     executions_success is incremented.
 *   - Validation failure, trap, gas exhaustion and OOM fail closed with an
 *     honest error code (AK_E_WASM_*) and the matching failure counter;
 *     output is never fabricated.
 */
s64 ak_wasm_exec_run(ak_wasm_exec_ctx_t *ctx, buffer input);

/*
 * Destroy execution context.
 */
void ak_wasm_exec_destroy(heap h, ak_wasm_exec_ctx_t *ctx);

/* ============================================================
 * ASYNC EXECUTION (SUSPENSION/RESUMPTION)
 * ============================================================ */

/*
 * Suspend execution for async operation.
 *
 * Called by host functions that need to perform async operations
 * (e.g., network I/O, approval requests).
 *
 * LIMITATION: This does NOT save real WASM machine state (PC, stack,
 * locals) - that state lives in the userspace supervisor. The kernel
 * only records the suspension reason and checkpoints the opaque,
 * caller-provided blob in @data. Resumption correctness depends on the
 * supervisor holding the actual interpreter state.
 *
 * @param ctx         Execution context
 * @param reason      Why we're suspending
 * @param data        Data to preserve across suspension (copied)
 * @param data_len    Length of data
 * @param resume_cb   Callback when ready to resume (may be NULL)
 * @param timeout_ms  Timeout for suspension (0 = no timeout)
 * @return            0 on success, error code on failure
 */
s64 ak_wasm_exec_suspend(ak_wasm_exec_ctx_t *ctx,
                         ak_wasm_suspend_reason_t reason, void *data,
                         u64 data_len, void *resume_cb, /* closure */
                         u64 timeout_ms);

/*
 * Resume suspended execution.
 *
 * Called when async operation completes.
 *
 * LIMITATION: As with ak_wasm_exec_suspend(), no WASM machine state is
 * restored here; the kernel stores the opaque result blob for the
 * userspace supervisor to deliver into the interpreter and flips the
 * context back to RUNNING.
 *
 * @param ctx         Execution context
 * @param result      Result data from async operation
 * @param result_len  Length of result
 * @return            0 on success, error code on failure
 */
s64 ak_wasm_exec_resume(ak_wasm_exec_ctx_t *ctx, void *result, u64 result_len);

/*
 * Check if execution is suspended.
 */
boolean ak_wasm_exec_is_suspended(ak_wasm_exec_ctx_t *ctx);

/*
 * Get suspension reason.
 */
ak_wasm_suspend_reason_t ak_wasm_exec_suspend_reason(ak_wasm_exec_ctx_t *ctx);

/* ============================================================
 * HOST FUNCTION REGISTRATION
 * ============================================================ */

/*
 * Register host function callable from WASM.
 *
 * SECURITY: Function must validate capabilities internally.
 */
s64 ak_host_fn_register(const char *name, ak_host_fn_t fn,
                        ak_cap_type_t cap_type, boolean async_capable);

/*
 * Get host function by name.
 */
ak_host_fn_entry_t *ak_host_fn_get(const char *name);

/* ============================================================
 * BUILT-IN HOST FUNCTIONS
 * ============================================================
 * Standard host ABI available to all WASM modules.
 */

/* Network operations (require AK_CAP_NET) */
s64 ak_host_http_get(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_http_post(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_tcp_connect(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_tcp_send(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_tcp_recv(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);

/* Filesystem operations (require AK_CAP_FS) */
s64 ak_host_fs_read(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_fs_write(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_fs_stat(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_fs_list(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);

/* Heap operations (require AK_CAP_HEAP) */
s64 ak_host_heap_read(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_heap_write(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);

/* Secret resolution (require AK_CAP_SECRETS) */
s64 ak_host_secret_get(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);

/* LLM operations (require AK_CAP_INFERENCE) */
s64 ak_host_llm_complete(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);

/* Utility (no capability required) */
s64 ak_host_log(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_time_now(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_random(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);

/* Streaming operations (require AK_CAP_NET for stream capability) */
s64 ak_host_stream_create(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_stream_send(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_stream_send_token(ak_wasm_exec_ctx_t *ctx, buffer args,
                              buffer *result);
s64 ak_host_stream_stats(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_stream_close(ak_wasm_exec_ctx_t *ctx, buffer args, buffer *result);
s64 ak_host_stream_set_stop(ak_wasm_exec_ctx_t *ctx, buffer args,
                            buffer *result);

/* ============================================================
 * RESOURCE LIMITS
 * ============================================================ */

/* Default limits */
#define AK_WASM_DEFAULT_MAX_MEMORY (64 * 1024 * 1024)        /* 64 MB */
#define AK_WASM_DEFAULT_MAX_STACK 4096                       /* Stack frames */
#define AK_WASM_DEFAULT_MAX_INSTRUCTIONS (100 * 1000 * 1000) /* 100M instr */
#define AK_WASM_DEFAULT_MAX_RUNTIME_MS 30000                 /* 30 seconds */
#define AK_WASM_MAX_CALL_DEPTH 16                            /* Nested calls */

/* Error codes specific to WASM */
#define AK_E_WASM_INVALID_MODULE (-4500)
#define AK_E_WASM_LOAD_FAILED (-4501)
#define AK_E_WASM_EXPORT_NOT_FOUND (-4502)
#define AK_E_WASM_TYPE_MISMATCH (-4503)
#define AK_E_WASM_TRAP (-4504)
#define AK_E_WASM_OOM (-4505)
#define AK_E_WASM_TIMEOUT (-4506)
#define AK_E_WASM_HOST_ERROR (-4507)
#define AK_E_WASM_DEPTH_EXCEEDED (-4508)
#define AK_E_WASM_UNSUPPORTED                                                  \
  (-4509) /* Valid WASM, but uses features outside the integer-only subset    \
             (float types/opcodes, unsupported opcodes/sections/imports) */

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_wasm_stats {
  u64 modules_loaded;
  u64 tools_registered;
  u64 executions_total;
  u64 executions_success;
  u64 executions_failed;
  u64 executions_timeout;
  u64 executions_oom;
  u64 total_instructions;
  u64 total_runtime_ms;
  u64 host_calls_total;
  u64 host_calls_denied;
  u64 signature_failures; /* Failed signature verifications */
} ak_wasm_stats_t;

void ak_wasm_get_stats(ak_wasm_stats_t *stats);

#endif /* AK_WASM_H */
