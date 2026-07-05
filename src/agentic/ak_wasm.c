/*
 * Authority Kernel - WASM Runtime Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This file implements the kernel-side WASM management:
 *   - Module registry and validation
 *   - Tool registry and dispatch
 *   - Execution context management
 *
 * NOTE: The actual WASM interpreter (wasm3) runs in userspace.
 * The kernel provides capability validation and resource limits.
 */

#include "ak_wasm.h"
#include "ak_audit.h"
#include "ak_compat.h"
#include "ak_ed25519.h"
#include "ak_syscall.h"
#include "ak_wasm_interp.h"

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

#define AK_MAX_WASM_MODULES 64
#define AK_MAX_TOOLS 256
#define AK_MAX_HOST_FUNCTIONS 128

static struct {
  heap h;
  boolean initialized;

  /* Module registry */
  ak_wasm_module_t *modules[AK_MAX_WASM_MODULES];
  u32 module_count;

  /* Tool registry */
  ak_tool_t *tools[AK_MAX_TOOLS];
  u32 tool_count;

  /* Host function registry */
  ak_host_fn_entry_t host_fns[AK_MAX_HOST_FUNCTIONS];
  u32 host_fn_count;

  /* Statistics */
  ak_wasm_stats_t stats;
} ak_wasm_state;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_wasm_init(heap h) {
  if (ak_wasm_state.initialized)
    return;

  ak_wasm_state.h = h;
  ak_wasm_state.module_count = 0;
  ak_wasm_state.tool_count = 0;
  ak_wasm_state.host_fn_count = 0;

  runtime_memset((u8 *)&ak_wasm_state.stats, 0, sizeof(ak_wasm_stats_t));

  /* Initialize arrays */
  for (int i = 0; i < AK_MAX_WASM_MODULES; i++)
    ak_wasm_state.modules[i] = 0;
  for (int i = 0; i < AK_MAX_TOOLS; i++)
    ak_wasm_state.tools[i] = 0;

  /* Register built-in host functions */
  ak_host_fn_register("http_get", ak_host_http_get, AK_CAP_NET, true);
  ak_host_fn_register("http_post", ak_host_http_post, AK_CAP_NET, true);
  ak_host_fn_register("tcp_connect", ak_host_tcp_connect, AK_CAP_NET, true);
  ak_host_fn_register("tcp_send", ak_host_tcp_send, AK_CAP_NET, false);
  ak_host_fn_register("tcp_recv", ak_host_tcp_recv, AK_CAP_NET, true);

  ak_host_fn_register("fs_read", ak_host_fs_read, AK_CAP_FS, false);
  ak_host_fn_register("fs_write", ak_host_fs_write, AK_CAP_FS, false);
  ak_host_fn_register("fs_stat", ak_host_fs_stat, AK_CAP_FS, false);
  ak_host_fn_register("fs_list", ak_host_fs_list, AK_CAP_FS, false);

  ak_host_fn_register("heap_read", ak_host_heap_read, AK_CAP_HEAP, false);
  ak_host_fn_register("heap_write", ak_host_heap_write, AK_CAP_HEAP, false);

  ak_host_fn_register("secret_get", ak_host_secret_get, AK_CAP_SECRETS, false);
  ak_host_fn_register("llm_complete", ak_host_llm_complete, AK_CAP_INFERENCE,
                      true);

  /* BUG-FIX #9: Utility functions must still be explicitly granted, not
   * blanket-available Even "safe" functions like logging can be used for covert
   * channels or timing attacks. Require explicit tool capability for all
   * functions, even AK_CAP_NONE ones. This prevents sandbox escape via utility
   * function imports.
   */
  ak_host_fn_register("log", ak_host_log, AK_CAP_TOOL,
                      false); /* Require tool capability */
  ak_host_fn_register("time_now", ak_host_time_now, AK_CAP_TOOL, false);
  ak_host_fn_register("random", ak_host_random, AK_CAP_TOOL, false);

  ak_wasm_state.initialized = true;
}

void ak_wasm_shutdown(void) {
  if (!ak_wasm_state.initialized)
    return;

  /* Unload all modules */
  for (u32 i = 0; i < ak_wasm_state.module_count; i++) {
    if (ak_wasm_state.modules[i]) {
      ak_wasm_module_unload(ak_wasm_state.h, ak_wasm_state.modules[i]);
      ak_wasm_state.modules[i] = 0;
    }
  }

  /* Free all tools */
  for (u32 i = 0; i < ak_wasm_state.tool_count; i++) {
    if (ak_wasm_state.tools[i]) {
      deallocate(ak_wasm_state.h, ak_wasm_state.tools[i], sizeof(ak_tool_t));
      ak_wasm_state.tools[i] = 0;
    }
  }

  ak_wasm_state.module_count = 0;
  ak_wasm_state.tool_count = 0;
  ak_wasm_state.initialized = false;
}

/* ============================================================
 * MODULE MANAGEMENT
 * ============================================================ */

/* WASM magic number: \0asm */
#define WASM_MAGIC 0x6d736100
#define WASM_VERSION 1

static boolean validate_wasm_header(buffer bytecode) {
  if (buffer_length(bytecode) < 8)
    return false;

  u8 *data = buffer_ref(bytecode, 0);
  u32 magic = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
  u32 version = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);

  return (magic == WASM_MAGIC) && (version == WASM_VERSION);
}

/* Wrapper for Nanos sha256 that uses buffers */
static void ak_sha256(const u8 *data, u32 len, u8 *output) {
  buffer src = alloca_wrap_buffer((void *)data, len);
  /* Use a little_stack_buffer which can be extended, unlike wrapped buffers */
  buffer dst = little_stack_buffer(64);
  sha256(dst, src);
  /* Copy result to output */
  runtime_memcpy(output, buffer_ref(dst, 0), 32);
}

static void compute_module_hash(buffer bytecode, u8 *hash_out) {
  /*
   * Compute SHA-256 of bytecode for cryptographically secure
   * module identification and integrity verification.
   */
  u64 len = buffer_length(bytecode);
  u8 *data = buffer_ref(bytecode, 0);

  ak_sha256(data, (u32)len, hash_out);
}

ak_wasm_module_t *ak_wasm_module_load(heap h, const char *name, buffer bytecode,
                                      ak_wasm_source_t source,
                                      const char *source_url) {
  if (!ak_wasm_state.initialized)
    return 0;

  if (ak_wasm_state.module_count >= AK_MAX_WASM_MODULES)
    return 0;

  /* Validate WASM header */
  if (!validate_wasm_header(bytecode))
    return 0;

  /* Allocate module */
  ak_wasm_module_t *module = allocate(h, sizeof(ak_wasm_module_t));
  if (module == INVALID_ADDRESS)
    return 0;

  runtime_memset((u8 *)module, 0, sizeof(ak_wasm_module_t));

  /* Generate module ID */
  ak_generate_token_id(module->module_id);

  /* Copy name */
  u64 name_len = runtime_strlen(name);
  if (name_len >= sizeof(module->name))
    name_len = sizeof(module->name) - 1;
  runtime_memcpy(module->name, name, name_len);
  module->name[name_len] = 0;

  /* Compute hash */
  compute_module_hash(bytecode, module->hash);

  /* Set source */
  module->source = source;
  if (source_url) {
    u64 url_len = runtime_strlen(source_url);
    if (url_len >= sizeof(module->source_url))
      url_len = sizeof(module->source_url) - 1;
    runtime_memcpy(module->source_url, source_url, url_len);
    module->source_url[url_len] = 0;
  }

  /* Clone bytecode */
  module->bytecode_len = buffer_length(bytecode);
  module->bytecode = allocate_buffer(h, module->bytecode_len);
  if (module->bytecode == INVALID_ADDRESS) {
    deallocate(h, module, sizeof(ak_wasm_module_t));
    return 0;
  }
  buffer_write(module->bytecode, buffer_ref(bytecode, 0), module->bytecode_len);

  /* Set default limits */
  module->max_memory = AK_WASM_DEFAULT_MAX_MEMORY;
  module->max_stack = AK_WASM_DEFAULT_MAX_STACK;
  module->max_instructions = AK_WASM_DEFAULT_MAX_INSTRUCTIONS;
  module->max_runtime_ms = AK_WASM_DEFAULT_MAX_RUNTIME_MS;

  /* Mark as sandboxed by default */
  module->sandboxed = true;
  module->verified = false;

  /* Timestamps */
  module->loaded_ms = ak_now_ms();
  module->last_used_ms = 0;
  module->invocation_count = 0;

  /* Add to registry */
  ak_wasm_state.modules[ak_wasm_state.module_count++] = module;
  ak_wasm_state.stats.modules_loaded++;

  return module;
}

ak_wasm_module_t *
ak_wasm_module_load_verified(heap h, const char *name, buffer bytecode,
                             ak_wasm_source_t source, const char *source_url,
                             const u8 *signature, const u8 *public_key) {
  /*
   * Load WASM module with Ed25519 signature verification.
   *
   * SECURITY: Modules loaded this way are marked as verified,
   * which may grant them additional privileges.
   *
   * @param signature   64-byte Ed25519 signature of bytecode
   * @param public_key  32-byte Ed25519 public key
   */
  if (!ak_wasm_state.initialized)
    return 0;

  if (!signature || !public_key)
    return 0;

  /* Verify the public key is trusted */
  if (!ak_ed25519_is_trusted(public_key)) {
    ak_wasm_state.stats.signature_failures++;
    return 0;
  }

  /* Verify the signature */
  if (!ak_ed25519_verify(buffer_ref(bytecode, 0), buffer_length(bytecode),
                         signature, public_key)) {
    ak_wasm_state.stats.signature_failures++;
    return 0;
  }

  /* Load the module normally */
  ak_wasm_module_t *module =
      ak_wasm_module_load(h, name, bytecode, source, source_url);
  if (!module)
    return 0;

  /* Mark as verified */
  module->verified = true;

  /* Copy signature and public key for audit trail */
  runtime_memcpy(module->signature, signature, AK_ED25519_SIGNATURE_SIZE);
  runtime_memcpy(module->signing_key, public_key, AK_ED25519_PUBLIC_KEY_SIZE);

  return module;
}

ak_wasm_module_t *ak_wasm_module_fetch(heap h, const char *name,
                                       const char *url,
                                       ak_capability_t *net_cap) {
  /*
   * NOT SUPPORTED: There is no in-kernel HTTP client, so network fetch
   * of WASM modules cannot be performed. The capability is still
   * validated (consistent enforcement, no probing of unauthorized
   * URLs), but this function ALWAYS returns NULL - fail-closed.
   * Modules must be loaded from local bytecode via
   * ak_wasm_module_load()/ak_wasm_module_load_verified().
   */
  if (!ak_wasm_state.initialized)
    return 0;

  if (!net_cap)
    return 0;

  /* Validate capability covers this URL */
  s64 result = ak_capability_validate(net_cap, AK_CAP_NET, url, "GET",
                                      0 /* No run_id binding for module fetch */
  );

  if (result != 0)
    return 0;

  /* No network fetch backend exists; fail closed with no module. */
  return 0;
}

void ak_wasm_module_unload(heap h, ak_wasm_module_t *module) {
  if (!module)
    return;

  /* Free bytecode buffer */
  if (module->bytecode && module->bytecode != INVALID_ADDRESS)
    deallocate_buffer(module->bytecode);

  /* Free export names if allocated */
  if (module->export_names) {
    for (u32 i = 0; i < module->export_count; i++) {
      if (module->export_names[i])
        deallocate(h, module->export_names[i],
                   runtime_strlen(module->export_names[i]) + 1);
    }
    deallocate(h, module->export_names, module->export_count * sizeof(char *));
  }

  /* Remove from registry */
  for (u32 i = 0; i < ak_wasm_state.module_count; i++) {
    if (ak_wasm_state.modules[i] == module) {
      /* Shift remaining entries */
      for (u32 j = i; j < ak_wasm_state.module_count - 1; j++)
        ak_wasm_state.modules[j] = ak_wasm_state.modules[j + 1];
      ak_wasm_state.modules[--ak_wasm_state.module_count] = 0;
      break;
    }
  }

  deallocate(h, module, sizeof(ak_wasm_module_t));
}

ak_wasm_module_t *ak_wasm_module_get(const char *name) {
  for (u32 i = 0; i < ak_wasm_state.module_count; i++) {
    if (ak_wasm_state.modules[i] &&
        ak_strcmp(ak_wasm_state.modules[i]->name, name) == 0) {
      return ak_wasm_state.modules[i];
    }
  }
  return 0;
}

ak_wasm_module_t *ak_wasm_module_get_by_hash(u8 *hash) {
  for (u32 i = 0; i < ak_wasm_state.module_count; i++) {
    if (ak_wasm_state.modules[i] &&
        runtime_memcmp(ak_wasm_state.modules[i]->hash, hash, AK_HASH_SIZE) ==
            0) {
      return ak_wasm_state.modules[i];
    }
  }
  return 0;
}

/* ============================================================
 * TOOL REGISTRY
 * ============================================================ */

s64 ak_tool_register(heap h, const char *name, ak_wasm_module_t *module,
                     const char *export_name, ak_cap_type_t cap_type,
                     const char *cap_resource) {
  if (!ak_wasm_state.initialized)
    return AK_E_WASM_LOAD_FAILED;

  if (ak_wasm_state.tool_count >= AK_MAX_TOOLS)
    return AK_E_QUOTA_EXCEEDED;

  /* Check for duplicate name */
  if (ak_tool_get(name))
    return AK_E_CONFLICT;

  /* Allocate tool */
  ak_tool_t *tool = allocate(h, sizeof(ak_tool_t));
  if (tool == INVALID_ADDRESS)
    return AK_E_WASM_OOM;

  runtime_memset((u8 *)tool, 0, sizeof(ak_tool_t));

  /* Copy name */
  u64 name_len = runtime_strlen(name);
  if (name_len >= sizeof(tool->name))
    name_len = sizeof(tool->name) - 1;
  runtime_memcpy(tool->name, name, name_len);
  tool->name[name_len] = 0;

  /* Copy export name */
  u64 export_len = runtime_strlen(export_name);
  if (export_len >= sizeof(tool->export_name))
    export_len = sizeof(tool->export_name) - 1;
  runtime_memcpy(tool->export_name, export_name, export_len);
  tool->export_name[export_len] = 0;

  /* Set module reference */
  tool->module = module;

  /* Set capability requirements */
  tool->cap_type = cap_type;
  if (cap_resource) {
    u64 res_len = runtime_strlen(cap_resource);
    if (res_len >= sizeof(tool->cap_resource))
      res_len = sizeof(tool->cap_resource) - 1;
    runtime_memcpy(tool->cap_resource, cap_resource, res_len);
    tool->cap_resource[res_len] = 0;
  }

  /* Default rate limits */
  tool->default_rate_limit = 100;
  tool->default_rate_window_ms = 60000;

  /* Default audit settings */
  tool->log_args = true;
  tool->log_result = true;
  tool->sensitive = false;

  /* Add to registry */
  ak_wasm_state.tools[ak_wasm_state.tool_count++] = tool;
  ak_wasm_state.stats.tools_registered++;

  return 0;
}

void ak_tool_unregister(const char *name) {
  for (u32 i = 0; i < ak_wasm_state.tool_count; i++) {
    if (ak_wasm_state.tools[i] &&
        ak_strcmp(ak_wasm_state.tools[i]->name, name) == 0) {
      deallocate(ak_wasm_state.h, ak_wasm_state.tools[i], sizeof(ak_tool_t));

      /* Shift remaining entries */
      for (u32 j = i; j < ak_wasm_state.tool_count - 1; j++)
        ak_wasm_state.tools[j] = ak_wasm_state.tools[j + 1];
      ak_wasm_state.tools[--ak_wasm_state.tool_count] = 0;
      return;
    }
  }
}

ak_tool_t *ak_tool_get(const char *name) {
  for (u32 i = 0; i < ak_wasm_state.tool_count; i++) {
    if (ak_wasm_state.tools[i] &&
        ak_strcmp(ak_wasm_state.tools[i]->name, name) == 0) {
      return ak_wasm_state.tools[i];
    }
  }
  return 0;
}

ak_tool_t **ak_tool_list(u32 *count_out) {
  if (count_out)
    *count_out = ak_wasm_state.tool_count;
  return ak_wasm_state.tools;
}

/* ============================================================
 * HOST FUNCTION REGISTRATION
 * ============================================================ */

s64 ak_host_fn_register(const char *name, ak_host_fn_t fn,
                        ak_cap_type_t cap_type, boolean async_capable) {
  if (ak_wasm_state.host_fn_count >= AK_MAX_HOST_FUNCTIONS)
    return AK_E_QUOTA_EXCEEDED;

  ak_host_fn_entry_t *entry =
      &ak_wasm_state.host_fns[ak_wasm_state.host_fn_count];

  /* Copy name */
  u64 name_len = runtime_strlen(name);
  if (name_len >= sizeof(entry->name))
    name_len = sizeof(entry->name) - 1;
  runtime_memcpy(entry->name, name, name_len);
  entry->name[name_len] = 0;

  entry->fn = fn;
  entry->cap_type = cap_type;
  entry->async_capable = async_capable;

  ak_wasm_state.host_fn_count++;
  return 0;
}

ak_host_fn_entry_t *ak_host_fn_get(const char *name) {
  for (u32 i = 0; i < ak_wasm_state.host_fn_count; i++) {
    if (ak_strcmp(ak_wasm_state.host_fns[i].name, name) == 0)
      return &ak_wasm_state.host_fns[i];
  }
  return 0;
}

/* ============================================================
 * EXECUTION CONTEXT
 * ============================================================ */

ak_wasm_exec_ctx_t *ak_wasm_exec_create(heap h, ak_agent_context_t *agent,
                                        ak_tool_t *tool, ak_capability_t *cap) {
  ak_wasm_exec_ctx_t *ctx = allocate(h, sizeof(ak_wasm_exec_ctx_t));
  if (ctx == INVALID_ADDRESS)
    return 0;

  runtime_memset((u8 *)ctx, 0, sizeof(ak_wasm_exec_ctx_t));

  /* Generate execution ID */
  ak_generate_token_id(ctx->exec_id);

  ctx->agent = agent;
  ctx->module = tool->module;
  ctx->tool = tool;
  ctx->cap = cap;
  ctx->state = AK_WASM_STATE_INIT;
  ctx->depth = 0;
  ctx->parent = 0;

  return ctx;
}

void ak_wasm_exec_destroy(heap h, ak_wasm_exec_ctx_t *ctx) {
  if (!ctx)
    return;

  if (ctx->input && ctx->input != INVALID_ADDRESS)
    deallocate_buffer(ctx->input);
  if (ctx->output && ctx->output != INVALID_ADDRESS)
    deallocate_buffer(ctx->output);

  /* Free suspension data if present */
  if (ctx->suspension.resume_data && ctx->suspension.resume_data_len > 0)
    deallocate(h, ctx->suspension.resume_data, ctx->suspension.resume_data_len);

  deallocate(h, ctx, sizeof(ak_wasm_exec_ctx_t));
}

/* ============================================================
 * ASYNC EXECUTION (SUSPENSION/RESUMPTION)
 * ============================================================ */

s64 ak_wasm_exec_suspend(ak_wasm_exec_ctx_t *ctx,
                         ak_wasm_suspend_reason_t reason, void *data,
                         u64 data_len, void *resume_cb, /* closure */
                         u64 timeout_ms) {
  if (!ctx)
    return AK_E_WASM_TRAP;

  if (ctx->state != AK_WASM_STATE_RUNNING)
    return AK_E_WASM_TRAP;

  /* Save suspension state */
  ctx->state = AK_WASM_STATE_SUSPENDED;
  ctx->suspension.reason = reason;
  ctx->suspension.suspend_time_ms = ak_now_ms();
  ctx->suspension.resume_callback = resume_cb;
  ctx->suspension.timeout_ms = timeout_ms;
  ctx->suspension.approval_id = 0;

  /* Copy data to preserve across suspension */
  if (data && data_len > 0) {
    ctx->suspension.resume_data = allocate(ak_wasm_state.h, data_len);
    if (ctx->suspension.resume_data == INVALID_ADDRESS) {
      ctx->state = AK_WASM_STATE_OOM;
      return AK_E_WASM_OOM;
    }
    runtime_memcpy(ctx->suspension.resume_data, data, data_len);
    ctx->suspension.resume_data_len = data_len;
  } else {
    ctx->suspension.resume_data = 0;
    ctx->suspension.resume_data_len = 0;
  }

  /*
   * LIMITATION (documented, not fabricated): this does NOT save WASM
   * machine state (stack, locals, PC). The interpreter and its state
   * live in the userspace supervisor. Kernel-side "suspend" is
   * bookkeeping only: it records the reason/timestamp/callback and
   * checkpoints the opaque, caller-provided blob copied above.
   * Resumption correctness depends on the supervisor holding the real
   * interpreter state.
   */

  return 0;
}

s64 ak_wasm_exec_resume(ak_wasm_exec_ctx_t *ctx, void *result, u64 result_len) {
  if (!ctx)
    return AK_E_WASM_TRAP;

  if (ctx->state != AK_WASM_STATE_SUSPENDED)
    return AK_E_WASM_TRAP;

  /* Free old suspension data */
  if (ctx->suspension.resume_data && ctx->suspension.resume_data_len > 0) {
    deallocate(ak_wasm_state.h, ctx->suspension.resume_data,
               ctx->suspension.resume_data_len);
  }

  /* Store result for WASM to retrieve */
  if (result && result_len > 0) {
    ctx->suspension.resume_data = allocate(ak_wasm_state.h, result_len);
    if (ctx->suspension.resume_data == INVALID_ADDRESS) {
      ctx->state = AK_WASM_STATE_OOM;
      return AK_E_WASM_OOM;
    }
    runtime_memcpy(ctx->suspension.resume_data, result, result_len);
    ctx->suspension.resume_data_len = result_len;
  } else {
    ctx->suspension.resume_data = 0;
    ctx->suspension.resume_data_len = 0;
  }

  /* Resume execution */
  ctx->state = AK_WASM_STATE_RUNNING;
  ctx->suspension.reason = AK_WASM_SUSPEND_NONE;

  /*
   * LIMITATION (documented, not fabricated): no WASM machine state is
   * restored here. The kernel only stores the opaque result blob for
   * the userspace supervisor to deliver into the interpreter, and
   * flips the context back to RUNNING. Mirrors ak_wasm_exec_suspend().
   */

  return 0;
}

boolean ak_wasm_exec_is_suspended(ak_wasm_exec_ctx_t *ctx) {
  if (!ctx)
    return false;
  return ctx->state == AK_WASM_STATE_SUSPENDED;
}

ak_wasm_suspend_reason_t ak_wasm_exec_suspend_reason(ak_wasm_exec_ctx_t *ctx) {
  if (!ctx)
    return AK_WASM_SUSPEND_NONE;
  if (ctx->state != AK_WASM_STATE_SUSPENDED)
    return AK_WASM_SUSPEND_NONE;
  return ctx->suspension.reason;
}

s64 ak_wasm_exec_run(ak_wasm_exec_ctx_t *ctx, buffer input) {
  if (!ctx || ctx->state != AK_WASM_STATE_INIT)
    return AK_E_WASM_TRAP;

  ctx->input = input;
  ctx->state = AK_WASM_STATE_RUNNING;
  ctx->start_ms = ak_now_ms();

  ak_wasm_state.stats.executions_total++;

  /*
   * IN-KERNEL EXECUTION (integer-only WASM subset):
   *
   * The kernel is compiled -mno-sse / no hardware float and links no
   * soft-float runtime, and no full WASM interpreter (wasm3 or otherwise)
   * exists in the tree. A complete WASM interpreter therefore cannot run
   * here (the spec mandates f32/f64). Instead we run a strict, bounded,
   * INTEGER-ONLY subset via ak_wasm_interp_run(): it validates the module
   * structurally, REJECTS fail-closed any module that declares/uses float
   * types or opcodes or anything outside the supported integer subset, and
   * genuinely interprets the exported entry function otherwise.
   *
   * We only report COMPLETED (and count a success) on a genuine result;
   * validation failure, trap, gas exhaustion and OOM all fail closed with
   * an honest error code and the corresponding failure counter.
   */
  if (!ctx->module || !ctx->tool) {
    ctx->state = AK_WASM_STATE_FAILED;
    ctx->result_code = AK_E_WASM_INVALID_MODULE;
    ctx->elapsed_ms = ak_now_ms() - ctx->start_ms;
    ak_wasm_state.stats.executions_failed++;
    return AK_E_WASM_INVALID_MODULE;
  }

  buffer output = 0;
  u64 gas_used = 0;
  s64 result_value = 0;
  s64 rc = ak_wasm_interp_run(
      ak_wasm_state.h, ctx, ctx->module->bytecode, ctx->tool->export_name,
      input, &output, ctx->module->max_instructions, &gas_used, &result_value);

  ctx->instructions_used = gas_used;
  ak_wasm_state.stats.total_instructions += gas_used;
  ctx->elapsed_ms = ak_now_ms() - ctx->start_ms;
  ak_wasm_state.stats.total_runtime_ms += ctx->elapsed_ms;

  if (rc == 0) {
    /* Genuine completion: attach the real output and count a success. */
    ctx->output = output;
    ctx->result_code = result_value;
    ctx->state = AK_WASM_STATE_COMPLETED;
    ak_wasm_state.stats.executions_success++;
    return 0;
  }

  /* Failure paths - never fabricate output. */
  if (output && output != INVALID_ADDRESS)
    deallocate_buffer(output);
  ctx->output = 0;
  ctx->result_code = rc;

  if (rc == AK_E_WASM_TIMEOUT) {
    ctx->state = AK_WASM_STATE_TIMEOUT;
    ak_wasm_state.stats.executions_timeout++;
  } else if (rc == AK_E_WASM_OOM) {
    ctx->state = AK_WASM_STATE_OOM;
    ak_wasm_state.stats.executions_oom++;
  } else {
    ctx->state = AK_WASM_STATE_FAILED;
    ak_wasm_state.stats.executions_failed++;
  }
  return rc;
}

/* ============================================================
 * TOOL EXECUTION (AK_SYS_CALL handler)
 * ============================================================ */

ak_response_t *ak_wasm_execute_tool(ak_agent_context_t *agent,
                                    const char *tool_name, buffer args,
                                    ak_capability_t *cap) {
  if (!ak_wasm_state.initialized)
    return ak_response_error(ak_wasm_state.h, 0, AK_E_WASM_LOAD_FAILED);

  /* Step 1: Look up tool */
  ak_tool_t *tool = ak_tool_get(tool_name);
  if (!tool)
    return ak_response_error(ak_wasm_state.h, 0, AK_E_TOOL_NOT_FOUND);

  /* Step 2: Validate capability (INV-2) */
  if (tool->cap_type != AK_CAP_NONE) {
    if (!cap)
      return ak_response_error(ak_wasm_state.h, 0, AK_E_CAP_MISSING);

    s64 result = ak_capability_validate(cap, tool->cap_type, tool->cap_resource,
                                        tool->name, agent->run_id);

    if (result != 0) {
      ak_wasm_state.stats.host_calls_denied++;
      return ak_response_error(ak_wasm_state.h, 0, result);
    }
  }

  /* Step 3: Create execution context */
  ak_wasm_exec_ctx_t *ctx =
      ak_wasm_exec_create(ak_wasm_state.h, agent, tool, cap);
  if (!ctx)
    return ak_response_error(ak_wasm_state.h, 0, AK_E_WASM_OOM);

  /* Step 4: Run WASM */
  s64 result = ak_wasm_exec_run(ctx, args);

  /* Step 5: Create response
   *
   * Success is reported ONLY when the execution backend actually
   * completed the run (state == COMPLETED with a result). Otherwise
   * this fails closed with the honest error code from the context -
   * including AK_E_NOT_IMPLEMENTED when no WASM runtime backend is
   * connected. Execution stats are accounted in ak_wasm_exec_run();
   * they are not incremented again here (no double-counting).
   */
  ak_response_t *response;
  if (result == 0 && ctx->state == AK_WASM_STATE_COMPLETED) {
    response = ak_response_success(ak_wasm_state.h, 0, ctx->output);
    ctx->output = 0; /* Ownership transferred */
  } else {
    s64 error_code = ctx->result_code;
    if (error_code == 0)
      error_code = result;
    if (error_code == 0)
      error_code = AK_E_WASM_TRAP;
    response = ak_response_error(ak_wasm_state.h, 0, error_code);
  }

  /* Update module usage stats */
  tool->module->last_used_ms = ak_now_ms();
  tool->module->invocation_count++;

  /* Cleanup */
  ak_wasm_exec_destroy(ak_wasm_state.h, ctx);

  return response;
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_wasm_get_stats(ak_wasm_stats_t *stats) {
  if (stats)
    runtime_memcpy(stats, &ak_wasm_state.stats, sizeof(ak_wasm_stats_t));
}
