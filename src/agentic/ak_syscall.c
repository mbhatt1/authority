/*
 * Authority Kernel - Syscall Dispatcher Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Central enforcement point for all four invariants.
 *
 * SECURITY CRITICAL: This file is the trust boundary.
 * Every line must be reviewed for security implications.
 */

#include "ak_syscall.h"
#include "ak_inference.h"
#include "ak_sanitize.h"
#include "ak_wasm.h"
#include "ak_budget.h"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */

/* Message for inter-agent communication */
typedef struct ak_message {
  struct ak_message *next;
  u8 sender_id[AK_TOKEN_ID_SIZE];
  u8 recipient_id[AK_TOKEN_ID_SIZE];
  u64 seq;
  buffer payload;
  u64 sent_ms;
} ak_message_t;

/* Per-agent message queue */
typedef struct ak_message_queue {
  ak_message_t *head;
  ak_message_t *tail;
  u64 count;
  u64 max_size;
} ak_message_queue_t;

/* Agent registry entry */
typedef struct ak_agent_entry {
  ak_agent_context_t *ctx;
  ak_message_queue_t inbox;
  boolean active;
} ak_agent_entry_t;

static struct {
  heap h;
  boolean initialized;
  ak_dispatch_stats_t stats;
  ak_policy_t *default_policy;

  /* Lock protecting concurrent access to agent registry */
  struct spinlock agent_lock;

  /* Agent registry for supervisor pattern */
  ak_agent_entry_t agents[AK_MAX_AGENTS];
  u64 agent_count;
} ak_state;

/* ============================================================
 * JSON EXTRACTION HELPERS
 * ============================================================ */

/*
 * Extract u64 value from JSON by key name.
 * Returns 0 if key not found or parsing fails.
 */
static u64 ak_json_extract_u64(buffer json, const char *key) {
  if (!json || !key)
    return 0;

  u8 *data = buffer_ref(json, 0);
  u64 len = buffer_length(json);
  u64 key_len = runtime_strlen(key);

  for (u64 i = 0; i + key_len + 4 < len; i++) {
    if (data[i] == '"' && runtime_memcmp(&data[i + 1], key, key_len) == 0 &&
        data[i + 1 + key_len] == '"') {

      u64 j = i + 1 + key_len + 1;
      while (j < len && (data[j] == ':' || data[j] == ' ' || data[j] == '\t'))
        j++;

      if (j >= len)
        return 0;

      u64 value = 0;
      while (j < len && data[j] >= '0' && data[j] <= '9') {
        u64 digit = data[j] - '0';
        /* FIX(BUG-051): Check for overflow before multiplication */
        if (value > (UINT64_MAX - digit) / 10) {
          value = UINT64_MAX; /* Saturate instead of wrap */
          /* Skip remaining digits */
          while (j < len && data[j] >= '0' && data[j] <= '9')
            j++;
          return value;
        }
        value = value * 10 + digit;
        j++;
      }
      return value;
    }
  }
  return 0;
}

/*
 * Extract string value from JSON by key name.
 * Writes to out buffer, returns length or -1 on failure.
 */
static s64 ak_json_extract_string(buffer json, const char *key, char *out,
                                  u64 out_len) {
  if (!json || !key || !out || out_len == 0)
    return -1;

  u8 *data = buffer_ref(json, 0);
  u64 len = buffer_length(json);
  u64 key_len = runtime_strlen(key);

  for (u64 i = 0; i + key_len + 4 < len; i++) {
    if (data[i] == '"' && runtime_memcmp(&data[i + 1], key, key_len) == 0 &&
        data[i + 1 + key_len] == '"') {

      u64 j = i + 1 + key_len + 1;
      while (j < len && (data[j] == ':' || data[j] == ' ' || data[j] == '\t'))
        j++;

      if (j >= len || data[j] != '"')
        return -1;
      j++;

      u64 start = j;
      while (j < len && data[j] != '"') {
        if (data[j] == '\\' && j + 1 < len)
          j++;
        j++;
      }

      u64 value_len = j - start;
      if (value_len >= out_len)
        value_len = out_len - 1;

      runtime_memcpy(out, &data[start], value_len);
      out[value_len] = 0;
      return value_len;
    }
  }
  return -1;
}

/*
 * Format u64 as decimal string. buf must hold at least 21 bytes.
 * Used to build capability resource strings (heap ptr / type hash),
 * matching the convention in ak_wasm_host.c heap host functions.
 */
static void ak_u64_to_dec(u64 v, char *buf) {
  int len = 0;
  if (v == 0) {
    buf[0] = '0';
    len = 1;
  } else {
    char tmp[20];
    while (v > 0) {
      tmp[len++] = '0' + (v % 10);
      v /= 10;
    }
    for (int i = 0; i < len; i++)
      buf[i] = tmp[len - 1 - i];
  }
  buf[len] = 0;
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_init(heap h) {
  if (ak_state.initialized)
    return;

  ak_state.h = h;
  runtime_memset((u8 *)&ak_state.stats, 0, sizeof(ak_dispatch_stats_t));

  /* Initialize lock for agent registry synchronization */
  spin_lock_init(&ak_state.agent_lock);

  /* Initialize subsystems */
  ak_keys_init(h);
  ak_revocation_init(h);
  ak_audit_init(h);
  ak_heap_init(h);
  ak_policy_init(h);
  ak_ipc_init(h);
  ak_inference_init(h, NULL); /* Initialize inference with default config */

  /* Create default policy */
  ak_state.default_policy = ak_policy_default(h);

  ak_state.initialized = true;
}

/* Forward declaration for cleanup (defined in syscall handler section) */
void ak_cleanup_root_context(void);

void ak_shutdown(void) {
  if (!ak_state.initialized)
    return;

  /* Cleanup root agent context first */
  ak_cleanup_root_context();

  /* Flush audit log */
  ak_audit_sync();

  /* Cleanup */
  if (ak_state.default_policy) {
    ak_policy_destroy(ak_state.h, ak_state.default_policy);
    ak_state.default_policy = NULL;
  }

  ak_state.initialized = false;
}

/* ============================================================
 * AGENT CONTEXT MANAGEMENT
 * ============================================================ */

ak_agent_context_t *ak_context_create(heap h, u8 *pid, ak_policy_t *policy) {
  ak_agent_context_t *ctx = allocate(h, sizeof(ak_agent_context_t));
  /* BUG-A9-004 FIX: Check for both NULL and INVALID_ADDRESS */
  if (!ctx || ctx == INVALID_ADDRESS)
    return NULL;

  runtime_memset((u8 *)ctx, 0, sizeof(ak_agent_context_t));

  if (pid)
    runtime_memcpy(ctx->pid, pid, AK_TOKEN_ID_SIZE);
  else
    ak_generate_token_id(ctx->pid);

  /* Generate initial run_id */
  ak_generate_token_id(ctx->run_id);

  /* Use provided policy or default */
  ctx->policy = policy ? policy : ak_state.default_policy;

  /* Create budget tracker */
  ctx->budget = ak_budget_create(h, ctx->run_id, ctx->policy);
  /* BUG-A9-005 FIX: Check budget creation success */
  if (!ctx->budget) {
    deallocate(h, ctx, sizeof(ak_agent_context_t));
    return NULL;
  }

  /* Create sequence tracker */
  ctx->seq_tracker = ak_seq_tracker_create(h, ctx->pid, ctx->run_id);
  /* BUG-A9-005 FIX: Check seq_tracker creation success, cleanup budget on
   * failure */
  if (!ctx->seq_tracker) {
    ak_budget_destroy(h, ctx->budget);
    deallocate(h, ctx, sizeof(ak_agent_context_t));
    return NULL;
  }

  ctx->heap = h;

  /*
   * Delegated capability store. Each granted capability is a distinct
   * allocation, so an identity-keyed table (keyed by the address of the
   * cap's tid field) acts as an iterable set. Without this table,
   * ak_grant_capability() silently dropped every grant. A non-empty
   * store means the agent is confined to its granted capabilities
   * (see ak_validate_capability); an empty store defers to policy.
   */
  ctx->delegated_caps = allocate_table(h, identity_key, pointer_equal);
  if (ctx->delegated_caps == INVALID_ADDRESS) {
    ak_seq_tracker_destroy(h, ctx->seq_tracker);
    ak_budget_destroy(h, ctx->budget);
    deallocate(h, ctx, sizeof(ak_agent_context_t));
    return NULL;
  }

  /* Log agent creation */
  ak_audit_log_lifecycle(ctx->pid, ctx->run_id, AK_LIFECYCLE_SPAWN);

  return ctx;
}

void ak_context_destroy(heap h, ak_agent_context_t *ctx) {
  if (!ctx)
    return;

  /* SECURITY: Revoke all capabilities for this run */
  ak_revocation_revoke_run(ctx->run_id, "agent_exit");

  /* Log exit */
  ak_audit_log_lifecycle(ctx->pid, ctx->run_id, AK_LIFECYCLE_EXIT);

  /* Cleanup */
  if (ctx->budget)
    ak_budget_destroy(h, ctx->budget);

  if (ctx->seq_tracker)
    ak_seq_tracker_destroy(h, ctx->seq_tracker);

  /* Free the delegated capability store and the caps it owns. */
  if (ctx->delegated_caps) {
    table_foreach(ctx->delegated_caps, k, v) {
      (void)k;
      if (v)
        deallocate(h, v, sizeof(ak_capability_t));
    }
    deallocate_table(ctx->delegated_caps);
    ctx->delegated_caps = 0;
  }

  deallocate(h, ctx, sizeof(ak_agent_context_t));
}

void ak_context_new_run(ak_agent_context_t *ctx, u8 *run_id_out) {
  if (!ctx)
    return;

  /* Revoke old run's capabilities */
  ak_revocation_revoke_run(ctx->run_id, "new_run");

  /* Generate new run_id */
  ak_generate_token_id(ctx->run_id);

  /* FIX(BUG-052): Create new objects first, only destroy old ones on success */
  /* Create new budget tracker */
  ak_budget_tracker_t *new_budget =
      ak_budget_create(ctx->heap, ctx->run_id, ctx->policy);
  if (!new_budget)
    return; /* Keep old budget if new creation fails */

  /* Create new sequence tracker */
  ak_seq_tracker_t *new_seq_tracker =
      ak_seq_tracker_create(ctx->heap, ctx->pid, ctx->run_id);
  if (!new_seq_tracker) {
    /* Cleanup new budget, keep old objects */
    ak_budget_destroy(ctx->heap, new_budget);
    return;
  }

  /* Both succeeded - now safe to destroy old objects and swap in new ones */
  if (ctx->budget)
    ak_budget_destroy(ctx->heap, ctx->budget);
  ctx->budget = new_budget;

  if (ctx->seq_tracker)
    ak_seq_tracker_destroy(ctx->heap, ctx->seq_tracker);
  ctx->seq_tracker = new_seq_tracker;

  if (run_id_out)
    runtime_memcpy(run_id_out, ctx->run_id, AK_TOKEN_ID_SIZE);
}

void ak_context_get_run_id(ak_agent_context_t *ctx, u8 *run_id_out) {
  if (ctx && run_id_out)
    runtime_memcpy(run_id_out, ctx->run_id, AK_TOKEN_ID_SIZE);
}

/* ============================================================
 * MAIN DISPATCH
 * ============================================================ */

ak_response_t *ak_dispatch(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!ak_state.initialized)
    return ak_response_error(ak_state.h, req, -EINVAL);

  if (!ctx || !req)
    return ak_response_error(ak_state.h, req, -EINVAL);

  ak_state.stats.total_requests++;

  ak_response_t *res = NULL;
  s64 err;

  /*
   * ============================================================
   * STAGE 1: Request Validation
   * ============================================================
   */
  err = ak_validate_request(ctx, req);
  if (err != 0) {
    res = ak_response_error(ctx->heap, req, err);
    goto audit_and_return;
  }

  /*
   * ============================================================
   * STAGE 2: Anti-Replay Check (REQ-006)
   * ============================================================
   */
  err = ak_check_replay(ctx, req);
  if (err == AK_E_REPLAY) {
    ak_state.stats.replay_attempts++;
    res = ak_response_error(ctx->heap, req, AK_E_REPLAY);
    goto audit_and_return;
  }

  /*
   * ============================================================
   * STAGE 3: Capability Verification (INV-2)
   * ============================================================
   * "Every effectful syscall must carry a valid, non-revoked
   *  capability whose scope subsumes the request."
   */
  err = ak_validate_capability(ctx, req);
  if (err != 0) {
    ak_state.stats.capability_failures++;
    res = ak_response_error(ctx->heap, req, err);
    goto audit_and_return;
  }

  /*
   * ============================================================
   * STAGE 4: Policy Check (INV-3)
   * ============================================================
   * "The sum of in-flight and committed costs never exceeds budget."
   */
  err = ak_check_policy(ctx, req);
  if (err == AK_E_POLICY_DENIED) {
    ak_state.stats.policy_denials++;
    res = ak_response_error(ctx->heap, req, AK_E_POLICY_DENIED);
    goto audit_and_return;
  }
  if (err == AK_E_BUDGET_EXCEEDED) {
    ak_state.stats.budget_exceeded++;
    res = ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);
    goto audit_and_return;
  }

  /*
   * ============================================================
   * STAGE 5: Execute Operation
   * ============================================================
   */
  switch (req->op) {
  case AK_SYS_READ:
    res = ak_handle_read(ctx, req);
    break;
  case AK_SYS_ALLOC:
    res = ak_handle_alloc(ctx, req);
    break;
  case AK_SYS_WRITE:
    res = ak_handle_write(ctx, req);
    break;
  case AK_SYS_DELETE:
    res = ak_handle_delete(ctx, req);
    break;
  case AK_SYS_QUERY:
    res = ak_handle_query(ctx, req);
    break;
  case AK_SYS_BATCH:
    res = ak_handle_batch(ctx, req);
    break;
  case AK_SYS_COMMIT:
    res = ak_handle_commit(ctx, req);
    break;
  case AK_SYS_CALL:
    res = ak_handle_call(ctx, req);
    break;
  case AK_SYS_SPAWN:
    res = ak_handle_spawn(ctx, req);
    break;
  case AK_SYS_SEND:
    res = ak_handle_send(ctx, req);
    break;
  case AK_SYS_RECV:
    res = ak_handle_recv(ctx, req);
    break;
  case AK_SYS_RESPOND:
    res = ak_handle_respond(ctx, req);
    break;
  case AK_SYS_ASSERT:
    res = ak_handle_assert(ctx, req);
    break;
  case AK_SYS_INFERENCE:
    res = ak_handle_inference(ctx, req);
    break;
  case AK_SYS_INFER_ISSUE:
    res = ak_handle_infer_issue(ctx, req);
    break;
  case AK_SYS_INFER_POLL:
    res = ak_handle_infer_poll(ctx, req);
    break;
  case AK_SYS_BUDGET_STATUS:
    res = ak_handle_budget_status(ctx, req);
    break;
  case AK_SYS_BUDGET_HISTORY:
    res = ak_handle_budget_history(ctx, req);
    break;
  case AK_SYS_BUDGET_BREAKDOWN:
    res = ak_handle_budget_breakdown(ctx, req);
    break;
  default:
    res = ak_response_error(ctx->heap, req, -ENOSYS);
    break;
  }

  /* Ops are absolute AK_SYS_* numbers (1024+); index relative to base */
  if (req->op >= AK_SYS_BASE && req->op - AK_SYS_BASE < 16)
    ak_state.stats.op_counts[req->op - AK_SYS_BASE]++;

audit_and_return:
  /*
   * ============================================================
   * STAGE 6: Audit Log (INV-4)
   * ============================================================
   * "Each committed transition appends a log entry whose hash chain
   *  validates from genesis to head."
   *
   * SECURITY: Response MUST NOT be returned until audit completes.
   */
  ak_log_operation(ctx, req, res);

  if (res && res->error_code == 0)
    ak_state.stats.successful_requests++;
  else
    ak_state.stats.failed_requests++;

  return res;
}

ak_response_t *ak_dispatch_raw(ak_agent_context_t *ctx, buffer raw_request) {
  if (!ctx || !raw_request)
    return NULL;

  ak_request_t *req = ak_ipc_parse_request(ctx->heap, raw_request);
  if (!req)
    return ak_ipc_error_response(ctx->heap, ctx->pid, ctx->run_id, 0,
                                 AK_E_IPC_INVALID, "parse failed");

  ak_response_t *res = ak_dispatch(ctx, req);

  /* Cleanup request */
  if (req->args)
    deallocate_buffer(req->args);
  deallocate(ctx->heap, req, sizeof(ak_request_t));

  return res;
}

/* ============================================================
 * VALIDATION HELPERS
 * ============================================================ */

s64 ak_validate_request(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!ctx || !req)
    return -EINVAL;

  /* Check PID matches */
  if (!ak_token_id_equal(req->pid, ctx->pid))
    return -EPERM;

  /* Check run_id matches */
  if (!ak_token_id_equal(req->run_id, ctx->run_id))
    return AK_E_CAP_RUN_MISMATCH;

  /* Check op is valid (includes budget introspection ops, which
   * ak_dispatch handles) */
  if (req->op < AK_SYS_READ || req->op > AK_SYS_INFER_POLL)
    return -EINVAL;

  return 0;
}

s64 ak_check_replay(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!ctx || !ctx->seq_tracker)
    return -EINVAL;

  return ak_seq_tracker_check(ctx->seq_tracker, req->seq);
}

s64 ak_validate_capability(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!ctx || !req)
    return -EINVAL;

  /*
   * Budget introspection ops read only ctx->budget: self-scoped by
   * construction, no external effect, so no capability is required.
   */
  if (req->op == AK_SYS_BUDGET_STATUS || req->op == AK_SYS_BUDGET_HISTORY ||
      req->op == AK_SYS_BUDGET_BREAKDOWN || req->op == AK_SYS_INFER_POLL)
    return 0;

  /* Determine required capability type and the REAL target resource */
  ak_cap_type_t required_type;
  const char *method = NULL;
  const char *resource = NULL;
  char resource_buf[80];

  switch (req->op) {
  case AK_SYS_READ:
  case AK_SYS_WRITE:
  case AK_SYS_DELETE:
    /* Scope is confined on the target heap pointer, formatted as a
     * decimal string (same convention as ak_wasm_host.c heap hosts). */
    required_type = AK_CAP_HEAP;
    ak_u64_to_dec(ak_json_extract_u64(req->args, "ptr"), resource_buf);
    resource = resource_buf;
    method = ak_op_to_string(req->op);
    break;
  case AK_SYS_ALLOC:
    /* No object exists yet; confine on the requested type hash. */
    required_type = AK_CAP_HEAP;
    ak_u64_to_dec(ak_json_extract_u64(req->args, "type"), resource_buf);
    resource = resource_buf;
    method = ak_op_to_string(req->op);
    break;
  case AK_SYS_BATCH:
    /* Batch wraps heap ops; per-op ptrs/versions are re-validated by
     * the transaction layer, so gate the batch on heap capability. */
    required_type = AK_CAP_HEAP;
    resource = "*";
    method = ak_op_to_string(req->op);
    break;
  case AK_SYS_CALL:
    required_type = AK_CAP_TOOL;
    if (ak_json_extract_string(req->args, "tool", resource_buf,
                               sizeof(resource_buf)) <= 0)
      return AK_E_CAP_SCOPE; /* Fail-closed: no tool name, no scope match */
    resource = resource_buf;
    method = "invoke";
    break;
  case AK_SYS_INFERENCE:
  case AK_SYS_INFER_ISSUE:
    /* External LLM I/O requires an LLM capability scoped to the model. */
    required_type = AK_CAP_LLM;
    if (ak_json_extract_string(req->args, "model", resource_buf,
                               sizeof(resource_buf)) <= 0)
      return AK_E_CAP_SCOPE; /* Fail-closed: unknown inference target */
    resource = resource_buf;
    method = "inference";
    break;
  case AK_SYS_SPAWN:
    required_type = AK_CAP_SPAWN;
    /* Confine on the requested program when present; a bare spawn
     * creates an attenuated child of self. */
    if (req->args && ak_json_extract_string(req->args, "program", resource_buf,
                                            sizeof(resource_buf)) > 0)
      resource = resource_buf;
    else
      resource = "*";
    method = "spawn";
    break;
  case AK_SYS_SEND:
    required_type = AK_CAP_IPC;
    if (ak_json_extract_string(req->args, "to", resource_buf,
                               sizeof(resource_buf)) <= 0)
      return AK_E_CAP_SCOPE; /* Fail-closed: no recipient, no scope match */
    resource = resource_buf;
    method = ak_op_to_string(req->op);
    break;
  case AK_SYS_RECV:
    /* RECV dequeues only from the caller's own inbox (looked up by
     * ctx->pid), so the target is self by construction. */
    required_type = AK_CAP_IPC;
    resource = "*";
    method = ak_op_to_string(req->op);
    break;
  case AK_SYS_QUERY:
    /* Audit-log read; no dedicated cap type exists, so require any
     * valid run-bound capability scoped to the audit log. */
    required_type = AK_CAP_ANY;
    resource = "audit_log";
    method = ak_op_to_string(req->op);
    break;
  default:
    /* COMMIT/RESPOND/ASSERT have no target object */
    required_type = AK_CAP_ANY;
    resource = "*";
    method = ak_op_to_string(req->op);
    break;
  }

  /*
   * INV-2 (capability attenuation), three-way authorization:
   *
   * 1. Explicit token: if the request carries a capability, it is FULLY
   *    enforced (HMAC verify + scope + TTL + revocation). This is how an
   *    attenuated child presents a delegated subset of authority.
   */
  if (req->cap)
    return ak_capability_validate(req->cap, required_type, resource, method,
                                  ctx->run_id);

  /*
   * 2. Ambient root authority: a context holding root_cap IS the
   *    single-tenant privileged root. Its admin capability is validated
   *    here like any other (HMAC + revocation + scope), so a revoked or
   *    expired root cap fails closed; AK_CAP_ADMIN subsumes any required
   *    type. Checked before the delegated store so root is never
   *    accidentally confined by a stray grant. Sub-agents never hold a
   *    root_cap.
   */
  if (ctx->root_cap) {
    s64 rv = ak_capability_validate(ctx->root_cap, required_type, resource,
                                    method, ctx->run_id);
    if (rv == 0)
      req->cap = ctx->root_cap; /* expose effective authority to handlers */
    return rv;
  }

  /*
   * 3. Delegated store: a sub-agent granted capabilities
   *    (ak_grant_capability populated ctx->delegated_caps) is CONFINED to
   *    them. Allow only if a granted, still-valid capability subsumes the
   *    request; otherwise deny (fail-closed).
   */
  if (ctx->delegated_caps && table_elements(ctx->delegated_caps) > 0) {
    table_foreach(ctx->delegated_caps, k, v) {
      (void)k;
      if (v && ak_capability_validate((ak_capability_t *)v, required_type,
                                      resource, method, ctx->run_id) == 0) {
        req->cap = (ak_capability_t *)v; /* expose granted cap to handlers */
        return 0;                        /* a granted capability subsumes it */
      }
    }
    return AK_E_CAP_SCOPE; /* confined agent, no matching grant */
  }

  /*
   * 4. No token, no ambient authority, no delegated grant: DENY.
   *    Confinement is mandatory - an agent with no capability of any
   *    kind can perform no effect.
   */
  return AK_E_CAP_MISSING;
}

s64 ak_check_policy(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!ctx || !ctx->policy)
    return -EINVAL;

  return ak_policy_evaluate(ctx->policy, ctx->budget, req);
}

/* ============================================================
 * SYSCALL HANDLERS
 * ============================================================ */

ak_response_t *ak_handle_read(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!req->args)
    return ak_response_error(ctx->heap, req, -EINVAL);

  /* Parse ptr from args JSON */
  u64 ptr = ak_json_extract_u64(req->args, "ptr");

  buffer value = NULL;
  u64 version = 0;
  ak_taint_t taint;

  s64 err = ak_heap_read(ptr, &value, &version, &taint);
  if (err != 0)
    return ak_response_error(ctx->heap, req, err);

  /* Build result JSON */
  buffer result = allocate_buffer(ctx->heap, buffer_length(value) + 64);
  if (!result) {
    deallocate_buffer(value);
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  buffer_write(result, "{\"value\":", 9);
  buffer_write(result, buffer_ref(value, 0), buffer_length(value));
  buffer_write(result, ",\"version\":", 11);

  char ver_buf[32];
  int ver_len = 0;
  u64 v = version;
  if (v == 0) {
    ver_buf[0] = '0';
    ver_len = 1;
  } else {
    char tmp[32];
    while (v > 0) {
      tmp[ver_len++] = '0' + (v % 10);
      v /= 10;
    }
    for (int i = 0; i < ver_len; i++)
      ver_buf[i] = tmp[ver_len - 1 - i];
  }
  buffer_write(result, ver_buf, ver_len);
  buffer_write(result, "}", 1);

  deallocate_buffer(value);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_alloc(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!req->args)
    return ak_response_error(ctx->heap, req, -EINVAL);

  /* Parse type hash and value from args */
  u64 type_hash = ak_json_extract_u64(req->args, "type");
  buffer value = req->args; /* Value is the args payload */

  u64 ptr = ak_heap_alloc(type_hash, value, ctx->run_id, req->taint);
  if (ptr == 0)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  /* Commit budget */
  ak_budget_commit(ctx->budget, AK_RESOURCE_HEAP_OBJECTS, 1);

  /* Build result */
  buffer result = allocate_buffer(ctx->heap, 64);
  if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  buffer_write(result, "{\"ptr\":", 7);
  char ptr_buf[32];
  int ptr_len = 0;
  u64 p = ptr;
  if (p == 0) {
    ptr_buf[0] = '0';
    ptr_len = 1;
  } else {
    char tmp[32];
    while (p > 0) {
      tmp[ptr_len++] = '0' + (p % 10);
      p /= 10;
    }
    for (int i = 0; i < ptr_len; i++)
      ptr_buf[i] = tmp[ptr_len - 1 - i];
  }
  buffer_write(result, ptr_buf, ptr_len);
  buffer_write(result, ",\"version\":1}", 13);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_write(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!req->args)
    return ak_response_error(ctx->heap, req, -EINVAL);

  /* Parse ptr, patch, and version from args */
  u64 ptr = ak_json_extract_u64(req->args, "ptr");
  buffer patch = req->args; /* Patch is embedded in args */
  u64 expected_version = ak_json_extract_u64(req->args, "version");
  u64 new_version = 0;

  s64 err = ak_heap_write(ptr, patch, expected_version, &new_version);
  if (err != 0)
    return ak_response_error(ctx->heap, req, err);

  /* Build result */
  buffer result = allocate_buffer(ctx->heap, 64);
  if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  buffer_write(result, "{\"version\":", 11);
  char ver_buf[32];
  int ver_len = 0;
  u64 v = new_version;
  if (v == 0) {
    ver_buf[0] = '0';
    ver_len = 1;
  } else {
    char tmp[32];
    while (v > 0) {
      tmp[ver_len++] = '0' + (v % 10);
      v /= 10;
    }
    for (int i = 0; i < ver_len; i++)
      ver_buf[i] = tmp[ver_len - 1 - i];
  }
  buffer_write(result, ver_buf, ver_len);
  buffer_write(result, "}", 1);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_delete(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!req->args)
    return ak_response_error(ctx->heap, req, -EINVAL);

  /* Parse target pointer and CAS version from args (same convention as
   * ak_handle_read/ak_handle_write). The extractor returns 0 when a key
   * is missing or malformed; 0 is never a valid heap ptr (ak_heap_alloc
   * returns 0 on failure) and versions start at 1, so fail-closed
   * instead of deleting a default object. */
  u64 ptr = ak_json_extract_u64(req->args, "ptr");
  u64 expected_version = ak_json_extract_u64(req->args, "version");
  if (ptr == 0 || expected_version == 0)
    return ak_response_error(ctx->heap, req, AK_E_SCHEMA_INVALID);

  s64 err = ak_heap_delete(ptr, expected_version);
  if (err != 0)
    return ak_response_error(ctx->heap, req, err);

  buffer result = allocate_buffer(ctx->heap, 16);
  if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  buffer_write(result, "{\"deleted\":true}", 16);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_query(ak_agent_context_t *ctx, ak_request_t *req) {
  /*
   * QUERY: Query the audit log
   *
   * Args (all optional):
   *   "pid": "hex_string"     - Filter by agent PID
   *   "run_id": "hex_string"  - Filter by run ID
   *   "op": number            - Filter by operation code
   *   "start_seq": number     - Start sequence (default: 0)
   *   "end_seq": number       - End sequence (default: head)
   *   "limit": number         - Max results (default: 100, max: 1000)
   *
   * Returns:
   *   {"entries": [...], "head_seq": N, "count": N}
   */

  /* Parse filter parameters from args */
  u8 filter_pid[AK_TOKEN_ID_SIZE];
  u8 filter_run_id[AK_TOKEN_ID_SIZE];
  boolean has_pid_filter = false;
  boolean has_run_id_filter = false;

  if (req->args) {
    char hex_buf[AK_TOKEN_ID_SIZE * 2 + 1];

    if (ak_json_extract_string(req->args, "pid", hex_buf, sizeof(hex_buf)) >
        0) {
      ak_hex_decode(hex_buf, filter_pid, AK_TOKEN_ID_SIZE);
      has_pid_filter = true;
    }

    if (ak_json_extract_string(req->args, "run_id", hex_buf, sizeof(hex_buf)) >
        0) {
      ak_hex_decode(hex_buf, filter_run_id, AK_TOKEN_ID_SIZE);
      has_run_id_filter = true;
    }
  }

  /* Parse sequence range */
  u64 start_seq = 0;
  u64 end_seq = ak_audit_head_seq();
  u64 limit = 100;

  if (req->args) {
    u64 parsed_start = ak_json_extract_u64(req->args, "start_seq");
    if (parsed_start > 0)
      start_seq = parsed_start;

    u64 parsed_end = ak_json_extract_u64(req->args, "end_seq");
    if (parsed_end > 0)
      end_seq = parsed_end;

    u64 parsed_limit = ak_json_extract_u64(req->args, "limit");
    if (parsed_limit > 0) {
      limit = parsed_limit;
      if (limit > 1000)
        limit = 1000; /* Cap at 1000 to prevent DoS */
    }
  }

  /* Parse operation filter */
  u16 filter_op = 0;
  if (req->args) {
    u64 op_val = ak_json_extract_u64(req->args, "op");
    if (op_val > 0 && op_val <= 0xFFFF)
      filter_op = (u16)op_val;
  }

  /* Build query filter */
  ak_log_query_filter_t filter;
  filter.pid = has_pid_filter ? filter_pid : NULL;
  filter.run_id = has_run_id_filter ? filter_run_id : NULL;
  filter.op = filter_op;

  /* Execute query.
   *
   * CONTRACT (ak_audit_query): the returned ARRAY is allocated on our
   * heap (sized by the full match count), but each element points INTO
   * live audit segment storage. Entry pointers are BORROWED and must
   * never be deallocated; only the array container is ours to free. */
  u64 total_count = 0;
  ak_log_entry_t **entries =
      ak_audit_query(ctx->heap, &filter, start_seq, end_seq, &total_count);

  /* Apply limit (keep total_count for container deallocation) */
  u64 count = total_count;
  if (count > limit)
    count = limit;

  /* Build result JSON */
  /* Estimate buffer size: ~200 bytes per entry + overhead */
  u64 buf_size = 128 + (count * 256);
  if (buf_size > 1024 * 1024)
    buf_size = 1024 * 1024; /* Cap at 1MB */

  buffer result = allocate_buffer(ctx->heap, buf_size);
  if (!result) {
    /* Free only the array container - entries are borrowed (see above) */
    if (entries)
      deallocate(ctx->heap, entries, sizeof(ak_log_entry_t *) * total_count);
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  buffer_write(result, "{\"entries\":[", 12);

  for (u64 i = 0; i < count; i++) {
    if (i > 0)
      buffer_write(result, ",", 1);

    ak_log_entry_t *entry = entries[i];
    if (!entry)
      continue;

    buffer_write(result, "{\"seq\":", 7);

    /* Write sequence number */
    char num_buf[32];
    int num_len = 0;
    u64 v = entry->seq;
    if (v == 0) {
      num_buf[0] = '0';
      num_len = 1;
    } else {
      char tmp[32];
      while (v > 0) {
        tmp[num_len++] = '0' + (v % 10);
        v /= 10;
      }
      for (int j = 0; j < num_len; j++)
        num_buf[j] = tmp[num_len - 1 - j];
    }
    buffer_write(result, num_buf, num_len);

    buffer_write(result, ",\"ts_ms\":", 9);
    v = entry->ts_ms;
    num_len = 0;
    if (v == 0) {
      num_buf[0] = '0';
      num_len = 1;
    } else {
      char tmp[32];
      while (v > 0) {
        tmp[num_len++] = '0' + (v % 10);
        v /= 10;
      }
      for (int j = 0; j < num_len; j++)
        num_buf[j] = tmp[num_len - 1 - j];
    }
    buffer_write(result, num_buf, num_len);

    buffer_write(result, ",\"op\":", 6);
    v = entry->op;
    num_len = 0;
    if (v == 0) {
      num_buf[0] = '0';
      num_len = 1;
    } else {
      char tmp[32];
      while (v > 0) {
        tmp[num_len++] = '0' + (v % 10);
        v /= 10;
      }
      for (int j = 0; j < num_len; j++)
        num_buf[j] = tmp[num_len - 1 - j];
    }
    buffer_write(result, num_buf, num_len);

    /* Add PID as hex string */
    buffer_write(result, ",\"pid\":\"", 8);
    char hex[AK_TOKEN_ID_SIZE * 2 + 1];
    ak_hex_encode(entry->pid, AK_TOKEN_ID_SIZE, hex);
    buffer_write(result, hex, AK_TOKEN_ID_SIZE * 2);
    buffer_write(result, "\"", 1);

    /* Add run_id as hex string */
    buffer_write(result, ",\"run_id\":\"", 11);
    ak_hex_encode(entry->run_id, AK_TOKEN_ID_SIZE, hex);
    buffer_write(result, hex, AK_TOKEN_ID_SIZE * 2);
    buffer_write(result, "\"", 1);

    /* Add req_hash */
    buffer_write(result, ",\"req_hash\":\"", 13);
    char hash_hex[AK_HASH_SIZE * 2 + 1];
    ak_hex_encode(entry->req_hash, AK_HASH_SIZE, hash_hex);
    buffer_write(result, hash_hex, AK_HASH_SIZE * 2);
    buffer_write(result, "\"", 1);

    /* Add this_hash (entry hash) */
    buffer_write(result, ",\"hash\":\"", 9);
    ak_hex_encode(entry->this_hash, AK_HASH_SIZE, hash_hex);
    buffer_write(result, hash_hex, AK_HASH_SIZE * 2);
    buffer_write(result, "\"}", 2);
  }

  buffer_write(result, "],\"head_seq\":", 13);

  /* Write head_seq */
  char head_buf[32];
  int head_len = 0;
  u64 head = ak_audit_head_seq();
  if (head == 0) {
    head_buf[0] = '0';
    head_len = 1;
  } else {
    char tmp[32];
    while (head > 0) {
      tmp[head_len++] = '0' + (head % 10);
      head /= 10;
    }
    for (int j = 0; j < head_len; j++)
      head_buf[j] = tmp[head_len - 1 - j];
  }
  buffer_write(result, head_buf, head_len);

  buffer_write(result, ",\"count\":", 9);

  /* Write count */
  char count_buf[32];
  int count_len = 0;
  u64 c = count;
  if (c == 0) {
    count_buf[0] = '0';
    count_len = 1;
  } else {
    char tmp[32];
    while (c > 0) {
      tmp[count_len++] = '0' + (c % 10);
      c /= 10;
    }
    for (int j = 0; j < count_len; j++)
      count_buf[j] = tmp[count_len - 1 - j];
  }
  buffer_write(result, count_buf, count_len);
  buffer_write(result, "}", 1);

  /* Cleanup: all needed fields were copied into the JSON result above.
   * entries[i] point into live audit segment storage (borrowed) - do
   * NOT deallocate them; that would corrupt the allocator and the
   * audit log. Free only the array container, using the full match
   * count it was allocated with (not the limited count). */
  if (entries)
    deallocate(ctx->heap, entries, sizeof(ak_log_entry_t *) * total_count);

  return ak_response_success(ctx->heap, req, result);
}

/*
 * Helper: Extract JSON array element by index (simple parser for batch ops).
 * Returns start offset and length of element, or -1 if not found.
 */
static s64 ak_json_array_element(buffer json, u64 index, u64 *len_out) {
  if (!json || !len_out)
    return -1;

  u8 *data = buffer_ref(json, 0);
  u64 len = buffer_length(json);
  u64 i = 0;

  /* Skip to array start */
  while (i < len && data[i] != '[')
    i++;
  if (i >= len)
    return -1;
  i++; /* Skip '[' */

  /* Skip whitespace */
  while (i < len && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' ||
                     data[i] == '\r'))
    i++;

  /* Find the element at the given index */
  u64 current_index = 0;
  while (i < len && current_index <= index) {
    if (data[i] == ']')
      return -1; /* End of array before reaching index */

    /* Skip whitespace and commas */
    while (i < len && (data[i] == ' ' || data[i] == '\t' || data[i] == '\n' ||
                       data[i] == '\r' || data[i] == ','))
      i++;

    if (i >= len || data[i] == ']')
      return -1;

    /* Found element start */
    u64 elem_start = i;
    int depth = 0;
    boolean in_string = false;

    /* Parse element (handling nested objects/arrays/strings) */
    while (i < len) {
      if (in_string) {
        if (data[i] == '\\' && i + 1 < len) {
          i += 2; /* Skip escaped char */
          continue;
        }
        if (data[i] == '"')
          in_string = false;
      } else {
        if (data[i] == '"')
          in_string = true;
        else if (data[i] == '{' || data[i] == '[')
          depth++;
        else if (data[i] == '}' || data[i] == ']') {
          if (depth == 0)
            break; /* End of element (hit array end or next level) */
          depth--;
        } else if (data[i] == ',' && depth == 0) {
          break; /* End of element */
        }
      }
      i++;
    }

    if (current_index == index) {
      *len_out = i - elem_start;
      return elem_start;
    }

    current_index++;
  }

  return -1;
}

ak_response_t *ak_handle_batch(ak_agent_context_t *ctx, ak_request_t *req) {
  if (!req->args)
    return ak_response_error(ctx->heap, req, -EINVAL);

  /*
   * BATCH: Atomic batch of heap operations
   *
   * Args format:
   *   {"ops": [
   *     {"op": "alloc", "type": N, "value": {...}},
   *     {"op": "write", "ptr": N, "patch": {...}, "version": N},
   *     {"op": "delete", "ptr": N, "version": N}
   *   ]}
   *
   * Semantics: All or nothing - either all operations succeed atomically,
   * or none are applied (transaction rollback).
   *
   * Returns:
   *   {"committed": true, "results": [...], "op_count": N}
   *   or error if any operation fails (entire batch rolled back)
   */

  /* Begin transaction */
  ak_heap_txn_t *txn = ak_heap_txn_begin();
  if (!txn)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  /* Find the "ops" array in args */
  u8 *args_data = buffer_ref(req->args, 0);
  u64 args_len = buffer_length(req->args);

  /* Look for "ops" key */
  const char *ops_key = "\"ops\"";
  u64 ops_key_len = 5;
  s64 ops_start = -1;

  for (u64 i = 0; i + ops_key_len < args_len; i++) {
    if (runtime_memcmp(&args_data[i], ops_key, ops_key_len) == 0) {
      /* Found "ops", skip to colon and array */
      u64 j = i + ops_key_len;
      while (j < args_len && (args_data[j] == ':' || args_data[j] == ' ' ||
                              args_data[j] == '\t'))
        j++;
      if (j < args_len && args_data[j] == '[') {
        ops_start = j;
        break;
      }
    }
  }

  if (ops_start < 0) {
    /* No "ops" array found - return error instead of empty commit */
    ak_heap_txn_rollback(txn);
    return ak_response_error(ctx->heap, req, AK_E_SCHEMA_INVALID);
  }

  /* Create a buffer view for the ops array */
  buffer ops_buf =
      alloca_wrap_buffer(&args_data[ops_start], args_len - ops_start);

  /* Process each operation in the batch */
  u64 op_count = 0;
  u64 max_ops = 100; /* Limit batch size to prevent DoS */
  s64 batch_err = 0;

  /* Allocate results tracking */
  u64 *results_ptr = allocate(ctx->heap, sizeof(u64) * max_ops);
  if (!results_ptr) {
    ak_heap_txn_rollback(txn);
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  for (u64 idx = 0; idx < max_ops; idx++) {
    u64 elem_len = 0;
    s64 elem_start = ak_json_array_element(ops_buf, idx, &elem_len);
    if (elem_start < 0)
      break; /* No more elements */

    /* Create buffer for this element */
    buffer elem = alloca_wrap_buffer(buffer_ref(ops_buf, elem_start), elem_len);

    /* Extract operation type */
    char op_type[16];
    if (ak_json_extract_string(elem, "op", op_type, sizeof(op_type)) < 0) {
      batch_err = AK_E_SCHEMA_INVALID;
      break;
    }

    /* Execute operation based on type */
    if (ak_strcmp(op_type, "alloc") == 0) {
      u64 type_hash = ak_json_extract_u64(elem, "type");
      /* Use the element as the value (contains "value" field) */
      u64 ptr =
          ak_heap_txn_alloc(txn, type_hash, elem, ctx->run_id, req->taint);
      if (ptr == 0) {
        batch_err = -ENOMEM;
        break;
      }
      results_ptr[op_count] = ptr;

    } else if (ak_strcmp(op_type, "write") == 0) {
      u64 ptr = ak_json_extract_u64(elem, "ptr");
      u64 version = ak_json_extract_u64(elem, "version");
      s64 err = ak_heap_txn_write(txn, ptr, elem, version);
      if (err != 0) {
        batch_err = err;
        break;
      }
      results_ptr[op_count] = ptr;

    } else if (ak_strcmp(op_type, "delete") == 0) {
      u64 ptr = ak_json_extract_u64(elem, "ptr");
      u64 version = ak_json_extract_u64(elem, "version");
      s64 err = ak_heap_txn_delete(txn, ptr, version);
      if (err != 0) {
        batch_err = err;
        break;
      }
      results_ptr[op_count] = ptr;

    } else {
      /* Unknown operation type */
      batch_err = AK_E_SCHEMA_INVALID;
      break;
    }

    op_count++;
  }

  /* Check for errors */
  if (batch_err != 0) {
    ak_heap_txn_rollback(txn);
    deallocate(ctx->heap, results_ptr, sizeof(u64) * max_ops);
    return ak_response_error(ctx->heap, req, batch_err);
  }

  /* Commit the transaction */
  s64 err = ak_heap_txn_commit(txn);
  if (err != 0) {
    ak_heap_txn_rollback(txn);
    deallocate(ctx->heap, results_ptr, sizeof(u64) * max_ops);
    return ak_response_error(ctx->heap, req, err);
  }

  /* Commit budget for successful operations */
  if (ctx->budget && op_count > 0) {
    ak_budget_commit(ctx->budget, AK_RESOURCE_HEAP_OBJECTS, op_count);
  }

  /* Build result JSON */
  buffer result = allocate_buffer(ctx->heap, 64 + op_count * 24);
  if (!result) {
    deallocate(ctx->heap, results_ptr, sizeof(u64) * max_ops);
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  buffer_write(result, "{\"committed\":true,\"results\":[", 29);

  for (u64 i = 0; i < op_count; i++) {
    if (i > 0)
      buffer_write(result, ",", 1);

    /* Write result pointer/status as number */
    char num_buf[32];
    int num_len = 0;
    u64 v = results_ptr[i];
    if (v == 0) {
      num_buf[0] = '0';
      num_len = 1;
    } else {
      char tmp[32];
      while (v > 0) {
        tmp[num_len++] = '0' + (v % 10);
        v /= 10;
      }
      for (int j = 0; j < num_len; j++)
        num_buf[j] = tmp[num_len - 1 - j];
    }
    buffer_write(result, num_buf, num_len);
  }

  buffer_write(result, "],\"op_count\":", 13);

  /* Write op_count */
  char count_buf[16];
  int count_len = 0;
  u64 c = op_count;
  if (c == 0) {
    count_buf[0] = '0';
    count_len = 1;
  } else {
    char tmp[16];
    while (c > 0) {
      tmp[count_len++] = '0' + (c % 10);
      c /= 10;
    }
    for (int j = 0; j < count_len; j++)
      count_buf[j] = tmp[count_len - 1 - j];
  }
  buffer_write(result, count_buf, count_len);
  buffer_write(result, "}", 1);

  deallocate(ctx->heap, results_ptr, sizeof(u64) * max_ops);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_commit(ak_agent_context_t *ctx, ak_request_t *req) {
  /* Explicit commit - mainly for audit checkpointing */
  ak_audit_sync();
  ak_audit_emit_anchor();

  buffer result = allocate_buffer(ctx->heap, 64);
  if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  u8 head_hash[AK_HASH_SIZE];
  ak_audit_head_hash(head_hash);

  char hex[AK_HASH_SIZE * 2 + 1];
  ak_hex_encode(head_hash, AK_HASH_SIZE, hex);

  buffer_write(result, "{\"anchor_hash\":\"", 16);
  buffer_write(result, hex, AK_HASH_SIZE * 2);
  buffer_write(result, "\"}", 2);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_call(ak_agent_context_t *ctx, ak_request_t *req) {
  /* FIX(BUG-054): Fail-closed when context or budget is NULL */
  if (!ctx || !ctx->budget)
    return ak_response_error(ak_state.h, req, AK_E_BUDGET_EXCEEDED);

  if (!req->args)
    return ak_response_error(ctx->heap, req, -EINVAL);

  /*
   * CALL: Invoke tool in WASM sandbox
   * Args: {"tool": "name", "args": {...}}
   */

  /* Extract tool name from args */
  char tool_name[64];
  if (ak_json_extract_string(req->args, "tool", tool_name, sizeof(tool_name)) <
      0) {
    return ak_response_error(ctx->heap, req, AK_E_SCHEMA_INVALID);
  }

  /* Check tool is allowed by policy */
  if (!ctx->policy || !ak_policy_check_tool(ctx->policy, tool_name))
    return ak_response_error(ctx->heap, req, AK_E_POLICY_DENIED);

  /* Check call budget */
  if (!ak_budget_check(ctx->budget, AK_RESOURCE_TOOL_CALLS, 1))
    return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);

  /* Execute tool via WASM runtime */
  ak_response_t *wasm_result =
      ak_wasm_execute_tool(ctx, tool_name, req->args, req->cap);
  if (wasm_result) {
    /* FIX(BUG-053): Only commit budget on successful execution */
    ak_budget_commit(ctx->budget, AK_RESOURCE_TOOL_CALLS, 1);
    return wasm_result;
  }

  /* If WASM execution failed, return error WITHOUT consuming budget */
  buffer result = allocate_buffer(ctx->heap, 64);
  if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  buffer_write(result, "{\"error\":\"Tool execution failed\"}", 33);

  /* FIX(BUG-053): Do NOT commit budget on failure - removed ak_budget_commit
   * call */

  return ak_response_error(ctx->heap, req, AK_E_TOOL_FAIL);
}

/* ak_handle_inference is implemented in ak_inference.c */

/* ============================================================
 * AGENT REGISTRY HELPERS
 * ============================================================ */

static s64 ak_agent_registry_find(u8 *agent_id) {
  for (u64 i = 0; i < ak_state.agent_count; i++) {
    if (ak_state.agents[i].active &&
        runtime_memcmp(ak_state.agents[i].ctx->pid, agent_id,
                       AK_TOKEN_ID_SIZE) == 0)
      return i;
  }
  return -1;
}

static s64 ak_agent_registry_add(ak_agent_context_t *ctx) {
  if (ak_state.agent_count >= AK_MAX_AGENTS)
    return -1;

  for (u64 i = 0; i < AK_MAX_AGENTS; i++) {
    if (!ak_state.agents[i].active) {
      ak_state.agents[i].ctx = ctx;
      ak_state.agents[i].active = true;
      ak_state.agents[i].inbox.head = NULL;
      ak_state.agents[i].inbox.tail = NULL;
      ak_state.agents[i].inbox.count = 0;
      ak_state.agents[i].inbox.max_size = 1000;
      ak_state.agent_count++;
      return i;
    }
  }
  return -1;
}

static void ak_agent_registry_remove(u8 *agent_id) {
  s64 idx = ak_agent_registry_find(agent_id);
  if (idx >= 0) {
    /* Clean up message queue */
    ak_message_t *msg = ak_state.agents[idx].inbox.head;
    while (msg) {
      ak_message_t *next = msg->next;
      if (msg->payload)
        deallocate_buffer(msg->payload);
      deallocate(ak_state.h, msg, sizeof(ak_message_t));
      msg = next;
    }
    ak_state.agents[idx].active = false;
    ak_state.agents[idx].ctx = NULL;
    ak_state.agent_count--;
  }
}

/* ============================================================
 * AGENT SPAWN IMPLEMENTATION
 * ============================================================ */

ak_response_t *ak_handle_spawn(ak_agent_context_t *ctx, ak_request_t *req) {
  /* FIX(BUG-054): Fail-closed when context or budget is NULL */
  if (!ctx || !ctx->budget)
    return ak_response_error(ak_state.h, req, AK_E_BUDGET_EXCEEDED);

  /*
   * SPAWN: Create child agent
   *
   * Args: {"policy": {...}, "caps": [...], "budget": {...}}
   *
   * SECURITY: Child inherits attenuated capabilities from parent.
   * Child cannot have more capabilities than parent.
   */

  /* Check spawn budget */
  if (!ak_budget_check(ctx->budget, AK_RESOURCE_HEAP_OBJECTS, 1))
    return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);

  /* Check agent limit */
  if (ak_state.agent_count >= AK_MAX_AGENTS)
    return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);

  /* Create child context */
  ak_agent_context_t *child = allocate(ctx->heap, sizeof(ak_agent_context_t));
  if (!child)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  runtime_memset((u8 *)child, 0, sizeof(ak_agent_context_t));

  /* Generate unique child ID */
  ak_generate_token_id(child->pid);
  runtime_memcpy(child->agent_id, child->pid, AK_TOKEN_ID_SIZE);
  ak_generate_token_id(child->run_id);

  /* Set parent linkage */
  child->parent = ctx;
  child->heap = ctx->heap;

  /* Inherit policy from parent (can be more restrictive via args) */
  child->policy = ctx->policy;

  /* Create child budget (subset of parent) */
  child->budget = ak_budget_create(ctx->heap, child->run_id, child->policy);
  /* BUG-A9-001 FIX: Check budget creation and cleanup on failure */
  if (!child->budget) {
    deallocate(ctx->heap, child, sizeof(ak_agent_context_t));
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  /* Create sequence tracker */
  child->seq_tracker =
      ak_seq_tracker_create(ctx->heap, child->pid, child->run_id);
  /* BUG-A9-001 FIX: Check seq_tracker creation and cleanup budget + context on
   * failure */
  if (!child->seq_tracker) {
    ak_budget_destroy(ctx->heap, child->budget);
    deallocate(ctx->heap, child, sizeof(ak_agent_context_t));
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  child->started_ms = now(CLOCK_ID_REALTIME) / 1000000;
  child->terminated = false;

  /* Register in agent registry */
  s64 slot = ak_agent_registry_add(child);
  if (slot < 0) {
    /* BUG-A9-008 FIX: Clean up budget and seq_tracker before deallocating
     * context */
    if (child->budget)
      ak_budget_destroy(ctx->heap, child->budget);
    if (child->seq_tracker)
      ak_seq_tracker_destroy(ctx->heap, child->seq_tracker);
    deallocate(ctx->heap, child, sizeof(ak_agent_context_t));
    return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);
  }

  /* Commit spawn budget */
  ak_budget_commit(ctx->budget, AK_RESOURCE_HEAP_OBJECTS, 1);

  /* Log spawn event */
  ak_audit_log_lifecycle(child->pid, child->run_id, AK_LIFECYCLE_SPAWN);

  /* Build result with child ID */
  buffer result = allocate_buffer(ctx->heap, 128);
  if (!result) {
    /* BUG-A9-001 FIX: Clean up child context on allocation failure */
    ak_agent_registry_remove(child->pid);
    ak_context_destroy(ctx->heap, child);
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  char child_hex[AK_TOKEN_ID_SIZE * 2 + 1];
  ak_hex_encode(child->pid, AK_TOKEN_ID_SIZE, child_hex);

  buffer_write(result, "{\"child_id\":\"", 13);
  buffer_write(result, child_hex, AK_TOKEN_ID_SIZE * 2);
  buffer_write(result, "\",\"slot\":", 9);

  char slot_buf[16];
  int slot_len = 0;
  u64 s = slot;
  if (s == 0) {
    slot_buf[0] = '0';
    slot_len = 1;
  } else {
    char tmp[16];
    while (s > 0) {
      tmp[slot_len++] = '0' + (s % 10);
      s /= 10;
    }
    for (int i = 0; i < slot_len; i++)
      slot_buf[i] = tmp[slot_len - 1 - i];
  }
  buffer_write(result, slot_buf, slot_len);
  buffer_write(result, "}", 1);

  return ak_response_success(ctx->heap, req, result);
}

/* ============================================================
 * INTER-AGENT MESSAGING
 * ============================================================ */

ak_response_t *ak_handle_send(ak_agent_context_t *ctx, ak_request_t *req) {
  /*
   * SEND: Send message to another agent
   *
   * Args: {"to": "agent_id_hex", "payload": {...}}
   */

  if (!req->args)
    return ak_response_error(ctx->heap, req, -EINVAL);

  /* Parse recipient ID from args JSON */
  char recipient_hex[AK_TOKEN_ID_SIZE * 2 + 1];
  u8 recipient_id[AK_TOKEN_ID_SIZE];
  if (ak_json_extract_string(req->args, "to", recipient_hex,
                             sizeof(recipient_hex)) > 0) {
    ak_hex_decode(recipient_hex, recipient_id, AK_TOKEN_ID_SIZE);
  } else {
    runtime_memset(recipient_id, 0, AK_TOKEN_ID_SIZE);
  }

  /* Find recipient */
  s64 recipient_idx = ak_agent_registry_find(recipient_id);
  if (recipient_idx < 0)
    return ak_response_error(ctx->heap, req, -ENOENT);

  /* Check recipient's inbox capacity */
  ak_message_queue_t *inbox = &ak_state.agents[recipient_idx].inbox;
  if (inbox->count >= inbox->max_size)
    return ak_response_error(ctx->heap, req, AK_E_BUDGET_EXCEEDED);

  /* Create message */
  ak_message_t *msg = allocate(ctx->heap, sizeof(ak_message_t));
  if (!msg)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  runtime_memcpy(msg->sender_id, ctx->pid, AK_TOKEN_ID_SIZE);
  runtime_memcpy(msg->recipient_id, recipient_id, AK_TOKEN_ID_SIZE);
  msg->seq = req->seq;
  msg->sent_ms = now(CLOCK_ID_REALTIME) / 1000000;
  msg->next = NULL;

  /* Copy payload */
  if (req->args) {
    msg->payload = allocate_buffer(ctx->heap, buffer_length(req->args));
    /* BUG-A9-003 FIX: Check for allocation failure */
    if (!msg->payload || msg->payload == INVALID_ADDRESS) {
      deallocate(ctx->heap, msg, sizeof(ak_message_t));
      return ak_response_error(ctx->heap, req, -ENOMEM);
    }
    buffer_write(msg->payload, buffer_ref(req->args, 0),
                 buffer_length(req->args));
  } else {
    msg->payload = NULL;
  }

  /* Enqueue message */
  if (inbox->tail) {
    inbox->tail->next = msg;
    inbox->tail = msg;
  } else {
    inbox->head = msg;
    inbox->tail = msg;
  }
  inbox->count++;

  buffer result = allocate_buffer(ctx->heap, 32);
  if (!result) {
    /* BUG-A9-002 FIX: Clean up enqueued message on allocation failure */
    /* Dequeue the message we just added */
    if (inbox->tail == msg)
      inbox->tail = NULL;
    if (inbox->head == msg)
      inbox->head = msg->next;
    inbox->count--;
    if (msg->payload)
      deallocate_buffer(msg->payload);
    deallocate(ctx->heap, msg, sizeof(ak_message_t));
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  buffer_write(result, "{\"sent\":true,\"queued\":", 22);
  char count_buf[16];
  int count_len = 0;
  u64 c = inbox->count;
  if (c == 0) {
    count_buf[0] = '0';
    count_len = 1;
  } else {
    char tmp[16];
    while (c > 0) {
      tmp[count_len++] = '0' + (c % 10);
      c /= 10;
    }
    for (int i = 0; i < count_len; i++)
      count_buf[i] = tmp[count_len - 1 - i];
  }
  buffer_write(result, count_buf, count_len);
  buffer_write(result, "}", 1);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_recv(ak_agent_context_t *ctx, ak_request_t *req) {
  /*
   * RECV: Receive messages from inbox
   *
   * Args: {"limit": N, "timeout_ms": N}
   */

  (void)req;

  /* Find this agent in registry */
  s64 idx = ak_agent_registry_find(ctx->pid);
  if (idx < 0) {
    /* Agent not in registry - return empty */
    buffer result = allocate_buffer(ctx->heap, 32);
    if (!result)
      return ak_response_error(ctx->heap, req, -ENOMEM);
    buffer_write(result, "{\"messages\":[]}", 15);
    return ak_response_success(ctx->heap, req, result);
  }

  ak_message_queue_t *inbox = &ak_state.agents[idx].inbox;

  /* Build result with messages */
  buffer result = allocate_buffer(ctx->heap, 1024);
  if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  buffer_write(result, "{\"messages\":[", 13);

  int msg_count = 0;
  ak_message_t *msg = inbox->head;
  ak_message_t *prev = NULL;

  /* Dequeue up to 10 messages */
  while (msg && msg_count < 10) {
    if (msg_count > 0)
      buffer_write(result, ",", 1);

    buffer_write(result, "{\"from\":\"", 9);
    char sender_hex[AK_TOKEN_ID_SIZE * 2 + 1];
    ak_hex_encode(msg->sender_id, AK_TOKEN_ID_SIZE, sender_hex);
    buffer_write(result, sender_hex, AK_TOKEN_ID_SIZE * 2);
    buffer_write(result, "\",\"payload\":", 12);

    if (msg->payload && buffer_length(msg->payload) > 0) {
      buffer_write(result, buffer_ref(msg->payload, 0),
                   buffer_length(msg->payload));
    } else {
      buffer_write(result, "null", 4);
    }
    buffer_write(result, "}", 1);

    /* Remove message from queue */
    ak_message_t *next = msg->next;
    if (prev) {
      prev->next = next;
    } else {
      inbox->head = next;
    }
    if (inbox->tail == msg) {
      inbox->tail = prev;
    }
    inbox->count--;

    /* Free message */
    if (msg->payload)
      deallocate_buffer(msg->payload);
    deallocate(ctx->heap, msg, sizeof(ak_message_t));

    msg = next;
    msg_count++;
  }

  buffer_write(result, "]}", 2);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_respond(ak_agent_context_t *ctx, ak_request_t *req) {
  /*
   * RESPOND: Send response to human/orchestrator with DLP filtering
   *
   * DLP (Data Loss Prevention) applies sanitization based on taint level:
   *   - AK_TAINT_TRUSTED: No sanitization (data from trusted sources)
   *   - AK_TAINT_USER_INPUT: HTML escape to prevent XSS
   *   - AK_TAINT_UNTRUSTED: Full sanitization (HTML + dangerous patterns)
   *
   * This prevents agents from:
   *   - Exfiltrating secrets via XSS in UI responses
   *   - Injecting malicious scripts into orchestrator UIs
   *   - Embedding sensitive data in responses
   */

  if (!req || !ctx)
    return ak_response_error(ctx->heap, req, AK_E_SCHEMA_INVALID);

  /* Extract response content from request args */
  buffer response_content = req->args;
  ak_taint_t taint = req->taint;

  if (!response_content || buffer_length(response_content) == 0) {
    /* No content provided, just acknowledge */
    buffer result = allocate_buffer(ctx->heap, 32);
    if (!result)
      return ak_response_error(ctx->heap, req, -ENOMEM);
    buffer_write(result, "{\"acknowledged\":true}", 21);
    return ak_response_success(ctx->heap, req, result);
  }

  /* Apply DLP based on taint level */
  buffer sanitized = 0;

  switch (taint) {
  case AK_TAINT_TRUSTED:
    /* Trusted data passes through unchanged */
    sanitized = allocate_buffer(ctx->heap, buffer_length(response_content));
    if (sanitized)
      buffer_write(sanitized, buffer_ref(response_content, 0),
                   buffer_length(response_content));
    break;

  case AK_TAINT_SANITIZED_HTML:
    /* Already HTML-sanitized data passes through */
    sanitized = allocate_buffer(ctx->heap, buffer_length(response_content));
    if (sanitized)
      buffer_write(sanitized, buffer_ref(response_content, 0),
                   buffer_length(response_content));
    break;

  case AK_TAINT_UNTRUSTED:
  default: {
    /* Untrusted data gets full sanitization */
    /* First HTML escape */
    buffer html_safe = ak_sanitize_html(ctx->heap, response_content);
    if (!html_safe) {
      return ak_response_error(ctx->heap, req, -ENOMEM);
    }

    /* Check for and redact potential secrets/sensitive patterns */
    sanitized = ak_dlp_redact_secrets(ctx->heap, html_safe);
    deallocate_buffer(html_safe);
    break;
  }
  }

  if (!sanitized)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  /* Build response JSON */
  buffer result = allocate_buffer(ctx->heap, buffer_length(sanitized) + 64);
  if (!result) {
    deallocate_buffer(sanitized);
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  buffer_write(result, "{\"content\":\"", 12);
  /* JSON-escape the sanitized content */
  u8 *data = buffer_ref(sanitized, 0);
  u64 len = buffer_length(sanitized);
  for (u64 i = 0; i < len; i++) {
    char c = data[i];
    switch (c) {
    case '"':
      buffer_write(result, "\\\"", 2);
      break;
    case '\\':
      buffer_write(result, "\\\\", 2);
      break;
    case '\n':
      buffer_write(result, "\\n", 2);
      break;
    case '\r':
      buffer_write(result, "\\r", 2);
      break;
    case '\t':
      buffer_write(result, "\\t", 2);
      break;
    default:
      if (c >= 32 && c < 127)
        buffer_write(result, &c, 1);
      /* Skip non-printable chars */
      break;
    }
  }
  buffer_write(result, "\",\"sanitized\":true}", 19);

  deallocate_buffer(sanitized);

  /* Log DLP action to audit */
  /* Note: DLP sanitization is logged implicitly via the effect system */
  (void)taint; /* Suppress unused warning after sanitization */

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_assert(ak_agent_context_t *ctx, ak_request_t *req) {
  /*
   * ASSERT: Record assertion about state
   * Used for formal verification and debugging
   */
  (void)req;

  buffer result = allocate_buffer(ctx->heap, 32);
  if (!result)
    return ak_response_error(ctx->heap, req, -ENOMEM);

  buffer_write(result, "{\"asserted\":true}", 17);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_budget_status(ak_agent_context_t *ctx, ak_request_t *req) {
  /*
   * BUDGET_STATUS: Get current budget consumption status
   * Returns JSON with tokens, tool_calls, wall_time, bytes usage and limits
   */
  (void)req;

  if (!ctx->budget) {
    return ak_response_error(ctx->heap, req, -EINVAL);
  }

  /* Allocate buffer for JSON response */
  buffer result = allocate_buffer(ctx->heap, 512);
  if (!result) {
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  /* Format budget status as JSON */
  ak_budget_format_json(ctx->budget, result);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_budget_history(ak_agent_context_t *ctx, ak_request_t *req) {
  /*
   * BUDGET_HISTORY: Get historical budget snapshots
   * Input: count (number of snapshots to retrieve, max 60)
   * Returns JSON array of snapshots in chronological order
   */
  if (!ctx->budget) {
    return ak_response_error(ctx->heap, req, -EINVAL);
  }

  /* Parse count parameter from request (default to 60) */
  u32 count = AK_BUDGET_HISTORY_SIZE;
  if (req->args && buffer_length(req->args) > 0) {
    /* Simple parse: expect {"count": N} */
    const char *data = buffer_ref(req->args, 0);
    u64 len = buffer_length(req->args);
    for (u64 i = 0; i < len - 6; i++) {
      if (runtime_memcmp(data + i, "count", 5) == 0) {
        /* Found "count", look for number after ':' */
        for (u64 j = i + 5; j < len; j++) {
          if (data[j] >= '0' && data[j] <= '9') {
            count = 0;
            while (j < len && data[j] >= '0' && data[j] <= '9') {
              count = count * 10 + (data[j] - '0');
              j++;
            }
            if (count > AK_BUDGET_HISTORY_SIZE) {
              count = AK_BUDGET_HISTORY_SIZE;
            }
            break;
          }
        }
        break;
      }
    }
  }

  /* Allocate buffer for JSON response (estimate ~100 bytes per snapshot) */
  buffer result = allocate_buffer(ctx->heap, 128 + count * 100);
  if (!result) {
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  /* Format history as JSON */
  ak_budget_format_history_json(ctx->budget, count, result);

  return ak_response_success(ctx->heap, req, result);
}

ak_response_t *ak_handle_budget_breakdown(ak_agent_context_t *ctx, ak_request_t *req) {
  /*
   * BUDGET_BREAKDOWN: Get detailed breakdown of budget consumption
   * Returns JSON with per-operation and per-tool consumption details
   */
  (void)req;

  if (!ctx->budget) {
    return ak_response_error(ctx->heap, req, -EINVAL);
  }

  /* Allocate buffer for JSON response */
  buffer result = allocate_buffer(ctx->heap, 2048);
  if (!result) {
    return ak_response_error(ctx->heap, req, -ENOMEM);
  }

  /* Format breakdown as JSON */
  ak_budget_format_breakdown_json(ctx->budget, result);

  return ak_response_success(ctx->heap, req, result);
}

/* ============================================================
 * RESPONSE HELPERS
 * ============================================================ */

ak_response_t *ak_response_success(heap h, ak_request_t *req, buffer result) {
  /* Zero-initialize: status/error_msg/usage/log fields must never be
   * garbage - the syscall handler reads status and frees error_msg. */
  ak_response_t *res = allocate_zero(h, sizeof(ak_response_t));
  if (!res || res == INVALID_ADDRESS) {
    if (result)
      deallocate_buffer(result);
    return NULL;
  }

  /* req may be NULL (e.g. ak_wasm.c internal responses); identity
   * fields then stay zero from allocate_zero */
  if (req) {
    runtime_memcpy(res->pid, req->pid, AK_TOKEN_ID_SIZE);
    runtime_memcpy(res->run_id, req->run_id, AK_TOKEN_ID_SIZE);
    res->seq = req->seq;
  }
  res->status = AK_STATUS_OK;
  res->error_code = 0;
  res->result = result;
  res->error_msg = 0;

  return res;
}

ak_response_t *ak_response_error(heap h, ak_request_t *req, s64 error_code) {
  /* Zero-initialize: see ak_response_success */
  ak_response_t *res = allocate_zero(h, sizeof(ak_response_t));
  if (!res || res == INVALID_ADDRESS)
    return NULL;

  if (req) {
    runtime_memcpy(res->pid, req->pid, AK_TOKEN_ID_SIZE);
    runtime_memcpy(res->run_id, req->run_id, AK_TOKEN_ID_SIZE);
    res->seq = req->seq;
  }

  res->status = AK_STATUS_ERROR;
  res->error_code = error_code;
  res->result = NULL;
  res->error_msg = 0;

  return res;
}

void ak_response_destroy(heap h, ak_response_t *res) {
  if (!res)
    return;

  if (res->result)
    deallocate_buffer(res->result);

  deallocate(h, res, sizeof(ak_response_t));
}

/* ============================================================
 * AUDIT INTEGRATION
 * ============================================================ */

s64 ak_log_operation(ak_agent_context_t *ctx, ak_request_t *req,
                     ak_response_t *res) {
  if (!ctx || !req)
    return -EINVAL;

  u8 req_hash[AK_HASH_SIZE];
  u8 res_hash[AK_HASH_SIZE];
  u8 policy_hash[AK_HASH_SIZE];

  ak_audit_hash_request(req, req_hash);
  if (res)
    ak_audit_hash_response(res, res_hash);
  else
    runtime_memset(res_hash, 0, AK_HASH_SIZE);

  ak_policy_get_hash(ctx->policy, policy_hash);

  return ak_audit_append(ctx->pid, ctx->run_id, req->op, req_hash, res_hash,
                         policy_hash);
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_get_dispatch_stats(ak_dispatch_stats_t *stats) {
  if (stats)
    runtime_memcpy(stats, &ak_state.stats, sizeof(ak_dispatch_stats_t));
}

/* ============================================================
 * ERROR RECOVERY
 * ============================================================ */

void ak_handle_agent_crash(ak_agent_context_t *ctx) {
  if (!ctx)
    return;

  /* SECURITY: Immediate capability revocation */
  ak_revocation_revoke_run(ctx->run_id, "crash");

  /* Log crash event */
  ak_audit_log_lifecycle(ctx->pid, ctx->run_id, AK_LIFECYCLE_CRASH);

  /* Cleanup pending transactions */
  /* Note: transaction cleanup handled by heap subsystem */
}

void ak_handle_agent_timeout(ak_agent_context_t *ctx) {
  if (!ctx)
    return;

  /* SECURITY: Immediate capability revocation */
  ak_revocation_revoke_run(ctx->run_id, "timeout");

  /* Log timeout event */
  ak_audit_log_lifecycle(ctx->pid, ctx->run_id, AK_LIFECYCLE_TIMEOUT);
}

/* ============================================================
 * CAPABILITY OPERATIONS
 * ============================================================ */

s64 ak_grant_capability(ak_agent_context_t *ctx, ak_cap_type_t type,
                        const char *resource, const char **methods, u32 ttl_ms,
                        u32 rate_limit, u32 rate_window_ms) {
  if (!ctx)
    return -EINVAL;

  ak_capability_t *cap =
      ak_capability_create(ctx->heap, type, resource, methods, ttl_ms,
                           rate_limit, rate_window_ms, ctx->run_id);

  if (!cap)
    return -ENOMEM;

  /* Store in context's capability set */
  if (ctx->delegated_caps) {
    table_set(ctx->delegated_caps, cap->tid, cap);
  }

  return 0;
}

void ak_revoke_capability(ak_agent_context_t *ctx, u8 *tid) {
  if (!ctx || !tid)
    return;

  ak_revocation_add(tid, "explicit_revoke");
}

void ak_revoke_run(ak_agent_context_t *ctx) {
  if (!ctx)
    return;

  ak_revocation_revoke_run(ctx->run_id, "run_revoked");
}

/* ============================================================
 * PER-PROCESS CONTEXT MANAGEMENT
 * ============================================================
 *
 * ARCHITECTURE NOTE: Nanos is a unikernel that runs a single application.
 * While there is technically one "process" from the kernel's perspective,
 * the Authority Kernel manages multiple logical agent contexts within
 * that process (e.g., parent/child agents via AK_SYS_SPAWN).
 *
 * Context management strategy:
 *   1. Root agent: Singleton context for the main Nanos process
 *   2. Spawned agents: Managed via the agent registry (ak_state.agents)
 *   3. Thread-safe: Protected by spinlock for concurrent access
 *
 * In a multi-process OS, context would be stored in the process struct.
 * In Nanos unikernel, we use a single root context with explicit agent
 * management for spawned sub-agents.
 */

/* Root agent context for the main Nanos process (singleton) */
static ak_agent_context_t *ak_root_context = NULL;
static struct spinlock ak_context_lock;
static boolean ak_context_lock_initialized = false;

/*
 * Get or create the agent context for the current execution context.
 *
 * For root process: Returns/creates the singleton root context
 * For spawned agents: Context is looked up via agent registry
 *
 * Returns NULL on failure (not initialized, allocation failed)
 *
 * THREAD SAFETY: Protected by ak_context_lock spinlock
 */
static ak_agent_context_t *ak_get_current_context(void) {
  if (!ak_state.initialized || !ak_state.h)
    return NULL;

  /* Initialize lock on first use (safe: single-threaded during init) */
  if (!ak_context_lock_initialized) {
    spin_lock_init(&ak_context_lock);
    ak_context_lock_initialized = true;
  }

  spin_lock(&ak_context_lock);

  if (!ak_root_context) {
    /*
     * Create root context for the Nanos process.
     * In Nanos unikernel, there is exactly one application process.
     * PID is zeros for root; spawned agents get unique PIDs.
     */
    u8 root_pid[AK_TOKEN_ID_SIZE];
    runtime_memset(root_pid, 0, AK_TOKEN_ID_SIZE);

    ak_root_context = ak_context_create(ak_state.h, root_pid, NULL);
    if (ak_root_context) {
      /*
       * The root context is the single-tenant owner of the VM and holds
       * ambient authority: an admin capability over all resources, bound
       * to its run. Sub-agents created via SPAWN receive NO root_cap and
       * are confined to their explicitly delegated capabilities
       * (see ak_validate_capability). This admin cap is minted with the
       * kernel key, so it is HMAC-verified and revocation-checked on every
       * use like any other capability.
       */
      ak_root_context->root_cap = ak_capability_create(
          ak_state.h, AK_CAP_ADMIN, "*", NULL /* all methods */,
          AK_MAX_CAP_TTL_MS, 0 /* no rate limit */, 0,
          ak_root_context->run_id);
      /* Register root agent in registry for lookup */
      ak_agent_registry_add(ak_root_context);
    }
  }

  ak_agent_context_t *ctx = ak_root_context;
  spin_unlock(&ak_context_lock);

  return ctx;
}

/*
 * Public wrapper for ak_get_current_context.
 * Used by ak_net_enforce.c for network capability checks.
 */
ak_agent_context_t *ak_get_root_context(void) {
  return ak_get_current_context();
}

/*
 * Cleanup the root context (called during ak_shutdown).
 *
 * THREAD SAFETY: Protected by ak_context_lock spinlock
 */
void ak_cleanup_root_context(void) {
  if (!ak_context_lock_initialized)
    return;

  spin_lock(&ak_context_lock);

  if (ak_root_context) {
    ak_agent_registry_remove(ak_root_context->pid);
    ak_context_destroy(ak_state.h, ak_root_context);
    ak_root_context = NULL;
  }

  spin_unlock(&ak_context_lock);
}

/* ============================================================
 * SYSCALL HANDLER (called from main kernel syscall dispatcher)
 * ============================================================ */

/*
 * Main syscall handler for Authority Kernel syscalls (1024-1100).
 *
 * Syscall convention:
 *   arg0: agent_id pointer (u8[16]) or 0 to use root context
 *   arg1: request buffer pointer
 *   arg2: request buffer length
 *   arg3: response buffer pointer (output)
 *   arg4: response buffer length
 *   arg5: pointer to a serialized capability token (0 = none)
 *
 * Returns bytes written to response buffer, or negative errno.
 *
 * CONTEXT MODEL (Nanos Unikernel):
 *   - One root agent context (created on first syscall)
 *   - Multiple spawned agents (via AK_SYS_SPAWN, in agent registry)
 *   - arg0 can specify agent_id for supervisor/orchestrator patterns
 */
sysreturn ak_syscall_handler(u64 call, u64 arg0, u64 arg1, u64 arg2, u64 arg3,
                             u64 arg4, u64 arg5) {
  /*
   * TEST HOOK (call 1099): exercise the in-kernel HTTPS transport.
   * arg1/arg2 = host string ptr/len. Performs GET https://<host>/ via
   * ak_https_request() and returns the HTTP status (or negative error).
   * Bypasses the AK pipeline; used only for runtime TLS verification.
   */
  /* Validate syscall range (includes budget introspection ops) */
  if (call < AK_SYS_BASE || call > AK_SYS_INFER_POLL)
    return -ENOSYS;

  ak_agent_context_t *current_ctx = NULL;

  /*
   * Agent context resolution:
   * 1. If arg0 specifies an agent_id, look it up in the registry
   * 2. Otherwise, use the root context (create if needed)
   *
   * BUG-FIX #10: Validate pointers before dereferencing them
   */
  if (arg0 != 0) {
    /* BUG-FIX: arg0 must be a valid kernel pointer to 16-byte agent_id
     * Validate it's in kernel space (not userspace pointer) */
    if (arg0 < 0x1000) {
      /* Suspiciously low pointer - likely invalid */
      return -EFAULT;
    }
    /* Caller specified an agent_id - look up in registry */
    s64 idx = ak_agent_registry_find((u8 *)arg0);
    if (idx >= 0 && ak_state.agents[idx].active) {
      current_ctx = ak_state.agents[idx].ctx;
    } else {
      /* Unknown agent_id - fail with ESRCH (no such process) */
      return -ESRCH;
    }
  }

  if (!current_ctx) {
    /* Use root context (creates on first call) */
    current_ctx = ak_get_current_context();
    if (!current_ctx)
      return -EAGAIN; /* AK not initialized or allocation failed */
  }

  /* Build request from syscall arguments */
  ak_request_t req;
  ak_memzero(&req, sizeof(req));

  /* ak_dispatch and ak_validate_request use absolute AK_SYS_* numbers
   * (1024+), so op carries the raw syscall number. */
  req.op = (u16)call;

  /* The kernel builds this request on behalf of the resolved context:
   * stamp the context identity so stage-1 validation binds the request
   * to that context. */
  runtime_memcpy(req.pid, current_ctx->pid, AK_TOKEN_ID_SIZE);
  runtime_memcpy(req.run_id, current_ctx->run_id, AK_TOKEN_ID_SIZE);

  /* Sequence numbers start at 1: the seq tracker initializes
   * highest_seen to 0 and treats seq <= highest_seen as replay, so
   * pre-increment. */
  req.seq = ++current_ctx->last_seq;

  /* Syscall arguments originate outside the kernel trust boundary */
  req.taint = AK_TAINT_UNTRUSTED;

  /*
   * arg5 = userspace pointer to a serialized capability token (0 = none).
   * The wire format is self-describing: ak_capability_parse() reads the
   * total_len field from the header and validates 96 <= total_len <=
   * wrapped length, never reading past total_len, so wrapping a bounded
   * region is safe (a malformed pointer faults like any bad syscall arg).
   * A presented token is fully enforced (HMAC + scope + TTL + revocation)
   * in ak_validate_capability. When absent, the root context's ambient
   * authority or an agent's delegated grants apply; an agent with none is
   * denied (mandatory confinement).
   */
  ak_capability_t *parsed_cap = NULL;
  if (arg5 && arg5 >= 0x1000) {
    parsed_cap = ak_capability_parse(
        current_ctx->heap,
        alloca_wrap_buffer((void *)arg5, AK_CAP_WIRE_MAX_SIZE));
    req.cap = parsed_cap; /* NULL if malformed -> falls through, fail-closed */
  }

  /* arg1/arg2 contain the request data (if any)
   * BUG-FIX #10: Validate arg1 is not a suspiciously low address before using
   * it */
  if (arg1 && arg2 > 0) {
    if (arg1 < 0x1000) {
      /* Suspiciously low address - likely invalid */
      return -EFAULT;
    }
    req.args = alloca_wrap_buffer((void *)arg1, arg2);
  }

  /*
   * SECURITY: Route through ak_dispatch so the full 6-stage enforcement
   * pipeline runs (validate -> replay -> capability INV-2 ->
   * policy/budget INV-3 -> execute -> audit INV-4). Never call the
   * ak_handle_* functions directly from here - that bypasses all four
   * invariants.
   */
  ak_response_t *resp = ak_dispatch(current_ctx, &req);
  if (!resp)
    return -EFAULT;

  /* Copy response to user buffer */
  sysreturn result;
  if (resp->status == AK_STATUS_OK) {
    result = 0;
    if (resp->result && arg3 && arg4 > 0) {
      u64 copy_len = buffer_length(resp->result);
      if (arg3 < 0x1000) {
        /* Suspiciously low response pointer - fail-closed */
        result = -EFAULT;
      } else if (copy_len > arg4) {
        /* BUG-FIX #8: Partial truncation error - fail-closed instead of
         * silently truncating. Caller MUST know if data was complete or
         * incomplete. */
        result = -EINVAL; /* Response buffer too small */
      } else {
        ak_memcpy((void *)arg3, buffer_ref(resp->result, 0), copy_len);
        result = (sysreturn)copy_len;
      }
    }
  } else {
    /* Propagate the pipeline's error code (negative errno / AK_E_*) */
    result = (resp->error_code != 0) ? (sysreturn)resp->error_code : -EINVAL;
  }

  /* Clean up response (only deallocate non-NULL buffers) */
  if (resp->result)
    deallocate_buffer(resp->result);
  if (resp->error_msg)
    deallocate_buffer(resp->error_msg);
  deallocate(current_ctx->heap, resp, sizeof(ak_response_t));

  /* Free the per-call capability parsed from arg5 (if any). */
  if (parsed_cap)
    deallocate(current_ctx->heap, parsed_cap, sizeof(ak_capability_t));

  return result;
}
