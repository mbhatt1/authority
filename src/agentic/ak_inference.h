/*
 * Authority Kernel - LLM Gateway Interface
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides a unified interface for LLM inference, supporting:
 *   1. Local models via the host akproxy over virtio-serial
 *      (host runs ollama/vLLM/akproxy)
 *   2. External APIs (OpenAI, Anthropic, etc.) via EITHER the host proxy
 *      OR real in-kernel HTTPS. In-kernel HTTPS works when the transport
 *      klib (klib/ak_https.c) is loaded: it registers a net_http_req /
 *      mbedTLS-backed transport into the kernel hook (see ak_transport.h)
 *      and ak_external_inference_request() issues a real TLS request.
 *      When NO transport klib is loaded and the proxy is down, external
 *      requests fail closed with AK_E_LLM_CONNECTION_FAILED - never a
 *      fabricated response.
 *
 * All inference calls are:
 *   - Capability-gated (AK_CAP_INFERENCE)
 *   - Budget-tracked (INV-3)
 *   - Audit-logged (INV-4)
 *
 * SECURITY: API keys are resolved via ak_host_secret_get(), never logged.
 */

#ifndef AK_INFERENCE_H
#define AK_INFERENCE_H

#include "ak_capability.h"
#include "ak_types.h"

/* ============================================================
 * LLM PROVIDER CONFIGURATION
 * ============================================================ */

typedef enum ak_llm_mode {
  AK_LLM_MODE_DISABLED = 0, /* No LLM access */
  AK_LLM_LOCAL = 1,         /* Local model via virtio-serial (akproxy) */
  AK_LLM_EXTERNAL = 2,      /* External API; served via host proxy or via
                             * real in-kernel HTTPS when the ak_https
                             * transport klib is loaded */
  AK_LLM_HYBRID = 3,        /* Both available, route by model */
} ak_llm_mode_t;

typedef enum ak_llm_provider {
  AK_LLM_PROVIDER_LOCAL = 0, /* Local inference server */
  AK_LLM_PROVIDER_OPENAI = 1,
  AK_LLM_PROVIDER_ANTHROPIC = 2,
  AK_LLM_PROVIDER_CUSTOM = 3, /* User-defined endpoint */
} ak_llm_provider_t;

/* Local inference configuration (virtio-serial) */
typedef struct ak_llm_local_config {
  char device_path[64];   /* virtio-serial device path */
  u32 timeout_ms;         /* Request timeout */
  u32 max_tokens;         /* Max output tokens */
  char default_model[64]; /* Default model name */
} ak_llm_local_config_t;

/* External API configuration */
typedef struct ak_llm_api_config {
  ak_llm_provider_t provider;
  char endpoint[256];   /* API endpoint URL */
  char secret_name[64]; /* Secret name for API key */
  char model[64];       /* Model identifier */
  u32 timeout_ms;
  u32 max_tokens;
  boolean stream; /* Enable streaming responses */
} ak_llm_api_config_t;

/* Combined LLM configuration */
typedef struct ak_llm_config {
  ak_llm_mode_t mode;
  ak_llm_local_config_t local;
  ak_llm_api_config_t api;

  /* Rate limiting */
  u32 requests_per_minute;
  u32 tokens_per_minute;

  /* Routing rules (for hybrid mode) */
  char local_models[8][64]; /* Models to route locally */
  u32 local_model_count;
} ak_llm_config_t;

/* ============================================================
 * INFERENCE REQUEST/RESPONSE
 * ============================================================ */

typedef enum ak_inference_type {
  AK_INFERENCE_COMPLETION = 0, /* Text completion */
  AK_INFERENCE_CHAT = 1,       /* Chat completion */
  AK_INFERENCE_EMBEDDING = 2,  /* Text embedding */
} ak_inference_type_t;

/* Chat message role */
typedef enum ak_chat_role {
  AK_ROLE_SYSTEM = 0,
  AK_ROLE_USER = 1,
  AK_ROLE_ASSISTANT = 2,
  AK_ROLE_TOOL = 3,
} ak_chat_role_t;

/* Single chat message */
typedef struct ak_chat_message {
  ak_chat_role_t role;
  buffer content;
  char name[64]; /* Optional: tool name for tool responses */
} ak_chat_message_t;

/* Inference request */
typedef struct ak_inference_request {
  /* Request type */
  ak_inference_type_t type;

  /* Model selection */
  char model[64]; /* Model name or "auto" */

  /* Completion parameters */
  buffer prompt;               /* For completion type */
  ak_chat_message_t *messages; /* For chat type */
  u32 message_count;

  /* Generation parameters */
  u32 max_tokens;
  float temperature;
  float top_p;
  u32 top_k;
  float frequency_penalty;
  float presence_penalty;
  char **stop_sequences;
  u32 stop_count;

  /* Tool use (function calling) */
  buffer tools_json; /* JSON array of tool definitions */
  boolean tool_choice_auto;

  /* Output format */
  boolean stream;
  buffer response_format; /* JSON schema for structured output */

  /* Security */
  ak_taint_t taint; /* Taint level of prompt data */
} ak_inference_request_t;

/* Token usage statistics */
typedef struct ak_inference_usage {
  u32 prompt_tokens;
  u32 completion_tokens;
  u32 total_tokens;
  u64 latency_ms;
  char model_used[64];
} ak_inference_usage_t;

/* Inference response */
typedef struct ak_inference_response {
  boolean success;
  s64 error_code;
  char error_message[256];

  /* Result */
  buffer content;    /* Generated text */
  buffer tool_calls; /* JSON array of tool calls, if any */

  /* Usage */
  ak_inference_usage_t usage;

  /* Finish reason */
  enum {
    AK_FINISH_STOP = 0,
    AK_FINISH_LENGTH = 1,
    AK_FINISH_TOOL_CALLS = 2,
    AK_FINISH_ERROR = 3,
  } finish_reason;
} ak_inference_response_t;

/* ============================================================
 * STREAMING CALLBACK
 * ============================================================ */

/* Callback for streaming responses */
typedef void (*ak_stream_callback_t)(void *ctx, const char *token,
                                     u32 token_len, boolean done);

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize LLM gateway subsystem.
 */
void ak_inference_init(heap h, ak_llm_config_t *config);

/*
 * Shutdown LLM gateway.
 */
void ak_inference_shutdown(void);

/*
 * Update configuration (runtime reconfiguration).
 */
s64 ak_inference_configure(ak_llm_config_t *config);

/*
 * Get current configuration.
 */
void ak_inference_get_config(ak_llm_config_t *config_out);

/* ============================================================
 * INFERENCE API
 * ============================================================ */

/*
 * Perform inference request (synchronous).
 *
 * Pipeline:
 *   1. Validate capability (AK_CAP_INFERENCE)
 *   2. Check budget (tokens_in, tokens_out)
 *   3. Route to local or external
 *   4. Execute request
 *   5. Track usage
 *   6. Log to audit
 *
 * Returns response structure.
 */
ak_inference_response_t *ak_inference_complete(ak_agent_context_t *agent,
                                               ak_inference_request_t *req,
                                               ak_capability_t *cap);

/*
 * Perform streaming inference.
 *
 * Callback is invoked for each token.
 * Returns response with usage stats after completion.
 */
ak_inference_response_t *ak_inference_stream(ak_agent_context_t *agent,
                                             ak_inference_request_t *req,
                                             ak_capability_t *cap,
                                             ak_stream_callback_t callback,
                                             void *callback_ctx);

/*
 * Generate text embeddings.
 *
 * Returns vector as JSON array of floats.
 */
ak_inference_response_t *ak_inference_embed(ak_agent_context_t *agent,
                                            buffer text, const char *model,
                                            ak_capability_t *cap);

/*
 * Free inference response.
 */
void ak_inference_response_free(heap h, ak_inference_response_t *res);

/* ============================================================
 * SYSCALL HANDLER
 * ============================================================
 * Entry point for AK_SYS_INFERENCE.
 */

/*
 * Handle inference syscall.
 *
 * Args format (JSON):
 * {
 *   "type": "chat" | "completion" | "embedding",
 *   "model": "...",
 *   "messages": [...] | "prompt": "...",
 *   "max_tokens": 1000,
 *   "temperature": 0.7,
 *   ...
 * }
 */
ak_response_t *ak_handle_inference(ak_agent_context_t *ctx, ak_request_t *req);
/* Async external LLM I/O (see ak_inference.c). INFER_ISSUE issues a non-blocking
 * HTTP(S) POST to an LLM endpoint; INFER_POLL reaps it (-EAGAIN until ready). */
ak_response_t *ak_handle_infer_issue(ak_agent_context_t *ctx, ak_request_t *req);
ak_response_t *ak_handle_infer_poll(ak_agent_context_t *ctx, ak_request_t *req);

/* ============================================================
 * LOCAL INFERENCE (virtio-serial)
 * ============================================================ */

/*
 * Initialize local inference connection.
 *
 * The working local transport is the host akproxy (virtio-serial),
 * initialized separately via ak_proxy_init(). This function snapshots
 * proxy availability; the legacy direct virtio-serial device path is
 * not implemented (no fd-level driver integration), so it never
 * connects.
 *
 * Returns:
 *   0                          - akproxy is connected
 *   AK_E_LLM_NOT_CONFIGURED    - no config / no device path
 *   AK_E_LLM_DEVICE_UNAVAILABLE - proxy down, legacy device unavailable
 */
s64 ak_local_inference_init(ak_llm_local_config_t *config);

/*
 * Send request to local inference server.
 */
ak_inference_response_t *
ak_local_inference_request(ak_inference_request_t *req);

/*
 * Check local inference server health.
 */
boolean ak_local_inference_healthy(void);

/* ============================================================
 * EXTERNAL INFERENCE (host proxy OR in-kernel HTTPS)
 * ============================================================ */

/*
 * Initialize external API connection.
 *
 * Records configuration only. External providers are reachable via the
 * host akproxy, or directly over real in-kernel HTTPS when the ak_https
 * transport klib is loaded (see ak_transport.h).
 */
s64 ak_external_inference_init(ak_llm_api_config_t *config);

/*
 * Send request to external API.
 *
 * When the in-kernel HTTPS transport is registered (ak_transport_available()),
 * this builds the provider-specific JSON body and headers (Authorization
 * bearer / x-api-key from the configured secret), issues a real TLS POST to
 * api.openai.com or api.anthropic.com via ak_https_request(), and parses the
 * response. When NO transport is registered it fails closed with
 * AK_E_LLM_CONNECTION_FAILED - it never fabricates a response.
 */
ak_inference_response_t *
ak_external_inference_request(ak_inference_request_t *req,
                              ak_llm_api_config_t *api_config);

/*
 * Format request for specific provider.
 */
buffer ak_format_api_request(heap h, ak_llm_provider_t provider,
                             ak_inference_request_t *req);

/*
 * Parse response from specific provider.
 */
ak_inference_response_t *
ak_parse_api_response(heap h, ak_llm_provider_t provider, buffer response);

/* ============================================================
 * ROUTING
 * ============================================================ */

/*
 * Determine routing for model.
 *
 * Because there is no in-kernel TLS/HTTP, requests that would go
 * external are routed through the host proxy (LOCAL path) when it is
 * connected. When the proxy is down, AK_LLM_EXTERNAL is returned so
 * the caller receives the fail-closed error from
 * ak_external_inference_request() - never a hang or fake success.
 *
 * Returns:
 *   AK_LLM_LOCAL         - Route to local/proxy inference
 *   AK_LLM_EXTERNAL      - Dead path; request will fail closed
 *   AK_LLM_MODE_DISABLED - No backend configured
 */
ak_llm_mode_t ak_inference_route(const char *model);

/* ============================================================
 * STATISTICS
 * ============================================================ */

typedef struct ak_inference_stats {
  u64 requests_total;
  u64 requests_local;
  u64 requests_external;
  u64 requests_failed;
  u64 tokens_in_total;
  u64 tokens_out_total;
  u64 total_latency_ms;
  u64 capability_denials;
  u64 budget_exceeded;
} ak_inference_stats_t;

void ak_inference_get_stats(ak_inference_stats_t *stats);

/* ============================================================
 * ERROR CODES
 * ============================================================ */

#define AK_E_LLM_NOT_CONFIGURED (-4600)
#define AK_E_LLM_CONNECTION_FAILED (-4601)
#define AK_E_LLM_TIMEOUT (-4602)
#define AK_E_LLM_API_ERROR (-4603)
#define AK_E_LLM_INVALID_REQUEST (-4604)
#define AK_E_LLM_MODEL_NOT_FOUND (-4605)
#define AK_E_LLM_RATE_LIMITED (-4606)
#define AK_E_LLM_CONTENT_FILTERED (-4607)
#define AK_E_LLM_DEVICE_UNAVAILABLE                                            \
  (-4608)                           /* virtio device not present/ready */
#define AK_E_LLM_PARTIAL_IO (-4609) /* incomplete read/write */
#define AK_E_LLM_MALFORMED_RESPONSE (-4610) /* response parsing failed */
#define AK_E_LLM_BUFFER_OVERFLOW (-4611) /* response exceeds buffer capacity   \
                                          */
#define AK_E_LLM_RETRY_EXHAUSTED (-4612) /* all retry attempts failed */

/* ============================================================
 * RETRY CONFIGURATION
 * ============================================================ */

#define AK_LLM_MAX_RETRIES 3 /* Max retry attempts for transient errors */
#define AK_LLM_RETRY_DELAY_MS                                                  \
  100 /* Base delay between retries (exponential backoff) */
#define AK_LLM_IDLE_TIMEOUT_MS 5000 /* Idle timeout for I/O operations */

#endif /* AK_INFERENCE_H */
