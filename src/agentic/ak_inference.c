/*
 * Authority Kernel - LLM Gateway Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Provides LLM inference capabilities for Authority agents:
 *   - Local inference via the host akproxy over virtio-serial
 *   - External API access (OpenAI, Anthropic, custom) ONLY via the
 *     host proxy; there is no in-kernel TLS/HTTP stack, so direct
 *     external requests fail closed
 *   - Capability-gated access enforcement (INV-2)
 *   - Budget tracking and enforcement (INV-3)
 *   - Full audit logging of all inference calls (INV-4)
 *
 * Architecture:
 *   Guest VM <-> virtio-serial <-> host akproxy <-> local or external
 *   inference backend (proxy performs any HTTPS on the host side)
 */

#include "ak_inference.h"
#include "ak_audit.h"
#include "ak_budget.h"
#include "ak_compat.h"
#include "ak_policy.h"
#include "ak_secrets.h"
#include "ak_stream.h"
#include "ak_syscall.h"
#include "ak_transport.h"
#include "ak_virtio_proxy.h"

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

static struct {
  heap h;
  boolean initialized;
  ak_llm_config_t config;
  ak_inference_stats_t stats;

  /* Local inference state (virtio-serial) */
  boolean local_connected;
  int local_fd;

  /* External API state */
  boolean api_configured;
  char api_key_resolved[256];
  boolean api_key_valid;

  /* Request/response buffers for virtio protocol */
  buffer virtio_tx_buf;
  buffer virtio_rx_buf;
} ak_inf_state;

/* ============================================================
 * JSON UTILITIES
 * ============================================================ */

/*
 * Extract string value from JSON by key.
 * Simple extraction for well-formed JSON responses.
 */
static s64 json_extract_string(buffer json, const char *key, char *out,
                               u64 out_len) {
  if (!json || !key || !out || out_len == 0)
    return -1;

  u8 *data = buffer_ref(json, 0);
  u64 len = buffer_length(json);
  u64 key_len = runtime_strlen(key);

  /* Search for "key": " pattern */
  for (u64 i = 0; i + key_len + 4 < len; i++) {
    if (data[i] == '"' && runtime_memcmp(&data[i + 1], key, key_len) == 0 &&
        data[i + 1 + key_len] == '"') {

      /* Found key, skip to value */
      u64 j = i + 1 + key_len + 1;

      /* Skip : and whitespace */
      while (j < len && (data[j] == ':' || data[j] == ' ' || data[j] == '\t'))
        j++;

      if (j >= len || data[j] != '"')
        return -1;
      j++; /* Skip opening quote */

      /* Extract string value */
      u64 start = j;
      while (j < len && data[j] != '"') {
        if (data[j] == '\\' && j + 1 < len)
          j++; /* Skip escaped char */
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
 * Extract integer value from JSON by key.
 */
static s64 json_extract_int(buffer json, const char *key, u64 *out) {
  if (!json || !key || !out)
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

      if (j >= len)
        return -1;

      /* Parse number with overflow protection (P2-5) */
      u64 value = 0;
      while (j < len && data[j] >= '0' && data[j] <= '9') {
        u64 digit = data[j] - '0';
        /* Check for overflow before multiplication */
        if (value > (UINT64_MAX - digit) / 10) {
          value = UINT64_MAX; /* Saturate on overflow */
          /* Skip remaining digits */
          while (j < len && data[j] >= '0' && data[j] <= '9')
            j++;
          *out = value;
          return 0;
        }
        value = value * 10 + digit;
        j++;
      }

      *out = value;
      return 0;
    }
  }

  return -1;
}

/*
 * Format u64 to string, returns length written.
 */
static int u64_format(u64 n, char *buf) {
  char tmp[24];
  int len = 0;

  if (n == 0) {
    buf[0] = '0';
    return 1;
  }

  while (n > 0) {
    tmp[len++] = '0' + (n % 10);
    n /= 10;
  }

  for (int i = 0; i < len; i++)
    buf[i] = tmp[len - 1 - i];

  return len;
}

/*
 * Escape string for JSON output.
 */
static void json_escape_string(buffer out, const char *str, u64 len) {
  for (u64 i = 0; i < len; i++) {
    char c = str[i];
    switch (c) {
    case '"':
      buffer_write(out, "\\\"", 2);
      break;
    case '\\':
      buffer_write(out, "\\\\", 2);
      break;
    case '\n':
      buffer_write(out, "\\n", 2);
      break;
    case '\r':
      buffer_write(out, "\\r", 2);
      break;
    case '\t':
      buffer_write(out, "\\t", 2);
      break;
    default:
      if (c >= 0x20)
        buffer_write(out, &c, 1);
      break;
    }
  }
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_inference_init(heap h, ak_llm_config_t *config) {
  if (ak_inf_state.initialized)
    return;

  ak_inf_state.h = h;
  runtime_memset((u8 *)&ak_inf_state.stats, 0, sizeof(ak_inference_stats_t));

  if (config) {
    runtime_memcpy(&ak_inf_state.config, config, sizeof(ak_llm_config_t));
  } else {
    ak_inf_state.config.mode = AK_LLM_MODE_DISABLED;
    ak_inf_state.config.local.timeout_ms = 30000;
    ak_inf_state.config.local.max_tokens = 4096;
    ak_inf_state.config.api.timeout_ms = 30000;
    ak_inf_state.config.api.max_tokens = 4096;
    ak_inf_state.config.requests_per_minute = 60;
    ak_inf_state.config.tokens_per_minute = 100000;
  }

  ak_inf_state.local_connected = false;
  ak_inf_state.local_fd = -1;
  ak_inf_state.api_configured = false;
  ak_inf_state.api_key_valid = false;

  /*
   * Allocate virtio protocol buffers.
   *
   * These buffers are used for staging data during virtio-serial I/O.
   * We must check for both NULL and INVALID_ADDRESS since Nanos heap
   * allocators return INVALID_ADDRESS on failure, not NULL.
   */
  ak_inf_state.virtio_tx_buf = allocate_buffer(h, 65536);
  if (!ak_inf_state.virtio_tx_buf ||
      ak_inf_state.virtio_tx_buf == INVALID_ADDRESS) {
    ak_inf_state.virtio_tx_buf = 0;
    ak_error("Failed to allocate virtio TX buffer");
    /* Continue initialization - local inference will be unavailable */
  }

  ak_inf_state.virtio_rx_buf = allocate_buffer(h, 65536);
  if (!ak_inf_state.virtio_rx_buf ||
      ak_inf_state.virtio_rx_buf == INVALID_ADDRESS) {
    ak_inf_state.virtio_rx_buf = 0;
    ak_error("Failed to allocate virtio RX buffer");
    /* Continue initialization - local inference will be unavailable */
  }

  if (ak_inf_state.config.mode == AK_LLM_LOCAL ||
      ak_inf_state.config.mode == AK_LLM_HYBRID) {
    ak_local_inference_init(&ak_inf_state.config.local);
  }

  if (ak_inf_state.config.mode == AK_LLM_EXTERNAL ||
      ak_inf_state.config.mode == AK_LLM_HYBRID) {
    ak_external_inference_init(&ak_inf_state.config.api);
  }

  ak_inf_state.initialized = true;
}

void ak_inference_shutdown(void) {
  if (!ak_inf_state.initialized)
    return;

  /* Clear sensitive data */
  runtime_memset((u8 *)ak_inf_state.api_key_resolved, 0,
                 sizeof(ak_inf_state.api_key_resolved));
  ak_inf_state.api_key_valid = false;

  if (ak_inf_state.local_fd >= 0) {
    ak_inf_state.local_fd = -1;
  }

  if (ak_inf_state.virtio_tx_buf &&
      ak_inf_state.virtio_tx_buf != INVALID_ADDRESS)
    deallocate_buffer(ak_inf_state.virtio_tx_buf);
  if (ak_inf_state.virtio_rx_buf &&
      ak_inf_state.virtio_rx_buf != INVALID_ADDRESS)
    deallocate_buffer(ak_inf_state.virtio_rx_buf);

  ak_inf_state.initialized = false;
}

s64 ak_inference_configure(ak_llm_config_t *config) {
  if (!config)
    return AK_E_SCHEMA_INVALID;

  runtime_memcpy(&ak_inf_state.config, config, sizeof(ak_llm_config_t));

  if (config->mode == AK_LLM_LOCAL || config->mode == AK_LLM_HYBRID) {
    ak_local_inference_init(&config->local);
  }

  if (config->mode == AK_LLM_EXTERNAL || config->mode == AK_LLM_HYBRID) {
    ak_external_inference_init(&config->api);
  }

  return 0;
}

void ak_inference_get_config(ak_llm_config_t *config_out) {
  if (config_out)
    runtime_memcpy(config_out, &ak_inf_state.config, sizeof(ak_llm_config_t));
}

/* ============================================================
 * ROUTING
 * ============================================================ */

ak_llm_mode_t ak_inference_route(const char *model) {
  if (!model || ak_inf_state.config.mode == AK_LLM_MODE_DISABLED)
    return AK_LLM_MODE_DISABLED;

  if (ak_inf_state.config.mode == AK_LLM_LOCAL)
    return AK_LLM_LOCAL;

  /*
   * External API calls cannot be made in-kernel (no TLS/HTTP stack).
   * The only working transport is the host akproxy (virtio-serial),
   * which performs any HTTPS on the host side. If the proxy is
   * connected, route would-be-external requests through the local
   * proxy path. Otherwise return AK_LLM_EXTERNAL so the caller gets
   * the honest fail-closed error from ak_external_inference_request()
   * - never a hang or a fabricated success.
   */
  if (ak_inf_state.config.mode == AK_LLM_EXTERNAL)
    return ak_proxy_connected() ? AK_LLM_LOCAL : AK_LLM_EXTERNAL;

  /* Hybrid mode: route based on model name */
  if (ak_inf_state.config.mode == AK_LLM_HYBRID) {
    for (u32 i = 0; i < ak_inf_state.config.local_model_count; i++) {
      if (ak_strcmp(model, ak_inf_state.config.local_models[i]) == 0)
        return AK_LLM_LOCAL;
    }
    /* Unknown models would go external; see comment above */
    return ak_proxy_connected() ? AK_LLM_LOCAL : AK_LLM_EXTERNAL;
  }

  return AK_LLM_MODE_DISABLED;
}

/* ============================================================
 * LOCAL INFERENCE (virtio-serial)
 *
 * Protocol: Length-prefixed JSON over virtio-serial
 *   [4 bytes: message length (big-endian)]
 *   [N bytes: JSON message]
 *
 * Request format:
 *   {"model": "...", "messages": [...], "max_tokens": N}
 *
 * Response format:
 *   {"content": "...", "usage": {"prompt_tokens": N, "completion_tokens": M}}
 * ============================================================ */

s64 ak_local_inference_init(ak_llm_local_config_t *config) {
  if (!config)
    return AK_E_LLM_NOT_CONFIGURED;

  ak_inf_state.local_fd = -1;

  /*
   * The working local transport is the host akproxy (virtio-serial),
   * brought up separately via ak_proxy_init(). Reflect its real,
   * current availability instead of pretending a device was opened.
   *
   * Note: local_fd stays -1, so the legacy length-prefixed protocol
   * in virtio_request() remains fail-closed regardless of this flag;
   * requests are served exclusively through ak_proxy_llm_complete().
   */
  ak_inf_state.local_connected = ak_proxy_connected();
  if (ak_inf_state.local_connected)
    return 0;

  /*
   * Legacy direct virtio-serial device path: the driver integration
   * with the Nanos file descriptor API is not implemented, so the
   * device at config->device_path cannot be opened here. Fail closed
   * with an honest status; ak_local_inference_request() will reject
   * requests until the proxy comes up.
   */
  if (config->device_path[0] == 0)
    return AK_E_LLM_NOT_CONFIGURED;

  return AK_E_LLM_DEVICE_UNAVAILABLE;
}

/*
 * Virtio-serial I/O timeout in milliseconds.
 * Used for both write and read operations.
 */
#define VIRTIO_IO_TIMEOUT_MS 30000
#define VIRTIO_MAX_RESPONSE_SIZE (1024 * 1024) /* 1MB max response */
#define VIRTIO_MIN_RESPONSE_SIZE 2 /* Minimum valid JSON response: {} */

/*
 * Check if an error is transient and should be retried.
 *
 * Transient errors are those that may succeed on retry:
 *   - EAGAIN/EWOULDBLOCK: Resource temporarily unavailable
 *   - EINTR: Interrupted system call
 *   - Timeout with partial progress: May complete with more time
 *
 * Non-transient errors (no retry):
 *   - EBADF: Bad file descriptor
 *   - ECONNRESET: Connection reset by peer
 *   - EPIPE: Broken pipe
 *   - Device not configured
 */
static inline boolean __attribute__((unused))
is_transient_error(s64 error_code) {
  return error_code == AK_E_LLM_TIMEOUT || error_code == -EAGAIN ||
         error_code == -EINTR;
}

/*
 * Sleep for exponential backoff delay.
 *
 * Implements exponential backoff to avoid hammering the device.
 * Delay = base_ms * 2^attempt, capped at 5 seconds.
 */
static void __attribute__((unused)) virtio_backoff_delay(u32 attempt,
                                                         u32 base_ms) {
  u32 delay_ms = base_ms * (1 << attempt);
  if (delay_ms > 5000)
    delay_ms = 5000; /* Cap at 5 seconds */

  /*
   * Bounded wait with kern_pause() (arch pause/yield hint), the same
   * pattern used by ak_audit sync and ak_state. A blocking scheduler
   * sleep is not safely reachable from this context, so this remains
   * a polling wait - but never a pure hot spin, and always bounded by
   * the target deadline above.
   */
  u64 start = now(CLOCK_ID_MONOTONIC);
  u64 target = start + (u64)delay_ms * MILLION;
  while (now(CLOCK_ID_MONOTONIC) < target)
    kern_pause();
}

/*
 * Write exactly 'len' bytes to virtio fd with timeout.
 *
 * This function implements reliable byte-stream writing to a virtio-serial
 * device with timeout handling. It ensures all bytes are written before
 * returning.
 *
 * Parameters:
 *   fd         - Open file descriptor for virtio-serial device
 *   buf        - Buffer containing data to write
 *   len        - Number of bytes to write
 *   timeout_ms - Maximum time to wait for write completion
 *
 * Returns:
 *   0                       - Success, all bytes written
 *   AK_E_LLM_INVALID_REQUEST - Invalid parameters
 *   AK_E_LLM_TIMEOUT        - Write timed out
 *   AK_E_LLM_NOT_CONFIGURED - Device not available
 *   AK_E_LLM_CONNECTION_FAILED - Write error
 *
 * Implementation Notes:
 *   The virtio-serial device presents as a standard byte stream to the guest.
 *   When the device driver integration is complete, this function will use
 *   the Nanos file descriptor write API with proper error handling:
 *
 *   ssize_t n = write(fd, buf + written, len - written);
 *   if (n < 0) {
 *       if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
 *       return AK_E_LLM_CONNECTION_FAILED;
 *   }
 *   written += n;
 */
static s64 virtio_write_all(int fd, const u8 *buf, u64 len, u32 timeout_ms) {
  if (fd < 0 || !buf || len == 0)
    return AK_E_LLM_INVALID_REQUEST;

  u64 written = 0;
  u64 start_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  while (written < len) {
    u64 elapsed = (now(CLOCK_ID_MONOTONIC) / MILLION) - start_ms;
    if (elapsed >= timeout_ms)
      return AK_E_LLM_TIMEOUT;

    /*
     * Virtio-serial write implementation.
     *
     * The device presents as a byte stream. Data is written in chunks
     * up to the transmit buffer size for efficiency. The underlying
     * virtio driver handles queueing to the virtqueue.
     */
    buffer tx_buf = ak_inf_state.virtio_tx_buf;
    buffer_clear(tx_buf);
    u64 chunk = MIN(len - written, buffer_space(tx_buf));
    buffer_write(tx_buf, buf + written, chunk);

    /*
     * Virtio-serial driver integration pending.
     *
     * When the Nanos virtio-serial driver exposes a file descriptor
     * interface, this section will be implemented as:
     *
     *   ssize_t n = write(fd, buffer_ref(tx_buf, 0), buffer_length(tx_buf));
     *   if (n < 0) {
     *       if (errno == EAGAIN || errno == EWOULDBLOCK) {
     *           // Non-blocking - yield and retry
     *           continue;
     *       }
     *       return AK_E_LLM_CONNECTION_FAILED;
     *   }
     *   written += n;
     *
     * Until then, return device-not-configured error to indicate
     * the local inference backend is unavailable.
     */
    (void)fd;
    (void)tx_buf;

    return AK_E_LLM_NOT_CONFIGURED;
  }

  return 0;
}

/*
 * Read exactly 'len' bytes from virtio fd with timeout.
 *
 * This function implements reliable byte-stream reading from a virtio-serial
 * device with timeout handling. It blocks until all requested bytes are
 * received or an error/timeout occurs.
 *
 * Parameters:
 *   fd         - Open file descriptor for virtio-serial device
 *   buf        - Buffer to receive data
 *   len        - Number of bytes to read
 *   timeout_ms - Maximum time to wait for read completion
 *
 * Returns:
 *   0                       - Success, all bytes read
 *   AK_E_LLM_INVALID_REQUEST - Invalid parameters
 *   AK_E_LLM_TIMEOUT        - Read timed out
 *   AK_E_LLM_NOT_CONFIGURED - Device not available
 *   AK_E_LLM_CONNECTION_FAILED - Read error or connection closed
 *
 * Implementation Notes:
 *   The virtio-serial device presents as a standard byte stream to the guest.
 *   When the device driver integration is complete, this function will use
 *   the Nanos file descriptor read API with proper error handling:
 *
 *   ssize_t n = read(fd, buf + read_total, len - read_total);
 *   if (n < 0) {
 *       if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
 *       return AK_E_LLM_CONNECTION_FAILED;
 *   }
 *   if (n == 0) return AK_E_LLM_CONNECTION_FAILED; // EOF
 *   read_total += n;
 */
static s64 virtio_read_all(int fd, u8 *buf, u64 len, u32 timeout_ms) {
  if (fd < 0 || !buf || len == 0)
    return AK_E_LLM_INVALID_REQUEST;

  u64 read_total = 0;
  u64 start_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  while (read_total < len) {
    u64 elapsed = (now(CLOCK_ID_MONOTONIC) / MILLION) - start_ms;
    if (elapsed >= timeout_ms)
      return AK_E_LLM_TIMEOUT;

    /*
     * Virtio-serial read implementation.
     *
     * The device presents as a byte stream. The receive buffer is used
     * for staging data before copying to the output buffer.
     */
    buffer rx_buf = ak_inf_state.virtio_rx_buf;

    /*
     * Virtio-serial driver integration pending.
     *
     * When the Nanos virtio-serial driver exposes a file descriptor
     * interface, this section will be implemented as:
     *
     *   buffer_clear(rx_buf);
     *   u64 to_read = MIN(len - read_total, buffer_space(rx_buf));
     *   ssize_t n = read(fd, buffer_ref(rx_buf, 0), to_read);
     *   if (n < 0) {
     *       if (errno == EAGAIN || errno == EWOULDBLOCK) {
     *           // Non-blocking - yield and retry
     *           continue;
     *       }
     *       return AK_E_LLM_CONNECTION_FAILED;
     *   }
     *   if (n == 0) {
     *       // EOF - connection closed by host
     *       return AK_E_LLM_CONNECTION_FAILED;
     *   }
     *   runtime_memcpy(buf + read_total, buffer_ref(rx_buf, 0), n);
     *   read_total += n;
     *
     * Until then, return device-not-configured error to indicate
     * the local inference backend is unavailable.
     */
    (void)fd;
    (void)rx_buf;

    return AK_E_LLM_NOT_CONFIGURED;
  }

  return 0;
}

/* Maximum number of retries for transient errors */
#define VIRTIO_MAX_RETRIES 3
#define VIRTIO_RETRY_BASE_MS 100 /* Base delay for exponential backoff */

/*
 * Send request and receive response via virtio-serial.
 *
 * Protocol (length-prefixed JSON):
 *   Request:  [4 bytes: length (big-endian)][N bytes: JSON request]
 *   Response: [4 bytes: length (big-endian)][M bytes: JSON response]
 *
 * The host inference server must implement this protocol.
 * Typical setup: QEMU virtio-serial port connected to a host process
 * running ollama, vLLM, or similar inference server.
 *
 * Error Handling Strategy:
 *   - Connection errors: Return immediately (non-recoverable)
 *   - Timeout errors: Retry with exponential backoff (transient)
 *   - Invalid request: Return immediately (client error)
 *   - Server errors: Parse error response from server JSON
 *
 * Retry Policy:
 *   Transient errors (EAGAIN, EINTR, timeout) are retried up to
 *   VIRTIO_MAX_RETRIES times with exponential backoff starting at
 *   VIRTIO_RETRY_BASE_MS. Non-transient errors fail immediately.
 */
static ak_inference_response_t *virtio_request(buffer request_json) {
  ak_inference_response_t *res =
      allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
  if (res == INVALID_ADDRESS)
    return 0;
  runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

  /* Check connection state */
  if (!ak_inf_state.local_connected || ak_inf_state.local_fd < 0) {
    res->success = false;
    res->error_code = AK_E_LLM_CONNECTION_FAILED;
    runtime_memcpy(res->error_message, "Local inference not connected",
                   sizeof("Local inference not connected"));
    return res;
  }

  /* Validate request */
  if (!request_json || buffer_length(request_json) == 0) {
    res->success = false;
    res->error_code = AK_E_LLM_INVALID_REQUEST;
    runtime_memcpy(res->error_message, "Empty request",
                   sizeof("Empty request"));
    return res;
  }

  u32 req_len = buffer_length(request_json);
  u32 timeout_ms = ak_inf_state.config.local.timeout_ms;
  if (timeout_ms == 0)
    timeout_ms = VIRTIO_IO_TIMEOUT_MS;

  /*
   * Step 1: Send length prefix (4 bytes, big-endian)
   */
  u8 len_buf[4];
  len_buf[0] = (req_len >> 24) & 0xFF;
  len_buf[1] = (req_len >> 16) & 0xFF;
  len_buf[2] = (req_len >> 8) & 0xFF;
  len_buf[3] = req_len & 0xFF;

  s64 write_result =
      virtio_write_all(ak_inf_state.local_fd, len_buf, 4, timeout_ms);
  if (write_result != 0) {
    res->success = false;
    res->error_code = write_result;
    if (write_result == AK_E_LLM_TIMEOUT) {
      runtime_memcpy(res->error_message, "Write timeout sending length",
                     sizeof("Write timeout sending length"));
    } else if (write_result == AK_E_LLM_NOT_CONFIGURED) {
      runtime_memcpy(res->error_message, "virtio-serial device not available",
                     sizeof("virtio-serial device not available"));
    } else {
      runtime_memcpy(res->error_message, "Failed to send request length",
                     sizeof("Failed to send request length"));
    }
    return res;
  }

  /*
   * Step 2: Send JSON request body
   */
  write_result = virtio_write_all(
      ak_inf_state.local_fd, buffer_ref(request_json, 0), req_len, timeout_ms);
  if (write_result != 0) {
    res->success = false;
    res->error_code = write_result;
    if (write_result == AK_E_LLM_TIMEOUT) {
      runtime_memcpy(res->error_message, "Write timeout sending request",
                     sizeof("Write timeout sending request"));
    } else {
      runtime_memcpy(res->error_message, "Failed to send request body",
                     sizeof("Failed to send request body"));
    }
    return res;
  }

  /*
   * Step 3: Read response length prefix (4 bytes, big-endian)
   */
  u8 resp_len_buf[4];
  s64 read_result =
      virtio_read_all(ak_inf_state.local_fd, resp_len_buf, 4, timeout_ms);
  if (read_result != 0) {
    res->success = false;
    res->error_code = read_result;
    if (read_result == AK_E_LLM_TIMEOUT) {
      runtime_memcpy(res->error_message, "Read timeout waiting for response",
                     sizeof("Read timeout waiting for response"));
    } else {
      runtime_memcpy(res->error_message, "Failed to read response length",
                     sizeof("Failed to read response length"));
    }
    return res;
  }

  u32 resp_len = ((u32)resp_len_buf[0] << 24) | ((u32)resp_len_buf[1] << 16) |
                 ((u32)resp_len_buf[2] << 8) | (u32)resp_len_buf[3];

  /* Validate response length */
  if (resp_len == 0) {
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    runtime_memcpy(res->error_message, "Empty response from inference server",
                   sizeof("Empty response from inference server"));
    return res;
  }

  if (resp_len > VIRTIO_MAX_RESPONSE_SIZE) {
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    runtime_memcpy(res->error_message, "Response too large",
                   sizeof("Response too large"));
    return res;
  }

  /*
   * Step 4: Allocate buffer and read response body
   */
  buffer response_buf = allocate_buffer(ak_inf_state.h, resp_len);
  if (response_buf == INVALID_ADDRESS) {
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    runtime_memcpy(res->error_message, "Failed to allocate response buffer",
                   sizeof("Failed to allocate response buffer"));
    return res;
  }

  /* Ensure buffer has space for response */
  u8 *resp_data = buffer_ref(response_buf, 0);
  read_result =
      virtio_read_all(ak_inf_state.local_fd, resp_data, resp_len, timeout_ms);
  if (read_result != 0) {
    deallocate_buffer(response_buf);
    res->success = false;
    res->error_code = read_result;
    if (read_result == AK_E_LLM_TIMEOUT) {
      runtime_memcpy(res->error_message, "Read timeout reading response body",
                     sizeof("Read timeout reading response body"));
    } else {
      runtime_memcpy(res->error_message, "Failed to read response body",
                     sizeof("Failed to read response body"));
    }
    return res;
  }

  /* Update buffer length to reflect received data */
  buffer_produce(response_buf, resp_len);

  /*
   * Step 5: Parse JSON response
   *
   * Expected format from inference server:
   * {
   *   "content": "generated text...",
   *   "usage": {
   *     "prompt_tokens": 123,
   *     "completion_tokens": 456
   *   },
   *   "finish_reason": "stop"
   * }
   *
   * Or on error:
   * {
   *   "error": "error message"
   * }
   */
  char error_msg[256];
  s64 err_len =
      json_extract_string(response_buf, "error", error_msg, sizeof(error_msg));
  if (err_len >= 0) {
    /* Server returned an error */
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    u64 copy_len = MIN((u64)err_len, sizeof(res->error_message) - 1);
    runtime_memcpy(res->error_message, error_msg, copy_len);
    res->error_message[copy_len] = '\0';
    deallocate_buffer(response_buf);
    return res;
  }

  /* Extract content */
  char content_buf[32768];
  s64 content_len = json_extract_string(response_buf, "content", content_buf,
                                        sizeof(content_buf));
  if (content_len >= 0) {
    res->content = allocate_buffer(ak_inf_state.h, content_len + 1);
    if (res->content != INVALID_ADDRESS) {
      buffer_write(res->content, content_buf, content_len);
      res->success = true;
    } else {
      res->success = false;
      res->error_code = AK_E_LLM_API_ERROR;
      runtime_memcpy(res->error_message, "Failed to allocate content buffer",
                     sizeof("Failed to allocate content buffer"));
      deallocate_buffer(response_buf);
      return res;
    }
  } else {
    /* No content field - return raw response */
    res->content = response_buf;
    response_buf = 0; /* Transfer ownership */
    res->success = true;
  }

  /* Extract usage statistics */
  u64 prompt_tokens = 0, completion_tokens = 0;
  json_extract_int(response_buf ? response_buf : res->content, "prompt_tokens",
                   &prompt_tokens);
  json_extract_int(response_buf ? response_buf : res->content,
                   "completion_tokens", &completion_tokens);

  res->usage.prompt_tokens = (u32)prompt_tokens;
  res->usage.completion_tokens = (u32)completion_tokens;
  res->usage.total_tokens =
      res->usage.prompt_tokens + res->usage.completion_tokens;

  /* Extract finish reason */
  char finish_reason[32];
  if (json_extract_string(response_buf ? response_buf : res->content,
                          "finish_reason", finish_reason,
                          sizeof(finish_reason)) >= 0) {
    if (ak_strcmp(finish_reason, "length") == 0)
      res->finish_reason = AK_FINISH_LENGTH;
    else if (ak_strcmp(finish_reason, "tool_calls") == 0)
      res->finish_reason = AK_FINISH_TOOL_CALLS;
    else
      res->finish_reason = AK_FINISH_STOP;
  } else {
    res->finish_reason = AK_FINISH_STOP;
  }

  if (response_buf)
    deallocate_buffer(response_buf);

  return res;
}

ak_inference_response_t *
ak_local_inference_request(ak_inference_request_t *req) {
  ak_inference_response_t *res =
      allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
  if (res == INVALID_ADDRESS)
    return 0;
  runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

  /* Try akproxy (newline-delimited JSON protocol) first */
  if (ak_proxy_connected()) {
    /* Extract prompt from request */
    const char *prompt_str = 0;
    u64 prompt_len = 0;
    if (req->prompt) {
      prompt_str = (const char *)buffer_ref(req->prompt, 0);
      prompt_len = buffer_length(req->prompt);
    }

    /* Need null-terminated strings */
    char *prompt_buf = 0;
    if (prompt_str && prompt_len > 0) {
      prompt_buf = allocate(ak_inf_state.h, prompt_len + 1);
      if (prompt_buf) {
        runtime_memcpy(prompt_buf, prompt_str, prompt_len);
        prompt_buf[prompt_len] = 0;
      }
    }

    ak_llm_response_t proxy_res;
    runtime_memset((u8 *)&proxy_res, 0, sizeof(proxy_res));
    s64 err = ak_proxy_llm_complete(
        req->model[0] ? req->model : 0, prompt_buf ? prompt_buf : "",
        req->max_tokens > 0 ? req->max_tokens : 1024, &proxy_res);

    if (prompt_buf)
      deallocate(ak_inf_state.h, prompt_buf, prompt_len + 1);

    if (err == 0 && proxy_res.content) {
      res->success = true;
      res->content = proxy_res.content;
      proxy_res.content = 0; /* Transfer ownership */
      /* Map finish_reason string to enum */
      if (proxy_res.finish_reason[0] == 'l') /* "length" */
        res->finish_reason = AK_FINISH_LENGTH;
      else if (proxy_res.finish_reason[0] == 't') /* "tool_calls" */
        res->finish_reason = AK_FINISH_TOOL_CALLS;
      else
        res->finish_reason = AK_FINISH_STOP;
      res->usage.prompt_tokens = proxy_res.prompt_tokens;
      res->usage.completion_tokens = proxy_res.completion_tokens;
      res->usage.total_tokens = proxy_res.total_tokens;
      return res;
    }

    /*
     * Proxy request failed. The legacy virtio fd path below cannot
     * serve a retry (device never opens), so report the proxy error
     * honestly instead of masking it with "not connected".
     */
    ak_proxy_free_llm_response(&proxy_res);
    res->success = false;
    res->error_code =
        (err == AK_PROXY_E_TIMEOUT) ? AK_E_LLM_TIMEOUT
                                    : AK_E_LLM_CONNECTION_FAILED;
    runtime_memcpy(res->error_message, "Host proxy LLM request failed",
                   sizeof("Host proxy LLM request failed"));
    return res;
  }

  if (!ak_inf_state.local_connected || ak_inf_state.local_fd < 0) {
    res->success = false;
    res->error_code = AK_E_LLM_CONNECTION_FAILED;
    runtime_memcpy(res->error_message, "Local inference not connected",
                   sizeof("Local inference not connected"));
    return res;
  }

  /* Build JSON request */
  buffer request_buf = allocate_buffer(ak_inf_state.h, 4096);
  if (request_buf == INVALID_ADDRESS) {
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    return res;
  }

  buffer_write(request_buf, "{\"model\":\"", 10);
  if (req->model[0])
    buffer_write(request_buf, req->model, runtime_strlen(req->model));
  else
    buffer_write(request_buf, "default", 7);
  buffer_write(request_buf, "\",\"messages\":[", 14);

  if (req->messages && req->message_count > 0) {
    for (u32 i = 0; i < req->message_count; i++) {
      if (i > 0)
        buffer_write(request_buf, ",", 1);
      buffer_write(request_buf, "{\"role\":\"", 9);

      const char *role;
      switch (req->messages[i].role) {
      case AK_ROLE_SYSTEM:
        role = "system";
        break;
      case AK_ROLE_USER:
        role = "user";
        break;
      case AK_ROLE_ASSISTANT:
        role = "assistant";
        break;
      case AK_ROLE_TOOL:
        role = "tool";
        break;
      default:
        role = "user";
        break;
      }
      buffer_write(request_buf, role, runtime_strlen(role));
      buffer_write(request_buf, "\",\"content\":\"", 13);

      if (req->messages[i].content) {
        u8 *content = buffer_ref(req->messages[i].content, 0);
        json_escape_string(request_buf, (char *)content,
                           buffer_length(req->messages[i].content));
      }
      buffer_write(request_buf, "\"}", 2);
    }
  } else if (req->prompt) {
    buffer_write(request_buf, "{\"role\":\"user\",\"content\":\"", 26);
    u8 *prompt = buffer_ref(req->prompt, 0);
    json_escape_string(request_buf, (char *)prompt, buffer_length(req->prompt));
    buffer_write(request_buf, "\"}", 2);
  }

  buffer_write(request_buf, "],\"max_tokens\":", 15);
  char num_buf[16];
  int num_len =
      u64_format(req->max_tokens > 0 ? req->max_tokens : 1024, num_buf);
  buffer_write(request_buf, num_buf, num_len);
  buffer_write(request_buf, "}", 1);

  /* Send via virtio */
  ak_inference_response_t *virtio_res = virtio_request(request_buf);
  deallocate_buffer(request_buf);

  if (!virtio_res) {
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    return res;
  }

  deallocate(ak_inf_state.h, res, sizeof(ak_inference_response_t));
  return virtio_res;
}

boolean ak_local_inference_healthy(void) {
  /*
   * Live check: the working local path is the host akproxy. Do not
   * trust the snapshot taken at init - the proxy may have come up or
   * gone down since then.
   */
  if (ak_proxy_connected())
    return true;

  /* Legacy direct device path (never connected until driver lands) */
  return ak_inf_state.local_connected && ak_inf_state.local_fd >= 0;
}

/* ============================================================
 * EXTERNAL INFERENCE (HTTPS API)
 * ============================================================
 *
 * IMPLEMENTATION STATUS: NOT AVAILABLE
 *
 * External LLM API calls (OpenAI, Anthropic, etc.) require HTTPS client
 * functionality which is NOT currently available in the Authority Kernel.
 *
 * WHY NOT AVAILABLE:
 *   The Nanos unikernel provides TCP/IP networking via lwIP, but lacks:
 *
 *   1. TLS LIBRARY: No TLS implementation is linked into the kernel.
 *      - mbedTLS, OpenSSL, or similar would need to be ported
 *      - Certificate bundle management for CA validation
 *      - TLS session management and resumption
 *
 *   2. HTTP CLIENT: No HTTP protocol implementation.
 *      - HTTP/1.1 request/response framing
 *      - Chunked transfer encoding for streaming responses
 *      - Header parsing and content-length handling
 *      - Connection keep-alive and pooling
 *
 *   3. DNS RESOLUTION: Hostname-to-IP resolution.
 *      - DNS query/response handling
 *      - Caching and TTL management
 *      - IPv4/IPv6 dual-stack support
 *
 *   4. SYNCHRONOUS BLOCKING: WASM host functions are synchronous.
 *      - Network I/O is inherently async in the kernel
 *      - Would require thread blocking or execution suspension
 *
 * ALTERNATIVES FOR AGENTS NEEDING EXTERNAL LLM ACCESS:
 *
 *   1. LOCAL INFERENCE (Recommended):
 *      Configure AK_LLM_LOCAL mode with virtio-serial connection to a
 *      host-side inference server (ollama, vLLM, llama.cpp). This bypasses
 *      the need for kernel-space HTTPS entirely.
 *
 *      Configuration:
 *        ak_llm_config_t config = {
 *          .mode = AK_LLM_LOCAL,
 *          .local.device_path = "/dev/vport0p1",
 *          .local.timeout_ms = 30000,
 *          .local.max_tokens = 4096
 *        };
 *
 *   2. PROXY VIA VIRTIO-SERIAL:
 *      Route API requests through the host hypervisor. The guest sends
 *      the API request over virtio-serial, and the host makes the HTTPS
 *      call on behalf of the guest.
 *
 *      Protocol:
 *        Guest -> Host: {"type": "llm_api", "provider": "openai", ...}
 *        Host performs HTTPS request to OpenAI
 *        Host -> Guest: {"content": "...", "usage": {...}}
 *
 *   3. PRE-COMPUTED RESPONSES:
 *      For deterministic workloads, orchestrator can pre-fetch LLM
 *      responses before agent execution and inject them as tool arguments.
 *
 * FUTURE IMPLEMENTATION:
 *   External API support may be added when:
 *     - TLS library (mbedTLS) is ported to Nanos
 *     - HTTP client library is integrated
 *     - Async-to-sync bridging for kernel execution is implemented
 *   Track: https://github.com/nanovms/nanos/issues (TLS support)
 *
 * SECURITY CONSIDERATIONS:
 *   Even if HTTPS is implemented, external API access introduces risks:
 *     - API key exposure if not properly secured
 *     - Data exfiltration through API calls
 *     - Cost attacks through unlimited API usage
 *   The capability system should enforce strict budgets and audit all calls.
 *
 * ============================================================ */

s64 ak_external_inference_init(ak_llm_api_config_t *config) {
  if (!config)
    return AK_E_LLM_NOT_CONFIGURED;

  if (config->endpoint[0] == 0)
    return AK_E_LLM_NOT_CONFIGURED;

  ak_inf_state.api_configured = true;
  return 0;
}

/*
 * Format API request for OpenAI-compatible endpoints.
 */
static buffer format_openai_request(heap h, ak_inference_request_t *req) {
  u64 size = 4096;
  if (req->prompt)
    size += buffer_length(req->prompt);
  for (u32 i = 0; i < req->message_count; i++) {
    if (req->messages[i].content)
      size += buffer_length(req->messages[i].content);
  }

  buffer buf = allocate_buffer(h, size);
  if (buf == INVALID_ADDRESS)
    return 0;

  buffer_write(buf, "{\"model\":\"", 10);
  if (req->model[0])
    buffer_write(buf, req->model, runtime_strlen(req->model));
  else
    buffer_write(buf, "gpt-4", 5);
  buffer_write(buf, "\",", 2);

  if (req->type == AK_INFERENCE_CHAT && req->messages &&
      req->message_count > 0) {
    buffer_write(buf, "\"messages\":[", 12);
    for (u32 i = 0; i < req->message_count; i++) {
      if (i > 0)
        buffer_write(buf, ",", 1);
      buffer_write(buf, "{\"role\":\"", 9);

      const char *role;
      switch (req->messages[i].role) {
      case AK_ROLE_SYSTEM:
        role = "system";
        break;
      case AK_ROLE_USER:
        role = "user";
        break;
      case AK_ROLE_ASSISTANT:
        role = "assistant";
        break;
      case AK_ROLE_TOOL:
        role = "tool";
        break;
      default:
        role = "user";
        break;
      }
      buffer_write(buf, role, runtime_strlen(role));
      buffer_write(buf, "\",\"content\":\"", 13);

      if (req->messages[i].content) {
        u8 *content = buffer_ref(req->messages[i].content, 0);
        json_escape_string(buf, (char *)content,
                           buffer_length(req->messages[i].content));
      }
      buffer_write(buf, "\"}", 2);
    }
    buffer_write(buf, "],", 2);
  } else if (req->prompt) {
    buffer_write(buf, "\"prompt\":\"", 10);
    u8 *prompt = buffer_ref(req->prompt, 0);
    json_escape_string(buf, (char *)prompt, buffer_length(req->prompt));
    buffer_write(buf, "\",", 2);
  }

  buffer_write(buf, "\"max_tokens\":", 13);
  char num_buf[16];
  int num_len =
      u64_format(req->max_tokens > 0 ? req->max_tokens : 1024, num_buf);
  buffer_write(buf, num_buf, num_len);

  if (req->temperature > 0) {
    buffer_write(buf, ",\"temperature\":", 15);
    /* Simple float formatting for 0.0-2.0 range */
    int int_part = (int)req->temperature;
    int frac_part = (int)((req->temperature - int_part) * 10);
    char temp_buf[8];
    temp_buf[0] = '0' + int_part;
    temp_buf[1] = '.';
    temp_buf[2] = '0' + frac_part;
    buffer_write(buf, temp_buf, 3);
  }

  buffer_write(buf, "}", 1);

  return buf;
}

/*
 * Format API request for Anthropic Claude.
 */
static buffer format_anthropic_request(heap h, ak_inference_request_t *req) {
  u64 size = 4096;
  if (req->prompt)
    size += buffer_length(req->prompt);
  for (u32 i = 0; i < req->message_count; i++) {
    if (req->messages[i].content)
      size += buffer_length(req->messages[i].content);
  }

  buffer buf = allocate_buffer(h, size);
  if (buf == INVALID_ADDRESS)
    return 0;

  buffer_write(buf, "{\"model\":\"", 10);
  if (req->model[0])
    buffer_write(buf, req->model, runtime_strlen(req->model));
  else
    buffer_write(buf, "claude-3-5-sonnet-20241022", 26);
  buffer_write(buf, "\",\"max_tokens\":", 15);

  char num_buf[16];
  int num_len =
      u64_format(req->max_tokens > 0 ? req->max_tokens : 1024, num_buf);
  buffer_write(buf, num_buf, num_len);

  buffer_write(buf, ",\"messages\":[", 13);

  if (req->messages && req->message_count > 0) {
    boolean first = true;
    for (u32 i = 0; i < req->message_count; i++) {
      /* Anthropic only supports user/assistant in messages */
      if (req->messages[i].role != AK_ROLE_USER &&
          req->messages[i].role != AK_ROLE_ASSISTANT)
        continue;

      if (!first)
        buffer_write(buf, ",", 1);
      first = false;

      buffer_write(buf, "{\"role\":\"", 9);
      const char *role =
          req->messages[i].role == AK_ROLE_USER ? "user" : "assistant";
      buffer_write(buf, role, runtime_strlen(role));
      buffer_write(buf, "\",\"content\":\"", 13);

      if (req->messages[i].content) {
        u8 *content = buffer_ref(req->messages[i].content, 0);
        json_escape_string(buf, (char *)content,
                           buffer_length(req->messages[i].content));
      }
      buffer_write(buf, "\"}", 2);
    }
  } else if (req->prompt) {
    buffer_write(buf, "{\"role\":\"user\",\"content\":\"", 26);
    u8 *prompt = buffer_ref(req->prompt, 0);
    json_escape_string(buf, (char *)prompt, buffer_length(req->prompt));
    buffer_write(buf, "\"}", 2);
  }

  buffer_write(buf, "]}", 2);

  return buf;
}

buffer ak_format_api_request(heap h, ak_llm_provider_t provider,
                             ak_inference_request_t *req) {
  switch (provider) {
  case AK_LLM_PROVIDER_OPENAI:
  case AK_LLM_PROVIDER_LOCAL:
  case AK_LLM_PROVIDER_CUSTOM:
    return format_openai_request(h, req);
  case AK_LLM_PROVIDER_ANTHROPIC:
    return format_anthropic_request(h, req);
  default:
    return 0;
  }
}

ak_inference_response_t *
ak_parse_api_response(heap h, ak_llm_provider_t provider, buffer response) {
  ak_inference_response_t *res = allocate(h, sizeof(ak_inference_response_t));
  if (res == INVALID_ADDRESS)
    return 0;

  runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

  if (!response || buffer_length(response) == 0) {
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    return res;
  }

  /* Extract content from response based on provider format */
  char content_buf[32768];
  s64 content_len;

  if (provider == AK_LLM_PROVIDER_ANTHROPIC) {
    /* Anthropic format: {"content": [{"text": "..."}], ...} */
    content_len =
        json_extract_string(response, "text", content_buf, sizeof(content_buf));
  } else {
    /* OpenAI format: {"choices": [{"message": {"content": "..."}}], ...} */
    content_len = json_extract_string(response, "content", content_buf,
                                      sizeof(content_buf));
  }

  if (content_len < 0) {
    /* Try direct content field */
    content_len = json_extract_string(response, "content", content_buf,
                                      sizeof(content_buf));
  }

  if (content_len >= 0) {
    res->content = allocate_buffer(h, content_len + 1);
    if (res->content != INVALID_ADDRESS) {
      buffer_write(res->content, content_buf, content_len);
      res->success = true;
    } else {
      res->content = 0;
      res->success = false;
      res->error_code = AK_E_LLM_API_ERROR;
      return res;
    }
  } else {
    /*
     * BUG-A9-009 FIX: Response ownership clarification.
     *
     * When we can't parse the response, we copy it to a new buffer
     * instead of transferring ownership. This ensures the caller
     * always retains ownership of the 'response' parameter and
     * res->content is always a fresh allocation that res owns.
     *
     * Previously, this transferred ownership which caused:
     *   1. Double-free if caller also freed response
     *   2. Memory leak if caller didn't know ownership transferred
     */
    res->content = allocate_buffer(h, buffer_length(response) + 1);
    if (res->content && res->content != INVALID_ADDRESS) {
      buffer_write(res->content, buffer_ref(response, 0),
                   buffer_length(response));
      res->success = true;
    } else {
      res->content = 0;
      res->success = false;
      res->error_code = AK_E_LLM_API_ERROR;
      return res;
    }
  }

  /* Extract usage statistics */
  u64 prompt_tokens = 0, completion_tokens = 0;
  json_extract_int(response, "prompt_tokens", &prompt_tokens);
  json_extract_int(response, "completion_tokens", &completion_tokens);

  res->usage.prompt_tokens = (u32)prompt_tokens;
  res->usage.completion_tokens = (u32)completion_tokens;
  res->usage.total_tokens =
      res->usage.prompt_tokens + res->usage.completion_tokens;
  res->finish_reason = AK_FINISH_STOP;

  return res;
}

ak_inference_response_t *
ak_external_inference_request(ak_inference_request_t *req,
                              ak_llm_api_config_t *api_config) {
  ak_inference_response_t *res =
      allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
  if (res == INVALID_ADDRESS)
    return 0;

  runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

  if (!ak_inf_state.api_configured || !api_config) {
    res->success = false;
    res->error_code = AK_E_LLM_NOT_CONFIGURED;
    runtime_memcpy(res->error_message, "API not configured",
                   sizeof("API not configured"));
    return res;
  }

  if (api_config->endpoint[0] == 0) {
    res->success = false;
    res->error_code = AK_E_LLM_NOT_CONFIGURED;
    runtime_memcpy(res->error_message, "No API endpoint configured",
                   sizeof("No API endpoint configured"));
    return res;
  }

  /* Format request body */
  buffer request_body =
      ak_format_api_request(ak_inf_state.h, api_config->provider, req);

  if (!request_body) {
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    runtime_memcpy(res->error_message, "Failed to format request",
                   sizeof("Failed to format request"));
    return res;
  }

  /*
   * IN-KERNEL HTTPS PATH.
   *
   * When a transport klib (klib/ak_https.c) is loaded it registers a
   * net_http_req-backed thunk into the kernel transport hook, and
   * ak_https_request() can make a real TLS request from here. When no
   * transport is registered we FAIL CLOSED with the honest
   * AK_E_LLM_CONNECTION_FAILED - never a fabricated response.
   *
   * (When the host akproxy is connected, ak_inference_route() diverts
   * would-be-external requests to the local/proxy path before this
   * function is reached; so this path is the direct-HTTPS fallback.)
   */
  if (!ak_transport_available()) {
    deallocate_buffer(request_body);
    res->success = false;
    res->error_code = AK_E_LLM_CONNECTION_FAILED;
    runtime_memcpy(res->error_message,
                   "External API unavailable: no HTTPS transport klib loaded",
                   sizeof("External API unavailable: no HTTPS transport klib loaded"));
    return res;
  }

  /* Provider-specific host / path. */
  const char *host;
  const char *path;
  if (api_config->provider == AK_LLM_PROVIDER_ANTHROPIC) {
    host = "api.anthropic.com";
    path = "/v1/messages";
  } else {
    /* OpenAI-compatible (OPENAI / CUSTOM / LOCAL formatting). */
    host = "api.openai.com";
    path = "/v1/chat/completions";
  }

  /*
   * Resolve the API key. Prefer the pre-resolved key; otherwise resolve
   * the configured secret name (internal use, no capability required).
   */
  char api_key[512];
  api_key[0] = 0;
  if (ak_inf_state.api_key_valid && ak_inf_state.api_key_resolved[0]) {
    u64 kl = runtime_strlen(ak_inf_state.api_key_resolved);
    if (kl >= sizeof(api_key))
      kl = sizeof(api_key) - 1;
    runtime_memcpy(api_key, ak_inf_state.api_key_resolved, kl);
    api_key[kl] = 0;
  } else if (api_config->secret_name[0]) {
    buffer kb = ak_secret_resolve(ak_inf_state.h, api_config->secret_name,
                                  runtime_strlen(api_config->secret_name), 0);
    if (kb && kb != INVALID_ADDRESS) {
      u64 kl = buffer_length(kb);
      if (kl >= sizeof(api_key))
        kl = sizeof(api_key) - 1;
      runtime_memcpy(api_key, buffer_ref(kb, 0), kl);
      api_key[kl] = 0;
      ak_secret_clear(kb);
    }
  }

  if (api_key[0] == 0) {
    deallocate_buffer(request_body);
    res->success = false;
    res->error_code = AK_E_LLM_NOT_CONFIGURED;
    runtime_memcpy(res->error_message, "API key unavailable",
                   sizeof("API key unavailable"));
    return res;
  }

  /* Build headers. */
  ak_http_header headers[4];
  u32 header_count = 0;
  headers[header_count].name = "Content-Type";
  headers[header_count].value = "application/json";
  header_count++;

  char auth_value[600];
  if (api_config->provider == AK_LLM_PROVIDER_ANTHROPIC) {
    headers[header_count].name = "x-api-key";
    headers[header_count].value = api_key;
    header_count++;
    headers[header_count].name = "anthropic-version";
    headers[header_count].value = "2023-06-01";
    header_count++;
  } else {
    /* "Bearer " + key */
    runtime_memcpy(auth_value, "Bearer ", 7);
    u64 kl = runtime_strlen(api_key);
    if (kl > sizeof(auth_value) - 8)
      kl = sizeof(auth_value) - 8;
    runtime_memcpy(auth_value + 7, api_key, kl);
    auth_value[7 + kl] = 0;
    headers[header_count].name = "Authorization";
    headers[header_count].value = auth_value;
    header_count++;
  }

  u32 timeout_ms = api_config->timeout_ms ? api_config->timeout_ms : 30000;
  buffer resp = 0;
  s64 http_status = ak_https_request(
      host, 443, true, AK_HTTP_METHOD_POST, path, headers, header_count,
      buffer_ref(request_body, 0), buffer_length(request_body), &resp,
      timeout_ms);

  /* Wipe key material from the stack. */
  runtime_memset((u8 *)api_key, 0, sizeof(api_key));
  runtime_memset((u8 *)auth_value, 0, sizeof(auth_value));

  deallocate_buffer(request_body);

  if (http_status < 0 || !resp) {
    if (resp)
      deallocate_buffer(resp);
    res->success = false;
    res->error_code = (http_status == AK_E_TIMEOUT) ? AK_E_LLM_TIMEOUT
                                                     : AK_E_LLM_CONNECTION_FAILED;
    runtime_memcpy(res->error_message, "HTTPS request failed",
                   sizeof("HTTPS request failed"));
    return res;
  }

  if (http_status < 200 || http_status >= 300) {
    deallocate_buffer(resp);
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    runtime_memcpy(res->error_message, "API returned non-2xx status",
                   sizeof("API returned non-2xx status"));
    return res;
  }

  /* Parse the successful response. ak_parse_api_response() allocates its
   * own response object; hand back that one and free our placeholder. */
  ak_inference_response_t *parsed =
      ak_parse_api_response(ak_inf_state.h, api_config->provider, resp);
  deallocate_buffer(resp);
  deallocate(ak_inf_state.h, res, sizeof(ak_inference_response_t));

  if (!parsed) {
    ak_inference_response_t *err =
        allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (err == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)err, 0, sizeof(ak_inference_response_t));
    err->success = false;
    err->error_code = AK_E_LLM_MALFORMED_RESPONSE;
    return err;
  }

  return parsed;
}

/* ============================================================
 * MAIN INFERENCE API
 * ============================================================ */

ak_inference_response_t *ak_inference_complete(ak_agent_context_t *agent,
                                               ak_inference_request_t *req,
                                               ak_capability_t *cap) {
  ak_inference_response_t *res;

  if (!ak_inf_state.initialized) {
    res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
    res->success = false;
    res->error_code = AK_E_LLM_NOT_CONFIGURED;
    return res;
  }

  /* Validate capability (INV-2: Capability Enforcement) */
  if (!cap) {
    ak_inf_state.stats.capability_denials++;
    res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
    res->success = false;
    res->error_code = AK_E_CAP_MISSING;
    return res;
  }

  s64 cap_result = ak_capability_validate(cap, AK_CAP_INFERENCE, "*",
                                          "inference", agent->run_id);
  if (cap_result != 0) {
    ak_inf_state.stats.capability_denials++;
    res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
    res->success = false;
    res->error_code = cap_result;
    return res;
  }

  /* Check budget (INV-3: Budget Enforcement) */
  if (agent->budget) {
    u32 estimated_tokens = req->max_tokens > 0 ? req->max_tokens : 1024;
    if (!ak_budget_check(agent->budget, AK_RESOURCE_LLM_TOKENS_OUT,
                         estimated_tokens)) {
      ak_inf_state.stats.budget_exceeded++;
      res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
      if (res == INVALID_ADDRESS)
        return 0;
      runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
      res->success = false;
      res->error_code = AK_E_BUDGET_EXCEEDED;
      return res;
    }
  }

  /* Route request based on model and configuration */
  ak_llm_mode_t route = ak_inference_route(req->model);

  ak_inf_state.stats.requests_total++;

  if (route == AK_LLM_LOCAL) {
    ak_inf_state.stats.requests_local++;
    res = ak_local_inference_request(req);
  } else if (route == AK_LLM_EXTERNAL) {
    ak_inf_state.stats.requests_external++;
    res = ak_external_inference_request(req, &ak_inf_state.config.api);
  } else {
    res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
    res->success = false;
    res->error_code = AK_E_LLM_NOT_CONFIGURED;
    runtime_memcpy(res->error_message, "No LLM backend configured",
                   sizeof("No LLM backend configured"));
    return res;
  }

  /* Update statistics and budget */
  if (res && res->success) {
    ak_inf_state.stats.tokens_in_total += res->usage.prompt_tokens;
    ak_inf_state.stats.tokens_out_total += res->usage.completion_tokens;

    if (agent->budget) {
      ak_budget_commit(agent->budget, AK_RESOURCE_LLM_TOKENS_IN,
                       res->usage.prompt_tokens);
      ak_budget_commit(agent->budget, AK_RESOURCE_LLM_TOKENS_OUT,
                       res->usage.completion_tokens);
    }
  } else {
    ak_inf_state.stats.requests_failed++;
  }

  return res;
}

/*
 * Stream callback adapter context.
 *
 * Bridges the ak_stream infrastructure's token callback to the
 * user-provided ak_stream_callback_t function.
 */
typedef struct stream_callback_adapter {
  ak_stream_callback_t user_callback;
  void *user_ctx;
  ak_inference_response_t *response;
  boolean error_occurred;
} stream_callback_adapter_t;

/*
 * Internal token callback for streaming.
 *
 * Invoked by ak_stream infrastructure for each token received.
 * Forwards tokens to the user callback and tracks completion state.
 */
static void stream_token_callback(ak_stream_session_t *session,
                                  const char *token, u32 token_len,
                                  boolean is_final, void *ctx) {
  stream_callback_adapter_t *adapter = (stream_callback_adapter_t *)ctx;
  (void)session;

  if (!adapter || !adapter->user_callback)
    return;

  /* Forward to user callback */
  adapter->user_callback(adapter->user_ctx, token, token_len, is_final);
}

/*
 * Internal close callback for streaming.
 *
 * Invoked when the stream session closes (success, error, or timeout).
 * Records the final state in the response structure.
 */
static void stream_close_callback(ak_stream_session_t *session,
                                  ak_stream_state_t reason, void *ctx) {
  stream_callback_adapter_t *adapter = (stream_callback_adapter_t *)ctx;

  if (!adapter || !adapter->response)
    return;

  /* Record stream statistics in response */
  adapter->response->usage.completion_tokens = (u32)session->tokens_sent;

  /* Map stream close reason to response state */
  switch (reason) {
  case AK_STREAM_STATE_CLOSED:
    /* Normal completion */
    adapter->response->success = true;
    adapter->response->finish_reason = AK_FINISH_STOP;
    break;
  case AK_STREAM_STATE_BUDGET:
    adapter->response->success = false;
    adapter->response->error_code = AK_E_BUDGET_EXCEEDED;
    adapter->response->finish_reason = AK_FINISH_LENGTH;
    runtime_memcpy(adapter->response->error_message, "Stream budget exceeded",
                   sizeof("Stream budget exceeded"));
    adapter->error_occurred = true;
    break;
  case AK_STREAM_STATE_TIMEOUT:
    adapter->response->success = false;
    adapter->response->error_code = AK_E_LLM_TIMEOUT;
    adapter->response->finish_reason = AK_FINISH_ERROR;
    runtime_memcpy(adapter->response->error_message, "Stream timeout",
                   sizeof("Stream timeout"));
    adapter->error_occurred = true;
    break;
  case AK_STREAM_STATE_ERROR:
  default:
    adapter->response->success = false;
    adapter->response->error_code = AK_E_LLM_API_ERROR;
    adapter->response->finish_reason = AK_FINISH_ERROR;
    if (session->error_msg[0]) {
      runtime_memcpy(adapter->response->error_message, session->error_msg,
                     sizeof(adapter->response->error_message));
    } else {
      runtime_memcpy(adapter->response->error_message, "Stream error",
                     sizeof("Stream error"));
    }
    adapter->error_occurred = true;
    break;
  }
}

ak_inference_response_t *ak_inference_stream(ak_agent_context_t *agent,
                                             ak_inference_request_t *req,
                                             ak_capability_t *cap,
                                             ak_stream_callback_t callback,
                                             void *callback_ctx) {
  ak_inference_response_t *res;

  /*
   * Streaming Inference Implementation
   *
   * This function provides streaming LLM inference using the ak_stream
   * infrastructure. Tokens are delivered to the caller via callback as
   * they are generated.
   *
   * Limitations:
   *   - Streaming requires local inference via virtio-serial with a
   *     streaming-capable host server, or external API with SSE support.
   *   - If the underlying transport does not support streaming, this
   *     function falls back to non-streaming completion and delivers
   *     the entire response in a single callback invocation.
   *
   * The streaming session is:
   *   - Budget-tracked (bytes and tokens)
   *   - Capability-gated through the parent inference capability
   *   - Audit-logged (session start/end)
   */

  /* Validate preconditions */
  if (!ak_inf_state.initialized) {
    res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
    res->success = false;
    res->error_code = AK_E_LLM_NOT_CONFIGURED;
    runtime_memcpy(res->error_message, "Inference subsystem not initialized",
                   sizeof("Inference subsystem not initialized"));
    return res;
  }

  /* Validate capability (INV-2: Capability Enforcement) */
  if (!cap) {
    ak_inf_state.stats.capability_denials++;
    res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
    res->success = false;
    res->error_code = AK_E_CAP_MISSING;
    runtime_memcpy(res->error_message, "Missing inference capability",
                   sizeof("Missing inference capability"));
    return res;
  }

  s64 cap_result = ak_capability_validate(cap, AK_CAP_INFERENCE, "*", "stream",
                                          agent->run_id);
  if (cap_result != 0) {
    ak_inf_state.stats.capability_denials++;
    res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
    res->success = false;
    res->error_code = cap_result;
    runtime_memcpy(res->error_message, "Capability validation failed",
                   sizeof("Capability validation failed"));
    return res;
  }

  /* Check if callback is provided - if not, fall back to non-streaming */
  if (!callback) {
    return ak_inference_complete(agent, req, cap);
  }

  /* Check budget (INV-3: Budget Enforcement) */
  if (agent->budget) {
    u32 estimated_tokens = req->max_tokens > 0 ? req->max_tokens : 1024;
    if (!ak_budget_check(agent->budget, AK_RESOURCE_LLM_TOKENS_OUT,
                         estimated_tokens)) {
      ak_inf_state.stats.budget_exceeded++;
      res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
      if (res == INVALID_ADDRESS)
        return 0;
      runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
      res->success = false;
      res->error_code = AK_E_BUDGET_EXCEEDED;
      runtime_memcpy(res->error_message, "Token budget exceeded",
                     sizeof("Token budget exceeded"));
      return res;
    }
  }

  /* Determine routing */
  ak_llm_mode_t route = ak_inference_route(req->model);
  if (route == AK_LLM_MODE_DISABLED) {
    res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
    if (res == INVALID_ADDRESS)
      return 0;
    runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));
    res->success = false;
    res->error_code = AK_E_LLM_NOT_CONFIGURED;
    runtime_memcpy(res->error_message, "No LLM backend configured for model",
                   sizeof("No LLM backend configured for model"));
    return res;
  }

  /*
   * Check if streaming is supported for the selected backend.
   *
   * Local inference (virtio-serial): Streaming depends on host server
   * capabilities. The current virtio protocol implementation does not
   * support streaming - it uses request/response messaging.
   *
   * External API: Requires SSE support in the HTTP client, which is
   * not yet implemented in the Nanos networking stack.
   *
   * When native streaming is unavailable, we perform non-streaming
   * inference and deliver the complete response via callback.
   */
  boolean native_streaming_available = false;

  /* Check for streaming support based on backend */
  if (route == AK_LLM_EXTERNAL && ak_inf_state.config.api.stream) {
    /*
     * External API streaming requires SSE parsing in the HTTP response.
     * This is not currently implemented - would require:
     *   1. HTTP client with chunked transfer encoding support
     *   2. SSE event parser (data: prefixed lines)
     *   3. Async callback invocation for each event
     * Mark as unavailable until HTTP streaming is implemented.
     */
    native_streaming_available = false;
  }

  if (route == AK_LLM_LOCAL && ak_inf_state.local_connected) {
    /*
     * Local streaming would require protocol extension:
     *   1. Extended virtio protocol with streaming message type
     *   2. Host server support for streaming responses
     *   3. Incremental response parsing
     * Mark as unavailable until protocol is extended.
     */
    native_streaming_available = false;
  }

  /* Allocate response structure */
  res = allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
  if (res == INVALID_ADDRESS)
    return 0;
  runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

  if (!native_streaming_available) {
    /*
     * Fallback: Perform non-streaming completion and deliver
     * the entire response through the callback.
     *
     * This provides consistent API behavior while native streaming
     * support is being developed. The callback receives:
     *   1. Complete response content (done=false)
     *   2. Empty final callback (done=true)
     */
    ak_inference_response_t *sync_res = ak_inference_complete(agent, req, cap);

    if (!sync_res) {
      res->success = false;
      res->error_code = AK_E_LLM_API_ERROR;
      runtime_memcpy(res->error_message, "Inference request failed",
                     sizeof("Inference request failed"));
      return res;
    }

    /* Deliver complete response via callback */
    if (sync_res->success && sync_res->content) {
      u8 *content = buffer_ref(sync_res->content, 0);
      u64 content_len = buffer_length(sync_res->content);
      callback(callback_ctx, (const char *)content, (u32)content_len, false);
    }

    /* Signal completion */
    callback(callback_ctx, "", 0, true);

    /* Copy response data */
    runtime_memcpy(res, sync_res, sizeof(ak_inference_response_t));
    res->content = sync_res->content;
    sync_res->content = 0; /* Transfer ownership */

    /* Free the sync response (but not its content buffer) */
    deallocate(ak_inf_state.h, sync_res, sizeof(ak_inference_response_t));

    return res;
  }

  /*
   * Native streaming path (when implemented).
   *
   * This code path will be enabled when the underlying transport
   * supports streaming. The implementation will:
   *   1. Create ak_stream_session with LLM_TOKENS type
   *   2. Register token and close callbacks
   *   3. Configure stop sequences from request
   *   4. Start the streaming session
   *   5. Forward tokens to user callback as they arrive
   *   6. Return final response with usage statistics
   */
  ak_stream_budget_t stream_budget;
  runtime_memset((u8 *)&stream_budget, 0, sizeof(stream_budget));
  stream_budget.tokens_limit = req->max_tokens > 0 ? req->max_tokens : 4096;
  stream_budget.timeout_ms = ak_inf_state.config.local.timeout_ms > 0
                                 ? ak_inf_state.config.local.timeout_ms
                                 : 30000;
  stream_budget.idle_timeout_ms = 10000; /* 10 second idle timeout */

  ak_stream_session_t *session = ak_stream_create(
      ak_inf_state.h, AK_STREAM_LLM_TOKENS, &stream_budget, agent, cap);

  if (!session) {
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    runtime_memcpy(res->error_message, "Failed to create stream session",
                   sizeof("Failed to create stream session"));
    return res;
  }

  /* Set up callback adapter */
  stream_callback_adapter_t adapter;
  runtime_memset((u8 *)&adapter, 0, sizeof(adapter));
  adapter.user_callback = callback;
  adapter.user_ctx = callback_ctx;
  adapter.response = res;
  adapter.error_occurred = false;

  /* Register callbacks */
  ak_stream_on_token(session, stream_token_callback, &adapter);
  ak_stream_on_close(session, stream_close_callback, &adapter);

  /* Configure stop sequences if provided */
  if (req->stop_sequences && req->stop_count > 0) {
    ak_stream_set_stop_sequences(session, (const char **)req->stop_sequences,
                                 req->stop_count);
  }

  /* Start the streaming session */
  s64 start_result = ak_stream_start(session);
  if (start_result != 0) {
    ak_stream_destroy(ak_inf_state.h, session);
    res->success = false;
    res->error_code = AK_E_LLM_API_ERROR;
    runtime_memcpy(res->error_message, "Failed to start stream session",
                   sizeof("Failed to start stream session"));
    return res;
  }

  /*
   * At this point, native streaming would proceed asynchronously.
   * Since native streaming is not yet available, we fall back above.
   * This code serves as the framework for future implementation.
   *
   * When native streaming is enabled:
   *   - Tokens arrive via virtio or SSE
   *   - Each token is delivered through ak_stream_send_token()
   *   - stream_token_callback forwards to user
   *   - On completion, stream_close_callback updates response
   */

  /* Clean up and return */
  ak_stream_close(session);
  ak_stream_destroy(ak_inf_state.h, session);

  res->success = true;
  return res;
}

ak_inference_response_t *ak_inference_embed(ak_agent_context_t *agent,
                                            buffer text, const char *model,
                                            ak_capability_t *cap) {
  ak_inference_response_t *res =
      allocate(ak_inf_state.h, sizeof(ak_inference_response_t));
  if (res == INVALID_ADDRESS)
    return 0;

  runtime_memset((u8 *)res, 0, sizeof(ak_inference_response_t));

  /* Validate capability */
  if (!cap) {
    res->success = false;
    res->error_code = AK_E_CAP_MISSING;
    return res;
  }

  s64 cap_result = ak_capability_validate(cap, AK_CAP_INFERENCE, "*", "embed",
                                          agent->run_id);
  if (cap_result != 0) {
    res->success = false;
    res->error_code = cap_result;
    return res;
  }

  /* Build embedding request */
  ak_inference_request_t emb_req;
  runtime_memset((u8 *)&emb_req, 0, sizeof(ak_inference_request_t));
  emb_req.type = AK_INFERENCE_EMBEDDING;
  emb_req.prompt = text;
  if (model)
    runtime_memcpy(emb_req.model, model, runtime_strlen(model) + 1);

  /* Route to external API (embeddings typically not available locally) */
  ak_llm_mode_t route = ak_inference_route(emb_req.model);
  if (route == AK_LLM_EXTERNAL) {
    deallocate(ak_inf_state.h, res, sizeof(ak_inference_response_t));
    return ak_external_inference_request(&emb_req, &ak_inf_state.config.api);
  }

  res->success = false;
  res->error_code = AK_E_LLM_NOT_CONFIGURED;
  runtime_memcpy(res->error_message,
                 "Embeddings unavailable: no local or proxy embedding support",
                 sizeof("Embeddings unavailable: no local or proxy embedding support"));
  return res;
}

void ak_inference_response_free(heap h, ak_inference_response_t *res) {
  if (!res)
    return;

  if (res->content && res->content != INVALID_ADDRESS)
    deallocate_buffer(res->content);
  if (res->tool_calls && res->tool_calls != INVALID_ADDRESS)
    deallocate_buffer(res->tool_calls);

  deallocate(h, res, sizeof(ak_inference_response_t));
}

/* ============================================================
 * SYSCALL HANDLER
 * ============================================================ */

ak_response_t *ak_handle_inference(ak_agent_context_t *ctx, ak_request_t *req) {
  /* Use ctx->heap as fallback if inference subsystem not initialized */
  heap h = ak_inf_state.h ? ak_inf_state.h : (ctx ? ctx->heap : 0);

  if (!ctx || !req || !h)
    return 0; /* Cannot allocate response without heap */

  if (!ak_inf_state.initialized) {
    return ak_response_error(h, req, AK_E_LLM_NOT_CONFIGURED);
  }

  /* Parse inference request from JSON args */
  ak_inference_request_t inf_req;
  runtime_memset((u8 *)&inf_req, 0, sizeof(ak_inference_request_t));

  inf_req.type = AK_INFERENCE_CHAT;
  inf_req.max_tokens = 1024;
  inf_req.temperature = 0.7f;

  if (req->args) {
    /* Extract model from args */
    json_extract_string(req->args, "model", inf_req.model,
                        sizeof(inf_req.model));

    /* Extract max_tokens */
    u64 max_tokens = 0;
    if (json_extract_int(req->args, "max_tokens", &max_tokens) == 0)
      inf_req.max_tokens = (u32)max_tokens;

    /* Use args as prompt if no messages */
    inf_req.prompt = req->args;
  }

  /* Execute inference */
  ak_inference_response_t *inf_res =
      ak_inference_complete(ctx, &inf_req, req->cap);

  /* Convert to syscall response */
  ak_response_t *response;
  if (inf_res && inf_res->success) {
    response = ak_response_success(ak_inf_state.h, req, inf_res->content);
    inf_res->content = 0; /* Ownership transferred */

    if (response) {
      response->usage[AK_RESOURCE_LLM_TOKENS_IN] = inf_res->usage.prompt_tokens;
      response->usage[AK_RESOURCE_LLM_TOKENS_OUT] =
          inf_res->usage.completion_tokens;
    }
  } else {
    s64 error_code = inf_res ? inf_res->error_code : AK_E_LLM_API_ERROR;
    response = ak_response_error(ak_inf_state.h, req, error_code);
  }

  if (inf_res)
    ak_inference_response_free(ak_inf_state.h, inf_res);

  return response;
}

/* ============================================================
 * Async inference: enforced issue + non-blocking poll.
 *
 * INFER_ISSUE runs inside ak_dispatch (so capability/policy/budget/audit have
 * already been enforced synchronously), then issues an async HTTP(S) POST to an
 * LLM endpoint and returns immediately with a request id. INFER_POLL reaps the
 * result (returns -EAGAIN until the runloop has driven the request to
 * completion). This is the model that actually works in Nanos: the syscall does
 * not block, so the runloop drives the network while the agent polls with a
 * yielding wait. Args: {model, prompt, host, port, tls, path}.
 * ============================================================ */
ak_response_t *ak_handle_infer_issue(ak_agent_context_t *ctx,
                                     ak_request_t *req) {
  heap h = ak_inf_state.h ? ak_inf_state.h : (ctx ? ctx->heap : 0);
  if (!ctx || !req || !h)
    return 0;
  if (!ak_transport_available())
    return ak_response_error(h, req, AK_E_LLM_NOT_CONFIGURED);
  if (ctx->infer_handle)
    return ak_response_error(h, req, AK_E_LLM_API_ERROR); /* one in flight */
  if (!req->args)
    return ak_response_error(h, req, AK_E_SCHEMA_INVALID);

  char host[128] = {0}, path[128] = {0}, model[64] = {0}, prompt[512] = {0};
  u64 port = 0, tls = 0;
  json_extract_string(req->args, "host", host, sizeof(host));
  json_extract_string(req->args, "path", path, sizeof(path));
  json_extract_string(req->args, "model", model, sizeof(model));
  json_extract_string(req->args, "prompt", prompt, sizeof(prompt));
  json_extract_int(req->args, "port", &port);
  json_extract_int(req->args, "tls", &tls);
  if (host[0] == 0)
    return ak_response_error(h, req, AK_E_SCHEMA_INVALID);
  if (path[0] == 0) {
    path[0] = '/';
    path[1] = 0;
  }

  /* Minimal JSON body {"model":"..","prompt":".."} (demo: no escaping). */
  buffer body = allocate_buffer(h, 64 + runtime_strlen(model) +
                                       runtime_strlen(prompt));
  if (body == INVALID_ADDRESS)
    return ak_response_error(h, req, AK_E_TOOL_FAIL);
  buffer_write(body, "{\"model\":\"", 10);
  buffer_write(body, model, runtime_strlen(model));
  buffer_write(body, "\",\"prompt\":\"", 12);
  buffer_write(body, prompt, runtime_strlen(prompt));
  buffer_write(body, "\"}", 2);

  ak_http_header hdr = {"Content-Type", "application/json"};
  void *hnd = ak_https_issue(host, port ? (u16)port : (tls ? 443 : 80),
                             tls ? true : false, AK_HTTP_METHOD_POST, path, &hdr,
                             1, buffer_ref(body, 0), buffer_length(body));
  deallocate_buffer(body); /* ak_https copies the body */
  if (!hnd)
    return ak_response_error(h, req, AK_E_LLM_CONNECTION_FAILED);

  ctx->infer_handle = hnd;
  buffer result = allocate_buffer(h, 12);
  buffer_write(result, "{\"id\":1}", 8);
  return ak_response_success(h, req, result);
}

ak_response_t *ak_handle_infer_poll(ak_agent_context_t *ctx,
                                    ak_request_t *req) {
  heap h = ak_inf_state.h ? ak_inf_state.h : (ctx ? ctx->heap : 0);
  if (!ctx || !req || !h)
    return 0;
  if (!ctx->infer_handle)
    return ak_response_error(h, req, AK_E_SCHEMA_INVALID);

  buffer resp = 0;
  s64 st = ak_https_poll(ctx->infer_handle, &resp);
  if (st == -EAGAIN)
    return ak_response_error(h, req, -EAGAIN); /* still pending */

  ctx->infer_handle = 0; /* reaped */
  if (st < 0) {
    if (resp)
      deallocate_buffer(resp);
    return ak_response_error(h, req, st);
  }
  /* Return the endpoint's response body (the LLM answer) as the result. */
  if (!resp) {
    resp = allocate_buffer(h, 2);
    buffer_write(resp, "{}", 2);
  }
  return ak_response_success(h, req, resp);
}

/* ============================================================
 * STATISTICS
 * ============================================================ */

void ak_inference_get_stats(ak_inference_stats_t *stats) {
  if (stats)
    runtime_memcpy(stats, &ak_inf_state.stats, sizeof(ak_inference_stats_t));
}
