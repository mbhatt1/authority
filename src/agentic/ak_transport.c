/*
 * Authority Kernel - In-Kernel HTTPS Transport Hook (implementation)
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * See ak_transport.h for the design rationale. This file implements:
 *   - the registration hook (filled by a klib at load time);
 *   - the async->sync completion latch and its signalling functions;
 *   - the synchronous ak_https_request() that spin-waits on the latch,
 *     mirroring the durability spin-wait in ak_audit.c / ak_state.c.
 *
 * The kernel here NEVER calls net_http_req/tls_connect directly (it
 * cannot - those are klib symbols). It only invokes the function pointer
 * a klib registered. With no klib loaded, every request fails closed.
 */

#include <unix_internal.h>

#include "ak_transport.h"
#include "ak_types.h"

/* ============================================================
 * REGISTERED TRANSPORT
 * ============================================================ */

/*
 * The klib-provided transport. Written once at klib load (single-threaded
 * klib init) and read on every request. Declared volatile so readers on
 * other CPUs observe the registration without a lock.
 */
static ak_https_transport_fn volatile ak_https_transport = 0;

void ak_transport_register_https(ak_https_transport_fn fn) {
  ak_https_transport = fn;
  memory_barrier();
}

boolean ak_transport_available(void) {
  return ak_https_transport != 0;
}

/* ============================================================
 * COMPLETION LATCH (async -> sync bridge)
 * ============================================================
 *
 * OWNERSHIP / TEARDOWN RACE
 *   The latch is heap-allocated (not stack) because the async completion
 *   may fire AFTER ak_https_request() gives up on a timeout. Ownership is
 *   handed off under `lock`:
 *     - if the caller is still waiting when completion fires, completion
 *       fills the latch and sets `done`; the caller frees it.
 *     - if the caller already timed out, it sets `abandoned` and leaves
 *       the latch for the completion side to free.
 *   Exactly one side frees the latch, so a late completion never writes
 *   to freed memory.
 */
typedef struct ak_https_latch {
  struct spinlock lock;
  heap h;
  volatile boolean done;    /* completion has filled the latch */
  boolean abandoned;        /* caller gave up (timed out); completion frees */
  s64 status;               /* HTTP status code on success, else < 0 */
  buffer response;          /* response body (caller takes ownership) */
} *ak_https_latch;

static void ak_https_latch_free(ak_https_latch latch) {
  heap h = latch->h;
  if (latch->response)
    deallocate_buffer(latch->response);
  deallocate(h, latch, sizeof(*latch));
}

void ak_https_complete_ok(void *completion, s64 status,
                          const void *body, u32 body_len) {
  ak_https_latch latch = completion;
  if (!latch)
    return;

  /* Copy the body before touching shared state so a failed copy can be
   * reported as a failure rather than a truncated success. */
  buffer b = 0;
  if (body && body_len > 0) {
    b = allocate_buffer(latch->h, body_len);
    if (b == INVALID_ADDRESS)
      b = 0;
    else
      buffer_write(b, body, body_len);
  }

  spin_lock(&latch->lock);
  if (latch->abandoned) {
    /* Caller is gone; we own the latch. */
    spin_unlock(&latch->lock);
    if (b)
      deallocate_buffer(b);
    ak_https_latch_free(latch);
    return;
  }
  if (b) {
    latch->response = b;
    latch->status = status;
  } else if (body && body_len > 0) {
    /* Body existed but could not be copied: report as failure. */
    latch->status = AK_HTTPS_FAIL_INTERNAL;
  } else {
    /* Legitimately empty body. */
    latch->response = 0;
    latch->status = status;
  }
  latch->done = true;
  memory_barrier();
  spin_unlock(&latch->lock);
}

void ak_https_complete_fail(void *completion, s64 reason) {
  ak_https_latch latch = completion;
  if (!latch)
    return;

  spin_lock(&latch->lock);
  if (latch->abandoned) {
    spin_unlock(&latch->lock);
    ak_https_latch_free(latch);
    return;
  }
  latch->status = (reason < 0) ? reason : AK_HTTPS_FAIL_CONNECT;
  latch->response = 0;
  latch->done = true;
  memory_barrier();
  spin_unlock(&latch->lock);
}

/* ============================================================
 * SYNCHRONOUS ENTRY POINT
 * ============================================================ */

/*
 * Bounded spin budget. We avoid the timestamp subsystem (and any float
 * math) and instead bound the wait by a large iteration count derived
 * from timeout_ms. kern_pause() yields the CPU on each iteration so this
 * does not monopolise the core; the exact wall-clock bound is best-effort
 * (the audit/state spin-waits are similarly coarse).
 */
#define AK_HTTPS_SPINS_PER_MS 200000ull
#define AK_HTTPS_MIN_TIMEOUT_MS 1u

s64 ak_https_request(const char *host, u16 port, boolean tls,
                     ak_http_method method, const char *path,
                     const ak_http_header *headers, u32 header_count,
                     const void *req_body, u32 body_len,
                     buffer *resp_out, u32 timeout_ms) {
  if (resp_out)
    *resp_out = 0;

  /* Fail closed when no transport klib has registered. */
  ak_https_transport_fn fn = ak_https_transport;
  if (!fn)
    return AK_E_NOT_IMPLEMENTED;

  if (!host || !path)
    return AK_E_SCHEMA_INVALID;

  heap h = heap_locked(get_kernel_heaps());
  ak_https_latch latch = allocate(h, sizeof(*latch));
  if (latch == INVALID_ADDRESS)
    return AK_E_TOOL_FAIL;

  spin_lock_init(&latch->lock);
  latch->h = h;
  latch->done = false;
  latch->abandoned = false;
  latch->status = 0;
  latch->response = 0;

  struct ak_https_req req;
  req.host = host;
  req.port = port;
  req.tls = tls;
  req.method = method;
  req.path = path;
  req.headers = headers;
  req.header_count = header_count;
  req.body = req_body;
  req.body_len = body_len;
  req.completion = latch;

  s64 issued = fn(&req);
  if (issued < 0) {
    /* Transport rejected the request outright; latch was never signalled
     * and never will be, so we own it. */
    ak_https_latch_free(latch);
    return AK_E_TOOL_FAIL;
  }

  /* Wait for the async completion against a real-time deadline.
   *
   * ARCHITECTURAL LIMITATION (do not "fix" with a busy-loop pump): the
   * completion (net_http_req -> tls/tcp) is driven by deferred work on the
   * runloop's queues, which are NOT serviced while this syscall context is
   * spinning here. Nanos processes the network stack from the runloop, and a
   * syscall context cannot correctly drive it cooperatively (verified: even a
   * guest->host TCP connect times out while DHCP - driven by the real runloop -
   * succeeds). Making external I/O actually complete requires converting this
   * into an ASYNC syscall (blockq_check + a completion that formats the result
   * and wakes the thread) so the syscall yields to the runloop and resumes on
   * completion. Until then this request is issued but times out. The deadline
   * is wall-clock based so the timeout is predictable. */
  u32 ms = timeout_ms ? timeout_ms : AK_HTTPS_MIN_TIMEOUT_MS;
  timestamp deadline = now(CLOCK_ID_MONOTONIC) + milliseconds(ms);
  boolean timed_out = false;
  while (!latch->done) {
    memory_barrier();
    kern_pause();
    if (now(CLOCK_ID_MONOTONIC) >= deadline) {
      timed_out = true;
      break;
    }
  }

  if (timed_out) {
    /* Re-check under the lock: completion may have won the final race. */
    spin_lock(&latch->lock);
    if (!latch->done) {
      latch->abandoned = true;   /* completion side will free the latch */
      spin_unlock(&latch->lock);
      return AK_E_TIMEOUT;
    }
    spin_unlock(&latch->lock);
    /* fallthrough: completion actually finished */
  }

  /* Completion has filled the latch and will not touch it again. */
  memory_barrier();
  s64 status = latch->status;
  buffer resp = latch->response;
  latch->response = 0;   /* transfer ownership before freeing the latch */
  ak_https_latch_free(latch);

  if (status < 0) {
    if (resp)
      deallocate_buffer(resp);
    return AK_E_TOOL_FAIL;
  }

  if (resp_out)
    *resp_out = resp;
  else if (resp)
    deallocate_buffer(resp);
  return status;
}

/* ============================================================
 * Async request/poll API.
 *
 * This is the model that actually works in Nanos: ak_https_issue() issues the
 * request WITHOUT blocking and returns immediately, so the syscall returns and
 * the runloop drives the network stack normally (as it does for DHCP). The
 * caller (agent) then polls ak_https_poll() with a yielding wait (e.g. a short
 * userspace sleep) between polls. The completion fires on the runloop while the
 * caller is not spinning. No in-kernel busy-wait, no cooperative pump.
 * ============================================================ */

/* Issue a request without waiting. Returns an opaque handle on success (which
 * MUST later be reaped with ak_https_poll), or NULL on immediate failure. */
void *ak_https_issue(const char *host, u16 port, boolean tls,
                     ak_http_method method, const char *path,
                     const ak_http_header *headers, u32 header_count,
                     const void *req_body, u32 body_len) {
  ak_https_transport_fn fn = ak_https_transport;
  if (!fn || !host || !path)
    return 0;

  heap h = heap_locked(get_kernel_heaps());
  ak_https_latch latch = allocate(h, sizeof(*latch));
  if (latch == INVALID_ADDRESS)
    return 0;

  spin_lock_init(&latch->lock);
  latch->h = h;
  latch->done = false;
  latch->abandoned = false;
  latch->status = 0;
  latch->response = 0;

  struct ak_https_req req;
  req.host = host;
  req.port = port;
  req.tls = tls;
  req.method = method;
  req.path = path;
  req.headers = headers;
  req.header_count = header_count;
  req.body = req_body;
  req.body_len = body_len;
  req.completion = latch;

  if (fn(&req) < 0) {
    ak_https_latch_free(latch);
    return 0;
  }
  return latch;
}

/* Poll an issued handle. Returns -EAGAIN if not yet complete (handle stays
 * valid for a later poll); otherwise returns the HTTP status (>=0) or an error
 * (<0), REAPS the handle (frees it), and sets *resp_out to the response buffer
 * on success. */
s64 ak_https_poll(void *handle, buffer *resp_out) {
  if (resp_out)
    *resp_out = 0;
  ak_https_latch latch = handle;
  if (!latch)
    return AK_E_SCHEMA_INVALID;

  memory_barrier();
  if (!latch->done)
    return -EAGAIN;

  s64 status = latch->status;
  buffer resp = latch->response;
  latch->response = 0;
  ak_https_latch_free(latch);

  if (status < 0) {
    if (resp)
      deallocate_buffer(resp);
    return status;
  }
  if (resp_out)
    *resp_out = resp;
  else if (resp)
    deallocate_buffer(resp);
  return status;
}
