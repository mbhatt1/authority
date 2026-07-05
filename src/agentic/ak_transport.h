/*
 * Authority Kernel - In-Kernel HTTPS Transport Hook
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * PURPOSE
 *   Provides a SYNCHRONOUS in-kernel HTTPS request primitive for the
 *   agentic subsystem (LLM gateway, WASM tool HTTP) that is backed by
 *   the kernel's real TLS/HTTP stack.
 *
 * LINKAGE PROBLEM THIS SOLVES
 *   The real HTTP client (net_http_req) and the TLS engine (tls_connect)
 *   live in KLIBS. The klib loader resolves KERNEL symbols FOR klibs
 *   (klib -> kernel), never the reverse, so kernel-compiled agentic code
 *   cannot call net_http_req directly.
 *
 *   The fix is an inversion-of-control hook that lives in the KERNEL:
 *     - the kernel exposes a registration function
 *       (ak_transport_register_https) and a synchronous entry point
 *       (ak_https_request);
 *     - a klib (see klib/ak_https.c) that CAN see net_http_req/tls_connect
 *       registers a net_http_req-backed thunk into this hook at load time.
 *
 *   Until a klib registers, ak_https_request() FAILS CLOSED with
 *   AK_E_NOT_IMPLEMENTED - it never fabricates a response.
 *
 * ASYNC -> SYNC BRIDGE
 *   net_http_req is async/callback-based; the agentic host functions are
 *   synchronous. ak_https_request() builds an opaque completion latch,
 *   hands it to the registered transport, and spin-waits (kern_pause() +
 *   memory_barrier(), bounded timeout) until the klib's response handler
 *   signals it via ak_https_complete_ok()/ak_https_complete_fail(). This
 *   mirrors the spin-wait durability pattern in ak_audit.c / ak_state.c.
 *
 * DEPENDENCY DISCIPLINE
 *   This header is deliberately klib-header-free: it references only
 *   runtime.h primitives. The klib adapts its own klib-only types
 *   (net_http_req_params, http_method, tuple, value_handler) to this
 *   interface when it registers - the kernel stays free of klib deps.
 */

#ifndef AK_TRANSPORT_H
#define AK_TRANSPORT_H

#include <runtime.h>

/*
 * HTTP method codes.
 *
 * INVARIANT: these values MUST match the http_method enum in
 * src/http/http.h. The klib adapter passes them straight through to
 * net_http_req_params.method; a mismatch would issue the wrong verb.
 */
typedef enum ak_http_method {
    AK_HTTP_METHOD_GET = 0,
    AK_HTTP_METHOD_HEAD = 1,
    AK_HTTP_METHOD_POST = 2,
    AK_HTTP_METHOD_PUT = 3,
    AK_HTTP_METHOD_DELETE = 4,
    AK_HTTP_METHOD_TRACE = 5,
    AK_HTTP_METHOD_OPTIONS = 6,
    AK_HTTP_METHOD_CONNECT = 7,
    AK_HTTP_METHOD_PATCH = 8,
} ak_http_method;

/*
 * A single request header. Both fields are NUL-terminated C strings owned
 * by the caller for the duration of the (synchronous) ak_https_request()
 * call; the klib copies whatever it needs before returning control.
 */
typedef struct ak_http_header {
    const char *name;   /* e.g. "Authorization" */
    const char *value;  /* e.g. "Bearer sk-..."  */
} ak_http_header;

/*
 * Request descriptor handed from the kernel to the registered klib
 * transport. Uses only runtime types - no klib/http headers.
 *
 * All pointers reference caller-owned memory that remains valid until the
 * transport function returns (the klib copies anything it needs to retain
 * across the async completion). `completion` is an opaque latch handle
 * that the klib passes back to ak_https_complete_ok()/_fail().
 */
typedef struct ak_https_req {
    const char *host;               /* NUL-terminated host, e.g. "api.openai.com" */
    u16 port;                       /* usually 443 */
    boolean tls;                    /* true for HTTPS */
    ak_http_method method;
    const char *path;               /* NUL-terminated path, e.g. "/v1/chat/completions" */
    const ak_http_header *headers;  /* array of extra headers (may be 0) */
    u32 header_count;
    const void *body;               /* request body bytes (may be 0) */
    u32 body_len;
    void *completion;               /* opaque: struct ak_https_latch * */
} ak_https_req;

/*
 * Transport callback implemented by the klib.
 *
 * Returns 0 when the request was successfully ISSUED (the completion latch
 * will be signalled asynchronously exactly once), or a negative value on
 * immediate failure (in which case the latch is NOT signalled and the
 * caller stops waiting).
 */
typedef s64 (*ak_https_transport_fn)(const ak_https_req *req);

/* ------------------------------------------------------------------ */
/* Registration (klib -> kernel), called from the klib's init().       */
/* ------------------------------------------------------------------ */

/* Register the net_http_req-backed transport. Idempotent/last-wins. */
void ak_transport_register_https(ak_https_transport_fn fn);

/* True once a transport klib has registered. */
boolean ak_transport_available(void);

/* ------------------------------------------------------------------ */
/* Completion signalling (klib -> kernel), called from the klib's      */
/* response handler exactly once per issued request.                   */
/* ------------------------------------------------------------------ */

/*
 * Signal success. `body`/`body_len` are copied into a fresh buffer owned
 * by the latch; the klib retains ownership of its own storage. `status`
 * is the HTTP status code (e.g. 200).
 */
void ak_https_complete_ok(void *completion, s64 status,
                          const void *body, u32 body_len);

/*
 * Signal failure. `reason` is one of the transport sentinels below (the
 * klib does NOT reference AK_E_* codes); ak_transport maps it to a stable
 * negative return value from ak_https_request().
 */
#define AK_HTTPS_FAIL_CONNECT  (-1) /* DNS / TCP / TLS / HTTP transport error */
#define AK_HTTPS_FAIL_INTERNAL (-2) /* klib-side allocation / logic error */
void ak_https_complete_fail(void *completion, s64 reason);

/* ------------------------------------------------------------------ */
/* Synchronous entry point (called by agentic kernel code).            */
/* ------------------------------------------------------------------ */

/*
 * Perform a blocking HTTPS request.
 *
 * On success returns the HTTP status code (>= 0) and, if resp_out is
 * non-NULL, sets *resp_out to a freshly allocated buffer holding the
 * response body (caller owns it and must deallocate_buffer() it).
 *
 * On failure returns a negative AK_E_* code (from ak_types.h) and leaves
 * *resp_out = 0:
 *   AK_E_NOT_IMPLEMENTED - no transport registered (fail closed)
 *   AK_E_TIMEOUT         - timeout_ms elapsed before completion
 *   AK_E_TOOL_FAIL       - transport could not issue, or the request
 *                          failed at the DNS/TCP/TLS/HTTP layer, or an
 *                          internal allocation failed
 *
 * Callers that need a domain-specific error (e.g. the LLM gateway) should
 * translate any negative return into their own code.
 *
 * Never fabricates a response.
 */
s64 ak_https_request(const char *host, u16 port, boolean tls,
                     ak_http_method method, const char *path,
                     const ak_http_header *headers, u32 header_count,
                     const void *req_body, u32 body_len,
                     buffer *resp_out, u32 timeout_ms);

/* Async request/poll API (works with Nanos's runloop model - see ak_transport.c).
 * ak_https_issue() issues without blocking and returns an opaque handle (or NULL
 * on immediate failure). ak_https_poll() returns -EAGAIN until complete, then the
 * HTTP status (>=0) or error (<0), reaping the handle and setting *resp_out. */
void *ak_https_issue(const char *host, u16 port, boolean tls,
                     ak_http_method method, const char *path,
                     const ak_http_header *headers, u32 header_count,
                     const void *req_body, u32 body_len);
s64 ak_https_poll(void *handle, buffer *resp_out);

#endif /* AK_TRANSPORT_H */
