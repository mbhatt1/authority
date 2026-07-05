/*
 * Authority Kernel - HTTPS Transport klib
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * This klib bridges the kernel-side agentic HTTPS hook (ak_transport.h)
 * to the real in-kernel HTTP client (net_http_req) and TLS engine
 * (tls_connect). It exists because those symbols live in klibs and the
 * kernel cannot call them directly: the klib registers a thunk into the
 * kernel's transport hook at load time.
 *
 * At init() it calls ak_transport_register_https(ak_https_do). Thereafter
 * ak_https_request() in the kernel drives real HTTPS through this thunk.
 *
 * The kernel symbols this klib depends on (ak_transport_register_https,
 * ak_https_complete_ok/_fail) are resolved by the klib loader against the
 * kernel symbol table. tls_connect (used indirectly via net_http_req,
 * compiled into this klib from net_utils.c) is resolved against the tls
 * klib's exported symbols; if the tls klib has not loaded yet, the klib
 * loader retries this klib once its dependency is available.
 *
 * NOTE: this file can only be RUNTIME-verified on hardware/QEMU (it needs
 * a live network stack + tls klib). It is written to compile and to be
 * architecturally correct against the net_utils/azure klib patterns.
 */

#include <kernel.h>
#include <lwip.h>
#include <tls.h>

#include "net_utils.h"

/* Kernel-side transport interface (resolved -Isrc/agentic via CFLAGS). */
#include "ak_transport.h"

#define AK_HTTPS_MAX_HDRS 8

/*
 * Per-request context. Heap-allocated so it survives the async lifetime
 * of the request (the kernel caller blocks in a spin-wait, but the
 * request completes on the network/timer path). Freed in the response
 * handler after exactly one completion.
 */
typedef struct ak_https_ctx {
    heap h;
    void *completion;                       /* opaque kernel latch handle */
    tuple req;                              /* request tuple (url + headers) */
    buffer url;                             /* path; referenced by req */
    buffer hdr_vals[AK_HTTPS_MAX_HDRS];     /* header value buffers */
    u32 hdr_count;
    char host[256];                         /* owned copy of host (sstring stability) */
    closure_struct(value_handler, vh);
} *ak_https_ctx;

static heap ak_https_heap;

/* Local NUL-terminated string length (runtime_strlen lives in the agentic
 * kernel headers, which this klib does not include). */
static u64 ak_cstrlen(const char *s)
{
    u64 n = 0;
    while (s[n] != '\0')
        n++;
    return n;
}

static void ak_https_ctx_free(ak_https_ctx ctx)
{
    if (ctx->req)
        deallocate_value(ctx->req);
    if (ctx->url)
        deallocate_buffer(ctx->url);
    for (u32 i = 0; i < ctx->hdr_count; i++)
        if (ctx->hdr_vals[i])
            deallocate_buffer(ctx->hdr_vals[i]);
    deallocate(ctx->h, ctx, sizeof(*ctx));
}

/*
 * Response handler. net_http_req invokes this exactly once: with the
 * parsed response value on success, or with 0 on failure/teardown.
 */
closure_func_basic(value_handler, void, ak_https_vh,
                   value v)
{
    ak_https_ctx ctx = struct_from_closure(ak_https_ctx, vh);
    void *completion = ctx->completion;

    if (!v) {
        ak_https_complete_fail(completion, AK_HTTPS_FAIL_CONNECT);
        ak_https_ctx_free(ctx);
        return;
    }

    /* Status code lives at index 1 of the start_line vector. */
    u64 code = 0;
    value start_line = get(v, sym(start_line));
    if (start_line) {
        buffer code_b = get(start_line, integer_key(1));
        if (code_b)
            parse_int(code_b, 10, &code);
    }

    buffer content = get(v, sym(content));
    if (content && (buffer_length(content) > 0))
        ak_https_complete_ok(completion, (s64)code,
                             buffer_ref(content, 0), buffer_length(content));
    else
        ak_https_complete_ok(completion, (s64)code, 0, 0);

    ak_https_ctx_free(ctx);
}

/* Map the kernel-side method enum to the klib http_method enum. */
static http_method ak_https_map_method(ak_http_method m)
{
    switch (m) {
    case AK_HTTP_METHOD_GET:     return HTTP_REQUEST_METHOD_GET;
    case AK_HTTP_METHOD_HEAD:    return HTTP_REQUEST_METHOD_HEAD;
    case AK_HTTP_METHOD_POST:    return HTTP_REQUEST_METHOD_POST;
    case AK_HTTP_METHOD_PUT:     return HTTP_REQUEST_METHOD_PUT;
    case AK_HTTP_METHOD_DELETE:  return HTTP_REQUEST_METHOD_DELETE;
    case AK_HTTP_METHOD_TRACE:   return HTTP_REQUEST_METHOD_TRACE;
    case AK_HTTP_METHOD_OPTIONS: return HTTP_REQUEST_METHOD_OPTIONS;
    case AK_HTTP_METHOD_CONNECT: return HTTP_REQUEST_METHOD_CONNECT;
    case AK_HTTP_METHOD_PATCH:   return HTTP_REQUEST_METHOD_PATCH;
    default:                     return HTTP_REQUEST_METHOD_GET;
    }
}

/*
 * Transport thunk registered into the kernel hook.
 *
 * Returns 0 when the request was issued (the completion latch will be
 * signalled asynchronously by ak_https_vh), or a negative AK_HTTPS_FAIL_*
 * sentinel on immediate failure (no completion will be signalled).
 */
static s64 ak_https_do(const ak_https_req *r)
{
    heap h = ak_https_heap;
    if (!h)
        return AK_HTTPS_FAIL_INTERNAL;
    if (!r->host || !r->path)
        return AK_HTTPS_FAIL_INTERNAL;

    u64 host_len = ak_cstrlen(r->host);
    if (host_len == 0 || host_len >= sizeof(((ak_https_ctx)0)->host))
        return AK_HTTPS_FAIL_INTERNAL;

    ak_https_ctx ctx = allocate(h, sizeof(*ctx));
    if (ctx == INVALID_ADDRESS)
        return AK_HTTPS_FAIL_INTERNAL;
    ctx->h = h;
    ctx->completion = r->completion;
    ctx->req = 0;
    ctx->url = 0;
    ctx->hdr_count = 0;
    runtime_memcpy(ctx->host, r->host, host_len);
    ctx->host[host_len] = '\0';

    /* Build the request tuple: url attribute + one entry per header. */
    tuple req = allocate_tuple();
    if (req == INVALID_ADDRESS) {
        deallocate(h, ctx, sizeof(*ctx));
        return AK_HTTPS_FAIL_INTERNAL;
    }
    ctx->req = req;

    u64 path_len = ak_cstrlen(r->path);
    buffer url = allocate_buffer(h, path_len ? path_len : 1);
    if (url == INVALID_ADDRESS) {
        ak_https_ctx_free(ctx);
        return AK_HTTPS_FAIL_INTERNAL;
    }
    buffer_write(url, r->path, path_len);
    ctx->url = url;
    set(req, sym_this("url"), url);

    if (r->headers && (r->header_count > 0)) {
        u32 n = r->header_count;
        if (n > AK_HTTPS_MAX_HDRS)
            n = AK_HTTPS_MAX_HDRS;
        for (u32 i = 0; i < n; i++) {
            const char *name = r->headers[i].name;
            const char *val = r->headers[i].value;
            if (!name || !val)
                continue;
            u64 nlen = ak_cstrlen(name);
            u64 vlen = ak_cstrlen(val);
            buffer vb = allocate_buffer(h, vlen ? vlen : 1);
            if (vb == INVALID_ADDRESS) {
                ak_https_ctx_free(ctx);
                return AK_HTTPS_FAIL_INTERNAL;
            }
            buffer_write(vb, val, vlen);
            ctx->hdr_vals[ctx->hdr_count++] = vb;
            symbol s = intern(alloca_wrap_buffer((void *)name, nlen));
            set(req, s, vb);
        }
    }

    /* Request body: net_http_req takes ownership of this buffer. */
    buffer body = 0;
    if (r->body && (r->body_len > 0)) {
        body = allocate_buffer(h, r->body_len);
        if (body == INVALID_ADDRESS) {
            ak_https_ctx_free(ctx);
            return AK_HTTPS_FAIL_INTERNAL;
        }
        buffer_write(body, r->body, r->body_len);
    }

    struct net_http_req_params params;
    params.host = isstring(ctx->host, host_len);
    params.port = r->port;
    params.tls = r->tls;
    params.method = ak_https_map_method(r->method);
    params.req = req;
    params.body = body;
    params.resp_handler = init_closure_func(&ctx->vh, value_handler, ak_https_vh);

    status s = net_http_req(&params);
    if (!is_ok(s)) {
        /* net_http_req did not take ownership of body/resp_handler on the
         * synchronous error path, and will not call our handler. Clean up
         * everything ourselves. */
        timm_dealloc(s);
        if (body)
            deallocate_buffer(body);
        ak_https_ctx_free(ctx);
        return AK_HTTPS_FAIL_CONNECT;
    }

    /* Issued: ownership of body + ctx (freed in ak_https_vh) transferred. */
    return 0;
}

int init(status_handler complete)
{
    ak_https_heap = heap_locked(get_kernel_heaps());
    ak_transport_register_https(ak_https_do);
    return KLIB_INIT_OK;
}
