/*
 * Authority Kernel - Network Enforcement Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements network access control at socket syscall layer.
 *
 * ============================================================
 * SECURITY MODEL (read this before changing any check)
 * ============================================================
 *
 * Nanos is a single-tenant unikernel: one application per VM.
 *
 * IMPORTANT: ak_get_root_context() LAZILY CREATES a root context for
 * the (single) Nanos process on first use, with NO capabilities and
 * NO network rules (see ak_get_current_context() in ak_syscall.c).
 * Therefore "context exists" does NOT mean "agent networking policy
 * is in force" - every workload has a context. The enforcement gate
 * is whether a NETWORK POLICY has been configured on that context.
 *
 * 1. NO NETWORK POLICY CONFIGURED (no context at all, or a context
 *    with neither network rules nor an AK_CAP_NET root capability):
 *    The workload is an ordinary (non-agent) process, so network
 *    operations are ALLOWED and the data plane is not filtered or
 *    budget-limited. This is intentional single-tenant behavior: AK
 *    network policy governs configured agent runs, not the base OS
 *    image. If you need to firewall non-agent workloads, do it at
 *    the hypervisor/cloud layer.
 *
 * 2. NETWORK POLICY CONFIGURED (context has a network rules table -
 *    even an empty one - or an AK_CAP_NET root capability):
 *    FAIL-CLOSED. An operation is allowed only if:
 *      - an explicit ALLOW rule matches (first match wins), or
 *      - the root capability is AK_CAP_NET and its resource pattern
 *        matches the "host:port" endpoint.
 *    Anything else - including "rules table present but empty" - is
 *    DENIED. This applies to connect(), bind(), accept() and DNS.
 *
 * 3. DATA PLANE (send/recv), only when a network policy is
 *    configured:
 *    Outbound sends are checked against the NET_BYTES_OUT budget and
 *    scanned for secrets (DLP); either failure blocks the send.
 *    Inbound receives are tracked against budget but never blocked.
 *    If no budget tracker exists on the context, byte accounting is
 *    skipped (budgets are an orthogonal limit, not an allow/deny
 *    gate; the connect() gate above is the access control).
 */

#include "ak_net_enforce.h"
#include "ak_audit.h"
#include "ak_budget.h" /* full ak_budget_tracker_t definition + lock */
#include "ak_capability.h"
#include "ak_sanitize.h"

/* ============================================================
 * INTERNAL STATE
 * ============================================================ */

/* Forward declaration - implemented in ak_syscall.c */
extern ak_agent_context_t *ak_get_root_context(void);

/* Network rule entry */
typedef struct ak_net_rule {
  struct ak_net_rule *next;
  ak_net_rule_type_t type;
  char host[256]; /* Host pattern */
  u16 port;       /* 0 = any port */
} ak_net_rule_t;

/* Default deny all state */
static boolean ak_net_default_deny = true;

/* Global heap for allocations */
static heap ak_net_heap = NULL;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_net_init(heap h) {
  ak_net_heap = h;
  ak_net_default_deny = true;
}

/* ============================================================
 * PATTERN MATCHING
 * ============================================================ */

/*
 * Match host against pattern.
 * Patterns:
 *   "*"           - Match anything
 *   "*.foo.com"   - Suffix match
 *   "foo.com"     - Exact match
 */
static boolean ak_net_host_match(const char *pattern, const char *host) {
  if (!pattern || !host)
    return false;

  /* Wildcard matches everything */
  if (pattern[0] == '*' && pattern[1] == '\0')
    return true;

  /* Suffix match: *.example.com */
  if (pattern[0] == '*' && pattern[1] == '.') {
    const char *suffix = pattern + 1; /* ".example.com" */
    u64 suffix_len = runtime_strlen(suffix);
    u64 host_len = runtime_strlen(host);

    if (host_len < suffix_len)
      return false;

    /* Check if host ends with suffix */
    return runtime_memcmp(host + host_len - suffix_len, suffix, suffix_len) ==
           0;
  }

  /* Exact match */
  return ak_strcmp(pattern, host) == 0;
}

/*
 * Does this context have a network policy configured?
 *
 * True if the context has a network rules table (even an empty one)
 * or an AK_CAP_NET root capability. Only then does fail-closed
 * enforcement apply; otherwise the workload is treated as a plain
 * (non-agent) process. See SECURITY MODEL at the top of this file.
 */
static boolean ak_net_policy_active(ak_agent_context_t *ctx) {
  if (!ctx)
    return false;
  if (ctx->network_rules)
    return true;
  if (ctx->root_cap && ctx->root_cap->type == AK_CAP_NET)
    return true;
  return false;
}

/*
 * Check host:port against rules for a context WITH an active network
 * policy (caller must have checked ak_net_policy_active()).
 *
 * FAIL-CLOSED: returns true only on an explicit ALLOW rule match
 * (first match wins) or a matching AK_CAP_NET root capability.
 * No match - including "rules table present but empty" - means deny.
 */
static boolean ak_net_check_rules(ak_agent_context_t *ctx, const char *host,
                                  u16 port) {
  if (!ctx)
    return false; /* Defensive: callers must pass an active context */

  /* Walk rule list - first match wins (explicit DENY rules honored) */
  if (ctx->network_rules) {
    ak_net_rule_t *rule = (ak_net_rule_t *)table_find(ctx->network_rules, 0);
    while (rule) {
      /* Check port match (0 = any) */
      if (rule->port != 0 && rule->port != port) {
        rule = rule->next;
        continue;
      }

      /* Check host match */
      if (ak_net_host_match(rule->host, host)) {
        return (rule->type == AK_NET_RULE_ALLOW);
      }

      rule = rule->next;
    }
  }

  /* No rule matched - fall back to the root AK_CAP_NET capability,
   * whose resource is a pattern matched against "host:port". */
  if (ctx->root_cap && ctx->root_cap->type == AK_CAP_NET) {
    char endpoint[320];
    ak_net_format_endpoint(host, port, endpoint);
    if (ak_pattern_match((const char *)ctx->root_cap->resource, endpoint))
      return true;
  }

  /* Nothing allowed it: deny (fail-closed; see SECURITY MODEL above).
   * ak_net_default_deny is always true; it exists so the policy is
   * explicit at initialization time. */
  return !ak_net_default_deny;
}

/* ============================================================
 * CONNECTION CONTROL
 * ============================================================ */

s64 ak_net_check_connect(const char *host, u16 port, boolean is_ipv6) {
  (void)is_ipv6; /* Currently unused */

  if (!host)
    return -EINVAL;

  /* Get current agent context */
  ak_agent_context_t *ctx = ak_get_root_context();
  if (!ak_net_policy_active(ctx)) {
    /* No network policy configured: non-agent workload, allow.
     * (Single-tenant behavior; see SECURITY MODEL at top of file.) */
    return 0;
  }

  /* Network policy configured: FAIL-CLOSED rule/capability check */
  boolean allowed = ak_net_check_rules(ctx, host, port);

  /* Audit log the attempt */
  ak_net_audit_log("connect", host, port, allowed, 0);

  if (!allowed) {
    return -EACCES;
  }

  return 0;
}

s64 ak_net_check_bind(u16 port, boolean is_ipv6) {
  ak_agent_context_t *ctx = ak_get_root_context();
  if (!ak_net_policy_active(ctx)) {
    /* No network policy configured: non-agent workload, allow.
     * (Single-tenant behavior; see SECURITY MODEL at top of file.) */
    return 0;
  }

  /* Network policy configured: FAIL-CLOSED. Binding (listening) is allowed
   * only if a rule or the root capability permits the wildcard local
   * address for this port. A rule with host "*" (any port or matching
   * port) permits serving; otherwise the bind is denied. */
  const char *bind_host = is_ipv6 ? "::" : "0.0.0.0";
  boolean allowed = ak_net_check_rules(ctx, bind_host, port);

  ak_net_audit_log("bind", bind_host, port, allowed, 0);

  if (!allowed) {
    return -EACCES;
  }

  return 0;
}

s64 ak_net_check_accept(const char *client_host, u16 client_port) {
  ak_agent_context_t *ctx = ak_get_root_context();
  if (!ak_net_policy_active(ctx)) {
    /* No network policy configured: non-agent workload, allow.
     * (Single-tenant behavior; see SECURITY MODEL at top of file.) */
    return 0;
  }

  /* Network policy configured: FAIL-CLOSED. The inbound peer must match an
   * ALLOW rule or the root capability. An unknown peer address can
   * only be admitted by a wildcard ("*") rule. */
  if (!client_host)
    client_host = "unknown";
  boolean allowed = ak_net_check_rules(ctx, client_host, client_port);

  ak_net_audit_log("accept", client_host, client_port, allowed, 0);

  if (!allowed) {
    return -EACCES;
  }

  return 0;
}

/* ============================================================
 * DATA FILTERING (DLP)
 * ============================================================ */

s64 ak_net_filter_send(u8 *data, u64 len, const char *dest_host,
                       u16 dest_port) {
  ak_agent_context_t *ctx = ak_get_root_context();
  if (!ak_net_policy_active(ctx)) {
    /* No network policy configured: non-agent workload, no filtering.
     * Budget limits and DLP scanning apply only to configured agent
     * runs; otherwise every plain app would hit the default
     * NET_BYTES_OUT budget and DLP false positives (e.g. an app
     * legitimately sending its own bearer tokens).
     * (Single-tenant behavior; see SECURITY MODEL at top of file.) */
    return 0;
  }

  /* Check-and-consume NET_BYTES_OUT budget atomically (the tracker
   * lock is the same one ak_budget.c uses for admission control). */
  if (ctx->budget) {
    ak_budget_tracker_t *tracker = ctx->budget;
    spin_lock(&tracker->lock);
    u64 used = tracker->budget.used[AK_RESOURCE_NET_BYTES_OUT];
    u64 limit = tracker->budget.limits[AK_RESOURCE_NET_BYTES_OUT];
    if (limit > 0 && used + len > limit) {
      spin_unlock(&tracker->lock);
      ak_net_audit_log("send_blocked", dest_host, dest_port, false, len);
      return AK_E_BUDGET_EXCEEDED;
    }
    tracker->budget.used[AK_RESOURCE_NET_BYTES_OUT] += len;
    spin_unlock(&tracker->lock);
  }

  /* DLP: scan outbound bytes for secrets. The stack-allocated wrapper
   * avoids any heap dependency, so scanning is always active for agent
   * contexts (no fail-open when ak_net_init() has not run). */
  if (data && len > 0) {
    buffer scan_buf = ak_wrap_buffer(data, len);
    u32 detected = ak_dlp_detect_secrets(scan_buf, AK_DLP_PATTERN_ALL);
    if (detected) {
      /* Secrets detected - block the send */
      ak_net_audit_log("send_dlp_block", dest_host, dest_port, false, len);
      return AK_E_DLP_BLOCK;
    }
  }

  /* Audit the send */
  ak_net_audit_log("send", dest_host, dest_port, true, len);

  return 0;
}

s64 ak_net_track_recv(u64 len, const char *src_host, u16 src_port) {
  ak_agent_context_t *ctx = ak_get_root_context();
  if (!ak_net_policy_active(ctx)) {
    /* No network policy configured: nothing to track (see SECURITY
     * MODEL at top of file). */
    return 0;
  }

  /* Track bytes against budget (but don't block inbound) */
  if (ctx->budget) {
    ak_budget_tracker_t *tracker = ctx->budget;
    spin_lock(&tracker->lock);
    tracker->budget.used[AK_RESOURCE_NETWORK_BYTES] += len;
    spin_unlock(&tracker->lock);
  }

  /* Audit the receive */
  ak_net_audit_log("recv", src_host, src_port, true, len);

  return 0;
}

/* ============================================================
 * DNS FILTERING
 * ============================================================ */

s64 ak_net_check_dns(const char *domain) {
  if (!domain)
    return -EINVAL;

  ak_agent_context_t *ctx = ak_get_root_context();
  if (!ak_net_policy_active(ctx)) {
    /* No network policy configured: non-agent workload, allow.
     * (Single-tenant behavior; see SECURITY MODEL at top of file.) */
    return 0;
  }

  /* Network policy configured: FAIL-CLOSED. The domain must match an
   * ALLOW rule or the root capability (checked against the domain
   * itself, with port 0 = any). */
  boolean allowed = ak_net_check_rules(ctx, domain, 0);

  ak_net_audit_log("dns", domain, 53, allowed, 0);

  if (!allowed) {
    return -EACCES;
  }

  /* NOTE: the POSIX routing layer (ak_posix_route.c) is not part of
   * the kernel build, so no additional routing-layer DNS check is
   * performed here. If ak_posix_route.c is ever added to the compiled
   * set, its ak_route_dns_resolve() can be consulted here as well. */

  return 0;
}

/* ============================================================
 * RULE MANAGEMENT
 * ============================================================ */

s64 ak_net_add_rule(ak_net_rule_type_t type, const char *host, u16 port) {
  if (!host)
    return -EINVAL;

  ak_agent_context_t *ctx = ak_get_root_context();
  if (!ctx)
    return -EINVAL;

  /* Prefer the heap given to ak_net_init(); fall back to the context
   * heap so rules can be installed even if init has not run. */
  heap h = ak_net_heap ? ak_net_heap : ctx->heap;
  if (!h)
    return -EINVAL;

  /* Allocate rule */
  ak_net_rule_t *rule = allocate(h, sizeof(ak_net_rule_t));
  if (!rule || rule == INVALID_ADDRESS)
    return -ENOMEM;

  rule->type = type;
  rule->port = port;
  runtime_memset((u8 *)rule->host, 0, sizeof(rule->host));

  u64 len = runtime_strlen(host);
  if (len >= sizeof(rule->host))
    len = sizeof(rule->host) - 1;
  runtime_memcpy(rule->host, host, len);

  /* Initialize rules table if needed */
  if (!ctx->network_rules) {
    ctx->network_rules = allocate_table(h, identity_key, pointer_equal);
    if (!ctx->network_rules || ctx->network_rules == INVALID_ADDRESS) {
      ctx->network_rules = NULL;
      deallocate(h, rule, sizeof(ak_net_rule_t));
      return -ENOMEM;
    }
  }

  /* Add to front of list (table stores head pointer at key 0) */
  rule->next = (ak_net_rule_t *)table_find(ctx->network_rules, 0);
  table_set(ctx->network_rules, 0, rule);

  return 0;
}

void ak_net_clear_rules(void) {
  ak_agent_context_t *ctx = ak_get_root_context();
  if (!ctx || !ctx->network_rules)
    return;

  /* Use the same heap-selection logic as ak_net_add_rule() so rules
   * are returned to the heap they came from. */
  heap h = ak_net_heap ? ak_net_heap : ctx->heap;
  if (!h)
    return;

  /* Free all rules */
  ak_net_rule_t *rule = (ak_net_rule_t *)table_find(ctx->network_rules, 0);
  while (rule) {
    ak_net_rule_t *next = rule->next;
    deallocate(h, rule, sizeof(ak_net_rule_t));
    rule = next;
  }

  table_set(ctx->network_rules, 0, NULL);
}

/* ============================================================
 * AUDIT LOGGING
 * ============================================================ */

/*
 * Network operation codes for audit ring buffer.
 * These are internal codes (not syscalls) for network enforcement events.
 * Range 0x8000+ to distinguish from AK_SYS_* syscall numbers.
 */
#define AK_NET_OP_CONNECT 0x8001
#define AK_NET_OP_BIND 0x8002
#define AK_NET_OP_ACCEPT 0x8003
#define AK_NET_OP_SEND 0x8004
#define AK_NET_OP_RECV 0x8005
#define AK_NET_OP_DNS 0x8006
#define AK_NET_OP_SEND_BLOCKED 0x8007
#define AK_NET_OP_DLP_BLOCK 0x8008

/*
 * Map event string to operation code.
 */
static u16 ak_net_event_to_op(const char *event) {
  if (!event)
    return 0;

  /* Use first character for fast dispatch, then verify */
  switch (event[0]) {
  case 'c':
    if (ak_strcmp(event, "connect") == 0)
      return AK_NET_OP_CONNECT;
    break;
  case 'b':
    if (ak_strcmp(event, "bind") == 0)
      return AK_NET_OP_BIND;
    break;
  case 'a':
    if (ak_strcmp(event, "accept") == 0)
      return AK_NET_OP_ACCEPT;
    break;
  case 's':
    if (ak_strcmp(event, "send") == 0)
      return AK_NET_OP_SEND;
    if (ak_strcmp(event, "send_blocked") == 0)
      return AK_NET_OP_SEND_BLOCKED;
    if (ak_strcmp(event, "send_dlp_block") == 0)
      return AK_NET_OP_DLP_BLOCK;
    break;
  case 'r':
    if (ak_strcmp(event, "recv") == 0)
      return AK_NET_OP_RECV;
    break;
  case 'd':
    if (ak_strcmp(event, "dns") == 0)
      return AK_NET_OP_DNS;
    break;
  }
  return 0;
}

/*
 * Compute a simple hash of the network event parameters.
 * This provides a fingerprint for correlation in the audit log.
 * Uses FNV-1a hash for simplicity and speed.
 */
static void ak_net_compute_event_hash(const char *event, const char *host,
                                      u16 port, u64 bytes, u8 *hash_out) {
  /* FNV-1a 256-bit approximation using multiple 64-bit accumulators */
  u64 h0 = 0xcbf29ce484222325ULL;
  u64 h1 = 0xcbf29ce484222325ULL;
  u64 h2 = 0xcbf29ce484222325ULL;
  u64 h3 = 0xcbf29ce484222325ULL;
  const u64 prime = 0x100000001b3ULL;

  /* Hash event type */
  if (event) {
    const char *p = event;
    while (*p) {
      h0 ^= (u8)*p++;
      h0 *= prime;
    }
  }

  /* Hash host */
  if (host) {
    const char *p = host;
    while (*p) {
      h1 ^= (u8)*p++;
      h1 *= prime;
    }
  }

  /* Hash port */
  h2 ^= (port & 0xFF);
  h2 *= prime;
  h2 ^= (port >> 8);
  h2 *= prime;

  /* Hash bytes */
  for (int i = 0; i < 8; i++) {
    h3 ^= (bytes >> (i * 8)) & 0xFF;
    h3 *= prime;
  }

  /* Pack into 32-byte hash output */
  runtime_memset(hash_out, 0, AK_HASH_SIZE);
  u64 *out = (u64 *)hash_out;
  out[0] = h0;
  out[1] = h1;
  out[2] = h2;
  out[3] = h3;
}

void ak_net_audit_log(const char *event, const char *host, u16 port,
                      boolean allowed, u64 bytes) {
  ak_agent_context_t *ctx = ak_get_root_context();
  u8 *pid = NULL;
  u8 *run_id = NULL;
  u8 req_hash[AK_HASH_SIZE];
  u8 res_hash[AK_HASH_SIZE];
  u8 flags = 0;
  s64 result_code = 0;

  /* Extract agent identity if available */
  if (ctx) {
    pid = ctx->pid;
    run_id = ctx->run_id;
  }

  /* Map event to operation code */
  u16 op = ak_net_event_to_op(event);
  if (op == 0) {
    /* Unknown event type - still log but mark as error */
    op = AK_NET_OP_CONNECT; /* Default fallback */
    flags |= AK_RING_FLAG_ERROR;
  }

  /* Set flags based on decision */
  if (!allowed) {
    flags |= AK_RING_FLAG_DENIED;
    result_code = -EACCES;
  }

  /* Compute hashes for audit trail */
  ak_net_compute_event_hash(event, host, port, bytes, req_hash);

  /* Response hash encodes the decision and bytes transferred */
  runtime_memset(res_hash, 0, AK_HASH_SIZE);
  res_hash[0] = allowed ? 1 : 0;
  /* Encode bytes in response hash for data plane events */
  if (bytes > 0) {
    u64 *bytes_ptr = (u64 *)&res_hash[8];
    *bytes_ptr = bytes;
  }
  /* Encode port for correlation */
  res_hash[16] = port & 0xFF;
  res_hash[17] = (port >> 8) & 0xFF;

  /*
   * Push to ring buffer for high-frequency data plane events.
   * This is non-blocking and will not fail the network operation
   * even if the ring buffer is full (it will overwrite oldest entries).
   *
   * The ring buffer is appropriate here because:
   * 1. Network events can be very high frequency
   * 2. We don't want audit logging to block data plane operations
   * 3. Ring buffer provides bounded memory usage
   * 4. Events can be drained asynchronously for persistent storage
   */
  ak_ring_push(pid, run_id, op, req_hash, res_hash, result_code,
               0, /* latency_us - not tracked for network events */
               flags);

  /*
   * Note: We intentionally do not call ak_audit_append() here because:
   * 1. Network data plane events are too high-frequency for synchronous logging
   * 2. ak_audit_append() requires fsync which would block network I/O
   * 3. The ring buffer provides sufficient audit trail for most use cases
   *
   * For critical control plane decisions (e.g., connection denials),
   * an external component can drain the ring buffer and persist
   * important events to the hash-chained audit log.
   */
}

/* ============================================================
 * ADDRESS FORMATTING
 * ============================================================ */

void ak_net_format_ipv4(u32 ip, char *out) {
  /* IP is in network byte order */
  u8 *bytes = (u8 *)&ip;

  /* Format as "a.b.c.d" */
  int pos = 0;
  for (int i = 0; i < 4; i++) {
    u8 b = bytes[i];
    if (b >= 100) {
      out[pos++] = '0' + (b / 100);
      b %= 100;
      out[pos++] = '0' + (b / 10);
      out[pos++] = '0' + (b % 10);
    } else if (b >= 10) {
      out[pos++] = '0' + (b / 10);
      out[pos++] = '0' + (b % 10);
    } else {
      out[pos++] = '0' + b;
    }
    if (i < 3)
      out[pos++] = '.';
  }
  out[pos] = '\0';
}

void ak_net_format_ipv6(const u8 *ip, char *out) {
  /* Simplified IPv6 formatting - full form only */
  static const char hex[] = "0123456789abcdef";
  int pos = 0;

  for (int i = 0; i < 16; i += 2) {
    out[pos++] = hex[(ip[i] >> 4) & 0xf];
    out[pos++] = hex[ip[i] & 0xf];
    out[pos++] = hex[(ip[i + 1] >> 4) & 0xf];
    out[pos++] = hex[ip[i + 1] & 0xf];
    if (i < 14)
      out[pos++] = ':';
  }
  out[pos] = '\0';
}

void ak_net_format_endpoint(const char *host, u16 port, char *out) {
  int pos = 0;

  /* Copy host */
  while (*host && pos < 300) {
    out[pos++] = *host++;
  }

  /* Add port */
  out[pos++] = ':';

  /* Format port number */
  if (port >= 10000) {
    out[pos++] = '0' + (port / 10000);
    port %= 10000;
    out[pos++] = '0' + (port / 1000);
    port %= 1000;
    out[pos++] = '0' + (port / 100);
    port %= 100;
    out[pos++] = '0' + (port / 10);
    out[pos++] = '0' + (port % 10);
  } else if (port >= 1000) {
    out[pos++] = '0' + (port / 1000);
    port %= 1000;
    out[pos++] = '0' + (port / 100);
    port %= 100;
    out[pos++] = '0' + (port / 10);
    out[pos++] = '0' + (port % 10);
  } else if (port >= 100) {
    out[pos++] = '0' + (port / 100);
    port %= 100;
    out[pos++] = '0' + (port / 10);
    out[pos++] = '0' + (port % 10);
  } else if (port >= 10) {
    out[pos++] = '0' + (port / 10);
    out[pos++] = '0' + (port % 10);
  } else {
    out[pos++] = '0' + port;
  }

  out[pos] = '\0';
}
