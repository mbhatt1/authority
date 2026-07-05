/*
 * Authority Kernel - Network Enforcement
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Enforces network access control at the socket syscall layer.
 * Intercepts connect(), send(), recv() to apply:
 *   - Capability-based destination filtering (INV-2)
 *   - Outbound DLP (secret redaction)
 *   - Budget tracking for network bytes (INV-3)
 *
 * SECURITY: This module implements INV-1 for network operations.
 * All network access MUST pass through these checks.
 *
 * SECURITY MODEL (see ak_net_enforce.c for full details):
 *   - No network policy configured on the current context (no network
 *     rules table and no AK_CAP_NET root capability - note the root
 *     context is created lazily for every Nanos process): operations
 *     are ALLOWED and the data plane is not filtered (single-tenant
 *     unikernel; AK policy governs configured agent runs, not plain
 *     workloads).
 *   - Network policy configured: FAIL-CLOSED. connect/bind/accept/DNS
 *     are allowed only via an explicit ALLOW rule or a matching
 *     AK_CAP_NET root capability; otherwise denied with -EACCES.
 *     Sends are budget-checked and DLP-scanned; receives are tracked.
 *
 * NOTE: These checks are invoked from src/net/netsyscall.c only when
 * the kernel is built with CONFIG_AGENTIC defined (see the platform
 * Makefiles). Without CONFIG_AGENTIC, socket-layer enforcement is
 * compiled out.
 */

#ifndef AK_NET_ENFORCE_H
#define AK_NET_ENFORCE_H

#include "ak_types.h"

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize network enforcement subsystem.
 * Called during ak_init().
 */
void ak_net_init(heap h);

/* ============================================================
 * CONNECTION CONTROL (INV-2 enforcement)
 * ============================================================ */

/*
 * Check if outbound connection is allowed.
 *
 * Called from connect() syscall before establishing connection.
 * Checks agent's network capabilities against destination.
 *
 * @param host      Destination hostname or IP (null-terminated)
 * @param port      Destination port
 * @param is_ipv6   Whether this is an IPv6 address
 *
 * @return 0 if allowed, negative error code if denied:
 *         -EACCES: No capability for this destination
 *         -EPERM:  Policy explicitly denies
 *
 * SECURITY: Fails-closed. Unknown hosts are denied.
 */
s64 ak_net_check_connect(const char *host, u16 port, boolean is_ipv6);

/*
 * Check if binding to a port is allowed.
 *
 * Called from bind() syscall.
 *
 * @param port      Port to bind
 * @param is_ipv6   Whether this is IPv6
 *
 * @return 0 if allowed, -EACCES if denied
 *
 * SECURITY: Fails-closed for agent contexts. The wildcard local
 * address ("0.0.0.0" / "::") plus port must match an ALLOW rule or
 * the root capability.
 */
s64 ak_net_check_bind(u16 port, boolean is_ipv6);

/*
 * Check if accepting connections is allowed.
 *
 * Called from accept() syscall.
 *
 * @param client_host   Client IP address (null-terminated); NULL is
 *                      treated as an unknown peer (only a "*" rule
 *                      can admit it)
 * @param client_port   Client port
 *
 * @return 0 if allowed, -EACCES if denied
 *
 * SECURITY: Fails-closed for agent contexts.
 */
s64 ak_net_check_accept(const char *client_host, u16 client_port);

/* ============================================================
 * DATA FILTERING (DLP)
 * ============================================================ */

/*
 * Filter outbound data for secret leakage.
 *
 * Called from send()/sendto()/write() on sockets.
 * Scans for secrets and either redacts or blocks.
 *
 * @param data      Data buffer
 * @param len       Data length
 * @param dest_host Destination host (for logging)
 * @param dest_port Destination port
 *
 * @return 0 if allowed (possibly with redaction applied in-place)
 *         AK_E_DLP_BLOCK if blocked due to sensitive content
 *         AK_E_BUDGET_EXCEEDED if network bytes quota exceeded
 *
 * SECURITY: This is the last line of defense for secret leakage.
 * Uses same patterns as ak_dlp_detect_secrets().
 */
s64 ak_net_filter_send(u8 *data, u64 len, const char *dest_host, u16 dest_port);

/*
 * Track inbound data.
 *
 * Called from recv()/recvfrom()/read() on sockets.
 * Tracks bytes against budget.
 *
 * @param len         Bytes received
 * @param src_host    Source host
 * @param src_port    Source port
 *
 * @return 0 always (inbound not filtered, just tracked)
 */
s64 ak_net_track_recv(u64 len, const char *src_host, u16 src_port);

/* ============================================================
 * DNS FILTERING
 * ============================================================ */

/*
 * Check if DNS resolution is allowed for a domain.
 *
 * Called before DNS lookup.
 *
 * @param domain    Domain name to resolve
 *
 * @return 0 if allowed, -EACCES if denied
 *
 * SECURITY: Prevents DNS exfiltration and unauthorized lookups.
 */
s64 ak_net_check_dns(const char *domain);

/* ============================================================
 * NETWORK RULES CONFIGURATION
 * ============================================================ */

/*
 * Network rule types for ak_net_add_rule()
 */
typedef enum ak_net_rule_type {
  AK_NET_RULE_ALLOW = 1, /* Allow connection */
  AK_NET_RULE_DENY = 2,  /* Deny connection */
} ak_net_rule_type_t;

/*
 * Add network rule for current agent context.
 *
 * @param type      Rule type (allow/deny)
 * @param host      Host pattern ("*" = any, "*.example.com" = suffix)
 * @param port      Port (0 = any)
 *
 * @return 0 on success
 */
s64 ak_net_add_rule(ak_net_rule_type_t type, const char *host, u16 port);

/*
 * Clear all network rules for current agent context.
 */
void ak_net_clear_rules(void);

/* ============================================================
 * AUDIT HELPERS
 * ============================================================ */

/*
 * Log network event to audit log.
 *
 * @param event     Event type ("connect", "send", "recv", "dns")
 * @param host      Host involved
 * @param port      Port involved
 * @param allowed   Whether operation was allowed
 * @param bytes     Bytes transferred (for send/recv)
 */
void ak_net_audit_log(const char *event, const char *host, u16 port,
                      boolean allowed, u64 bytes);

/* ============================================================
 * ADDRESS FORMATTING HELPERS
 * ============================================================ */

/*
 * Format IPv4 address as string.
 *
 * @param ip        32-bit IP address in network byte order
 * @param out       Output buffer (at least 16 bytes)
 */
void ak_net_format_ipv4(u32 ip, char *out);

/*
 * Format IPv6 address as string.
 *
 * @param ip        128-bit IP address
 * @param out       Output buffer (at least 46 bytes)
 */
void ak_net_format_ipv6(const u8 *ip, char *out);

/*
 * Format "host:port" as string.
 *
 * @param host      Host string
 * @param port      Port number
 * @param out       Output buffer (at least 64 bytes)
 */
void ak_net_format_endpoint(const char *host, u16 port, char *out);

#endif /* AK_NET_ENFORCE_H */
