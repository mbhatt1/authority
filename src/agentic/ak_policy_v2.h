/*
 * Authority Kernel - Policy V2 (Deny-by-Default)
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * OWNER: Agent B (Policy + Bootstrap)
 *
 * This file implements the P0 deny-by-default policy engine for the
 * Authority Kernel migration. It provides:
 *   - JSON-based policy loading
 *   - Fail-closed semantics (missing policy = deny all)
 *   - Pattern matching for FS/NET/DNS/Tool/WASM/Infer rules
 *   - Budget enforcement
 *   - Suggested snippet generation for denied effects
 *
 * Load Order (DENY-BY-DEFAULT):
 *   1. Check embedded policy (CONFIG_AK_EMBEDDED_POLICY)
 *   2. Check initrd /ak/policy.json
 *   3. If no policy: fail closed with clear message
 *
 * SECURITY: All policy checks fail-closed on ambiguity.
 * No effect is allowed unless explicitly permitted by policy.
 */

#ifndef AK_POLICY_V2_H
#define AK_POLICY_V2_H

#include "ak_effects.h"
#include "ak_types.h"

/* ============================================================
 * POLICY VERSION AND CONSTANTS
 * ============================================================ */

#define AK_POLICY_V2_VERSION "1.0"
#define AK_POLICY_V2_PATH "/ak/policy.json"
#define AK_POLICY_V2_MAX_RULES 256
#define AK_POLICY_V2_MAX_PATTERN 256
#define AK_POLICY_V2_MAX_PROFILES 16
#define AK_POLICY_V2_MAX_HOSTCALLS 32

/* ============================================================
 * FILESYSTEM RULES
 * ============================================================
 * Pattern matching for filesystem access control.
 * Supports glob patterns (*, **) for path matching.
 */

typedef struct ak_fs_rule_v2 {
  char pattern[AK_POLICY_V2_MAX_PATTERN]; /* Glob path pattern with * and
                                           * ** wildcards */
  boolean read;                           /* Allow read access */
  boolean write;                          /* Allow write access */
  struct ak_fs_rule_v2 *next;
} ak_fs_rule_v2_t;

/* ============================================================
 * NETWORK RULES
 * ============================================================
 * Pattern matching for network connect/bind/listen.
 * Format: "dns:host:port" or "ip:addr:port" or "ip:addr/cidr:port"
 */

typedef struct ak_net_rule_v2 {
  char pattern[AK_POLICY_V2_MAX_PATTERN]; /* "dns:*.example.com:*" */
  boolean connect;                        /* Allow outbound connect */
  boolean bind;                           /* Allow local bind */
  boolean listen;                         /* Allow listen */
  struct ak_net_rule_v2 *next;
} ak_net_rule_v2_t;

/* ============================================================
 * DNS RULES (P0 REQUIRED)
 * ============================================================
 * Separate gating for DNS resolution.
 * DNS resolution MUST be separately authorized from connect.
 */

typedef struct ak_dns_rule_v2 {
  char
      pattern[AK_POLICY_V2_MAX_PATTERN]; /* "*.example.com", "api.github.com" */
  boolean allow;
  struct ak_dns_rule_v2 *next;
} ak_dns_rule_v2_t;

/* ============================================================
 * TOOL RULES
 * ============================================================
 * Allow/deny patterns for tool execution.
 */

typedef struct ak_tool_rule_v2 {
  char pattern[64]; /* "http_*", "file_read" */
  boolean allow;    /* true = allow, false = deny */
  struct ak_tool_rule_v2 *next;
} ak_tool_rule_v2_t;

/* ============================================================
 * WASM RULES
 * ============================================================
 * Module and hostcall whitelisting for WASM execution.
 */

typedef struct ak_wasm_rule_v2 {
  char module_pattern[64]; /* Module name pattern */
  char *allowed_hostcalls[AK_POLICY_V2_MAX_HOSTCALLS];
  u32 hostcall_count;
  struct ak_wasm_rule_v2 *next;
} ak_wasm_rule_v2_t;

/* ============================================================
 * INFERENCE RULES
 * ============================================================
 * Model patterns and token limits for LLM inference.
 */

typedef struct ak_infer_rule_v2 {
  char model_pattern[64]; /* "gpt-4", "claude-*" */
  u64 max_tokens;         /* Token limit for this model */
  struct ak_infer_rule_v2 *next;
} ak_infer_rule_v2_t;

/* ============================================================
 * PROCESS SPAWN RULES
 * ============================================================
 * Pattern matching for process spawning with capability inheritance.
 * Controls which programs can be spawned and with what restrictions.
 */

typedef struct ak_spawn_rule_v2 {
  char pattern[AK_POLICY_V2_MAX_PATTERN]; /* Program path glob pattern,
                                           * e.g. everything under /usr/bin */
  boolean allow;                          /* Allow spawn */
  boolean inherit_caps;                   /* Child inherits caps */
  boolean inherit_policy;                 /* Child inherits policy */
  boolean sandboxed;                      /* Spawn in sandbox */
  u32 max_children; /* Max concurrent children (0=unlimited) */
  u64 max_wall_ms;  /* Max wall time for child */
  struct ak_spawn_rule_v2 *next;
} ak_spawn_rule_v2_t;

/* ============================================================
 * BUDGET CONFIGURATION
 * ============================================================
 * Resource limits for the policy.
 */

typedef struct ak_budgets_v2 {
  u64 cpu_ns;     /* CPU time limit (nanoseconds) */
  u64 wall_ns;    /* Wall time limit (nanoseconds) */
  u64 bytes;      /* Total byte budget */
  u64 tokens;     /* LLM token budget */
  u64 tool_calls; /* Max tool invocations */
} ak_budgets_v2_t;

/* ============================================================
 * POLICY V2 STRUCTURE
 * ============================================================
 * The main policy structure containing all rules and budgets.
 */

typedef struct ak_policy_v2 {
  /* Memory allocator */
  heap h;

  /* Identity and versioning */
  char version[16];             /* Policy format version */
  u8 policy_hash[AK_HASH_SIZE]; /* SHA-256 of policy content */
  u64 loaded_ns;                /* Load timestamp (monotonic) */

  /*
   * Integrity: HMAC-SHA256 authentication tag (symmetric - anyone with
   * the key can forge; this is NOT an Ed25519 digital signature).
   * Parsed from the top-level "signature" member (64 hex chars).
   * The tag covers SHA-256 of the document with the signature value
   * emptied ("signature":"").
   */
  u8 signature[AK_MAC_SIZE];  /* HMAC-SHA256 tag */
  boolean has_signature;      /* "signature" was present in document */
  boolean signature_verified; /* Tag verified against configured key */

  /* Filesystem capabilities */
  ak_fs_rule_v2_t *fs_rules;

  /* Network capabilities */
  ak_net_rule_v2_t *net_rules;

  /* DNS capabilities (P0 REQUIRED) */
  ak_dns_rule_v2_t *dns_rules;

  /* Tool capabilities */
  ak_tool_rule_v2_t *tool_rules;

  /* WASM capabilities */
  ak_wasm_rule_v2_t *wasm_rules;

  /* Inference capabilities */
  ak_infer_rule_v2_t *infer_rules;

  /* Process spawn capabilities */
  ak_spawn_rule_v2_t *spawn_rules;

  /* Resource budgets */
  ak_budgets_v2_t budgets;

  /* Profile includes (P0: simple string list) */
  char *included_profiles[AK_POLICY_V2_MAX_PROFILES];
  u32 profile_count;

  /* Load state */
  boolean loaded;      /* true if policy loaded successfully */
  boolean fail_closed; /* true if in fail-closed state */

} ak_policy_v2_t;

/* ============================================================
 * POLICY LOAD RESULT
 * ============================================================ */

typedef enum ak_policy_v2_result {
  AK_POLICY_V2_OK = 0,
  AK_POLICY_V2_ERR_NO_POLICY = -1, /* No policy found */
  AK_POLICY_V2_ERR_PARSE = -2,     /* JSON parse error */
  AK_POLICY_V2_ERR_INVALID = -3,   /* Invalid policy structure */
  AK_POLICY_V2_ERR_VERSION = -4,   /* Unsupported version */
  AK_POLICY_V2_ERR_ALLOC = -5,     /* Memory allocation failed */
  AK_POLICY_V2_ERR_IO = -6,        /* I/O error reading policy */
} ak_policy_v2_result_t;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

/*
 * Initialize the policy V2 subsystem.
 *
 * Must be called before any other policy V2 functions.
 * Sets up global state and prepares for policy loading.
 */
void ak_policy_v2_init(heap h);

/*
 * Shutdown the policy V2 subsystem.
 *
 * Releases all resources and destroys any loaded policies.
 */
void ak_policy_v2_shutdown(void);

/* ============================================================
 * POLICY LOADING
 * ============================================================ */

/*
 * Configure the HMAC-SHA256 policy verification key (AK_KEY_SIZE bytes).
 *
 * Once set, ak_policy_v2_load() rejects any policy whose HMAC tag does
 * not verify (including unsigned policies).  Pass NULL to clear the key
 * (subsequent loads accept policies but flag them unsigned).
 *
 * NOTE: symmetric authentication (HMAC-SHA256), not an Ed25519 signature.
 */
void ak_policy_v2_set_verification_key(const u8 *key);

/*
 * Load policy from JSON buffer.
 *
 * SECURITY (fail-closed):
 *   - If a verification key is configured, unsigned or wrongly-tagged
 *     policies are REJECTED (NULL).
 *   - If no key is configured, the policy is accepted but
 *     signature_verified stays false (never treated as verified).
 *
 * Parses the P0 JSON policy format:
 * {
 *   "version": "1.0",
 *   "signature": "<64 hex chars, optional HMAC-SHA256 tag>",
 *   "fs": { "read": [...], "write": [...] },
 *   "net": { "dns": [...], "connect": [...] },
 *   "tools": { "allow": [...], "deny": [...] },
 *   "wasm": { "modules": [...], "hostcalls": [...] },
 *   "infer": { "models": [...], "max_tokens": N },
 *   "budgets": { ... },
 *   "profiles": [...]
 * }
 *
 * @param h     Heap for allocations
 * @param json  JSON buffer (null-terminated not required)
 * @param len   Length of JSON buffer
 * @return      Loaded policy, or NULL on error
 */
ak_policy_v2_t *ak_policy_v2_load(heap h, const u8 *json, u64 len);

/*
 * Load policy from runtime buffer (Team Contract compatible).
 *
 * Wrapper for ak_policy_v2_load() that accepts a buffer type.
 *
 * @param h     Heap for allocations
 * @param json  JSON buffer
 * @return      Loaded policy, or NULL on error
 */
ak_policy_v2_t *ak_policy_v2_load_buffer(heap h, buffer json);

/*
 * Load policy from file path.
 *
 * Reads the file and calls ak_policy_v2_load().
 *
 * @param h     Heap for allocations
 * @param path  Path to policy JSON file
 * @return      Loaded policy, or NULL on error
 */
ak_policy_v2_t *ak_policy_v2_load_file(heap h, const char *path);

/*
 * Bootstrap policy loading.
 *
 * Implements the deny-by-default load order:
 *   1. Check embedded policy (CONFIG_AK_EMBEDDED_POLICY)
 *   2. Check initrd /ak/policy.json
 *   3. If no policy: fail closed
 *
 * @param h     Heap for allocations
 * @return      Loaded policy, or fail-closed policy if none found
 */
ak_policy_v2_t *ak_policy_v2_bootstrap(heap h);

/*
 * Destroy a policy and free all resources.
 *
 * @param policy  Policy to destroy
 */
void ak_policy_v2_destroy(ak_policy_v2_t *policy);

/* ============================================================
 * POLICY CHECKING
 * ============================================================ */

/*
 * Check if an effect is allowed by the policy.
 *
 * This is the main authorization function for P0.
 * Returns true and populates decision_out on success.
 * Returns false and populates decision_out with denial info on deny.
 *
 * @param policy        Policy to check against
 * @param req           Effect request to authorize
 * @param decision_out  Authorization decision (always populated)
 * @return              true if allowed, false if denied
 */
boolean ak_policy_v2_check(ak_policy_v2_t *policy, const ak_effect_req_t *req,
                           ak_decision_t *decision_out);

/*
 * Check filesystem access.
 *
 * @param policy    Policy to check
 * @param path      Canonical absolute path
 * @param write     true for write, false for read
 * @return          true if allowed
 */
boolean ak_policy_v2_check_fs(ak_policy_v2_t *policy, const char *path,
                              boolean write);

/*
 * Check network connect.
 *
 * @param policy    Policy to check
 * @param target    Canonical target: "ip:addr:port" or "dns:host:port"
 * @return          true if allowed
 */
boolean ak_policy_v2_check_net_connect(ak_policy_v2_t *policy,
                                       const char *target);

/*
 * Check DNS resolution.
 *
 * @param policy    Policy to check
 * @param hostname  Domain to resolve
 * @return          true if allowed
 */
boolean ak_policy_v2_check_dns(ak_policy_v2_t *policy, const char *hostname);

/*
 * Check tool execution.
 *
 * @param policy    Policy to check
 * @param tool_name Tool name
 * @return          true if allowed
 */
boolean ak_policy_v2_check_tool(ak_policy_v2_t *policy, const char *tool_name);

/*
 * Check WASM module invocation.
 *
 * @param policy    Policy to check
 * @param module    Module name
 * @param hostcall  Hostcall name (NULL to check module only)
 * @return          true if allowed
 */
boolean ak_policy_v2_check_wasm(ak_policy_v2_t *policy, const char *module,
                                const char *hostcall);

/*
 * Check LLM inference.
 *
 * @param policy        Policy to check
 * @param model         Model name
 * @param tokens        Requested tokens
 * @param max_out       If non-NULL, receives max allowed tokens
 * @return              true if allowed
 */
boolean ak_policy_v2_check_infer(ak_policy_v2_t *policy, const char *model,
                                 u64 tokens, u64 *max_out);

/*
 * Check budget limits.
 *
 * @param policy    Policy to check
 * @param req       Effect request with budget fields
 * @return          true if within budget
 */
boolean ak_policy_v2_check_budget(ak_policy_v2_t *policy,
                                  const ak_effect_req_t *req);

/*
 * Check process spawn.
 *
 * @param policy    Policy to check
 * @param program   Program path to spawn
 * @return          true if allowed
 */
boolean ak_policy_v2_check_spawn(ak_policy_v2_t *policy, const char *program);

/*
 * Get spawn rule details for a program.
 *
 * Returns the matching spawn rule (if any) for additional restrictions.
 *
 * @param policy    Policy to check
 * @param program   Program path
 * @return          Matching rule or NULL if no explicit rule
 */
const ak_spawn_rule_v2_t *ak_policy_v2_get_spawn_rule(ak_policy_v2_t *policy,
                                                      const char *program);

/* ============================================================
 * SUGGESTION GENERATION
 * ============================================================ */

/*
 * Generate a suggested policy snippet for a denied effect.
 *
 * The snippet can be copy-pasted into ak.toml to allow the effect.
 * This is a key UX feature for deny-by-default.
 *
 * @param req       The denied effect request
 * @param snippet   Buffer to receive snippet (must be AK_MAX_SUGGEST bytes)
 * @param max_len   Size of snippet buffer
 */
void ak_policy_v2_suggest(const ak_effect_req_t *req, char *snippet,
                          u32 max_len);

/*
 * Get the missing capability string for a denied effect.
 *
 * Returns strings like "fs.read", "net.connect", "tool.http_get".
 *
 * @param req       The denied effect request
 * @param cap       Buffer to receive capability string
 * @param max_len   Size of cap buffer
 */
void ak_policy_v2_get_missing_cap(const ak_effect_req_t *req, char *cap,
                                  u32 max_len);

/* ============================================================
 * POLICY INSPECTION
 * ============================================================ */

/*
 * Get policy hash.
 *
 * @param policy    Policy to inspect
 * @param hash_out  Buffer to receive hash (AK_HASH_SIZE bytes)
 */
void ak_policy_v2_get_hash(ak_policy_v2_t *policy, u8 *hash_out);

/*
 * Check if policy is in fail-closed state.
 *
 * @param policy    Policy to check
 * @return          true if fail-closed (no policy loaded)
 */
boolean ak_policy_v2_is_fail_closed(ak_policy_v2_t *policy);

/*
 * Get policy load timestamp.
 *
 * @param policy    Policy to inspect
 * @return          Monotonic timestamp when policy was loaded
 */
u64 ak_policy_v2_get_loaded_ns(ak_policy_v2_t *policy);

/* ============================================================
 * PATTERN MATCHING UTILITIES
 * ============================================================ */

/*
 * Match path against glob pattern.
 *
 * Supports:
 *   * - matches any characters within a path segment
 *   ** - matches any characters including /
 *
 * @param pattern   Glob pattern
 * @param path      Path to match
 * @return          true if matches
 */
boolean ak_policy_v2_match_path(const char *pattern, const char *path);

/*
 * Match network target against pattern.
 *
 * Formats:
 *   - "dns:*.example.com:443"
 *   - "ip:10.0.0.0/8:*"
 *   - "ip:1.2.3.4:443"
 *
 * @param pattern   Network pattern
 * @param target    Network target
 * @return          true if matches
 */
boolean ak_policy_v2_match_net(const char *pattern, const char *target);

/*
 * Match DNS domain against pattern.
 *
 * Supports wildcard: *.example.com matches sub.example.com
 *
 * @param pattern   Domain pattern
 * @param domain    Domain to match
 * @return          true if matches
 */
boolean ak_policy_v2_match_dns(const char *pattern, const char *domain);

/* ============================================================
 * BUILT-IN PROFILES
 * ============================================================ */

/* Tier 1 profile: Static/musl minimal access */
extern const char *AK_PROFILE_TIER1_MUSL;

/* Tier 2 profile: Dynamic/glibc with library access */
extern const char *AK_PROFILE_TIER2_GLIBC;

/*
 * Expand a profile into the policy.
 *
 * @param policy        Policy to expand into
 * @param profile_name  Name of profile to expand
 * @return              0 on success, negative on error
 */
int ak_policy_v2_expand_profile(ak_policy_v2_t *policy,
                                const char *profile_name);

#endif /* AK_POLICY_V2_H */
