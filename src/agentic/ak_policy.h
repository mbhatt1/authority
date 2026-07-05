/*
 * Authority Kernel - Policy Engine
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements INV-3: Budget Invariant (admission control)
 * "The sum of in-flight and committed costs never exceeds budget."
 *
 * Policy files define:
 *   - Resource budgets (token limits, call quotas)
 *   - Tool allowlists/denylists
 *   - Domain restrictions
 *   - Taint flow rules
 *
 * SECURITY: Policy is signed and immutable during a run.
 */

#ifndef AK_POLICY_H
#define AK_POLICY_H

#include "ak_types.h"
#include "ak_budget.h"

/* ============================================================
 * POLICY STRUCTURE
 * ============================================================
 *
 * Policy YAML format:
 *
 * version: "1.0"
 * signature: "base64..."
 *
 * budgets:
 *   tokens: 100000
 *   calls: 50
 *   inference_ms: 60000
 *   file_bytes: 10485760
 *
 * tools:
 *   allow:
 *     - "file_read"
 *     - "file_write"
 *     - "http_get"
 *   deny:
 *     - "shell_exec"
 *
 * domains:
 *   allow:
 *     - "*.github.com"
 *     - "api.openai.com"
 *   deny:
 *     - "*.internal"
 *
 * taint:
 *   sources:
 *     - "user_input"
 *     - "network"
 *   sinks:
 *     - "shell_exec"
 *     - "file_write"
 *   sanitizers:
 *     - "html_escape"
 *     - "sql_escape"
 */

/* Policy version */
#define AK_POLICY_VERSION "1.0"

/* Budget types */
typedef struct ak_budget_limits {
  u64 tokens;        /* Max LLM tokens */
  u64 calls;         /* Max tool/API calls */
  u64 inference_ms;  /* Max inference time */
  u64 file_bytes;    /* Max file I/O bytes */
  u64 network_bytes; /* Max network I/O */
  u64 spawn_count;   /* Max child agents */
  u64 heap_objects;  /* Max heap objects */
  u64 heap_bytes;    /* Max heap size */
} ak_budget_limits_t;

/* Tool rule */
typedef struct ak_tool_rule {
  char *name;    /* Tool name/pattern */
  boolean allow; /* true = allow, false = deny */
  struct ak_tool_rule *next;
} ak_tool_rule_t;

/* Domain rule */
typedef struct ak_domain_rule {
  char *pattern; /* Domain pattern */
  boolean allow;
  struct ak_domain_rule *next;
} ak_domain_rule_t;

/* Taint source/sink/sanitizer */
typedef struct ak_taint_rule {
  char *name;
  enum {
    AK_TAINT_RULE_SOURCE,
    AK_TAINT_RULE_SINK,
    AK_TAINT_RULE_SANITIZER
  } type;
  struct ak_taint_rule *next;
} ak_taint_rule_t;

/* Policy version record (for versioning/rollback) */
typedef struct ak_policy_version {
  u32 version_number;             /* Monotonic version number */
  u64 activated_ms;               /* When this version became active */
  u8 hash[AK_HASH_SIZE];          /* Hash of policy content */
  buffer rules_json;              /* Serialized rules for this version */
  struct ak_policy_version *prev; /* Previous version (for rollback) */
} ak_policy_version_t;

/* Complete policy */
typedef struct ak_policy {
  /* Heap for allocations */
  heap h;

  /* Metadata */
  char version[16];
  /*
   * Policy authentication tag.
   *
   * NOTE: Despite AK_SIG_SIZE being labeled "Ed25519 signature size" in
   * ak_config.h/ak_types.h, this is NOT an Ed25519 digital signature.
   * Only the first AK_MAC_SIZE (32) bytes are used, holding
   * HMAC-SHA256(key, policy_hash) - symmetric authentication.  Anyone
   * who holds the key can both create and verify tags; it provides
   * tamper detection, not third-party-verifiable provenance.
   */
  u8 signature[AK_SIG_SIZE];
  u8 policy_hash[AK_HASH_SIZE]; /* SHA-256 of canonical serialization
                                 * (see ak_policy_compute_hash) */
  boolean signature_verified;   /* true only if the HMAC tag was checked
                                 * against a configured verification key
                                 * at load time */
  u64 created_ms;
  u64 expires_ms;

  /* Budget limits */
  ak_budget_limits_t budgets;

  /* Rules (linked lists) */
  ak_tool_rule_t *tool_rules;
  ak_domain_rule_t *domain_rules;
  ak_taint_rule_t *taint_rules;

  /* Default behaviors */
  boolean default_tool_allow; /* Default if no rule matches */
  boolean default_domain_allow;

  /* Versioning support */
  ak_policy_version_t *current_version;
  u32 version_count; /* Number of versions in history */

} ak_policy_t;

/* ============================================================
 * POLICY LOADING
 * ============================================================ */

/* Initialize policy subsystem */
void ak_policy_init(heap h);

/*
 * Load policy from buffer (JSON format).
 *
 * Parses the JSON policy document produced by host tooling:
 *
 *   {
 *     "version": "1.0",
 *     "signature": "<64 or 128 hex chars, HMAC-SHA256 tag>",
 *     "budgets": { "tokens": N, "calls": N, ... },
 *     "tools": { "allow": ["file_read", ...], "deny": ["shell_exec"] },
 *     "domains": { "allow": ["*.github.com"], "deny": ["*.internal"] },
 *     "taint": { "sources": [...], "sinks": [...], "sanitizers": [...] }
 *   }
 *
 * Returns: parsed policy on success, NULL on error.
 *
 * SECURITY (fail-closed):
 *   - Input that is not a valid JSON policy object is REJECTED (NULL).
 *     Nothing is silently replaced with defaults; use ak_policy_default()
 *     if a defaults policy is wanted.
 *   - If a verification key is configured (ak_policy_set_verification_key),
 *     unsigned or wrongly-signed policies are REJECTED.
 *   - If no key is configured, the policy is accepted but
 *     policy->signature_verified stays false ("unsigned" - never treated
 *     as verified).
 *   - Unmatched tools/domains default to DENY.
 */
ak_policy_t *ak_policy_load(heap h, buffer yaml_data);

/*
 * Configure the HMAC-SHA256 policy verification key (AK_KEY_SIZE bytes).
 *
 * Once set, ak_policy_load() rejects any policy whose HMAC tag does not
 * verify (including unsigned policies).  Pass NULL to clear the key
 * (subsequent loads accept policies but flag them unsigned).
 *
 * NOTE: symmetric authentication (HMAC-SHA256), not an Ed25519 signature.
 */
void ak_policy_set_verification_key(const u8 *key);

/*
 * Load policy from file.
 */
ak_policy_t *ak_policy_load_file(heap h, const char *path);

/*
 * Destroy policy (frees all resources).
 */
void ak_policy_destroy(heap h, ak_policy_t *policy);

/*
 * Get hash of policy content (for audit logging).
 */
void ak_policy_get_hash(ak_policy_t *policy, u8 *hash_out);

/* ============================================================
 * POLICY VERIFICATION
 * ============================================================ */

/*
 * Verify policy authentication tag using HMAC-SHA256.
 *
 * NOTE: This is symmetric authentication (HMAC-SHA256), NOT an Ed25519
 * digital signature - the "Ed25519" labeling of AK_SIG_SIZE in
 * ak_config.h/ak_types.h refers only to the field width (64 bytes).
 *
 * Signature format:
 *   - First AK_MAC_SIZE (32) bytes of policy->signature contain
 *     HMAC-SHA256(signing_key, policy_hash)
 *   - policy_hash is SHA-256 of the canonical policy serialization
 *     (ak_policy_serialize), which covers all security-relevant fields
 *
 * Behavior by configuration:
 *   - AK_ALLOW_UNSIGNED_POLICIES=0 (default, production):
 *     Rejects unsigned policies. Requires valid signature.
 *   - AK_ALLOW_UNSIGNED_POLICIES=1 (development only):
 *     Accepts unsigned policies with a warning logged.
 *   - AK_REQUIRE_POLICY_SIGNATURES=1 (runtime override):
 *     Always requires signatures, overrides dev mode.
 *
 * @param policy        Policy to verify
 * @param signing_key   32-byte HMAC key (NULL allowed for unsigned check)
 * @return              true if valid (or unsigned in dev mode), false otherwise
 *
 * SECURITY: In production, always set AK_ALLOW_UNSIGNED_POLICIES=0
 */
boolean ak_policy_verify_signature(ak_policy_t *policy, u8 *signing_key);

/*
 * Sign a policy using HMAC-SHA256.
 *
 * Computes HMAC-SHA256(signing_key, policy_hash) and stores
 * the result in the first AK_MAC_SIZE bytes of policy->signature.
 *
 * @param policy        Policy to sign (policy_hash must be computed)
 * @param signing_key   32-byte HMAC key (must not be NULL)
 * @return              true on success, false on error
 *
 * Note: This function is provided for policy generation tools.
 * The signing key should be kept secure and never exposed.
 */
boolean ak_policy_sign(ak_policy_t *policy, const u8 *signing_key);

/*
 * Check if policy is expired.
 */
boolean ak_policy_expired(ak_policy_t *policy);

/* ============================================================
 * POLICY VERSIONING
 * ============================================================ */

/* Policy result codes for versioning */
typedef enum ak_policy_result {
  AK_POLICY_OK = 0,
  AK_POLICY_ERROR_VERSION,      /* Version number invalid */
  AK_POLICY_ERROR_PARSE,        /* Failed to parse rules */
  AK_POLICY_ERROR_NO_PREVIOUS,  /* No previous version for rollback */
  AK_POLICY_ERROR_INCOMPATIBLE, /* Versions incompatible */
} ak_policy_result_t;

/*
 * Upgrade policy to new version.
 *
 * The new version must have a higher version number.
 * Old version is preserved for potential rollback.
 *
 * @param policy        Policy to upgrade
 * @param new_rules     New rules in JSON/YAML format
 * @param new_version   New version number (must be > current)
 * @return              AK_POLICY_OK on success, error code on failure
 */
ak_policy_result_t ak_policy_upgrade(ak_policy_t *policy, buffer new_rules,
                                     u32 new_version);

/*
 * Rollback to previous version.
 *
 * Restores the policy state to the previous version.
 *
 * @param policy        Policy to rollback
 * @return              AK_POLICY_OK on success, error code on failure
 */
ak_policy_result_t ak_policy_rollback(ak_policy_t *policy);

/*
 * Check if versions are compatible.
 *
 * Used to validate upgrades don't break running agents.
 *
 * @param old_version   Current version number
 * @param new_version   Proposed new version number
 * @return              true if compatible
 */
boolean ak_policy_is_compatible(u32 old_version, u32 new_version);

/*
 * Get current policy version number.
 */
u32 ak_policy_get_version(ak_policy_t *policy);

/*
 * Get version history count.
 */
u32 ak_policy_version_count(ak_policy_t *policy);

/* ============================================================
 * BUDGET CHECKING (INV-3)
 * ============================================================ */

/* Runtime budget tracker - see ak_budget.h for complete definition */

/*
 * Create budget tracker for a run.
 */
ak_budget_tracker_t *ak_budget_create(heap h, u8 *run_id, ak_policy_t *policy);

/*
 * Destroy budget tracker.
 */
void ak_budget_destroy(heap h, ak_budget_tracker_t *tracker);

/*
 * Reserve budget (before operation).
 *
 * Returns:
 *   0                   - Success, budget reserved
 *   AK_E_BUDGET_EXCEEDED - Would exceed limit
 */
s64 ak_budget_reserve(ak_budget_tracker_t *tracker, ak_resource_type_t type,
                      u64 amount);

/*
 * Commit reserved budget (after successful operation).
 *
 * Moves from reserved to committed.
 */
void ak_budget_commit(ak_budget_tracker_t *tracker, ak_resource_type_t type,
                      u64 amount);

/*
 * Release reserved budget (operation failed/cancelled).
 *
 * Returns reserved amount to available.
 */
void ak_budget_release(ak_budget_tracker_t *tracker, ak_resource_type_t type,
                       u64 amount);

/*
 * Check if budget allows operation (without reserving).
 */
boolean ak_budget_check(ak_budget_tracker_t *tracker, ak_resource_type_t type,
                        u64 amount);

/*
 * Get remaining budget for resource type.
 */
u64 ak_budget_remaining(ak_budget_tracker_t *tracker, ak_resource_type_t type);

/*
 * Get budget statistics.
 */
typedef struct ak_budget_stats {
  ak_budget_limits_t limits;
  ak_budget_limits_t used;
  ak_budget_limits_t reserved;
  ak_budget_limits_t remaining;
} ak_budget_stats_t;

void ak_budget_get_stats(ak_budget_tracker_t *tracker,
                         ak_budget_stats_t *stats);

/* ============================================================
 * TOOL AUTHORIZATION
 * ============================================================ */

/*
 * Check if tool is allowed by policy.
 *
 * Returns: true if allowed, false if denied.
 *
 * Matching:
 *   - Exact match first
 *   - Then glob patterns
 *   - Then default
 */
boolean ak_policy_check_tool(ak_policy_t *policy, const char *tool_name);

/*
 * Get list of allowed tools (for CALL syscall).
 */
const char **ak_policy_list_allowed_tools(heap h, ak_policy_t *policy,
                                          u64 *count_out);

/* ============================================================
 * DOMAIN AUTHORIZATION
 * ============================================================ */

/*
 * Check if domain is allowed for network access.
 *
 * Returns: true if allowed, false if denied.
 */
boolean ak_policy_check_domain(ak_policy_t *policy, const char *domain);

/*
 * Check URL (extracts domain and checks).
 */
boolean ak_policy_check_url(ak_policy_t *policy, const char *url);

/* ============================================================
 * TAINT FLOW CONTROL
 * ============================================================ */

/*
 * Check if taint source is defined.
 */
boolean ak_policy_is_source(ak_policy_t *policy, const char *name);

/*
 * Check if taint sink is defined.
 */
boolean ak_policy_is_sink(ak_policy_t *policy, const char *name);

/*
 * Check if sanitizer is defined.
 */
boolean ak_policy_is_sanitizer(ak_policy_t *policy, const char *name);

/*
 * Check if data flow is allowed.
 *
 * source_taint: taint level of data
 * sink_name: name of sink operation
 * sanitized: whether data passed through sanitizer
 *
 * Returns: true if flow allowed, false if blocked.
 */
boolean ak_policy_check_flow(ak_policy_t *policy, ak_taint_t source_taint,
                             const char *sink_name, boolean sanitized);

/* ============================================================
 * REQUEST EVALUATION
 * ============================================================ */

/*
 * Evaluate request against policy (comprehensive check).
 *
 * Checks:
 *   - Budget availability
 *   - Tool authorization
 *   - Domain restrictions
 *   - Taint flow rules
 *
 * Returns:
 *   0                   - Allowed
 *   AK_E_POLICY_DENIED  - Policy denies request
 *   AK_E_BUDGET_EXCEEDED - Would exceed budget
 *   AK_E_TAINT          - Taint flow violation
 */
s64 ak_policy_evaluate(ak_policy_t *policy, ak_budget_tracker_t *budget,
                       ak_request_t *req);

/* ============================================================
 * POLICY SERIALIZATION
 * ============================================================ */

/*
 * Serialize policy to canonical YAML-style text.
 *
 * Deterministically emits ALL security-relevant fields: version,
 * expiration, default allow flags, every budget limit, and all
 * tool/domain/taint rules.  The signature itself is excluded.
 *
 * SECURITY: ak_policy_compute_hash() hashes this output, so any field
 * that affects enforcement MUST be emitted here - otherwise two
 * different policies could hash (and therefore sign) identically.
 */
buffer ak_policy_serialize(heap h, ak_policy_t *policy);

/*
 * Compute policy hash (for signing/verification).
 *
 * hash_out = SHA-256(ak_policy_serialize(policy)); binds the entire
 * policy content (budgets, tools, domains, taint, defaults).
 */
void ak_policy_compute_hash(ak_policy_t *policy, u8 *hash_out);

/* ============================================================
 * DEFAULT POLICY
 * ============================================================ */

/*
 * Create default restrictive policy.
 *
 * - Low budgets
 * - No dangerous tools
 * - Limited domains
 */
ak_policy_t *ak_policy_default(heap h);

/*
 * Create permissive development policy.
 *
 * WARNING: Only for testing!
 */
ak_policy_t *ak_policy_permissive(heap h);

#endif /* AK_POLICY_H */
