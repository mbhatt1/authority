/*
 * Authority Kernel - Capability System
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements INV-2: Capability Invariant
 * "Every effectful syscall must carry a valid, non-revoked capability
 *  whose scope subsumes the request."
 *
 * SECURITY CRITICAL: This file enforces the capability invariant.
 * All functions MUST fail-closed on any ambiguity.
 */

#ifndef AK_CAPABILITY_H
#define AK_CAPABILITY_H

#include "ak_types.h"

/* ============================================================
 * KEY MANAGEMENT
 * ============================================================
 * HMAC keys for capability signing/verification.
 * Supports key rotation without invalidating all tokens.
 */

typedef struct ak_key {
  u8 kid;                 /* Key ID (0-255) */
  u8 secret[AK_KEY_SIZE]; /* HMAC key material */
  u64 created_ms;
  u64 expires_ms;  /* Grace period end */
  boolean active;  /* Can sign new tokens */
  boolean retired; /* Cannot verify */
} ak_key_t;

#define AK_MAX_KEYS 4                            /* Active + 3 grace keys */
#define AK_KEY_ROTATION_MS (24 * 60 * 60 * 1000) /* 24 hours */
#define AK_KEY_GRACE_MS (4 * AK_KEY_ROTATION_MS)

/* Initialize key management subsystem.
 *
 * If a seed was staged with ak_keys_set_seed() before this call, the
 * initial signing key is derived deterministically from that seed
 * (allowing capabilities issued in a previous boot to verify).
 * Otherwise a fresh random key is generated (fail-safe default). */
void ak_keys_init(heap h);

/* Get current active key for signing */
ak_key_t *ak_key_get_active(void);

/* Get key by ID for verification (never returns retired keys) */
ak_key_t *ak_key_get(u8 kid);

/* Rotate keys (called periodically) */
void ak_key_rotate(void);

/* ============================================================
 * KEY PERSISTENCE
 * ============================================================
 * PERSISTENCE CONTRACT:
 *
 * Without persistence, every boot generates a fresh random signing
 * key and all previously-issued capabilities fail verification.
 * A caller that wants capabilities to survive a restart must either:
 *
 *   (a) call ak_keys_set_seed(seed, len) BEFORE ak_keys_init() with a
 *       stable secret seed (>= 16 bytes recommended); the initial key
 *       is derived deterministically from the seed, so the same seed
 *       reproduces the same key set at boot; or
 *
 *   (b) after boot, call ak_keys_export() and persist the returned
 *       blob to protected storage; on the next boot, call
 *       ak_keys_init() then ak_keys_import(blob) to restore the full
 *       key set (all grace keys + rotation counter).
 *
 * SECURITY: The exported blob contains RAW HMAC KEY MATERIAL.
 * The caller MUST store it in integrity- and confidentiality-
 * protected storage and zero its copies after use. Import rebases
 * key lifetimes onto the current (monotonic) clock: the active key
 * gets a full rotation+grace lifetime, restored grace keys get a
 * grace-period lifetime.
 */

/* Exported key-set blob framing */
#define AK_KEYS_BLOB_MAGIC 0x534B4B41u /* "AKKS" (little-endian) */
#define AK_KEYS_BLOB_VERSION 1
#define AK_KEYS_BLOB_SIZE (16 + AK_MAX_KEYS * 56)

/*
 * Stage a seed for deterministic key derivation in ak_keys_init().
 * Must be called before ak_keys_init(); the staged copy is zeroed
 * once consumed. Passing NULL or len == 0 clears a staged seed.
 */
void ak_keys_set_seed(const u8 *seed, u32 len);

/*
 * Export the current key set (all slots, active index, rotation
 * counter) as an opaque blob of AK_KEYS_BLOB_SIZE bytes.
 * Returns NULL on allocation failure.
 */
buffer ak_keys_export(heap h);

/*
 * Restore a key set previously produced by ak_keys_export().
 * Must be called after ak_keys_init(). Fail-closed: returns false
 * (leaving the existing key set untouched) on any malformed input.
 */
boolean ak_keys_import(buffer blob);

/* ============================================================
 * CAPABILITY CREATION
 * ============================================================ */

/*
 * Create new capability token.
 *
 * PRECONDITIONS:
 *   - h must be valid heap
 *   - resource must be non-NULL, null-terminated string
 *   - methods may be NULL (no method restrictions)
 *   - ttl_ms > 0
 *   - run_id may be NULL (unbound capability)
 *
 * POSTCONDITIONS:
 *   - Returns valid capability with MAC computed
 *   - capability->type == type
 *   - capability->ttl_ms <= AK_MAX_CAP_TTL_MS
 *
 * RETURNS:
 *   - Valid capability on success
 *   - NULL on failure (allocation, resource too long)
 *
 * SECURITY: Caller must have authority to grant these permissions.
 * Use ak_capability_delegate() for child tokens.
 */
ak_capability_t *ak_capability_create(
    heap h, ak_cap_type_t type, const char *resource, /* Domain/path pattern */
    const char **methods, /* NULL-terminated array */
    u32 ttl_ms, u32 rate_limit, u32 rate_window_ms, u8 *run_id /* Bound run */
);

/*
 * Delegate (attenuate) capability to create child.
 *
 * SECURITY: Child MUST be subset of parent.
 * child.scope ⊆ parent.scope
 * child.ttl ≤ parent.ttl
 * child.rate ≤ parent.rate
 *
 * Returns NULL if delegation would violate monotonicity.
 */
ak_capability_t *ak_capability_delegate(heap h, ak_capability_t *parent,
                                        ak_cap_type_t type,
                                        const char *resource,
                                        const char **methods, u32 ttl_ms,
                                        u32 rate_limit, u32 rate_window_ms);

/* Free capability (zeros memory for security) */
void ak_capability_destroy(heap h, ak_capability_t *cap);

/* ============================================================
 * CAPABILITY VERIFICATION
 * ============================================================
 * CRITICAL: This is the enforcement of INV-2.
 */

/*
 * Verify capability integrity (HMAC check).
 *
 * PRECONDITIONS:
 *   - cap may be NULL (returns AK_E_CAP_MISSING)
 *
 * POSTCONDITIONS:
 *   - Returns 0 only if MAC is valid AND TTL not expired
 *   - On failure, capability MUST NOT be used for authorization
 *
 * Returns:
 *   0               - Valid
 *   AK_E_CAP_MISSING - cap is NULL
 *   AK_E_CAP_INVALID - MAC verification failed (forged/corrupted)
 *                      or signing key unknown/retired
 *   AK_E_CAP_EXPIRED - TTL exceeded
 *
 * SECURITY: Uses constant-time comparison to prevent timing attacks.
 * INV-2: This is the first step in capability validation.
 */
s64 ak_capability_verify(ak_capability_t *cap);

/*
 * Check if capability scope covers the request.
 *
 * Returns:
 *   0              - Scope valid
 *   AK_E_CAP_SCOPE - Resource or method not covered
 *   AK_E_CAP_RATE  - Rate limit exceeded
 *   AK_E_CAP_RUN_MISMATCH - Wrong run_id binding
 *
 * SECURITY: Fails-closed on any ambiguity.
 */
s64 ak_capability_check_scope(ak_capability_t *cap, ak_cap_type_t required_type,
                              const char *resource, const char *method,
                              u8 *run_id);

/*
 * Full capability validation (verify + scope + revocation).
 *
 * This is the single entry point for syscall capability checks.
 * Combines: HMAC verification, scope matching, revocation lookup.
 *
 * Returns: 0 on success, negative error code on failure.
 */
s64 ak_capability_validate(ak_capability_t *cap, ak_cap_type_t required_type,
                           const char *resource, const char *method,
                           u8 *run_id);

/* ============================================================
 * REVOCATION
 * ============================================================
 * Immediate revocation with persistence (survives restart).
 */

typedef struct ak_revocation_entry {
  u8 tid[AK_TOKEN_ID_SIZE];
  u64 revoked_ms;
  buffer reason;
  /* Hash-chain link: the revocation table is keyed by a 64-bit hash
   * of the full 16-byte tid; entries whose tids collide on that hash
   * are chained here and disambiguated by full-tid comparison. */
  struct ak_revocation_entry *next;
} ak_revocation_entry_t;

/* Initialize revocation subsystem */
void ak_revocation_init(heap h);

/*
 * Check if token is revoked.
 *
 * Returns: true if revoked, false if valid.
 *
 * SECURITY: O(1) lookup, no timing leak.
 */
boolean ak_revocation_check(u8 *tid);

/*
 * Revoke a capability token.
 *
 * SECURITY: Revocation is immediate and persistent.
 * Token becomes invalid for all future requests.
 */
void ak_revocation_add(u8 *tid, const char *reason);

/*
 * Revoke all tokens for a run (on unexpected exit).
 *
 * SECURITY: Implements REQ-005 (anti-tamper exit monitoring).
 */
void ak_revocation_revoke_run(u8 *run_id, const char *reason);

/* Load revocations from log (crash recovery) */
void ak_revocation_load_from_log(void);

/* ============================================================
 * RATE LIMITING
 * ============================================================ */

/*
 * Check and update rate limit for capability.
 *
 * Returns:
 *   true  - Within limit, counter incremented
 *   false - Limit exceeded
 */
boolean ak_rate_limit_check(u8 *tid, u32 limit, u32 window_ms);

/* Reset rate limit counters (for testing) */
void ak_rate_limit_reset(u8 *tid);

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

/*
 * Serialize capability to canonical JSON (for HMAC computation).
 * Excludes the 'mac' field.
 */
buffer ak_capability_canonicalize(heap h, ak_capability_t *cap);

/*
 * Capability wire format v1 (host byte order; tokens never leave the
 * machine that minted them - the HMAC key is local):
 *
 *   off  size  field
 *   0    4     magic = AK_CAP_WIRE_MAGIC
 *   4    1     version = AK_CAP_WIRE_VERSION
 *   5    1     kid
 *   6    1     type (ak_cap_type_t)
 *   7    1     method_count (0..8)
 *   8    2     total_len (u16, whole message incl. header)
 *   10   2     resource_len (u16, < 256)
 *   12   8     issued_ms
 *   20   4     ttl_ms
 *   24   4     rate_limit
 *   28   4     rate_window_ms
 *   32   16    run_id
 *   48   16    tid
 *   64   32    mac
 *   96   var   resource bytes (resource_len, no NUL)
 *        var   method_count x { u8 len (< 32); len bytes }
 *
 *   total_len == 96 + resource_len + sum(1 + len_i)
 *
 * Trailing bytes past total_len (e.g. padding in a fixed-size
 * transport buffer) are ignored by the parser.
 */
#define AK_CAP_WIRE_MAGIC 0x31504143u /* "CAP1" (little-endian) */
#define AK_CAP_WIRE_VERSION 1
#define AK_CAP_WIRE_HDR_SIZE 96
/* Upper bound on a serialized capability: header + max resource (255) +
 * up to 8 methods of (1 length byte + 31 chars). Used to bound the read
 * of a per-call token from the syscall ABI. */
#define AK_CAP_WIRE_MAX_SIZE (AK_CAP_WIRE_HDR_SIZE + 255 + 8 * 32)

/*
 * Serialize capability to wire format (includes MAC).
 * Returns NULL on allocation failure.
 */
buffer ak_capability_serialize(heap h, ak_capability_t *cap);

/*
 * Parse capability from wire format (exact inverse of
 * ak_capability_serialize). Fail-closed: returns NULL on any
 * malformation (short buffer, bad magic/version/lengths).
 * Does NOT verify - caller must call ak_capability_verify();
 * the mac bytes are preserved for that purpose.
 */
ak_capability_t *ak_capability_parse(heap h, buffer data);

/* ============================================================
 * SUBSUMPTION CHECK
 * ============================================================
 * For delegation: verify child ⊆ parent.
 */

/*
 * Check if child capability is subsumed by parent.
 *
 * c2 ⊆ c1 iff:
 *   c2.type = c1.type
 *   c2.resource matches subset of c1.resource
 *   c2.methods ⊆ c1.methods
 *   c2.ttl ≤ remaining_ttl(c1)
 *   c2.rate ≤ c1.rate
 */
boolean ak_capability_subsumed(ak_capability_t *parent, ak_capability_t *child);

/* ============================================================
 * PATTERN MATCHING
 * ============================================================ */

/*
 * Match resource against pattern.
 *
 * Patterns:
 *   "*"           - Match anything
 *   "*.github.com" - Suffix match
 *   "/tmp/..."    - Prefix match (use * for glob)
 *   "exact"       - Exact match
 *
 * SECURITY: Fails-closed on malformed patterns.
 */
boolean ak_pattern_match(const char *pattern, const char *resource);

/* ============================================================
 * HELPERS
 * ============================================================ */

/* Generate random token ID */
void ak_generate_token_id(u8 *tid);

/* Compare token IDs (constant-time) */
boolean ak_token_id_equal(u8 *a, u8 *b);

/* Get remaining TTL in ms (0 if expired) */
u32 ak_capability_remaining_ttl(ak_capability_t *cap);

/* Debug: print capability (redacts MAC) */
void ak_capability_debug_print(ak_capability_t *cap);

#endif /* AK_CAPABILITY_H */
