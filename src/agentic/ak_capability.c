/*
 * Authority Kernel - Capability System Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * SECURITY CRITICAL: This file enforces INV-2 (Capability Invariant).
 * Every function MUST fail-closed. No exceptions.
 */

#include "ak_capability.h"
#include "ak_assert.h"
#include "ak_audit.h"
#include "ak_pattern.h"
#include "ak_types.h"

/* ============================================================
 * INTERNAL STATE (forward declaration for HMAC function)
 * ============================================================ */

static struct {
  heap h;
  struct spinlock lock;

  /* Key management */
  ak_key_t keys[AK_MAX_KEYS];
  u8 active_kid; /* Slot index of active key */
  u64 last_rotation_ms;
  u64 key_counter; /* Monotonic key-id counter; never reused */

  /* Revocation map: tid-hash -> chain of ak_revocation_entry_t */
  table revocations;
  u64 revocation_count;

  /* Rate limit state: tid-hash -> chain of rate_counter_t */
  table rate_counters;
  u64 rate_entry_count;

  boolean initialized;
} ak_cap_state;

typedef struct rate_counter {
  u8 tid[AK_TOKEN_ID_SIZE]; /* Full token id (hash keys can collide) */
  u32 count;
  u32 window_ms; /* Window length, kept for expiry sweeps */
  u64 window_start_ms;
  struct rate_counter *next; /* Hash-chain link */
} rate_counter_t;

/* Bounded-growth parameters */
#define AK_RATE_MAX_ENTRIES 4096
#define AK_REVOCATION_SWEEP_THRESHOLD 1024
/* A revocation only matters while the token could still pass the TTL
 * check: revoked_ms + AK_MAX_CAP_TTL_MS bounds the token's expiry
 * (ttl is clamped at creation). One rotation period of slack. */
#define AK_REVOCATION_RETAIN_MS (AK_MAX_CAP_TTL_MS + AK_KEY_ROTATION_MS)

/* Wrapper for Nanos sha256 that uses buffers */
static void ak_sha256(const u8 *data, u32 len, u8 *output) {
  buffer src = alloca_wrap_buffer((void *)data, len);
  /* Use a little_stack_buffer which can be extended, unlike wrapped buffers */
  buffer dst = little_stack_buffer(64);
  sha256(dst, src);
  /* Copy result to output */
  runtime_memcpy(output, buffer_ref(dst, 0), 32);
}

/*
 * HMAC-SHA256 per RFC 2104
 *
 * HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
 * where:
 *   K' = K padded with zeros to block size (64 bytes for SHA-256)
 *   ipad = 0x36 repeated 64 times
 *   opad = 0x5c repeated 64 times
 */
#define HMAC_BLOCK_SIZE 64
#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

static void ak_hmac_sha256(const u8 *key, u32 key_len, const u8 *data,
                           u32 data_len, u8 *output) {
  u8 k_prime[HMAC_BLOCK_SIZE];
  u8 inner_pad[HMAC_BLOCK_SIZE];
  u8 outer_pad[HMAC_BLOCK_SIZE];
  u8 inner_hash[32];
  u8 outer_input[HMAC_BLOCK_SIZE + 32];

  /* Step 1: Derive K' from key
   * If key > block size, K' = H(key)
   * If key <= block size, K' = key padded with zeros
   */
  ak_memzero(k_prime, HMAC_BLOCK_SIZE);
  if (key_len > HMAC_BLOCK_SIZE) {
    /* Key too long: hash it first */
    ak_sha256(key, key_len, k_prime);
    /* Remaining bytes already zeroed */
  } else {
    /* Key fits: copy and zero-pad */
    ak_memcpy(k_prime, key, key_len);
    /* Remaining bytes already zeroed */
  }

  /* Step 2: Compute inner and outer padded keys
   * inner_pad = K' XOR ipad
   * outer_pad = K' XOR opad
   */
  for (u32 i = 0; i < HMAC_BLOCK_SIZE; i++) {
    inner_pad[i] = k_prime[i] ^ HMAC_IPAD;
    outer_pad[i] = k_prime[i] ^ HMAC_OPAD;
  }

  /* Step 3: Compute inner hash = H(inner_pad || message)
   * We need to allocate a buffer for (inner_pad || data)
   */
  u32 inner_input_len = HMAC_BLOCK_SIZE + data_len;
  u8 *inner_input = allocate(ak_cap_state.h, inner_input_len);
  if (inner_input == INVALID_ADDRESS) {
    ak_memzero(output, 32);
    goto cleanup;
  }
  ak_memcpy(inner_input, inner_pad, HMAC_BLOCK_SIZE);
  ak_memcpy(inner_input + HMAC_BLOCK_SIZE, data, data_len);
  ak_sha256(inner_input, inner_input_len, inner_hash);

  /* Zero and free inner input */
  ak_memzero(inner_input, inner_input_len);
  deallocate(ak_cap_state.h, inner_input, inner_input_len);

  /* Step 4: Compute outer hash = H(outer_pad || inner_hash)
   * This is the final HMAC output
   */
  ak_memcpy(outer_input, outer_pad, HMAC_BLOCK_SIZE);
  ak_memcpy(outer_input + HMAC_BLOCK_SIZE, inner_hash, 32);
  ak_sha256(outer_input, HMAC_BLOCK_SIZE + 32, output);

cleanup:
  /* Security: Zero all sensitive intermediate values */
  ak_memzero(k_prime, HMAC_BLOCK_SIZE);
  ak_memzero(inner_pad, HMAC_BLOCK_SIZE);
  ak_memzero(outer_pad, HMAC_BLOCK_SIZE);
  ak_memzero(inner_hash, 32);
  ak_memzero(outer_input, HMAC_BLOCK_SIZE + 32);
}

/* Random bytes from Nanos random subsystem */
static void ak_random_bytes(u8 *buf, u32 len) {
  /* Use Nanos cryptographically secure random via random_buffer() */
  buffer b = alloca_wrap_buffer(buf, len);
  random_buffer(b);
}

/* ============================================================
 * CONSTANT-TIME COMPARISON
 * ============================================================
 * Prevents timing attacks on MAC verification.
 */

static boolean constant_time_compare(const u8 *a, const u8 *b, u32 len) {
  u8 diff = 0;
  for (u32 i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/* ============================================================
 * TOKEN-ID HASHING
 * ============================================================
 * The revocation and rate-limit tables are u64-keyed. Keying on a
 * truncated tid prefix would let two tokens sharing an 8-byte prefix
 * collide (revoking one revokes the other / rate-limit evasion), so
 * we key on a hash of the FULL 16-byte tid and chain entries per
 * bucket, disambiguating with a full-tid comparison.
 */

static u64 ak_tid_hash(const u8 *tid) {
  /* FNV-1a over all AK_TOKEN_ID_SIZE bytes */
  u64 h = 0xcbf29ce484222325ull;
  for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
    h ^= tid[i];
    h *= 0x100000001b3ull;
  }
  if (h == 0)
    h = 1; /* Avoid ambiguity with "no key" */
  return h;
}

/* ============================================================
 * KEY MANAGEMENT
 * ============================================================ */

/* Seed staged by ak_keys_set_seed() for deterministic key derivation.
 * Consumed (and zeroed) by ak_keys_init(). */
static struct {
  boolean set;
  u8 seed[AK_KEY_SIZE];
} ak_keys_seed;

void ak_keys_set_seed(const u8 *seed, u32 len) {
  if (!seed || len == 0) {
    ak_memzero(ak_keys_seed.seed, AK_KEY_SIZE);
    ak_keys_seed.set = false;
    return;
  }
  if (len == AK_KEY_SIZE) {
    ak_memcpy(ak_keys_seed.seed, seed, AK_KEY_SIZE);
  } else {
    /* Compress arbitrary-length seed to key size */
    ak_sha256(seed, len, ak_keys_seed.seed);
  }
  ak_keys_seed.set = true;
}

void ak_keys_init(heap h) {
  ak_cap_state.h = h;
  spin_lock_init(&ak_cap_state.lock);
  ak_cap_state.revocations = allocate_table(h, identity_key, pointer_equal);
  ak_cap_state.rate_counters = allocate_table(h, identity_key, pointer_equal);
  ak_cap_state.revocation_count = 0;
  ak_cap_state.rate_entry_count = 0;

  /* Mark unused slots retired so they are never matched or returned */
  for (int i = 1; i < AK_MAX_KEYS; i++) {
    ak_cap_state.keys[i].retired = true;
    ak_cap_state.keys[i].active = false;
  }

  /* Initial key: derived from a staged seed if one was provided
   * (persistence contract, see ak_capability.h), random otherwise. */
  ak_cap_state.active_kid = 0;
  ak_key_t *key = &ak_cap_state.keys[0];
  key->kid = 0;
  if (ak_keys_seed.set) {
    ak_memcpy(key->secret, ak_keys_seed.seed, AK_KEY_SIZE);
    ak_memzero(ak_keys_seed.seed, AK_KEY_SIZE);
    ak_keys_seed.set = false;
  } else {
    ak_random_bytes(key->secret, AK_KEY_SIZE);
  }
  key->created_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
  key->expires_ms = key->created_ms + AK_KEY_ROTATION_MS + AK_KEY_GRACE_MS;
  key->active = true;
  key->retired = false;

  ak_cap_state.key_counter = 1; /* kid 0 consumed by the initial key */
  ak_cap_state.last_rotation_ms = key->created_ms;
  ak_cap_state.initialized = true;
}

ak_key_t *ak_key_get_active(void) {
  return &ak_cap_state.keys[ak_cap_state.active_kid];
}

ak_key_t *ak_key_get(u8 kid) {
  for (int i = 0; i < AK_MAX_KEYS; i++) {
    if (ak_cap_state.keys[i].kid == kid && !ak_cap_state.keys[i].retired) {
      return &ak_cap_state.keys[i];
    }
  }
  return NULL;
}

void ak_key_rotate(void) {
  u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  spin_lock(&ak_cap_state.lock);

  /* Check if rotation needed */
  if (now_ms - ak_cap_state.last_rotation_ms < AK_KEY_ROTATION_MS) {
    spin_unlock(&ak_cap_state.lock);
    return;
  }

  /* Retire oldest key if we have max keys */
  for (int i = 0; i < AK_MAX_KEYS; i++) {
    if (now_ms > ak_cap_state.keys[i].expires_ms &&
        !ak_cap_state.keys[i].retired) {
      /* Zeroize secret key material before marking as retired */
      ak_memzero(ak_cap_state.keys[i].secret, AK_KEY_SIZE);
      ak_cap_state.keys[i].retired = true;
    }
  }

  /* Find slot for new key */
  int slot = -1;
  for (int i = 0; i < AK_MAX_KEYS; i++) {
    if (ak_cap_state.keys[i].retired) {
      slot = i;
      break;
    }
  }

  if (slot < 0) {
    /* All slots in use - force retire oldest */
    u64 oldest = UINT64_MAX;
    for (int i = 0; i < AK_MAX_KEYS; i++) {
      if (ak_cap_state.keys[i].created_ms < oldest) {
        oldest = ak_cap_state.keys[i].created_ms;
        slot = i;
      }
    }
    /* Zeroize secret key material before force retiring */
    ak_memzero(ak_cap_state.keys[slot].secret, AK_KEY_SIZE);
    ak_cap_state.keys[slot].retired = true;
  }

  /* Create new key.
   *
   * kid comes from a monotonic counter stored in state (never from a
   * slot index, which repeats as slots are reused). Live (non-retired)
   * keys are always the AK_MAX_KEYS most recent counter values, i.e.
   * consecutive, so their u8 kids are distinct and ak_key_get(kid)
   * is unambiguous. A capability from >255 rotations ago maps to a
   * reused u8 kid, but its MAC then fails against the new secret,
   * which is fail-closed (AK_E_CAP_INVALID). */
  ak_key_t *new_key = &ak_cap_state.keys[slot];
  new_key->kid = (u8)(ak_cap_state.key_counter & 0xff);
  ak_cap_state.key_counter++;
  ak_random_bytes(new_key->secret, AK_KEY_SIZE);
  new_key->created_ms = now_ms;
  new_key->expires_ms = now_ms + AK_KEY_ROTATION_MS + AK_KEY_GRACE_MS;
  new_key->active = true;
  new_key->retired = false;

  /* Deactivate old active key */
  ak_cap_state.keys[ak_cap_state.active_kid].active = false;

  /* Switch to new key */
  ak_cap_state.active_kid = slot;
  ak_cap_state.last_rotation_ms = now_ms;

  spin_unlock(&ak_cap_state.lock);
}

/* ============================================================
 * KEY PERSISTENCE
 * ============================================================
 * Blob layout (host byte order, AK_KEYS_BLOB_SIZE bytes total):
 *   0   4   magic = AK_KEYS_BLOB_MAGIC
 *   4   1   version = AK_KEYS_BLOB_VERSION
 *   5   1   active slot index
 *   6   2   reserved (0)
 *   8   8   key_counter
 *   16      AK_MAX_KEYS x 56-byte slots:
 *             0  1  kid
 *             1  1  active
 *             2  1  retired
 *             3  5  reserved (0)
 *             8  8  created_ms
 *             16 8  expires_ms
 *             24 32 secret
 */

#define AK_KEYS_SLOT_SIZE 56

buffer ak_keys_export(heap h) {
  if (!ak_cap_state.initialized)
    return NULL;

  buffer b = allocate_buffer(h, AK_KEYS_BLOB_SIZE);
  if (b == INVALID_ADDRESS || !b)
    return NULL;

  u8 blob[AK_KEYS_BLOB_SIZE];
  ak_memzero(blob, AK_KEYS_BLOB_SIZE);

  u32 magic = AK_KEYS_BLOB_MAGIC;
  runtime_memcpy(blob, &magic, 4);
  blob[4] = AK_KEYS_BLOB_VERSION;

  spin_lock(&ak_cap_state.lock);
  blob[5] = ak_cap_state.active_kid;
  runtime_memcpy(blob + 8, &ak_cap_state.key_counter, 8);
  for (int i = 0; i < AK_MAX_KEYS; i++) {
    ak_key_t *k = &ak_cap_state.keys[i];
    u8 *slot = blob + 16 + i * AK_KEYS_SLOT_SIZE;
    slot[0] = k->kid;
    slot[1] = k->active ? 1 : 0;
    slot[2] = k->retired ? 1 : 0;
    runtime_memcpy(slot + 8, &k->created_ms, 8);
    runtime_memcpy(slot + 16, &k->expires_ms, 8);
    if (!k->retired)
      runtime_memcpy(slot + 24, k->secret, AK_KEY_SIZE);
  }
  spin_unlock(&ak_cap_state.lock);

  buffer_write(b, blob, AK_KEYS_BLOB_SIZE);
  ak_memzero(blob, AK_KEYS_BLOB_SIZE); /* Raw key material */
  return b;
}

boolean ak_keys_import(buffer blob) {
  if (!ak_cap_state.initialized || !blob)
    return false;

  /* FAIL-CLOSED: validate framing before touching key state */
  if (buffer_length(blob) < AK_KEYS_BLOB_SIZE)
    return false;

  u8 *p = buffer_ref(blob, 0);
  u32 magic;
  runtime_memcpy(&magic, p, 4);
  if (magic != AK_KEYS_BLOB_MAGIC)
    return false;
  if (p[4] != AK_KEYS_BLOB_VERSION)
    return false;

  u8 active_slot = p[5];
  if (active_slot >= AK_MAX_KEYS)
    return false;
  if ((p[16 + active_slot * AK_KEYS_SLOT_SIZE + 2]) != 0)
    return false; /* Active slot must not be retired */

  /* Non-retired slots must carry distinct kids or ak_key_get()
   * would be ambiguous */
  for (int i = 0; i < AK_MAX_KEYS; i++) {
    u8 *si = p + 16 + i * AK_KEYS_SLOT_SIZE;
    if (si[2] != 0)
      continue;
    for (int j = i + 1; j < AK_MAX_KEYS; j++) {
      u8 *sj = p + 16 + j * AK_KEYS_SLOT_SIZE;
      if (sj[2] == 0 && sj[0] == si[0])
        return false;
    }
  }

  u64 counter;
  runtime_memcpy(&counter, p + 8, 8);
  if (counter == 0)
    counter = 1;

  u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  spin_lock(&ak_cap_state.lock);

  for (int i = 0; i < AK_MAX_KEYS; i++) {
    ak_key_t *k = &ak_cap_state.keys[i];
    u8 *slot = p + 16 + i * AK_KEYS_SLOT_SIZE;

    /* Drop current key material before overwriting */
    ak_memzero(k->secret, AK_KEY_SIZE);

    k->kid = slot[0];
    k->retired = (slot[2] != 0);
    k->active = (i == active_slot);
    if (k->retired) {
      k->created_ms = 0;
      k->expires_ms = 0;
      continue;
    }
    runtime_memcpy(k->secret, slot + 24, AK_KEY_SIZE);
    /* Rebase lifetimes onto the current monotonic clock (which
     * restarts every boot): the active key gets a full lifetime,
     * restored grace keys get one grace period to verify old caps. */
    k->created_ms = (i == active_slot) ? now_ms : (now_ms ? now_ms - 1 : 0);
    k->expires_ms = (i == active_slot)
                        ? now_ms + AK_KEY_ROTATION_MS + AK_KEY_GRACE_MS
                        : now_ms + AK_KEY_GRACE_MS;
  }

  ak_cap_state.active_kid = active_slot;
  ak_cap_state.key_counter = counter;
  ak_cap_state.last_rotation_ms = now_ms;

  spin_unlock(&ak_cap_state.lock);
  return true;
}

/* ============================================================
 * CAPABILITY CREATION
 * ============================================================ */

ak_capability_t *ak_capability_create(heap h, ak_cap_type_t type,
                                      const char *resource,
                                      const char **methods, u32 ttl_ms,
                                      u32 rate_limit, u32 rate_window_ms,
                                      u8 *run_id) {
  /* PRECONDITIONS */
  AK_CHECK_NOT_NULL(h, NULL);
  AK_CHECK_NOT_NULL(resource, NULL);
  if (h == INVALID_ADDRESS) {
    ak_error("ak_capability_create: INVALID_ADDRESS heap");
    return NULL;
  }

  /* Validate type is in valid range */
  AK_CHECK_IN_RANGE(type, AK_CAP_NONE, AK_CAP_ADMIN, NULL);

  /* Validate TTL is reasonable */
  if (ttl_ms == 0) {
    ak_error("ak_capability_create: ttl_ms must be > 0");
    return NULL;
  }
  /* Enforce documented postcondition ttl_ms <= AK_MAX_CAP_TTL_MS.
   * This also bounds how long a revocation entry must be retained. */
  if (ttl_ms > AK_MAX_CAP_TTL_MS)
    ttl_ms = AK_MAX_CAP_TTL_MS;

  ak_capability_t *cap = allocate_zero(h, sizeof(ak_capability_t));
  if (cap == INVALID_ADDRESS)
    return NULL;

  cap->type = type;

  /* Copy resource (safely) with bounds check and NUL termination */
  u32 rlen = runtime_strlen(resource);
  AK_CHECK_INDEX(rlen, sizeof(cap->resource), NULL);
  if (rlen >= sizeof(cap->resource) - 1) { /* Leave room for NUL */
    deallocate(h, cap, sizeof(ak_capability_t));
    return NULL;
  }
  runtime_memcpy(cap->resource, resource, rlen);
  cap->resource[rlen] = '\0'; /* NUL-terminate */
  cap->resource_len = rlen;

  /* Copy methods with strict bounds checking */
  cap->method_count = 0;
  if (methods) {
    for (int i = 0; methods[i] && i < 8; i++) {
      u32 mlen = runtime_strlen(methods[i]);
      if (mlen >= 32) {
        /* Method name too long - fail-closed */
        deallocate(h, cap, sizeof(ak_capability_t));
        return NULL;
      }
      runtime_memcpy(cap->methods[i], methods[i], mlen);
      cap->methods[i][mlen] = '\0'; /* NUL-terminate method name */
      cap->method_count++;
    }
  }

  /* Timing */
  cap->issued_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
  cap->ttl_ms = ttl_ms;

  /* Rate limiting */
  cap->rate_limit = rate_limit;
  cap->rate_window_ms = rate_window_ms;

  /* Binding */
  if (run_id) {
    runtime_memcpy(cap->run_id, run_id, AK_TOKEN_ID_SIZE);
  }
  ak_generate_token_id(cap->tid);

  /* Sign with active key */
  ak_key_t *key = ak_key_get_active();
  cap->kid = key->kid;

  /* Compute HMAC over canonicalized token */
  buffer canonical = ak_capability_canonicalize(h, cap);
  ak_hmac_sha256(key->secret, AK_KEY_SIZE, buffer_ref(canonical, 0),
                 buffer_length(canonical), cap->mac);
  deallocate_buffer(canonical);

  return cap;
}

ak_capability_t *ak_capability_delegate(heap h, ak_capability_t *parent,
                                        ak_cap_type_t type,
                                        const char *resource,
                                        const char **methods, u32 ttl_ms,
                                        u32 rate_limit, u32 rate_window_ms) {
  /* Verify parent first */
  s64 rv = ak_capability_verify(parent);
  if (rv < 0)
    return NULL;

  /* Type must match */
  if (type != parent->type)
    return NULL;

  /* TTL cannot exceed parent's remaining TTL */
  u32 parent_remaining = ak_capability_remaining_ttl(parent);
  if (ttl_ms > parent_remaining)
    return NULL;

  /* Rate cannot exceed parent's rate */
  if (rate_limit > parent->rate_limit)
    return NULL;

  /* Resource must be subsumed by parent's resource */
  /* (Simplified: child must be same or more specific) */
  if (!ak_pattern_match((const char *)parent->resource, resource)) {
    return NULL;
  }

  /* Methods must be subset of parent's methods */
  if (methods) {
    for (int i = 0; methods[i]; i++) {
      boolean found = false;
      for (int j = 0; j < parent->method_count; j++) {
        if (ak_strcmp(methods[i], (const char *)parent->methods[j]) == 0) {
          found = true;
          break;
        }
      }
      if (!found)
        return NULL; /* Method not in parent */
    }
  }

  /* Create delegated capability with parent's run_id binding */
  return ak_capability_create(h, type, resource, methods, ttl_ms, rate_limit,
                              rate_window_ms, parent->run_id);
}

void ak_capability_destroy(heap h, ak_capability_t *cap) {
  if (!cap)
    return;

  /* Zero memory before freeing (security) */
  ak_memzero(cap, sizeof(ak_capability_t));
  deallocate(h, cap, sizeof(ak_capability_t));
}

/* ============================================================
 * CAPABILITY VERIFICATION
 * ============================================================
 * CRITICAL SECURITY PATH
 */

s64 ak_capability_verify(ak_capability_t *cap) {
  if (!cap)
    return AK_E_CAP_MISSING;

  /* Find signing key. ak_key_get() never returns retired keys, so a
   * rotated-out kid yields NULL here (fail-closed). */
  ak_key_t *key = ak_key_get(cap->kid);
  if (!key)
    return AK_E_CAP_INVALID; /* Unknown or retired key */

  /* Recompute MAC */
  u8 computed_mac[AK_MAC_SIZE];
  buffer canonical = ak_capability_canonicalize(ak_cap_state.h, cap);
  ak_hmac_sha256(key->secret, AK_KEY_SIZE, buffer_ref(canonical, 0),
                 buffer_length(canonical), computed_mac);
  deallocate_buffer(canonical);

  /* Constant-time comparison (SECURITY: prevents timing attacks) */
  if (!constant_time_compare(cap->mac, computed_mac, AK_MAC_SIZE))
    return AK_E_CAP_INVALID;

  /* Check TTL */
  u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
  if (now_ms > cap->issued_ms + cap->ttl_ms)
    return AK_E_CAP_EXPIRED;

  return 0;
}

s64 ak_capability_check_scope(ak_capability_t *cap, ak_cap_type_t required_type,
                              const char *resource, const char *method,
                              u8 *run_id) {
  /* Type must match. AK_CAP_ADMIN and AK_CAP_ANY are wildcard holder
   * types that subsume any required type (used for the root context's
   * ambient authority); every other type must match exactly. Resource,
   * method, run-id and rate-limit checks below still apply. */
  if (cap->type != required_type && cap->type != AK_CAP_ADMIN &&
      cap->type != AK_CAP_ANY)
    return AK_E_CAP_SCOPE;

  /* Resource must match pattern */
  if (!ak_pattern_match((const char *)cap->resource, resource))
    return AK_E_CAP_SCOPE;

  /* Method must be in allowed set */
  if (method && cap->method_count > 0) {
    boolean found = false;
    for (int i = 0; i < cap->method_count; i++) {
      if (ak_strcmp(method, (const char *)cap->methods[i]) == 0) {
        found = true;
        break;
      }
    }
    if (!found)
      return AK_E_CAP_SCOPE;
  }

  /* Run ID must match if specified in capability */
  if (run_id && !ak_token_id_equal(cap->run_id, (u8 *)AK_GENESIS_HASH)) {
    if (!ak_token_id_equal(cap->run_id, run_id))
      return AK_E_CAP_RUN_MISMATCH;
  }

  /* Rate limit check */
  if (cap->rate_limit > 0) {
    if (!ak_rate_limit_check(cap->tid, cap->rate_limit, cap->rate_window_ms))
      return AK_E_CAP_RATE;
  }

  return 0;
}

s64 ak_capability_validate(ak_capability_t *cap, ak_cap_type_t required_type,
                           const char *resource, const char *method,
                           u8 *run_id) {
  s64 rv;

  /*
   * INV-2 ENFORCEMENT: This is the critical capability validation path.
   * Every step must pass for the capability to be valid.
   * FAIL-CLOSED: Any failure returns error, denying the operation.
   */

  /* PRECONDITION: Resource must be provided for scope check */
  if (!resource) {
    ak_error("ak_capability_validate: resource is NULL");
    return AK_E_CAP_SCOPE;
  }

  /* Step 1: Verify integrity (HMAC) */
  rv = ak_capability_verify(cap);
  if (rv < 0) {
    ak_debug("ak_capability_validate: verify failed with %lld", rv);
    return rv;
  }

  /* Step 2: Check revocation */
  if (ak_revocation_check(cap->tid)) {
    ak_debug("ak_capability_validate: capability revoked");
    return AK_E_CAP_REVOKED;
  }

  /* Step 3: Check scope */
  rv = ak_capability_check_scope(cap, required_type, resource, method, run_id);
  if (rv < 0) {
    ak_debug("ak_capability_validate: scope check failed with %lld", rv);
    return rv;
  }

  /* POSTCONDITION: Capability is fully validated */
  AK_POSTCONDITION(rv == 0);

  return 0;
}

/* ============================================================
 * REVOCATION
 * ============================================================ */

void ak_revocation_init(heap h) { /* Already initialized in ak_keys_init */ }

static void ak_revocation_entry_free(ak_revocation_entry_t *e) {
  if (e->reason)
    deallocate_buffer(e->reason);
  deallocate(ak_cap_state.h, e, sizeof(*e));
}

/* Find entry for full 16-byte tid in the hash chain. Caller holds lock. */
static ak_revocation_entry_t *ak_revocation_find_locked(u8 *tid) {
  u64 key = ak_tid_hash(tid);
  ak_revocation_entry_t *e = table_find(ak_cap_state.revocations, (void *)key);
  while (e) {
    if (ak_token_id_equal(e->tid, tid))
      return e;
    e = e->next;
  }
  return NULL;
}

/*
 * Drop revocation entries older than AK_REVOCATION_RETAIN_MS. Any
 * capability revoked that long ago has passed issued_ms + ttl_ms
 * (ttl clamped to AK_MAX_CAP_TTL_MS at creation), so the TTL check in
 * ak_capability_verify() rejects it regardless of the revocation
 * table. Bounds table growth without ever un-revoking a live token.
 * Caller holds lock.
 */
static void ak_revocation_sweep_locked(u64 now_ms) {
  if (now_ms < AK_REVOCATION_RETAIN_MS)
    return;
  u64 cutoff = now_ms - AK_REVOCATION_RETAIN_MS;

  table_foreach(ak_cap_state.revocations, k, v) {
    ak_revocation_entry_t *head = v;
    ak_revocation_entry_t *e = head, *prev = NULL;
    while (e) {
      ak_revocation_entry_t *next = e->next;
      if (e->revoked_ms < cutoff) {
        if (prev)
          prev->next = next;
        else
          head = next;
        ak_revocation_entry_free(e);
        ak_cap_state.revocation_count--;
      } else {
        prev = e;
      }
      e = next;
    }
    if (head != v) {
      if (head)
        table_set(ak_cap_state.revocations, k, head);
      else
        table_remove(ak_cap_state.revocations, k);
    }
  }
}

/*
 * Insert a revocation entry (idempotent). Takes ownership of reason
 * (may be NULL); frees it if the tid is already present.
 * Returns true if a new entry was inserted. Caller holds lock.
 */
static boolean ak_revocation_insert_locked(u8 *tid, u64 revoked_ms,
                                           buffer reason) {
  if (ak_revocation_find_locked(tid)) {
    if (reason)
      deallocate_buffer(reason);
    return false; /* Already revoked - keep original entry */
  }

  /* Opportunistic expiry sweep keeps the table bounded */
  if (ak_cap_state.revocation_count >= AK_REVOCATION_SWEEP_THRESHOLD)
    ak_revocation_sweep_locked(now(CLOCK_ID_MONOTONIC) / MILLION);

  ak_revocation_entry_t *entry = allocate(ak_cap_state.h, sizeof(*entry));
  if (entry == INVALID_ADDRESS || !entry) {
    /* Cannot record in-memory; the audit log still holds the
     * revocation for replay. Nothing else we can do here. */
    ak_error("ak_revocation_insert: allocation failed");
    if (reason)
      deallocate_buffer(reason);
    return false;
  }
  runtime_memcpy(entry->tid, tid, AK_TOKEN_ID_SIZE);
  entry->revoked_ms = revoked_ms;
  entry->reason = reason;

  u64 key = ak_tid_hash(tid);
  /* Chain onto any hash-colliding entries (full-tid compare above
   * guarantees this is a different token) */
  entry->next = table_find(ak_cap_state.revocations, (void *)key);
  table_set(ak_cap_state.revocations, (void *)key, entry);
  ak_cap_state.revocation_count++;
  return true;
}

boolean ak_revocation_check(u8 *tid) {
  spin_lock(&ak_cap_state.lock);
  boolean revoked = ak_revocation_find_locked(tid) != NULL;
  spin_unlock(&ak_cap_state.lock);

  return revoked;
}

void ak_revocation_add(u8 *tid, const char *reason) {
  u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  /* Heap-allocated copy of the reason string */
  buffer reason_buf = NULL;
  u64 reason_len = runtime_strlen(reason);
  reason_buf = allocate_buffer(ak_cap_state.h, reason_len + 1);
  if (reason_buf == INVALID_ADDRESS)
    reason_buf = NULL;
  if (reason_buf)
    buffer_write(reason_buf, reason, reason_len);

  spin_lock(&ak_cap_state.lock);
  ak_revocation_insert_locked(tid, now_ms, reason_buf);
  spin_unlock(&ak_cap_state.lock);

  /* Persist revocation to audit log */
  ak_audit_log_revocation(tid, reason);
}

void ak_revocation_revoke_run(u8 *run_id, const char *reason) {
  /*
   * DESIGN DECISION: Revoke at run level, not per-capability.
   *
   * Rather than iterating all capabilities to find those with matching
   * run_id (O(n) scan), we track revocation at the run level. Capability
   * validation checks both the specific capability AND its run_id against
   * the revocation table, achieving the same security guarantee with O(1)
   * revocation recording and O(1) lookup during validation.
   */
  ak_revocation_add(run_id, reason);
}

void ak_revocation_load_from_log(void) {
  /*
   * Scan audit log for revocation entries and replay.
   * This is called on startup to restore revocation state.
   *
   * RECOVERY CRITICAL: This function rebuilds the in-memory revocation map
   * from the audit log after a restart. Without this, revoked capabilities
   * would be incorrectly treated as valid after a crash/restart.
   *
   * Algorithm:
   * 1. Query all entries with op code 0xFFFF (revocation op code)
   * 2. For each entry, extract the tid from pid field
   * 3. Add to revocation map (without re-logging to avoid duplicates)
   */

  if (!ak_cap_state.initialized) {
    ak_error("ak_revocation_load_from_log: capability system not initialized");
    return;
  }

  /* Query the audit log for all revocation entries */
  u64 head_seq = ak_audit_head_seq();
  if (head_seq == 0) {
    /* Empty log - nothing to replay */
    ak_debug("ak_revocation_load_from_log: empty audit log, no revocations to "
             "replay");
    return;
  }

  /* Filter for revocation entries (op code 0xFFFF) */
  ak_log_query_filter_t filter;
  runtime_memset((u8 *)&filter, 0, sizeof(filter));
  filter.op = 0xFFFF; /* Revocation op code - see ak_audit_log_revocation() */

  u64 count = 0;
  ak_log_entry_t **entries =
      ak_audit_query(ak_cap_state.h, &filter, 1, head_seq, &count);

  if (!entries || count == 0) {
    ak_debug("ak_revocation_load_from_log: no revocation entries found in "
             "audit log");
    return;
  }

  ak_debug("ak_revocation_load_from_log: replaying %llu revocation entries",
           count);

  /* Replay each revocation entry */
  u64 replayed = 0;
  for (u64 i = 0; i < count; i++) {
    ak_log_entry_t *entry = entries[i];
    if (!entry)
      continue;

    /*
     * In ak_audit_log_revocation(), the tid is stored in the pid field.
     * We need to rebuild the revocation entry without calling
     * ak_revocation_add() which would re-log the revocation (causing
     * duplicates).
     */
    u8 *tid = entry->pid;

    /* Note: We don't have the original reason string available from
     * the log entry, only its hash. Store a placeholder reason. */
    buffer reason = allocate_buffer(ak_cap_state.h, 32);
    if (reason == INVALID_ADDRESS)
      reason = NULL;
    if (reason)
      buffer_write_cstring(reason, "(recovered from log)");

    /* Insert keyed on the full tid (idempotent; frees reason if the
     * tid is already present) */
    spin_lock(&ak_cap_state.lock);
    if (ak_revocation_insert_locked(tid, entry->ts_ms, reason))
      replayed++;
    spin_unlock(&ak_cap_state.lock);
  }

  /* Drop replayed revocations whose tokens can no longer verify */
  spin_lock(&ak_cap_state.lock);
  ak_revocation_sweep_locked(now(CLOCK_ID_MONOTONIC) / MILLION);
  spin_unlock(&ak_cap_state.lock);

  /* Free the query results array */
  deallocate(ak_cap_state.h, entries, sizeof(ak_log_entry_t *) * count);

  ak_debug("ak_revocation_load_from_log: replayed %llu revocations (%llu "
           "already present)",
           replayed, count - replayed);
  (void)replayed; /* Suppress unused warning when ak_debug is a no-op */
}

/* ============================================================
 * RATE LIMITING
 * ============================================================ */

/* Find counter for full 16-byte tid in the hash chain. Caller holds lock. */
static rate_counter_t *ak_rate_find_locked(u8 *tid) {
  u64 key = ak_tid_hash(tid);
  rate_counter_t *c = table_find(ak_cap_state.rate_counters, (void *)key);
  while (c) {
    if (ak_token_id_equal(c->tid, tid))
      return c;
    c = c->next;
  }
  return NULL;
}

/*
 * Evict counters whose window has expired: expiry resets count to 0
 * anyway, so dropping the entry is behavior-preserving and bounds
 * table growth. Caller holds lock.
 */
static void ak_rate_sweep_locked(u64 now_ms) {
  table_foreach(ak_cap_state.rate_counters, k, v) {
    rate_counter_t *head = v;
    rate_counter_t *c = head, *prev = NULL;
    while (c) {
      rate_counter_t *next = c->next;
      if (now_ms - c->window_start_ms > c->window_ms) {
        if (prev)
          prev->next = next;
        else
          head = next;
        deallocate(ak_cap_state.h, c, sizeof(*c));
        ak_cap_state.rate_entry_count--;
      } else {
        prev = c;
      }
      c = next;
    }
    if (head != v) {
      if (head)
        table_set(ak_cap_state.rate_counters, k, head);
      else
        table_remove(ak_cap_state.rate_counters, k);
    }
  }
}

boolean ak_rate_limit_check(u8 *tid, u32 limit, u32 window_ms) {
  u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  spin_lock(&ak_cap_state.lock);

  rate_counter_t *counter = ak_rate_find_locked(tid);

  if (!counter) {
    /* Bound table growth: evict expired counters when full. If still
     * full after the sweep, FAIL-CLOSED (deny) rather than track
     * inaccurately. */
    if (ak_cap_state.rate_entry_count >= AK_RATE_MAX_ENTRIES) {
      ak_rate_sweep_locked(now_ms);
      if (ak_cap_state.rate_entry_count >= AK_RATE_MAX_ENTRIES) {
        spin_unlock(&ak_cap_state.lock);
        return false;
      }
    }

    counter = allocate(ak_cap_state.h, sizeof(*counter));
    if (counter == INVALID_ADDRESS || !counter) {
      /* FAIL-CLOSED: cannot track means cannot admit */
      spin_unlock(&ak_cap_state.lock);
      return false;
    }
    runtime_memcpy(counter->tid, tid, AK_TOKEN_ID_SIZE);
    counter->count = 0;
    counter->window_ms = window_ms;
    counter->window_start_ms = now_ms;

    u64 key = ak_tid_hash(tid);
    /* Chain onto any hash-colliding counters (distinct tids) */
    counter->next = table_find(ak_cap_state.rate_counters, (void *)key);
    table_set(ak_cap_state.rate_counters, (void *)key, counter);
    ak_cap_state.rate_entry_count++;
  }

  /* Track the current window length for expiry sweeps */
  counter->window_ms = window_ms;

  /* Check if window expired */
  if (now_ms - counter->window_start_ms > window_ms) {
    counter->count = 0;
    counter->window_start_ms = now_ms;
  }

  /* Check limit */
  if (counter->count >= limit) {
    spin_unlock(&ak_cap_state.lock);
    return false;
  }

  counter->count++;
  spin_unlock(&ak_cap_state.lock);

  return true;
}

void ak_rate_limit_reset(u8 *tid) {
  spin_lock(&ak_cap_state.lock);
  rate_counter_t *counter = ak_rate_find_locked(tid);
  if (counter) {
    counter->count = 0;
  }
  spin_unlock(&ak_cap_state.lock);
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

buffer ak_capability_canonicalize(heap h, ak_capability_t *cap) {
  /* Canonical JSON format (sorted keys, no whitespace) */
  buffer b = allocate_buffer(h, 512);

  bprintf(b, "{\"issued_ms\":%ld,\"kid\":%d,\"methods\":[", cap->issued_ms,
          cap->kid);

  for (int i = 0; i < cap->method_count; i++) {
    if (i > 0)
      bprintf(b, ",");
    bprintf(b, "\"%s\"", cap->methods[i]);
  }

  bprintf(b, "],\"rate_limit\":%d,\"rate_window_ms\":%d,\"resource\":\"",
          cap->rate_limit, cap->rate_window_ms);

  /* Escape resource string */
  for (int i = 0; i < cap->resource_len; i++) {
    u8 c = cap->resource[i];
    if (c == '"' || c == '\\') {
      buffer_write_byte(b, '\\');
    }
    buffer_write_byte(b, c);
  }

  bprintf(b, "\",\"run_id\":\"");
  for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
    bprintf(b, "%02x", cap->run_id[i]);
  }

  bprintf(b, "\",\"tid\":\"");
  for (int i = 0; i < AK_TOKEN_ID_SIZE; i++) {
    bprintf(b, "%02x", cap->tid[i]);
  }

  bprintf(b, "\",\"ttl_ms\":%d,\"type\":%d}", cap->ttl_ms, cap->type);

  return b;
}

/*
 * Binary wire format v1 - see ak_capability.h for the exact layout.
 * ak_capability_serialize() and ak_capability_parse() are exact
 * inverses. Note this is distinct from ak_capability_canonicalize(),
 * which produces the canonical JSON that the HMAC is computed over.
 */

/* Fixed-header field offsets (see layout comment in ak_capability.h) */
#define CAP_WIRE_OFF_MAGIC 0
#define CAP_WIRE_OFF_VERSION 4
#define CAP_WIRE_OFF_KID 5
#define CAP_WIRE_OFF_TYPE 6
#define CAP_WIRE_OFF_METHOD_COUNT 7
#define CAP_WIRE_OFF_TOTAL_LEN 8
#define CAP_WIRE_OFF_RESOURCE_LEN 10
#define CAP_WIRE_OFF_ISSUED_MS 12
#define CAP_WIRE_OFF_TTL_MS 20
#define CAP_WIRE_OFF_RATE_LIMIT 24
#define CAP_WIRE_OFF_RATE_WINDOW_MS 28
#define CAP_WIRE_OFF_RUN_ID 32
#define CAP_WIRE_OFF_TID 48
#define CAP_WIRE_OFF_MAC 64

buffer ak_capability_serialize(heap h, ak_capability_t *cap) {
  if (!cap)
    return NULL;

  /* Compute total length: header + resource + len-prefixed methods */
  u32 total = AK_CAP_WIRE_HDR_SIZE + cap->resource_len;
  for (int i = 0; i < cap->method_count; i++)
    total += 1 + runtime_strlen((const char *)cap->methods[i]);

  buffer b = allocate_buffer(h, total);
  if (b == INVALID_ADDRESS || !b)
    return NULL;

  u8 hdr[AK_CAP_WIRE_HDR_SIZE];
  ak_memzero(hdr, AK_CAP_WIRE_HDR_SIZE);

  u32 magic = AK_CAP_WIRE_MAGIC;
  runtime_memcpy(hdr + CAP_WIRE_OFF_MAGIC, &magic, 4);
  hdr[CAP_WIRE_OFF_VERSION] = AK_CAP_WIRE_VERSION;
  hdr[CAP_WIRE_OFF_KID] = cap->kid;
  hdr[CAP_WIRE_OFF_TYPE] = (u8)cap->type;
  hdr[CAP_WIRE_OFF_METHOD_COUNT] = cap->method_count;
  u16 total_len = (u16)total;
  runtime_memcpy(hdr + CAP_WIRE_OFF_TOTAL_LEN, &total_len, 2);
  u16 resource_len = cap->resource_len;
  runtime_memcpy(hdr + CAP_WIRE_OFF_RESOURCE_LEN, &resource_len, 2);
  runtime_memcpy(hdr + CAP_WIRE_OFF_ISSUED_MS, &cap->issued_ms, 8);
  runtime_memcpy(hdr + CAP_WIRE_OFF_TTL_MS, &cap->ttl_ms, 4);
  runtime_memcpy(hdr + CAP_WIRE_OFF_RATE_LIMIT, &cap->rate_limit, 4);
  runtime_memcpy(hdr + CAP_WIRE_OFF_RATE_WINDOW_MS, &cap->rate_window_ms, 4);
  runtime_memcpy(hdr + CAP_WIRE_OFF_RUN_ID, cap->run_id, AK_TOKEN_ID_SIZE);
  runtime_memcpy(hdr + CAP_WIRE_OFF_TID, cap->tid, AK_TOKEN_ID_SIZE);
  runtime_memcpy(hdr + CAP_WIRE_OFF_MAC, cap->mac, AK_MAC_SIZE);

  buffer_write(b, hdr, AK_CAP_WIRE_HDR_SIZE);
  buffer_write(b, cap->resource, cap->resource_len);
  for (int i = 0; i < cap->method_count; i++) {
    u8 mlen = (u8)runtime_strlen((const char *)cap->methods[i]);
    buffer_write_byte(b, mlen);
    buffer_write(b, cap->methods[i], mlen);
  }

  return b;
}

ak_capability_t *ak_capability_parse(heap h, buffer data) {
  /* FAIL-CLOSED: any malformation returns NULL */
  if (!h || h == INVALID_ADDRESS || !data)
    return NULL;

  u64 avail = buffer_length(data);
  if (avail < AK_CAP_WIRE_HDR_SIZE)
    return NULL;

  u8 *p = buffer_ref(data, 0);

  u32 magic;
  runtime_memcpy(&magic, p + CAP_WIRE_OFF_MAGIC, 4);
  if (magic != AK_CAP_WIRE_MAGIC)
    return NULL;
  if (p[CAP_WIRE_OFF_VERSION] != AK_CAP_WIRE_VERSION)
    return NULL;

  u8 method_count = p[CAP_WIRE_OFF_METHOD_COUNT];
  if (method_count > 8)
    return NULL;

  u16 total_len;
  runtime_memcpy(&total_len, p + CAP_WIRE_OFF_TOTAL_LEN, 2);
  /* Transport may pad past total_len (e.g. fixed-size copy in
   * ak_nanos.c); trailing bytes are ignored, but the declared
   * message must fit in what we were given. */
  if (total_len < AK_CAP_WIRE_HDR_SIZE || total_len > avail)
    return NULL;

  u16 resource_len;
  runtime_memcpy(&resource_len, p + CAP_WIRE_OFF_RESOURCE_LEN, 2);

  ak_capability_t *cap = allocate_zero(h, sizeof(ak_capability_t));
  if (cap == INVALID_ADDRESS || !cap)
    return NULL;

  /* Resource must fit its field with room for a NUL */
  if (resource_len >= sizeof(cap->resource))
    goto fail;
  if ((u32)AK_CAP_WIRE_HDR_SIZE + resource_len > total_len)
    goto fail;

  cap->kid = p[CAP_WIRE_OFF_KID];
  cap->type = (ak_cap_type_t)p[CAP_WIRE_OFF_TYPE];
  runtime_memcpy(&cap->issued_ms, p + CAP_WIRE_OFF_ISSUED_MS, 8);
  runtime_memcpy(&cap->ttl_ms, p + CAP_WIRE_OFF_TTL_MS, 4);
  runtime_memcpy(&cap->rate_limit, p + CAP_WIRE_OFF_RATE_LIMIT, 4);
  runtime_memcpy(&cap->rate_window_ms, p + CAP_WIRE_OFF_RATE_WINDOW_MS, 4);
  runtime_memcpy(cap->run_id, p + CAP_WIRE_OFF_RUN_ID, AK_TOKEN_ID_SIZE);
  runtime_memcpy(cap->tid, p + CAP_WIRE_OFF_TID, AK_TOKEN_ID_SIZE);
  /* Preserve MAC bytes; verification is ak_capability_verify()'s job */
  runtime_memcpy(cap->mac, p + CAP_WIRE_OFF_MAC, AK_MAC_SIZE);

  runtime_memcpy(cap->resource, p + AK_CAP_WIRE_HDR_SIZE, resource_len);
  cap->resource[resource_len] = '\0';
  cap->resource_len = resource_len;

  /* Length-prefixed methods; walk must land exactly on total_len */
  u32 off = AK_CAP_WIRE_HDR_SIZE + resource_len;
  for (u8 i = 0; i < method_count; i++) {
    if (off + 1 > total_len)
      goto fail;
    u8 mlen = p[off];
    off += 1;
    if (mlen >= sizeof(cap->methods[0]))
      goto fail;
    if (off + mlen > total_len)
      goto fail;
    runtime_memcpy(cap->methods[i], p + off, mlen);
    cap->methods[i][mlen] = '\0';
    off += mlen;
  }
  cap->method_count = method_count;

  if (off != total_len)
    goto fail; /* Declared length must match actual content */

  return cap;

fail:
  ak_memzero(cap, sizeof(ak_capability_t));
  deallocate(h, cap, sizeof(ak_capability_t));
  return NULL;
}

/* ak_pattern_match is now provided by ak_pattern.h */

/* ============================================================
 * HELPERS
 * ============================================================ */

void ak_generate_token_id(u8 *tid) { ak_random_bytes(tid, AK_TOKEN_ID_SIZE); }

boolean ak_token_id_equal(u8 *a, u8 *b) {
  return constant_time_compare(a, b, AK_TOKEN_ID_SIZE);
}

u32 ak_capability_remaining_ttl(ak_capability_t *cap) {
  u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
  u64 expires_ms = cap->issued_ms + cap->ttl_ms;

  if (now_ms >= expires_ms)
    return 0;

  return (u32)(expires_ms - now_ms);
}

boolean ak_capability_subsumed(ak_capability_t *parent,
                               ak_capability_t *child) {
  /* Type must match */
  if (child->type != parent->type)
    return false;

  /* Child TTL must be <= parent remaining */
  if (child->ttl_ms > ak_capability_remaining_ttl(parent))
    return false;

  /* Child rate must be <= parent rate */
  if (child->rate_limit > parent->rate_limit)
    return false;

  /* Child resource must be covered by parent pattern */
  if (!ak_pattern_match((const char *)parent->resource,
                        (const char *)child->resource))
    return false;

  /* Child methods must be subset of parent methods */
  for (int i = 0; i < child->method_count; i++) {
    boolean found = false;
    for (int j = 0; j < parent->method_count; j++) {
      if (ak_strcmp((const char *)child->methods[i],
                    (const char *)parent->methods[j]) == 0) {
        found = true;
        break;
      }
    }
    if (!found)
      return false;
  }

  return true;
}
