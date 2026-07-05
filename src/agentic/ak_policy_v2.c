/*
 * Authority Kernel - Policy V2 Implementation (Deny-by-Default)
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * OWNER: Agent B (Policy + Bootstrap)
 *
 * This file implements the P0 deny-by-default policy engine.
 *
 * SECURITY INVARIANTS:
 *   - DENY-BY-DEFAULT: Missing policy = fail closed (deny all)
 *   - All patterns are matched exactly; no implicit wildcards
 *   - All checks fail-closed on any error
 *   - Suggestions never reveal internal state beyond the denied request
 */

#include "ak_policy_v2.h"
#include "ak_compat.h"
#include "ak_pattern.h"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */

static struct {
  heap h;
  boolean initialized;
  ak_policy_v2_t *current_policy;
} ak_policy_v2_state;

/*
 * HMAC-SHA256 policy verification key (symmetric authentication, not an
 * Ed25519 digital signature). When configured, ak_policy_v2_load()
 * rejects unsigned/invalid policies (fail-closed).
 */
static struct {
  u8 key[AK_KEY_SIZE];
  boolean configured;
} ak_policy_v2_verify_key;

void ak_policy_v2_set_verification_key(const u8 *key) {
  if (!key) {
    runtime_memset(ak_policy_v2_verify_key.key, 0, AK_KEY_SIZE);
    ak_policy_v2_verify_key.configured = false;
    return;
  }
  runtime_memcpy(ak_policy_v2_verify_key.key, key, AK_KEY_SIZE);
  ak_policy_v2_verify_key.configured = true;
}

/* ============================================================
 * BUILT-IN PROFILES (JSON)
 * ============================================================ */

/* Tier 1: Static/musl - minimal access for statically linked binaries */
const char *AK_PROFILE_TIER1_MUSL = "{"
                                    "  \"fs\": {"
                                    "    \"read\": [\"/proc/self/**\"]"
                                    "  },"
                                    "  \"net\": {"
                                    "    \"dns\": []"
                                    "  }"
                                    "}";

/* Tier 2: Dynamic/glibc - additional library access */
const char *AK_PROFILE_TIER2_GLIBC = "{"
                                     "  \"fs\": {"
                                     "    \"read\": ["
                                     "      \"/lib/**\","
                                     "      \"/lib64/**\","
                                     "      \"/etc/ld.so.cache\","
                                     "      \"/etc/ld.so.preload\","
                                     "      \"/etc/nsswitch.conf\","
                                     "      \"/etc/resolv.conf\","
                                     "      \"/proc/self/**\""
                                     "    ]"
                                     "  }"
                                     "}";

/* ============================================================
 * FORWARD DECLARATIONS
 * ============================================================ */

static void compute_policy_hash(const u8 *json, u64 len, u8 *hash_out);
static boolean parse_json_policy(ak_policy_v2_t *policy, const u8 *json,
                                 u64 len);
static void free_fs_rules(heap h, ak_fs_rule_v2_t *rules);
static void free_net_rules(heap h, ak_net_rule_v2_t *rules);
static void free_dns_rules(heap h, ak_dns_rule_v2_t *rules);
static void free_tool_rules(heap h, ak_tool_rule_v2_t *rules);
static void free_wasm_rules(heap h, ak_wasm_rule_v2_t *rules);
static void free_infer_rules(heap h, ak_infer_rule_v2_t *rules);

/* ============================================================
 * STRING UTILITIES
 * ============================================================ */

static u64 local_strlen(const char *s) {
  if (!s)
    return 0;
  u64 len = 0;
  while (s[len])
    len++;
  return len;
}

static void local_strncpy(char *dest, const char *src, u64 n) {
  if (!dest || !src || n == 0)
    return;
  u64 i;
  for (i = 0; i < n - 1 && src[i]; i++) {
    dest[i] = src[i];
  }
  dest[i] = '\0';
}

static int local_strcmp(const char *s1, const char *s2) {
  if (!s1 || !s2)
    return s1 ? 1 : (s2 ? -1 : 0);
  while (*s1 && (*s1 == *s2)) {
    s1++;
    s2++;
  }
  return (unsigned char)*s1 - (unsigned char)*s2;
}

static int local_strncmp(const char *s1, const char *s2, u64 n) {
  if (!s1 || !s2)
    return s1 ? 1 : (s2 ? -1 : 0);
  for (u64 i = 0; i < n; i++) {
    if (s1[i] != s2[i])
      return (unsigned char)s1[i] - (unsigned char)s2[i];
    if (s1[i] == '\0')
      return 0;
  }
  return 0;
}

/* ============================================================
 * HASH COMPUTATION
 * ============================================================ */

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
 * Compute cryptographically secure hash for policy identification.
 * Uses SHA-256 for collision resistance and integrity verification.
 */
static void compute_policy_hash(const u8 *json, u64 len, u8 *hash_out) {
  runtime_memset(hash_out, 0, AK_HASH_SIZE);
  if (!json || len == 0)
    return;

  ak_sha256(json, (u32)len, hash_out);
}

/* ============================================================
 * POLICY INTEGRITY (HMAC-SHA256)
 * ============================================================
 * Symmetric authentication of the policy document. NOT an Ed25519
 * digital signature: any key holder can forge tags, so this protects
 * against tampering by parties without the key only.
 *
 * Tag = HMAC-SHA256(key, SHA-256(document with "signature" value
 * emptied)). The host signer builds the document with "signature":"",
 * computes the tag over its hash, and inserts the hex tag in place.
 */

/* HMAC-SHA256 for short messages (data_len <= AK_HASH_SIZE) */
static boolean v2_hmac_sha256(const u8 *key, u32 key_len, const u8 *data,
                              u32 data_len, u8 *output) {
  u8 key_block[64];
  u8 pad_buf[64 + AK_HASH_SIZE];
  u8 inner_hash[32];

  if (data_len > AK_HASH_SIZE)
    return false;

  runtime_memset(key_block, 0, 64);
  if (key_len > 64)
    ak_sha256(key, key_len, key_block);
  else
    runtime_memcpy(key_block, key, key_len);

  /* Inner hash: H((key ^ ipad) || message) */
  for (int i = 0; i < 64; i++)
    pad_buf[i] = key_block[i] ^ 0x36;
  runtime_memcpy(pad_buf + 64, data, data_len);
  ak_sha256(pad_buf, 64 + data_len, inner_hash);

  /* Outer hash: H((key ^ opad) || inner_hash) */
  for (int i = 0; i < 64; i++)
    pad_buf[i] = key_block[i] ^ 0x5c;
  runtime_memcpy(pad_buf + 64, inner_hash, 32);
  ak_sha256(pad_buf, 64 + 32, output);

  runtime_memset(key_block, 0, 64);
  runtime_memset(pad_buf, 0, sizeof(pad_buf));
  runtime_memset(inner_hash, 0, 32);
  return true;
}

/* Constant-time comparison to prevent timing attacks */
static boolean v2_constant_time_compare(const u8 *a, const u8 *b, u32 len) {
  u8 diff = 0;
  for (u32 i = 0; i < len; i++)
    diff |= a[i] ^ b[i];
  return diff == 0;
}

static int v2_hex_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Decode exactly 2 * out_len hex chars into out */
static boolean v2_parse_hex(const char *hex, u8 *out, u64 out_len) {
  for (u64 i = 0; i < out_len; i++) {
    int hi = v2_hex_nibble(hex[i * 2]);
    int lo = v2_hex_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return false;
    out[i] = (u8)((hi << 4) | lo);
  }
  return true;
}

/*
 * Locate the top-level "signature" string value in the raw document.
 * On success, vstart/vend delimit the value characters (exclusive of
 * the surrounding quotes).
 */
static boolean find_signature_value_span(const u8 *json, u64 len, u64 *vstart,
                                         u64 *vend) {
  static const char sig_key[] = "\"signature\"";
  const u64 key_len = sizeof(sig_key) - 1;

  for (u64 i = 0; i + key_len < len; i++) {
    if (local_strncmp((const char *)&json[i], sig_key, key_len) != 0)
      continue;

    u64 j = i + key_len;
    while (j < len && (json[j] == ' ' || json[j] == '\t' || json[j] == '\n' ||
                       json[j] == '\r'))
      j++;
    if (j >= len || json[j] != ':')
      continue;
    j++;
    while (j < len && (json[j] == ' ' || json[j] == '\t' || json[j] == '\n' ||
                       json[j] == '\r'))
      j++;
    if (j >= len || json[j] != '"')
      continue;
    j++;

    u64 start = j;
    while (j < len && json[j] != '"') {
      if (json[j] == '\\' && j + 1 < len)
        j++;
      j++;
    }
    if (j >= len)
      return false; /* Unterminated value */

    *vstart = start;
    *vend = j;
    return true;
  }
  return false;
}

/*
 * Compute the signed-content hash: SHA-256 of the document with the
 * "signature" value emptied. If no signature member exists, the whole
 * document is hashed.
 */
static boolean compute_signed_content_hash(heap h, const u8 *json, u64 len,
                                           u8 *hash_out) {
  u64 vstart, vend;

  if (!find_signature_value_span(json, len, &vstart, &vend)) {
    compute_policy_hash(json, len, hash_out);
    return true;
  }

  u8 *scratch = allocate(h, len);
  if (!scratch)
    return false;

  runtime_memcpy(scratch, json, vstart);
  runtime_memcpy(scratch + vstart, json + vend, len - vend);
  compute_policy_hash(scratch, len - (vend - vstart), hash_out);

  deallocate(h, scratch, len);
  return true;
}

/* ============================================================
 * JSON PARSING
 * ============================================================
 * Simple hand-rolled JSON parser for P0 policy format.
 * Limitations:
 *   - No nested objects beyond expected structure
 *   - No escape sequences (except \")
 *   - Arrays are string-only
 *   - Numbers are u64 only
 */

/* Skip whitespace */
static const u8 *skip_ws(const u8 *p, const u8 *end) {
  while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
    p++;
  return p;
}

/* Parse a JSON string, return end position */
/* SECURITY FIX (S1-4): Proper JSON escape sequence handling */
static const u8 *parse_string(const u8 *p, const u8 *end, char *out,
                              u64 max_len) {
  if (p >= end || *p != '"')
    return NULL;
  p++;

  u64 i = 0;
  while (p < end && *p != '"') {
    if (*p == '\\' && p + 1 < end) {
      p++;
      char escaped = 0;
      switch (*p) {
      case '"':
        escaped = '"';
        break;
      case '\\':
        escaped = '\\';
        break;
      case 'n':
        escaped = '\n';
        break;
      case 'r':
        escaped = '\r';
        break;
      case 't':
        escaped = '\t';
        break;
      case '/':
        escaped = '/';
        break;
      case 'u':      /* Reject unicode escapes in security-critical paths */
        return NULL; /* Parse error - unicode not supported */
      default:       /* Unknown escape - reject for security */
        return NULL;
      }
      if (i < max_len - 1)
        out[i++] = escaped;
    } else {
      if (i < max_len - 1)
        out[i++] = *p;
    }
    p++;
  }
  if (p < end && *p == '"')
    p++;
  out[i] = '\0';
  return p;
}

/* Parse a JSON number (u64 only) with overflow protection */
static const u8 *parse_number(const u8 *p, const u8 *end, u64 *out) {
  *out = 0;
  while (p < end && *p >= '0' && *p <= '9') {
    u64 digit = *p - '0';
    /* FIX(S0-2): Check for overflow before multiplication */
    if (*out > (UINT64_MAX - digit) / 10) {
      *out = UINT64_MAX; /* Saturate instead of wrap */
      /* Skip remaining digits */
      while (p < end && *p >= '0' && *p <= '9')
        p++;
      return p;
    }
    *out = (*out * 10) + digit;
    p++;
  }
  return p;
}

/* FIX(S2-1): Maximum JSON nesting depth to prevent stack exhaustion */
#define MAX_JSON_DEPTH 32

/* Skip a JSON value (string, number, object, array, bool, null) */
static const u8 *skip_value(const u8 *p, const u8 *end) {
  p = skip_ws(p, end);
  if (p >= end)
    return NULL;

  if (*p == '"') {
    p++;
    while (p < end && *p != '"') {
      if (*p == '\\' && p + 1 < end)
        p++;
      p++;
    }
    return (p < end) ? p + 1 : NULL;
  } else if (*p == '{') {
    int depth = 1;
    p++;
    while (p < end && depth > 0) {
      if (*p == '{') {
        depth++;
        /* FIX(S2-1): Reject too-deep nesting */
        if (depth > MAX_JSON_DEPTH)
          return NULL;
      } else if (*p == '}')
        depth--;
      else if (*p == '"') {
        p++;
        while (p < end && *p != '"') {
          if (*p == '\\' && p + 1 < end)
            p++;
          p++;
        }
      }
      p++;
    }
    return p;
  } else if (*p == '[') {
    int depth = 1;
    p++;
    while (p < end && depth > 0) {
      if (*p == '[') {
        depth++;
        /* FIX(S2-1): Reject too-deep nesting */
        if (depth > MAX_JSON_DEPTH)
          return NULL;
      } else if (*p == ']')
        depth--;
      else if (*p == '"') {
        p++;
        while (p < end && *p != '"') {
          if (*p == '\\' && p + 1 < end)
            p++;
          p++;
        }
      }
      p++;
    }
    return p;
  } else if (*p >= '0' && *p <= '9') {
    while (p < end && ((*p >= '0' && *p <= '9') || *p == '.'))
      p++;
    return p;
    /* FIX(S2-3): Check remaining buffer length before comparing */
  } else if ((end - p >= 4) && local_strncmp((const char *)p, "true", 4) == 0) {
    return p + 4;
  } else if ((end - p >= 5) &&
             local_strncmp((const char *)p, "false", 5) == 0) {
    return p + 5;
  } else if ((end - p >= 4) && local_strncmp((const char *)p, "null", 4) == 0) {
    return p + 4;
  }
  return NULL;
}

/* Parse array of strings */
typedef void (*string_array_cb)(void *ctx, const char *str);

static const u8 *parse_string_array(const u8 *p, const u8 *end,
                                    string_array_cb cb, void *ctx) {
  p = skip_ws(p, end);
  if (p >= end || *p != '[')
    return NULL;
  p++;

  while (p < end) {
    p = skip_ws(p, end);
    if (p >= end)
      return NULL;
    if (*p == ']')
      return p + 1;

    char str[AK_POLICY_V2_MAX_PATTERN];
    p = parse_string(p, end, str, sizeof(str));
    if (!p)
      return NULL;

    if (cb)
      cb(ctx, str);

    p = skip_ws(p, end);
    if (p >= end)
      return NULL;
    if (*p == ',')
      p++;
    else if (*p != ']')
      return NULL;
  }
  return NULL;
}

/* ============================================================
 * JSON SCHEMA VALIDATION (P2-2)
 * ============================================================
 * Validates policy JSON structure:
 *   - Version field must be supported (currently "1.0")
 *   - Unknown keys are safely skipped (already handled by parser)
 *   - Required structural constraints are checked post-parse
 */

#define AK_POLICY_SUPPORTED_VERSION_MAJOR 1
#define AK_POLICY_SUPPORTED_VERSION_MINOR 0

/*
 * Validate policy version string.
 * Returns true if version is supported, false otherwise.
 * Supported format: "MAJOR.MINOR" (e.g., "1.0")
 */
static boolean validate_policy_version(const char *version) {
  if (!version || version[0] == '\0')
    return true; /* No version = accept (for backward compatibility) */

  /* Parse major version */
  int major = 0;
  int minor = 0;
  const char *p = version;

  while (*p >= '0' && *p <= '9') {
    major = major * 10 + (*p - '0');
    p++;
  }

  if (*p != '.')
    return false; /* Invalid format */
  p++;

  while (*p >= '0' && *p <= '9') {
    minor = minor * 10 + (*p - '0');
    p++;
  }

  if (*p != '\0')
    return false; /* Trailing characters */

  /* Check compatibility: major must match, minor can be <= supported */
  if (major != AK_POLICY_SUPPORTED_VERSION_MAJOR)
    return false;

  if (minor > AK_POLICY_SUPPORTED_VERSION_MINOR)
    return false;

  return true;
}

/*
 * Post-parse validation of policy structure.
 * Called after JSON parsing to verify semantic constraints.
 */
static boolean validate_policy_schema(ak_policy_v2_t *policy) {
  if (!policy)
    return false;

  /* Validate version if specified */
  if (policy->version[0] != '\0') {
    if (!validate_policy_version(policy->version)) {
      rprintf("[AK] Policy version '%s' not supported (expected %d.%d or "
              "earlier)\n",
              policy->version, AK_POLICY_SUPPORTED_VERSION_MAJOR,
              AK_POLICY_SUPPORTED_VERSION_MINOR);
      return false;
    }
  }

  /* Validate budget constraints (must be reasonable) */
  if (policy->budgets.tool_calls > 1000000) {
    rprintf(
        "[AK] Warning: tool_calls budget %llu exceeds recommended maximum\n",
        (unsigned long long)policy->budgets.tool_calls);
    /* Non-fatal: just warn */
  }

  if (policy->budgets.tokens > 100000000) {
    rprintf("[AK] Warning: tokens budget %llu exceeds recommended maximum\n",
            (unsigned long long)policy->budgets.tokens);
    /* Non-fatal: just warn */
  }

  /* Validate profile count */
  if (policy->profile_count > AK_POLICY_V2_MAX_PROFILES) {
    rprintf("[AK] Too many profiles (%u > %u)\n", policy->profile_count,
            AK_POLICY_V2_MAX_PROFILES);
    return false;
  }

  return true;
}

/* ============================================================
 * RULE ADDITION HELPERS
 * ============================================================ */

/* Context for adding FS read rules */
typedef struct {
  ak_policy_v2_t *policy;
  boolean write;
} fs_rule_ctx_t;

static void add_fs_rule(void *ctx, const char *pattern) {
  fs_rule_ctx_t *fctx = ctx;
  ak_policy_v2_t *policy = fctx->policy;

  ak_fs_rule_v2_t *rule = allocate(policy->h, sizeof(ak_fs_rule_v2_t));
  if (!rule)
    return;

  runtime_memset((u8 *)rule, 0, sizeof(ak_fs_rule_v2_t));
  /* FIX(BUG-005): Explicit NULL termination guarantee */
  local_strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
  rule->pattern[sizeof(rule->pattern) - 1] = '\0';
  rule->read = !fctx->write;
  rule->write = fctx->write;

  /* Prepend to list */
  rule->next = policy->fs_rules;
  policy->fs_rules = rule;
}

/* Context for DNS rules */
static void add_dns_rule(void *ctx, const char *pattern) {
  ak_policy_v2_t *policy = ctx;

  ak_dns_rule_v2_t *rule = allocate(policy->h, sizeof(ak_dns_rule_v2_t));
  if (!rule)
    return;

  runtime_memset((u8 *)rule, 0, sizeof(ak_dns_rule_v2_t));
  /* FIX(BUG-005): Explicit NULL termination guarantee */
  local_strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
  rule->pattern[sizeof(rule->pattern) - 1] = '\0';
  rule->allow = true;

  rule->next = policy->dns_rules;
  policy->dns_rules = rule;
}

/* Context for NET connect rules */
static void add_net_connect_rule(void *ctx, const char *pattern) {
  ak_policy_v2_t *policy = ctx;

  ak_net_rule_v2_t *rule = allocate(policy->h, sizeof(ak_net_rule_v2_t));
  if (!rule)
    return;

  runtime_memset((u8 *)rule, 0, sizeof(ak_net_rule_v2_t));
  /* FIX(BUG-005): Explicit NULL termination guarantee */
  local_strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
  rule->pattern[sizeof(rule->pattern) - 1] = '\0';
  rule->connect = true;

  rule->next = policy->net_rules;
  policy->net_rules = rule;
}

/* Context for tool rules */
typedef struct {
  ak_policy_v2_t *policy;
  boolean allow;
} tool_rule_ctx_t;

static void add_tool_rule(void *ctx, const char *pattern) {
  tool_rule_ctx_t *tctx = ctx;
  ak_policy_v2_t *policy = tctx->policy;

  ak_tool_rule_v2_t *rule = allocate(policy->h, sizeof(ak_tool_rule_v2_t));
  if (!rule)
    return;

  runtime_memset((u8 *)rule, 0, sizeof(ak_tool_rule_v2_t));
  /* FIX(BUG-005): Explicit NULL termination guarantee */
  local_strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
  rule->pattern[sizeof(rule->pattern) - 1] = '\0';
  rule->allow = tctx->allow;

  rule->next = policy->tool_rules;
  policy->tool_rules = rule;
}

/* Context for WASM modules */
static void add_wasm_module(void *ctx, const char *pattern) {
  ak_policy_v2_t *policy = ctx;

  ak_wasm_rule_v2_t *rule = allocate(policy->h, sizeof(ak_wasm_rule_v2_t));
  if (!rule)
    return;

  runtime_memset((u8 *)rule, 0, sizeof(ak_wasm_rule_v2_t));
  /* FIX(BUG-005): Explicit NULL termination guarantee */
  local_strncpy(rule->module_pattern, pattern,
                sizeof(rule->module_pattern) - 1);
  rule->module_pattern[sizeof(rule->module_pattern) - 1] = '\0';

  rule->next = policy->wasm_rules;
  policy->wasm_rules = rule;
}

/* Context for infer models */
typedef struct {
  ak_policy_v2_t *policy;
  u64 max_tokens;
} infer_rule_ctx_t;

static void add_infer_model(void *ctx, const char *pattern) {
  infer_rule_ctx_t *ictx = ctx;
  ak_policy_v2_t *policy = ictx->policy;

  ak_infer_rule_v2_t *rule = allocate(policy->h, sizeof(ak_infer_rule_v2_t));
  if (!rule)
    return;

  runtime_memset((u8 *)rule, 0, sizeof(ak_infer_rule_v2_t));
  /* FIX(BUG-005): Explicit NULL termination guarantee */
  local_strncpy(rule->model_pattern, pattern, sizeof(rule->model_pattern) - 1);
  rule->model_pattern[sizeof(rule->model_pattern) - 1] = '\0';
  rule->max_tokens = ictx->max_tokens;

  rule->next = policy->infer_rules;
  policy->infer_rules = rule;
}

/* Context for spawn rules */
typedef struct {
  ak_policy_v2_t *policy;
  boolean allow;
  boolean inherit_caps;
  boolean inherit_policy;
  boolean sandboxed;
} spawn_rule_ctx_t;

static void add_spawn_rule(void *ctx, const char *pattern) {
  spawn_rule_ctx_t *sctx = ctx;
  ak_policy_v2_t *policy = sctx->policy;

  ak_spawn_rule_v2_t *rule = allocate(policy->h, sizeof(ak_spawn_rule_v2_t));
  if (!rule)
    return;

  runtime_memset((u8 *)rule, 0, sizeof(ak_spawn_rule_v2_t));
  /* FIX(BUG-005): Explicit NULL termination guarantee */
  local_strncpy(rule->pattern, pattern, sizeof(rule->pattern) - 1);
  rule->pattern[sizeof(rule->pattern) - 1] = '\0';
  rule->allow = sctx->allow;
  rule->inherit_caps = sctx->inherit_caps;
  rule->inherit_policy = sctx->inherit_policy;
  rule->sandboxed = sctx->sandboxed;
  rule->max_children = 0; /* Default: unlimited */
  rule->max_wall_ms = 0;  /* Default: no limit */

  rule->next = policy->spawn_rules;
  policy->spawn_rules = rule;
}

/* Context for profiles */
static void add_profile(void *ctx, const char *profile) {
  ak_policy_v2_t *policy = ctx;

  if (policy->profile_count >= AK_POLICY_V2_MAX_PROFILES)
    return;

  u64 len = local_strlen(profile) + 1;
  char *copy = allocate(policy->h, len);
  if (!copy)
    return;

  local_strncpy(copy, profile, len);
  policy->included_profiles[policy->profile_count++] = copy;
}

/* ============================================================
 * JSON POLICY PARSER
 * ============================================================ */

static boolean parse_json_policy(ak_policy_v2_t *policy, const u8 *json,
                                 u64 len) {
  const u8 *p = json;
  const u8 *end = json + len;

  p = skip_ws(p, end);
  if (p >= end || *p != '{')
    return false;
  p++;

  while (p < end) {
    p = skip_ws(p, end);
    if (p >= end)
      return false;
    if (*p == '}')
      break;

    /* Parse key */
    char key[64];
    p = parse_string(p, end, key, sizeof(key));
    if (!p)
      return false;

    p = skip_ws(p, end);
    if (p >= end || *p != ':')
      return false;
    p++;
    p = skip_ws(p, end);

    /* Handle known keys */
    if (local_strcmp(key, "version") == 0) {
      p = parse_string(p, end, policy->version, sizeof(policy->version));
      if (!p)
        return false;
    } else if (local_strcmp(key, "signature") == 0) {
      /* HMAC-SHA256 tag: exactly 64 hex chars (32-byte MAC).
       * Symmetric authentication, not an Ed25519 signature. */
      char sighex[2 * AK_MAC_SIZE + 2];
      p = parse_string(p, end, sighex, sizeof(sighex));
      if (!p)
        return false;
      u64 hexlen = local_strlen(sighex);
      if (hexlen == 2 * AK_MAC_SIZE &&
          v2_parse_hex(sighex, policy->signature, AK_MAC_SIZE)) {
        policy->has_signature = true;
      } else if (hexlen != 0) {
        rprintf("[AK] Policy signature malformed (expected %d hex chars)\n",
                2 * AK_MAC_SIZE);
        return false; /* Malformed signature - reject (fail-closed) */
      }
    } else if (local_strcmp(key, "fs") == 0) {
      /* Parse fs object: { "read": [...], "write": [...] } */
      if (*p != '{') {
        p = skip_value(p, end);
        goto next;
      }
      p++;

      while (p < end) {
        p = skip_ws(p, end);
        if (p >= end)
          return false;
        if (*p == '}') {
          p++;
          break;
        }

        char fs_key[32];
        p = parse_string(p, end, fs_key, sizeof(fs_key));
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p >= end || *p != ':')
          return false;
        p++;

        if (local_strcmp(fs_key, "read") == 0) {
          fs_rule_ctx_t ctx = {.policy = policy, .write = false};
          p = parse_string_array(p, end, add_fs_rule, &ctx);
        } else if (local_strcmp(fs_key, "write") == 0) {
          fs_rule_ctx_t ctx = {.policy = policy, .write = true};
          p = parse_string_array(p, end, add_fs_rule, &ctx);
        } else {
          p = skip_value(p, end);
        }
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p < end && *p == ',')
          p++;
      }
    } else if (local_strcmp(key, "net") == 0) {
      /* Parse net object: { "dns": [...], "connect": [...] } */
      if (*p != '{') {
        p = skip_value(p, end);
        goto next;
      }
      p++;

      while (p < end) {
        p = skip_ws(p, end);
        if (p >= end)
          return false;
        if (*p == '}') {
          p++;
          break;
        }

        char net_key[32];
        p = parse_string(p, end, net_key, sizeof(net_key));
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p >= end || *p != ':')
          return false;
        p++;

        if (local_strcmp(net_key, "dns") == 0) {
          p = parse_string_array(p, end, add_dns_rule, policy);
        } else if (local_strcmp(net_key, "connect") == 0) {
          p = parse_string_array(p, end, add_net_connect_rule, policy);
        } else {
          p = skip_value(p, end);
        }
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p < end && *p == ',')
          p++;
      }
    } else if (local_strcmp(key, "tools") == 0) {
      /* Parse tools object: { "allow": [...], "deny": [...] } */
      if (*p != '{') {
        p = skip_value(p, end);
        goto next;
      }
      p++;

      while (p < end) {
        p = skip_ws(p, end);
        if (p >= end)
          return false;
        if (*p == '}') {
          p++;
          break;
        }

        char tool_key[32];
        p = parse_string(p, end, tool_key, sizeof(tool_key));
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p >= end || *p != ':')
          return false;
        p++;

        if (local_strcmp(tool_key, "allow") == 0) {
          tool_rule_ctx_t ctx = {.policy = policy, .allow = true};
          p = parse_string_array(p, end, add_tool_rule, &ctx);
        } else if (local_strcmp(tool_key, "deny") == 0) {
          tool_rule_ctx_t ctx = {.policy = policy, .allow = false};
          p = parse_string_array(p, end, add_tool_rule, &ctx);
        } else {
          p = skip_value(p, end);
        }
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p < end && *p == ',')
          p++;
      }
    } else if (local_strcmp(key, "wasm") == 0) {
      /* Parse wasm object: { "modules": [...], "hostcalls": [...] } */
      if (*p != '{') {
        p = skip_value(p, end);
        goto next;
      }
      p++;

      while (p < end) {
        p = skip_ws(p, end);
        if (p >= end)
          return false;
        if (*p == '}') {
          p++;
          break;
        }

        char wasm_key[32];
        p = parse_string(p, end, wasm_key, sizeof(wasm_key));
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p >= end || *p != ':')
          return false;
        p++;

        if (local_strcmp(wasm_key, "modules") == 0) {
          p = parse_string_array(p, end, add_wasm_module, policy);
        } else if (local_strcmp(wasm_key, "hostcalls") == 0) {
          /* Design note: JSON policy format places hostcalls at the same
           * level as modules, but the data structure (ak_wasm_rule_v2_t)
           * supports per-module hostcalls. Global hostcalls would need to
           * be applied to all existing rules, which requires iterating
           * the rule list and duplicating strings. For simplicity, this
           * JSON parser ignores top-level hostcalls. Use TOML format for
           * per-module hostcall configuration. */
          p = skip_value(p, end);
        } else {
          p = skip_value(p, end);
        }
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p < end && *p == ',')
          p++;
      }
    } else if (local_strcmp(key, "infer") == 0) {
      /* Parse infer object: { "models": [...], "max_tokens": N } */
      if (*p != '{') {
        p = skip_value(p, end);
        goto next;
      }
      p++;

      u64 max_tokens = 100000; /* Default */

      /* First pass: find max_tokens */
      const u8 *saved_p = p;
      while (p < end) {
        p = skip_ws(p, end);
        if (*p == '}')
          break;

        char infer_key[32];
        p = parse_string(p, end, infer_key, sizeof(infer_key));
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (*p != ':')
          return false;
        p++;
        p = skip_ws(p, end);

        if (local_strcmp(infer_key, "max_tokens") == 0) {
          p = parse_number(p, end, &max_tokens);
        } else {
          p = skip_value(p, end);
        }
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (*p == ',')
          p++;
      }

      /* Second pass: add models with max_tokens */
      p = saved_p;
      while (p < end) {
        p = skip_ws(p, end);
        if (*p == '}') {
          p++;
          break;
        }

        char infer_key[32];
        p = parse_string(p, end, infer_key, sizeof(infer_key));
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (*p != ':')
          return false;
        p++;

        if (local_strcmp(infer_key, "models") == 0) {
          infer_rule_ctx_t ctx = {.policy = policy, .max_tokens = max_tokens};
          p = parse_string_array(p, end, add_infer_model, &ctx);
        } else {
          p = skip_value(p, end);
        }
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (*p == ',')
          p++;
      }
    } else if (local_strcmp(key, "budgets") == 0) {
      /* Parse budgets object */
      if (*p != '{') {
        p = skip_value(p, end);
        goto next;
      }
      p++;

      while (p < end) {
        p = skip_ws(p, end);
        if (*p == '}') {
          p++;
          break;
        }

        char budget_key[32];
        p = parse_string(p, end, budget_key, sizeof(budget_key));
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (*p != ':')
          return false;
        p++;
        p = skip_ws(p, end);

        u64 val;
        p = parse_number(p, end, &val);
        if (!p)
          return false;

        if (local_strcmp(budget_key, "tool_calls") == 0) {
          policy->budgets.tool_calls = val;
        } else if (local_strcmp(budget_key, "tokens") == 0) {
          policy->budgets.tokens = val;
        } else if (local_strcmp(budget_key, "wall_time_ms") == 0) {
          policy->budgets.wall_ns = val * MILLION;
        } else if (local_strcmp(budget_key, "cpu_time_ns") == 0) {
          policy->budgets.cpu_ns = val;
        } else if (local_strcmp(budget_key, "bytes") == 0) {
          policy->budgets.bytes = val;
        }

        p = skip_ws(p, end);
        if (*p == ',')
          p++;
      }
    } else if (local_strcmp(key, "profiles") == 0) {
      p = parse_string_array(p, end, add_profile, policy);
      if (!p)
        return false;
    } else if (local_strcmp(key, "spawn") == 0) {
      /* Parse spawn object: { "allow": [...], "deny": [...] } */
      if (*p != '{') {
        p = skip_value(p, end);
        goto next;
      }
      p++;

      while (p < end) {
        p = skip_ws(p, end);
        if (p >= end)
          return false;
        if (*p == '}') {
          p++;
          break;
        }

        char spawn_key[32];
        p = parse_string(p, end, spawn_key, sizeof(spawn_key));
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p >= end || *p != ':')
          return false;
        p++;

        if (local_strcmp(spawn_key, "allow") == 0) {
          spawn_rule_ctx_t ctx = {.policy = policy,
                                  .allow = true,
                                  .inherit_caps = true,
                                  .inherit_policy = true,
                                  .sandboxed = false};
          p = parse_string_array(p, end, add_spawn_rule, &ctx);
        } else if (local_strcmp(spawn_key, "deny") == 0) {
          spawn_rule_ctx_t ctx = {.policy = policy,
                                  .allow = false,
                                  .inherit_caps = false,
                                  .inherit_policy = false,
                                  .sandboxed = false};
          p = parse_string_array(p, end, add_spawn_rule, &ctx);
        } else if (local_strcmp(spawn_key, "sandbox") == 0) {
          spawn_rule_ctx_t ctx = {.policy = policy,
                                  .allow = true,
                                  .inherit_caps = false,
                                  .inherit_policy = true,
                                  .sandboxed = true};
          p = parse_string_array(p, end, add_spawn_rule, &ctx);
        } else {
          p = skip_value(p, end);
        }
        if (!p)
          return false;

        p = skip_ws(p, end);
        if (p < end && *p == ',')
          p++;
      }
    } else {
      /* Unknown key, skip value */
      p = skip_value(p, end);
      if (!p)
        return false;
    }

  next:
    p = skip_ws(p, end);
    if (p < end && *p == ',')
      p++;
  }

  return true;
}

/* ============================================================
 * RULE CLEANUP
 * ============================================================ */

static void free_fs_rules(heap h, ak_fs_rule_v2_t *rules) {
  while (rules) {
    ak_fs_rule_v2_t *next = rules->next;
    deallocate(h, rules, sizeof(ak_fs_rule_v2_t));
    rules = next;
  }
}

static void free_net_rules(heap h, ak_net_rule_v2_t *rules) {
  while (rules) {
    ak_net_rule_v2_t *next = rules->next;
    deallocate(h, rules, sizeof(ak_net_rule_v2_t));
    rules = next;
  }
}

static void free_dns_rules(heap h, ak_dns_rule_v2_t *rules) {
  while (rules) {
    ak_dns_rule_v2_t *next = rules->next;
    deallocate(h, rules, sizeof(ak_dns_rule_v2_t));
    rules = next;
  }
}

static void free_tool_rules(heap h, ak_tool_rule_v2_t *rules) {
  while (rules) {
    ak_tool_rule_v2_t *next = rules->next;
    deallocate(h, rules, sizeof(ak_tool_rule_v2_t));
    rules = next;
  }
}

static void free_wasm_rules(heap h, ak_wasm_rule_v2_t *rules) {
  while (rules) {
    ak_wasm_rule_v2_t *next = rules->next;
    for (u32 i = 0; i < rules->hostcall_count; i++) {
      if (rules->allowed_hostcalls[i]) {
        deallocate(h, rules->allowed_hostcalls[i],
                   local_strlen(rules->allowed_hostcalls[i]) + 1);
      }
    }
    deallocate(h, rules, sizeof(ak_wasm_rule_v2_t));
    rules = next;
  }
}

static void free_infer_rules(heap h, ak_infer_rule_v2_t *rules) {
  while (rules) {
    ak_infer_rule_v2_t *next = rules->next;
    deallocate(h, rules, sizeof(ak_infer_rule_v2_t));
    rules = next;
  }
}

static void free_spawn_rules(heap h, ak_spawn_rule_v2_t *rules) {
  while (rules) {
    ak_spawn_rule_v2_t *next = rules->next;
    deallocate(h, rules, sizeof(ak_spawn_rule_v2_t));
    rules = next;
  }
}

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_policy_v2_init(heap h) {
  if (ak_policy_v2_state.initialized)
    return;

  ak_policy_v2_state.h = h;
  ak_policy_v2_state.current_policy = NULL;
  ak_policy_v2_state.initialized = true;
}

void ak_policy_v2_shutdown(void) {
  if (!ak_policy_v2_state.initialized)
    return;

  if (ak_policy_v2_state.current_policy) {
    ak_policy_v2_destroy(ak_policy_v2_state.current_policy);
    ak_policy_v2_state.current_policy = NULL;
  }

  ak_policy_v2_state.initialized = false;
}

/* ============================================================
 * POLICY LOADING
 * ============================================================ */

ak_policy_v2_t *ak_policy_v2_load(heap h, const u8 *json, u64 len) {
  if (!json || len == 0)
    return NULL;

  /* Allocate policy structure */
  ak_policy_v2_t *policy = allocate(h, sizeof(ak_policy_v2_t));
  if (!policy)
    return NULL;

  runtime_memset((u8 *)policy, 0, sizeof(ak_policy_v2_t));
  policy->h = h;
  policy->loaded_ns = now(CLOCK_ID_MONOTONIC);

  /* Set default version */
  local_strncpy(policy->version, AK_POLICY_V2_VERSION, sizeof(policy->version));

  /* Set default budgets */
  policy->budgets.cpu_ns = 0;                 /* No CPU limit by default */
  policy->budgets.wall_ns = 300000 * MILLION; /* 5 minutes */
  policy->budgets.bytes = 100 * 1024 * 1024;  /* 100 MB */
  policy->budgets.tokens = 100000;
  policy->budgets.tool_calls = 100;

  /* Parse JSON */
  if (!parse_json_policy(policy, json, len)) {
    ak_policy_v2_destroy(policy);
    return NULL;
  }

  /* Validate schema (P2-2: version and structural constraints) */
  if (!validate_policy_schema(policy)) {
    ak_policy_v2_destroy(policy);
    return NULL;
  }

  /* Compute hash (identifies the full raw document) */
  compute_policy_hash(json, len, policy->policy_hash);

  /*
   * Integrity check (HMAC-SHA256, symmetric - not an Ed25519 signature):
   *   - Key configured: unsigned or wrongly-tagged policies are REJECTED.
   *   - No key configured: policy is accepted but explicitly flagged
   *     unsigned; it is never treated as verified.
   */
  if (ak_policy_v2_verify_key.configured) {
    u8 signed_hash[AK_HASH_SIZE];
    u8 mac[AK_MAC_SIZE];
    boolean ok = policy->has_signature &&
                 compute_signed_content_hash(h, json, len, signed_hash) &&
                 v2_hmac_sha256(ak_policy_v2_verify_key.key, AK_KEY_SIZE,
                                signed_hash, AK_HASH_SIZE, mac) &&
                 v2_constant_time_compare(mac, policy->signature, AK_MAC_SIZE);
    if (!ok) {
      rprintf("[AK] SECURITY: policy rejected: %s (verification key "
              "configured)\n",
              policy->has_signature ? "HMAC verification failed"
                                    : "unsigned policy");
      ak_policy_v2_destroy(policy);
      return NULL;
    }
    policy->signature_verified = true;
  } else {
    policy->signature_verified = false;
    if (!policy->has_signature)
      rprintf("[AK] SECURITY WARNING: policy loaded UNSIGNED (no "
              "verification key configured); integrity is NOT guaranteed\n");
    else
      rprintf("[AK] SECURITY WARNING: policy carries an HMAC tag but no "
              "verification key is configured; treating as UNVERIFIED\n");
  }

  /* Expand included profiles */
  for (u32 i = 0; i < policy->profile_count; i++) {
    ak_policy_v2_expand_profile(policy, policy->included_profiles[i]);
  }

  policy->loaded = true;
  policy->fail_closed = false;

  return policy;
}

ak_policy_v2_t *ak_policy_v2_load_buffer(heap h, buffer json) {
  if (!json || buffer_length(json) == 0)
    return NULL;

  return ak_policy_v2_load(h, buffer_ref(json, 0), buffer_length(json));
}

ak_policy_v2_t *ak_policy_v2_load_file(heap h, const char *path) {
  /*
   * File loading requires filesystem integration.
   * In unikernel context, this would read from initrd.
   *
   * For P0, we expect the caller to read the file and call
   * ak_policy_v2_load() directly.
   */
  (void)h;
  (void)path;
  return NULL;
}

ak_policy_v2_t *ak_policy_v2_bootstrap(heap h) {
  ak_policy_v2_t *policy = NULL;

  /*
   * DENY-BY-DEFAULT Load Order:
   *
   * 1. Check embedded policy (CONFIG_AK_EMBEDDED_POLICY)
   */
#ifdef CONFIG_AK_EMBEDDED_POLICY
  extern const u8 ak_embedded_policy[];
  extern const u64 ak_embedded_policy_len;
  policy = ak_policy_v2_load(h, ak_embedded_policy, ak_embedded_policy_len);
  if (policy) {
    rprintf("[AK] Loaded embedded policy (hash=");
    for (int i = 0; i < 8; i++)
      rprintf("%02x", policy->policy_hash[i]);
    rprintf("...)\n");
    return policy;
  }
#endif

  /*
   * 2. Check initrd /ak/policy.json
   *    Policy loading from initrd is handled by ak_policy_v2_load_from_file()
   *    which should be called after the filesystem is initialized. This
   *    bootstrap function is called before filesystem init, so we proceed
   *    to fail-closed behavior.
   */

  /*
   * 3. FAIL CLOSED: No policy found
   *    Create a deny-all policy and log a clear message.
   */
  rprintf("\n");
  rprintf("========================================\n");
  rprintf("  AUTHORITY KERNEL: NO POLICY FOUND\n");
  rprintf("========================================\n");
  rprintf("\n");
  rprintf("  The Authority Kernel operates in DENY-BY-DEFAULT mode.\n");
  rprintf("  No policy was found at:\n");
  rprintf("    - Embedded policy (CONFIG_AK_EMBEDDED_POLICY)\n");
  rprintf("    - Initrd: %s\n", AK_POLICY_V2_PATH);
  rprintf("\n");
  rprintf("  ALL EFFECTS WILL BE DENIED.\n");
  rprintf("\n");
  rprintf("  To resolve:\n");
  rprintf("    1. Create a policy file at %s\n", AK_POLICY_V2_PATH);
  rprintf("    2. Or embed a policy at build time\n");
  rprintf("\n");
  rprintf("  See docs/ak-roadmap.md for policy format.\n");
  rprintf("\n");
  rprintf("========================================\n");
  rprintf("\n");

  /* Create fail-closed policy */
  policy = allocate(h, sizeof(ak_policy_v2_t));
  if (!policy) {
    /* Cannot even allocate - fatal */
    rprintf("[AK] FATAL: Cannot allocate fail-closed policy\n");
    return NULL;
  }

  runtime_memset((u8 *)policy, 0, sizeof(ak_policy_v2_t));
  policy->h = h;
  policy->loaded_ns = now(CLOCK_ID_MONOTONIC);
  local_strncpy(policy->version, AK_POLICY_V2_VERSION, sizeof(policy->version));
  policy->loaded = false;
  policy->fail_closed = true;

  /* No rules = deny everything */

  return policy;
}

void ak_policy_v2_destroy(ak_policy_v2_t *policy) {
  if (!policy)
    return;

  heap h = policy->h;

  /* Free all rules */
  free_fs_rules(h, policy->fs_rules);
  free_net_rules(h, policy->net_rules);
  free_dns_rules(h, policy->dns_rules);
  free_tool_rules(h, policy->tool_rules);
  free_wasm_rules(h, policy->wasm_rules);
  free_infer_rules(h, policy->infer_rules);
  free_spawn_rules(h, policy->spawn_rules);

  /* Free profile strings */
  for (u32 i = 0; i < policy->profile_count; i++) {
    if (policy->included_profiles[i]) {
      deallocate(h, policy->included_profiles[i],
                 local_strlen(policy->included_profiles[i]) + 1);
    }
  }

  /* Free policy itself */
  deallocate(h, policy, sizeof(ak_policy_v2_t));
}

/* ============================================================
 * PATTERN MATCHING
 * ============================================================ */

/*
 * Path glob matching with ** support.
 *
 * * matches any characters except /
 * ** matches any characters including /
 */
boolean ak_policy_v2_match_path(const char *pattern, const char *path) {
  if (!pattern || !path)
    return false;

  const char *pp = pattern;
  const char *tp = path;
  const char *star_pp = NULL;
  const char *star_tp = NULL;

  while (*tp) {
    /* Check for ** pattern */
    if (pp[0] == '*' && pp[1] == '*') {
      /* ** matches anything including / */
      star_pp = pp;
      star_tp = tp;
      pp += 2;
      /* Skip trailing / after ** if present */
      if (*pp == '/')
        pp++;
    } else if (*pp == '*') {
      /* * matches anything except / */
      star_pp = pp;
      star_tp = tp;
      pp++;
    } else if (*pp == *tp) {
      pp++;
      tp++;
    } else if (*pp == '?' && *tp != '/') {
      pp++;
      tp++;
    } else if (star_pp) {
      /* Backtrack to last * or ** */
      if (star_pp[0] == '*' && star_pp[1] == '*') {
        /* ** can consume anything */
        pp = star_pp + 2;
        if (*pp == '/')
          pp++;
        star_tp++;
        tp = star_tp;
      } else {
        /* * cannot match / */
        if (*star_tp == '/') {
          return false;
        }
        pp = star_pp + 1;
        star_tp++;
        tp = star_tp;
      }
    } else {
      return false;
    }
  }

  /* Skip trailing wildcards in pattern */
  while (*pp == '*')
    pp++;
  while (pp[0] == '/' && pp[1] == '*' && pp[2] == '*') {
    pp += 3;
  }

  return (*pp == '\0');
}

/*
 * Network target matching.
 * Pattern format: "dns:pattern:port" or "ip:pattern:port"
 * Port can be * for wildcard.
 */
boolean ak_policy_v2_match_net(const char *pattern, const char *target) {
  if (!pattern || !target)
    return false;

  /* Both must have same prefix (dns: or ip:) */
  if (local_strncmp(pattern, "dns:", 4) == 0 &&
      local_strncmp(target, "dns:", 4) == 0) {
    /* DNS pattern matching */
    pattern += 4;
    target += 4;
  } else if (local_strncmp(pattern, "ip:", 3) == 0 &&
             local_strncmp(target, "ip:", 3) == 0) {
    /* IP pattern matching */
    pattern += 3;
    target += 3;
  } else {
    /* Cross-type matching: dns pattern can match dns target only */
    return false;
  }

  /* Simple glob match for the rest */
  return ak_pattern_match(pattern, target);
}

/*
 * DNS domain matching.
 * Supports wildcard prefix: *.example.com
 */
boolean ak_policy_v2_match_dns(const char *pattern, const char *domain) {
  if (!pattern || !domain)
    return false;

  /* Handle wildcard prefix */
  if (pattern[0] == '*' && pattern[1] == '.') {
    /* *.example.com matches sub.example.com and example.com */
    const char *suffix = pattern + 1; /* .example.com */
    u64 suffix_len = local_strlen(suffix);
    u64 domain_len = local_strlen(domain);

    if (domain_len < suffix_len - 1)
      return false;

    /* Check if domain ends with suffix (without leading .) */
    const char *domain_suffix = domain + domain_len - suffix_len + 1;
    if (local_strcmp(domain_suffix, suffix + 1) == 0)
      return true;

    /* Also match if domain is exactly the suffix without wildcard */
    if (local_strcmp(domain, suffix + 1) == 0)
      return true;

    return false;
  }

  /* Exact match */
  return (local_strcmp(pattern, domain) == 0);
}

/* ============================================================
 * POLICY CHECKING
 * ============================================================ */

boolean ak_policy_v2_check_fs(ak_policy_v2_t *policy, const char *path,
                              boolean write) {
  if (!policy || !path)
    return false; /* Fail-closed */

  if (policy->fail_closed)
    return false;

  ak_fs_rule_v2_t *rule = policy->fs_rules;
  while (rule) {
    if (ak_policy_v2_match_path(rule->pattern, path)) {
      if (write && rule->write)
        return true;
      if (!write && rule->read)
        return true;
    }
    rule = rule->next;
  }

  return false; /* Deny-by-default */
}

boolean ak_policy_v2_check_net_connect(ak_policy_v2_t *policy,
                                       const char *target) {
  if (!policy || !target)
    return false;

  if (policy->fail_closed)
    return false;

  ak_net_rule_v2_t *rule = policy->net_rules;
  while (rule) {
    if (rule->connect && ak_policy_v2_match_net(rule->pattern, target))
      return true;
    rule = rule->next;
  }

  return false;
}

boolean ak_policy_v2_check_dns(ak_policy_v2_t *policy, const char *hostname) {
  if (!policy || !hostname)
    return false;

  if (policy->fail_closed)
    return false;

  ak_dns_rule_v2_t *rule = policy->dns_rules;
  while (rule) {
    if (rule->allow && ak_policy_v2_match_dns(rule->pattern, hostname))
      return true;
    rule = rule->next;
  }

  return false;
}

boolean ak_policy_v2_check_tool(ak_policy_v2_t *policy, const char *tool_name) {
  if (!policy || !tool_name)
    return false;

  if (policy->fail_closed)
    return false;

  /* Check deny rules first (deny takes precedence) */
  ak_tool_rule_v2_t *rule = policy->tool_rules;
  while (rule) {
    if (!rule->allow && ak_pattern_match(rule->pattern, tool_name))
      return false;
    rule = rule->next;
  }

  /* Then check allow rules */
  rule = policy->tool_rules;
  while (rule) {
    if (rule->allow && ak_pattern_match(rule->pattern, tool_name))
      return true;
    rule = rule->next;
  }

  return false; /* Deny-by-default */
}

boolean ak_policy_v2_check_wasm(ak_policy_v2_t *policy, const char *module,
                                const char *hostcall) {
  if (!policy || !module)
    return false;

  if (policy->fail_closed)
    return false;

  ak_wasm_rule_v2_t *rule = policy->wasm_rules;
  while (rule) {
    if (ak_pattern_match(rule->module_pattern, module)) {
      if (!hostcall)
        return true; /* Module allowed, no hostcall check needed */

      /* Check hostcall whitelist */
      for (u32 i = 0; i < rule->hostcall_count; i++) {
        if (rule->allowed_hostcalls[i] &&
            ak_pattern_match(rule->allowed_hostcalls[i], hostcall))
          return true;
      }
      /* Hostcall not in whitelist */
      return false;
    }
    rule = rule->next;
  }

  return false;
}

boolean ak_policy_v2_check_infer(ak_policy_v2_t *policy, const char *model,
                                 u64 tokens, u64 *max_out) {
  if (!policy || !model)
    return false;

  if (policy->fail_closed)
    return false;

  ak_infer_rule_v2_t *rule = policy->infer_rules;
  while (rule) {
    if (ak_pattern_match(rule->model_pattern, model)) {
      if (max_out)
        *max_out = rule->max_tokens;
      return (tokens <= rule->max_tokens);
    }
    rule = rule->next;
  }

  return false;
}

boolean ak_policy_v2_check_budget(ak_policy_v2_t *policy,
                                  const ak_effect_req_t *req) {
  if (!policy || !req)
    return false;

  if (policy->fail_closed)
    return false;

  /* Check each budget constraint */
  if (policy->budgets.cpu_ns > 0 && req->budget.cpu_ns > policy->budgets.cpu_ns)
    return false;
  if (policy->budgets.wall_ns > 0 &&
      req->budget.wall_ns > policy->budgets.wall_ns)
    return false;
  if (policy->budgets.bytes > 0 && req->budget.bytes > policy->budgets.bytes)
    return false;
  if (policy->budgets.tokens > 0 && req->budget.tokens > policy->budgets.tokens)
    return false;

  return true;
}

/* ============================================================
 * PROCESS SPAWN CHECKING
 * ============================================================ */

boolean ak_policy_v2_check_spawn(ak_policy_v2_t *policy, const char *program) {
  if (!policy || !program)
    return false;

  if (policy->fail_closed)
    return false;

  /* Check deny rules first (deny takes precedence) */
  ak_spawn_rule_v2_t *rule = policy->spawn_rules;
  while (rule) {
    if (!rule->allow && ak_policy_v2_match_path(rule->pattern, program))
      return false;
    rule = rule->next;
  }

  /* Then check allow rules */
  rule = policy->spawn_rules;
  while (rule) {
    if (rule->allow && ak_policy_v2_match_path(rule->pattern, program))
      return true;
    rule = rule->next;
  }

  return false; /* Deny-by-default */
}

const ak_spawn_rule_v2_t *ak_policy_v2_get_spawn_rule(ak_policy_v2_t *policy,
                                                      const char *program) {
  if (!policy || !program)
    return NULL;

  ak_spawn_rule_v2_t *rule = policy->spawn_rules;
  while (rule) {
    if (ak_policy_v2_match_path(rule->pattern, program))
      return rule;
    rule = rule->next;
  }

  return NULL;
}

/* ============================================================
 * MAIN CHECK FUNCTION
 * ============================================================ */

/*
 * Extract target components for suggestion generation.
 * For FS: extracts path
 * For NET: extracts address:port
 * For DNS: extracts hostname
 * For TOOL: extracts tool name
 */
static void extract_target_info(const ak_effect_req_t *req, char *info,
                                u32 max_len) {
  if (!req || !info || max_len == 0)
    return;
  local_strncpy(info, req->target, max_len);
}

/*
 * Open flag constants (Linux ABI, matching src/unix/system_structs.h;
 * defined locally because the unix headers are not visible here).
 */
#ifndef O_RDONLY
#define O_RDONLY 00000000
#endif
#ifndef O_WRONLY
#define O_WRONLY 00000001
#endif
#ifndef O_RDWR
#define O_RDWR 00000002
#endif
#ifndef O_ACCMODE
#define O_ACCMODE 00000003
#endif
#ifndef O_CREAT
#define O_CREAT 00000100
#endif
#ifndef O_TRUNC
#define O_TRUNC 00001000
#endif
#ifndef O_APPEND
#define O_APPEND 00002000
#endif

/*
 * Extract a numeric member (e.g. "f") from the minimal params JSON
 * emitted by ak_effect_from_open(): {"f":<flags>,"m":<mode>}.
 * Returns true and stores the value on success.
 */
static boolean parse_params_u64(const u8 *params, u32 params_len,
                                const char *key, u64 *out) {
  if (!params || params_len == 0 || !key || !out)
    return false;

  u64 key_len = local_strlen(key);

  for (u64 i = 0; i + key_len + 2 < params_len; i++) {
    if (params[i] != '"' ||
        local_strncmp((const char *)&params[i + 1], key, key_len) != 0 ||
        params[i + 1 + key_len] != '"')
      continue;

    u64 j = i + 1 + key_len + 1;
    while (j < params_len &&
           (params[j] == ':' || params[j] == ' ' || params[j] == '\t'))
      j++;
    if (j >= params_len || params[j] < '0' || params[j] > '9')
      return false;

    const u8 *end_num =
        parse_number(&params[j], params + params_len, out);
    return (end_num != NULL);
  }
  return false;
}

boolean ak_policy_v2_check(ak_policy_v2_t *policy, const ak_effect_req_t *req,
                           ak_decision_t *decision_out) {
  if (!decision_out)
    return false;

  /* Initialize decision */
  runtime_memset((u8 *)decision_out, 0, sizeof(ak_decision_t));
  decision_out->trace_id = req ? req->trace_id : 0;
  decision_out->allow = false;

  /* Validate inputs */
  if (!policy) {
    decision_out->reason_code = AK_DENY_NO_POLICY;
    decision_out->errno_equiv = EPERM;
    local_strncpy(decision_out->missing_cap, "policy",
                  sizeof(decision_out->missing_cap));
    local_strncpy(decision_out->detail, "No policy loaded",
                  sizeof(decision_out->detail));
    return false;
  }

  if (!req) {
    decision_out->reason_code = AK_DENY_NO_CAP;
    decision_out->errno_equiv = EINVAL;
    local_strncpy(decision_out->detail, "Invalid request",
                  sizeof(decision_out->detail));
    return false;
  }

  /* Check fail-closed state */
  if (policy->fail_closed) {
    decision_out->reason_code = AK_DENY_NO_POLICY;
    decision_out->errno_equiv = EPERM;
    local_strncpy(decision_out->missing_cap, "policy",
                  sizeof(decision_out->missing_cap));
    local_strncpy(decision_out->detail, "No policy loaded (fail-closed)",
                  sizeof(decision_out->detail));
    ak_policy_v2_suggest(req, decision_out->suggested_snippet,
                         sizeof(decision_out->suggested_snippet));
    return false;
  }

  boolean allowed = false;
  const char *missing_cap = NULL;

  /* Check based on effect type */
  switch (req->op) {
  case AK_E_FS_OPEN: {
    /*
     * Determine access intent from the open flags encoded in
     * req->params by ak_effect_from_open(): {"f":<flags>,"m":<mode>}.
     * Write-intent opens (O_WRONLY/O_RDWR access mode, or
     * O_CREAT/O_TRUNC/O_APPEND) require WRITE scope. If the flags
     * cannot be determined, require BOTH scopes (fail-closed).
     */
    u64 flags = 0;
    boolean need_read = true;
    boolean need_write = true;
    if (parse_params_u64(req->params, req->params_len, "f", &flags)) {
      u64 acc = flags & O_ACCMODE;
      need_read = (acc != O_WRONLY);
      need_write = (acc != O_RDONLY) ||
                   (flags & (O_CREAT | O_TRUNC | O_APPEND)) != 0;
    }

    allowed = true;
    if (need_read && !ak_policy_v2_check_fs(policy, req->target, false))
      allowed = false;
    if (allowed && need_write &&
        !ak_policy_v2_check_fs(policy, req->target, true))
      allowed = false;
    missing_cap = need_write ? "fs.write" : "fs.read";
    break;
  }

  case AK_E_FS_UNLINK:
  case AK_E_FS_RENAME:
  case AK_E_FS_MKDIR:
  case AK_E_FS_RMDIR:
    allowed = ak_policy_v2_check_fs(policy, req->target, true);
    missing_cap = "fs.write";
    break;

  case AK_E_FS_STAT:
    allowed = ak_policy_v2_check_fs(policy, req->target, false);
    missing_cap = "fs.read";
    break;

  case AK_E_NET_CONNECT:
    allowed = ak_policy_v2_check_net_connect(policy, req->target);
    missing_cap = "net.connect";
    break;

  case AK_E_NET_DNS_RESOLVE: {
    /* Extract hostname from target (format: "dns:hostname") */
    const char *hostname = req->target;
    if (local_strncmp(hostname, "dns:", 4) == 0)
      hostname += 4;
    allowed = ak_policy_v2_check_dns(policy, hostname);
    missing_cap = "net.dns";
    break;
  }

  case AK_E_NET_BIND:
  case AK_E_NET_LISTEN:
    /* P0: bind/listen not routed yet */
    allowed = false;
    missing_cap = "net.bind";
    break;

  case AK_E_TOOL_CALL: {
    /* Extract tool name from target (format: "tool:name:version") */
    const char *tool = req->target;
    if (local_strncmp(tool, "tool:", 5) == 0)
      tool += 5;
    /* Find end of name (at : or end) */
    char tool_name[64];
    u64 i = 0;
    while (tool[i] && tool[i] != ':' && i < sizeof(tool_name) - 1) {
      tool_name[i] = tool[i];
      i++;
    }
    tool_name[i] = '\0';
    allowed = ak_policy_v2_check_tool(policy, tool_name);
    missing_cap = "tool";
    break;
  }

  case AK_E_WASM_INVOKE: {
    /* Extract module and function from target */
    const char *module = req->target;
    if (local_strncmp(module, "wasm:", 5) == 0)
      module += 5;
    char mod_name[64];
    u64 i = 0;
    while (module[i] && module[i] != ':' && i < sizeof(mod_name) - 1) {
      mod_name[i] = module[i];
      i++;
    }
    mod_name[i] = '\0';
    allowed = ak_policy_v2_check_wasm(policy, mod_name, NULL);
    missing_cap = "wasm";
    break;
  }

  case AK_E_INFER: {
    /* Extract model from target */
    const char *model = req->target;
    if (local_strncmp(model, "model:", 6) == 0)
      model += 6;
    char model_name[64];
    u64 i = 0;
    while (model[i] && model[i] != ':' && i < sizeof(model_name) - 1) {
      model_name[i] = model[i];
      i++;
    }
    model_name[i] = '\0';
    allowed =
        ak_policy_v2_check_infer(policy, model_name, req->budget.tokens, NULL);
    missing_cap = "infer";
    break;
  }

  case AK_E_PROC_SPAWN: {
    /* Extract program from target (format: "spawn:<program>") */
    const char *program = req->target;
    if (local_strncmp(program, "spawn:", 6) == 0)
      program += 6;
    allowed = ak_policy_v2_check_spawn(policy, program);
    missing_cap = "spawn";
    break;
  }

  case AK_E_PROC_SIGNAL:
  case AK_E_PROC_WAIT:
    /* Signal and wait are allowed if parent has spawn capability for the target
     * process */
    /* For P0, we allow these if spawns are allowed (simplified) */
    allowed = (policy->spawn_rules != NULL);
    missing_cap = "proc";
    break;

  default:
    allowed = false;
    missing_cap = "unknown";
    break;
  }

  /* Also check budget */
  if (allowed && !ak_policy_v2_check_budget(policy, req)) {
    allowed = false;
    missing_cap = "budget";
    decision_out->reason_code = AK_DENY_BUDGET_EXCEEDED;
  }

  /* Populate decision */
  decision_out->allow = allowed;

  if (!allowed) {
    if (decision_out->reason_code == AK_DENY_NONE)
      decision_out->reason_code = AK_DENY_PATTERN_MISMATCH;
    decision_out->errno_equiv = EACCES;
    if (missing_cap) {
      local_strncpy(decision_out->missing_cap, missing_cap,
                    sizeof(decision_out->missing_cap));
    }
    /* Generate user-readable detail */
    char target_info[128];
    extract_target_info(req, target_info, sizeof(target_info));
    rprintf("[AK] Denied %s: %s (missing: %s)\n",
            missing_cap ? missing_cap : "effect", target_info,
            missing_cap ? missing_cap : "unknown");

    /* Generate suggested snippet */
    ak_policy_v2_suggest(req, decision_out->suggested_snippet,
                         sizeof(decision_out->suggested_snippet));
  }

  return allowed;
}

/* ============================================================
 * SUGGESTION GENERATION
 * ============================================================ */

void ak_policy_v2_suggest(const ak_effect_req_t *req, char *snippet,
                          u32 max_len) {
  if (!req || !snippet || max_len == 0)
    return;

  snippet[0] = '\0';
  char *p = snippet;
  char *end = snippet + max_len - 1;

#define APPEND(str)                                                            \
  do {                                                                         \
    const char *s = (str);                                                     \
    while (*s && p < end)                                                      \
      *p++ = *s++;                                                             \
    *p = '\0';                                                                 \
  } while (0)

  switch (req->op) {
  case AK_E_FS_OPEN:
  case AK_E_FS_STAT:
    APPEND("[fs]\nread = [\"");
    APPEND(req->target);
    APPEND("\"]\n");
    break;

  case AK_E_FS_UNLINK:
  case AK_E_FS_RENAME:
  case AK_E_FS_MKDIR:
  case AK_E_FS_RMDIR:
    APPEND("[fs]\nwrite = [\"");
    APPEND(req->target);
    APPEND("\"]\n");
    break;

  case AK_E_NET_CONNECT:
    APPEND("[net]\nconnect = [\"");
    APPEND(req->target);
    APPEND("\"]\n");
    break;

  case AK_E_NET_DNS_RESOLVE: {
    const char *hostname = req->target;
    if (local_strncmp(hostname, "dns:", 4) == 0)
      hostname += 4;
    APPEND("[net]\ndns = [\"");
    APPEND(hostname);
    APPEND("\"]\n");
    break;
  }

  case AK_E_TOOL_CALL: {
    const char *tool = req->target;
    if (local_strncmp(tool, "tool:", 5) == 0)
      tool += 5;
    APPEND("[tools]\nallow = [\"");
    /* Copy just the tool name */
    while (*tool && *tool != ':' && p < end)
      *p++ = *tool++;
    *p = '\0';
    APPEND("\"]\n");
    break;
  }

  case AK_E_WASM_INVOKE: {
    const char *module = req->target;
    if (local_strncmp(module, "wasm:", 5) == 0)
      module += 5;
    APPEND("[wasm]\nmodules = [\"");
    while (*module && *module != ':' && p < end)
      *p++ = *module++;
    *p = '\0';
    APPEND("\"]\n");
    break;
  }

  case AK_E_INFER: {
    const char *model = req->target;
    if (local_strncmp(model, "model:", 6) == 0)
      model += 6;
    APPEND("[infer]\nmodels = [\"");
    while (*model && *model != ':' && p < end)
      *p++ = *model++;
    *p = '\0';
    APPEND("\"]\n");
    break;
  }

  case AK_E_PROC_SPAWN: {
    const char *program = req->target;
    if (local_strncmp(program, "spawn:", 6) == 0)
      program += 6;
    APPEND("[spawn]\nallow = [\"");
    while (*program && p < end)
      *p++ = *program++;
    *p = '\0';
    APPEND("\"]\n");
    break;
  }

  case AK_E_PROC_SIGNAL:
  case AK_E_PROC_WAIT:
    APPEND("[spawn]\n# Enable spawn rules to allow signal/wait\n");
    break;

  default:
    APPEND("# Unknown effect type\n");
    break;
  }

#undef APPEND
}

void ak_policy_v2_get_missing_cap(const ak_effect_req_t *req, char *cap,
                                  u32 max_len) {
  if (!req || !cap || max_len == 0)
    return;

  const char *cap_str = "unknown";

  switch (req->op) {
  case AK_E_FS_OPEN:
  case AK_E_FS_STAT:
    cap_str = "fs.read";
    break;
  case AK_E_FS_UNLINK:
  case AK_E_FS_RENAME:
  case AK_E_FS_MKDIR:
  case AK_E_FS_RMDIR:
    cap_str = "fs.write";
    break;
  case AK_E_NET_CONNECT:
    cap_str = "net.connect";
    break;
  case AK_E_NET_DNS_RESOLVE:
    cap_str = "net.dns";
    break;
  case AK_E_NET_BIND:
    cap_str = "net.bind";
    break;
  case AK_E_NET_LISTEN:
    cap_str = "net.listen";
    break;
  case AK_E_TOOL_CALL:
    cap_str = "tool";
    break;
  case AK_E_WASM_INVOKE:
    cap_str = "wasm";
    break;
  case AK_E_INFER:
    cap_str = "infer";
    break;
  case AK_E_PROC_SPAWN:
    cap_str = "spawn";
    break;
  case AK_E_PROC_SIGNAL:
    cap_str = "proc.signal";
    break;
  case AK_E_PROC_WAIT:
    cap_str = "proc.wait";
    break;
  default:
    break;
  }

  local_strncpy(cap, cap_str, max_len);
}

/* ============================================================
 * POLICY INSPECTION
 * ============================================================ */

void ak_policy_v2_get_hash(ak_policy_v2_t *policy, u8 *hash_out) {
  if (!policy || !hash_out)
    return;
  runtime_memcpy(hash_out, policy->policy_hash, AK_HASH_SIZE);
}

boolean ak_policy_v2_is_fail_closed(ak_policy_v2_t *policy) {
  if (!policy)
    return true;
  return policy->fail_closed;
}

u64 ak_policy_v2_get_loaded_ns(ak_policy_v2_t *policy) {
  if (!policy)
    return 0;
  return policy->loaded_ns;
}

/* ============================================================
 * PROFILE EXPANSION
 * ============================================================ */

int ak_policy_v2_expand_profile(ak_policy_v2_t *policy,
                                const char *profile_name) {
  if (!policy || !profile_name)
    return -EINVAL;

  const char *profile_json = NULL;

  /* Find built-in profile */
  if (local_strcmp(profile_name, "tier1-musl") == 0) {
    profile_json = AK_PROFILE_TIER1_MUSL;
  } else if (local_strcmp(profile_name, "tier2-glibc") == 0) {
    profile_json = AK_PROFILE_TIER2_GLIBC;
  } else {
    /* Unknown profile */
    return -ENOENT;
  }

  /* Parse profile JSON and merge into policy */
  if (profile_json) {
    if (!parse_json_policy(policy, (const u8 *)profile_json,
                           local_strlen(profile_json))) {
      return -EINVAL;
    }
  }

  return 0;
}
