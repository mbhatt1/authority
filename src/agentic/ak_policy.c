/*
 * Authority Kernel - Policy Engine Implementation
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * Implements INV-3: Budget Invariant
 * "The sum of in-flight and committed costs never exceeds budget."
 *
 * SECURITY: All policy decisions fail-closed on ambiguity.
 */

#include "ak_policy.h"
#include "ak_capability.h"
#include "ak_compat.h"
#include "ak_pattern.h"

/* ============================================================
 * GLOBAL STATE
 * ============================================================ */

static struct {
  heap h;
  boolean initialized;
} ak_policy_state;

/*
 * HMAC-SHA256 policy verification key (symmetric authentication, not an
 * Ed25519 digital signature - see ak_policy_verify_signature).
 * When configured, ak_policy_load() rejects unsigned/invalid policies.
 */
static struct {
  u8 key[AK_KEY_SIZE];
  boolean configured;
} ak_policy_verify_key;

/* ============================================================
 * INITIALIZATION
 * ============================================================ */

void ak_policy_init(heap h) {
  if (ak_policy_state.initialized)
    return;

  ak_policy_state.h = h;
  ak_policy_state.initialized = true;
}

void ak_policy_set_verification_key(const u8 *key) {
  if (!key) {
    runtime_memset(ak_policy_verify_key.key, 0, AK_KEY_SIZE);
    ak_policy_verify_key.configured = false;
    return;
  }
  runtime_memcpy(ak_policy_verify_key.key, key, AK_KEY_SIZE);
  ak_policy_verify_key.configured = true;
}

/* ============================================================
 * POLICY LOADING
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
static void compute_hash(buffer data, u8 *hash_out) {
  runtime_memset(hash_out, 0, AK_HASH_SIZE);
  if (data && buffer_length(data) > 0) {
    u8 *p = buffer_ref(data, 0);
    u64 len = buffer_length(data);
    ak_sha256(p, (u32)len, hash_out);
  }
}

/* Forward declaration (defined in POLICY VERIFICATION below) */
static boolean ak_policy_signature_is_empty(const u8 *sig, u32 len);

/* ============================================================
 * JSON POLICY PARSER
 * ============================================================
 * Minimal JSON parser for the host-produced policy document
 * (see ak_policy_load() in ak_policy.h for the format).
 * Any parse error fails the whole load (fail-closed).
 */

#define AK_POLICY_MAX_STR 256
#define AK_POLICY_MAX_JSON_DEPTH 32

static char *policy_strdup(heap h, const char *s) {
  u64 len = runtime_strlen(s) + 1;
  char *copy = allocate(h, len);
  if (copy)
    runtime_memcpy(copy, s, len);
  return copy;
}

/* Conservative default budgets (overridden by the parsed document) */
static void policy_set_default_budgets(ak_policy_t *policy) {
  policy->budgets.tokens = 10000;
  policy->budgets.calls = 10;
  policy->budgets.inference_ms = 30000;
  policy->budgets.file_bytes = 1024 * 1024; /* 1 MB */
  policy->budgets.network_bytes = 1024 * 1024;
  policy->budgets.spawn_count = 0; /* No spawning by default */
  policy->budgets.heap_objects = 100;
  policy->budgets.heap_bytes = 10 * 1024 * 1024; /* 10 MB */
}

static void free_tool_rules(heap h, ak_tool_rule_t *rule) {
  while (rule) {
    ak_tool_rule_t *next = rule->next;
    if (rule->name)
      deallocate(h, rule->name, runtime_strlen(rule->name) + 1);
    deallocate(h, rule, sizeof(ak_tool_rule_t));
    rule = next;
  }
}

static void free_domain_rules(heap h, ak_domain_rule_t *rule) {
  while (rule) {
    ak_domain_rule_t *next = rule->next;
    if (rule->pattern)
      deallocate(h, rule->pattern, runtime_strlen(rule->pattern) + 1);
    deallocate(h, rule, sizeof(ak_domain_rule_t));
    rule = next;
  }
}

static void free_taint_rules(heap h, ak_taint_rule_t *rule) {
  while (rule) {
    ak_taint_rule_t *next = rule->next;
    if (rule->name)
      deallocate(h, rule->name, runtime_strlen(rule->name) + 1);
    deallocate(h, rule, sizeof(ak_taint_rule_t));
    rule = next;
  }
}

/*
 * Rule insertion. Deny rules are prepended and allow rules appended so
 * that deny always wins for overlapping patterns under the first-match
 * semantics of ak_policy_check_tool()/ak_policy_check_domain(),
 * regardless of JSON key order.
 */
static boolean policy_add_tool_rule(ak_policy_t *policy, const char *name,
                                    u64 allow) {
  ak_tool_rule_t *rule = allocate(policy->h, sizeof(ak_tool_rule_t));
  if (!rule)
    return false;
  runtime_memset((u8 *)rule, 0, sizeof(ak_tool_rule_t));
  rule->name = policy_strdup(policy->h, name);
  if (!rule->name) {
    deallocate(policy->h, rule, sizeof(ak_tool_rule_t));
    return false;
  }
  rule->allow = (allow != 0);
  if (!rule->allow || !policy->tool_rules) {
    rule->next = policy->tool_rules;
    policy->tool_rules = rule;
  } else {
    ak_tool_rule_t *tail = policy->tool_rules;
    while (tail->next)
      tail = tail->next;
    rule->next = NULL;
    tail->next = rule;
  }
  return true;
}

static boolean policy_add_domain_rule(ak_policy_t *policy, const char *pattern,
                                      u64 allow) {
  ak_domain_rule_t *rule = allocate(policy->h, sizeof(ak_domain_rule_t));
  if (!rule)
    return false;
  runtime_memset((u8 *)rule, 0, sizeof(ak_domain_rule_t));
  rule->pattern = policy_strdup(policy->h, pattern);
  if (!rule->pattern) {
    deallocate(policy->h, rule, sizeof(ak_domain_rule_t));
    return false;
  }
  rule->allow = (allow != 0);
  if (!rule->allow || !policy->domain_rules) {
    rule->next = policy->domain_rules;
    policy->domain_rules = rule;
  } else {
    ak_domain_rule_t *tail = policy->domain_rules;
    while (tail->next)
      tail = tail->next;
    rule->next = NULL;
    tail->next = rule;
  }
  return true;
}

static boolean policy_add_taint_rule(ak_policy_t *policy, const char *name,
                                     u64 type) {
  ak_taint_rule_t *rule = allocate(policy->h, sizeof(ak_taint_rule_t));
  if (!rule)
    return false;
  runtime_memset((u8 *)rule, 0, sizeof(ak_taint_rule_t));
  rule->name = policy_strdup(policy->h, name);
  if (!rule->name) {
    deallocate(policy->h, rule, sizeof(ak_taint_rule_t));
    return false;
  }
  rule->type = (int)type;
  rule->next = policy->taint_rules;
  policy->taint_rules = rule;
  return true;
}

/* --- JSON scanning primitives --- */

static const u8 *pj_skip_ws(const u8 *p, const u8 *end) {
  while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
    p++;
  return p;
}

/* Parse a JSON string into out (NUL-terminated, truncating). */
static const u8 *pj_parse_string(const u8 *p, const u8 *end, char *out,
                                 u64 max_len) {
  if (p >= end || *p != '"')
    return NULL;
  p++;

  u64 i = 0;
  while (p < end && *p != '"') {
    char c;
    if (*p == '\\' && p + 1 < end) {
      p++;
      switch (*p) {
      case '"':
        c = '"';
        break;
      case '\\':
        c = '\\';
        break;
      case '/':
        c = '/';
        break;
      case 'n':
        c = '\n';
        break;
      case 'r':
        c = '\r';
        break;
      case 't':
        c = '\t';
        break;
      default:
        return NULL; /* Unknown/unicode escape - reject (fail-closed) */
      }
    } else {
      c = (char)*p;
    }
    if (i < max_len - 1)
      out[i++] = c;
    p++;
  }
  if (p >= end)
    return NULL; /* Unterminated string */
  out[i] = '\0';
  return p + 1;
}

/* Parse a non-negative decimal number, saturating on overflow. */
static const u8 *pj_parse_u64(const u8 *p, const u8 *end, u64 *out) {
  if (p >= end || *p < '0' || *p > '9')
    return NULL;
  *out = 0;
  while (p < end && *p >= '0' && *p <= '9') {
    u64 digit = *p - '0';
    if (*out > ((u64)-1 - digit) / 10) {
      *out = (u64)-1; /* Saturate */
      while (p < end && *p >= '0' && *p <= '9')
        p++;
      return p;
    }
    *out = (*out * 10) + digit;
    p++;
  }
  return p;
}

/* Skip any JSON value (bounded nesting depth). */
static const u8 *pj_skip_value(const u8 *p, const u8 *end) {
  p = pj_skip_ws(p, end);
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
  }
  if (*p == '{' || *p == '[') {
    int depth = 0;
    while (p < end) {
      if (*p == '{' || *p == '[') {
        if (++depth > AK_POLICY_MAX_JSON_DEPTH)
          return NULL;
      } else if (*p == '}' || *p == ']') {
        if (--depth == 0)
          return p + 1;
      } else if (*p == '"') {
        p++;
        while (p < end && *p != '"') {
          if (*p == '\\' && p + 1 < end)
            p++;
          p++;
        }
        if (p >= end)
          return NULL;
      }
      p++;
    }
    return NULL;
  }
  if (*p == '-' || (*p >= '0' && *p <= '9')) {
    if (*p == '-')
      p++;
    while (p < end && ((*p >= '0' && *p <= '9') || *p == '.'))
      p++;
    return p;
  }
  if ((end - p >= 4) && runtime_memcmp(p, "true", 4) == 0)
    return p + 4;
  if ((end - p >= 5) && runtime_memcmp(p, "false", 5) == 0)
    return p + 5;
  if ((end - p >= 4) && runtime_memcmp(p, "null", 4) == 0)
    return p + 4;
  return NULL;
}

/* Parse an array of strings, invoking cb(policy, str, arg) per element. */
typedef boolean (*pj_string_cb)(ak_policy_t *policy, const char *str, u64 arg);

static const u8 *pj_parse_string_array(const u8 *p, const u8 *end,
                                       ak_policy_t *policy, pj_string_cb cb,
                                       u64 arg) {
  p = pj_skip_ws(p, end);
  if (p >= end || *p != '[')
    return NULL;
  p++;

  while (p < end) {
    p = pj_skip_ws(p, end);
    if (p >= end)
      return NULL;
    if (*p == ']')
      return p + 1;

    char str[AK_POLICY_MAX_STR];
    p = pj_parse_string(p, end, str, sizeof(str));
    if (!p)
      return NULL;
    if (!cb(policy, str, arg))
      return NULL; /* Allocation failure - fail the whole load */

    p = pj_skip_ws(p, end);
    if (p >= end)
      return NULL;
    if (*p == ',')
      p++;
    else if (*p != ']')
      return NULL;
  }
  return NULL;
}

/* Parse an object whose members are string arrays: {"key": [...], ...} */
typedef struct pj_array_field {
  const char *key;
  pj_string_cb cb;
  u64 arg;
} pj_array_field_t;

static const u8 *pj_parse_array_object(const u8 *p, const u8 *end,
                                       ak_policy_t *policy,
                                       const pj_array_field_t *fields,
                                       int nfields) {
  p = pj_skip_ws(p, end);
  if (p >= end || *p != '{')
    return NULL;
  p++;

  while (p < end) {
    p = pj_skip_ws(p, end);
    if (p >= end)
      return NULL;
    if (*p == '}')
      return p + 1;

    char key[64];
    p = pj_parse_string(p, end, key, sizeof(key));
    if (!p)
      return NULL;
    p = pj_skip_ws(p, end);
    if (p >= end || *p != ':')
      return NULL;
    p++;

    int i;
    for (i = 0; i < nfields; i++) {
      if (ak_strcmp(key, fields[i].key) == 0) {
        p = pj_parse_string_array(p, end, policy, fields[i].cb, fields[i].arg);
        break;
      }
    }
    if (i == nfields)
      p = pj_skip_value(p, end); /* Unknown member */
    if (!p)
      return NULL;

    p = pj_skip_ws(p, end);
    if (p < end && *p == ',')
      p++;
  }
  return NULL;
}

/* Parse the budgets object: {"tokens": N, "calls": N, ...} */
static const u8 *pj_parse_budgets(const u8 *p, const u8 *end,
                                  ak_policy_t *policy) {
  p = pj_skip_ws(p, end);
  if (p >= end || *p != '{')
    return NULL;
  p++;

  while (p < end) {
    p = pj_skip_ws(p, end);
    if (p >= end)
      return NULL;
    if (*p == '}')
      return p + 1;

    char key[32];
    p = pj_parse_string(p, end, key, sizeof(key));
    if (!p)
      return NULL;
    p = pj_skip_ws(p, end);
    if (p >= end || *p != ':')
      return NULL;
    p++;
    p = pj_skip_ws(p, end);
    if (p >= end)
      return NULL;

    if (*p >= '0' && *p <= '9') {
      u64 val;
      p = pj_parse_u64(p, end, &val);
      if (!p)
        return NULL;
      if (ak_strcmp(key, "tokens") == 0)
        policy->budgets.tokens = val;
      else if (ak_strcmp(key, "calls") == 0 ||
               ak_strcmp(key, "tool_calls") == 0)
        policy->budgets.calls = val;
      else if (ak_strcmp(key, "inference_ms") == 0)
        policy->budgets.inference_ms = val;
      else if (ak_strcmp(key, "file_bytes") == 0)
        policy->budgets.file_bytes = val;
      else if (ak_strcmp(key, "network_bytes") == 0)
        policy->budgets.network_bytes = val;
      else if (ak_strcmp(key, "spawn_count") == 0)
        policy->budgets.spawn_count = val;
      else if (ak_strcmp(key, "heap_objects") == 0)
        policy->budgets.heap_objects = val;
      else if (ak_strcmp(key, "heap_bytes") == 0)
        policy->budgets.heap_bytes = val;
      /* Unknown numeric budget keys are ignored */
    } else {
      p = pj_skip_value(p, end);
      if (!p)
        return NULL;
    }

    p = pj_skip_ws(p, end);
    if (p < end && *p == ',')
      p++;
  }
  return NULL;
}

static int hex_nibble(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

/* Decode exactly 2 * out_len hex chars into out. */
static boolean parse_hex_bytes(const char *hex, u8 *out, u64 out_len) {
  for (u64 i = 0; i < out_len; i++) {
    int hi = hex_nibble(hex[i * 2]);
    int lo = hex_nibble(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0)
      return false;
    out[i] = (u8)((hi << 4) | lo);
  }
  return true;
}

/*
 * Parse the top-level policy document into an initialized policy.
 * Returns false on any parse or allocation error (fail-closed).
 */
static boolean ak_policy_parse_json(ak_policy_t *policy, const u8 *data,
                                    u64 len) {
  static const pj_array_field_t tool_fields[] = {
      {"allow", policy_add_tool_rule, 1},
      {"deny", policy_add_tool_rule, 0},
  };
  static const pj_array_field_t domain_fields[] = {
      {"allow", policy_add_domain_rule, 1},
      {"deny", policy_add_domain_rule, 0},
  };
  static const pj_array_field_t taint_fields[] = {
      {"sources", policy_add_taint_rule, AK_TAINT_RULE_SOURCE},
      {"sinks", policy_add_taint_rule, AK_TAINT_RULE_SINK},
      {"sanitizers", policy_add_taint_rule, AK_TAINT_RULE_SANITIZER},
  };

  const u8 *p = data;
  const u8 *end = data + len;

  p = pj_skip_ws(p, end);
  if (p >= end || *p != '{')
    return false; /* Not a JSON policy document */
  p++;

  while (p < end) {
    p = pj_skip_ws(p, end);
    if (p >= end)
      return false;
    if (*p == '}') {
      p++;
      p = pj_skip_ws(p, end);
      return (p == end); /* Reject trailing garbage */
    }

    char key[64];
    p = pj_parse_string(p, end, key, sizeof(key));
    if (!p)
      return false;
    p = pj_skip_ws(p, end);
    if (p >= end || *p != ':')
      return false;
    p++;
    p = pj_skip_ws(p, end);

    if (ak_strcmp(key, "version") == 0) {
      p = pj_parse_string(p, end, policy->version, sizeof(policy->version));
    } else if (ak_strcmp(key, "signature") == 0) {
      /* Hex-encoded HMAC-SHA256 tag: 64 hex chars (32-byte MAC) or
       * 128 hex chars (full AK_SIG_SIZE field, tail normally zero) */
      char sighex[2 * AK_SIG_SIZE + 1];
      p = pj_parse_string(p, end, sighex, sizeof(sighex));
      if (p) {
        u64 hexlen = runtime_strlen(sighex);
        if (hexlen == 2 * AK_MAC_SIZE) {
          if (!parse_hex_bytes(sighex, policy->signature, AK_MAC_SIZE))
            return false;
        } else if (hexlen == 2 * AK_SIG_SIZE) {
          if (!parse_hex_bytes(sighex, policy->signature, AK_SIG_SIZE))
            return false;
        } else if (hexlen != 0) {
          return false; /* Malformed signature - reject */
        }
      }
    } else if (ak_strcmp(key, "budgets") == 0) {
      p = pj_parse_budgets(p, end, policy);
    } else if (ak_strcmp(key, "tools") == 0) {
      p = pj_parse_array_object(p, end, policy, tool_fields, 2);
    } else if (ak_strcmp(key, "domains") == 0) {
      p = pj_parse_array_object(p, end, policy, domain_fields, 2);
    } else if (ak_strcmp(key, "taint") == 0) {
      p = pj_parse_array_object(p, end, policy, taint_fields, 3);
    } else {
      p = pj_skip_value(p, end); /* Unknown top-level member */
    }
    if (!p)
      return false;

    p = pj_skip_ws(p, end);
    if (p < end && *p == ',')
      p++;
  }
  return false; /* Unterminated object */
}

ak_policy_t *ak_policy_load(heap h, buffer yaml_data) {
  if (!yaml_data || buffer_length(yaml_data) == 0)
    return NULL;

  ak_policy_t *policy = allocate(h, sizeof(ak_policy_t));
  if (!policy)
    return NULL;

  runtime_memset((u8 *)policy, 0, sizeof(ak_policy_t));
  policy->h = h;
  runtime_memcpy(policy->version, AK_POLICY_VERSION,
                 runtime_strlen(AK_POLICY_VERSION));

  /* Conservative defaults; the parsed document overrides budgets. */
  policy_set_default_budgets(policy);

  /* Deny-by-default; rules from the document open access explicitly. */
  policy->default_tool_allow = false;
  policy->default_domain_allow = false;

  /*
   * Parse the JSON policy document. Input that does not parse is
   * REJECTED rather than silently replaced with defaults - callers
   * wanting defaults must use ak_policy_default().
   */
  if (!ak_policy_parse_json(policy, buffer_ref(yaml_data, 0),
                            buffer_length(yaml_data))) {
    ak_error("SECURITY: policy load rejected: input is not a valid JSON "
             "policy document (fail-closed)");
    ak_policy_destroy(h, policy);
    return NULL;
  }

  /*
   * Compute the canonical policy hash. This binds ALL security-relevant
   * fields (budgets, tools, domains, taint, defaults) and is the value
   * covered by the HMAC-SHA256 tag.
   */
  ak_policy_compute_hash(policy, policy->policy_hash);

  /*
   * Integrity check (HMAC-SHA256 symmetric authentication, not an
   * Ed25519 signature):
   *   - Key configured: unsigned or wrongly-tagged policies are REJECTED.
   *   - No key configured: policy is accepted but explicitly flagged
   *     unsigned; it is never treated as verified.
   */
  boolean is_unsigned =
      ak_policy_signature_is_empty(policy->signature, AK_SIG_SIZE);
  if (ak_policy_verify_key.configured) {
    if (is_unsigned ||
        !ak_policy_verify_signature(policy, ak_policy_verify_key.key)) {
      ak_error("SECURITY: policy rejected: %s (verification key configured)",
               is_unsigned ? "unsigned policy" : "HMAC verification failed");
      ak_policy_destroy(h, policy);
      return NULL;
    }
    policy->signature_verified = true;
  } else {
    policy->signature_verified = false;
    if (is_unsigned)
      ak_warn("SECURITY: policy loaded UNSIGNED (no verification key "
              "configured); integrity is NOT guaranteed");
    else
      ak_warn("SECURITY: policy carries an HMAC tag but no verification key "
              "is configured; treating policy as UNVERIFIED");
  }

  /* Initialize versioning */
  ak_policy_version_t *ver = allocate(h, sizeof(ak_policy_version_t));
  if (ver) {
    runtime_memset((u8 *)ver, 0, sizeof(ak_policy_version_t));
    ver->version_number = 1;
    ver->activated_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
    runtime_memcpy(ver->hash, policy->policy_hash, AK_HASH_SIZE);
    /* Clone raw document for version history */
    ver->rules_json = allocate_buffer(h, buffer_length(yaml_data));
    if (ver->rules_json)
      buffer_write(ver->rules_json, buffer_ref(yaml_data, 0),
                   buffer_length(yaml_data));
    ver->prev = NULL;
    policy->current_version = ver;
    policy->version_count = 1;
  }

  return policy;
}

ak_policy_t *ak_policy_load_file(heap h, const char *path) {
  if (!path)
    return NULL;

  /*
   * File loading requires filesystem integration.
   * In unikernel context, policies are typically:
   *   - Embedded in supervisor binary
   *   - Loaded via virtio from host
   *   - Fetched from network at boot
   */
  (void)h;
  (void)path;

  return NULL;
}

void ak_policy_destroy(heap h, ak_policy_t *policy) {
  if (!policy)
    return;

  free_tool_rules(h, policy->tool_rules);
  free_domain_rules(h, policy->domain_rules);
  free_taint_rules(h, policy->taint_rules);

  deallocate(h, policy, sizeof(ak_policy_t));
}

void ak_policy_get_hash(ak_policy_t *policy, u8 *hash_out) {
  if (policy && hash_out)
    runtime_memcpy(hash_out, policy->policy_hash, AK_HASH_SIZE);
}

/* ============================================================
 * POLICY VERIFICATION
 * ============================================================ */

/*
 * HMAC-SHA256 implementation for policy signature verification.
 * Computes HMAC(key, message) = H((key XOR opad) || H((key XOR ipad) ||
 * message))
 */
static void ak_policy_hmac_sha256(const u8 *key, u32 key_len, const u8 *data,
                                  u32 data_len, u8 *output) {
  u8 key_block[64];
  u8 inner_hash[32];
  u8 ipad[64];
  u8 opad[64];

  /* Step 1: Prepare key block (pad or hash if necessary) */
  runtime_memset(key_block, 0, 64);
  if (key_len > 64) {
    /* Key longer than block size: hash it first */
    ak_sha256(key, key_len, key_block);
  } else {
    /* Copy key, padding with zeros */
    runtime_memcpy(key_block, key, key_len);
  }

  /* Step 2: Compute ipad and opad */
  for (int i = 0; i < 64; i++) {
    ipad[i] = key_block[i] ^ 0x36;
    opad[i] = key_block[i] ^ 0x5c;
  }

  /* Step 3: Inner hash: H(ipad || message) */
  /* We need to allocate a temporary buffer for ipad || message */
  u32 inner_len = 64 + data_len;
  u8 *inner_buf = allocate(ak_policy_state.h, inner_len);
  if (!inner_buf) {
    runtime_memset(output, 0, 32);
    return;
  }
  runtime_memcpy(inner_buf, ipad, 64);
  runtime_memcpy(inner_buf + 64, data, data_len);
  ak_sha256(inner_buf, inner_len, inner_hash);
  deallocate(ak_policy_state.h, inner_buf, inner_len);

  /* Step 4: Outer hash: H(opad || inner_hash) */
  u8 outer_buf[64 + 32];
  runtime_memcpy(outer_buf, opad, 64);
  runtime_memcpy(outer_buf + 64, inner_hash, 32);
  ak_sha256(outer_buf, 64 + 32, output);

  /* Clear sensitive data */
  runtime_memset(key_block, 0, 64);
  runtime_memset(inner_hash, 0, 32);
  runtime_memset(ipad, 0, 64);
  runtime_memset(opad, 0, 64);
}

/*
 * Constant-time comparison to prevent timing attacks.
 * Returns true if buffers are equal, false otherwise.
 */
static boolean ak_policy_constant_time_compare(const u8 *a, const u8 *b,
                                               u32 len) {
  u8 diff = 0;
  for (u32 i = 0; i < len; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

/*
 * Check if a signature buffer contains all zeros (unsigned policy).
 */
static boolean ak_policy_signature_is_empty(const u8 *sig, u32 len) {
  for (u32 i = 0; i < len; i++) {
    if (sig[i] != 0)
      return false;
  }
  return true;
}

/*
 * Verify policy authentication tag using HMAC-SHA256.
 *
 * NOTE: This is SYMMETRIC authentication (HMAC-SHA256), not an Ed25519
 * digital signature - AK_SIG_SIZE's "Ed25519" label in ak_config.h and
 * ak_types.h describes only the 64-byte field width. Anyone holding the
 * key can forge tags, so this provides tamper detection against parties
 * without the key, not third-party-verifiable provenance.
 *
 * Verification process:
 * 1. Compute HMAC-SHA256 over the canonical policy hash using the key
 * 2. Compare computed MAC with stored tag using constant-time comparison
 * 3. Return true only if the tags match exactly
 *
 * SECURITY: Policy tags protect against tampering. Always require
 * signatures in production. ak_policy_load() enforces this whenever a
 * verification key is configured via ak_policy_set_verification_key().
 */
boolean ak_policy_verify_signature(ak_policy_t *policy, u8 *signing_key) {
  if (!policy)
    return false;

  /*
   * Check if signature is empty (all zeros = unsigned policy)
   */
  boolean is_unsigned =
      ak_policy_signature_is_empty(policy->signature, AK_SIG_SIZE);

  /*
   * Handle unsigned policies based on configuration
   */
  if (is_unsigned) {
    /*
     * Runtime override: If AK_REQUIRE_POLICY_SIGNATURES is set,
     * always require signatures regardless of compile-time setting.
     */
#if AK_REQUIRE_POLICY_SIGNATURES
    ak_error("SECURITY: Unsigned policy rejected (runtime signature "
             "requirement enabled)");
    return false;
#endif

    /*
     * Development mode: Allow unsigned policies with warning
     */
#if AK_ALLOW_UNSIGNED_POLICIES
    ak_warn("SECURITY WARNING: Loading unsigned policy in development mode");
    ak_warn("  Policy hash: %02x%02x%02x%02x%02x%02x%02x%02x...",
            policy->policy_hash[0], policy->policy_hash[1],
            policy->policy_hash[2], policy->policy_hash[3],
            policy->policy_hash[4], policy->policy_hash[5],
            policy->policy_hash[6], policy->policy_hash[7]);
    ak_warn("  Unsigned policies are ONLY permitted for development");
    ak_warn("  Production builds MUST set AK_ALLOW_UNSIGNED_POLICIES=0");
    return true;
#else
    /*
     * Production mode: Reject unsigned policies
     */
    ak_error("SECURITY: Unsigned policy rejected (signatures required in "
             "production)");
    ak_error("  Policy hash: %02x%02x%02x%02x%02x%02x%02x%02x...",
             policy->policy_hash[0], policy->policy_hash[1],
             policy->policy_hash[2], policy->policy_hash[3],
             policy->policy_hash[4], policy->policy_hash[5],
             policy->policy_hash[6], policy->policy_hash[7]);
    return false;
#endif
  }

  /*
   * Policy has a signature - verify it
   */
  if (!signing_key) {
    ak_error("SECURITY: Cannot verify policy signature without signing key");
    return false;
  }

  /*
   * Compute expected HMAC over policy content hash
   * The signature covers: HMAC-SHA256(signing_key, policy_hash)
   */
  u8 computed_mac[AK_MAC_SIZE];
  ak_policy_hmac_sha256(signing_key, AK_KEY_SIZE, policy->policy_hash,
                        AK_HASH_SIZE, computed_mac);

  /*
   * Constant-time comparison to prevent timing attacks
   * Compare only first AK_MAC_SIZE bytes of signature
   */
  boolean valid = ak_policy_constant_time_compare(
      computed_mac, policy->signature, AK_MAC_SIZE);

  /* Clear sensitive data */
  runtime_memset(computed_mac, 0, AK_MAC_SIZE);

  if (!valid) {
    ak_error("SECURITY: Policy signature verification failed");
    ak_error("  Policy hash: %02x%02x%02x%02x%02x%02x%02x%02x...",
             policy->policy_hash[0], policy->policy_hash[1],
             policy->policy_hash[2], policy->policy_hash[3],
             policy->policy_hash[4], policy->policy_hash[5],
             policy->policy_hash[6], policy->policy_hash[7]);
    return false;
  }

  return true;
}

/*
 * Sign a policy using HMAC-SHA256.
 *
 * This function is provided for policy generation tools to create
 * signed policies that can be verified at runtime.
 */
boolean ak_policy_sign(ak_policy_t *policy, const u8 *signing_key) {
  if (!policy || !signing_key)
    return false;

  /*
   * Compute HMAC-SHA256 over policy content hash
   * Store result in first AK_MAC_SIZE bytes of signature field
   */
  ak_policy_hmac_sha256(signing_key, AK_KEY_SIZE, policy->policy_hash,
                        AK_HASH_SIZE, policy->signature);

  /* Zero out remaining bytes of signature field */
  runtime_memset(policy->signature + AK_MAC_SIZE, 0, AK_SIG_SIZE - AK_MAC_SIZE);

  return true;
}

boolean ak_policy_expired(ak_policy_t *policy) {
  if (!policy)
    return true;

  if (policy->expires_ms == 0)
    return false; /* No expiration */

  /* Get current monotonic time and compare to expiration */
  u64 now_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
  return now_ms > policy->expires_ms;
}

/* ============================================================
 * BUDGET TRACKING
 * ============================================================
 * Budget functions have been moved to ak_budget.c as part of
 * production-grade budget tracking implementation.
 * See ak_budget.h for API documentation.
 * ============================================================ */

/* ============================================================
 * TOOL AUTHORIZATION
 * ============================================================ */

boolean ak_policy_check_tool(ak_policy_t *policy, const char *tool_name) {
  if (!policy || !tool_name)
    return false; /* Fail-closed */

  ak_tool_rule_t *rule = policy->tool_rules;
  while (rule) {
    if (rule->name) {
      /* Exact match */
      if (ak_strcmp(rule->name, tool_name) == 0)
        return rule->allow;

      /* Glob pattern match */
      if (ak_pattern_match(rule->name, tool_name))
        return rule->allow;
    }
    rule = rule->next;
  }

  return policy->default_tool_allow;
}

const char **ak_policy_list_allowed_tools(heap h, ak_policy_t *policy,
                                          u64 *count_out) {
  if (!policy || !count_out)
    return NULL;

  /* Count allowed tools */
  u64 count = 0;
  ak_tool_rule_t *rule = policy->tool_rules;
  while (rule) {
    if (rule->allow)
      count++;
    rule = rule->next;
  }

  if (count == 0) {
    *count_out = 0;
    return NULL;
  }

  const char **result = allocate(h, count * sizeof(char *));
  if (!result) {
    *count_out = 0;
    return NULL;
  }

  u64 idx = 0;
  rule = policy->tool_rules;
  while (rule) {
    if (rule->allow)
      result[idx++] = rule->name;
    rule = rule->next;
  }

  *count_out = count;
  return result;
}

/* ============================================================
 * DOMAIN AUTHORIZATION
 * ============================================================ */

boolean ak_policy_check_domain(ak_policy_t *policy, const char *domain) {
  if (!policy || !domain)
    return false; /* Fail-closed */

  ak_domain_rule_t *rule = policy->domain_rules;
  while (rule) {
    if (rule->pattern && ak_pattern_match(rule->pattern, domain))
      return rule->allow;
    rule = rule->next;
  }

  return policy->default_domain_allow;
}

boolean ak_policy_check_url(ak_policy_t *policy, const char *url) {
  if (!policy || !url)
    return false;

  /*
   * Extract domain from URL
   * Handle: http://domain/path, https://domain/path
   */
  const char *start = url;

  /* Skip scheme */
  if (runtime_strncmp(url, "http://", 7) == 0)
    start = url + 7;
  else if (runtime_strncmp(url, "https://", 8) == 0)
    start = url + 8;

  /* Find end of domain (at / or end of string) */
  const char *end = start;
  while (*end && *end != '/' && *end != ':')
    end++;

  u64 len = end - start;
  if (len == 0 || len > 256)
    return false;

  /* Copy domain */
  char domain[257];
  runtime_memcpy(domain, start, len);
  domain[len] = '\0';

  return ak_policy_check_domain(policy, domain);
}

/* ============================================================
 * TAINT FLOW CONTROL
 * ============================================================ */

boolean ak_policy_is_source(ak_policy_t *policy, const char *name) {
  if (!policy || !name)
    return false;

  ak_taint_rule_t *rule = policy->taint_rules;
  while (rule) {
    if (rule->type == AK_TAINT_RULE_SOURCE && rule->name &&
        ak_strcmp(rule->name, name) == 0)
      return true;
    rule = rule->next;
  }
  return false;
}

boolean ak_policy_is_sink(ak_policy_t *policy, const char *name) {
  if (!policy || !name)
    return false;

  ak_taint_rule_t *rule = policy->taint_rules;
  while (rule) {
    if (rule->type == AK_TAINT_RULE_SINK && rule->name &&
        ak_strcmp(rule->name, name) == 0)
      return true;
    rule = rule->next;
  }
  return false;
}

boolean ak_policy_is_sanitizer(ak_policy_t *policy, const char *name) {
  if (!policy || !name)
    return false;

  ak_taint_rule_t *rule = policy->taint_rules;
  while (rule) {
    if (rule->type == AK_TAINT_RULE_SANITIZER && rule->name &&
        ak_strcmp(rule->name, name) == 0)
      return true;
    rule = rule->next;
  }
  return false;
}

boolean ak_policy_check_flow(ak_policy_t *policy, ak_taint_t source_taint,
                             const char *sink_name, boolean sanitized) {
  if (!policy)
    return false;

  /* Trusted data can flow anywhere */
  if (source_taint == AK_TAINT_TRUSTED)
    return true;

  /* Check if this is a defined sink */
  if (!ak_policy_is_sink(policy, sink_name))
    return true; /* Not a sensitive sink */

  /* Tainted data to sensitive sink requires sanitization */
  if (source_taint == AK_TAINT_UNTRUSTED && !sanitized)
    return false;

  /* Sanitized data is allowed */
  if (sanitized)
    return true;

  /* Default: block tainted flows to sinks */
  return false;
}

/* ============================================================
 * REQUEST EVALUATION
 * ============================================================ */

/*
 * Extract a top-level string field from a JSON args buffer.
 * Returns value length (> 0) on success, -1 on failure.
 * (Same scanning approach as ak_json_extract_string in ak_syscall.c.)
 */
static s64 json_get_string_field(buffer json, const char *key, char *out,
                                 u64 out_len) {
  if (!json || !key || !out || out_len == 0)
    return -1;

  u8 *data = buffer_ref(json, 0);
  u64 len = buffer_length(json);
  u64 key_len = runtime_strlen(key);

  for (u64 i = 0; i + key_len + 4 < len; i++) {
    if (data[i] == '"' && runtime_memcmp(&data[i + 1], key, key_len) == 0 &&
        data[i + 1 + key_len] == '"') {

      u64 j = i + 1 + key_len + 1;
      while (j < len && (data[j] == ':' || data[j] == ' ' || data[j] == '\t'))
        j++;

      if (j >= len || data[j] != '"')
        return -1;
      j++;

      u64 start = j;
      while (j < len && data[j] != '"') {
        if (data[j] == '\\' && j + 1 < len)
          j++;
        j++;
      }

      u64 value_len = j - start;
      if (value_len >= out_len)
        value_len = out_len - 1;

      runtime_memcpy(out, &data[start], value_len);
      out[value_len] = 0;
      return value_len;
    }
  }
  return -1;
}

s64 ak_policy_evaluate(ak_policy_t *policy, ak_budget_tracker_t *budget,
                       ak_request_t *req) {
  if (!policy || !req)
    return -EINVAL;

  /*
   * Comprehensive policy check:
   * 1. Budget check
   * 2. Tool authorization (for CALL)
   * 3. Domain restrictions (for network-bound CALL args)
   * 4. Taint flow rules
   */

  /* Budget check */
  if (budget) {
    ak_resource_type_t resource_type;
    u64 estimated_cost = 1; /* Default cost */

    switch (req->op) {
    case AK_SYS_INFERENCE:
    case AK_SYS_INFER_ISSUE:
      resource_type = AK_RESOURCE_TOKENS;
      estimated_cost = 1000; /* Estimate */
      break;
    case AK_SYS_CALL:
      resource_type = AK_RESOURCE_CALLS;
      estimated_cost = 1;
      break;
    case AK_SYS_ALLOC:
      resource_type = AK_RESOURCE_HEAP_OBJECTS;
      estimated_cost = 1;
      break;
    default:
      resource_type = AK_RESOURCE_CALLS;
      estimated_cost = 0; /* No cost for reads */
    }

    if (estimated_cost > 0 &&
        !ak_budget_check(budget, resource_type, estimated_cost))
      return AK_E_BUDGET_EXCEEDED;
  }

  /*
   * Data that passed a sanitizer carries one of the intermediate
   * AK_TAINT_SANITIZED_* levels (between TRUSTED and UNTRUSTED).
   */
  boolean sanitized =
      (req->taint > AK_TAINT_TRUSTED && req->taint < AK_TAINT_UNTRUSTED);

  /* Tool authorization for CALL (fail-closed) */
  if (req->op == AK_SYS_CALL) {
    char tool_name[64];
    if (json_get_string_field(req->args, "tool", tool_name,
                              sizeof(tool_name)) <= 0)
      return AK_E_POLICY_DENIED; /* Cannot identify tool - deny */

    if (!ak_policy_check_tool(policy, tool_name))
      return AK_E_POLICY_DENIED;

    /* Domain restrictions for network-bound tool calls */
    char target[257];
    if (json_get_string_field(req->args, "url", target, sizeof(target)) > 0) {
      if (!ak_policy_check_url(policy, target))
        return AK_E_POLICY_DENIED;
    } else if (json_get_string_field(req->args, "domain", target,
                                     sizeof(target)) > 0) {
      if (!ak_policy_check_domain(policy, target))
        return AK_E_POLICY_DENIED;
    }

    /* Taint flow: untrusted data must not reach a sink tool unsanitized */
    if (!ak_policy_check_flow(policy, req->taint, tool_name, sanitized))
      return AK_E_TAINT;
  }

  /* Taint flow for other policy-defined sinks */
  if (req->op == AK_SYS_INFERENCE &&
      !ak_policy_check_flow(policy, req->taint, "inference", sanitized))
    return AK_E_TAINT;

  if (req->op == AK_SYS_RESPOND &&
      !ak_policy_check_flow(policy, req->taint, "respond", sanitized))
    return AK_E_TAINT;

  return 0; /* Allowed */
}

/* ============================================================
 * SERIALIZATION
 * ============================================================ */

/* Append a NUL-terminated string to a buffer */
static void buffer_write_cstr(buffer b, const char *s) {
  buffer_write(b, s, runtime_strlen(s));
}

/* Append a u64 in decimal to a buffer */
static void buffer_write_u64_dec(buffer b, u64 val) {
  char num_buf[24];
  int len = 0;

  if (val == 0) {
    num_buf[0] = '0';
    len = 1;
  } else {
    char tmp[24];
    while (val > 0) {
      tmp[len++] = '0' + (val % 10);
      val /= 10;
    }
    for (int i = 0; i < len; i++)
      num_buf[i] = tmp[len - 1 - i];
  }
  buffer_write(b, num_buf, len);
}

/* Append "  key: value\n" */
static void serialize_u64_field(buffer b, const char *key, u64 val) {
  buffer_write_cstr(b, "  ");
  buffer_write_cstr(b, key);
  buffer_write_cstr(b, ": ");
  buffer_write_u64_dec(b, val);
  buffer_write_cstr(b, "\n");
}

buffer ak_policy_serialize(heap h, ak_policy_t *policy) {
  if (!policy)
    return NULL;

  /*
   * Canonical, deterministic serialization of ALL security-relevant
   * fields. ak_policy_compute_hash() hashes this output, and the
   * HMAC-SHA256 tag covers that hash, so every field that affects
   * enforcement MUST be emitted here (the signature itself is
   * intentionally excluded). Rule order follows the stored lists,
   * which is deterministic for a given input document.
   */

  buffer result = allocate_buffer(h, 1024);
  if (!result)
    return NULL;

  buffer_write_cstr(result, "version: \"");
  buffer_write_cstr(result, policy->version);
  buffer_write_cstr(result, "\"\n");

  buffer_write_cstr(result, "expires_ms: ");
  buffer_write_u64_dec(result, policy->expires_ms);
  buffer_write_cstr(result, "\n");

  buffer_write_cstr(result, "defaults:\n");
  serialize_u64_field(result, "tool_allow", policy->default_tool_allow ? 1 : 0);
  serialize_u64_field(result, "domain_allow",
                      policy->default_domain_allow ? 1 : 0);

  buffer_write_cstr(result, "budgets:\n");
  serialize_u64_field(result, "tokens", policy->budgets.tokens);
  serialize_u64_field(result, "calls", policy->budgets.calls);
  serialize_u64_field(result, "inference_ms", policy->budgets.inference_ms);
  serialize_u64_field(result, "file_bytes", policy->budgets.file_bytes);
  serialize_u64_field(result, "network_bytes", policy->budgets.network_bytes);
  serialize_u64_field(result, "spawn_count", policy->budgets.spawn_count);
  serialize_u64_field(result, "heap_objects", policy->budgets.heap_objects);
  serialize_u64_field(result, "heap_bytes", policy->budgets.heap_bytes);

  buffer_write_cstr(result, "tools:\n");
  for (ak_tool_rule_t *tool = policy->tool_rules; tool; tool = tool->next) {
    buffer_write_cstr(result, "  - \"");
    buffer_write_cstr(result, tool->name ? tool->name : "");
    buffer_write_cstr(result, tool->allow ? "\": allow\n" : "\": deny\n");
  }

  buffer_write_cstr(result, "domains:\n");
  for (ak_domain_rule_t *dom = policy->domain_rules; dom; dom = dom->next) {
    buffer_write_cstr(result, "  - \"");
    buffer_write_cstr(result, dom->pattern ? dom->pattern : "");
    buffer_write_cstr(result, dom->allow ? "\": allow\n" : "\": deny\n");
  }

  buffer_write_cstr(result, "taint:\n");
  for (ak_taint_rule_t *taint = policy->taint_rules; taint;
       taint = taint->next) {
    buffer_write_cstr(result, "  - \"");
    buffer_write_cstr(result, taint->name ? taint->name : "");
    switch (taint->type) {
    case AK_TAINT_RULE_SOURCE:
      buffer_write_cstr(result, "\": source\n");
      break;
    case AK_TAINT_RULE_SINK:
      buffer_write_cstr(result, "\": sink\n");
      break;
    default:
      buffer_write_cstr(result, "\": sanitizer\n");
      break;
    }
  }

  return result;
}

void ak_policy_compute_hash(ak_policy_t *policy, u8 *hash_out) {
  if (!policy || !hash_out)
    return;

  /*
   * Hash is computed over the canonical serialization, which covers
   * all security-relevant policy fields (see ak_policy_serialize).
   */
  heap h = policy->h ? policy->h : ak_policy_state.h;
  buffer serialized = ak_policy_serialize(h, policy);
  if (serialized) {
    compute_hash(serialized, hash_out);
    deallocate_buffer(serialized);
  }
}

/* ============================================================
 * DEFAULT POLICIES
 * ============================================================ */

ak_policy_t *ak_policy_default(heap h) {
  ak_policy_t *policy = allocate(h, sizeof(ak_policy_t));
  if (!policy)
    return NULL;

  runtime_memset((u8 *)policy, 0, sizeof(ak_policy_t));
  policy->h = h;
  runtime_memcpy(policy->version, AK_POLICY_VERSION,
                 runtime_strlen(AK_POLICY_VERSION));

  /* Conservative budgets */
  policy->budgets.tokens = 10000;
  policy->budgets.calls = 10;
  policy->budgets.inference_ms = 30000;
  policy->budgets.file_bytes = 1024 * 1024;    /* 1 MB */
  policy->budgets.network_bytes = 1024 * 1024; /* 1 MB */
  policy->budgets.spawn_count = 0;             /* No spawning */
  policy->budgets.heap_objects = 100;
  policy->budgets.heap_bytes = 10 * 1024 * 1024; /* 10 MB */

  /* Deny by default */
  policy->default_tool_allow = false;
  policy->default_domain_allow = false;

  /* Add safe tools */
  ak_tool_rule_t *rule1 = allocate(h, sizeof(ak_tool_rule_t));
  if (rule1) {
    const char *name = "file_read";
    rule1->name = allocate(h, runtime_strlen(name) + 1);
    if (rule1->name)
      runtime_memcpy(rule1->name, name, runtime_strlen(name) + 1);
    rule1->allow = true;
    rule1->next = policy->tool_rules;
    policy->tool_rules = rule1;
  }

  /* Add taint sink for dangerous operations */
  ak_taint_rule_t *taint1 = allocate(h, sizeof(ak_taint_rule_t));
  if (taint1) {
    const char *name = "shell_exec";
    taint1->name = allocate(h, runtime_strlen(name) + 1);
    if (taint1->name)
      runtime_memcpy(taint1->name, name, runtime_strlen(name) + 1);
    taint1->type = AK_TAINT_RULE_SINK;
    taint1->next = policy->taint_rules;
    policy->taint_rules = taint1;
  }

  ak_policy_compute_hash(policy, policy->policy_hash);

  /* Initialize versioning */
  ak_policy_version_t *ver = allocate(h, sizeof(ak_policy_version_t));
  if (ver) {
    runtime_memset((u8 *)ver, 0, sizeof(ak_policy_version_t));
    ver->version_number = 1;
    ver->activated_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
    runtime_memcpy(ver->hash, policy->policy_hash, AK_HASH_SIZE);
    ver->rules_json = NULL;
    ver->prev = NULL;
    policy->current_version = ver;
    policy->version_count = 1;
  }

  return policy;
}

ak_policy_t *ak_policy_permissive(heap h) {
  ak_policy_t *policy = allocate(h, sizeof(ak_policy_t));
  if (!policy)
    return NULL;

  runtime_memset((u8 *)policy, 0, sizeof(ak_policy_t));
  policy->h = h;
  runtime_memcpy(policy->version, AK_POLICY_VERSION,
                 runtime_strlen(AK_POLICY_VERSION));

  /* High budgets for development */
  policy->budgets.tokens = 1000000;
  policy->budgets.calls = 10000;
  policy->budgets.inference_ms = 3600000;         /* 1 hour */
  policy->budgets.file_bytes = 1024 * 1024 * 100; /* 100 MB */
  policy->budgets.network_bytes = 1024 * 1024 * 100;
  policy->budgets.spawn_count = 100;
  policy->budgets.heap_objects = 100000;
  policy->budgets.heap_bytes = 1024 * 1024 * 1024; /* 1 GB */

  /* Allow by default (DANGEROUS) */
  policy->default_tool_allow = true;
  policy->default_domain_allow = true;

  ak_policy_compute_hash(policy, policy->policy_hash);

  /* Initialize versioning */
  ak_policy_version_t *ver = allocate(h, sizeof(ak_policy_version_t));
  if (ver) {
    runtime_memset((u8 *)ver, 0, sizeof(ak_policy_version_t));
    ver->version_number = 1;
    ver->activated_ms = now(CLOCK_ID_MONOTONIC) / MILLION;
    runtime_memcpy(ver->hash, policy->policy_hash, AK_HASH_SIZE);
    ver->rules_json = NULL;
    ver->prev = NULL;
    policy->current_version = ver;
    policy->version_count = 1;
  }

  return policy;
}

/* ============================================================
 * POLICY VERSIONING
 * ============================================================ */

/*
 * Parse rules from a JSON buffer and apply them to the policy.
 *
 * The document is parsed into a staged copy first, so any parse,
 * allocation, or integrity failure leaves the active rules untouched
 * (fail-closed: the previous policy remains in force).
 *
 * If a verification key is configured, the staged policy's HMAC-SHA256
 * tag must verify against its canonical hash or the update is rejected.
 *
 * Returns true on success, false on error.
 */
static boolean ak_policy_parse_rules(ak_policy_t *policy, buffer rules) {
  if (!policy || !rules)
    return false;

  u64 len = buffer_length(rules);

  /* Reject empty or unreasonably large rules (> 1MB) */
  if (len == 0 || len > 1024 * 1024)
    return false;

  u8 *data = buffer_ref(rules, 0);
  if (!data)
    return false;

  /* Stage: copy metadata, start from empty rules and default budgets */
  ak_policy_t staged;
  runtime_memcpy((u8 *)&staged, (u8 *)policy, sizeof(ak_policy_t));
  staged.tool_rules = NULL;
  staged.domain_rules = NULL;
  staged.taint_rules = NULL;
  runtime_memset(staged.signature, 0, AK_SIG_SIZE);
  policy_set_default_budgets(&staged);
  staged.default_tool_allow = false;
  staged.default_domain_allow = false;

  if (!ak_policy_parse_json(&staged, data, len))
    goto fail;

  /* Canonical hash binds the staged rules */
  ak_policy_compute_hash(&staged, staged.policy_hash);

  /* Integrity check - same semantics as ak_policy_load() */
  if (ak_policy_verify_key.configured) {
    boolean is_unsigned =
        ak_policy_signature_is_empty(staged.signature, AK_SIG_SIZE);
    if (is_unsigned ||
        !ak_policy_verify_signature(&staged, ak_policy_verify_key.key)) {
      ak_error("SECURITY: policy rules rejected: %s (verification key "
               "configured)",
               is_unsigned ? "unsigned rules" : "HMAC verification failed");
      goto fail;
    }
    staged.signature_verified = true;
  } else {
    staged.signature_verified = false;
  }

  /* Commit: swap in the staged rules */
  free_tool_rules(policy->h, policy->tool_rules);
  free_domain_rules(policy->h, policy->domain_rules);
  free_taint_rules(policy->h, policy->taint_rules);
  policy->tool_rules = staged.tool_rules;
  policy->domain_rules = staged.domain_rules;
  policy->taint_rules = staged.taint_rules;
  policy->budgets = staged.budgets;
  policy->default_tool_allow = staged.default_tool_allow;
  policy->default_domain_allow = staged.default_domain_allow;
  runtime_memcpy(policy->version, staged.version, sizeof(policy->version));
  runtime_memcpy(policy->signature, staged.signature, AK_SIG_SIZE);
  runtime_memcpy(policy->policy_hash, staged.policy_hash, AK_HASH_SIZE);
  policy->signature_verified = staged.signature_verified;

  return true;

fail:
  free_tool_rules(policy->h, staged.tool_rules);
  free_domain_rules(policy->h, staged.domain_rules);
  free_taint_rules(policy->h, staged.taint_rules);
  return false;
}

ak_policy_result_t ak_policy_upgrade(ak_policy_t *policy, buffer new_rules,
                                     u32 new_version) {
  if (!policy || !new_rules)
    return AK_POLICY_ERROR_PARSE;

  /* Validate new version is strictly greater */
  u32 current =
      policy->current_version ? policy->current_version->version_number : 0;
  if (new_version <= current)
    return AK_POLICY_ERROR_VERSION;

  /* Check version compatibility */
  if (!ak_policy_is_compatible(current, new_version))
    return AK_POLICY_ERROR_INCOMPATIBLE;

  /* Allocate new version record */
  ak_policy_version_t *new_ver =
      allocate(policy->h, sizeof(ak_policy_version_t));
  if (!new_ver)
    return AK_POLICY_ERROR_PARSE;

  runtime_memset((u8 *)new_ver, 0, sizeof(ak_policy_version_t));
  new_ver->version_number = new_version;
  new_ver->activated_ms = now(CLOCK_ID_MONOTONIC) / MILLION;

  /* Clone rules for version history */
  new_ver->rules_json = allocate_buffer(policy->h, buffer_length(new_rules));
  if (!new_ver->rules_json) {
    deallocate(policy->h, new_ver, sizeof(ak_policy_version_t));
    return AK_POLICY_ERROR_PARSE;
  }
  buffer_write(new_ver->rules_json, buffer_ref(new_rules, 0),
               buffer_length(new_rules));

  /* Link to previous version */
  new_ver->prev = policy->current_version;

  /* Parse and apply new rules (also updates policy->policy_hash and
   * enforces signature verification when a key is configured) */
  if (!ak_policy_parse_rules(policy, new_rules)) {
    deallocate_buffer(new_ver->rules_json);
    deallocate(policy->h, new_ver, sizeof(ak_policy_version_t));
    return AK_POLICY_ERROR_PARSE;
  }

  /* Record canonical hash of the applied rules */
  runtime_memcpy(new_ver->hash, policy->policy_hash, AK_HASH_SIZE);

  /* Update policy state */
  policy->current_version = new_ver;
  policy->version_count++;

  return AK_POLICY_OK;
}

ak_policy_result_t ak_policy_rollback(ak_policy_t *policy) {
  if (!policy)
    return AK_POLICY_ERROR_PARSE;

  if (!policy->current_version || !policy->current_version->prev)
    return AK_POLICY_ERROR_NO_PREVIOUS;

  /* Get previous version */
  ak_policy_version_t *prev_ver = policy->current_version->prev;

  /* Re-parse previous rules if available */
  if (prev_ver->rules_json) {
    if (!ak_policy_parse_rules(policy, prev_ver->rules_json)) {
      /* Rollback parse failed - keep current version */
      return AK_POLICY_ERROR_PARSE;
    }
  }

  /* Update policy state */
  policy->current_version = prev_ver;

  /* Update policy hash to previous version */
  runtime_memcpy(policy->policy_hash, prev_ver->hash, AK_HASH_SIZE);

  /*
   * NOTE: We intentionally do NOT deallocate the old version here.
   *
   * Rationale:
   * 1. Use-after-free risk: Other code may still hold references to
   *    the old version structure (e.g., for audit logging, debugging).
   * 2. The old version's memory will be reclaimed when the entire
   *    policy is destroyed or when the heap is cleaned up.
   *
   * For memory-constrained environments, consider implementing a
   * deferred garbage collection mechanism that safely reclaims
   * unreferenced version structures after a grace period.
   */

  /* Decrement version_count since the active version chain is now shorter */
  if (policy->version_count > 0)
    policy->version_count--;

  return AK_POLICY_OK;
}

boolean ak_policy_is_compatible(u32 old_version, u32 new_version) {
  /*
   * Version compatibility rules:
   * - Major version changes (1.x -> 2.x) may be incompatible
   * - Minor version increments within same major are compatible
   *
   * For simple monotonic versioning:
   * - Sequential increments are always compatible
   * - Large jumps (> 100) require explicit migration
   */
  if (new_version <= old_version)
    return false;

  /* Allow single-step upgrades always */
  if (new_version == old_version + 1)
    return true;

  /* Allow reasonable jumps (up to 100 versions) */
  if (new_version - old_version <= 100)
    return true;

  /* Large jumps require explicit migration (return false) */
  return false;
}

u32 ak_policy_get_version(ak_policy_t *policy) {
  if (!policy || !policy->current_version)
    return 0;
  return policy->current_version->version_number;
}

u32 ak_policy_version_count(ak_policy_t *policy) {
  if (!policy)
    return 0;
  return policy->version_count;
}
