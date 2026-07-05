/*
 * Authority Kernel - Integer-only WASM subset interpreter
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * See ak_wasm_interp.h for the substrate rationale (kernel is -mno-sse, no
 * float, no soft-float, no vendored WASM interpreter) and the exact
 * supported/rejected surface.
 *
 * SECURITY: this file decodes UNTRUSTED WASM bytecode. It is written
 * adversarially:
 *   - Every byte read goes through a bounds-checked cursor (rd_*).
 *   - Every LEB128 decode caps its byte count and shift.
 *   - Every count (types, imports, funcs, locals, if-blocks) and every
 *     index (type, function, local) is bounded and checked before use.
 *   - The operand stack has a fixed cap; under/overflow traps.
 *   - No linear memory, no loops/branches, no indirect calls: execution of
 *     a validated body is guaranteed to terminate, and gas metering bounds
 *     it further.
 *   - There is NO floating point anywhere in this file.
 */

#include "ak_wasm_interp.h"
#include "ak_compat.h"

/* ============================================================
 * BOUNDS
 * ============================================================ */

#define IN_MAX_TYPES 128
#define IN_MAX_PARAMS 16   /* params per function type */
#define IN_MAX_IMPORTS 64  /* imported functions */
#define IN_MAX_FUNCS 256   /* locally-defined functions */
#define IN_MAX_LOCALS 256  /* params + declared locals of the entry fn */
#define IN_STACK_MAX 1024  /* operand stack depth */
#define IN_MAX_IFS 512     /* if/else/end blocks in the entry body */
#define IN_MAX_NAME 64     /* import field-name length (matches registry) */
#define IN_DEFAULT_GAS (10 * 1000 * 1000) /* if caller passes gas_limit 0 */

/* WASM constants */
#define IN_WASM_MAGIC 0x6d736100u
#define IN_WASM_VERSION 1u

/* value types */
#define VT_I32 0x7F
#define VT_I64 0x7E
#define VT_F32 0x7D
#define VT_F64 0x7C

/* section ids */
#define SEC_CUSTOM 0
#define SEC_TYPE 1
#define SEC_IMPORT 2
#define SEC_FUNCTION 3
#define SEC_EXPORT 7
#define SEC_CODE 10

/* ============================================================
 * BOUNDS-CHECKED CURSOR
 * ============================================================
 * A cursor is a (data, len, pos) triple. Every accessor validates before
 * touching memory and returns false on any out-of-range access.
 */

typedef struct {
  const u8 *data;
  u64 len;
  u64 pos;
} rd_t;

static boolean rd_byte(rd_t *r, u8 *out) {
  if (r->pos >= r->len)
    return false;
  *out = r->data[r->pos++];
  return true;
}

/* Advance over n bytes, bounds-checked (no read). */
static boolean rd_skip(rd_t *r, u64 n) {
  if (n > r->len || r->pos > r->len - n)
    return false;
  r->pos += n;
  return true;
}

/* Unsigned LEB128, up to 32 bits. Rejects overlong/oversized encodings. */
static boolean rd_u32(rd_t *r, u32 *out) {
  u32 result = 0;
  u32 shift = 0;
  for (int i = 0; i < 5; i++) {
    u8 b;
    if (!rd_byte(r, &b))
      return false;
    /* On the 5th byte only the low 4 bits are valid for a 32-bit value. */
    if (i == 4 && (b & 0x70))
      return false;
    result |= ((u32)(b & 0x7f)) << shift;
    if ((b & 0x80) == 0) {
      *out = result;
      return true;
    }
    shift += 7;
  }
  return false;
}

/* Signed LEB128, 32-bit. */
static boolean rd_s32(rd_t *r, s32 *out) {
  s32 result = 0;
  u32 shift = 0;
  u8 b = 0;
  for (int i = 0; i < 5; i++) {
    if (!rd_byte(r, &b))
      return false;
    result |= (s32)((u32)(b & 0x7f) << shift);
    shift += 7;
    if ((b & 0x80) == 0) {
      if (shift < 32 && (b & 0x40))
        result |= (s32)(~(u32)0 << shift);
      *out = result;
      return true;
    }
  }
  return false;
}

/* Signed LEB128, 64-bit. */
static boolean rd_s64(rd_t *r, s64 *out) {
  s64 result = 0;
  u32 shift = 0;
  u8 b = 0;
  for (int i = 0; i < 10; i++) {
    if (!rd_byte(r, &b))
      return false;
    result |= (s64)((u64)(b & 0x7f) << shift);
    shift += 7;
    if ((b & 0x80) == 0) {
      if (shift < 64 && (b & 0x40))
        result |= (s64)(~(u64)0 << shift);
      *out = result;
      return true;
    }
  }
  return false;
}

/*
 * Read a value type, mapping the result to an AK_E code:
 *   0                       -> ok (*vt is VT_I32 or VT_I64)
 *   AK_E_WASM_UNSUPPORTED   -> f32/f64 (honest "no float" rejection)
 *   AK_E_WASM_INVALID_MODULE-> truncated / not a value type
 */
static s64 rd_valtype(rd_t *r, u8 *vt) {
  u8 t;
  if (!rd_byte(r, &t))
    return AK_E_WASM_INVALID_MODULE;
  if (t == VT_I32 || t == VT_I64) {
    *vt = t;
    return 0;
  }
  if (t == VT_F32 || t == VT_F64)
    return AK_E_WASM_UNSUPPORTED;
  return AK_E_WASM_INVALID_MODULE;
}

/* Little-endian 32-bit read for magic/version (NOT LEB128). Defined at the
 * end of the file; prototyped here so the section parsers can use it. */
static boolean rd_u32_raw_le(rd_t *r, u32 *out);

/* ============================================================
 * PARSED MODULE (bounded, integer-only)
 * ============================================================ */

typedef struct {
  /* type section: only param/result COUNTS are retained (values are all
   * treated as 64-bit slots at runtime; float value types are rejected
   * during parsing). */
  u8 type_pcount[IN_MAX_TYPES];
  u8 type_rcount[IN_MAX_TYPES];
  u32 num_types;

  /* imported functions (host calls) */
  u32 import_type[IN_MAX_IMPORTS];
  char import_name[IN_MAX_IMPORTS][IN_MAX_NAME];
  u32 num_imports;

  /* locally defined functions: type index per function */
  u32 func_type[IN_MAX_FUNCS];
  u32 num_funcs;

  boolean have_type;
  boolean have_import;
  boolean have_function;
  boolean have_export;
  boolean have_code;

  /* resolved entry function */
  boolean entry_found;
  u32 entry_func_index;   /* index in the combined func index space */
  u32 entry_local_index;  /* index among locally-defined functions */

  /* entry body location (set while scanning the code section) */
  boolean entry_body_set;
  u64 entry_body_start;   /* first byte of the function body (locals decl) */
  u64 entry_body_end;     /* one past the last body byte (the trailing end) */
} wmod_t;

/* if/else/end jump record for the entry body */
typedef struct {
  u64 if_off;
  u64 else_off; /* 0 = none */
  u64 end_off;
} ifrec_t;

/* ============================================================
 * SECTION PARSERS
 * ============================================================ */

static s64 parse_type_section(wmod_t *m, rd_t *r) {
  u32 count;
  if (!rd_u32(r, &count))
    return AK_E_WASM_INVALID_MODULE;
  if (count > IN_MAX_TYPES)
    return AK_E_WASM_UNSUPPORTED;
  for (u32 i = 0; i < count; i++) {
    u8 form;
    if (!rd_byte(r, &form))
      return AK_E_WASM_INVALID_MODULE;
    if (form != 0x60) /* func type */
      return AK_E_WASM_INVALID_MODULE;

    u32 pcount;
    if (!rd_u32(r, &pcount))
      return AK_E_WASM_INVALID_MODULE;
    if (pcount > IN_MAX_PARAMS)
      return AK_E_WASM_UNSUPPORTED;
    for (u32 p = 0; p < pcount; p++) {
      u8 vt;
      s64 e = rd_valtype(r, &vt);
      if (e != 0)
        return e;
    }

    u32 rcount;
    if (!rd_u32(r, &rcount))
      return AK_E_WASM_INVALID_MODULE;
    if (rcount > 1) /* multi-value results are post-MVP */
      return AK_E_WASM_UNSUPPORTED;
    for (u32 rr = 0; rr < rcount; rr++) {
      u8 vt;
      s64 e = rd_valtype(r, &vt);
      if (e != 0)
        return e;
    }

    m->type_pcount[i] = (u8)pcount;
    m->type_rcount[i] = (u8)rcount;
  }
  m->num_types = count;
  return 0;
}

/* Read a name (vec of bytes). If dst != NULL, copy up to IN_MAX_NAME-1 and
 * NUL-terminate; a name that does not fit is rejected (it can never match a
 * registry entry, and we must not silently truncate an import name). */
static s64 read_name(rd_t *r, char *dst) {
  u32 nlen;
  if (!rd_u32(r, &nlen))
    return AK_E_WASM_INVALID_MODULE;
  if (dst) {
    if (nlen >= IN_MAX_NAME)
      return AK_E_WASM_UNSUPPORTED;
    for (u32 i = 0; i < nlen; i++) {
      u8 c;
      if (!rd_byte(r, &c))
        return AK_E_WASM_INVALID_MODULE;
      dst[i] = (char)c;
    }
    dst[nlen] = 0;
    return 0;
  }
  if (!rd_skip(r, nlen))
    return AK_E_WASM_INVALID_MODULE;
  return 0;
}

static s64 parse_import_section(wmod_t *m, rd_t *r) {
  u32 count;
  if (!rd_u32(r, &count))
    return AK_E_WASM_INVALID_MODULE;
  for (u32 i = 0; i < count; i++) {
    /* module name (ignored) */
    s64 e = read_name(r, 0);
    if (e != 0)
      return e;

    char field[IN_MAX_NAME];
    e = read_name(r, field);
    if (e != 0)
      return e;

    u8 kind;
    if (!rd_byte(r, &kind))
      return AK_E_WASM_INVALID_MODULE;
    if (kind != 0x00) /* only function imports; table/mem/global rejected */
      return AK_E_WASM_UNSUPPORTED;

    u32 typeidx;
    if (!rd_u32(r, &typeidx))
      return AK_E_WASM_INVALID_MODULE;
    if (typeidx >= m->num_types) /* type section must precede imports */
      return AK_E_WASM_INVALID_MODULE;
    if (m->num_imports >= IN_MAX_IMPORTS)
      return AK_E_WASM_UNSUPPORTED;

    /* Integer host imports must take no params (the host ABI is JSON-buffer
     * based; we cannot marshal integer operands into it) and return 0 or 1
     * result. Enforce here, fail-closed. */
    if (m->type_pcount[typeidx] != 0)
      return AK_E_WASM_UNSUPPORTED;

    /* The import must resolve to a synchronous registry function. */
    ak_host_fn_entry_t *hf = ak_host_fn_get(field);
    if (!hf || !hf->fn)
      return AK_E_WASM_UNSUPPORTED; /* unresolved / disallowed import */
    if (hf->async_capable)
      return AK_E_WASM_UNSUPPORTED; /* no async suspension in-interp */

    m->import_type[m->num_imports] = typeidx;
    runtime_memcpy(m->import_name[m->num_imports], field, IN_MAX_NAME);
    m->num_imports++;
  }
  return 0;
}

static s64 parse_function_section(wmod_t *m, rd_t *r) {
  u32 count;
  if (!rd_u32(r, &count))
    return AK_E_WASM_INVALID_MODULE;
  if (count > IN_MAX_FUNCS)
    return AK_E_WASM_UNSUPPORTED;
  for (u32 i = 0; i < count; i++) {
    u32 typeidx;
    if (!rd_u32(r, &typeidx))
      return AK_E_WASM_INVALID_MODULE;
    if (typeidx >= m->num_types)
      return AK_E_WASM_INVALID_MODULE;
    m->func_type[i] = typeidx;
  }
  m->num_funcs = count;
  return 0;
}

static s64 parse_export_section(wmod_t *m, rd_t *r, const char *want) {
  boolean want_empty = (!want || want[0] == 0);
  u32 count;
  if (!rd_u32(r, &count))
    return AK_E_WASM_INVALID_MODULE;
  for (u32 i = 0; i < count; i++) {
    char name[IN_MAX_NAME];
    /* An export name longer than IN_MAX_NAME-1 cannot be the one we want;
     * read_name rejects it. That is acceptable: we only run named exports. */
    s64 e = read_name(r, name);
    if (e != 0)
      return e;

    u8 kind;
    if (!rd_byte(r, &kind))
      return AK_E_WASM_INVALID_MODULE;
    u32 idx;
    if (!rd_u32(r, &idx))
      return AK_E_WASM_INVALID_MODULE;

    if (kind != 0x00) /* only function exports are of interest */
      continue;
    if (m->entry_found)
      continue; /* already selected */

    boolean match = want_empty ? true : (ak_strcmp(name, want) == 0);
    if (match) {
      m->entry_found = true;
      m->entry_func_index = idx;
    }
  }
  return 0;
}

/*
 * Parse the code section. We only need to locate and bound the entry
 * function's body; other bodies are skipped by their declared size (still
 * bounds-checked). The entry body is fully opcode-validated later.
 */
static s64 parse_code_section(wmod_t *m, rd_t *r) {
  u32 count;
  if (!rd_u32(r, &count))
    return AK_E_WASM_INVALID_MODULE;
  if (count != m->num_funcs) /* one body per declared local function */
    return AK_E_WASM_INVALID_MODULE;
  for (u32 i = 0; i < count; i++) {
    u32 body_size;
    if (!rd_u32(r, &body_size))
      return AK_E_WASM_INVALID_MODULE;
    u64 body_start = r->pos;
    if (body_size > r->len || body_start > r->len - body_size)
      return AK_E_WASM_INVALID_MODULE;
    u64 body_end = body_start + body_size;

    if (m->entry_found && (m->num_imports + i) == m->entry_func_index) {
      m->entry_local_index = i;
      m->entry_body_start = body_start;
      m->entry_body_end = body_end;
      m->entry_body_set = true;
    }
    r->pos = body_end; /* skip to next body */
  }
  return 0;
}

/* ============================================================
 * TOP-LEVEL MODULE PARSE (VALIDATION PHASE 1)
 * ============================================================ */

static s64 parse_module(wmod_t *m, const u8 *data, u64 len, const char *want) {
  rd_t r = {data, len, 0};

  /* magic + version */
  u32 magic, version;
  if (!rd_u32_raw_le(&r, &magic) || !rd_u32_raw_le(&r, &version))
    return AK_E_WASM_INVALID_MODULE;
  if (magic != IN_WASM_MAGIC || version != IN_WASM_VERSION)
    return AK_E_WASM_INVALID_MODULE;

  while (r.pos < r.len) {
    u8 id;
    if (!rd_byte(&r, &id))
      return AK_E_WASM_INVALID_MODULE;
    u32 size;
    if (!rd_u32(&r, &size))
      return AK_E_WASM_INVALID_MODULE;
    u64 sec_start = r.pos;
    if (size > r.len || sec_start > r.len - size)
      return AK_E_WASM_INVALID_MODULE;
    u64 sec_end = sec_start + size;

    /* sub-cursor limited to this section's payload */
    rd_t sr = {data, sec_end, sec_start};
    s64 e = 0;

    switch (id) {
    case SEC_CUSTOM:
      /* ignored, skipped by size */
      break;
    case SEC_TYPE:
      if (m->have_type)
        return AK_E_WASM_INVALID_MODULE;
      m->have_type = true;
      e = parse_type_section(m, &sr);
      break;
    case SEC_IMPORT:
      if (m->have_import)
        return AK_E_WASM_INVALID_MODULE;
      m->have_import = true;
      e = parse_import_section(m, &sr);
      break;
    case SEC_FUNCTION:
      if (m->have_function)
        return AK_E_WASM_INVALID_MODULE;
      m->have_function = true;
      e = parse_function_section(m, &sr);
      break;
    case SEC_EXPORT:
      if (m->have_export)
        return AK_E_WASM_INVALID_MODULE;
      m->have_export = true;
      e = parse_export_section(m, &sr, want);
      break;
    case SEC_CODE:
      if (m->have_code)
        return AK_E_WASM_INVALID_MODULE;
      m->have_code = true;
      e = parse_code_section(m, &sr);
      break;
    default:
      /* table/memory/global/start/element/data/... : outside the subset */
      return AK_E_WASM_UNSUPPORTED;
    }
    if (e != 0)
      return e;

    r.pos = sec_end; /* advance to next section by declared size */
  }

  if (!m->entry_found || !m->entry_body_set)
    return AK_E_WASM_EXPORT_NOT_FOUND;
  /* The entry must be a locally-defined function (imports have no body). */
  if (m->entry_func_index < m->num_imports)
    return AK_E_WASM_UNSUPPORTED;
  return 0;
}

/* ============================================================
 * ENTRY BODY VALIDATION (opcode whitelist + structure)
 * ============================================================ */

/* Numeric opcodes that carry no immediate. Returns true if `op` is one of
 * the supported integer arithmetic/comparison opcodes. */
static boolean is_supported_numeric(u8 op) {
  switch (op) {
  /* i32 comparisons */
  case 0x45: /* i32.eqz */
  case 0x46: /* i32.eq */
  case 0x47: /* i32.ne */
  case 0x48: /* i32.lt_s */
  case 0x49: /* i32.lt_u */
  case 0x4A: /* i32.gt_s */
  case 0x4B: /* i32.gt_u */
  /* i64 comparisons */
  case 0x50: /* i64.eqz */
  case 0x51: /* i64.eq */
  case 0x52: /* i64.ne */
  case 0x54: /* i64.lt_s */
  case 0x55: /* i64.lt_u */
  case 0x56: /* i64.gt_s */
  case 0x57: /* i64.gt_u */
  /* i32 arithmetic */
  case 0x6A: /* i32.add */
  case 0x6B: /* i32.sub */
  case 0x6C: /* i32.mul */
  case 0x6E: /* i32.div_u */
  case 0x71: /* i32.and */
  case 0x72: /* i32.or */
  case 0x73: /* i32.xor */
  case 0x74: /* i32.shl */
  case 0x76: /* i32.shr_u */
  /* i64 arithmetic */
  case 0x7C: /* i64.add */
  case 0x7D: /* i64.sub */
  case 0x7E: /* i64.mul */
  case 0x80: /* i64.div_u */
  case 0x83: /* i64.and */
  case 0x84: /* i64.or */
  case 0x85: /* i64.xor */
  case 0x86: /* i64.shl */
  case 0x88: /* i64.shr_u */
    return true;
  default:
    return false;
  }
}

/* Read and validate a single-byte block type for `if`. */
static s64 read_blocktype(rd_t *r) {
  u8 bt;
  if (!rd_byte(r, &bt))
    return AK_E_WASM_INVALID_MODULE;
  if (bt == 0x40 || bt == VT_I32 || bt == VT_I64)
    return 0;
  if (bt == VT_F32 || bt == VT_F64)
    return AK_E_WASM_UNSUPPORTED;
  /* Any other value would be an s33 type index (multi-value block) - not
   * supported. */
  return AK_E_WASM_UNSUPPORTED;
}

/*
 * Validate the entry function body: read the locals declaration, then scan
 * every instruction, whitelisting opcodes, decoding & bounds-checking
 * immediates, verifying if/else/end nesting, and recording jump targets.
 *
 * On success sets *instr_start_out (first instruction after locals),
 * *total_locals_out, and fills recs[]/ *num_recs_out.
 */
static s64 validate_body(wmod_t *m, const u8 *data, u64 body_start,
                         u64 body_end, u32 param_count, ifrec_t *recs,
                         u32 *num_recs_out, u64 *instr_start_out,
                         u32 *total_locals_out, u64 *func_end_out) {
  rd_t r = {data, body_end, body_start};

  /* locals declaration */
  u32 decl_count;
  if (!rd_u32(&r, &decl_count))
    return AK_E_WASM_INVALID_MODULE;
  u64 total_locals = param_count;
  for (u32 i = 0; i < decl_count; i++) {
    u32 n;
    if (!rd_u32(&r, &n))
      return AK_E_WASM_INVALID_MODULE;
    u8 vt;
    s64 e = rd_valtype(&r, &vt); /* rejects float locals */
    if (e != 0)
      return e;
    total_locals += n;
    if (total_locals > IN_MAX_LOCALS)
      return AK_E_WASM_UNSUPPORTED;
  }
  *total_locals_out = (u32)total_locals;
  *instr_start_out = r.pos;

  /* instruction scan */
  u32 ctrl[IN_MAX_IFS]; /* stack of record indices for open ifs */
  u32 csp = 0;
  u32 nrec = 0;
  boolean done = false;

  while (!done) {
    if (r.pos >= r.len)
      return AK_E_WASM_INVALID_MODULE; /* ran off the end without final end */
    u64 op_off = r.pos;
    u8 op;
    if (!rd_byte(&r, &op))
      return AK_E_WASM_INVALID_MODULE;

    switch (op) {
    case 0x00: /* unreachable */
    case 0x01: /* nop */
    case 0x0F: /* return */
    case 0x1A: /* drop */
      break;

    case 0x41: { /* i32.const */
      s32 v;
      if (!rd_s32(&r, &v))
        return AK_E_WASM_INVALID_MODULE;
      break;
    }
    case 0x42: { /* i64.const */
      s64 v;
      if (!rd_s64(&r, &v))
        return AK_E_WASM_INVALID_MODULE;
      break;
    }

    case 0x20: /* local.get */
    case 0x21: /* local.set */
    case 0x22: { /* local.tee */
      u32 idx;
      if (!rd_u32(&r, &idx))
        return AK_E_WASM_INVALID_MODULE;
      if (idx >= *total_locals_out)
        return AK_E_WASM_INVALID_MODULE;
      break;
    }

    case 0x10: { /* call */
      u32 idx;
      if (!rd_u32(&r, &idx))
        return AK_E_WASM_INVALID_MODULE;
      /* Only host (imported) calls are supported; a call to a locally
       * defined function is outside the subset. */
      if (idx >= m->num_imports)
        return AK_E_WASM_UNSUPPORTED;
      /* Import type constraints (0 params, <=1 result) were enforced at
       * import parse; nothing further to check here. */
      break;
    }

    case 0x04: { /* if */
      s64 e = read_blocktype(&r);
      if (e != 0)
        return e;
      if (csp >= IN_MAX_IFS || nrec >= IN_MAX_IFS)
        return AK_E_WASM_UNSUPPORTED;
      recs[nrec].if_off = op_off;
      recs[nrec].else_off = 0;
      recs[nrec].end_off = 0;
      ctrl[csp++] = nrec;
      nrec++;
      break;
    }
    case 0x05: { /* else */
      if (csp == 0)
        return AK_E_WASM_INVALID_MODULE;
      u32 top = ctrl[csp - 1];
      if (recs[top].else_off != 0)
        return AK_E_WASM_INVALID_MODULE; /* two elses */
      recs[top].else_off = op_off;
      break;
    }
    case 0x0B: { /* end */
      if (csp == 0) {
        /* function-final end */
        *func_end_out = op_off;
        if (r.pos != body_end)
          return AK_E_WASM_INVALID_MODULE; /* trailing bytes after body */
        done = true;
        break;
      }
      u32 top = ctrl[--csp];
      recs[top].end_off = op_off;
      break;
    }

    default:
      if (is_supported_numeric(op))
        break;
      /* Everything else (float ops, memory ops, block/loop/br/br_if/
       * br_table/call_indirect, globals, etc.) is honestly rejected. */
      return AK_E_WASM_UNSUPPORTED;
    }
  }

  if (csp != 0)
    return AK_E_WASM_INVALID_MODULE; /* unbalanced blocks */
  *num_recs_out = nrec;
  return 0;
}

/* ============================================================
 * EXECUTION (PHASE 2)
 * ============================================================ */

/* Find the if-record whose if_off == off. Linear scan over the bounded
 * record set. Returns index or -1. */
static s64 find_rec_by_if(ifrec_t *recs, u32 n, u64 off) {
  for (u32 i = 0; i < n; i++)
    if (recs[i].if_off == off)
      return (s64)i;
  return -1;
}
static s64 find_rec_by_else(ifrec_t *recs, u32 n, u64 off) {
  for (u32 i = 0; i < n; i++)
    if (recs[i].else_off == off)
      return (s64)i;
  return -1;
}

/* sign-extend low 32 bits of a slot to s64 */
static s64 sext32(u64 v) { return (s64)(s32)(u32)v; }

typedef struct {
  u64 *st;   /* operand stack */
  u32 sp;    /* current depth */
} opstack_t;

static boolean op_push(opstack_t *s, u64 v) {
  if (s->sp >= IN_STACK_MAX)
    return false;
  s->st[s->sp++] = v;
  return true;
}
static boolean op_pop(opstack_t *s, u64 *v) {
  if (s->sp == 0)
    return false;
  *v = s->st[--s->sp];
  return true;
}

/*
 * Execute a validated entry body. Returns 0 on completion (with *result set
 * to the top-of-stack value if the function declares a result), or a
 * negative AK_E trap/limit code.
 */
static s64 exec_body(ak_wasm_exec_ctx_t *ctx, wmod_t *m, const u8 *data,
                     u64 body_end, u64 instr_start, u64 func_end,
                     u32 total_locals, u32 result_count, ifrec_t *recs,
                     u32 nrec, u64 *locals, opstack_t *stk, buffer input,
                     u64 gas_limit, u64 *gas_used, s64 *result_out) {
  u64 pc = instr_start;
  u64 gas = 0;

  for (;;) {
    if (pc >= body_end || pc == func_end) {
      /* fell through to the function's final end: normal return */
      break;
    }
    if (++gas > gas_limit) {
      *gas_used = gas;
      return AK_E_WASM_TIMEOUT;
    }

    u8 op = data[pc++];
    /* helper: bounded immediate cursor starting at pc */
    rd_t r = {data, body_end, pc};

    switch (op) {
    case 0x00: /* unreachable */
      *gas_used = gas;
      return AK_E_WASM_TRAP;
    case 0x01: /* nop */
      break;
    case 0x0F: /* return */
      *gas_used = gas;
      goto done;
    case 0x1A: { /* drop */
      u64 t;
      if (!op_pop(stk, &t)) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      break;
    }

    case 0x41: { /* i32.const */
      s32 v;
      if (!rd_s32(&r, &v) || !op_push(stk, (u64)(u32)v)) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      pc = r.pos;
      break;
    }
    case 0x42: { /* i64.const */
      s64 v;
      if (!rd_s64(&r, &v) || !op_push(stk, (u64)v)) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      pc = r.pos;
      break;
    }

    case 0x20: { /* local.get */
      u32 idx;
      if (!rd_u32(&r, &idx) || idx >= total_locals ||
          !op_push(stk, locals[idx])) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      pc = r.pos;
      break;
    }
    case 0x21: { /* local.set */
      u32 idx;
      u64 v;
      if (!rd_u32(&r, &idx) || idx >= total_locals || !op_pop(stk, &v)) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      locals[idx] = v;
      pc = r.pos;
      break;
    }
    case 0x22: { /* local.tee */
      u32 idx;
      if (!rd_u32(&r, &idx) || idx >= total_locals || stk->sp == 0) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      locals[idx] = stk->st[stk->sp - 1];
      pc = r.pos;
      break;
    }

    case 0x04: { /* if */
      /* skip the (validated) single-byte block type */
      pc += 1;
      u64 cond;
      if (!op_pop(stk, &cond)) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      if ((u32)cond != 0) {
        /* enter then-branch (pc already past block type) */
        break;
      }
      s64 ri = find_rec_by_if(recs, nrec, pc - 2);
      if (ri < 0) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      if (recs[ri].else_off != 0)
        pc = recs[ri].else_off + 1; /* enter else-branch */
      else
        pc = recs[ri].end_off + 1; /* skip whole if */
      break;
    }
    case 0x05: { /* else - reached after finishing a then-branch */
      s64 ri = find_rec_by_else(recs, nrec, pc - 1);
      if (ri < 0) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      pc = recs[ri].end_off + 1; /* skip else-branch */
      break;
    }
    case 0x0B: /* end (of an if block) - just continue */
      break;

    default:
      break; /* numeric ops handled below */
    }

    if (op != 0x00 && op != 0x01 && op != 0x0F && op != 0x1A && op != 0x41 &&
        op != 0x42 && op != 0x20 && op != 0x21 && op != 0x22 && op != 0x04 &&
        op != 0x05 && op != 0x0B && op != 0x10) {
      /* numeric opcode: pop operands, compute, push result */
      s64 e = 0;
      /* unary (eqz) vs binary handled per-op */
      switch (op) {
      case 0x45: { /* i32.eqz */
        u64 a;
        if (!op_pop(stk, &a) || !op_push(stk, ((u32)a == 0) ? 1 : 0))
          e = AK_E_WASM_TRAP;
        break;
      }
      case 0x50: { /* i64.eqz */
        u64 a;
        if (!op_pop(stk, &a) || !op_push(stk, (a == 0) ? 1 : 0))
          e = AK_E_WASM_TRAP;
        break;
      }
      default: {
        u64 b, a;
        if (!op_pop(stk, &b) || !op_pop(stk, &a)) {
          e = AK_E_WASM_TRAP;
          break;
        }
        u64 res = 0;
        switch (op) {
        /* i32 arithmetic (result truncated to 32 bits) */
        case 0x6A: res = (u32)(a + b); break;                 /* add */
        case 0x6B: res = (u32)(a - b); break;                 /* sub */
        case 0x6C: res = (u32)(a * b); break;                 /* mul */
        case 0x6E:                                            /* div_u */
          if ((u32)b == 0) { e = AK_E_WASM_TRAP; }
          else res = (u32)((u32)a / (u32)b);
          break;
        case 0x71: res = (u32)(a & b); break;                 /* and */
        case 0x72: res = (u32)(a | b); break;                 /* or */
        case 0x73: res = (u32)(a ^ b); break;                 /* xor */
        case 0x74: res = (u32)((u32)a << ((u32)b & 31)); break; /* shl */
        case 0x76: res = (u32)((u32)a >> ((u32)b & 31)); break; /* shr_u */
        /* i32 comparisons (result 0/1) */
        case 0x46: res = ((u32)a == (u32)b) ? 1 : 0; break;   /* eq */
        case 0x47: res = ((u32)a != (u32)b) ? 1 : 0; break;   /* ne */
        case 0x48: res = (sext32(a) < sext32(b)) ? 1 : 0; break; /* lt_s */
        case 0x49: res = ((u32)a < (u32)b) ? 1 : 0; break;    /* lt_u */
        case 0x4A: res = (sext32(a) > sext32(b)) ? 1 : 0; break; /* gt_s */
        case 0x4B: res = ((u32)a > (u32)b) ? 1 : 0; break;    /* gt_u */
        /* i64 arithmetic (full 64-bit) */
        case 0x7C: res = a + b; break;                        /* add */
        case 0x7D: res = a - b; break;                        /* sub */
        case 0x7E: res = a * b; break;                        /* mul */
        case 0x80:                                            /* div_u */
          if (b == 0) { e = AK_E_WASM_TRAP; }
          else res = a / b;
          break;
        case 0x83: res = a & b; break;                        /* and */
        case 0x84: res = a | b; break;                        /* or */
        case 0x85: res = a ^ b; break;                        /* xor */
        case 0x86: res = a << (b & 63); break;                /* shl */
        case 0x88: res = a >> (b & 63); break;                /* shr_u */
        /* i64 comparisons */
        case 0x51: res = (a == b) ? 1 : 0; break;             /* eq */
        case 0x52: res = (a != b) ? 1 : 0; break;             /* ne */
        case 0x54: res = ((s64)a < (s64)b) ? 1 : 0; break;    /* lt_s */
        case 0x55: res = (a < b) ? 1 : 0; break;              /* lt_u */
        case 0x56: res = ((s64)a > (s64)b) ? 1 : 0; break;    /* gt_s */
        case 0x57: res = (a > b) ? 1 : 0; break;              /* gt_u */
        default:
          e = AK_E_WASM_TRAP; /* unreachable: validated set */
          break;
        }
        if (e == 0 && !op_push(stk, res))
          e = AK_E_WASM_TRAP;
        break;
      }
      }
      if (e != 0) {
        *gas_used = gas;
        return e;
      }
    } else if (op == 0x10) {
      /* host call */
      u32 idx;
      if (!rd_u32(&r, &idx) || idx >= m->num_imports) {
        *gas_used = gas;
        return AK_E_WASM_TRAP;
      }
      pc = r.pos;
      ak_host_fn_entry_t *hf = ak_host_fn_get(m->import_name[idx]);
      if (!hf || !hf->fn) {
        *gas_used = gas;
        return AK_E_WASM_HOST_ERROR;
      }
      buffer res = 0;
      s64 rc = hf->fn(ctx, input, &res);
      if (res && res != INVALID_ADDRESS)
        deallocate_buffer(res);
      if (rc < 0) {
        *gas_used = gas;
        return AK_E_WASM_HOST_ERROR;
      }
      if (m->type_rcount[m->import_type[idx]] == 1) {
        if (!op_push(stk, (u64)rc)) {
          *gas_used = gas;
          return AK_E_WASM_TRAP;
        }
      }
    }
  }

done:
  *gas_used = gas;
  /* Produce the result value if the entry function declares one. */
  if (result_count == 1) {
    if (stk->sp == 0)
      return AK_E_WASM_TRAP; /* result expected but stack empty */
    if (result_out)
      *result_out = (s64)stk->st[stk->sp - 1];
  } else if (result_out) {
    *result_out = 0;
  }
  return 0;
}

/* ============================================================
 * PUBLIC ENTRY POINT
 * ============================================================ */

s64 ak_wasm_interp_run(heap h, ak_wasm_exec_ctx_t *ctx, buffer bytecode,
                       const char *export_name, buffer input,
                       buffer *output_out, u64 gas_limit, u64 *gas_used_out,
                       s64 *result_out) {
  if (gas_used_out)
    *gas_used_out = 0;
  if (result_out)
    *result_out = 0;
  if (!h || h == INVALID_ADDRESS)
    return AK_E_WASM_INVALID_MODULE;
  if (!bytecode || bytecode == INVALID_ADDRESS)
    return AK_E_WASM_INVALID_MODULE;

  u64 len = buffer_length(bytecode);
  if (len < 8)
    return AK_E_WASM_INVALID_MODULE;
  const u8 *data = (const u8 *)buffer_ref(bytecode, 0);
  if (!data)
    return AK_E_WASM_INVALID_MODULE;

  if (gas_limit == 0)
    gas_limit = IN_DEFAULT_GAS;

  /* --- Phase 1: parse + validate module structure --- */
  wmod_t *m = allocate_zero(h, sizeof(wmod_t));
  if (!m || m == INVALID_ADDRESS)
    return AK_E_WASM_OOM;

  s64 e = parse_module(m, data, len, export_name);
  if (e != 0) {
    deallocate(h, m, sizeof(wmod_t));
    return e;
  }

  u32 entry_type = m->func_type[m->entry_local_index];
  u32 param_count = m->type_pcount[entry_type];
  u32 result_count = m->type_rcount[entry_type];

  /* --- Phase 1b: validate the entry body & record jump targets --- */
  ifrec_t *recs = allocate_zero(h, sizeof(ifrec_t) * IN_MAX_IFS);
  if (!recs || recs == INVALID_ADDRESS) {
    deallocate(h, m, sizeof(wmod_t));
    return AK_E_WASM_OOM;
  }

  u32 num_recs = 0;
  u64 instr_start = 0;
  u32 total_locals = 0;
  u64 func_end = 0;
  e = validate_body(m, data, m->entry_body_start, m->entry_body_end,
                    param_count, recs, &num_recs, &instr_start, &total_locals,
                    &func_end);
  if (e != 0) {
    deallocate(h, recs, sizeof(ifrec_t) * IN_MAX_IFS);
    deallocate(h, m, sizeof(wmod_t));
    return e;
  }

  /* --- Phase 2: execute --- */
  u64 *locals = allocate_zero(h, sizeof(u64) * (total_locals ? total_locals : 1));
  u64 *stack_mem = allocate_zero(h, sizeof(u64) * IN_STACK_MAX);
  if (!locals || locals == INVALID_ADDRESS || !stack_mem ||
      stack_mem == INVALID_ADDRESS) {
    if (locals && locals != INVALID_ADDRESS)
      deallocate(h, locals, sizeof(u64) * (total_locals ? total_locals : 1));
    if (stack_mem && stack_mem != INVALID_ADDRESS)
      deallocate(h, stack_mem, sizeof(u64) * IN_STACK_MAX);
    deallocate(h, recs, sizeof(ifrec_t) * IN_MAX_IFS);
    deallocate(h, m, sizeof(wmod_t));
    return AK_E_WASM_OOM;
  }

  /* Initialise params from the input buffer as little-endian i64 values. */
  if (input && input != INVALID_ADDRESS) {
    u64 in_len = buffer_length(input);
    const u8 *in = (const u8 *)buffer_ref(input, 0);
    if (in) {
      for (u32 i = 0; i < param_count; i++) {
        u64 v = 0;
        for (u32 b = 0; b < 8; b++) {
          u64 off = (u64)i * 8 + b;
          if (off < in_len)
            v |= ((u64)in[off]) << (8 * b);
        }
        locals[i] = v;
      }
    }
  }

  opstack_t stk = {stack_mem, 0};
  s64 rv = 0;
  u64 gas_used = 0;
  e = exec_body(ctx, m, data, m->entry_body_end, instr_start, func_end,
                total_locals, result_count, recs, num_recs, locals, &stk,
                input, gas_limit, &gas_used, &rv);
  if (gas_used_out)
    *gas_used_out = gas_used;

  s64 ret;
  if (e == 0) {
    /* Emit the result value as 8 little-endian bytes (empty if no result). */
    buffer out = allocate_buffer(h, 8);
    if (!out || out == INVALID_ADDRESS) {
      ret = AK_E_WASM_OOM;
    } else {
      if (result_count == 1) {
        u8 tmp[8];
        for (u32 i = 0; i < 8; i++)
          tmp[i] = (u8)((u64)rv >> (8 * i));
        buffer_write(out, tmp, 8);
      }
      if (output_out)
        *output_out = out;
      else
        deallocate_buffer(out);
      if (result_out)
        *result_out = rv;
      ret = 0;
    }
  } else {
    ret = e;
  }

  deallocate(h, stack_mem, sizeof(u64) * IN_STACK_MAX);
  deallocate(h, locals, sizeof(u64) * (total_locals ? total_locals : 1));
  deallocate(h, recs, sizeof(ifrec_t) * IN_MAX_IFS);
  deallocate(h, m, sizeof(wmod_t));
  return ret;
}

/* Out-of-line definition (forward-declared above parse_module). */
static boolean rd_u32_raw_le(rd_t *r, u32 *out) {
  if (r->pos + 4 > r->len)
    return false;
  const u8 *d = r->data + r->pos;
  *out = (u32)d[0] | ((u32)d[1] << 8) | ((u32)d[2] << 16) | ((u32)d[3] << 24);
  r->pos += 4;
  return true;
}
