/*
 * Authority Kernel - Integer-only WASM subset interpreter
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2024 Authority Systems
 *
 * SUBSTRATE CONSTRAINT (why this exists):
 *   The kernel is compiled -mno-mmx -mno-sse -mno-sse2 (see rules.mk) and
 *   -fno-builtin/-nostdinc: there is NO hardware floating point and NO
 *   soft-float runtime linked into the kernel. The WASM specification
 *   MANDATES f32/f64 numeric types and float opcodes, so a *complete* WASM
 *   interpreter cannot run here (it would either need SSE, which is
 *   disabled, or a soft-float library, which is absent). There is also no
 *   wasm3 or any other WASM interpreter vendored in the tree.
 *
 *   This module is therefore an HONEST, BOUNDED executor: a strict
 *   validator + interpreter for an INTEGER-ONLY subset of WASM. Any module
 *   that declares or uses f32/f64 types or float opcodes, or any opcode
 *   outside the supported integer subset, is REJECTED fail-closed. Nothing
 *   is mis-executed or fabricated.
 *
 * SECURITY: This parses UNTRUSTED bytecode. Every read is bounds-checked
 * against the module length; every count/index/stack-depth is bounded and
 * checked before use; all failures are fail-closed with an AK_E_ error.
 */

#ifndef AK_WASM_INTERP_H
#define AK_WASM_INTERP_H

#include "ak_wasm.h"

/*
 * Validate and execute the integer-only WASM subset.
 *
 * Two phases:
 *   1. VALIDATE: parse magic/version and the type/import/function/export/
 *      code sections; reject float types, float opcodes, unsupported
 *      opcodes/sections/imports, and any malformed/oversized structure.
 *      The exported entry function's body is fully opcode-validated.
 *   2. EXECUTE: interpret the entry function's body over a bounded operand
 *      stack with per-instruction gas metering. Traps (unreachable, integer
 *      divide-by-zero, stack under/overflow, host-call error) fail closed.
 *
 * Supported opcodes (integer only):
 *   const:    i32.const, i64.const
 *   locals:   local.get, local.set, local.tee
 *   i32 alu:  add sub mul div_u and or xor shl shr_u
 *   i32 cmp:  eqz eq ne lt_s lt_u gt_s gt_u
 *   i64 alu:  add sub mul div_u and or xor shl shr_u
 *   i64 cmp:  eqz eq ne lt_s lt_u gt_s gt_u
 *   control:  nop drop unreachable if else end return
 *   call:     call (to imported host functions only; see below)
 *
 * Host calls: `call` may target an IMPORTED function that resolves to a
 * name in the ak_host_fn registry. Because the host-function ABI is
 * JSON-buffer based (not integer based), an integer host import is only
 * accepted if its WASM type declares ZERO params and 0-or-1 results, and
 * the registry entry is synchronous (not async_capable). The host function
 * is invoked with the tool's input buffer as args; its s64 return code is
 * pushed as the (i32/i64) result. Anything else - a local (non-import)
 * call, a parameterised host import, an async host import, or an unresolved
 * import name - is rejected as AK_E_WASM_UNSUPPORTED. This wires the
 * interpreter to the real registry without pretending an integer<->JSON
 * marshalling that does not exist.
 *
 * @param h            heap for temporary allocations and the output buffer
 * @param ctx          execution context (passed through to host functions)
 * @param bytecode     the WASM module bytes (untrusted)
 * @param export_name  name of the exported function to run; if NULL/empty,
 *                     the first exported function is used
 * @param input        tool input buffer; the entry function's params are
 *                     initialised from it as little-endian i64 values, and
 *                     it is passed verbatim to host functions (may be NULL)
 * @param output_out   on success (return 0), set to a newly allocated buffer
 *                     holding the entry function's result as 8 little-endian
 *                     bytes (empty buffer if the function returns no value);
 *                     ownership passes to the caller. Untouched on failure.
 * @param gas_limit    maximum instructions to execute (0 uses a safe default)
 * @param gas_used_out if non-NULL, receives the number of instructions run
 * @param result_out   if non-NULL, receives the i64 result value (0 if none)
 *
 * @return 0 on genuine completion; a negative AK_E_ code otherwise:
 *   AK_E_WASM_INVALID_MODULE  - malformed/oversized/truncated bytecode
 *   AK_E_WASM_UNSUPPORTED     - valid WASM but outside the integer subset
 *   AK_E_WASM_EXPORT_NOT_FOUND- requested export missing / not a function
 *   AK_E_WASM_TRAP            - runtime trap (div0, unreachable, stack fault)
 *   AK_E_WASM_HOST_ERROR      - a host function returned an error
 *   AK_E_WASM_TIMEOUT         - gas (instruction) budget exhausted
 *   AK_E_WASM_OOM             - temporary allocation failed
 */
s64 ak_wasm_interp_run(heap h, ak_wasm_exec_ctx_t *ctx, buffer bytecode,
                       const char *export_name, buffer input,
                       buffer *output_out, u64 gas_limit, u64 *gas_used_out,
                       s64 *result_out);

#endif /* AK_WASM_INTERP_H */
