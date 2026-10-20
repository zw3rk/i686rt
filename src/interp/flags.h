/*
 * src/interp/flags.h — frozen lazy-flags API (Phase 1 freeze, SPEC D6)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reference semantics live in src/interp/flags.c (coordinator-owned).
 * width is 8, 16, or 32; the lazy descriptor stores 32-bit values
 * zero-extended to the width, and materialization applies the width.
 */

#ifndef I686RT_INTERP_FLAGS_H
#define I686RT_INTERP_FLAGS_H

#include <stdint.h>

#include "i686rt.h"

/* Materialize EFLAGS (CF PF AF ZF SF OF) from the lazy descriptor into
 * ctx->eflags and set lazy_op = I686_FOP_NONE.  Idempotent. */
void i686_flags_materialize(i686_ctx_t *ctx);

/* Current architecturally correct EFLAGS (materializes if needed). */
uint32_t i686_flags_read(i686_ctx_t *ctx);

/* Evaluate a jcc/setcc/cmovcc condition code (0..15) — materializes. */
uint8_t i686_flags_cc(i686_ctx_t *ctx, uint8_t cond);

/* Lazy setters: record the operation; res/src1/src2 are the width-sized
 * values zero-extended to u32.  For INC/DEC only src1/res are used
 * (CF preserved); NEG uses src1 (operand) with res = 0 - src1. */
void i686_flags_add(i686_ctx_t *ctx, uint32_t src1, uint32_t src2, unsigned width);
void i686_flags_adc(i686_ctx_t *ctx, uint32_t src1, uint32_t src2, uint32_t cf_in, unsigned width);
void i686_flags_sub(i686_ctx_t *ctx, uint32_t src1, uint32_t src2, unsigned width);
void i686_flags_sbb(i686_ctx_t *ctx, uint32_t src1, uint32_t src2, uint32_t cf_in, unsigned width);
void i686_flags_logic(i686_ctx_t *ctx, uint32_t res, unsigned width); /* and/or/xor/test */
void i686_flags_inc(i686_ctx_t *ctx, uint32_t src1, unsigned width);
void i686_flags_dec(i686_ctx_t *ctx, uint32_t src1, unsigned width);
void i686_flags_neg(i686_ctx_t *ctx, uint32_t src1, unsigned width);

/* Shift/rotate flag rules differ per count and are set eagerly (not via
 * the lazy descriptor): helpers compute PF/ZF/SF from res; CF/OF per op. */
uint8_t i686_flags_parity(uint8_t v); /* PF lookup: 1 if even parity */
void i686_flags_logiczx(i686_ctx_t *ctx, uint32_t res, unsigned width); /* z/s/p, cf=of=0 */

#endif /* I686RT_INTERP_FLAGS_H */
