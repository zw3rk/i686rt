/*
 * src/dbt/flags_dbt.c — DBT flags seam (SPEC D6, S3 coordinator fix)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * L3a's fused ALU ops record the lazy descriptor and set in-block NZCV;
 * L3c's condition consumers rebuild NZCV from ctx->eflags. This helper
 * materializes any pending lazy descriptor into ctx->eflags so the
 * rebuild sees architecturally current flags. Emitted code parks the
 * guest GPRs into ctx->gpr[0..7] before the call (AAPCS clobbers
 * x0-x18) and reloads them after.
 *
 * C6a dead-flag elimination: the consumer-side emitted sequences live
 * here too, shared by emit_branch.c (jcc/setcc/cmovcc) and emit_sse.c
 * (COMIS class):
 *   - i686_dbt_emit_rebuild_nzcv: rebuild the natural-polarity NZCV
 *     image from ctx->eflags (the S/N/Z/V insertions + C := !CF and
 *     MSR) — no GPR park, no helper call.  Only legal when the emit
 *     context proves ctx->eflags architecturally current
 *     (e->flags_src != I686_FLAGS_DEAD).
 *   - i686_dbt_emit_elide_bump: ctx->flags_elided += 1 from generated
 *     code, counting one elided park/sync/rebuild sequence.  The field
 *     is a uint64 deep in the C-only tail (offset pinned by the
 *     _Static_assert on I686_CTX_FLAGS_ELIDED_OFFSET in i686rt.h), far
 *     beyond the unsigned-imm12 load/store range, so the offset rides
 *     w11 (offset>>3, MOVZ imm16) into ADD X12, X19, X11, LSL #3 and
 *     plain [X12] loads/stores.  Clobbers x11 and x12 only.
 */
#include "dbt/emit.h"
#include "interp/flags.h"

void i686_dbt_flags_sync(i686_ctx_t *ctx)
{
    if (ctx->lazy_op != I686_FOP_NONE) {
        i686_flags_materialize(ctx);
    }
}

/* The offset>>3 immediate must fit MOVZ's imm16; the alignment comes
 * with the i686rt.h pin (uint64 field). */
_Static_assert((I686_CTX_FLAGS_ELIDED_OFFSET & 7U) == 0U,
               "flags_elided must be 8-aligned for the LSL #3 form");
_Static_assert((I686_CTX_FLAGS_ELIDED_OFFSET >> 3) <= 0xFFFFU,
               "flags_elided offset must fit the MOVZ imm16 of the bump");

void i686_dbt_emit_elide_bump(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;

    /* MOVZ W11, #(offset>>3): W form zeroes the upper half (wanted). */
    a64_emit_movz_w(b, 11U, (uint16_t)(I686_CTX_FLAGS_ELIDED_OFFSET >> 3),
                    0U);
    /* ADD X12, X19, X11, LSL #3: x12 = &ctx->flags_elided.  The address
     * MUST live in a register distinct from the loaded value: a naive
     * `str x11, [x19, x11, lsl #3]` after the increment would index the
     * store with the NEW counter value (observed: a stray write to
     * ctx->gpr[2] masked by the trampoline store-back, counter stuck). */
    a64_emit(b, 0x8B0B0E6CU);
    /* LDR X11, [X12]. */
    a64_emit(b, 0xF940018BU);
    /* ADD X11, X11, #1. */
    a64_emit(b, 0x9100056BU);
    /* STR X11, [X12]. */
    a64_emit(b, 0xF900018BU);
}

/* Rebuild NZCV from ctx->eflags (natural SUBS polarity: C := !CF).
 * The emitted word stream is exactly the tail of the former full
 * l3c_flags_to_nzcv sequence (unchanged DEAD path).  Clobbers w8/w9/
 * w11; leaves NZCV holding the architectural image. */
void i686_dbt_emit_rebuild_nzcv(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;
    unsigned w_eflags = 8U;
    unsigned w_mask = 9U;
    unsigned w_tmp = 11U;

    a64_emit_ldr_imm_w(b, w_eflags, A64_XCTX, 36U); /* ctx->eflags */
    /* w9 = 0x0FFFFFFF (NZCV low 27 architectural bits are RES1) */
    a64_emit_movz_w(b, w_mask, 0xFFFFU, 0U);
    a64_emit_movk_w(b, w_mask, 0x0FFFU, 1U);
    /* N<-SF(bit7) Z<-ZF(bit6) V<-OF(bit11), via BFI */
    a64_emit_ubfm_w(b, w_tmp, w_eflags, 7U, 7U);
    a64_emit_bfm_w(b, w_mask, w_tmp, 1U, 0U);  /* insert at bit 31 */
    a64_emit_ubfm_w(b, w_tmp, w_eflags, 6U, 6U);
    a64_emit_bfm_w(b, w_mask, w_tmp, 2U, 0U);  /* bit 30 */
    a64_emit_ubfm_w(b, w_tmp, w_eflags, 11U, 11U);
    a64_emit_bfm_w(b, w_mask, w_tmp, 4U, 0U);  /* bit 28 */
    /* C <- !CF (natural SUBS polarity): w11 = 1 - CF, inserted at 29 */
    a64_emit_ubfm_w(b, w_tmp, w_eflags, 0U, 0U); /* w11 = CF */
    a64_emit_movz_w(b, w_eflags, 1U, 0U);        /* w8 = 1 (done with eflags) */
    a64_emit_sub_reg_w(b, false, w_tmp, w_eflags, w_tmp,
                       A64_SHIFT_LSL, 0U);
    a64_emit_bfm_w(b, w_mask, w_tmp, 3U, 0U);  /* bit 29 */
    a64_emit_msr_nzcv(b, w_mask);
}
