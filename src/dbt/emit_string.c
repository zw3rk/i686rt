/*
 * src/dbt/emit_string.c — DBT string-op emitters (Phase 3 lane L3c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single-step (non-REP) MOVS/CMPS/STOS/LODS/SCAS, byte form and
 * operand-size form (32-bit plain, 16-bit under 66), mirroring
 * src/interp/h_string.c:
 *   - source side = DS:ESI (66/67 aside; pfx_seg override honored),
 *     destination side = ES:EDI (never overridable); seg bases are
 *     runtime state and loaded from ctx each execution (D8),
 *   - DF is read from ctx->eflags bit 10 at runtime: a cbz/b.al dual
 *     path selects add (DF=0) or sub (DF=1) of the width in bytes for
 *     the index registers (w6=ESI, w7=EDI), all wrapping in 32 bits,
 *   - the access is ldr/str [x20, wAddr uxtw] (guest EA wraps before
 *     xG is added, D4/D7); indices bump AFTER the access,
 *   - CMPS/SCAS compare via SUBS on width-masked operands shifted so
 *     the width's sign bit sits at bit 31 (byte/word SF/OF then match
 *     the architectural definition) and write the NZCV-derived
 *     SF/ZF/CF/OF back into ctx->eflags (CF = !C, i.e. x86 borrow
 *     polarity); PF/AF are NOT materialized in v1 — parity and
 *     BCD-ish consumers must not follow an in-block cmps/scas until
 *     the coordinator-owned flags_dbt.h materializer lands (documented
 *     coordination point with L3a's alu emitters).
 *
 * REP/REPNE (F2/F3) and 0x67 (16-bit addressing) forms are declined in
 * v1 (return -1 -> D2 interpret-one; always safe, per the card).
 *
 * Scratch: w8..w11 and w21..w23 in-block (guest state only in w0..w7);
 * x19=xCtx, x20=xG.  Plain loads/stores (single-threaded D5 v1).
 */

#include <stdint.h>

#include "dbt/emit.h"

#define L3S_NONE 0xFFU

#define L3S_W8   8U
#define L3S_W9   9U
#define L3S_W10  10U
#define L3S_W11  11U
#define L3S_A0   21U /* source (or only) linear address */
#define L3S_A1   22U /* destination linear address */
#define L3S_TMP  23U

/* Add ctx->seg_base[seg] to wDst. */
static void l3s_add_seg(i686_emit_ctx_t *e, unsigned w_dst, unsigned seg)
{
    a64_emit_ldr_imm_w(&e->buf, L3S_TMP, A64_XCTX, 40U + 4U * seg);
    a64_emit_add_reg_w(&e->buf, false, w_dst, w_dst, L3S_TMP,
                       A64_SHIFT_LSL, 0U);
}

/* ESI (w6) + source segment into w21: DS default, pfx_seg override. */
static void l3s_src_addr(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned seg = insn->pfx_seg != L3S_NONE ? (unsigned)insn->pfx_seg
                                             : (unsigned)I686_SEG_DS;
    a64_emit_mov_w(b, L3S_A0, I686_REG_ESI);
    l3s_add_seg(e, L3S_A0, seg);
}

/* EDI (w7) + ES base into w22 (destination side is never overridable). */
static void l3s_dst_addr(i686_emit_ctx_t *e)
{
    a64_emit_mov_w(&e->buf, L3S_A1, I686_REG_EDI);
    l3s_add_seg(e, L3S_A1, I686_SEG_ES);
}

/* Index bumps per DF (ctx->eflags bit 10): DF=0 adds, DF=1 subtracts
 * `bytes` from the selected index registers (w6=ESI, w7=EDI). */
static void l3s_bump_df(i686_emit_ctx_t *e, bool esi, bool edi,
                        uint16_t bytes)
{
    a64_buf_t *b = &e->buf;
    size_t p_fwd, p_done;

    a64_emit_ldr_imm_w(b, L3S_W9, A64_XCTX, 36U);
    a64_emit_ubfm_w(b, L3S_W9, L3S_W9, 10U, 10U); /* DF isolated */
    p_fwd = a64_emit_cbz_w_placeholder(b, false, L3S_W9);
    if (esi) {
        a64_emit_sub_imm_w(b, false, I686_REG_ESI, I686_REG_ESI, bytes,
                           0U);
    }
    if (edi) {
        a64_emit_sub_imm_w(b, false, I686_REG_EDI, I686_REG_EDI, bytes,
                           0U);
    }
    p_done = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, p_fwd, b->count);
    if (esi) {
        a64_emit_add_imm_w(b, false, I686_REG_ESI, I686_REG_ESI, bytes,
                           0U);
    }
    if (edi) {
        a64_emit_add_imm_w(b, false, I686_REG_EDI, I686_REG_EDI, bytes,
                           0U);
    }
    a64_patch_b_cond(b, p_done, b->count);
}

/* CSET w11, cond (local CSINC encoding). */
static void l3s_emit_cset_w11(i686_emit_ctx_t *e, unsigned cond)
{
    a64_emit(&e->buf,
             0x1A800400U | (((cond ^ 1U) & 15U) << 12) | (31U << 16) |
                 (31U << 5) | L3S_W11);
}

/* Load width-sized operand from [x20, wAddr uxtw] into wR, then shift
 * it so the width's sign bit lands on bit 31 (width 32: plain move).
 * LSL #n = UBFM #((32-n) MOD 32), #(31-n). */
static void l3s_load_shifted(i686_emit_ctx_t *e, unsigned w_r,
                             unsigned w_addr, unsigned bytes)
{
    a64_buf_t *b = &e->buf;

    if (bytes == 1U) {
        a64_emit_guest_ldrb_w(b, w_r, w_addr);
        a64_emit_ubfm_w(b, w_r, w_r, 8U, 7U);   /* lsl #24 */
    } else if (bytes == 2U) {
        a64_emit_guest_ldrh_w(b, w_r, w_addr);
        a64_emit_ubfm_w(b, w_r, w_r, 16U, 15U); /* lsl #16 */
    } else {
        a64_emit_guest_ldr_w(b, w_r, w_addr);
    }
}

/* Materialize the SUBS-derived x86 flags (SF/ZF/CF/OF; CF = !C borrow
 * polarity) into ctx->eflags; PF/AF are left as-is (see header note). */
static void l3s_store_flags(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;

    a64_emit_mrs_nzcv(b, L3S_W8);
    a64_emit_mov_w(b, L3S_W9, A64_ZR); /* w9 = new SF|ZF|CF|OF bits */
    a64_emit_ubfm_w(b, L3S_W11, L3S_W8, 31U, 31U);
    a64_emit_bfm_w(b, L3S_W9, L3S_W11, 25U, 0U); /* SF <- N, bit 7 */
    a64_emit_ubfm_w(b, L3S_W11, L3S_W8, 30U, 30U);
    a64_emit_bfm_w(b, L3S_W9, L3S_W11, 26U, 0U); /* ZF <- Z, bit 6 */
    l3s_emit_cset_w11(e, A64_COND_CC);           /* CF = (C == 0) */
    a64_emit_bfm_w(b, L3S_W9, L3S_W11, 0U, 0U);  /* bit 0 */
    a64_emit_ubfm_w(b, L3S_W11, L3S_W8, 28U, 28U);
    a64_emit_bfm_w(b, L3S_W9, L3S_W11, 21U, 0U); /* OF <- V, bit 11 */
    a64_emit_ldr_imm_w(b, L3S_W10, A64_XCTX, 36U);
    a64_emit_movz_w(b, L3S_W11, 0x08C1U, 0U); /* CF|ZF|SF|OF mask */
    a64_emit_bic_reg_w(b, false, L3S_W10, L3S_W10, L3S_W11,
                       A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, L3S_W10, L3S_W10, L3S_W9, A64_SHIFT_LSL, 0U);
    a64_emit_str_imm_w(b, L3S_W10, A64_XCTX, 36U);
}

/* CSET w11 helper used above is shared; width in bytes for this insn. */
static unsigned l3s_bytes(const x86_insn_t *insn, int is_wide)
{
    if (!is_wide) {
        return 1U;
    }
    return insn->pfx_opsize != 0U ? 2U : 4U;
}

int i686_emit_string(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned bytes;

    if (insn->pfx_rep != 0U || insn->pfx_addrsize != 0U ||
        insn->pfx_lock != 0U) {
        return -1; /* REP and 16-bit addressing declined in v1 */
    }

    switch (insn->op) {
    case I686_OP_MOVSb:
    case I686_OP_MOVSw:
        bytes = l3s_bytes(insn, insn->op == I686_OP_MOVSw);
        l3s_src_addr(e, insn);
        l3s_dst_addr(e);
        if (bytes == 1U) {
            a64_emit_guest_ldrb_w(b, L3S_W10, L3S_A0);
            a64_emit_guest_strb_w(b, L3S_W10, L3S_A1);
        } else if (bytes == 2U) {
            a64_emit_guest_ldrh_w(b, L3S_W10, L3S_A0);
            a64_emit_guest_strh_w(b, L3S_W10, L3S_A1);
        } else {
            a64_emit_guest_ldr_w(b, L3S_W10, L3S_A0);
            a64_emit_guest_str_w(b, L3S_W10, L3S_A1);
        }
        l3s_bump_df(e, true, true, (uint16_t)bytes);
        return 0;

    case I686_OP_STOSb:
    case I686_OP_STOSw:
        bytes = l3s_bytes(insn, insn->op == I686_OP_STOSw);
        l3s_dst_addr(e);
        if (bytes == 1U) {
            a64_emit_guest_strb_w(b, I686_REG_EAX, L3S_A1);
        } else if (bytes == 2U) {
            a64_emit_guest_strh_w(b, I686_REG_EAX, L3S_A1);
        } else {
            a64_emit_guest_str_w(b, I686_REG_EAX, L3S_A1);
        }
        l3s_bump_df(e, false, true, (uint16_t)bytes);
        return 0;

    case I686_OP_LODSb:
    case I686_OP_LODSw:
        bytes = l3s_bytes(insn, insn->op == I686_OP_LODSw);
        l3s_src_addr(e, insn);
        if (bytes == 1U) {
            a64_emit_guest_ldrb_w(b, I686_REG_EAX, L3S_A0);
        } else if (bytes == 2U) {
            a64_emit_guest_ldrh_w(b, I686_REG_EAX, L3S_A0);
        } else {
            a64_emit_guest_ldr_w(b, I686_REG_EAX, L3S_A0);
        }
        /* ldrb/ldrh zero-extend, matching x86_reg_write(EAX, width). */
        l3s_bump_df(e, true, false, (uint16_t)bytes);
        return 0;

    case I686_OP_CMPSb:
    case I686_OP_CMPSw:
        bytes = l3s_bytes(insn, insn->op == I686_OP_CMPSw);
        l3s_src_addr(e, insn);
        l3s_dst_addr(e);
        l3s_load_shifted(e, L3S_W10, L3S_A0, bytes); /* [DS:ESI] */
        l3s_load_shifted(e, L3S_W11, L3S_A1, bytes); /* [ES:EDI] */
        a64_emit_sub_reg_w(b, true, A64_ZR, L3S_W10, L3S_W11,
                           A64_SHIFT_LSL, 0U); /* SUBS wzr, a, b */
        l3s_store_flags(e);
        l3s_bump_df(e, true, true, (uint16_t)bytes);
        return 0;

    case I686_OP_SCASb:
    case I686_OP_SCASw:
        bytes = l3s_bytes(insn, insn->op == I686_OP_SCASw);
        l3s_dst_addr(e);
        /* a = AL/eAX masked and sign-positioned (LSL via UBFM, above) */
        if (bytes == 1U) {
            a64_emit_ubfm_w(b, L3S_W10, I686_REG_EAX, 0U, 7U);
            a64_emit_ubfm_w(b, L3S_W10, L3S_W10, 8U, 7U);
        } else if (bytes == 2U) {
            a64_emit_ubfm_w(b, L3S_W10, I686_REG_EAX, 0U, 15U);
            a64_emit_ubfm_w(b, L3S_W10, L3S_W10, 16U, 15U);
        } else {
            a64_emit_mov_w(b, L3S_W10, I686_REG_EAX);
        }
        l3s_load_shifted(e, L3S_W11, L3S_A1, bytes); /* [ES:EDI] */
        a64_emit_sub_reg_w(b, true, A64_ZR, L3S_W10, L3S_W11,
                           A64_SHIFT_LSL, 0U); /* SUBS wzr, a, b */
        l3s_store_flags(e);
        l3s_bump_df(e, false, true, (uint16_t)bytes);
        return 0;

    default:
        return -1; /* not a string op */
    }
}
