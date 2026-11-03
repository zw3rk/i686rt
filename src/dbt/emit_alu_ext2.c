/*
 * src/dbt/emit_alu_ext2.c — extended ALU emitters, part 2 (Wave P Lane P3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * CL-count shifts (D2/D3 /4,/5,/7), one-operand MUL/IMUL/DIV/IDIV
 * (F6/F7 /4../5../6../7), SHLD/SHRD (0F A4/A5/AC/AD), and the
 * i686_emit_alu_ext dispatcher.  Shared helpers live in
 * src/dbt/emit_alu_impl.h; flag rules are documented per emitter (all
 * bit-identical to the interpreter oracle, see emit_alu_ext.c).
 */

#include "dbt/emit_alu_impl.h"

/* ---- SHL/SHR/SAR by CL (D2/D3 /4,/5,/7; eager) ------------------------ */

/* Runtime-count twin of emit_shift_imm: cnt = CL & 31; a zero masked
 * count skips everything (no write, no flags).  Otherwise the flag
 * rules are exactly h_shift.c's (logiczx + CF + OF-when-1, AF
 * cleared). */
int xalu_shift_cl(i686_emit_ctx_t *e, const x86_insn_t *insn,
                         unsigned kind)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->opnd[0] == I686_OPND_RM8
                         ? 8U
                         : (insn->pfx_opsize != 0U ? 16U : 32U);
    unsigned msb = width - 1U;
    unsigned wE = XALU_T0;
    int is_mem = insn->modrm_mod != 3U && insn->ea_has != 0U;
    size_t to_done;
    size_t to_no_of = 0;
    int have_no_of = 0;

    if (is_mem != 0 && insn->pfx_lock != 0U) {
        return -1; /* LOCKed memory: the interpreter's atomic path */
    }
    xalu_sync_eflags(e);
    /* wT2 = CL & 31; skip everything on a zero masked count. */
    a64_emit_ubfm_w(b, XALU_T2, 1U, 0U, 7U);  /* CL */
    a64_emit_ubfm_w(b, XALU_T2, XALU_T2, 0U, 4U); /* & 31 */
    to_done = xalu_cbz_x_placeholder(b, 0, XALU_T2);

    xalu_load_rm(e, insn, XALU_A, width);
    if (kind == XSHK_SHL) {
        a64_emit_shift_reg_w(b, XALU_RES, XALU_A, XALU_T2, A64_SHIFT_LSL);
        if (width != 32U) {
            xalu_and_imm_w(b, XALU_RES, XALU_RES,
                           width == 8U ? 0xFFU : 0xFFFFU);
        }
    } else if (kind == XSHK_SHR) {
        a64_emit_shift_reg_w(b, XALU_RES, XALU_A, XALU_T2, A64_SHIFT_LSR);
    } else { /* SAR: sign-extend first for sub-32 widths. */
        if (width == 32U) {
            a64_emit_shift_reg_w(b, XALU_RES, XALU_A, XALU_T2,
                                 A64_SHIFT_ASR);
        } else {
            a64_emit_sbfm_w(b, XALU_T1, XALU_A, 0U, msb);
            a64_emit_shift_reg_w(b, XALU_RES, XALU_T1, XALU_T2,
                                 A64_SHIFT_ASR);
            xalu_and_imm_w(b, XALU_RES, XALU_RES,
                           width == 8U ? 0xFFU : 0xFFFFU);
        }
    }
    xalu_store_rm(e, insn, XALU_RES, width);

    /* Eager flags (mirror emit_shift_imm, runtime count). */
    a64_emit_ldr_imm_w(b, wE, 19U, 36U);
    a64_emit_movz_w(b, XALU_T1, 0x08D5U, 0U); /* CF|PF|AF|ZF|SF|OF */
    a64_emit_bic_reg_w(b, false, wE, wE, XALU_T1, A64_SHIFT_LSL, 0U);
    /* CF: SHL: bit (w-cnt) of A (0 when cnt > w); SHR: bit (cnt-1);
     * SAR: bit (cnt-1), or the sign bit when cnt > w. */
    a64_emit_sub_imm_w(b, false, XALU_T3, XALU_T2, 1U, 0U); /* cnt-1 */
    if (kind == XSHK_SHL) {
        /* CF = bit (w-1) of (A << (cnt-1)): the original bit (w-cnt)
         * when cnt <= w, else 0 (A's low w bits shift out fully). */
        a64_emit_shift_reg_w(b, XALU_T1, XALU_A, XALU_T3, A64_SHIFT_LSL);
        a64_emit_ubfm_w(b, XALU_T1, XALU_T1, msb, msb);
    } else if (kind == XSHK_SHR) {
        a64_emit_shift_reg_w(b, XALU_T1, XALU_A, XALU_T3, A64_SHIFT_LSR);
        a64_emit_ubfm_w(b, XALU_T1, XALU_T1, 0U, 0U);
    } else {
        a64_emit_mov_imm32(b, XALU_T4, msb);
        a64_emit_sub_reg_w(b, true, 31U, XALU_T2, XALU_T4,
                           A64_SHIFT_LSL, 0U); /* cmp cnt, w */
        /* HI (cnt > w): the sign-bit path; LS (cnt <= w) falls
         * through to the bit (cnt-1) path. */
        to_no_of = a64_emit_b_cond_placeholder(b, A64_COND_HI);
        have_no_of = 1;
        a64_emit_shift_reg_w(b, XALU_T1, XALU_A, XALU_T3, A64_SHIFT_LSR);
        a64_emit_ubfm_w(b, XALU_T1, XALU_T1, 0U, 0U);
    }
    xalu_bfi_w(b, wE, XALU_T1, 0U, 1U);
    if (kind == XSHK_SAR && have_no_of != 0) {
        size_t to_end = xalu_b_placeholder(b);
        a64_patch_b_cond(b, to_no_of, b->count);
        a64_emit_ubfm_w(b, XALU_T1, XALU_A, msb, msb); /* sign bit */
        xalu_bfi_w(b, wE, XALU_T1, 0U, 1U);
        /* NOTE: the first CF insert above is skipped on this path
         * (branch taken), so exactly one insert executes. */
        xalu_patch_b(b, to_end, b->count);
        (void)to_end;
    }
    /* OF only when cnt == 1 (same rules as the imm path). */
    if (kind == XSHK_SHL) {
        /* OF = CF ^ MSB(result). */
        a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb, msb);
        a64_emit_ubfm_w(b, XALU_T3, wE, 0U, 0U); /* CF just set */
        a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_T3, A64_SHIFT_LSL, 0U);
    } else if (kind == XSHK_SHR) {
        /* OF = MSB(operand). */
        a64_emit_ubfm_w(b, XALU_T1, XALU_A, msb, msb);
    } else {
        /* SAR count 1: OF = 0 (already cleared).  Reuse the SHR slot
         * shape with a zero so the csel below stays uniform. */
        a64_emit_movz_w(b, XALU_T1, 0U, 0U);
    }
    a64_emit_ubfm_w(b, XALU_T3, wE, 11U, 11U); /* old OF */
    a64_emit_sub_imm_w(b, true, 31U, XALU_T2, 1U, 0U); /* cmp cnt, 1 */
    a64_emit_csel_w(b, XALU_T1, XALU_T1, XALU_T3, A64_COND_EQ);
    xalu_bfi_w(b, wE, XALU_T1, 11U, 1U);

    xalu_fold_zsp(e, XALU_RES, msb, wE);
    xalu_commit_eflags(e, wE);
    xalu_patch_cbz_x(b, to_done, b->count);

    e->insn_count++;
    return 0;
}

/* ---- one-operand MUL/IMUL (F6/F7 /4,/5; eager, CF/OF only) ------------- */

/* Double-width product into EDX:EAX (AX for the byte form); CF = OF =
 * (upper half != 0 for MUL, upper != sign-extension of lower for
 * IMUL).  All other flags are architecturally undefined and stay
 * stale: materialize first, then RMW only CF/OF. */
int xalu_mul1(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_imul)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->opnd[0] == I686_OPND_RM8
                         ? 8U
                         : (insn->pfx_opsize != 0U ? 16U : 32U);
    unsigned wE = XALU_T0;
    int is_mem = insn->modrm_mod != 3U && insn->ea_has != 0U;

    if (is_mem != 0 && insn->pfx_lock != 0U) {
        return -1; /* LOCKed memory: the interpreter's atomic path */
    }
    /* The stale-flag RMW needs current eflags first. */
    xalu_sync_eflags(e);
    xalu_load_rm(e, insn, XALU_B, width);
    if (width == 8U) {
        xalu_load_reg(b, XALU_A, I686_REG_EAX, 8U);
        if (is_imul != 0) {
            a64_emit_sbfm_w(b, XALU_A, XALU_A, 0U, 7U);
            a64_emit_sbfm_w(b, XALU_B, XALU_B, 0U, 7U);
        }
        a64_emit_madd_w(b, XALU_RES, XALU_A, XALU_B, 31U);
        /* CF = (product >> 8) != 0; IMUL: product != sext8(product),
         * i.e. the upper 24 bits are not the sign extension of bit 7. */
        if (is_imul != 0) {
            a64_emit_sbfm_w(b, XALU_T1, XALU_RES, 0U, 7U);
            a64_emit_sub_reg_w(b, true, 31U, XALU_RES, XALU_T1,
                               A64_SHIFT_LSL, 0U);
        } else {
            a64_emit_ubfm_w(b, XALU_T1, XALU_RES, 8U, 31U);
            a64_emit_sub_imm_w(b, true, 31U, XALU_T1, 0U, 0U);
        }
        xalu_cset_w(b, XALU_T2, A64_COND_NE);
        /* AX = low 16 bits of the product. */
        xalu_store_reg(b, XALU_RES, I686_REG_EAX, 16U);
    } else {
        xalu_load_reg(b, XALU_A, I686_REG_EAX, width);
        if (is_imul != 0) {
            /* Sign-extend both halves before the widening multiply. */
            a64_emit_sbfm_w(b, XALU_A, XALU_A, 0U, width - 1U);
            a64_emit_sbfm_w(b, XALU_B, XALU_B, 0U, width - 1U);
            a64_emit_smaddl_x(b, XALU_T1, XALU_A, XALU_B, 31U);
        } else {
            a64_emit_umaddl_x(b, XALU_T1, XALU_A, XALU_B, 31U);
        }
        /* CF/OF check runs on a copy so the product in xT1 survives
         * for the stores. IMUL: xT1 != sext_w(low w bits); MUL
         * (R7-47): upper half != 0. */
        if (is_imul != 0) {
            xalu_orr_x(b, 11U, 31U, XALU_T1); /* x11 = xZR | xT1 */
            xalu_sbfx_x(b, XALU_T2, 11U, 0U, width);
            xalu_subs_x(b, 11U, XALU_T2);
        } else {
            xalu_lsr_x_imm(b, 11U, XALU_T1, width); /* upper half */
            xalu_subs_x(b, 11U, 31U); /* cmp upper, #0 */
        }
        xalu_cset_w(b, XALU_T2, A64_COND_NE);
        if (width == 16U) {
            xalu_store_reg(b, XALU_T1, I686_REG_EAX, 16U);
            a64_emit_ubfm_w(b, XALU_T3, XALU_T1, 16U, 31U);
            xalu_store_reg(b, XALU_T3, I686_REG_EDX, 16U);
        } else {
            a64_emit_mov_w(b, 0U, XALU_T1); /* EAX = low 32 */
            xalu_lsr_x_imm(b, XALU_T3, XALU_T1, 32U);
            a64_emit_mov_w(b, 2U, XALU_T3); /* EDX = high 32 */
        }
    }
    /* CF = OF = T2; every other bit of eflags is preserved. */
    a64_emit_ldr_imm_w(b, wE, 19U, 36U);
    a64_emit_movz_w(b, XALU_T1, 0x0801U, 0U); /* CF|OF */
    a64_emit_bic_reg_w(b, false, wE, wE, XALU_T1, A64_SHIFT_LSL, 0U);
    xalu_bfi_w(b, wE, XALU_T2, 0U, 1U);
    xalu_lsl_imm_w(b, XALU_T3, XALU_T2, 11U); /* OF bit position */
    a64_emit_orr_reg_w(b, wE, wE, XALU_T3, A64_SHIFT_LSL, 0U);
    xalu_commit_eflags(e, wE);

    e->insn_count++;
    return 0;
}

/* ---- DIV/IDIV (F6/F7 /6,/7; no flags; D2 fault stub) ------------------- */

/* Quotient/remainder exactly as h_muldiv.c h_div/h_idiv; divide errors
 * (zero divisor, quotient overflow, INT_MIN/-1) branch to an
 * I686_EXIT_UNDEF exit carrying (len, pc), so the engine's
 * interpret-one reproduces today's fault behaviour bit-identically.
 * Flags (descriptor, eflags, NZCV proof) are untouched. */
int xalu_divide(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_idiv)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->opnd[0] == I686_OPND_RM8
                         ? 8U
                         : (insn->pfx_opsize != 0U ? 16U : 32U);
    int is_mem = insn->modrm_mod != 3U && insn->ea_has != 0U;
    /* Forward fault branches, patched to the stub below. */
    size_t faults[6];
    unsigned nfaults = 0U;
    size_t to_end;

    if (is_mem != 0 && insn->pfx_lock != 0U) {
        return -1; /* LOCKed memory: the interpreter's atomic path */
    }
    xalu_load_rm(e, insn, XALU_B, width);
    if (width == 8U) {
        /* tmp = AX (16 bits); d = r/m8. */
        a64_emit_ubfm_w(b, XALU_A, 0U, 0U, 15U);
        if (is_idiv != 0) {
            a64_emit_sbfm_w(b, XALU_A, XALU_A, 0U, 15U);
            a64_emit_sbfm_w(b, XALU_B, XALU_B, 0U, 7U);
        }
        faults[nfaults++] = a64_emit_cbz_w_placeholder(b, false, XALU_B);
        if (is_idiv == 0) {
            /* hi = AX >> 8; fault iff hi >= d. */
            a64_emit_ubfm_w(b, XALU_T0, XALU_A, 8U, 15U);
            a64_emit_sub_reg_w(b, true, 31U, XALU_T0, XALU_B,
                               A64_SHIFT_LSL, 0U);
            faults[nfaults++] =
                a64_emit_b_cond_placeholder(b, A64_COND_CS);
            a64_emit_udiv_w(b, XALU_RES, XALU_A, XALU_B);
            a64_emit_msub_w(b, XALU_T1, XALU_RES, XALU_B, XALU_A);
        } else {
            /* MIN check: tmp == -32768 && d == -1. */
            a64_emit_mov_imm32(b, XALU_T0, 0xFFFF8000U);
            a64_emit_sub_reg_w(b, true, 31U, XALU_A, XALU_T0,
                               A64_SHIFT_LSL, 0U);
            {
                size_t no_min =
                    a64_emit_b_cond_placeholder(b, A64_COND_NE);
                /* cmn d, #1: ADDS XZR sets Z iff d == -1. */
                a64_emit_add_imm_w(b, true, 31U, XALU_B, 1U, 0U);
                faults[nfaults++] =
                    a64_emit_b_cond_placeholder(b, A64_COND_EQ);
                a64_patch_b_cond(b, no_min, b->count);
            }
            a64_emit_sdiv_w(b, XALU_RES, XALU_A, XALU_B);
            a64_emit_msub_w(b, XALU_T1, XALU_RES, XALU_B, XALU_A);
            /* Range: q + 128 must fit 8 bits unsigned. */
            a64_emit_add_imm_w(b, false, XALU_T0, XALU_RES, 128U, 0U);
            a64_emit_sub_imm_w(b, true, 31U, XALU_T0, 0x100U, 0U);
            faults[nfaults++] =
                a64_emit_b_cond_placeholder(b, A64_COND_CS);
        }
        /* AX = q | (r << 8). */
        a64_emit_ubfm_w(b, XALU_RES, XALU_RES, 0U, 7U);
        a64_emit_ubfm_w(b, XALU_T1, XALU_T1, 0U, 7U);
        xalu_lsl_imm_w(b, XALU_T1, XALU_T1, 8U);
        a64_emit_orr_reg_w(b, XALU_RES, XALU_RES, XALU_T1,
                           A64_SHIFT_LSL, 0U);
        xalu_store_reg(b, XALU_RES, I686_REG_EAX, 16U);
    } else if (width == 16U) {
        /* tmp = DX:AX (32 bits); d = r/m16. */
        a64_emit_ubfm_w(b, XALU_T0, 0U, 0U, 15U);  /* AX */
        a64_emit_ubfm_w(b, XALU_T1, 2U, 0U, 15U);  /* DX */
        xalu_lsl_imm_w(b, XALU_T1, XALU_T1, 16U);
        a64_emit_orr_reg_w(b, XALU_A, XALU_T0, XALU_T1, A64_SHIFT_LSL, 0U);
        if (is_idiv != 0) {
            a64_emit_sbfm_w(b, XALU_B, XALU_B, 0U, 15U);
        }
        faults[nfaults++] = a64_emit_cbz_w_placeholder(b, false, XALU_B);
        if (is_idiv == 0) {
            /* Fault iff hi(DX) >= d. */
            a64_emit_ubfm_w(b, XALU_T1, 2U, 0U, 15U);
            a64_emit_sub_reg_w(b, true, 31U, XALU_T1, XALU_B,
                               A64_SHIFT_LSL, 0U);
            faults[nfaults++] =
                a64_emit_b_cond_placeholder(b, A64_COND_CS);
            a64_emit_udiv_w(b, XALU_RES, XALU_A, XALU_B);
            a64_emit_msub_w(b, XALU_T1, XALU_RES, XALU_B, XALU_A);
        } else {
            /* MIN check: tmp == INT32_MIN && d == -1. */
            a64_emit_mov_imm32(b, XALU_T0, 0x80000000U);
            a64_emit_sub_reg_w(b, true, 31U, XALU_A, XALU_T0,
                               A64_SHIFT_LSL, 0U);
            {
                size_t no_min =
                    a64_emit_b_cond_placeholder(b, A64_COND_NE);
                a64_emit_add_imm_w(b, true, 31U, XALU_B, 1U, 0U);
                faults[nfaults++] =
                    a64_emit_b_cond_placeholder(b, A64_COND_EQ);
                a64_patch_b_cond(b, no_min, b->count);
            }
            a64_emit_sdiv_w(b, XALU_RES, XALU_A, XALU_B);
            a64_emit_msub_w(b, XALU_T1, XALU_RES, XALU_B, XALU_A);
            /* Range: (q + 32768) must fit 16 bits unsigned. */
            a64_emit_movz_w(b, XALU_T0, 0x8000U, 0U);
            a64_emit_add_reg_w(b, false, XALU_T0, XALU_RES, XALU_T0,
                               A64_SHIFT_LSL, 0U);
            a64_emit_ubfm_w(b, XALU_T0, XALU_T0, 16U, 31U);
            faults[nfaults++] =
                a64_emit_cbz_w_placeholder(b, true, XALU_T0);
        }
        xalu_store_reg(b, XALU_RES, I686_REG_EAX, 16U);
        xalu_store_reg(b, XALU_T1, I686_REG_EDX, 16U);
    } else {
        /* tmp = EDX:EAX (64 bits, xT0/xT3); d = sext32(r/m32). */
        a64_emit_mov_w(b, XALU_T0, 0U); /* wT0 = EAX, upper zeroed */
        xalu_lsl_x_imm(b, 13U, 2U, 32U); /* x13 = (x2 << 32): high
                                         * garbage shifts out */
        xalu_orr_x(b, 13U, 13U, XALU_T0);
        if (is_idiv != 0) {
            xalu_sbfx_x(b, XALU_B, XALU_B, 0U, 32U);
        } else {
            a64_emit_mov_w(b, XALU_B, XALU_B); /* zero-extend to X */
        }
        faults[nfaults++] = a64_emit_cbz_w_placeholder(b, false, XALU_B);
        if (is_idiv == 0) {
            /* Fault iff hi(EDX) >= d. */
            a64_emit_sub_reg_w(b, true, 31U, 2U, XALU_B,
                               A64_SHIFT_LSL, 0U);
            faults[nfaults++] =
                a64_emit_b_cond_placeholder(b, A64_COND_CS);
            xalu_udiv_x(b, XALU_RES, 13U, XALU_B);
            xalu_msub_x(b, XALU_T1, XALU_RES, XALU_B, 13U);
        } else {
            /* MIN check: tmp == INT64_MIN && d == -1. */
            a64_emit(b, 0xD2800000U | (1U << 21) | (0x8000U << 5) | 12U);
            xalu_lsl_x_imm(b, 12U, 12U, 48U); /* x12 = INT64_MIN */
            xalu_subs_x(b, 13U, 12U);
            {
                size_t no_min =
                    a64_emit_b_cond_placeholder(b, A64_COND_NE);
                /* cmn d, #1 (W-form ADDS XZR; d == -1 iff Z). */
                a64_emit_add_imm_w(b, true, 31U, XALU_B, 1U, 0U);
                faults[nfaults++] =
                    a64_emit_b_cond_placeholder(b, A64_COND_EQ);
                a64_patch_b_cond(b, no_min, b->count);
            }
            xalu_sdiv_x(b, XALU_RES, 13U, XALU_B);
            xalu_msub_x(b, XALU_T1, XALU_RES, XALU_B, 13U);
            /* Range: (q + 2^31) must fit 32 bits unsigned.  Runs in
             * x11 (the lo half is dead after the msub); the remainder
             * stays live in x12 for the stores below. */
            a64_emit(b, 0xD2800000U | (1U << 21) | (0x8000U << 5) | 11U);
            /* MOVZ X11, #0x8000, LSL #16 = 2^31. */
            a64_emit(b, 0x8B000000U | ((XALU_RES & 31U) << 16) |
                             (11U << 5) | 11U); /* ADD X11, X11, Xres */
            xalu_lsr_x_imm(b, 11U, 11U, 32U);
            faults[nfaults++] = xalu_cbz_x_placeholder(b, true, 11U);
        }
        a64_emit_mov_w(b, 0U, XALU_RES); /* EAX = low 32 of q */
        a64_emit_mov_w(b, 2U, XALU_T1);  /* EDX = low 32 of r */
    }
    to_end = xalu_b_placeholder(b);
    /* Fault stub: D2 interpret-one with today's (len, pc) shape.  The
     * UNDEF exit closes the block, so the main path needs a real
     * landing pad: a BRANCH exit to the fallthrough PC.  Ending the
     * block at DIV/IDIV matches the fault-barrier analysis (DIV is
     * always a barrier there). */
    for (unsigned i = 0U; i < nfaults; i++) {
        uint32_t w = b->words[faults[i]];
        if ((w & 0xFF000000U) == 0x54000000U) {
            a64_patch_b_cond(b, faults[i], b->count);
        } else {
            a64_patch_cbz_w(b, faults[i], b->count);
        }
    }
    i686_emit_exit(e, I686_EXIT_UNDEF, insn->len, e->insn_pc);
    xalu_patch_b(b, to_end, b->count);
    i686_emit_exit(e, I686_EXIT_BRANCH, 0U, e->insn_pc + insn->len);

    e->insn_count++;
    return 0;
}

/* ---- SHLD/SHRD (0F A4/A5/AC/AD; eager) --------------------------------- */

/* Double-shift on the 2w-bit concatenation (dest:src for SHLD,
 * src:dest for SHRD), exactly h_bit.c dshift_common: cnt&31 == 0 is a
 * no-op; otherwise dest = middle half, CF = last bit shifted out, OF
 * only for count 1 (SHLD: MSB(res)^CF, SHRD: MSB(dest)^MSB(res)),
 * SF/ZF/PF from the result, AF untouched (logiczx clears it, same as
 * the shift path). */
int xalu_shxd(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_shrd,
                     uint32_t count, int count_is_reg)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->pfx_opsize != 0U ? 16U : 32U;
    unsigned msb = width - 1U;
    unsigned wE = XALU_T0;
    unsigned cfreg = XALU_T4; /* stashed CF bit (bit 0) */
    int is_mem = insn->modrm_mod != 3U && insn->ea_has != 0U;
    size_t to_done = 0;
    int have_done = 0;

    if (count_is_reg == 0 && (count & 31U) == 0U) {
        e->insn_count++; /* full no-op: no write, no flags */
        return 0;
    }
    if (is_mem != 0 && insn->pfx_lock != 0U) {
        return -1; /* LOCKed memory: the interpreter's atomic path */
    }
    xalu_sync_eflags(e);
    if (count_is_reg != 0) {
        /* wT2 = CL & 31; a zero masked count skips everything. */
        a64_emit_ubfm_w(b, XALU_T2, 1U, 0U, 7U);  /* CL */
        a64_emit_ubfm_w(b, XALU_T2, XALU_T2, 0U, 4U); /* & 31 */
        to_done = xalu_cbz_x_placeholder(b, 0, XALU_T2);
        have_done = 1;
    }
    xalu_load_rm(e, insn, XALU_A, width);        /* A = dest */
    xalu_load_reg(b, XALU_B, insn->modrm_reg, width); /* B = src */
    if (width == 32U) {
        /* v = dest:src (SHLD) or src:dest (SHRD) in x11.  x13 is NOT
         * usable here: it aliases the CL-count register XALU_T2.  The
         * W-form loads zeroed the upper halves; the MOV into w12
         * extends the low half exactly, and the LSL #32 shifts stale
         * xA/xB high bits out.  (x11 is XALU_T0, dead until the flag
         * fold commits wE below.) */
        if (is_shrd == 0) {
            xalu_lsl_x_imm(b, 11U, XALU_A, 32U);
            a64_emit_mov_w(b, 12U, XALU_B);
        } else {
            xalu_lsl_x_imm(b, 11U, XALU_B, 32U);
            a64_emit_mov_w(b, 12U, XALU_A);
        }
        xalu_orr_x(b, 11U, 11U, 12U);
        /* Stash CF from the UNSHIFTED v: bit (64-cnt) for SHLD,
         * bit (cnt-1) for SHRD. */
        if (count_is_reg != 0) {
            if (is_shrd == 0) {
                /* T3 = -cnt (W form); LSRV reads its low 6 bits =
                 * 64-cnt for cnt in 1..31. */
                a64_emit_movz_w(b, XALU_T3, 0U, 0U);
                a64_emit_sub_reg_w(b, false, XALU_T3, XALU_T3, XALU_T2,
                                   A64_SHIFT_LSL, 0U);
            } else {
                a64_emit_sub_imm_w(b, false, XALU_T3, XALU_T2, 1U, 0U);
            }
            xalu_lsrv_x(b, cfreg, 11U, XALU_T3);
        } else if (is_shrd == 0) {
            xalu_lsr_x_imm(b, cfreg, 11U, 64U - (count & 31U));
        } else {
            xalu_lsr_x_imm(b, cfreg, 11U, (count & 31U) - 1U);
        }
        a64_emit_ubfm_w(b, cfreg, cfreg, 0U, 0U);
        /* Result: the middle half of the shifted v. */
        if (is_shrd == 0) {
            if (count_is_reg != 0) {
                xalu_lslv_x(b, 11U, 11U, XALU_T2);
            } else {
                xalu_lsl_x_imm(b, 11U, 11U, count & 31U);
            }
            xalu_lsr_x_imm(b, XALU_RES, 11U, 32U);
        } else {
            if (count_is_reg != 0) {
                xalu_lsrv_x(b, 11U, 11U, XALU_T2);
            } else {
                xalu_lsr_x_imm(b, 11U, 11U, count & 31U);
            }
            a64_emit_mov_w(b, XALU_RES, 11U);
        }
    } else {
        /* 16-bit: v = dest:src (SHLD) or src:dest (SHRD) in wT1. */
        xalu_lsl_imm_w(b, XALU_T1, is_shrd == 0 ? XALU_A : XALU_B, 16U);
        a64_emit_orr_reg_w(b, XALU_T1, XALU_T1,
                           is_shrd == 0 ? XALU_B : XALU_A,
                           A64_SHIFT_LSL, 0U);
        /* Stash CF from the UNSHIFTED v: bit (32-cnt) / bit (cnt-1). */
        if (count_is_reg != 0) {
            if (is_shrd == 0) {
                /* T3 = 32 - cnt (both in 1..31, exact). */
                a64_emit_mov_imm32(b, XALU_T3, 32U);
                a64_emit_sub_reg_w(b, false, XALU_T3, XALU_T3, XALU_T2,
                                   A64_SHIFT_LSL, 0U);
            } else {
                a64_emit_sub_imm_w(b, false, XALU_T3, XALU_T2, 1U, 0U);
            }
            a64_emit_shift_reg_w(b, cfreg, XALU_T1, XALU_T3,
                                 A64_SHIFT_LSR);
        } else if (is_shrd == 0) {
            a64_emit_ubfm_w(b, cfreg, XALU_T1, 32U - (count & 31U),
                            32U - (count & 31U));
        } else {
            a64_emit_ubfm_w(b, cfreg, XALU_T1, (count & 31U) - 1U,
                            (count & 31U) - 1U);
        }
        a64_emit_ubfm_w(b, cfreg, cfreg, 0U, 0U);
        /* Result: the middle half of the shifted v.  The 32-bit
         * shift is exact for the low 16 result bits (guest bits
         * above 31 are zero in the 64-bit reference too). */
        if (is_shrd == 0) {
            if (count_is_reg != 0) {
                a64_emit_shift_reg_w(b, XALU_T1, XALU_T1, XALU_T2,
                                     A64_SHIFT_LSL);
            } else {
                xalu_lsl_imm_w(b, XALU_T1, XALU_T1, count & 31U);
            }
            xalu_lsr_imm_w(b, XALU_RES, XALU_T1, 16U);
        } else {
            if (count_is_reg != 0) {
                a64_emit_shift_reg_w(b, XALU_T1, XALU_T1, XALU_T2,
                                     A64_SHIFT_LSR);
            } else {
                xalu_lsr_imm_w(b, XALU_T1, XALU_T1, count & 31U);
            }
            a64_emit_ubfm_w(b, XALU_RES, XALU_T1, 0U, 15U);
        }
    }
    xalu_store_rm(e, insn, XALU_RES, width);

    /* Eager flags (dshift_common shape): CF stashed above, OF only
     * when count == 1, SF/ZF/PF from the result, AF cleared. */
    a64_emit_ldr_imm_w(b, wE, 19U, 36U);
    a64_emit_movz_w(b, XALU_T1, 0x08D5U, 0U); /* CF|PF|AF|ZF|SF|OF */
    a64_emit_bic_reg_w(b, false, wE, wE, XALU_T1, A64_SHIFT_LSL, 0U);
    xalu_bfi_w(b, wE, cfreg, 0U, 1U);
    /* OF only when count == 1 (dshift_common: logiczx clears OF, and
     * only cnt == 1 sets it).  Static counts fold the decision at
     * emit time; CL counts select at runtime. */
    if (count_is_reg == 0 && (count & 31U) != 1U) {
        /* leave OF cleared */
    } else {
        if (is_shrd == 0) {
            /* OF = MSB(res) ^ CF. */
            a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb, msb);
            a64_emit_ubfm_w(b, XALU_T3, wE, 0U, 0U); /* CF just set */
            a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_T3,
                               A64_SHIFT_LSL, 0U);
        } else {
            /* OF = MSB(dest) ^ MSB(res). */
            a64_emit_ubfm_w(b, XALU_T1, XALU_A, msb, msb);
            a64_emit_ubfm_w(b, XALU_T3, XALU_RES, msb, msb);
            a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_T3,
                               A64_SHIFT_LSL, 0U);
        }
        if (count_is_reg != 0) {
            a64_emit_ubfm_w(b, XALU_T3, wE, 11U, 11U); /* old OF */
            a64_emit_sub_imm_w(b, true, 31U, XALU_T2, 1U, 0U);
            a64_emit_csel_w(b, XALU_T1, XALU_T1, XALU_T3, A64_COND_EQ);
        }
        xalu_bfi_w(b, wE, XALU_T1, 11U, 1U);
    }

    xalu_fold_zsp(e, XALU_RES, msb, wE);
    xalu_commit_eflags(e, wE);
    if (have_done != 0) {
        xalu_patch_cbz_x(b, to_done, b->count);
    }

    e->insn_count++;
    return 0;
}

