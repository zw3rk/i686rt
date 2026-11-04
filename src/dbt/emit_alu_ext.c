/*
 * src/dbt/emit_alu_ext.c — extended ALU emitters (Wave P Lane P3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lowers the ALU forms emit_alu.c declined in v1: ROL/ROR (C0/C1/D0-D3
 * /0,/1), INC/DEC (0x40..0x4F, FE/FF /0,/1), CL-count shifts (D2/D3
 * /4,/5,/7), memory shifts and memory NEG/NOT, one-operand MUL/IMUL/
 * DIV/IDIV (F6/F7 /4../5../6../7), ADC/SBB (all nine forms), and
 * SHLD/SHRD (0F A4/A5/AC/AD).  BSWAP already lives in emit_mov.c.
 *
 * Flag rules (bit-identical to the interpreter oracle):
 *  - INC/DEC write every arith flag except CF (preserved): the pending
 *    descriptor is materialized first (helper call unless flags_src is
 *    already EFLAGS), then ctx->eflags is updated by RMW.
 *  - ROL/ROR write CF (+OF when masked count == 1) and preserve
 *    ZF/SF/PF/AF (materialize-first, same as h_shift.c); a masked
 *    count of 0 is a full no-op (no write, no flags).
 *  - CL shifts and SHLD/SHRD-CL with (count & 31) == 0 at runtime are
 *    full no-ops; otherwise they are eager producers exactly like the
 *    imm-shift path (logiczx + CF + OF-when-1, AF cleared).
 *  - 1-op MUL/IMUL define only CF/OF (preserved-neighbour RMW, stale
 *    SF/ZF/PF/AF kept); DIV/IDIV touch no flags at all.
 *  - ADC/SBB are eager producers (lazy_op = NONE, flags_src =
 *    EFLAGS): the carry-in rides NZCV.C through ADCS/SBCS; the result
 *    flags are folded into ctx->eflags by RMW.
 *  - DIV/IDIV divide errors take the D2 path: a conditional branch to
 *    an I686_EXIT_UNDEF exit carrying (len, pc), so the engine's
 *    interpret-one reproduces today's fault behaviour exactly.
 *
 * LOCK discipline (matches the atomic module's contract): memory-dest
 * forms with pfx_lock decline (-1) so the interpreter's atomic CAS
 * path runs them; register forms ignore a redundant LOCK exactly like
 * the interpreter (which only locks memory RMWs).
 *
 * Scratch map (same as emit_alu.c): w8 = A, w9 = B, w10 = result,
 * w11..w15 = temps, x11..x13 = 64-bit temps; w21 survives each
 * load...store pair (the EA), so flag sequences never touch w21/w22.
 * NZCV polarity follows the emit_alu.c convention (C = !CF) except
 * transiently around ADCS/SBCS.
 */

#include "dbt/emit_alu_impl.h"
/* ---- ADC/SBB (all nine forms, eager) ---------------------------------- */

int xalu_adc_sbb(i686_emit_ctx_t *e, const x86_insn_t *insn,
                        int is_sbb, unsigned form)
{
    a64_buf_t *b = &e->buf;
    unsigned width;
    unsigned wE = XALU_T0;
    unsigned wTc = XALU_T4; /* carry-in, kept across the flag fold */
    int dst_rm;
    int src_imm = 0;
    uint32_t imm = 0U;

    switch (form) {
    case XFRM_EbGb:
    case XFRM_GbEb:
    case XFRM_ALIb:
    case XFRM_EbIb:
        width = 8U;
        break;
    default:
        width = insn->pfx_opsize != 0U ? 16U : 32U;
        break;
    }
    switch (form) {
    case XFRM_EbGb:
    case XFRM_EvGv:
        dst_rm = 1;
        break;
    case XFRM_EbIb:
    case XFRM_EvIz:
    case XFRM_EvIbSX:
        dst_rm = 1;
        src_imm = 1;
        break;
    case XFRM_ALIb:
    case XFRM_eAXIz:
        dst_rm = 0;
        src_imm = 1;
        break;
    default: /* XFRM_GbEb, XFRM_GvEv */
        dst_rm = 0;
        break;
    }
    if (src_imm != 0) {
        imm = insn->imm;
        if (form == XFRM_EvIbSX) {
            imm = xalu_sext_imm8(imm);
        }
        if (width == 8U) {
            imm &= 0xFFU;
        } else if (width == 16U) {
            imm &= 0xFFFFU;
        }
    }

    if (dst_rm != 0 && insn->modrm_mod != 3U && insn->ea_has != 0U &&
        insn->pfx_lock != 0U) {
        return -1; /* LOCKed memory: the interpreter's atomic path */
    }
    /* Carry-in before any operand load (the DEAD-path call clobbers
     * x0-x18); the NZCV path needs no call at all. */
    if (e->flags_src != I686_FLAGS_NZCV) {
        xalu_sync_eflags(e);
    }
    xalu_carry_in(e, wTc);
    if (is_sbb != 0) {
        /* SBCS computes Rn - Rm - NOT(C): present !CF, the natural
         * fused polarity (emit_binop inverts the same way).  The
         * numeric wTc stays the true CF for the flag fold below. */
        a64_emit_mrs_nzcv(b, XALU_T0);
        a64_emit_movz_w(b, XALU_T1, 0x2000U, 1U); /* (1 << 29): C mask */
        a64_emit_eor_reg_w(b, XALU_T0, XALU_T0, XALU_T1, A64_SHIFT_LSL, 0U);
        a64_emit_msr_nzcv(b, XALU_T0);
    }

    /* A = destination value (width-masked, zero-extended). */
    if (dst_rm != 0) {
        xalu_load_rm(e, insn, XALU_A, width);
    } else if (src_imm != 0 && (form == XFRM_ALIb || form == XFRM_eAXIz)) {
        xalu_load_reg(b, XALU_A, I686_REG_EAX, width);
    } else {
        xalu_load_reg(b, XALU_A, insn->modrm_reg, width);
    }
    /* B = source value or immediate. */
    if (src_imm != 0) {
        a64_emit_mov_imm32(b, XALU_B, imm);
    } else if (dst_rm != 0) {
        xalu_load_reg(b, XALU_B, insn->modrm_reg, width);
    } else {
        xalu_load_rm(e, insn, XALU_B, width);
    }

    if (is_sbb == 0) {
        a64_emit_adc_w(b, true, XALU_RES, XALU_A, XALU_B);
    } else {
        a64_emit_sbc_w(b, true, XALU_RES, XALU_A, XALU_B);
    }

    if (dst_rm != 0) {
        xalu_store_rm(e, insn, XALU_RES, width);
    } else if (src_imm != 0 && (form == XFRM_ALIb || form == XFRM_eAXIz)) {
        xalu_store_reg(b, XALU_RES, I686_REG_EAX, width);
    } else {
        xalu_store_reg(b, XALU_RES, insn->modrm_reg, width);
    }

    /* Eager flags, bit-identical to flags.c i686_flags_adc/sbb. */
    a64_emit_ldr_imm_w(b, wE, 19U, 36U);
    a64_emit_movz_w(b, XALU_T1, 0x08D5U, 0U); /* CF|PF|AF|ZF|SF|OF */
    a64_emit_bic_reg_w(b, false, wE, wE, XALU_T1, A64_SHIFT_LSL, 0U);
    if (width == 32U) {
        a64_emit_mrs_nzcv(b, XALU_T1);
        a64_emit_ubfm_w(b, XALU_T2, XALU_T1, 29U, 29U); /* C */
        if (is_sbb != 0) {
            xalu_eor_imm1_w(b, XALU_T2, XALU_T2);       /* CF = !C */
        }
        xalu_bfi_w(b, wE, XALU_T2, 0U, 1U);
        a64_emit_ubfm_w(b, XALU_T2, XALU_T1, 28U, 28U); /* V */
        xalu_bfi_w(b, wE, XALU_T2, 11U, 1U);
        /* AF = bit 4 of (A ^ B ^ res). */
        a64_emit_eor_reg_w(b, XALU_T1, XALU_A, XALU_B, A64_SHIFT_LSL, 0U);
        a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_RES, A64_SHIFT_LSL, 0U);
        a64_emit_ubfm_w(b, XALU_T1, XALU_T1, 4U, 4U);
        xalu_bfi_w(b, wE, XALU_T1, 4U, 1U);
    } else {
        unsigned msb = width - 1U;
        xalu_and_imm_w(b, XALU_RES, XALU_RES,
                       width == 8U ? 0xFFU : 0xFFFFU);
        if (is_sbb == 0) {
            /* CF = bit w of (A + B + cf). */
            a64_emit_add_reg_w(b, false, XALU_T1, XALU_A, XALU_B,
                               A64_SHIFT_LSL, 0U);
            a64_emit_add_reg_w(b, false, XALU_T1, XALU_T1, wTc,
                               A64_SHIFT_LSL, 0U);
            a64_emit_ubfm_w(b, XALU_T1, XALU_T1, width, width);
            xalu_bfi_w(b, wE, XALU_T1, 0U, 1U);
            /* OF = bit msb of ((A^res) & (B^res)). */
            a64_emit_eor_reg_w(b, XALU_T1, XALU_A, XALU_RES,
                               A64_SHIFT_LSL, 0U);
            a64_emit_eor_reg_w(b, XALU_T2, XALU_B, XALU_RES,
                               A64_SHIFT_LSL, 0U);
        } else {
            /* CF = borrow: (A < B + cf). */
            a64_emit_add_reg_w(b, false, XALU_T1, XALU_B, wTc,
                               A64_SHIFT_LSL, 0U);
            a64_emit_sub_reg_w(b, true, 31U, XALU_A, XALU_T1,
                               A64_SHIFT_LSL, 0U);
            xalu_cset_w(b, XALU_T2, A64_COND_CC);
            xalu_bfi_w(b, wE, XALU_T2, 0U, 1U);
            /* OF = bit msb of ((A^B) & (A^res)). */
            a64_emit_eor_reg_w(b, XALU_T1, XALU_A, XALU_B,
                               A64_SHIFT_LSL, 0U);
            a64_emit_eor_reg_w(b, XALU_T2, XALU_A, XALU_RES,
                               A64_SHIFT_LSL, 0U);
        }
        a64_emit_and_reg_w(b, false, XALU_T1, XALU_T1, XALU_T2,
                           A64_SHIFT_LSL, 0U);
        a64_emit_ubfm_w(b, XALU_T1, XALU_T1, msb, msb);
        xalu_bfi_w(b, wE, XALU_T1, 11U, 1U);
        /* AF = bit 4 of (A ^ B ^ res). */
        a64_emit_eor_reg_w(b, XALU_T1, XALU_A, XALU_B, A64_SHIFT_LSL, 0U);
        a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_RES, A64_SHIFT_LSL, 0U);
        a64_emit_ubfm_w(b, XALU_T1, XALU_T1, 4U, 4U);
        xalu_bfi_w(b, wE, XALU_T1, 4U, 1U);
    }
    xalu_fold_zsp(e, XALU_RES, width - 1U, wE);
    xalu_commit_eflags(e, wE);

    e->insn_count++;
    return 0;
}

/* ---- INC/DEC (0x40..0x4F, FE/FF /0,/1; eager, CF preserved) ------------ */

int xalu_incdec(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_inc)
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
    /* CF (and every other flag) must be current before the RMW:
     * materialize unless already EFLAGS (or proven dead by pre-scan). */
    if (e->skip_lazy == 0U) {
        if (e->flags_src == I686_FLAGS_NZCV) {
            xalu_cset_w(b, XALU_T4, A64_COND_CC); /* CF = !NZCV.C */
        } else {
            xalu_sync_eflags(e);
        }
    }
    /* A = operand (width-masked).  0x40+r synthesize mod=3 with the
     * register in modrm_rm; FE/FF share these ids for mod=3. */
    xalu_load_rm(e, insn, XALU_A, width);
    {
        int need_flags = (e->skip_lazy == 0U || e->skip_lazy >= 4U);
        if (is_inc != 0) {
            a64_emit_add_imm_w(b, width == 32U && need_flags != 0, XALU_RES,
                               XALU_A, 1U, 0U);
        } else {
            a64_emit_sub_imm_w(b, width == 32U && need_flags != 0, XALU_RES,
                               XALU_A, 1U, 0U);
        }
        if (width == 32U && (e->skip_lazy == 0U || e->skip_lazy == 4U)) {
            a64_emit_mrs_nzcv(b, XALU_T3);
        }
    }
    if (width != 32U) {
        xalu_and_imm_w(b, XALU_RES, XALU_RES,
                       width == 8U ? 0xFFU : 0xFFFFU);
    }
    xalu_store_rm(e, insn, XALU_RES, width);
    if (e->skip_lazy == 1U) {
        e->flags_src = I686_FLAGS_DEAD;
        e->insn_count++;
        return 0;
    }
    if (e->skip_lazy == 2U) {
        unsigned code = (is_inc != 0 ? 4U : 8U) +
                        (width == 8U ? 0U : (width == 16U ? 1U : 2U));
        a64_emit_str_imm_w(b, XALU_RES, 19U, 92U); /* lazy_cf_in = res */
        a64_emit_movz_w(b, XALU_T0, (uint16_t)code, 0U);
        a64_emit(b, 0x39013E60U | (XALU_T0 & 31U)); /* strb wT0, [x19, #79] */
        e->flags_src = I686_FLAGS_DEAD;
        e->insn_count++;
        return 0;
    }
    if (e->skip_lazy == 5U) {
        unsigned fop = (is_inc != 0) ? I686_FOP_INC : I686_FOP_DEC;
        a64_emit_movz_w(b, XALU_T0, (uint16_t)(fop | (32U << 8)), 0U);
        a64_emit(b, 0x79009A60U | (XALU_T0 & 31U)); /* strh wT0, [x19, #76] */
        a64_emit(b, 0x39013E7FU);                   /* strb wzr, [x19, #79] */
        a64_emit(b, 0x290A0260U | ((XALU_A & 31U) << 10) |
                     (XALU_RES & 31U));             /* stp wRES, wA, [x19, #80] */
        e->flags_src = I686_FLAGS_NZCV;
        e->insn_count++;
        return 0;
    }

    /* Eager flags, bit-identical to flags.c i686_flags_inc/dec:
     * everything but CF is rewritten; CF is preserved. */
    a64_emit_ldr_imm_w(b, wE, 19U, 36U);
    if (e->flags_src == I686_FLAGS_NZCV || e->skip_lazy == 4U) {
        if (e->skip_lazy == 4U) {
            a64_emit(b, 0x39413A60U | (XALU_T4 & 31U)); /* ldrb wT4, [x19, #78] */
        }
        a64_emit_movz_w(b, XALU_T1, 0x08D5U, 0U); /* CF|PF|AF|ZF|SF|OF */
        a64_emit_bic_reg_w(b, false, wE, wE, XALU_T1, A64_SHIFT_LSL, 0U);
        xalu_bfi_w(b, wE, XALU_T4, 0U, 1U);
    } else {
        a64_emit_movz_w(b, XALU_T1, 0x08D4U, 0U); /* ZF|SF|PF|OF|AF (no CF) */
        a64_emit_bic_reg_w(b, false, wE, wE, XALU_T1, A64_SHIFT_LSL, 0U);
    }
    if (width == 32U) {
        a64_emit_ubfm_w(b, XALU_T2, XALU_T3, 28U, 28U); /* V -> OF */
        xalu_bfi_w(b, wE, XALU_T2, 11U, 1U);
    } else {
        /* OF: INC iff res == SMIN-width (0x80/0x8000); DEC iff src == SMIN. */
        a64_emit_mov_imm32(b, XALU_T1, width == 8U ? 0x80U : 0x8000U);
        a64_emit_sub_reg_w(b, true, 31U, is_inc != 0 ? XALU_RES : XALU_A,
                           XALU_T1, A64_SHIFT_LSL, 0U);
        xalu_cset_w(b, XALU_T2, A64_COND_EQ);
        xalu_bfi_w(b, wE, XALU_T2, 11U, 1U);
    }
    /* AF = bit 4 of (src ^ 1 ^ res). */
    a64_emit_eor_reg_w(b, XALU_T1, XALU_A, XALU_RES, A64_SHIFT_LSL, 0U);
    a64_emit_ubfm_w(b, XALU_T1, XALU_T1, 4U, 4U);
    xalu_bfi_w(b, wE, XALU_T1, 4U, 1U);
    xalu_fold_zsp(e, XALU_RES, width - 1U, wE);
    xalu_commit_eflags(e, wE);
    if (width == 32U) {
        xalu_eor_imm1_w(b, XALU_T1, wE);
        xalu_bfi_w(b, XALU_T3, XALU_T1, 29U, 1U); /* C = !CF */
        a64_emit_msr_nzcv(b, XALU_T3);
        e->flags_src = I686_FLAGS_NZCV;
    }

    e->insn_count++;
    return 0;
}

/* ---- ROL/ROR (C0/C1/D0/D1/D2/D3 /0,/1; eager, CF+OF only) -------------- */

/* Rotate via the doubled value t = A | (A << w): ROL = (t >> (w-n'))
 * & mask, ROR = (t >> n') & mask, with n' = count % w.  For w = 32 a
 * single RORV/EXTR does the job.  Bit-identical to h_shift.c h_rol/
 * h_ror (CF = LSB/MSB of the result for every count != 0, OF only
 * when the masked count == 1, all other flags preserved). */
int xalu_rolror(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_ror,
                       uint32_t count, int count_is_reg)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->opnd[0] == I686_OPND_RM8
                         ? 8U
                         : (insn->pfx_opsize != 0U ? 16U : 32U);
    unsigned wE = XALU_T0;
    unsigned msb = width - 1U;
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
    /* ZF/SF/PF/AF are preserved: materialize first (no-op if EFLAGS),
     * then only CF (+OF for count 1) change. */
    if (e->skip_lazy == 0U) {
        xalu_sync_eflags(e);
    }
    if (count_is_reg != 0) {
        /* wT2 = CL & 31; a zero masked count skips everything. */
        a64_emit_ubfm_w(b, XALU_T2, 1U, 0U, 7U); /* CL */
        a64_emit_ubfm_w(b, XALU_T2, XALU_T2, 0U, 4U); /* & 31 */
        /* The masked count is < 32, so the X-form cbz tests it exactly. */
        to_done = xalu_cbz_x_placeholder(b, 0, XALU_T2);
        have_done = 1;
    }
    xalu_load_rm(e, insn, XALU_A, width);
    if (width == 32U) {
        if (count_is_reg != 0) {
            /* ROL by n = ROR by (32-n) & 31. */
            a64_emit_movz_w(b, XALU_T1, 0U, 0U);
            if (is_ror == 0) {
                /* T1 = (0 - cnt), already in 1..31 (cnt != 0). */
                a64_emit_sub_reg_w(b, false, XALU_T1, XALU_T1, XALU_T2,
                                   A64_SHIFT_LSL, 0U);
            } else {
                a64_emit_mov_w(b, XALU_T1, XALU_T2);
            }
            a64_emit_shift_reg_w(b, XALU_RES, XALU_A, XALU_T1,
                                 A64_SHIFT_ROR);
        } else {
            unsigned n = (count & 31U) % 32U;
            unsigned sh = (is_ror != 0) ? n : (32U - n) & 31U;
            /* ROR #sh = EXTR Wd, Wn, Wn, #sh. */
            a64_emit(b, 0x13800000U | ((XALU_A & 31U) << 16) |
                             ((sh & 31U) << 10) | ((XALU_A & 31U) << 5) |
                             (XALU_RES & 31U));
        }
    } else {
        /* t = A | (A << w); then shift + mask. */
        xalu_lsl_imm_w(b, XALU_T1, XALU_A, width);
        a64_emit_orr_reg_w(b, XALU_T1, XALU_A, XALU_T1, A64_SHIFT_LSL, 0U);
        if (count_is_reg != 0) {
            /* n' = cnt % w; ROL shifts by (w - n') % w ... expressed
             * without a modulo: ROL = (t >> (w - n')) & m.  Compute
             * k = (w - n') & (w*2-1)... simpler: n' via AND, then
             * k = (w - n') & 31 (w <= 16 so (w-n') in [0,16] fits). */
            a64_emit_ubfm_w(b, XALU_T3, XALU_T2, 0U,
                            width == 8U ? 2U : 3U); /* n' = cnt & (w-1) */
            if (is_ror == 0) {
                /* k = w - n', already in 0..w (w <= 16). */
                a64_emit_mov_imm32(b, XALU_T4, width);
                a64_emit_sub_reg_w(b, false, XALU_T3, XALU_T4, XALU_T3,
                                   A64_SHIFT_LSL, 0U);
            }
            a64_emit_shift_reg_w(b, XALU_RES, XALU_T1, XALU_T3,
                                 A64_SHIFT_LSR);
        } else {
            unsigned n = (count & 31U) % width;
            unsigned sh = (is_ror != 0) ? n : width - n;
            xalu_lsr_imm_w(b, XALU_RES, XALU_T1, sh == 0U ? width : sh);
            /* sh == 0 impossible here (count & 31 != 0 and n = 0
             * means count % width == 0, e.g. ROL8 by 8: shift by w
             * recovers A, matching the identity rotation). */
        }
        xalu_and_imm_w(b, XALU_RES, XALU_RES,
                       width == 8U ? 0xFFU : 0xFFFFU);
    }
    xalu_store_rm(e, insn, XALU_RES, width);
    if (e->skip_lazy == 1U) {
        if (have_done != 0) {
            xalu_patch_cbz_x(b, to_done, b->count);
        }
        e->flags_src = I686_FLAGS_DEAD;
        e->insn_count++;
        return 0;
    }
    if (e->skip_lazy == 2U) {
        /* Fault-safe CF/OF override in lazy_op[31:16] for static-count
         * rotates across non-flag-reading memory instructions. */
        if ((count & 31U) == 1U) {
            a64_emit_movz_w(b, wE, 0x0202U, 0U);
            a64_emit_ubfm_w(b, XALU_T1, XALU_RES, is_ror == 0 ? 0U : msb,
                            is_ror == 0 ? 0U : msb);
            xalu_bfi_w(b, wE, XALU_T1, 0U, 1U);
            a64_emit_ubfm_w(b, XALU_T2, XALU_RES, msb, msb);
            if (is_ror == 0) {
                a64_emit_eor_reg_w(b, XALU_T2, XALU_T2, XALU_T1,
                                   A64_SHIFT_LSL, 0U);
            } else {
                a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb - 1U, msb - 1U);
                a64_emit_eor_reg_w(b, XALU_T2, XALU_T2, XALU_T1,
                                   A64_SHIFT_LSL, 0U);
            }
            xalu_bfi_w(b, wE, XALU_T2, 8U, 1U);
            a64_emit(b, 0x79009E60U | (wE & 31U)); /* strh wE, [x19, #78] */
        } else {
            a64_emit_movz_w(b, wE, 2U, 0U);
            if (is_ror == 0) {
                xalu_bfi_w(b, wE, XALU_RES, 0U, 1U);
            } else {
                a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb, msb);
                xalu_bfi_w(b, wE, XALU_T1, 0U, 1U);
            }
            a64_emit(b, 0x39013A60U | (wE & 31U)); /* strb wE, [x19, #78] */
        }
        e->flags_src = I686_FLAGS_DEAD;
        e->insn_count++;
        return 0;
    }

    /* CF = LSB (ROL) / MSB (ROR) of the result, for every count != 0. */
    a64_emit_ldr_imm_w(b, wE, 19U, 36U);
    a64_emit_movz_w(b, XALU_T1, 0x0801U, 0U); /* CF|OF */
    a64_emit_bic_reg_w(b, false, wE, wE, XALU_T1, A64_SHIFT_LSL, 0U);
    if (is_ror == 0) {
        a64_emit_ubfm_w(b, XALU_T1, XALU_RES, 0U, 0U);
    } else {
        a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb, msb);
    }
    xalu_bfi_w(b, wE, XALU_T1, 0U, 1U);
    /* OF only when the masked count == 1: ROL: MSB^CF, ROR: the two
     * MSBs of the result. */
    if (count_is_reg != 0) {
        /* of_new into T1 (T4 scratch; the count in T2 stays live for
         * the cmp below), then keep old OF unless count == 1. */
        a64_emit_ubfm_w(b, XALU_T3, wE, 11U, 11U); /* old OF */
        if (is_ror == 0) {
            a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb, msb);
            a64_emit_ubfm_w(b, XALU_T4, wE, 0U, 0U); /* CF just set */
            a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_T4,
                               A64_SHIFT_LSL, 0U);
        } else {
            a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb, msb);
            a64_emit_ubfm_w(b, XALU_T4, XALU_RES, msb - 1U, msb - 1U);
            a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_T4,
                               A64_SHIFT_LSL, 0U);
        }
        a64_emit_sub_imm_w(b, true, 31U, XALU_T2, 1U, 0U); /* cmp cnt,1 */
        a64_emit_csel_w(b, XALU_T1, XALU_T1, XALU_T3, A64_COND_EQ);
        xalu_bfi_w(b, wE, XALU_T1, 11U, 1U);
    } else if ((count & 31U) == 1U) {
        if (is_ror == 0) {
            a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb, msb);
            a64_emit_ubfm_w(b, XALU_T2, wE, 0U, 0U); /* CF just set */
            a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_T2,
                               A64_SHIFT_LSL, 0U);
        } else {
            a64_emit_ubfm_w(b, XALU_T1, XALU_RES, msb, msb);
            a64_emit_ubfm_w(b, XALU_T2, XALU_RES, msb - 1U, msb - 1U);
            a64_emit_eor_reg_w(b, XALU_T1, XALU_T1, XALU_T2,
                               A64_SHIFT_LSL, 0U);
        }
        xalu_bfi_w(b, wE, XALU_T1, 11U, 1U);
    }
    xalu_commit_eflags(e, wE);
    if (have_done != 0) {
        xalu_patch_cbz_x(b, to_done, b->count);
    }

    e->insn_count++;
    return 0;
}

static int xalu_bt_reg(i686_emit_ctx_t *e, const x86_insn_t *insn,
                       unsigned mode, int from_reg)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->pfx_opsize != 0U ? 16U : 32U;

    if (insn->modrm_mod != 3U) {
        return -1;
    }
    if (e->skip_lazy == 0U) {
        xalu_sync_eflags(e);
    }
    xalu_load_reg(b, XALU_A, insn->modrm_rm, width);
    if (from_reg != 0) {
        xalu_load_reg(b, XALU_B, insn->modrm_reg, 32U);
        a64_emit_ubfm_w(b, XALU_B, XALU_B, 0U, width == 16U ? 3U : 4U);
        a64_emit_shift_reg_w(b, XALU_T1, XALU_A, XALU_B, A64_SHIFT_LSR);
        a64_emit_ubfm_w(b, XALU_T1, XALU_T1, 0U, 0U);
    } else {
        unsigned idx = insn->imm & (width - 1U);
        a64_emit_ubfm_w(b, XALU_T1, XALU_A, idx, idx);
    }
    if (mode != 0U) {
        if (from_reg != 0) {
            a64_emit_movz_w(b, XALU_T2, 1U, 0U);
            a64_emit_shift_reg_w(b, XALU_T2, XALU_T2, XALU_B, A64_SHIFT_LSL);
        } else {
            a64_emit_mov_imm32(b, XALU_T2, 1U << (insn->imm & (width - 1U)));
        }
        if (mode == 1U) {
            a64_emit_orr_reg_w(b, XALU_RES, XALU_A, XALU_T2, A64_SHIFT_LSL, 0U);
        } else if (mode == 2U) {
            a64_emit_bic_reg_w(b, false, XALU_RES, XALU_A, XALU_T2,
                               A64_SHIFT_LSL, 0U);
        } else {
            a64_emit_eor_reg_w(b, XALU_RES, XALU_A, XALU_T2, A64_SHIFT_LSL, 0U);
        }
        xalu_store_reg(b, XALU_RES, insn->modrm_rm, width);
    }
    if (e->skip_lazy == 1U) {
        e->flags_src = I686_FLAGS_DEAD;
        e->insn_count++;
        return 0;
    }
    if (e->skip_lazy == 2U) {
        a64_emit_movz_w(b, XALU_T0, 2U, 0U);
        xalu_bfi_w(b, XALU_T0, XALU_T1, 0U, 1U);
        a64_emit(b, 0x39013A60U | (XALU_T0 & 31U)); /* strb wT0, [x19, #78] */
        e->flags_src = I686_FLAGS_DEAD;
        e->insn_count++;
        return 0;
    }
    a64_emit_ldr_imm_w(b, XALU_T0, 19U, 36U);
    xalu_bfi_w(b, XALU_T0, XALU_T1, 0U, 1U);
    xalu_commit_eflags(e, XALU_T0);
    e->insn_count++;
    return 0;
}

/* ---- dispatcher ------------------------------------------------------- */

/* ADC/SBB share the ADD/SUB form ids with the carry folded in at
 * runtime; every other row below is its own op id. */
int i686_emit_alu_ext(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    switch (insn->op) {
#define ALU9X(mn, is_sbb)                                                     \
    case I686_OP_##mn##_EbGb: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_EbGb); \
    case I686_OP_##mn##_EvGv: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_EvGv); \
    case I686_OP_##mn##_GbEb: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_GbEb); \
    case I686_OP_##mn##_GvEv: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_GvEv); \
    case I686_OP_##mn##_ALIb: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_ALIb); \
    case I686_OP_##mn##_eAXIz: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_eAXIz); \
    case I686_OP_##mn##_EbIb: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_EbIb); \
    case I686_OP_##mn##_EvIz: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_EvIz); \
    case I686_OP_##mn##_EvIbSX: return xalu_adc_sbb(e, insn, (is_sbb), XFRM_EvIbSX)

        ALU9X(ADC, 0);
        ALU9X(SBB, 1);
#undef ALU9X

    case I686_OP_INC_Eb:
    case I686_OP_INC_Ev:
        return xalu_incdec(e, insn, 1);
    case I686_OP_DEC_Eb:
    case I686_OP_DEC_Ev:
        return xalu_incdec(e, insn, 0);

    case I686_OP_ROL_Eb1:
    case I686_OP_ROL_Ev1:
        return xalu_rolror(e, insn, 0, 1U, 0);
    case I686_OP_ROL_EbIb:
    case I686_OP_ROL_EvIb:
        return xalu_rolror(e, insn, 0, insn->imm & 0xFFU, 0);
    case I686_OP_ROL_EbCL:
    case I686_OP_ROL_EvCL:
        return xalu_rolror(e, insn, 0, 0U, 1);
    case I686_OP_ROR_Eb1:
    case I686_OP_ROR_Ev1:
        return xalu_rolror(e, insn, 1, 1U, 0);
    case I686_OP_ROR_EbIb:
    case I686_OP_ROR_EvIb:
        return xalu_rolror(e, insn, 1, insn->imm & 0xFFU, 0);
    case I686_OP_ROR_EbCL:
    case I686_OP_ROR_EvCL:
        return xalu_rolror(e, insn, 1, 0U, 1);

    case I686_OP_SHL_EbCL:
    case I686_OP_SHL_EvCL:
        return xalu_shift_cl(e, insn, XSHK_SHL);
    case I686_OP_SHR_EbCL:
    case I686_OP_SHR_EvCL:
        return xalu_shift_cl(e, insn, XSHK_SHR);
    case I686_OP_SAR_EbCL:
    case I686_OP_SAR_EvCL:
        return xalu_shift_cl(e, insn, XSHK_SAR);

    case I686_OP_MUL_Eb:
    case I686_OP_MUL_Ev:
        return xalu_mul1(e, insn, 0);
    case I686_OP_IMUL_Eb:
    case I686_OP_IMUL_Ev:
        return xalu_mul1(e, insn, 1);
    case I686_OP_DIV_Eb:
    case I686_OP_DIV_Ev:
        return xalu_divide(e, insn, 0);
    case I686_OP_IDIV_Eb:
    case I686_OP_IDIV_Ev:
        return xalu_divide(e, insn, 1);

    case I686_OP_SHLD_EvIb:
        return xalu_shxd(e, insn, 0, insn->imm & 0xFFU, 0);
    case I686_OP_SHLD_EvCL:
        return xalu_shxd(e, insn, 0, 0U, 1);
    case I686_OP_SHRD_EvIb:
        return xalu_shxd(e, insn, 1, insn->imm & 0xFFU, 0);
    case I686_OP_SHRD_EvCL:
        return xalu_shxd(e, insn, 1, 0U, 1);

    case I686_OP_BT_EvGv:  return xalu_bt_reg(e, insn, 0U, 1);
    case I686_OP_BTS_EvGv: return xalu_bt_reg(e, insn, 1U, 1);
    case I686_OP_BTR_EvGv: return xalu_bt_reg(e, insn, 2U, 1);
    case I686_OP_BTC_EvGv: return xalu_bt_reg(e, insn, 3U, 1);
    case I686_OP_BT_EvIb:  return xalu_bt_reg(e, insn, 0U, 0);
    case I686_OP_BTS_EvIb: return xalu_bt_reg(e, insn, 1U, 0);
    case I686_OP_BTR_EvIb: return xalu_bt_reg(e, insn, 2U, 0);
    case I686_OP_BTC_EvIb: return xalu_bt_reg(e, insn, 3U, 0);

    default:
        return -1;
    }
}

