/*
 * src/dbt/emit_alu.c — ALU/TEST/NEG/NOT/IMUL/shift-by-imm emitters (L3a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * NZCV fusion (D6, docs/lanes/phase-3.md conventions):
 *  - ADD          -> ADDS Wres, Wa, Wb        (A64 C == x86 CF, V == x86 OF)
 *  - SUB/CMP/NEG  -> SUBS                     (A64 C = no-borrow, i.e. the
 *                    INVERSE of x86 CF for sub-class ops; A64 V == x86 OF)
 *  - AND/OR/XOR/TEST -> plain op + ADDS wzr, Wres, #0 (N/Z from the result,
 *                    C = V = 0 exactly as x86 logic ops require)
 *  - 8/16-bit operands use the shift trick: the width-masked operand rides
 *    bits 31:8 / 31:16 of the w-scratch, so bit 31 doubles as the width MSB
 *    and carry/overflow act at the operand width (byte add carry, word
 *    borrow, byte NEG overflow are all width-true in NZCV).
 *
 * Every flag-setting op ALSO records the interpreter-compatible lazy
 * descriptor {lazy_op, lazy_res, lazy_src1, lazy_src2, lazy_width} into
 * ctx, and IMUL/shifts (whose flag rules the lazy descriptor cannot
 * express) update ctx->eflags eagerly exactly like the interpreter's
 * h_muldiv.c md_set_cf_of / h_shift.c i686_flags_logiczx.  A block may
 * therefore end after any insn and land in the same architectural state
 * as the interpreter; src/interp/flags.c materializes on demand.
 *
 * flags_src maintenance (C6a dead-flag elimination seam, emit.h): the
 * emitters here tell later same-block flag consumers what they may
 * rely on:
 *   - fused ops (binop ADD/SUB/CMP/AND/OR/XOR/TEST, NEG) leave the
 *     architectural image live in A64 NZCV (natural SUBS polarity,
 *     width-true via the shift trick) -> I686_FLAGS_NZCV;
 *   - eager-eflags ops (IMUL, shift-by-imm) leave ctx->eflags current
 *     (lazy_op = NONE) but clobber NZCV with internal compares ->
 *     I686_FLAGS_EFLAGS;
 *   - NOT and the cnt==0 shift write no flag state at all -> the
 *     previous proof still holds, leave e->flags_src untouched.
 *
 * Lowered since v1 (Lane P3, Wave P): NEG/NOT and SHL/SHR/SAR cover
 * register and memory destinations; the remaining new rows (ROL/ROR,
 * INC/DEC, CL-shifts, one-operand MUL/IMUL/DIV/IDIV, ADC/SBB, SHLD/
 * SHRD) live in src/dbt/emit_alu_ext.c and dispatch from i686_emit_alu
 * below.  RCL/RCR still decline (returning -1 is always D2-safe;
 * translate.c emits the UNDEF fallback and the engine interprets one).
 *
 * Scratch map (w0..w7 guest GPRs, x19 ctx, x20 xG per D7; w21/w22 belong
 * to i686_emit_ea): w8 = A (dest value), w9 = B (src/imm), w10 = result,
 * w11..w15 = temps, x23 = TSO address scratch.
 */

#include <stdint.h>
#include <string.h>

#include "dbt/aot/aot.h"
#include "dbt/emit.h"
#include "dbt/emit_alu_impl.h"

#define SCR_A    8U  /* destination operand value (width-masked) */
#define SCR_B    9U  /* source operand value / immediate         */
#define SCR_RES 10U  /* result                                    */
#define SCR_T0  11U
#define SCR_T1  12U
#define SCR_T2  13U
#define SCR_T3  14U
#define SCR_T4  15U

/* ---- width-trivial raw encoders ------------------------------------- */

/* AND Wd, Wn, #imm — only 0xFF / 0xFFFF are needed (N=0, immr=0). */
static void emit_and_imm_w(a64_buf_t *b, unsigned rd, unsigned rn, uint32_t imm)
{
    unsigned imms = (imm == 0xFFFFU) ? 15U : 7U;
    a64_emit(b, 0x12000000U | ((uint32_t)imms << 10) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

/* CSET Wd, cond = CSINC Wd, WZR, WZR, invert(cond). */
static void emit_cset_w(a64_buf_t *b, unsigned rd, unsigned cond)
{
    a64_emit(b, 0x1A800400U | (31U << 16) | (((cond ^ 1U) & 15U) << 12) |
                     (31U << 5) | (rd & 31U));
}

/* EOR Wd, Wn, #1 (parity flip in the PF fold). */
static void emit_eor_imm1_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x52000000U | ((rn & 31U) << 5) | (rd & 31U));
}

/* SBFMX (X form) — sbfx used on the 64-bit IMUL product. */
static void emit_sbfx_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x,
                        unsigned lsb, unsigned width)
{
    a64_emit(b, 0x93400000U | ((lsb & 63U) << 16) | (((width - 1U) & 63U) << 10) |
                     ((rn_x & 31U) << 5) | (rd_x & 31U));
}

/* SUBS XZR, Xn, Xm (64-bit compare for the IMUL overflow rule). */
static void emit_subs_x(a64_buf_t *b, unsigned rn_x, unsigned rm_x)
{
    a64_emit(b, 0xEB000000U | ((rm_x & 31U) << 16) | ((rn_x & 31U) << 5) | 31U);
}

/* BFI Wd, Wn, #lsb, #width = BFM Wd, Wn, #(32-lsb)&31, #(width-1). */
static void emit_bfi_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned lsb,
                       unsigned width)
{
    a64_emit_bfm_w(b, rd, rn, (32U - lsb) & 31U, width - 1U);
}

/* LSL Wd, Wn, #s (1..31) = UBFM #(32-s)&31, #(31-s). */
static void emit_lsl_imm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned s)
{
    a64_emit_ubfm_w(b, rd, rn, (32U - s) & 31U, 31U - s);
}

/* LSR Wd, Wn, #s (1..31) = UBFM #s, #31. */
static void emit_lsr_imm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned s)
{
    a64_emit_ubfm_w(b, rd, rn, s, 31U);
}

/* ---- guest memory (w21 = EA from i686_emit_ea) ----------------------- */

static void emit_guest_load(i686_emit_ctx_t *e, unsigned rt, unsigned width)
{
    a64_buf_t *b = &e->buf;

    if (width == 8U) {
        a64_emit_guest_ldrb_w(b, rt, 21U);
    } else if (width == 16U) {
        a64_emit_guest_ldrh_w(b, rt, 21U);
    } else {
        a64_emit_guest_ldr_w(b, rt, 21U);
    }
    if (e->tso) {
        a64_emit(b, 0xD50339BFU); /* dmb ishld */
    }
}

static void emit_guest_store(i686_emit_ctx_t *e, unsigned rt, unsigned width)
{
    a64_buf_t *b = &e->buf;

    if (width == 8U) {
        a64_emit_guest_strb_w(b, rt, 21U);
    } else if (width == 16U) {
        a64_emit_guest_strh_w(b, rt, 21U);
    } else {
        a64_emit_guest_str_w(b, rt, 21U);
    }
    if (e->tso) {
        a64_emit(b, 0xD5033BBFU); /* dmb ish */
    }
}

/* ---- x86 register file on the fixed w0..w7 map ----------------------- */

/* 8-bit high halves (AH..BH) live in bits 15:8 of EAX..EBX (D7). */
static unsigned byte_pos(uint8_t reg)
{
    return (reg >= 4U) ? 8U : 0U;
}

static unsigned byte_host(uint8_t reg)
{
    return (reg >= 4U) ? (unsigned)(reg - 4U) : (unsigned)reg;
}

static void emit_load_reg(a64_buf_t *b, unsigned dst, uint8_t reg,
                          unsigned width)
{
    if (width == 32U) {
        a64_emit_mov_w(b, dst, i686_w(reg));
    } else if (width == 16U) {
        a64_emit_ubfm_w(b, dst, i686_w(reg), 0U, 15U);
    } else {
        a64_emit_ubfm_w(b, dst, byte_host(reg), byte_pos(reg),
                        byte_pos(reg) + 7U);
    }
}

static void emit_store_reg(a64_buf_t *b, unsigned src, uint8_t reg,
                           unsigned width)
{
    if (width == 32U) {
        a64_emit_mov_w(b, i686_w(reg), src);
    } else if (width == 16U) {
        emit_bfi_w(b, i686_w(reg), src, 0U, 16U);
    } else {
        emit_bfi_w(b, i686_w(byte_host(reg)), src, byte_pos(reg), 8U);
    }
}

/* r/m operand: mod==3 (or no EA) is a register, else guest memory via
 * i686_emit_ea; w21 survives the load for the matching store.  Recovery
 * sites come from the shared xalu_note_mem_site (emit_alu_impl.h) so the
 * base and extended ALU families record the identical shape. */
static void emit_load_rm(i686_emit_ctx_t *e, const x86_insn_t *insn,
                         unsigned dst, unsigned width)
{
    if (insn->modrm_mod == 3U || insn->ea_has == 0U) {
        emit_load_reg(&e->buf, dst, insn->modrm_rm, width);
        return;
    }
    {
        a64_buf_t *b = &e->buf;
        uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t mem;
        uint32_t cont;
        i686_emit_ea(e, insn, 1);
        mem = (uint32_t)((uint64_t)b->count * 4u);
        emit_guest_load(e, dst, width);
        cont = (uint32_t)((uint64_t)b->count * 4u);
        xalu_note_mem_site(e, insn, seq, mem, cont, width, dst, 0U);
    }
}

static void emit_store_rm(i686_emit_ctx_t *e, const x86_insn_t *insn,
                          unsigned src, unsigned width)
{
    if (insn->modrm_mod == 3U || insn->ea_has == 0U) {
        emit_store_reg(&e->buf, src, insn->modrm_rm, width);
        return;
    }
    /* Nothing between load and store touched w21. */
    {
        a64_buf_t *b = &e->buf;
        uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t mem = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t cont;
        emit_guest_store(e, src, width);
        cont = (uint32_t)((uint64_t)b->count * 4u);
        xalu_note_mem_site(e, insn, seq, mem, cont, width, src, 1U);
    }
}

/* ---- lazy descriptor (bit-identical to flags.c's set_lazy) ---------- */

static void emit_lazy(i686_emit_ctx_t *e, uint32_t fop, unsigned res,
                      unsigned s1, unsigned s2, unsigned width)
{
    a64_buf_t *b = &e->buf;

    if (e->skip_lazy == 1U) {
        return; /* Lane P3 pre-scan proved this store dead. */
    }
    if (e->skip_lazy == 2U) {
        /* Fault-safe compact lazy descriptor across non-flag-reading memory
         * instructions: pack width in lazy_op[15:8] and skip lazy_cf_in /
         * lazy_width (and lazy_src1/src2 for LOGIC). */
        a64_emit_movz_w(b, SCR_T0, (uint16_t)(fop | (width << 8)), 0U);
        a64_emit(b, 0x29098260U | ((res & 31U) << 10) | (SCR_T0 & 31U));
        if (fop != I686_FOP_LOGIC) {
            a64_emit(b, 0x290A8260U | ((s2 & 31U) << 10) | (s1 & 31U));
        }
        return;
    }
    a64_emit_movz_w(b, SCR_T0, (uint16_t)fop, 0U);
    a64_emit(b, 0x29098260U | ((res & 31U) << 10) | (SCR_T0 & 31U));
    a64_emit(b, 0x290A8260U | ((s2 & 31U) << 10) | (s1 & 31U));
    a64_emit_str_imm_w(b, 31U, 19U, 92U);     /* lazy_cf_in = 0 (WZR) */
    a64_emit_movz_w(b, SCR_T0, (uint16_t)width, 0U);
    a64_emit_str_imm_w(b, SCR_T0, 19U, 104U); /* lazy_width */
}

/* ---- binary ALU ------------------------------------------------------ */

enum { ALUK_ADD, ALUK_SUB, ALUK_CMP, ALUK_AND, ALUK_OR, ALUK_XOR, ALUK_TEST };
enum {
    FRM_EbGb,
    FRM_EvGv,
    FRM_GbEb,
    FRM_GvEv,
    FRM_ALIb,
    FRM_eAXIz,
    FRM_EbIb,
    FRM_EvIz,
    FRM_EvIbSX
};

static uint32_t sext_imm8(uint32_t imm)
{
    return ((imm & 0xFFU) ^ 0x80U) - 0x80U;
}

static int emit_binop(i686_emit_ctx_t *e, const x86_insn_t *insn,
                      unsigned kind, unsigned form)
{
    a64_buf_t *b = &e->buf;
    unsigned width;
    unsigned sh;
    int dst_rm;
    int src_rm;
    int src_imm;
    uint32_t imm = 0U;

    switch (form) {
    case FRM_EbGb:
    case FRM_GbEb:
    case FRM_ALIb:
    case FRM_EbIb:
        width = 8U;
        break;
    default:
        width = insn->pfx_opsize != 0U ? 16U : 32U;
        break;
    }
    sh = (width == 32U) ? 0U : 32U - width;

    switch (form) {
    case FRM_EbGb:
    case FRM_EvGv:
        dst_rm = 1;
        src_rm = 0;
        src_imm = 0;
        break;
    case FRM_GbEb:
    case FRM_GvEv:
        dst_rm = 0;
        src_rm = 1;
        src_imm = 0;
        break;
    case FRM_ALIb:
    case FRM_eAXIz:
        dst_rm = 0;
        src_rm = 0;
        src_imm = 1;
        break;
    default: /* FRM_EbIb, FRM_EvIz, FRM_EvIbSX */
        dst_rm = 1;
        src_rm = 0;
        src_imm = 1;
        break;
    }
    if (src_imm != 0) {
        imm = insn->imm;
        if (form == FRM_EvIbSX) {
            imm = sext_imm8(imm);
        }
        if (width == 8U) {
            imm &= 0xFFU;
        } else if (width == 16U) {
            imm &= 0xFFFFU;
        }
    }

    /* A = destination value (width-masked, zero-extended). */
    if (dst_rm != 0) {
        emit_load_rm(e, insn, SCR_A, width);
    } else if (form == FRM_ALIb || form == FRM_eAXIz) {
        emit_load_reg(b, SCR_A, I686_REG_EAX, width);
    } else {
        emit_load_reg(b, SCR_A, insn->modrm_reg, width);
    }
    /* B = source value or immediate. */
    if (src_imm != 0) {
        a64_emit_mov_imm32(b, SCR_B, imm);
    } else if (src_rm != 0) {
        emit_load_rm(e, insn, SCR_B, width);
    } else {
        emit_load_reg(b, SCR_B, insn->modrm_reg, width);
    }

    if (sh != 0U) { /* shift trick: operand MSB -> bit 31 */
        emit_lsl_imm_w(b, SCR_A, SCR_A, sh);
        emit_lsl_imm_w(b, SCR_B, SCR_B, sh);
    }

    if (kind == ALUK_ADD) {
        a64_emit_add_reg_w(b, e->skip_lazy == 0U, SCR_RES, SCR_A, SCR_B,
                           A64_SHIFT_LSL, 0U);
        if (e->skip_lazy == 0U) {
            /* Invert C so NZCV holds C = !CF (natural SUBS polarity). */
            a64_emit_mrs_nzcv(b, SCR_T0);
            a64_emit_movz_w(b, SCR_T1, 0x2000U, 1U);
            a64_emit_eor_reg_w(b, SCR_T0, SCR_T0, SCR_T1, A64_SHIFT_LSL, 0U);
            a64_emit_msr_nzcv(b, SCR_T0);
        }
    } else if (kind == ALUK_SUB) {
        a64_emit_sub_reg_w(b, e->skip_lazy == 0U, SCR_RES, SCR_A, SCR_B,
                           A64_SHIFT_LSL, 0U);
    } else if (kind == ALUK_CMP) {
        if (e->skip_lazy == 0U) {
            a64_emit_sub_reg_w(b, true, SCR_RES, SCR_A, SCR_B,
                               A64_SHIFT_LSL, 0U);
        }
    } else {
        if (kind == ALUK_AND || kind == ALUK_TEST) {
            a64_emit_and_reg_w(b, false, SCR_RES, SCR_A, SCR_B, A64_SHIFT_LSL,
                               0U);
        } else if (kind == ALUK_OR) {
            a64_emit_orr_reg_w(b, SCR_RES, SCR_A, SCR_B, A64_SHIFT_LSL, 0U);
        } else { /* ALUK_XOR */
            a64_emit_eor_reg_w(b, SCR_RES, SCR_A, SCR_B, A64_SHIFT_LSL, 0U);
        }
        if (e->skip_lazy == 0U) {
            /* x86 logic flags: CF = OF = 0 (so SUBS C = !CF = 1), N/Z from result. */
            a64_emit_sub_imm_w(b, true, 31U, SCR_RES, 0U, 0U);
        }
    }

    if (sh != 0U) { /* un-shift A, B, RES back to width-masked values */
        emit_lsr_imm_w(b, SCR_A, SCR_A, sh);
        emit_lsr_imm_w(b, SCR_B, SCR_B, sh);
        emit_lsr_imm_w(b, SCR_RES, SCR_RES, sh);
    }

    if (kind != ALUK_CMP && kind != ALUK_TEST) {
        if (dst_rm != 0) {
            emit_store_rm(e, insn, SCR_RES, width);
        } else if (form == FRM_ALIb || form == FRM_eAXIz) {
            emit_store_reg(b, SCR_RES, I686_REG_EAX, width);
        } else {
            emit_store_reg(b, SCR_RES, insn->modrm_reg, width);
        }
    }

    if (kind == ALUK_ADD) {
        emit_lazy(e, I686_FOP_ADD, SCR_RES, SCR_A, SCR_B, width);
    } else if (kind == ALUK_SUB || kind == ALUK_CMP) {
        emit_lazy(e, I686_FOP_SUB, SCR_RES, SCR_A, SCR_B, width);
    } else {
        emit_lazy(e, I686_FOP_LOGIC, SCR_RES, SCR_RES, 31U, width);
    }
    /* Fused image live in NZCV (natural SUBS polarity): a later
     * same-block consumer may fuse on it directly (emit.h seam).
     * A skipped producer emits no NZCV image, so downgrade (DEAD is
     * always correct): the overwriting j re-establishes the proof. */
    if (e->skip_lazy != 0U) {
        e->flags_src = I686_FLAGS_DEAD;
    } else {
        e->flags_src = I686_FLAGS_NZCV;
    }

    e->insn_count++;
    return 0;
}

/* ---- NOT / NEG (register forms) -------------------------------------- */

static int emit_negnot(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_neg)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->opnd[0] == I686_OPND_RM8
                         ? 8U
                         : (insn->pfx_opsize != 0U ? 16U : 32U);
    unsigned sh = (width == 32U) ? 0U : 32U - width;
    int is_mem = insn->modrm_mod != 3U && insn->ea_has != 0U;

    if (is_mem != 0 && insn->pfx_lock != 0U) {
        /* LOCKed memory: the interpreter's atomic path (lane atomic
         * module does not cover NEG/NOT). */
        return -1;
    }
    emit_load_rm(e, insn, SCR_A, width);
    if (sh != 0U) {
        emit_lsl_imm_w(b, SCR_A, SCR_A, sh);
    }
    if (is_neg != 0) {
        /* subs res, wzr, a: C = (0 >= a) i.e. !x86-CF(a != 0); V set iff
         * a == width-signed-min == x86 OF for NEG. */
        a64_emit_sub_reg_w(b, e->skip_lazy == 0U, SCR_RES, 31U, SCR_A,
                           A64_SHIFT_LSL, 0U);
        if (sh != 0U) {
            emit_lsr_imm_w(b, SCR_A, SCR_A, sh);
            emit_lsr_imm_w(b, SCR_RES, SCR_RES, sh);
        }
        emit_store_rm(e, insn, SCR_RES, width);
        emit_lazy(e, I686_FOP_NEG, SCR_RES, SCR_A, 31U, width);
        /* SUBS wzr-derived image is live in NZCV (natural polarity). */
        e->flags_src =
            (e->skip_lazy != 0U) ? I686_FLAGS_DEAD : I686_FLAGS_NZCV;
    } else {
        a64_emit_orn_reg_w(b, SCR_RES, 31U, SCR_A, A64_SHIFT_LSL, 0U); /* mvn */
        if (sh != 0U) {
            emit_lsr_imm_w(b, SCR_RES, SCR_RES, sh);
        }
        emit_store_rm(e, insn, SCR_RES, width);
        /* NOT sets no flags: descriptor, eflags and the previous
         * flags_src proof all stay untouched. */
    }
    e->insn_count++;
    return 0;
}

/* ---- IMUL two/three-operand forms ------------------------------------ */

static int emit_imul(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->pfx_opsize != 0U ? 16U : 32U;
    int three = insn->op == I686_OP_IMUL_GvEvIz ||
                insn->op == I686_OP_IMUL_GvEvIb;
    uint32_t imm = 0U;

    emit_load_rm(e, insn, SCR_B, width); /* B = r/m source */
    if (width != 32U) {
        a64_emit_sbfm_w(b, SCR_B, SCR_B, 0U, width - 1U); /* sext(B) */
    }
    if (three == 0) {
        emit_load_reg(b, SCR_A, insn->modrm_reg, width);
        if (width != 32U) {
            a64_emit_sbfm_w(b, SCR_A, SCR_A, 0U, width - 1U);
        }
        a64_emit_smaddl_x(b, SCR_T0, SCR_A, SCR_B, 31U); /* x11 = a*b */
    } else {
        imm = insn->imm;
        if (insn->op == I686_OP_IMUL_GvEvIb) {
            imm = sext_imm8(imm);
        }
        if (width == 16U) {
            imm &= 0xFFFFU;
        }
        a64_emit_mov_imm32(b, SCR_T2, imm);
        if (width != 32U) {
            a64_emit_sbfm_w(b, SCR_T2, SCR_T2, 0U, width - 1U);
        }
        a64_emit_smaddl_x(b, SCR_T0, SCR_B, SCR_T2, 31U); /* x11 = b*imm */
    }

    /* Overflow: 64-bit product != sign-extension of its low width bits. */
    emit_sbfx_x(b, SCR_T1, SCR_T0, 0U, width); /* x12 = sext_w(x11) */
    emit_subs_x(b, SCR_T0, SCR_T1);
    emit_cset_w(b, SCR_T3, A64_COND_NE);

    if (width == 32U) {
        a64_emit_mov_w(b, i686_w(insn->modrm_reg), SCR_T0);
    } else {
        emit_bfi_w(b, i686_w(insn->modrm_reg), SCR_T0, 0U, width);
    }

    /* Flags exactly like h_muldiv md_set_cf_of: CF = OF = overflow, all
     * other bits architecturally undefined and left stale in eflags. */
    a64_emit_ldr_imm_w(b, SCR_T0, 19U, 36U);
    a64_emit_movz_w(b, SCR_T1, 0x0801U, 0U); /* CF | OF */
    a64_emit_bic_reg_w(b, false, SCR_T0, SCR_T0, SCR_T1, A64_SHIFT_LSL, 0U);
    emit_lsl_imm_w(b, SCR_T4, SCR_T3, 11U); /* OF bit position */
    a64_emit_orr_reg_w(b, SCR_T3, SCR_T3, SCR_T4, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, SCR_T0, SCR_T0, SCR_T3, A64_SHIFT_LSL, 0U);
    a64_emit_str_imm_w(b, SCR_T0, 19U, 36U);
    a64_emit_str_imm_w(b, 31U, 19U, 76U); /* lazy_op = NONE */
    /* Eager-eflags producer: ctx->eflags is current (lazy_op NONE) but
     * NZCV holds the internal overflow compare -> rebuild path only. */
    e->flags_src = I686_FLAGS_EFLAGS;

    e->insn_count++;
    return 0;
}

/* ---- SHL/SHR/SAR by immediate (register forms) ----------------------- */

enum { SHK_SHL, SHK_SHR, SHK_SAR };

static int emit_shift_imm(i686_emit_ctx_t *e, const x86_insn_t *insn,
                          unsigned kind)
{
    a64_buf_t *b = &e->buf;
    unsigned width = insn->opnd[0] == I686_OPND_RM8
                         ? 8U
                         : (insn->pfx_opsize != 0U ? 16U : 32U);
    unsigned msb = width - 1U;
    uint32_t cnt;
    int is_mem = insn->modrm_mod != 3U && insn->ea_has != 0U;

    if (is_mem != 0 && insn->pfx_lock != 0U) {
        /* LOCKed memory: the interpreter's atomic path (lane atomic
         * module does not cover shifts). */
        return -1;
    }
    if (insn->opnd[1] == I686_OPND_ONE) {
        cnt = 1U;
    } else {
        cnt = insn->imm & 0xFFU; /* CL forms live in emit_alu_ext.c */
    }
    cnt &= 31U;                  /* i386 5-bit count mask */
    if (cnt == 0U) {
        e->insn_count++;         /* full no-op: no write, no flags
                                  * (previous flags_src proof stands) */
        return 0;
    }

    emit_load_rm(e, insn, SCR_A, width);

    if (kind == SHK_SHL) {
        emit_lsl_imm_w(b, SCR_RES, SCR_A, cnt);
        if (width != 32U) {
            emit_and_imm_w(b, SCR_RES, SCR_RES,
                           width == 8U ? 0xFFU : 0xFFFFU);
        }
    } else if (kind == SHK_SHR) {
        emit_lsr_imm_w(b, SCR_RES, SCR_A, cnt);
    } else { /* SAR: sign-extend first for sub-32 widths */
        if (width == 32U) {
            a64_emit_sbfm_w(b, SCR_RES, SCR_A, cnt, 31U);
        } else {
            a64_emit_sbfm_w(b, SCR_T1, SCR_A, 0U, msb);
            a64_emit_sbfm_w(b, SCR_RES, SCR_T1, cnt, 31U);
            emit_and_imm_w(b, SCR_RES, SCR_RES,
                           width == 8U ? 0xFFU : 0xFFFFU);
        }
    }

    /* Eager flags, exactly h_shift.c + i686_flags_logiczx: clear
     * CF PF AF ZF SF OF, then set Z/S/P from the result, CF from the last
     * bit shifted out, OF only when cnt == 1 (SHL: CF^MSB(res), SHR:
     * MSB(operand), SAR: 0).  Skipped when the pre-scan proved a later
     * full writer overwrites the flags first (JONLY producers are never
     * skipped themselves, so this arm is normally untaken).
     *
     * R7-15: the faultable store commits before flags publish — a
     * faulting store leaves the pre-instruction flags intact for the
     * retry (the store touches only w21/SCR_RES, so the flag scratch
     * registers below stay live across it). */
    emit_store_rm(e, insn, SCR_RES, width);
    if (e->skip_lazy == 0U) {
        a64_emit_ldr_imm_w(b, SCR_T0, 19U, 36U);
        a64_emit_movz_w(b, SCR_T1, 0x08D5U, 0U); /* CF|PF|AF|ZF|SF|OF */
        a64_emit_bic_reg_w(b, false, SCR_T0, SCR_T0, SCR_T1, A64_SHIFT_LSL, 0U);

        a64_emit_sub_imm_w(b, true, 31U, SCR_RES, 0U, 0U); /* cmp res, #0 */
        emit_cset_w(b, SCR_T2, A64_COND_EQ);               /* ZF */
        emit_bfi_w(b, SCR_T0, SCR_T2, 6U, 1U);

        a64_emit_ubfm_w(b, SCR_T2, SCR_RES, msb, msb);     /* SF */
        emit_bfi_w(b, SCR_T0, SCR_T2, 7U, 1U);

        emit_and_imm_w(b, SCR_T3, SCR_RES, 0xFFU);         /* PF: even parity */
        a64_emit_eor_reg_w(b, SCR_T3, SCR_T3, SCR_T3, A64_SHIFT_LSR, 4U);
        a64_emit_eor_reg_w(b, SCR_T3, SCR_T3, SCR_T3, A64_SHIFT_LSR, 2U);
        a64_emit_eor_reg_w(b, SCR_T3, SCR_T3, SCR_T3, A64_SHIFT_LSR, 1U);
        a64_emit_ubfm_w(b, SCR_T3, SCR_T3, 0U, 0U);        /* odd parity bit */
        emit_eor_imm1_w(b, SCR_T4, SCR_T3);                /* -> even parity */
        emit_bfi_w(b, SCR_T0, SCR_T4, 2U, 1U);

        if (kind == SHK_SHL) {
            if (cnt <= width) {
                a64_emit_ubfm_w(b, SCR_T3, SCR_A, width - cnt, width - cnt);
                emit_bfi_w(b, SCR_T0, SCR_T3, 0U, 1U); /* CF */
            } /* cnt > width: CF stays 0 */
        } else if (kind == SHK_SHR) {
            a64_emit_ubfm_w(b, SCR_T3, SCR_A, cnt - 1U, cnt - 1U);
            emit_bfi_w(b, SCR_T0, SCR_T3, 0U, 1U);
        } else {
            unsigned bit = (cnt <= width) ? cnt - 1U : msb;
            a64_emit_ubfm_w(b, SCR_T3, SCR_A, bit, bit);
            emit_bfi_w(b, SCR_T0, SCR_T3, 0U, 1U);
        }

        if (cnt == 1U) {
            if (kind == SHK_SHL) {
                /* OF = CF ^ MSB(result): w13 = MSB(res), w14 = CF. */
                a64_emit_eor_reg_w(b, SCR_T4, SCR_T2, SCR_T3, A64_SHIFT_LSL, 0U);
                emit_bfi_w(b, SCR_T0, SCR_T4, 11U, 1U);
            } else if (kind == SHK_SHR) {
                a64_emit_ubfm_w(b, SCR_T4, SCR_A, msb, msb); /* MSB(operand) */
                emit_bfi_w(b, SCR_T0, SCR_T4, 11U, 1U);
            } /* SAR count 1: OF = 0, already cleared */
        }

        a64_emit_str_imm_w(b, SCR_T0, 19U, 36U);
        a64_emit_str_imm_w(b, 31U, 19U, 76U); /* lazy_op = NONE */
        /* Eager-eflags producer (h_shift.c shape): ctx->eflags current,
         * NZCV holds the internal `cmp res, #0` -> rebuild path only. */
        e->flags_src = I686_FLAGS_EFLAGS;
    } else {
        e->flags_src = I686_FLAGS_DEAD;
    }

    e->insn_count++;
    return 0;
}

/* ---- dispatcher ------------------------------------------------------ */

int i686_emit_alu(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    switch (insn->op) {
/* Nine frozen forms per binary mnemonic (insn_tab.h). */
#define ALU9(mn, K)                                                          \
    case I686_OP_##mn##_EbGb: return emit_binop(e, insn, (K), FRM_EbGb);     \
    case I686_OP_##mn##_EvGv: return emit_binop(e, insn, (K), FRM_EvGv);     \
    case I686_OP_##mn##_GbEb: return emit_binop(e, insn, (K), FRM_GbEb);     \
    case I686_OP_##mn##_GvEv: return emit_binop(e, insn, (K), FRM_GvEv);     \
    case I686_OP_##mn##_ALIb: return emit_binop(e, insn, (K), FRM_ALIb);     \
    case I686_OP_##mn##_eAXIz: return emit_binop(e, insn, (K), FRM_eAXIz);   \
    case I686_OP_##mn##_EbIb: return emit_binop(e, insn, (K), FRM_EbIb);     \
    case I686_OP_##mn##_EvIz: return emit_binop(e, insn, (K), FRM_EvIz);     \
    case I686_OP_##mn##_EvIbSX: return emit_binop(e, insn, (K), FRM_EvIbSX)

        ALU9(ADD, ALUK_ADD);
        ALU9(SUB, ALUK_SUB);
        ALU9(CMP, ALUK_CMP);
        ALU9(AND, ALUK_AND);
        ALU9(OR, ALUK_OR);
        ALU9(XOR, ALUK_XOR);
#undef ALU9

    case I686_OP_TEST_EbGb: return emit_binop(e, insn, ALUK_TEST, FRM_EbGb);
    case I686_OP_TEST_EvGv: return emit_binop(e, insn, ALUK_TEST, FRM_EvGv);
    case I686_OP_TEST_ALIb: return emit_binop(e, insn, ALUK_TEST, FRM_ALIb);
    case I686_OP_TEST_eAXIz: return emit_binop(e, insn, ALUK_TEST, FRM_eAXIz);
    case I686_OP_TEST_EbIb: return emit_binop(e, insn, ALUK_TEST, FRM_EbIb);
    case I686_OP_TEST_EvIz: return emit_binop(e, insn, ALUK_TEST, FRM_EvIz);

    case I686_OP_NOT_Eb:
    case I686_OP_NOT_Ev:
        return emit_negnot(e, insn, 0);
    case I686_OP_NEG_Eb:
    case I686_OP_NEG_Ev:
        return emit_negnot(e, insn, 1);

    case I686_OP_IMUL_GvEv:
    case I686_OP_IMUL_GvEvIz:
    case I686_OP_IMUL_GvEvIb:
        return emit_imul(e, insn);

    case I686_OP_SHL_Eb1:
    case I686_OP_SHL_Ev1:
    case I686_OP_SHL_EbIb:
    case I686_OP_SHL_EvIb:
        return emit_shift_imm(e, insn, SHK_SHL);
    case I686_OP_SHR_Eb1:
    case I686_OP_SHR_Ev1:
    case I686_OP_SHR_EbIb:
    case I686_OP_SHR_EvIb:
        return emit_shift_imm(e, insn, SHK_SHR);
    case I686_OP_SAR_Eb1:
    case I686_OP_SAR_Ev1:
    case I686_OP_SAR_EbIb:
    case I686_OP_SAR_EvIb:
        return emit_shift_imm(e, insn, SHK_SAR);

    default: {
        /* Lane P3 (Wave P): ROL/ROR, INC/DEC, CL-shifts, one-operand
         * MUL/IMUL/DIV/IDIV, ADC/SBB and SHLD/SHRD live in
         * emit_alu_ext.c; RCL/RCR still decline (D2-safe). */
        extern int i686_emit_alu_ext(i686_emit_ctx_t *,
                                     const x86_insn_t *);
        return i686_emit_alu_ext(e, insn);
    }
    }
}
