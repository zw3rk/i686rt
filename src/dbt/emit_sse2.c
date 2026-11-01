/*
 * src/dbt/emit_sse2.c — SSE2 compare/convert/misc DBT emitters (Phase 5 lane L5a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Second half of the Lane P13-6 split of src/dbt/emit_sse.c (see
 * emit_sse.c for the move/logic/arithmetic rows and the entry point).
 * Shares emit_sse_shared.h (raw encoders, ctx staging, and the
 * write-through XMM cache mapping xmm0..xmm7 onto v16..v23).
 *
 * Emitted forms (row id + prefixes; reg-reg and memory where x86
 * defines them):
 *   COMISS/COMISD/UCOMISS/UCOMISD (FCMP; ZF=Z, PF=V, CF=!C|V, clear
 *     OF/SF/AF, lazy_op = NONE)
 *   MOVMSKPS/PD (0F 50, SSHR+UMOV sign-bit extraction)
 *   CVTPI2PS/PD, CVTSI2SS/SD (SCVTF; 2S->2D via SSHLL#0 + SCVTF),
 *     CVTTPS2PI, CVTTSS2SI/CVTTSD2SI (FCVTZS), CVTTPD2PI (FCVTZS.2D
 *     + XTN), CVTPS2PD (FCVTL), CVTPD2PS (FCVTN + zero upper),
 *     CVTSS2SD/CVTSD2SS (FCVT), CVTDQ2PS (SCVTF), CVTPS2DQ (FCVTNS),
 *     CVTTPS2DQ (FCVTZS)
 *   LDMXCSR/STMXCSR (0F AE /2 /3, m32, reserved bits masked on load),
 *     SFENCE lives in emit_sse.c
 *   MOVDQA/MOVDQU (66/F3 0F 6F load / 0F 7F store as plain Q moves),
 *     MOVQ2DQ (66/F3/F2 0F D6), MOVNTDQ (66 0F E7 as plain Q store),
 *     PSRLDQ/PSLLDQ (66 0F 73 /3 /7 via EXT against a zero temp),
 *     PCMPGTB/PCMPEQB/PCMPEQD (66 0F 64/74/76), PMOVMSKB (66 0F D7),
 *     PMINUB/PMAXUB (66 0F DA/DE), PSUBB (66 0F F8),
 *     PREFETCHh (0F 18) = no-op
 *
 * Scalar reads copy only the low lane from the cached slot (only lane 0
 * is consumed below; verified per call site). Full dest overwrites
 * (CVTPD2PS, CVTDQ2PS-class) skip the dst preimage load and write the
 * computed scratch register through. The declined encodings, v1
 * deviations and scratch map are documented in emit_sse.c and
 * emit_sse_shared.h.
 */

#include <stdint.h>

#include "dbt/emit_sse_shared.h"

/* COMISS/COMISD/UCOMISS/UCOMISD: FCMP + eflags {ZF=Z, PF=V,
 * CF=!C|V}, OF/SF/AF cleared, other bits kept, lazy_op = NONE.
 *
 * C6a seam: the park/blr/reload dance in sse_flags_sync is only
 * needed on the DEAD path (no proof).  On NZCV/EFLAGS the kept
 * ctx->eflags bits (everything outside CF|PF|AF|ZF|SF|OF) are current
 * and the six cleared bits are exactly the bits a pending lazy
 * materialize would write, so skipping the helper call is
 * architecturally identical — comis overwrites all six either way. */
static int sse_emit_comis(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned dbl;

    if (insn->pfx_rep != 0U) {
        return -1;
    }
    dbl = (insn->pfx_opsize != 0U) ? 1U : 0U;

    /* Frozen flags_src switch (emit.h): NZCV counts the elision,
     * EFLAGS falls through silently, DEAD runs the full sync.  The
     * helper call clobbers the caller-saved scratch, so EA + operands
     * load after it (the bump clobbers x11 only, fine before them). */
    switch (e->flags_src) {
    case I686_FLAGS_NZCV: {
        extern void i686_dbt_emit_elide_bump(i686_emit_ctx_t *);
        i686_dbt_emit_elide_bump(e);
        break;
    }
    case I686_FLAGS_EFLAGS:
        break;
    default: /* I686_FLAGS_DEAD: conservative full sequence */
        sse_flags_sync(e);
        break;
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (dbl != 0U) {
        if (insn->modrm_mod == 3U) {
            sse_d_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        }
        sse_fcmp_d(b, 0U, 1U);
    } else {
        if (insn->modrm_mod == 3U) {
            sse_s_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_s(b, 1U, SSE_ADDR, 0U);
        }
        sse_fcmp_s(b, 0U, 1U);
    }

    /* A64 FCMP: less N=1; greater NZCV=0010; equal 0110; unordered
     * 0011 (Z=0, C=1, V=1).  x86 COMIS*: ZF = Z | V (unordered sets
     * ZF), PF = V, CF = !C | V; OF/SF/AF cleared; the remaining bits
     * (DF/IF/...) keep their ctx->eflags value. */
    a64_emit_mrs_nzcv(b, SSE_W8);
    a64_emit_ubfm_w(b, SSE_W9, SSE_W8, 30U, 30U);  /* Z            */
    a64_emit_ubfm_w(b, SSE_W10, SSE_W8, 28U, 28U); /* V            */
    a64_emit_ubfm_w(b, SSE_W11, SSE_W8, 29U, 29U); /* C            */
    sse_eor_w11_1(b);                               /* !C           */
    a64_emit_orr_reg_w(b, SSE_W11, SSE_W11, SSE_W10, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, SSE_W9, SSE_W9, SSE_W10, A64_SHIFT_LSL, 0U);
    a64_emit_ubfm_w(b, SSE_W9, SSE_W9, 26U, 25U);  /* ZF <<= 6     */
    a64_emit_ubfm_w(b, SSE_W10, SSE_W10, 30U, 29U);/* PF <<= 2     */
    a64_emit_mov_imm32(b, SSE_W12, 0x8D5U); /* BIC clears CF|PF|AF|ZF|SF|OF */
    a64_emit_ldr_imm_w(b, SSE_W13, A64_XCTX, 36U); /* old eflags   */
    a64_emit_bic_reg_w(b, false, SSE_W13, SSE_W13, SSE_W12, A64_SHIFT_LSL,
                       0U);
    a64_emit_orr_reg_w(b, SSE_W13, SSE_W13, SSE_W9, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, SSE_W13, SSE_W13, SSE_W10, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, SSE_W13, SSE_W13, SSE_W11, A64_SHIFT_LSL, 0U);
    a64_emit_str_imm_w(b, SSE_W13, A64_XCTX, 36U);
    a64_emit_str_imm_w(b, 31U, A64_XCTX, 76U); /* lazy_op = NONE */
    /* Eager-eflags producer now: NZCV holds the raw FCMP image (not
     * the x86-natural polarity), so a following consumer must take the
     * rebuild path, not the fused one. */
    e->flags_src = I686_FLAGS_EFLAGS;
    return 0;
}

/* CVTPI2PS/CVTSI2SS/CVTSI2SD/CVTPI2PD (0F 2A). */
static int sse_emit_cvtpi2(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_rep == 1U) { /* CVTSI2SS: s0 = (f32)i32, upper kept */
        if (insn->modrm_mod == 3U) {
            a64_emit_mov_w(b, SSE_W8, i686_w(insn->modrm_rm));
        } else {
            sse_guest_addr(e, insn);
            a64_emit_ldr_imm_w(b, SSE_W8, SSE_ADDR, 0U);
        }
        sse_scvtf_s_w(b, 2U, SSE_W8);
        sse_s_str(e, insn->modrm_reg & 7U, 2U);
        return 0;
    }
    if (insn->pfx_rep == 2U) { /* CVTSI2SD */
        if (insn->modrm_mod == 3U) {
            a64_emit_mov_w(b, SSE_W8, i686_w(insn->modrm_rm));
        } else {
            sse_guest_addr(e, insn);
            a64_emit_ldr_imm_w(b, SSE_W8, SSE_ADDR, 0U);
        }
        sse_scvtf_d_w(b, 2U, SSE_W8);
        sse_d_str(e, insn->modrm_reg & 7U, 2U);
        return 0;
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (insn->pfx_opsize == 0U) { /* CVTPI2PS: 2 x s32 -> 2 f32 */
        sse_mmx_file(e);
        sse_src_d_mmx(e, insn);
        sse_scvtf_2s(b, 2U, 1U);
        sse_ins_s_elt(b, 0U, 0U, 2U, 0U);
        sse_ins_s_elt(b, 0U, 1U, 2U, 1U);
    } else { /* CVTPI2PD: 2 x s32 -> 2 f64 via SSHLL#0 + SCVTF */
        sse_mmx_file(e);
        sse_src_d_mmx(e, insn);
        sse_sshll_2d_0(b, 2U, 1U);
        sse_scvtf_2d(b, 2U, 2U);
        sse_ins_d_elt(b, 0U, 0U, 2U, 0U);
        sse_ins_d_elt(b, 0U, 1U, 2U, 1U);
    }
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* CVTTPS2PI/CVTTSS2SI/CVTTSD2SI/CVTTPD2PI (0F 2C).
 *
 * Scalar range guards: x86 converts NaN and out-of-range sources to
 * the integer-indefinite 0x80000000 (+IE), while A64 FCVTZS saturates
 * (INT32_MAX / INT32_MIN / 0).  Sources outside [-2^31, 2^31) (NaN
 * included) take the D2 interpret-one path, which produces the exact
 * x86 result and flags; in-range sources convert natively.  The CMPs
 * bracket with an NZCV save/restore so pending lazy flags survive. */
static int sse_emit_cvttpi(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_rep == 1U) { /* CVTTSS2SI r32, m32/xmm */
        unsigned dst = i686_w(insn->modrm_reg);
        size_t to_pos, to_interp, to_valid, to_done;

        if (insn->modrm_mod == 3U) {
            sse_s_ldr(e, 1U, insn->modrm_rm & 7U);
            sse_fmov_w_from_s(b, SSE_W8, 1U); /* source bits */
        } else {
            sse_guest_addr(e, insn);
            a64_emit_ldr_imm_w(b, SSE_W8, SSE_ADDR, 0U); /* bits */
            sse_ldr_s(b, 1U, SSE_ADDR, 0U);              /* value */
        }
        a64_emit_mrs_nzcv(b, SSE_W10);
        /* sign -> bit 0; nonzero (negative) skips the +2^31 bound. */
        a64_emit_ubfm_w(b, SSE_W9, SSE_W8, 31U, 31U);
        to_pos = a64_emit_cbz_w_placeholder(b, false, SSE_W9);
        /* Negative: invalid iff bits > 0xCF000000 (-2^31 is valid). */
        a64_emit_movz_w(b, SSE_W9, 0xCF00U, 1U);
        a64_emit_sub_reg_w(b, true, 31U, SSE_W8, SSE_W9, A64_SHIFT_LSL, 0U);
        to_interp = a64_emit_b_cond_placeholder(b, A64_COND_HI);
        to_valid = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_cbz_w(b, to_pos, b->count);
        /* Non-negative: invalid iff bits >= 0x4F000000 (+2^31, Inf, NaN). */
        a64_emit_movz_w(b, SSE_W9, 0x4F00U, 1U);
        a64_emit_sub_reg_w(b, true, 31U, SSE_W8, SSE_W9, A64_SHIFT_LSL, 0U);
        a64_patch_b_cond(b, to_interp, b->count);
        to_interp = a64_emit_b_cond_placeholder(b, A64_COND_CS);
        a64_patch_b_cond(b, to_valid, b->count);
        a64_emit_msr_nzcv(b, SSE_W10);
        sse_fcvtzs_w_s(b, dst, 1U);
        to_done = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_b_cond(b, to_interp, b->count);
        a64_emit_msr_nzcv(b, SSE_W10);
        i686_emit_exit(e, I686_EXIT_UNDEF, insn->len, e->insn_pc);
        a64_patch_b_cond(b, to_done, b->count);
        e->block_open = true; /* guard exit closed it; NEON path inlines */
        return 0;
    }
    if (insn->pfx_rep == 2U) { /* CVTTSD2SI r32, m64/xmm */
        unsigned dst = i686_w(insn->modrm_reg);
        size_t to_pos, to_interp, to_valid, to_done, to_interp_lo, to_valid_lo;

        if (insn->modrm_mod == 3U) {
            sse_d_ldr(e, 1U, insn->modrm_rm & 7U);
            sse_umov_d(b, 8U, 1U, 0U); /* full 64-bit source bits */
            a64_emit_ubfx_x_to_w(b, SSE_W9, 8U, 32U, 32U); /* high word */
            a64_emit_mov_w(b, SSE_W10, SSE_W8);            /* low word */
        } else {
            sse_guest_addr(e, insn);
            a64_emit_ldr_imm_w(b, SSE_W8, SSE_ADDR, 0U);  /* low word */
            a64_emit_ldr_imm_w(b, SSE_W9, SSE_ADDR, 4U);  /* high word */
            a64_emit_mov_w(b, SSE_W10, SSE_W8);           /* low copy */
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);               /* value */
        }
        a64_emit_mrs_nzcv(b, 12U);
        /* sign (high bit 31 of the high word) -> bit 0. */
        a64_emit_ubfm_w(b, 11U, SSE_W9, 31U, 31U);
        to_pos = a64_emit_cbz_w_placeholder(b, false, 11U);
        /* Negative: invalid iff high > 0xC1E00000, or equal with low != 0
         * (-2^31 exactly, low == 0, is the one valid boundary value). */
        a64_emit_movz_w(b, 13U, 0xC1E0U, 1U);
        a64_emit_sub_reg_w(b, true, 31U, SSE_W9, 13U, A64_SHIFT_LSL, 0U);
        to_interp = a64_emit_b_cond_placeholder(b, A64_COND_HI);
        to_valid = a64_emit_b_cond_placeholder(b, A64_COND_NE);
        to_interp_lo = a64_emit_cbz_w_placeholder(b, true, SSE_W10);
        to_valid_lo = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_cbz_w(b, to_pos, b->count);
        /* Non-negative: invalid iff high >= 0x41E00000 (+2^31, Inf, NaN). */
        a64_emit_movz_w(b, 13U, 0x41E0U, 1U);
        a64_emit_sub_reg_w(b, true, 31U, SSE_W9, 13U, A64_SHIFT_LSL, 0U);
        a64_patch_b_cond(b, to_interp, b->count);
        a64_patch_cbz_w(b, to_interp_lo, b->count);
        to_interp = a64_emit_b_cond_placeholder(b, A64_COND_CS);
        a64_patch_b_cond(b, to_valid, b->count);
        a64_patch_b_cond(b, to_valid_lo, b->count);
        a64_emit_msr_nzcv(b, 12U);
        sse_fcvtzs_w_d(b, dst, 1U);
        to_done = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_b_cond(b, to_interp, b->count);
        a64_emit_msr_nzcv(b, 12U);
        i686_emit_exit(e, I686_EXIT_UNDEF, insn->len, e->insn_pc);
        a64_patch_b_cond(b, to_done, b->count);
        /* (the earlier AL placeholder targeted here as well) */
        e->block_open = true; /* guard exit closed it; NEON path inlines */
        return 0;
    }
    /* CVTTPS2PI mm, xmm/m64 (plain, MMX dest) and CVTTPD2PI (66, m128/
     * xmm src); MMX dest: tags -> valid. */
    if (insn->modrm_mod == 3U) {
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        if (insn->pfx_opsize != 0U) {
            sse_ldr_q(b, 1U, SSE_ADDR, 0U); /* CVTTPD2PI reads m128 */
        } else {
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        }
    }
    if (insn->pfx_opsize != 0U) {
        sse_fcvtzs_2d(b, 2U, 1U); /* 2 x f64 -> 2 x s64 */
        sse_xtn_2s(b, 2U, 2U);    /* narrow: low 64 of v2 = 2 x s32 */
        sse_mmx_file(e);
        sse_str_d(b, 2U, SSE_MMX_BASE, 2U * (insn->modrm_reg & 7U));
        sse_mmx_tags_valid(e);
        return 0;
    }
    sse_fcvtzs_2s(b, 0U, 1U);
    sse_mmx_file(e);
    sse_str_d(b, 0U, SSE_MMX_BASE, 2U * (insn->modrm_reg & 7U));
    sse_mmx_tags_valid(e);
    return 0;
}

/* CVTPS2PD/CVTSS2SD/CVTSD2SS/CVTPD2PS (0F 5A). CVTPS2PD and CVTPD2PS
 * fully overwrite the dest, so they skip the dst preimage load and
 * write the computed scratch register through. */
static int sse_emit_cvt_5a(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_rep == 0U && insn->pfx_opsize == 0U) {
        /* CVTPS2PD: dest.2d = (double)src.s[0..1] */
        if (insn->modrm_mod == 3U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        }
        sse_fcvtl_2d(b, 0U, 1U);
        sse_q_str(e, insn->modrm_reg & 7U, 0U);
    } else if (insn->pfx_rep == 0U) {
        /* CVTPD2PS: dest.s[0..1] = (float)src.d[0..1]; bits 127:64 = 0 */
        if (insn->modrm_mod == 3U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_q(b, 1U, SSE_ADDR, 0U);
        }
        sse_fcvtn_2s(b, 2U, 1U);
        sse_ins_s_elt(b, 0U, 0U, 2U, 0U);
        sse_ins_s_elt(b, 0U, 1U, 2U, 1U);
        sse_ins_d_gpr(b, 0U, 1U, 31U);
        sse_q_str(e, insn->modrm_reg & 7U, 0U);
    } else if (insn->pfx_rep == 1U) { /* CVTSS2SD */
        if (insn->modrm_mod == 3U) {
            sse_s_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_s(b, 1U, SSE_ADDR, 0U);
        }
        sse_fcvt_d_s(b, 2U, 1U);
        sse_d_str(e, insn->modrm_reg & 7U, 2U);
    } else { /* CVTSD2SS */
        if (insn->modrm_mod == 3U) {
            sse_d_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        }
        sse_fcvt_s_d(b, 2U, 1U);
        sse_s_str(e, insn->modrm_reg & 7U, 2U);
    }
    return 0;
}

/* CVTDQ2PS/CVTPS2DQ/CVTTPS2DQ (0F 5B): full-width overwrites of the
 * dest from the src (no dest preimage needed). */
static int sse_emit_cvt_5b(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_rep == 2U) {
        return -1; /* F2 5B = CVTPD2DQ (unlisted) */
    }
    if (insn->modrm_mod == 3U) {
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_q(b, 1U, SSE_ADDR, 0U);
    }
    if (insn->pfx_rep == 1U) {
        sse_fcvtzs_4s(b, 0U, 1U); /* CVTTPS2DQ (truncate) */
    } else if (insn->pfx_opsize != 0U) {
        sse_fcvtns_4s(b, 0U, 1U); /* CVTPS2DQ (nearest-even, v1) */
    } else {
        sse_scvtf_4s(b, 0U, 1U); /* CVTDQ2PS */
    }
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* LDMXCSR/STMXCSR (0F AE /2 /3, m32). */
static int sse_emit_mxcsr(i686_emit_ctx_t *e, const x86_insn_t *insn,
                          unsigned store)
{
    a64_buf_t *b = &e->buf;

    if (insn->modrm_mod == 3U) {
        return -1; /* reg form is x86 #UD */
    }
    sse_guest_addr(e, insn);
    if (store != 0U) { /* STMXCSR: m32 <- ctx->mxcsr */
        a64_emit_ldr_imm_w(b, SSE_W8, A64_XCTX, 0x198U);
        a64_emit_str_imm_w(b, SSE_W8, SSE_ADDR, 0U);
    } else { /* LDMXCSR: m32 -> ctx->mxcsr (reserved bits masked) */
        a64_emit_ldr_imm_w(b, SSE_W8, SSE_ADDR, 0U);
        sse_and_ffff(b, SSE_W8, SSE_W8);
        a64_emit_str_imm_w(b, SSE_W8, A64_XCTX, 0x198U);
    }
    return 0;
}

/* ---- RC7b T1 emitters (docs/lanes/phase-7.md) ----------------------- */

/* MOVDQA/MOVDQU rows (0F 6F load / 0F 7F store, one id): 66/F3 = full
 * 128-bit move (plain Q LDR/STR; the alignment check is interpreter-
 * only, same class as the documented v1 MOVAPS deviation).  Plain
 * (MMX MOVQ) and F2 decline to the D2 oracle. */
static int sse_emit_movdqa(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    int load = (insn->opnd[0] == I686_OPND_R32);

    if (insn->pfx_rep == 2U || insn->pfx_opsize == 0U) {
        return -1;
    }
    if (load) {
        if (insn->modrm_mod == 3U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_q(b, 1U, SSE_ADDR, 0U);
        }
        sse_q_str(e, insn->modrm_reg & 7U, 1U);
    } else {
        sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
        if (insn->modrm_mod == 3U) {
            sse_q_str(e, insn->modrm_rm & 7U, 0U);
        } else {
            sse_guest_addr(e, insn);
            sse_str_q(b, 0U, SSE_ADDR, 0U);
        }
    }
    return 0;
}

/* MOVQ2DQ row (0F D6): 66 = MOVQ m64/xmm-low64 <- xmm.d0 (reg-reg keeps
 * the dest upper), F3 = MOVQ2DQ xmm <- mm (upper zeroed), F2 =
 * MOVDQ2Q mm <- xmm.d0 (reg-only, MMX dest + tags).  Plain D6 (m64
 * form of the F2/F3 family) declines. */
static int sse_emit_movq2dq(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_rep == 2U) { /* F2 MOVDQ2Q mm, xmm */
        if (insn->modrm_mod != 3U) {
            return -1; /* memory form is x86 #UD */
        }
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        sse_mmx_file(e);
        sse_str_d(b, 1U, SSE_MMX_BASE, 2U * (insn->modrm_reg & 7U));
        sse_mmx_tags_valid(e);
        return 0;
    }
    if (insn->pfx_rep == 1U) { /* F3 MOVQ2DQ xmm, mm */
        if (insn->modrm_mod != 3U) {
            return -1; /* mm-only source */
        }
        sse_mmx_file(e);
        sse_ldr_d(b, 1U, SSE_MMX_BASE, 2U * (insn->modrm_rm & 7U));
        sse_zero_d_str(e, insn->modrm_reg & 7U, 1U);
        return 0;
    }
    if (insn->pfx_opsize == 0U) {
        return -1; /* plain 0F D6 undefined x86 */
    }
    /* 66: MOVQ m64 <- xmm.d0.  Register destination: legacy MOVQ
     * CLEARS bits 127:64 of the dest (RC7b T2, oracle-verified). */
    sse_q_ldr(e, 1U, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_zero_d_str(e, insn->modrm_rm & 7U, 1U);
    } else {
        sse_guest_addr(e, insn);
        sse_str_d(b, 1U, SSE_ADDR, 0U);
    }
    return 0;
}

/* MOVNTDQ row (0F E7): 66 = m128 <- xmm NT store, emitted as a plain Q
 * store (single-threaded TSO; alignment check is interpreter-only).
 * Plain MOVNTQ (MMX), the register form, and F2/F3 decline. */
static int sse_emit_movntdq(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U ||
        insn->modrm_mod == 3U) {
        return -1;
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    sse_guest_addr(e, insn);
    sse_str_q(&e->buf, 0U, SSE_ADDR, 0U);
    return 0;
}

/* PSRLDQ row (0F 73).  RC7b T2 rewrite: the shift-by-imm8 group carries
 * the /digit in modrm_reg and the register operand in modrm_rm (the old
 * code stored the result to the digit-indexed register), and the group
 * map is /3 PSRLDQ, /7 PSLLDQ (whole-register byte shifts via EXT
 * against a zero temp; imm8 >= 16 gives zero, imm8 == 0 is a register
 * move) — /2 PSRLQ and /6 PSLLQ (packed 64-bit bit shifts) decline to
 * the interpreter.  Plain (MMX) and other prefixes decline. */
static int sse_emit_psrldq(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned imm = insn->imm & 0xFFU;
    unsigned dig = insn->modrm_reg;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    if (dig == 3U) { /* PSRLDQ: out[j] = in[j+imm] */
        if (imm == 0U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
            sse_mov_v_v(b, 0U, 1U);
        } else if (imm < 16U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
            sse_movi_v_zero(b, 2U);
            sse_ext_16b(b, 0U, 2U, 1U, 16U - imm);
        } else {
            sse_movi_v_zero(b, 0U);
        }
    } else if (dig == 7U) { /* PSLLDQ: out[j] = in[j-imm] */
        if (imm == 0U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
            sse_mov_v_v(b, 0U, 1U);
        } else if (imm < 16U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
            sse_movi_v_zero(b, 2U);
            sse_ext_16b(b, 0U, 1U, 2U, imm);
        } else {
            sse_movi_v_zero(b, 0U);
        }
    } else {
        return -1; /* /2 /6 packed PSRLQ/PSLLQ and other digits:
                    * interpreter fallback (D2) */
    }
    sse_q_str(e, insn->modrm_rm & 7U, 0U);
    return 0;
}

/* PCMPGTB (64) / PCMPEQB (74) / PCMPEQD (76): 66 forms via CMGT/CMEQ;
 * plain (MMX) and F2/F3 decline. */
static int sse_emit_pcmp(i686_emit_ctx_t *e, const x86_insn_t *insn,
                         unsigned kind)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_q(b, 1U, SSE_ADDR, 0U);
    }
    switch (kind) {
    case 0U: sse_cmgt_16b(b, 0U, 0U, 1U); break; /* PCMPGTB: d > s */
    case 1U: sse_cmeq_16b(b, 0U, 0U, 1U); break; /* PCMPEQB */
    default: sse_cmeq_4s(b, 0U, 0U, 1U); break;  /* PCMPEQD */
    }
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* MOVMSKPS/PD (0F 50): mod=3 required.  SSHR puts each sign bit in a
 * lane; the mask is the WEIGHTED bit assembly (s0 + s1<<1 + ...), not
 * a lane sum, so UMOV each lane and OR the shifted bits in.  (PD has
 * no ADDV.2D anyway.) */
static int sse_emit_movmsk(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->modrm_mod != 3U || insn->pfx_rep != 0U) {
        return -1;
    }
    sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    if (insn->pfx_opsize == 0U) {
        sse_ushr_4s_31(b, 2U, 1U);
        sse_umov_s(b, SSE_W8, 2U, 0U);
        sse_umov_s(b, SSE_W9, 2U, 1U);
        a64_emit_ubfm_w(b, SSE_W9, SSE_W9, 31U, 30U); /* lsl #1 */
        a64_emit_orr_reg_w(b, SSE_W8, SSE_W8, SSE_W9, A64_SHIFT_LSL, 0U);
        sse_umov_s(b, SSE_W9, 2U, 2U);
        a64_emit_ubfm_w(b, SSE_W9, SSE_W9, 30U, 29U); /* lsl #2 */
        a64_emit_orr_reg_w(b, SSE_W8, SSE_W8, SSE_W9, A64_SHIFT_LSL, 0U);
        sse_umov_s(b, SSE_W9, 2U, 3U);
        a64_emit_ubfm_w(b, SSE_W9, SSE_W9, 29U, 28U); /* lsl #3 */
        a64_emit_orr_reg_w(b, SSE_W8, SSE_W8, SSE_W9, A64_SHIFT_LSL, 0U);
    } else {
        sse_ushr_2d_63(b, 2U, 1U);
        sse_umov_d(b, SSE_W8, 2U, 0U);
        sse_umov_d(b, SSE_W9, 2U, 1U);
        a64_emit_ubfm_w(b, SSE_W9, SSE_W9, 31U, 30U); /* lsl #1 */
        a64_emit_orr_reg_w(b, SSE_W8, SSE_W8, SSE_W9, A64_SHIFT_LSL, 0U);
    }
    a64_emit_mov_w(b, i686_w(insn->modrm_reg), SSE_W8);
    return 0;
}

/* PMOVMSKB (0F D7, 66): r32 <- 16 byte sign bits; the mask is the
 * weighted bit assembly (UMOV each byte lane, isolate bit 7, OR at the
 * lane weight — MOVMSKPS pattern).  Plain (MMX) declines. */
static int sse_emit_pmovmskb(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned i;

    if (insn->modrm_mod != 3U || insn->pfx_rep != 0U ||
        insn->pfx_opsize == 0U) {
        return -1;
    }
    sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    a64_emit_movz_w(b, SSE_W9, 0U, 0U); /* acc = 0 */
    for (i = 0U; i < 16U; i++) {
        sse_umov_b(b, SSE_W8, 1U, i);
        a64_emit_ubfm_w(b, SSE_W8, SSE_W8, 7U, 7U); /* bit 7 -> bit 0 */
        a64_emit_orr_reg_w(b, SSE_W9, SSE_W9, SSE_W8, A64_SHIFT_LSL, i);
    }
    a64_emit_mov_w(b, i686_w(insn->modrm_reg), SSE_W9);
    return 0;
}

/* PMINUB (DA) / PMAXUB (DE): 66 forms via UMIN/UMAX; plain (MMX) and
 * F2/F3 decline. */
static int sse_emit_pminmaxub(i686_emit_ctx_t *e, const x86_insn_t *insn,
                              unsigned is_max)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_q(b, 1U, SSE_ADDR, 0U);
    }
    if (is_max != 0U) {
        sse_umax_16b(b, 0U, 0U, 1U);
    } else {
        sse_umin_16b(b, 0U, 0U, 1U);
    }
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* PSUBB (0F F8): 66 form via SUB .16B; plain (MMX) and F2/F3 decline. */
static int sse_emit_psubb(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_q(b, 1U, SSE_ADDR, 0U);
    }
    sse_sub_16b(b, 0U, 0U, 1U);
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* PREFETCHh (0F 18): hint with no architected effect — emit nothing.
 * 66/F2/F3 forms are undefined x86 (decline to the oracle's UNDEF). */
static int sse_emit_prefetch(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    (void)e;
    if (insn->pfx_opsize != 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    return 0;
}

/* ---- entry point (second half; reached from i686_emit_sse) ---------- */

int i686_emit_sse2(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->pfx_lock != 0U) {
        return -1; /* LOCK on an SSE row is invalid x86 */
    }

    switch (insn->op) {
    case I686_OP_MOVDQA:
        return sse_emit_movdqa(e, insn);
    case I686_OP_MOVQ2DQ:
        return sse_emit_movq2dq(e, insn);
    case I686_OP_MOVNTDQ:
        return sse_emit_movntdq(e, insn);
    case I686_OP_PSRLDQ:
        return sse_emit_psrldq(e, insn);
    case I686_OP_PCMPGTB:
        return sse_emit_pcmp(e, insn, 0U);
    case I686_OP_PCMPEQB:
        return sse_emit_pcmp(e, insn, 1U);
    case I686_OP_PCMPEQD:
        return sse_emit_pcmp(e, insn, 2U);
    case I686_OP_MOVMSKPS:
        return sse_emit_movmsk(e, insn);
    case I686_OP_PMOVMSKB:
        return sse_emit_pmovmskb(e, insn);
    case I686_OP_PMINUB:
        return sse_emit_pminmaxub(e, insn, 0U);
    case I686_OP_PMAXUB:
        return sse_emit_pminmaxub(e, insn, 1U);
    case I686_OP_PSUBB:
        return sse_emit_psubb(e, insn);
    case I686_OP_PREFETCH:
        return sse_emit_prefetch(e, insn);
    case I686_OP_CVTPI2PS:
        return sse_emit_cvtpi2(e, insn);
    case I686_OP_CVTTPS2PI:
        return sse_emit_cvttpi(e, insn);
    case I686_OP_COMISS:
    case I686_OP_UCOMISS:
        return sse_emit_comis(e, insn);
    case I686_OP_CVTPS2PD:
        return sse_emit_cvt_5a(e, insn);
    case I686_OP_CVTDQ2PS:
        return sse_emit_cvt_5b(e, insn);
    case I686_OP_LDMXCSR:
        return sse_emit_mxcsr(e, insn, 0U);
    case I686_OP_STMXCSR:
        return sse_emit_mxcsr(e, insn, 1U);
    default:
        return -1;
    }
}
