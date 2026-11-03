/*
 * src/dbt/emit_sse.c — SSE move/logic/arithmetic DBT emitters (Phase 5 lane L5a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * i686_emit_sse handles the NEON-mappable move/logic/arithmetic subset of
 * the Phase 5 opcode rows (docs/lanes/phase-5.md, shared generator spec)
 * 1:1 per SPEC D10. Companion file emit_sse2.c owns the
 * compare/convert/misc rows; both share emit_sse_shared.h (raw encoders,
 * ctx staging, and the Lane P13-6 write-through XMM cache mapping
 * xmm0..xmm7 onto v16..v23).
 *
 * Emitted forms (row id + prefixes; reg-reg and memory where x86
 * defines them):
 *   MOVUPS/MOVAPS (+66 = MOVUPD/MOVAPD; F3/F2 at 0F 10/11 = MOVSS/
 *     MOVSD with the dest upper preserved / low-lane stores)
 *   MOVLPS/MOVHPS rows (0F 12/13/16/17): plain memory forms
 *     (low/high 64-bit lane), MOVHLPS/MOVLHPS register forms, and the
 *     66 variants MOVLPD/MOVHPD (m64 only; 66 reg-reg is invalid x86)
 *   MOVD_xmm load/store (66 0F 6E/7E), MOVQ_xmm (F3 0F 7E load with
 *     upper zeroed)
 *   PUNPCKLBW/LWD/LDQ/HDQ/HBW/HWD/HQDQ/LQDQ (66 0F 60-6D; ZIP1/ZIP2
 *     or INS lane composition)
 *   PSHUFW (0F 70 + imm8, MMX), PSHUFD/PSHUFLW/PSHUFHW (66/F2/F3 0F 70)
 *     via emit-time-constant TBL index vectors
 *   PADDD/PADDQ/PSUBD/PSUBQ/PMULLW/PMULUDQ, PXOR/POR/PAND/PANDN (66)
 *   ANDPS/ANDNPS/ORPS/XORPS (+66 = *PD)
 *   (R7-51: ADD/SUB/MUL/DIV PS/PD/SS/SD declined to D2; see below)
 *   CMPPS/SS/PD/SD imm8 predicates 0..7 (eq/lt/le/unord/neq/nlt/nle/
 *     ord via FCMEQ/FCMGT/FCMGE + AND/MVN; NaN = x86 unord semantics)
 *   MOVMSKPS/PD lives in emit_sse2.c (with PMOVMSKB)
 *
 * Scalar writes into XMM always go through INS into the destination
 * lane so the upper bits stay architecturally preserved regardless of
 * the A64 scalar-write zeroing rules; full-width ops write whole Q.
 * (Cache-preserving forms: sse_d/s_str INS the cached slot, sse_q_str
 * ORRs it; see emit_sse_shared.h.)
 *
 * Declined (return -1 -> D2 interpret-one, per the card): the MMX
 * (unprefixed) integer forms, MOVDDUP/MOVSLDUP/MOVSHDUP, F2 0F 5B
 * (CVTPD2DQ), CMPPS-family predicates imm8 > 7, x86-rejected encodings,
 * LOCK-prefixed anything, FXSAVE/FXRSTOR/XSAVE (ride the D2
 * interpreter), and — R7-51 — ADD/SUB/MUL/DIV PS/PD/SS/SD plus the
 * CVTDQ2PS/CVTPS2DQ/CVTTPS2DQ row (guest rounding/status/result
 * semantics unmet). See the shared header and emit_sse2.c for the rows
 * owned there. Remaining known v1 deviations (CVTTPS2PI/CVTTPD2PI
 * saturation, TSO plain Q stores, MMX tag rules) are documented in
 * emit_sse_shared.h and unchanged.
 */

#include <stdint.h>

#include "dbt/emit_sse_shared.h"

/* ---- per-family emitters -------------------------------------------- */

/* MOVUPS/MOVAPS rows (0F 10/11/28/29): full 128-bit; F3/F2 scalar at
 * the 10/11 rows only.  Direction from opnd[0]: R32 first = load
 * (dest = reg), RM32 first = store (dest = rm/memory). */
static int sse_emit_movx(i686_emit_ctx_t *e, const x86_insn_t *insn,
                         unsigned aligned_row)
{
    a64_buf_t *b = &e->buf;
    int load = (insn->opnd[0] == I686_OPND_R32);

    if (aligned_row != 0U && insn->pfx_rep != 0U) {
        return -1; /* F3/F2 0F 28/29 are not x86 encodings */
    }

    if (insn->pfx_rep != 0U) {
        /* MOVSS (F3) / MOVSD (F2). Register-to-register copies preserve
         * the destination's upper lanes; memory loads zero upper lanes
         * (127:32 for MOVSS, 127:64 for MOVSD; I686-R2-11). */
        if (load) {
            if (insn->modrm_mod == 3U) {
                sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
                if (insn->pfx_rep == 1U) {
                    sse_s_str(e, insn->modrm_reg & 7U, 1U);
                } else {
                    sse_d_str(e, insn->modrm_reg & 7U, 1U);
                }
            } else {
                sse_guest_addr(e, insn);
                if (insn->pfx_rep == 1U) {
                    sse_ldr_s(b, 1U, SSE_ADDR, 0U);
                    if (e->tso) {
                        a64_emit(b, 0xD50339BFU); /* dmb ishld */
                    }
                    sse_zero_s_str(e, insn->modrm_reg & 7U, 1U);
                } else {
                    sse_ldr_d(b, 1U, SSE_ADDR, 0U);
                    if (e->tso) {
                        a64_emit(b, 0xD50339BFU); /* dmb ishld */
                    }
                    sse_zero_d_str(e, insn->modrm_reg & 7U, 1U);
                }
            }
        } else {
            /* MOVSS/MOVSD xmm2/m32, xmm1: store the low lane only; the
             * mod=3 form copies the lane register-to-register with the
             * destination upper preserved. */
            sse_q_ldr(e, 1U, insn->modrm_reg & 7U);
            if (insn->modrm_mod == 3U) {
                if (insn->pfx_rep == 1U) {
                    sse_s_str(e, insn->modrm_rm & 7U, 1U);
                } else {
                    sse_d_str(e, insn->modrm_rm & 7U, 1U);
                }
            } else {
                sse_guest_addr(e, insn);
                if (insn->pfx_rep == 1U) {
                    sse_str_s(b, 1U, SSE_ADDR, 0U);
                } else {
                    sse_str_d(b, 1U, SSE_ADDR, 0U);
                }
                if (e->tso) {
                    a64_emit(b, 0xD5033BBFU); /* dmb ish */
                }
            }
        }
        return 0;
    }

    /* Full width: load = src copied into the dest slot; store = reg
     * copied into the rm slot/memory.  MOVAPD/MOVUPD are identical. */
    if (load) {
        if (insn->modrm_mod == 3U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_q(b, 1U, SSE_ADDR, 0U);
            if (e->tso) {
                a64_emit(b, 0xD50339BFU); /* dmb ishld */
            }
        }
        sse_q_str(e, insn->modrm_reg & 7U, 1U);
    } else {
        sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
        if (insn->modrm_mod == 3U) {
            sse_q_str(e, insn->modrm_rm & 7U, 0U);
        } else {
            sse_guest_addr(e, insn);
            sse_str_q(b, 0U, SSE_ADDR, 0U);
            if (e->tso) {
                a64_emit(b, 0xD5033BBFU); /* dmb ish */
            }
        }
    }
    return 0;
}

/* MOVLPS/MOVHPS rows (0F 12/13/16/17; hi = the 64-bit lane, 12/13 low,
 * 16/17 high): plain forms are MOVLPS/MOVHPS (m64 lane move) with the
 * reg-reg loads decoding as MOVHLPS (dest low <- src high) and
 * MOVLHPS (dest high <- src low); 66 selects MOVLPD/MOVHPD, which are
 * memory-only (66 reg-reg is invalid x86). */
static int sse_emit_movlp_hp(i686_emit_ctx_t *e, const x86_insn_t *insn,
                             unsigned hi)
{
    a64_buf_t *b = &e->buf;
    int load = (insn->opnd[0] == I686_OPND_R32);

    if (insn->pfx_rep != 0U) {
        return -1; /* F2/F3 0F 12/16 = MOVDDUP/MOVSLDUP-class: unlisted */
    }
    if (insn->modrm_mod == 3U) {
        if (insn->pfx_opsize != 0U || !load) {
            return -1; /* 66 reg-reg and 0F 13/17 reg-reg: invalid x86 */
        }
        sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        if (hi != 0U) {
            sse_ins_d_elt(b, 0U, 1U, 1U, 0U); /* MOVLHPS: d1 <- s0 */
        } else {
            sse_ins_d_elt(b, 0U, 0U, 1U, 1U); /* MOVHLPS: d0 <- s1 */
        }
        sse_q_str(e, insn->modrm_reg & 7U, 0U);
        return 0;
    }
    if (load) {
        sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
        sse_guest_addr(e, insn);
        sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        sse_ins_d_elt(b, 0U, hi != 0U ? 1U : 0U, 1U, 0U);
        sse_q_str(e, insn->modrm_reg & 7U, 0U);
    } else {
        sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
        if (hi != 0U) {
            sse_ins_d_elt(b, 2U, 0U, 0U, 1U); /* v2.d0 = v0.d1 */
            sse_guest_addr(e, insn);
            sse_str_d(b, 2U, SSE_ADDR, 0U);
        } else {
            sse_guest_addr(e, insn);
            sse_str_d(b, 0U, SSE_ADDR, 0U);
        }
    }
    return 0;
}

/* MOVQ_xmm rows (0F 6E/7E, one id): 66 0F 6E/7E = MOVD xmm<-r/m32 /
 * r/m32<-xmm (zero-extended); F3 0F 7E = MOVQ xmm, xmm/m64 load into
 * the reg field with bits 127:64 zeroed.  Plain (MMX) forms are
 * declined, and F2/F3 on 0F 6E are undefined 32-bit x86 (D2 decline;
 * the 64-bit-mode r64 form needs REX.W, out of scope). */
static int sse_emit_movd(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    int load = (insn->opnd[0] == I686_OPND_R32);

    if (load) {
        if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
            return -1; /* MMX form; F2/F3 6E undefined in 32-bit mode */
        }
        /* 66 0F 6E: MOVD xmm, r/m32 (zero-extended). */
        if (insn->modrm_mod == 3U) {
            a64_emit_mov_w(b, SSE_W8, i686_w(insn->modrm_rm));
        } else {
            sse_guest_addr(e, insn);
            a64_emit_ldr_imm_w(b, SSE_W8, SSE_ADDR, 0U);
        }
        sse_fmov_d_from_x(b, 0U, SSE_W8); /* zext 32 -> 128 */
        sse_q_str(e, insn->modrm_reg & 7U, 0U);
        return 0;
    }

    if (insn->pfx_rep == 1U) {
        /* F3 0F 7E: MOVQ_xmm reg, xmm/m64; bits 127:64 zeroed. */
        if (insn->modrm_mod == 3U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        }
        sse_zero_d_str(e, insn->modrm_reg & 7U, 1U);
        return 0;
    }

    /* 66 0F 7E: MOVD r/m32, xmm (low 32 of xmm). */
    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1; /* MMX store / F2 7E unlisted & undefined */
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_fmov_w_from_s(b, SSE_W8, 0U);
        a64_emit_mov_w(b, i686_w(insn->modrm_rm), SSE_W8);
    } else {
        sse_guest_addr(e, insn);
        sse_str_s(b, 0U, SSE_ADDR, 0U);
    }
    return 0;
}

/* PUNPCKLBW/LWD/LDQ (66 0F 60/61/62) + PUNPCKHBW/HWD/HDQ (68/69/6A) +
 * PUNPCKLQDQ/HQDQ (6C/6D).  The BW/WD pairs are exactly ZIP1/ZIP2 on
 * the full 128-bit operands; the DQ/QDQ forms compose with INS (or
 * ZIP1) over 64-bit lanes. */
static int sse_emit_punpck(i686_emit_ctx_t *e, const x86_insn_t *insn,
                           unsigned kind)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1; /* MMX forms unlisted */
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_q(b, 1U, SSE_ADDR, 0U);
    }
    switch (kind) {
    case 0U: /* PUNPCKLBW: interleave low 8 bytes */
        sse_zip1_16b(b, 0U, 0U, 1U);
        break;
    case 1U: /* PUNPCKLWD: interleave low 4 words */
        sse_zip1_8h(b, 0U, 0U, 1U);
        break;
    case 2U: /* PUNPCKLDQ: {d0,s0,d1,s1} */
        sse_zip1_4s(b, 0U, 0U, 1U);
        break;
    case 3U: /* PUNPCKHBW: interleave high 8 bytes */
        sse_zip2_16b(b, 0U, 0U, 1U);
        break;
    case 4U: /* PUNPCKHWD: interleave high 4 words */
        sse_zip2_8h(b, 0U, 0U, 1U);
        break;
    case 5U:
        /* R7-49 PUNPCKHDQ: {d2,s2,d3,s3} — the HIGH two dwords of the
         * 128-bit operand (lanes 2 and 3); composed with INS. */
        sse_ins_s_elt(b, 2U, 0U, 0U, 2U);
        sse_ins_s_elt(b, 2U, 1U, 1U, 2U);
        sse_ins_s_elt(b, 2U, 2U, 0U, 3U);
        sse_ins_s_elt(b, 2U, 3U, 1U, 3U);
        sse_mov_v_v(b, 0U, 2U);
        break;
    case 6U: /* PUNPCKLQDQ: {d0,s0} */
        sse_ins_d_elt(b, 0U, 1U, 1U, 0U);
        break;
    default: /* PUNPCKHQDQ: {d1,s1} */
        sse_ins_d_elt(b, 0U, 0U, 0U, 1U);
        sse_ins_d_elt(b, 0U, 1U, 1U, 1U);
        break;
    }
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* PSHUF family (0F 70 + imm8): the selector is an emit-time constant,
 * so the TBL index vector is materialized from four 32-bit immediates.
 * For 16-bit lanes each source word contributes the byte pair
 * {2s, 2s+1} (+8 when the shuffle reads the high half). */
static int sse_emit_pshuf(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    uint32_t imm = insn->imm & 0xFFU;
    uint32_t idx[4];
    unsigned i;

    if (insn->pfx_opsize != 0U) {
        /* PSHUFD: dword permute of the SRC (byte 4i+j -> 4s_i+j). */
        for (i = 0U; i < 4U; i++) {
            unsigned sel = (imm >> (2U * i)) & 3U;
            idx[i] = 0x03020100U + (4U * sel) * 0x01010101U;
        }
        if (insn->modrm_mod == 3U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_q(b, 1U, SSE_ADDR, 0U);
        }
    } else if (insn->pfx_rep == 0U) {
        /* PSHUFW (MMX): 8 index bytes, TBL.8B, MMX dest + tags. */
        uint32_t w0 = 0U;
        uint32_t w1 = 0U;
        for (i = 0U; i < 4U; i++) {
            unsigned sel = (imm >> (2U * i)) & 3U;
            uint32_t pair = 0x0100U + (2U * sel) * 0x0101U;
            if (i < 2U) {
                w0 |= pair << (16U * i);
            } else {
                w1 |= pair << (16U * (i - 2U));
            }
        }
        sse_mmx_file(e);
        sse_src_d_mmx(e, insn);
        a64_emit_mov_imm32(b, SSE_W8, w0);
        a64_emit_mov_imm32(b, SSE_W9, w1);
        sse_ins_s_gpr(b, 2U, 0U, SSE_W8);
        sse_ins_s_gpr(b, 2U, 1U, SSE_W9);
        sse_tbl_8b(b, 0U, 1U, 2U);
        sse_mmx_file(e);
        sse_str_d(b, 0U, SSE_MMX_BASE, 2U * (insn->modrm_reg & 7U));
        sse_mmx_tags_valid(e);
        return 0;
    } else {
        /* PSHUFHW (F3): high half shuffled over source words 4..7;
         * PSHUFLW (F2): low half over words 0..3; other half identity. */
        unsigned base_add = (insn->pfx_rep == 1U) ? 8U : 0U;
        uint32_t ident_lo0 = (insn->pfx_rep == 1U) ? 0x03020100U : 0U;
        uint32_t ident_lo1 = (insn->pfx_rep == 1U) ? 0x07060504U : 0U;
        uint32_t ident_hi0 = (insn->pfx_rep == 1U) ? 0U : 0x0B0A0908U;
        uint32_t ident_hi1 = (insn->pfx_rep == 1U) ? 0U : 0x0F0E0D0CU;
        for (i = 0U; i < 4U; i++) {
            unsigned sel = (imm >> (2U * i)) & 3U;
            uint32_t pair = 0x0100U + (base_add + 2U * sel) * 0x0101U;
            idx[i] = pair;
        }
        /* idx[0..1] = bytes 0..7, idx[2..3] = bytes 8..15; the shuffled
         * half packs two 16-bit pairs per 32-bit lane. */
        {
            uint32_t sh0 = idx[0] | (idx[1] << 16);
            uint32_t sh1 = idx[2] | (idx[3] << 16);
            if (insn->pfx_rep == 1U) {
                idx[0] = ident_lo0;
                idx[1] = ident_lo1;
                idx[2] = sh0;
                idx[3] = sh1;
            } else {
                idx[0] = sh0;
                idx[1] = sh1;
                idx[2] = ident_hi0;
                idx[3] = ident_hi1;
            }
        }
        if (insn->modrm_mod == 3U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_q(b, 1U, SSE_ADDR, 0U);
        }
    }

    for (i = 0U; i < 4U; i++) {
        a64_emit_mov_imm32(b, SSE_W8 + i, idx[i]);
        sse_ins_s_gpr(b, 2U, i, SSE_W8 + i);
    }
    sse_tbl_16b(b, 0U, 1U, 2U);
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* PADDD/PADDQ/PSUBD/PSUBQ/PMULLW (66). */
static int sse_emit_pint(i686_emit_ctx_t *e, const x86_insn_t *insn,
                         unsigned kind)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1; /* MMX forms unlisted */
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_q(b, 1U, SSE_ADDR, 0U);
    }
    switch (kind) {
    case 0U: sse_add_4s(b, 0U, 0U, 1U); break; /* PADDD  */
    case 1U: sse_add_2d(b, 0U, 0U, 1U); break; /* PADDQ  */
    case 2U: sse_sub_4s(b, 0U, 0U, 1U); break; /* PSUBD  */
    case 3U: sse_sub_2d(b, 0U, 0U, 1U); break; /* PSUBQ  */
    default: sse_mul_8h(b, 0U, 0U, 1U); break; /* PMULLW */
    }
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* PMULUDQ (66 0F F4): q[i] = zext(d[2i]) * zext(s[2i]) via UZP1+UMLAL. */
static int sse_emit_pmuludq(i686_emit_ctx_t *e, const x86_insn_t *insn)
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
    sse_uzp1_4s(b, 2U, 0U, 0U); /* v2.2s = {d0, d2} */
    sse_uzp1_4s(b, 3U, 1U, 1U); /* v3.2s = {s0, s2} */
    sse_movi_v_zero(b, 4U);
    sse_umlal_2d_2s(b, 4U, 2U, 3U);
    sse_q_str(e, insn->modrm_reg & 7U, 4U);
    return 0;
}

/* PXOR/POR/PAND/PANDN (66) + ANDPS/ANDNPS/ORPS/XORPS (+66 = *PD).
 * kind: 0 xor, 1 or, 2 and, 3 andn (dest = ~dest & src).
 * XMM-only: the MMX (unprefixed PAND/PANDN/POR/PXOR) forms are
 * declined at dispatch (R7-48) and never reach here. */
static int sse_emit_plogic(i686_emit_ctx_t *e, const x86_insn_t *insn,
                           unsigned kind)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_rep != 0U) {
        return -1; /* F2/F3 invalid on the logic rows */
    }
    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_q(b, 1U, SSE_ADDR, 0U);
    }
    switch (kind) {
    case 0U: sse_eor_16b(b, 0U, 0U, 1U); break;
    case 1U: sse_orr_16b(b, 0U, 0U, 1U); break;
    case 2U: sse_and_16b(b, 0U, 0U, 1U); break;
    default: sse_bic_16b(b, 0U, 1U, 0U); break; /* src & ~dest */
    }
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* ADD/SUB/MUL/DIV PS/PD/SS/SD (kind: 0 add, 1 sub, 2 mul, 3 div).
 *
 * R7-51: declined to the D2 interpret-one path.  The retired NEON
 * fast path ran under host FPCR (round-to-nearest, no flush) with
 * only an FTZ/DAZ guard: guest rounding modes, unmasked traps, and
 * guest exception-status accumulation (IE/ZE/OE/UE/PE/DE, e.g. masked
 * DIVSS-by-zero's ZE) never matched, and invalid results carried the
 * A64 default-NaN payload (0x7FC00000) instead of the x86 indefinite
 * QNaN (0xFFC00000/0xFFF8...).  Re-enable only with guest
 * rounding/status/result semantics proven against the interpreter. */
static int sse_emit_fparith(i686_emit_ctx_t *e, const x86_insn_t *insn,
                            unsigned kind)
{
    (void)e;
    (void)insn;
    (void)kind;
    return -1;
}

/* le core: v2 = (dest < src) | (dest == src).  A64 FCMEQ/FCMGT are
 * false when either side is NaN, so the OR is false for unordered
 * inputs exactly like x86 CMPPS-le (unlike !(dest > src), which is
 * true for NaN).  Only lane 0 of v2/v3 is consumed (scalar forms), so
 * upper-lane ORR/MVN residue is harmless there. */
static void sse_cmp_le(a64_buf_t *b, unsigned dbl, unsigned vec)
{
    if (vec != 0U) {
        if (dbl != 0U) {
            sse_fcmgt_vd(b, 2U, 1U, 0U);
            sse_fcmeq_vd(b, 3U, 0U, 1U);
        } else {
            sse_fcmgt_vs(b, 2U, 1U, 0U);
            sse_fcmeq_vs(b, 3U, 0U, 1U);
        }
    } else if (dbl != 0U) {
        sse_fcmgt_sd(b, 2U, 1U, 0U);
        sse_fcmeq_sd(b, 3U, 0U, 1U);
    } else {
        sse_fcmgt_ss(b, 2U, 1U, 0U);
        sse_fcmeq_ss(b, 3U, 0U, 1U);
    }
    sse_orr_16b(b, 2U, 2U, 3U);
}

/* CMPPS/SS/PD/SD imm8 predicates 0..7.  All predicates compose into
 * v2 (AND-chains for unord/ord); NOT forms invert v2.  The row forms
 * then move v2 into v0 whole; the scalar forms INS v2's low lane into
 * the dest, preserving its upper lanes.  NaN compares are false on
 * A64, so unord = !(eq & self-eq & src-eq) matches x86 exactly, while
 * le/nlt/nle are built from ordered lt/eq pieces (NOT-of-gt/ge is
 * wrong for NaN: x86 le is false but nlt/nle are true on unordered).
 * Scalar sources copy only lane 0; only lane 0 is consumed below. */
static int sse_emit_cmpp(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned pred = insn->imm & 7U;
    unsigned dbl;
    unsigned vec; /* row (vector) form */

    if (insn->imm > 7U) {
        return -1; /* imm8 > 7: x86 #UD, D2-safe decline */
    }
    if (insn->pfx_rep == 1U) {
        dbl = 0U;
        vec = 0U;
    } else if (insn->pfx_rep == 2U) {
        dbl = 1U;
        vec = 0U;
    } else {
        dbl = (insn->pfx_opsize != 0U) ? 1U : 0U;
        vec = 1U;
    }

    sse_q_ldr(e, 0U, insn->modrm_reg & 7U);
    if (vec != 0U) {
        if (insn->modrm_mod == 3U) {
            sse_q_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_q(b, 1U, SSE_ADDR, 0U);
        }
    } else if (dbl != 0U) {
        if (insn->modrm_mod == 3U) {
            sse_d_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        }
    } else {
        if (insn->modrm_mod == 3U) {
            sse_s_ldr(e, 1U, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_s(b, 1U, SSE_ADDR, 0U);
        }
    }

/* One compare: vector form -> v0 lanes, scalar form -> v2 low lane. */
#define SSE_CMP1(vfn, sfn, vd, n, m)                                          \
    do {                                                                      \
        if (vec != 0U) {                                                      \
            vfn(b, (vd), (n), (m));                                           \
        } else {                                                              \
            sfn(b, (vd), (n), (m));                                           \
        }                                                                     \
    } while (0)

    switch (pred) {
    case 0U: /* eq */
        if (dbl != 0U) {
            SSE_CMP1(sse_fcmeq_vd, sse_fcmeq_sd, 2U, 0U, 1U);
        } else {
            SSE_CMP1(sse_fcmeq_vs, sse_fcmeq_ss, 2U, 0U, 1U);
        }
        break;
    case 1U: /* lt: dest < src == FCMGT(src, dest) */
        if (dbl != 0U) {
            SSE_CMP1(sse_fcmgt_vd, sse_fcmgt_sd, 2U, 1U, 0U);
        } else {
            SSE_CMP1(sse_fcmgt_vs, sse_fcmgt_ss, 2U, 1U, 0U);
        }
        break;
    case 2U: /* le: (dest < src) | (dest == src) */
        sse_cmp_le(b, dbl, vec);
        break;
    case 3U: /* unord: !(dest==dest & src==src) — NaN self-compares false */
    case 7U: /* ord:    dest==dest & src==src                        */
        if (dbl != 0U) {
            sse_fcmeq_vd(b, 2U, 0U, 0U);
            sse_fcmeq_vd(b, 3U, 1U, 1U);
        } else {
            sse_fcmeq_vs(b, 2U, 0U, 0U);
            sse_fcmeq_vs(b, 3U, 1U, 1U);
        }
        sse_and_16b(b, 2U, 2U, 3U);
        if (pred == 3U) {
            sse_mvn_16b(b, 2U, 2U);
        }
        break;
    case 4U: /* neq */
        if (dbl != 0U) {
            SSE_CMP1(sse_fcmeq_vd, sse_fcmeq_sd, 2U, 0U, 1U);
        } else {
            SSE_CMP1(sse_fcmeq_vs, sse_fcmeq_ss, 2U, 0U, 1U);
        }
        sse_mvn_16b(b, 2U, 2U);
        break;
    case 5U: /* nlt: !(dest < src) */
        if (dbl != 0U) {
            SSE_CMP1(sse_fcmgt_vd, sse_fcmgt_sd, 2U, 1U, 0U);
        } else {
            SSE_CMP1(sse_fcmgt_vs, sse_fcmgt_ss, 2U, 1U, 0U);
        }
        sse_mvn_16b(b, 2U, 2U);
        break;
    default: /* nle: !((dest < src) | (dest == src)) */
        sse_cmp_le(b, dbl, vec);
        sse_mvn_16b(b, 2U, 2U);
        break;
    }
#undef SSE_CMP1

    if (vec != 0U) {
        sse_mov_v_v(b, 0U, 2U);
    } else if (dbl != 0U) {
        sse_ins_d_elt(b, 0U, 0U, 2U, 0U);
    } else {
        sse_ins_s_elt(b, 0U, 0U, 2U, 0U);
    }
    sse_q_str(e, insn->modrm_reg & 7U, 0U);
    return 0;
}

/* MOVMSKPS/PD (I686_OP_MOVMSKPS) lives in emit_sse2.c next to its
 * sibling PMOVMSKB. */

/* ---- entry point ----------------------------------------------------- */

int i686_emit_sse(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->pfx_lock != 0U) {
        return -1; /* LOCK on an SSE row is invalid x86 */
    }

    switch (insn->op) {
    case I686_OP_MOVUPS:
        return sse_emit_movx(e, insn, 0U);
    case I686_OP_MOVAPS:
        return sse_emit_movx(e, insn, 1U);
    case I686_OP_MOVLPS:
        return sse_emit_movlp_hp(e, insn, 0U);
    case I686_OP_MOVHPS:
        return sse_emit_movlp_hp(e, insn, 1U);
    case I686_OP_MOVQ_xmm:
        return sse_emit_movd(e, insn);
    case I686_OP_PSHUFW:
        return sse_emit_pshuf(e, insn);
    case I686_OP_PUNPCKLBW:
        return sse_emit_punpck(e, insn, 0U);
    case I686_OP_PUNPCKLWD:
        return sse_emit_punpck(e, insn, 1U);
    case I686_OP_PUNPCKLDQ:
        return sse_emit_punpck(e, insn, 2U);
    case I686_OP_PUNPCKHBW:
        return sse_emit_punpck(e, insn, 3U);
    case I686_OP_PUNPCKHWD:
        return sse_emit_punpck(e, insn, 4U);
    case I686_OP_PUNPCKHDQ:
        return sse_emit_punpck(e, insn, 5U);
    case I686_OP_PUNPCKLQDQ:
        return sse_emit_punpck(e, insn, 6U);
    case I686_OP_PUNPCKHQDQ:
        return sse_emit_punpck(e, insn, 7U);
    case I686_OP_PADDD:
        return sse_emit_pint(e, insn, 0U);
    case I686_OP_PADDQ:
        return sse_emit_pint(e, insn, 1U);
    case I686_OP_PSUBD:
        return sse_emit_pint(e, insn, 2U);
    case I686_OP_PSUBQ:
        return sse_emit_pint(e, insn, 3U);
    case I686_OP_PMULLW:
        return sse_emit_pint(e, insn, 4U);
    case I686_OP_PMULUDQ:
        return sse_emit_pmuludq(e, insn);
    case I686_OP_PAND:
        /* R7-48: unprefixed form is MMX (mm bank, 8-byte mem); the
         * XMM-only plogic emitter must not see it. */
        if (insn->pfx_opsize == 0U) {
            return -1;
        }
        return sse_emit_plogic(e, insn, 2U);
    case I686_OP_PANDN:
        if (insn->pfx_opsize == 0U) {
            return -1;
        }
        return sse_emit_plogic(e, insn, 3U);
    case I686_OP_POR:
        if (insn->pfx_opsize == 0U) {
            return -1;
        }
        return sse_emit_plogic(e, insn, 1U);
    case I686_OP_PXOR:
        if (insn->pfx_opsize == 0U) {
            return -1;
        }
        return sse_emit_plogic(e, insn, 0U);
    case I686_OP_ANDPS:
        return sse_emit_plogic(e, insn, 2U);
    case I686_OP_ANDNPS:
        return sse_emit_plogic(e, insn, 3U);
    case I686_OP_ORPS:
        return sse_emit_plogic(e, insn, 1U);
    case I686_OP_XORPS:
        return sse_emit_plogic(e, insn, 0U);
    case I686_OP_ADDPS:
        return sse_emit_fparith(e, insn, 0U);
    case I686_OP_SUBPS:
        return sse_emit_fparith(e, insn, 1U);
    case I686_OP_MULPS:
        return sse_emit_fparith(e, insn, 2U);
    case I686_OP_DIVPS:
        return sse_emit_fparith(e, insn, 3U);
    case I686_OP_CMPPS:
        return sse_emit_cmpp(e, insn);
    case I686_OP_SFENCE:
        /* 0F AE /7: store fence; the memory modrm forms are x86 #UD (D2 decline). */
        if (insn->modrm_mod != 3U) {
            return -1;
        }
        a64_emit(&e->buf, 0xD5033ABFU); /* dmb ishst */
        return 0;
    case I686_OP_EMMS: {
        /* ftag = 0xFFFF (all empty); TOP untouched. */
        a64_emit_movz_w(&e->buf, SSE_W8, 0xFFFFU, 0U);
        a64_emit_strh_imm_w(&e->buf, SSE_W8, A64_XCTX, 0x18CU);
        return 0;
    }
    case I686_OP_SETcc_Eb:
        /* F3 0F 90 = PAUSE (modrm consumed, no write): emit_branch
         * declines rep-prefixed SETcc, so PAUSE lands here.  Other
         * rep-prefixed SETcc bytes stay declined. */
        if (insn->pfx_rep == 1U && insn->modrm_reg == 0U) {
            return 0; /* NOP */
        }
        return -1;
    default:
        break;
    }
    /* Remaining rows (compares, converts, misc) live in emit_sse2.c. */
    return i686_emit_sse2(e, insn);
}
