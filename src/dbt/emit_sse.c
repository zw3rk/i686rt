/*
 * src/dbt/emit_sse.c — SSE/SSE2/MMX DBT emitters (Phase 5 lane L5a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * i686_emit_sse handles the NEON-mappable subset of the Phase 5 opcode
 * rows (docs/lanes/phase-5.md, shared generator spec) 1:1 per SPEC D10:
 * XMM operands live in ctx->xmm[0..7] (offset 0x108 — the array is 8
 * mod 16, so a per-insn base x9 = x19+0x108 feeds scaled Q accesses)
 * and are staged through NEON scratch v0..v4; MMX registers alias the
 * low 8 bytes of ctx->x87_st[0..7] via x10 = x19+0x88.  Guest memory
 * goes through i686_emit_ea into w21 and x23 = xG + uxtw(w21) (D4/D7).
 * Prefix disambiguation follows the generator convention: the row id is
 * the unprefixed (or 66-only) form and 66/F2/F3 variants — MOVAPD,
 * MOVSS, ADDSD, CMPSD, CVTSS2SD, ... — are resolved here from
 * insn->pfx_opsize / insn->pfx_rep (CWDE/CBW precedent).
 *
 * Scalar writes into XMM always go through INS into the destination
 * lane so the upper bits stay architecturally preserved regardless of
 * the A64 scalar-write zeroing rules; full-width ops write whole Q.
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
 *   ADD/SUB/MUL/DIV PS/PD/SS/SD (FADD/FSUB/FMUL/FDIV .4S/.2D/scalar)
 *   CMPPS/SS/PD/SD imm8 predicates 0..7 (eq/lt/le/unord/neq/nlt/nle/
 *     ord via FCMEQ/FCMGT/FCMGE + AND/MVN; NaN = x86 unord semantics)
 *   MOVMSKPS/MOVMSKPD (SSHR+UMOV sign-bit extraction)
 *   COMISS/COMISD/UCOMISS/UCOMISD (FCMP; ZF=Z, PF=V, CF=!C|V, clear
 *     OF/SF/AF, lazy_op = NONE; pending lazy flags materialized first
 *     unless the C6a flags_src proof makes that path a no-op)
 *   CVTPI2PS/PD, CVTSI2SS/SD (SCVTF; 2S->2D via SSHLL#0 + SCVTF),
 *     CVTTPS2PI, CVTTSS2SI/CVTTSD2SI (FCVTZS), CVTTPD2PI (FCVTZS.2D
 *     + XTN), CVTPS2PD (FCVTL), CVTPD2PS (FCVTN + zero upper),
 *     CVTSS2SD/CVTSD2SS (FCVT), CVTDQ2PS (SCVTF), CVTPS2DQ (FCVTNS),
 *     CVTTPS2DQ (FCVTZS)
 *   LDMXCSR/STMXCSR (0F AE /2 /3, m32, reserved bits masked on load),
 *   SFENCE (0F AE /7) = no-op, PAUSE (F3 0F 90, decode reports SETcc_Eb
 *     with pfx_rep=1) = NOP.
 *   RC7b T1 (docs/lanes/phase-7.md): MOVDQA/MOVDQU (66/F3 0F 6F load /
 *     0F 7F store as plain Q moves — the alignment #GP is interpreter-
 *     only, v1 MOVAPS-class deviation), MOVQ2DQ row (66 0F D6 store-
 *     low64, F3 MOVQ2DQ, F2 MOVDQ2Q via the MMX file), MOVNTDQ (66 0F E7
 *     as a plain Q store), PSRLDQ/PSLLDQ (66 0F 73 /3 /7 via EXT against
 *     a zero temp; RC7b T2: the old /2 /3 digit map wrote the result to
 *     the /digit register — 0F 73 carries the digit in modrm_reg and the
 *     operand in modrm_rm), PCMPGTB/PCMPEQB/PCMPEQD (66 0F 64/74/76 via
 *     CMGT/
 *     CMEQ), PMOVMSKB (66 0F D7, 16-bit UMOV sign-bit assembly),
 *     PMINUB/PMAXUB (66 0F DA/DE via UMIN/UMAX), PSUBB (66 0F F8),
 *     PREFETCHh (0F 18) = no-op.
 *
 * Declined (return -1 -> D2 interpret-one, per the card):
 *   - every MMX (unprefixed) integer form of the new rows (MOVD, the
 *     PUNPCK family, PADDD..PMULUDQ mm encodings, and the RC7b T1 MMX
 *     forms of 6F/7F/64/73/74/76/D7/DA/DE/F8): the shared spec lists
 *     only their 66 (xmm) forms -- the interpreter oracle implements
 *     them; PSHUFW/CVTPI2PS/CVTTPS2PI/CVTPI2PD/CVTTPD2PI touch the MMX
 *     alias file and ARE emitted, as are the RC7b F2/F3 0F D6 forms;
 *   - MOVDDUP/MOVSLDUP/MOVSHDUP (F2/F3 0F 12/16): not in the frozen
 *     name list;
 *   - F2 0F 5B (CVTPD2DQ): unlisted name -- the card's "CVTTPS2DQ =
 *     66 2C" is actually F3 0F 5B (generator header notes);
 *   - CMPPS-family predicates imm8 > 7 (x86 #UD);
 *   - encodings x86 rejects: MOVMSKPS/PD with memory rm, MOVLPD/MOVHPD
 *     reg-reg (66 0F 12/16 mod=3), the plain 0F 13/17 reg-reg stores,
 *     LDMXCSR/STMXCSR reg form, F2/F3 on the aligned-move and logic
 *     rows, 66 on the CVTTPS2PI scalar forms (only 66 2C = CVTTPD2PI
 *     is emitted), F2 on 0F 6E;
 *   - LOCK-prefixed anything (translate.c routes LOCK to the atomic
 *     module first; LOCK on an SSE row is invalid x86);
 *   - FXSAVE/FXRSTOR/XSAVE family (0F AE /0 /1 /4-/7): those ids never
 *     dispatch here (no cases) -- they ride the D2 interpreter.
 *
 * Known v1 deviations (Phase H per SPEC D10/sse.h, documented): MXCSR
 * rounding/FTZ/DAZ are not mapped into FPCR (default NEON rounding),
 * CVTT* NaN/overflow produce NEON saturation instead of x86's integer
 * indefinite 0x80000000, and SSE memory ops stay plain LDR/STR Q in
 * TSO mode (x86 SSE non-atomic stores need TSO ordering only for LOCK
 * RMW, owned by the atomic module).  MMX-writing insns set the x87 tag
 * word to valid (0x0000) and EMMS sets it empty (0xFFFF); fstat.TOP
 * and the x87_st payload otherwise stay untouched.
 *
 * Scratch inside one insn (D7): v0 = dest value, v1 = src value, v2/v3
 * = temps, v4 = result temp; w8..w12 integer scratch; x9 = &xmm[0],
 * x10 = &x87_st[0], w21/x21 = EA (i686_emit_ea), x23 = guest address.
 * Every raw A64 word below was verified against a reference assembly
 * listing (see the lane report); shared encoders come from
 * src/rt32/rt32_a64_emit.h.
 */

#include <stdint.h>

#include "dbt/emit.h"

/* ---- ctx access bases (recomputed per insn; 0x108 is 8 mod 16) ---- */

/* ADD Xd, Xn, #imm12 (64-bit, imm12 = byte offset). */
static void sse_add_x_imm12(a64_buf_t *b, unsigned rd, unsigned rn,
                            uint32_t imm12)
{
    a64_emit(b, 0x91000000U | ((imm12 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

#define SSE_XMM_BASE 9U   /* x9  = x19 + 0x108 = &ctx->xmm[0]   */
#define SSE_MMX_BASE 10U  /* x10 = x19 + 0x88  = &ctx->x87_st[0] */
#define SSE_ADDR    23U   /* x23 = xG + uxtw(w21) guest address  */
#define SSE_W8       8U
#define SSE_W9       9U
#define SSE_W10     10U
#define SSE_W11     11U
#define SSE_W12     12U
#define SSE_W13     13U

/* ---- raw SIMD&FP encoders (verified; see file header) --------------
 * Immediate offsets are in natural units: off16/off8/off4 are already
 * scaled (imm12 counts 16/8/4-byte units). */

static void sse_ldr_q(a64_buf_t *b, unsigned vt, unsigned rn, uint32_t off16)
{
    a64_emit(b, 0x3DC00000U | ((off16 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static void sse_str_q(a64_buf_t *b, unsigned vt, unsigned rn, uint32_t off16)
{
    a64_emit(b, 0x3D800000U | ((off16 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static void sse_ldr_d(a64_buf_t *b, unsigned vt, unsigned rn, uint32_t off8)
{
    a64_emit(b, 0xFD400000U | ((off8 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static void sse_str_d(a64_buf_t *b, unsigned vt, unsigned rn, uint32_t off8)
{
    a64_emit(b, 0xFD000000U | ((off8 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static void sse_ldr_s(a64_buf_t *b, unsigned vt, unsigned rn, uint32_t off4)
{
    a64_emit(b, 0xBD400000U | ((off4 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static void sse_str_s(a64_buf_t *b, unsigned vt, unsigned rn, uint32_t off4)
{
    a64_emit(b, 0xBD000000U | ((off4 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

/* INS (general): Vd.S[i] <- Wn / Vd.D[i] <- Xn (31 = zeroing). */
static void sse_ins_s_gpr(a64_buf_t *b, unsigned vd, unsigned i, unsigned wn)
{
    a64_emit(b, 0x4E001C00U | ((4U + 8U * (i & 3U)) << 16) |
                     ((wn & 31U) << 5) | (vd & 31U));
}

static void sse_ins_d_gpr(a64_buf_t *b, unsigned vd, unsigned i, unsigned xn)
{
    a64_emit(b, 0x4E001C00U | ((8U + 16U * (i & 1U)) << 16) |
                     ((xn & 31U) << 5) | (vd & 31U));
}

/* INS (element), source lane 0..3 (S) / 0..1 (D): the src index rides
 * the imm4 field — si<<13 (S) or si<<14 (D); imm5 = 4+8*di / 8+16*di. */
static void sse_ins_s_elt(a64_buf_t *b, unsigned vd, unsigned di, unsigned vn,
                          unsigned si)
{
    a64_emit(b, 0x6E000400U | ((4U + 8U * (di & 3U)) << 16) |
                     ((si & 3U) << 13) | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_ins_d_elt(a64_buf_t *b, unsigned vd, unsigned di, unsigned vn,
                          unsigned si)
{
    a64_emit(b, 0x6E000400U | ((8U + 16U * (di & 1U)) << 16) |
                     ((si & 1U) << 14) | ((vn & 31U) << 5) | (vd & 31U));
}

/* FMOV scalars across the GPR/NEON boundary. */
static void sse_fmov_d_from_x(a64_buf_t *b, unsigned vd, unsigned xn)
{
    a64_emit(b, 0x9E670000U | ((xn & 31U) << 5) | (vd & 31U));
}

static void sse_fmov_w_from_s(a64_buf_t *b, unsigned wd, unsigned vn)
{
    a64_emit(b, 0x1E260000U | ((vn & 31U) << 5) | (wd & 31U));
}

static void sse_movi_v_zero(a64_buf_t *b, unsigned vd)
{
    /* MOVI Vd.16B, #0 */
    a64_emit(b, 0x4F00E400U | (vd & 31U));
}

static void sse_mov_v_v(a64_buf_t *b, unsigned vd, unsigned vn)
{
    /* MOV Vd.16B, Vn.16B (ORR Vd.16B, Vn.16B, Vn.16B) */
    a64_emit(b, 0x4EA01C00U | ((vn & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_zip1_4s(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E803800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

/* ZIP1/ZIP2 bytewise and halfword (PUNPCK BW/WD families). */
static void sse_zip1_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E003800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_zip2_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E007800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_zip1_8h(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E403800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_zip2_8h(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E407800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_tbl_16b(a64_buf_t *b, unsigned vd, unsigned vtab, unsigned vid)
{
    /* TBL Vd.16B, {Vtab.16B}, Vid.16B */
    a64_emit(b, 0x4E001000U | ((vid & 31U) << 16) | ((vtab & 31U) << 5) |
                     (vd & 31U));
}

static void sse_tbl_8b(a64_buf_t *b, unsigned vd, unsigned vtab, unsigned vid)
{
    /* TBL Vd.8B, {Vtab.16B}, Vid.8B (upper 64 of Vd zeroed) */
    a64_emit(b, 0x0E001000U | ((vid & 31U) << 16) | ((vtab & 31U) << 5) |
                     (vd & 31U));
}

static void sse_uzp1_4s(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E801800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_eor_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6E201C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_orr_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4EA01C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_and_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E201C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_bic_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    /* BIC Vd, Vn, Vm = Vn & ~Vm (PANDN/ANDNPS: dest = src & ~dest) */
    a64_emit(b, 0x4E601C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_mvn_16b(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x6E205800U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_add_4s(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4EA08400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_add_2d(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4EE08400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_sub_4s(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6EA08400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_sub_2d(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6EE08400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_mul_8h(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E609C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_umlal_2d_2s(a64_buf_t *b, unsigned vd, unsigned vn,
                            unsigned vm)
{
    /* UMLAL Vd.2D, Vn.2S, Vm.2S (32->64; size bits set) */
    a64_emit(b, 0x2EA08000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_ushr_4s_31(a64_buf_t *b, unsigned vd, unsigned vn)
{
    /* USHR Vd.4S, Vn.4S, #31: logical shift leaves 0/1 lanes (SSHR
     * would sign-extend to 0xFFFFFFFF). */
    a64_emit(b, 0x6F210400U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_ushr_2d_63(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x6F410400U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_umov_d(a64_buf_t *b, unsigned xd, unsigned vn, unsigned i)
{
    /* UMOV Xd, Vn.D[i]: imm5 field (bits 20:16) = 8 + 16*i */
    a64_emit(b, 0x4E083C00U | ((8U + 16U * (i & 1U)) << 16) |
                     ((vn & 31U) << 5) | (xd & 31U));
}

static void sse_umov_s(a64_buf_t *b, unsigned wd, unsigned vn, unsigned i)
{
    /* UMOV Wd, Vn.S[i]: imm5 field (bits 20:16) = 4 + 8*i */
    a64_emit(b, 0x0E043C00U | ((4U + 8U * (i & 3U)) << 16) |
                     ((vn & 31U) << 5) | (wd & 31U));
}

/* FP arithmetic raw words, one per (op, width); op order add/sub/mul/
 * div mirrors the dispatch table. */
static const uint32_t sse_fp_vec_s[4] = {
    0x4E20D400U, /* FADD V.4S */
    0x4EA0D400U, /* FSUB V.4S */
    0x6E20DC00U, /* FMUL V.4S */
    0x6E20FC00U, /* FDIV V.4S */
};
static const uint32_t sse_fp_vec_d[4] = {
    0x4E60D400U, /* FADD V.2D */
    0x4EE0D400U, /* FSUB V.2D */
    0x6E60DC00U, /* FMUL V.2D */
    0x6E60FC00U, /* FDIV V.2D */
};
static const uint32_t sse_fp_sca_s[4] = {
    0x1E202800U, /* FADD S */
    0x1E203800U, /* FSUB S */
    0x1E200800U, /* FMUL S */
    0x1E201800U, /* FDIV S */
};
static const uint32_t sse_fp_sca_d[4] = {
    0x1E602800U, /* FADD D */
    0x1E603800U, /* FSUB D */
    0x1E600800U, /* FMUL D */
    0x1E601800U, /* FDIV D */
};

static void sse_fp_vec(a64_buf_t *b, uint32_t base, unsigned vd, unsigned vn,
                       unsigned vm)
{
    a64_emit(b, base | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_fp_sca(a64_buf_t *b, uint32_t base, unsigned vd, unsigned vn,
                       unsigned vm)
{
    a64_emit(b, base | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

/* Compares (all-ones/all-zeros masks; NaN comparisons are false, which
 * drives the unord/ord composition below). */
static void sse_fcmeq_vs(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E20E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmeq_vd(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E60E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmgt_vs(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6EA0E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmgt_vd(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6EE0E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmge_vs(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6E20E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmge_vd(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6E60E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmeq_ss(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E20E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmeq_sd(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x5E60E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmgt_ss(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x7EA0E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmgt_sd(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x7EE0E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmge_ss(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x7E20E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmge_sd(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x7E60E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_fcmp_s(a64_buf_t *b, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x1E202000U | ((vm & 31U) << 16) | ((vn & 31U) << 5));
}

static void sse_fcmp_d(a64_buf_t *b, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x1E602000U | ((vm & 31U) << 16) | ((vn & 31U) << 5));
}

/* Converts. */
static void sse_scvtf_2s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0E21D800U | ((vn & 31U) << 5) | (vd & 31U));
}

/* SSHLL Vd.2D, Vn.2S, #0: widen two s32 lanes to s64 (feeds SCVTF for
 * CVTPI2PD -- A64 has no widening vector int-to-fp convert). */
static void sse_sshll_2d_0(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0F20A400U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_scvtf_2d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E61D800U | ((vn & 31U) << 5) | (vd & 31U));
}

/* FCVTZS Vd.2D, Vn.2D then XTN Vd.2S, Vd.2D narrows doubles to two
 * s32 (CVTTPD2PI; see the v1 saturation deviation note above). */
static void sse_fcvtzs_2d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4EE1B800U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_xtn_2s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0EA12800U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_scvtf_4s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E21D800U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_scvtf_s_w(a64_buf_t *b, unsigned vd, unsigned wn)
{
    a64_emit(b, 0x1E220000U | ((wn & 31U) << 5) | (vd & 31U));
}

static void sse_scvtf_d_w(a64_buf_t *b, unsigned vd, unsigned wn)
{
    a64_emit(b, 0x1E620000U | ((wn & 31U) << 5) | (vd & 31U));
}

static void sse_fcvtzs_2s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0EA1B800U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_fcvtzs_4s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4EA1B800U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_fcvtzs_w_s(a64_buf_t *b, unsigned wd, unsigned vn)
{
    a64_emit(b, 0x1E380000U | ((vn & 31U) << 5) | (wd & 31U));
}

static void sse_fcvtzs_w_d(a64_buf_t *b, unsigned wd, unsigned vn)
{
    a64_emit(b, 0x1E780000U | ((vn & 31U) << 5) | (wd & 31U));
}

static void sse_fcvt_d_s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x1E22C000U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_fcvt_s_d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x1E624000U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_fcvtl_2d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0E617800U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_fcvtn_2s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0E616800U | ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_fcvtns_4s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E21A800U | ((vn & 31U) << 5) | (vd & 31U));
}

/* AND Wd, Wn, #0xFFFF (LDMXCSR reserved-bit mask; N=0 immr=0 imms=15). */
static void sse_and_ffff(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x12000000U | (15U << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

/* EOR w11, w11, #1 (fixed operands; COMISS CF = !C_a64 | V). */
static void sse_eor_w11_1(a64_buf_t *b)
{
    a64_emit(b, 0x5200016BU);
}

/* ---- RC7b T1 raw SIMD words (verified against the cross assembler) -- */

/* EXT Vd.16B, Vn.16B, Vm.16B, #imm4: result[j] = concat(Vn:Vm)[j+imm4]
 * (whole-register byte shifts against a zero temp). */
static void sse_ext_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm,
                        unsigned imm4)
{
    a64_emit(b, 0x6E001800U | ((imm4 & 15U) << 11) | ((vm & 31U) << 16) |
                     ((vn & 31U) << 5) | (vd & 31U));
}

static void sse_cmeq_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6E208C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_cmeq_4s(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6EA08C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_cmgt_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x4E203400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_umin_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6E206C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_umax_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6E206400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static void sse_sub_16b(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x6E208400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

/* UMOV Wd, Vn.B[i]: imm5 = 2i+1 (bit 0 selects the B element size). */
static void sse_umov_b(a64_buf_t *b, unsigned wd, unsigned vn, unsigned i)
{
    a64_emit(b, 0x0E003C00U | (((2U * (i & 15U)) + 1U) << 16) |
                     ((vn & 31U) << 5) | (wd & 31U));
}

/* ---- operand staging ------------------------------------------------ */

/* x9 = &ctx->xmm[0]; scaled Q accesses use 16*reg. */
static void sse_xmm_file(i686_emit_ctx_t *e)
{
    sse_add_x_imm12(&e->buf, SSE_XMM_BASE, A64_XCTX, 0x108U);
}

/* x10 = &ctx->x87_st[0] (MMX alias file; D accesses use 2*reg). */
static void sse_mmx_file(i686_emit_ctx_t *e)
{
    sse_add_x_imm12(&e->buf, SSE_MMX_BASE, A64_XCTX, 0x88U);
}

/* Guest EA into x23 = xG + uxtw(w21) via the frozen i686_emit_ea. */
static void sse_guest_addr(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    i686_emit_ea(e, insn, 1);
    a64_emit_add_uxtw_x(&e->buf, SSE_ADDR, A64_XG, 21U);
}

/* Full-width XMM source into v1: reg-reg or m128. */
static void sse_src_q(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        sse_ldr_q(&e->buf, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_q(&e->buf, 1U, SSE_ADDR, 0U);
    }
}

/* 64-bit source into v1 (MMX reg or m64); upper 64 of v1 irrelevant. */
static void sse_src_d_mmx(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        sse_ldr_d(&e->buf, 1U, SSE_MMX_BASE, 2U * (insn->modrm_rm & 7U));
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_d(&e->buf, 1U, SSE_ADDR, 0U);
    }
}

/* Scalar 32-bit source into v1.s[0] (xmm reg or m32). */
static void sse_src_s(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        sse_ldr_q(&e->buf, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_s(&e->buf, 1U, SSE_ADDR, 0U);
    }
}

/* Scalar 64-bit source into v1.d[0] (xmm reg or m64). */
static void sse_src_d(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        sse_ldr_q(&e->buf, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_d(&e->buf, 1U, SSE_ADDR, 0U);
    }
}

/* v0 <- / -> ctx->xmm[reg]. */
static void sse_dst_load(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    sse_ldr_q(&e->buf, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
}

static void sse_dst_store(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    sse_str_q(&e->buf, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
}

/* MMX writes mark the x87 tag word valid (Intel MMX rule). */
static void sse_mmx_tags_valid(i686_emit_ctx_t *e)
{
    a64_emit_strh_imm_w(&e->buf, 31U, A64_XCTX, 0x18CU);
}

/* ---- pending-flags materialization (COMIS family) ------------------ */

/* Call i686_dbt_flags_sync(ctx) with the GPR park/reload dance, so the
 * eflags read-modify-write below sees architecturally current bits even
 * when a same-block ALU insn left a lazy descriptor (S3 seam).  Mirrors
 * emit_branch.c's helper-call sequence exactly. */
static void sse_flags_sync(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;
    extern void i686_dbt_flags_sync(i686_ctx_t *);
    uintptr_t fn = (uintptr_t)&i686_dbt_flags_sync;
    unsigned i;

    a64_emit_str_imm_w(b, 0U, A64_XCTX, 0U);
    a64_emit_str_imm_w(b, 1U, A64_XCTX, 4U);
    a64_emit_str_imm_w(b, 2U, A64_XCTX, 8U);
    a64_emit_str_imm_w(b, 3U, A64_XCTX, 12U);
    a64_emit_str_imm_w(b, 4U, A64_XCTX, 16U);
    a64_emit_str_imm_w(b, 5U, A64_XCTX, 20U);
    a64_emit_str_imm_w(b, 6U, A64_XCTX, 24U);
    a64_emit_str_imm_w(b, 7U, A64_XCTX, 28U);
    for (i = 0U; i < 4U; i++) {
        uint32_t hw = (uint32_t)((fn >> (16U * i)) & 0xFFFFU);
        uint32_t word;
        if (i == 0U) {
            word = 0xD2800000U; /* MOVZ X17, hw */
        } else if (hw != 0U) {
            word = 0xF2800000U; /* MOVK X17, hw, LSL #16i */
        } else {
            continue;
        }
        a64_emit(b, word | (i << 21) | (hw << 5) | 17U);
    }
    a64_emit(b, 0xAA1F0260U); /* x0 = x19 */
    a64_emit(b, 0xAA1F03DCU); /* x28 = x30 (park lr) */
    a64_emit(b, 0xD63F0220U); /* blr x17 */
    a64_emit(b, 0xAA1F039EU); /* x30 = x28 */
    a64_emit_ldr_imm_w(b, 0U, A64_XCTX, 0U);
    a64_emit_ldr_imm_w(b, 1U, A64_XCTX, 4U);
    a64_emit_ldr_imm_w(b, 2U, A64_XCTX, 8U);
    a64_emit_ldr_imm_w(b, 3U, A64_XCTX, 12U);
    a64_emit_ldr_imm_w(b, 4U, A64_XCTX, 16U);
    a64_emit_ldr_imm_w(b, 5U, A64_XCTX, 20U);
    a64_emit_ldr_imm_w(b, 6U, A64_XCTX, 24U);
    a64_emit_ldr_imm_w(b, 7U, A64_XCTX, 28U);
}

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
        /* MOVSS (F3) / MOVSD (F2). */
        if (load) {
            sse_xmm_file(e);
            sse_dst_load(e, insn);
            if (insn->modrm_mod == 3U) {
                sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
            } else {
                sse_guest_addr(e, insn);
                if (insn->pfx_rep == 1U) {
                    sse_ldr_s(b, 1U, SSE_ADDR, 0U);
                } else {
                    sse_ldr_d(b, 1U, SSE_ADDR, 0U);
                }
            }
            if (insn->pfx_rep == 1U) {
                sse_ins_s_elt(b, 0U, 0U, 1U, 0U);
            } else {
                sse_ins_d_elt(b, 0U, 0U, 1U, 0U);
            }
            sse_dst_store(e, insn);
        } else {
            /* MOVSS/MOVSD xmm2/m32, xmm1: store the low lane only; the
             * mod=3 form copies the lane register-to-register with the
             * destination upper preserved. */
            sse_xmm_file(e);
            sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_reg & 7U);
            if (insn->modrm_mod == 3U) {
                sse_ldr_q(b, 0U, SSE_XMM_BASE, insn->modrm_rm & 7U);
                if (insn->pfx_rep == 1U) {
                    sse_ins_s_elt(b, 0U, 0U, 1U, 0U);
                } else {
                    sse_ins_d_elt(b, 0U, 0U, 1U, 0U);
                }
                sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_rm & 7U);
            } else {
                sse_guest_addr(e, insn);
                if (insn->pfx_rep == 1U) {
                    sse_str_s(b, 1U, SSE_ADDR, 0U);
                } else {
                    sse_str_d(b, 1U, SSE_ADDR, 0U);
                }
            }
        }
        return 0;
    }

    /* Full width: load = src copied into the dest slot; store = reg
     * copied into the rm slot/memory.  MOVAPD/MOVUPD are identical. */
    sse_xmm_file(e);
    if (load) {
        if (insn->modrm_mod == 3U) {
            sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_q(b, 1U, SSE_ADDR, 0U);
        }
        sse_str_q(b, 1U, SSE_XMM_BASE, insn->modrm_reg & 7U);
    } else {
        sse_ldr_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
        if (insn->modrm_mod == 3U) {
            sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_str_q(b, 0U, SSE_ADDR, 0U);
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
        sse_xmm_file(e);
        sse_dst_load(e, insn);
        sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
        if (hi != 0U) {
            sse_ins_d_elt(b, 0U, 1U, 1U, 0U); /* MOVLHPS: d1 <- s0 */
        } else {
            sse_ins_d_elt(b, 0U, 0U, 1U, 1U); /* MOVHLPS: d0 <- s1 */
        }
        sse_dst_store(e, insn);
        return 0;
    }
    sse_xmm_file(e);
    if (load) {
        sse_dst_load(e, insn);
        sse_guest_addr(e, insn);
        sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        sse_ins_d_elt(b, 0U, hi != 0U ? 1U : 0U, 1U, 0U);
        sse_dst_store(e, insn);
    } else {
        sse_ldr_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
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
        sse_xmm_file(e);
        sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
        return 0;
    }

    if (insn->pfx_rep == 1U) {
        /* F3 0F 7E: MOVQ_xmm reg, xmm/m64; bits 127:64 zeroed. */
        sse_xmm_file(e);
        if (insn->modrm_mod == 3U) {
            sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        }
        sse_ins_d_elt(b, 0U, 0U, 1U, 0U);
        sse_ins_d_gpr(b, 0U, 1U, 31U); /* zero bits 127:64 */
        sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
        return 0;
    }

    /* 66 0F 7E: MOVD r/m32, xmm (low 32 of xmm). */
    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1; /* MMX store / F2 7E unlisted & undefined */
    }
    sse_xmm_file(e);
    sse_ldr_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
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
    sse_xmm_file(e);
    sse_dst_load(e, insn);
    sse_src_q(e, insn);
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
        /* PUNPCKHDQ: {d1,s1,d3,s3} — the HIGH dword of each 64-bit
         * half, i.e. lanes 1 and 3; composed with INS. */
        sse_ins_s_elt(b, 2U, 0U, 0U, 1U);
        sse_ins_s_elt(b, 2U, 1U, 1U, 1U);
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
    sse_dst_store(e, insn);
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
        sse_xmm_file(e);
        sse_src_q(e, insn);
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
        sse_xmm_file(e);
        sse_src_q(e, insn);
    }

    for (i = 0U; i < 4U; i++) {
        a64_emit_mov_imm32(b, SSE_W8 + i, idx[i]);
        sse_ins_s_gpr(b, 2U, i, SSE_W8 + i);
    }
    sse_tbl_16b(b, 0U, 1U, 2U);
    sse_xmm_file(e);
    sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
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
    sse_xmm_file(e);
    sse_dst_load(e, insn);
    sse_src_q(e, insn);
    switch (kind) {
    case 0U: sse_add_4s(b, 0U, 0U, 1U); break; /* PADDD  */
    case 1U: sse_add_2d(b, 0U, 0U, 1U); break; /* PADDQ  */
    case 2U: sse_sub_4s(b, 0U, 0U, 1U); break; /* PSUBD  */
    case 3U: sse_sub_2d(b, 0U, 0U, 1U); break; /* PSUBQ  */
    default: sse_mul_8h(b, 0U, 0U, 1U); break; /* PMULLW */
    }
    sse_dst_store(e, insn);
    return 0;
}

/* PMULUDQ (66 0F F4): q[i] = zext(d[2i]) * zext(s[2i]) via UZP1+UMLAL. */
static int sse_emit_pmuludq(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    sse_xmm_file(e);
    sse_dst_load(e, insn);
    sse_src_q(e, insn);
    sse_uzp1_4s(b, 2U, 0U, 0U); /* v2.2s = {d0, d2} */
    sse_uzp1_4s(b, 3U, 1U, 1U); /* v3.2s = {s0, s2} */
    sse_movi_v_zero(b, 4U);
    sse_umlal_2d_2s(b, 4U, 2U, 3U);
    sse_str_q(b, 4U, SSE_XMM_BASE, insn->modrm_reg & 7U);
    return 0;
}

/* PXOR/POR/PAND/PANDN (66) + ANDPS/ANDNPS/ORPS/XORPS (+66 = *PD).
 * kind: 0 xor, 1 or, 2 and, 3 andn (dest = ~dest & src). */
static int sse_emit_plogic(i686_emit_ctx_t *e, const x86_insn_t *insn,
                           unsigned kind)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_rep != 0U) {
        return -1; /* F2/F3 invalid on the logic rows */
    }
    sse_xmm_file(e);
    sse_dst_load(e, insn);
    sse_src_q(e, insn);
    switch (kind) {
    case 0U: sse_eor_16b(b, 0U, 0U, 1U); break;
    case 1U: sse_orr_16b(b, 0U, 0U, 1U); break;
    case 2U: sse_and_16b(b, 0U, 0U, 1U); break;
    default: sse_bic_16b(b, 0U, 1U, 0U); break; /* src & ~dest */
    }
    sse_dst_store(e, insn);
    return 0;
}

/* ADD/SUB/MUL/DIV PS/PD/SS/SD (kind: 0 add, 1 sub, 2 mul, 3 div). */
static int sse_emit_fparith(i686_emit_ctx_t *e, const x86_insn_t *insn,
                            unsigned kind)
{
    a64_buf_t *b = &e->buf;

    sse_xmm_file(e);
    sse_dst_load(e, insn);
    if (insn->pfx_rep == 0U && insn->pfx_opsize == 0U) { /* PS */
        sse_src_q(e, insn);
        sse_fp_vec(b, sse_fp_vec_s[kind], 0U, 0U, 1U);
    } else if (insn->pfx_rep == 0U) { /* PD */
        sse_src_q(e, insn);
        sse_fp_vec(b, sse_fp_vec_d[kind], 0U, 0U, 1U);
    } else if (insn->pfx_rep == 1U) { /* SS: result lane only */
        sse_src_s(e, insn);
        sse_fp_sca(b, sse_fp_sca_s[kind], 2U, 0U, 1U);
        sse_ins_s_elt(b, 0U, 0U, 2U, 0U);
    } else { /* SD */
        sse_src_d(e, insn);
        sse_fp_sca(b, sse_fp_sca_d[kind], 2U, 0U, 1U);
        sse_ins_d_elt(b, 0U, 0U, 2U, 0U);
    }
    sse_dst_store(e, insn);
    return 0;
}

/* CMPPS/SS/PD/SD imm8 predicates 0..7.  All predicates compose into
 * v2 (AND-chains for unord/ord); NOT forms invert v2.  The row forms
 * then move v2 into v0 whole; the scalar forms INS v2's low lane into
 * the dest, preserving its upper lanes.  NaN compares are false on
 * A64, so unord = !(eq & self-eq & src-eq) matches x86 exactly. */
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

    sse_xmm_file(e);
    sse_dst_load(e, insn);
    if (vec != 0U) {
        sse_src_q(e, insn);
    } else if (dbl != 0U) {
        sse_src_d(e, insn);
    } else {
        sse_src_s(e, insn);
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
    case 2U: /* le: !(dest > src) */
        if (dbl != 0U) {
            SSE_CMP1(sse_fcmgt_vd, sse_fcmgt_sd, 2U, 0U, 1U);
        } else {
            SSE_CMP1(sse_fcmgt_vs, sse_fcmgt_ss, 2U, 0U, 1U);
        }
        sse_mvn_16b(b, 2U, 2U);
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
    case 5U: /* nlt: dest >= src */
        if (dbl != 0U) {
            SSE_CMP1(sse_fcmge_vd, sse_fcmge_sd, 2U, 0U, 1U);
        } else {
            SSE_CMP1(sse_fcmge_vs, sse_fcmge_ss, 2U, 0U, 1U);
        }
        break;
    default: /* nle: dest > src */
        if (dbl != 0U) {
            SSE_CMP1(sse_fcmgt_vd, sse_fcmgt_sd, 2U, 0U, 1U);
        } else {
            SSE_CMP1(sse_fcmgt_vs, sse_fcmgt_ss, 2U, 0U, 1U);
        }
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
    sse_dst_store(e, insn);
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
    sse_xmm_file(e);
    sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
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
     * EFLAGS falls through silently, DEAD runs today's full sync.  The
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
    sse_xmm_file(e);
    sse_dst_load(e, insn);
    if (dbl != 0U) {
        sse_src_d(e, insn);
        sse_fcmp_d(b, 0U, 1U);
    } else {
        sse_src_s(e, insn);
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

    sse_xmm_file(e);
    sse_dst_load(e, insn);
    if (insn->pfx_rep == 1U) { /* CVTSI2SS: s0 = (f32)i32, upper kept */
        if (insn->modrm_mod == 3U) {
            a64_emit_mov_w(b, SSE_W8, i686_w(insn->modrm_rm));
        } else {
            sse_guest_addr(e, insn);
            a64_emit_ldr_imm_w(b, SSE_W8, SSE_ADDR, 0U);
        }
        sse_scvtf_s_w(b, 2U, SSE_W8);
        sse_ins_s_elt(b, 0U, 0U, 2U, 0U);
    } else if (insn->pfx_rep == 2U) { /* CVTSI2SD */
        if (insn->modrm_mod == 3U) {
            a64_emit_mov_w(b, SSE_W8, i686_w(insn->modrm_rm));
        } else {
            sse_guest_addr(e, insn);
            a64_emit_ldr_imm_w(b, SSE_W8, SSE_ADDR, 0U);
        }
        sse_scvtf_d_w(b, 2U, SSE_W8);
        sse_ins_d_elt(b, 0U, 0U, 2U, 0U);
    } else if (insn->pfx_opsize == 0U) { /* CVTPI2PS: 2 x s32 -> 2 f32 */
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
    sse_dst_store(e, insn);
    return 0;
}

/* CVTTPS2PI/CVTTSS2SI/CVTTSD2SI/CVTTPD2PI (0F 2C). */
static int sse_emit_cvttpi(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_rep == 1U) { /* CVTTSS2SI r32, m32/xmm */
        sse_xmm_file(e);
        sse_src_s(e, insn);
        sse_fcvtzs_w_s(b, i686_w(insn->modrm_reg), 1U);
        return 0;
    }
    if (insn->pfx_rep == 2U) { /* CVTTSD2SI r32, m64/xmm */
        sse_xmm_file(e);
        sse_src_d(e, insn);
        sse_fcvtzs_w_d(b, i686_w(insn->modrm_reg), 1U);
        return 0;
    }
    /* CVTTPS2PI mm, xmm/m64 (plain, MMX dest) and CVTTPD2PI (66, m128/
     * xmm src); MMX dest: tags -> valid. */
    if (insn->modrm_mod == 3U) {
        sse_xmm_file(e);
        sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
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

/* CVTPS2PD/CVTSS2SD/CVTSD2SS/CVTPD2PS (0F 5A). */
static int sse_emit_cvt_5a(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    sse_xmm_file(e);
    sse_dst_load(e, insn);
    if (insn->pfx_rep == 0U && insn->pfx_opsize == 0U) {
        /* CVTPS2PD: dest.2d = (double)src.s[0..1] */
        if (insn->modrm_mod == 3U) {
            sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_d(b, 1U, SSE_ADDR, 0U);
        }
        sse_fcvtl_2d(b, 0U, 1U);
    } else if (insn->pfx_rep == 0U) {
        /* CVTPD2PS: dest.s[0..1] = (float)src.d[0..1]; bits 127:64 = 0 */
        sse_src_q(e, insn);
        sse_fcvtn_2s(b, 2U, 1U);
        sse_ins_s_elt(b, 0U, 0U, 2U, 0U);
        sse_ins_s_elt(b, 0U, 1U, 2U, 1U);
        sse_ins_d_gpr(b, 0U, 1U, 31U);
    } else if (insn->pfx_rep == 1U) { /* CVTSS2SD */
        sse_src_s(e, insn);
        sse_fcvt_d_s(b, 2U, 1U);
        sse_ins_d_elt(b, 0U, 0U, 2U, 0U);
    } else { /* CVTSD2SS */
        sse_src_d(e, insn);
        sse_fcvt_s_d(b, 2U, 1U);
        sse_ins_s_elt(b, 0U, 0U, 2U, 0U);
    }
    sse_dst_store(e, insn);
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
    sse_xmm_file(e);
    sse_src_q(e, insn);
    if (insn->pfx_rep == 1U) {
        sse_fcvtzs_4s(b, 0U, 1U); /* CVTTPS2DQ (truncate) */
    } else if (insn->pfx_opsize != 0U) {
        sse_fcvtns_4s(b, 0U, 1U); /* CVTPS2DQ (nearest-even, v1) */
    } else {
        sse_scvtf_4s(b, 0U, 1U); /* CVTDQ2PS */
    }
    sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
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
 * only — same class as the documented v1 MOVAPS deviation).  Plain
 * (MMX MOVQ) and F2 decline to the D2 oracle. */
static int sse_emit_movdqa(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    int load = (insn->opnd[0] == I686_OPND_R32);

    if (insn->pfx_rep == 2U || insn->pfx_opsize == 0U) {
        return -1;
    }
    sse_xmm_file(e);
    if (load) {
        if (insn->modrm_mod == 3U) {
            sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
        } else {
            sse_guest_addr(e, insn);
            sse_ldr_q(b, 1U, SSE_ADDR, 0U);
        }
        sse_str_q(b, 1U, SSE_XMM_BASE, insn->modrm_reg & 7U);
    } else {
        sse_ldr_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
        if (insn->modrm_mod == 3U) {
            sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_rm & 7U);
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
        sse_xmm_file(e);
        sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
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
        sse_ins_d_elt(b, 0U, 0U, 1U, 0U);
        sse_ins_d_gpr(b, 0U, 1U, 31U); /* zero bits 127:64 */
        sse_xmm_file(e);
        sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
        return 0;
    }
    if (insn->pfx_opsize == 0U) {
        return -1; /* plain 0F D6 undefined x86 */
    }
    /* 66: MOVQ m64 <- xmm.d0.  Register destination: legacy MOVQ
     * CLEARS bits 127:64 of the dest (RC7b T2, oracle-verified). */
    sse_xmm_file(e);
    sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_reg & 7U);
    if (insn->modrm_mod == 3U) {
        sse_ins_d_elt(b, 0U, 0U, 1U, 0U);
        sse_ins_d_gpr(b, 0U, 1U, 31U); /* zero bits 127:64 */
        sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_rm & 7U);
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
    sse_xmm_file(e);
    sse_ldr_q(&e->buf, 0U, SSE_XMM_BASE, insn->modrm_reg & 7U);
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
    unsigned imm = insn->imm & 0xFFu;
    unsigned dig = insn->modrm_reg;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    if (dig == 3U) { /* PSRLDQ: out[j] = in[j+imm] */
        if (imm == 0U) {
            sse_src_q(e, insn);
            sse_mov_v_v(b, 0U, 1U);
        } else if (imm < 16U) {
            sse_src_q(e, insn);
            sse_movi_v_zero(b, 2U);
            sse_ext_16b(b, 0U, 2U, 1U, 16U - imm);
        } else {
            sse_movi_v_zero(b, 0U);
        }
    } else if (dig == 7U) { /* PSLLDQ: out[j] = in[j-imm] */
        if (imm == 0U) {
            sse_src_q(e, insn);
            sse_mov_v_v(b, 0U, 1U);
        } else if (imm < 16U) {
            sse_src_q(e, insn);
            sse_movi_v_zero(b, 2U);
            sse_ext_16b(b, 0U, 1U, 2U, imm);
        } else {
            sse_movi_v_zero(b, 0U);
        }
    } else {
        return -1; /* /2 /6 packed PSRLQ/PSLLQ and other digits:
                    * interpreter fallback (D2) */
    }
    sse_xmm_file(e);
    sse_str_q(b, 0U, SSE_XMM_BASE, insn->modrm_rm & 7U);
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
    sse_xmm_file(e);
    sse_dst_load(e, insn);
    sse_src_q(e, insn);
    switch (kind) {
    case 0U: sse_cmgt_16b(b, 0U, 0U, 1U); break; /* PCMPGTB: d > s */
    case 1U: sse_cmeq_16b(b, 0U, 0U, 1U); break; /* PCMPEQB */
    default: sse_cmeq_4s(b, 0U, 0U, 1U); break;  /* PCMPEQD */
    }
    sse_dst_store(e, insn);
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
    sse_xmm_file(e);
    sse_ldr_q(b, 1U, SSE_XMM_BASE, insn->modrm_rm & 7U);
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
    sse_xmm_file(e);
    sse_dst_load(e, insn);
    sse_src_q(e, insn);
    if (is_max != 0U) {
        sse_umax_16b(b, 0U, 0U, 1U);
    } else {
        sse_umin_16b(b, 0U, 0U, 1U);
    }
    sse_dst_store(e, insn);
    return 0;
}

/* PSUBB (0F F8): 66 form via SUB .16B; plain (MMX) and F2/F3 decline. */
static int sse_emit_psubb(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (insn->pfx_opsize == 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    sse_xmm_file(e);
    sse_dst_load(e, insn);
    sse_src_q(e, insn);
    sse_sub_16b(b, 0U, 0U, 1U);
    sse_dst_store(e, insn);
    return 0;
}

/* PREFETCHh (0F 18): hint with no architected effect — emit nothing.
 * 66/F2/F3 forms are undefined x86 (decline to the oracle's UNDEF). */
static int sse_emit_prefetch(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->pfx_opsize != 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    return 0;
}

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
    case I686_OP_SFENCE:
        /* 0F AE /7: store fence, no-op in the single-threaded TSO guest
         * model; the memory modrm forms are x86 #UD (D2 decline). */
        if (insn->modrm_mod != 3U) {
            return -1;
        }
        return 0;
    case I686_OP_CVTPI2PS:
        return sse_emit_cvtpi2(e, insn);
    case I686_OP_CVTTPS2PI:
        return sse_emit_cvttpi(e, insn);
    case I686_OP_COMISS:
    case I686_OP_UCOMISS:
        return sse_emit_comis(e, insn);
    case I686_OP_MOVMSKPS:
        return sse_emit_movmsk(e, insn);
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
        return sse_emit_plogic(e, insn, 2U);
    case I686_OP_PANDN:
        return sse_emit_plogic(e, insn, 3U);
    case I686_OP_POR:
        return sse_emit_plogic(e, insn, 1U);
    case I686_OP_PXOR:
        return sse_emit_plogic(e, insn, 0U);
    case I686_OP_CVTPS2PD:
        return sse_emit_cvt_5a(e, insn);
    case I686_OP_CVTDQ2PS:
        return sse_emit_cvt_5b(e, insn);
    case I686_OP_LDMXCSR:
        return sse_emit_mxcsr(e, insn, 0U);
    case I686_OP_STMXCSR:
        return sse_emit_mxcsr(e, insn, 1U);
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
        return -1;
    }
}
