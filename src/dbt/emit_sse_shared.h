/*
 * src/dbt/emit_sse_shared.h — shared SSE/SSE2 emission core (Phase 5 lane L5a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split out of src/dbt/emit_sse.c in Lane P13-6 for the <= 900-line file
 * discipline. Holds every raw AArch64 encoder, the ctx-file staging
 * helpers and the Lane P13-6 write-through XMM register cache; the two
 * emitter files (emit_sse.c: moves/logic/arithmetic, emit_sse2.c:
 * compares/converts/misc) include this header and own only their
 * per-family emitters plus their dispatch half.
 *
 * XMM cache protocol (Lane P13-6): xmm0..xmm7 map 1-to-1 onto v16..v23.
 * Bit reg of e->xmm_valid set means v(16+reg) holds ctx->xmm[reg] (a full
 * 128-bit copy). Reads (sse_q/d/s_ldr) hit in 1 instruction with 0 memory
 * loads and 0 address ADDs; misses fill v(16+reg) from ctx->xmm[reg] and
 * set the bit. Writes (sse_q/d/s_str, sse_zero_d/s_str) always store
 * through to ctx->xmm[reg] in memory first, so ctx->xmm[] is coherent on
 * faults, signals, FXSAVE and helper exits, then update v(16+reg).
 * The mask clears at block entry (i686_emit_begin memset, which also
 * covers FXRSTOR: unemittable insns always end the block), after the
 * sse_flags_sync C helper call, and after the branch flags-sync helper
 * call (both BLRs can clobber caller-saved v16..v23 mid-block).
 *
 * Scratch inside one insn (D7, unchanged): v0 = dest value, v1 = src
 * value, v2/v3 = temps, v4 = result temp; w8..w12 integer scratch;
 * x9 = &xmm[0], x10 = &x87_st[0], w21/x21 = EA, x23 = guest address.
 * Every raw A64 word below was verified against a reference assembly
 * listing; shared encoders come from src/rt32/rt32_a64_emit.h.
 *
 * Known v1 deviations (Phase H per SPEC D10/sse.h, documented): MXCSR
 * rounding is not mapped into FPCR (default NEON rounding); FTZ/DAZ
 * arithmetic and out-of-range scalar CVTTSS2SI/CVTTSD2SI take the D2
 * interpret-one path instead (exact flags and 0x80000000), while
 * packed CVTT* NaN/overflow still produce NEON saturation instead of
 * x86's integer indefinite 0x80000000.  SSE memory ops stay plain
 * LDR/STR Q in TSO mode (x86 SSE non-atomic stores need TSO ordering
 * only for LOCK RMW, owned by the atomic module).  MMX-writing insns
 * set the x87 tag word to valid (0x0000) and EMMS sets it empty
 * (0xFFFF); fstat.TOP and the x87_st payload otherwise stay untouched.
 */

#ifndef I686RT_DBT_EMIT_SSE_SHARED_H
#define I686RT_DBT_EMIT_SSE_SHARED_H

#include <stdint.h>

#include "dbt/emit.h"

/* ---- ctx access bases (recomputed per insn; 0x108 is 8 mod 16) ---- */

/* ADD Xd, Xn, #imm12 (64-bit, imm12 = byte offset). */
static inline void sse_add_x_imm12(a64_buf_t *b, unsigned rd, unsigned rn,
                                   uint32_t imm12)
{
    a64_emit(b, 0x91000000U | ((imm12 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

#define SSE_XMM_BASE 9U   /* x9  = x19 + 0x108 = &ctx->xmm[0]   */
#define SSE_MMX_BASE 10U  /* x10 = x19 + 0x88  = &x87_st[0] */
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

static inline void sse_ldr_q(a64_buf_t *b, unsigned vt, unsigned rn,
                             uint32_t off16)
{
    a64_emit(b, 0x3DC00000U | ((off16 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static inline void sse_str_q(a64_buf_t *b, unsigned vt, unsigned rn,
                             uint32_t off16)
{
    a64_emit(b, 0x3D800000U | ((off16 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static inline void sse_ldr_d(a64_buf_t *b, unsigned vt, unsigned rn,
                             uint32_t off8)
{
    a64_emit(b, 0xFD400000U | ((off8 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static inline void sse_str_d(a64_buf_t *b, unsigned vt, unsigned rn,
                             uint32_t off8)
{
    a64_emit(b, 0xFD000000U | ((off8 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static inline void sse_ldr_s(a64_buf_t *b, unsigned vt, unsigned rn,
                             uint32_t off4)
{
    a64_emit(b, 0xBD400000U | ((off4 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

static inline void sse_str_s(a64_buf_t *b, unsigned vt, unsigned rn,
                             uint32_t off4)
{
    a64_emit(b, 0xBD000000U | ((off4 & 0xFFFU) << 10) | ((rn & 31U) << 5) |
                     (vt & 31U));
}

/* INS (general): Vd.S[i] <- Wn / Vd.D[i] <- Xn (31 = zeroing). */
static inline void sse_ins_s_gpr(a64_buf_t *b, unsigned vd, unsigned i,
                                 unsigned wn)
{
    a64_emit(b, 0x4E001C00U | ((4U + 8U * (i & 3U)) << 16) |
                     ((wn & 31U) << 5) | (vd & 31U));
}

static inline void sse_ins_d_gpr(a64_buf_t *b, unsigned vd, unsigned i,
                                 unsigned xn)
{
    a64_emit(b, 0x4E001C00U | ((8U + 16U * (i & 1U)) << 16) |
                     ((xn & 31U) << 5) | (vd & 31U));
}

/* INS (element), source lane 0..3 (S) / 0..1 (D): the src index rides
 * the imm4 field — si<<13 (S) or si<<14 (D); imm5 = 4+8*di / 8+16*di. */
static inline void sse_ins_s_elt(a64_buf_t *b, unsigned vd, unsigned di,
                                 unsigned vn, unsigned si)
{
    a64_emit(b, 0x6E000400U | ((4U + 8U * (di & 3U)) << 16) |
                     ((si & 3U) << 13) | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_ins_d_elt(a64_buf_t *b, unsigned vd, unsigned di,
                                 unsigned vn, unsigned si)
{
    a64_emit(b, 0x6E000400U | ((8U + 16U * (di & 1U)) << 16) |
                     ((si & 1U) << 14) | ((vn & 31U) << 5) | (vd & 31U));
}

/* FMOV scalars across the GPR/NEON boundary. */
static inline void sse_fmov_d_from_x(a64_buf_t *b, unsigned vd, unsigned xn)
{
    a64_emit(b, 0x9E670000U | ((xn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fmov_w_from_s(a64_buf_t *b, unsigned wd, unsigned vn)
{
    a64_emit(b, 0x1E260000U | ((vn & 31U) << 5) | (wd & 31U));
}

static inline void sse_fmov_d_d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    /* FMOV Dd, Dn (scalar lane copy; zeroes the upper 64 of Qd). */
    a64_emit(b, 0x1E604000U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fmov_s_s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    /* FMOV Sd, Sn (scalar lane copy; zeroes the upper 96 of Qd). */
    a64_emit(b, 0x1E204000U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_movi_v_zero(a64_buf_t *b, unsigned vd)
{
    /* MOVI Vd.16B, #0 */
    a64_emit(b, 0x4F00E400U | (vd & 31U));
}

static inline void sse_mov_v_v(a64_buf_t *b, unsigned vd, unsigned vn)
{
    /* MOV Vd.16B, Vn.16B (ORR Vd.16B, Vn.16B, Vn.16B) */
    a64_emit(b, 0x4EA01C00U | ((vn & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_zip1_4s(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x4E803800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

/* ZIP1/ZIP2 bytewise and halfword (PUNPCK BW/WD families). */
static inline void sse_zip1_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x4E003800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_zip2_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x4E007800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_zip1_8h(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x4E403800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_zip2_8h(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x4E407800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_tbl_16b(a64_buf_t *b, unsigned vd, unsigned vtab,
                               unsigned vid)
{
    /* TBL Vd.16B, {Vtab.16B}, Vid.16B */
    a64_emit(b, 0x4E001000U | ((vid & 31U) << 16) | ((vtab & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_tbl_8b(a64_buf_t *b, unsigned vd, unsigned vtab,
                              unsigned vid)
{
    /* TBL Vd.8B, {Vtab.16B}, Vid.8B (upper 64 of Vd zeroed) */
    a64_emit(b, 0x0E001000U | ((vid & 31U) << 16) | ((vtab & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_uzp1_4s(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x4E801800U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_eor_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x6E201C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_orr_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x4EA01C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_and_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x4E201C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_bic_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    /* BIC Vd, Vn, Vm = Vn & ~Vm (PANDN/ANDNPS: dest = src & ~dest) */
    a64_emit(b, 0x4E601C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_mvn_16b(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x6E205800U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_add_4s(a64_buf_t *b, unsigned vd, unsigned vn,
                              unsigned vm)
{
    a64_emit(b, 0x4EA08400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_add_2d(a64_buf_t *b, unsigned vd, unsigned vn,
                              unsigned vm)
{
    a64_emit(b, 0x4EE08400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_sub_4s(a64_buf_t *b, unsigned vd, unsigned vn,
                              unsigned vm)
{
    a64_emit(b, 0x6EA08400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_sub_2d(a64_buf_t *b, unsigned vd, unsigned vn,
                              unsigned vm)
{
    a64_emit(b, 0x6EE08400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_mul_8h(a64_buf_t *b, unsigned vd, unsigned vn,
                              unsigned vm)
{
    a64_emit(b, 0x4E609C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_umlal_2d_2s(a64_buf_t *b, unsigned vd, unsigned vn,
                                   unsigned vm)
{
    /* UMLAL Vd.2D, Vn.2S, Vm.2S (32->64; size bits set) */
    a64_emit(b, 0x2EA08000U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_ushr_4s_31(a64_buf_t *b, unsigned vd, unsigned vn)
{
    /* USHR Vd.4S, Vn.4S, #31: logical shift leaves 0/1 lanes (SSHR
     * would sign-extend to 0xFFFFFFFF). */
    a64_emit(b, 0x6F210400U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_ushr_2d_63(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x6F410400U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_umov_d(a64_buf_t *b, unsigned xd, unsigned vn,
                              unsigned i)
{
    /* UMOV Xd, Vn.D[i]: imm5 field (bits 20:16) = 8 + 16*i */
    a64_emit(b, 0x4E083C00U | ((8U + 16U * (i & 1U)) << 16) |
                     ((vn & 31U) << 5) | (xd & 31U));
}

static inline void sse_umov_s(a64_buf_t *b, unsigned wd, unsigned vn,
                              unsigned i)
{
    /* UMOV Wd, Vn.S[i]: imm5 field (bits 20:16) = 4 + 8*i */
    a64_emit(b, 0x0E043C00U | ((4U + 8U * (i & 3U)) << 16) |
                     ((vn & 31U) << 5) | (wd & 31U));
}

/* FP arithmetic bases (op order add/sub/mul/div mirrors the dispatch
 * table). The per-width tables live in emit_sse.c next to their only
 * user (sse_emit_fparith). */
static inline void sse_fp_vec(a64_buf_t *b, uint32_t base, unsigned vd,
                              unsigned vn, unsigned vm)
{
    a64_emit(b, base | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fp_sca(a64_buf_t *b, uint32_t base, unsigned vd,
                              unsigned vn, unsigned vm)
{
    a64_emit(b, base | ((vm & 31U) << 16) | ((vn & 31U) << 5) | (vd & 31U));
}

/* Compares (all-ones/all-zeros masks; NaN comparisons are false, which
 * drives the unord/ord composition below). */
static inline void sse_fcmeq_vs(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x4E20E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmeq_vd(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x4E60E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmgt_vs(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x6EA0E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmgt_vd(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x6EE0E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmge_vs(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x6E20E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmge_vd(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x6E60E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmeq_ss(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x5E20E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmeq_sd(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x5E60E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmgt_ss(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x7EA0E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmgt_sd(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x7EE0E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmge_ss(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x7E20E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmge_sd(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x7E60E400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_fcmp_s(a64_buf_t *b, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x1E202000U | ((vm & 31U) << 16) | ((vn & 31U) << 5));
}

static inline void sse_fcmp_d(a64_buf_t *b, unsigned vn, unsigned vm)
{
    a64_emit(b, 0x1E602000U | ((vm & 31U) << 16) | ((vn & 31U) << 5));
}

/* Converts. */
static inline void sse_scvtf_2s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0E21D800U | ((vn & 31U) << 5) | (vd & 31U));
}

/* SSHLL Vd.2D, Vn.2S, #0: widen two s32 lanes to s64 (feeds SCVTF for
 * CVTPI2PD -- A64 has no widening vector int-to-fp convert). */
static inline void sse_sshll_2d_0(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0F20A400U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_scvtf_2d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E61D800U | ((vn & 31U) << 5) | (vd & 31U));
}

/* FCVTZS Vd.2D, Vn.2D then XTN Vd.2S, Vd.2D narrows doubles to two
 * s32 (CVTTPD2PI; see the v1 saturation deviation note above). */
static inline void sse_fcvtzs_2d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4EE1B800U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_xtn_2s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0EA12800U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_scvtf_4s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E21D800U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_scvtf_s_w(a64_buf_t *b, unsigned vd, unsigned wn)
{
    a64_emit(b, 0x1E220000U | ((wn & 31U) << 5) | (vd & 31U));
}

static inline void sse_scvtf_d_w(a64_buf_t *b, unsigned vd, unsigned wn)
{
    a64_emit(b, 0x1E620000U | ((wn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fcvtzs_2s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0EA1B800U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fcvtzs_4s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4EA1B800U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fcvtzs_w_s(a64_buf_t *b, unsigned wd, unsigned vn)
{
    a64_emit(b, 0x1E380000U | ((vn & 31U) << 5) | (wd & 31U));
}

static inline void sse_fcvtzs_w_d(a64_buf_t *b, unsigned wd, unsigned vn)
{
    a64_emit(b, 0x1E780000U | ((vn & 31U) << 5) | (wd & 31U));
}

static inline void sse_fcvt_d_s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x1E22C000U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fcvt_s_d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x1E624000U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fcvtl_2d(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0E617800U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fcvtn_2s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x0E616800U | ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_fcvtns_4s(a64_buf_t *b, unsigned vd, unsigned vn)
{
    a64_emit(b, 0x4E21A800U | ((vn & 31U) << 5) | (vd & 31U));
}

/* AND Wd, Wn, #0xFFFF (LDMXCSR reserved-bit mask; N=0 immr=0 imms=15). */
static inline void sse_and_ffff(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x12000000U | (15U << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

/* EOR w11, w11, #1 (fixed operands; COMISS CF = !C_a64 | V). */
static inline void sse_eor_w11_1(a64_buf_t *b)
{
    a64_emit(b, 0x5200016BU);
}

/* ---- RC7b T1 raw SIMD words (verified against the cross assembler) -- */

/* EXT Vd.16B, Vn.16B, Vm.16B, #imm4: result[j] = concat(Vn:Vm)[j+imm4]
 * (whole-register byte shifts against a zero temp). */
static inline void sse_ext_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm, unsigned imm4)
{
    a64_emit(b, 0x6E001800U | ((imm4 & 15U) << 11) | ((vm & 31U) << 16) |
                     ((vn & 31U) << 5) | (vd & 31U));
}

static inline void sse_cmeq_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x6E208C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_cmeq_4s(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x6EA08C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_cmgt_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x4E203400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_umin_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x6E206C00U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_umax_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                                unsigned vm)
{
    a64_emit(b, 0x6E206400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

static inline void sse_sub_16b(a64_buf_t *b, unsigned vd, unsigned vn,
                               unsigned vm)
{
    a64_emit(b, 0x6E208400U | ((vm & 31U) << 16) | ((vn & 31U) << 5) |
                     (vd & 31U));
}

/* UMOV Wd, Vn.B[i]: imm5 = 2i+1 (bit 0 selects the B element size). */
static inline void sse_umov_b(a64_buf_t *b, unsigned wd, unsigned vn,
                              unsigned i)
{
    a64_emit(b, 0x0E003C00U | (((2U * (i & 15U)) + 1U) << 16) |
                     ((vn & 31U) << 5) | (wd & 31U));
}

/* ---- operand staging ------------------------------------------------ */

/* x9 = &ctx->xmm[0]; scaled Q accesses use 16*reg. */
static inline void sse_xmm_file(i686_emit_ctx_t *e)
{
    sse_add_x_imm12(&e->buf, SSE_XMM_BASE, A64_XCTX, 0x108U);
}

/* x10 = &ctx->x87_st[0] (MMX alias file; D accesses use 2*reg). */
static inline void sse_mmx_file(i686_emit_ctx_t *e)
{
    sse_add_x_imm12(&e->buf, SSE_MMX_BASE, A64_XCTX, 0x88U);
}

/* Guest EA into x23 = xG + uxtw(w21) via the frozen i686_emit_ea. */
static inline void sse_guest_addr(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    i686_emit_ea(e, insn, 1);
    a64_emit_add_uxtw_x(&e->buf, SSE_ADDR, A64_XG, 21U);
}

/* 64-bit source into v1 (MMX reg or m64); upper 64 of v1 irrelevant. */
static inline void sse_src_d_mmx(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        sse_ldr_d(&e->buf, 1U, SSE_MMX_BASE, 2U * (insn->modrm_rm & 7U));
    } else {
        sse_guest_addr(e, insn);
        sse_ldr_d(&e->buf, 1U, SSE_ADDR, 0U);
    }
}

/* MMX writes mark the x87 tag word valid (Intel MMX rule). */
static inline void sse_mmx_tags_valid(i686_emit_ctx_t *e)
{
    a64_emit_strh_imm_w(&e->buf, 31U, A64_XCTX, 0x18CU);
}

/* ---- Lane P13-6 write-through XMM register cache ----------------------
 * xmm0..xmm7 map 1-to-1 onto v16..v23 (bit reg of e->xmm_valid set means
 * v(16+reg) holds ctx->xmm[reg]). All helpers take the XMM index
 * (0..7, already masked by the caller) and a scratch vector (v0..v4).
 *
 * Reads hit in 1 instruction with 0 memory loads and 0 address ADDs;
 * misses emit the x9 base ADD, fill v(16+reg) from ctx->xmm[reg], set
 * the valid bit, and copy into the destination. Scalar reads copy only
 * the low lane (callers consume lane 0 only; verified per call site).
 *
 * Writes store through to ctx->xmm[reg] first (memory always coherent)
 * and then update v(16+reg): full 128-bit writes ORR the whole register
 * in; scalar writes INS the low lane, preserving the cached upper lanes
 * (on a miss the slot is filled from memory first); zeroing writes
 * (MOVQ, memory MOVSD/MOVSS) FMOV the lane, which zeroes the upper lanes
 * of the slot architecturally. */

/* Full 128-bit XMM source into Vd. */
static inline void sse_q_ldr(i686_emit_ctx_t *e, unsigned vd, unsigned reg)
{
    if ((e->xmm_valid & (uint8_t)(1u << reg)) != 0u) {
        sse_mov_v_v(&e->buf, vd, 16u + reg);
    } else {
        sse_xmm_file(e);
        sse_ldr_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
        e->xmm_valid |= (uint8_t)(1u << reg);
        if (vd != 16u + reg)
            sse_mov_v_v(&e->buf, vd, 16u + reg);
    }
}

/* 64-bit scalar XMM source low lane into Dd. */
static inline void sse_d_ldr(i686_emit_ctx_t *e, unsigned dd, unsigned reg)
{
    if ((e->xmm_valid & (uint8_t)(1u << reg)) == 0u) {
        sse_xmm_file(e);
        sse_ldr_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
        e->xmm_valid |= (uint8_t)(1u << reg);
    }
    sse_fmov_d_d(&e->buf, dd, 16u + reg);
}

/* 32-bit scalar XMM source low lane into Sd. */
static inline void sse_s_ldr(i686_emit_ctx_t *e, unsigned sd, unsigned reg)
{
    if ((e->xmm_valid & (uint8_t)(1u << reg)) == 0u) {
        sse_xmm_file(e);
        sse_ldr_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
        e->xmm_valid |= (uint8_t)(1u << reg);
    }
    sse_fmov_s_s(&e->buf, sd, 16u + reg);
}

/* Full 128-bit XMM write from Vs, write-through to memory. */
static inline void sse_q_str(i686_emit_ctx_t *e, unsigned reg, unsigned vs)
{
    sse_xmm_file(e);
    sse_str_q(&e->buf, vs, SSE_XMM_BASE, reg);
    sse_mov_v_v(&e->buf, 16u + reg, vs);
    e->xmm_valid |= (uint8_t)(1u << reg);
}

/* Scalar 64-bit XMM write from Vs.D[0], preserving the upper 64 bits. */
static inline void sse_d_str(i686_emit_ctx_t *e, unsigned reg, unsigned vs)
{
    sse_xmm_file(e);
    if ((e->xmm_valid & (uint8_t)(1u << reg)) == 0u) {
        sse_ldr_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
        e->xmm_valid |= (uint8_t)(1u << reg);
    }
    /* INS V(16+reg).D[0], Vs.D[0] (0x6E080400, assembler-verified). */
    a64_emit(&e->buf, 0x6E080400U | ((vs & 31U) << 5) | ((16u + reg) & 31U));
    sse_str_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
}

/* Scalar 32-bit XMM write from Vs.S[0], preserving the upper 96 bits. */
static inline void sse_s_str(i686_emit_ctx_t *e, unsigned reg, unsigned vs)
{
    sse_xmm_file(e);
    if ((e->xmm_valid & (uint8_t)(1u << reg)) == 0u) {
        sse_ldr_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
        e->xmm_valid |= (uint8_t)(1u << reg);
    }
    /* INS V(16+reg).S[0], Vs.S[0] (0x6E040400, assembler-verified). */
    a64_emit(&e->buf, 0x6E040400U | ((vs & 31U) << 5) | ((16u + reg) & 31U));
    sse_str_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
}

/* Scalar 64-bit XMM write from Vs.D[0] that zeroes the upper 64 bits
 * (MOVQ, memory MOVSD). */
static inline void sse_zero_d_str(i686_emit_ctx_t *e, unsigned reg,
                                  unsigned vs)
{
    sse_fmov_d_d(&e->buf, 16u + reg, vs);
    e->xmm_valid |= (uint8_t)(1u << reg);
    sse_xmm_file(e);
    sse_str_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
}

/* Scalar 32-bit XMM write from Vs.S[0] that zeroes the upper 96 bits
 * (memory MOVSS). */
static inline void sse_zero_s_str(i686_emit_ctx_t *e, unsigned reg,
                                  unsigned vs)
{
    sse_fmov_s_s(&e->buf, 16u + reg, vs);
    e->xmm_valid |= (uint8_t)(1u << reg);
    sse_xmm_file(e);
    sse_str_q(&e->buf, 16u + reg, SSE_XMM_BASE, reg);
}

/* ---- pending-flags materialization (COMIS family) ------------------ */

/* Call i686_dbt_flags_sync(ctx) with the GPR park/reload dance, so the
 * eflags read-modify-write below sees architecturally current bits even
 * when a same-block ALU insn left a lazy descriptor (S3 seam).  Mirrors
 * emit_branch.c's helper-call sequence exactly. */
static inline void sse_flags_sync(i686_emit_ctx_t *e)
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
    /* The BLR can clobber caller-saved v16..v23: the XMM cache dies here
     * (operands load after this call, repopulating it). */
    e->xmm_valid = 0u;
}

#endif /* I686RT_DBT_EMIT_SSE_SHARED_H */
