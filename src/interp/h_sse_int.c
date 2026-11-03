/*
 * src/interp/h_sse_int.c — SSE2/MMX packed integer, shuffle, and MXCSR handlers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>

#include "interp/h_sse_internal.h"

/* ------------------------------------------------------------------ */
/* Comparisons                                                         */
/* ------------------------------------------------------------------ */

static int cmp_eval(i686_ctx_t *ctx, uint64_t a, uint64_t b, unsigned pred,
                    int wide)
{
    int unord, lt, eq;
    uint32_t a32;
    uint32_t b32;

    if (wide != 0) {
        a = sse_f64_src(ctx, a);
        b = sse_f64_src(ctx, b);
    } else {
        a = sse_f32_src(ctx, (uint32_t)(a & 0xFFFFFFFFu));
        b = sse_f32_src(ctx, (uint32_t)(b & 0xFFFFFFFFu));
    }
    a32 = (uint32_t)(a & 0xFFFFFFFFu);
    b32 = (uint32_t)(b & 0xFFFFFFFFu);

    if (wide == 0 ? (f32_nan(a32) || f32_nan(b32)) : (f64_nan(a) || f64_nan(b))) {
        int sn = wide == 0 ? (f32_snan(a32) || f32_snan(b32))
                           : (f64_snan(a) || f64_snan(b));
        if (pred <= 2U || sn) {
            ctx->mxcsr |= MXCSR_IE;
        }
        unord = 1;
        lt = 0;
        eq = 0;
    } else {
        double da = wide ? f64_from(a) : (double)f32_from(a32);
        double db = wide ? f64_from(b) : (double)f32_from(b32);
        unord = 0;
        eq = da == db;
        lt = da < db;
    }

    switch (pred) {
    case 0U: return eq;
    case 1U: return lt;
    case 2U: return lt || eq;
    case 3U: return unord;
    case 4U: return !eq;
    case 5U: return !lt;
    case 6U: return !(lt || eq);
    default: return !unord;
    }
}

static int h_cmpps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t dst[16];
    unsigned pred = insn->imm & 7U;

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->pfx_rep == 1U) {
        uint32_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane32(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 4);
        }
        set_lane32(dst, 0, cmp_eval(ctx, lane32(dst, 0), s, pred, 0)
                             ? 0xFFFFFFFFu : 0U);
    } else if (insn->pfx_rep == 2U) {
        uint64_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane64(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 8);
        }
        set_lane64(dst, 0, cmp_eval(ctx, lane64(dst, 0), s, pred, 1)
                             ? 0xFFFFFFFFFFFFFFFFull : 0U);
    } else if (insn->pfx_opsize != 0U) {
        uint8_t src[16];
        unsigned i;
        src128(ctx, insn, src);
        for (i = 0U; i < 2U; i++) {
            set_lane64(dst, i, cmp_eval(ctx, lane64(dst, i), lane64(src, i),
                                        pred, 1)
                                  ? 0xFFFFFFFFFFFFFFFFull : 0U);
        }
    } else {
        uint8_t src[16];
        unsigned i;
        src128(ctx, insn, src);
        for (i = 0U; i < 4U; i++) {
            set_lane32(dst, i, cmp_eval(ctx, lane32(dst, i), lane32(src, i),
                                        pred, 0)
                                  ? 0xFFFFFFFFu : 0U);
        }
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

static void comis_flags(i686_ctx_t *ctx, unsigned kind)
{
    i686_flags_materialize(ctx);
    ctx->eflags &= ~(I686_EF_CF | I686_EF_ZF | I686_EF_PF | I686_EF_OF |
                     I686_EF_SF | I686_EF_AF);
    if (kind == 1U) {
        ctx->eflags |= I686_EF_ZF;
    } else if (kind == 2U) {
        ctx->eflags |= I686_EF_CF;
    } else if (kind == 3U) {
        ctx->eflags |= I686_EF_CF | I686_EF_ZF | I686_EF_PF;
    }
    ctx->lazy_op = I686_FOP_NONE;
}

static int h_comis(i686_ctx_t *ctx, const x86_insn_t *insn, int signaling)
{
    int wide = (insn->pfx_opsize != 0U);

    if (wide) {
        uint8_t src[16];
        uint64_t a, b;
        sse_get_xmm(ctx, insn->modrm_reg, src);
        a = lane64(src, 0);
        if (insn->modrm_mod == 3U) {
            sse_get_xmm(ctx, insn->modrm_rm, src);
            b = lane64(src, 0);
        } else {
            sse_ld(ctx, insn, &b, 8);
        }
        a = sse_f64_src(ctx, a);
        b = sse_f64_src(ctx, b);
        if (f64_nan(a) || f64_nan(b)) {
            if (signaling || f64_snan(a) || f64_snan(b)) {
                ctx->mxcsr |= MXCSR_IE;
            }
            comis_flags(ctx, 3U);
        } else {
            double da = f64_from(a), db = f64_from(b);
            comis_flags(ctx, da < db ? 2U : (da == db ? 1U : 0U));
        }
        return sse_done(ctx, insn);
    }
    {
        uint8_t src[16];
        uint32_t a, b;
        sse_get_xmm(ctx, insn->modrm_reg, src);
        a = lane32(src, 0);
        if (insn->modrm_mod == 3U) {
            sse_get_xmm(ctx, insn->modrm_rm, src);
            b = lane32(src, 0);
        } else {
            sse_ld(ctx, insn, &b, 4);
        }
        a = sse_f32_src(ctx, a);
        b = sse_f32_src(ctx, b);
        if (f32_nan(a) || f32_nan(b)) {
            if (signaling || f32_snan(a) || f32_snan(b)) {
                ctx->mxcsr |= MXCSR_IE;
            }
            comis_flags(ctx, 3U);
        } else {
            double da = (double)f32_from(a), db = (double)f32_from(b);
            comis_flags(ctx, da < db ? 2U : (da == db ? 1U : 0U));
        }
        return sse_done(ctx, insn);
    }
}

static int h_comiss(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_comis(ctx, insn, 1); }
static int h_ucomiss(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_comis(ctx, insn, 0); }

static int h_movmskps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t src[16];
    uint32_t r = 0U;

    if (insn->modrm_mod != 3U) {
        return I686_EXIT_UNDEF;
    }
    sse_get_xmm(ctx, insn->modrm_rm, src);
    if (insn->pfx_opsize != 0U) {
        r = (uint32_t)((lane64(src, 0) >> 63) | ((lane64(src, 1) >> 62) & 2U));
    } else {
        unsigned i;
        for (i = 0U; i < 4U; i++) {
            r |= (lane32(src, i) >> 31) << i;
        }
    }
    ctx->gpr[insn->modrm_reg & 7U] = r;
    return sse_done(ctx, insn);
}

/* PADDD / PSUBD (also MMX plain forms). */
static int h_paddd(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 4U : 2U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        uint32_t a, b, r;
        memcpy(&a, d + 4U * i, 4);
        memcpy(&b, s + 4U * i, 4);
        r = a + b;
        memcpy(d + 4U * i, &r, 4);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_psubd(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 4U : 2U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        uint32_t a, b, r;
        memcpy(&a, d + 4U * i, 4);
        memcpy(&b, s + 4U * i, 4);
        r = a - b;
        memcpy(d + 4U * i, &r, 4);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

/* PADDQ / PSUBQ: 64-bit lanes. */
static int h_pq(i686_ctx_t *ctx, const x86_insn_t *insn, int sub)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 2U : 1U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        uint64_t a, b, r;
        memcpy(&a, d + 8U * i, 8);
        memcpy(&b, s + 8U * i, 8);
        r = sub ? a - b : a + b;
        memcpy(d + 8U * i, &r, 8);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_paddq(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_pq(ctx, insn, 0); }
static int h_psubq(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_pq(ctx, insn, 1); }

/* PMULLW: 8/4 lanes of signed 16-bit multiply, low 16 bits kept. */
static int h_pmullw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 8U : 4U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        int32_t a = (int16_t)(d[2U * i] | ((uint16_t)d[2U * i + 1U] << 8));
        int32_t b = (int16_t)(s[2U * i] | ((uint16_t)s[2U * i + 1U] << 8));
        uint16_t r = (uint16_t)(a * b);
        d[2U * i] = (uint8_t)r;
        d[2U * i + 1U] = (uint8_t)(r >> 8);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

/* PMULUDQ: even 32-bit lanes -> 64-bit unsigned products. */
static int h_pmuludq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 2U : 1U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        uint32_t a, b;
        uint64_t r;
        memcpy(&a, d + 8U * i, 4);
        memcpy(&b, s + 8U * i, 4);
        r = (uint64_t)a * (uint64_t)b;
        memcpy(d + 8U * i, &r, 8);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

/* PUNPCKL/H BW/WD/DQ (+LQDQ/HQDQ, 66 only) */
static int h_punpck(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned esize,
                    int high)
{
    uint8_t d[16], s[16], out[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned per = xmm ? 16U : 8U;
    unsigned n = per / esize;
    unsigned take = n / 2U;
    unsigned base = high ? per / 2U : 0U;
    unsigned j;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    memset(out, 0, sizeof out);
    for (j = 0U; j < take; j++) {
        memcpy(out + esize * (2U * j), d + base + esize * j, esize);
        memcpy(out + esize * (2U * j + 1U), s + base + esize * j, esize);
    }
    int_vec_dst(ctx, insn, out, xmm);
    return sse_done(ctx, insn);
}

static int h_punpcklbw(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_punpck(ctx, insn, 1, 0); }
static int h_punpcklwd(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_punpck(ctx, insn, 2, 0); }
static int h_punpckldq(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_punpck(ctx, insn, 4, 0); }
static int h_punpckhbw(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_punpck(ctx, insn, 1, 1); }
static int h_punpckhwd(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_punpck(ctx, insn, 2, 1); }
static int h_punpckhdq(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_punpck(ctx, insn, 4, 1); }
static int h_punpcklqdq(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_punpck(ctx, insn, 8, 0); }
static int h_punpckhqdq(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_punpck(ctx, insn, 8, 1); }

static int h_pshufw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16], out[16];
    int xmm = int_vec_src(ctx, insn, s,
                          insn->pfx_opsize != 0U || insn->pfx_rep != 0U);
    unsigned imm = insn->imm & 0xFFu;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    memset(out, 0, sizeof out);

    if (insn->pfx_opsize != 0U) {
        unsigned j;
        for (j = 0U; j < 4U; j++) {
            unsigned sel = (imm >> (2U * j)) & 3U;
            memcpy(out + 4U * j, s + 4U * sel, 4);
        }
    } else if (insn->pfx_rep == 2U) {
        unsigned j;
        for (j = 0U; j < 4U; j++) {
            unsigned sel = (imm >> (2U * j)) & 3U;
            out[2U * j] = s[2U * sel];
            out[2U * j + 1U] = s[2U * sel + 1U];
        }
        memcpy(out + 8, s + 8, 8);
    } else if (insn->pfx_rep == 1U) {
        unsigned j;
        memcpy(out, s, 8);
        for (j = 4U; j < 8U; j++) {
            unsigned sel = (imm >> (2U * (j - 4U))) & 3U;
            out[2U * j] = s[2U * (4U + sel)];
            out[2U * j + 1U] = s[2U * (4U + sel) + 1U];
        }
    } else {
        unsigned j;
        for (j = 0U; j < 4U; j++) {
            unsigned sel = (imm >> (2U * j)) & 3U;
            out[2U * j] = s[2U * sel];
            out[2U * j + 1U] = s[2U * sel + 1U];
        }
    }
    int_vec_dst(ctx, insn, out, xmm);
    return sse_done(ctx, insn);
}

static int h_movdqa(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t buf[16];

    if (insn->pfx_rep == 2U) {
        return I686_EXIT_UNDEF;
    }
    if (insn->pfx_opsize == 0U && insn->pfx_rep == 0U) {
        uint64_t v;
        if (load) {
            if (insn->modrm_mod == 3U) {
                v = mm_rd(ctx, insn->modrm_rm);
            } else {
                sse_ld(ctx, insn, &v, 8);
            }
            mm_wr(ctx, insn->modrm_reg, v);
        } else {
            v = mm_rd(ctx, insn->modrm_reg);
            if (insn->modrm_mod == 3U) {
                mm_wr(ctx, insn->modrm_rm, v);
            } else {
                sse_st(ctx, insn, &v, 8);
            }
        }
        return sse_done(ctx, insn);
    }
    if (load) {
        src128(ctx, insn, buf);
        sse_set_xmm(ctx, insn->modrm_reg, buf);
    } else {
        sse_get_xmm(ctx, insn->modrm_reg, buf);
        if (insn->modrm_mod == 3U) {
            sse_set_xmm(ctx, insn->modrm_rm, buf);
        } else {
            sse_st(ctx, insn, buf, 16);
        }
    }
    return sse_done(ctx, insn);
}

static int h_movq2dq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t src[16];
    uint64_t v;

    if (insn->pfx_opsize != 0U) {
        sse_get_xmm(ctx, insn->modrm_reg, src);
        memcpy(&v, src, 8);
        if (insn->modrm_mod == 3U) {
            uint8_t dst[16];
            memset(dst, 0, sizeof dst);
            memcpy(dst, &v, 8);
            sse_set_xmm(ctx, insn->modrm_rm, dst);
        } else {
            sse_st(ctx, insn, &v, 8);
        }
    } else if (insn->pfx_rep == 2U) {
        if (insn->modrm_mod != 3U) {
            return I686_EXIT_UNDEF;
        }
        sse_get_xmm(ctx, insn->modrm_rm, src);
        memcpy(&v, src, 8);
        mm_wr(ctx, insn->modrm_reg, v);
    } else if (insn->pfx_rep == 1U) {
        uint8_t x[16];
        v = mm_rd(ctx, insn->modrm_rm);
        memset(x, 0, sizeof x);
        memcpy(x, &v, 8);
        sse_set_xmm(ctx, insn->modrm_reg, x);
    } else {
        return I686_EXIT_UNDEF;
    }
    return sse_done(ctx, insn);
}

static int h_movntdq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->pfx_rep != 0U || insn->modrm_mod == 3U) {
        return I686_EXIT_UNDEF;
    }
    if (insn->pfx_opsize != 0U) {
        uint8_t buf[16];
        sse_get_xmm(ctx, insn->modrm_reg, buf);
        sse_st(ctx, insn, buf, 16);
    } else {
        uint64_t v = mm_rd(ctx, insn->modrm_reg);
        sse_st(ctx, insn, &v, 8);
    }
    return sse_done(ctx, insn);
}

static int h_pshiftdq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned imm = insn->imm & 0xFFu;
    unsigned dig = insn->modrm_reg;

    if (insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    if (insn->pfx_opsize != 0U) {
        uint8_t s[16], out[16];
        if (dig != 2U && dig != 3U && dig != 6U && dig != 7U) {
            return I686_EXIT_UNDEF;
        }
        src128(ctx, insn, s);
        memset(out, 0, sizeof out);
        if (dig == 3U) {
            if (imm < 16U) {
                memcpy(out, s + imm, 16U - imm);
            }
        } else if (dig == 7U) {
            if (imm < 16U) {
                memcpy(out + imm, s, 16U - imm);
            }
        } else {
            uint64_t lo = lane64(s, 0);
            uint64_t hi = lane64(s, 1);
            unsigned cnt = imm & 63U;
            if (cnt != 0U) {
                if (dig == 2U) {
                    lo >>= cnt;
                    hi >>= cnt;
                } else {
                    lo <<= cnt;
                    hi <<= cnt;
                }
            }
            set_lane64(out, 0, lo);
            set_lane64(out, 1, hi);
        }
        sse_set_xmm(ctx, insn->modrm_rm, out);
    } else {
        uint64_t v;
        unsigned cnt;
        if (dig != 2U && dig != 6U) {
            return I686_EXIT_UNDEF;
        }
        if (insn->modrm_mod == 3U) {
            v = mm_rd(ctx, insn->modrm_rm);
        } else {
            sse_ld(ctx, insn, &v, 8);
        }
        cnt = imm & 63U;
        if (cnt != 0U) {
            v = (dig == 2U) ? (v >> cnt) : (v << cnt);
        }
        mm_wr(ctx, insn->modrm_rm, v);
    }
    return sse_done(ctx, insn);
}

typedef enum { PCMP_GT8 = 0, PCMP_EQ8, PCMP_EQ32 } pcmp_kind;

static int h_pcmp(i686_ctx_t *ctx, const x86_insn_t *insn, pcmp_kind k)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 16U : 8U;
    unsigned esz = (k == PCMP_EQ32) ? 4U : 1U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i += esz) {
        int t;
        if (k == PCMP_GT8) {
            t = (int8_t)d[i] > (int8_t)s[i];
        } else if (esz == 4U) {
            t = lane32(d, i / 4U) == lane32(s, i / 4U);
        } else {
            t = d[i] == s[i];
        }
        memset(d + i, t ? 0xFF : 0x00, esz);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_pcmp_gt8(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_pcmp(ctx, insn, PCMP_GT8); }
static int h_pcmp_eq8(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_pcmp(ctx, insn, PCMP_EQ8); }
static int h_pcmp_eq32(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_pcmp(ctx, insn, PCMP_EQ32); }

static int h_pmovmskb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t src[16];
    uint32_t r = 0U;
    unsigned n, i;

    if (insn->modrm_mod != 3U || insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    if (insn->pfx_opsize != 0U) {
        sse_get_xmm(ctx, insn->modrm_rm, src);
        n = 16U;
    } else {
        uint64_t m = mm_rd(ctx, insn->modrm_rm);
        memset(src, 0, sizeof src);
        memcpy(src, &m, 8);
        n = 8U;
    }
    for (i = 0U; i < n; i++) {
        r |= (uint32_t)(src[i] >> 7) << i;
    }
    ctx->gpr[insn->modrm_reg & 7U] = r;
    return sse_done(ctx, insn);
}

static int h_pminmaxub(i686_ctx_t *ctx, const x86_insn_t *insn, int is_max)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 16U : 8U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        d[i] = (is_max ? (d[i] > s[i]) : (d[i] < s[i])) ? d[i] : s[i];
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_pminub(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_pminmaxub(ctx, insn, 0); }
static int h_pmaxub(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_pminmaxub(ctx, insn, 1); }

static int h_psubb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 16U : 8U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        d[i] = (uint8_t)(d[i] - s[i]);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_prefetch(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->pfx_opsize != 0U || insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    return sse_done(ctx, insn);
}

static int h_sfence(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U) {
        return I686_EXIT_UNDEF;
    }
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    return sse_done(ctx, insn);
}

static int h_ldmxcsr(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v;

    if (insn->modrm_mod == 3U) {
        return I686_EXIT_UNDEF;
    }
    sse_ld(ctx, insn, &v, 4);
    /* I686-R5-2: reserved MXCSR bits set -> #GP (guest SIGSEGV) without
     * modifying MXCSR or advancing EIP. */
    if ((v & ~0xFFFFu) != 0U) {
        return I686_EXIT_FAULT;
    }
    sse_set_mxcsr(ctx, v);
    return sse_done(ctx, insn);
}

static int h_stmxcsr(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v;

    if (insn->modrm_mod == 3U) {
        return I686_EXIT_UNDEF;
    }
    v = sse_get_mxcsr(ctx);
    sse_st(ctx, insn, &v, 4);
    return sse_done(ctx, insn);
}

static int h_emms(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->ftag = 0xFFFFu;
    return sse_done(ctx, insn);
}

static int h_unpckps(i686_ctx_t *ctx, const x86_insn_t *insn, int hi)
{
    uint8_t d[16], s[16], out[16];
    if (insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    sse_get_xmm(ctx, insn->modrm_reg, d);
    src128(ctx, insn, s);
    if (insn->pfx_opsize != 0U) {
        unsigned off = hi ? 8U : 0U;
        memcpy(out + 0, d + off, 8);
        memcpy(out + 8, s + off, 8);
    } else {
        unsigned off = hi ? 8U : 0U;
        memcpy(out + 0,  d + off + 0, 4);
        memcpy(out + 4,  s + off + 0, 4);
        memcpy(out + 8,  d + off + 4, 4);
        memcpy(out + 12, s + off + 4, 4);
    }
    sse_set_xmm(ctx, insn->modrm_reg, out);
    return sse_done(ctx, insn);
}

static int h_unpcklps(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_unpckps(ctx, insn, 0); }
static int h_unpckhps(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_unpckps(ctx, insn, 1); }

static int h_packuswb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16], out[16];
    int xmm;
    unsigned half, i;

    if (insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    int_vec_dst_fetch(ctx, insn, d, xmm);
    half = xmm ? 8U : 4U;
    memset(out, 0, sizeof out);
    for (i = 0U; i < half; i++) {
        int16_t w0 = (int16_t)((uint16_t)d[2U * i] | ((uint16_t)d[2U * i + 1U] << 8));
        int16_t w1 = (int16_t)((uint16_t)s[2U * i] | ((uint16_t)s[2U * i + 1U] << 8));
        out[i]        = (w0 < 0) ? 0U : ((w0 > 255) ? 255U : (uint8_t)w0);
        out[half + i] = (w1 < 0) ? 0U : ((w1 > 255) ? 255U : (uint8_t)w1);
    }
    int_vec_dst(ctx, insn, out, xmm);
    return sse_done(ctx, insn);
}

static int h_shufps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16], out[16];
    unsigned imm = insn->imm & 0xFFu;

    if (insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    sse_get_xmm(ctx, insn->modrm_reg, d);
    src128(ctx, insn, s);
    if (insn->pfx_opsize != 0U) {
        memcpy(out + 0, d + 8U * ((imm >> 0) & 1U), 8);
        memcpy(out + 8, s + 8U * ((imm >> 1) & 1U), 8);
    } else {
        memcpy(out + 0,  d + 4U * ((imm >> 0) & 3U), 4);
        memcpy(out + 4,  d + 4U * ((imm >> 2) & 3U), 4);
        memcpy(out + 8,  s + 4U * ((imm >> 4) & 3U), 4);
        memcpy(out + 12, s + 4U * ((imm >> 6) & 3U), 4);
    }
    sse_set_xmm(ctx, insn->modrm_reg, out);
    return sse_done(ctx, insn);
}

void i686_interp_sse_int_init(void)
{
    i686_interp_register(I686_OP_UCOMISS, h_ucomiss);
    i686_interp_register(I686_OP_COMISS, h_comiss);
    i686_interp_register(I686_OP_MOVMSKPS, h_movmskps);
    i686_interp_register(I686_OP_CMPPS, h_cmpps);
    i686_interp_register(I686_OP_PUNPCKLBW, h_punpcklbw);
    i686_interp_register(I686_OP_PUNPCKLWD, h_punpcklwd);
    i686_interp_register(I686_OP_PUNPCKLDQ, h_punpckldq);
    i686_interp_register(I686_OP_PUNPCKHBW, h_punpckhbw);
    i686_interp_register(I686_OP_PUNPCKHWD, h_punpckhwd);
    i686_interp_register(I686_OP_PUNPCKHDQ, h_punpckhdq);
    i686_interp_register(I686_OP_PUNPCKLQDQ, h_punpcklqdq);
    i686_interp_register(I686_OP_PUNPCKHQDQ, h_punpckhqdq);
    i686_interp_register(I686_OP_PSHUFW, h_pshufw);
    i686_interp_register(I686_OP_PADDQ, h_paddq);
    i686_interp_register(I686_OP_PMULLW, h_pmullw);
    i686_interp_register(I686_OP_PMULUDQ, h_pmuludq);
    i686_interp_register(I686_OP_PSUBD, h_psubd);
    i686_interp_register(I686_OP_PSUBQ, h_psubq);
    i686_interp_register(I686_OP_PADDD, h_paddd);
    i686_interp_register(I686_OP_MOVDQA, h_movdqa);
    i686_interp_register(I686_OP_MOVQ2DQ, h_movq2dq);
    i686_interp_register(I686_OP_MOVNTDQ, h_movntdq);
    i686_interp_register(I686_OP_PSRLDQ, h_pshiftdq);
    i686_interp_register(I686_OP_PCMPGTB, h_pcmp_gt8);
    i686_interp_register(I686_OP_PCMPEQB, h_pcmp_eq8);
    i686_interp_register(I686_OP_PCMPEQD, h_pcmp_eq32);
    i686_interp_register(I686_OP_PMOVMSKB, h_pmovmskb);
    i686_interp_register(I686_OP_PMINUB, h_pminub);
    i686_interp_register(I686_OP_PMAXUB, h_pmaxub);
    i686_interp_register(I686_OP_PSUBB, h_psubb);
    i686_interp_register(I686_OP_PREFETCH, h_prefetch);
    i686_interp_register(I686_OP_SFENCE, h_sfence);
    i686_interp_register(I686_OP_LDMXCSR, h_ldmxcsr);
    i686_interp_register(I686_OP_STMXCSR, h_stmxcsr);
    i686_interp_register(I686_OP_EMMS, h_emms);
    i686_interp_register(470 /* UNPCKLPS/PD */, h_unpcklps);
    i686_interp_register(471 /* UNPCKHPS/PD */, h_unpckhps);
    i686_interp_register(472 /* PACKUSWB */, h_packuswb);
    i686_interp_register(473 /* SHUFPS/PD */, h_shufps);
}
