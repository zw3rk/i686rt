/*
 * src/interp/h_sse_ext.c — remaining SSE/SSE2/MMX 0F opcodes (I686_OP7_SSEX)
 *
 * The generated opcode table leaves these bytes INVALID; the decoder maps
 * them to one synthetic id and parks the 0F byte in insn->far_sel.  Covers
 * SQRT/RSQRT/RCP, MIN/MAX, CVT(T)PS2PI/SD2SI, CVTDQ2PD/PD2DQ, packed
 * integer add/sub (saturating), average, multiply-high, multiply-add,
 * SAD, word/dword compares, packs, shifts, PINSRW/PEXTRW and MOVNTI.
 * Plain (no 66) forms are MMX; 66 selects the 128-bit XMM form.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "interp/h_sse_internal.h"

#define OP7_SSEX 474

static int host_rm(const i686_ctx_t *ctx, int trunc)
{
    if (trunc) {
        return FE_TOWARDZERO;
    }
    switch (sse_round_mode(ctx)) {
    case 1U: return FE_DOWNWARD;
    case 2U: return FE_UPWARD;
    case 3U: return FE_TOWARDZERO;
    default: return FE_TONEAREST;
    }
}

/* ------------------------------------------------------------------ */
/* Scalar float kernels                                                */
/* ------------------------------------------------------------------ */

static uint32_t minmax32(i686_ctx_t *ctx, uint32_t a, uint32_t b, int is_max)
{
    a = sse_f32_src(ctx, a);
    b = sse_f32_src(ctx, b);
    if (f32_nan(a) || f32_nan(b)) {
        ctx->mxcsr |= MXCSR_IE; /* NaN signals even when quiet; src2 wins */
        return b;
    }
    if (is_max) {
        return (f32_from(a) > f32_from(b)) ? a : b;
    }
    return (f32_from(a) < f32_from(b)) ? a : b;
}

static uint64_t minmax64(i686_ctx_t *ctx, uint64_t a, uint64_t b, int is_max)
{
    a = sse_f64_src(ctx, a);
    b = sse_f64_src(ctx, b);
    if (f64_nan(a) || f64_nan(b)) {
        ctx->mxcsr |= MXCSR_IE;
        return b;
    }
    if (is_max) {
        return (f64_from(a) > f64_from(b)) ? a : b;
    }
    return (f64_from(a) < f64_from(b)) ? a : b;
}

/* Unary kernels: result from the source lane only. */
static uint32_t unary32(i686_ctx_t *ctx, unsigned k, uint32_t b)
{
    float r;
    int saved = fegetround();

    b = sse_f32_src(ctx, b);
    if (f32_nan(b)) {
        if (f32_snan(b)) {
            ctx->mxcsr |= MXCSR_IE;
        }
        return f32_quiet(b);
    }
    if ((b & 0x7FFFFFFFu) == 0U) {
        return (k == 0x51U) ? b : ((b & 0x80000000u) | F32_POS_INF);
    }
    if ((b & 0x80000000u) != 0U && k != 0x53U) {
        ctx->mxcsr |= MXCSR_IE;
        return F32_QNAN_INDEF;
    }
    if (k == 0x51U) {
        volatile float v = f32_from(b);

        (void)fesetround(host_rm(ctx, 0));
        (void)feclearexcept(FE_ALL_EXCEPT);
        r = sqrtf(v);
        if (fetestexcept(FE_INEXACT) != 0) {
            ctx->mxcsr |= MXCSR_PE;
        }
        (void)fesetround(saved);
    } else if (k == 0x52U) {
        r = 1.0f / sqrtf(f32_from(b)); /* approximation is allowed */
    } else {
        r = 1.0f / f32_from(b);
    }
    return f32_bits(r);
}

static uint64_t unary64(i686_ctx_t *ctx, uint64_t b)
{
    double r;
    int saved = fegetround();

    b = sse_f64_src(ctx, b);
    if (f64_nan(b)) {
        if (f64_snan(b)) {
            ctx->mxcsr |= MXCSR_IE;
        }
        return f64_quiet(b);
    }
    if ((b & 0x7FFFFFFFFFFFFFFFull) == 0U) {
        return b;
    }
    if ((b & 0x8000000000000000ull) != 0U) {
        ctx->mxcsr |= MXCSR_IE;
        return F64_QNAN_INDEF;
    }
    {
        volatile double v = f64_from(b);

        (void)fesetround(host_rm(ctx, 0));
        (void)feclearexcept(FE_ALL_EXCEPT);
        r = sqrt(v);
        if (fetestexcept(FE_INEXACT) != 0) {
            ctx->mxcsr |= MXCSR_PE;
        }
        (void)fesetround(saved);
    }
    return f64_bits(r);
}

/* 51 sqrt, 52 rsqrt, 53 rcp (unary); 5D min, 5F max (binary). */
static int h_fp(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned k)
{
    uint8_t dst[16];
    uint8_t src[16];
    uint32_t mx_entry = sse_entry(ctx);
    int unary = (k == 0x51U || k == 0x52U || k == 0x53U);
    int is_max = (k == 0x5FU);
    unsigned i;

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->pfx_rep == 1U || insn->pfx_rep == 2U) {
        unsigned n = (insn->pfx_rep == 1U) ? 4U : 8U;

        if (insn->modrm_mod == 3U) {
            sse_get_xmm(ctx, insn->modrm_rm, src);
        } else {
            memset(src, 0, sizeof src);
            sse_ld(ctx, insn, src, n);
        }
        if (insn->pfx_rep == 1U) {
            uint32_t s = lane32(src, 0);
            set_lane32(dst, 0, unary ? unary32(ctx, k, s)
                                     : minmax32(ctx, lane32(dst, 0), s, is_max));
        } else {
            uint64_t s = lane64(src, 0);
            if (k == 0x52U || k == 0x53U) {
                return I686_EXIT_UNDEF;
            }
            set_lane64(dst, 0, unary ? unary64(ctx, s)
                                     : minmax64(ctx, lane64(dst, 0), s, is_max));
        }
    } else if (insn->pfx_66 != 0U) {
        if (k == 0x52U || k == 0x53U) {
            return I686_EXIT_UNDEF;
        }
        src128(ctx, insn, src);
        for (i = 0U; i < 2U; i++) {
            set_lane64(dst, i, unary ? unary64(ctx, lane64(src, i))
                                     : minmax64(ctx, lane64(dst, i),
                                                lane64(src, i), is_max));
        }
    } else {
        src128(ctx, insn, src);
        for (i = 0U; i < 4U; i++) {
            set_lane32(dst, i, unary ? unary32(ctx, k, lane32(src, i))
                                     : minmax32(ctx, lane32(dst, i),
                                                lane32(src, i), is_max));
        }
    }
    if (sse_xm_check(ctx, mx_entry) != I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT;
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done_nocheck(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Conversions                                                         */
/* ------------------------------------------------------------------ */

/* double -> int32 under the given rounding; indefinite on overflow/NaN. */
static int32_t d2i(i686_ctx_t *ctx, double v, int trunc)
{
    double r;
    int saved = fegetround();

    if (v != v || v >= 2147483648.0 || v <= -2147483649.0) {
        ctx->mxcsr |= MXCSR_IE;
        return INT32_MIN;
    }
    (void)fesetround(host_rm(ctx, trunc));
    r = nearbyint(v);
    (void)fesetround(saved);
    if (r >= 2147483648.0 || r < -2147483648.0) {
        ctx->mxcsr |= MXCSR_IE;
        return INT32_MIN;
    }
    if (r != v) {
        ctx->mxcsr |= MXCSR_PE;
    }
    return (int32_t)r;
}

static int h_cvt2d(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t mx_entry = sse_entry(ctx);
    uint8_t src[16];

    memset(src, 0, sizeof src);
    if (insn->pfx_rep == 1U || insn->pfx_rep == 2U) { /* CVTSS2SI / CVTSD2SI */
        double v;

        if (insn->modrm_mod == 3U) {
            sse_get_xmm(ctx, insn->modrm_rm, src);
        } else {
            sse_ld(ctx, insn, src, insn->pfx_rep == 1U ? 4U : 8U);
        }
        v = (insn->pfx_rep == 1U)
                ? (double)f32_from(sse_f32_src(ctx, lane32(src, 0)))
                : f64_from(sse_f64_src(ctx, lane64(src, 0)));
        {
            int32_t r = d2i(ctx, v, 0);

            if (sse_xm_check(ctx, mx_entry) != I686_INTERP_CONTINUE) {
                return I686_EXIT_FAULT;
            }
            ctx->gpr[insn->modrm_reg & 7U] = (uint32_t)r;
        }
    } else { /* CVTPS2PI / CVTPD2PI: mm <- 2 x int32 */
        uint32_t r0;
        uint32_t r1;

        if (insn->modrm_mod == 3U) {
            sse_get_xmm(ctx, insn->modrm_rm, src);
        } else if (insn->pfx_66 != 0U) {
            /* CVTPD2PI m128: the aligned 128-bit load faults #GP on a
             * misaligned address before any side effect. */
            sse_align16(ctx, insn);
            src128(ctx, insn, src);
        } else {
            sse_ld(ctx, insn, src, 8U);
        }
        if (insn->pfx_66 != 0U) {
            r0 = (uint32_t)d2i(ctx, f64_from(sse_f64_src(ctx, lane64(src, 0))), 0);
            r1 = (uint32_t)d2i(ctx, f64_from(sse_f64_src(ctx, lane64(src, 1))), 0);
        } else {
            r0 = (uint32_t)d2i(ctx, (double)f32_from(sse_f32_src(ctx, lane32(src, 0))), 0);
            r1 = (uint32_t)d2i(ctx, (double)f32_from(sse_f32_src(ctx, lane32(src, 1))), 0);
        }
        if (sse_xm_check(ctx, mx_entry) != I686_INTERP_CONTINUE) {
            return I686_EXIT_FAULT;
        }
        mm_wr(ctx, insn->modrm_reg, ((uint64_t)r1 << 32) | r0);
    }
    return sse_done_nocheck(ctx, insn);
}

/* E6: F3 CVTDQ2PD, F2 CVTPD2DQ, 66 CVTTPD2DQ. */
static int h_cvte6(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t mx_entry = sse_entry(ctx);
    uint8_t src[16];
    uint8_t dst[16];

    memset(dst, 0, sizeof dst);
    if (insn->pfx_rep == 1U) {
        int32_t a;
        int32_t b;

        if (insn->modrm_mod == 3U) {
            sse_get_xmm(ctx, insn->modrm_rm, src);
        } else {
            memset(src, 0, sizeof src);
            sse_ld(ctx, insn, src, 8);
        }
        a = (int32_t)lane32(src, 0);
        b = (int32_t)lane32(src, 1);
        set_lane64(dst, 0, f64_bits((double)a));
        set_lane64(dst, 1, f64_bits((double)b));
    } else if (insn->pfx_rep == 2U || insn->pfx_66 != 0U) {
        int trunc = (insn->pfx_rep == 0U);

        src128(ctx, insn, src);
        set_lane32(dst, 0, (uint32_t)d2i(ctx, f64_from(sse_f64_src(ctx, lane64(src, 0))), trunc));
        set_lane32(dst, 1, (uint32_t)d2i(ctx, f64_from(sse_f64_src(ctx, lane64(src, 1))), trunc));
    } else {
        return I686_EXIT_UNDEF;
    }
    if (sse_xm_check(ctx, mx_entry) != I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT;
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done_nocheck(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Packed integer                                                      */
/* ------------------------------------------------------------------ */

static int16_t rd16(const uint8_t *v, unsigned i)
{
    return (int16_t)((uint16_t)v[2U * i] | ((uint16_t)v[2U * i + 1U] << 8));
}

static void wr16(uint8_t *v, unsigned i, uint16_t x)
{
    v[2U * i] = (uint8_t)x;
    v[2U * i + 1U] = (uint8_t)(x >> 8);
}

static int32_t rd32(const uint8_t *v, unsigned i)
{
    return (int32_t)lane32(v, i);
}

static int sat_s(int v, int lo, int hi)
{
    return v < lo ? lo : (v > hi ? hi : v);
}

/* Byte-granular ops: FC paddb, D8/DC saturating unsigned, E0 pavgb, E8/EC signed. */
static void byte_op(unsigned k, uint8_t *d, const uint8_t *s, unsigned n)
{
    unsigned i;

    for (i = 0U; i < n; i++) {
        int a = d[i];
        int b = s[i];

        switch (k) {
        case 0xFCU: d[i] = (uint8_t)(a + b); break;
        case 0xD8U: d[i] = (uint8_t)sat_s(a - b, 0, 255); break;
        case 0xDCU: d[i] = (uint8_t)sat_s(a + b, 0, 255); break;
        case 0xE0U: d[i] = (uint8_t)((a + b + 1) >> 1); break;
        case 0xE8U: d[i] = (uint8_t)(int8_t)sat_s((int8_t)a - (int8_t)b, -128, 127); break;
        default:    d[i] = (uint8_t)(int8_t)sat_s((int8_t)a + (int8_t)b, -128, 127); break; /* EC */
        }
    }
}

/* Word-granular ops.  Returns 0 on a handled opcode, I686_EXIT_UNDEF
 * otherwise: unknown opcodes must never silently alias PCMPEQW. */
static int word_op(unsigned k, uint8_t *d, const uint8_t *s, unsigned n)
{
    unsigned i;

    for (i = 0U; i < n / 2U; i++) {
        int a = rd16(d, i);
        int b = rd16(s, i);
        int ua = (uint16_t)a;
        int ub = (uint16_t)b;
        uint16_t r;

        switch (k) {
        case 0xFDU: r = (uint16_t)(a + b); break;
        case 0xF9U: r = (uint16_t)(a - b); break;
        case 0xD9U: r = (uint16_t)sat_s(ua - ub, 0, 65535); break;
        case 0xDDU: r = (uint16_t)sat_s(ua + ub, 0, 65535); break;
        case 0xE3U: r = (uint16_t)((ua + ub + 1) >> 1); break;
        case 0xE4U: r = (uint16_t)(((uint32_t)ua * (uint32_t)ub) >> 16); break;
        case 0xE5U: r = (uint16_t)((a * b) >> 16); break;
        case 0xE9U: r = (uint16_t)sat_s(a - b, -32768, 32767); break;
        case 0xEDU: r = (uint16_t)sat_s(a + b, -32768, 32767); break;
        case 0xEAU: r = (uint16_t)(a < b ? a : b); break;
        case 0xEEU: r = (uint16_t)(a > b ? a : b); break;
        case 0x65U: r = (a > b) ? 0xFFFFu : 0U; break;
        case 0x75U: r = (a == b) ? 0xFFFFu : 0U; break;
        default: return I686_EXIT_UNDEF;
        }
        wr16(d, i, r);
    }
    return 0;
}

static int h_intop(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned k)
{
    uint8_t d[16];
    uint8_t s[16];
    uint8_t o[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_66 != 0U);
    unsigned n = xmm ? 16U : 8U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    memcpy(o, d, sizeof o);
    switch (k) {
    case 0xFCU: case 0xD8U: case 0xDCU: case 0xE0U: case 0xE8U: case 0xECU:
        byte_op(k, o, s, n);
        break;
    case 0xF5U: /* PMADDWD */
        for (i = 0U; i < n / 4U; i++) {
            int64_t v = (int64_t)rd16(d, 2U * i) * rd16(s, 2U * i) +
                        (int64_t)rd16(d, 2U * i + 1U) * rd16(s, 2U * i + 1U);
            set_lane32(o, i, (uint32_t)v);
        }
        break;
    case 0xF6U: /* PSADBW */
        for (i = 0U; i < n / 8U; i++) {
            unsigned sum = 0U;
            unsigned j;

            for (j = 0U; j < 8U; j++) {
                int df = (int)d[8U * i + j] - (int)s[8U * i + j];
                sum += (unsigned)(df < 0 ? -df : df);
            }
            set_lane64(o, i, sum);
        }
        break;
    case 0x66U: /* PCMPGTD */
        for (i = 0U; i < n / 4U; i++) {
            set_lane32(o, i, rd32(d, i) > rd32(s, i) ? 0xFFFFFFFFu : 0U);
        }
        break;
    case 0x63U: /* PACKSSWB: n bytes from n/2 words of each source */
        memset(o, 0, sizeof o);
        for (i = 0U; i < n; i++) {
            unsigned h = n / 2U;
            unsigned idx = i % h;
            const uint8_t *src = (i < h) ? d : s;
            o[i] = (uint8_t)(int8_t)sat_s(rd16(src, idx), -128, 127);
        }
        break;
    case 0x6BU: /* PACKSSDW: n/2 words from n/4 dwords of each source */
        memset(o, 0, sizeof o);
        for (i = 0U; i < n / 2U; i++) {
            unsigned h = n / 4U;
            unsigned idx = i % h;
            const uint8_t *src = (i < h) ? d : s;
            wr16(o, i, (uint16_t)sat_s(rd32(src, idx), -32768, 32767));
        }
        break;
    case 0xFDU: case 0xF9U: case 0xD9U: case 0xDDU: case 0xE3U:
    case 0xE4U: case 0xE5U: case 0xE9U: case 0xEDU: case 0xEAU:
    case 0xEEU: case 0x65U: case 0x75U:
        if (word_op(k, o, s, n) != 0) {
            return I686_EXIT_UNDEF;
        }
        break;
    default:
        return I686_EXIT_UNDEF;
    }
    int_vec_dst(ctx, insn, o, xmm);
    return sse_done_nocheck(ctx, insn);
}

/* Shift of every lane of `w` bits (16/32/64) by cnt; kind 0 srl, 1 sra, 2 sll. */
static void shift_lanes(uint8_t *v, unsigned n, unsigned w, uint64_t cnt,
                        unsigned kind)
{
    unsigned i;

    for (i = 0U; i < n * 8U / w; i++) {
        uint64_t x = 0U;
        uint64_t r;

        memcpy(&x, v + i * (w / 8U), w / 8U);
        if (kind == 1U) {
            int64_t sx = (w == 16U) ? (int16_t)x : (w == 32U) ? (int32_t)x : (int64_t)x;
            unsigned c = (cnt > w - 1U) ? w - 1U : (unsigned)cnt;
            r = (uint64_t)(sx >> c);
        } else if (cnt >= w) {
            r = 0U;
        } else {
            r = (kind == 0U) ? (x >> cnt) : (x << cnt);
        }
        memcpy(v + i * (w / 8U), &r, w / 8U);
    }
}

static int h_shift(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned k)
{
    uint8_t d[16];
    uint8_t s[16];
    int xmm = (insn->pfx_66 != 0U);
    unsigned n = xmm ? 16U : 8U;
    uint64_t cnt;
    unsigned w;
    unsigned kind;

    if (k == 0x71U || k == 0x72U) { /* group: /2 srl /4 sra /6 sll, Ib */
        unsigned r = insn->modrm_reg;

        if (insn->modrm_mod != 3U || (r != 2U && r != 4U && r != 6U)) {
            return I686_EXIT_UNDEF;
        }
        w = (k == 0x71U) ? 16U : 32U;
        kind = (r == 2U) ? 0U : (r == 4U) ? 1U : 2U;
        cnt = insn->imm & 0xFFU;
        if (xmm) {
            sse_get_xmm(ctx, insn->modrm_rm, d);
        } else {
            uint64_t m = mm_rd(ctx, insn->modrm_rm);
            memset(d, 0, sizeof d);
            memcpy(d, &m, 8);
        }
    } else { /* D1-D3 srl, E1-E2 sra, F1-F3 sll: count in src low qword */
        int_vec_src(ctx, insn, s, xmm);
        memcpy(&cnt, s, 8);
        int_vec_dst_fetch(ctx, insn, d, xmm);
        w = ((k & 3U) == 1U) ? 16U : ((k & 3U) == 2U) ? 32U : 64U;
        kind = (k >= 0xF1U) ? 2U : (k >= 0xE1U) ? 1U : 0U;
    }
    shift_lanes(d, n, w, cnt, kind);
    if (k == 0x71U || k == 0x72U) {
        if (xmm) {
            sse_set_xmm(ctx, insn->modrm_rm, d);
        } else {
            uint64_t m;
            memcpy(&m, d, 8);
            mm_wr(ctx, insn->modrm_rm, m);
        }
    } else {
        int_vec_dst(ctx, insn, d, xmm);
    }
    return sse_done_nocheck(ctx, insn);
}

/* C4 PINSRW, C5 PEXTRW, C3 MOVNTI. */
static int h_misc(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned k)
{
    uint8_t v[16];
    int xmm = (insn->pfx_66 != 0U);
    unsigned idx = insn->imm & (xmm ? 7U : 3U);

    if (k == 0xC3U) {
        if (insn->modrm_mod == 3U) {
            return I686_EXIT_UNDEF;
        }
        sse_st(ctx, insn, &ctx->gpr[insn->modrm_reg & 7U], 4);
    } else if (k == 0xC4U) {
        uint16_t w;

        if (insn->modrm_mod == 3U) {
            w = (uint16_t)ctx->gpr[insn->modrm_rm & 7U];
        } else {
            sse_ld(ctx, insn, &w, 2);
        }
        int_vec_dst_fetch(ctx, insn, v, xmm);
        wr16(v, idx, w);
        int_vec_dst(ctx, insn, v, xmm);
    } else {
        if (insn->modrm_mod != 3U) {
            return I686_EXIT_UNDEF;
        }
        if (xmm) {
            sse_get_xmm(ctx, insn->modrm_rm, v);
        } else {
            uint64_t m = mm_rd(ctx, insn->modrm_rm);
            memset(v, 0, sizeof v);
            memcpy(v, &m, 8);
        }
        ctx->gpr[insn->modrm_reg & 7U] = (uint16_t)rd16(v, idx);
    }
    return sse_done_nocheck(ctx, insn);
}

/* F7 MASKMOVQ/MASKMOVDQU: byte-masked store to DS:[EDI]. */
static int h_maskmov(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16];
    uint8_t m[16];
    int xmm = (insn->pfx_66 != 0U);
    unsigned n = xmm ? 16U : 8U;
    unsigned i;
    uint32_t ea = ctx->gpr[I686_REG_EDI];

    if (insn->modrm_mod != 3U) {
        return I686_EXIT_UNDEF;
    }
    int_vec_dst_fetch(ctx, insn, d, xmm);
    memset(m, 0, sizeof m);
    if (xmm) {
        sse_get_xmm(ctx, insn->modrm_rm, m);
    } else {
        uint64_t x = mm_rd(ctx, insn->modrm_rm);
        memcpy(m, &x, 8);
    }
    for (i = 0U; i < n; i++) {
        if ((m[i] & 0x80U) != 0U) {
            *(uint8_t *)i686_guest_ptr(ctx, ea + i) = d[i];
        }
    }
    return sse_done_nocheck(ctx, insn);
}

static int h_ssex(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned k = insn->far_sel & 0xFFU;

    switch (k) {
    case 0x51U: case 0x52U: case 0x53U: case 0x5DU: case 0x5FU:
        return h_fp(ctx, insn, k);
    case 0x2DU:
        return h_cvt2d(ctx, insn);
    case 0xE6U:
        return h_cvte6(ctx, insn);
    case 0x71U: case 0x72U: case 0xD1U: case 0xD2U: case 0xD3U:
    case 0xE1U: case 0xE2U: case 0xF1U: case 0xF2U: case 0xF3U:
        return h_shift(ctx, insn, k);
    case 0xC3U: case 0xC4U: case 0xC5U:
        return h_misc(ctx, insn, k);
    case 0xF7U:
        return h_maskmov(ctx, insn);
    /* Packed-integer ops (every 0F byte the decoder routes to SSEX):
     * byte, SAD, compare, pack and word forms.  Anything else is #UD,
     * never a silent PCMPEQW. */
    case 0xFCU: case 0xD8U: case 0xDCU: case 0xE0U: case 0xE8U: case 0xECU:
    case 0xF5U: case 0xF6U: case 0x66U: case 0x63U: case 0x6BU:
    case 0xFDU: case 0xF9U: case 0xD9U: case 0xDDU: case 0xE3U:
    case 0xE4U: case 0xE5U: case 0xE9U: case 0xEDU: case 0xEAU:
    case 0xEEU: case 0x65U: case 0x75U:
        return h_intop(ctx, insn, k);
    default:
        return I686_EXIT_UNDEF;
    }
}

void i686_interp_sse_ext_init(void)
{
    i686_interp_register(OP7_SSEX, h_ssex);
}
