/*
 * src/interp/x87.c — x87 state-core accessors (Phase 5 L5c, SPEC D9)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements every function of the frozen src/interp/x87.h for BOTH
 * storage modes (fixed per process via ctx->x87_80):
 *  - default: ST(i) keeps an IEEE binary64 in the low 8 bytes of the
 *    physical slot; the upper bytes stay zero.
 *  - --x87-80: ST(i) keeps the exact 10-byte x87 extended encoding
 *    (8-byte mantissa with explicit integer bit, then sign+biased
 *    exponent, little-endian).
 *
 * This TU is deliberately SELF-CONTAINED: it performs no softfloat
 * arithmetic and never calls src/interp/x87_80.c, so FP-state consumers
 * (signal frames, fxsave) link without the extended core.  All
 * conversions are exact bit math except ext80->f64, which rounds to
 * nearest-even; the RC-aware integer conversions use host libm only on
 * the default-mode double path (the interpreter never changes the host
 * FE rounding mode, so it stays nearest-even as C11 requires).
 *
 * Tag-word convention (v1): ctx->ftag is LIVE state in x86 2-bit-per-
 * physical-register packing (0 valid, 1 zero, 2 special, 3 empty).
 * x87_set_f64/x87_set_ext80 classify the written slot; push/pop mark
 * the pushed/popped slot; x87_sync_tag re-derives every non-empty
 * slot's class from the stored bits (fxsave/fnstenv boundaries).
 */

#include <math.h>
#include <string.h>

#include "interp/x87.h"

/* --- little-endian byte helpers ---------------------------------------- */

static uint64_t rd64(const uint8_t *p)
{
    uint64_t v = 0;

    for (unsigned i = 0; i < 8; i++) {
        v |= (uint64_t)p[i] << (8U * i);
    }
    return v;
}

static void wr64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8U * i));
    }
}

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
}

/* --- register-stack state ---------------------------------------------- */

uint8_t x87_top(const i686_ctx_t *ctx)
{
    return (uint8_t)(ctx->x87_top & 7U);
}

void x87_set_top(i686_ctx_t *ctx, uint8_t top)
{
    ctx->x87_top = top & 7U;
    x87_update_fstat(ctx);
}

void x87_push(i686_ctx_t *ctx)
{
    ctx->x87_top = (ctx->x87_top + 7U) & 7U;
    x87_update_fstat(ctx);
}

/* Pop frees the popped physical slot (hardware frees ST(0) on pop). */
void x87_pop(i686_ctx_t *ctx)
{
    uint8_t t = x87_top(ctx);
    unsigned shift = (unsigned)t * 2U;

    ctx->ftag |= (uint16_t)(3U << shift); /* tag = empty */
    ctx->x87_top = ((unsigned)t + 1U) & 7U;
    x87_update_fstat(ctx);
}

static unsigned phys_of(const i686_ctx_t *ctx, unsigned i)
{
    return ((unsigned)x87_top(ctx) + i) & 7U;
}

/* --- tag helpers -------------------------------------------------------- */

/* 0 valid, 1 zero, 2 special (NaN/Inf), 3 empty. */
static unsigned tag_of(const i686_ctx_t *ctx, unsigned phys)
{
    return (ctx->ftag >> (phys * 2U)) & 3U;
}

static void set_tag(i686_ctx_t *ctx, unsigned phys, unsigned val)
{
    unsigned shift = phys * 2U;

    ctx->ftag = (uint16_t)((ctx->ftag & ~(3U << shift)) | (val << shift));
}

/* Pure value classification of a stored slot (0 valid, 1 zero, 2 special);
 * emptiness lives only in the tag word. */
static unsigned classify(const i686_ctx_t *ctx, unsigned phys)
{
    if (ctx->x87_80) {
        uint16_t se = rd16(&ctx->x87_st[phys][8]);
        unsigned e = se & 0x7fffU;
        uint64_t m = rd64(&ctx->x87_st[phys][0]);

        if (e == 0x7fffU) {
            return 2U; /* NaN / Inf */
        }
        if (e == 0U && m == 0U) {
            return 1U;
        }
        return 0U;
    }
    {
        uint64_t bits = rd64(&ctx->x87_st[phys][0]);
        unsigned e = (unsigned)((bits >> 52) & 0x7ffU);

        if (e == 0x7ffU) {
            return 2U;
        }
        if (e == 0U && (bits & 0x000fffffffffffffULL) == 0U) {
            return 1U;
        }
        return 0U;
    }
}

void x87_sync_tag(i686_ctx_t *ctx)
{
    for (unsigned p = 0; p < 8; p++) {
        if (tag_of(ctx, p) == 3U) {
            continue; /* empty stays empty */
        }
        set_tag(ctx, p, classify(ctx, p));
    }
}

void x87_mark_empty(i686_ctx_t *ctx, unsigned i)
{
    set_tag(ctx, phys_of(ctx, i), 3U);
}

/* --- m80 <-> m64 conversion helpers ------------------------------------ */

void x87_f64_to_ext80(double v, uint8_t out[10])
{
    uint64_t bits;
    uint64_t m;
    uint16_t se;
    unsigned sign;
    unsigned be;

    memcpy(&bits, &v, 8);
    sign = (unsigned)(bits >> 63);
    be = (unsigned)((bits >> 52) & 0x7ffU);
    {
        uint64_t frac = bits & 0x000fffffffffffffULL;

        if (be == 0x7ffU) {
            /* Infinity / NaN: x87 keeps the explicit integer bit set and
             * the payload shifted into the low mantissa bits (quiet bit
             * of binary64 (bit 51) lands on ext80 bit 62). */
            m = (frac == 0U) ? 0x8000000000000000ULL
                             : ((1ULL << 63) | (frac << 11));
            se = 0x7fffU;
        } else if (be == 0U && frac == 0U) {
            m = 0;
            se = 0;
        } else {
            int unb;

            if (be == 0U) {
                /* binary64 subnormal: normalize the 52-bit fraction. */
                unb = -1022;
                while ((frac & (1ULL << 51)) == 0U) {
                    frac <<= 1;
                    unb--;
                }
                m = frac << 12; /* 1.f to bit 63 */
            } else {
                unb = (int)be - 1023;
                m = (1ULL << 63) | (frac << 11);
            }
            se = (uint16_t)((int)unb + 16383); /* fits: unb in [-1074,1023] */
        }
    }
    wr64(out, m);
    wr16(&out[8], (uint16_t)((sign << 15) | se));
}

double x87_ext80_to_f64(const uint8_t in[10])
{
    uint64_t m = rd64(in);
    uint16_t se = rd16(&in[8]);
    unsigned sign = se >> 15;
    unsigned e = se & 0x7fffU;
    uint64_t out_bits;

    if (e == 0x7fffU) {
        if (m == 0x8000000000000000ULL) {
            out_bits = 0x7ff0000000000000ULL; /* infinity */
        } else {
            /* NaN: shift payload down and force quiet (bit 51). */
            uint64_t q = (m >> 11) & 0x000fffffffffffffULL;

            out_bits = 0x7ff0000000000000ULL | q | (1ULL << 51);
        }
    } else if (m == 0U) {
        out_bits = 0;
    } else {
        int eff = (e == 0U) ? -16382 : (int)e - 16383;

        while ((m & (1ULL << 63)) == 0U) {
            m <<= 1;
            eff--;
        }
        if (eff > 1023) {
            out_bits = 0x7ff0000000000000ULL; /* overflow -> inf */
        } else if (eff >= -1022) {
            uint64_t kept = m >> 11; /* 53 significant bits (bit 52 .. 0) */
            uint64_t dropped = m & 0x7ffU;

            if (dropped > 0x400U || (dropped == 0x400U && (kept & 1U) != 0U)) {
                kept++;
            }
            {
                int de = eff + 1023; /* 1..2046 */

                if (kept == (1ULL << 53)) {
                    kept >>= 1;
                    de++;
                }
                if (de > 2046) {
                    out_bits = 0x7ff0000000000000ULL;
                } else {
                    out_bits = ((uint64_t)de << 52) |
                               (kept & 0x000fffffffffffffULL);
                }
            }
        } else {
            /* binary64 subnormal / underflow: value = m / 2^total units
             * of 2^-1074, rounded to nearest-even. */
            int total = -eff - 1011; /* >= 12 */

            if (total >= 65) {
                out_bits = 0;
            } else if (total == 64) {
                out_bits = (m > (1ULL << 63)) ? 1ULL : 0ULL;
            } else {
                uint64_t q = m >> (unsigned)total;
                uint64_t r = m & (((uint64_t)1 << total) - 1U);
                uint64_t half = (uint64_t)1 << (total - 1);

                if (r > half || (r == half && (q & 1U) != 0U)) {
                    q++;
                }
                out_bits = (q == (1ULL << 52)) ? (1ULL << 52) : q;
            }
        }
    }
    out_bits |= (uint64_t)sign << 63;
    {
        double d;

        memcpy(&d, &out_bits, 8);
        return d;
    }
}

/* --- mode-aware ST access ----------------------------------------------- */

double x87_get_f64(const i686_ctx_t *ctx, unsigned i)
{
    unsigned p = phys_of(ctx, i);

    if (!ctx->x87_80) {
        uint64_t bits = rd64(&ctx->x87_st[p][0]);
        double d;

        memcpy(&d, &bits, 8);
        return d;
    }
    return x87_ext80_to_f64(&ctx->x87_st[p][0]);
}

/* Value stores always classify the written slot: a freshly pushed slot
 * still carries its old (usually empty) tag until a real value lands in
 * it (push cannot classify — it has no value). */
void x87_set_f64(i686_ctx_t *ctx, unsigned i, double v)
{
    unsigned p = phys_of(ctx, i);

    if (!ctx->x87_80) {
        uint64_t bits;

        memcpy(&bits, &v, 8);
        wr64(&ctx->x87_st[p][0], bits);
        memset(&ctx->x87_st[p][8], 0, 8);
    } else {
        x87_f64_to_ext80(v, &ctx->x87_st[p][0]);
    }
    set_tag(ctx, p, classify(ctx, p));
}

void x87_get_ext80(const i686_ctx_t *ctx, unsigned i, uint8_t out[10])
{
    unsigned p = phys_of(ctx, i);

    if (ctx->x87_80) {
        memcpy(out, &ctx->x87_st[p][0], 10);
    } else {
        uint64_t bits = rd64(&ctx->x87_st[p][0]);
        double d;

        memcpy(&d, &bits, 8);
        x87_f64_to_ext80(d, out);
    }
}

void x87_set_ext80(i686_ctx_t *ctx, unsigned i, const uint8_t in[10])
{
    unsigned p = phys_of(ctx, i);

    if (ctx->x87_80) {
        memcpy(&ctx->x87_st[p][0], in, 10);
    } else {
        uint64_t bits;
        double d = x87_ext80_to_f64(in);

        memcpy(&bits, &d, 8);
        wr64(&ctx->x87_st[p][0], bits);
        memset(&ctx->x87_st[p][8], 0, 8);
    }
    set_tag(ctx, p, classify(ctx, p));
}

/* --- MMX view (raw bits, no interpretation, no tag effects) ------------ */

uint64_t mmx_get(const i686_ctx_t *ctx, unsigned reg)
{
    return rd64(&ctx->x87_st[reg & 7U][0]);
}

void mmx_set(i686_ctx_t *ctx, unsigned reg, uint64_t v)
{
    wr64(&ctx->x87_st[reg & 7U][0], v);
}

/* --- integer push/pop --------------------------------------------------- */

/* |v| as 1.f x 2^k into a 64-bit mantissa with explicit integer bit. */
static void i64_to_ext80(int64_t v, uint8_t out[10])
{
    uint64_t mag;
    unsigned sign;

    if (v < 0) {
        mag = (uint64_t)(-(v + 1)) + 1U;
        sign = 1U;
    } else {
        mag = (uint64_t)v;
        sign = 0U;
    }
    if (mag == 0U) {
        wr64(out, 0);
        wr16(&out[8], 0);
        return;
    }
    {
        unsigned k = 63;

        while ((mag & (1ULL << k)) == 0U) {
            k--;
        }
        wr64(out, mag << (63U - k));
        wr16(&out[8], (uint16_t)((sign << 15) | (k + 16383U)));
    }
}

#define X87_I64_INDEFINITE INT64_MIN

/* Round an extended value held as normalized (m,e,sign) to int64 per rc.
 * rc: 0 nearest-even, 1 down, 2 up, 3 toward zero.  Out-of-range, Inf and
 * NaN produce the x87 integer indefinite. */
static int64_t ext80_parts_to_i64(uint64_t m, int eff, unsigned sign,
                                  unsigned rc)
{
    uint64_t q;

    if (eff >= 63) {
        /* Integral but |v| >= 2^63: only -2^63 itself is representable. */
        if (sign != 0U && eff == 63 && m == (1ULL << 63)) {
            return INT64_MIN;
        }
        return X87_I64_INDEFINITE;
    }
    {
        unsigned drop = (unsigned)(63 - eff);
        uint64_t r = m & (((uint64_t)1 << drop) - 1U);

        q = m >> drop;
        if (rc == 0U) {
            uint64_t half = (uint64_t)1 << (drop - 1U);

            if (r > half || (r == half && (q & 1U) != 0U)) {
                q++;
            }
        } else if (rc == 1U) {
            if (sign != 0U && r != 0U) {
                q++; /* toward -inf */
            }
        } else if (rc == 2U) {
            if (sign == 0U && r != 0U) {
                q++; /* toward +inf */
            }
        }
        if (q > (1ULL << 63)) {
            return X87_I64_INDEFINITE;
        }
        if (q == (1ULL << 63)) {
            return sign != 0U ? INT64_MIN : X87_I64_INDEFINITE;
        }
        return sign != 0U ? -(int64_t)q : (int64_t)q;
    }
}

static int64_t ext80_to_i64(const uint8_t in[10], unsigned rc)
{
    uint64_t m = rd64(in);
    uint16_t se = rd16(&in[8]);
    unsigned sign = se >> 15;
    unsigned e = se & 0x7fffU;

    if (e == 0x7fffU || m == 0U) {
        return (e == 0x7fffU) ? X87_I64_INDEFINITE : 0;
    }
    {
        int eff = (e == 0U) ? -16382 : (int)e - 16383;

        while ((m & (1ULL << 63)) == 0U) {
            m <<= 1;
            eff--;
        }
        return ext80_parts_to_i64(m, eff, sign, rc);
    }
}

static int64_t f64_to_i64_rc(double d, unsigned rc)
{
    double r;

    if (isnan(d) || isinf(d)) {
        return X87_I64_INDEFINITE;
    }
    switch (rc) {
    case 1U:
        r = floor(d);
        break;
    case 2U:
        r = ceil(d);
        break;
    case 3U:
        r = trunc(d);
        break;
    default:
        r = nearbyint(d); /* host FE stays nearest-even (C11 default) */
        break;
    }
    if (r >= 9223372036854775808.0 || r < -9223372036854775808.0) {
        return X87_I64_INDEFINITE;
    }
    if (r == -9223372036854775808.0) {
        return INT64_MIN;
    }
    return (int64_t)r;
}

void x87_set_int(i686_ctx_t *ctx, int64_t v)
{
    x87_push(ctx);
    if (ctx->x87_80) {
        uint8_t buf[10];

        i64_to_ext80(v, buf);
        memcpy(&ctx->x87_st[x87_top(ctx)][0], buf, 10);
    } else {
        x87_set_f64(ctx, 0, (double)v);
    }
    set_tag(ctx, x87_top(ctx), classify(ctx, x87_top(ctx)));
}

int64_t x87_get_int(const i686_ctx_t *ctx, unsigned i)
{
    unsigned p = phys_of(ctx, i);
    unsigned rc = x87_round_mode(ctx);

    if (ctx->x87_80) {
        return ext80_to_i64(&ctx->x87_st[p][0], rc);
    }
    {
        uint64_t bits = rd64(&ctx->x87_st[p][0]);
        double d;

        memcpy(&d, &bits, 8);
        return f64_to_i64_rc(d, rc);
    }
}

/* --- environment --------------------------------------------------------- */

unsigned x87_round_mode(const i686_ctx_t *ctx)
{
    return (ctx->fctrl >> 10) & 3U;
}

unsigned x87_prec_mode(const i686_ctx_t *ctx)
{
    unsigned pc = (ctx->fctrl >> 8) & 3U;

    if (pc == 2U) {
        return 53U;
    }
    if (pc == 3U) {
        return 64U;
    }
    return 24U; /* 0 single; 1 reserved on hardware, treated as 24 */
}

void x87_update_fstat(i686_ctx_t *ctx)
{
    ctx->fstat = (uint16_t)((ctx->fstat & ~0x3800U) |
                            ((uint16_t)x87_top(ctx) << 11));
}

void x87_set_exc(i686_ctx_t *ctx, unsigned bits)
{
    ctx->fstat = (uint16_t)(ctx->fstat | (bits & 0x3fU));
    if ((bits & ~(unsigned)ctx->fctrl & 0x3fU) != 0U) {
        /* Unmasked: raise the summary (ES, bit 7) and B (bit 15). */
        ctx->fstat = (uint16_t)(ctx->fstat | 0x80U | 0x8000U);
    }
}
