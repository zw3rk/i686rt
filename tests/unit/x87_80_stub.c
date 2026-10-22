/*
 * tests/unit/x87_80_stub.c — TEST-ONLY x87_80 core stub (Phase 5 L5c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the frozen src/interp/x87_80.h API on the HOST long double
 * so tests/unit/test_l5c.c can link src/interp/h_x87.c before lane L5d's
 * real softfloat core lands.  On the check hosts (macOS/aarch64 clang,
 * aarch64 musl) long double IS binary128 — a strict superset of the
 * 64-bit-mantissa x87 extended format — so every operation on
 * ext80-exact inputs is representable exactly in the intermediate and a
 * single rounding step produces correctly-rounded ext80 results.
 *
 * This file is for TESTING ONLY and is never compiled into src/ or the
 * shipped runtime.  Conventions the L5c handlers rely on (the real L5d
 * core must match):
 *   x87_80_fyl2x(out, a, b)     out = b * log2(a);   a = ST(0), b = ST(1)
 *   x87_80_fyl2xp1(out, a, b)   out = b * log2(a+1); a = ST(0), b = ST(1)
 *   x87_80_fpatan(out, a, b)    out = atan2(b, a);   a = ST(0) (x), b = ST(1) (y)
 *   x87_80_fxtract(sig, exp, a) sig in [1,2), exp = integer exponent
 *   fprem/fprem1 *qq            low 3 bits of the (trunc / nearest) quotient
 *   *reduction_complete         always true here (full reduction in one step)
 *   to_i32 rc_override          a CW RC value (0..3) applied for that store
 */

#include <float.h>
#include <math.h>
#include <string.h>

#include "interp/x87_80.h"

/* --- state -------------------------------------------------------------- */

static unsigned g_rc = 0;   /* CW RC: 0 nearest, 1 down, 2 up, 3 zero */
static unsigned g_prec = 64; /* CW PC: 24/53/64 mantissa bits */

unsigned x87_80_set_round(unsigned rc)
{
    unsigned prev = g_rc;

    g_rc = rc & 3U;
    return prev;
}

unsigned x87_80_set_prec(unsigned bits)
{
    unsigned prev = g_prec;

    g_prec = (bits == 24U || bits == 53U || bits == 64U) ? bits : 64U;
    return prev;
}

/* --- ext80 <-> host long double ----------------------------------------- */

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

static long double ld_of(const uint8_t in[10])
{
    uint64_t m = rd64(in);
    uint16_t se = rd16(&in[8]);
    unsigned sign = se >> 15;
    unsigned e = se & 0x7fffU;
    long double v;

    if (e == 0x7fffU) {
        if (m == 0x8000000000000000ULL) {
            return sign != 0U ? -INFINITY : INFINITY;
        }
        return sign != 0U ? -(long double)NAN : (long double)NAN;
    }
    if (m == 0U) {
        return sign != 0U ? -0.0L : 0.0L;
    }
    {
        int eff = (e == 0U) ? -16382 : (int)e - 16383;

        /* m is exact in binary128; scaling by a power of two is exact
         * (smallest ext80 denormal 2^-16445 is still binary128-normal). */
        v = (long double)m * scalbnl(1.0L, eff - 63);
    }
    return sign != 0U ? -v : v;
}

/* Store: the caller's value carries at most 64 significand bits (every
 * stub op rounds to g_prec first), so the integer extraction below is
 * exact.  Values underflowing ext80 clamp to zero (never hit by tests). */
static void ext80_of(long double v, uint8_t out[10])
{
    unsigned sign = signbit(v) ? 1U : 0U;

    if (isnan(v)) {
        wr64(out, 0xC000000000000000ULL); /* quiet NaN, explicit int bit */
        wr16(&out[8], (uint16_t)((sign << 15) | 0x7fffU));
        return;
    }
    if (isinf(v)) {
        wr64(out, 0x8000000000000000ULL);
        wr16(&out[8], (uint16_t)((sign << 15) | 0x7fffU));
        return;
    }
    if (v == 0.0L) {
        wr64(out, 0);
        wr16(&out[8], (uint16_t)(sign << 15));
        return;
    }
    {
        int e;
        long double f = frexpl(fabsl(v), &e); /* |f| in [0.5,1) */
        uint64_t mant = (uint64_t)(f * 0x1p64L); /* [2^63, 2^64) */
        int unb = e - 1;

        if (unb + 16383 <= 0) {
            wr64(out, 0);
            wr16(&out[8], (uint16_t)(sign << 15));
            return;
        }
        wr64(out, mant);
        wr16(&out[8], (uint16_t)((sign << 15) |
                                 (uint16_t)(unb + 16383)));
    }
}

/* --- rounding ----------------------------------------------------------- */

/* Round v to g_prec significand bits under g_rc (single rounding on the
 * exact binary128 intermediate — correct for ext80 inputs). */
static long double round_prec_rc(long double v, unsigned prec, unsigned rc)
{
    long double res;

    if (v == 0.0L || isnan(v) || isinf(v)) {
        return v;
    }
    if (prec >= 113U) {
        return v;
    }
    {
        int e;
        long double f = frexpl(fabsl(v), &e); /* |f| in [0.5,1) */
        /* 113-bit significand: |f| * 2^113 in [2^112, 2^113). */
        unsigned __int128 m = (unsigned __int128)(f * 0x1p113L);
        unsigned drop = 113U - prec;

        if (drop > 112U) {
            drop = 112U;
        }
        {
            unsigned __int128 kept = m >> drop;
            unsigned __int128 rem = m - (kept << drop);
            unsigned __int128 half = (unsigned __int128)1 << (drop - 1U);
            int up;

            if (rc == 0U) {
                up = (rem > half) ||
                     (rem == half && (kept & 1U) != 0U);
            } else if (rc == 1U) {
                up = (v < 0.0L) && (rem != 0U);
            } else if (rc == 2U) {
                up = (v > 0.0L) && (rem != 0U);
            } else {
                up = 0; /* toward zero */
            }
            if (up != 0) {
                kept++;
            }
            if (kept >= ((unsigned __int128)1 << prec)) {
                kept >>= 1;
                e++;
            }
            /* |v| = kept x 2^(e - prec): kept is the p-bit significand. */
            res = scalbnl((long double)kept, e - (int)prec);
        }
    }
    return v < 0.0L ? -res : res;
}

static long double finish(long double v)
{
    return round_prec_rc(v, g_prec, g_rc);
}

/* Directed correction of an RNE double/float cast. */
static double d64_rc(long double v)
{
    double d = (double)v;

    if (g_rc == 1U) {
        if ((long double)d > v) {
            d = nextafter(d, -INFINITY);
        }
    } else if (g_rc == 2U) {
        if ((long double)d < v) {
            d = nextafter(d, INFINITY);
        }
    } else if (g_rc == 3U) {
        if ((long double)d > v) {
            d = nextafter(d, -INFINITY);
        } else if ((long double)d < v) {
            d = nextafter(d, INFINITY);
        }
    }
    return d;
}

static long double rint_rc(long double v)
{
    switch (g_rc) {
    case 1U:
        return floorl(v);
    case 2U:
        return ceill(v);
    case 3U:
        return truncl(v);
    default:
        return nearbyintl(v); /* host FE stays nearest-even */
    }
}

/* --- arithmetic --------------------------------------------------------- */

#define X87_EXC_IE 1U
#define X87_EXC_DE 2U
#define X87_EXC_ZE 4U
#define X87_EXC_OE 8U
#define X87_EXC_UE 16U
#define X87_EXC_PE 32U

static unsigned exc_of(long double exact, long double rounded)
{
    unsigned e = 0;

    if (isinf(rounded) && !isinf(exact)) {
        e |= X87_EXC_OE;
    }
    if (rounded != exact && !isnan(rounded)) {
        e |= X87_EXC_PE;
    }
    return e;
}

static unsigned binop(uint8_t out[10], const uint8_t a[10], const uint8_t b[10],
                      char op)
{
    long double x = ld_of(a);
    long double y = ld_of(b);
    long double r;
    unsigned e = 0;

    if (isnan(x) || isnan(y)) {
        e |= X87_EXC_IE;
    }
    switch (op) {
    case '+':
        r = x + y;
        break;
    case '-':
        r = x - y;
        break;
    case '*':
        r = x * y;
        break;
    default:
        if (y == 0.0L && !isinf(x) && !isnan(x)) {
            e |= X87_EXC_ZE;
        }
        if ((isinf(x) && y == 0.0L) || (x == 0.0L && isinf(y))) {
            e |= X87_EXC_IE;
        }
        r = x / y;
        break;
    }
    {
        long double fr = finish(r);

        e |= exc_of(r, fr);
        ext80_of(fr, out);
    }
    return e;
}

unsigned x87_80_add(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    return binop(out, a, b, '+');
}

unsigned x87_80_sub(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    return binop(out, a, b, '-');
}

unsigned x87_80_mul(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    return binop(out, a, b, '*');
}

unsigned x87_80_div(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    return binop(out, a, b, '/');
}

unsigned x87_80_sqrt(uint8_t out[10], const uint8_t a[10])
{
    long double x = ld_of(a);
    unsigned e = 0;

    if (isnan(x) || x < 0.0L) {
        e |= X87_EXC_IE;
    }
    {
        long double r = (x < 0.0L) ? (long double)NAN : sqrtl(x);
        long double fr = finish(r);

        e |= exc_of(r, fr);
        ext80_of(fr, out);
    }
    return e;
}

/* --- compare ------------------------------------------------------------ */

void x87_80_fcom(const uint8_t a[10], const uint8_t b[10],
                 bool unordered, unsigned *c3, unsigned *c2, unsigned *c0)
{
    long double x = ld_of(a);
    long double y = ld_of(b);

    (void)unordered; /* IE-vs-not is the caller's (COM/UCOM) decision */
    if (isnan(x) || isnan(y)) {
        *c3 = 1U;
        *c2 = 1U;
        *c0 = 1U;
        return;
    }
    if (x > y) {
        *c3 = 0U;
        *c2 = 0U;
        *c0 = 0U;
    } else if (x < y) {
        *c3 = 0U;
        *c2 = 0U;
        *c0 = 1U;
    } else {
        *c3 = 1U;
        *c2 = 0U;
        *c0 = 0U;
    }
}

/* --- partial remainder / fscale / fxtract -------------------------------- */

unsigned x87_80_fprem(uint8_t out[10], const uint8_t a[10], const uint8_t b[10],
                      uint32_t *qq, bool *reduction_complete)
{
    long double x = ld_of(a);
    long double y = ld_of(b);
    unsigned e = 0;

    if (isnan(x) || isnan(y) || isinf(x) || y == 0.0L) {
        e |= X87_EXC_IE;
        *qq = 0;
        ext80_of((long double)NAN, out);
        *reduction_complete = true;
        return e;
    }
    {
        long double q = truncl(x / y);
        long double r = fmodl(x, y);

        *qq = (uint32_t)((int64_t)q & 7);
        if (r != x) {
            e |= X87_EXC_PE;
        }
        ext80_of(r, out);
    }
    *reduction_complete = true; /* stub reduces fully in one step */
    return e;
}

unsigned x87_80_fprem1(uint8_t out[10], const uint8_t a[10],
                       const uint8_t b[10], uint32_t *qq,
                       bool *reduction_complete)
{
    long double x = ld_of(a);
    long double y = ld_of(b);
    unsigned e = 0;

    if (isnan(x) || isnan(y) || isinf(x) || y == 0.0L) {
        e |= X87_EXC_IE;
        *qq = 0;
        ext80_of((long double)NAN, out);
        *reduction_complete = true;
        return e;
    }
    {
        long double q = nearbyintl(x / y);
        long double r = remainderl(x, y);

        *qq = (uint32_t)((int64_t)q & 7);
        if (r != x) {
            e |= X87_EXC_PE;
        }
        ext80_of(r, out);
    }
    *reduction_complete = true;
    return e;
}

unsigned x87_80_fscale(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    long double x = ld_of(a);
    long double y = ld_of(b);
    long double r;

    if (isnan(x) || isnan(y)) {
        ext80_of((long double)NAN, out);
        return X87_EXC_IE;
    }
    if (isinf(y)) {
        ext80_of((x == 0.0L) ? x : y, out);
        return 0;
    }
    r = scalbnl(x, (int)truncl(y));
    ext80_of(r, out);
    return 0;
}

unsigned x87_80_fxtract(uint8_t out_sig[10], uint8_t out_exp[10],
                        const uint8_t a[10])
{
    long double x = ld_of(a);

    if (x == 0.0L || isnan(x) || isinf(x)) {
        memcpy(out_sig, a, 10); /* copy through; tests use normals only */
        ext80_of(x == 0.0L ? (long double)-65536.0L : x, out_exp);
        return 0;
    }
    {
        int e = ilogbl(x);
        long double sig = scalbnl(x, -e); /* [1,2) */

        ext80_of(sig, out_sig);
        ext80_of((long double)e, out_exp);
    }
    return 0;
}

/* --- constants ----------------------------------------------------------- */

void x87_80_pi(uint8_t out[10])
{
    ext80_of(3.14159265358979323846264338327950288419716939937510582097494L,
             out);
}

void x87_80_log2e(uint8_t out[10])
{
    ext80_of(1.44269504088896340735992468100189213742664595415298593413545L,
             out);
}

void x87_80_ln2(uint8_t out[10])
{
    ext80_of(0.69314718055994530941723212145817656807550013436025525412068L,
             out);
}

void x87_80_ln10(uint8_t out[10])
{
    ext80_of(2.30258509299404568401799145468436420760110148862877297603333L,
             out);
}

void x87_80_zero(uint8_t out[10])
{
    wr64(out, 0);
    wr16(&out[8], 0);
}

void x87_80_one(uint8_t out[10])
{
    ext80_of(1.0L, out);
}

void x87_80_inf(uint8_t out[10], bool sign)
{
    wr64(out, 0x8000000000000000ULL);
    wr16(&out[8], (uint16_t)((sign ? 1U : 0U) << 15) | 0x7fffU);
}

void x87_80_nan(uint8_t out[10], bool signaling, bool sign)
{
    if (signaling) {
        wr64(out, 0x8000000000000001ULL); /* int bit + payload, quiet clear */
    } else {
        wr64(out, 0xC000000000000001ULL); /* int bit + quiet + payload */
    }
    wr16(&out[8], (uint16_t)((sign ? 1U : 0U) << 15) | 0x7fffU);
}

/* --- transcendentals ------------------------------------------------------ */

unsigned x87_80_f2xm1(uint8_t out[10], const uint8_t a[10])
{
    long double x = ld_of(a);
    long double r = expm1l(x * 0.69314718055994530941723212145817656807550013436025525412068L);
    long double fr = finish(r);

    ext80_of(fr, out);
    return exc_of(r, fr);
}

unsigned x87_80_fyl2x(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    long double x = ld_of(a); /* ST(0): log argument */
    long double y = ld_of(b); /* ST(1): multiplier */
    unsigned e = 0;

    if (x < 0.0L || isnan(x) || isnan(y)) {
        e |= X87_EXC_IE;
        ext80_of((long double)NAN, out);
        return e;
    }
    if (x == 0.0L) {
        e |= X87_EXC_ZE;
        ext80_of(signbit(y) ? INFINITY : -INFINITY, out);
        return e;
    }
    {
        long double r = y * log2l(x);
        long double fr = finish(r);

        e |= exc_of(r, fr);
        ext80_of(fr, out);
    }
    return e;
}

unsigned x87_80_fyl2xp1(uint8_t out[10], const uint8_t a[10],
                        const uint8_t b[10])
{
    long double x = ld_of(a); /* ST(0): 1 + this is the log argument */
    long double y = ld_of(b); /* ST(1): multiplier */
    unsigned e = 0;

    if (x <= -1.0L || isnan(x) || isnan(y)) {
        e |= X87_EXC_IE;
        ext80_of((long double)NAN, out);
        return e;
    }
    {
        long double r = y * log2l(1.0L + x);
        long double fr = finish(r);

        e |= exc_of(r, fr);
        ext80_of(fr, out);
    }
    return e;
}

unsigned x87_80_fsin(uint8_t out[10], const uint8_t a[10], bool *stack_fault)
{
    long double x = ld_of(a);

    if (fabsl(x) >= 9223372036854775808.0L) {
        *stack_fault = true; /* C2: unreduced argument */
        memcpy(out, a, 10);
        return 0;
    }
    *stack_fault = false;
    {
        long double r = sinl(x);
        long double fr = finish(r);

        ext80_of(fr, out);
        return exc_of(r, fr);
    }
}

unsigned x87_80_fcos(uint8_t out[10], const uint8_t a[10], bool *stack_fault)
{
    long double x = ld_of(a);

    if (fabsl(x) >= 9223372036854775808.0L) {
        *stack_fault = true;
        memcpy(out, a, 10);
        return 0;
    }
    *stack_fault = false;
    {
        long double r = cosl(x);
        long double fr = finish(r);

        ext80_of(fr, out);
        return exc_of(r, fr);
    }
}

unsigned x87_80_fptan(uint8_t out_tan[10], uint8_t out_one[10],
                      const uint8_t a[10], bool *stack_fault)
{
    long double x = ld_of(a);

    if (fabsl(x) >= 9223372036854775808.0L) {
        *stack_fault = true;
        memcpy(out_tan, a, 10);
        ext80_of(1.0L, out_one);
        return 0;
    }
    *stack_fault = false;
    {
        long double r = tanl(x);
        long double fr = finish(r);

        ext80_of(fr, out_tan);
        ext80_of(1.0L, out_one);
        return exc_of(r, fr);
    }
}

unsigned x87_80_fpatan(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    long double x = ld_of(a); /* ST(0): x */
    long double y = ld_of(b); /* ST(1): y; result atan2(y, x) */
    long double r = atan2l(y, x);
    long double fr = finish(r);

    ext80_of(fr, out);
    return exc_of(r, fr);
}

/* --- conversions ----------------------------------------------------------- */

unsigned x87_80_from_i32(uint8_t out[10], int32_t v)
{
    ext80_of((long double)v, out);
    return 0;
}

unsigned x87_80_from_i64(uint8_t out[10], int64_t v)
{
    ext80_of((long double)v, out);
    return 0;
}

unsigned x87_80_from_f32(uint8_t out[10], float v)
{
    ext80_of((long double)v, out);
    return 0;
}

unsigned x87_80_from_f64(uint8_t out[10], double v)
{
    ext80_of((long double)v, out);
    return 0;
}

unsigned x87_80_to_i32(const uint8_t in[10], int32_t *out, unsigned rc_override)
{
    long double x = ld_of(in);
    long double r;

    if (isnan(x) || isinf(x)) {
        *out = INT32_MIN; /* integer indefinite */
        return X87_EXC_IE;
    }
    switch (rc_override & 3U) {
    case 1U:
        r = floorl(x);
        break;
    case 2U:
        r = ceill(x);
        break;
    case 3U:
        r = truncl(x);
        break;
    default:
        r = nearbyintl(x);
        break;
    }
    if (r < -2147483648.0L || r > 2147483647.0L) {
        *out = INT32_MIN;
        return X87_EXC_IE;
    }
    *out = (int32_t)r;
    return (r != x) ? X87_EXC_PE : 0U;
}

unsigned x87_80_to_i64(const uint8_t in[10], int64_t *out)
{
    long double x = ld_of(in);
    long double r;

    if (isnan(x) || isinf(x)) {
        *out = INT64_MIN;
        return X87_EXC_IE;
    }
    r = rint_rc(x);
    if (r < -9223372036854775808.0L || r >= 9223372036854775808.0L) {
        *out = INT64_MIN;
        return X87_EXC_IE;
    }
    *out = (int64_t)r;
    return (r != x) ? X87_EXC_PE : 0U;
}

unsigned x87_80_to_f64(const uint8_t in[10], double *out)
{
    long double x = ld_of(in);
    double d = d64_rc(x);

    *out = d;
    return ((long double)d != x) ? X87_EXC_PE : 0U;
}

unsigned x87_80_to_f32(const uint8_t in[10], float *out)
{
    long double x = ld_of(in);
    float f = (float)x;

    if (g_rc == 1U) {
        if ((long double)f > x) {
            f = nextafterf(f, -INFINITY);
        }
    } else if (g_rc == 2U) {
        if ((long double)f < x) {
            f = nextafterf(f, INFINITY);
        }
    } else if (g_rc == 3U) {
        if ((long double)f > x) {
            f = nextafterf(f, -INFINITY);
        } else if ((long double)f < x) {
            f = nextafterf(f, INFINITY);
        }
    }
    *out = f;
    return ((long double)f != x) ? X87_EXC_PE : 0U;
}

/* --- predicates ------------------------------------------------------------- */

bool x87_80_is_zero(const uint8_t v[10])
{
    return rd64(v) == 0U && (rd16(&v[8]) & 0x7fffU) == 0U;
}

bool x87_80_is_inf(const uint8_t v[10])
{
    return (rd16(&v[8]) & 0x7fffU) == 0x7fffU &&
           rd64(v) == 0x8000000000000000ULL;
}

bool x87_80_is_nan(const uint8_t v[10])
{
    return (rd16(&v[8]) & 0x7fffU) == 0x7fffU &&
           rd64(v) != 0x8000000000000000ULL;
}

bool x87_80_is_snan(const uint8_t v[10])
{
    return x87_80_is_nan(v) && (rd64(v) & (1ULL << 62)) == 0U;
}

bool x87_80_sign(const uint8_t v[10])
{
    return (rd16(&v[8]) >> 15) != 0U;
}
