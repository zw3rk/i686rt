/*
 * src/interp/h_x87_math.c — x87 unary/transcendental ops (environment
 * and state images live in h_x87_env.c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interp/h_x87_internal.h"

#ifndef M_LOG2E
#define M_LOG2E 1.44269504088896340736
#endif

/* ------------------------------------------------------------------ */
/* Unary / transcendental ops (both modes)                             */
/* ------------------------------------------------------------------ */

void i686_x87_op_fchs(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t b[10];

        x87_get_ext80(ctx, 0, b);
        b[9] ^= 0x80U;
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, -x87_get_f64(ctx, 0));
    }
}

void i686_x87_op_fabs(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t b[10];

        x87_get_ext80(ctx, 0, b);
        b[9] &= 0x7fU;
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, fabs(x87_get_f64(ctx, 0)));
    }
}

/* R7-30: checked (an unmasked raise faults; FTST has no
 * store/pop to inhibit). */
int i686_x87_op_ftst(i686_ctx_t *ctx)
{
    int un;

    /* R7-31: stack sources validated before any read (faults
     * with no state change beyond IE/SF when unmasked). */
    if (x87_src(ctx, 0)) {
        return I686_EXIT_FAULT;
    }

    if (ctx->x87_80) {
        uint8_t sa[10];
        uint8_t z[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        x87_80_zero(z);
        x87_80_fcom(sa, z, false, &c3, &c2, &c0);
        set_cc(ctx, c0, 0, c2, c3);
        un = (c0 && c2 && c3);
    } else {
        double a = x87_get_f64(ctx, 0);
        double z = 0.0;

        un = cc_of_cmp(a, z, ctx);
    }
    if (un) {
        return x87_exc_raise(ctx, SW_IE);
    }
    return I686_INTERP_CONTINUE;
}

/* FXAM class table (C3 C2 C0, sign in C1): unsupported 000, NaN 001,
 * normal 010, infinity 011, zero 100, empty 101, denormal 110. */
void i686_x87_op_fxam(i686_ctx_t *ctx)
{
    unsigned c3 = 0;
    unsigned c2 = 0;
    unsigned c0 = 0;
    unsigned c1;
    unsigned empty;
    unsigned phys = (unsigned)x87_top(ctx);

    empty = ((ctx->ftag >> (phys * 2U)) & 3U) == 3U;
    if (ctx->x87_80) {
        uint8_t b[10];
        uint16_t se;
        uint64_t m;

        x87_get_ext80(ctx, 0, b);
        m = 0;
        for (unsigned i = 0; i < 8; i++) {
            m |= (uint64_t)b[i] << (8U * i);
        }
        se = (uint16_t)((uint16_t)b[8] | ((uint16_t)b[9] << 8));
        c1 = (se >> 15) & 1U;
        {
            unsigned e = se & 0x7fffU;

            if (empty) {
                c3 = 1;
                c2 = 0;
                c0 = 1;
            } else if (e == 0x7fffU) {
                if (m == 0x8000000000000000ULL) {
                    c3 = 0;
                    c2 = 1;
                    c0 = 1; /* infinity */
                } else {
                    c3 = 0;
                    c2 = 0;
                    c0 = 1; /* NaN */
                }
            } else if (m == 0U) {
                c3 = 1;
                c2 = 0;
                c0 = 0; /* zero */
            } else if (e == 0U) {
                c3 = 1;
                c2 = 1;
                c0 = 0; /* denormal / unsupported */
            } else {
                c3 = 0;
                c2 = 1;
                c0 = 0; /* normal */
            }
        }
    } else {
        uint64_t bits;
        unsigned e;
        double d = x87_get_f64(ctx, 0);

        memcpy(&bits, &d, 8);
        e = (unsigned)((bits >> 52) & 0x7ffU);
        c1 = (unsigned)(bits >> 63);
        if (empty) {
            c3 = 1;
            c2 = 0;
            c0 = 1;
        } else if (e == 0x7ffU) {
            if ((bits & 0x000fffffffffffffULL) == 0U) {
                c3 = 0;
                c2 = 1;
                c0 = 1;
            } else {
                c3 = 0;
                c2 = 0;
                c0 = 1;
            }
        } else if (d == 0.0) {
            c3 = 1;
            c2 = 0;
            c0 = 0;
        } else if (e == 0U) {
            c3 = 1;
            c2 = 1;
            c0 = 0;
        } else {
            c3 = 0;
            c2 = 1;
            c0 = 0;
        }
    }
    set_cc(ctx, c0, c1, c2, c3);
}

/* D9 E8+i constants.  80-bit mode uses the frozen x87_80 tables; the
 * API has no log2(10)/log10(2) entries (FLDL2T/FLDG2), so those go
 * through x87_80_from_f64 on the double literal (matches the
 * double-rounded constant; exact 64-bit tables are L5d's to add).
 * R7-31: checked (overflow faults with TOP unchanged). */
int i686_x87_op_fld_const(i686_ctx_t *ctx, unsigned rm)
{
    static const double dc[7] = {
        1.0,                                   /* FLD1   */
        3.32192809488736234787,                /* FLDL2T */
        1.44269504088896340736,                /* FLDL2E */
        3.14159265358979323846,                /* FLDPI  */
        0.30102999566398119521,                /* FLDLG2 */
        0.69314718055994530942,                /* FLDLN2 */
        0.0,                                   /* FLDZ   */
    };

    if (!ctx->x87_80) {
        return push_f64(ctx, dc[rm]);
    }
    {
        uint8_t b[10];

        switch (rm) {
        case 0:
            x87_80_one(b);
            break;
        case 2:
            x87_80_log2e(b);
            break;
        case 3:
            x87_80_pi(b);
            break;
        case 5:
            x87_80_ln2(b);
            break;
        case 6:
            x87_80_zero(b);
            break;
        default: /* 1 FLDL2T, 4 FLDLG2 */
            x87_80_from_f64(b, dc[rm]);
            break;
        }
        if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
            return I686_EXIT_FAULT;
        }
        x87_set_ext80(ctx, 0, b);
    }
    return I686_INTERP_CONTINUE;
}

void i686_x87_op_fsin(i686_ctx_t *ctx, int is_cos)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t r[10];
        bool fault;
        unsigned exc;

        x87_get_ext80(ctx, 0, a);
        exc = is_cos ? x87_80_fcos(r, a, &fault) : x87_80_fsin(r, a, &fault);
        if (fault) {
            set_c2(ctx, 1);
        } else {
            set_c2(ctx, 0);
            /* R7-30: an unmasked raise inhibits the store. */
            if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
                return;
            }
            x87_set_ext80(ctx, 0, r);
        }
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (fabs(a) >= 9223372036854775808.0) {
            set_c2(ctx, 1);
            return;
        }
        set_c2(ctx, 0); /* R7-38: success clears a stale C2 */
        x87_set_f64(ctx, 0, is_cos ? cos(a) : sin(a));
    }
}

void i686_x87_op_fsincos(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t s[10];
        uint8_t c[10];
        bool fault;
        unsigned exc;

        x87_get_ext80(ctx, 0, a);
        exc = x87_80_fsin(s, a, &fault);
        if (fault) {
            set_c2(ctx, 1);
            return;
        }
        set_c2(ctx, 0);
        exc |= x87_80_fcos(c, a, &fault);
        /* R7-30: an unmasked raise inhibits the stores/push
         * (the core reports e.g. SNaN invalid here). */
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 0, s);
        /* R7-31: overflow validated before TOP moves (the
         * dispatch returns #MF on ES). */
        if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 0, c); /* after: ST(0)=cos, ST(1)=sin */
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double s;
        double c;

        if (fabs(a) >= 9223372036854775808.0) {
            set_c2(ctx, 1);
            return;
        }
        s = sin(a);
        c = cos(a);
        set_c2(ctx, 0); /* R7-38: success clears a stale C2 */
        x87_set_f64(ctx, 0, s);
        /* R7-31: overflow validated before TOP moves. */
        if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_f64(ctx, 0, c);
    }
}

void i686_x87_op_fsqrt(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_sqrt(r, a);
        /* R7-30: an unmasked raise inhibits the store below. */
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 0, r);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (a < 0.0) {
            /* R7-30: an unmasked raise inhibits the store. */
            if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                return;
            }
            x87_set_f64(ctx, 0, (double)NAN);
            return;
        }
        x87_set_f64(ctx, 0, sqrt(a));
    }
}

void i686_x87_op_frndint(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        int64_t i;
        unsigned exc;

        x80_set_mode(ctx, 0);
        x87_get_ext80(ctx, 0, a);
        if (x87_80_is_inf(a) || x87_80_is_nan(a)) {
            return; /* unchanged */
        }
        {
            /* R7-33: unbiased exponents >= 63 carry no fraction
             * bits in the 64-bit significand, so the value is
             * already integral — converting through int64 would
             * wrongly yield the integer-indefinite value (2^64). */
            unsigned raw = (unsigned)a[8] |
                           ((unsigned)a[9] << 8);
            unsigned exp = raw & 0x7FFFu;

            if (exp != 0x7FFFu && exp >= 16383u + 63u) {
                return; /* unchanged, no exception */
            }
        }
        exc = x87_80_to_i64(a, &i);
        x87_80_from_i64(a, i);
        /* R7-30: an unmasked raise inhibits the store below. */
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 0, a);
        return;
    }
    {
        double d = x87_get_f64(ctx, 0);
        double r;
        unsigned rc = x87_round_mode(ctx);

        if (isnan(d) || isinf(d)) {
            return;
        }
        if (rc == 1U) {
            r = floor(d);
        } else if (rc == 2U) {
            r = ceil(d);
        } else if (rc == 3U) {
            r = trunc(d);
        } else {
            r = nearbyint(d);
        }
        /* R7-30: an unmasked raise inhibits the store below. */
        if (r != d && x87_exc_raise(ctx, SW_PE) !=
            I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_f64(ctx, 0, r);
    }
}

/* ------------------------------------------------------------------ */
/* Fixed-form ops reached by sub-dispatch                              */
/* ------------------------------------------------------------------ */

void i686_x87_op_f2xm1(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_f2xm1(r, a);
        /* R7-30: an unmasked raise inhibits the store below
         * (the fixed-form dispatch returns #MF on ES). */
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 0, r);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double r = expm1(a * 0.693147180559945309417232121458176568);

        x87_set_f64(ctx, 0, r);
    }
}

/* FYL2X/FYL2XP1, FPTAN and FPATAN live in h_x87_trans.c (split
 * for the 900-line gate). */
void i686_x87_op_fxtract(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t sig[10];
        uint8_t ex[10];

        x87_get_ext80(ctx, 0, a);
        /* R7-30: the core reports status (zero/SNaN input); an
         * unmasked raise inhibits the push/stores below. */
        if (x87_exc_raise(ctx, x87_80_fxtract(sig, ex, a)) !=
            I686_INTERP_CONTINUE) {
            return;
        }
        /* R7-31: overflow validated before TOP moves. */
        if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 1, ex); /* after: ST(1)=exponent, ST(0)=sig */
        x87_set_ext80(ctx, 0, sig);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        /* R7-45: zero/NaN/Inf never reach ilogb below (ilogb(0)
         * is INT_MIN, whose negation is undefined).  Push is
         * validated before TOP moves in every arm. */
        if (a == 0.0) {
            if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
                return;
            }
            x87_set_f64(ctx, 1, -INFINITY);
            x87_set_f64(ctx, 0, a);
            /* R7-30: an unmasked raise faults (dispatch tail). */
            if (x87_exc_raise(ctx, SW_ZE) != I686_INTERP_CONTINUE) {
                return;
            }
            return;
        }
        if (isnan(a)) {
            if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
                return;
            }
            x87_set_f64(ctx, 1, (double)NAN);
            x87_set_f64(ctx, 0, a);
            if (d_is_snan(a) &&
                x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                return;
            }
            return;
        }
        if (isinf(a)) {
            if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
                return;
            }
            x87_set_f64(ctx, 1, INFINITY);
            x87_set_f64(ctx, 0, a);
            return;
        }
        {
            /* Finite nonzero: e in [-1074, 1023], so -e is safe. */
            int e = ilogb(a);
            double sig = scalbn(a, -e); /* [1,2) */

            /* R7-31: overflow validated before TOP moves. */
            if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
                return;
            }
            x87_set_f64(ctx, 1, (double)e);
            x87_set_f64(ctx, 0, sig);
        }
    }
}

void i686_x87_op_fscale(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];

        x87_get_ext80(ctx, 0, a);
        x87_get_ext80(ctx, 1, b);
        /* R7-30: the core reports status (overflow/underflow); an
         * unmasked raise inhibits the store below. */
        if (x87_exc_raise(ctx, x87_80_fscale(r, a, b)) !=
            I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 0, r);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, 1);

        /* R7-45: the scale factor saturates without host casts —
         * NaN/Inf magnitudes never reach (int)trunc(b), which is
         * undefined for them and for |b| >= 2^31.  Special cases
         * mirror the exact core above. */
        if (isnan(a) || isnan(b)) {
            x87_set_f64(ctx, 0, (double)NAN);
            if ((d_is_snan(a) || d_is_snan(b)) &&
                x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                return;
            }
            return;
        }
        if (isinf(a)) {
            if (isinf(b) && signbit(b) != 0) {
                x87_set_f64(ctx, 0, (double)NAN);
            } else {
                x87_set_f64(ctx, 0, a);
            }
            return;
        }
        if (a == 0.0) {
            if (isinf(b)) {
                x87_set_f64(ctx, 0, (double)NAN);
            } else {
                x87_set_f64(ctx, 0, a);
            }
            return;
        }
        if (isinf(b)) {
            if (signbit(b) != 0) {
                x87_set_f64(ctx, 0, copysign(0.0, a));
            } else {
                x87_set_f64(ctx, 0, copysign(INFINITY, a));
            }
            return;
        }
        {
            int n;

            if (b >= 2147483648.0) {
                n = 1075; /* saturates to signed infinity */
            } else if (b <= -2147483648.0) {
                n = -1075; /* saturates to signed zero */
            } else {
                n = (int)trunc(b);
            }
            x87_set_f64(ctx, 0, scalbn(a, n));
        }
    }
}

void i686_x87_op_fprem(i686_ctx_t *ctx, int ieee)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0) || x87_src(ctx, 1)) {
        return;
    }

    unsigned c0 = 0;
    unsigned c1 = 0;
    unsigned c3 = 0;

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];
        uint32_t qq = 0;
        bool complete;
        unsigned exc;

        x87_get_ext80(ctx, 0, a);
        x87_get_ext80(ctx, 1, b);
        exc = ieee ? x87_80_fprem1(r, a, b, &qq, &complete)
                   : x87_80_fprem(r, a, b, &qq, &complete);
        /* R7-30: an unmasked raise inhibits the store/CC below. */
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 0, r);
        if (complete) {
            c1 = qq & 1U;
            c3 = (qq >> 1) & 1U;
            c0 = (qq >> 2) & 1U;
        }
        set_cc(ctx, c0, c1, complete ? 0U : 1U, c3);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, 1);
        double q;
        double r;

        if (isnan(a) || isnan(b) || isinf(a) || b == 0.0) {
            if (!isnan(a) && !isnan(b)) {
                /* R7-30: an unmasked raise inhibits the
                 * store/CC below. */
                if (x87_exc_raise(ctx, SW_IE) !=
                    I686_INTERP_CONTINUE) {
                    return;
                }
            }
            x87_set_f64(ctx, 0, (double)NAN);
            set_cc(ctx, 1, 0, 0, 1);
            return;
        }
        q = ieee ? nearbyint(a / b) : trunc(a / b);
        r = ieee ? remainder(a, b) : fmod(a, b);
        /* R7-30: an unmasked raise inhibits the store below. */
        if (r != a && x87_exc_raise(ctx, SW_PE) !=
            I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_f64(ctx, 0, r);
        {
            double q8 = fmod(q, 8.0);
            uint32_t qq = (uint32_t)(q8 < 0.0 ? q8 + 8.0 : q8);

            c1 = qq & 1U;
            c3 = (qq >> 1) & 1U;
            c0 = (qq >> 2) & 1U;
        }
        set_cc(ctx, c0, c1, 0, c3);
    }
}
