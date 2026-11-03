/*
 * src/interp/h_x87_math.c — x87 unary/transcendental and state-image ops
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
    if (ctx->x87_80) {
        uint8_t b[10];

        x87_get_ext80(ctx, 0, b);
        b[9] &= 0x7fU;
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, fabs(x87_get_f64(ctx, 0)));
    }
}

void i686_x87_op_ftst(i686_ctx_t *ctx)
{
    int un;

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
        x87_set_exc(ctx, SW_IE);
    }
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
 * double-rounded constant; exact 64-bit tables are L5d's to add). */
void i686_x87_op_fld_const(i686_ctx_t *ctx, unsigned rm)
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
        push_f64(ctx, dc[rm]);
        return;
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
        x87_push(ctx);
        x87_set_ext80(ctx, 0, b);
    }
}

void i686_x87_op_fsin(i686_ctx_t *ctx, int is_cos)
{
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
            x87_set_ext80(ctx, 0, r);
            x87_set_exc(ctx, exc);
        }
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (fabs(a) >= 9223372036854775808.0) {
            set_c2(ctx, 1);
            return;
        }
        x87_set_f64(ctx, 0, is_cos ? cos(a) : sin(a));
    }
}

void i686_x87_op_fsincos(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t s[10];
        uint8_t c[10];
        bool fault;

        x87_get_ext80(ctx, 0, a);
        (void)x87_80_fsin(s, a, &fault);
        if (fault) {
            set_c2(ctx, 1);
            return;
        }
        (void)x87_80_fcos(c, a, &fault);
        x87_set_ext80(ctx, 0, s);
        x87_push(ctx);
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
        x87_set_f64(ctx, 0, s);
        x87_push(ctx);
        x87_set_f64(ctx, 0, c);
    }
}

void i686_x87_op_fsqrt(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_sqrt(r, a);
        x87_set_ext80(ctx, 0, r);
        x87_set_exc(ctx, exc);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (a < 0.0) {
            x87_set_exc(ctx, SW_IE);
            x87_set_f64(ctx, 0, (double)NAN);
            return;
        }
        x87_set_f64(ctx, 0, sqrt(a));
    }
}

void i686_x87_op_frndint(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        int64_t i;
        unsigned exc;

        x80_set_mode(ctx, 0);
        x87_get_ext80(ctx, 0, a);
        if (x87_80_is_inf(a) || x87_80_is_nan(a)) {
            return; /* unchanged */
        }
        exc = x87_80_to_i64(a, &i);
        x87_80_from_i64(a, i);
        x87_set_ext80(ctx, 0, a);
        x87_set_exc(ctx, exc);
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
        if (r != d) {
            x87_set_exc(ctx, SW_PE);
        }
        x87_set_f64(ctx, 0, r);
    }
}

/* ------------------------------------------------------------------ */
/* FPU environment (28-byte protected mode) and FXSAVE m512            */
/* ------------------------------------------------------------------ */

void i686_x87_op_fnstenv(i686_ctx_t *ctx, uint32_t va)
{
    for (unsigned i = 0; i < 28; i++) {
        mem_wr(ctx, va + i, 1, 0);
    }
    mem_wr(ctx, va + 0, 2, ctx->fctrl);
    mem_wr(ctx, va + 4, 2, ctx->fstat);
    mem_wr(ctx, va + 8, 2, ctx->ftag);
    mem_wr(ctx, va + 12, 4, ctx->fpu_ip);
    mem_wr(ctx, va + 16, 2, ctx->seg_sel[I686_SEG_CS]);
    mem_wr(ctx, va + 18, 2, ctx->fop);
    mem_wr(ctx, va + 20, 4, ctx->fpu_dp);
    mem_wr(ctx, va + 24, 2, ctx->seg_sel[I686_SEG_DS]);
}

void i686_x87_op_fldenv(i686_ctx_t *ctx, uint32_t va)
{
    ctx->fctrl = (uint16_t)mem_rd(ctx, va + 0, 2);
    ctx->fstat = (uint16_t)mem_rd(ctx, va + 4, 2);
    ctx->ftag = (uint16_t)mem_rd(ctx, va + 8, 2);
    ctx->x87_top = (ctx->fstat >> 11) & 7U;
    ctx->fpu_ip = (uint32_t)mem_rd(ctx, va + 12, 4);
    ctx->fop = (uint16_t)mem_rd(ctx, va + 18, 2);
    ctx->fpu_dp = (uint32_t)mem_rd(ctx, va + 20, 4);
}

void i686_x87_op_fxsave(i686_ctx_t *ctx, uint32_t va)
{
    uint8_t *img = (uint8_t *)i686_guest_ptr(ctx, va);
    uint16_t atw = 0;

    memset(img, 0, 512);
    img_wr16(img, 0, ctx->fctrl);
    img_wr16(img, 2, ctx->fstat);
    for (unsigned p = 0; p < 8; p++) {
        if (((ctx->ftag >> (p * 2U)) & 3U) == 3U) {
            atw |= (uint16_t)(1U << p);
        }
    }
    img[4] = (uint8_t)atw; /* abridged tag: 1 = empty (physical order) */
    img_wr16(img, 6, ctx->fop);
    img_wr32(img, 8, ctx->fpu_ip);
    img_wr16(img, 12, ctx->seg_sel[I686_SEG_CS]);
    img_wr32(img, 16, ctx->fpu_dp);
    img_wr16(img, 20, ctx->seg_sel[I686_SEG_DS]);
    img_wr32(img, 24, ctx->mxcsr);
    img_wr32(img, 28, ctx->mxcsr_mask);
    for (unsigned i = 0; i < 8; i++) {
        uint8_t b[10];

        x87_get_ext80(ctx, i, b); /* stack-relative ST(i) */
        memcpy(&img[32 + 16 * i], b, 10);
        memcpy(&img[160 + 16 * i], ctx->xmm[i], 16);
    }
}

void i686_x87_op_fxrstor(i686_ctx_t *ctx, uint32_t va)
{
    const uint8_t *img = (const uint8_t *)i686_guest_ptr(ctx, va);

    ctx->fctrl = img_rd16(img, 0);
    ctx->fstat = img_rd16(img, 2);
    ctx->x87_top = (ctx->fstat >> 11) & 7U;
    ctx->fop = img_rd16(img, 6);
    ctx->fpu_ip = img_rd32(img, 8);
    ctx->fpu_dp = img_rd32(img, 16);
    ctx->mxcsr = img_rd32(img, 24) & 0xffbfU; /* bit 6 reserved */
    ctx->ftag = 0;
    for (unsigned p = 0; p < 8; p++) {
        if ((img[4] & (1U << p)) != 0U) {
            ctx->ftag |= (uint16_t)(3U << (p * 2U)); /* empty */
        }
    }
    for (unsigned i = 0; i < 8; i++) {
        x87_set_ext80(ctx, i, &img[32 + 16 * i]);
        memcpy(ctx->xmm[i], &img[160 + 16 * i], 16);
    }
}

void i686_x87_op_fnsave(i686_ctx_t *ctx, uint32_t va)
{
    uint8_t *img = (uint8_t *)i686_guest_ptr(ctx, va);
    uint16_t atw = 0;

    memset(img, 0, 108);
    img_wr16(img, 0, ctx->fctrl);
    img_wr16(img, 2, ctx->fstat);
    for (unsigned p = 0; p < 8; p++) {
        if (((ctx->ftag >> (p * 2U)) & 3U) == 3U) {
            atw |= (uint16_t)(1U << p);
        }
    }
    img[4] = (uint8_t)atw;
    img_wr32(img, 8, ctx->fpu_ip);
    img_wr16(img, 12, ctx->seg_sel[I686_SEG_CS]);
    img_wr16(img, 14, ctx->fop);
    img_wr32(img, 16, ctx->fpu_dp);
    img_wr16(img, 20, ctx->seg_sel[I686_SEG_DS]);
    for (unsigned p = 0; p < 8; p++) {
        uint8_t b[10];

        x87_get_ext80(ctx, (p - ctx->x87_top) & 7U, b); /* ST(i)=Rp */
        memcpy(&img[28 + 10 * p], b, 10);
    }
    /* FNSAVE reinitializes (FINIT semantics). */
    ctx->fctrl = 0x037fU;
    ctx->fstat = 0;
    ctx->ftag = 0xffffU;
    ctx->x87_top = 0;
    ctx->fop = 0;
    ctx->fpu_ip = 0;
    ctx->fpu_dp = 0;
}

void i686_x87_op_frstor(i686_ctx_t *ctx, uint32_t va)
{
    const uint8_t *img = (const uint8_t *)i686_guest_ptr(ctx, va);

    ctx->fctrl = img_rd16(img, 0);
    ctx->fstat = img_rd16(img, 2);
    ctx->x87_top = (ctx->fstat >> 11) & 7U;
    ctx->ftag = 0;
    for (unsigned p = 0; p < 8; p++) {
        if ((img[4] & (1U << p)) != 0U) {
            ctx->ftag |= (uint16_t)(3U << (p * 2U)); /* empty */
        }
    }
    ctx->fpu_ip = img_rd32(img, 8);
    ctx->fop = img_rd16(img, 14);
    ctx->fpu_dp = img_rd32(img, 16);
    for (unsigned p = 0; p < 8; p++) {
        uint8_t b[10];

        memcpy(b, &img[28 + 10 * p], 10);
        x87_set_ext80(ctx, (p - ctx->x87_top) & 7U, b);
    }
}

/* ------------------------------------------------------------------ */
/* Fixed-form ops reached by sub-dispatch                              */
/* ------------------------------------------------------------------ */

void i686_x87_op_f2xm1(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_f2xm1(r, a);
        x87_set_ext80(ctx, 0, r);
        x87_set_exc(ctx, exc);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double r = expm1(a * 0.693147180559945309417232121458176568);

        x87_set_f64(ctx, 0, r);
    }
}

void i686_x87_op_fyl2x(i686_ctx_t *ctx, int p1)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        x87_get_ext80(ctx, 1, b);
        exc = p1 ? x87_80_fyl2xp1(r, a, b) : x87_80_fyl2x(r, a, b);
        x87_set_ext80(ctx, 1, r);
        x87_set_exc(ctx, exc);
        x87_pop(ctx);
        return;
    }
    {
        /* I686-R4-7: FYL2X (p1 == 0) computes b * log2(a) valid for
         * a >= 0; FYL2XP1 (p1 != 0) computes b * log2(a + 1) valid for
         * a >= -1, so -1 < a < 0 is legal input there. A zero logarithm
         * argument yields a signed infinity (b * -Inf, opposite sign to
         * b) with #Z, except 0 * -Inf which is #I; an infinite argument
         * yields b * +Inf (b's sign) with no flag, except 0 * +Inf which
         * is #I. A zero logarithm with an infinite multiplier is #I. */
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, 1);
        double r;

        if (isnan(a) || isnan(b)) {
            x87_set_exc(ctx, SW_IE);
            x87_set_f64(ctx, 1, (double)NAN);
            x87_pop(ctx);
            return;
        }
        if (p1) {
            if (a < -1.0) {
                x87_set_exc(ctx, SW_IE);
                x87_set_f64(ctx, 1, (double)NAN);
                x87_pop(ctx);
                return;
            }
            if (a == -1.0) {
                if (b == 0.0) {
                    x87_set_exc(ctx, SW_IE);
                    x87_set_f64(ctx, 1, (double)NAN);
                } else {
                    x87_set_exc(ctx, SW_ZE);
                    x87_set_f64(ctx, 1,
                                signbit(b) ? HUGE_VAL : -HUGE_VAL);
                }
                x87_pop(ctx);
                return;
            }
            if (isinf(a)) {
                if (b == 0.0) {
                    x87_set_exc(ctx, SW_IE);
                    x87_set_f64(ctx, 1, (double)NAN);
                } else {
                    x87_set_f64(ctx, 1,
                                signbit(b) ? -HUGE_VAL : HUGE_VAL);
                }
                x87_pop(ctx);
                return;
            }
            {
                double l = log1p(a) * M_LOG2E;
                if (l == 0.0 && isinf(b)) {
                    x87_set_exc(ctx, SW_IE);
                    x87_set_f64(ctx, 1, (double)NAN);
                    x87_pop(ctx);
                    return;
                }
                r = d_mul(ctx, b, l);
            }
        } else {
            if (a < 0.0) {
                x87_set_exc(ctx, SW_IE);
                x87_set_f64(ctx, 1, (double)NAN);
                x87_pop(ctx);
                return;
            }
            if (a == 0.0) {
                if (b == 0.0) {
                    x87_set_exc(ctx, SW_IE);
                    x87_set_f64(ctx, 1, (double)NAN);
                } else {
                    x87_set_exc(ctx, SW_ZE);
                    x87_set_f64(ctx, 1,
                                signbit(b) ? HUGE_VAL : -HUGE_VAL);
                }
                x87_pop(ctx);
                return;
            }
            if (isinf(a)) {
                if (b == 0.0) {
                    x87_set_exc(ctx, SW_IE);
                    x87_set_f64(ctx, 1, (double)NAN);
                } else {
                    x87_set_f64(ctx, 1,
                                signbit(b) ? -HUGE_VAL : HUGE_VAL);
                }
                x87_pop(ctx);
                return;
            }
            {
                double l = log2(a);
                if (l == 0.0 && isinf(b)) {
                    x87_set_exc(ctx, SW_IE);
                    x87_set_f64(ctx, 1, (double)NAN);
                    x87_pop(ctx);
                    return;
                }
                r = d_mul(ctx, b, l);
            }
        }
        x87_set_f64(ctx, 1, r);
        x87_pop(ctx);
    }
}

void i686_x87_op_fptan(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t t[10];
        uint8_t one[10];
        bool fault;
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_fptan(t, one, a, &fault);
        if (fault) {
            set_c2(ctx, 1);
            return;
        }
        x87_set_ext80(ctx, 0, t);
        x87_push(ctx);
        x87_set_ext80(ctx, 0, one);
        x87_set_exc(ctx, exc);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (fabs(a) >= 9223372036854775808.0) {
            set_c2(ctx, 1);
            return;
        }
        x87_set_f64(ctx, 0, tan(a));
        x87_push(ctx);
        x87_set_f64(ctx, 0, 1.0);
    }
}

void i686_x87_op_fpatan(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a); /* x */
        x87_get_ext80(ctx, 1, b); /* y */
        exc = x87_80_fpatan(r, a, b);
        x87_set_ext80(ctx, 1, r);
        x87_set_exc(ctx, exc);
        x87_pop(ctx);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0); /* x */
        double b = x87_get_f64(ctx, 1); /* y */

        x87_set_f64(ctx, 1, atan2(b, a));
        x87_pop(ctx);
    }
}

void i686_x87_op_fxtract(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t sig[10];
        uint8_t ex[10];

        x87_get_ext80(ctx, 0, a);
        (void)x87_80_fxtract(sig, ex, a);
        x87_push(ctx);
        x87_set_ext80(ctx, 1, ex); /* after: ST(1)=exponent, ST(0)=sig */
        x87_set_ext80(ctx, 0, sig);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        int e = ilogb(a);
        double sig = scalbn(a, -e); /* [1,2) */

        x87_push(ctx);
        x87_set_f64(ctx, 1, (double)e);
        x87_set_f64(ctx, 0, sig);
    }
}

void i686_x87_op_fscale(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];

        x87_get_ext80(ctx, 0, a);
        x87_get_ext80(ctx, 1, b);
        (void)x87_80_fscale(r, a, b);
        x87_set_ext80(ctx, 0, r);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, 1);

        x87_set_f64(ctx, 0, scalbn(a, (int)trunc(b)));
    }
}

void i686_x87_op_fprem(i686_ctx_t *ctx, int ieee)
{
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
        x87_set_ext80(ctx, 0, r);
        x87_set_exc(ctx, exc);
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
                x87_set_exc(ctx, SW_IE);
            }
            x87_set_f64(ctx, 0, (double)NAN);
            set_cc(ctx, 1, 0, 0, 1);
            return;
        }
        q = ieee ? nearbyint(a / b) : trunc(a / b);
        r = ieee ? remainder(a, b) : fmod(a, b);
        x87_set_f64(ctx, 0, r);
        if (r != a) {
            x87_set_exc(ctx, SW_PE);
        }
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
