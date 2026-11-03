/*
 * src/interp/x87_80_trig.c — 80-bit x87 trigonometric ops (fsin/fcos/fptan/fpatan)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interp/x87_80_wx.h"

/* atan(t) for 0 <= t <= 1; folds t > 2-sqrt3 through
 * atan(t) = pi/6 + atan((t*sqrt3-1)/(t+sqrt3)) so the series argument
 * stays <= 2-sqrt3 (about 36 terms to 2^-140). */
static wx_t wx_atan1(const wx_t *t)
{
    wx_t tn = *t, sum, term, res;
    wx_t c2s3 = wxc(C_2MSQ3);
    bool fold = wx_cmp_abs(&tn, &c2s3) > 0;

    if (fold) {
        wx_t s3 = wxc(C_SQRT3);
        wx_t one = wx_one();
        wx_t num = wx_mul(&tn, &s3);
        wx_t den;
        num = wx_sub(&num, &one);
        den = wx_add(&tn, &s3);
        tn = wx_div(&num, &den);
    }
    sum = tn;
    term = tn;
    {
        wx_t t2 = wx_mul(&tn, &tn);
        int k;
        for (k = 1; k <= 44; k++) {
            wx_t f = wxc(C_INV_K(2 * k + 1));
            wx_t num = wx_int((uint64_t)(2 * k - 1));
            term = wx_mul(&term, &t2);
            term = wx_mul(&term, &num);
            term = wx_mul(&term, &f);
            term.sign = tn.sign ^ (((unsigned)k & 1u) != 0u);
            sum = wx_add(&sum, &term);
            if (k > 6 && wx_tiny(&term, &sum)) break;
        }
    }
    res = sum;
    if (fold) {
        wx_t p6 = wxc(C_PI6);
        res = wx_add(&p6, &res);
    }
    return res;
}

/* --- exact sin/cos argument reduction ------------------------------------ */

static void add_carry64(uint64_t *a, unsigned nlimbs, unsigned at, uint64_t v)
{
    unsigned i = at;
    uint64_t old = a[i];
    unsigned carry;

    a[i] = old + v;
    carry = (a[i] < old) ? 1u : 0u;
    while (carry && ++i < nlimbs) {
        old = a[i];
        a[i] = old + 1u;
        carry = (a[i] < old) ? 1u : 0u;
    }
}

static void reduce_pi2(uint64_t ma, int32_t ea, uint64_t ru[6], bool *rneg,
                       unsigned *oct)
{
    u2 P;
    uint64_t n, acc[8], au[6], npl[6];
    unsigned t, bits, limbs, b, i;
    bool guard, rest;

    P = mul64(ma, C_2OPI[0]);
    t = (unsigned)(126 - ea);
    n = u2_shr(P, t).lo;
    {
        unsigned g = t - 1u;
        if (g >= 64u) {
            guard = ((P.hi >> (g - 64u)) & 1u) != 0;
            if (g == 64u) {
                rest = P.lo != 0;
            } else {
                rest = ((P.hi & ((((uint64_t)1) << (g - 64u)) - 1)) != 0) ||
                       (P.lo != 0);
            }
        } else {
            guard = ((P.lo >> 63) & 1u) != 0;
            rest = (P.lo & 0x7FFFFFFFFFFFFFFFULL) != 0;
        }
    }
    if (guard && rest) n++;

    memset(acc, 0, sizeof acc);
    for (i = 0; i < 5; i++) {
        u2 p = mul64(n, C_PI2_320[i]);
        add_carry64(acc, 8u, 4 - i, p.lo);
        add_carry64(acc, 8u, 5 - i, p.hi);
    }
    for (i = 0; i < 6; i++) npl[i] = acc[i];

    memset(au, 0, sizeof au);
    bits = (unsigned)(ea + 256);
    limbs = bits / 64u;
    b = bits % 64u;
    if (b == 0u) {
        au[limbs] = ma;
    } else {
        au[limbs] = ma << b;
        au[limbs + 1] = ma >> (64u - b);
    }

    {
        int cmp = 0, j;
        for (j = 5; j >= 0; j--) {
            if (au[j] != npl[j]) { cmp = au[j] < npl[j] ? -1 : 1; break; }
        }
        if (cmp >= 0) {
            unsigned borrow = 0;
            for (j = 0; j < 6; j++) {
                uint64_t sub = npl[j] + borrow;
                unsigned nb = (sub < npl[j]) ? 1u : 0u;
                uint64_t rr = au[j] - sub;
                if (rr > au[j]) nb = 1u;
                au[j] = rr;
                borrow = nb;
            }
            *rneg = false;
        } else {
            unsigned borrow = 0;
            for (j = 0; j < 6; j++) {
                uint64_t sub = au[j] + borrow;
                unsigned nb = (sub < au[j]) ? 1u : 0u;
                uint64_t rr = npl[j] - sub;
                if (rr > npl[j]) nb = 1u;
                npl[j] = rr;
                borrow = nb;
            }
            for (j = 0; j < 6; j++) au[j] = npl[j];
            *rneg = true;
        }
    }
    for (i = 0; i < 6; i++) ru[i] = au[i];
    *oct = (unsigned)(n & 3u);
}

static void sincos_w(const wx_t *r, wx_t *s, wx_t *c)
{
    wx_t r2, p, sum, one = wx_one();
    int k;

    r2 = wx_mul(r, r);
    p = *r;
    sum = *r;
    for (k = 1; k <= 24; k++) {
        wx_t f1 = wxc(C_INV_K(2 * k)), f2 = wxc(C_INV_K(2 * k + 1));
        p = wx_mul(&p, &r2);
        p = wx_mul(&p, &f1);
        p = wx_mul(&p, &f2);
        p.sign = !p.sign;
        sum = wx_add(&sum, &p);
        if (k > 8 && wx_tiny(&p, &sum)) break;
    }
    *s = sum;

    {
        wx_t half = wxc(C_INV_K(2));
        p = wx_mul(&r2, &half);
    }
    p.sign = true;
    sum = wx_add(&one, &p);
    for (k = 2; k <= 24; k++) {
        wx_t f1 = wxc(C_INV_K(2 * k - 1)), f2 = wxc(C_INV_K(2 * k));
        p = wx_mul(&p, &r2);
        p = wx_mul(&p, &f1);
        p = wx_mul(&p, &f2);
        p.sign = !p.sign;
        sum = wx_add(&sum, &p);
        if (k > 8 && wx_tiny(&p, &sum)) break;
    }
    *c = sum;
}

static void wx_from_ru(const uint64_t ru[6], bool rneg, wx_t *w, bool *sticky)
{
    int k = 5, b;
    unsigned p, shift;
    u2 m;
    bool stick = false;

    while (k >= 0 && ru[k] == 0) k--;
    if (k < 0) {
        *w = wx_zero();
        w->sign = rneg;
        *sticky = false;
        return;
    }
    b = 63;
    while (!((ru[k] >> b) & 1u)) b--;
    p = (unsigned)(64 * k + b);
    if (p >= 127) {
        shift = p - 127;
        {
            uint64_t tmp[6];
            unsigned limbs = shift / 64u, sb = shift % 64u, i;
            memset(tmp, 0, sizeof tmp);
            for (i = 0; i + limbs < 6u; i++) tmp[i] = ru[i + limbs];
            if (sb) {
                uint64_t carry = 0;
                int j;
                for (j = 5; j >= 0; j--) {
                    uint64_t nv = (tmp[j] >> sb) | carry;
                    carry = tmp[j] << (64u - sb);
                    tmp[j] = nv;
                }
            }
            m.hi = tmp[1];
            m.lo = tmp[0];
            for (i = 2; i < 6u; i++) if (tmp[i] != 0) { stick = true; break; }
        }
        w->e = (int32_t)p - 319 - 127;
    } else {
        shift = 127 - p;
        {
            unsigned limbs = shift / 64u, sb = shift % 64u;
            m = u2_fr(0, 0);
            if (limbs == 0) {
                m.lo = ru[0] << sb;
                m.hi = (ru[1] << sb) | (sb ? (ru[0] >> (64u - sb)) : 0);
            } else if (limbs == 1) {
                m.lo = ru[1] << sb;
                m.hi = (ru[2] << sb) | (sb ? (ru[1] >> (64u - sb)) : 0);
            }
        }
        w->e = (int32_t)p - 319 - 127;
    }
    w->m = m;
    w->sign = rneg;
    *sticky = stick;
}

typedef struct {
    wx_t sin_r, cos_r;
    bool sin_sticky, cos_sticky;
    unsigned oct;
} tri_t;

static void trig_reduce(const xf_t *ax, tri_t *tr)
{
    uint64_t ma;
    int32_t ea;
    wx_t r;

    tr->oct = 0;
    if (ax->exp <= -34) {
        xf_norm_num(ax, &ma, &ea);
        tr->sin_r.m = u2_fr(0, ma);
        tr->sin_r.e = ea - 63;
        tr->sin_r.sign = false;
        u2_norm(&tr->sin_r.m, &tr->sin_r.e);
        tr->sin_sticky = false;
        tr->cos_r = wx_one();
        tr->cos_sticky = true;
        return;
    }
    if (ax->exp < -2 || (ax->exp == -2 && ax->mant <= C_PI4_LIMIT)) {
        xf_norm_num(ax, &ma, &ea);
        r.m = u2_fr(0, ma);
        r.e = ea - 63;
        r.sign = false;
        u2_norm(&r.m, &r.e);
        sincos_w(&r, &tr->sin_r, &tr->cos_r);
        tr->sin_sticky = true;
        tr->cos_sticky = true;
        return;
    }
    {
        uint64_t ru[6];
        bool rneg, stick;
        unsigned p_top;
        int k = 5, b;

        xf_norm_num(ax, &ma, &ea);
        reduce_pi2(ma, ea, ru, &rneg, &tr->oct);
        while (k >= 0 && ru[k] == 0) k--;
        if (k < 0) {
            tr->sin_r = wx_zero();
            tr->sin_r.sign = false;
            tr->sin_sticky = false;
            tr->cos_r = wx_one();
            tr->cos_sticky = true;
            return;
        }
        b = 63;
        while (!((ru[k] >> b) & 1u)) b--;
        p_top = (unsigned)(64 * k + b);
        if (p_top < 286) {
            wx_from_ru(ru, rneg, &tr->sin_r, &stick);
            tr->sin_sticky = stick;
            tr->cos_r = wx_one();
            tr->cos_sticky = true;
            return;
        }
        wx_from_ru(ru, rneg, &r, &stick);
        sincos_w(&r, &tr->sin_r, &tr->cos_r);
        tr->sin_sticky = true;
        tr->cos_sticky = true;
    }
}

static unsigned fsincos_common(uint8_t out[10], const uint8_t av[10],
                               bool want_cos, bool *stack_fault)
{
    xf_t a, r;
    unsigned flags = 0;
    tri_t tr;
    wx_t v;
    bool neg;

    *stack_fault = false;
    xf_decode(av, &a);
    if (a.unsup) {
        xf_out_indef(out);
        return X_IE;
    }
    if (xf_is_nan_cls(&a)) {
        flags = xf_nan_prop(&r, &a, NULL);
        xf_encode(&r, out);
        return flags;
    }
    if (a.cls == X_INF) {
        xf_out_indef(out);
        return X_IE;
    }
    if (a.cls == X_NUM && a.exp >= 63) {
        /* R7-38: outside the reduction range: C2 (incomplete),
         * operand unchanged, no exception (not #IA). */
        memcpy(out, av, 10);
        *stack_fault = true;
        return 0;
    }
    if (xf_is_den(&a)) flags |= X_DE;
    if (a.cls == X_ZERO) {
        if (want_cos) x87_80_one(out);
        else memcpy(out, av, 10);
        return flags;
    }

    {
        xf_t ax = a;
        ax.sign = false;
        trig_reduce(&ax, &tr);
    }
    if (want_cos) {
        switch (tr.oct) {
        case 0: v = tr.cos_r; neg = false; break;
        case 1: v = tr.sin_r; neg = true; break;
        case 2: v = tr.cos_r; neg = true; break;
        default: v = tr.sin_r; neg = false; break;
        }
        flags |= round_pack80(&r, v.sign ^ neg, v.m, v.e, tr.cos_sticky, 64u);
    } else {
        switch (tr.oct) {
        case 0: case 2: v = tr.sin_r; break;
        default: v = tr.cos_r; break;
        }
        neg = (tr.oct & 2u) != 0u;
        flags |= round_pack80(&r, v.sign ^ neg ^ a.sign, v.m, v.e,
                              tr.sin_sticky, 64u);
    }
    xf_encode(&r, out);
    return flags;
}

unsigned x87_80_fsin(uint8_t out[10], const uint8_t a[10], bool *stack_fault)
{
    return fsincos_common(out, a, false, stack_fault);
}

unsigned x87_80_fcos(uint8_t out[10], const uint8_t a[10], bool *stack_fault)
{
    return fsincos_common(out, a, true, stack_fault);
}

unsigned x87_80_fptan(uint8_t out_tan[10], uint8_t out_one[10],
                      const uint8_t av[10], bool *stack_fault)
{
    xf_t a, r;
    unsigned flags = 0;
    tri_t tr;
    wx_t sin_v, cos_v, tan_v;

    *stack_fault = false;
    xf_decode(av, &a);
    if (a.unsup) {
        xf_out_indef(out_tan);
        x87_80_one(out_one);
        return X_IE;
    }
    if (xf_is_nan_cls(&a)) {
        flags = xf_nan_prop(&r, &a, NULL);
        xf_encode(&r, out_tan);
        x87_80_one(out_one);
        return flags;
    }
    if (a.cls == X_INF) {
        xf_out_indef(out_tan);
        x87_80_one(out_one);
        return X_IE;
    }
    if (a.cls == X_NUM && a.exp >= 63) {
        /* R7-38: outside the reduction range: C2 (incomplete),
         * operand unchanged, no exception (not #IA). */
        memcpy(out_tan, av, 10);
        x87_80_one(out_one);
        *stack_fault = true;
        return 0;
    }
    if (xf_is_den(&a)) flags |= X_DE;
    x87_80_one(out_one);
    if (a.cls == X_ZERO) {
        memcpy(out_tan, av, 10);
        return flags;
    }

    {
        xf_t ax = a;
        ax.sign = false;
        trig_reduce(&ax, &tr);
    }
    switch (tr.oct) {
    case 0: sin_v = tr.sin_r; cos_v = tr.cos_r; break;
    case 1: sin_v = tr.cos_r; cos_v = tr.sin_r; cos_v.sign = !cos_v.sign; break;
    case 2: sin_v = tr.sin_r; sin_v.sign = !sin_v.sign; cos_v = tr.cos_r; cos_v.sign = !cos_v.sign; break;
    default: sin_v = tr.cos_r; cos_v = tr.sin_r; sin_v.sign = !sin_v.sign; break;
    }
    tan_v = wx_div(&sin_v, &cos_v);
    flags |= round_pack80(&r, tan_v.sign ^ a.sign, tan_v.m, tan_v.e, true, 64u);
    xf_encode(&r, out_tan);
    return flags;
}

unsigned x87_80_fpatan(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10])
{
    xf_t x, y, r;
    unsigned flags = 0;

    xf_decode(av, &x);
    xf_decode(bv, &y);
    if (x.unsup || y.unsup) {
        xf_out_indef(out);
        return X_IE;
    }
    if (xf_is_nan_cls(&x) || xf_is_nan_cls(&y)) {
        flags = xf_nan_prop(&r, &x, &y);
        xf_encode(&r, out);
        return flags;
    }
    if (xf_is_den(&x) || xf_is_den(&y)) flags |= X_DE;

    {
        wx_t pi = wx_pi(), pi2 = wxc(C_PI2), pi4 = wxc(C_PI4);
        wx_t t3pi4 = wx_add(&pi2, &pi4);
        bool y0 = y.cls == X_ZERO, x0 = x.cls == X_ZERO;
        bool yi = y.cls == X_INF, xi = x.cls == X_INF;

        if (yi && xi) {
            /* R7-46: atan2(+-inf,+-inf) is +-pi/4 for x>0 but
             * +-3*pi/4 for x<0 (each with the sign of y). */
            if (x.sign) {
                flags |= round_pack80(&r, y.sign, t3pi4.m, t3pi4.e, true, 64u);
            } else {
                flags |= round_pack80(&r, y.sign, pi4.m, pi4.e, true, 64u);
            }
            xf_encode(&r, out);
            return flags;
        }
        if (xi) {
            if (x.sign) {
                flags |= round_pack80(&r, y.sign, pi.m, pi.e, true, 64u);
            } else {
                xf_out_zero(out, y.sign);
                return flags;
            }
            xf_encode(&r, out);
            return flags;
        }
        if (yi) {
            flags |= round_pack80(&r, y.sign, pi2.m, pi2.e, true, 64u);
            xf_encode(&r, out);
            return flags;
        }
        if (x0 || y0) {
            if (x0 && y0) {
                if (x.sign) {
                    flags |= round_pack80(&r, y.sign, pi.m, pi.e, true, 64u);
                    xf_encode(&r, out);
                } else {
                    xf_out_zero(out, y.sign);
                }
                return flags;
            }
            if (x0) {
                flags |= round_pack80(&r, y.sign, pi2.m, pi2.e, true, 64u);
                xf_encode(&r, out);
                return flags;
            }
            if (x.sign) {
                flags |= round_pack80(&r, y.sign, pi.m, pi.e, true, 64u);
                xf_encode(&r, out);
            } else {
                xf_out_zero(out, y.sign);
            }
            return flags;
        }
    }

    {
        wx_t yw, xw, t, R, res;
        uint64_t my, mx;
        int32_t ey, ex;
        bool swap;

        xf_norm_num(&y, &my, &ey);
        xf_norm_num(&x, &mx, &ex);
        yw.m = u2_fr(0, my); yw.e = ey - 63; yw.sign = false;
        u2_norm(&yw.m, &yw.e);
        xw.m = u2_fr(0, mx); xw.e = ex - 63; xw.sign = false;
        u2_norm(&xw.m, &xw.e);
        swap = wx_cmp_abs(&yw, &xw) > 0;
        if (swap) {
            t = wx_div(&xw, &yw);
            R = wx_atan1(&t);
            {
                wx_t pi2 = wxc(C_PI2);
                R = wx_sub(&pi2, &R);
            }
        } else {
            t = wx_div(&yw, &xw);
            R = wx_atan1(&t);
        }
        if (!x.sign) {
            res = R;
            res.sign = y.sign;
        } else {
            wx_t pi = wx_pi();
            res = wx_sub(&pi, &R);
            res.sign = res.sign ^ y.sign;
        }
        flags |= round_pack80(&r, res.sign, res.m, res.e, true, 64u);
        xf_encode(&r, out);
    }
    return flags;
}
