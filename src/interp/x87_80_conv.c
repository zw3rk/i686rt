/*
 * src/interp/x87_80_conv.c — 80-bit x87 exp/log ops, conversions, and predicates
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interp/x87_80_wx.h"

/* --- f2xm1 / fyl2x / fyl2xp1 --------------------------------------------- */

unsigned x87_80_f2xm1(uint8_t out[10], const uint8_t av[10])
{
    xf_t a, r;
    unsigned flags = 0;

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
        if (a.sign) {
            xf_out_sig(out, true, 0x8000000000000000ULL, -63);
            return 0;
        }
        memcpy(out, av, 10);
        return 0;
    }
    if (a.cls == X_ZERO) {
        memcpy(out, av, 10);
        return 0;
    }
    if (a.exp >= 63) {
        if (a.sign) {
            xf_out_sig(out, true, 0x8000000000000000ULL, -63);
            return 0;
        }
        xf_out_inf(out, false);
        return X_OE | X_PE;
    }
    if (xf_is_den(&a)) flags |= X_DE;

    {
        uint64_t ma;
        int32_t ea;
        int64_t n;
        uint64_t f_int;
        wx_t f, y, e;
        bool exact;

        xf_norm_num(&a, &ma, &ea);
        if (ea <= -1) {
            n = 0;
            f_int = ma;
        } else {
            n = (int64_t)(ma >> (63 - ea));
            f_int = ma - (uint64_t)(n << (63 - ea));
        }
        if (a.sign) n = -n;
        if (n >= 16384) {
            xf_out_inf(out, false);
            return flags | X_OE | X_PE;
        }
        if (n <= -16446) {
            xf_out_sig(out, true, 0x8000000000000000ULL, -63);
            return flags | X_PE;
        }
        exact = (f_int == 0);
        f.m = u2_fr(0, f_int);
        f.e = ea - 63;
        f.sign = a.sign;
        u2_norm(&f.m, &f.e);
        {
            wx_t l2 = wxc(C_LN2);
            y = wx_mul(&f, &l2);
        }
        e = wx_expm1(&y);
        if (n == 0) {
            flags |= round_pack80(&r, e.sign, e.m, e.e, true, 64u);
            xf_encode(&r, out);
            return flags;
        }
        {
            wx_t one = wx_one(), v, res;
            v = wx_add(&one, &e);
            v.e += (int32_t)n;
            res = wx_sub(&v, &one);
            flags |= round_pack80(&r, res.sign, res.m, res.e, !exact, 64u);
            xf_encode(&r, out);
        }
    }
    return flags;
}

static wx_t wx_log2(uint64_t ma)
{
    wx_t m, ln, l2e;
    m.m = u2_fr(0, ma);
    m.e = -63;
    m.sign = false;
    u2_norm(&m.m, &m.e);
    ln = wx_ln_m(m);
    l2e = wxc(C_LOG2E);
    return wx_mul(&ln, &l2e);
}

unsigned x87_80_fyl2x(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10])
{
    xf_t a, b, r;
    unsigned flags = 0;

    xf_decode(av, &a);
    xf_decode(bv, &b);
    if (a.unsup || b.unsup) {
        xf_out_indef(out);
        return X_IE;
    }
    if (xf_is_nan_cls(&a) || xf_is_nan_cls(&b)) {
        flags = xf_nan_prop(&r, &a, &b);
        xf_encode(&r, out);
        return flags;
    }
    if (xf_is_den(&a) || xf_is_den(&b)) flags |= X_DE;

    if (a.cls == X_INF) {
        if (b.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
        if (b.cls == X_INF) { xf_out_inf(out, b.sign); return 0; }
        xf_out_inf(out, b.sign);
        return 0;
    }
    if (a.cls == X_ZERO) {
        if (b.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
        if (b.cls == X_INF) { xf_out_inf(out, !b.sign); return 0; }
        flags |= X_ZE;
        xf_out_inf(out, !b.sign);
        return flags;
    }
    if (a.sign) {
        xf_out_indef(out);
        return X_IE;
    }
    if (a.cls == X_NUM && !a.den_enc && a.exp == 0 &&
        a.mant == 0x8000000000000000ULL) {
        if (b.cls == X_INF) { xf_out_indef(out); return X_IE; }
        xf_out_zero(out, b.sign);
        return 0;
    }
    if (b.cls == X_INF) {
        bool lneg = a.exp < 0 || (a.exp == 0 && a.mant < 0x8000000000000000ULL);
        xf_out_inf(out, b.sign ^ lneg);
        return 0;
    }
    if (b.cls == X_ZERO) {
        xf_out_zero(out, b.sign);
        return 0;
    }
    if (a.cls == X_NUM && !a.den_enc && a.mant == 0x8000000000000000ULL) {
        uint64_t mb;
        int32_t eb;
        int64_t eint = a.exp;
        u2 prod;
        xf_norm_num(&b, &mb, &eb);
        prod = mul64(mb, (uint64_t)(eint < 0 ? -eint : eint));
        flags |= round_pack80(&r, b.sign ^ (eint < 0), prod, eb - 63, false, 64u);
        xf_encode(&r, out);
        return flags;
    }

    {
        uint64_t ma;
        int32_t ea;
        wx_t L, res;
        xf_norm_num(&a, &ma, &ea);
        L = wx_log2(ma);
        {
            wx_t E;
            E.m = u2_fr(0, (uint64_t)(ea < 0 ? -ea : ea));
            E.e = 0;
            E.sign = ea < 0;
            u2_norm(&E.m, &E.e);
            L = wx_add(&L, &E);
        }
        {
            wx_t bw;
            xf_norm_num(&b, &ma, &ea);
            bw.m = u2_fr(0, ma);
            bw.e = ea - 63;
            bw.sign = b.sign;
            u2_norm(&bw.m, &bw.e);
            res = wx_mul(&bw, &L);
        }
        flags |= round_pack80(&r, res.sign, res.m, res.e, b.cls != X_ZERO, 64u);
        xf_encode(&r, out);
    }
    return flags;
}

unsigned x87_80_fyl2xp1(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10])
{
    xf_t a, b, r;
    unsigned flags = 0;

    xf_decode(av, &a);
    xf_decode(bv, &b);
    if (a.unsup || b.unsup) {
        xf_out_indef(out);
        return X_IE;
    }
    if (xf_is_nan_cls(&a) || xf_is_nan_cls(&b)) {
        flags = xf_nan_prop(&r, &a, &b);
        xf_encode(&r, out);
        return flags;
    }
    if (xf_is_den(&a) || xf_is_den(&b)) flags |= X_DE;

    if (a.cls == X_ZERO) {
        if (b.cls == X_INF) { xf_out_indef(out); return X_IE; }
        xf_out_zero(out, b.sign);
        return 0;
    }
    if (a.cls == X_INF) {
        if (!a.sign) {
            if (b.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
            xf_out_inf(out, b.sign);
            return 0;
        }
        xf_out_indef(out);
        return X_IE;
    }
    if (a.sign && a.cls == X_NUM) {
        if (a.exp > 0 || (a.exp == 0 && a.mant > 0x8000000000000000ULL)) {
            xf_out_indef(out);
            return X_IE;
        }
        if (a.exp == 0 && a.mant == 0x8000000000000000ULL) {
            if (b.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
            if (b.cls == X_INF) { xf_out_inf(out, !b.sign); return 0; }
            xf_out_inf(out, !b.sign);
            return 0;
        }
    }
    if (b.cls == X_INF) {
        xf_out_inf(out, b.sign ^ a.sign);
        return 0;
    }
    if (a.cls == X_NUM && !a.den_enc) {
        unsigned k = 0;
        uint64_t m = a.mant;
        while (k < 64u && (m >> (63u - k)) & 1u) k++;
        if (k >= 1u && (k == 64u || (m << k) == 0u) &&
            ((a.sign && a.exp == -1) || (!a.sign && (int)k == a.exp + 1))) {
            int64_t eint = a.sign ? -(int64_t)k : (int64_t)k;
            uint64_t mb;
            int32_t eb;
            u2 prod;
            xf_norm_num(&b, &mb, &eb);
            prod = mul64(mb, (uint64_t)(eint < 0 ? -eint : eint));
            flags |= round_pack80(&r, b.sign ^ (eint < 0), prod, eb - 63,
                                  false, 64u);
            xf_encode(&r, out);
            return flags;
        }
    }

    {
        wx_t aw, z, den, ln, l2e, res;
        uint64_t ma;
        int32_t ea;

        xf_norm_num(&a, &ma, &ea);
        aw.m = u2_fr(0, ma);
        aw.e = ea - 63;
        aw.sign = a.sign;
        u2_norm(&aw.m, &aw.e);

        if (ea >= 1 || (a.sign && ea >= -1)) {
            uint8_t one80[10], sum80[10];
            xf_t s;
            unsigned pc_saved = g_pc;
            g_pc = 64u;
            x87_80_one(one80);
            x87_80_add(sum80, av, one80);
            g_pc = pc_saved;
            xf_decode(sum80, &s);
            if (s.cls != X_NUM) {
                xf_out_inf(out, false);
                return X_OE | X_PE;
            }
            xf_norm_num(&s, &ma, &ea);
            ln = wx_log2(ma);
            {
                wx_t E;
                E.m = u2_fr(0, (uint64_t)(ea < 0 ? -ea : ea));
                E.e = 0;
                E.sign = ea < 0;
                u2_norm(&E.m, &E.e);
                ln = wx_add(&ln, &E);
            }
            goto have_log;
        }
        {
            wx_t one = wx_one(), two = wx_add(&one, &one);
            z = aw;
            den = wx_add(&two, &z);
            z = wx_div(&z, &den);
        }
        {
            wx_t sum, term;
            int k;
            sum = z;
            term = z;
            {
                wx_t z2 = wx_mul(&z, &z);
                for (k = 1; k <= 44; k++) {
                    wx_t f = wxc(C_INV_K(2 * k + 1));
                    wx_t num = wx_int((uint64_t)(2 * k - 1));
                    term = wx_mul(&term, &z2);
                    term = wx_mul(&term, &num);
                    term = wx_mul(&term, &f);
                    sum = wx_add(&sum, &term);
                    if (k > 6 && wx_tiny(&term, &sum)) break;
                }
            }
            ln = wx_add(&sum, &sum);
        }
        l2e = wxc(C_LOG2E);
        ln = wx_mul(&ln, &l2e);
    have_log:;
        {
            wx_t bw;
            xf_norm_num(&b, &ma, &ea);
            bw.m = u2_fr(0, ma);
            bw.e = ea - 63;
            bw.sign = b.sign;
            u2_norm(&bw.m, &bw.e);
            res = wx_mul(&bw, &ln);
        }
        flags |= round_pack80(&r, res.sign, res.m, res.e, b.cls != X_ZERO, 64u);
        xf_encode(&r, out);
    }
    return flags;
}

/* --- conversions --------------------------------------------------------- */

unsigned x87_80_from_i32(uint8_t out[10], int32_t v)
{
    xf_out_sig(out, v < 0, (uint64_t)(v < 0 ? -(int64_t)v : (int64_t)v), 0);
    return 0;
}

unsigned x87_80_from_i64(uint8_t out[10], int64_t v)
{
    bool neg = v < 0;
    uint64_t m = neg ? (uint64_t)(-(v + 1)) + 1u : (uint64_t)v;
    xf_out_sig(out, neg, m, 0);
    return 0;
}

unsigned x87_80_from_f32(uint8_t out[10], float v)
{
    uint32_t bits;
    uint32_t be, frac;
    bool sign;

    memcpy(&bits, &v, 4);
    sign = (bits >> 31) != 0;
    be = (bits >> 23) & 0xFFu;
    frac = bits & 0x7FFFFFu;
    if (be == 0xFFu) {
        if (frac == 0) {
            xf_out_inf(out, sign);
        } else {
            xf_t f;
            memset(&f, 0, sizeof f);
            f.cls = (frac >> 22) ? X_QNAN : X_SNAN;
            f.sign = sign;
            f.mant = 0x8000000000000000ULL | ((uint64_t)frac << 40);
            xf_encode(&f, out);
        }
        return 0;
    }
    if (be == 0) {
        if (frac == 0) { xf_out_zero(out, sign); return 0; }
        xf_out_sig(out, sign, frac, -149);
        return X_DE;
    }
    xf_out_sig(out, sign, 0x8000000000000000ULL | ((uint64_t)frac << 40),
               (int32_t)be - 127 - 63);
    return 0;
}

unsigned x87_80_from_f64(uint8_t out[10], double v)
{
    uint64_t bits, frac;
    unsigned be;
    bool sign;

    memcpy(&bits, &v, 8);
    sign = (bits >> 63) != 0;
    be = (unsigned)((bits >> 52) & 0x7FFu);
    frac = bits & 0xFFFFFFFFFFFFFULL;
    if (be == 0x7FFu) {
        if (frac == 0) xf_out_inf(out, sign);
        else {
            xf_t f;
            memset(&f, 0, sizeof f);
            f.cls = (frac >> 51) ? X_QNAN : X_SNAN;
            f.sign = sign;
            f.mant = 0x8000000000000000ULL | (frac << 11);
            xf_encode(&f, out);
        }
        return 0;
    }
    if (be == 0) {
        if (frac == 0) { xf_out_zero(out, sign); return 0; }
        xf_out_sig(out, sign, frac, -1074);
        return X_DE;
    }
    xf_out_sig(out, sign, 0x8000000000000000ULL | (frac << 11),
               (int32_t)be - 1023 - 63);
    return 0;
}

static unsigned to_int_core(const xf_t *f, uint64_t limit, uint64_t *ival,
                            bool *valid)
{
    uint64_t m, q;
    int32_t e;
    unsigned flags = 0;
    bool inexact = false;

    *valid = true;
    if (f->unsup || xf_is_nan_cls(f) || f->cls == X_INF) {
        *ival = limit;
        *valid = false;
        return X_IE;
    }
    if (xf_is_den(f)) flags |= X_DE;
    if (f->cls == X_ZERO) {
        *ival = 0;
        return flags;
    }
    xf_norm_num(f, &m, &e);
    if (e <= -1) {
        /* R7-33: nearest-even on [0.5, 1) (e == -1): exact one-half
         * is even (0); anything above rounds to 1.  The old code
         * rounded every such value to zero (0.75 -> 0). */
        bool up;

        if (g_rc == 0u && e == -1) {
            up = (m != 0x8000000000000000ULL);
        } else {
            up = (g_rc == 2u && !f->sign) || (g_rc == 1u && f->sign);
        }
        *ival = up ? 1u : 0u;
        return flags | X_PE;
    }
    if (e <= 63) {
        unsigned k = (unsigned)(63 - e);
        if (k == 0) {
            q = m;
        } else {
            uint64_t fl = m >> k;
            bool guard = ((m >> (k - 1)) & 1u) != 0;
            bool rest = (k > 1 && (m & ((((uint64_t)1) << (k - 1)) - 1)) != 0);
            bool lsb = (fl & 1u) != 0;
            inexact = guard || rest;
            if (round_inc(lsb, guard, rest, f->sign)) fl++;
            q = fl;
        }
    } else {
        unsigned sh = (unsigned)(e - 63);
        if (sh >= 64 || (m >> (64 - sh)) != 0) {
            *ival = limit;
            *valid = false;
            return flags | X_IE;
        }
        q = m << sh;
    }
    if (q > limit || (q == limit && !f->sign)) {
        *ival = limit;
        *valid = false;
        return flags | X_IE;
    }
    *ival = q;
    return flags | (inexact ? X_PE : 0u);
}

unsigned x87_80_to_i32(const uint8_t in[10], int32_t *out, unsigned rc_override)
{
    xf_t f;
    uint64_t q;
    bool valid;
    unsigned flags, rc_saved;

    if (rc_override <= 3u) {
        rc_saved = g_rc;
        g_rc = rc_override;
        xf_decode(in, &f);
        flags = to_int_core(&f, 0x80000000ULL, &q, &valid);
        g_rc = rc_saved;
    } else {
        xf_decode(in, &f);
        flags = to_int_core(&f, 0x80000000ULL, &q, &valid);
    }
    if (!valid) {
        *out = -2147483647 - 1;
        return flags;
    }
    if (q == 0x80000000ULL) *out = -2147483647 - 1;
    else *out = f.sign ? -(int32_t)q : (int32_t)q;
    return flags;
}

unsigned x87_80_to_i64(const uint8_t in[10], int64_t *out)
{
    xf_t f;
    uint64_t q;
    bool valid;
    unsigned flags;

    xf_decode(in, &f);
    flags = to_int_core(&f, 0x8000000000000000ULL, &q, &valid);
    if (!valid) {
        *out = (int64_t)(uint64_t)0x8000000000000000ULL;
        return flags;
    }
    if (q == 0x8000000000000000ULL) {
        *out = (int64_t)(uint64_t)0x8000000000000000ULL;
    } else {
        *out = f.sign ? -(int64_t)q : (int64_t)q;
    }
    return flags;
}

/* R7-24: the sign lands at `signbit` (bit 63 for binary64, bit 31
 * for binary32) so narrowing callers keep negative signs. */
static unsigned to_ieee_bits(const xf_t *f, unsigned p, int emax, int emin,
                             int bias, int fracbits, uint64_t inf_bits,
                             uint64_t max_bits, uint64_t signbit,
                             uint64_t *bits)
{
    uint64_t m, sig;
    int32_t e;
    unsigned flags = 0;
    int eff, shift;
    bool inexact, tiny;

    if (xf_is_den(f)) flags |= X_DE;
    xf_norm_num(f, &m, &e);
    {
        u2 m128 = u2_fr(m, 0);
        int32_t exp = e;
        tiny = exp < emin;
        shift = tiny ? (emin - exp) : 0;
        eff = (int)p - shift;
        if (eff < 0) {
            bool up = (g_rc == 1u && f->sign) || (g_rc == 2u && !f->sign);

            *bits = up ? 1u : 0u;
            if (f->sign) *bits |= signbit;
            return flags | X_UE | X_PE;
        }
        sig = rnd_sig(m128, false, eff, f->sign, &inexact);
        if (eff >= 1 && sig == (((uint64_t)1) << eff)) {
            sig >>= 1;
            exp++;
        }
        if (inexact) flags |= X_PE;
        if (tiny && inexact) flags |= X_UE;
        if (exp > emax) {
            bool to_inf = (g_rc == 0u) || (g_rc == 2u && !f->sign) ||
                          (g_rc == 1u && f->sign);
            flags |= X_OE | X_PE;
            *bits = to_inf ? inf_bits : max_bits;
            if (f->sign) *bits |= signbit;
            return flags;
        }
        if (exp >= emin) {
            uint64_t expf = (uint64_t)(exp + bias) << fracbits;
            *bits = expf | (sig - (((uint64_t)1) << (int)(p - 1)));
        } else {
            int64_t sh = (int64_t)exp - eff + 1 + (int64_t)(fracbits - emin);
            uint64_t frac = sh >= 64 ? 0 : (sig << sh);
            *bits = frac;
        }
        if (f->sign) *bits |= signbit;
    }
    return flags;
}

unsigned x87_80_to_f64(const uint8_t in[10], double *out)
{
    xf_t f;
    uint64_t bits = 0;
    unsigned flags;

    xf_decode(in, &f);
    if (f.unsup || xf_is_nan_cls(&f)) {
        bool snan = f.unsup || f.cls == X_SNAN;
        bits = 0x7FF0000000000000ULL | 0x0008000000000000ULL |
               ((f.mant >> 11) & 0x000FFFFFFFFFFFFFULL);
        if (f.sign) bits |= 0x8000000000000000ULL;
        memcpy(out, &bits, 8);
        return snan ? X_IE : 0u;
    }
    if (f.cls == X_INF) {
        bits = f.sign ? 0xFFF0000000000000ULL : 0x7FF0000000000000ULL;
        memcpy(out, &bits, 8);
        return 0;
    }
    if (f.cls == X_ZERO) {
        bits = f.sign ? 0x8000000000000000ULL : 0;
        memcpy(out, &bits, 8);
        return 0;
    }
    flags = to_ieee_bits(&f, 53u, 1023, -1022, 1023, 52,
                         0x7FF0000000000000ULL, 0x7FEFFFFFFFFFFFFFULL,
                         0x8000000000000000ULL, &bits);
    memcpy(out, &bits, 8);
    return flags;
}

unsigned x87_80_to_f32(const uint8_t in[10], float *out)
{
    xf_t f;
    uint64_t bits = 0;
    uint32_t b32;
    unsigned flags;

    xf_decode(in, &f);
    if (f.unsup || xf_is_nan_cls(&f)) {
        bool snan = f.unsup || f.cls == X_SNAN;
        bits = 0x7F800000ULL | 0x400000ULL |
               ((f.mant >> 40) & 0x7FFFFFULL);
        if (f.sign) bits |= 0x80000000ULL;
        b32 = (uint32_t)bits;
        memcpy(out, &b32, 4);
        return snan ? X_IE : 0u;
    }
    if (f.cls == X_INF) {
        b32 = f.sign ? 0xFF800000u : 0x7F800000u;
        memcpy(out, &b32, 4);
        return 0;
    }
    if (f.cls == X_ZERO) {
        b32 = f.sign ? 0x80000000u : 0u;
        memcpy(out, &b32, 4);
        return 0;
    }
    flags = to_ieee_bits(&f, 24u, 127, -126, 127, 23,
                         0x7F800000ULL, 0x7F7FFFFFULL,
                         0x80000000ULL, &bits);
    b32 = (uint32_t)bits;
    memcpy(out, &b32, 4);
    return flags;
}

/* --- predicates ---------------------------------------------------------- */

bool x87_80_is_zero(const uint8_t v[10])
{
    xf_t f;
    xf_decode(v, &f);
    return f.cls == X_ZERO;
}

bool x87_80_is_inf(const uint8_t v[10])
{
    xf_t f;
    xf_decode(v, &f);
    return f.cls == X_INF && !f.unsup;
}

bool x87_80_is_nan(const uint8_t v[10])
{
    xf_t f;
    xf_decode(v, &f);
    return xf_is_nan_cls(&f) && !f.unsup;
}

bool x87_80_is_snan(const uint8_t v[10])
{
    xf_t f;
    xf_decode(v, &f);
    return f.cls == X_SNAN && !f.unsup;
}

bool x87_80_sign(const uint8_t v[10])
{
    return (v[9] >> 7) != 0;
}
