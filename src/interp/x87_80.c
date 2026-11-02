/*
 * src/interp/x87_80.c — exact 80-bit x87 softfloat extended core (L5d, D9)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interp/x87_80_internal.h"

unsigned i686_x87_80_rc = 0u;  /* x87 CW RC: 0 NE, 1 down(-inf), 2 up(+inf), 3 zero */
unsigned i686_x87_80_pc = 64u; /* x87 CW PC: 24 / 53 / 64 */

unsigned x87_80_set_round(unsigned rc)
{
    unsigned prev = g_rc;
    if (rc <= 3u) g_rc = rc;
    return prev;
}

unsigned x87_80_set_prec(unsigned bits)
{
    unsigned prev = g_pc;
    if (bits == 24u || bits == 53u || bits == 64u) g_pc = bits;
    return prev;
}

/* --- add/sub ------------------------------------------------------------- */

static unsigned addsub(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10],
                       bool sub)
{
    xf_t a, b, r;
    unsigned flags = 0;
    bool bsign;

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
    bsign = sub ? !b.sign : b.sign;

    if (a.cls == X_ZERO && b.cls == X_ZERO) {
        if (a.sign == bsign) xf_out_zero(out, a.sign);
        else xf_out_zero(out, g_rc == 1u);
        return 0;
    }
    if (a.cls == X_INF || b.cls == X_INF) {
        if (a.cls == X_INF && b.cls == X_INF && a.sign != bsign) {
            xf_out_indef(out);
            return X_IE;
        }
        if (a.cls == X_INF) xf_out_inf(out, a.sign);
        else xf_out_inf(out, bsign);
        return 0;
    }
    if (a.cls == X_ZERO) { memcpy(out, bv, 10); if (sub) out[9] ^= 0x80u; return 0; }
    if (b.cls == X_ZERO) { memcpy(out, av, 10); return 0; }

    if (xf_is_den(&a) || xf_is_den(&b)) flags |= X_DE;

    {
        uint64_t ma, mb;
        int32_t ea, eb, c;
        u2 A, B, S;
        bool sgn;

        xf_norm_num(&a, &ma, &ea);
        xf_norm_num(&b, &mb, &eb);

        bool stick = false;
        if (ea >= eb) {
            int d = ea - eb;
            A = u2_shl(u2_fr(0, ma), 64);
            if (d <= 64) {
                B = u2_shl(u2_fr(0, mb), 64 - (unsigned)d);
            } else if (d < 128) {
                stick = (mb & ((((uint64_t)1) << (unsigned)(d - 64)) - 1)) != 0;
                B = u2_shr(u2_fr(0, mb), (unsigned)(d - 64));
            } else {
                B = u2_fr(0, 1);
            }
            c = ea;
        } else {
            int d = eb - ea;
            B = u2_shl(u2_fr(0, mb), 64);
            if (d <= 64) {
                A = u2_shl(u2_fr(0, ma), 64 - (unsigned)d);
            } else if (d < 128) {
                stick = (ma & ((((uint64_t)1) << (unsigned)(d - 64)) - 1)) != 0;
                A = u2_shr(u2_fr(0, ma), (unsigned)(d - 64));
            } else {
                A = u2_fr(0, 1);
            }
            c = eb;
        }
        {
            bool carry, borrow;
            if (a.sign == bsign) {
                S = u2_add(A, B, &carry);
                sgn = a.sign;
                if (carry) {
                    S = u2_fr((S.hi >> 1) | 0x8000000000000000ULL,
                              (S.lo >> 1) | (S.hi << 63));
                    c++;
                }
            } else {
                bool neg = u2_cmp(A, B) < 0;
                if (neg) { S = u2_sub(B, A, &borrow); sgn = bsign; }
                else { S = u2_sub(A, B, &borrow); sgn = a.sign; }
                (void)borrow;
            }
            flags |= round_pack80(&r, sgn, S, c - 127, stick, g_pc);
            xf_encode(&r, out);
            return flags;
        }
    }
}

unsigned x87_80_add(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    return addsub(out, a, b, false);
}

unsigned x87_80_sub(uint8_t out[10], const uint8_t a[10], const uint8_t b[10])
{
    return addsub(out, a, b, true);
}

/* --- mul ------------------------------------------------------------------ */

unsigned x87_80_mul(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10])
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
    if (a.cls == X_INF || b.cls == X_INF) {
        if (a.cls == X_ZERO || b.cls == X_ZERO) {
            xf_out_indef(out);
            return X_IE;
        }
        xf_out_inf(out, a.sign ^ b.sign);
        return 0;
    }
    if (a.cls == X_ZERO || b.cls == X_ZERO) {
        xf_out_zero(out, a.sign ^ b.sign);
        return 0;
    }
    if (xf_is_den(&a) || xf_is_den(&b)) flags |= X_DE;

    {
        uint64_t ma, mb;
        int32_t ea, eb;
        u2 P;
        xf_norm_num(&a, &ma, &ea);
        xf_norm_num(&b, &mb, &eb);
        P = mul64(ma, mb);
        flags |= round_pack80(&r, a.sign ^ b.sign, P, ea + eb - 126, false, g_pc);
        xf_encode(&r, out);
    }
    return flags;
}

/* --- div ------------------------------------------------------------------ */

unsigned x87_80_div(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10])
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
    if (a.cls == X_INF) {
        if (b.cls == X_INF) { xf_out_indef(out); return X_IE; }
        xf_out_inf(out, a.sign ^ b.sign);
        return 0;
    }
    if (b.cls == X_INF) {
        xf_out_zero(out, a.sign ^ b.sign);
        return 0;
    }
    if (b.cls == X_ZERO) {
        if (a.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
        xf_out_inf(out, a.sign ^ b.sign);
        return X_ZE;
    }
    if (a.cls == X_ZERO) {
        xf_out_zero(out, a.sign ^ b.sign);
        return 0;
    }
    if (xf_is_den(&a) || xf_is_den(&b)) flags |= X_DE;

    {
        uint64_t ma, mb, rem;
        int32_t ea, eb;
        u2 A, q;
        xf_norm_num(&a, &ma, &ea);
        xf_norm_num(&b, &mb, &eb);
        A = u2_shl(u2_fr(0, ma), 64);
        div_u2_u64(A, 2u, mb, &q, &rem);
        flags |= round_pack80(&r, a.sign ^ b.sign, q, ea - eb - 66,
                              rem != 0, g_pc);
        xf_encode(&r, out);
    }
    return flags;
}

/* --- sqrt ----------------------------------------------------------------- */

unsigned x87_80_sqrt(uint8_t out[10], const uint8_t av[10])
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
    if (a.cls == X_ZERO) {
        memcpy(out, av, 10);
        return 0;
    }
    if (a.cls == X_INF) {
        if (a.sign) { xf_out_indef(out); return X_IE; }
        memcpy(out, av, 10);
        return 0;
    }
    if (a.sign) {
        xf_out_indef(out);
        return X_IE;
    }
    if (xf_is_den(&a)) flags |= X_DE;

    {
        uint64_t m, s;
        int32_t e, half;
        u2 R, rem, t;
        bool borrow_dummy;
        bool guard, sticky;

        xf_norm_num(&a, &m, &e);
        if ((e & 1) != 0) {
            R = u2_shl(u2_fr(0, m), 64);
            half = (e - 127) / 2;
        } else {
            R = u2_shl(u2_fr(0, m), 63);
            half = (e - 126) / 2;
        }
        s = isqrt128(R, &rem);
        t = mul64(s, s);
        {
            u2 one = u2_fr(0, 1);
            u2 sp1 = u2_fr(0, s);
            bool c1, c2;
            t = u2_add(t, sp1, &c1);
            t = u2_add(t, one, &c2);
            (void)c1;
            (void)c2;
        }
        sticky = !u2_is_zero(rem);
        guard = sticky && u2_cmp(R, t) >= 0;
        {
            u2 m128 = u2_fr(s, guard ? 0x8000000000000000ULL : 0);
            (void)borrow_dummy;
            flags |= round_pack80(&r, false, m128, half - 64, sticky, g_pc);
            xf_encode(&r, out);
        }
    }
    return flags;
}

/* --- fcom ------------------------------------------------------------------ */

void x87_80_fcom(const uint8_t av[10], const uint8_t bv[10],
                 bool unordered, unsigned *c3, unsigned *c2, unsigned *c0)
{
    xf_t a, b;
    (void)unordered;
    xf_decode(av, &a);
    xf_decode(bv, &b);
    if (a.unsup || b.unsup || xf_is_nan_cls(&a) || xf_is_nan_cls(&b)) {
        *c3 = 1; *c2 = 1; *c0 = 1;
        return;
    }
    if (a.cls == X_ZERO && b.cls == X_ZERO) { *c3 = 1; *c2 = 0; *c0 = 0; return; }
    if (a.cls == X_ZERO) {
        if (b.sign) { *c3 = 0; *c2 = 0; *c0 = 0; }
        else { *c3 = 0; *c2 = 0; *c0 = 1; }
        return;
    }
    if (b.cls == X_ZERO) {
        if (a.sign) { *c3 = 0; *c2 = 0; *c0 = 1; }
        else { *c3 = 0; *c2 = 0; *c0 = 0; }
        return;
    }
    if (a.sign != b.sign) {
        *c3 = 0; *c2 = 0; *c0 = a.sign ? 1u : 0u;
        return;
    }
    {
        int ak = a.cls == X_INF ? 2 : 1;
        int bk = b.cls == X_INF ? 2 : 1;
        int cmp;
        if (ak != bk) cmp = ak > bk ? 1 : -1;
        else if (ak == 1 && a.exp != b.exp) cmp = a.exp > b.exp ? 1 : -1;
        else if (ak == 1) cmp = a.mant > b.mant ? 1 : (a.mant < b.mant ? -1 : 0);
        else cmp = 0;
        if (a.sign) cmp = -cmp;
        if (cmp > 0) { *c3 = 0; *c2 = 0; *c0 = 0; }
        else if (cmp < 0) { *c3 = 0; *c2 = 0; *c0 = 1; }
        else { *c3 = 1; *c2 = 0; *c0 = 0; }
    }
}

/* --- fprem / fprem1 --------------------------------------------------------- */

static unsigned fprem_core(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10],
                           uint32_t *qq, bool *complete, bool ieee)
{
    xf_t a, b, r;
    unsigned flags = 0;

    *qq = 0;
    *complete = true;

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
    if (b.cls == X_ZERO || a.cls == X_INF) {
        xf_out_indef(out);
        return X_IE;
    }
    if (b.cls == X_INF) {
        memcpy(out, av, 10);
        return 0;
    }
    if (a.cls == X_ZERO) {
        memcpy(out, av, 10);
        return 0;
    }
    if (xf_is_den(&a) || xf_is_den(&b)) flags |= X_DE;

    {
        uint64_t ma, mb;
        int32_t ea, eb;
        int64_t d;
        xf_norm_num(&a, &ma, &ea);
        xf_norm_num(&b, &mb, &eb);
        d = (int64_t)ea - (int64_t)eb;

        if (d < 0) {
            memcpy(out, av, 10);
            return flags;
        }
        if (d < 64) {
            u2 A = u2_shl(u2_fr(0, ma), (unsigned)d);
            u2 q;
            uint64_t rem;
            div_u2_u64(A, 0u, mb, &q, &rem);
            if (ieee) {
                uint64_t q0 = q.lo;
                bool inc = rem > (mb - rem);
                if (!inc && rem == (mb - rem) && (q0 & 1u) != 0u) inc = true;
                if (inc) {
                    *qq = (uint32_t)((q0 + 1u) & 7u);
                    xf_out_sig(out, !a.sign, mb - rem, eb - 63);
                    return flags;
                }
                *qq = (uint32_t)(q0 & 7u);
                xf_out_sig(out, a.sign, rem, eb - 63);
                return flags;
            }
            *qq = (uint32_t)(q.lo & 7u);
            xf_out_sig(out, a.sign, rem, eb - 63);
            return flags;
        }
        {
            u2 A = u2_shl(u2_fr(0, ma), 62u);
            u2 q;
            uint64_t rem;
            div_u2_u64(A, 0u, mb, &q, &rem);
            *qq = (uint32_t)(q.lo & 7u);
            *complete = false;
            xf_out_sig(out, a.sign, rem, ea - 125);
            return flags;
        }
    }
}

unsigned x87_80_fprem(uint8_t out[10], const uint8_t a[10], const uint8_t b[10],
                      uint32_t *qq, bool *reduction_complete)
{
    return fprem_core(out, a, b, qq, reduction_complete, false);
}

unsigned x87_80_fprem1(uint8_t out[10], const uint8_t a[10], const uint8_t b[10],
                       uint32_t *qq, bool *reduction_complete)
{
    return fprem_core(out, a, b, qq, reduction_complete, true);
}

/* --- fscale / fxtract -------------------------------------------------------- */

unsigned x87_80_fscale(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10])
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
    if (a.cls == X_INF) {
        if (b.cls == X_INF) {
            if (b.sign) { xf_out_indef(out); return 0; }
            xf_out_inf(out, a.sign);
            return 0;
        }
        xf_out_inf(out, a.sign);
        return 0;
    }
    if (a.cls == X_ZERO) {
        if (b.cls == X_INF) { xf_out_indef(out); return 0; }
        memcpy(out, av, 10);
        return 0;
    }
    if (b.cls == X_INF) {
        if (b.sign) xf_out_zero(out, a.sign);
        else xf_out_inf(out, a.sign);
        return 0;
    }
    if (xf_is_den(&a) || xf_is_den(&b)) flags |= X_DE;

    {
        uint64_t ma, mb;
        int32_t ea, eb;
        int64_t n;
        xf_norm_num(&a, &ma, &ea);
        xf_norm_num(&b, &mb, &eb);
        if (eb >= 64) n = 40000;
        else if (eb <= -1) n = 0;
        else n = (int64_t)(mb >> (63 - eb));
        if (b.sign) n = -n;
        if (n > 40000) n = 40000;
        if (n < -40000) n = -40000;
        flags |= round_pack80(&r, a.sign, u2_fr(0, ma),
                              (int32_t)((int64_t)ea + n - 63), false, g_pc);
        xf_encode(&r, out);
    }
    return flags;
}

unsigned x87_80_fxtract(uint8_t out_sig[10], uint8_t out_exp[10], const uint8_t av[10])
{
    xf_t a, r;
    unsigned flags = 0;

    xf_decode(av, &a);
    if (a.unsup) {
        xf_out_indef(out_sig);
        xf_out_indef(out_exp);
        return X_IE;
    }
    if (xf_is_nan_cls(&a)) {
        flags = xf_nan_prop(&r, &a, NULL);
        xf_encode(&r, out_sig);
        xf_encode(&r, out_exp);
        return flags;
    }
    if (a.cls == X_ZERO) {
        xf_out_inf(out_exp, true);
        memcpy(out_sig, av, 10);
        return X_ZE;
    }
    if (a.cls == X_INF) {
        xf_out_inf(out_exp, false);
        xf_out_inf(out_sig, a.sign);
        return 0;
    }
    {
        int32_t e = a.den_enc ? X_EMIN : a.exp;
        {
            bool esign = e < 0;
            uint64_t em = esign ? (uint64_t)(-(int64_t)e) : (uint64_t)e;
            xf_out_sig(out_exp, esign, em, 0);
        }
        xf_out_sig(out_sig, a.sign, a.mant, -63);
    }
    return flags;
}

/* --- constants ----------------------------------------------------------- */

static void const_out(uint8_t out[10], unsigned se, uint64_t mant)
{
    uint64_t m = mant;
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(m >> (8 * i));
    out[8] = (uint8_t)se;
    out[9] = (uint8_t)(se >> 8);
}

void x87_80_pi(uint8_t out[10])
{
    const_out(out, 0x4000u, 0xC90FDAA22168C235ULL);
}

void x87_80_log2e(uint8_t out[10])
{
    const_out(out, 0x3FFFu, 0xB8AA3B295C17F0BCULL);
}

void x87_80_ln2(uint8_t out[10])
{
    const_out(out, 0x3FFEu, 0xB17217F7D1CF79ACULL);
}

void x87_80_ln10(uint8_t out[10])
{
    const_out(out, 0x4000u, 0x935D8DDDAAA8AC17ULL);
}

void x87_80_zero(uint8_t out[10]) { memset(out, 0, 10); }

void x87_80_one(uint8_t out[10]) { const_out(out, 0x3FFFu, 0x8000000000000000ULL); }

void x87_80_inf(uint8_t out[10], bool sign) { xf_out_inf(out, sign); }

void x87_80_nan(uint8_t out[10], bool signaling, bool sign)
{
    unsigned se = 0x7FFFu | (sign ? 0x8000u : 0u);
    uint64_t mant = signaling ? 0x8000000000000001ULL : 0xC000000000000000ULL;
    const_out(out, se, mant);
}
