/*
 * src/interp/x87_80_wx.h — 128-bit wide-float transcendental primitives
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_INTERP_X87_80_WX_H
#define I686RT_INTERP_X87_80_WX_H

#include "interp/x87_80_internal.h"

typedef struct { u2 m; int32_t e; bool sign; } wx_t;

static const uint64_t C_LN2[2]   = {0x58B90BFBE8E7BCD5ULL, 0xE4F1D9CC01F97B58ULL};
static const uint64_t C_LOG2E[2] = {0xB8AA3B295C17F0BBULL, 0xBE87FED0691D3E89ULL};
static const uint64_t C_SQRT2[2] = {0xB504F333F9DE6484ULL, 0x597D89B3754ABE9FULL};
static const uint64_t C_SQRT3[2] = {0xDDB3D742C265539DULL, 0x92BA16B83C5C1DC5ULL};
static const uint64_t C_PI2[2]   = {0xC90FDAA22168C234ULL, 0xC4C6628B80DC1CD1ULL};
static const uint64_t C_PI4[2]   = {0x6487ED5110B4611AULL, 0x62633145C06E0E69ULL};
static const uint64_t C_PI6[2]   = {0x430548E0B5CD9611ULL, 0x96ECCB83D59EB446ULL};
static const uint64_t C_2MSQ3[2] = {0x224C28BD3D9AAC62ULL, 0x6D45E947C3A3E23BULL};
static const uint64_t C_PI2_320[5] = {
    0xC90FDAA22168C234ULL, 0xC4C6628B80DC1CD1ULL, 0x29024E088A67CC74ULL,
    0x020BBEA63B139B22ULL, 0x514A08798E3404DEULL
};
static const uint64_t C_2OPI[4] = {
    0x517CC1B727220A94ULL, 0xFE13ABE8FA9A6EE0ULL,
    0x6DB14ACC9E21C820ULL, 0xFF28B1D5EF5DE2B1ULL
};
#define C_PI4_LIMIT 0x6487ED5110B461A6ULL

static const uint64_t C_INV[90][2] = {
    {0x4000000000000000ULL, 0x0000000000000000ULL}, {0x2AAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAABULL},
    {0x2000000000000000ULL, 0x0000000000000000ULL}, {0x1999999999999999ULL, 0x999999999999999AULL},
    {0x1555555555555555ULL, 0x5555555555555555ULL}, {0x1249249249249249ULL, 0x2492492492492492ULL},
    {0x1000000000000000ULL, 0x0000000000000000ULL}, {0x0E38E38E38E38E38ULL, 0xE38E38E38E38E38EULL},
    {0x0CCCCCCCCCCCCCCCULL, 0xCCCCCCCCCCCCCCCDULL}, {0x0BA2E8BA2E8BA2E8ULL, 0xBA2E8BA2E8BA2E8CULL},
    {0x0AAAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAABULL}, {0x09D89D89D89D89D8ULL, 0x9D89D89D89D89D8AULL},
    {0x0924924924924924ULL, 0x9249249249249249ULL}, {0x0888888888888888ULL, 0x8888888888888889ULL},
    {0x0800000000000000ULL, 0x0000000000000000ULL}, {0x0787878787878787ULL, 0x8787878787878788ULL},
    {0x071C71C71C71C71CULL, 0x71C71C71C71C71C7ULL}, {0x06BCA1AF286BCA1AULL, 0xF286BCA1AF286BCAULL},
    {0x0666666666666666ULL, 0x6666666666666666ULL}, {0x0618618618618618ULL, 0x6186186186186186ULL},
    {0x05D1745D1745D174ULL, 0x5D1745D1745D1746ULL}, {0x0590B21642C8590BULL, 0x21642C8590B21643ULL},
    {0x0555555555555555ULL, 0x5555555555555555ULL}, {0x051EB851EB851EB8ULL, 0x51EB851EB851EB85ULL},
    {0x04EC4EC4EC4EC4ECULL, 0x4EC4EC4EC4EC4EC5ULL}, {0x04BDA12F684BDA12ULL, 0xF684BDA12F684BDAULL},
    {0x0492492492492492ULL, 0x4924924924924925ULL}, {0x0469EE58469EE584ULL, 0x69EE58469EE5846AULL},
    {0x0444444444444444ULL, 0x4444444444444444ULL}, {0x0421084210842108ULL, 0x4210842108421084ULL},
    {0x0400000000000000ULL, 0x0000000000000000ULL}, {0x03E0F83E0F83E0F8ULL, 0x3E0F83E0F83E0F84ULL},
    {0x03C3C3C3C3C3C3C3ULL, 0xC3C3C3C3C3C3C3C4ULL}, {0x03A83A83A83A83A8ULL, 0x3A83A83A83A83A84ULL},
    {0x038E38E38E38E38EULL, 0x38E38E38E38E38E4ULL}, {0x03759F22983759F2ULL, 0x2983759F2298375AULL},
    {0x035E50D79435E50DULL, 0x79435E50D79435E5ULL}, {0x0348348348348348ULL, 0x3483483483483483ULL},
    {0x0333333333333333ULL, 0x3333333333333333ULL}, {0x031F3831F3831F38ULL, 0x31F3831F3831F383ULL},
    {0x030C30C30C30C30CULL, 0x30C30C30C30C30C3ULL}, {0x02FA0BE82FA0BE82ULL, 0xFA0BE82FA0BE82FAULL},
    {0x02E8BA2E8BA2E8BAULL, 0x2E8BA2E8BA2E8BA3ULL}, {0x02D82D82D82D82D8ULL, 0x2D82D82D82D82D83ULL},
    {0x02C8590B21642C85ULL, 0x90B21642C8590B21ULL}, {0x02B9310572620AE4ULL, 0xC415C9882B931057ULL},
    {0x02AAAAAAAAAAAAAAULL, 0xAAAAAAAAAAAAAAABULL}, {0x029CBC14E5E0A72FULL, 0x05397829CBC14E5EULL},
    {0x028F5C28F5C28F5CULL, 0x28F5C28F5C28F5C3ULL}, {0x0282828282828282ULL, 0x8282828282828283ULL},
    {0x0276276276276276ULL, 0x2762762762762762ULL}, {0x026A439F656F1826ULL, 0xA439F656F1826A44ULL},
    {0x025ED097B425ED09ULL, 0x7B425ED097B425EDULL}, {0x0253C8253C8253C8ULL, 0x253C8253C8253C82ULL},
    {0x0249249249249249ULL, 0x2492492492492492ULL}, {0x023EE08FB823EE08ULL, 0xFB823EE08FB823EEULL},
    {0x0234F72C234F72C2ULL, 0x34F72C234F72C235ULL}, {0x022B63CBEEA4E1A0ULL, 0x8AD8F2FBA9386823ULL},
    {0x0222222222222222ULL, 0x2222222222222222ULL}, {0x02192E29F79B4758ULL, 0x2192E29F79B47582ULL},
    {0x0210842108421084ULL, 0x2108421084210842ULL}, {0x0208208208208208ULL, 0x2082082082082082ULL},
    {0x0200000000000000ULL, 0x0000000000000000ULL}, {0x01F81F81F81F81F8ULL, 0x1F81F81F81F81F82ULL},
    {0x01F07C1F07C1F07CULL, 0x1F07C1F07C1F07C2ULL}, {0x01E9131ABF0B7672ULL, 0xA07A44C6AFC2DD9DULL},
    {0x01E1E1E1E1E1E1E1ULL, 0xE1E1E1E1E1E1E1E2ULL}, {0x01DAE6076B981DAEULL, 0x6076B981DAE6076CULL},
    {0x01D41D41D41D41D4ULL, 0x1D41D41D41D41D42ULL}, {0x01CD85689039B0ADULL, 0x12073615A240E6C3ULL},
    {0x01C71C71C71C71C7ULL, 0x1C71C71C71C71C72ULL}, {0x01C0E070381C0E07ULL, 0x0381C0E070381C0EULL},
    {0x01BACF914C1BACF9ULL, 0x14C1BACF914C1BADULL}, {0x01B4E81B4E81B4E8ULL, 0x1B4E81B4E81B4E82ULL},
    {0x01AF286BCA1AF286ULL, 0xBCA1AF286BCA1AF3ULL}, {0x01A98EF606A63BD8ULL, 0x1A98EF606A63BD82ULL},
    {0x01A41A41A41A41A4ULL, 0x1A41A41A41A41A42ULL}, {0x019EC8E951033D91ULL, 0xD2A2067B23A5440DULL},
    {0x0199999999999999ULL, 0x999999999999999AULL}, {0x01948B0FCD6E9E06ULL, 0x522C3F35BA781949ULL},
    {0x018F9C18F9C18F9CULL, 0x18F9C18F9C18F9C2ULL}, {0x018ACB90F6BF3A9AULL, 0x3784A062B2E43DB0ULL},
    {0x0186186186186186ULL, 0x1861861861861862ULL}, {0x0181818181818181ULL, 0x8181818181818182ULL},
    {0x017D05F417D05F41ULL, 0x7D05F417D05F417DULL}, {0x0178A4C8178A4C81ULL, 0x78A4C8178A4C8179ULL},
    {0x01745D1745D1745DULL, 0x1745D1745D1745D1ULL}, {0x01702E05C0B81702ULL, 0xE05C0B81702E05C1ULL},
    {0x016C16C16C16C16CULL, 0x16C16C16C16C16C1ULL}, {0x0168168168168168ULL, 0x1681681681681681ULL},
};
#define C_INV_K(k) (C_INV[(k) - 2])

static inline wx_t wxc(const uint64_t t[2])
{
    wx_t r;
    r.m = u2_fr(t[0], t[1]);
    r.e = -127;
    r.sign = false;
    u2_norm(&r.m, &r.e);
    return r;
}

static inline wx_t wx_zero(void)
{
    wx_t r;
    r.m = u2_fr(0, 0);
    r.e = 0;
    r.sign = false;
    return r;
}

static inline wx_t wx_one(void)
{
    wx_t r;
    r.m = u2_fr(0x8000000000000000ULL, 0);
    r.e = -127;
    r.sign = false;
    return r;
}

static inline wx_t wx_pi(void)
{
    wx_t r = wxc(C_PI2);
    r.e += 1;
    return r;
}

static inline bool wx_is_zero(const wx_t *a) { return u2_is_zero(a->m); }

static inline wx_t wx_int(uint64_t n)
{
    wx_t r;
    r.m = u2_fr(0, n);
    r.e = 0;
    r.sign = false;
    u2_norm(&r.m, &r.e);
    return r;
}

static inline int wx_cmp_abs(const wx_t *a, const wx_t *b)
{
    if (wx_is_zero(a) && wx_is_zero(b)) return 0;
    if (wx_is_zero(a)) return -1;
    if (wx_is_zero(b)) return 1;
    if (a->e != b->e) return a->e < b->e ? -1 : 1;
    return u2_cmp(a->m, b->m);
}

static inline wx_t wx_mul(const wx_t *a, const wx_t *b)
{
    wx_t r;
    u2 p01, p12a, p12b, p34, mid;
    bool cmid, ovf;

    if (wx_is_zero(a) || wx_is_zero(b)) return wx_zero();
    p01 = mul64(a->m.lo, b->m.lo);
    p12a = mul64(a->m.lo, b->m.hi);
    p12b = mul64(a->m.hi, b->m.lo);
    p34 = mul64(a->m.hi, b->m.hi);
    mid = u2_add(p12a, p12b, &cmid);
    {
        uint64_t l1, s2, l2, l3;
        bool k1, k2, k3;
        u2 m;

        l1 = p01.hi + mid.lo;
        k1 = l1 < p01.hi;
        s2 = p34.lo + mid.hi;
        k2 = s2 < p34.lo;
        l2 = s2 + (k1 ? 1u : 0u);
        k3 = k2 || (k1 && s2 == 0xFFFFFFFFFFFFFFFFULL);
        l3 = p34.hi + (k3 ? 1u : 0u) + (cmid ? 1u : 0u);
        m.hi = (l3 << 1) | (l2 >> 63);
        m.lo = (l2 << 1) | (l1 >> 63);
        ovf = (l3 >> 63) != 0;
        if (ovf) {
            m = u2_fr((m.hi >> 1) | 0x8000000000000000ULL,
                      (m.lo >> 1) | (m.hi << 63));
            r.e = a->e + b->e + 127 + 1;
        } else {
            r.e = a->e + b->e + 127;
        }
        r.m = m;
    }
    r.sign = a->sign ^ b->sign;
    return r;
}

static inline wx_t wx_addmag(const wx_t *a, const wx_t *b, bool sign)
{
    wx_t r;
    u2 S, X, Y;
    const wx_t *hi = a, *lo = b;
    int32_t d;

    if (wx_is_zero(a)) { r = *b; r.sign ^= sign; return r; }
    if (wx_is_zero(b)) { r = *a; r.sign ^= sign; return r; }
    if (hi->e < lo->e) { const wx_t *t = hi; hi = lo; lo = t; }
    d = hi->e - lo->e;
    X = hi->m;
    if (d >= 128) {
        Y = u2_fr(0, 0);
    } else {
        Y = u2_shr(lo->m, (unsigned)d);
    }
    {
        bool carry;
        S = u2_add(X, Y, &carry);
        if (carry) {
            S = u2_fr((S.hi >> 1) | 0x8000000000000000ULL,
                      (S.lo >> 1) | (S.hi << 63));
            r.e = hi->e + 1;
        } else {
            r.e = hi->e;
        }
    }
    r.m = S;
    r.sign = sign;
    return r;
}

static inline wx_t wx_add(const wx_t *a, const wx_t *b)
{
    wx_t r;
    bool borrow;

    if (a->sign == b->sign) return wx_addmag(a, b, a->sign);
    {
        const wx_t *hi = a, *lo = b;
        int32_t d;
        u2 X, Y;

        if (wx_is_zero(a)) { r = *b; return r; }
        if (wx_is_zero(b)) { r = *a; return r; }
        if (wx_cmp_abs(a, b) < 0) { hi = b; lo = a; }
        d = hi->e - lo->e;
        X = hi->m;
        if (d >= 128) {
            Y = u2_fr(0, 0);
        } else {
            Y = u2_shr(lo->m, (unsigned)d);
        }
        {
            u2 S = u2_sub(X, Y, &borrow);
            (void)borrow;
            r.m = S;
            r.e = hi->e;
            r.sign = hi->sign;
        }
        if (!u2_norm(&r.m, &r.e)) r.sign = false;
        return r;
    }
}

static inline wx_t wx_sub(const wx_t *a, const wx_t *b)
{
    wx_t nb = *b;
    nb.sign = !nb.sign;
    return wx_add(a, &nb);
}

static inline wx_t wx_div(const wx_t *a, const wx_t *b)
{
    wx_t r;
    u2 B, rem = u2_fr(0, 0), q = u2_fr(0, 0);
    bool ovf = false;
    unsigned i;

    if (wx_is_zero(a)) return wx_zero();
    B = b->m;
    for (i = 0; i < 256; i++) {
        uint64_t bit;
        u2 t;
        unsigned bi = 127u - i;
        bool top;
        if (i < 128) {
            if (bi < 64) bit = (a->m.lo >> bi) & 1u;
            else bit = (a->m.hi >> (bi - 64)) & 1u;
        } else {
            bit = 0;
        }
        top = (rem.hi >> 63) != 0;
        t = u2_shl(rem, 1);
        t.lo |= bit;
        rem = t;
        if (i >= 127) {
            bool newbit = false;
            if (top) {
                bool dum;
                u2 dsub = u2_sub(B, rem, &dum);
                rem.hi = ~dsub.hi;
                rem.lo = ~dsub.lo;
                rem.lo += 1u;
                if (rem.lo == 0u) rem.hi += 1u;
                newbit = true;
            } else if (u2_cmp(rem, B) >= 0) {
                bool dum;
                rem = u2_sub(rem, B, &dum);
                newbit = true;
            }
            q = u2_shl(q, 1);
            if (newbit) q.lo |= 1u;
            if (i == 127) ovf = newbit;
        }
    }
    if (ovf) {
        r.m = u2_fr((q.hi >> 1) | 0x8000000000000000ULL,
                    (q.lo >> 1) | (q.hi << 63));
        r.e = a->e - b->e - 127;
    } else {
        r.m = q;
        r.e = a->e - b->e - 128;
        u2_norm(&r.m, &r.e);
    }
    r.sign = a->sign ^ b->sign;
    return r;
}

static inline bool wx_tiny(const wx_t *term, const wx_t *acc)
{
    return wx_is_zero(term) || term->e <= acc->e - 140;
}

static inline wx_t wx_expm1(const wx_t *y)
{
    wx_t sum, term;
    int k;

    sum = *y;
    term = *y;
    for (k = 2; k <= 44; k++) {
        wx_t f = wxc(C_INV_K(k));
        term = wx_mul(&term, y);
        term = wx_mul(&term, &f);
        sum = wx_add(&sum, &term);
        if (k > 8 && wx_tiny(&term, &sum)) break;
    }
    return sum;
}

static inline wx_t wx_ln_m(wx_t m)
{
    wx_t one = wx_one(), sq2 = wxc(C_SQRT2);
    wx_t z, sum, term, res;
    int halves = 0, k;

    while (wx_cmp_abs(&m, &sq2) >= 0) {
        m.e -= 1;
        halves++;
    }
    z = wx_sub(&m, &one);
    {
        wx_t two = wx_add(&one, &one);
        wx_t den = wx_add(&two, &z);
        z = wx_div(&z, &den);
    }
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
    res = wx_add(&sum, &sum);
    while (halves--) {
        wx_t l2 = wxc(C_LN2);
        res = wx_add(&res, &l2);
    }
    return res;
}

#endif /* I686RT_INTERP_X87_80_WX_H */
