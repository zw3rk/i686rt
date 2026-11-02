/*
 * src/interp/x87_80_internal.h — Internal helpers for 80-bit x87 softfloat core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_INTERP_X87_80_INTERNAL_H
#define I686RT_INTERP_X87_80_INTERNAL_H

#include "interp/x87_80.h"

#include <string.h>

extern unsigned i686_x87_80_rc;
extern unsigned i686_x87_80_pc;
#define g_rc i686_x87_80_rc
#define g_pc i686_x87_80_pc

/* --- exception bits ----------------------------------------------------- */

#define X_IE 1u
#define X_DE 2u
#define X_ZE 4u
#define X_OE 8u
#define X_UE 16u
#define X_PE 32u

/* --- classes / internal value ------------------------------------------ */

enum { X_ZERO = 0, X_NUM, X_INF, X_QNAN, X_SNAN };

#define X_EMIN (-16382)
#define X_EMAX 16383
#define X_BIAS 16383
#define X_QBIT 0x4000000000000000ULL

typedef struct {
    uint64_t mant;
    int32_t exp;    /* value = mant * 2^(exp-63) */
    bool sign;
    int cls;
    bool unsup;     /* unsupported encoding operand */
    bool den_enc;   /* field-0 encoding (subnormal or pseudo-denormal) */
} xf_t;

/* --- encode / decode ----------------------------------------------------- */

static inline void xf_decode(const uint8_t v[10], xf_t *f)
{
    uint64_t mant;
    unsigned e;
    bool sign;

    mant = (uint64_t)v[0] | (uint64_t)v[1] << 8 | (uint64_t)v[2] << 16 |
           (uint64_t)v[3] << 24 | (uint64_t)v[4] << 32 | (uint64_t)v[5] << 40 |
           (uint64_t)v[6] << 48 | (uint64_t)v[7] << 56;
    e = (unsigned)v[8] | (unsigned)v[9] << 8;
    sign = (e >> 15) != 0u;
    e &= 0x7FFFu;

    f->sign = sign;
    f->unsup = false;
    f->den_enc = false;
    f->exp = 0;
    f->mant = mant;

    if (e == 0x7FFFu) {
        if (mant >> 63) {
            if (mant == 0x8000000000000000ULL) f->cls = X_INF;
            else f->cls = (mant & X_QBIT) ? X_QNAN : X_SNAN;
        } else { /* pseudo-infinity / pseudo-NaN */
            f->cls = (mant == 0) ? X_INF : X_QNAN;
            f->unsup = true;
        }
        return;
    }
    if (e == 0) {
        if (mant == 0) { f->cls = X_ZERO; return; }
        /* subnormal (J=0) or pseudo-denormal (J=1): value = mant * 2^-16445 */
        f->cls = X_NUM;
        f->exp = X_EMIN;
        f->den_enc = true;
        return;
    }
    f->cls = X_NUM;
    f->exp = (int32_t)e - X_BIAS;
    if (!(mant >> 63)) f->unsup = true; /* unnormal */
}

static inline void xf_encode(const xf_t *f, uint8_t out[10])
{
    unsigned se = 0;
    uint64_t mant = 0;
    int i;

    switch (f->cls) {
    case X_ZERO:
        se = 0;
        mant = 0;
        break;
    case X_INF:
        se = 0x7FFF;
        mant = 0x8000000000000000ULL;
        break;
    case X_QNAN:
    case X_SNAN:
        se = 0x7FFF;
        mant = f->mant | 0x8000000000000000ULL;
        if (f->cls == X_QNAN) {
            mant |= X_QBIT;
        } else {
            mant &= ~X_QBIT;
            if ((mant & 0x3FFFFFFFFFFFFFFFULL) == 0) mant |= 1;
        }
        break;
    default: /* X_NUM */
        if (f->den_enc) {
            se = 0; /* subnormal / pseudo-denormal field */
        } else {
            se = (unsigned)(f->exp + X_BIAS);
            if (se > 0x7FFFu) se = f->exp < 0 ? 0u : 0x7FFFu;
        }
        mant = f->mant;
        break;
    }
    if (f->sign) se |= 0x8000u;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(mant >> (8 * i));
    out[8] = (uint8_t)se;
    out[9] = (uint8_t)(se >> 8);
}

static inline void xf_out_sig(uint8_t out[10], bool sign, uint64_t mant, int32_t vexp)
{
    xf_t f;
    int s = 0;
    int32_t top;

    f.sign = sign;
    f.unsup = false;
    f.den_enc = false;
    if (mant == 0) {
        f.cls = X_ZERO;
        f.mant = 0;
        f.exp = 0;
        xf_encode(&f, out);
        return;
    }
    while (!(mant & 0x8000000000000000ULL)) { mant <<= 1; s++; }
    top = vexp + 63 - s; /* exponent of the leading bit */
    f.cls = X_NUM;
    if (top >= X_EMIN) {
        f.mant = mant;
        f.exp = top;
    } else {
        int sh = X_EMIN - top;
        f.mant = sh < 64 ? (mant >> sh) : 0;
        f.exp = X_EMIN;
        f.den_enc = true;
    }
    xf_encode(&f, out);
}

static inline void xf_out_indef(uint8_t out[10])
{
    uint8_t v[10];
    unsigned se = 0xFFFFu;
    uint64_t mant = 0xC000000000000000ULL;
    int i;
    for (i = 0; i < 8; i++) v[i] = (uint8_t)(mant >> (8 * i));
    v[8] = (uint8_t)se;
    v[9] = (uint8_t)(se >> 8);
    memcpy(out, v, 10);
}

static inline void xf_out_inf(uint8_t out[10], bool sign)
{
    uint8_t v[10];
    unsigned se = sign ? 0xFFFFu : 0x7FFFu;
    uint64_t mant = 0x8000000000000000ULL;
    int i;
    for (i = 0; i < 8; i++) v[i] = (uint8_t)(mant >> (8 * i));
    v[8] = (uint8_t)se;
    v[9] = (uint8_t)(se >> 8);
    memcpy(out, v, 10);
}

static inline void xf_out_zero(uint8_t out[10], bool sign)
{
    memset(out, 0, 10);
    if (sign) out[9] = 0x80u;
}

static inline bool xf_is_nan_cls(const xf_t *f) { return f->cls == X_QNAN || f->cls == X_SNAN; }
static inline bool xf_is_den(const xf_t *f) { return f->cls == X_NUM && f->den_enc; }

static inline unsigned xf_nan_prop(xf_t *r, const xf_t *a, const xf_t *b)
{
    unsigned flags = 0;
    const xf_t *n = NULL;

    if (xf_is_nan_cls(a)) n = a;
    else if (b && xf_is_nan_cls(b)) n = b;
    if (a->cls == X_SNAN || (b && b->cls == X_SNAN)) flags |= X_IE;
    if (n) {
        *r = *n;
        r->cls = X_QNAN;
        r->mant |= X_QBIT;
        r->unsup = false;
        r->den_enc = false;
        r->exp = 0;
    }
    return flags;
}

static inline void xf_norm_num(const xf_t *f, uint64_t *m, int32_t *e)
{
    uint64_t mant = f->mant;
    if (f->den_enc && !(mant >> 63)) {
        int s = 0;
        while (!(mant & 0x8000000000000000ULL)) { mant <<= 1; s++; }
        *m = mant;
        *e = X_EMIN - s;
        return;
    }
    *m = mant;
    *e = f->exp;
}

/* --- 128-bit helpers ----------------------------------------------------- */

typedef struct { uint64_t hi, lo; } u2;

static inline u2 u2_fr(uint64_t hi, uint64_t lo) { u2 r; r.hi = hi; r.lo = lo; return r; }

static inline u2 u2_shl(u2 a, unsigned n)
{
    if (n == 0) return a;
    if (n >= 128) return u2_fr(0, 0);
    if (n < 64) return u2_fr((a.hi << n) | (a.lo >> (64 - n)), a.lo << n);
    if (n == 64) return u2_fr(a.lo, 0);
    return u2_fr(a.lo << (n - 64), 0);
}

static inline u2 u2_shr(u2 a, unsigned n)
{
    if (n == 0) return a;
    if (n >= 128) return u2_fr(0, 0);
    if (n < 64) return u2_fr(a.hi >> n, (a.lo >> n) | (a.hi << (64 - n)));
    if (n == 64) return u2_fr(0, a.hi);
    return u2_fr(0, a.hi >> (n - 64));
}

static inline u2 u2_add(u2 a, u2 b, bool *carry)
{
    u2 r;
    uint64_t s1;
    bool c1, c2;

    r.lo = a.lo + b.lo;
    c1 = r.lo < a.lo;
    s1 = a.hi + b.hi;
    c2 = s1 < a.hi;
    r.hi = s1 + (c1 ? 1u : 0u);
    if (c1 && r.hi == 0) c2 = true;
    *carry = c2;
    return r;
}

static inline u2 u2_sub(u2 a, u2 b, bool *borrow)
{
    u2 r;
    uint64_t d1;
    bool b1, b2;

    r.lo = a.lo - b.lo;
    d1 = a.hi - b.hi;
    b1 = a.hi < b.hi;
    b2 = r.lo > a.lo; /* a.lo < b.lo */
    if (b2) {
        r.hi = d1 - 1;
        if (d1 == 0) b1 = true;
    } else {
        r.hi = d1;
    }
    *borrow = b1;
    return r;
}

static inline int u2_cmp(u2 a, u2 b)
{
    if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
    if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
    return 0;
}

static inline u2 mul64(uint64_t a, uint64_t b)
{
    uint64_t al = a & 0xFFFFFFFFULL, ah = a >> 32;
    uint64_t bl = b & 0xFFFFFFFFULL, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = lh + (ll >> 32);
    bool c1 = mid < lh;
    uint64_t mid2 = mid + hl;
    bool c2 = mid2 < mid;
    {
        u2 r;
        r.lo = (mid2 << 32) | (ll & 0xFFFFFFFFULL);
        r.hi = hh + (mid2 >> 32) +
               (((uint64_t)(c1 ? 1u : 0u) + (uint64_t)(c2 ? 1u : 0u)) << 32);
        return r;
    }
}

static inline bool u2_is_zero(u2 a) { return a.hi == 0 && a.lo == 0; }

static inline bool u2_norm(u2 *m, int32_t *exp)
{
    unsigned s = 0;
    if (u2_is_zero(*m)) return false;
    if (m->hi >> 63) return true;
    if (m->hi == 0) {
        uint64_t v = m->lo;
        while (!(v >> 63)) { v <<= 1; s++; }
        s += 64;
    } else {
        uint64_t v = m->hi;
        while (!(v >> 63)) { v <<= 1; s++; }
    }
    *m = u2_shl(*m, s);
    *exp -= (int32_t)s;
    return true;
}

static inline void div_u2_u64(u2 A, unsigned extra, uint64_t d, u2 *q, uint64_t *rem)
{
    u2 r = u2_fr(0, 0), qq = u2_fr(0, 0);
    unsigned total = 128u + extra;
    unsigned i;

    for (i = 0; i < total; i++) {
        uint64_t bit;
        unsigned bi = 127u - i;
        if (i < 128) {
            if (bi < 64) bit = (A.lo >> bi) & 1u;
            else bit = (A.hi >> (bi - 64)) & 1u;
        } else {
            bit = 0;
        }
        {
            u2 t = u2_shl(r, 1);
            t.lo |= bit;
            r = t;
        }
        qq = u2_shl(qq, 1);
        if (r.hi != 0 || r.lo >= d) {
            r.lo -= d;
            r.hi = 0;
            qq.lo |= 1u;
        }
    }
    *q = qq;
    *rem = r.lo;
}

static inline uint64_t isqrt128(u2 n, u2 *remout)
{
    u2 rem = u2_fr(0, 0);
    uint64_t root = 0;
    int i;

    for (i = 0; i < 64; i++) {
        u2 trial;
        bool dummy;
        rem = u2_shl(rem, 2);
        rem.lo |= n.hi >> 62;
        n = u2_shl(n, 2);
        root <<= 1;
        trial = u2_fr(root >> 63, (root << 1) | 1u);
        if (u2_cmp(rem, trial) >= 0) {
            rem = u2_sub(rem, trial, &dummy);
            root |= 1u;
        }
    }
    *remout = rem;
    return root;
}

/* --- rounding core ------------------------------------------------------ */

static inline bool round_inc(bool lsb, bool guard, bool rest, bool sign)
{
    switch (g_rc) {
    case 1: return sign && (guard || rest);   /* toward -inf */
    case 2: return !sign && (guard || rest);  /* toward +inf */
    case 3: return false;                     /* toward zero */
    default: return guard && (rest || lsb);   /* nearest-even */
    }
}

static inline uint64_t rnd_sig(u2 m, bool sticky, int eff, bool sign, bool *inexact)
{
    uint64_t sig;
    bool guard, rest, lsb;

    if (eff <= 0) {
        guard = (m.hi >> 63) != 0;
        rest = ((m.hi << 1) != 0) || (m.lo != 0) || sticky;
        *inexact = guard || rest;
        return round_inc(false, guard, rest, sign) ? 1u : 0u;
    }
    {
        unsigned t = (unsigned)(128 - eff) - 64u;
        sig = t ? (m.hi >> t) : m.hi;
        if (t == 0) {
            guard = (m.lo >> 63) != 0;
            rest = ((m.lo << 1) != 0) || sticky;
        } else {
            guard = ((m.hi >> (t - 1)) & 1u) != 0;
            rest = (t > 1 && (m.hi & ((((uint64_t)1) << (t - 1)) - 1)) != 0) ||
                   (m.lo != 0) || sticky;
        }
    }
    lsb = (sig & 1u) != 0;
    *inexact = guard || rest;
    if (round_inc(lsb, guard, rest, sign)) sig++;
    return sig;
}

static inline unsigned round_pack80(xf_t *r, bool sign, u2 m, int32_t exp, bool sticky,
                                    unsigned pc)
{
    unsigned flags = 0;
    int eff, shift;
    bool inexact, tiny;
    uint64_t sig;

    r->sign = sign;
    r->unsup = false;
    r->den_enc = false;

    if (u2_is_zero(m) && !sticky) {
        r->cls = X_ZERO;
        r->mant = 0;
        r->exp = 0;
        return 0;
    }
    if (u2_is_zero(m)) {
        m = u2_fr(0, 1);
        exp -= 128;
    }
    u2_norm(&m, &exp);
    exp += 127;
    tiny = exp < X_EMIN;
    shift = tiny ? (X_EMIN - exp) : 0;
    eff = (int)pc < 64 - shift ? (int)pc : 64 - shift;

    if (eff < 0 || (eff == 0 && exp < X_EMIN - 64)) {
        bool up = (g_rc == 1u && sign) || (g_rc == 2u && !sign);

        if (up) {
            r->cls = X_NUM;
            r->mant = 1;
            r->exp = X_EMIN;
            r->den_enc = true;
        } else {
            r->cls = X_ZERO;
            r->mant = 0;
            r->exp = 0;
        }
        return X_UE | X_PE;
    }
    if (eff == 0) {
        bool dummy;
        sig = rnd_sig(m, sticky, 0, sign, &dummy);
        inexact = true;
        if (sig) {
            r->cls = X_NUM;
            r->mant = 1;
            r->exp = X_EMIN;
            r->den_enc = true;
        } else {
            r->cls = X_ZERO;
            r->mant = 0;
            r->exp = 0;
        }
        return X_UE | X_PE;
    }

    sig = rnd_sig(m, sticky, eff, sign, &inexact);
    if (eff >= 1 && sig == (((uint64_t)1) << eff)) {
        sig >>= 1;
        exp++;
    }
    if (inexact) flags |= X_PE;
    if (tiny && inexact) flags |= X_UE;

    if (exp > X_EMAX) {
        bool to_inf = (g_rc == 0u) || (g_rc == 2u && !sign) || (g_rc == 1u && sign);
        flags |= X_OE | X_PE;
        if (to_inf) {
            r->cls = X_INF;
            r->mant = 0;
            r->exp = 0;
        } else {
            r->cls = X_NUM;
            r->mant = 0xFFFFFFFFFFFFFFFFULL;
            r->exp = X_EMAX;
        }
        return flags;
    }
    r->cls = X_NUM;
    if (exp >= X_EMIN) {
        r->mant = sig << (64 - eff);
        r->exp = exp;
    } else {
        int sh = exp - eff + 16446;
        r->mant = sh >= 64 ? 0 : (sig << sh);
        r->exp = X_EMIN;
        r->den_enc = true;
        if (r->mant == 0) r->cls = X_ZERO;
    }
    return flags;
}

#endif /* I686RT_INTERP_X87_80_INTERNAL_H */
