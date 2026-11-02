/*
 * tests/unit/test_l5d.c — L5d unit check: x87_80 softfloat extended core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Standalone host unit test (clang, macOS).  The lane card asked for a
 * __float128 oracle; Apple clang on arm64 Darwin supports neither
 * __float128 ("__float128 is not supported on this target") nor a
 * binary128 long double (sizeof(long double) == 8, binary64 — both
 * verified at write time).  The oracle here is therefore an INDEPENDENT
 * exact-integer implementation written for this test (32-bit-limb
 * bignums; single correct rounding straight from the mathematical
 * definition): add/sub/mul are exact; div carries 192 quotient bits plus
 * the exact remainder; sqrt derives its guard from R >= s^2+s+1.  This
 * is strictly stronger than the prescribed binary128-op-then-round
 * oracle (no double rounding) and runs under the frozen clang command.
 *
 * Golden vectors (arithmetic edges, fprem/fprem1 incl. the partial step,
 * fscale, transcendental spot values, conversions) were generated
 * offline with exact integer/Fraction math (round-to-nearest-even on
 * big ints) and 130-digit Decimal sin/cos/atan/ln series on the exact
 * rational inputs; the four public constants reproduce the canonical
 * FLDPI/FLDL2E/FLDLN2/FLDL2T hardware patterns.  Transcendentals are
 * checked to <= 1 ulp on the 64-bit mantissa (card budget); arithmetic,
 * fprem, fscale and conversions are checked bit-exact.
 *
 * Expected final line: L5D OK.
 */

#include "test_l5d_internal.h"




int g_fail = 0;


/* ---------------- 80-bit helpers ---------------------------------------- */

void mk80(uint8_t v[10], unsigned se, uint64_t mant)
{
    int i;
    for (i = 0; i < 8; i++) v[i] = (uint8_t)(mant >> (8 * i));
    v[8] = (uint8_t)se;
    v[9] = (uint8_t)(se >> 8);
}

void hx80(const uint8_t v[10], char *buf, size_t cap)
{
    unsigned se = (unsigned)v[8] | ((unsigned)v[9] << 8);
    uint64_t m = 0;
    int i;
    for (i = 7; i >= 0; i--) m = (m << 8) | v[i];
    snprintf(buf, cap, "%04X%016" PRIX64, se, m);
}

int eq80(const uint8_t a[10], const uint8_t b[10])
{
    return memcmp(a, b, 10) == 0;
}

void from_hex(uint8_t v[10], const char *hex)
{
    unsigned se = 0;
    uint64_t m = 0;
    int i;
    for (i = 0; i < 4; i++) {
        char c = hex[i];
        se = (se << 4) | (unsigned)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    for (i = 4; i < 20; i++) {
        char c = hex[i];
        m = (m << 4) | (uint64_t)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    mk80(v, se, m);
}

/* decoded numeric view (test side) */

void dec(const uint8_t v[10], dec_t *d)
{
    uint64_t m = 0;
    unsigned se;
    int i;
    for (i = 7; i >= 0; i--) m = (m << 8) | v[i];
    se = (unsigned)v[8] | ((unsigned)v[9] << 8);
    d->sign = (se >> 15) != 0;
    se &= 0x7FFFu;
    d->den_enc = false;
    d->mant = m;
    d->exp = 0;
    if (se == 0x7FFFu) {
        if (m >> 63) {
            if (m == 0x8000000000000000ULL) d->cls = 2;
            else d->cls = (m & 0x4000000000000000ULL) ? 3 : 4;
        } else {
            d->cls = 5;
        }
        return;
    }
    if (se == 0) {
        d->den_enc = true;
        if (m == 0) { d->cls = 0; return; }
        d->cls = 1;
        d->exp = -16382;
        {
            int s = 0;
            while (!(m & 0x8000000000000000ULL)) { m <<= 1; s++; }
            d->mant = m;
            d->exp -= s;
        }
        return;
    }
    if (!(m >> 63)) { d->cls = 5; return; }
    d->cls = 1;
    d->exp = (int32_t)se - 16383;
}

/* <=1 ulp compare on the 64-bit mantissa (same sign/class/exp) */
int ulp1(const uint8_t a[10], const uint8_t b[10])
{
    dec_t x, y;
    uint64_t d;
    dec(a, &x);
    dec(b, &y);
    if (x.cls != y.cls || x.sign != y.sign) return 0;
    if (x.cls != 1) return eq80(a, b);
    if (x.exp != y.exp) return 0;
    d = x.mant > y.mant ? x.mant - y.mant : y.mant - x.mant;
    if (d <= 1) return 1;
    /* boundary: ...FFFF -> ...000 of the next exponent */
    if (x.mant == 0xFFFFFFFFFFFFFFFFULL && y.mant == 0x8000000000000000ULL)
        return x.exp + 1 == y.exp;
    if (y.mant == 0xFFFFFFFFFFFFFFFFULL && x.mant == 0x8000000000000000ULL)
        return y.exp + 1 == x.exp;
    return 0;
}

/* ---------------- test-side bignum (32-bit limbs, little endian) ------- */



void big_zero(big_t *b)
{ memset(b, 0, sizeof *b); }

void big_u64(big_t *b, uint64_t v)
{
    big_zero(b);
    b->l[0] = (uint32_t)v;
    b->l[1] = (uint32_t)(v >> 32);
}

int big_is_zero(const big_t *b)
{
    int i;
    for (i = 0; i < NL; i++) if (b->l[i]) return 0;
    return 1;
}

unsigned big_bit(const big_t *b, unsigned pos)
{
    return (b->l[pos / 32u] >> (pos % 32u)) & 1u;
}

int big_bits_below(const big_t *b, unsigned pos)
{
    unsigned l = pos / 32u, sh = pos % 32u;
    uint32_t mask = sh ? (((uint32_t)1 << sh) - 1u) : 0u;
    int i;
    if (b->l[l] & mask) return 1;
    for (i = (int)l - 1; i >= 0; i--) if (b->l[i]) return 1;
    return 0;
}

/* shift left so bit TOPBIT is set; adjusts *e */
void big_norm(big_t *b, int32_t *e)
{
    int limb = NL - 1, bit;
    unsigned s;
    if (big_is_zero(b)) return;
    while (b->l[limb] == 0) limb--;
    bit = 31;
    while (!((b->l[limb] >> bit) & 1u)) bit--;
    s = (unsigned)(31 - bit) + (unsigned)(NL - 1 - limb) * 32u;
    if (s) {
        unsigned limbs = s / 32u, bb = s % 32u;
        int i;
        if (bb) {
            uint32_t carry = 0;
            for (i = 0; i < NL; i++) {
                uint32_t nv = (b->l[i] << bb) | carry;
                carry = b->l[i] >> (32u - bb);
                b->l[i] = nv;
            }
        }
        if (limbs) {
            for (i = NL - 1; i >= 0; i--) {
                if ((unsigned)i >= limbs) b->l[i] = b->l[i - (int)limbs];
                else b->l[i] = 0;
            }
        }
    }
    *e -= (int32_t)s;
}

int big_cmp(const big_t *a, const big_t *b)
{
    int i;
    for (i = NL - 1; i >= 0; i--) {
        if (a->l[i] != b->l[i]) return a->l[i] < b->l[i] ? -1 : 1;
    }
    return 0;
}

void big_add(big_t *a, const big_t *b)
{
    uint64_t carry = 0;
    int i;
    for (i = 0; i < NL; i++) {
        uint64_t s = (uint64_t)a->l[i] + b->l[i] + carry;
        a->l[i] = (uint32_t)s;
        carry = s >> 32;
    }
}

void big_add_u64(big_t *a, uint64_t v)
{
    big_t t;
    big_u64(&t, v);
    big_add(a, &t);
}

static void big_sub(big_t *a, const big_t *b) /* a >= b */
{
    uint32_t borrow = 0;
    int i;
    for (i = 0; i < NL; i++) {
        uint64_t bi = (uint64_t)b->l[i] + borrow;
        uint32_t nb = bi > a->l[i];
        a->l[i] = (uint32_t)(a->l[i] - bi);
        borrow = nb;
    }
}

void big_shl(big_t *a, unsigned bits)
{
    unsigned limbs = bits / 32u, bb = bits % 32u;
    int i;
    if (limbs >= (unsigned)NL) { big_zero(a); return; }
    if (bb) {
        uint32_t carry = 0;
        for (i = 0; i < NL; i++) {
            uint32_t nv = (a->l[i] << bb) | carry;
            carry = a->l[i] >> (32u - bb);
            a->l[i] = nv;
        }
    }
    if (limbs) {
        for (i = NL - 1; i >= 0; i--) {
            if ((unsigned)i >= limbs) a->l[i] = a->l[i - (int)limbs];
            else a->l[i] = 0;
        }
    }
}

/* shift right; ORs the discarded low bits into *sticky */
void big_shr(big_t *a, unsigned bits, int *sticky)
{
    unsigned limbs = bits / 32u, bb = bits % 32u;
    int i;
    if (limbs >= (unsigned)NL) {
        if (!big_is_zero(a)) *sticky = 1;
        big_zero(a);
        return;
    }
    if (limbs) {
        for (i = 0; i < (int)limbs; i++) {
            if (a->l[i]) *sticky = 1;
        }
        for (i = 0; i + (int)limbs < NL; i++) {
            a->l[i] = a->l[i + (int)limbs];
        }
        for (i = NL - 1; i >= NL - (int)limbs; i--) a->l[i] = 0;
    }
    if (bb) {
        uint32_t carry = 0;
        if (a->l[0] & (((uint32_t)1 << bb) - 1u)) *sticky = 1;
        for (i = NL - 1; i >= 0; i--) {
            uint32_t nv = (a->l[i] >> bb) | carry;
            carry = a->l[i] << (32u - bb);
            a->l[i] = nv;
        }
    }
}

/* a *= m via two 32-bit halves (a 32x64 limb product overflows u64) */
void big_mul_small(big_t *a, uint32_t m)
{
    uint64_t carry = 0;
    int i;
    for (i = 0; i < NL; i++) {
        uint64_t p = (uint64_t)a->l[i] * m + carry;
        a->l[i] = (uint32_t)p;
        carry = p >> 32;
    }
}

void big_mul_u64(big_t *a, uint64_t m)
{
    big_t hi, lo;

    lo = *a;
    big_mul_small(&lo, (uint32_t)m);
    hi = *a;
    big_mul_small(&hi, (uint32_t)(m >> 32));
    big_shl(&hi, 32u);
    big_add(&lo, &hi);
    *a = lo;
}

/* q = a / d (bit-serial), rem = a % d; d != 0. */
void big_divmod_u64(const big_t *a, uint64_t d, big_t *q, uint64_t *rem)
{
    uint64_t r = 0;
    int i;
    big_zero(q);
    for (i = NL * 32 - 1; i >= 0; i--) {
        uint64_t bit = big_bit(a, (unsigned)i);
        bool top = (r >> 63) != 0;
        r = (r << 1) | bit;
        big_shl(q, 1);
        if (top || r >= d) {
            r -= d;
            q->l[0] |= 1u;
        }
    }
    *rem = r;
}

/* s = floor(sqrt(n)), n given as two u64 halves (n < 2^128) */
uint64_t big_isqrt(uint64_t nhi, uint64_t nlo)
{
    big_t t;
    uint64_t s = 0;
    int i;
    big_zero(&t);
    for (i = 0; i < 64; i++) {
        uint32_t pair;
        if (i < 32) pair = (uint32_t)(nhi >> (64u - 2u * (unsigned)(i + 1)));
        else pair = (uint32_t)(nlo >> (128u - 2u * (unsigned)(i + 1)));
        big_shl(&t, 2);
        t.l[0] |= pair & 3u;
        s <<= 1;
        {
            big_t trial;
            big_u64(&trial, s);
            big_shl(&trial, 1u);
            trial.l[0] |= 1u;
            if (big_cmp(&t, &trial) >= 0) {
                big_sub(&t, &trial);
                s |= 1u;
            }
        }
    }
    return s;
}

/* ---------------- oracle rounding (independent of src) ------------------ */

unsigned orc(uint8_t out[10], bool sign, big_t m, int32_t e, int sticky,
                    unsigned rc, unsigned pc)
{
    unsigned flags = 0;
    int eff, shift, tiny, sd = 0;
    bool inexact, guard, rest, lsb, inc;
    uint64_t sig;

    if (big_is_zero(&m) && !sticky) {
        mk80(out, sign ? 0x8000u : 0u, 0);
        return 0;
    }
    if (big_is_zero(&m)) { /* below the window: minimal representation */
        big_u64(&m, 1);
        e -= TOPBIT;
    }
    big_norm(&m, &e);
    e += TOPBIT; /* m*2^e (big scaled) -> true top-bit exponent */
    tiny = e < -16382;
    shift = tiny ? (-16382 - e) : 0;
    eff = (int)pc < 64 - shift ? (int)pc : 64 - shift;

    if (eff < 0 || (eff == 0 && e < -16446)) {
        bool up = (rc == 1u && sign) || (rc == 2u && !sign);

        mk80(out, sign ? 0x8000u : 0u, up ? 1u : 0u);
        return X_UE | X_PE;
    }
    if (eff == 0) {
        /* value in [2^-16446, 2^-16445): 0 or the minimum subnormal */
        guard = big_bit(&m, TOPBIT);
        rest = big_bits_below(&m, TOPBIT) || sticky;
        inexact = true;
        if (rc == 0u) inc = guard && rest;
        else if (rc == 2u) inc = !sign && (guard || rest);
        else if (rc == 1u) inc = sign && (guard || rest);
        else inc = false;
        if (inc) mk80(out, sign ? 0x8000u : 0u, 1);
        else mk80(out, sign ? 0x8000u : 0u, 0);
        return X_UE | X_PE;
    }

    guard = big_bit(&m, (unsigned)(TOPBIT - eff));
    rest = big_bits_below(&m, (unsigned)(TOPBIT - eff)) || sticky;
    {
        big_t t = m;
        big_shr(&t, (unsigned)(TOPBIT + 1 - eff), &sd);
        sig = ((uint64_t)t.l[1] << 32) | t.l[0];
    }
    lsb = sig & 1u;
    inexact = guard || rest;
    if (rc == 0u) inc = guard && (rest || lsb);
    else if (rc == 2u) inc = !sign && (guard || rest);
    else if (rc == 1u) inc = sign && (guard || rest);
    else inc = false;
    if (inc) sig++;
    if (sig == (((uint64_t)1) << eff)) {
        sig >>= 1;
        e++;
    }
    if (inexact) flags |= X_PE;
    if (tiny && inexact) flags |= X_UE;
    if (e > 16383) {
        bool to_inf = (rc == 0u) || (rc == 2u && !sign) || (rc == 1u && sign);
        flags |= X_OE | X_PE;
        if (to_inf) mk80(out, (sign ? 0x8000u : 0u) | 0x7FFFu,
                         0x8000000000000000ULL);
        else mk80(out, (sign ? 0x8000u : 0u) | 0x7FFE, 0xFFFFFFFFFFFFFFFFULL);
        return flags;
    }
    if (e >= -16382) {
        mk80(out, (unsigned)((sign ? 0x8000u : 0u) | (unsigned)(e + 16383)),
             sig << (64 - eff));
    } else {
        int sh = e - eff + 16446;
        mk80(out, sign ? 0x8000u : 0u, sh >= 64 ? 0 : (sig << sh));
    }
    return flags;
}

/* ---------------- oracle arithmetic (finite nonzero numerics) ---------- */

unsigned orc_addsub(uint8_t out[10], const dec_t *a, const dec_t *b,
                           bool sub, unsigned rc, unsigned pc)
{
    big_t A, B;
    int32_t c;
    bool bs = sub ? !b->sign : b->sign;
    int sticky = 0;
    bool sgn;

    big_u64(&A, a->mant);
    big_shl(&A, (unsigned)(TOPBIT - 64)); /* bit63 -> TOPBIT-1 (headroom) */
    big_u64(&B, b->mant);
    big_shl(&B, (unsigned)(TOPBIT - 64));
    if (a->exp >= b->exp) {
        int d = a->exp - b->exp;
        c = a->exp;
        if (d >= NL * 32) {
            big_zero(&B);
            B.l[0] = 1u;
        } else {
            big_shr(&B, (unsigned)d, &sticky);
        }
    } else {
        int d = b->exp - a->exp;
        c = b->exp;
        if (d >= NL * 32) {
            big_zero(&A);
            A.l[0] = 1u;
        } else {
            big_shr(&A, (unsigned)d, &sticky);
        }
    }
    if (a->sign == bs) {
        big_add(&A, &B);
        sgn = a->sign;
    } else {
        if (big_cmp(&A, &B) >= 0) {
            big_sub(&A, &B);
            sgn = a->sign;
        } else {
            big_t T = A;
            A = B;
            B = T;
            big_sub(&A, &B);
            sgn = bs;
        }
    }
    return orc(out, sgn, A, c - (TOPBIT - 1), sticky, rc, pc);
}

unsigned orc_mul(uint8_t out[10], const dec_t *a, const dec_t *b,
                        unsigned rc, unsigned pc)
{
    big_t P;
    big_u64(&P, a->mant);
    big_mul_u64(&P, b->mant);
    return orc(out, a->sign ^ b->sign, P, a->exp + b->exp - 126, 0, rc, pc);
}

unsigned orc_div(uint8_t out[10], const dec_t *a, const dec_t *b,
                        unsigned rc, unsigned pc)
{
    big_t N, Q;
    uint64_t rem;
    big_u64(&N, a->mant);
    big_shl(&N, 128u);
    big_divmod_u64(&N, b->mant, &Q, &rem);
    /* Q = floor(ma * 2^128 / mb): value = Q * 2^(ea-eb-128) */
    return orc(out, a->sign ^ b->sign, Q, a->exp - b->exp - 128, rem != 0,
               rc, pc);
}

unsigned orc_sqrt(uint8_t out[10], const dec_t *a, unsigned rc, unsigned pc)
{
    uint64_t s, nhi, nlo;
    big_t R, S2;
    int32_t half;
    int guard, inexact;

    if (a->exp & 1) {
        nhi = a->mant;
        nlo = 0;
        half = (a->exp - 127) / 2;
    } else {
        nhi = a->mant >> 1;
        nlo = a->mant << 63;
        half = (a->exp - 126) / 2;
    }
    s = big_isqrt(nhi, nlo);
    {
        big_t t, r2;
        big_u64(&R, 0);
        R.l[0] = (uint32_t)nlo;
        R.l[1] = (uint32_t)(nlo >> 32);
        R.l[2] = (uint32_t)nhi;
        R.l[3] = (uint32_t)(nhi >> 32);
        big_u64(&r2, s);
        big_mul_u64(&r2, s);
        t = R;
        big_sub(&t, &r2);
        inexact = !big_is_zero(&t);
    }
    guard = 0;
    if (inexact) {
        big_u64(&S2, s);
        big_mul_u64(&S2, s);
        big_add_u64(&S2, s);
        big_add_u64(&S2, 1);
        guard = big_cmp(&R, &S2) >= 0;
    }
    {
        big_t B;
        big_u64(&B, s);
        big_shl(&B, 1u);
        if (guard) B.l[0] |= 1u;
        big_shl(&B, (unsigned)(TOPBIT - 64));
        return orc(out, false, B, half - 1 - (TOPBIT - 64), inexact, rc, pc);
    }
}


int main(void)
{
    x87_80_set_round(0u);
    x87_80_set_prec(64u);
    run_specials();
    run_goldens();
    run_random();
    if (g_fail == 0) {
        printf("L5D OK\n");
        return 0;
    }
    printf("L5D FAILURES: %d\n", g_fail);
    return 1;
}
