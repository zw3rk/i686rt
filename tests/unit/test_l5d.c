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

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "interp/x87_80.h"

#define X_IE 1u
#define X_DE 2u
#define X_ZE 4u
#define X_OE 8u
#define X_UE 16u
#define X_PE 32u

static int g_fail = 0;

#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            g_fail++;                                                       \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                     \
            printf(__VA_ARGS__);                                            \
            printf("\n");                                                   \
        }                                                                   \
    } while (0)

/* ---------------- 80-bit helpers ---------------------------------------- */

static void mk80(uint8_t v[10], unsigned se, uint64_t mant)
{
    int i;
    for (i = 0; i < 8; i++) v[i] = (uint8_t)(mant >> (8 * i));
    v[8] = (uint8_t)se;
    v[9] = (uint8_t)(se >> 8);
}

static void hx80(const uint8_t v[10], char *buf, size_t cap)
{
    unsigned se = (unsigned)v[8] | ((unsigned)v[9] << 8);
    uint64_t m = 0;
    int i;
    for (i = 7; i >= 0; i--) m = (m << 8) | v[i];
    snprintf(buf, cap, "%04X%016" PRIX64, se, m);
}

static int eq80(const uint8_t a[10], const uint8_t b[10])
{
    return memcmp(a, b, 10) == 0;
}

static void from_hex(uint8_t v[10], const char *hex)
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
typedef struct {
    uint64_t mant; /* normalized, bit63 set (finite nonzero numerics) */
    int32_t exp;   /* value = mant * 2^(exp-63) */
    bool sign;
    int cls; /* 0 zero, 1 num, 2 inf, 3 qnan, 4 snan, 5 unsupported */
    bool den_enc;
} dec_t;

static void dec(const uint8_t v[10], dec_t *d)
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
static int ulp1(const uint8_t a[10], const uint8_t b[10])
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

#define NL 12
#define TOPBIT (NL * 32 - 1)

typedef struct { uint32_t l[NL]; } big_t;

static void big_zero(big_t *b) { memset(b, 0, sizeof *b); }

static void big_u64(big_t *b, uint64_t v)
{
    big_zero(b);
    b->l[0] = (uint32_t)v;
    b->l[1] = (uint32_t)(v >> 32);
}

static int big_is_zero(const big_t *b)
{
    int i;
    for (i = 0; i < NL; i++) if (b->l[i]) return 0;
    return 1;
}

static unsigned big_bit(const big_t *b, unsigned pos)
{
    return (b->l[pos / 32u] >> (pos % 32u)) & 1u;
}

static int big_bits_below(const big_t *b, unsigned pos)
{
    unsigned l = pos / 32u, sh = pos % 32u;
    uint32_t mask = sh ? (((uint32_t)1 << sh) - 1u) : 0u;
    int i;
    if (b->l[l] & mask) return 1;
    for (i = (int)l - 1; i >= 0; i--) if (b->l[i]) return 1;
    return 0;
}

/* shift left so bit TOPBIT is set; adjusts *e */
static void big_norm(big_t *b, int32_t *e)
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

static int big_cmp(const big_t *a, const big_t *b)
{
    int i;
    for (i = NL - 1; i >= 0; i--) {
        if (a->l[i] != b->l[i]) return a->l[i] < b->l[i] ? -1 : 1;
    }
    return 0;
}

static void big_add(big_t *a, const big_t *b)
{
    uint64_t carry = 0;
    int i;
    for (i = 0; i < NL; i++) {
        uint64_t s = (uint64_t)a->l[i] + b->l[i] + carry;
        a->l[i] = (uint32_t)s;
        carry = s >> 32;
    }
}

static void big_add_u64(big_t *a, uint64_t v)
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

static void big_shl(big_t *a, unsigned bits)
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
static void big_shr(big_t *a, unsigned bits, int *sticky)
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
static void big_mul_small(big_t *a, uint32_t m)
{
    uint64_t carry = 0;
    int i;
    for (i = 0; i < NL; i++) {
        uint64_t p = (uint64_t)a->l[i] * m + carry;
        a->l[i] = (uint32_t)p;
        carry = p >> 32;
    }
}

static void big_mul_u64(big_t *a, uint64_t m)
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

/* q = a / d (bit-serial), rem = a % d; d != 0.  The running remainder
 * stays below 2d which can need 65 bits (d >= 2^63): the overflow bit
 * is tracked separately; r -= d wraps to the right value either way. */
static void big_divmod_u64(const big_t *a, uint64_t d, big_t *q, uint64_t *rem)
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
static uint64_t big_isqrt(uint64_t nhi, uint64_t nlo)
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
            big_u64(&trial, s); /* trial = (s << 1) | 1 as a big: s can
                                 * have bit 63 set, so build it wide */
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

/* value = m(normalized to TOPBIT) * 2^e (+ sticky below).  Returns flags
 * and writes the expected 80-bit result. */
static unsigned orc(uint8_t out[10], bool sign, big_t m, int32_t e, int sticky,
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
        /* Entire value below half the minimum subnormal: nearest-even
         * and toward-zero keep the signed zero; toward -inf of a
         * negative / +inf of a positive tiny value rounds to the
         * minimum subnormal (1 ulp of 2^-16445). */
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

static unsigned orc_addsub(uint8_t out[10], const dec_t *a, const dec_t *b,
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
            /* entirely below the big window: clamp to 1 at the bottom
             * so the rounding sees the perturbation DIRECTION (a - tiny
             * borrows, a + tiny does not) — mirrors the implementation */
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

static unsigned orc_mul(uint8_t out[10], const dec_t *a, const dec_t *b,
                        unsigned rc, unsigned pc)
{
    big_t P;
    big_u64(&P, a->mant);
    big_mul_u64(&P, b->mant);
    return orc(out, a->sign ^ b->sign, P, a->exp + b->exp - 126, 0, rc, pc);
}

static unsigned orc_div(uint8_t out[10], const dec_t *a, const dec_t *b,
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

static unsigned orc_sqrt(uint8_t out[10], const dec_t *a, unsigned rc, unsigned pc)
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
    /* rem = R - s^2 (needs up to 65 bits: compare as bigs) */
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
        big_sub(&t, &r2); /* t = rem */
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
        /* value = (s + guard/2) * 2^half = (2s+guard) * 2^(half-1);
         * build (2s+guard) wide (s can have bit 63 set) */
        big_t B;
        big_u64(&B, s);
        big_shl(&B, 1u);
        if (guard) B.l[0] |= 1u;
        big_shl(&B, (unsigned)(TOPBIT - 64));
        return orc(out, false, B, half - 1 - (TOPBIT - 64), inexact, rc, pc);
    }
}

/* ---------------- golden table ----------------------------------------- */

enum {
    OP_ADD, OP_SUB, OP_MUL, OP_DIV, OP_SQRT, OP_FPREM, OP_FPREM1,
    OP_FSCALE, OP_FSIN, OP_FCOS, OP_FPTAN, OP_FPATAN, OP_F2XM1,
    OP_FYL2X, OP_FYL2XP1, OP_TOI32, OP_TOI64
};

typedef struct {
    const char *op;
    unsigned rc, pc;
    const char *a, *b, *out;
    unsigned flags;
    int qq, complete; /* FPREM/FPREM1 only; -1 otherwise */
} grow_t;

/* Generated offline (exact integer/Fraction math; Decimal series for the
 * transcendentals).  See tests write-up in the file header. */
static const grow_t GOLD[] = {
    {"ADD",0,64,"3FFF8000000000000000","3FBE8000000000000000","3FFF8000000000000000",32,-1,-1},
    {"ADD",0,64,"3FFF8000000000000000","3FBF8000000000000000","3FFF8000000000000000",32,-1,-1},
    {"ADD",0,64,"3FFF8000000000000001","3FBF8000000000000000","3FFF8000000000000002",32,-1,-1},
    {"MUL",0,64,"3FFF8000000000000001","3FFF8000000000000001","3FFF8000000000000002",32,-1,-1},
    {"MUL",0,64,"1FF78000000000000000","3FFF8000000000000001","1FF78000000000000001",0,-1,-1},
    {"SUB",0,64,"00018000000000000000","00000000000000000001","00007FFFFFFFFFFFFFFF",2,-1,-1},
    {"DIV",0,64,"3FFF8000000000000000","4000C000000000000000","3FFDAAAAAAAAAAAAAAAB",32,-1,-1},
    {"DIV",1,64,"3FFF8000000000000000","4000C000000000000000","3FFDAAAAAAAAAAAAAAAA",32,-1,-1},
    {"DIV",2,64,"3FFF8000000000000000","4000C000000000000000","3FFDAAAAAAAAAAAAAAAB",32,-1,-1},
    {"DIV",3,64,"3FFF8000000000000000","4000C000000000000000","3FFDAAAAAAAAAAAAAAAA",32,-1,-1},
    {"ADD",0,24,"3FFF8000080000000000","3FE18000000000000000","3FFF8000080000000000",32,-1,-1},
    {"ADD",0,53,"3FFF8000000000004000","3FC48000000000000000","3FFF8000000000004000",32,-1,-1},
    {"MUL",0,24,"00007FFFFF8000000000","3FFF8000000000000000","00007FFFFF8000000000",2,-1,-1},
    {"MUL",0,64,"7FFEFFFFFFFFFFFFFFFF","40008000000000000000","7FFF8000000000000000",40,-1,-1},
    {"MUL",3,64,"7FFEFFFFFFFFFFFFFFFF","40008000000000000000","7FFEFFFFFFFFFFFFFFFF",40,-1,-1},
    {"MUL",1,64,"7FFEFFFFFFFFFFFFFFFF","40008000000000000000","7FFEFFFFFFFFFFFFFFFF",40,-1,-1},
    {"SQRT",0,64,"40008000000000000000","00000000000000000000","3FFFB504F333F9DE6484",32,-1,-1},
    {"SQRT",0,64,"40018000000000000000","00000000000000000000","40008000000000000000",0,-1,-1},
    {"SQRT",0,64,"40029000000000000000","00000000000000000000","4000C000000000000000",0,-1,-1},
    {"SQRT",0,64,"3FFEFFFFFFFFFFFFFFFE","00000000000000000000","3FFEFFFFFFFFFFFFFFFF",32,-1,-1},
    {"DIV",0,64,"00018000000000000000","40458000000000000000","00000000000000000000",48,-1,-1},
    {"ADD",0,64,"00004000000000000000","00004000000000000000","00018000000000000000",2,-1,-1},
    {"SUB",0,64,"00018000000000000000","00000000000000000002","00007FFFFFFFFFFFFFFE",2,-1,-1},
    {"FPREM",0,64,"4001B800000000000000","3FFF8000000000000000","3FFEC000000000000000",0,5,1},
    {"FPREM1",0,64,"4001B800000000000000","3FFF8000000000000000","BFFD8000000000000000",0,6,1},
    {"FPREM",0,64,"4001F000000000000000","40008000000000000000","3FFFC000000000000000",0,3,1},
    {"FPREM1",0,64,"4001F000000000000000","40008000000000000000","BFFE8000000000000000",0,4,1},
    {"FPREM",0,64,"3FFFA000000000000000","3FFF8000000000000000","3FFD8000000000000000",0,1,1},
    {"FPREM1",0,64,"3FFFA000000000000000","3FFF8000000000000000","3FFD8000000000000000",0,1,1},
    {"FPREM",0,64,"401D8000000080000000","3FFEC000000000000000","3FFE8000000000000000",0,5,1},
    {"FPREM1",0,64,"401D8000000080000000","3FFEC000000000000000","BFFD8000000000000000",0,6,1},
    {"FPREM",0,64,"4000E000000000000000","4000C000000000000000","3FFE8000000000000000",0,1,1},
    {"FPREM1",0,64,"4000E000000000000000","4000C000000000000000","3FFE8000000000000000",0,1,1},
    {"FPREM",0,64,"40638000000000000000","3FFFC000000000000000","40258000000000000000",0,2,0},
    {"FPREM1",0,64,"40638000000000000000","3FFFC000000000000000","40258000000000000000",0,2,0},
    {"FPREM",0,64,"4000C000000000000000","40638000000000000000","4000C000000000000000",0,0,1},
    {"FPREM1",0,64,"4000C000000000000000","40638000000000000000","4000C000000000000000",0,0,1},
    {"FSCALE",0,64,"3FFF8000000000000000","3FFFF333333333333333","40008000000000000000",0,-1,-1},
    {"FSCALE",0,64,"4000C000000000000000","C000A000000000000000","3FFEC000000000000000",0,-1,-1},
    {"FSCALE",0,64,"3FFE8000000000000000","4005C800000000000000","40628000000000000000",0,-1,-1},
    {"FSCALE",0,64,"3FFEC000000000000000","BFFF8000000000000000","3FFDC000000000000000",0,-1,-1},
    {"FSCALE",0,64,"3FFEC000000000000000","3FFE8000000000000000","3FFEC000000000000000",0,-1,-1},
    {"FSIN",0,64,"3FFF8000000000000000","00000000000000000000","3FFED76AA47848677021",32,-1,-1},
    {"FSIN",0,64,"3FFE8000000000000000","00000000000000000000","3FFDF57743A2582F7F44",32,-1,-1},
    {"FCOS",0,64,"3FFF8000000000000000","00000000000000000000","3FFE8A51407DA8345C92",32,-1,-1},
    {"FCOS",0,64,"3FFE8000000000000000","00000000000000000000","3FFEE0A94032DBEA7CEE",32,-1,-1},
    {"FPTAN",0,64,"3FFF8000000000000000","00000000000000000000","3FFFC75922E5F71D2DC5",32,-1,-1},
    {"FPTAN",0,64,"3FFE8000000000000000","00000000000000000000","3FFE8BDA7ADF9A3A5219",32,-1,-1},
    {"FPATAN",0,64,"3FFF8000000000000000","3FFF8000000000000000","3FFEC90FDAA22168C235",32,-1,-1},
    {"FPATAN",0,64,"3FFDAAAAAAAAAAAAAAAB","3FFF8000000000000000","3FFF9FE0BB5BD42AFFEC",32,-1,-1},
    {"F2XM1",0,64,"3FFE8000000000000000","00000000000000000000","3FFDD413CCCFE7799211",32,-1,-1},
    {"F2XM1",0,64,"BFFE8000000000000000","00000000000000000000","BFFD95F619980C4336F7",32,-1,-1},
    {"F2XM1",0,64,"3FFF8000000000000000","00000000000000000000","3FFF8000000000000000",0,-1,-1},
    {"F2XM1",0,64,"BFFF8000000000000000","00000000000000000000","BFFE8000000000000000",0,-1,-1},
    {"FSIN",0,64,"40278000000000000000","00000000000000000000","BFFDCFB89138B6AEC68E",32,-1,-1},
    {"FSIN",0,64,"40138000040000000000","00000000000000000000","3FFEBE15D8EBE0492119",32,-1,-1},
    {"FSIN",0,64,"4004C900000000000000","00000000000000000000","BFF8FDA789F15A413AA5",32,-1,-1},
    {"FSIN",0,64,"4005C900000000000000","00000000000000000000","BFF9FD9FC19A387F8615",32,-1,-1},
    {"FYL2X",0,64,"4000C000000000000000","40008000000000000000","4000CAE00D1CFDEB43D0",32,-1,-1},
    {"FYL2X",0,64,"40008000000000000000","3FFE8000000000000000","3FFE8000000000000000",0,-1,-1},
    {"FYL2X",0,64,"40018000000000000000","3FFE8000000000000000","3FFF8000000000000000",0,-1,-1},
    {"FYL2XP1",0,64,"3FFE8000000000000000","4000C000000000000000","3FFFE0A02756F9C1CB6F",32,-1,-1},
    {"FYL2XP1",0,64,"BFFE8000000000000000","40008000000000000000","C0008000000000000000",0,-1,-1},
    {"TOI32",0,64,"4000A000000000000000","00000000000000000000","00000002",32,-1,-1},
    {"TOI32",2,64,"4000A000000000000000","00000000000000000000","00000003",32,-1,-1},
    {"TOI32",1,64,"4000A000000000000000","00000000000000000000","00000002",32,-1,-1},
    {"TOI32",1,64,"C000A000000000000000","00000000000000000000","FFFFFFFD",32,-1,-1},
    {"TOI32",0,64,"4000E000000000000000","00000000000000000000","00000004",32,-1,-1},
    {"TOI32",3,64,"3FFE8000000000000000","00000000000000000000","00000000",32,-1,-1},
    {"TOI32",0,64,"4001A000000000000000","00000000000000000000","00000005",0,-1,-1},
    {"TOI32",0,64,"401E8000000000000000","00000000000000000000","80000000",1,-1,-1},
    {"TOI32",0,64,"4062C9F2C9CD04674EDF","00000000000000000000","80000000",1,-1,-1},
    {"TOI64",0,64,"403D8000000000000000","00000000000000000000","4000000000000000",0,-1,-1},
    {"TOI64",0,64,"403E8000000000000001","00000000000000000000","8000000000000000",1,-1,-1},
    {"TOI64",3,64,"3FFFC000000000000000","00000000000000000000","0000000000000001",32,-1,-1},

    /* Directed-rounding deep-tiny (C4): values below/around 2^-16446
     * (half the minimum subnormal), all four RC modes, both signs.
     * Nearest, toward-zero, and the direction-opposite sign keep the
     * signed zero (nearest keeps the tie at the exact halfway value
     * 0.5 * min subnormal, and rounds 0.75 up); toward -inf of a
     * negative / +inf of a positive nonzero tiny value takes the
     * minimum subnormal (1 ulp of 2^-16445).  0.5/0.75 pin the eff==0
     * halfway window and 1.5 pins the min-subnormal/next tie; 0.25,
     * minsub/5, minsub * (0.25 - 2^-65) and minsub/2^100 fall below
     * the window (eff < 0: exact, inexact division remainder, inexact
     * low product limb, and the sticky-only tail).
     * Flags = DE|UE|PE (field-0 operand + tiny inexact result). */
    {"MUL",0,64,"00000000000000000001","3FFE8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFE8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFE8000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFE8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFE8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFE8000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFE8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFE8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",0,64,"00000000000000000001","3FFEC000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFEC000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFEC000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFEC000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFEC000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFEC000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFEC000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFEC000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",0,64,"00000000000000000001","3FFFC000000000000000","00000000000000000002",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFFC000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFFC000000000000000","00000000000000000002",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFFC000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFFC000000000000000","80000000000000000002",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFFC000000000000000","80000000000000000002",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFFC000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFFC000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",0,64,"00000000000000000001","3FFD8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFD8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFD8000000000000000","00000000000000000001",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFD8000000000000000","00000000000000000000",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFD8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFD8000000000000000","80000000000000000001",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFD8000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFD8000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",0,64,"00000000000000000001","4001A000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",1,64,"00000000000000000001","4001A000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",2,64,"00000000000000000001","4001A000000000000000","00000000000000000001",50,-1,-1},
    {"DIV",3,64,"00000000000000000001","4001A000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",0,64,"80000000000000000001","4001A000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",1,64,"80000000000000000001","4001A000000000000000","80000000000000000001",50,-1,-1},
    {"DIV",2,64,"80000000000000000001","4001A000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",3,64,"80000000000000000001","4001A000000000000000","80000000000000000000",50,-1,-1},
    {"MUL",0,64,"00000000000000000001","3FFCFFFFFFFFFFFFFFFE","00000000000000000000",50,-1,-1},
    {"MUL",1,64,"00000000000000000001","3FFCFFFFFFFFFFFFFFFE","00000000000000000000",50,-1,-1},
    {"MUL",2,64,"00000000000000000001","3FFCFFFFFFFFFFFFFFFE","00000000000000000001",50,-1,-1},
    {"MUL",3,64,"00000000000000000001","3FFCFFFFFFFFFFFFFFFE","00000000000000000000",50,-1,-1},
    {"MUL",0,64,"80000000000000000001","3FFCFFFFFFFFFFFFFFFE","80000000000000000000",50,-1,-1},
    {"MUL",1,64,"80000000000000000001","3FFCFFFFFFFFFFFFFFFE","80000000000000000001",50,-1,-1},
    {"MUL",2,64,"80000000000000000001","3FFCFFFFFFFFFFFFFFFE","80000000000000000000",50,-1,-1},
    {"MUL",3,64,"80000000000000000001","3FFCFFFFFFFFFFFFFFFE","80000000000000000000",50,-1,-1},
    {"DIV",0,64,"00000000000000000001","40638000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",1,64,"00000000000000000001","40638000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",2,64,"00000000000000000001","40638000000000000000","00000000000000000001",50,-1,-1},
    {"DIV",3,64,"00000000000000000001","40638000000000000000","00000000000000000000",50,-1,-1},
    {"DIV",0,64,"80000000000000000001","40638000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",1,64,"80000000000000000001","40638000000000000000","80000000000000000001",50,-1,-1},
    {"DIV",2,64,"80000000000000000001","40638000000000000000","80000000000000000000",50,-1,-1},
    {"DIV",3,64,"80000000000000000001","40638000000000000000","80000000000000000000",50,-1,-1},
};

static int op_id(const char *s)
{
    if (!strcmp(s, "ADD")) return OP_ADD;
    if (!strcmp(s, "SUB")) return OP_SUB;
    if (!strcmp(s, "MUL")) return OP_MUL;
    if (!strcmp(s, "DIV")) return OP_DIV;
    if (!strcmp(s, "SQRT")) return OP_SQRT;
    if (!strcmp(s, "FPREM")) return OP_FPREM;
    if (!strcmp(s, "FPREM1")) return OP_FPREM1;
    if (!strcmp(s, "FSCALE")) return OP_FSCALE;
    if (!strcmp(s, "FSIN")) return OP_FSIN;
    if (!strcmp(s, "FCOS")) return OP_FCOS;
    if (!strcmp(s, "FPTAN")) return OP_FPTAN;
    if (!strcmp(s, "FPATAN")) return OP_FPATAN;
    if (!strcmp(s, "F2XM1")) return OP_F2XM1;
    if (!strcmp(s, "FYL2X")) return OP_FYL2X;
    if (!strcmp(s, "FYL2XP1")) return OP_FYL2XP1;
    if (!strcmp(s, "TOI32")) return OP_TOI32;
    return OP_TOI64;
}

static int eq_hex(const uint8_t o[10], const char *want)
{
    uint8_t w[10];
    from_hex(w, want);
    return eq80(o, w);
}

static uint32_t strtoul_hex32(const char *h)
{
    uint32_t v = 0;
    while (*h) {
        char c = *h++;
        v = (v << 4) | (uint32_t)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    return v;
}

static uint64_t strtoul_hex64(const char *h)
{
    uint64_t v = 0;
    while (*h) {
        char c = *h++;
        v = (v << 4) | (uint64_t)(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
    }
    return v;
}

static int ulp1_hex(const uint8_t o[10], const char *want)
{
    uint8_t w[10];
    from_hex(w, want);
    return ulp1(o, w);
}

static void run_goldens(void)
{
    size_t i;
    for (i = 0; i < sizeof GOLD / sizeof GOLD[0]; i++) {
        const grow_t *g = &GOLD[i];
        uint8_t a[10], b[10], o[10] = {0};
        uint32_t qq = 0xFFFFFFFFu;
        bool comp = true, sf = false;
        int32_t i32 = 0;
        int64_t i64 = 0;
        unsigned fl = 0;
        char eo[32];

        from_hex(a, g->a);
        from_hex(b, g->b);
        x87_80_set_prec(g->pc);
        x87_80_set_round(g->rc);
        switch (op_id(g->op)) {
        case OP_ADD: fl = x87_80_add(o, a, b); break;
        case OP_SUB: fl = x87_80_sub(o, a, b); break;
        case OP_MUL: fl = x87_80_mul(o, a, b); break;
        case OP_DIV: fl = x87_80_div(o, a, b); break;
        case OP_SQRT: fl = x87_80_sqrt(o, a); break;
        case OP_FPREM: fl = x87_80_fprem(o, a, b, &qq, &comp); break;
        case OP_FPREM1: fl = x87_80_fprem1(o, a, b, &qq, &comp); break;
        case OP_FSCALE: fl = x87_80_fscale(o, a, b); break;
        case OP_FSIN: fl = x87_80_fsin(o, a, &sf); break;
        case OP_FCOS: fl = x87_80_fcos(o, a, &sf); break;
        case OP_FPTAN: {
            uint8_t one[10];
            fl = x87_80_fptan(o, one, a, &sf);
            CHECK(eq_hex(one, "3FFF8000000000000000"),
                  "fptan(%s) one-push: got non-1.0", g->a);
            break;
        }
        case OP_FPATAN: fl = x87_80_fpatan(o, a, b); break;
        case OP_F2XM1: fl = x87_80_f2xm1(o, a); break;
        case OP_FYL2X: fl = x87_80_fyl2x(o, a, b); break;
        case OP_FYL2XP1: fl = x87_80_fyl2xp1(o, a, b); break;
        case OP_TOI32: fl = x87_80_to_i32(a, &i32, g->rc); break;
        default: fl = x87_80_to_i64(a, &i64); break;
        }
        hx80(o, eo, sizeof eo);

        if (op_id(g->op) == OP_TOI32) {
            CHECK((uint32_t)i32 == (uint32_t)strtoul_hex32(g->out) &&
                      fl == g->flags,
                  "golden %s(%s) rc=%u: got %" PRIX32 "/%u want %s/%u",
                  g->op, g->a, g->rc, (uint32_t)i32, fl, g->out, g->flags);
        } else if (op_id(g->op) == OP_TOI64) {
            CHECK((uint64_t)i64 == strtoul_hex64(g->out) && fl == g->flags,
                  "golden %s(%s): got %016" PRIX64 "/%u want %s/%u",
                  g->op, g->a, (uint64_t)i64, fl, g->out, g->flags);
        } else {
            /* transcendentals to <= 1 ulp; everything else bit-exact */
            int series = op_id(g->op) == OP_FSIN || op_id(g->op) == OP_FCOS ||
                         op_id(g->op) == OP_FPTAN || op_id(g->op) == OP_FPATAN;
            int ok = series ? ulp1_hex(o, g->out) : eq_hex(o, g->out);
            CHECK(ok && fl == g->flags,
                  "golden %s(%s,%s) rc=%u pc=%u: got %s/%u want %s/%u",
                  g->op, g->a, g->b, g->rc, g->pc, eo, fl, g->out, g->flags);
        }
        if ((op_id(g->op) == OP_FPREM || op_id(g->op) == OP_FPREM1) &&
            g->qq >= 0) {
            CHECK(qq == (uint32_t)g->qq && comp == (g->complete == 1),
                  "golden %s(%s,%s): qq=%u complete=%d want %d/%d",
                  g->op, g->a, g->b, qq, comp ? 1 : 0, g->qq, g->complete);
        }
    }
    x87_80_set_round(0u);
    x87_80_set_prec(64u);
}


/* ---------------- specials --------------------------------------------- */

static void run_specials(void)
{
    uint8_t a[10], b[10], o[10], o2[10];
    unsigned fl, c3, c2, c0;
    uint32_t qq;
    bool comp, sf;
    int32_t i32;
    int64_t i64;
    double d;
    float f;

    x87_80_set_round(0u);
    x87_80_set_prec(64u);

    /* constants: canonical FLDPI/FLDL2E/FLDLN2 patterns (+ln10) */
    x87_80_pi(o);
    CHECK(eq_hex(o, "4000C90FDAA22168C235"), "pi pattern");
    x87_80_log2e(o);
    CHECK(eq_hex(o, "3FFFB8AA3B295C17F0BC"), "log2e pattern");
    x87_80_ln2(o);
    CHECK(eq_hex(o, "3FFEB17217F7D1CF79AC"), "ln2 pattern");
    x87_80_ln10(o);
    CHECK(eq_hex(o, "4000935D8DDDAAA8AC17"), "ln10 pattern");
    x87_80_zero(o);
    CHECK(eq_hex(o, "00000000000000000000") && !x87_80_sign(o), "zero");
    x87_80_one(o);
    CHECK(eq_hex(o, "3FFF8000000000000000"), "one");
    x87_80_inf(o, true);
    CHECK(eq_hex(o, "FFFF8000000000000000") && x87_80_is_inf(o), "-inf");
    x87_80_nan(o, false, false);
    CHECK(eq_hex(o, "7FFFC000000000000000") && x87_80_is_nan(o) && !x87_80_is_snan(o), "qnan");
    x87_80_nan(o, true, true);
    CHECK(eq_hex(o, "FFFF8000000000000001") && x87_80_is_snan(o), "snan");

    /* set_round/set_prec */
    CHECK(x87_80_set_round(2u) == 0u, "set_round prev");
    CHECK(x87_80_set_round(9u) == 2u, "set_round invalid keeps");
    CHECK(x87_80_set_round(0u) == 2u, "set_round back");
    CHECK(x87_80_set_prec(24u) == 64u && x87_80_set_prec(64u) == 24u,
          "set_prec");

    /* NaN propagation: first NaN wins, snan quiets + IE */
    from_hex(a, "3FFF8000000000000000"); /* 1.0 */
    from_hex(b, "7FFF8000000000000001"); /* snan payload 1 */
    fl = x87_80_add(o, b, a);
    CHECK(eq_hex(o, "7FFFC000000000000001") && fl == X_IE, "snan quieting");
    from_hex(b, "7FFFC000000000000123"); /* qnan */
    fl = x87_80_add(o, b, a);
    CHECK(eq_hex(o, "7FFFC000000000000123") && fl == 0, "qnan first operand");
    from_hex(b, "FFFF8000000000000001"); /* negative snan as b */
    fl = x87_80_mul(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000001") && fl == X_IE,
          "snan as b operand quiets");

    /* invalid arithmetic -> real indefinite */
    from_hex(a, "7FFF8000000000000000");
    from_hex(b, "FFFF8000000000000000");
    fl = x87_80_add(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "inf + -inf");
    fl = x87_80_sub(o, a, a);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "inf - inf");
    from_hex(b, "00000000000000000000");
    fl = x87_80_mul(o, b, a);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "0 * inf");
    fl = x87_80_div(o, b, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "0/0");
    fl = x87_80_div(o, a, a);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "inf/inf");

    /* divide by zero */
    from_hex(a, "3FFF8000000000000000");
    fl = x87_80_div(o, a, b);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == X_ZE, "1/0");
    from_hex(a, "BFFF8000000000000000");
    fl = x87_80_div(o, a, b);
    CHECK(eq_hex(o, "FFFF8000000000000000") && fl == X_ZE, "-1/0");
    from_hex(a, "3FFF8000000000000000");
    fl = x87_80_div(o, b, a); /* 0 / 1 = 0 exact */
    CHECK(eq_hex(o, "00000000000000000000") && fl == 0, "0/1");

    /* sqrt specials */
    from_hex(a, "BFFF8000000000000000");
    fl = x87_80_sqrt(o, a);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "sqrt(-1)");
    from_hex(a, "80000000000000000000");
    fl = x87_80_sqrt(o, a);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "sqrt(-0)");
    from_hex(a, "7FFF8000000000000000");
    fl = x87_80_sqrt(o, a);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == 0, "sqrt(inf)");

    /* signed zeros */
    from_hex(a, "00000000000000000000");
    from_hex(b, "80000000000000000000");
    fl = x87_80_add(o, a, b);
    CHECK(eq_hex(o, "00000000000000000000") && fl == 0, "+0 + -0 = +0 (NE)");
    fl = x87_80_add(o, b, b);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "-0 + -0 = -0");
    x87_80_set_round(1u);
    fl = x87_80_add(o, a, b);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "+0 + -0 = -0 (RD)");
    x87_80_set_round(0u);

    /* DE on denormal and pseudo-denormal operands */
    from_hex(a, "00008000000000000001"); /* pseudo-denormal (J=1, field 0) */
    from_hex(b, "3FFF8000000000000000");
    fl = x87_80_add(o, a, b);
    CHECK(fl == (X_DE | X_PE), "pseudo-denormal operand DE: fl=%u", fl);
    CHECK(eq_hex(o, "3FFF8000000000000000"), "pseudo-den + 1 rounds to 1");
    from_hex(a, "00000000000000000001"); /* subnormal */
    fl = x87_80_mul(o, a, b);
    CHECK(fl == X_DE, "subnormal mul flags: %u", fl);
    CHECK(eq_hex(o, "00000000000000000001"), "subnormal * 1 exact");

    /* fcom codes */
    from_hex(a, "3FFF8000000000000000");
    from_hex(b, "40008000000000000000");
    x87_80_fcom(a, b, false, &c3, &c2, &c0);
    CHECK(c3 == 0 && c2 == 0 && c0 == 1, "fcom 1<2");
    x87_80_fcom(b, a, false, &c3, &c2, &c0);
    CHECK(c3 == 0 && c2 == 0 && c0 == 0, "fcom 2>1");
    x87_80_fcom(a, a, false, &c3, &c2, &c0);
    CHECK(c3 == 1 && c2 == 0 && c0 == 0, "fcom 1==1");
    from_hex(a, "80000000000000000000");
    from_hex(b, "00000000000000000000");
    x87_80_fcom(a, b, false, &c3, &c2, &c0);
    CHECK(c3 == 1 && c2 == 0 && c0 == 0, "fcom -0 == +0");
    from_hex(b, "7FFFC000000000000000");
    x87_80_fcom(a, b, true, &c3, &c2, &c0);
    CHECK(c3 == 1 && c2 == 1 && c0 == 1, "fcom unordered");

    /* fprem specials */
    from_hex(a, "3FFF8000000000000000");
    from_hex(b, "00000000000000000000");
    fl = x87_80_fprem(o, a, b, &qq, &comp);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fprem mod 0");
    from_hex(a, "7FFF8000000000000000");
    from_hex(b, "3FFF8000000000000000");
    fl = x87_80_fprem(o, a, b, &qq, &comp);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fprem inf dividend");
    from_hex(a, "40008000000000000000");
    from_hex(b, "7FFF8000000000000000");
    fl = x87_80_fprem(o, a, b, &qq, &comp);
    CHECK(eq_hex(o, "40008000000000000000") && fl == 0 && comp, "fprem inf modulus");
    from_hex(a, "80000000000000000000");
    from_hex(b, "3FFF8000000000000000");
    fl = x87_80_fprem(o, a, b, &qq, &comp);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0 && qq == 0 && comp,
          "fprem 0 dividend");

    /* fscale table cells (SDM Table 3-34) */
    from_hex(a, "3FFF8000000000000000");
    from_hex(b, "7FFF8000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == 0, "fscale(1,+inf)");
    from_hex(b, "FFFF8000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "00000000000000000000") && fl == 0, "fscale(1,-inf)");
    from_hex(a, "00000000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == 0, "fscale(0,-inf) indef no IE");
    from_hex(a, "7FFF8000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == 0, "fscale(inf,-inf)");
    from_hex(b, "7FFF8000000000000000");
    fl = x87_80_fscale(o, a, b);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == 0, "fscale(inf,+inf)");

    /* fxtract */
    from_hex(a, "00000000000000000000");
    fl = x87_80_fxtract(o, o2, a);
    CHECK(eq_hex(o, "00000000000000000000") && eq_hex(o2, "FFFF8000000000000000") &&
              fl == X_ZE, "fxtract(0): ZE, sig 0, exp -inf");
    from_hex(a, "4002A000000000000000"); /* 10.0 */
    fl = x87_80_fxtract(o, o2, a);
    CHECK(eq_hex(o, "3FFFA000000000000000"), "fxtract sig 1.25");
    CHECK(eq_hex(o2, "4000C000000000000000"), "fxtract exp 3");

    /* fsin/fcos/fptan domain and specials (card protocol) */
    from_hex(a, "403E8000000000000000"); /* 2^63 */
    fl = x87_80_fsin(o, a, &sf);
    CHECK(eq_hex(o, "403E8000000000000000") && fl == X_IE && !sf,
          "fsin(2^63) domain: out=a IE");
    from_hex(a, "7FFF8000000000000000");
    fl = x87_80_fsin(o, a, &sf);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fsin(inf)");
    fl = x87_80_fcos(o, a, &sf);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fcos(inf)");
    from_hex(a, "80000000000000000000");
    fl = x87_80_fsin(o, a, &sf);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "fsin(-0)");

    /* f2xm1 specials */
    from_hex(a, "80000000000000000000");
    fl = x87_80_f2xm1(o, a);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "f2xm1(-0)");
    from_hex(a, "FFFF8000000000000000");
    fl = x87_80_f2xm1(o, a);
    CHECK(eq_hex(o, "BFFF8000000000000000") && fl == 0, "f2xm1(-inf) = -1");
    from_hex(a, "7FFF8000000000000000");
    fl = x87_80_f2xm1(o, a);
    CHECK(eq_hex(o, "7FFF8000000000000000") && fl == 0, "f2xm1(+inf)");

    /* fyl2x specials */
    from_hex(a, "BFFF8000000000000000");
    from_hex(b, "3FFF8000000000000000");
    fl = x87_80_fyl2x(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fyl2x(-1,1)");
    from_hex(a, "00000000000000000000");
    fl = x87_80_fyl2x(o, a, b);
    CHECK(eq_hex(o, "FFFF8000000000000000") && fl == X_ZE, "fyl2x(0,1) = -inf ZE");
    from_hex(b, "80000000000000000000");
    fl = x87_80_fyl2x(o, a, b);
    CHECK(eq_hex(o, "FFFFC000000000000000") && fl == X_IE, "fyl2x(0,0)");

    /* fpatan zero cases (SDM Table 3-30); a = ST(0) = x, b = ST(1) = y,
     * result = atan2(y, x) per the frozen header convention */
    from_hex(a, "00000000000000000000"); /* x=+0 */
    from_hex(b, "80000000000000000000"); /* y=-0 */
    fl = x87_80_fpatan(o, a, b);
    CHECK(eq_hex(o, "80000000000000000000") && fl == 0, "fpatan(+0,-0)=-0");
    from_hex(a, "80000000000000000000"); /* x=-0, y=-0 */
    fl = x87_80_fpatan(o, a, b);
    CHECK(ulp1_hex(o, "C000C90FDAA22168C235") && (fl & X_PE), "fpatan(-0,-0)=-pi");
    from_hex(b, "00000000000000000000"); /* y=+0, x=-0 */
    fl = x87_80_fpatan(o, a, b);
    CHECK(ulp1_hex(o, "4000C90FDAA22168C235") && (fl & X_PE), "fpatan(-0,+0)=+pi");

    /* conversions */
    fl = x87_80_from_i32(o, -5);
    CHECK(eq_hex(o, "C001A000000000000000") && fl == 0, "from_i32(-5)");
    fl = x87_80_from_i64(o, INT64_MIN);
    CHECK(eq_hex(o, "C03E8000000000000000") && fl == 0, "from_i64(min)");
    d = 0.1;
    fl = x87_80_from_f64(o, d);
    CHECK(eq_hex(o, "3FFBCCCCCCCCCCCCD000") && fl == 0, "from_f64(0.1)");
    fl = x87_80_to_f64(o, &d);
    CHECK(d == 0.1 && fl == 0, "to_f64(0.1 ext) roundtrip");
    from_hex(a, "3FFF8000000000000020"); /* 1 + 2^-58 */
    fl = x87_80_to_f64(a, &d);
    CHECK(d == 1.0 && fl == X_PE, "to_f64(1+2^-58) = 1.0 PE");
    from_hex(a, "3FFF8000000000000000");
    fl = x87_80_to_i32(a, &i32, 0xFFu);
    CHECK(i32 == 1 && fl == 0, "to_i32 rc passthrough");
    from_hex(a, "7FFFC000000000000000");
    fl = x87_80_to_i32(a, &i32, 4u);
    CHECK(i32 == (-2147483647 - 1) && fl == X_IE, "to_i32(qnan) indefinite");
    from_hex(a, "C03E8000000000000000"); /* -2^63 exactly */
    fl = x87_80_to_i64(a, &i64);
    CHECK(i64 == INT64_MIN && fl == 0, "to_i64(-2^63)");
    from_hex(a, "403E8000000000000001"); /* 2^63+2 */
    fl = x87_80_to_i64(a, &i64);
    CHECK((uint64_t)i64 == 0x8000000000000000ULL && fl == X_IE,
          "to_i64(2^63+2) indefinite");
    f = 0.5f;
    fl = x87_80_from_f32(o, f);
    CHECK(eq_hex(o, "3FFE8000000000000000") && fl == 0, "from_f32(0.5)");
    fl = x87_80_to_f32(o, &f);
    CHECK(f == 0.5f && fl == 0, "to_f32 roundtrip");

    /* predicates */
    from_hex(a, "FFFF8000000000000001");
    CHECK(x87_80_sign(a) && x87_80_is_nan(a) && x87_80_is_snan(a),
          "predicates on -snan");
}

/* ---------------- randomized arithmetic vs the oracle ------------------- */

static uint64_t rng_state = 0x5DEECE66D12345ULL;

static uint64_t nextr(void)
{
    rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
    return rng_state;
}

static void gen_operand(uint8_t v[10], dec_t *d)
{
    uint64_t m = nextr() ^ (nextr() << 21);
    unsigned r = (unsigned)(nextr() & 0xFu);
    unsigned field;
    bool sign = (nextr() & 1u) != 0;

    switch (r) {
    case 0: field = 0; break;                       /* denormal zone */
    case 1: field = 1; break;
    case 2: field = 0x3FFF; break;
    case 3: field = 0x3FFE; break;
    case 4: field = 0x4000; break;
    case 5: field = 16383; break;                   /* near overflow */
    case 6: field = 16382; break;
    case 7: field = 16384 - 4; break;
    case 8: field = 0x3FFF + 200; break;
    case 9: field = 0x3FFF - 200; break;
    default: field = (unsigned)(nextr() % 0x7FFEu) + 1u; break;
    }
    if (field == 0) {
        /* subnormal / pseudo-denormal / (rarely) zero */
        if ((nextr() & 7u) == 0) m = 0;
        else if (nextr() & 1u) m |= 0x8000000000000000ULL; /* pseudo-den. */
        else m &= 0x7FFFFFFFFFFFFFFFULL;
        if (m == 0) m = 1;
    } else {
        m |= 0x8000000000000000ULL;
    }
    mk80(v, (field | (sign ? 0x8000u : 0u)), m);
    dec(v, d);
}

static void run_random(void)
{
    int i;
    static const unsigned rcs[4] = {0, 1, 2, 3};
    static const unsigned pcs[3] = {64, 53, 24};
    int n_add = 0, n_sub = 0, n_mul = 0, n_div = 0, n_sqrt = 0;

    for (i = 0; i < 600; i++) {
        uint8_t a[10], b[10], o[10], e[10];
        dec_t da, db;
        unsigned rc = rcs[i & 3u], pc = pcs[(i / 4u) % 3u];
        unsigned fl, ef;
        int kind = i % 5;
        char ba[32], bb[32], bo[32], be[32];

        x87_80_set_round(rc);
        x87_80_set_prec(pc);
        gen_operand(a, &da);
        gen_operand(b, &db);
        if (db.cls != 1) continue;
        if (kind != 4 && da.cls != 1) continue;

        switch (kind) {
        case 0:
            fl = x87_80_add(o, a, b);
            ef = orc_addsub(e, &da, &db, false, rc, pc);
            n_add++;
            break;
        case 1:
            fl = x87_80_sub(o, a, b);
            ef = orc_addsub(e, &da, &db, true, rc, pc);
            n_sub++;
            break;
        case 2:
            fl = x87_80_mul(o, a, b);
            ef = orc_mul(e, &da, &db, rc, pc);
            n_mul++;
            break;
        case 3:
            fl = x87_80_div(o, a, b);
            ef = orc_div(e, &da, &db, rc, pc);
            n_div++;
            break;
        default:
            if (da.sign) continue; /* sqrt covered by specials for negatives */
            fl = x87_80_sqrt(o, a);
            ef = orc_sqrt(e, &da, rc, pc);
            n_sqrt++;
            break;
        }
        /* DE from either operand's field-0 encoding */
        if (da.den_enc || db.den_enc) ef |= X_DE;
        hx80(a, ba, sizeof ba);
        hx80(b, bb, sizeof bb);
        hx80(o, bo, sizeof bo);
        hx80(e, be, sizeof be);
        CHECK(eq80(o, e) && fl == ef,
              "random %s rc=%u pc=%u\n  a=%s\n  b=%s\n  got %s fl=%u\n  want %s fl=%u",
              kind == 0 ? "add" : kind == 1 ? "sub" : kind == 2 ? "mul"
                        : kind == 3 ? "div" : "sqrt",
              rc, pc, ba, bb, bo, fl, be, ef);
        if (g_fail > 20) return;
    }
    printf("random cases: add=%d sub=%d mul=%d div=%d sqrt=%d\n",
           n_add, n_sub, n_mul, n_div, n_sqrt);
    CHECK(n_add >= 50 && n_div >= 50, "random case counts");
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
