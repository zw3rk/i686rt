/*
 * src/interp/x87_80.c — exact 80-bit x87 softfloat extended core (L5d, D9)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure Curated C11 integer math: no host long double / __float128 /
 * _Generic / VLA / __int128; every significand operation is explicit
 * uint64 limb arithmetic.  Host FP touches only the from_f32/from_f64 bit
 * decoders (the header allows host double "ONLY for the m64 conversion
 * edges").
 *
 * ================= x86 semantics implemented (SDM readings) =============
 *
 * Encodings (10-byte LE: 64-bit mantissa with explicit integer bit J at
 * bit 63, then sign + 15-bit biased exponent, bias 16383):
 *   field=0,     mant=0        : zero
 *   field=0, J=0, frac!=0      : subnormal (denormal)
 *   field=0, J=1               : pseudo-denormal; the 387+ "continues to
 *       support pseudo-denormals ... in the same way it does regular
 *       denormals, by generating a denormal operand exception" (Intel SDM
 *       Vol.1 §8.2.2 "Unsupported double extended-precision encodings and
 *       pseudo-denormals").  Value = 1.frac * 2^-16382 (a normal-valued
 *       number); pass-throughs keep the field-0 bytes; arithmetic
 *       normalizes; DE is signalled on operand use (the card's
 *       "pseudo-denormal ... normal value" treatment).
 *   1<=field<=0x7FFE, J=1      : normal
 *   1<=field<=0x7FFE, J=0      : "unnormal" — unsupported: the FPU
 *       "will raise an invalid operation exception if it encounters ... an
 *       unnormal (normal number with integer bit clear)" (same section).
 *   field=0x7FFF, J=1, frac=0  : infinity
 *   field=0x7FFF, J=1, frac!=0 : QNaN (bit 62 set) / SNaN (bit 62 clear)
 *   field=0x7FFF, J=0          : pseudo-infinity / pseudo-NaN —
 *       unsupported: IE + real indefinite on arithmetic use.
 *
 * Flags returned packed in x86 SW positions IE=1 DE=2 ZE=4 OE=8 UE=16
 * PE=32; all responses are the MASKED ones (v1 never unmasks).
 *
 * UE (the card asked to VERIFY): the SDM Vol.1 underflow discussion
 * splits #U into two events, the creation of a "tiny result" and the
 * creation of an "inexact tiny result", and sets the masked UE flag only
 * when both occur — an exact tiny result is delivered as a denormal with
 * no UE (8087 behaviour differed; 387+ is implemented here).  x87
 * detects tininess BEFORE rounding, so an exact value just below 2^-16382
 * that rounds up to the minimum normal still sets UE|PE.  Implemented:
 * tiny := exact normalized exponent < -16382; UE := tiny && inexact.
 * In-register subnormals exist at every PC (the 80-bit exponent range
 * never shrinks under precision control), so a tiny inexact result sets
 * UE at PC=24/53 just as at PC=64; PE accompanies every inexact result.
 *
 * OE: detected after rounding (card); masked response per RC —
 * nearest/away deliver +-inf, toward-zero/against-direction deliver the
 * format maximum; OE always co-sets PE (the exact finite value was not
 * representable).
 *
 * NaN propagation: the FIRST NaN operand (a, then b) is quieted and
 * returned; any SNaN operand sets IE.  Invalid arithmetic (inf-inf, 0*inf,
 * 0/0, inf/inf, sqrt(negative), unsupported encodings) sets IE and returns
 * the real indefinite QNaN (sign 1, field 0x7FFF, mant 0xC000000000000000).
 *
 * FPREM/FPREM1: SDM — "C0, C3, C1 := LeastSignificantBits(Q);
 * (* Q2, Q1, Q0 *)": *qq returns Q&7 (bit0=Q0->C1, bit1=Q1->C3,
 * bit2=Q2->C0).  The remainder is exact (no PE, rounding/PC ignored); one
 * execution reduces the exponent difference by at most 63 (SDM: the
 * partial step uses an implementation-defined N in [32,63]; here
 * N = 63: Q = floor(mant_a * 2^62 / mant_b)); *reduction_complete is
 * false (x87 C2=1) when the exponent difference was >= 64.  SDM Table
 * 3-38 specials: modulus +-inf -> result = a; modulus 0 or dividend +-inf
 * -> IE + indefinite; dividend +-0 -> +-0.  FPREM1 uses the IEEE
 * round-to-nearest-even quotient in the complete case; partial reduction
 * uses the same truncated 63-bit quotient (SDM leaves the partial step
 * implementation-specific).
 *
 * FSCALE per SDM Table 3-34 (rows ST(0)=a, cols ST(1)=b): a=+-inf:
 * b=+inf -> sign(a) inf, b=-inf -> real indefinite; a=+-0 with b=+-inf ->
 * real indefinite; a finite: b=-inf -> sign(a) zero, b=+inf -> sign(a)
 * inf; b finite scales by 2^trunc(b) through the rounding pipeline
 * (OE/UE/PE possible; a denormal a may normalize, which can set PE —
 * SDM: "if ST(0) holds a denormal, the mantissa is also changed").  The
 * SDM flag list for FSCALE names #IA only for SNaN/unsupported operands,
 * so the indefinite cells deliver the NaN WITHOUT IE (documented choice).
 *
 * FXTRACT: SDM — source +-0 raises #Z (not #IA) with masked response
 * exponent -inf, significand +-0; +-inf yields exponent +inf and
 * significand +-inf (deterministic extension; not tabulated by the SDM);
 * denormal/pseudo-denormal source: significand = mantissa (normalized
 * encoding), exponent -16382.
 *
 * FSIN/FCOS/FPTAN domain: the SDM requires |ST(0)| < 2^63 and for larger
 * finite sources says "the C2 flag in the FPU status word is set, and the
 * value in register ST(0) remains unchanged ... The instruction does not
 * raise an exception" (FSIN page, SDM Vol.2).  The frozen x87_80.h has no
 * C2 output, and the L5d card therefore fixes the protocol: out = a
 * unchanged, IE set in the returned flags, *stack_fault = false; the
 * caller maps that to C2=1 (and NOT to the IE flag).  +-inf raises IE and
 * yields the real indefinite (SDM *-marked cells); NaN propagates.
 * FPTAN pushes +1.0 through out_one on success; on the domain error the
 * caller must not push (flags carry IE per the protocol above).
 *
 * F2XM1/FYL2XP1 outside the SDM accuracy window are "undefined" in the
 * SDM; this implementation computes the true mathematical value through
 * the same pipelines (deterministic, documented): f2xm1 handles any
 * finite a via 2^a = 2^trunc(a) * 2^frac(a) (|a| >= 2^63 saturates:
 * +inf/OE for positive, exactly -1 for negative); f2xm1(+inf) = +inf,
 * f2xm1(-inf) = -1 (exact).
 *
 * FYL2X/FYL2XP1/FPATAN specials follow SDM Tables 3-21/3-33/3-30 as
 * fetched from the SDM instruction pages (see each function); FYL2XP1 has
 * no #Z in its flag list, so log2(1+a)=log2(0) results deliver +-inf
 * without ZE (documented).
 *
 * FCOM: C3,C2,C0 = (a>b:000, a<b:001, a==b:100, unordered:111).  -0
 * compares equal to +0.  The codes are identical for FCOM/FUCOM; the
 * `unordered` parameter records which variant the caller is emulationg —
 * IE signalling is the caller's duty (FCOM: any NaN operand; FUCOM: SNaN
 * only) because this entry point returns condition codes only.
 *
 * ================= implementation =======================================
 *
 * Internal value: struct { uint64_t mant; int32_t exp; bool sign; cls }
 * (the card's representation) plus two encoding flags: unsup (unsupported
 * encoding) and den_enc (field-0 encoding: subnormal or pseudo-denormal).
 * value = mant * 2^(exp-63); normal numbers have bit 63 set.  Exact
 * intermediates are (128-bit hi:lo significand, exponent, sticky) tuples
 * rounded ONCE by round_pack80 at eff = min(PC, 64-shift) significant
 * bits — the exact pipeline the Python goldens were generated against.
 * Division and sqrt derive the guard bit exactly (division keeps 69
 * quotient bits; sqrt tests R >= s^2+s+1 for the half-ulp), so both are
 * correctly rounded.  Transcendentals evaluate in 128-bit wide-float
 * (normalized 128-bit significand + exponent) with <= 2^-120 relative
 * error and round once — inside the card's 1-ulp budget.  sin/cos/tan
 * argument reduction is exact Cody-Waite on a 320-bit pi/2 significand
 * (reduction error ~2^-250 for |a| < 2^63); |r| < 2^-33 cases are
 * assembled exactly (sin/tan(r) = r to 64 bits; cos(r) = 1).
 *
 * All rounding constants were generated offline with exact integer math
 * (round-to-nearest-even on big ints) from 110+-digit source constants;
 * the four public 80-bit patterns reproduce the canonical x87 FLDPI /
 * FLDL2E / FLDLN2 encodings (cross-checked against FLDL2T = log2(10)).
 */

#include "interp/x87_80.h"

#include <string.h>

/* --- module state (process-wide CW mirror; handlers set per-ctx) ------ */

static unsigned g_rc = 0u;  /* x87 CW RC: 0 NE, 1 down(-inf), 2 up(+inf), 3 zero */
static unsigned g_pc = 64u; /* x87 CW PC: 24 / 53 / 64 */

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

static void xf_decode(const uint8_t v[10], xf_t *f)
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

static void xf_encode(const xf_t *f, uint8_t out[10])
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

/* Encode an exact integer significand: value = mant * 2^vexp, placing
 * into the 80-bit format without rounding (callers guarantee the value
 * fits in 64 significant bits). */
static void xf_out_sig(uint8_t out[10], bool sign, uint64_t mant, int32_t vexp)
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

static void xf_out_indef(uint8_t out[10])
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

static void xf_out_inf(uint8_t out[10], bool sign)
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

static void xf_out_zero(uint8_t out[10], bool sign)
{
    memset(out, 0, 10);
    if (sign) out[9] = 0x80u;
}

static bool xf_is_nan_cls(const xf_t *f) { return f->cls == X_QNAN || f->cls == X_SNAN; }
static bool xf_is_den(const xf_t *f) { return f->cls == X_NUM && f->den_enc; }

/* NaN propagation: first NaN operand wins (quieted); any SNaN sets IE. */
static unsigned xf_nan_prop(xf_t *r, const xf_t *a, const xf_t *b)
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

/* normalized (mant bit63 set, top-bit exponent) for finite numerics */
static void xf_norm_num(const xf_t *f, uint64_t *m, int32_t *e)
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

static u2 u2_fr(uint64_t hi, uint64_t lo) { u2 r; r.hi = hi; r.lo = lo; return r; }

static u2 u2_shl(u2 a, unsigned n)
{
    if (n == 0) return a;
    if (n >= 128) return u2_fr(0, 0);
    if (n < 64) return u2_fr((a.hi << n) | (a.lo >> (64 - n)), a.lo << n);
    if (n == 64) return u2_fr(a.lo, 0);
    return u2_fr(a.lo << (n - 64), 0);
}

static u2 u2_shr(u2 a, unsigned n)
{
    if (n == 0) return a;
    if (n >= 128) return u2_fr(0, 0);
    if (n < 64) return u2_fr(a.hi >> n, (a.lo >> n) | (a.hi << (64 - n)));
    if (n == 64) return u2_fr(0, a.hi);
    return u2_fr(0, a.hi >> (n - 64));
}

static u2 u2_add(u2 a, u2 b, bool *carry)
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

static u2 u2_sub(u2 a, u2 b, bool *borrow)
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

static int u2_cmp(u2 a, u2 b)
{
    if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
    if (a.lo != b.lo) return a.lo < b.lo ? -1 : 1;
    return 0;
}

static u2 mul64(uint64_t a, uint64_t b)
{
    uint64_t al = a & 0xFFFFFFFFULL, ah = a >> 32;
    uint64_t bl = b & 0xFFFFFFFFULL, bh = b >> 32;
    uint64_t ll = al * bl, lh = al * bh, hl = ah * bl, hh = ah * bh;
    uint64_t mid = lh + (ll >> 32);
    bool c1 = mid < lh; /* bit 64 of (lh + ll>>32) */
    uint64_t mid2 = mid + hl;
    bool c2 = mid2 < mid; /* carry into bit 64 of the running sum */
    {
        u2 r;
        /* carries c1/c2 weigh 2^96 in the product (bit 32 of the high
         * limb), NOT 2^64 */
        r.lo = (mid2 << 32) | (ll & 0xFFFFFFFFULL);
        r.hi = hh + (mid2 >> 32) +
               (((uint64_t)(c1 ? 1u : 0u) + (uint64_t)(c2 ? 1u : 0u)) << 32);
        return r;
    }
}

static bool u2_is_zero(u2 a) { return a.hi == 0 && a.lo == 0; }

/* normalize to bit 127; adjusts *exp.  Returns false when zero. */
static bool u2_norm(u2 *m, int32_t *exp)
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

/* bit-serial long division: Q = floor(A * 2^extra / d), R = remainder.
 * A is fed MSB-first, then `extra` zero bits. */
static void div_u2_u64(u2 A, unsigned extra, uint64_t d, u2 *q, uint64_t *rem)
{
    u2 r = u2_fr(0, 0), qq = u2_fr(0, 0);
    unsigned total = 128u + extra;
    unsigned i;

    for (i = 0; i < total; i++) {
        uint64_t bit;
        unsigned bi = 127u - i; /* MSB-first */
        if (i < 128) {
            if (bi < 64) bit = (A.lo >> bi) & 1u;
            else bit = (A.hi >> (bi - 64)) & 1u;
        } else {
            bit = 0;
        }
        /* r = (r << 1) | bit;  r stays < 2d after the trial subtract */
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

/* integer sqrt of a 128-bit value: root = floor(sqrt(n)), rem = n-root^2 */
static uint64_t isqrt128(u2 n, u2 *remout)
{
    u2 rem = u2_fr(0, 0);
    uint64_t root = 0;
    int i;

    for (i = 0; i < 64; i++) {
        u2 trial;
        bool dummy;
        rem = u2_shl(rem, 2);
        rem.lo |= n.hi >> 62; /* top 2 bits of n */
        n = u2_shl(n, 2);
        root <<= 1;
        trial = u2_fr(root >> 63, (root << 1) | 1u); /* 65-bit trial */
        if (u2_cmp(rem, trial) >= 0) {
            rem = u2_sub(rem, trial, &dummy);
            root |= 1u;
        }
    }
    *remout = rem;
    return root;
}

/* --- rounding core ------------------------------------------------------ */

/* round decision; lsb = least kept bit, guard = first dropped bit,
 * rest = any lower bit (incl. sticky).  Uses the current RC. */
static bool round_inc(bool lsb, bool guard, bool rest, bool sign)
{
    switch (g_rc) {
    case 1: return sign && (guard || rest);   /* toward -inf */
    case 2: return !sign && (guard || rest);  /* toward +inf */
    case 3: return false;                     /* toward zero */
    default: return guard && (rest || lsb);   /* nearest-even */
    }
}

/* Round the 128-bit significand m to eff significant bits (eff in
 * [0,64]); returns the rounded significand (== 1<<eff on carry when
 * eff >= 1; eff == 0 returns 0/1 = the "2^(exp+1)" bit). */
static uint64_t rnd_sig(u2 m, bool sticky, int eff, bool sign, bool *inexact)
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
        unsigned t = (unsigned)(128 - eff) - 64u; /* 0..63 */
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

/* Round (sign, m normalized-or-zero, exp, sticky) into an 80-bit value at
 * precision pc (24/53/64).  m's bit 127 is the value's leading bit:
 * value = m * 2^exp.  Single correct rounding at eff = min(pc, 64-shift)
 * significant bits with the documented UE/OE rules. */
static unsigned round_pack80(xf_t *r, bool sign, u2 m, int32_t exp, bool sticky,
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
    if (u2_is_zero(m)) { /* value entirely below the window */
        m = u2_fr(0, 1);
        exp -= 128;
    }
    u2_norm(&m, &exp);
    exp += 127; /* m*2^exp (128-bit m) -> true top-bit exponent */
    tiny = exp < X_EMIN; /* tininess detected before rounding */
    shift = tiny ? (X_EMIN - exp) : 0;
    eff = (int)pc < 64 - shift ? (int)pc : 64 - shift;

    if (eff < 0 || (eff == 0 && exp < X_EMIN - 64)) {
        /* below half the minimum subnormal: rounds to (signed) zero */
        r->cls = X_ZERO;
        r->mant = 0;
        r->exp = 0;
        return X_UE | X_PE;
    }
    if (eff == 0) {
        /* value in [2^-16446, 2^-16445): rounds to 0 or the minimum
         * subnormal (the tie goes to even = 0) */
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
    if (eff >= 1 && sig == (((uint64_t)1) << eff)) { /* rounding carry */
        sig >>= 1;
        exp++;
    }
    if (inexact) flags |= X_PE;
    if (tiny && inexact) flags |= X_UE;

    if (exp > X_EMAX) { /* masked overflow per RC */
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
        /* subnormal placement: value = sig * 2^(exp-eff+1) */
        int sh = exp - eff + 16446;
        r->mant = sh >= 64 ? 0 : (sig << sh);
        r->exp = X_EMIN;
        r->den_enc = true;
        if (r->mant == 0) r->cls = X_ZERO; /* unreachable for exact inputs */
    }
    return flags;
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
        else xf_out_zero(out, g_rc == 1u); /* x + (-x) = +0 (NE), -0 (RD) */
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

        /* align both into a 128-bit window whose bit 127 weighs 2^c.
         * Drops of the smaller operand below the window matter for the
         * rounding DIRECTION, so an entirely-dropped operand (d >= 128)
         * is clamped to a 1 at window bit 0: the sum/difference then
         * carries the right guard/rest pattern (a - tiny borrows to
         * ...FFFF, a + tiny keeps the low bits) instead of a bare
         * sticky bit. */
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
                B = u2_fr(0, 1); /* clamped direction-preserving tail */
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
                A = u2_fr(0, 1); /* clamped direction-preserving tail */
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
        P = mul64(ma, mb); /* exact 128-bit product */
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
        xf_out_inf(out, a.sign ^ b.sign); /* inf / finite */
        return 0;
    }
    if (b.cls == X_INF) {
        xf_out_zero(out, a.sign ^ b.sign); /* finite / inf, exact */
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
        div_u2_u64(A, 2u, mb, &q, &rem); /* q = floor(ma * 2^66 / mb): 67 bits */
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
    if (a.cls == X_ZERO) { /* sqrt(+-0) = +-0, exact (SDM) */
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
        if ((e & 1) != 0) { /* e odd: radicand m<<64, value = s*2^((e-127)/2) */
            R = u2_shl(u2_fr(0, m), 64);
            half = (e - 127) / 2;
        } else {            /* e even: radicand m<<63, value = s*2^((e-126)/2) */
            R = u2_shl(u2_fr(0, m), 63);
            half = (e - 126) / 2;
        }
        s = isqrt128(R, &rem);
        /* exact guard bit: sqrt(R) >= s + 1/2  <=>  R >= s^2 + s + 1 */
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
    (void)unordered; /* codes identical for FCOM/FUCOM; IE is caller-side
                      * (FCOM: any NaN; FUCOM: SNaN only) — see header. */
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
        /* same sign: compare classes/exponents/mantissas */
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
    if (b.cls == X_ZERO || a.cls == X_INF) { /* modulus 0 / dividend inf */
        xf_out_indef(out);
        return X_IE;
    }
    if (b.cls == X_INF) { /* modulus inf: result = dividend */
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

        if (d < 0) { /* |a| < |b|: q = 0 */
            memcpy(out, av, 10);
            return flags;
        }
        if (d < 64) {
            u2 A = u2_shl(u2_fr(0, ma), (unsigned)d);
            u2 q;
            uint64_t rem;
            div_u2_u64(A, 0u, mb, &q, &rem);
            if (ieee) { /* FPREM1: quotient rounded to nearest-even */
                uint64_t q0 = q.lo;
                bool inc = rem > (mb - rem); /* 2*rem > mb, overflow-safe */
                if (!inc && rem == (mb - rem) && (q0 & 1u) != 0u) inc = true;
                if (inc) { /* rint = rem - mb < 0: sign flips */
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
        /* partial reduction: N = 63 quotient bits (SDM: impl-defined) */
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
    /* SDM Table 3-34 (rows ST(0)=a, cols ST(1)=b) */
    if (a.cls == X_INF) {
        if (b.cls == X_INF) {
            if (b.sign) { xf_out_indef(out); return 0; } /* no IA per flags list */
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
        /* n = trunc(b) from the representation (frac truncation) */
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
    if (a.cls == X_ZERO) { /* SDM: #Z; masked: exp = -inf, sig = +-0 */
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
        /* exponent as extended integer, significand in [1,2) (denormal:
         * mantissa, normalized encoding) */
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
/* Generated with exact integer math (RNE to the 64-bit mantissa) from
 * 110-digit constants; pi/log2e/ln2 reproduce the canonical FLDPI/FLDL2E/
 * FLDLN2 encodings.  ln10 serves FLDLG2-style derivations (log10(2) =
 * ln2/ln10) in the caller. */

static void const_out(uint8_t out[10], unsigned se, uint64_t mant)
{
    uint64_t m = mant;
    int i;
    for (i = 0; i < 8; i++) out[i] = (uint8_t)(m >> (8 * i));
    out[8] = (uint8_t)se;
    out[9] = (uint8_t)(se >> 8);
}

void x87_80_pi(uint8_t out[10])   /* 3.14159265358979323846... */
{
    const_out(out, 0x4000u, 0xC90FDAA22168C235ULL);
}

void x87_80_log2e(uint8_t out[10]) /* 1.44269504088896340735... */
{
    const_out(out, 0x3FFFu, 0xB8AA3B295C17F0BCULL);
}

void x87_80_ln2(uint8_t out[10])  /* 0.69314718055994530941... */
{
    const_out(out, 0x3FFEu, 0xB17217F7D1CF79ACULL);
}

void x87_80_ln10(uint8_t out[10]) /* 2.30258509299404568401... */
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

/* ================= wide float (transcendental internals) ============== */
/* value = +- m * 2^e, m normalized (bit 127 set) or zero.  Products keep
 * the top 128 bits (relative error <= 2^-127 per op, far inside the 1-ulp
 * budget); series run until terms are 2^-140 of the accumulator. */

typedef struct { u2 m; int32_t e; bool sign; } wx_t;

static const uint64_t C_LN2[2]   = {0x58B90BFBE8E7BCD5ULL, 0xE4F1D9CC01F97B58ULL};
static const uint64_t C_LOG2E[2] = {0xB8AA3B295C17F0BBULL, 0xBE87FED0691D3E89ULL};
static const uint64_t C_SQRT2[2] = {0xB504F333F9DE6484ULL, 0x597D89B3754ABE9FULL};
static const uint64_t C_SQRT3[2] = {0xDDB3D742C265539DULL, 0x92BA16B83C5C1DC5ULL};
/* pi itself does not fit Q1.127 (pi >= 2): use wx_pi() = 2 * C_PI2 */
static const uint64_t C_PI2[2]   = {0xC90FDAA22168C234ULL, 0xC4C6628B80DC1CD1ULL};
static const uint64_t C_PI4[2]   = {0x6487ED5110B4611AULL, 0x62633145C06E0E69ULL};
static const uint64_t C_PI6[2]   = {0x430548E0B5CD9611ULL, 0x96ECCB83D59EB446ULL};
static const uint64_t C_2MSQ3[2] = {0x224C28BD3D9AAC62ULL, 0x6D45E947C3A3E23BULL};
/* pi/2 as a 320-bit significand (value * 2^319), MSB limb first */
static const uint64_t C_PI2_320[5] = {
    0xC90FDAA22168C234ULL, 0xC4C6628B80DC1CD1ULL, 0x29024E088A67CC74ULL,
    0x020BBEA63B139B22ULL, 0x514A08798E3404DEULL
};
/* 2/pi as a 256-bit fraction (value * 2^255), MSB limb first */
static const uint64_t C_2OPI[4] = {
    0x517CC1B727220A94ULL, 0xFE13ABE8FA9A6EE0ULL,
    0x6DB14ACC9E21C820ULL, 0xFF28B1D5EF5DE2B1ULL
};
/* floor(pi/4 * 2^65): |a| below this and exponent -2 skips reduction */
#define C_PI4_LIMIT 0x6487ED5110B461A6ULL

/* 1/k for k = 2..91 (Q1.127, RNE) — covers every series divisor used
 * (the 44-term atanh/atan loops reach 2k+1 = 89) */
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

static wx_t wxc(const uint64_t t[2])
{
    wx_t r;
    r.m = u2_fr(t[0], t[1]);
    r.e = -127;
    r.sign = false;
    u2_norm(&r.m, &r.e);
    return r;
}

static wx_t wx_zero(void)
{
    wx_t r;
    r.m = u2_fr(0, 0);
    r.e = 0;
    r.sign = false;
    return r;
}

static wx_t wx_one(void)
{
    wx_t r;
    r.m = u2_fr(0x8000000000000000ULL, 0);
    r.e = -127;
    r.sign = false;
    return r;
}

static wx_t wx_pi(void) /* pi = 2 * (pi/2): pi/2 kept in Q1.127 */
{
    wx_t r = wxc(C_PI2);
    r.e += 1; /* value doubles: e grows by one */
    return r;
}

static bool wx_is_zero(const wx_t *a) { return u2_is_zero(a->m); }

/* the small integer n as a wx value (series ratio numerators) */
static wx_t wx_int(uint64_t n)
{
    wx_t r;
    r.m = u2_fr(0, n);
    r.e = 0;
    r.sign = false;
    u2_norm(&r.m, &r.e);
    return r;
}

static int wx_cmp_abs(const wx_t *a, const wx_t *b)
{
    if (wx_is_zero(a) && wx_is_zero(b)) return 0;
    if (wx_is_zero(a)) return -1;
    if (wx_is_zero(b)) return 1;
    if (a->e != b->e) return a->e < b->e ? -1 : 1;
    return u2_cmp(a->m, b->m);
}

static wx_t wx_mul(const wx_t *a, const wx_t *b)
{
    wx_t r;
    u2 p01, p12a, p12b, p34, mid;
    bool cmid, ovf;

    if (wx_is_zero(a) || wx_is_zero(b)) return wx_zero();
    p01 = mul64(a->m.lo, b->m.lo);   /* bits 0..127   */
    p12a = mul64(a->m.lo, b->m.hi);  /* bits 64..191  */
    p12b = mul64(a->m.hi, b->m.lo);  /* bits 64..191  */
    p34 = mul64(a->m.hi, b->m.hi);   /* bits 128..255 */
    mid = u2_add(p12a, p12b, &cmid); /* bits 64..192  */
    /* assemble the 256-bit product limbs with the carry chain:
     * L0 = p01.lo (bits 0..63);  L1 = p01.hi + mid.lo (bits 64..127);
     * L2 = p34.lo + mid.hi + carry (bits 128..191);
     * L3 = p34.hi + carry + cmid (bits 192..255). */
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
        /* significand = bits 127..254 of the product; bit 255 = ovf */
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

/* magnitude add of a and b (signs assumed positive) */
static wx_t wx_addmag(const wx_t *a, const wx_t *b, bool sign)
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
        Y = u2_shr(lo->m, (unsigned)d); /* dropped bits < 2^-127 relative */
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

static wx_t wx_add(const wx_t *a, const wx_t *b)
{
    wx_t r;
    bool borrow;

    if (a->sign == b->sign) return wx_addmag(a, b, a->sign);
    /* opposite signs: subtract the smaller magnitude, aligned to the
     * larger exponent (dropped low bits sit below 2^-127 relative). */
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
            Y = u2_fr(0, 0); /* lo entirely below the window: hi - lo
                              * keeps bit 127 set (hi >= 2^(e+127) and
                              * lo < 2^e) — still normalized. */
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

static wx_t wx_sub(const wx_t *a, const wx_t *b)
{
    wx_t nb = *b;
    nb.sign = !nb.sign;
    return wx_add(a, &nb);
}

/* quotient of normalized 128-bit significands (a/b), 256-bit serial
 * division; remainder != 0 only perturbs below bit -128 (ignored).
 * The running remainder can cross 2^128 (129th bit) when B > 2^127:
 * rem stays < 2B < 2^129, so the top bit is tracked separately. */
static wx_t wx_div(const wx_t *a, const wx_t *b)
{
    wx_t r;
    u2 B, rem = u2_fr(0, 0), q = u2_fr(0, 0);
    bool ovf = false;
    unsigned i;

    if (wx_is_zero(a)) return wx_zero();
    B = b->m; /* normalized bit 127 */
    for (i = 0; i < 256; i++) {
        uint64_t bit;
        u2 t;
        unsigned bi = 127u - i; /* MSB-first */
        bool top;
        if (i < 128) {
            if (bi < 64) bit = (a->m.lo >> bi) & 1u;
            else bit = (a->m.hi >> (bi - 64)) & 1u;
        } else {
            bit = 0;
        }
        top = (rem.hi >> 63) != 0; /* would-be bit 128 after the shift */
        t = u2_shl(rem, 1);
        t.lo |= bit;
        rem = t;
        if (i >= 127) {
            bool newbit = false;
            if (top) {
                /* 129-bit remainder 2^128 + rem; rem < B holds here (the
                 * pre-shift remainder was < B), so the difference
                 * 2^128 + rem - B = 2^128 - (B - rem) is the two's
                 * complement of B - rem and stays < B < 2^128. */
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
        } else if (top) {
            /* i < 127 with the top bit set cannot happen for normalized
             * inputs (rem < 2^127 there); defensive no-op. */
        }
    }
    if (ovf) { /* quotient significand in [1,2): value = m * 2^(ea-eb-127) */
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

/* --- series kernels ------------------------------------------------------ */

static bool wx_tiny(const wx_t *term, const wx_t *acc)
{
    return wx_is_zero(term) || term->e <= acc->e - 140;
}

/* e^y - 1 for |y| <= ~0.7 (sign inside y) */
static wx_t wx_expm1(const wx_t *y)
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

/* ln(m) for m in [1, 2): compress to [1, sqrt2), then the atanh series
 * ln(1+z) = 2*(z + z^3/3 + z^5/5 + ...) on z = (m-1)/(m+1),
 * |z| <= 0.1716 (about 26 terms to 2^-140). */
static wx_t wx_ln_m(wx_t m)
{
    wx_t one = wx_one(), sq2 = wxc(C_SQRT2);
    wx_t z, sum, term, res;
    int halves = 0, k;

    while (wx_cmp_abs(&m, &sq2) >= 0) {
        m.e -= 1; /* m /= 2 */
        halves++;
    }
    z = wx_sub(&m, &one); /* [0, 0.4142) */
    {
        wx_t two = wx_add(&one, &one);
        wx_t den = wx_add(&two, &z); /* m + 1 = 2 + z */
        z = wx_div(&z, &den);
    }
    sum = z;
    term = z;
    {
        wx_t z2 = wx_mul(&z, &z);
        for (k = 1; k <= 44; k++) {
            /* term_k = z^(2k+1)/(2k+1): ratio (2k-1)/(2k+1) on t^2 */
            wx_t f = wxc(C_INV_K(2 * k + 1));
            wx_t num = wx_int((uint64_t)(2 * k - 1));
            term = wx_mul(&term, &z2);
            term = wx_mul(&term, &num);
            term = wx_mul(&term, &f);
            sum = wx_add(&sum, &term);
            if (k > 6 && wx_tiny(&term, &sum)) break;
        }
    }
    res = wx_add(&sum, &sum); /* 2*sum */
    while (halves--) {
        wx_t l2 = wxc(C_LN2);
        res = wx_add(&res, &l2);
    }
    return res;
}

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
            /* term_k = t^(2k+1)/(2k+1) alternating: ratio
             * (2k-1)/(2k+1) on t^2, sign flips each step */
            wx_t f = wxc(C_INV_K(2 * k + 1));
            wx_t num = wx_int((uint64_t)(2 * k - 1));
            term = wx_mul(&term, &t2);
            term = wx_mul(&term, &num);
            term = wx_mul(&term, &f);
            /* flip relative to the natural sign: the fold can hand the
             * series a NEGATIVE tn (t < 1/sqrt3), whose odd powers are
             * all negative already */
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

/* Cody-Waite reduction for pi/4 <= |a| < 2^63 (ea <= 62, ma bit63 set):
 * n = round(a*2/pi) via the 256-bit 2/pi fraction, then
 * r = a - n*(pi/2) EXACTLY on a 2^-319 grid (pi/2 kept to 320 bits), so
 * the reduction error is ~n*2^-320 <= 2^-257.  Outputs the remainder in
 * 2^-319 units (magnitude), its sign, and the octant n&3. */
static void reduce_pi2(uint64_t ma, int32_t ea, uint64_t ru[6], bool *rneg,
                       unsigned *oct)
{
    u2 P;
    uint64_t n, acc[8], au[6], npl[6];
    unsigned t, bits, limbs, b, i;
    bool guard, rest;

    /* a*2/pi = P * 2^(ea-126); P = top 128 bits of ma * (2/pi) */
    P = mul64(ma, C_2OPI[0]);
    t = (unsigned)(126 - ea); /* in [64, 128]: integer n = P >> t */
    n = u2_shr(P, t).lo;
    /* fraction bits of P below t: guard = bit (t-1), rest = below that */
    {
        unsigned g = t - 1u; /* in [63, 127] */
        if (g >= 64u) {
            guard = ((P.hi >> (g - 64u)) & 1u) != 0;
            if (g == 64u) {
                rest = P.lo != 0;
            } else {
                rest = ((P.hi & ((((uint64_t)1) << (g - 64u)) - 1)) != 0) ||
                       (P.lo != 0);
            }
        } else { /* g == 63: ea == 62 */
            guard = ((P.lo >> 63) & 1u) != 0;
            rest = (P.lo & 0x7FFFFFFFFFFFFFFFULL) != 0;
        }
    }
    if (guard && rest) n++; /* fraction > 1/2; an exact 1/2 tie keeps |r|<=pi/4 either way */

    /* npl = n * C_PI2_320 (320-bit pi/2 significand), 384-bit product.
     * C_PI2_320 is stored MSB limb first: limb i spans bits
     * 319-64i..256-64i, so it lands at the little-endian limb 4-i. */
    memset(acc, 0, sizeof acc);
    for (i = 0; i < 5; i++) {
        u2 p = mul64(n, C_PI2_320[i]);
        add_carry64(acc, 8u, 4 - i, p.lo);
        add_carry64(acc, 8u, 5 - i, p.hi);
    }
    for (i = 0; i < 6; i++) npl[i] = acc[i];

    /* au = ma << (ea + 256) : a in 2^-319 units (exact: a's ulp >= 2^-64
     * is coarser than the grid) */
    memset(au, 0, sizeof au);
    bits = (unsigned)(ea + 256); /* in [255, 318] */
    limbs = bits / 64u;
    b = bits % 64u;
    if (b == 0u) {
        au[limbs] = ma;
    } else {
        au[limbs] = ma << b;
        au[limbs + 1] = ma >> (64u - b);
    }

    /* r = au - npl on the 2^-319 grid */
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

/* sin(r)/cos(r) for |r| <= pi/4 + eps via Taylor (signed r) */
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

/* wx from the exact 2^-319-grid remainder (magnitude) */
static void wx_from_ru(const uint64_t ru[6], bool rneg, wx_t *w, bool *sticky)
{
    int k = 5, b;
    unsigned p, shift;
    u2 m;
    bool stick = false;

    while (k >= 0 && ru[k] == 0) k--;
    if (k < 0) { /* exact zero remainder */
        *w = wx_zero();
        w->sign = rneg;
        *sticky = false;
        return;
    }
    b = 63;
    while (!((ru[k] >> b) & 1u)) b--;
    p = (unsigned)(64 * k + b); /* top bit position */
    if (p >= 127) {
        shift = p - 127;
        /* m128 = top 128 bits of (ru >> shift): shifted limbs 1,0; the
         * shifted-out low bits (limbs 2..5) feed the sticky bit */
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
        w->e = (int32_t)p - 319 - 127; /* normalized-128 convention */
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

/* trig state after reduction of |a| */
typedef struct {
    wx_t sin_r, cos_r;    /* sin(r), cos(r), r signed */
    bool sin_sticky, cos_sticky;
    unsigned oct;
} tri_t;

/* |ax| positive finite, domain-checked (exp <= 62); DE by caller */
static void trig_reduce(const xf_t *ax, tri_t *tr)
{
    uint64_t ma;
    int32_t ea;
    wx_t r;

    tr->oct = 0;
    if (ax->exp <= -34) { /* |a| < 2^-33: sin = a exactly, cos = 1 */
        xf_norm_num(ax, &ma, &ea);
        tr->sin_r.m = u2_fr(0, ma);
        tr->sin_r.e = ea - 63;
        tr->sin_r.sign = false;
        u2_norm(&tr->sin_r.m, &tr->sin_r.e);
        tr->sin_sticky = false;
        tr->cos_r = wx_one();
        tr->cos_sticky = true; /* 1 - r^2/2 rounds to 1: inexact */
        return;
    }
    if (ax->exp < -2 || (ax->exp == -2 && ax->mant <= C_PI4_LIMIT)) {
        /* |a| < pi/4: no reduction */
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
        if (k < 0) { /* a is an exact multiple of pi/2 (grid-exact) */
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
        if (p_top < 286) { /* |r| < 2^-33: sin = r exactly, cos = 1 */
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

    *stack_fault = false; /* IS is the caller's detection; never faulted here */
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
    if (a.cls == X_INF) { /* SDM *-marked: #IA + indefinite */
        xf_out_indef(out);
        return X_IE;
    }
    if (a.cls == X_NUM && a.exp >= 63) {
        /* |a| >= 2^63: card protocol — out = a unchanged, IE set (caller
         * maps to C2=1); SDM hardware sets C2 without an exception. */
        memcpy(out, av, 10);
        return X_IE;
    }
    if (xf_is_den(&a)) flags |= X_DE;
    if (a.cls == X_ZERO) {
        if (want_cos) x87_80_one(out); /* cos(+-0) = +1 exact */
        else memcpy(out, av, 10);      /* sin(+-0) = +-0 exact */
        return flags;
    }

    {
        xf_t ax = a;
        ax.sign = false;
        trig_reduce(&ax, &tr);
    }
    /* octant mapping; the FINAL sign must reach round_pack80 so directed
     * roundings (RC 1/2) apply on the correct side */
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
    if (a.cls == X_NUM && a.exp >= 63) { /* domain: see fsin */
        memcpy(out_tan, av, 10);
        x87_80_one(out_one);
        return X_IE;
    }
    if (xf_is_den(&a)) flags |= X_DE;
    x87_80_one(out_one); /* the +1.0 push (not pushed on domain error) */
    if (a.cls == X_ZERO) {
        memcpy(out_tan, av, 10); /* tan(+-0) = +-0 exact */
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
    /* tan(n*pi/2 + r) from the true octant sin/cos values */
    tan_v = wx_div(&sin_v, &cos_v);
    flags |= round_pack80(&r, tan_v.sign ^ a.sign, tan_v.m, tan_v.e, true, 64u);
    xf_encode(&r, out_tan);
    return flags;
}

unsigned x87_80_fpatan(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10])
{
    xf_t x, y, r;
    unsigned flags = 0;

    xf_decode(av, &x); /* ST(0) = x (first parameter) */
    xf_decode(bv, &y); /* ST(1) = y; result = atan2(y, x) */
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

    /* SDM Table 3-30 (rows ST(1)=y, cols ST(0)=x) */
    {
        wx_t pi = wx_pi(), pi2 = wxc(C_PI2), pi4 = wxc(C_PI4);
        wx_t t3pi4 = wx_add(&pi2, &pi4); /* 3*pi/4 */
        bool y0 = y.cls == X_ZERO, x0 = x.cls == X_ZERO;
        bool yi = y.cls == X_INF, xi = x.cls == X_INF;

        if (yi && xi) {
            flags |= round_pack80(&r, y.sign, t3pi4.m, t3pi4.e, true, 64u);
            xf_encode(&r, out);
            return flags;
        }
        if (xi) {
            if (x.sign) { /* +-pi per sign(y) */
                flags |= round_pack80(&r, y.sign, pi.m, pi.e, true, 64u);
            } else { /* +-0 */
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
                if (x.sign) { /* (+0,-0) -> +pi ; (-0,-0) -> -pi */
                    flags |= round_pack80(&r, y.sign, pi.m, pi.e, true, 64u);
                    xf_encode(&r, out);
                } else {
                    xf_out_zero(out, y.sign);
                }
                return flags;
            }
            if (x0) { /* y nonzero finite: +-pi/2 sign(y) */
                flags |= round_pack80(&r, y.sign, pi2.m, pi2.e, true, 64u);
                xf_encode(&r, out);
                return flags;
            }
            /* y == 0: x<0 -> +-pi; x>0 -> +-0 */
            if (x.sign) {
                flags |= round_pack80(&r, y.sign, pi.m, pi.e, true, 64u);
                xf_encode(&r, out);
            } else {
                xf_out_zero(out, y.sign);
            }
            return flags;
        }
    }

    /* core: both finite nonzero */
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
            t = wx_div(&xw, &yw); /* |x|/|y| < 1 */
            R = wx_atan1(&t);
            {
                wx_t pi2 = wxc(C_PI2);
                R = wx_sub(&pi2, &R); /* pi/2 - atan(|x|/|y|) */
            }
        } else {
            t = wx_div(&yw, &xw); /* |y|/|x| <= 1 */
            R = wx_atan1(&t);
        }
        if (!x.sign) {
            res = R;
            res.sign = y.sign;
        } else {
            wx_t pi = wx_pi();
            res = wx_sub(&pi, &R); /* pi - R, sign via y.sign below */
            res.sign = res.sign ^ y.sign;
        }
        flags |= round_pack80(&r, res.sign, res.m, res.e, true, 64u);
        xf_encode(&r, out);
    }
    return flags;
}

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
        if (a.sign) { /* 2^-inf - 1 = -1 exactly */
            xf_out_sig(out, true, 0x8000000000000000ULL, -63);
            return 0;
        }
        memcpy(out, av, 10);
        return 0;
    }
    if (a.cls == X_ZERO) {
        memcpy(out, av, 10); /* 2^(+-0) - 1 = +-0 exact */
        return 0;
    }
    if (a.exp >= 63) { /* |a| >= 2^63: documented saturation */
        if (a.sign) {
            xf_out_sig(out, true, 0x8000000000000000ULL, -63); /* -1 */
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
        if (a.sign) n = -n; /* 2^a = 2^-n * 2^(-f) for a < 0 */
        if (n >= 16384) {
            /* 2^n * 2^f (f in [0,1)) exceeds the format maximum */
            xf_out_inf(out, false);
            return flags | X_OE | X_PE;
        }
        if (n <= -16446) {
            /* 2^n - 1 rounds to -1 (2^n is below half an ulp of 1) */
            xf_out_sig(out, true, 0x8000000000000000ULL, -63);
            return flags | X_PE;
        }
        /* f == 0 (a a power of two): 2^a - 1 is exact for |n| <= 64
         * (mantissa all representable) and the pipeline's single
         * rounding reports inexactness correctly otherwise. */
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
            v = wx_add(&one, &e); /* 1 + (2^f - 1) = 2^f */
            v.e += (int32_t)n;    /* * 2^n (mantissa unchanged) */
            res = wx_sub(&v, &one);
            flags |= round_pack80(&r, res.sign, res.m, res.e, !exact, 64u);
            xf_encode(&r, out);
        }
    }
    return flags;
}

/* log2(mantissa in [1,2)) as wx (integer exponent added by the caller) */
static wx_t wx_log2(uint64_t ma)
{
    wx_t m, ln, l2e;
    m.m = u2_fr(0, ma);
    m.e = -63;
    m.sign = false;
    u2_norm(&m.m, &m.e); /* m in [1,2) at e = -127 */
    ln = wx_ln_m(m);
    l2e = wxc(C_LOG2E);
    return wx_mul(&ln, &l2e);
}

unsigned x87_80_fyl2x(uint8_t out[10], const uint8_t av[10], const uint8_t bv[10])
{
    xf_t a, b, r;
    unsigned flags = 0;

    xf_decode(av, &a); /* ST(0): log2 argument */
    xf_decode(bv, &b); /* ST(1): multiplier */
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

    /* SDM Table 3-21 (cols ST(0)=a, rows ST(1)=b) */
    if (a.cls == X_INF) {
        if (b.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
        if (b.cls == X_INF) { xf_out_inf(out, b.sign); return 0; }
        xf_out_inf(out, b.sign); /* log2(+inf) = +inf; b * +inf */
        return 0;
    }
    if (a.cls == X_ZERO) { /* log2(+-0) = -inf */
        if (b.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
        if (b.cls == X_INF) { xf_out_inf(out, !b.sign); return 0; }
        flags |= X_ZE; /* finite nonzero b */
        xf_out_inf(out, !b.sign);
        return flags;
    }
    if (a.sign) { /* negative finite log argument */
        xf_out_indef(out);
        return X_IE;
    }
    if (a.cls == X_NUM && !a.den_enc && a.exp == 0 &&
        a.mant == 0x8000000000000000ULL) {
        /* a == 1: log2(1) = +0 exactly; b * 0 = +-0 sign(b) */
        if (b.cls == X_INF) { xf_out_indef(out); return X_IE; }
        xf_out_zero(out, b.sign);
        return 0;
    }
    if (b.cls == X_INF) {
        /* log2(a) sign picks the infinity's sign (a != 1 here:
         * a in (0,1) -> negative, a > 1 -> positive) */
        bool lneg = a.exp < 0 || (a.exp == 0 && a.mant < 0x8000000000000000ULL);
        xf_out_inf(out, b.sign ^ lneg);
        return 0;
    }
    if (b.cls == X_ZERO) { /* 0 * log2(a), log2(a) != 0: exact +-0 sign(b) */
        xf_out_zero(out, b.sign);
        return 0;
    }
    if (a.cls == X_NUM && !a.den_enc && a.mant == 0x8000000000000000ULL) {
        /* a = 2^a.exp exactly: log2(a) = a.exp (an integer), so the
         * product b * a.exp goes through the exact integer pipeline —
         * PE only if the product genuinely needs rounding. */
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
        /* L = log2(a) ~ ea + log2(ma) */
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

    xf_decode(av, &a); /* ST(0): the epsilon */
    xf_decode(bv, &b); /* ST(1): multiplier */
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

    if (a.cls == X_ZERO) { /* log2(1) = +0 */
        if (b.cls == X_INF) { xf_out_indef(out); return X_IE; }
        xf_out_zero(out, b.sign);
        return 0;
    }
    if (a.cls == X_INF) {
        if (!a.sign) { /* 1+a = +inf: log2 = +inf; b * +inf */
            if (b.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
            xf_out_inf(out, b.sign); /* sign(b): +inf*+ or -inf*- */
            return 0;
        }
        /* a = -inf: log2 of -inf is invalid (documented choice) */
        xf_out_indef(out);
        return X_IE;
    }
    if (a.sign && a.cls == X_NUM) {
        /* a < 0: valid while 1+a > 0; a == -1 -> log2(0) = -inf;
         * a < -1 -> invalid */
        if (a.exp > 0 || (a.exp == 0 && a.mant > 0x8000000000000000ULL)) {
            xf_out_indef(out);
            return X_IE;
        }
        if (a.exp == 0 && a.mant == 0x8000000000000000ULL) { /* a == -1 */
            if (b.cls == X_ZERO) { xf_out_indef(out); return X_IE; }
            if (b.cls == X_INF) { xf_out_inf(out, !b.sign); return 0; }
            /* FYL2XP1 has no #Z: deliver -inf * b without ZE */
            xf_out_inf(out, !b.sign);
            return 0;
        }
    }
    if (b.cls == X_INF) {
        /* sign of log2(1+a): a > 0 -> +, -1 < a < 0 -> - */
        xf_out_inf(out, b.sign ^ a.sign);
        return 0;
    }
    if (a.cls == X_NUM && !a.den_enc) {
        /* 1 + a exactly a power of two: log2(1+a) is an integer.
         * Pattern: a.mant is a run of k leading ones over zeros with
         * a.exp == -1 (a < 0: a = -(1 - 2^-k), 1+a = 2^-k) or
         * a.exp == k-1 (a > 0: a = 2^k - 1, 1+a = 2^k). */
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
        /* log2(1+a): |a| <= 0.5 uses ln(1+a) = 2*atanh(a/(2+a)) with
         * |z| <= 1/3; a in [-1, -0.5] decomposes 1+a EXACTLY (1+a has
         * at most 64 significant bits there) and takes the fyl2x ln_m
         * path — the atanh z would approach -1 and diverge; a >= 2
         * falls back to ln_m on the rounded 1+a (documented). */
        wx_t aw, z, den, ln, l2e, res;
        uint64_t ma;
        int32_t ea;

        xf_norm_num(&a, &ma, &ea);
        aw.m = u2_fr(0, ma);
        aw.e = ea - 63;
        aw.sign = a.sign;
        u2_norm(&aw.m, &aw.e);

        if (ea >= 1 || (a.sign && ea >= -1)) {
            /* 1+a is exact for a in [-1, -0.5] and rounded-only for
             * a >= 2; either way ln_m on its significand is the path */
            uint8_t one80[10], sum80[10];
            xf_t s;
            unsigned pc_saved = g_pc;
            g_pc = 64u;
            x87_80_one(one80);
            x87_80_add(sum80, av, one80);
            g_pc = pc_saved;
            xf_decode(sum80, &s);
            if (s.cls != X_NUM) { /* 1+a overflowed to +inf */
                xf_out_inf(out, false);
                return X_OE | X_PE;
            }
            xf_norm_num(&s, &ma, &ea);
            ln = wx_log2(ma); /* log2 of the (exact for a<=-0.5) 1+a
                               * significand */
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
            /* |a| <= 0.5 here: z = a/(2+a) has |z| <= 1/3 and the
             * 44-term atanh series (divisors through 89) reaches
             * ~2^-140 relative error */
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
                    /* atanh series: ratio (2k-1)/(2k+1) on z^2 */
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
        } else { /* NaN: payload preserved, quiet/signaling kept (FLD) */
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
        xf_out_sig(out, sign, frac, -149); /* value = frac * 2^-149 */
        return X_DE; /* FLD m32 of a denormal signals #D */
    }
    xf_out_sig(out, sign, 0x8000000000000000ULL | ((uint64_t)frac << 40),
               (int32_t)be - 127 - 63);
    /* value = (2^23|frac) * 2^(be-127-23) = mant * 2^(be-127-63) */
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
            f.cls = (frac >> 51) ? X_QNAN : X_SNAN; /* payload preserved */
            f.sign = sign;
            f.mant = 0x8000000000000000ULL | (frac << 11);
            xf_encode(&f, out);
        }
        return 0;
    }
    if (be == 0) {
        if (frac == 0) { xf_out_zero(out, sign); return 0; }
        xf_out_sig(out, sign, frac, -1074); /* value = frac * 2^-1074 */
        return X_DE; /* FLD m64 of a denormal signals #D */
    }
    xf_out_sig(out, sign, 0x8000000000000000ULL | (frac << 11),
               (int32_t)be - 1023 - 63);
    /* value = (2^52|frac) * 2^(be-1023-52) = mant * 2^(be-1023-63) */
    return 0;
}

/* integer conversion core; limit = 2^(bits-1) (the magnitude of the
 * negative limit).  Returns flags; *ival = |rounded value|; *valid false
 * means invalid (NaN/inf/unsupported/out of range -> integer indefinite). */
static unsigned to_int_core(const xf_t *f, uint64_t limit, uint64_t *ival,
                            bool *valid)
{
    uint64_t m, q;
    int32_t e;
    unsigned flags = 0;
    bool inexact = false;

    *valid = true;
    if (f->unsup || xf_is_nan_cls(f) || f->cls == X_INF) {
        *ival = limit; /* integer indefinite */
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
        /* |v| < 1/2: rounds to 0 (or +-1 toward the RC direction) */
        bool up = (g_rc == 2u && !f->sign) || (g_rc == 1u && f->sign);
        *ival = up ? 1u : 0u;
        return flags | X_PE;
    }
    if (e <= 63) {
        unsigned k = (unsigned)(63 - e); /* fractional bits, 0..63 */
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
        *out = -2147483647 - 1; /* integer indefinite */
        return flags;
    }
    if (q == 0x80000000ULL) *out = -2147483647 - 1; /* only -2^31 fits */
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

/* IEEE double/single store rounding (x87 FSTP m64/m32 semantics: RC
 * honoured, PC ignored, subnormal/overflow per the target format).
 * bias/fracbits/inf_bits/max_bits parameterize binary64 vs binary32. */
static unsigned to_ieee_bits(const xf_t *f, unsigned p, int emax, int emin,
                             int bias, int fracbits, uint64_t inf_bits,
                             uint64_t max_bits, uint64_t *bits)
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
        int32_t exp = e; /* true exponent of the top bit: m128 bit127 == 2^e */
        tiny = exp < emin;
        shift = tiny ? (emin - exp) : 0;
        eff = (int)p - shift; /* IEEE: the subnormal field shrinks directly */
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
            if (f->sign) *bits |= 0x8000000000000000ULL;
            return flags;
        }
        if (exp >= emin) {
            uint64_t expf = (uint64_t)(exp + bias) << fracbits;
            *bits = expf | (sig - (((uint64_t)1) << (int)(p - 1)));
        } else {
            /* subnormal: frac = value * 2^(fracbits-emin) */
            int64_t sh = (int64_t)exp - eff + 1 + (int64_t)(fracbits - emin);
            uint64_t frac = sh >= 64 ? 0 : (sig << sh);
            *bits = frac;
        }
        if (f->sign) *bits |= 0x8000000000000000ULL;
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
        /* FSTP m64 of an SNaN signals IE and stores the quieted NaN;
         * the payload keeps its top 52 fraction bits */
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
                         0x7FF0000000000000ULL, 0x7FEFFFFFFFFFFFFFULL, &bits);
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
                         0x7F800000ULL, 0x7F7FFFFFULL, &bits);
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
