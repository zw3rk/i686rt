/*
 * src/interp/h_sse.c — SSE/SSE2 floating-point interpreter handlers (lane L5b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "interp/h_sse_internal.h"

/* ------------------------------------------------------------------ */
/* Frozen sse.h helpers                                                */
/* ------------------------------------------------------------------ */

void sse_set_xmm(i686_ctx_t *ctx, unsigned reg, const uint8_t v[16])
{
    if (reg < 8U) {
        memcpy(ctx->xmm[reg], v, 16);
    }
}

void sse_get_xmm(const i686_ctx_t *ctx, unsigned reg, uint8_t out[16])
{
    if (reg < 8U) {
        memcpy(out, ctx->xmm[reg], 16);
    } else {
        memset(out, 0, 16);
    }
}

uint32_t sse_get_mxcsr(const i686_ctx_t *ctx)
{
    return ctx->mxcsr & MXCSR_DEFINED;
}

void sse_set_mxcsr(i686_ctx_t *ctx, uint32_t v)
{
    ctx->mxcsr = v & MXCSR_DEFINED;
    if (ctx->mxcsr_mask == 0U) {
        ctx->mxcsr_mask = 0xFFFFu;
    }
}

unsigned sse_round_mode(const i686_ctx_t *ctx)
{
    return (ctx->mxcsr >> 13) & 3U; /* 0=nearest,1=down,2=up,3=zero */
}

bool sse_ftz(const i686_ctx_t *ctx)
{
    return (ctx->mxcsr & MXCSR_FTZ) != 0U;
}

bool sse_daz(const i686_ctx_t *ctx)
{
    return (ctx->mxcsr & MXCSR_DAZ) != 0U;
}

/* ------------------------------------------------------------------ */
/* double -> float32 under MXCSR RC/FTZ + flags                        */
/* ------------------------------------------------------------------ */

static uint32_t sse_round_f64_to_f32(i686_ctx_t *ctx, double d)
{
    float f;
    uint32_t fb;
    uint64_t db = f64_bits(d);
    unsigned rc = sse_round_mode(ctx);
    unsigned mag;

    if (f64_nan(db)) {
        return F32_QNAN_INDEF;
    }
    if ((db & 0x7FFFFFFFFFFFFFFFull) == 0x7FF0000000000000ull) {
        return (db >> 63) != 0U ? F32_NEG_INF : F32_POS_INF;
    }

    f = (float)d;
    /* I686-R5-1: (float)d rounds to nearest-even, which may already lie
     * on the desired side of the exact value d. Step only when the
     * nearest result is on the wrong side of d. */
    if ((double)f != d && rc != 0U) {
        if (rc == 1U) {
            if ((double)f > d) {
                f = nextafterf(f, -INFINITY);
            }
        } else if (rc == 2U) {
            if ((double)f < d) {
                f = nextafterf(f, INFINITY);
            }
        } else {
            if (fabs((double)f) > fabs(d)) {
                f = nextafterf(f, 0.0f);
            }
        }
    }
    fb = f32_bits(f);
    mag = fb & 0x7FFFFFFFu;

    if (mag >= 0x7F800000u) {
        ctx->mxcsr |= MXCSR_OE | MXCSR_PE;
        if (rc == 0U || (rc == 2U && d > 0.0) || (rc == 1U && d < 0.0)) {
            return (d < 0.0) ? F32_NEG_INF : F32_POS_INF;
        }
        return (d < 0.0) ? (F32_MAX_BITS | 0x80000000u) : F32_MAX_BITS;
    }

    if (mag < 0x00800000u) {
        if ((db & 0x7FFFFFFFFFFFFFFFull) == 0U) {
            return fb;
        }
        if (sse_ftz(ctx)) {
            ctx->mxcsr |= MXCSR_UE | MXCSR_PE;
            return fb & 0x80000000u;
        }
        if ((double)f32_from(fb) != d) {
            ctx->mxcsr |= MXCSR_UE | MXCSR_PE;
        }
        return fb;
    }

    if ((double)f32_from(fb) != d) {
        ctx->mxcsr |= MXCSR_PE;
    }
    return fb;
}

/* ------------------------------------------------------------------ */
/* Scalar arithmetic engines                                           */
/* ------------------------------------------------------------------ */

typedef enum { FOP_ADD = 0, FOP_SUB, FOP_MUL, FOP_DIV } fop_kind;

static int f32_same_inf_sign(uint32_t a, uint32_t b)
{
    return f32_inf(a) && f32_inf(b) && ((a ^ b) & 0x80000000u) == 0U;
}

static uint32_t sse_f32_op(i686_ctx_t *ctx, uint32_t a, uint32_t b, fop_kind k)
{
    double da, db, dr = 0.0;

    a = sse_f32_src(ctx, a);
    b = sse_f32_src(ctx, b);

    if (f32_nan(a) || f32_nan(b)) {
        uint32_t pick = f32_nan(a) ? a : b;
        if (f32_snan(a) || f32_snan(b)) {
            ctx->mxcsr |= MXCSR_IE;
        }
        return f32_quiet(pick);
    }

    da = (double)f32_from(a);
    db = (double)f32_from(b);

    if (k == FOP_DIV && db == 0.0) {
        if (da == 0.0) {
            ctx->mxcsr |= MXCSR_IE;
            return F32_QNAN_INDEF;
        }
        ctx->mxcsr |= MXCSR_ZE;
        return (((a ^ b) & 0x80000000u)) | F32_POS_INF;
    }
    if ((k == FOP_DIV && f32_inf(a) && f32_inf(b)) ||
        (k == FOP_MUL && ((f32_inf(a) && db == 0.0) || (da == 0.0 && f32_inf(b)))) ||
        (k == FOP_ADD && f32_inf(a) && f32_inf(b) && ((a ^ b) & 0x80000000u) != 0U) ||
        (k == FOP_SUB && f32_same_inf_sign(a, b))) {
        ctx->mxcsr |= MXCSR_IE;
        return F32_QNAN_INDEF;
    }

    switch (k) {
    case FOP_ADD: dr = da + db; break;
    case FOP_SUB: dr = da - db; break;
    case FOP_MUL: dr = da * db; break;
    case FOP_DIV: dr = da / db; break;
    default: break;
    }
    return sse_round_f64_to_f32(ctx, dr);
}

static int f64_same_inf_sign(uint64_t a, uint64_t b)
{
    return ((a & 0x7FF0000000000000ull) == 0x7FF0000000000000ull &&
            (b & 0x7FF0000000000000ull) == 0x7FF0000000000000ull &&
            (a & 0xFFFFFFFFFFFFFull) == 0U && (b & 0xFFFFFFFFFFFFFull) == 0U &&
            ((a ^ b) & 0x8000000000000000ull) == 0U);
}

static int f64_inf_bits(uint64_t b)
{
    return (b & 0x7FFFFFFFFFFFFFFFull) == 0x7FF0000000000000ull;
}

static uint64_t sse_f64_op(i686_ctx_t *ctx, uint64_t a, uint64_t b, fop_kind k)
{
    double da, db, r = 0.0;
    int flg;

    a = sse_f64_src(ctx, a);
    b = sse_f64_src(ctx, b);

    if (f64_nan(a) || f64_nan(b)) {
        uint64_t pick = f64_nan(a) ? a : b;
        if (f64_snan(a) || f64_snan(b)) {
            ctx->mxcsr |= MXCSR_IE;
        }
        return f64_quiet(pick);
    }

    da = f64_from(a);
    db = f64_from(b);

    if (k == FOP_DIV && db == 0.0) {
        if (da == 0.0) {
            ctx->mxcsr |= MXCSR_IE;
            return F64_QNAN_INDEF;
        }
        ctx->mxcsr |= MXCSR_ZE;
        return ((a ^ b) & 0x8000000000000000ull) | F64_POS_INF;
    }
    if ((k == FOP_DIV && f64_inf_bits(a) && f64_inf_bits(b)) ||
        (k == FOP_MUL && ((f64_inf_bits(a) && db == 0.0) ||
                          (da == 0.0 && f64_inf_bits(b)))) ||
        (k == FOP_ADD && f64_inf_bits(a) && f64_inf_bits(b) &&
         ((a ^ b) & 0x8000000000000000ull) != 0U) ||
        (k == FOP_SUB && f64_same_inf_sign(a, b))) {
        ctx->mxcsr |= MXCSR_IE;
        return F64_QNAN_INDEF;
    }

    /* Host double op under guest MXCSR rounding mode (I686-9). */
    {
        unsigned rc = sse_round_mode(ctx);
        int saved_rm = fegetround();
        int host_rm = FE_TONEAREST;
        volatile double vda = da;
        volatile double vdb = db;
        volatile double vr = 0.0;
        switch (rc) {
        case 1U: host_rm = FE_DOWNWARD; break;
        case 2U: host_rm = FE_UPWARD; break;
        case 3U: host_rm = FE_TOWARDZERO; break;
        default: host_rm = FE_TONEAREST; break;
        }
        if (host_rm != saved_rm) {
            (void)fesetround(host_rm);
        }
        (void)feclearexcept(FE_ALL_EXCEPT);
        switch (k) {
        case FOP_ADD: vr = vda + vdb; break;
        case FOP_SUB: vr = vda - vdb; break;
        case FOP_MUL: vr = vda * vdb; break;
        case FOP_DIV: vr = vda / vdb; break;
        default: break;
        }
        r = vr;
        flg = fetestexcept(FE_INEXACT | FE_OVERFLOW | FE_UNDERFLOW);
        if (host_rm != saved_rm) {
            (void)fesetround(saved_rm);
        }
        /* I686-R5-1: verify directed rounding against a higher-precision
         * long double exact value and step only when the host result is
         * on the wrong side (host rounding modes may be unavailable or
         * coarse on some platforms). */
        if (rc != 0U && !isnan(r) && !isinf(r)) {
            long double exact = 0.0L;
            long double rr = (long double)r;
            double stepped = r;
            bool has_exact = true;
            switch (k) {
            case FOP_ADD: exact = (long double)da + (long double)db; break;
            case FOP_SUB: exact = (long double)da - (long double)db; break;
            case FOP_MUL: exact = (long double)da * (long double)db; break;
            case FOP_DIV:
                if (db != 0.0) {
                    exact = (long double)da / (long double)db;
                }
                break;
            default: has_exact = false; break;
            }
            if (has_exact && rr != exact) {
                if (rc == 1U && rr > exact) {
                    stepped = nextafter(r, -INFINITY);
                } else if (rc == 2U && rr < exact) {
                    stepped = nextafter(r, INFINITY);
                } else if (rc == 3U && fabsl(rr) > fabsl(exact)) {
                    stepped = nextafter(r, 0.0);
                }
            }
            if (stepped != r) {
                r = stepped;
                flg |= FE_INEXACT;
                if (isinf(r)) {
                    flg |= FE_OVERFLOW;
                }
            }
        }
    }
    if ((flg & FE_INEXACT) != 0) {
        ctx->mxcsr |= MXCSR_PE;
    }
    if ((flg & FE_OVERFLOW) != 0) {
        ctx->mxcsr |= MXCSR_OE;
    }
    if ((flg & FE_UNDERFLOW) != 0) {
        ctx->mxcsr |= MXCSR_UE;
        if (sse_ftz(ctx)) {
            return f64_bits(r) & 0x8000000000000000ull; /* signed zero */
        }
    }
    return f64_bits(r);
}

/* ------------------------------------------------------------------ */
/* Float -> int32 conversions                                          */
/* ------------------------------------------------------------------ */

static uint32_t sse_cvtt_f2i(i686_ctx_t *ctx, double d)
{
    int32_t t;

    if (!(d >= -2147483648.0 && d < 2147483648.0)) {
        ctx->mxcsr |= MXCSR_IE;
        return 0x80000000u;
    }
    t = (int32_t)d;
    if ((double)t != d) {
        ctx->mxcsr |= MXCSR_PE;
    }
    return (uint32_t)t;
}

static uint32_t sse_cvt_f2i(i686_ctx_t *ctx, double d)
{
    double t;

    if (isnan(d) || d < -2147483648.0 || d > 2147483647.5) {
        ctx->mxcsr |= MXCSR_IE;
        return 0x80000000u;
    }

    switch (sse_round_mode(ctx)) {
    case 1U: t = floor(d); break;
    case 2U: t = ceil(d); break;
    case 3U: t = trunc(d); break;
    default: {
        double tr = trunc(d);
        double frac = d - tr;
        t = tr;
        if (frac > 0.5) {
            t += 1.0;
        } else if (frac < -0.5) {
            t -= 1.0;
        } else if (frac == 0.5 && ((int64_t)tr & 1) != 0) {
            t += 1.0;
        } else if (frac == -0.5 && ((int64_t)tr & 1) != 0) {
            t -= 1.0;
        }
        break;
    }
    }

    if (!(t >= -2147483648.0 && t < 2147483648.0)) {
        ctx->mxcsr |= MXCSR_IE;
        return 0x80000000u;
    }
    if (t != d) {
        ctx->mxcsr |= MXCSR_PE;
    }
    return (uint32_t)(int32_t)t;
}

/* ------------------------------------------------------------------ */
/* Data movement                                                       */
/* ------------------------------------------------------------------ */

static int h_movups(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned size = (insn->pfx_rep == 1U) ? 4U : (insn->pfx_rep == 2U) ? 8U : 16U;
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t buf[16];

    if (load) {
        uint8_t dst[16];
        sse_get_xmm(ctx, insn->modrm_reg, dst);
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            memcpy(dst, src, size);
        } else {
            /* R7-34: legacy scalar memory loads (MOVSS/MOVSD)
             * zero the upper lanes; preservation applies only
             * to register-source forms. */
            if (size != 16U) {
                memset(dst, 0, sizeof dst);
            }
            sse_ld(ctx, insn, dst, size);
        }
        sse_set_xmm(ctx, insn->modrm_reg, dst);
    } else {
        sse_get_xmm(ctx, insn->modrm_reg, buf);
        if (insn->modrm_mod == 3U) {
            uint8_t dst[16];
            sse_get_xmm(ctx, insn->modrm_rm, dst);
            memcpy(dst, buf, size);
            sse_set_xmm(ctx, insn->modrm_rm, dst);
        } else {
            sse_st(ctx, insn, buf, size);
        }
    }
    return sse_done(ctx, insn);
}

static int h_movaps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t buf[16];

    /* R7-43: MOVAPS/MOVAPD fault #GP(0) on misaligned memory
     * operands before any side effect. */
    sse_align16(ctx, insn);
    if (load) {
        src128(ctx, insn, buf);
        sse_set_xmm(ctx, insn->modrm_reg, buf);
    } else {
        sse_get_xmm(ctx, insn->modrm_reg, buf);
        if (insn->modrm_mod == 3U) {
            sse_set_xmm(ctx, insn->modrm_rm, buf);
        } else {
            sse_st(ctx, insn, buf, 16);
        }
    }
    return sse_done(ctx, insn);
}

static int h_movlps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t dst[16], src[16];

    if (load) {
        sse_get_xmm(ctx, insn->modrm_reg, dst);
        if (insn->modrm_mod == 3U) {
            if (insn->pfx_66 != 0U) {
                return I686_EXIT_UNDEF;
            }
            sse_get_xmm(ctx, insn->modrm_rm, src);
            memcpy(dst, src + 8, 8);
        } else {
            sse_ld(ctx, insn, dst, 8);
        }
        sse_set_xmm(ctx, insn->modrm_reg, dst);
    } else {
        sse_get_xmm(ctx, insn->modrm_reg, src);
        sse_st(ctx, insn, src, 8);
    }
    return sse_done(ctx, insn);
}

static int h_movhps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t dst[16], src[16];

    if (load) {
        sse_get_xmm(ctx, insn->modrm_reg, dst);
        if (insn->modrm_mod == 3U) {
            if (insn->pfx_66 != 0U) {
                return I686_EXIT_UNDEF;
            }
            sse_get_xmm(ctx, insn->modrm_rm, src);
            memcpy(dst + 8, src, 8);
        } else {
            uint8_t m[8];
            sse_ld(ctx, insn, m, 8);
            memcpy(dst + 8, m, 8);
        }
        sse_set_xmm(ctx, insn->modrm_reg, dst);
    } else {
        sse_get_xmm(ctx, insn->modrm_reg, src);
        sse_st(ctx, insn, src + 8, 8);
    }
    return sse_done(ctx, insn);
}

static int h_movq_xmm(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->opnd[0] == I686_OPND_R32) {
        uint32_t v;
        if (insn->modrm_mod == 3U) {
            v = ctx->gpr[insn->modrm_rm & 7U];
        } else {
            sse_ld(ctx, insn, &v, 4);
        }
        if (insn->pfx_66 != 0U) {
            uint8_t x[16];
            memset(x, 0, sizeof x);
            memcpy(x, &v, 4);
            sse_set_xmm(ctx, insn->modrm_reg, x);
        } else {
            mm_wr(ctx, insn->modrm_reg, (uint64_t)v);
        }
    } else if (insn->pfx_rep == 1U) {
        uint8_t dst[16];
        uint64_t v;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            memcpy(&v, src, 8);
        } else {
            sse_ld(ctx, insn, &v, 8);
        }
        memset(dst, 0, sizeof dst);
        memcpy(dst, &v, 8);
        sse_set_xmm(ctx, insn->modrm_reg, dst);
    } else {
        uint32_t v;
        if (insn->pfx_66 != 0U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_reg, src);
            memcpy(&v, src, 4);
        } else {
            uint64_t m = mm_rd(ctx, insn->modrm_reg);
            v = (uint32_t)m;
        }
        if (insn->modrm_mod == 3U) {
            ctx->gpr[insn->modrm_rm & 7U] = v;
        } else {
            sse_st(ctx, insn, &v, 4);
        }
    }
    return sse_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Packed/scalar arithmetic                                            */
/* ------------------------------------------------------------------ */

static int h_arith(i686_ctx_t *ctx, const x86_insn_t *insn, fop_kind k)
{
    uint8_t dst[16];

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->pfx_rep == 1U) {
        uint32_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane32(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 4);
        }
        set_lane32(dst, 0, sse_f32_op(ctx, lane32(dst, 0), s, k));
    } else if (insn->pfx_rep == 2U) {
        uint64_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane64(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 8);
        }
        set_lane64(dst, 0, sse_f64_op(ctx, lane64(dst, 0), s, k));
    } else if (insn->pfx_66 != 0U) {
        uint8_t src[16];
        src128(ctx, insn, src);
        set_lane64(dst, 0, sse_f64_op(ctx, lane64(dst, 0), lane64(src, 0), k));
        set_lane64(dst, 1, sse_f64_op(ctx, lane64(dst, 1), lane64(src, 1), k));
    } else {
        uint8_t src[16];
        unsigned i;
        src128(ctx, insn, src);
        for (i = 0U; i < 4U; i++) {
            set_lane32(dst, i, sse_f32_op(ctx, lane32(dst, i), lane32(src, i), k));
        }
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

static int h_addps(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_arith(ctx, insn, FOP_ADD); }
static int h_subps(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_arith(ctx, insn, FOP_SUB); }
static int h_mulps(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_arith(ctx, insn, FOP_MUL); }
static int h_divps(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_arith(ctx, insn, FOP_DIV); }

/* ------------------------------------------------------------------ */
/* Bitwise logic                                                       */
/* ------------------------------------------------------------------ */

typedef enum { LOG_AND = 0, LOG_ANDN, LOG_OR, LOG_XOR } log_kind;

static void log_apply(uint8_t *d, const uint8_t *s, unsigned n, log_kind k)
{
    unsigned i;
    for (i = 0U; i < n; i++) {
        switch (k) {
        case LOG_AND: d[i] &= s[i]; break;
        case LOG_ANDN: d[i] = (uint8_t)(~d[i] & s[i]); break;
        case LOG_OR: d[i] |= s[i]; break;
        default: d[i] ^= s[i]; break;
        }
    }
}

static int h_logic(i686_ctx_t *ctx, const x86_insn_t *insn, log_kind k)
{
    uint8_t dst[16], src[16];
    sse_get_xmm(ctx, insn->modrm_reg, dst);
    src128(ctx, insn, src);
    log_apply(dst, src, 16, k);
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

static int h_andps(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_logic(ctx, insn, LOG_AND); }
static int h_andnps(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_logic(ctx, insn, LOG_ANDN); }
static int h_orps(i686_ctx_t *ctx, const x86_insn_t *insn)   { return h_logic(ctx, insn, LOG_OR); }
static int h_xorps(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_logic(ctx, insn, LOG_XOR); }

static int h_plogic(i686_ctx_t *ctx, const x86_insn_t *insn, log_kind k)
{
    if (insn->pfx_66 != 0U) {
        return h_logic(ctx, insn, k);
    }
    {
        uint64_t d = mm_rd(ctx, insn->modrm_reg);
        uint64_t s;
        if (insn->modrm_mod == 3U) {
            s = mm_rd(ctx, insn->modrm_rm);
        } else {
            sse_ld(ctx, insn, &s, 8);
        }
        switch (k) {
        case LOG_AND: d &= s; break;
        case LOG_ANDN: d = ~d & s; break;
        case LOG_OR: d |= s; break;
        default: d ^= s; break;
        }
        mm_wr(ctx, insn->modrm_reg, d);
    }
    return sse_done(ctx, insn);
}

static int h_pand(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_plogic(ctx, insn, LOG_AND); }
static int h_pandn(i686_ctx_t *ctx, const x86_insn_t *insn) { return h_plogic(ctx, insn, LOG_ANDN); }
static int h_por(i686_ctx_t *ctx, const x86_insn_t *insn)   { return h_plogic(ctx, insn, LOG_OR); }
static int h_pxor(i686_ctx_t *ctx, const x86_insn_t *insn)  { return h_plogic(ctx, insn, LOG_XOR); }

/* ------------------------------------------------------------------ */
/* Conversions                                                         */
/* ------------------------------------------------------------------ */

static int h_cvtpi2ps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t dst[16];
    uint32_t w0, w1;

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->pfx_rep != 0U) {
        int32_t s32;
        if (insn->modrm_mod == 3U) {
            s32 = (int32_t)ctx->gpr[insn->modrm_rm & 7U];
        } else {
            sse_ld(ctx, insn, &s32, 4);
        }
        if (insn->pfx_rep == 1U) {
            set_lane32(dst, 0, sse_round_f64_to_f32(ctx, (double)s32));
        } else {
            double d = (double)s32;
            set_lane64(dst, 0, f64_bits(d));
        }
    } else {
        uint64_t s;
        if (insn->modrm_mod == 3U) {
            s = mm_rd(ctx, insn->modrm_rm);
        } else {
            sse_ld(ctx, insn, &s, 8);
        }
        w0 = (uint32_t)s;
        w1 = (uint32_t)(s >> 32);
        if (insn->pfx_66 != 0U) {
            set_lane64(dst, 0, f64_bits((double)(int32_t)w0));
            set_lane64(dst, 1, f64_bits((double)(int32_t)w1));
        } else {
            set_lane32(dst, 0, sse_round_f64_to_f32(ctx, (double)(int32_t)w0));
            set_lane32(dst, 1, sse_round_f64_to_f32(ctx, (double)(int32_t)w1));
        }
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

static int h_cvttps2pi(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->pfx_rep != 0U) {
        uint32_t r;
        if (insn->pfx_rep == 1U) {
            uint32_t s;
            if (insn->modrm_mod == 3U) {
                uint8_t src[16];
                sse_get_xmm(ctx, insn->modrm_rm, src);
                s = lane32(src, 0);
            } else {
                sse_ld(ctx, insn, &s, 4);
            }
            r = sse_cvtt_f2i(ctx, (double)f32_from(sse_f32_src(ctx, s)));
        } else {
            uint64_t s;
            if (insn->modrm_mod == 3U) {
                uint8_t src[16];
                sse_get_xmm(ctx, insn->modrm_rm, src);
                s = lane64(src, 0);
            } else {
                sse_ld(ctx, insn, &s, 8);
            }
            r = sse_cvtt_f2i(ctx, f64_from(sse_f64_src(ctx, s)));
        }
        ctx->gpr[insn->modrm_reg & 7U] = r;
        return sse_done(ctx, insn);
    }
    {
        uint64_t out = 0U;
        if (insn->pfx_66 != 0U) {
            uint8_t src[16];
            src128(ctx, insn, src);
            out = (uint64_t)sse_cvtt_f2i(ctx, f64_from(sse_f64_src(ctx, lane64(src, 0)))) |
                  ((uint64_t)sse_cvtt_f2i(ctx, f64_from(sse_f64_src(ctx, lane64(src, 1)))) << 32);
        } else {
            uint8_t src[8];
            uint32_t s0, s1;
            if (insn->modrm_mod == 3U) {
                uint8_t v[16];
                sse_get_xmm(ctx, insn->modrm_rm, v);
                memcpy(src, v, 8);
            } else {
                sse_ld(ctx, insn, src, 8);
            }
            memcpy(&s0, src, 4);
            memcpy(&s1, src + 4, 4);
            out = (uint64_t)sse_cvtt_f2i(ctx, (double)f32_from(sse_f32_src(ctx, s0))) |
                  ((uint64_t)sse_cvtt_f2i(ctx, (double)f32_from(sse_f32_src(ctx, s1))) << 32);
        }
        mm_wr(ctx, insn->modrm_reg, out);
    }
    return sse_done(ctx, insn);
}

static int h_cvtps2pd(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t dst[16];

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->pfx_rep == 1U) {
        uint32_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane32(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 4);
        }
        set_lane64(dst, 0, f64_bits((double)f32_from(sse_f32_src(ctx, s))));
    } else if (insn->pfx_rep == 2U) {
        uint64_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane64(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 8);
        }
        set_lane32(dst, 0,
                   sse_round_f64_to_f32(ctx, f64_from(sse_f64_src(ctx, s))));
    } else if (insn->pfx_66 != 0U) {
        uint8_t src[16];
        src128(ctx, insn, src);
        set_lane32(dst, 0,
                   sse_round_f64_to_f32(ctx, f64_from(sse_f64_src(ctx, lane64(src, 0)))));
        set_lane32(dst, 1,
                   sse_round_f64_to_f32(ctx, f64_from(sse_f64_src(ctx, lane64(src, 1)))));
        set_lane32(dst, 2, 0U);
        set_lane32(dst, 3, 0U);
    } else {
        uint32_t s0, s1;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s0 = lane32(src, 0);
            s1 = lane32(src, 1);
        } else {
            uint8_t src[8];
            sse_ld(ctx, insn, src, 8);
            memcpy(&s0, src, 4);
            memcpy(&s1, src + 4, 4);
        }
        set_lane64(dst, 0, f64_bits((double)f32_from(sse_f32_src(ctx, s0))));
        set_lane64(dst, 1, f64_bits((double)f32_from(sse_f32_src(ctx, s1))));
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

static int h_cvtdq2ps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t dst[16], src[16];
    unsigned i;

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->modrm_mod == 3U) {
        sse_get_xmm(ctx, insn->modrm_rm, src);
    } else {
        sse_ld(ctx, insn, src, 16);
    }

    if (insn->pfx_66 != 0U) {
        for (i = 0U; i < 4U; i++) {
            uint32_t s = lane32(src, i);
            set_lane32(dst, i, sse_cvt_f2i(ctx, (double)f32_from(sse_f32_src(ctx, s))));
        }
    } else if (insn->pfx_rep == 1U) {
        for (i = 0U; i < 4U; i++) {
            uint32_t s = lane32(src, i);
            set_lane32(dst, i, sse_cvtt_f2i(ctx, (double)f32_from(sse_f32_src(ctx, s))));
        }
    } else {
        for (i = 0U; i < 4U; i++) {
            set_lane32(dst, i,
                       sse_round_f64_to_f32(ctx, (double)(int32_t)lane32(src, i)));
        }
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

void i686_interp_sse_init(void)
{
    i686_interp_register(I686_OP_MOVUPS, h_movups);
    i686_interp_register(I686_OP_MOVLPS, h_movlps);
    i686_interp_register(I686_OP_MOVHPS, h_movhps);
    i686_interp_register(I686_OP_MOVAPS, h_movaps);
    i686_interp_register(I686_OP_MOVQ_xmm, h_movq_xmm);
    i686_interp_register(I686_OP_CVTPI2PS, h_cvtpi2ps);
    i686_interp_register(I686_OP_CVTTPS2PI, h_cvttps2pi);
    i686_interp_register(I686_OP_CVTPS2PD, h_cvtps2pd);
    i686_interp_register(I686_OP_CVTDQ2PS, h_cvtdq2ps);
    i686_interp_register(I686_OP_ANDPS, h_andps);
    i686_interp_register(I686_OP_ANDNPS, h_andnps);
    i686_interp_register(I686_OP_ORPS, h_orps);
    i686_interp_register(I686_OP_XORPS, h_xorps);
    i686_interp_register(I686_OP_ADDPS, h_addps);
    i686_interp_register(I686_OP_MULPS, h_mulps);
    i686_interp_register(I686_OP_SUBPS, h_subps);
    i686_interp_register(I686_OP_DIVPS, h_divps);
    i686_interp_register(I686_OP_PAND, h_pand);
    i686_interp_register(I686_OP_PANDN, h_pandn);
    i686_interp_register(I686_OP_POR, h_por);
    i686_interp_register(I686_OP_PXOR, h_pxor);
    i686_interp_sse_int_init();
}
