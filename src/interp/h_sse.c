/*
 * src/interp/h_sse.c — SSE/SSE2/MMX interpreter handlers (lane L5b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Registers handlers for the Phase 5 shared SSE/MMX opcode rows
 * (docs/lanes/phase-5.md).  One id per 0F opcode byte: the mandatory
 * prefixes select the family member here — 66 rides insn->pfx_opsize,
 * F2 (pfx_rep==2) and F3 (pfx_rep==1) ride insn->pfx_rep.  This file
 * also implements the frozen src/interp/sse.h helpers.
 *
 * MXCSR decisions (documented per card):
 *  - Defined bits are 0xFFFF (bits 0..15; DAZ is supported, so bit 6
 *    counts as defined).  The card's "0x1F880" literal is treated as
 *    garbled: 0x3F|0x40|0x1F80|0x6000|0x8000 == 0xFFFF is the only
 *    self-consistent defined mask.  sse_get_mxcsr reads back
 *    ctx->mxcsr & 0xFFFF; sse_set_mxcsr masks reserved bits away.
 *  - ctx->mxcsr_mask publishes the FXSAVE mask: the first
 *    sse_set_mxcsr stores 0xFFFF when the field is still 0 (DAZ
 *    supported; the pre-DAZ 0xFFBF default is deliberately NOT used).
 *    A preset mask is never overwritten.
 *  - LDMXCSR with reserved bits (>= bit 16) set raises only the IE
 *    status bit in v1: the value is masked, no #XM signal is
 *    delivered.  Likewise UNMASKED exceptions on arithmetic never trap
 *    in v1: the default result is produced and the flag OR'd in.
 *  - Exception flags accumulate by OR and are only cleared by a new
 *    LDMXCSR value writing zeros (sse.h contract).
 *  - FTZ: results that underflow (tiny per the after-rounding rule)
 *    become signed zero with UE|PE set.  DAZ: denormal INPUTS are
 *    treated as signed zeros (no DE is raised for flushed inputs);
 *    with DAZ off, denormal inputs set DE.
 *  - f32 arithmetic computes an exact double intermediate and rounds
 *    once under the MXCSR round mode (f32 division keeps a documented
 *    double-rounding corner: double-then-float can misround on exact
 *    float-boundary quotients).  f64 arithmetic uses host double ops
 *    with <fenv.h> flag readback (the host FPCR must have FZ/DAZ off,
 *    which holds in-process) — MXCSR RC != nearest is honored for f32
 *    results and every conversion, but f64 arithmetic itself is
 *    host-nearest in v1 (documented gap).
 *
 * Other v1 notes: no alignment fault is raised for the Phase 5 aligned
 * forms (MOVAPS/MOVAPD on unaligned EAs simply load/store); the RC7b T1
 * aligned forms (66 0F 6F/7F MOVDQA, 0F E7 MOVNTDQ/MOVNTQ) DO check and
 * raise #GP(0) through the seg-fault channel with eip at the faulting
 * instruction.  MOVMSKPS/PD and LDMXCSR/STMXCSR reject the reserved
 * mod=3 / memory forms as I686_EXIT_UNDEF (matching #UD); PAUSE (F3 90)
 * already decodes to NOP and needs nothing here; FXSAVE/XSAVE-family
 * rows were declined in the generator and never reach a handler.  MMX
 * registers alias the low 8 bytes of ctx->x87_st[] and EMMS empties the
 * tag word — both touch the frozen state directly until L5c's x87.c
 * lands the mmx_get/mmx_set + tag-sync accessors (S5 coordination:
 * switch these few lines over then; the storage layout is ABI-
 * identical).
 *
 * i686_interp_sse_init is NOT called by interp.c yet — the coordinator
 * wires it at S5.  Calling it twice is harmless (registry last-wins).
 */

#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>

#include "interp/flags.h"
#include "interp/interp.h"
#include "interp/sse.h"

/* ------------------------------------------------------------------ */
/* MXCSR bits                                                          */
/* ------------------------------------------------------------------ */

#define MXCSR_IE 0x0001u /* invalid operation                         */
#define MXCSR_DE 0x0002u /* denormal operand                          */
#define MXCSR_ZE 0x0004u /* divide by zero                            */
#define MXCSR_OE 0x0008u /* overflow                                  */
#define MXCSR_UE 0x0010u /* underflow                                 */
#define MXCSR_PE 0x0020u /* precision (inexact)                       */
#define MXCSR_DAZ 0x0040u /* denormals-are-zero input mode            */
#define MXCSR_FTZ 0x8000u /* flush-to-zero output mode                */

/* Bits 0..15 are defined (DAZ supported); 16..31 reserved. */
#define MXCSR_DEFINED 0xFFFFu

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
        /* DAZ supported: publish the full FXSAVE mask (documented
         * choice; the pre-DAZ 0xFFBF default is not used). */
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
/* IEEE bit-level helpers (little-endian IEEE-754 host assumed)        */
/* ------------------------------------------------------------------ */

static uint32_t f32_bits(float f)
{
    uint32_t u;
    memcpy(&u, &f, 4);
    return u;
}

static float f32_from(uint32_t b)
{
    float f;
    memcpy(&f, &b, 4);
    return f;
}

static uint64_t f64_bits(double d)
{
    uint64_t u;
    memcpy(&u, &d, 8);
    return u;
}

static double f64_from(uint64_t b)
{
    double d;
    memcpy(&d, &b, 8);
    return d;
}

static int f32_nan(uint32_t b)
{
    return (b & 0x7F800000u) == 0x7F800000u && (b & 0x007FFFFFu) != 0U;
}

static int f32_snan(uint32_t b)
{
    return f32_nan(b) && (b & 0x00400000u) == 0U;
}

static int f32_den(uint32_t b)
{
    return (b & 0x7F800000u) == 0U && (b & 0x007FFFFFu) != 0U;
}

static int f32_inf(uint32_t b)
{
    return (b & 0x7FFFFFFFu) == 0x7F800000u;
}

static int f64_nan(uint64_t b)
{
    return (b & 0x7FF0000000000000ull) == 0x7FF0000000000000ull &&
           (b & 0x000FFFFFFFFFFFFFull) != 0U;
}

static int f64_snan(uint64_t b)
{
    return f64_nan(b) && (b & 0x0008000000000000ull) == 0U;
}

static int f64_den(uint64_t b)
{
    return (b & 0x7FF0000000000000ull) == 0U && (b & 0xFFFFFFFFFFFFFull) != 0U;
}

static uint32_t f32_quiet(uint32_t b)
{
    return b | 0x00400000u;
}

static uint64_t f64_quiet(uint64_t b)
{
    return b | 0x0008000000000000ull;
}

#define F32_QNAN_INDEF 0xFFC00000u
#define F64_QNAN_INDEF 0xFFF8000000000000ull
#define F32_POS_INF 0x7F800000u
#define F32_NEG_INF 0xFF800000u
#define F32_MAX_BITS 0x7F7FFFFFu
#define F64_POS_INF 0x7FF0000000000000ull
#define F64_NEG_INF 0xFFF0000000000000ull
#define F64_MAX_BITS 0x7FEFFFFFFFFFFFFFull

/* ------------------------------------------------------------------ */
/* DAZ-apply on sources (returns possibly flushed bits, sets DE)       */
/* ------------------------------------------------------------------ */

static uint32_t sse_f32_src(i686_ctx_t *ctx, uint32_t b)
{
    if (f32_den(b)) {
        if (sse_daz(ctx)) {
            return b & 0x80000000u; /* signed zero */
        }
        ctx->mxcsr |= MXCSR_DE;
    }
    return b;
}

static uint64_t sse_f64_src(i686_ctx_t *ctx, uint64_t b)
{
    if (f64_den(b)) {
        if (sse_daz(ctx)) {
            return b & 0x8000000000000000ull;
        }
        ctx->mxcsr |= MXCSR_DE;
    }
    return b;
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
        return F32_QNAN_INDEF; /* unreachable guard: callers pre-handle */
    }
    if ((db & 0x7FFFFFFFFFFFFFFFull) == 0x7FF0000000000000ull) {
        /* Exact +-inf passthrough (inf operands never overflow). */
        return (db >> 63) != 0U ? F32_NEG_INF : F32_POS_INF;
    }

    f = (float)d; /* host nearest */
    fb = f32_bits(f);
    mag = fb & 0x7FFFFFFFu;

    if (mag >= 0x7F800000u) {
        /* Overflowed the float range under nearest: RC picks inf or
         * FLT_MAX (PE always; OE always). */
        ctx->mxcsr |= MXCSR_OE | MXCSR_PE;
        if (rc == 0U || (rc == 2U && d > 0.0) || (rc == 1U && d < 0.0)) {
            return (d < 0.0) ? F32_NEG_INF : F32_POS_INF;
        }
        return (d < 0.0) ? (F32_MAX_BITS | 0x80000000u) : F32_MAX_BITS;
    }

    if ((double)f != d && rc != 0U && mag >= 0x00800000u) {
        /* Normal range: adjust one ulp of magnitude when the nearest
         * rounding went against RC.  (Subnormal range keeps nearest:
         * documented v1 gap.) */
        int bump; /* +1 / -1 on the magnitude */
        unsigned neg = (fb >> 31) & 1U;

        if (rc == 1U) { /* toward -inf */
            bump = neg ? 1 : -1;
        } else if (rc == 2U) { /* toward +inf */
            bump = neg ? -1 : 1;
        } else { /* toward zero */
            bump = -1;
        }
        if (bump > 0) {
            mag += 1U;
            if (mag >= 0x7F800000u) {
                ctx->mxcsr |= MXCSR_OE | MXCSR_PE; /* bumped into inf */
                return neg ? F32_NEG_INF : F32_POS_INF;
            }
        } else {
            mag -= 1U;
        }
        fb = (neg << 31) | mag;
        if ((double)f32_from(fb) == d) {
            fb = f32_bits(f); /* exact after all (defensive) */
        }
    }

    if (mag < 0x00800000u) {
        /* Zero or subnormal: tiny. */
        if ((db & 0x7FFFFFFFFFFFFFFFull) == 0U) {
            return fb; /* d exactly zero */
        }
        if (sse_ftz(ctx)) {
            ctx->mxcsr |= MXCSR_UE | MXCSR_PE;
            return fb & 0x80000000u;
        }
        if ((double)f32_from(fb) != d) {
            ctx->mxcsr |= MXCSR_UE | MXCSR_PE; /* tiny + inexact */
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

    /* Invalid-operation corner cases before the raw op (the double
     * intermediate would produce host NaNs / raise host flags). */
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

    /* Host double op; IEEE flags via <fenv.h> readback (the host FPCR
     * never gains FZ/DAZ in-process; RC != nearest on f64 arithmetic
     * is the documented v1 gap). */
    (void)feclearexcept(FE_ALL_EXCEPT);
    switch (k) {
    case FOP_ADD: r = da + db; break;
    case FOP_SUB: r = da - db; break;
    case FOP_MUL: r = da * db; break;
    case FOP_DIV: r = da / db; break;
    default: break;
    }
    flg = fetestexcept(FE_INEXACT | FE_OVERFLOW | FE_UNDERFLOW);
    if ((flg & FE_INEXACT) != 0) {
        ctx->mxcsr |= MXCSR_PE;
    }
    if ((flg & FE_OVERFLOW) != 0) {
        ctx->mxcsr |= MXCSR_OE; /* v1: +-inf result even for RC!=nearest */
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

/* Truncating (CVTT*): invalid (NaN/out-of-range) -> 0x80000000 + IE;
 * a dropped fraction additionally sets PE. */
static uint32_t sse_cvtt_f2i(i686_ctx_t *ctx, double d)
{
    int32_t t;

    if (!(d >= -2147483648.0 && d < 2147483648.0)) {
        ctx->mxcsr |= MXCSR_IE; /* NaN lands here too (comparisons false) */
        return 0x80000000u;
    }
    t = (int32_t)d; /* guarded range: cast is defined */
    if ((double)t != d) {
        ctx->mxcsr |= MXCSR_PE;
    }
    return (uint32_t)t;
}

/* RC-rounding (CVTPS2DQ): ties-to-even under RC=0.  The pre-range
 * [-2^31, 2^31-0.5] keeps every intermediate cast defined; float lane
 * sources at/beyond those bounds are integral, so RC cannot pull them
 * back into range. */
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
/* Guest operand plumbing                                              */
/* ------------------------------------------------------------------ */

/* 0xFF sentinel in the frozen x86_insn_t (pfx_seg/ea_base/ea_index). */
#define I686_NONE 0xFFU

static int sse_done(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

/* Flat-model EA from the decoded descriptor (mirrors decode.c's
 * x86_ea_compute: SS default for BP/SP-based mod!=0, else DS). */
static uint32_t sse_ea(const i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t ea = insn->ea_disp;
    uint8_t seg;

    if (insn->ea_base != I686_NONE) {
        ea += ctx->gpr[insn->ea_base & 7U];
    }
    if (insn->ea_index != I686_NONE) {
        ea += ctx->gpr[insn->ea_index & 7U] << insn->ea_scale;
    }
    if (insn->pfx_seg != I686_NONE) {
        seg = insn->pfx_seg;
    } else if (insn->modrm_mod != 0U &&
               (insn->ea_base == I686_REG_EBP || insn->ea_base == I686_REG_ESP ||
                (insn->pfx_addrsize != 0U && insn->ea_base == I686_REG_EBP))) {
        seg = I686_SEG_SS;
    } else {
        seg = I686_SEG_DS;
    }
    if (seg < I686_SEG_COUNT) {
        ea += ctx->seg_base[seg];
    }
    return ea; /* natural 32-bit wrap (D4) */
}

static void sse_ld(const i686_ctx_t *ctx, const x86_insn_t *insn,
                   void *out, unsigned n)
{
    memcpy(out, i686_guest_ptr(ctx, sse_ea(ctx, insn)), n);
}

static void sse_st(i686_ctx_t *ctx, const x86_insn_t *insn,
                   const void *in, unsigned n)
{
    memcpy(i686_guest_ptr(ctx, sse_ea(ctx, insn)), in, n);
}

/* 128-bit source: xmm register or m128. */
static void src128(const i686_ctx_t *ctx, const x86_insn_t *insn, uint8_t out[16])
{
    if (insn->modrm_mod == 3U) {
        sse_get_xmm(ctx, insn->modrm_rm, out);
    } else {
        sse_ld(ctx, insn, out, 16);
    }
}

static uint32_t lane32(const uint8_t *v, unsigned i)
{
    uint32_t r;
    memcpy(&r, v + 4U * i, 4);
    return r;
}

static void set_lane32(uint8_t *v, unsigned i, uint32_t b)
{
    memcpy(v + 4U * i, &b, 4);
}

static uint64_t lane64(const uint8_t *v, unsigned i)
{
    uint64_t r;
    memcpy(&r, v + 8U * i, 8);
    return r;
}

static void set_lane64(uint8_t *v, unsigned i, uint64_t b)
{
    memcpy(v + 8U * i, &b, 8);
}

/* MMX view: low 8 bytes of x87_st[r] (physical slot, TOP-independent).
 * Direct until L5c's x87.c provides the frozen mmx_get/mmx_set (S5). */
static uint64_t mm_rd(const i686_ctx_t *ctx, unsigned r)
{
    uint64_t v;
    memcpy(&v, ctx->x87_st[r & 7U], 8);
    return v;
}

static void mm_wr(i686_ctx_t *ctx, unsigned r, uint64_t v)
{
    memcpy(ctx->x87_st[r & 7U], &v, 8);
}

/* ------------------------------------------------------------------ */
/* Data movement                                                       */
/* ------------------------------------------------------------------ */

/* MOVUPS family (0F 10/11): 16B plain/66; MOVSS (F3) 4B; MOVSD (F2)
 * 8B.  Load rows keep opnd[0]=R32 (reg = xmm dest), store rows
 * opnd[0]=RM32. */
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
            memcpy(dst, src, size); /* upper lanes preserved */
        } else {
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

/* MOVAPS/MOVAPD (0F 28/29): full 128-bit; v1 raises no alignment
 * fault (documented). */
static int h_movaps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t buf[16];

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

/* MOVLPS/MOVLPD (0F 12/13); reg-reg plain form is MOVHLPS. */
static int h_movlps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t dst[16], src[16];

    if (load) {
        sse_get_xmm(ctx, insn->modrm_reg, dst);
        if (insn->modrm_mod == 3U) {
            if (insn->pfx_opsize != 0U) {
                return I686_EXIT_UNDEF; /* MOVLPD reg,reg reserved */
            }
            sse_get_xmm(ctx, insn->modrm_rm, src);
            memcpy(dst, src + 8, 8); /* MOVHLPS: low64 <- src high64 */
        } else {
            sse_ld(ctx, insn, dst, 8);
        }
        sse_set_xmm(ctx, insn->modrm_reg, dst);
    } else {
        sse_get_xmm(ctx, insn->modrm_reg, src);
        sse_st(ctx, insn, src, 8); /* m64 <- low64 */
    }
    return sse_done(ctx, insn);
}

/* MOVHPS/MOVHPD (0F 16/17); reg-reg plain form is MOVLHPS. */
static int h_movhps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t dst[16], src[16];

    if (load) {
        sse_get_xmm(ctx, insn->modrm_reg, dst);
        if (insn->modrm_mod == 3U) {
            if (insn->pfx_opsize != 0U) {
                return I686_EXIT_UNDEF; /* MOVHPD reg,reg reserved */
            }
            sse_get_xmm(ctx, insn->modrm_rm, src);
            memcpy(dst + 8, src, 8); /* MOVLHPS: high64 <- src low64 */
        } else {
            uint8_t m[8];
            sse_ld(ctx, insn, m, 8);
            memcpy(dst + 8, m, 8);
        }
        sse_set_xmm(ctx, insn->modrm_reg, dst);
    } else {
        sse_get_xmm(ctx, insn->modrm_reg, src);
        sse_st(ctx, insn, src + 8, 8); /* m64 <- high64 */
    }
    return sse_done(ctx, insn);
}

/* MOVD/MOVQ gpr <-> mm/xmm (0F 6E load-gpr row: opnd[0]=R32;
 * 0F 7E store-gpr row: opnd[0]=RM32; F3 7E is a 64-bit load). */
static int h_movq_xmm(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->opnd[0] == I686_OPND_R32) {
        /* 0F 6E: mm (plain) / xmm (66) <- r/m32, zero-extended. */
        uint32_t v;
        if (insn->modrm_mod == 3U) {
            v = ctx->gpr[insn->modrm_rm & 7U];
        } else {
            sse_ld(ctx, insn, &v, 4);
        }
        if (insn->pfx_opsize != 0U) {
            uint8_t x[16];
            memset(x, 0, sizeof x);
            memcpy(x, &v, 4); /* MOVD xmm zero-extends all 96 upper bits */
            sse_set_xmm(ctx, insn->modrm_reg, x);
        } else {
            mm_wr(ctx, insn->modrm_reg, (uint64_t)v);
        }
    } else if (insn->pfx_rep == 1U) {
        /* F3 0F 7E: MOVQ xmm1, xmm2/m64.  Legacy MOVQ CLEARS
         * dest[127:64] (RC7b T2, oracle-verified; only the VEX form
         * preserves). */
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
        /* 0F 7E plain/66: r/m32 <- MOVD of mm (plain) / xmm (66). */
        uint32_t v;
        if (insn->pfx_opsize != 0U) {
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
    if (insn->pfx_rep == 1U) { /* SS: lane 0 only */
        uint32_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane32(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 4);
        }
        set_lane32(dst, 0, sse_f32_op(ctx, lane32(dst, 0), s, k));
    } else if (insn->pfx_rep == 2U) { /* SD: lane 0 only */
        uint64_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane64(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 8);
        }
        set_lane64(dst, 0, sse_f64_op(ctx, lane64(dst, 0), s, k));
    } else if (insn->pfx_opsize != 0U) { /* PD */
        uint8_t src[16];
        src128(ctx, insn, src);
        set_lane64(dst, 0, sse_f64_op(ctx, lane64(dst, 0), lane64(src, 0), k));
        set_lane64(dst, 1, sse_f64_op(ctx, lane64(dst, 1), lane64(src, 1), k));
    } else { /* PS */
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

static int h_addps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_arith(ctx, insn, FOP_ADD);
}

static int h_subps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_arith(ctx, insn, FOP_SUB);
}

static int h_mulps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_arith(ctx, insn, FOP_MUL);
}

static int h_divps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_arith(ctx, insn, FOP_DIV);
}

/* ------------------------------------------------------------------ */
/* Bitwise logic (identical for PS/PD; PS form has no FP exceptions)   */
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
    uint8_t dst[16];
    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->modrm_mod == 3U) {
        uint8_t src[16];
        sse_get_xmm(ctx, insn->modrm_rm, src);
        log_apply(dst, src, 16, k);
    } else {
        uint8_t src[16];
        sse_ld(ctx, insn, src, 16);
        log_apply(dst, src, 16, k);
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

static int h_andps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_logic(ctx, insn, LOG_AND);
}

static int h_andnps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_logic(ctx, insn, LOG_ANDN);
}

static int h_orps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_logic(ctx, insn, LOG_OR);
}

static int h_xorps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_logic(ctx, insn, LOG_XOR);
}

/* PAND/PANDN/POR/PXOR: 66 = xmm 128-bit, plain = MMX 64-bit. */
static int h_plogic(i686_ctx_t *ctx, const x86_insn_t *insn, log_kind k)
{
    if (insn->pfx_opsize != 0U) {
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

static int h_pand(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_plogic(ctx, insn, LOG_AND);
}

static int h_pandn(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_plogic(ctx, insn, LOG_ANDN);
}

static int h_por(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_plogic(ctx, insn, LOG_OR);
}

static int h_pxor(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_plogic(ctx, insn, LOG_XOR);
}

/* ------------------------------------------------------------------ */
/* Comparisons                                                         */
/* ------------------------------------------------------------------ */

/* One predicate evaluation on raw bits; returns 0 or all-ones at the
 * element width.  Predicates 0/1/2 (EQ/LT/LE) are signaling: IE on
 * ANY NaN; 3..7 are quiet: IE on SNaN only. */
static int cmp_eval(i686_ctx_t *ctx, uint64_t a, uint64_t b, unsigned pred,
                    int wide /* 0: f32 lanes in low 32, 1: f64 */)
{
    int unord, lt, eq;
    uint32_t a32;
    uint32_t b32;

    if (wide != 0) {
        a = sse_f64_src(ctx, a); /* DAZ/DE apply to compare inputs too */
        b = sse_f64_src(ctx, b);
    } else {
        a = sse_f32_src(ctx, (uint32_t)(a & 0xFFFFFFFFu));
        b = sse_f32_src(ctx, (uint32_t)(b & 0xFFFFFFFFu));
    }
    a32 = (uint32_t)(a & 0xFFFFFFFFu);
    b32 = (uint32_t)(b & 0xFFFFFFFFu);

    if (wide == 0 ? (f32_nan(a32) || f32_nan(b32)) : (f64_nan(a) || f64_nan(b))) {
        int sn = wide == 0 ? (f32_snan(a32) || f32_snan(b32))
                           : (f64_snan(a) || f64_snan(b));
        if (pred <= 2U || sn) {
            ctx->mxcsr |= MXCSR_IE;
        }
        unord = 1;
        lt = 0;
        eq = 0;
    } else {
        double da = wide ? f64_from(a) : (double)f32_from(a32);
        double db = wide ? f64_from(b) : (double)f32_from(b32);
        unord = 0;
        eq = da == db;
        lt = da < db;
    }

    switch (pred) {
    case 0U: return eq;
    case 1U: return lt;
    case 2U: return lt || eq;
    case 3U: return unord;
    case 4U: return !eq;
    case 5U: return !lt;
    case 6U: return !(lt || eq);
    default: return !unord; /* 7: ORD */
    }
}

static int h_cmpps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t dst[16];
    unsigned pred = insn->imm & 7U;

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->pfx_rep == 1U) { /* CMPSS */
        uint32_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane32(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 4);
        }
        set_lane32(dst, 0, cmp_eval(ctx, lane32(dst, 0), s, pred, 0)
                             ? 0xFFFFFFFFu : 0U);
    } else if (insn->pfx_rep == 2U) { /* CMPSD */
        uint64_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane64(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 8);
        }
        set_lane64(dst, 0, cmp_eval(ctx, lane64(dst, 0), s, pred, 1)
                             ? 0xFFFFFFFFFFFFFFFFull : 0U);
    } else if (insn->pfx_opsize != 0U) { /* CMPPD */
        uint8_t src[16];
        unsigned i;
        src128(ctx, insn, src);
        for (i = 0U; i < 2U; i++) {
            set_lane64(dst, i, cmp_eval(ctx, lane64(dst, i), lane64(src, i),
                                        pred, 1)
                                  ? 0xFFFFFFFFFFFFFFFFull : 0U);
        }
    } else { /* CMPPS */
        uint8_t src[16];
        unsigned i;
        src128(ctx, insn, src);
        for (i = 0U; i < 4U; i++) {
            set_lane32(dst, i, cmp_eval(ctx, lane32(dst, i), lane32(src, i),
                                        pred, 0)
                                  ? 0xFFFFFFFFu : 0U);
        }
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

/* kind: 0 = greater, 1 = equal, 2 = less, 3 = unordered. */
static void comis_flags(i686_ctx_t *ctx, unsigned kind)
{
    i686_flags_materialize(ctx); /* eflags may hold a lazy descriptor */
    ctx->eflags &= ~(I686_EF_CF | I686_EF_ZF | I686_EF_PF | I686_EF_OF |
                     I686_EF_SF | I686_EF_AF);
    if (kind == 1U) {
        ctx->eflags |= I686_EF_ZF;
    } else if (kind == 2U) {
        ctx->eflags |= I686_EF_CF;
    } else if (kind == 3U) {
        ctx->eflags |= I686_EF_CF | I686_EF_ZF | I686_EF_PF;
    } /* greater: no bits */
    ctx->lazy_op = I686_FOP_NONE;
}

/* COMIS/UCOMIS: ZF/CF/PF per the x86 mapping (CF=less, ZF=equal,
 * PF=unordered; OF/SF/AF cleared).  Direct eflags write, lazy_op
 * cleared.  signaling=1 (COMIS*) raises IE on any NaN. */
static int h_comis(i686_ctx_t *ctx, const x86_insn_t *insn, int signaling)
{
    int wide = (insn->pfx_opsize != 0U);

    if (wide) {
        uint8_t src[16];
        uint64_t a, b;
        sse_get_xmm(ctx, insn->modrm_reg, src);
        a = lane64(src, 0);
        if (insn->modrm_mod == 3U) {
            sse_get_xmm(ctx, insn->modrm_rm, src);
            b = lane64(src, 0);
        } else {
            sse_ld(ctx, insn, &b, 8);
        }
        a = sse_f64_src(ctx, a);
        b = sse_f64_src(ctx, b);
        if (f64_nan(a) || f64_nan(b)) {
            if (signaling || f64_snan(a) || f64_snan(b)) {
                ctx->mxcsr |= MXCSR_IE;
            }
            comis_flags(ctx, 3U);
        } else {
            double da = f64_from(a), db = f64_from(b);
            comis_flags(ctx, da < db ? 2U : (da == db ? 1U : 0U));
        }
        return sse_done(ctx, insn);
    }
    {
        uint8_t src[16];
        uint32_t a, b;
        sse_get_xmm(ctx, insn->modrm_reg, src);
        a = lane32(src, 0);
        if (insn->modrm_mod == 3U) {
            sse_get_xmm(ctx, insn->modrm_rm, src);
            b = lane32(src, 0);
        } else {
            sse_ld(ctx, insn, &b, 4);
        }
        a = sse_f32_src(ctx, a);
        b = sse_f32_src(ctx, b);
        if (f32_nan(a) || f32_nan(b)) {
            if (signaling || f32_snan(a) || f32_snan(b)) {
                ctx->mxcsr |= MXCSR_IE;
            }
            comis_flags(ctx, 3U);
        } else {
            double da = (double)f32_from(a), db = (double)f32_from(b);
            comis_flags(ctx, da < db ? 2U : (da == db ? 1U : 0U));
        }
        return sse_done(ctx, insn);
    }
}

static int h_comiss(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_comis(ctx, insn, 1);
}

static int h_ucomiss(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_comis(ctx, insn, 0);
}

/* MOVMSKPS/PD (0F 50): sign bits into r32; reg-only (mod=3). */
static int h_movmskps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t src[16];
    uint32_t r = 0U;

    if (insn->modrm_mod != 3U) {
        return I686_EXIT_UNDEF; /* memory form reserved (#UD) */
    }
    sse_get_xmm(ctx, insn->modrm_rm, src);
    if (insn->pfx_opsize != 0U) { /* MOVMSKPD */
        r = (uint32_t)((lane64(src, 0) >> 63) | ((lane64(src, 1) >> 62) & 2U));
    } else {
        unsigned i;
        for (i = 0U; i < 4U; i++) {
            r |= (lane32(src, i) >> 31) << i;
        }
    }
    ctx->gpr[insn->modrm_reg & 7U] = r;
    return sse_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Conversions                                                         */
/* ------------------------------------------------------------------ */

/* 0F 2A: CVTPI2PS (plain), CVTPI2PD (66), CVTSI2SS (F3), CVTSI2SD
 * (F2).  int32 sources -> FP lanes. */
static int h_cvtpi2ps(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t dst[16];
    uint32_t w0, w1;

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->pfx_rep != 0U) { /* scalar from r/m32 */
        int32_t s32;
        if (insn->modrm_mod == 3U) {
            s32 = (int32_t)ctx->gpr[insn->modrm_rm & 7U];
        } else {
            sse_ld(ctx, insn, &s32, 4);
        }
        if (insn->pfx_rep == 1U) { /* CVTSI2SS */
            set_lane32(dst, 0, sse_round_f64_to_f32(ctx, (double)s32));
        } else { /* CVTSI2SD (exact) */
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
        if (insn->pfx_opsize != 0U) { /* CVTPI2PD */
            set_lane64(dst, 0, f64_bits((double)(int32_t)w0));
            set_lane64(dst, 1, f64_bits((double)(int32_t)w1));
        } else { /* CVTPI2PS */
            set_lane32(dst, 0, sse_round_f64_to_f32(ctx, (double)(int32_t)w0));
            set_lane32(dst, 1, sse_round_f64_to_f32(ctx, (double)(int32_t)w1));
        }
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

/* 0F 2C: CVTTPS2PI (plain), CVTTPD2PI (66), CVTTSS2SI (F3),
 * CVTTSD2SI (F2); invalid -> 0x80000000 + IE. */
static int h_cvttps2pi(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->pfx_rep != 0U) { /* scalar to r32 (reg = dest gpr) */
        uint32_t r;
        if (insn->pfx_rep == 1U) { /* CVTTSS2SI */
            uint32_t s;
            if (insn->modrm_mod == 3U) {
                uint8_t src[16];
                sse_get_xmm(ctx, insn->modrm_rm, src);
                s = lane32(src, 0);
            } else {
                sse_ld(ctx, insn, &s, 4);
            }
            r = sse_cvtt_f2i(ctx, (double)f32_from(sse_f32_src(ctx, s)));
        } else { /* CVTTSD2SI */
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
        if (insn->pfx_opsize != 0U) { /* CVTTPD2PI from 2 doubles */
            uint8_t src[16];
            src128(ctx, insn, src);
            out = (uint64_t)sse_cvtt_f2i(ctx, f64_from(sse_f64_src(ctx, lane64(src, 0)))) |
                  ((uint64_t)sse_cvtt_f2i(ctx, f64_from(sse_f64_src(ctx, lane64(src, 1)))) << 32);
        } else { /* CVTTPS2PI from 2 floats */
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

/* 0F 5A: CVTPS2PD (plain), CVTPD2PS (66, upper 64 zeroed),
 * CVTSS2SD (F3), CVTSD2SS (F2). */
static int h_cvtps2pd(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t dst[16];

    sse_get_xmm(ctx, insn->modrm_reg, dst);
    if (insn->pfx_rep == 1U) { /* CVTSS2SD: exact widen */
        uint32_t s;
        if (insn->modrm_mod == 3U) {
            uint8_t src[16];
            sse_get_xmm(ctx, insn->modrm_rm, src);
            s = lane32(src, 0);
        } else {
            sse_ld(ctx, insn, &s, 4);
        }
        set_lane64(dst, 0, f64_bits((double)f32_from(sse_f32_src(ctx, s))));
    } else if (insn->pfx_rep == 2U) { /* CVTSD2SS */
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
    } else if (insn->pfx_opsize != 0U) { /* CVTPD2PS */
        uint8_t src[16];
        src128(ctx, insn, src);
        set_lane32(dst, 0,
                   sse_round_f64_to_f32(ctx, f64_from(sse_f64_src(ctx, lane64(src, 0)))));
        set_lane32(dst, 1,
                   sse_round_f64_to_f32(ctx, f64_from(sse_f64_src(ctx, lane64(src, 1)))));
        set_lane32(dst, 2, 0U);
        set_lane32(dst, 3, 0U);
    } else { /* CVTPS2PD: exact widen, 2 -> 2 */
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

/* 0F 5B: CVTDQ2PS (plain), CVTPS2DQ (66, RC), CVTTPS2DQ (F3). */
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

    if (insn->pfx_opsize != 0U) { /* CVTPS2DQ: RC rounding */
        for (i = 0U; i < 4U; i++) {
            uint32_t s = lane32(src, i);
            set_lane32(dst, i, sse_cvt_f2i(ctx, (double)f32_from(sse_f32_src(ctx, s))));
        }
    } else if (insn->pfx_rep == 1U) { /* CVTTPS2DQ: truncation */
        for (i = 0U; i < 4U; i++) {
            uint32_t s = lane32(src, i);
            set_lane32(dst, i, sse_cvtt_f2i(ctx, (double)f32_from(sse_f32_src(ctx, s))));
        }
    } else { /* CVTDQ2PS: int32 -> float32 */
        for (i = 0U; i < 4U; i++) {
            set_lane32(dst, i,
                       sse_round_f64_to_f32(ctx, (double)(int32_t)lane32(src, i)));
        }
    }
    sse_set_xmm(ctx, insn->modrm_reg, dst);
    return sse_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Packed integer arithmetic (66 = xmm 128-bit, plain = MMX 64-bit)    */
/* ------------------------------------------------------------------ */

static void int_vec_dst_fetch(i686_ctx_t *ctx, const x86_insn_t *insn,
                              uint8_t d[16], int xmm)
{
    if (xmm) {
        sse_get_xmm(ctx, insn->modrm_reg, d);
    } else {
        uint64_t m = mm_rd(ctx, insn->modrm_reg);
        memset(d, 0, 16);
        memcpy(d, &m, 8);
    }
}

/* Loads the source vector into v (16 bytes; plain/MMX forms zero the
 * upper 8); xmm selects the 128-bit form (callers pass the prefix
 * decode — PSHUFLW/PSHUFHW are xmm forms under F2/F3, not 66). */
static int int_vec_src(i686_ctx_t *ctx, const x86_insn_t *insn, uint8_t v[16],
                       int xmm)
{
    memset(v, 0, 16);
    if (xmm) {
        src128(ctx, insn, v);
    } else if (insn->modrm_mod == 3U) {
        uint64_t m = mm_rd(ctx, insn->modrm_rm);
        memcpy(v, &m, 8);
    } else {
        sse_ld(ctx, insn, v, 8);
    }
    return xmm;
}

static void int_vec_dst(i686_ctx_t *ctx, const x86_insn_t *insn,
                        const uint8_t v[16], int xmm)
{
    if (xmm) {
        sse_set_xmm(ctx, insn->modrm_reg, v);
    } else {
        uint64_t m;
        memcpy(&m, v, 8);
        mm_wr(ctx, insn->modrm_reg, m);
    }
}

/* PADDD / PSUBD (also MMX plain forms). */
static int h_paddd(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 4U : 2U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        uint32_t a, b, r;
        memcpy(&a, d + 4U * i, 4);
        memcpy(&b, s + 4U * i, 4);
        r = a + b;
        memcpy(d + 4U * i, &r, 4);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_psubd(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 4U : 2U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        uint32_t a, b, r;
        memcpy(&a, d + 4U * i, 4);
        memcpy(&b, s + 4U * i, 4);
        r = a - b;
        memcpy(d + 4U * i, &r, 4);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

/* PADDQ / PSUBQ: 64-bit lanes. */
static int h_pq(i686_ctx_t *ctx, const x86_insn_t *insn, int sub)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 2U : 1U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        uint64_t a, b, r;
        memcpy(&a, d + 8U * i, 8);
        memcpy(&b, s + 8U * i, 8);
        r = sub ? a - b : a + b;
        memcpy(d + 8U * i, &r, 8);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_paddq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_pq(ctx, insn, 0);
}

static int h_psubq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_pq(ctx, insn, 1);
}

/* PMULLW: 8/4 lanes of signed 16-bit multiply, low 16 bits kept. */
static int h_pmullw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 8U : 4U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        int32_t a = (int16_t)(d[2U * i] | ((uint16_t)d[2U * i + 1U] << 8));
        int32_t b = (int16_t)(s[2U * i] | ((uint16_t)s[2U * i + 1U] << 8));
        uint16_t r = (uint16_t)(a * b);
        d[2U * i] = (uint8_t)r;
        d[2U * i + 1U] = (uint8_t)(r >> 8);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

/* PMULUDQ: even 32-bit lanes -> 64-bit unsigned products. */
static int h_pmuludq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 2U : 1U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        uint32_t a, b;
        uint64_t r;
        memcpy(&a, d + 8U * i, 4);
        memcpy(&b, s + 8U * i, 4);
        r = (uint64_t)a * (uint64_t)b;
        memcpy(d + 8U * i, &r, 8);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* PUNPCK / shuffle                                                    */
/* ------------------------------------------------------------------ */

/* PUNPCKL/H BW/WD/DQ (+LQDQ/HQDQ, 66 only): interleave the low/high
 * half-elements of dest and src at element size esize. */
static int h_punpck(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned esize,
                    int high)
{
    uint8_t d[16], s[16], out[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned per = xmm ? 16U : 8U;     /* operand bytes              */
    unsigned n = per / esize;          /* elements per operand       */
    unsigned take = n / 2U;            /* from the chosen half       */
    unsigned base = high ? per / 2U : 0U;
    unsigned j;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    memset(out, 0, sizeof out);
    for (j = 0U; j < take; j++) {
        memcpy(out + esize * (2U * j), d + base + esize * j, esize);
        memcpy(out + esize * (2U * j + 1U), s + base + esize * j, esize);
    }
    int_vec_dst(ctx, insn, out, xmm);
    return sse_done(ctx, insn);
}

static int h_punpcklbw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_punpck(ctx, insn, 1, 0);
}

static int h_punpcklwd(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_punpck(ctx, insn, 2, 0);
}

static int h_punpckldq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_punpck(ctx, insn, 4, 0);
}

static int h_punpckhbw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_punpck(ctx, insn, 1, 1);
}

static int h_punpckhwd(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_punpck(ctx, insn, 2, 1);
}

static int h_punpckhdq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_punpck(ctx, insn, 4, 1);
}

static int h_punpcklqdq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_punpck(ctx, insn, 8, 0);
}

static int h_punpckhqdq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_punpck(ctx, insn, 8, 1);
}

/* PSHUFW (plain, MMX) / PSHUFD (66) / PSHUFLW (F2) / PSHUFHW (F3);
 * the F2/F3 forms are xmm, only plain is 64-bit MMX. */
static int h_pshufw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16], out[16];
    int xmm = int_vec_src(ctx, insn, s,
                          insn->pfx_opsize != 0U || insn->pfx_rep != 0U);
    unsigned imm = insn->imm & 0xFFu;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    memset(out, 0, sizeof out);

    if (insn->pfx_opsize != 0U) { /* PSHUFD: 4 dwords */
        unsigned j;
        for (j = 0U; j < 4U; j++) {
            unsigned sel = (imm >> (2U * j)) & 3U;
            memcpy(out + 4U * j, s + 4U * sel, 4);
        }
    } else if (insn->pfx_rep == 2U) { /* PSHUFLW: low words shuffled */
        unsigned j;
        for (j = 0U; j < 4U; j++) {
            unsigned sel = (imm >> (2U * j)) & 3U;
            out[2U * j] = s[2U * sel];
            out[2U * j + 1U] = s[2U * sel + 1U];
        }
        memcpy(out + 8, s + 8, 8);
    } else if (insn->pfx_rep == 1U) { /* PSHUFHW: high words shuffled */
        unsigned j;
        memcpy(out, s, 8);
        for (j = 4U; j < 8U; j++) {
            unsigned sel = (imm >> (2U * (j - 4U))) & 3U;
            out[2U * j] = s[2U * (4U + sel)];
            out[2U * j + 1U] = s[2U * (4U + sel) + 1U];
        }
    } else { /* PSHUFW: MMX 4 words */
        unsigned j;
        for (j = 0U; j < 4U; j++) {
            unsigned sel = (imm >> (2U * j)) & 3U;
            out[2U * j] = s[2U * sel];
            out[2U * j + 1U] = s[2U * sel + 1U];
        }
    }
    int_vec_dst(ctx, insn, out, xmm);
    return sse_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* RC7b T1: SSE2 data movement + integer rows (docs/lanes/phase-7.md)  */
/* ------------------------------------------------------------------ */

/* #GP(0) for the aligned forms (MOVDQA, MOVNTDQ/MOVNTQ): delivered via
 * the seg-fault channel (trapno 13 in exit_arg, error code 0 in
 * exit_dest, cr2 = the offending EA); eip stays at the instruction. */
static int sse_aligned_fault(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->exit_arg = 13u; /* #GP */
    ctx->exit_dest = 0u;
    ctx->fault_addr = sse_ea(ctx, insn);
    return I686_EXIT_FAULT;
}

/* MOVDQA/MOVDQU + MMX MOVQ (0F 6F load row / 0F 7F store row, one id;
 * direction from opnd[0]): 66 = MOVDQA (#GP(0) on a misaligned 16-byte
 * EA), F3 = MOVDQU, plain = MMX MOVQ (8 bytes, m64/mm); F2 is undefined
 * x86.  MOVAPS keeps its documented v1 no-fault behavior -- only the
 * RC7b aligned forms check alignment.  RC7b T2 fix: the plain-form test
 * is (opsize == 0 && rep == 0); the old pfx_rep == 0 test also caught
 * the 66 prefix (which rides opsize, not rep), so every MOVDQA executed
 * as an 8-byte MMX MOVQ through the x87_st slot and left the XMM file
 * stale -- the exact wedge that made glibc's aligned-loop strchr return
 * NULL inside dash. */
static int h_movdqa(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int load = (insn->opnd[0] == I686_OPND_R32);
    uint8_t buf[16];

    if (insn->pfx_rep == 2U) {
        return I686_EXIT_UNDEF; /* F2 0F 6F/7F: undefined x86 */
    }
    if (insn->pfx_opsize == 0U && insn->pfx_rep == 0U) { /* plain MMX */
        uint64_t v;
        if (load) {
            if (insn->modrm_mod == 3U) {
                v = mm_rd(ctx, insn->modrm_rm);
            } else {
                sse_ld(ctx, insn, &v, 8);
            }
            mm_wr(ctx, insn->modrm_reg, v);
        } else {
            v = mm_rd(ctx, insn->modrm_reg);
            if (insn->modrm_mod == 3U) {
                mm_wr(ctx, insn->modrm_rm, v);
            } else {
                sse_st(ctx, insn, &v, 8);
            }
        }
        return sse_done(ctx, insn);
    }
    if (insn->pfx_opsize != 0U && insn->modrm_mod != 3U &&
        (sse_ea(ctx, insn) & 15U) != 0U) {
        return sse_aligned_fault(ctx, insn); /* MOVDQA: #GP(0) */
    }
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

/* MOVQ family row (0F D6): 66 = MOVQ m64/xmm-low64 <- xmm.d0 (the store
 * form: reg field is the source, rm the destination; a register dest
 * has its upper half CLEARED, matching legacy MOVQ -- verified against
 * the linux/386 oracle in RC7b T2), F2 = MOVDQ2Q mm <- xmm.d0 (reg-
 * only), F3 = MOVQ2DQ xmm <- mm (upper zeroed); plain D6 is undefined
 * x86. */
static int h_movq2dq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t src[16];
    uint64_t v;

    if (insn->pfx_opsize != 0U) { /* 66: MOVQ xmm2/m64, xmm1 */
        sse_get_xmm(ctx, insn->modrm_reg, src);
        memcpy(&v, src, 8);
        if (insn->modrm_mod == 3U) {
            uint8_t dst[16];
            memset(dst, 0, sizeof dst); /* legacy MOVQ clears the upper */
            memcpy(dst, &v, 8);
            sse_set_xmm(ctx, insn->modrm_rm, dst);
        } else {
            sse_st(ctx, insn, &v, 8);
        }
    } else if (insn->pfx_rep == 2U) { /* F2: MOVDQ2Q mm, xmm */
        if (insn->modrm_mod != 3U) {
            return I686_EXIT_UNDEF; /* memory form is #UD */
        }
        sse_get_xmm(ctx, insn->modrm_rm, src);
        memcpy(&v, src, 8);
        mm_wr(ctx, insn->modrm_reg, v);
    } else if (insn->pfx_rep == 1U) { /* F3: MOVQ2DQ xmm, mm */
        uint8_t x[16];
        v = mm_rd(ctx, insn->modrm_rm);
        memset(x, 0, sizeof x);
        memcpy(x, &v, 8);
        sse_set_xmm(ctx, insn->modrm_reg, x);
    } else {
        return I686_EXIT_UNDEF; /* plain 0F D6: undefined x86 */
    }
    return sse_done(ctx, insn);
}

/* MOVNTDQ/MOVNTQ (0F E7): 66 = m128 <- xmm (16-byte-aligned NT store),
 * plain = MOVNTQ m64 <- mm (8-byte-aligned); the register form and
 * F2/F3 are undefined x86.  Non-temporal semantics are plain stores at
 * this level (single-threaded TSO guest). */
static int h_movntdq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned align;

    if (insn->pfx_rep != 0U || insn->modrm_mod == 3U) {
        return I686_EXIT_UNDEF;
    }
    align = (insn->pfx_opsize != 0U) ? 16U : 8U;
    if ((sse_ea(ctx, insn) & (align - 1U)) != 0U) {
        return sse_aligned_fault(ctx, insn); /* #GP(0) */
    }
    if (insn->pfx_opsize != 0U) {
        uint8_t buf[16];
        sse_get_xmm(ctx, insn->modrm_reg, buf);
        sse_st(ctx, insn, buf, 16);
    } else {
        uint64_t v = mm_rd(ctx, insn->modrm_reg);
        sse_st(ctx, insn, &v, 8);
    }
    return sse_done(ctx, insn);
}

/* PSRLDQ row (0F 73).  RC7b T2 rewrite: this is the shift-by-imm8
 * GROUP, so the modrm reg field carries the /digit and the register
 * operand is modrm_rm (the old code wrote the result to the digit-
 * indexed register and left the real destination stale).  Group map
 * (Intel SDM "PSRLDQ/PSLLQ/PSRLQ/PSLLW", verified against the
 * linux/386 oracle):
 *   66 /2 PSRLQ  (packed 64-bit BIT shift, BOTH quadwords)
 *   66 /3 PSRLDQ (whole-register byte shift, out[j] = s[j+imm])
 *   66 /6 PSLLQ  (packed 64-bit BIT shift)
 *   66 /7 PSLLDQ (out[j] = s[j-imm])
 * plain /2 MMX PSRLQ, /6 MMX PSLLQ (single qword, bit shift; counts
 * masked to 6 bits).  imm8 >= 16 gives zero for the byte shifts;
 * other /digits and F2/F3 are undefined. */
static int h_pshiftdq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned imm = insn->imm & 0xFFu;
    unsigned dig = insn->modrm_reg;

    if (insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    if (insn->pfx_opsize != 0U) { /* 66: xmm forms */
        uint8_t s[16], out[16];
        if (dig != 2U && dig != 3U && dig != 6U && dig != 7U) {
            return I686_EXIT_UNDEF;
        }
        src128(ctx, insn, s);
        memset(out, 0, sizeof out);
        if (dig == 3U) { /* PSRLDQ: out[j] = s[j+imm] */
            if (imm < 16U) {
                memcpy(out, s + imm, 16U - imm);
            }
        } else if (dig == 7U) { /* PSLLDQ: out[j] = s[j-imm] */
            if (imm < 16U) {
                memcpy(out + imm, s, 16U - imm);
            }
        } else { /* PSRLQ (/2) / PSLLQ (/6): packed 64-bit bit shifts */
            uint64_t lo = lane64(s, 0);
            uint64_t hi = lane64(s, 1);
            unsigned cnt = imm & 63U;
            if (cnt != 0U) {
                if (dig == 2U) {
                    lo >>= cnt;
                    hi >>= cnt;
                } else {
                    lo <<= cnt;
                    hi <<= cnt;
                }
            }
            set_lane64(out, 0, lo);
            set_lane64(out, 1, hi);
        }
        sse_set_xmm(ctx, insn->modrm_rm, out);
    } else { /* plain: MMX PSRLQ /2, PSLLQ /6 */
        uint64_t v;
        unsigned cnt;
        if (dig != 2U && dig != 6U) {
            return I686_EXIT_UNDEF;
        }
        if (insn->modrm_mod == 3U) {
            v = mm_rd(ctx, insn->modrm_rm);
        } else {
            sse_ld(ctx, insn, &v, 8);
        }
        cnt = imm & 63U; /* MMX: count masked to 6 bits */
        if (cnt != 0U) {
            v = (dig == 2U) ? (v >> cnt) : (v << cnt);
        }
        mm_wr(ctx, insn->modrm_rm, v);
    }
    return sse_done(ctx, insn);
}

/* PCMPGTB (0F 64) / PCMPEQB (0F 74) / PCMPEQD (0F 76): per-element
 * compares with all-ones/zero masks; 66 = 16-byte xmm, plain = 8-byte
 * MMX. */
typedef enum { PCMP_GT8 = 0, PCMP_EQ8, PCMP_EQ32 } pcmp_kind;

static int h_pcmp(i686_ctx_t *ctx, const x86_insn_t *insn, pcmp_kind k)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 16U : 8U; /* operand bytes */
    unsigned esz = (k == PCMP_EQ32) ? 4U : 1U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i += esz) {
        int t;
        if (k == PCMP_GT8) {
            t = (int8_t)d[i] > (int8_t)s[i];
        } else if (esz == 4U) {
            t = lane32(d, i / 4U) == lane32(s, i / 4U);
        } else {
            t = d[i] == s[i];
        }
        memset(d + i, t ? 0xFF : 0x00, esz);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_pcmp_gt8(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_pcmp(ctx, insn, PCMP_GT8);
}

static int h_pcmp_eq8(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_pcmp(ctx, insn, PCMP_EQ8);
}

static int h_pcmp_eq32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_pcmp(ctx, insn, PCMP_EQ32);
}

/* PMOVMSKB (0F D7): r32 <- byte sign mask of xmm[rm] (66, 16 bits) or
 * mm[rm] (plain, 8 bits); reg-only (mod=3), F2/F3 undefined. */
static int h_pmovmskb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t src[16];
    uint32_t r = 0U;
    unsigned n, i;

    if (insn->modrm_mod != 3U || insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    if (insn->pfx_opsize != 0U) {
        sse_get_xmm(ctx, insn->modrm_rm, src);
        n = 16U;
    } else {
        uint64_t m = mm_rd(ctx, insn->modrm_rm);
        memset(src, 0, sizeof src);
        memcpy(src, &m, 8);
        n = 8U;
    }
    for (i = 0U; i < n; i++) {
        r |= (uint32_t)(src[i] >> 7) << i;
    }
    ctx->gpr[insn->modrm_reg & 7U] = r;
    return sse_done(ctx, insn);
}

/* PMINUB (0F DA) / PMAXUB (0F DE): unsigned byte min/max; 66 = xmm,
 * plain = MMX. */
static int h_pminmaxub(i686_ctx_t *ctx, const x86_insn_t *insn, int is_max)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 16U : 8U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        d[i] = (is_max ? (d[i] > s[i]) : (d[i] < s[i])) ? d[i] : s[i];
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

static int h_pminub(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_pminmaxub(ctx, insn, 0);
}

static int h_pmaxub(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_pminmaxub(ctx, insn, 1);
}

/* PSUBB (0F F8): byte lanes; 66 = xmm, plain = MMX. */
static int h_psubb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t d[16], s[16];
    int xmm = int_vec_src(ctx, insn, s, insn->pfx_opsize != 0U);
    unsigned n = xmm ? 16U : 8U;
    unsigned i;

    int_vec_dst_fetch(ctx, insn, d, xmm);
    for (i = 0U; i < n; i++) {
        d[i] = (uint8_t)(d[i] - s[i]);
    }
    int_vec_dst(ctx, insn, d, xmm);
    return sse_done(ctx, insn);
}

/* PREFETCHh (0F 18): performance hint — no memory access, no faults,
 * no architected result (the modrm byte only sizes the instruction).
 * The 66/F2/F3 forms are undefined x86. */
static int h_prefetch(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->pfx_opsize != 0U || insn->pfx_rep != 0U) {
        return I686_EXIT_UNDEF;
    }
    return sse_done(ctx, insn);
}

/* SFENCE (0F AE /7): store fence — a no-op in the single-threaded TSO
 * guest model (plain stores order naturally).  The memory modrm forms
 * are undefined x86 (#UD). */
static int h_sfence(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U) {
        return I686_EXIT_UNDEF;
    }
    return sse_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* MXCSR / EMMS                                                        */
/* ------------------------------------------------------------------ */

static int h_ldmxcsr(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v;

    if (insn->modrm_mod == 3U) {
        return I686_EXIT_UNDEF; /* register form reserved (#UD) */
    }
    sse_ld(ctx, insn, &v, 4);
    sse_set_mxcsr(ctx, v); /* masks reserved bits, overwrites flags */
    if ((v & ~MXCSR_DEFINED) != 0U) {
        ctx->mxcsr |= MXCSR_IE; /* v1: flag only, no #XM (documented) */
    }
    return sse_done(ctx, insn);
}

static int h_stmxcsr(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v;

    if (insn->modrm_mod == 3U) {
        return I686_EXIT_UNDEF; /* register form reserved (#UD) */
    }
    v = sse_get_mxcsr(ctx);
    sse_st(ctx, insn, &v, 4);
    return sse_done(ctx, insn);
}

/* EMMS (0F 77): tag word <- all empty.  Coordination note: L5c's x87.c
 * owns the full tag/TOP state machine; until it lands, EMMS writes the
 * packed empty value directly. */
static int h_emms(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->ftag = 0xFFFFu;
    return sse_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

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
    i686_interp_register(I686_OP_UCOMISS, h_ucomiss);
    i686_interp_register(I686_OP_COMISS, h_comiss);
    i686_interp_register(I686_OP_MOVMSKPS, h_movmskps);
    i686_interp_register(I686_OP_ANDPS, h_andps);
    i686_interp_register(I686_OP_ANDNPS, h_andnps);
    i686_interp_register(I686_OP_ORPS, h_orps);
    i686_interp_register(I686_OP_XORPS, h_xorps);
    i686_interp_register(I686_OP_ADDPS, h_addps);
    i686_interp_register(I686_OP_MULPS, h_mulps);
    i686_interp_register(I686_OP_SUBPS, h_subps);
    i686_interp_register(I686_OP_DIVPS, h_divps);
    i686_interp_register(I686_OP_PUNPCKLBW, h_punpcklbw);
    i686_interp_register(I686_OP_PUNPCKLWD, h_punpcklwd);
    i686_interp_register(I686_OP_PUNPCKLDQ, h_punpckldq);
    i686_interp_register(I686_OP_PUNPCKHBW, h_punpckhbw);
    i686_interp_register(I686_OP_PUNPCKHWD, h_punpckhwd);
    i686_interp_register(I686_OP_PUNPCKHDQ, h_punpckhdq);
    i686_interp_register(I686_OP_PUNPCKLQDQ, h_punpcklqdq);
    i686_interp_register(I686_OP_PUNPCKHQDQ, h_punpckhqdq);
    i686_interp_register(I686_OP_PSHUFW, h_pshufw);
    i686_interp_register(I686_OP_CMPPS, h_cmpps);
    i686_interp_register(I686_OP_PADDQ, h_paddq);
    i686_interp_register(I686_OP_PMULLW, h_pmullw);
    i686_interp_register(I686_OP_PAND, h_pand);
    i686_interp_register(I686_OP_PANDN, h_pandn);
    i686_interp_register(I686_OP_POR, h_por);
    i686_interp_register(I686_OP_PXOR, h_pxor);
    i686_interp_register(I686_OP_PMULUDQ, h_pmuludq);
    i686_interp_register(I686_OP_PSUBD, h_psubd);
    i686_interp_register(I686_OP_PSUBQ, h_psubq);
    i686_interp_register(I686_OP_PADDD, h_paddd);
    i686_interp_register(I686_OP_MOVDQA, h_movdqa);
    i686_interp_register(I686_OP_MOVQ2DQ, h_movq2dq);
    i686_interp_register(I686_OP_MOVNTDQ, h_movntdq);
    i686_interp_register(I686_OP_PSRLDQ, h_pshiftdq);
    i686_interp_register(I686_OP_PCMPGTB, h_pcmp_gt8);
    i686_interp_register(I686_OP_PCMPEQB, h_pcmp_eq8);
    i686_interp_register(I686_OP_PCMPEQD, h_pcmp_eq32);
    i686_interp_register(I686_OP_PMOVMSKB, h_pmovmskb);
    i686_interp_register(I686_OP_PMINUB, h_pminub);
    i686_interp_register(I686_OP_PMAXUB, h_pmaxub);
    i686_interp_register(I686_OP_PSUBB, h_psubb);
    i686_interp_register(I686_OP_PREFETCH, h_prefetch);
    i686_interp_register(I686_OP_SFENCE, h_sfence);
    i686_interp_register(I686_OP_LDMXCSR, h_ldmxcsr);
    i686_interp_register(I686_OP_STMXCSR, h_stmxcsr);
    i686_interp_register(I686_OP_EMMS, h_emms);
}
