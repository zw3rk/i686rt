/*
 * src/interp/h_x87_internal.h — Internal helpers for x87 interpreter handlers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_INTERP_H_X87_INTERNAL_H
#define I686RT_INTERP_H_X87_INTERNAL_H

#include <float.h>
#include <math.h>
#include <string.h>

#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"
#include "interp/seg.h"
#include "interp/x87.h"
#include "interp/x87_80.h"
#include "x86/decode.h"

/* 0xFF "none" sentinel shared with the other handler modules (frozen
 * x86_insn_t convention; no named macro exists in the headers). */
#define X87_NONE 0xFFU

/* Status-word bit positions (x86): IE..PE 0..5, SF 6, ES 7, C0 8, C1 9,
 * C2 10, TOP 11..13, C3 14, B 15. */
#define SW_IE 0x01U
#define SW_DE 0x02U
#define SW_ZE 0x04U
#define SW_OE 0x08U
#define SW_UE 0x10U
#define SW_PE 0x20U
#define SW_C0 0x0100U
#define SW_C1 0x0200U
#define SW_C2 0x0400U
#define SW_C3 0x4000U
#define SW_CC_MASK (SW_C0 | SW_C1 | SW_C2 | SW_C3)
#define SW_SF 0x40U /* stack fault */
#define SW_ES 0x80U /* error summary */
#define SW_B 0x8000U /* FPU busy */
#define X87_SRC_EMPTY 1 /* x87_val_src: empty but masked (substitute) */

/* Shared epilogue: advance EIP, continue (frozen handler contract). */
static inline int done(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

/* Architecturally invalid / declined form: no state change, no EIP
 * advance (the UNDEF path delivers with the faulting EIP). */
static inline int undef_form(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)ctx;
    (void)insn;
    return I686_EXIT_UNDEF;
}

/* R7-31: checked push (x87.c): the destination tag is validated
 * before TOP moves.  Overflow sets IE + SF with C1=1; unmasked
 * records #MF and returns FAULT with state unchanged; masked
 * proceeds (circular stack). */
int x87_push_checked(i686_ctx_t *ctx);

/* R7-31: stack-operand validation.  Checks ST(i) BEFORE the op
 * reads it: nonempty returns CONTINUE.  Empty sets IE + SF with
 * C1=0; unmasked records #MF and returns FAULT (no state change);
 * masked returns X87_SRC_EMPTY so the caller substitutes the
 * indefinite operand (quiet NaN / x87_80_nan image) and runs on. */
static inline int x87_val_src(i686_ctx_t *ctx, unsigned i)
{
    extern void i686_fault_sig_record(int sig);
    unsigned p = ((unsigned)ctx->x87_top + i) & 7U;

    if ((((unsigned)ctx->ftag >> (p * 2U)) & 3U) != 3U) {
        return I686_INTERP_CONTINUE;
    }
    ctx->fstat = (uint16_t)((ctx->fstat | SW_IE | SW_SF) & ~SW_C1);
    if ((SW_IE & ~(unsigned)ctx->fctrl & 0x3fU) != 0U) {
        ctx->fstat = (uint16_t)(ctx->fstat | SW_ES | SW_B);
        ctx->exit_arg = 16U; /* #MF trapno */
        i686_fault_sig_record(8); /* SIGFPE */
        return I686_EXIT_FAULT;
    }
    return X87_SRC_EMPTY;
}

/* R7-31: stage the indefinite value in ST(i) WITHOUT touching
 * tags (the slot stays empty): the op below consumes it as its
 * masked-underflow operand, so NaN propagation yields the masked
 * response (indefinite result, unordered compare, indefinite
 * store) with no per-op substitute plumbing. */
static inline void x87_stage_indef(i686_ctx_t *ctx, unsigned i)
{
    unsigned p = ((unsigned)ctx->x87_top + i) & 7U;

    if (!ctx->x87_80) {
        double q = (double)NAN;

        memcpy(&ctx->x87_st[p][0], &q, 8);
    } else {
        x87_80_nan(&ctx->x87_st[p][0], false, false);
    }
}

/* R7-31: validate-and-stage one stack source.  Nonempty returns
 * CONTINUE.  Empty-masked stages the indefinite operand and
 * returns CONTINUE; empty-unmasked returns FAULT (no state change
 * beyond IE/SF).  Callers check each stack operand before reading:
 *   if (x87_src(ctx, i)) return I686_EXIT_FAULT; */
static inline int x87_src(i686_ctx_t *ctx, unsigned i)
{
    int v = x87_val_src(ctx, i);

    if (v == X87_SRC_EMPTY) {
        x87_stage_indef(ctx, i);
        return I686_INTERP_CONTINUE;
    }
    return v;
}

/* R7-31: post-helper check for void push paths (FILD): entry ES
 * is guaranteed clear by the dispatch checks, so a set ES means
 * the push just raised unmasked overflow (store inhibited
 * inside).  Returns FAULT with EIP at the instruction. */
static inline int x87_es_fault(i686_ctx_t *ctx)
{
    extern void i686_fault_sig_record(int sig);

    if ((ctx->fstat & SW_ES) == 0U) {
        return I686_INTERP_CONTINUE;
    }
    ctx->exit_arg = 16U; /* #MF trapno */
    i686_fault_sig_record(8); /* SIGFPE */
    return I686_EXIT_FAULT;
}

/* R7-30: FP-op marking for the interpreter's pending-#MF check
 * (owned by interp.c).  The x87 init functions register through
 * fp_reg so every FP/WAIT opcode carries the mark. */
void i686_interp_mark_fp(uint16_t op);

/* N3: no-wait control/save forms (defined in h_x87.c) that execute
 * despite a pending unmasked x87 exception. */
int i686_x87_is_nowait(const x86_insn_t *insn);

static inline void fp_reg(uint16_t op, i686_interp_fn fn)
{
    i686_interp_register(op, fn);
    i686_interp_mark_fp(op);
}

/* R7-30: raise-and-check.  Sets exc, then faults #MF (SIGFPE)
 * when an unmasked exception is pending — which the dispatch checks
 * (interp.c) keep clear at FP entry, so a set ES means this op just
 * raised one.  The caller places this BEFORE its store/pop and
 * returns the fault with EIP at the instruction (stores/pops
 * inhibited); masked status continues to done().  With exc == 0 it
 * is a pure post-computation check for value helpers (d_*) that set
 * status internally. */
static inline int x87_exc_raise(i686_ctx_t *ctx, unsigned exc)
{
    extern void i686_fault_sig_record(int sig);

    x87_set_exc(ctx, exc);
    if ((ctx->fstat & 0x80U) != 0U) {
        ctx->exit_arg = 16U; /* #MF trapno */
        i686_fault_sig_record(8); /* SIGFPE */
        return I686_EXIT_FAULT;
    }
    return I686_INTERP_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* Guest memory                                                        */
/* ------------------------------------------------------------------ */

static inline uint64_t mem_rd(i686_ctx_t *ctx, uint32_t va, unsigned bytes)
{
    const uint8_t *p = (const uint8_t *)i686_guest_ptr(ctx, va);
    uint64_t v = 0;

    for (unsigned i = 0; i < bytes; i++) {
        v |= (uint64_t)p[i] << (8U * i);
    }
    return v;
}

static inline void mem_wr(i686_ctx_t *ctx, uint32_t va, unsigned bytes, uint64_t v)
{
    uint8_t *p = (uint8_t *)i686_guest_ptr(ctx, va);

    for (unsigned i = 0; i < bytes; i++) {
        p[i] = (uint8_t)(v >> (8U * i));
    }
}

static inline float ld_f32(i686_ctx_t *ctx, uint32_t va)
{
    uint32_t b = (uint32_t)mem_rd(ctx, va, 4);
    float f;

    memcpy(&f, &b, 4);
    return f;
}

static inline double ld_f64(i686_ctx_t *ctx, uint32_t va)
{
    uint64_t b = mem_rd(ctx, va, 8);
    double d;

    memcpy(&d, &b, 8);
    return d;
}

/* R7-9: x87 memory operands honor segment limits like every other
 * access.  Computes the linear address and runs the LDT limit/type
 * and null-selector checks for the access width and direction (the
 * segment is the insn's override-aware segment, as in x86_rm_read).
 * Callers pass the full image width (FLDENV 14/28, FNSAVE 108,
 * FXSAVE 512). */
static inline uint32_t x87_ea_checked(i686_ctx_t *ctx, const x86_insn_t *insn,
                                      unsigned bytes, unsigned write)
{
    extern void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg,
                                    uint32_t linear, unsigned bytes,
                                    unsigned write);
    extern uint8_t x86_ea_seg(const x86_insn_t *insn);
    uint32_t va = x86_ea_compute(ctx, insn);

    i686_seg_check_data(ctx, x86_ea_seg(insn), va, bytes, write);
    return va;
}

/* ------------------------------------------------------------------ */
/* Condition codes                                                     */
/* ------------------------------------------------------------------ */

static inline void set_cc(i686_ctx_t *ctx, unsigned c0, unsigned c1, unsigned c2,
                          unsigned c3)
{
    ctx->fstat = (uint16_t)((ctx->fstat & ~SW_CC_MASK) |
                            (c0 ? SW_C0 : 0U) | (c1 ? SW_C1 : 0U) |
                            (c2 ? SW_C2 : 0U) | (c3 ? SW_C3 : 0U));
}

static inline void set_c2(i686_ctx_t *ctx, unsigned on)
{
    ctx->fstat = (uint16_t)((ctx->fstat & ~SW_C2) | (on ? SW_C2 : 0U));
}

/* FCOM encoding helper: a is ST(0)-side, b the other operand.  Returns
 * 1 if the comparison was unordered. */
static inline int cc_of_cmp(double a, double b, i686_ctx_t *ctx)
{
    if (isnan(a) || isnan(b)) {
        set_cc(ctx, 1, 0, 1, 1);
        return 1;
    }
    if (a > b) {
        set_cc(ctx, 0, 0, 0, 0);
    } else if (a < b) {
        set_cc(ctx, 1, 0, 0, 0);
    } else {
        set_cc(ctx, 0, 0, 0, 1);
    }
    return 0;
}

/* COM raises IE on any NaN; UCOM only on SNaN (R7-30: checked —
 * an unmasked raise faults, inhibiting the caller's pop). */
static inline int exc_ie_cmp(i686_ctx_t *ctx, double a, double b, int unordered,
                             bool ucom)
{
    if (!unordered) {
        return I686_INTERP_CONTINUE;
    }
    if (!ucom) {
        return x87_exc_raise(ctx, SW_IE);
    }
    {
        uint64_t ba, bb;

        memcpy(&ba, &a, 8);
        memcpy(&bb, &b, 8);
        if ((isnan(a) && (ba & 0x0007ffffffffffffULL) != 0U &&
             (ba & 0x0008000000000000ULL) == 0U) ||
            (isnan(b) && (bb & 0x0007ffffffffffffULL) != 0U &&
             (bb & 0x0008000000000000ULL) == 0U)) {
            return x87_exc_raise(ctx, SW_IE);
        }
    }
    return I686_INTERP_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* Default-mode double arithmetic with CW RC (exact-residual tricks)   */
/* ------------------------------------------------------------------ */

/* R7-39: all four rounding directions with exactness at zero.
 * err is the exact residual (true value = s + err, |err| < 1 ulp):
 * a nonzero err on the rounding side steps one ulp, otherwise s is
 * already correctly rounded.  Zero is signed: +tiny rounds to +0.0
 * or -0.0 according to direction, never across the zero. */
static inline double d_round_rc(i686_ctx_t *ctx, double s, double err)
{
    unsigned rc = x87_round_mode(ctx);

    if (err == 0.0 || isnan(s) || isinf(s)) {
        return s;
    }
    if (rc == 1U) {
        /* Toward -inf: a low true value steps down (this also
         * carries +0.0 to -0.0); a high true value landing on
         * -0.0 steps up to +0.0. */
        if (err < 0.0) {
            return nextafter(s, -INFINITY);
        }
        if (err > 0.0 && s == 0.0 && signbit(s) != 0) {
            return nextafter(s, INFINITY);
        }
        return s;
    }
    if (rc == 2U) {
        /* Toward +inf: mirror image (+0.0 with a low true value
         * steps down to -0.0). */
        if (err > 0.0) {
            return nextafter(s, INFINITY);
        }
        if (err < 0.0 && s == 0.0 && signbit(s) == 0) {
            return nextafter(s, -INFINITY);
        }
        return s;
    }
    if (rc == 3U) {
        /* Toward zero, signed by signbit so +tiny truncates to
         * +0.0 and -tiny to -0.0. */
        if (signbit(s) == 0) {
            if (err < 0.0) {
                return nextafter(s, -INFINITY);
            }
        } else if (err > 0.0) {
            return nextafter(s, INFINITY);
        }
        return s;
    }
    return s; /* rc == 0: the host already rounds to nearest-even */
}

/* Quiet-bit test for a double SNaN (mirrors the UCOM branch of
 * exc_ie_cmp below). */
static inline int d_is_snan(double d)
{
    uint64_t bits;

    memcpy(&bits, &d, 8);
    return isnan(d) && (bits & 0x0007ffffffffffffULL) != 0U &&
           (bits & 0x0008000000000000ULL) == 0U;
}

static inline void d_exc(i686_ctx_t *ctx, double a, double b, double s, double err)
{
    if (isnan(s)) {
        /* R7-44: a NaN result is invalid when an input signals
         * (SNaN) or when no input is NaN at all (Inf-Inf, Inf*0,
         * Inf/Inf); quiet inputs propagate without IE. */
        if (d_is_snan(a) || d_is_snan(b) || (!isnan(a) && !isnan(b))) {
            x87_set_exc(ctx, SW_IE);
        }
        return;
    }
    if (err != 0.0) {
        x87_set_exc(ctx, SW_PE);
    }
    if (isinf(s) && !isinf(a) && !isinf(b)) {
        x87_set_exc(ctx, SW_OE | SW_PE);
    }
    if (s != 0.0 && !isinf(s) && fabs(s) < (double)FLT_MIN && err != 0.0) {
        x87_set_exc(ctx, SW_UE);
    }
}

static inline double d_add(i686_ctx_t *ctx, double a, double b)
{
    double s = a + b;
    double t = s - a;
    double err = (a - (s - t)) + (b - t); /* exact (Knuth two-sum) */
    double r = d_round_rc(ctx, s, err);

    d_exc(ctx, a, b, s, err);
    return r;
}

static inline double d_sub(i686_ctx_t *ctx, double a, double b)
{
    double s = a - b;
    double t = s - a;
    double err = (a - (s - t)) - (b + t);
    double r = d_round_rc(ctx, s, err);

    d_exc(ctx, a, b, s, err);
    return r;
}

static inline double d_mul(i686_ctx_t *ctx, double a, double b)
{
    double s = a * b;
    double err = (isfinite(a) && isfinite(b)) ? fma(a, b, -s) : 0.0;
    double r = d_round_rc(ctx, s, err);

    d_exc(ctx, a, b, s, err);
    return r;
}

static inline double d_div(i686_ctx_t *ctx, double a, double b)
{
    double s = a / b;
    double err;

    /* N4: only a finite nonzero dividend over zero is zero-divide
     * (signed infinity + ZE).  0/0 is invalid (indefinite QNaN + IE);
     * Inf/Inf falls through to the quiet-NaN path below (IE via
     * d_exc); ±Inf/0 is exact signed infinity with NO flags. */
    if (b == 0.0 && !isnan(a) && !isinf(a)) {
        if (a == 0.0) {
            x87_set_exc(ctx, SW_IE);
            return (double)NAN;
        }
        x87_set_exc(ctx, SW_ZE);
        return copysign(HUGE_VAL, copysign(1.0, a) * copysign(1.0, b));
    }
    err = (isfinite(a) && isfinite(b) && !isinf(s)) ? fma(-s, b, a) : 0.0;
    {
        double r = d_round_rc(ctx, s, err);

        d_exc(ctx, a, b, s, err);
        return r;
    }
}

/* ------------------------------------------------------------------ */
/* Operation kinds shared by the D8/DC/DE arith dispatch               */
/* ------------------------------------------------------------------ */

enum { K_ADD, K_MUL, K_SUB, K_SUBR, K_DIV, K_DIVR };

static inline double dcalc(i686_ctx_t *ctx, unsigned kind, double a, double b)
{
    switch (kind) {
    case K_ADD:
        return d_add(ctx, a, b);
    case K_MUL:
        return d_mul(ctx, a, b);
    case K_SUB:
        return d_sub(ctx, a, b);
    case K_SUBR:
        return d_sub(ctx, b, a);
    case K_DIV:
        return d_div(ctx, a, b);
    default:
        return d_div(ctx, b, a);
    }
}

/* Point the x87_80 core at the current CW before a computational op. */
static inline void x80_set_mode(i686_ctx_t *ctx, int computational)
{
    (void)x87_80_set_round(x87_round_mode(ctx));
    if (computational) {
        (void)x87_80_set_prec(x87_prec_mode(ctx));
    }
}

static inline unsigned x80calc(i686_ctx_t *ctx, unsigned kind, uint8_t out[10],
                               const uint8_t a[10], const uint8_t b[10])
{
    x80_set_mode(ctx, 1);
    switch (kind) {
    case K_ADD:
        return x87_80_add(out, a, b);
    case K_MUL:
        return x87_80_mul(out, a, b);
    case K_SUB:
        return x87_80_sub(out, a, b);
    case K_SUBR:
        return x87_80_sub(out, b, a);
    case K_DIV:
        return x87_80_div(out, a, b);
    default:
        return x87_80_div(out, b, a);
    }
}

/* ------------------------------------------------------------------ */
/* Loads / stores                                                      */
/* ------------------------------------------------------------------ */

/* R7-31: checked pushes (overflow validated before TOP moves;
 * the caller returns the fault with EIP at the instruction). */
static inline int push_f32(i686_ctx_t *ctx, float f)
{
    if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT;
    }
    if (ctx->x87_80) {
        uint8_t b[10];

        x87_80_from_f32(b, f);
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, (double)f);
    }
    return I686_INTERP_CONTINUE;
}

static inline int push_f64(i686_ctx_t *ctx, double d)
{
    if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT;
    }
    if (ctx->x87_80) {
        uint8_t b[10];

        x87_80_from_f64(b, d);
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, d);
    }
    return I686_INTERP_CONTINUE;
}

static inline void push_int(i686_ctx_t *ctx, int64_t v)
{
    x87_set_int(ctx, v);
}

/* CW-RC-aware double -> float for FST m32 (default mode). */
/* R7-39: directed float32 conversion with exactness at zero
 * (+tiny truncates to +0.0, not +denormal; -tiny to -0.0). */
static inline float d_to_f32_rc(i686_ctx_t *ctx, double d)
{
    float f = (float)d;
    unsigned rc = x87_round_mode(ctx);

    if (isnan(d) || isinf(d)) {
        return f;
    }
    if (rc == 1U) {
        if ((double)f > d) {
            f = nextafterf(f, -INFINITY);
        }
    } else if (rc == 2U) {
        if ((double)f < d) {
            f = nextafterf(f, INFINITY);
        }
    } else if (rc == 3U) {
        if (signbit(d) == 0) {
            if ((double)f > d) {
                f = nextafterf(f, -INFINITY);
            }
        } else if ((double)f < d) {
            f = nextafterf(f, INFINITY);
        }
    }
    return f;
}

/* R7-30: checked (an unmasked raise inhibits the memory store;
 * the caller inhibits its pop on a fault return). */
static inline int st_f32(i686_ctx_t *ctx, uint32_t va)
{
    float f;

    if (ctx->x87_80) {
        uint8_t b[10];
        unsigned exc;

        x80_set_mode(ctx, 0);
        x87_get_ext80(ctx, 0, b);
        exc = x87_80_to_f32(b, &f);
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return I686_EXIT_FAULT;
        }
    } else {
        f = d_to_f32_rc(ctx, x87_get_f64(ctx, 0));
    }
    {
        uint32_t bits;

        memcpy(&bits, &f, 4);
        mem_wr(ctx, va, 4, bits);
    }
    return I686_INTERP_CONTINUE;
}

/* R7-30: checked, as above. */
static inline int st_f64(i686_ctx_t *ctx, uint32_t va)
{
    double d;

    if (ctx->x87_80) {
        uint8_t b[10];
        unsigned exc;

        x80_set_mode(ctx, 0);
        x87_get_ext80(ctx, 0, b);
        exc = x87_80_to_f64(b, &d);
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return I686_EXIT_FAULT;
        }
    } else {
        d = x87_get_f64(ctx, 0);
    }
    {
        uint64_t bits;

        memcpy(&bits, &d, 8);
        mem_wr(ctx, va, 8, bits);
    }
    return I686_INTERP_CONTINUE;
}

static inline void st_m80(i686_ctx_t *ctx, uint32_t va)
{
    uint8_t b[10];

    x87_get_ext80(ctx, 0, b);
    for (unsigned i = 0; i < 10; i++) {
        mem_wr(ctx, va + i, 1, b[i]);
    }
}

/* R7-26: status-returning conversion (x87.c; kept out of frozen
 * x87.h).  Narrow-width overflow is detected here so FIST m16/m32 of
 * an out-of-range value stores the indefinite integer with IE. */
int64_t x87_get_int_exc(const i686_ctx_t *ctx, unsigned i, unsigned rc,
                        unsigned *exc);

static inline int st_int_checked(i686_ctx_t *ctx, uint32_t va,
                                  unsigned bytes, unsigned rc)
{
    unsigned exc;
    int64_t v = x87_get_int_exc(ctx, 0, rc, &exc);
    uint64_t out;

    if (bytes == 2) {
        if (v < -32768 || v > 32767) {
            out = 0x8000U;
            exc |= SW_IE;
        } else {
            out = (uint64_t)v & 0xffffU;
        }
    } else if (bytes == 4) {
        if (v < -2147483648LL || v > 2147483647LL) {
            out = 0x80000000U;
            exc |= SW_IE;
        } else {
            out = (uint64_t)v & 0xffffffffU;
        }
    } else {
        out = (uint64_t)v;
    }
    /* R7-30: an unmasked raise inhibits the memory store. */
    if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT;
    }
    mem_wr(ctx, va, bytes, out);
    return I686_INTERP_CONTINUE;
}

static inline int st_int(i686_ctx_t *ctx, uint32_t va, unsigned bytes)
{
    return st_int_checked(ctx, va, bytes, x87_round_mode(ctx));
}

static inline int st_int_trunc(i686_ctx_t *ctx, uint32_t va, unsigned bytes)
{
    return st_int_checked(ctx, va, bytes, 3U);
}

static inline void img_wr16(uint8_t *img, unsigned off, uint16_t v)
{
    img[off] = (uint8_t)v;
    img[off + 1] = (uint8_t)(v >> 8);
}

static inline void img_wr32(uint8_t *img, unsigned off, uint32_t v)
{
    img[off] = (uint8_t)v;
    img[off + 1] = (uint8_t)(v >> 8);
    img[off + 2] = (uint8_t)(v >> 16);
    img[off + 3] = (uint8_t)(v >> 24);
}

static inline uint16_t img_rd16(const uint8_t *img, unsigned off)
{
    return (uint16_t)((uint16_t)img[off] | ((uint16_t)img[off + 1] << 8));
}

static inline uint32_t img_rd32(const uint8_t *img, unsigned off)
{
    return (uint32_t)img[off] | ((uint32_t)img[off + 1] << 8) |
           ((uint32_t)img[off + 2] << 16) | ((uint32_t)img[off + 3] << 24);
}

/* Cross-TU helpers in h_x87_math.c */
void i686_x87_op_fchs(i686_ctx_t *ctx);
void i686_x87_op_fabs(i686_ctx_t *ctx);
int i686_x87_op_ftst(i686_ctx_t *ctx); /* R7-30: checked */
void i686_x87_op_fxam(i686_ctx_t *ctx);
int i686_x87_op_fld_const(i686_ctx_t *ctx, unsigned rm); /* R7-31 */
void i686_x87_op_fsin(i686_ctx_t *ctx, int is_cos);
void i686_x87_op_fsincos(i686_ctx_t *ctx);
void i686_x87_op_fsqrt(i686_ctx_t *ctx);
void i686_x87_op_frndint(i686_ctx_t *ctx);
void i686_x87_op_fnstenv(i686_ctx_t *ctx, uint32_t va, unsigned op16);
void i686_x87_op_fldenv(i686_ctx_t *ctx, uint32_t va, unsigned op16);
void i686_x87_op_fxsave(i686_ctx_t *ctx, uint32_t va);
void i686_x87_op_fxrstor(i686_ctx_t *ctx, uint32_t va);
void i686_x87_op_fnsave(i686_ctx_t *ctx, uint32_t va, unsigned op16);
void i686_x87_op_frstor(i686_ctx_t *ctx, uint32_t va, unsigned op16);
void i686_x87_op_f2xm1(i686_ctx_t *ctx);
void i686_x87_op_fyl2x(i686_ctx_t *ctx, int p1);
void i686_x87_op_fptan(i686_ctx_t *ctx);
void i686_x87_op_fpatan(i686_ctx_t *ctx);
void i686_x87_op_fxtract(i686_ctx_t *ctx);
void i686_x87_op_fscale(i686_ctx_t *ctx);
void i686_x87_op_fprem(i686_ctx_t *ctx, int ieee);

/* Cross-TU helpers in h_x87_arith.c */
void i686_interp_x87_init_arith(void);

#endif /* I686RT_INTERP_H_X87_INTERNAL_H */
