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

/* COM raises IE on any NaN; UCOM only on SNaN (v1 flag discipline; no
 * traps are delivered). */
static inline void exc_ie_cmp(i686_ctx_t *ctx, double a, double b, int unordered,
                              bool ucom)
{
    if (!unordered) {
        return;
    }
    if (!ucom) {
        x87_set_exc(ctx, SW_IE);
        return;
    }
    {
        uint64_t ba, bb;

        memcpy(&ba, &a, 8);
        memcpy(&bb, &b, 8);
        if ((isnan(a) && (ba & 0x0007ffffffffffffULL) != 0U &&
             (ba & 0x0008000000000000ULL) == 0U) ||
            (isnan(b) && (bb & 0x0007ffffffffffffULL) != 0U &&
             (bb & 0x0008000000000000ULL) == 0U)) {
            x87_set_exc(ctx, SW_IE);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Default-mode double arithmetic with CW RC (exact-residual tricks)   */
/* ------------------------------------------------------------------ */

static inline double d_round_rc(i686_ctx_t *ctx, double s, double err)
{
    unsigned rc = x87_round_mode(ctx);

    if (err == 0.0 || isnan(s) || isinf(s)) {
        return s;
    }
    if (rc == 1U && err < 0.0) {
        return nextafter(s, -INFINITY);
    }
    if (rc == 2U && err > 0.0) {
        return nextafter(s, INFINITY);
    }
    if (rc == 3U) {
        if (s > 0.0 && err < 0.0) {
            return nextafter(s, -INFINITY);
        }
        if (s < 0.0 && err > 0.0) {
            return nextafter(s, INFINITY);
        }
    }
    return s;
}

static inline void d_exc(i686_ctx_t *ctx, double a, double b, double s, double err)
{
    if (isnan(s)) {
        if (isnan(a) || isnan(b)) {
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

    if (b == 0.0 && !isnan(a)) {
        x87_set_exc(ctx, SW_ZE);
        if (a == 0.0 || isinf(a)) {
            x87_set_exc(ctx, SW_IE);
        }
        return a == 0.0 ? (double)NAN : copysign(HUGE_VAL, copysign(1.0, a) *
                                                           copysign(1.0, b));
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

static inline void push_f32(i686_ctx_t *ctx, float f)
{
    x87_push(ctx);
    if (ctx->x87_80) {
        uint8_t b[10];

        x87_80_from_f32(b, f);
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, (double)f);
    }
}

static inline void push_f64(i686_ctx_t *ctx, double d)
{
    x87_push(ctx);
    if (ctx->x87_80) {
        uint8_t b[10];

        x87_80_from_f64(b, d);
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, d);
    }
}

static inline void push_int(i686_ctx_t *ctx, int64_t v)
{
    x87_set_int(ctx, v);
}

/* CW-RC-aware double -> float for FST m32 (default mode). */
static inline float d_to_f32_rc(i686_ctx_t *ctx, double d)
{
    float f = (float)d;
    unsigned rc = x87_round_mode(ctx);

    if (rc == 1U) {
        if ((double)f > d) {
            f = nextafterf(f, -INFINITY);
        }
    } else if (rc == 2U) {
        if ((double)f < d) {
            f = nextafterf(f, INFINITY);
        }
    } else if (rc == 3U) {
        if ((double)f > d) {
            f = nextafterf(f, -INFINITY);
        } else if ((double)f < d) {
            f = nextafterf(f, INFINITY);
        }
    }
    return f;
}

static inline void st_f32(i686_ctx_t *ctx, uint32_t va)
{
    float f;

    if (ctx->x87_80) {
        uint8_t b[10];
        unsigned exc;

        x80_set_mode(ctx, 0);
        x87_get_ext80(ctx, 0, b);
        exc = x87_80_to_f32(b, &f);
        x87_set_exc(ctx, exc);
    } else {
        f = d_to_f32_rc(ctx, x87_get_f64(ctx, 0));
    }
    {
        uint32_t bits;

        memcpy(&bits, &f, 4);
        mem_wr(ctx, va, 4, bits);
    }
}

static inline void st_f64(i686_ctx_t *ctx, uint32_t va)
{
    double d;

    if (ctx->x87_80) {
        uint8_t b[10];
        unsigned exc;

        x80_set_mode(ctx, 0);
        x87_get_ext80(ctx, 0, b);
        exc = x87_80_to_f64(b, &d);
        x87_set_exc(ctx, exc);
    } else {
        d = x87_get_f64(ctx, 0);
    }
    {
        uint64_t bits;

        memcpy(&bits, &d, 8);
        mem_wr(ctx, va, 8, bits);
    }
}

static inline void st_m80(i686_ctx_t *ctx, uint32_t va)
{
    uint8_t b[10];

    x87_get_ext80(ctx, 0, b);
    for (unsigned i = 0; i < 10; i++) {
        mem_wr(ctx, va + i, 1, b[i]);
    }
}

static inline void st_int(i686_ctx_t *ctx, uint32_t va, unsigned bytes)
{
    int64_t v = x87_get_int(ctx, 0);
    uint64_t out;

    if (bytes == 2) {
        out = (v < -32768 || v > 32767) ? 0x8000U : (uint64_t)v & 0xffffU;
    } else if (bytes == 4) {
        out = (v < -2147483648LL || v > 2147483647LL) ? 0x80000000U
                                                      : (uint64_t)v & 0xffffffffU;
    } else {
        out = (uint64_t)v;
    }
    mem_wr(ctx, va, bytes, out);
}

static inline void st_int_trunc(i686_ctx_t *ctx, uint32_t va, unsigned bytes)
{
    int64_t v = x87_get_int_trunc(ctx, 0);
    uint64_t out;

    if (bytes == 2) {
        out = (v < -32768 || v > 32767) ? 0x8000U : (uint64_t)v & 0xffffU;
    } else if (bytes == 4) {
        out = (v < -2147483648LL || v > 2147483647LL) ? 0x80000000U
                                                      : (uint64_t)v & 0xffffffffU;
    } else {
        out = (uint64_t)v;
    }
    mem_wr(ctx, va, bytes, out);
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
void i686_x87_op_ftst(i686_ctx_t *ctx);
void i686_x87_op_fxam(i686_ctx_t *ctx);
void i686_x87_op_fld_const(i686_ctx_t *ctx, unsigned rm);
void i686_x87_op_fsin(i686_ctx_t *ctx, int is_cos);
void i686_x87_op_fsincos(i686_ctx_t *ctx);
void i686_x87_op_fsqrt(i686_ctx_t *ctx);
void i686_x87_op_frndint(i686_ctx_t *ctx);
void i686_x87_op_fnstenv(i686_ctx_t *ctx, uint32_t va);
void i686_x87_op_fldenv(i686_ctx_t *ctx, uint32_t va);
void i686_x87_op_fxsave(i686_ctx_t *ctx, uint32_t va);
void i686_x87_op_fxrstor(i686_ctx_t *ctx, uint32_t va);
void i686_x87_op_fnsave(i686_ctx_t *ctx, uint32_t va);
void i686_x87_op_frstor(i686_ctx_t *ctx, uint32_t va);
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
