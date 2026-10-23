/*
 * src/interp/h_x87.c — x87/MMX-state interpreter handlers (Phase 5 L5c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Registers the Phase 5 x87 opcode set (D8-DF groups + 0F 77 EMMS +
 * 0F AE /0-/1 FXSAVE/FXRSTOR, see tools/gen_insn_tab.py) into the frozen
 * interpreter registry.  The group mechanism resolves the modrm reg
 * field to one id per /digit; the mod bit (memory vs ST(i)) and, for the
 * fixed D9/DB/DF second-byte forms, the rm field are sub-dispatched HERE
 * because the frozen one-id-per-(byte,reg) table cannot express the full
 * x87 escape map.  Declined modrm forms (FIADD-class memory, FBLD/FBSTP,
 * undefined second bytes) return I686_EXIT_UNDEF (D2: never assert).
 *
 * Modes (fixed per process, ctx->x87_80, SPEC D9):
 *  - default: double arithmetic through x87_get_f64/x87_set_f64.  CW RC
 *    is applied with exact-residual tricks (Knuth two-sum for add/sub,
 *    fma residuals for mul/div, then a single nextafter step), so
 *    directed rounding matches bit-exact double semantics.  CW PC is
 *    NOT applied in this mode: every value is a double (53-bit) anyway;
 *    PC matters only for the f2xm1-class on 64-bit mantissas, i.e. only
 *    in --x87-80 (documented deviation; the oracle tier L5E exercises
 *    exactly this).
 *  - --x87-80: arithmetic goes through the frozen x87_80 extended core
 *    (x87_80_set_round/set_prec first, exception bits collected into
 *    the status word via x87_set_exc).
 *
 * FPU instruction/data pointers (fpu_ip/fpu_dp/fop) stay 0 in v1; env
 * stores (fnstenv/fxsave) save the ctx fields as they are.
 *
 * This module's init (i686_interp_x87_init) is exported for the
 * coordinator's S5 wiring into i686_interp_init_all (same pattern as the
 * SSE lane): interp.h's frozen declaration list is not edited here.
 */

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
static int done(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

/* FCOMI family (defined below; DB/DF slot handlers call it). */
static int do_fcomi(i686_ctx_t *ctx, const x86_insn_t *insn, int pop);

/* Architecturally invalid / declined form: no state change, no EIP
 * advance (the UNDEF path delivers with the faulting EIP). */
static int undef_form(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)ctx;
    (void)insn;
    return I686_EXIT_UNDEF;
}

/* ------------------------------------------------------------------ */
/* Guest memory                                                        */
/* ------------------------------------------------------------------ */

static uint64_t mem_rd(i686_ctx_t *ctx, uint32_t va, unsigned bytes)
{
    const uint8_t *p = (const uint8_t *)i686_guest_ptr(ctx, va);
    uint64_t v = 0;

    for (unsigned i = 0; i < bytes; i++) {
        v |= (uint64_t)p[i] << (8U * i);
    }
    return v;
}

static void mem_wr(i686_ctx_t *ctx, uint32_t va, unsigned bytes, uint64_t v)
{
    uint8_t *p = (uint8_t *)i686_guest_ptr(ctx, va);

    for (unsigned i = 0; i < bytes; i++) {
        p[i] = (uint8_t)(v >> (8U * i));
    }
}

static float ld_f32(i686_ctx_t *ctx, uint32_t va)
{
    uint32_t b = (uint32_t)mem_rd(ctx, va, 4);
    float f;

    memcpy(&f, &b, 4);
    return f;
}

static double ld_f64(i686_ctx_t *ctx, uint32_t va)
{
    uint64_t b = mem_rd(ctx, va, 8);
    double d;

    memcpy(&d, &b, 8);
    return d;
}

/* ------------------------------------------------------------------ */
/* Condition codes                                                     */
/* ------------------------------------------------------------------ */

static void set_cc(i686_ctx_t *ctx, unsigned c0, unsigned c1, unsigned c2,
                   unsigned c3)
{
    ctx->fstat = (uint16_t)((ctx->fstat & ~SW_CC_MASK) |
                            (c0 ? SW_C0 : 0U) | (c1 ? SW_C1 : 0U) |
                            (c2 ? SW_C2 : 0U) | (c3 ? SW_C3 : 0U));
}

static void set_c2(i686_ctx_t *ctx, unsigned on)
{
    ctx->fstat = (uint16_t)((ctx->fstat & ~SW_C2) | (on ? SW_C2 : 0U));
}

/* FCOM encoding helper: a is ST(0)-side, b the other operand.  Returns
 * 1 if the comparison was unordered. */
static int cc_of_cmp(double a, double b, i686_ctx_t *ctx)
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
static void exc_ie_cmp(i686_ctx_t *ctx, double a, double b, int unordered,
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

/* One directed-adjust step: s is the nearest-even double result, err the
 * EXACT residual (s + err == infinitely precise result), so the directed
 * neighbours differ by at most one ulp. */
static double d_round_rc(i686_ctx_t *ctx, double s, double err)
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

static void d_exc(i686_ctx_t *ctx, double a, double b, double s, double err)
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

static double d_add(i686_ctx_t *ctx, double a, double b)
{
    double s = a + b;
    double t = s - a;
    double err = (a - (s - t)) + (b - t); /* exact (Knuth two-sum) */
    double r = d_round_rc(ctx, s, err);

    d_exc(ctx, a, b, s, err);
    return r;
}

static double d_sub(i686_ctx_t *ctx, double a, double b)
{
    double s = a - b;
    double t = s - a;
    double err = (a - (s - t)) - (b + t);
    double r = d_round_rc(ctx, s, err);

    d_exc(ctx, a, b, s, err);
    return r;
}

static double d_mul(i686_ctx_t *ctx, double a, double b)
{
    double s = a * b;
    double err = (isfinite(a) && isfinite(b)) ? fma(a, b, -s) : 0.0;
    double r = d_round_rc(ctx, s, err);

    d_exc(ctx, a, b, s, err);
    return r;
}

static double d_div(i686_ctx_t *ctx, double a, double b)
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

static double dcalc(i686_ctx_t *ctx, unsigned kind, double a, double b)
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
static void x80_set_mode(i686_ctx_t *ctx, int computational)
{
    (void)x87_80_set_round(x87_round_mode(ctx));
    if (computational) {
        (void)x87_80_set_prec(x87_prec_mode(ctx));
    }
}

static unsigned x80calc(i686_ctx_t *ctx, unsigned kind, uint8_t out[10],
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
/* D8 / DC / DE arithmetic + compare                                   */
/* ------------------------------------------------------------------ */

/* D8 (m32) and DC (m64) /digit arithmetic.  Memory form: ST(0) op= mem.
 * Register form: D8 does ST(0) op= ST(rm); DC does ST(rm) op= ST(0)
 * with SUB/SUBR and DIV/DIVR swapped relative to the memory letter
 * (SDM DC C0+/E0+ families).  DE pop forms ride arith_de. */
static int arith_d8dc(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned kind,
                      unsigned mbytes)
{
    unsigned reg = insn->modrm_mod == 3U;
    unsigned k = kind;
    unsigned dst = 0;

    if (reg && mbytes == 8) {
        dst = insn->modrm_rm;
        if (kind == K_SUB) {
            k = K_SUBR;
        } else if (kind == K_SUBR) {
            k = K_SUB;
        } else if (kind == K_DIV) {
            k = K_DIVR;
        } else if (kind == K_DIVR) {
            k = K_DIV;
        }
    }
    if (!ctx->x87_80) {
        double a;
        double b;
        double r;

        if (reg) {
            if (mbytes == 4) {
                a = x87_get_f64(ctx, 0);
                b = x87_get_f64(ctx, insn->modrm_rm);
            } else {
                a = x87_get_f64(ctx, insn->modrm_rm);
                b = x87_get_f64(ctx, 0);
            }
        } else {
            uint32_t va = x86_ea_compute(ctx, insn);
            a = x87_get_f64(ctx, 0);
            b = (mbytes == 4) ? (double)ld_f32(ctx, va) : ld_f64(ctx, va);
        }
        r = dcalc(ctx, k, a, b);
        x87_set_f64(ctx, dst, r);
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        uint8_t r[10];
        unsigned exc;

        if (reg) {
            if (mbytes == 4) {
                x87_get_ext80(ctx, 0, sa);
                x87_get_ext80(ctx, insn->modrm_rm, sb);
            } else {
                x87_get_ext80(ctx, insn->modrm_rm, sa);
                x87_get_ext80(ctx, 0, sb);
            }
        } else {
            uint32_t va = x86_ea_compute(ctx, insn);
            x87_get_ext80(ctx, 0, sa);
            if (mbytes == 4) {
                x87_80_from_f32(sb, ld_f32(ctx, va));
            } else {
                x87_80_from_f64(sb, ld_f64(ctx, va));
            }
        }
        exc = x80calc(ctx, k, r, sa, sb);
        x87_set_ext80(ctx, dst, r);
        x87_set_exc(ctx, exc);
    }
    return done(ctx, insn);
}

/* DE C0+/C8+/E0+/E8+/F0+/F8+: ST(rm) op= ST(0), then pop.  The memory
 * FIADD-class forms are declined (return UNDEF). */
static int arith_de(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned kind)
{
    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn); /* FIADD/FIMUL/FISUB/FIDIV declined */
    }
    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, insn->modrm_rm);
        double b = x87_get_f64(ctx, 0);
        double r = dcalc(ctx, kind, a, b);

        x87_set_f64(ctx, insn->modrm_rm, r);
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        uint8_t r[10];
        unsigned exc;

        x87_get_ext80(ctx, insn->modrm_rm, sa);
        x87_get_ext80(ctx, 0, sb);
        exc = x80calc(ctx, kind, r, sa, sb);
        x87_set_ext80(ctx, insn->modrm_rm, r);
        x87_set_exc(ctx, exc);
    }
    x87_pop(ctx);
    return done(ctx, insn);
}

/* FCOM/FCOMP with an m32/m64/ST(rm) source. */
static int do_fcom(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned mbytes,
                   int pop)
{
    int un;

    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b;

        if (insn->modrm_mod == 3U) {
            b = x87_get_f64(ctx, insn->modrm_rm);
        } else {
            uint32_t va = x86_ea_compute(ctx, insn);
            b = (mbytes == 4) ? (double)ld_f32(ctx, va) : ld_f64(ctx, va);
        }
        un = cc_of_cmp(a, b, ctx);
        exc_ie_cmp(ctx, a, b, un, false);
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        if (insn->modrm_mod == 3U) {
            x87_get_ext80(ctx, insn->modrm_rm, sb);
        } else {
            uint32_t va = x86_ea_compute(ctx, insn);
            if (mbytes == 4) {
                x87_80_from_f32(sb, ld_f32(ctx, va));
            } else {
                x87_80_from_f64(sb, ld_f64(ctx, va));
            }
        }
        x87_80_fcom(sa, sb, false, &c3, &c2, &c0);
        set_cc(ctx, c0, 0, c2, c3);
        if (c0 && c2 && c3) {
            /* FCOM (ordered): any NaN raises IE. */
            x87_set_exc(ctx, SW_IE);
        }
    }
    if (pop) {
        x87_pop(ctx);
    }
    return done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Loads / stores                                                      */
/* ------------------------------------------------------------------ */

static void push_f32(i686_ctx_t *ctx, float f)
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

static void push_f64(i686_ctx_t *ctx, double d)
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

static void push_int(i686_ctx_t *ctx, int64_t v)
{
    x87_set_int(ctx, v);
}

/* CW-RC-aware double -> float for FST m32 (default mode). */
static float d_to_f32_rc(i686_ctx_t *ctx, double d)
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

static void st_f32(i686_ctx_t *ctx, uint32_t va)
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

static void st_f64(i686_ctx_t *ctx, uint32_t va)
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

static void st_m80(i686_ctx_t *ctx, uint32_t va)
{
    uint8_t b[10];

    x87_get_ext80(ctx, 0, b);
    for (unsigned i = 0; i < 10; i++) {
        mem_wr(ctx, va + i, 1, b[i]);
    }
}

/* Integer store per CW RC via the state core (mode-aware); truncates to
 * the memory width with the x87 integer indefinite on overflow. */
static void st_int(i686_ctx_t *ctx, uint32_t va, unsigned bytes)
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

/* DD /4 memory form (FRSTOR, defined in the state-image section). */
static void op_frstor(i686_ctx_t *ctx, uint32_t va);

/* FISTTP (SSE3, RC7b T4b): same width clamping as st_int but the
 * conversion ALWAYS truncates toward zero (CW RC ignored). */
static void st_int_trunc(i686_ctx_t *ctx, uint32_t va, unsigned bytes)
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

/* ------------------------------------------------------------------ */
/* Unary / transcendental ops (both modes)                             */
/* ------------------------------------------------------------------ */

static void op_fchs(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t b[10];

        x87_get_ext80(ctx, 0, b);
        b[9] ^= 0x80U;
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, -x87_get_f64(ctx, 0));
    }
}

static void op_fabs(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t b[10];

        x87_get_ext80(ctx, 0, b);
        b[9] &= 0x7fU;
        x87_set_ext80(ctx, 0, b);
    } else {
        x87_set_f64(ctx, 0, fabs(x87_get_f64(ctx, 0)));
    }
}

static void op_ftst(i686_ctx_t *ctx)
{
    int un;

    if (ctx->x87_80) {
        uint8_t sa[10];
        uint8_t z[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        x87_80_zero(z);
        x87_80_fcom(sa, z, false, &c3, &c2, &c0);
        set_cc(ctx, c0, 0, c2, c3);
        un = (c0 && c2 && c3);
    } else {
        double a = x87_get_f64(ctx, 0);
        double z = 0.0;

        un = cc_of_cmp(a, z, ctx);
    }
    if (un) {
        x87_set_exc(ctx, SW_IE);
    }
}

/* FXAM class table (C3 C2 C0, sign in C1): unsupported 000, NaN 001,
 * normal 010, infinity 011, zero 100, empty 101, denormal 110. */
static void op_fxam(i686_ctx_t *ctx)
{
    unsigned c3 = 0;
    unsigned c2 = 0;
    unsigned c0 = 0;
    unsigned c1;
    unsigned empty;
    unsigned phys = (unsigned)x87_top(ctx);

    empty = ((ctx->ftag >> (phys * 2U)) & 3U) == 3U;
    if (ctx->x87_80) {
        uint8_t b[10];
        uint16_t se;
        uint64_t m;

        x87_get_ext80(ctx, 0, b);
        m = 0;
        for (unsigned i = 0; i < 8; i++) {
            m |= (uint64_t)b[i] << (8U * i);
        }
        se = (uint16_t)((uint16_t)b[8] | ((uint16_t)b[9] << 8));
        c1 = (se >> 15) & 1U;
        {
            unsigned e = se & 0x7fffU;

            if (empty) {
                c3 = 1;
                c2 = 0;
                c0 = 1;
            } else if (e == 0x7fffU) {
                if (m == 0x8000000000000000ULL) {
                    c3 = 0;
                    c2 = 1;
                    c0 = 1; /* infinity */
                } else {
                    c3 = 0;
                    c2 = 0;
                    c0 = 1; /* NaN */
                }
            } else if (m == 0U) {
                c3 = 1;
                c2 = 0;
                c0 = 0; /* zero */
            } else if (e == 0U) {
                c3 = 1;
                c2 = 1;
                c0 = 0; /* denormal / unsupported */
            } else {
                c3 = 0;
                c2 = 1;
                c0 = 0; /* normal */
            }
        }
    } else {
        uint64_t bits;
        unsigned e;
        double d = x87_get_f64(ctx, 0);

        memcpy(&bits, &d, 8);
        e = (unsigned)((bits >> 52) & 0x7ffU);
        c1 = (unsigned)(bits >> 63);
        if (empty) {
            c3 = 1;
            c2 = 0;
            c0 = 1;
        } else if (e == 0x7ffU) {
            if ((bits & 0x000fffffffffffffULL) == 0U) {
                c3 = 0;
                c2 = 1;
                c0 = 1;
            } else {
                c3 = 0;
                c2 = 0;
                c0 = 1;
            }
        } else if (d == 0.0) {
            c3 = 1;
            c2 = 0;
            c0 = 0;
        } else if (e == 0U) {
            c3 = 1;
            c2 = 1;
            c0 = 0;
        } else {
            c3 = 0;
            c2 = 1;
            c0 = 0;
        }
    }
    set_cc(ctx, c0, c1, c2, c3);
}

/* D9 E8+i constants.  80-bit mode uses the frozen x87_80 tables; the
 * API has no log2(10)/log10(2) entries (FLDL2T/FLDG2), so those go
 * through x87_80_from_f64 on the double literal (matches the
 * double-rounded constant; exact 64-bit tables are L5d's to add). */
static void op_fld_const(i686_ctx_t *ctx, unsigned rm)
{
    static const double dc[7] = {
        1.0,                                   /* FLD1   */
        3.32192809488736234787,                /* FLDL2T */
        1.44269504088896340736,                /* FLDL2E */
        3.14159265358979323846,                /* FLDPI  */
        0.30102999566398119521,                /* FLDLG2 */
        0.69314718055994530942,                /* FLDLN2 */
        0.0,                                   /* FLDZ   */
    };

    if (!ctx->x87_80) {
        push_f64(ctx, dc[rm]);
        return;
    }
    {
        uint8_t b[10];

        switch (rm) {
        case 0:
            x87_80_one(b);
            break;
        case 2:
            x87_80_log2e(b);
            break;
        case 3:
            x87_80_pi(b);
            break;
        case 5:
            x87_80_ln2(b);
            break;
        case 6:
            x87_80_zero(b);
            break;
        default: /* 1 FLDL2T, 4 FLDLG2 */
            x87_80_from_f64(b, dc[rm]);
            break;
        }
        x87_push(ctx);
        x87_set_ext80(ctx, 0, b);
    }
}

static void op_fsin(i686_ctx_t *ctx, int is_cos)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t r[10];
        bool fault;
        unsigned exc;

        x87_get_ext80(ctx, 0, a);
        exc = is_cos ? x87_80_fcos(r, a, &fault) : x87_80_fsin(r, a, &fault);
        if (fault) {
            set_c2(ctx, 1);
        } else {
            set_c2(ctx, 0);
            x87_set_ext80(ctx, 0, r);
            x87_set_exc(ctx, exc);
        }
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (fabs(a) >= 9223372036854775808.0) {
            set_c2(ctx, 1);
            return;
        }
        x87_set_f64(ctx, 0, is_cos ? cos(a) : sin(a));
    }
}

static void op_fsincos(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t s[10];
        uint8_t c[10];
        bool fault;

        x87_get_ext80(ctx, 0, a);
        (void)x87_80_fsin(s, a, &fault);
        if (fault) {
            set_c2(ctx, 1);
            return;
        }
        (void)x87_80_fcos(c, a, &fault);
        x87_set_ext80(ctx, 0, s);
        x87_push(ctx);
        x87_set_ext80(ctx, 0, c); /* after: ST(0)=cos, ST(1)=sin */
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double s;
        double c;

        if (fabs(a) >= 9223372036854775808.0) {
            set_c2(ctx, 1);
            return;
        }
        s = sin(a);
        c = cos(a);
        x87_set_f64(ctx, 0, s);
        x87_push(ctx);
        x87_set_f64(ctx, 0, c);
    }
}

static void op_fsqrt(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_sqrt(r, a);
        x87_set_ext80(ctx, 0, r);
        x87_set_exc(ctx, exc);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (a < 0.0) {
            x87_set_exc(ctx, SW_IE);
            x87_set_f64(ctx, 0, (double)NAN);
            return;
        }
        x87_set_f64(ctx, 0, sqrt(a));
    }
}

static void op_frndint(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        int64_t i;
        unsigned exc;

        x80_set_mode(ctx, 0);
        x87_get_ext80(ctx, 0, a);
        if (x87_80_is_inf(a) || x87_80_is_nan(a)) {
            return; /* unchanged */
        }
        exc = x87_80_to_i64(a, &i);
        x87_80_from_i64(a, i);
        x87_set_ext80(ctx, 0, a);
        x87_set_exc(ctx, exc);
        return;
    }
    {
        double d = x87_get_f64(ctx, 0);
        double r;
        unsigned rc = x87_round_mode(ctx);

        if (isnan(d) || isinf(d)) {
            return;
        }
        if (rc == 1U) {
            r = floor(d);
        } else if (rc == 2U) {
            r = ceil(d);
        } else if (rc == 3U) {
            r = trunc(d);
        } else {
            r = nearbyint(d);
        }
        if (r != d) {
            x87_set_exc(ctx, SW_PE);
        }
        x87_set_f64(ctx, 0, r);
    }
}

/* ------------------------------------------------------------------ */
/* FPU environment (28-byte protected mode) and FXSAVE m512            */
/* ------------------------------------------------------------------ */

/* 28-byte protected-mode x87 environment:
 * +0 CW(2) +2 pad, +4 SW(2) +6 pad, +8 TW(2) +10 pad, +12 IP(4),
 * +16 CS(2)+FOP(2), +20 DP(4), +24 DS(2)+pad. */
static void op_fnstenv(i686_ctx_t *ctx, uint32_t va)
{
    for (unsigned i = 0; i < 28; i++) {
        mem_wr(ctx, va + i, 1, 0);
    }
    mem_wr(ctx, va + 0, 2, ctx->fctrl);
    mem_wr(ctx, va + 4, 2, ctx->fstat);
    mem_wr(ctx, va + 8, 2, ctx->ftag);
    mem_wr(ctx, va + 12, 4, ctx->fpu_ip);
    mem_wr(ctx, va + 16, 2, ctx->seg_sel[I686_SEG_CS]);
    mem_wr(ctx, va + 18, 2, ctx->fop);
    mem_wr(ctx, va + 20, 4, ctx->fpu_dp);
    mem_wr(ctx, va + 24, 2, ctx->seg_sel[I686_SEG_DS]);
}

static void op_fldenv(i686_ctx_t *ctx, uint32_t va)
{
    ctx->fctrl = (uint16_t)mem_rd(ctx, va + 0, 2);
    ctx->fstat = (uint16_t)mem_rd(ctx, va + 4, 2);
    ctx->ftag = (uint16_t)mem_rd(ctx, va + 8, 2);
    ctx->x87_top = (ctx->fstat >> 11) & 7U;
    ctx->fpu_ip = (uint32_t)mem_rd(ctx, va + 12, 4);
    ctx->fop = (uint16_t)mem_rd(ctx, va + 18, 2);
    ctx->fpu_dp = (uint32_t)mem_rd(ctx, va + 20, 4);
}

/* FXSAVE/FXRSTOR m512 image (32-bit mode; matches the kernel _fpstate_32
 * FXSAVE area documented in src/os/sigframe_i386.h): CW@0 SW@2 TW@4
 * (abridged, 1 bit per physical register) FOP@6 IP@8 CS@12 DP@16 DS@20
 * MXCSR@24 MASK@28 ST0..7@32 (10 B per 16-B slot, stack-relative) then
 * XMM0..7@160. */
static void img_wr16(uint8_t *img, unsigned off, uint16_t v)
{
    img[off] = (uint8_t)v;
    img[off + 1] = (uint8_t)(v >> 8);
}

static void img_wr32(uint8_t *img, unsigned off, uint32_t v)
{
    img[off] = (uint8_t)v;
    img[off + 1] = (uint8_t)(v >> 8);
    img[off + 2] = (uint8_t)(v >> 16);
    img[off + 3] = (uint8_t)(v >> 24);
}

static uint16_t img_rd16(const uint8_t *img, unsigned off)
{
    return (uint16_t)((uint16_t)img[off] | ((uint16_t)img[off + 1] << 8));
}

static uint32_t img_rd32(const uint8_t *img, unsigned off)
{
    return (uint32_t)img[off] | ((uint32_t)img[off + 1] << 8) |
           ((uint32_t)img[off + 2] << 16) | ((uint32_t)img[off + 3] << 24);
}

static void op_fxsave(i686_ctx_t *ctx, uint32_t va)
{
    uint8_t *img = (uint8_t *)i686_guest_ptr(ctx, va);
    uint16_t atw = 0;

    memset(img, 0, 512);
    img_wr16(img, 0, ctx->fctrl);
    img_wr16(img, 2, ctx->fstat);
    for (unsigned p = 0; p < 8; p++) {
        if (((ctx->ftag >> (p * 2U)) & 3U) == 3U) {
            atw |= (uint16_t)(1U << p);
        }
    }
    img[4] = (uint8_t)atw; /* abridged tag: 1 = empty (physical order) */
    img_wr16(img, 6, ctx->fop);
    img_wr32(img, 8, ctx->fpu_ip);
    img_wr16(img, 12, ctx->seg_sel[I686_SEG_CS]);
    img_wr32(img, 16, ctx->fpu_dp);
    img_wr16(img, 20, ctx->seg_sel[I686_SEG_DS]);
    img_wr32(img, 24, ctx->mxcsr);
    img_wr32(img, 28, ctx->mxcsr_mask);
    for (unsigned i = 0; i < 8; i++) {
        uint8_t b[10];

        x87_get_ext80(ctx, i, b); /* stack-relative ST(i) */
        memcpy(&img[32 + 16 * i], b, 10);
        memcpy(&img[160 + 16 * i], ctx->xmm[i], 16);
    }
}

static void op_fxrstor(i686_ctx_t *ctx, uint32_t va)
{
    const uint8_t *img = (const uint8_t *)i686_guest_ptr(ctx, va);

    ctx->fctrl = img_rd16(img, 0);
    ctx->fstat = img_rd16(img, 2);
    ctx->x87_top = (ctx->fstat >> 11) & 7U;
    ctx->fop = img_rd16(img, 6);
    ctx->fpu_ip = img_rd32(img, 8);
    ctx->fpu_dp = img_rd32(img, 16);
    ctx->mxcsr = img_rd32(img, 24) & 0xffbfU; /* bit 6 reserved */
    ctx->ftag = 0;
    for (unsigned p = 0; p < 8; p++) {
        if ((img[4] & (1U << p)) != 0U) {
            ctx->ftag |= (uint16_t)(3U << (p * 2U)); /* empty */
        }
    }
    for (unsigned i = 0; i < 8; i++) {
        x87_set_ext80(ctx, i, &img[32 + 16 * i]);
        memcpy(ctx->xmm[i], &img[160 + 16 * i], 16);
    }
}

/* ------------------------------------------------------------------ */
/* Fixed-form ops reached by sub-dispatch                              */
/* ------------------------------------------------------------------ */

static void op_f2xm1(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_f2xm1(r, a);
        x87_set_ext80(ctx, 0, r);
        x87_set_exc(ctx, exc);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double r = expm1(a * 0.693147180559945309417232121458176568);

        /* PE not derivable exactly here (default-mode transcendental):
         * left unset; the exact-mode path above carries it. */
        x87_set_f64(ctx, 0, r);
    }
}

/* FYL2X: ST(1) = ST(1) * log2(ST(0)); pop.  Same shape for FYL2XP1. */
static void op_fyl2x(i686_ctx_t *ctx, int p1)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        x87_get_ext80(ctx, 1, b);
        exc = p1 ? x87_80_fyl2xp1(r, a, b) : x87_80_fyl2x(r, a, b);
        x87_set_ext80(ctx, 1, r);
        x87_set_exc(ctx, exc);
        x87_pop(ctx);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, 1);
        double r;

        if (isnan(a) || isnan(b) || a < 0.0 || (p1 && a <= -1.0)) {
            x87_set_exc(ctx, SW_IE);
            x87_set_f64(ctx, 1, (double)NAN);
            x87_pop(ctx);
            return;
        }
        if (!p1 && a == 0.0) {
            x87_set_exc(ctx, SW_ZE);
            x87_set_f64(ctx, 1, signbit(b) ? -HUGE_VAL : HUGE_VAL);
            x87_pop(ctx);
            return;
        }
        r = d_mul(ctx, b, p1 ? log2(a + 1.0) : log2(a));
        x87_set_f64(ctx, 1, r);
        x87_pop(ctx);
    }
}

static void op_fptan(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t t[10];
        uint8_t one[10];
        bool fault;
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_fptan(t, one, a, &fault);
        if (fault) {
            set_c2(ctx, 1);
            return;
        }
        x87_set_ext80(ctx, 0, t);
        x87_push(ctx);
        x87_set_ext80(ctx, 0, one);
        x87_set_exc(ctx, exc);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (fabs(a) >= 9223372036854775808.0) {
            set_c2(ctx, 1);
            return;
        }
        x87_set_f64(ctx, 0, tan(a));
        x87_push(ctx);
        x87_set_f64(ctx, 0, 1.0);
    }
}

static void op_fpatan(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a); /* x */
        x87_get_ext80(ctx, 1, b); /* y */
        exc = x87_80_fpatan(r, a, b);
        x87_set_ext80(ctx, 1, r);
        x87_set_exc(ctx, exc);
        x87_pop(ctx);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0); /* x */
        double b = x87_get_f64(ctx, 1); /* y */

        x87_set_f64(ctx, 1, atan2(b, a));
        x87_pop(ctx);
    }
}

static void op_fxtract(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t sig[10];
        uint8_t ex[10];

        x87_get_ext80(ctx, 0, a);
        (void)x87_80_fxtract(sig, ex, a);
        x87_push(ctx);
        x87_set_ext80(ctx, 1, ex); /* after: ST(1)=exponent, ST(0)=sig */
        x87_set_ext80(ctx, 0, sig);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        int e = ilogb(a);
        double sig = scalbn(a, -e); /* [1,2) */

        x87_push(ctx);
        x87_set_f64(ctx, 1, (double)e);
        x87_set_f64(ctx, 0, sig);
    }
}

static void op_fscale(i686_ctx_t *ctx)
{
    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];

        x87_get_ext80(ctx, 0, a);
        x87_get_ext80(ctx, 1, b);
        (void)x87_80_fscale(r, a, b);
        x87_set_ext80(ctx, 0, r);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, 1);

        x87_set_f64(ctx, 0, scalbn(a, (int)trunc(b)));
    }
}

/* FPREM/FPREM1: C0/Q2, C1/Q0, C3/Q1 on completion; C2 = 0 (this
 * implementation always finishes the reduction in one step). */
static void op_fprem(i686_ctx_t *ctx, int ieee)
{
    unsigned c0 = 0;
    unsigned c1 = 0;
    unsigned c3 = 0;

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];
        uint32_t qq = 0;
        bool complete;
        unsigned exc;

        x87_get_ext80(ctx, 0, a);
        x87_get_ext80(ctx, 1, b);
        exc = ieee ? x87_80_fprem1(r, a, b, &qq, &complete)
                   : x87_80_fprem(r, a, b, &qq, &complete);
        x87_set_ext80(ctx, 0, r);
        x87_set_exc(ctx, exc);
        if (complete) {
            c1 = qq & 1U;
            c3 = (qq >> 1) & 1U;
            c0 = (qq >> 2) & 1U;
        }
        set_cc(ctx, c0, c1, complete ? 0U : 1U, c3);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, 1);
        double q;
        double r;

        if (isnan(a) || isnan(b) || isinf(a) || b == 0.0) {
            /* #IA indefinite.  C2 stays clear (hardware leaves it 0;
             * musl's fmod/remainder loops spin while C2 is set).  The
             * exception flag follows the SDM: quiet-NaN inputs
             * propagate silently (musl's special/*.h vectors expect no
             * flag); only SNaN operands, an infinite dividend, or a
             * zero divisor raise #IA — v1 treats every NaN as quiet. */
            if (!isnan(a) && !isnan(b)) {
                x87_set_exc(ctx, SW_IE);
            }
            x87_set_f64(ctx, 0, (double)NAN);
            set_cc(ctx, 1, 0, 0, 1);
            return;
        }
        q = ieee ? nearbyint(a / b) : trunc(a / b);
        r = ieee ? remainder(a, b) : fmod(a, b);
        x87_set_f64(ctx, 0, r);
        if (r != a) {
            x87_set_exc(ctx, SW_PE);
        }
        {
            /* low 3 quotient bits, safe for huge quotients */
            double q8 = fmod(q, 8.0);
            uint32_t qq = (uint32_t)(q8 < 0.0 ? q8 + 8.0 : q8);

            c1 = qq & 1U;
            c3 = (qq >> 1) & 1U;
            c0 = (qq >> 2) & 1U;
        }
        set_cc(ctx, c0, c1, 0, c3);
    }
}

/* ------------------------------------------------------------------ */
/* D8-DF slot handlers                                                 */
/* ------------------------------------------------------------------ */

static int h_fadd_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_ADD, 4);
}

static int h_fmul_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_MUL, 4);
}

static int h_fcom_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_fcom(ctx, insn, 4, 0);
}

static int h_fcomp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_fcom(ctx, insn, 4, 1);
}

static int h_fsub_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_SUB, 4);
}

static int h_fsubr_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_SUBR, 4);
}

static int h_fdiv_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_DIV, 4);
}

static int h_fdivr_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_DIVR, 4);
}

static int h_fadd_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_ADD, 8);
}

static int h_fmul_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_MUL, 8);
}

static int h_fcom_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_fcom(ctx, insn, 8, 0);
}

static int h_fcomp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_fcom(ctx, insn, 8, 1);
}

static int h_fsub_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_SUB, 8);
}

static int h_fsubr_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_SUBR, 8);
}

static int h_fdiv_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_DIV, 8);
}

static int h_fdivr_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_DIVR, 8);
}

static int h_faddp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_ADD);
}

static int h_fmulp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_MUL);
}

static int h_fsubrp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_SUBR);
}

static int h_fsubp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_SUB);
}

static int h_fdivrp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_DIVR);
}

static int h_fdivp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_DIV);
}

/* --- D9 ---------------------------------------------------------------- */

/* D9 /0: FLD m32 | mod=3 C0+i FLD ST(i). */
static int h_fld_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (!ctx->x87_80) {
            double v = x87_get_f64(ctx, insn->modrm_rm);

            x87_push(ctx);
            x87_set_f64(ctx, 0, v);
        } else {
            uint8_t b[10];

            x87_get_ext80(ctx, insn->modrm_rm, b);
            x87_push(ctx);
            x87_set_ext80(ctx, 0, b);
        }
        return done(ctx, insn);
    }
    push_f32(ctx, ld_f32(ctx, x86_ea_compute(ctx, insn)));
    return done(ctx, insn);
}

/* D9 /1 memory is invalid; mod=3 C8+i FXCH ST(i) (contents AND tags
 * move with the values). */
static int h_fxch(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned p0 = (unsigned)x87_top(ctx);
    unsigned p1 = (p0 + insn->modrm_rm) & 7U;
    unsigned t0;
    unsigned t1;
    uint8_t tmp[16];

    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    memcpy(tmp, &ctx->x87_st[p0][0], 16);
    memcpy(&ctx->x87_st[p0][0], &ctx->x87_st[p1][0], 16);
    memcpy(&ctx->x87_st[p1][0], tmp, 16);
    t0 = (ctx->ftag >> (p0 * 2U)) & 3U;
    t1 = (ctx->ftag >> (p1 * 2U)) & 3U;
    ctx->ftag = (uint16_t)((ctx->ftag & ~(3U << (p0 * 2U))) | (t1 << (p0 * 2U)));
    ctx->ftag = (uint16_t)((ctx->ftag & ~(3U << (p1 * 2U))) | (t0 << (p1 * 2U)));
    return done(ctx, insn);
}

/* D9 /2: FST m32 | mod=3 D0 FNOP (D1-D7 invalid). */
static int h_fst_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (insn->modrm_rm != 0U) {
            return undef_form(ctx, insn);
        }
        return done(ctx, insn); /* FNOP */
    }
    st_f32(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* D9 /3: FSTP m32 (mod=3 invalid). */
static int h_fstp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_f32(ctx, x86_ea_compute(ctx, insn));
    x87_pop(ctx);
    return done(ctx, insn);
}

/* D9 /4: FLDENV m14/28 | mod=3 E0 FCHS, E1 FABS, E4 FTST, E5 FXAM. */
static int h_fldenv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        switch (insn->modrm_rm) {
        case 0:
            op_fchs(ctx);
            break;
        case 1:
            op_fabs(ctx);
            break;
        case 4:
            op_ftst(ctx);
            break;
        case 5:
            op_fxam(ctx);
            break;
        default:
            return undef_form(ctx, insn);
        }
        return done(ctx, insn);
    }
    op_fldenv(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* D9 /5: FLDCW m16 | mod=3 E8+i constants (rm 7, D9 EF, is invalid). */
static int h_fldcw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (insn->modrm_rm > 6U) {
            return undef_form(ctx, insn);
        }
        op_fld_const(ctx, insn->modrm_rm);
        return done(ctx, insn);
    }
    ctx->fctrl = (uint16_t)mem_rd(ctx, x86_ea_compute(ctx, insn), 2);
    return done(ctx, insn);
}

/* D9 /6: FNSTENV m14/28 | mod=3 F0 F2XM1, F1 FYL2X, F2 FPTAN, F3 FPATAN,
 * F4 FXTRACT, F5 FPREM1, F6 FDECSTP, F7 FINCSTP. */
static int h_fnstenv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        switch (insn->modrm_rm) {
        case 0:
            op_f2xm1(ctx);
            break;
        case 1:
            op_fyl2x(ctx, 0);
            break;
        case 2:
            op_fptan(ctx);
            break;
        case 3:
            op_fpatan(ctx);
            break;
        case 4:
            op_fxtract(ctx);
            break;
        case 5:
            op_fprem(ctx, 1);
            break;
        case 6:
            ctx->x87_top = (ctx->x87_top + 7U) & 7U;
            x87_update_fstat(ctx);
            break;
        default:
            ctx->x87_top = (ctx->x87_top + 1U) & 7U;
            x87_update_fstat(ctx);
            break;
        }
        return done(ctx, insn);
    }
    op_fnstenv(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* D9 /7: FNSTCW m16 | mod=3 F8 FPREM, F9 FYL2XP1, FA FSQRT, FB FSINCOS,
 * FC FRNDINT, FD FSCALE, FE FSIN, FF FCOS. */
static int h_fnstcw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        switch (insn->modrm_rm) {
        case 0:
            op_fprem(ctx, 0);
            break;
        case 1:
            op_fyl2x(ctx, 1);
            break;
        case 2:
            op_fsqrt(ctx);
            break;
        case 3:
            op_fsincos(ctx);
            break;
        case 4:
            op_frndint(ctx);
            break;
        case 5:
            op_fscale(ctx);
            break;
        case 6:
            op_fsin(ctx, 0);
            break;
        default:
            op_fsin(ctx, 1);
            break;
        }
        return done(ctx, insn);
    }
    mem_wr(ctx, x86_ea_compute(ctx, insn), 2, ctx->fctrl);
    return done(ctx, insn);
}

/* --- DD ---------------------------------------------------------------- */

/* DD /0: FLD m64 | mod=3 C0+i FFREE ST(i). */
static int h_fld_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        x87_mark_empty(ctx, insn->modrm_rm);
        return done(ctx, insn);
    }
    push_f64(ctx, ld_f64(ctx, x86_ea_compute(ctx, insn)));
    return done(ctx, insn);
}

/* DD /2: FST m64 | mod=3 D0+i FST ST(i) (store ST(0) into ST(i)). */
static int h_fst_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (!ctx->x87_80) {
            x87_set_f64(ctx, insn->modrm_rm, x87_get_f64(ctx, 0));
        } else {
            uint8_t b[10];

            x87_get_ext80(ctx, 0, b);
            x87_set_ext80(ctx, insn->modrm_rm, b);
        }
        return done(ctx, insn);
    }
    st_f64(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* DD /3: FSTP m64 | mod=3 D8+i FSTP ST(i). */
static int h_fstp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (!ctx->x87_80) {
            x87_set_f64(ctx, insn->modrm_rm, x87_get_f64(ctx, 0));
        } else {
            uint8_t b[10];

            x87_get_ext80(ctx, 0, b);
            x87_set_ext80(ctx, insn->modrm_rm, b);
        }
        x87_pop(ctx);
        return done(ctx, insn);
    }
    st_f64(ctx, x86_ea_compute(ctx, insn));
    x87_pop(ctx);
    return done(ctx, insn);
}

/* DD /4 mod=3 E0+i FUCOM ST(i) (no memory form). */
static int h_fucom(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int un;

    if (insn->modrm_mod != 3U) {
        /* DD /4 memory form: FRSTOR m108 (RC7b T4b). */
        op_frstor(ctx, x86_ea_compute(ctx, insn));
        return done(ctx, insn);
    }
    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, insn->modrm_rm);

        un = cc_of_cmp(a, b, ctx);
        exc_ie_cmp(ctx, a, b, un, true);
        return done(ctx, insn);
    }
    {
        uint8_t sa[10];
        uint8_t sb[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        x87_get_ext80(ctx, insn->modrm_rm, sb);
        x87_80_fcom(sa, sb, true, &c3, &c2, &c0);
        set_cc(ctx, c0, 0, c2, c3);
        if ((c0 && c2 && c3) &&
            (x87_80_is_snan(sa) || x87_80_is_snan(sb))) {
            x87_set_exc(ctx, SW_IE);
        }
    }
    return done(ctx, insn);
}

/* DD /5 mod=3 E8+i FUCOMP ST(i) (compare then pop). */
static int h_fucomp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int r = h_fucom(ctx, insn);

    if (r == I686_INTERP_CONTINUE) {
        x87_pop(ctx);
    }
    return r;
}

/* DA mod=3 register forms (RC7b T4b; glibc/i386 FP compare code uses
 * them): DA C0+i FCOM ST,ST(i), DA D0+i FUCOM ST,ST(i), DA D8+i
 * FCOMP ST,ST(i).  CC bits per FCOM; FCOMP pops once.  Memory forms of
 * the DA row stay declined (FIADD-class, D2). */
static int do_da_fcom(i686_ctx_t *ctx, const x86_insn_t *insn, int pop)
{
    int un;

    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, insn->modrm_rm);

        un = cc_of_cmp(a, b, ctx);
        exc_ie_cmp(ctx, a, b, un, true);
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        x87_get_ext80(ctx, insn->modrm_rm, sb);
        x87_80_fcom(sa, sb, true, &c3, &c2, &c0);
        set_cc(ctx, c0, 0, c2, c3);
        if ((c0 && c2 && c3) &&
            (x87_80_is_snan(sa) || x87_80_is_snan(sb))) {
            x87_set_exc(ctx, SW_IE);
        }
    }
    if (pop != 0) {
        x87_pop(ctx);
    }
    return done(ctx, insn);
}

static int h_fcom_sti(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_da_fcom(ctx, insn, 0);
}

static int h_fucom_sti(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_da_fcom(ctx, insn, 0);
}

static int h_fcomp_sti(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_da_fcom(ctx, insn, 1);
}

/* DD /7: FNSTSW m16 (mod=3 invalid). */
static int h_fnstsw_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    mem_wr(ctx, x86_ea_compute(ctx, insn), 2, ctx->fstat);
    return done(ctx, insn);
}

/* --- DA ---------------------------------------------------------------- */

/* DA E9 FUCOMPP only (memory FIADD-class declined). */
static int h_fucompp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int r;

    if (insn->modrm_mod != 3U || insn->modrm_rm != 1U) {
        return undef_form(ctx, insn);
    }
    r = h_fucom(ctx, insn); /* compares ST(0) vs ST(rm=1) */
    if (r == I686_INTERP_CONTINUE) {
        x87_pop(ctx);
        x87_pop(ctx);
    }
    return r;
}

/* --- DB ---------------------------------------------------------------- */

/* DB /0: FILD m32 (mod=3 invalid). */
static int h_fild_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v;

    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    v = (uint32_t)mem_rd(ctx, x86_ea_compute(ctx, insn), 4);
    push_int(ctx, (int64_t)(int32_t)v);
    return done(ctx, insn);
}

/* DB /2: FIST m32 (no pop; mod=3 invalid). */
static int h_fist_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int(ctx, x86_ea_compute(ctx, insn), 4);
    return done(ctx, insn);
}

static int h_fistp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int r = h_fist_m32(ctx, insn);

    if (r == I686_INTERP_CONTINUE) {
        x87_pop(ctx);
    }
    return r;
}

/* FISTTP: DB /1 m32, DD /1 m64, DF /1 m16 (RC7b T4b; wine's ntdll.dll
 * uses it for C99 truncating conversions).  Truncates toward zero
 * regardless of CW RC; NaN/inf/out-of-range store the integer
 * indefinite silently (no #P/#I fault, SDM Vol.1 x87 FISTTP). */
static int h_fisttp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int_trunc(ctx, x86_ea_compute(ctx, insn), 4);
    x87_pop(ctx);
    return done(ctx, insn);
}

static int h_fisttp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int_trunc(ctx, x86_ea_compute(ctx, insn), 8);
    x87_pop(ctx);
    return done(ctx, insn);
}

static int h_fisttp_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int_trunc(ctx, x86_ea_compute(ctx, insn), 2);
    x87_pop(ctx);
    return done(ctx, insn);
}

/* DB /4 mod=3: E2 FNCLEX, E3 FNINIT (no memory form). */
static int h_fninit(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    if (insn->modrm_rm == 3U) {
        ctx->fctrl = 0x037fU;
        ctx->fstat = 0;
        ctx->ftag = 0xffffU;
        ctx->x87_top = 0;
        ctx->fop = 0;
        ctx->fpu_ip = 0;
        ctx->fpu_dp = 0;
        return done(ctx, insn);
    }
    if (insn->modrm_rm == 2U) {
        ctx->fstat = (uint16_t)(ctx->fstat & ~(0xffU | 0x8000U));
        return done(ctx, insn);
    }
    return undef_form(ctx, insn);
}

/* DB /5: FLD m80 | mod=3 E8+i FUCOMI ST(0),ST(i) (eflags form). */
static int h_fld_m80(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return do_fcomi(ctx, insn, 0);
    }
    {
        uint32_t va = x86_ea_compute(ctx, insn);
        uint8_t b[10];

        for (unsigned i = 0; i < 10; i++) {
            b[i] = (uint8_t)mem_rd(ctx, va + i, 1);
        }
        x87_push(ctx);
        x87_set_ext80(ctx, 0, b);
    }
    return done(ctx, insn);
}

/* DB /6 mod=3: F0+i FCOMI ST(0),ST(i) (no memory form). */
static int h_fcomi(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    return do_fcomi(ctx, insn, 0);
}

/* DB /7: FSTP m80 (mod=3 invalid). */
static int h_fstp_m80(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_m80(ctx, x86_ea_compute(ctx, insn));
    x87_pop(ctx);
    return done(ctx, insn);
}

/* --- DF ---------------------------------------------------------------- */

static int h_fild_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v;

    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    v = (uint32_t)mem_rd(ctx, x86_ea_compute(ctx, insn), 2);
    push_int(ctx, (int64_t)(int16_t)v);
    return done(ctx, insn);
}

static int h_fist_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int(ctx, x86_ea_compute(ctx, insn), 2);
    return done(ctx, insn);
}

static int h_fistp_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int r = h_fist_m16(ctx, insn);

    if (r == I686_INTERP_CONTINUE) {
        x87_pop(ctx);
    }
    return r;
}

/* DF E0: FNSTSW AX (mod=3 rm=0 only). */
static int h_fnstsw_ax(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U || insn->modrm_rm != 0U) {
        return undef_form(ctx, insn);
    }
    x86_reg_write(ctx, I686_REG_EAX, 16, ctx->fstat);
    return done(ctx, insn);
}

/* DF /5: FILD m64 | mod=3 E8+i FUCOMIP ST(0),ST(i). */
static int h_fild_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return do_fcomi(ctx, insn, 1);
    }
    {
        uint64_t v = mem_rd(ctx, x86_ea_compute(ctx, insn), 8);
        int64_t s;

        memcpy(&s, &v, 8);
        push_int(ctx, s);
    }
    return done(ctx, insn);
}

/* DF /6 mod=3: F0+i FCOMIP ST(0),ST(i) (memory /6 is FBSTP: declined at
 * decode; unreachable here). */
static int h_fcomip(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    return do_fcomi(ctx, insn, 1);
}

static int h_fistp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int(ctx, x86_ea_compute(ctx, insn), 8);
    x87_pop(ctx);
    return done(ctx, insn);
}

/* --- 0F map ------------------------------------------------------------ */

static int h_emms(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->ftag = 0xffffU;
    return done(ctx, insn);
}

static int h_fxsave(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    op_fxsave(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

static int h_fxrstor(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    op_fxrstor(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}


/* FNSAVE (DD /6 m108, RC7b T4b): store the x87 state in the i387
 * (16-bit-era) image format, then reinitialize the FPU.  Image:
 * FCW@0, FSW@2, abridged tag@4 (1 bit/register, 1 = empty, PHYSICAL
 * order), FIP@8, FCS@12, FOP@14, FDP@16, FDS@20, R0..R7@28 (10 B
 * each, physical order).  wine's ntdll.dll start path saves/restores
 * the FPU state across thread setup. */
static void op_fnsave(i686_ctx_t *ctx, uint32_t va)
{
    uint8_t *img = (uint8_t *)i686_guest_ptr(ctx, va);
    uint16_t atw = 0;

    memset(img, 0, 108);
    img_wr16(img, 0, ctx->fctrl);
    img_wr16(img, 2, ctx->fstat);
    for (unsigned p = 0; p < 8; p++) {
        if (((ctx->ftag >> (p * 2U)) & 3U) == 3U) {
            atw |= (uint16_t)(1U << p);
        }
    }
    img[4] = (uint8_t)atw;
    img_wr32(img, 8, ctx->fpu_ip);
    img_wr16(img, 12, ctx->seg_sel[I686_SEG_CS]);
    img_wr16(img, 14, ctx->fop);
    img_wr32(img, 16, ctx->fpu_dp);
    img_wr16(img, 20, ctx->seg_sel[I686_SEG_DS]);
    for (unsigned p = 0; p < 8; p++) {
        uint8_t b[10];

        x87_get_ext80(ctx, (p - ctx->x87_top) & 7U, b); /* ST(i)=Rp */
        memcpy(&img[28 + 10 * p], b, 10);
    }
    /* FNSAVE reinitializes (FINIT semantics). */
    ctx->fctrl = 0x037fU;
    ctx->fstat = 0;
    ctx->ftag = 0xffffU;
    ctx->x87_top = 0;
    ctx->fop = 0;
    ctx->fpu_ip = 0;
    ctx->fpu_dp = 0;
}

/* FRSTOR (DD /4 m108 memory form; the mod=3 form of the same slot is
 * FUCOM and stays in h_fucom). */
static void op_frstor(i686_ctx_t *ctx, uint32_t va)
{
    const uint8_t *img = (const uint8_t *)i686_guest_ptr(ctx, va);

    ctx->fctrl = img_rd16(img, 0);
    ctx->fstat = img_rd16(img, 2);
    ctx->x87_top = (ctx->fstat >> 11) & 7U;
    ctx->ftag = 0;
    for (unsigned p = 0; p < 8; p++) {
        if ((img[4] & (1U << p)) != 0U) {
            ctx->ftag |= (uint16_t)(3U << (p * 2U)); /* empty */
        }
    }
    ctx->fpu_ip = img_rd32(img, 8);
    ctx->fop = img_rd16(img, 14);
    ctx->fpu_dp = img_rd32(img, 16);
    for (unsigned p = 0; p < 8; p++) {
        uint8_t b[10];

        memcpy(b, &img[28 + 10 * p], 10);
        x87_set_ext80(ctx, (p - ctx->x87_top) & 7U, b);
    }
}

static int h_fnsave(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn); /* DD /6 has no register form */
    }
    op_fnsave(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* FCOMI/FCOMIP/FUCOMI/FUCOMIP: EFLAGS ZF/PF/CF                        */
/* ------------------------------------------------------------------ */

/* Compares ST(0) with ST(rm): > → ZF=0,PF=0,CF=0; < → CF=1; = → ZF=1;
 * unordered → ZF=1,PF=1,CF=1.  OF/SF/AF cleared; the lazy-flags
 * descriptor is materialized first (direct EFLAGS manipulation per the
 * lane card).  pop>0 pops once after the compare. */
static int do_fcomi(i686_ctx_t *ctx, const x86_insn_t *insn, int pop)
{
    unsigned un;
    unsigned lt;
    unsigned eq;

    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, insn->modrm_rm);

        un = (isnan(a) || isnan(b)) ? 1U : 0U;
        lt = !un && a < b ? 1U : 0U;
        eq = !un && a == b ? 1U : 0U;
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        x87_get_ext80(ctx, insn->modrm_rm, sb);
        x87_80_fcom(sa, sb, true, &c3, &c2, &c0);
        un = (c0 && c2 && c3) ? 1U : 0U;
        lt = !un && c0 ? 1U : 0U;
        eq = !un && c3 ? 1U : 0U;
    }
    if (un) {
        x87_set_exc(ctx, SW_IE); /* FCOMI raises IE on QNaN too */
    }
    i686_flags_materialize(ctx);
    ctx->eflags &= ~(uint32_t)(I686_EF_ZF | I686_EF_PF | I686_EF_CF |
                               I686_EF_OF | I686_EF_SF | I686_EF_AF);
    if (un) {
        ctx->eflags |= I686_EF_ZF | I686_EF_PF | I686_EF_CF;
    } else if (lt) {
        ctx->eflags |= I686_EF_CF;
    } else if (eq) {
        ctx->eflags |= I686_EF_ZF;
    }
    if (pop) {
        x87_pop(ctx);
    }
    return done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

void i686_interp_x87_init(void)
{
    /* D8 (m32 / ST(i)) */
    i686_interp_register(I686_OP_FADD_m32, h_fadd_m32);
    i686_interp_register(I686_OP_FMUL_m32, h_fmul_m32);
    i686_interp_register(I686_OP_FCOM_m32, h_fcom_m32);
    i686_interp_register(I686_OP_FCOMP_m32, h_fcomp_m32);
    i686_interp_register(I686_OP_FSUB_m32, h_fsub_m32);
    i686_interp_register(I686_OP_FSUBR_m32, h_fsubr_m32);
    i686_interp_register(I686_OP_FDIV_m32, h_fdiv_m32);
    i686_interp_register(I686_OP_FDIVR_m32, h_fdivr_m32);
    /* DC (m64 / ST(i),ST(0)) */
    i686_interp_register(I686_OP_FADD_m64, h_fadd_m64);
    i686_interp_register(I686_OP_FMUL_m64, h_fmul_m64);
    i686_interp_register(I686_OP_FCOM_m64, h_fcom_m64);
    i686_interp_register(I686_OP_FCOMP_m64, h_fcomp_m64);
    i686_interp_register(I686_OP_FSUB_m64, h_fsub_m64);
    i686_interp_register(I686_OP_FSUBR_m64, h_fsubr_m64);
    i686_interp_register(I686_OP_FDIV_m64, h_fdiv_m64);
    i686_interp_register(I686_OP_FDIVR_m64, h_fdivr_m64);
    /* DE (pop) */
    i686_interp_register(I686_OP_FADDP, h_faddp);
    i686_interp_register(I686_OP_FMULP, h_fmulp);
    i686_interp_register(I686_OP_FSUBRP, h_fsubrp);
    i686_interp_register(I686_OP_FSUBP, h_fsubp);
    i686_interp_register(I686_OP_FDIVRP, h_fdivrp);
    i686_interp_register(I686_OP_FDIVP, h_fdivp);
    /* D9 */
    i686_interp_register(I686_OP_FLD_m32, h_fld_m32);
    i686_interp_register(I686_OP_FXCH, h_fxch);
    i686_interp_register(I686_OP_FST_m32, h_fst_m32);
    i686_interp_register(I686_OP_FSTP_m32, h_fstp_m32);
    i686_interp_register(I686_OP_FLDENV, h_fldenv);
    i686_interp_register(I686_OP_FLDCW, h_fldcw);
    i686_interp_register(I686_OP_FNSTENV, h_fnstenv);
    i686_interp_register(I686_OP_FNSTCW, h_fnstcw);
    /* DD */
    i686_interp_register(I686_OP_FLD_m64, h_fld_m64);
    i686_interp_register(I686_OP_FST_m64, h_fst_m64);
    i686_interp_register(I686_OP_FSTP_m64, h_fstp_m64);
    i686_interp_register(I686_OP_FUCOM, h_fucom);
    i686_interp_register(I686_OP_FUCOMP, h_fucomp);
    i686_interp_register(I686_OP_FNSTSW_m16, h_fnstsw_m16);
    i686_interp_register(I686_OP_FNSAVE, h_fnsave); /* DD /6; /4 mem = FRSTOR */
    /* DB */
    i686_interp_register(I686_OP_FILD_m32, h_fild_m32);
    i686_interp_register(I686_OP_FIST_m32, h_fist_m32);
    i686_interp_register(I686_OP_FISTP_m32, h_fistp_m32);
    i686_interp_register(I686_OP_FNINIT, h_fninit);
    i686_interp_register(I686_OP_FLD_m80, h_fld_m80);
    i686_interp_register(I686_OP_FCOMI, h_fcomi);
    i686_interp_register(I686_OP_FSTP_m80, h_fstp_m80);
    /* DA */
    i686_interp_register(I686_OP_FUCOMPP, h_fucompp);
    /* DA mod=3 register forms (RC7b T4b) */
    i686_interp_register(I686_OP_FCOM_STi, h_fcom_sti);
    i686_interp_register(I686_OP_FUCOM_STi, h_fucom_sti);
    i686_interp_register(I686_OP_FCOMP_STi, h_fcomp_sti);
    /* DF */
    i686_interp_register(I686_OP_FILD_m16, h_fild_m16);
    i686_interp_register(I686_OP_FIST_m16, h_fist_m16);
    i686_interp_register(I686_OP_FISTP_m16, h_fistp_m16);
    i686_interp_register(I686_OP_FNSTSW_AX, h_fnstsw_ax);
    i686_interp_register(I686_OP_FILD_m64, h_fild_m64);
    i686_interp_register(I686_OP_FCOMIP, h_fcomip);
    i686_interp_register(I686_OP_FISTP_m64, h_fistp_m64);
    /* FISTTP (SSE3, RC7b T4b) */
    i686_interp_register(I686_OP_FISTTP_m32, h_fisttp_m32);
    i686_interp_register(I686_OP_FISTTP_m64, h_fisttp_m64);
    i686_interp_register(I686_OP_FISTTP_m16, h_fisttp_m16);
    /* 0F map */
    i686_interp_register(I686_OP_EMMS, h_emms);
    i686_interp_register(I686_OP_FXSAVE, h_fxsave);
    i686_interp_register(I686_OP_FXRSTOR, h_fxrstor);
}
