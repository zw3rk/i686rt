/*
 * tests/unit/test_l5c.c — host-native unit driver for lane L5c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the x87 handlers in src/interp/h_x87.c (and the state core in
 * src/interp/x87.c) through the REAL decoder (src/x86/decode.c) against
 * a fake malloc'ed guest window, in BOTH storage modes (two context
 * variants: default double and --x87-80).  Arithmetic is checked against
 * a host long double oracle where the modes agree exactly (dyadic
 * values) and against fixed bit patterns for mode-specific storage,
 * encoding and rounding cases.  tests/unit/x87_80_stub.c stands in for
 * lane L5d's softfloat core (test-only; host long double is binary128).
 *
 * The interpreter-registry stand-in mirrors the L1c pattern: interp.c is
 * not linked, so this file provides i686_interp_register plus no-op
 * stubs for the two cross-module registrations the linked handler files
 * import (h_string.c / h_bit.c are not linked either).
 *
 * Expected final line: L5C OK.
 */

#include <float.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "i686rt.h"
#include "interp/interp.h"
#include "interp/x87.h"
#include "x86/decode.h"

/* Exported by src/interp/h_x87.c. */
void i686_interp_x87_init(void);

/* ------------------------------------------------------------------ */
/* interp.c / h_string.c / h_bit.c stand-ins                           */
/* ------------------------------------------------------------------ */

static i686_interp_fn t_tab[I686_OP_COUNT];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    if ((unsigned)op < I686_OP_COUNT) {
        t_tab[op] = fn;
    }
}

void i686_interp_string_register(void) /* h_string.c not linked */
{
}

void i686_interp_bit_init(void) /* h_bit.c not linked */
{
}

/* ------------------------------------------------------------------ */
/* Fixture                                                             */
/* ------------------------------------------------------------------ */

#define WIN_SIZE 0x100000U /* 1 MiB fake guest window */
#define CODE_VA  0x001000U
#define DATA_VA  0x002000U
#define ENV_VA   0x003000U
#define FX_VA    0x003800U

static uint8_t *t_win;
static int t_pass;
static int t_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            t_pass++;                                                        \
        } else {                                                             \
            t_fail++;                                                        \
            printf("FAIL %d: %s\n", __LINE__, #cond);                        \
        }                                                                    \
    } while (0)

static uint32_t gm_rd32(const i686_ctx_t *ctx, uint32_t va)
{
    const uint8_t *p = (const uint8_t *)i686_guest_ptr(ctx, va);

    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t gm_rd64(const i686_ctx_t *ctx, uint32_t va)
{
    return (uint64_t)gm_rd32(ctx, va) | ((uint64_t)gm_rd32(ctx, va + 4) << 32);
}

static void gm_wr32(i686_ctx_t *ctx, uint32_t va, uint32_t v)
{
    uint8_t *p = (uint8_t *)i686_guest_ptr(ctx, va);

    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void gm_wr64m(i686_ctx_t *ctx, uint32_t va, uint64_t v)
{
    gm_wr32(ctx, va, (uint32_t)v);
    gm_wr32(ctx, va + 4, (uint32_t)(v >> 32));
}

static void reset_fpu(i686_ctx_t *ctx)
{
    ctx->fctrl = 0x037fU;
    ctx->fstat = 0;
    ctx->ftag = 0xffffU;
    ctx->x87_top = 0;
    ctx->fop = 0;
    ctx->fpu_ip = 0;
    ctx->fpu_dp = 0;
}

static i686_ctx_t *mkctx(int mode80)
{
    i686_ctx_t *ctx = calloc(1, sizeof(*ctx));

    ctx->guest_base = (uint64_t)(uintptr_t)t_win;
    ctx->x87_80 = mode80 != 0;
    ctx->gpr[I686_REG_EAX] = DATA_VA;
    reset_fpu(ctx);
    return ctx;
}

static int run(i686_ctx_t *ctx, const uint8_t *b, unsigned n)
{
    x86_insn_t insn;
    i686_interp_fn fn;

    memcpy((uint8_t *)i686_guest_ptr(ctx, CODE_VA), b, n);
    ctx->eip = CODE_VA;
    if (x86_decode(ctx, CODE_VA, &insn) != 0) {
        return -2; /* decode failed (declined group slot) */
    }
    fn = (unsigned)insn.op < I686_OP_COUNT ? t_tab[insn.op] : NULL;
    if (fn == NULL) {
        return -3;
    }
    return fn(ctx, &insn);
}

/* runb(ctx, 0xD9, 0xFF, -1): bytes then a negative terminator. */
static int runb(i686_ctx_t *ctx, ...)
{
    uint8_t buf[16];
    unsigned n = 0;
    va_list ap;

    va_start(ap, ctx);
    for (;;) {
        int v = va_arg(ap, int);

        if (v < 0 || n == sizeof(buf)) {
            break;
        }
        buf[n++] = (uint8_t)v;
    }
    va_end(ap);
    return run(ctx, buf, n);
}

static void wr32m(i686_ctx_t *ctx, uint32_t v)
{
    gm_wr32(ctx, DATA_VA, v);
}

static void wr64m(i686_ctx_t *ctx, double d)
{
    uint64_t bits;

    memcpy(&bits, &d, 8);
    gm_wr64m(ctx, DATA_VA, bits);
}

/* Push a double through the state core (stack depth + 1). */
static void push_d(i686_ctx_t *ctx, double v)
{
    x87_push(ctx);
    x87_set_f64(ctx, 0, v);
}

/* ------------------------------------------------------------------ */
/* 1. state core: stack wrap, storage layout, tags, CW/SW helpers      */
/* ------------------------------------------------------------------ */

static void test_state_core(void)
{
    i686_ctx_t *c = mkctx(0);
    double d = 1.5;
    uint64_t dbits;

    memcpy(&dbits, &d, 8);

    /* top wrap 8 + fstat mirror */
    x87_set_top(c, 0);
    for (int i = 0; i < 9; i++) {
        x87_push(c);
    }
    CHECK(x87_top(c) == 7U);
    x87_pop(c);
    x87_pop(c);
    CHECK(x87_top(c) == 1U);
    CHECK(((c->fstat >> 11) & 7U) == 1U);

    /* default-mode storage: double bits low 8, zeros above */
    reset_fpu(c);
    x87_set_f64(c, 0, d);
    {
        uint64_t lo = 0;
        uint64_t hi = 0;

        for (unsigned i = 0; i < 8; i++) {
            lo |= (uint64_t)c->x87_st[x87_top(c)][i] << (8U * i);
        }
        for (unsigned i = 8; i < 16; i++) {
            hi |= (uint64_t)c->x87_st[x87_top(c)][i] << (8U * (i - 8U));
        }
        CHECK(lo == dbits);
        CHECK(hi == 0U);
    }
    CHECK(x87_get_f64(c, 0) == 1.5);

    /* tag classification: valid / zero / special / empty / sync */
    CHECK(((c->ftag >> (x87_top(c) * 2U)) & 3U) == 0U);
    x87_set_f64(c, 0, 0.0);
    CHECK(((c->ftag >> (x87_top(c) * 2U)) & 3U) == 1U);
    x87_set_f64(c, 0, INFINITY);
    CHECK(((c->ftag >> (x87_top(c) * 2U)) & 3U) == 2U);
    x87_mark_empty(c, 0);
    CHECK(((c->ftag >> (x87_top(c) * 2U)) & 3U) == 3U);
    x87_sync_tag(c);
    CHECK(((c->ftag >> (x87_top(c) * 2U)) & 3U) == 3U);
    x87_set_f64(c, 0, 2.0);
    CHECK(((c->ftag >> (x87_top(c) * 2U)) & 3U) == 0U);

    /* mmx raw view */
    mmx_set(c, 3, 0x1122334455667788ULL);
    CHECK(mmx_get(c, 3) == 0x1122334455667788ULL);

    /* round/prec mode decode */
    c->fctrl = 0x037fU;
    CHECK(x87_round_mode(c) == 0U);
    CHECK(x87_prec_mode(c) == 64U);
    c->fctrl = 0x027fU;
    CHECK(x87_prec_mode(c) == 53U);
    c->fctrl = 0x007fU;
    CHECK(x87_prec_mode(c) == 24U);
    c->fctrl = 0x0c7fU;
    CHECK(x87_round_mode(c) == 3U);

    /* set_exc: ES/B only when unmasked */
    c->fstat = 0;
    c->fctrl = 0x003fU;
    x87_set_exc(c, 0x21U);
    CHECK((c->fstat & 0x21U) == 0x21U);
    CHECK((c->fstat & 0x8080U) == 0U);
    c->fctrl = 0x0000U;
    x87_set_exc(c, 0x02U);
    CHECK((c->fstat & 0x8080U) == 0x8080U);

    /* integer push/pop + get_int under CW RC (default mode) */
    reset_fpu(c);
    x87_set_int(c, -5);
    CHECK(x87_get_f64(c, 0) == -5.0);
    x87_set_f64(c, 0, 2.5);
    c->fctrl = 0x037fU;
    CHECK(x87_get_int(c, 0) == 2);
    c->fctrl = 0x077fU;
    CHECK(x87_get_int(c, 0) == 2);
    c->fctrl = 0x0b7fU;
    CHECK(x87_get_int(c, 0) == 3);
    c->fctrl = 0x0f7fU;
    CHECK(x87_get_int(c, 0) == 2);
    x87_set_f64(c, 0, -2.5);
    c->fctrl = 0x0b7fU;
    CHECK(x87_get_int(c, 0) == -2);
    free(c);
}

/* ------------------------------------------------------------------ */
/* 2. f64 <-> ext80 conversions (fixed bit patterns)                   */
/* ------------------------------------------------------------------ */

static uint64_t e80_lo(const uint8_t b[10])
{
    uint64_t v = 0;

    for (unsigned i = 0; i < 8; i++) {
        v |= (uint64_t)b[i] << (8U * i);
    }
    return v;
}

static uint16_t e80_hi(const uint8_t b[10])
{
    return (uint16_t)((uint16_t)b[8] | ((uint16_t)b[9] << 8));
}

static void test_conversions(void)
{
    uint8_t b[10];

    x87_f64_to_ext80(1.0, b);
    CHECK(e80_lo(b) == 0x8000000000000000ULL);
    CHECK(e80_hi(b) == 0x3fffU);
    x87_f64_to_ext80(-2.5, b);
    CHECK(e80_lo(b) == 0xa000000000000000ULL);
    CHECK(e80_hi(b) == 0xc000U); /* sign | (1 + 16383) */
    x87_f64_to_ext80((double)FLT_TRUE_MIN, b);
    CHECK(x87_ext80_to_f64(b) == (double)FLT_TRUE_MIN);
    x87_f64_to_ext80(INFINITY, b);
    CHECK(e80_hi(b) == 0x7fffU && e80_lo(b) == 0x8000000000000000ULL);
    CHECK(isinf(x87_ext80_to_f64(b)));
    x87_f64_to_ext80((double)NAN, b);
    CHECK(isnan(x87_ext80_to_f64(b)));

    /* RNE on ext80 -> f64: 1+2^-53 rounds down to 1.0; just above the
     * tie rounds up to 1+2^-52 */
    {
        uint64_t mant = 0x8000000000000000ULL | (1ULL << 10); /* 1+2^-53 */

        for (unsigned i = 0; i < 8; i++) {
            b[i] = (uint8_t)(mant >> (8U * i));
        }
        b[8] = 0xffU;
        b[9] = 0x3fU;
        CHECK(x87_ext80_to_f64(b) == 1.0);
        mant |= 1ULL; /* strictly above the tie */
        for (unsigned i = 0; i < 8; i++) {
            b[i] = (uint8_t)(mant >> (8U * i));
        }
        CHECK(x87_ext80_to_f64(b) == 1.0 + 0x1p-52);
    }

    /* round trip over a spread of doubles */
    {
        static const double vs[] = { 0.0, -0.0, 1.0, -1.0, 0.1,
                                     3.141592653589793, 1e300, 1e-300,
                                     9223372036854775808.0 };
        for (unsigned k = 0; k < sizeof(vs) / sizeof(vs[0]); k++) {
            x87_f64_to_ext80(vs[k], b);
            CHECK(x87_ext80_to_f64(b) == vs[k]);
        }
    }

    /* 80-bit mode raw passthrough through the accessors */
    {
        i686_ctx_t *c = mkctx(1);
        uint8_t in[10];
        uint8_t out[10];

        x87_f64_to_ext80(1.5, in);
        x87_push(c);
        x87_set_ext80(c, 0, in);
        x87_get_ext80(c, 0, out);
        CHECK(memcmp(in, out, 10) == 0);
        CHECK(e80_lo(in) == 0xc000000000000000ULL);
        CHECK(e80_hi(in) == 0x3fffU);
        free(c);
    }
}

/* ------------------------------------------------------------------ */
/* 3. handlers, both modes                                             */
/* ------------------------------------------------------------------ */

static void test_load_store(int mode80)
{
    i686_ctx_t *c = mkctx(mode80);

    /* fld/fstp m32 */
    wr32m(c, 0x40200000U); /* 2.5f */
    CHECK(runb(c, 0xD9, 0x00, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 2.5);
    CHECK(c->eip == CODE_VA + 2);
    CHECK(runb(c, 0xD9, 0x18, -1) == 0); /* fstp m32 */
    CHECK(gm_rd32(c, DATA_VA) == 0x40200000U);

    /* fld/fstp m64 */
    wr64m(c, 3.141592653589793);
    CHECK(runb(c, 0xDD, 0x00, -1) == 0); /* fld m64 */
    CHECK(x87_get_f64(c, 0) == 3.141592653589793);
    CHECK(runb(c, 0xDD, 0x18, -1) == 0); /* fstp m64 */
    {
        uint64_t want;

        memcpy(&want, &(double){3.141592653589793}, 8);
        CHECK(gm_rd64(c, DATA_VA) == want);
    }

    /* fld m80 / fstp m80 round trip (1.5's exact ext80) */
    {
        uint64_t mant = 0xc000000000000000ULL;
        uint8_t *p = (uint8_t *)i686_guest_ptr(c, DATA_VA);

        for (unsigned i = 0; i < 8; i++) {
            p[i] = (uint8_t)(mant >> (8U * i));
        }
        p[8] = 0xffU;
        p[9] = 0x3fU;
        CHECK(runb(c, 0xDB, 0x28, -1) == 0); /* fld m80 */
        CHECK(x87_get_f64(c, 0) == 1.5);
        CHECK(runb(c, 0xDB, 0x38, -1) == 0); /* fstp m80 */
        CHECK(p[8] == 0xffU && p[9] == 0x3fU);
        CHECK(gm_rd64(c, DATA_VA) == mant);
    }

    /* fild m32 / fistp m32 */
    wr32m(c, 42U);
    CHECK(runb(c, 0xDB, 0x00, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 42.0);
    CHECK(runb(c, 0xDB, 0x18, -1) == 0);
    CHECK((int32_t)gm_rd32(c, DATA_VA) == 42);

    /* fild m16 negative / fistp m16 */
    wr32m(c, 0xFC18U); /* -1000 int16 */
    CHECK(runb(c, 0xDF, 0x00, -1) == 0);
    CHECK(x87_get_f64(c, 0) == -1000.0);
    CHECK(runb(c, 0xDF, 0x18, -1) == 0);
    CHECK((int16_t)gm_rd32(c, DATA_VA) == -1000);

    /* fistp m16 overflow -> integer indefinite 0x8000 */
    x87_set_f64(c, 0, 1e10);
    CHECK(runb(c, 0xDF, 0x18, -1) == 0);
    CHECK((gm_rd32(c, DATA_VA) & 0xffffU) == 0x8000U);

    /* fild m64 / fistp m64 (within 2^53) */
    gm_wr64m(c, DATA_VA, (uint64_t)1234567890123LL);
    CHECK(runb(c, 0xDF, 0x28, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 1234567890123.0);
    CHECK(runb(c, 0xDF, 0x38, -1) == 0);
    CHECK(gm_rd64(c, DATA_VA) == 1234567890123ULL);

    /* fist rounding per CW RC (m32) */
    wr32m(c, 0U);
    x87_set_f64(c, 0, 2.6);
    c->fctrl = 0x037fU;
    CHECK(runb(c, 0xDB, 0x18, -1) == 0);
    CHECK((int32_t)gm_rd32(c, DATA_VA) == 3);
    x87_set_f64(c, 0, 2.6);
    c->fctrl = 0x0f7fU;
    CHECK(runb(c, 0xDB, 0x18, -1) == 0);
    CHECK((int32_t)gm_rd32(c, DATA_VA) == 2);

    /* fld st(1), fxch, fst/fstp st(i) */
    reset_fpu(c);
    CHECK(runb(c, 0xD9, 0xE8, -1) == 0); /* fld1 */
    CHECK(runb(c, 0xD9, 0xEE, -1) == 0); /* fldz */
    CHECK(x87_get_f64(c, 0) == 0.0 && x87_get_f64(c, 1) == 1.0);
    CHECK(runb(c, 0xD9, 0xC1, -1) == 0); /* fld st(1) */
    CHECK(x87_get_f64(c, 0) == 1.0);
    CHECK(runb(c, 0xD9, 0xC9, -1) == 0); /* fxch st(1) */
    CHECK(x87_get_f64(c, 0) == 0.0 && x87_get_f64(c, 1) == 1.0);
    CHECK(runb(c, 0xDD, 0xD1, -1) == 0); /* fst st(1) */
    CHECK(x87_get_f64(c, 1) == 0.0);
    CHECK(runb(c, 0xDD, 0xD9, -1) == 0); /* fstp st(1) */
    CHECK(x87_top(c) == 6U); /* 3 pushes (top 0->5), one pop -> 6 */
    free(c);
}

static void test_arith(int mode80)
{
    i686_ctx_t *c = mkctx(mode80);
    static const double pairs[][2] = {
        {1.0, 2.5}, {0.5, 0.25}, {1.5, 3.75}, {8.0, 0.5},
    };

    /* long double oracle over exact dyadic values (modes agree) */
    for (unsigned k = 0; k < 4; k++) {
        double a = pairs[k][0];
        double b = pairs[k][1];
        long double la = (long double)a;
        long double lb = (long double)b;

        wr32m(c, 0);
        {
            uint32_t fb32;
            float fb = (float)b;

            memcpy(&fb32, &fb, 4);
            wr32m(c, fb32);
        }
        reset_fpu(c);
        x87_set_f64(c, 0, a);
        CHECK(runb(c, 0xD8, 0x00, -1) == 0); /* fadd m32 */
        CHECK(x87_get_f64(c, 0) == (double)(la + lb));

        wr64m(c, b);
        reset_fpu(c);
        x87_set_f64(c, 0, a);
        CHECK(runb(c, 0xDC, 0x20, -1) == 0); /* fsub m64 (/4) */
        CHECK(x87_get_f64(c, 0) == (double)(la - lb));
        reset_fpu(c);
        x87_set_f64(c, 0, a);
        CHECK(runb(c, 0xDC, 0x28, -1) == 0); /* fsubr m64 (/5) */
        CHECK(x87_get_f64(c, 0) == (double)(lb - la));
        reset_fpu(c);
        x87_set_f64(c, 0, a);
        CHECK(runb(c, 0xDC, 0x08, -1) == 0); /* fmul m64 (/1) */
        CHECK(x87_get_f64(c, 0) == (double)(la * lb));
    }

    /* fdiv/fdivr m64: exact both directions */
    reset_fpu(c);
    x87_set_f64(c, 0, 16.0);
    wr64m(c, 2.0);
    CHECK(runb(c, 0xDC, 0x30, -1) == 0); /* fdiv m64: 16/2 */
    CHECK(x87_get_f64(c, 0) == 8.0);
    reset_fpu(c);
    x87_set_f64(c, 0, 16.0);
    CHECK(runb(c, 0xDC, 0x38, -1) == 0); /* fdivr m64: 2/16 */
    CHECK(x87_get_f64(c, 0) == 0.125);

    /* register forms */
    reset_fpu(c);
    CHECK(runb(c, 0xD9, 0xE8, -1) == 0); /* fld1 */
    CHECK(runb(c, 0xD9, 0xE8, -1) == 0); /* fld1 */
    CHECK(runb(c, 0xD8, 0xC1, -1) == 0); /* fadd st, st(1) */
    CHECK(x87_get_f64(c, 0) == 2.0);

    reset_fpu(c);
    x87_set_int(c, 3);
    x87_set_int(c, 4); /* st0=4, st1=3 */
    CHECK(runb(c, 0xDC, 0xC1, -1) == 0); /* fadd st(1), st */
    CHECK(x87_get_f64(c, 1) == 7.0);

    reset_fpu(c);
    x87_set_int(c, 3);
    x87_set_int(c, 4);
    CHECK(runb(c, 0xDE, 0xC1, -1) == 0); /* faddp st(1) */
    CHECK(x87_get_f64(c, 0) == 7.0);

    reset_fpu(c);
    x87_set_int(c, 9);
    x87_set_int(c, 4);
    CHECK(runb(c, 0xDE, 0xE1, -1) == 0); /* DE E0+1: FSUBRP st(1) = st0-st1 */
    CHECK(x87_get_f64(c, 0) == -5.0);

    reset_fpu(c);
    x87_set_int(c, 9);
    x87_set_int(c, 4);
    CHECK(runb(c, 0xDE, 0xE9, -1) == 0); /* DE E8+1: FSUBP st(1) -= st0 */
    CHECK(x87_get_f64(c, 0) == 5.0);

    reset_fpu(c);
    x87_set_int(c, 8);
    x87_set_int(c, 2);
    CHECK(runb(c, 0xDE, 0xF1, -1) == 0); /* DE F0+1: FDIVRP st(1) = st0/st1 */
    CHECK(x87_get_f64(c, 0) == 0.25);

    reset_fpu(c);
    x87_set_int(c, 8);
    x87_set_int(c, 2);
    CHECK(runb(c, 0xDE, 0xF9, -1) == 0); /* DE F8+1: FDIVP st(1) /= st0 */
    CHECK(x87_get_f64(c, 0) == 4.0);

    /* default-mode directed rounding via the exact-residual path */
    if (!mode80) {
        double one = 1.0 + 0x1p-52;
        double half_ulp = 0x1p-53;

        reset_fpu(c);
        c->fctrl = 0x077fU; /* RC=down */
        wr64m(c, half_ulp);
        x87_set_f64(c, 0, one);
        CHECK(runb(c, 0xDC, 0x00, -1) == 0); /* fadd m64 */
        CHECK(x87_get_f64(c, 0) == one);
        reset_fpu(c);
        c->fctrl = 0x0b7fU; /* RC=up */
        x87_set_f64(c, 0, one);
        CHECK(runb(c, 0xDC, 0x00, -1) == 0);
        CHECK(x87_get_f64(c, 0) == 1.0 + 0x1p-51);
    }
    free(c);
}

static void test_compare(int mode80)
{
    i686_ctx_t *c = mkctx(mode80);

    /* fcom m32: below / equal / above (fcomp pops) */
    reset_fpu(c);
    x87_set_f64(c, 0, 1.0);
    wr32m(c, 0x40000000U); /* 2.0f */
    CHECK(runb(c, 0xD8, 0x10, -1) == 0);
    CHECK((c->fstat & 0x4700U) == 0x0100U); /* C0: st0 < src */
    wr32m(c, 0x3f800000U); /* 1.0f */
    CHECK(runb(c, 0xD8, 0x10, -1) == 0);
    CHECK((c->fstat & 0x4700U) == 0x4000U); /* C3: equal */
    wr32m(c, 0x3f000000U); /* 0.5f */
    CHECK(runb(c, 0xD8, 0x18, -1) == 0); /* fcomp */
    CHECK((c->fstat & 0x4700U) == 0U); /* above */

    /* fcom with QNaN: unordered + IE (ordered compare) */
    reset_fpu(c);
    x87_set_f64(c, 0, (double)NAN);
    wr32m(c, 0x3f800000U);
    c->fstat = 0;
    CHECK(runb(c, 0xD8, 0x10, -1) == 0);
    CHECK((c->fstat & 0x4700U) == 0x4500U); /* C0|C2|C3 */
    CHECK((c->fstat & 0x3fU) == 0x01U); /* IE */

    /* fucom st(1) with QNaN: unordered, NO IE */
    reset_fpu(c);
    push_d(c, (double)NAN);
    push_d(c, 2.0);
    c->fstat = 0;
    CHECK(runb(c, 0xDD, 0xE1, -1) == 0);
    CHECK((c->fstat & 0x4700U) == 0x4500U);
    CHECK((c->fstat & 0x3fU) == 0U);

    /* fucompp pops two */
    reset_fpu(c);
    x87_set_int(c, 1);
    x87_set_int(c, 2);
    CHECK(runb(c, 0xDA, 0xE9, -1) == 0);
    CHECK(x87_top(c) == 0U);

    /* ftst */
    reset_fpu(c);
    x87_set_f64(c, 0, 0.0);
    CHECK(runb(c, 0xD9, 0xE4, -1) == 0);
    CHECK((c->fstat & 0x4700U) == 0x4000U);
    x87_set_f64(c, 0, -1.0);
    CHECK(runb(c, 0xD9, 0xE4, -1) == 0);
    CHECK((c->fstat & 0x4700U) == 0x0100U);

    /* fxam: normal; -0 is zero-class with C1 sign */
    reset_fpu(c);
    x87_set_f64(c, 0, 1.5);
    CHECK(runb(c, 0xD9, 0xE5, -1) == 0);
    CHECK((c->fstat & 0x4700U) == 0x0400U); /* C2: normal */
    x87_set_f64(c, 0, -0.0);
    CHECK(runb(c, 0xD9, 0xE5, -1) == 0);
    CHECK((c->fstat & 0x4700U) == 0x4200U); /* C3|C1: zero, negative */

    /* fcomi/fcomip: EFLAGS CF/ZF, OF/SF/AF cleared, pop discipline */
    reset_fpu(c);
    x87_set_int(c, 1);
    x87_set_int(c, 2); /* st0=2 st1=1 -> greater */
    c->eflags = 0xffffffffU;
    CHECK(runb(c, 0xDB, 0xF1, -1) == 0); /* fcomi st(1) */
    CHECK((c->eflags & (I686_EF_CF | I686_EF_ZF | I686_EF_PF | I686_EF_OF |
                        I686_EF_SF | I686_EF_AF)) == 0U);
    CHECK(x87_top(c) == 6U); /* depth 2 from top=0 -> 6, no pop */

    reset_fpu(c);
    x87_set_int(c, 2);
    x87_set_int(c, 2);
    c->eflags = 0xffffffffU;
    CHECK(runb(c, 0xDF, 0xF1, -1) == 0); /* fcomip st(1) */
    CHECK((c->eflags & I686_EF_ZF) != 0U);
    CHECK((c->eflags & I686_EF_CF) == 0U);
    CHECK(x87_top(c) == 7U); /* popped once from 6 */
    free(c);
}

static void test_transcendentals(int mode80)
{
    i686_ctx_t *c = mkctx(mode80);
    uint8_t b[10];

    /* fchs / fabs */
    reset_fpu(c);
    x87_set_f64(c, 0, -3.0);
    CHECK(runb(c, 0xD9, 0xE0, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 3.0);
    x87_set_f64(c, 0, -3.0);
    CHECK(runb(c, 0xD9, 0xE1, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 3.0);

    /* constants */
    reset_fpu(c);
    CHECK(runb(c, 0xD9, 0xE8, -1) == 0); /* fld1 */
    CHECK(x87_get_f64(c, 0) == 1.0);
    if (mode80) { /* raw ext80 of fld1 before the stack grows */
        x87_get_ext80(c, 0, b);
        CHECK(e80_lo(b) == 0x8000000000000000ULL);
        CHECK(e80_hi(b) == 0x3fffU);
    }
    CHECK(runb(c, 0xD9, 0xEE, -1) == 0); /* fldz */
    CHECK(x87_get_f64(c, 0) == 0.0 && !signbit(x87_get_f64(c, 0)));
    CHECK(runb(c, 0xD9, 0xEB, -1) == 0); /* fldpi */
    CHECK(x87_get_f64(c, 0) == 3.141592653589793);
    CHECK(runb(c, 0xD9, 0xEA, -1) == 0); /* fldl2e */
    CHECK(x87_get_f64(c, 0) == 1.4426950408889634);
    CHECK(runb(c, 0xD9, 0xED, -1) == 0); /* fldln2 */
    CHECK(x87_get_f64(c, 0) == 0.6931471805599453);
    CHECK(runb(c, 0xD9, 0xE9, -1) == 0); /* fldl2t */
    CHECK(x87_get_f64(c, 0) == 3.321928094887362);
    CHECK(runb(c, 0xD9, 0xEC, -1) == 0); /* fldlg2 */
    CHECK(x87_get_f64(c, 0) == 0.3010299956639812);

    /* fsqrt */
    reset_fpu(c);
    x87_set_f64(c, 0, 4.0);
    CHECK(runb(c, 0xD9, 0xFA, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 2.0);

    /* frndint under all four RC values */
    reset_fpu(c);
    x87_set_f64(c, 0, 2.5);
    c->fctrl = 0x037fU;
    CHECK(runb(c, 0xD9, 0xFC, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 2.0);
    x87_set_f64(c, 0, 2.5);
    c->fctrl = 0x077fU;
    CHECK(runb(c, 0xD9, 0xFC, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 2.0);
    x87_set_f64(c, 0, 2.5);
    c->fctrl = 0x0b7fU;
    CHECK(runb(c, 0xD9, 0xFC, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 3.0);
    x87_set_f64(c, 0, -2.5);
    c->fctrl = 0x0f7fU;
    CHECK(runb(c, 0xD9, 0xFC, -1) == 0);
    CHECK(x87_get_f64(c, 0) == -2.0);

    /* fscale: st0 *= 2^trunc(st1); st1 unchanged */
    reset_fpu(c);
    push_d(c, 4.0);
    push_d(c, 1.5); /* st0=1.5, st1=4 */
    CHECK(runb(c, 0xD9, 0xFD, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 24.0);
    CHECK(x87_get_f64(c, 1) == 4.0);

    /* fprem: value + qq condition codes (q=3: C1,C3) */
    reset_fpu(c);
    push_d(c, 2.0);
    push_d(c, 7.5);
    CHECK(runb(c, 0xD9, 0xF8, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 1.5);
    CHECK((c->fstat & 0x4700U) == 0x4200U);

    /* fprem1: q=4 -> r=-0.5, C0 set */
    reset_fpu(c);
    push_d(c, 2.0);
    push_d(c, 7.5);
    CHECK(runb(c, 0xD9, 0xF5, -1) == 0);
    CHECK(x87_get_f64(c, 0) == -0.5);
    CHECK((c->fstat & 0x4700U) == 0x0100U);

    /* fxtract: st0=24 -> sig 1.5, exp 4 */
    reset_fpu(c);
    x87_set_f64(c, 0, 24.0);
    CHECK(runb(c, 0xD9, 0xF4, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 1.5);
    CHECK(x87_get_f64(c, 1) == 4.0);

    /* f2xm1 at 0 and 1 */
    reset_fpu(c);
    x87_set_f64(c, 0, 0.0);
    CHECK(runb(c, 0xD9, 0xF0, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 0.0);
    x87_set_f64(c, 0, 1.0);
    CHECK(runb(c, 0xD9, 0xF0, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 1.0);

    /* fyl2x: st1 * log2(st0), pop */
    reset_fpu(c);
    push_d(c, 0.5);
    push_d(c, 8.0);
    CHECK(runb(c, 0xD9, 0xF1, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 1.5);

    /* fyl2xp1: st1 * log2(1+st0) = 1 * log2(2) = 1 */
    reset_fpu(c);
    push_d(c, 1.0);
    push_d(c, 1.0);
    CHECK(runb(c, 0xD9, 0xF9, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 1.0);

    /* fptan(0): tan 0 then push 1 */
    reset_fpu(c);
    x87_set_f64(c, 0, 0.0);
    CHECK(runb(c, 0xD9, 0xF2, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 1.0);
    CHECK(x87_get_f64(c, 1) == 0.0);

    /* fpatan(1,1) = pi/4 */
    reset_fpu(c);
    push_d(c, 1.0);
    push_d(c, 1.0);
    CHECK(runb(c, 0xD9, 0xF3, -1) == 0);
    CHECK(fabs(x87_get_f64(c, 0) - 3.141592653589793 / 4.0) < 1e-15);

    /* fsin/fcos at 0, then fsincos on a fresh 0 */
    reset_fpu(c);
    x87_set_f64(c, 0, 0.0);
    CHECK(runb(c, 0xD9, 0xFE, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 0.0);
    CHECK(runb(c, 0xD9, 0xFF, -1) == 0);
    CHECK(x87_get_f64(c, 0) == 1.0);
    reset_fpu(c);
    x87_set_f64(c, 0, 0.0);
    CHECK(runb(c, 0xD9, 0xFB, -1) == 0); /* fsincos */
    CHECK(x87_get_f64(c, 0) == 1.0); /* cos on top */
    CHECK(x87_get_f64(c, 1) == 0.0); /* sin below */
    free(c);
}

static void test_env(int mode80)
{
    i686_ctx_t *c = mkctx(mode80);

    /* fldcw / fnstcw */
    wr32m(c, 0x0f7fU);
    CHECK(runb(c, 0xD9, 0x28, -1) == 0);
    CHECK(c->fctrl == 0x0f7fU);
    wr32m(c, 0U);
    CHECK(runb(c, 0xD9, 0x38, -1) == 0);
    CHECK(gm_rd32(c, DATA_VA) == 0x0f7fU);

    /* fnstsw AX mirrors fstat incl TOP */
    reset_fpu(c);
    x87_set_int(c, 1);
    c->fstat |= 0x0101U;
    c->gpr[I686_REG_EAX] = 0xffff0000U;
    CHECK(runb(c, 0xDF, 0xE0, -1) == 0);
    CHECK((c->gpr[I686_REG_EAX] & 0xffffU) == (c->fstat & 0xffffU));
    CHECK((c->gpr[I686_REG_EAX] & 0xffffU) != 0U);

    /* fnstsw m16 */
    wr32m(c, 0U);
    c->gpr[I686_REG_EAX] = DATA_VA;
    CHECK(runb(c, 0xDD, 0x38, -1) == 0);
    CHECK(gm_rd32(c, DATA_VA) == (c->fstat & 0xffffU));

    /* fnstenv/fldenv 28-byte layout: CW@0 SW@4 TW@8 */
    reset_fpu(c);
    x87_set_int(c, 7);
    {
        uint8_t *p = (uint8_t *)i686_guest_ptr(c, ENV_VA);

        memset(p, 0xAA, 28);
        c->gpr[I686_REG_EAX] = ENV_VA;
        CHECK(runb(c, 0xD9, 0x30, -1) == 0); /* fnstenv */
        CHECK(gm_rd32(c, ENV_VA + 0) == 0x037fU);
        CHECK((gm_rd32(c, ENV_VA + 4) & 0xffffU) == (c->fstat & 0xffffU));
        /* top=7 -> physical slot 7 (bits 14-15) valid */
        CHECK(gm_rd32(c, ENV_VA + 8) == 0x3fffU);
        CHECK(p[12] == 0 && p[13] == 0); /* FPU IP zeroed (v1) */
        p[0] = 0x7fU;
        p[1] = 0x0fU;
        CHECK(runb(c, 0xD9, 0x20, -1) == 0); /* fldenv */
        CHECK(c->fctrl == 0x0f7fU);
        CHECK(c->ftag == 0x3fffU);
    }

    /* fxsave/fxrstor m512 */
    reset_fpu(c);
    x87_set_int(c, 1);
    push_d(c, 2.5); /* st0=2.5, st1=1 */
    c->mxcsr = 0x1f80U;
    c->xmm[3][0] = 0x99U;
    {
        uint8_t *img = (uint8_t *)i686_guest_ptr(c, FX_VA);

        memset(img, 0xCC, 512);
        c->gpr[I686_REG_EAX] = FX_VA;
        CHECK(runb(c, 0x0F, 0xAE, 0x00, -1) == 0); /* fxsave */
        CHECK((gm_rd32(c, FX_VA + 0) & 0xffffU) == 0x037fU);
        CHECK((gm_rd32(c, FX_VA + 2) & 0xffffU) == (uint32_t)(c->fstat & 0xffffU));
        CHECK(gm_rd32(c, FX_VA + 24) == 0x1f80U);
        CHECK(img[4] == 0x3fU); /* abridged tag: slots 6,7 non-empty */
        CHECK(gm_rd64(c, FX_VA + 32) == 0xa000000000000000ULL); /* 2.5 */
        CHECK(img[40] == 0x00U && img[41] == 0x40U); /* se 0x4000 */
        CHECK(gm_rd64(c, FX_VA + 48) == 0x8000000000000000ULL); /* 1.0 */
        CHECK(img[160 + 16 * 3] == 0x99U);

        reset_fpu(c);
        c->xmm[3][0] = 0;
        CHECK(runb(c, 0x0F, 0xAE, 0x08, -1) == 0); /* fxrstor */
        CHECK(x87_get_f64(c, 0) == 2.5);
        CHECK(x87_get_f64(c, 1) == 1.0);
        CHECK(c->mxcsr == 0x1f80U);
        CHECK(c->xmm[3][0] == 0x99U);
        CHECK(((c->ftag >> (x87_top(c) * 2U)) & 3U) == 0U);
    }

    /* fnclex / fninit */
    reset_fpu(c);
    x87_set_int(c, 5);
    c->fstat |= 0x80ffU;
    CHECK(runb(c, 0xDB, 0xE2, -1) == 0);
    CHECK((c->fstat & 0x80ffU) == 0U);
    CHECK(((c->fstat >> 11) & 7U) == x87_top(c));
    CHECK(runb(c, 0xDB, 0xE3, -1) == 0);
    CHECK(c->fctrl == 0x037fU && c->fstat == 0 && c->ftag == 0xffffU);
    CHECK(x87_top(c) == 0U);

    /* emms */
    reset_fpu(c);
    x87_set_int(c, 5);
    x87_set_int(c, 6);
    CHECK(runb(c, 0x0F, 0x77, -1) == 0);
    CHECK(c->ftag == 0xffffU);

    /* fnop: no state change */
    reset_fpu(c);
    x87_set_int(c, 3);
    {
        uint16_t fstat = c->fstat;
        uint8_t top = x87_top(c);

        CHECK(runb(c, 0xD9, 0xD0, -1) == 0);
        CHECK(c->fstat == fstat && x87_top(c) == top);
    }

    /* ffree / fincstp / fdecstp */
    reset_fpu(c);
    x87_set_int(c, 3);
    x87_set_int(c, 4);
    CHECK(runb(c, 0xDD, 0xC1, -1) == 0); /* ffree st(1) */
    CHECK(((c->ftag >> (((x87_top(c) + 1U) & 7U) * 2U)) & 3U) == 3U);
    {
        uint8_t top = x87_top(c);

        CHECK(runb(c, 0xD9, 0xF7, -1) == 0); /* fincstp */
        CHECK(x87_top(c) == ((top + 1U) & 7U));
        CHECK(runb(c, 0xD9, 0xF6, -1) == 0); /* fdecstp */
        CHECK(x87_top(c) == top);
    }

    /* stack wrap through fld1 handlers */
    reset_fpu(c);
    for (int i = 0; i < 10; i++) {
        CHECK(runb(c, 0xD9, 0xE8, -1) == 0);
    }
    CHECK(x87_top(c) == 6U);
    CHECK(((c->fstat >> 11) & 7U) == 6U);
    free(c);
}

static void test_declined(int mode80)
{
    i686_ctx_t *c = mkctx(mode80);
    uint32_t eip_before;

    c->gpr[I686_REG_EAX] = DATA_VA;
    /* FIADD m32 (DA /0): INVALID group slot -> decode fails */
    CHECK(runb(c, 0xDA, 0x00, -1) == -2);
    /* FISTTP m32 (DB /1): declined slot -> decode fails */
    CHECK(runb(c, 0xDB, 0x08, -1) == -2);
    /* FBLD m80 (DF /4 memory): FNSTSW_AX id, memory form refused */
    CHECK(runb(c, 0xDF, 0x20, -1) == I686_EXIT_UNDEF);
    eip_before = c->eip;
    CHECK(runb(c, 0xDF, 0x20, -1) == I686_EXIT_UNDEF);
    CHECK(c->eip == eip_before); /* UNDEF never advances EIP */
    /* FIADD m16 (DE /0 memory): FADDP id, memory refused at runtime */
    CHECK(runb(c, 0xDE, 0x00, -1) == I686_EXIT_UNDEF);
    /* D9 D1: undefined fixed second byte */
    CHECK(runb(c, 0xD9, 0xD1, -1) == I686_EXIT_UNDEF);
    /* D9 /1 memory (FXCH slot): invalid memory form */
    CHECK(runb(c, 0xD9, 0x08, -1) == I686_EXIT_UNDEF);
    free(c);
}

int main(void)
{
    t_win = malloc(WIN_SIZE);
    if (t_win == NULL) {
        printf("FAIL: no window\n");
        return 1;
    }
    memset(t_win, 0, WIN_SIZE);

    i686_interp_x87_init();

    test_state_core();
    test_conversions();
    for (int mode = 0; mode <= 1; mode++) {
        test_load_store(mode);
        test_arith(mode);
        test_compare(mode);
        test_transcendentals(mode);
        test_env(mode);
        test_declined(mode);
    }

    printf("%d checks, %d failed\n", t_pass, t_fail);
    if (t_fail != 0) {
        return 1;
    }
    printf("L5C OK\n");
    return 0;
}
