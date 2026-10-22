/*
 * tests/unit/test_l5b.c — host-native unit driver for lane L5b
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the SSE/SSE2/MMX interpreter handlers of src/interp/h_sse.c
 * directly: after calling i686_interp_sse_init() (the coordinator wires
 * the call into i686_interp_init_all at S5), every case invokes the
 * registered handler with a hand-built x86_insn_t over a fake guest
 * window (tests/unit/test_l2e.c pattern).  Little-endian IEEE-754 host
 * assumed (macOS arm64, aarch64 Linux).
 *
 * Covers: sse.h state helpers (xmm get/set bounds, MXCSR masking and
 * the mxcsr_mask publication choice, RC/FTZ/DAZ getters), packed and
 * scalar add/sub/mul/div in f32+f64 incl. FTZ/DAZ on and off, 0/0 and
 * x/0 exception bits, all 8 CMPPS predicates on (1,2)/(2,1)/(nan,1),
 * MOVMSKPS/PD, COMISD/UCOMISD flag mapping, the cvt families incl.
 * CVTTPS2DQ overflow -> 0x80000000, the integer MMX/SSE2 ops, shuffles,
 * MOVD/MOVQ gpr forms, memory-form MOVUPS/MOVHPD/MOVLPD, LDMXCSR/STMXCSR
 * masking, and EMMS.  Prints "L5B OK" and exits 0 when all checks pass.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "i686rt.h"
#include "interp/interp.h"
#include "interp/sse.h"

/* src/interp/h_sse.c export (wired into i686_interp_init_all at S5). */
extern void i686_interp_sse_init(void);

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

static int g_pass;
static int g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

/* Test-local handler registry (interp.c is not linked into this unit
 * test; h_sse.c's only external dependency is i686_interp_register). */
static i686_interp_fn t_reg[I686_OP_COUNT];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    if ((unsigned)op < I686_OP_COUNT) {
        t_reg[op] = fn;
    }
}

/* Test-local lazy-flags stub (src/interp/flags.c is not linked; the
 * test always keeps ctx->eflags authoritative, lazy_op = NONE). */
void i686_flags_materialize(i686_ctx_t *ctx)
{
    (void)ctx;
}

/* MXCSR exception bits (mirror of src/interp/h_sse.c). */
#define T_IE 0x01u
#define T_DE 0x02u
#define T_ZE 0x04u
#define T_OE 0x08u
#define T_UE 0x10u
#define T_PE 0x20u
#define T_DAZ 0x40u
#define T_FTZ 0x8000u

#define DATA_VA 0x2000u

static uint8_t g_window[0x10000];
static i686_ctx_t ctx;

static void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
    ctx.lazy_op = I686_FOP_NONE;
    memset(g_window, 0, sizeof g_window);
}

static void w32va(uint32_t va, uint32_t v)
{
    memcpy(&g_window[va], &v, 4);
}

static void w64va(uint32_t va, uint64_t v)
{
    memcpy(&g_window[va], &v, 8);
}

static uint32_t r32va(uint32_t va)
{
    uint32_t v;
    memcpy(&v, &g_window[va], 4);
    return v;
}

static uint64_t r64va(uint32_t va)
{
    uint64_t v;
    memcpy(&v, &g_window[va], 8);
    return v;
}

/* Hand-built insn: reg-reg form. */
static x86_insn_t mkrr(uint16_t op, unsigned reg, unsigned rm)
{
    x86_insn_t i;
    memset(&i, 0, sizeof i);
    i.op = op;
    i.opnd[0] = I686_OPND_R32;
    i.opnd[1] = I686_OPND_RM32;
    i.len = 4;
    i.has_modrm = 1;
    i.modrm_mod = 3;
    i.modrm_reg = (uint8_t)reg;
    i.modrm_rm = (uint8_t)rm;
    i.pfx_seg = 0xFF;
    return i;
}

/* Hand-built insn: memory form at DATA_VA. */
static x86_insn_t mkmem(uint16_t op, unsigned reg)
{
    x86_insn_t i = mkrr(op, reg, 0);
    i.modrm_mod = 0;
    i.ea_has = 1;
    i.ea_base = 0xFF;
    i.ea_index = 0xFF;
    i.ea_disp = DATA_VA;
    return i;
}

static int run(const x86_insn_t *insn)
{
    return t_reg[insn->op](&ctx, insn);
}

/* FP bit helpers. */
static uint32_t bitsf(float f)
{
    uint32_t u;
    memcpy(&u, &f, 4);
    return u;
}

static uint32_t xl32(unsigned reg, unsigned lane)
{
    uint32_t v;
    memcpy(&v, ctx.xmm[reg] + 4U * lane, 4);
    return v;
}

static void xs32(unsigned reg, unsigned lane, uint32_t b)
{
    memcpy(ctx.xmm[reg] + 4U * lane, &b, 4);
}

static uint64_t xl64(unsigned reg, unsigned lane)
{
    uint64_t v;
    memcpy(&v, ctx.xmm[reg] + 8U * lane, 8);
    return v;
}

static void xs64(unsigned reg, unsigned lane, uint64_t b)
{
    memcpy(ctx.xmm[reg] + 8U * lane, &b, 8);
}

static uint64_t mm(unsigned reg)
{
    uint64_t v;
    memcpy(&v, ctx.x87_st[reg], 8);
    return v;
}

static void mmset(unsigned reg, uint64_t v)
{
    memcpy(ctx.x87_st[reg], &v, 8);
}

/* ------------------------------------------------------------------ */
/* sse.h state helpers                                                 */
/* ------------------------------------------------------------------ */

static void t_state(void)
{
    uint8_t buf[16], out[16];
    unsigned i;

    for (i = 0; i < 16; i++) {
        buf[i] = (uint8_t)(0x10 + i);
    }
    sse_set_xmm(&ctx, 3, buf);
    sse_get_xmm(&ctx, 3, out);
    CHECK(memcmp(buf, out, 16) == 0);                    /* xmm roundtrip */
    memset(ctx.xmm[5], 0xAB, 16);
    sse_set_xmm(&ctx, 9, buf);                           /* OOR: ignored */
    CHECK(ctx.xmm[5][0] == 0xAB && ctx.xmm[5][15] == 0xAB);
    sse_get_xmm(&ctx, 9, out);                           /* OOR: zeros */
    CHECK(out[0] == 0 && out[15] == 0);

    /* Masking: reserved bits read/write-masked; first set publishes
     * mxcsr_mask = 0xFFFF (documented DAZ-supported choice). */
    ctx.mxcsr_mask = 0;
    sse_set_mxcsr(&ctx, 0xFFFFFFFFu);
    CHECK(sse_get_mxcsr(&ctx) == 0x0000FFFFu);
    CHECK(ctx.mxcsr_mask == 0xFFFFu);
    ctx.mxcsr_mask = 0xFFBFu;                            /* preset kept */
    sse_set_mxcsr(&ctx, 0x12345678u);
    CHECK(ctx.mxcsr_mask == 0xFFBFu);
    CHECK(sse_get_mxcsr(&ctx) == 0x5678u);

    /* RC/FTZ/DAZ getters (0xE040: RC=3, FTZ=1, DAZ=1). */
    sse_set_mxcsr(&ctx, 0x0000E040u);
    CHECK(sse_round_mode(&ctx) == 3U);
    CHECK(sse_ftz(&ctx));
    CHECK(sse_daz(&ctx));
    sse_set_mxcsr(&ctx, 0x00000000u);
    CHECK(!sse_ftz(&ctx) && !sse_daz(&ctx) && sse_round_mode(&ctx) == 0U);
}

/* ------------------------------------------------------------------ */
/* Packed/scalar arithmetic                                            */
/* ------------------------------------------------------------------ */

static void t_arith(void)
{
    x86_insn_t in;

    /* ADDPS: (1,2,3,4) + (10,20,30,40) = (11,22,33,44). */
    reset();
    xs32(0, 0, bitsf(1.0f)); xs32(0, 1, bitsf(2.0f));
    xs32(0, 2, bitsf(3.0f)); xs32(0, 3, bitsf(4.0f));
    xs32(1, 0, bitsf(10.0f)); xs32(1, 1, bitsf(20.0f));
    xs32(1, 2, bitsf(30.0f)); xs32(1, 3, bitsf(40.0f));
    in = mkrr(I686_OP_ADDPS, 0, 1);
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(11.0f) && xl32(0, 1) == bitsf(22.0f) &&
          xl32(0, 2) == bitsf(33.0f) && xl32(0, 3) == bitsf(44.0f));

    /* ADDSS (F3): lane 0 only, upper preserved. */
    reset();
    xs32(0, 0, bitsf(1.0f)); xs32(0, 1, bitsf(2.0f));
    xs32(0, 2, bitsf(3.0f)); xs32(0, 3, bitsf(4.0f));
    xs32(1, 0, bitsf(10.0f));
    in = mkrr(I686_OP_ADDPS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(11.0f) && xl32(0, 1) == bitsf(2.0f) &&
          xl32(0, 2) == bitsf(3.0f) && xl32(0, 3) == bitsf(4.0f));

    /* ADDPD (66): (1.5, 2.5) + (0.25, 0.25). */
    reset();
    xs64(0, 0, 0x3FF8000000000000ull); /* 1.5 */
    xs64(0, 1, 0x4004000000000000ull); /* 2.5 */
    xs64(1, 0, 0x3FD0000000000000ull); /* 0.25 */
    xs64(1, 1, 0x3FD0000000000000ull);
    in = mkrr(I686_OP_ADDPS, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x3FFC000000000000ull &&  /* 1.75 */
          xl64(0, 1) == 0x4006000000000000ull);   /* 2.75 */

    /* ADDSD (F2): lane 0 only. */
    reset();
    xs64(0, 0, 0x3FF0000000000000ull);
    xs64(0, 1, 0x1111111111111111ull);
    xs64(1, 0, 0x4000000000000000ull); /* 2.0 */
    in = mkrr(I686_OP_ADDPS, 0, 1);
    in.pfx_rep = 2;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x4008000000000000ull &&  /* 3.0 */
          xl64(0, 1) == 0x1111111111111111ull);

    /* SUBPS + SUBSD. */
    reset();
    xs32(0, 0, bitsf(5.0f)); xs32(0, 1, bitsf(1.25f));
    xs32(0, 2, bitsf(0.0f)); xs32(0, 3, bitsf(9.0f));
    xs32(1, 0, bitsf(2.0f)); xs32(1, 1, bitsf(0.25f));
    xs32(1, 2, bitsf(1.0f)); xs32(1, 3, bitsf(3.0f));
    in = mkrr(I686_OP_SUBPS, 0, 1);
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(3.0f) && xl32(0, 1) == bitsf(1.0f) &&
          xl32(0, 2) == bitsf(-1.0f) && xl32(0, 3) == bitsf(6.0f));
    reset();
    xs64(0, 0, 0x4059000000000000ull); /* 100.0 */
    xs64(1, 0, 0x4000000000000000ull); /* 2.0 */
    in = mkrr(I686_OP_SUBPS, 0, 1);
    in.pfx_rep = 2;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x4058800000000000ull); /* 98.0 */

    /* MULPS + MULPD. */
    reset();
    xs32(0, 0, bitsf(3.0f)); xs32(0, 1, bitsf(-2.0f));
    xs32(0, 2, bitsf(0.5f)); xs32(0, 3, bitsf(7.0f));
    xs32(1, 0, bitsf(2.0f)); xs32(1, 1, bitsf(4.0f));
    xs32(1, 2, bitsf(8.0f)); xs32(1, 3, bitsf(0.0f));
    in = mkrr(I686_OP_MULPS, 0, 1);
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(6.0f) && xl32(0, 1) == bitsf(-8.0f) &&
          xl32(0, 2) == bitsf(4.0f) && xl32(0, 3) == bitsf(0.0f));
    reset();
    xs64(0, 0, 0x3FF8000000000000ull); /* 1.5 */
    xs64(1, 0, 0x4008000000000000ull); /* 3.0 */
    in = mkrr(I686_OP_MULPS, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x4012000000000000ull); /* 4.5 */

    /* DIVPS: x/0 -> +-inf + ZE. */
    reset();
    xs32(0, 0, bitsf(1.0f)); xs32(0, 1, bitsf(-2.0f));
    xs32(0, 2, bitsf(0.0f)); xs32(0, 3, bitsf(9.0f));
    xs32(1, 0, bitsf(0.0f)); xs32(1, 1, bitsf(0.0f));
    xs32(1, 2, bitsf(0.0f)); xs32(1, 3, bitsf(3.0f));
    in = mkrr(I686_OP_DIVPS, 0, 1);
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x7F800000u && xl32(0, 1) == 0xFF800000u &&
          xl32(0, 2) == 0xFFC00000u && xl32(0, 3) == bitsf(3.0f));
    CHECK((ctx.mxcsr & T_ZE) != 0);                      /* 1/0 and -2/0 */
    CHECK((ctx.mxcsr & T_IE) != 0);                      /* 0/0 invalid  */

    /* DIVSD: 1.0/0.0 -> +inf + ZE, no IE beyond this lane. */
    reset();
    xs64(0, 0, 0x3FF0000000000000ull);
    xs64(1, 0, 0x0000000000000000ull);
    in = mkrr(I686_OP_DIVPS, 0, 1);
    in.pfx_rep = 2;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x7FF0000000000000ull);
    CHECK((ctx.mxcsr & T_ZE) != 0 && (ctx.mxcsr & T_IE) == 0);

    /* Scalar f32 division value check: 1/3. */
    reset();
    xs32(0, 0, bitsf(1.0f));
    xs32(1, 0, bitsf(3.0f));
    in = mkrr(I686_OP_DIVPS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(1.0f / 3.0f));
}

static void t_ftz_daz(void)
{
    x86_insn_t in;

    /* FLT_MIN * 0.5 = exact subnormal 0x00400000.  FTZ off: kept, no
     * flags (exact).  FTZ on: +0 + UE|PE. */
    reset();
    xs32(0, 0, 0x00800000u); /* FLT_MIN */
    xs32(1, 0, bitsf(0.5f));
    in = mkrr(I686_OP_MULPS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x00400000u);
    CHECK((ctx.mxcsr & (T_UE | T_PE | T_DE)) == 0);

    reset();
    sse_set_mxcsr(&ctx, T_FTZ);
    xs32(0, 0, 0x00800000u);
    xs32(1, 0, bitsf(0.5f));
    in = mkrr(I686_OP_MULPS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x00000000u);
    CHECK((ctx.mxcsr & T_UE) != 0 && (ctx.mxcsr & T_PE) != 0);

    /* Inexact underflow without FTZ: tiny + inexact -> UE|PE. */
    reset();
    xs32(0, 0, 0x00000001u); /* smallest subnormal */
    xs32(1, 0, bitsf(0.5f)); /* product 2^-150 -> rounds to 0 */
    in = mkrr(I686_OP_MULPS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x00000000u);
    CHECK((ctx.mxcsr & (T_UE | T_PE | T_DE)) == (T_UE | T_PE | T_DE));

    /* DAZ on: denormal inputs are signed zeros (no DE). */
    reset();
    sse_set_mxcsr(&ctx, T_DAZ);
    xs32(0, 0, 0x00000001u);
    xs32(1, 0, 0x00000002u);
    in = mkrr(I686_OP_ADDPS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x00000000u);
    CHECK((ctx.mxcsr & T_DE) == 0);

    /* DAZ off: denormal inputs set DE; denorm+denorm = exact subnormal. */
    reset();
    xs32(0, 0, 0x00000001u);
    xs32(1, 0, 0x00000002u);
    in = mkrr(I686_OP_ADDPS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x00000003u);
    CHECK((ctx.mxcsr & T_DE) != 0);
    CHECK((ctx.mxcsr & (T_UE | T_PE)) == 0); /* exact result */

    /* f64 DAZ/DE mirror. */
    reset();
    sse_set_mxcsr(&ctx, T_DAZ);
    xs64(0, 0, 0x0000000000000001ull); /* smallest f64 subnormal */
    xs64(1, 0, 0x0000000000000002ull);
    in = mkrr(I686_OP_ADDPS, 0, 1);
    in.pfx_rep = 2;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x0000000000000000ull);
    CHECK((ctx.mxcsr & T_DE) == 0);
}

/* ------------------------------------------------------------------ */
/* CMPPS predicates                                                    */
/* ------------------------------------------------------------------ */

static void t_cmpps(void)
{
    /* (want for a=1,b=2), (a=2,b=1), (a=nan,b=1) per predicate 0..7. */
    static const int w1[8] = { 0, 1, 1, 0, 1, 0, 0, 1 };
    static const int w2[8] = { 0, 0, 0, 0, 1, 1, 1, 1 };
    static const int wn[8] = { 0, 0, 0, 1, 1, 1, 1, 0 };
    unsigned pred;

    for (pred = 0; pred < 8U; pred++) {
        x86_insn_t in;
        reset();
        xs32(0, 0, bitsf(1.0f)); xs32(0, 1, bitsf(1.0f));
        xs32(0, 2, bitsf(1.0f)); xs32(0, 3, bitsf(1.0f));
        xs32(1, 0, bitsf(2.0f)); xs32(1, 1, bitsf(2.0f));
        xs32(1, 2, bitsf(2.0f)); xs32(1, 3, bitsf(2.0f));
        in = mkrr(I686_OP_CMPPS, 0, 1);
        in.imm = pred;
        CHECK(run(&in) == 0);
        CHECK((xl32(0, 0) == 0xFFFFFFFFu) == (w1[pred] != 0));

        reset();
        xs32(0, 0, bitsf(2.0f)); xs32(0, 1, bitsf(2.0f));
        xs32(0, 2, bitsf(2.0f)); xs32(0, 3, bitsf(2.0f));
        xs32(1, 0, bitsf(1.0f)); xs32(1, 1, bitsf(1.0f));
        xs32(1, 2, bitsf(1.0f)); xs32(1, 3, bitsf(1.0f));
        in = mkrr(I686_OP_CMPPS, 0, 1);
        in.imm = pred;
        CHECK(run(&in) == 0);
        CHECK((xl32(0, 0) == 0xFFFFFFFFu) == (w2[pred] != 0));

        reset();
        xs32(0, 0, 0x7FC00000u); /* QNaN */
        xs32(0, 1, 0x7FC00000u);
        xs32(1, 0, bitsf(1.0f)); xs32(1, 1, bitsf(1.0f));
        in = mkrr(I686_OP_CMPPS, 0, 1);
        in.imm = pred;
        CHECK(run(&in) == 0);
        CHECK((xl32(0, 0) == 0xFFFFFFFFu) == (wn[pred] != 0));
        /* signaling predicates (0,1,2) raise IE on QNaN; quiet don't */
        CHECK(((ctx.mxcsr & T_IE) != 0) == (pred <= 2U));
    }

    /* Scalar CMPSS NEQ on unordered lane 0 only. */
    {
        x86_insn_t in;
        reset();
        xs32(0, 0, 0x7FC00000u); xs32(0, 1, bitsf(5.0f));
        xs32(1, 0, bitsf(1.0f));
        in = mkrr(I686_OP_CMPPS, 0, 1);
        in.pfx_rep = 1;
        in.imm = 4;
        CHECK(run(&in) == 0);
        CHECK(xl32(0, 0) == 0xFFFFFFFFu && xl32(0, 1) == bitsf(5.0f));
        CHECK((ctx.mxcsr & T_IE) == 0); /* quiet predicate, QNaN */
    }
}

/* ------------------------------------------------------------------ */
/* MOVMSK / COMIS                                                      */
/* ------------------------------------------------------------------ */

static void t_movmsk_comis(void)
{
    x86_insn_t in;

    reset();
    xs32(2, 0, 0x80000000u); xs32(2, 1, 0x00000001u);
    xs32(2, 2, 0xC0000000u); xs32(2, 3, 0x00000002u);
    in = mkrr(I686_OP_MOVMSKPS, 0, 2);
    CHECK(run(&in) == 0);
    CHECK(ctx.gpr[0] == 0x5u);

    xs64(2, 0, 0x8000000000000000ull); /* lane0 sign set  */
    xs64(2, 1, 0x0000000000000001ull); /* lane1 sign clear */
    in.pfx_opsize = 1; /* MOVMSKPD: bits 63/127 */
    CHECK(run(&in) == 0);
    CHECK(ctx.gpr[0] == 0x1u);

    /* COMISD 1.0 vs 2.0: CF only; OF/SF/AF cleared; EIP advanced. */
    reset();
    ctx.eflags = I686_EF_OF | I686_EF_SF | I686_EF_AF | I686_EF_IF;
    ctx.eip = 0x1000;
    xs64(0, 0, 0x3FF0000000000000ull);
    xs64(1, 0, 0x4000000000000000ull);
    in = mkrr(I686_OP_COMISS, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK((ctx.eflags & I686_EF_CF) != 0);
    CHECK((ctx.eflags & (I686_EF_ZF | I686_EF_PF | I686_EF_OF |
                         I686_EF_SF | I686_EF_AF)) == 0);
    CHECK((ctx.eflags & I686_EF_IF) != 0); /* untouched bits kept */
    CHECK(ctx.lazy_op == I686_FOP_NONE);
    CHECK(ctx.eip == 0x1004u); /* advanced by len */

    /* COMISD equal: ZF. */
    reset();
    xs64(0, 0, 0x3FF0000000000000ull);
    xs64(1, 0, 0x3FF0000000000000ull);
    in = mkrr(I686_OP_COMISS, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK((ctx.eflags & (I686_EF_ZF)) != 0 &&
          (ctx.eflags & (I686_EF_CF | I686_EF_PF)) == 0);

    /* COMISD vs QNaN: unordered CF|ZF|PF + IE (signaling form). */
    reset();
    xs64(0, 0, 0x7FF8000000000000ull);
    xs64(1, 0, 0x3FF0000000000000ull);
    in = mkrr(I686_OP_COMISS, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK((ctx.eflags & (I686_EF_CF | I686_EF_ZF | I686_EF_PF)) ==
          (I686_EF_CF | I686_EF_ZF | I686_EF_PF));
    CHECK((ctx.mxcsr & T_IE) != 0);

    /* UCOMISD vs QNaN: same flags, NO IE (quiet form). */
    reset();
    xs64(0, 0, 0x7FF8000000000000ull);
    xs64(1, 0, 0x3FF0000000000000ull);
    in = mkrr(I686_OP_UCOMISS, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK((ctx.eflags & I686_EF_PF) != 0);
    CHECK((ctx.mxcsr & T_IE) == 0);

    /* COMISS f32 greater: no flags set. */
    reset();
    xs32(0, 0, bitsf(9.0f));
    xs32(1, 0, bitsf(1.0f));
    in = mkrr(I686_OP_COMISS, 0, 1);
    CHECK(run(&in) == 0);
    CHECK((ctx.eflags & (I686_EF_CF | I686_EF_ZF | I686_EF_PF)) == 0);
}

/* ------------------------------------------------------------------ */
/* Conversions                                                         */
/* ------------------------------------------------------------------ */

static void t_cvt(void)
{
    x86_insn_t in;

    /* CVTTPS2DQ overflow -> 0x80000000 + IE; in-range truncation. */
    reset();
    xs32(1, 0, bitsf(2.0e10f)); xs32(1, 1, bitsf(-3.75f));
    xs32(1, 2, bitsf(1.9f));    xs32(1, 3, bitsf(1.0e10f));
    in = mkrr(I686_OP_CVTDQ2PS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x80000000u);
    CHECK(xl32(0, 1) == 0xFFFFFFFDu); /* -3 */
    CHECK(xl32(0, 2) == 0x00000001u); /* 1 */
    CHECK(xl32(0, 3) == 0x80000000u);
    CHECK((ctx.mxcsr & T_IE) != 0);
    CHECK((ctx.mxcsr & T_PE) != 0); /* dropped fractions */

    /* CVTPS2DQ ties-to-even under default RC: 1.5->2, 2.5->2. */
    reset();
    xs32(1, 0, bitsf(1.5f)); xs32(1, 1, bitsf(2.5f));
    xs32(1, 2, bitsf(-1.5f)); xs32(1, 3, bitsf(3.5f));
    in = mkrr(I686_OP_CVTDQ2PS, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 2u && xl32(0, 1) == 2u &&
          xl32(0, 2) == 0xFFFFFFFEu && xl32(0, 3) == 4u);

    /* CVTDQ2PS roundtrip. */
    reset();
    w32va(DATA_VA, 0x00000064);
    w32va(DATA_VA + 4, 0xFFFFFF9C); /* -100 */
    w32va(DATA_VA + 8, 0x01000000);
    w32va(DATA_VA + 12, 0);
    in = mkmem(I686_OP_CVTDQ2PS, 0);
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(100.0f) && xl32(0, 1) == bitsf(-100.0f) &&
          xl32(0, 2) == bitsf(16777216.0f) && xl32(0, 3) == bitsf(0.0f));

    /* CVTPS2PD widen then CVTPD2PS back, upper lanes zeroed. */
    reset();
    xs32(1, 0, bitsf(1.5f)); xs32(1, 1, bitsf(-0.25f));
    in = mkrr(I686_OP_CVTPS2PD, 0, 1);
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x3FF8000000000000ull &&
          xl64(0, 1) == 0xBFD0000000000000ull);
    in = mkrr(I686_OP_CVTPS2PD, 0, 0); /* CVTPD2PS on the result */
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(1.5f) && xl32(0, 1) == bitsf(-0.25f));
    CHECK(xl32(0, 2) == 0u && xl32(0, 3) == 0u);

    /* CVTSD2SS rounding with PE on inexact. */
    reset();
    xs64(1, 0, 0x3FD5555555555555ull); /* ~1/3 */
    in = mkrr(I686_OP_CVTPS2PD, 0, 1);
    in.pfx_rep = 2;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(1.0f / 3.0f));
    CHECK((ctx.mxcsr & T_PE) != 0);

    /* CVTTSD2SI: NaN -> 0x80000000 + IE; plain value truncates. */
    reset();
    xs64(1, 0, 0x7FF8000000000000ull);
    in = mkrr(I686_OP_CVTTPS2PI, 0, 1);
    in.pfx_rep = 2;
    CHECK(run(&in) == 0);
    CHECK(ctx.gpr[0] == 0x80000000u);
    CHECK((ctx.mxcsr & T_IE) != 0);
    reset();
    xs64(1, 0, 0x4059000000000000ull); /* 100.0 */
    in = mkrr(I686_OP_CVTTPS2PI, 0, 1);
    in.pfx_rep = 2;
    CHECK(run(&in) == 0);
    CHECK(ctx.gpr[0] == 100u);

    /* CVTTSS2SI from memory m32. */
    reset();
    w32va(DATA_VA, bitsf(-77.75f));
    in = mkmem(I686_OP_CVTTPS2PI, 0);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(ctx.gpr[0] == 0xFFFFFFB3u); /* -77 */

    /* CVTSI2SD exact widen; CVTSI2SS of 0x7FFFFFFF rounds + PE. */
    reset();
    ctx.gpr[1] = 12345;
    in = mkrr(I686_OP_CVTPI2PS, 0, 1);
    in.pfx_rep = 2;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x40C81C8000000000ull); /* 12345.0 */
    reset();
    ctx.gpr[1] = 0x7FFFFFFFu;
    in = mkrr(I686_OP_CVTPI2PS, 0, 1);
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x4F000000u); /* 2147483648.0f */
    CHECK((ctx.mxcsr & T_PE) != 0);

    /* CVTPI2PS from MMX pair (plain, MMX source). */
    reset();
    mmset(1, 0x00000064000000C8ull); /* 200, 100 */
    in = mkrr(I686_OP_CVTPI2PS, 0, 1);
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == bitsf(200.0f) && xl32(0, 1) == bitsf(100.0f));

    /* CVTTPS2PI (plain) to MMX. */
    reset();
    xs32(1, 0, bitsf(6.9f)); xs32(1, 1, bitsf(-7.9f));
    in = mkrr(I686_OP_CVTTPS2PI, 0, 1);
    CHECK(run(&in) == 0);
    CHECK(mm(0) == 0xFFFFFFF900000006ull);
}

/* ------------------------------------------------------------------ */
/* Integer ops, shuffles, MOVD/MOVQ, EMMS                              */
/* ------------------------------------------------------------------ */

static void t_intops(void)
{
    x86_insn_t in;

    /* PXOR xmm zero idiom then PAND/POR/PANDN spot. */
    reset();
    in = mkrr(I686_OP_PXOR, 0, 0);
    in.pfx_opsize = 1;
    memset(ctx.xmm[0], 0xEE, 16);
    CHECK(run(&in) == 0);
    {
        unsigned i;
        int zero = 1;
        for (i = 0; i < 16; i++) {
            zero = zero && ctx.xmm[0][i] == 0;
        }
        CHECK(zero);
    }
    reset();
    xs64(0, 0, 0xF0F0F0F0F0F0F0F0ull);
    xs64(0, 1, 0x0F0F0F0F0F0F0F0Full);
    xs64(1, 0, 0xFFFF0000FFFF0000ull);
    xs64(1, 1, 0x0000FFFF0000FFFFull);
    in = mkrr(I686_OP_PAND, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0xF0F00000F0F00000ull &&
          xl64(0, 1) == 0x00000F0F00000F0Full);

    reset();
    xs32(0, 0, 0x12345678u);
    xs32(1, 0, 0xFF00FF00u);
    in = mkrr(I686_OP_POR, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0xFF34FF78u);

    reset();
    xs32(0, 0, 0xF0F0F0F0u);
    xs32(1, 0, 0x0FF00FF0u);
    in = mkrr(I686_OP_PANDN, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x0F000F00u); /* ~dest & src */

    /* PADDD xmm + PSUBD. */
    reset();
    xs32(0, 0, 100u); xs32(0, 1, 0xFFFFFFFFu);
    xs32(0, 2, 5u);   xs32(0, 3, 7u);
    xs32(1, 0, 1u);   xs32(1, 1, 3u);
    xs32(1, 2, 0xFFFFFFFFu); xs32(1, 3, 0u);
    in = mkrr(I686_OP_PADDD, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 101u && xl32(0, 1) == 2u &&
          xl32(0, 2) == 4u && xl32(0, 3) == 7u);
    in = mkrr(I686_OP_PSUBD, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 100u && xl32(0, 1) == 0xFFFFFFFFu &&
          xl32(0, 2) == 5u && xl32(0, 3) == 7u);

    /* PADDQ wrap (xmm) + MMX plain PADDQ. */
    reset();
    xs64(0, 0, 0xFFFFFFFFFFFFFFFFull);
    xs64(1, 0, 1ull);
    in = mkrr(I686_OP_PADDQ, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0ull);
    reset();
    mmset(0, 0x8888888888888888ull);
    mmset(1, 0x1111111111111111ull);
    in = mkrr(I686_OP_PADDQ, 0, 1);
    CHECK(run(&in) == 0);
    CHECK(mm(0) == 0x9999999999999999ull);

    /* PSUBQ. */
    reset();
    xs64(0, 0, 0ull);
    xs64(1, 0, 1ull);
    in = mkrr(I686_OP_PSUBQ, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0xFFFFFFFFFFFFFFFFull);

    /* PMULLW: -1 * 2 = -2 (low 16 bits), 300*300 wraps to 26464. */
    reset();
    ctx.xmm[0][0] = 0xFF; ctx.xmm[0][1] = 0xFF;
    ctx.xmm[1][0] = 0x02; ctx.xmm[1][1] = 0x00;
    in = mkrr(I686_OP_PMULLW, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(ctx.xmm[0][0] == 0xFE && ctx.xmm[0][1] == 0xFF);

    /* PMULUDQ: 0xFFFFFFFF * 2 = 0x1FFFFFFFE. */
    reset();
    xs32(0, 0, 0xFFFFFFFFu);
    xs32(1, 0, 2u);
    in = mkrr(I686_OP_PMULUDQ, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x1FFFFFFFEull);

    /* PSHUFD imm 0x1B reverses dwords. */
    reset();
    xs32(0, 0, 0x30); xs32(0, 1, 0x21);
    xs32(0, 2, 0x12); xs32(0, 3, 0x03);
    xs32(1, 0, 0x30); xs32(1, 1, 0x21);
    xs32(1, 2, 0x12); xs32(1, 3, 0x03);
    in = mkrr(I686_OP_PSHUFW, 0, 1);
    in.pfx_opsize = 1;
    in.imm = 0x1B;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0x03 && xl32(0, 1) == 0x12 &&
          xl32(0, 2) == 0x21 && xl32(0, 3) == 0x30);

    /* PSHUFLW (F2) imm 0x1B reverses low words, high words kept. */
    reset();
    memcpy(ctx.xmm[1], "\x00\x11\x22\x33\x44\x55\x66\x77"
                       "\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16);
    in = mkrr(I686_OP_PSHUFW, 0, 1);
    in.pfx_rep = 2;
    in.imm = 0x1B;
    CHECK(run(&in) == 0);
    CHECK(memcmp(ctx.xmm[0], "\x66\x77\x44\x55\x22\x33\x00\x11"
                              "\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF", 16) == 0);

    /* MMX PSHUFW (plain) imm 0x1B reverses the 4 words. */
    reset();
    mmset(1, 0x33221100DDCCBBAAull);
    in = mkrr(I686_OP_PSHUFW, 0, 1);
    in.imm = 0x1B;
    CHECK(run(&in) == 0);
    CHECK(mm(0) == 0xBBAADDCC11003322ull); /* words reversed */

    /* PUNPCKLDQ: (A0,B0,A1,B1). */
    reset();
    xs32(0, 0, 0xA0); xs32(0, 1, 0xA1);
    xs32(0, 2, 0xA2); xs32(0, 3, 0xA3);
    xs32(1, 0, 0xB0); xs32(1, 1, 0xB1);
    xs32(1, 2, 0xB2); xs32(1, 3, 0xB3);
    in = mkrr(I686_OP_PUNPCKLDQ, 0, 1);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0xA0 && xl32(0, 1) == 0xB0 &&
          xl32(0, 2) == 0xA1 && xl32(0, 3) == 0xB1);

    /* MOVD/MOVQ gpr forms: 6E xmm<-gpr zero-extended; 7E gpr<-xmm. */
    reset();
    ctx.gpr[2] = 0xDEADBEEFu;
    in = mkrr(I686_OP_MOVQ_xmm, 0, 2);
    in.pfx_opsize = 1;
    memset(ctx.xmm[0], 0x5A, 16);
    CHECK(run(&in) == 0);
    CHECK(xl32(0, 0) == 0xDEADBEEFu && xl32(0, 1) == 0u &&
          xl32(0, 2) == 0u && xl32(0, 3) == 0u);
    in = mkrr(I686_OP_MOVQ_xmm, 0, 3); /* row 7E: opnd[0]=RM32 */
    in.opnd[0] = I686_OPND_RM32;
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(ctx.gpr[3] == 0xDEADBEEFu);

    /* MOVD plain 6E: mm zero-extended from gpr. */
    reset();
    ctx.gpr[2] = 0xCAFEBABEu;
    mmset(0, 0x1212121212121212ull);
    in = mkrr(I686_OP_MOVQ_xmm, 0, 2);
    CHECK(run(&in) == 0);
    CHECK(mm(0) == 0x00000000CAFEBABEull);

    /* F3 7E MOVQ xmm,xmm: low 64 copied, high preserved. */
    reset();
    memcpy(ctx.xmm[1], "\x01\x02\x03\x04\x05\x06\x07\x08"
                       "\x11\x12\x13\x14\x15\x16\x17\x18", 16);
    memcpy(ctx.xmm[0], "\xA0\xA1\xA2\xA3\xA4\xA5\xA6\xA7"
                       "\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7", 16);
    in = mkrr(I686_OP_MOVQ_xmm, 0, 1);
    in.opnd[0] = I686_OPND_RM32;
    in.pfx_rep = 1;
    CHECK(run(&in) == 0);
    CHECK(memcmp(ctx.xmm[0], "\x01\x02\x03\x04\x05\x06\x07\x08"
                              "\xB0\xB1\xB2\xB3\xB4\xB5\xB6\xB7", 16) == 0);

    /* EMMS: ftag all-empty. */
    reset();
    ctx.ftag = 0x0000;
    in = mkrr(I686_OP_EMMS, 0, 0);
    CHECK(run(&in) == 0);
    CHECK(ctx.ftag == 0xFFFFu);
}

/* ------------------------------------------------------------------ */
/* Memory-form moves, MXCSR ld/st                                      */
/* ------------------------------------------------------------------ */

static void t_mem_mxcsr(void)
{
    x86_insn_t in;

    /* MOVUPS store to m128, load back into another reg. */
    reset();
    memcpy(ctx.xmm[0], "\x10\x20\x30\x40\x50\x60\x70\x80"
                       "\x90\xA0\xB0\xC0\xD0\xE0\xF0\x00", 16);
    in = mkmem(I686_OP_MOVUPS, 0);
    in.opnd[0] = I686_OPND_RM32; /* store row */
    CHECK(run(&in) == 0);
    CHECK(memcmp(&g_window[DATA_VA], ctx.xmm[0], 16) == 0);
    in = mkmem(I686_OP_MOVAPS, 2); /* load (aligned: same path) */
    in.opnd[0] = I686_OPND_R32;
    in.modrm_mod = 3; /* reg form of MOVAPS copies full 128 */
    CHECK(run(&in) == 0);
    CHECK(memcmp(ctx.xmm[2], ctx.xmm[0], 16) == 0);

    /* MOVHPD store (66 0F 17): m64 <- high64. */
    reset();
    xs64(0, 0, 0x1122334455667788ull);
    xs64(0, 1, 0x99AABBCCDDEEFF00ull);
    in = mkmem(I686_OP_MOVHPS, 0);
    in.opnd[0] = I686_OPND_RM32;
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(r64va(DATA_VA) == 0x99AABBCCDDEEFF00ull);

    /* MOVLPD load (66 0F 12): low64 <- m64, high64 kept. */
    reset();
    w64va(DATA_VA, 0x0102030405060708ull);
    xs64(0, 0, 0xAABBCCDDEEFF0011ull);
    xs64(0, 1, 0xDEADBEEFDEADBEEFull);
    in = mkmem(I686_OP_MOVLPS, 0);
    in.pfx_opsize = 1;
    CHECK(run(&in) == 0);
    CHECK(xl64(0, 0) == 0x0102030405060708ull &&
          xl64(0, 1) == 0xDEADBEEFDEADBEEFull);

    /* LDMXCSR: reserved bits masked + IE; STMXCSR reads back. */
    reset();
    w32va(DATA_VA, 0x0001FFFFu); /* bit 16 is reserved */
    in = mkmem(I686_OP_LDMXCSR, 0);
    in.opnd[0] = I686_OPND_RM32;
    CHECK(run(&in) == 0);
    CHECK(sse_get_mxcsr(&ctx) == 0x0000FFFFu);
    CHECK((ctx.mxcsr & T_IE) != 0);
    in = mkmem(I686_OP_STMXCSR, 0);
    in.opnd[0] = I686_OPND_RM32;
    w32va(DATA_VA + 8, 0);
    in.ea_disp = DATA_VA + 8;
    CHECK(run(&in) == 0);
    CHECK(r32va(DATA_VA + 8) == 0x0000FFFFu);
}

int main(void)
{
    i686_interp_sse_init();

    t_state();
    t_arith();
    t_ftz_daz();
    t_cmpps();
    t_movmsk_comis();
    t_cvt();
    t_intops();
    t_mem_mxcsr();

    if (g_fail != 0) {
        printf("%d check(s) failed\n", g_fail);
        return 1;
    }
    printf("L5B OK (%d checks)\n", g_pass);
    return 0;
}
