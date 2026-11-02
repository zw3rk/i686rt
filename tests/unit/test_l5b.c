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

#include "test_l5b_internal.h"



/* src/interp/h_sse.c export (wired into i686_interp_init_all at S5). */
extern void i686_interp_sse_init(void);

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

int g_pass;
int g_fail;


/* Test-local handler registry (interp.c is not linked into this unit
 * test; h_sse.c's only external dependency is i686_interp_register). */
i686_interp_fn t_reg[I686_OP_COUNT];

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


uint8_t g_window[0x10000];
i686_ctx_t ctx;

void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
    ctx.lazy_op = I686_FOP_NONE;
    memset(g_window, 0, sizeof g_window);
}

void w32va(uint32_t va, uint32_t v)
{
    memcpy(&g_window[va], &v, 4);
}

void w64va(uint32_t va, uint64_t v)
{
    memcpy(&g_window[va], &v, 8);
}

uint32_t r32va(uint32_t va)
{
    uint32_t v;
    memcpy(&v, &g_window[va], 4);
    return v;
}

uint64_t r64va(uint32_t va)
{
    uint64_t v;
    memcpy(&v, &g_window[va], 8);
    return v;
}

/* Hand-built insn: reg-reg form. */
x86_insn_t mkrr(uint16_t op, unsigned reg, unsigned rm)
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
x86_insn_t mkmem(uint16_t op, unsigned reg)
{
    x86_insn_t i = mkrr(op, reg, 0);
    i.modrm_mod = 0;
    i.ea_has = 1;
    i.ea_base = 0xFF;
    i.ea_index = 0xFF;
    i.ea_disp = DATA_VA;
    return i;
}

int run(const x86_insn_t *insn)
{
    return t_reg[insn->op](&ctx, insn);
}

/* FP bit helpers. */
uint32_t bitsf(float f)
{
    uint32_t u;
    memcpy(&u, &f, 4);
    return u;
}

uint32_t xl32(unsigned reg, unsigned lane)
{
    uint32_t v;
    memcpy(&v, ctx.xmm[reg] + 4U * lane, 4);
    return v;
}

void xs32(unsigned reg, unsigned lane, uint32_t b)
{
    memcpy(ctx.xmm[reg] + 4U * lane, &b, 4);
}

uint64_t xl64(unsigned reg, unsigned lane)
{
    uint64_t v;
    memcpy(&v, ctx.xmm[reg] + 8U * lane, 8);
    return v;
}

void xs64(unsigned reg, unsigned lane, uint64_t b)
{
    memcpy(ctx.xmm[reg] + 8U * lane, &b, 8);
}

uint64_t mm(unsigned reg)
{
    uint64_t v;
    memcpy(&v, ctx.x87_st[reg], 8);
    return v;
}

void mmset(unsigned reg, uint64_t v)
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
