/*
 * tests/unit/test_l5b_cases.c — Unit test cases for test_l5b
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_l5b_internal.h"

void t_cvt(void)
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

void t_intops(void)
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

void t_mem_mxcsr(void)
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


