/*
 * tests/unit/test_l5c_cases.c — Unit test cases for test_l5c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_l5c_internal.h"

void test_compare(int mode80)
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

void test_transcendentals(int mode80)
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

void test_env(int mode80)
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

void test_declined(int mode80)
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


