/*
 * tests/unit/test_l1e_cases.c — Unit test cases for test_l1e
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_l1e_internal.h"

void t_idiv(void)
{
    x86_insn_t i;

    /* -7 / 2 -> q = -3, r = -1 (truncate toward zero); the numerator is
     * the sign-extended EDX:EAX pair. */
    reset();
    ctx.gpr[I686_REG_EAX] = (uint32_t)-7;
    ctx.gpr[I686_REG_EDX] = 0xFFFFFFFFU;
    ctx.gpr[I686_REG_EBX] = 2;
    i = mkinsn(I686_OP_IDIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xFFFFFFFDU);
    CHECK(ctx.gpr[I686_REG_EDX] == 0xFFFFFFFFU);

    /* INT64-style corner: EDX:EAX = 0x80000000_00000000 / -1 -> fault. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0;
    ctx.gpr[I686_REG_EDX] = 0x80000000U;
    ctx.gpr[I686_REG_EBX] = 0xFFFFFFFFU;
    i = mkinsn(I686_OP_IDIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_EXIT_FAULT);
    CHECK(ctx.exit_reason == I686_EXIT_FAULT);
    CHECK(ctx.exit_arg == 0U);
    CHECK(ctx.gpr[I686_REG_EAX] == 0U);
    CHECK(ctx.gpr[I686_REG_EDX] == 0x80000000U);

    /* 16-bit: DX:AX = 0xFFFF8000 (-32768) / -1 = +32768 -> fault. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x8000;
    ctx.gpr[I686_REG_EDX] = 0xFFFF;
    ctx.gpr[I686_REG_EBX] = 0xFFFF;
    i = mkinsn(I686_OP_IDIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_EXIT_FAULT);

    /* 16-bit ok: DX:AX = 0x00008000 (32768) / -1 = -32768 -> fits. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x8000;
    ctx.gpr[I686_REG_EDX] = 0;
    ctx.gpr[I686_REG_EBX] = 0xFFFF;
    i = mkinsn(I686_OP_IDIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0x8000U);
    CHECK(x86_reg_read(&ctx, I686_REG_EDX, 16) == 0U);

    /* 8-bit: AX = 0xFF85 (-123) / 10 -> AL = -12 (0xF4), AH = -3 (0xFD). */
    reset();
    ctx.gpr[I686_REG_EAX] = 0xFF85;
    ctx.gpr[I686_REG_EBX] = 10;
    i = mkinsn(I686_OP_IDIV_Eb, I686_OPND_RM8, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0xFDF4U);

    /* idiv by zero -> fault. */
    reset();
    ctx.gpr[I686_REG_EAX] = 5;
    ctx.gpr[I686_REG_EBX] = 0;
    i = mkinsn(I686_OP_IDIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_EXIT_FAULT);
}

void t_cwde_cdq(void)
{
    x86_insn_t i;

    /* CWDE: AX = 0x8000 -> EAX = 0xFFFF8000. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x12348000U;
    i = mkinsn(I686_OP_CWDE, I686_OPND_NONE, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xFFFF8000U);

    /* CWDE positive: AX = 0x2F7E -> EAX = 0x00002F7E. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0xFFFF2F7EU;
    i = mkinsn(I686_OP_CWDE, I686_OPND_NONE, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x2F7EU);

    /* 66 98 (CBW placement): AL = 0x80 -> AX = 0xFF80. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x12345680U;
    i = mkinsn(I686_OP_CWDE, I686_OPND_NONE, I686_OPND_NONE);
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0xFF80U);

    /* CDQ negative: EAX = 0x80000000 -> EDX = 0xFFFFFFFF. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x80000000U;
    i = mkinsn(I686_OP_CDQ, I686_OPND_NONE, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EDX] == 0xFFFFFFFFU);

    /* CDQ positive: EAX = 0x7FFF -> EDX = 0. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x7FFF;
    i = mkinsn(I686_OP_CDQ, I686_OPND_NONE, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EDX] == 0U);

    /* 66 99 (CWD placement): AX = 0x8000 -> DX = 0xFFFF. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x8000;
    i = mkinsn(I686_OP_CDQ, I686_OPND_NONE, I686_OPND_NONE);
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EDX, 16) == 0xFFFFU);
}

void t_shifts(void)
{
    x86_insn_t i;

    /* SHL32 by 1: 0x40000000 -> 0x80000000, CF=0, OF=CF^MSB=1, SF=1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x40000000U;
    i = mkinsn(I686_OP_SHL_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0x80000000U);
    CHECK(!F_CF(ctx));
    CHECK(F_OF(ctx));
    CHECK(F_SF(ctx));
    CHECK(!F_ZF(ctx));
    CHECK(ctx.lazy_op == I686_FOP_NONE);

    /* SHL8 by 8: 0xFF -> 0, CF=1, ZF=1 (OF undefined -> left cleared). */
    reset();
    ctx.gpr[I686_REG_EBX] = 0xFF;
    i = mkinsn(I686_OP_SHL_EbIb, I686_OPND_RM8, I686_OPND_I8);
    i.imm = 8;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0U);
    CHECK(F_CF(ctx));
    CHECK(F_ZF(ctx));
    CHECK(!F_OF(ctx));

    /* SHL with Ib=0: nothing changes — value, eflags, lazy state. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x1234;
    arm_add(2, 3, 32);
    i = mkinsn(I686_OP_SHL_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 0;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0x1234U);
    CHECK(ctx.lazy_op == I686_FOP_ADD);
    CHECK(ctx.lazy_res == 5U);

    /* SHL with Ib=32: masked to 0 -> same no-op. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x77;
    i = mkinsn(I686_OP_SHL_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 32;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0x77U);

    /* SHL by CL: CL=4, 0xF -> 0xF0, CF=0, SF=ZF=0. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0xF;
    ctx.gpr[I686_REG_ECX] = 4;
    i = mkinsn(I686_OP_SHL_EvCL, I686_OPND_RM32, I686_OPND_CL);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0xF0U);
    CHECK(!F_CF(ctx));
    CHECK(!F_SF(ctx) && !F_ZF(ctx));

    /* SHL16 by 1 with 66: 0x4000 -> 0x8000, CF=0, OF=1, SF=1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x4000;
    i = mkinsn(I686_OP_SHL_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EBX, 16) == 0x8000U);
    CHECK(F_OF(ctx) && F_SF(ctx));

    /* SHR32 by 1: 0x80000000 -> 0x40000000, CF=0, OF=MSB(orig)=1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x80000000U;
    i = mkinsn(I686_OP_SHR_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0x40000000U);
    CHECK(!F_CF(ctx));
    CHECK(F_OF(ctx));

    /* SHR CF = last bit out: 5>>1 -> 2 (CF=1), 6>>1 -> 3 (CF=0). */
    reset();
    ctx.gpr[I686_REG_EBX] = 5;
    i = mkinsn(I686_OP_SHR_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 2U && F_CF(ctx));
    reset();
    ctx.gpr[I686_REG_EBX] = 6;
    i = mkinsn(I686_OP_SHR_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 3U && !F_CF(ctx));

    /* SHR8 by 8: 0xFF -> 0, CF=1, ZF=1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0xFF;
    i = mkinsn(I686_OP_SHR_EbIb, I686_OPND_RM8, I686_OPND_I8);
    i.imm = 8;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0U);
    CHECK(F_CF(ctx) && F_ZF(ctx));

    /* SAR32 by 1: 0x80000000 -> 0xC0000000, CF=0, OF=0. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x80000000U;
    i = mkinsn(I686_OP_SAR_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0xC0000000U);
    CHECK(!F_CF(ctx) && !F_OF(ctx));
    CHECK(F_SF(ctx));

    /* SAR16 by 4: 0x8000 -> 0xF800. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x8000;
    i = mkinsn(I686_OP_SAR_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 4;
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EBX, 16) == 0xF800U);

    /* SAR8 by 31 (>width): 0xFF -> 0xFF, CF = sign bit = 1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0xFF;
    i = mkinsn(I686_OP_SAR_EbIb, I686_OPND_RM8, I686_OPND_I8);
    i.imm = 31;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0xFFU);
    CHECK(F_CF(ctx) && F_SF(ctx));

    /* SAR8 positive saturates to 0: 0x7F by 31 -> 0, CF=0, ZF=1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x7F;
    i = mkinsn(I686_OP_SAR_EbIb, I686_OPND_RM8, I686_OPND_I8);
    i.imm = 31;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0U);
    CHECK(!F_CF(ctx) && F_ZF(ctx));
}

void t_rotates(void)
{
    x86_insn_t i;

    /* ROL8 by 1: 0x80 -> 0x01, CF=1, OF=CF^MSB(res)=1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x80;
    i = mkinsn(I686_OP_ROL_Eb1, I686_OPND_RM8, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0x01U);
    CHECK(F_CF(ctx));
    CHECK(F_OF(ctx));

    /* ROL16 by 16: value unchanged, CF = LSB(result) = 0; the pending
     * lazy ADD's SF/ZF/PF are preserved (undefined flags), OF left
     * alone (count != 1). */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x8000;
    arm_add(0x8000, 0x8000, 16); /* CF=1 ZF=1 SF=0 PF=1 OF=1 AF=0 */
    i = mkinsn(I686_OP_ROL_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 16;
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EBX, 16) == 0x8000U);
    CHECK(!F_CF(ctx)); /* rewritten from result LSB */
    CHECK(F_ZF(ctx));  /* preserved from the lazy ADD */
    CHECK(!F_SF(ctx));
    CHECK(F_PF(ctx));
    CHECK(F_OF(ctx)); /* undefined, preserved */
    CHECK(F_AF(ctx) == false);
    CHECK(ctx.lazy_op == I686_FOP_NONE);

    /* ROL32 by 4: 0x12345678 -> 0x23456781, CF=1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x12345678U;
    i = mkinsn(I686_OP_ROL_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 4;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0x23456781U);
    CHECK(F_CF(ctx));

    /* ROL8 by CL=31 (31%8=7): 0x01 -> 0x80, CF=0. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x01;
    ctx.gpr[I686_REG_ECX] = 31;
    i = mkinsn(I686_OP_ROL_EbCL, I686_OPND_RM8, I686_OPND_CL);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0x80U);
    CHECK(!F_CF(ctx));

    /* ROR8 by 1: 0x01 -> 0x80, CF=1, OF = MSB ^ bit6 = 1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x01;
    i = mkinsn(I686_OP_ROR_Eb1, I686_OPND_RM8, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0x80U);
    CHECK(F_CF(ctx));
    CHECK(F_OF(ctx));

    /* ROR32 by 1: 0x80000000 -> 0x40000000, CF=0, OF = res[31]^res[30]
     * = 1 (sign changed). */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x80000000U;
    i = mkinsn(I686_OP_ROR_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0x40000000U);
    CHECK(!F_CF(ctx));
    CHECK(F_OF(ctx));

    /* ROR16 by 16: unchanged, CF = MSB(result) = 1. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x8000;
    i = mkinsn(I686_OP_ROR_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 16;
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EBX, 16) == 0x8000U);
    CHECK(F_CF(ctx));
}

void t_rcl_rcr(void)
{
    x86_insn_t i;

    /* RCL8 by 1, CF=1: 0x80 -> 0x01, CF=1, OF=MSB(res)^CF=1. */
    reset();
    ctx.eflags |= I686_EF_CF;
    ctx.gpr[I686_REG_EBX] = 0x80;
    i = mkinsn(I686_OP_RCL_Eb1, I686_OPND_RM8, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0x01U);
    CHECK(F_CF(ctx));
    CHECK(F_OF(ctx));

    /* RCL32 by 1, CF=0: 0x80000000 -> 0x00000000, CF=1, OF=0^1=1. */
    reset();
    ctx.eflags &= ~(uint32_t)I686_EF_CF;
    ctx.gpr[I686_REG_EBX] = 0x80000000U;
    i = mkinsn(I686_OP_RCL_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0U);
    CHECK(F_CF(ctx));
    CHECK(F_OF(ctx));

    /* RCL16 by 17: full 17-bit rotation -> identity incl. CF. */
    reset();
    ctx.eflags |= I686_EF_CF | I686_EF_OF;
    ctx.gpr[I686_REG_EBX] = 0xBEEF;
    i = mkinsn(I686_OP_RCL_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 17;
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EBX, 16) == 0xBEEFU);
    CHECK(F_CF(ctx));
    CHECK(F_OF(ctx)); /* undefined (count != 1), preserved */

    /* RCL8 by 9: identity (9-bit entity, full turn). */
    reset();
    ctx.eflags &= ~(uint32_t)I686_EF_CF;
    ctx.gpr[I686_REG_EBX] = 0x5A;
    i = mkinsn(I686_OP_RCL_EbIb, I686_OPND_RM8, I686_OPND_I8);
    i.imm = 9;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0x5AU);
    CHECK(!F_CF(ctx));

    /* RCL CF can live in a pending lazy descriptor: materialized first
     * (arm ADD 0xFFFFFFFF+1 -> CF=1), then 0x80 rcl 1 -> 0x01, CF=1. */
    reset();
    arm_add(0xFFFFFFFFU, 1U, 32);
    ctx.gpr[I686_REG_EBX] = 0x80;
    i = mkinsn(I686_OP_RCL_Eb1, I686_OPND_RM8, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0x01U);
    CHECK(F_CF(ctx));
    CHECK(ctx.lazy_op == I686_FOP_NONE);

    /* RCR8 by 1, CF=0: 0x01 -> 0x00, CF=1, OF = res[7]^res[6] = 0. */
    reset();
    ctx.eflags &= ~(uint32_t)I686_EF_CF;
    ctx.gpr[I686_REG_EBX] = 0x01;
    i = mkinsn(I686_OP_RCR_Eb1, I686_OPND_RM8, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EBX] & 0xFFU) == 0x00U);
    CHECK(F_CF(ctx));
    CHECK(!F_OF(ctx));

    /* RCR32 by 1, CF=1: 0x00000001 -> 0x80000000, CF=1, OF=1^0=1. */
    reset();
    ctx.eflags |= I686_EF_CF;
    ctx.gpr[I686_REG_EBX] = 1;
    i = mkinsn(I686_OP_RCR_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0x80000000U);
    CHECK(F_CF(ctx));
    CHECK(F_OF(ctx));

    /* RCR16 by 1, CF=1: 0xFFFF -> 0xFFFF, CF=1, OF = 1^1 = 0. */
    reset();
    ctx.eflags |= I686_EF_CF;
    ctx.gpr[I686_REG_EBX] = 0xFFFF;
    i = mkinsn(I686_OP_RCR_Ev1, I686_OPND_RM32, I686_OPND_ONE);
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EBX, 16) == 0xFFFFU);
    CHECK(F_CF(ctx));
    CHECK(!F_OF(ctx));
}

void t_mem_forms(void)
{
    x86_insn_t i;

    /* SHL EvIb on memory: word 3 << 4 -> 0x30 written back. */
    reset();
    mem_set(0x200, 3U, 32);
    i = mkinsn(I686_OP_SHL_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 4;
    mkmem(&i, 0x200);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(mem_get(0x200, 32) == 0x30U);
    CHECK(!F_CF(ctx) && !F_ZF(ctx) && !F_SF(ctx));

    /* Count 0 on memory: no write at all. */
    reset();
    mem_set(0x204, 0xCAFEBABEU, 32);
    i = mkinsn(I686_OP_SHR_EvIb, I686_OPND_RM32, I686_OPND_I8);
    i.imm = 0;
    mkmem(&i, 0x204);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(mem_get(0x204, 32) == 0xCAFEBABEU);

    /* SAR byte on memory: 0x80 by 2 -> 0xE0. */
    reset();
    mem_set(0x208, 0x80U, 8);
    i = mkinsn(I686_OP_SAR_EbIb, I686_OPND_RM8, I686_OPND_I8);
    i.imm = 2;
    mkmem(&i, 0x208);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(mem_get(0x208, 8) == 0xE0U);
    CHECK(F_SF(ctx));
}


