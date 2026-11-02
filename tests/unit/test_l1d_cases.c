/*
 * tests/unit/test_l1d_cases.c — Unit test cases for test_l1d
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_l1d_internal.h"

void test_bt_regs(void)
{
    x86_insn_t in;

    /* BT_EvGv register: bit set, index mod width, other flags kept */
    in = mk_insn(I686_OP_BT_EvGv);
    in.len = 3U;
    set_rr(&in, I686_REG_ECX, I686_REG_EAX); /* dst EAX, idx ECX */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x00000100U;
    ctx.gpr[I686_REG_ECX] = 8U;
    ctx.eflags = I686_EF_ZF | I686_EF_SF;
    CHECK(run(I686_OP_BT_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);
    CHECK((ctx.eflags & I686_EF_ZF) != 0U); /* untouched */
    CHECK((ctx.eflags & I686_EF_SF) != 0U);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x00000100U); /* no write */
    CHECK(ctx.eip == 0x1003U);

    /* index 40 wraps to bit 8 (mod 32) */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x00000100U;
    ctx.gpr[I686_REG_ECX] = 40U;
    CHECK(run(I686_OP_BT_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);

    /* bit clear */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x00000100U;
    ctx.gpr[I686_REG_ECX] = 0U;
    CHECK(run(I686_OP_BT_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) == 0U);

    /* BT_EvIb: imm 31 and 30 */
    in = mk_insn(I686_OP_BT_EvIb);
    in.len = 4U; /* 0F BA /4 ib */
    in.imm = 31U;
    in.imm_size = 1U;
    set_rr(&in, 4U, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x80000000U;
    CHECK(run(I686_OP_BT_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);

    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x80000000U;
    in.imm = 30U;
    CHECK(run(I686_OP_BT_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) == 0U);

    /* BTS / BTR / BTC on a register */
    in = mk_insn(I686_OP_BTS_EvGv);
    in.len = 3U;
    set_rr(&in, I686_REG_ECX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0U;
    ctx.gpr[I686_REG_ECX] = 5U;
    CHECK(run(I686_OP_BTS_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x20U);
    CHECK((ctx.eflags & I686_EF_CF) == 0U);

    in = mk_insn(I686_OP_BTR_EvGv);
    in.len = 3U;
    set_rr(&in, I686_REG_ECX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x20U;
    ctx.gpr[I686_REG_ECX] = 5U;
    CHECK(run(I686_OP_BTR_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0U);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);

    in = mk_insn(I686_OP_BTC_EvGv);
    in.len = 3U;
    set_rr(&in, I686_REG_ECX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x20U;
    ctx.gpr[I686_REG_ECX] = 5U;
    CHECK(run(I686_OP_BTC_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0U);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);

    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x20U;
    ctx.gpr[I686_REG_ECX] = 6U;
    CHECK(run(I686_OP_BTC_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x60U);
    CHECK((ctx.eflags & I686_EF_CF) == 0U);

    /* 16-bit operand size: AX bit 15 via index 15 and 31 */
    in = mk_insn(I686_OP_BT_EvGv);
    in.len = 4U;
    in.pfx_opsize = 1U;
    set_rr(&in, I686_REG_ECX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x00008000U;
    ctx.gpr[I686_REG_ECX] = 15U;
    CHECK(run(I686_OP_BT_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);

    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x00008000U;
    ctx.gpr[I686_REG_ECX] = 31U; /* 31 mod 16 = 15 */
    CHECK(run(I686_OP_BT_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);
}

void test_bt_mem(void)
{
    x86_insn_t in;

    /* BT_EvGv memory: index 10 -> byte 1, bit 2 */
    in = mk_insn(I686_OP_BT_EvGv);
    in.len = 7U;
    set_mem(&in, I686_REG_ECX, 0x2000U);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 10U;
    window[0x2001U] = 0x04U;
    CHECK(run(I686_OP_BT_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);
    CHECK(ctx.eip == 0x1007U);

    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 10U;
    window[0x2001U] = 0x00U;
    CHECK(run(I686_OP_BT_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) == 0U);

    /* BTS memory: index 17 -> byte 2, bit 1 */
    in = mk_insn(I686_OP_BTS_EvGv);
    in.len = 7U;
    set_mem(&in, I686_REG_ECX, 0x2000U);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 17U;
    CHECK(run(I686_OP_BTS_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(window[0x2002U] == 0x02U);
    CHECK((ctx.eflags & I686_EF_CF) == 0U);

    /* BTR memory removes it again */
    in = mk_insn(I686_OP_BTR_EvGv);
    in.len = 7U;
    set_mem(&in, I686_REG_ECX, 0x2000U);
    CHECK(run(I686_OP_BTR_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(window[0x2002U] == 0x00U);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);

    /* BTC memory: index 27 -> byte 3, bit 3 */
    in = mk_insn(I686_OP_BTC_EvGv);
    in.len = 7U;
    set_mem(&in, I686_REG_ECX, 0x2000U);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 27U;
    CHECK(run(I686_OP_BTC_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(window[0x2003U] == 0x08U);
    CHECK((ctx.eflags & I686_EF_CF) == 0U);

    /* BT_EvIb memory: imm 0x0B -> byte 1, bit 3 */
    in = mk_insn(I686_OP_BT_EvIb);
    in.len = 8U; /* 0F BA /4 ib with disp32 */
    in.imm = 0x0BU;
    in.imm_size = 1U;
    set_mem(&in, 4U, 0x2000U);
    reset_ctx();
    ctx.eip = 0x1000U;
    window[0x2001U] = 0x08U;
    CHECK(run(I686_OP_BT_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);

    /* 16-bit memory: index 12 -> byte 1, bit 4 */
    in = mk_insn(I686_OP_BT_EvGv);
    in.len = 8U;
    in.pfx_opsize = 1U;
    set_mem(&in, I686_REG_ECX, 0x2000U);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 12U; /* 12 mod 16 = 12 */
    window[0x2001U] = 0x10U;
    CHECK(run(I686_OP_BT_EvGv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);
}

void test_bsf_bsr(void)
{
    x86_insn_t in;

    in = mk_insn(I686_OP_BSF_GvEv);
    in.len = 3U;
    set_rr(&in, I686_REG_EAX, I686_REG_EBX); /* dst EAX, src EBX */

    /* single-bit source: index 20 both directions */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EBX] = 0x00100000U;
    CHECK(run(I686_OP_BSF_GvEv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 20U);
    CHECK((ctx.eflags & I686_EF_ZF) == 0U);

    in = mk_insn(I686_OP_BSR_GvEv);
    in.len = 3U;
    set_rr(&in, I686_REG_EAX, I686_REG_EBX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EBX] = 0x00100000U;
    CHECK(run(I686_OP_BSR_GvEv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 20U);

    /* 0x0000FFFF: BSF -> 0 (ZF must be forced clear), BSR -> 15 */
    in = mk_insn(I686_OP_BSF_GvEv);
    in.len = 3U;
    set_rr(&in, I686_REG_EAX, I686_REG_EBX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EBX] = 0x0000FFFFU;
    CHECK(run(I686_OP_BSF_GvEv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0U);
    CHECK((ctx.eflags & I686_EF_ZF) == 0U); /* ZF tracks src==0, not index */

    in = mk_insn(I686_OP_BSR_GvEv);
    in.len = 3U;
    set_rr(&in, I686_REG_EAX, I686_REG_EBX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EBX] = 0x0000FFFFU;
    CHECK(run(I686_OP_BSR_GvEv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 15U);

    /* zero source: ZF set, destination untouched (both directions) */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EBX] = 0U;
    ctx.gpr[I686_REG_EAX] = 0xCAFED00DU;
    CHECK(run(I686_OP_BSF_GvEv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_ZF) != 0U);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xCAFED00DU);

    in = mk_insn(I686_OP_BSR_GvEv);
    in.len = 3U;
    set_rr(&in, I686_REG_EAX, I686_REG_EBX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EBX] = 0U;
    ctx.gpr[I686_REG_EAX] = 0xCAFED00DU;
    CHECK(run(I686_OP_BSR_GvEv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.eflags & I686_EF_ZF) != 0U);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xCAFED00DU);

    /* memory source */
    in = mk_insn(I686_OP_BSF_GvEv);
    in.len = 7U;
    set_mem(&in, I686_REG_EAX, 0x2100U);
    reset_ctx();
    ctx.eip = 0x1000U;
    tstore32(0x2100U, 0x00000010U);
    CHECK(run(I686_OP_BSF_GvEv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 4U);
}

void test_shld_shrd(void)
{
    x86_insn_t in;

    /* SHLD by 8: classic funnel; CF = old bit 24 */
    in = mk_insn(I686_OP_SHLD_EvIb);
    in.len = 4U; /* 0F A4 /r ib */
    in.imm = 8U;
    in.imm_size = 1U;
    set_rr(&in, I686_REG_EBX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x12345678U;
    ctx.gpr[I686_REG_EBX] = 0x9ABCDEF0U;
    CHECK(run(I686_OP_SHLD_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x3456789AU);
    CHECK((ctx.eflags & I686_EF_CF) == 0U);
    CHECK((ctx.eflags & I686_EF_ZF) == 0U);
    CHECK((ctx.eflags & I686_EF_SF) == 0U);

    /* SHLD by 1 through the sign bit: result 0, CF/OF/ZF all set */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x80000000U;
    ctx.gpr[I686_REG_EBX] = 1U;
    in.imm = 1U;
    CHECK(run(I686_OP_SHLD_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x00000000U);
    CHECK((ctx.eflags & I686_EF_CF) != 0U); /* old bit 31 out */
    CHECK((ctx.eflags & I686_EF_OF) != 0U); /* MSB(0) XOR CF */
    CHECK((ctx.eflags & I686_EF_ZF) != 0U);

    /* SHLD by 5: CF = old bit 27, SF set */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0xFFFFFFFFU;
    ctx.gpr[I686_REG_EBX] = 0U;
    in.imm = 5U;
    CHECK(run(I686_OP_SHLD_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xFFFFFFE0U);
    CHECK((ctx.eflags & I686_EF_CF) != 0U);
    CHECK((ctx.eflags & I686_EF_SF) != 0U);

    /* SHLD by 32: masked to 0 -> value and flags untouched */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x12345678U;
    ctx.gpr[I686_REG_EBX] = 0x9ABCDEF0U;
    ctx.eflags = I686_EF_CF | I686_EF_ZF;
    in.imm = 32U;
    CHECK(run(I686_OP_SHLD_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x12345678U);
    CHECK(ctx.eflags == (I686_EF_CF | I686_EF_ZF));

    /* SHLD by CL with CL = 0: same no-op through the CL form */
    in = mk_insn(I686_OP_SHLD_EvCL);
    in.len = 3U;
    set_rr(&in, I686_REG_EBX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x12345678U;
    ctx.gpr[I686_REG_EBX] = 0x9ABCDEF0U;
    ctx.eflags = 0U;
    CHECK(run(I686_OP_SHLD_EvCL, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x12345678U);
    CHECK(ctx.eflags == 0U);

    /* SHLD 16-bit: AX:BX funnel, EAX upper half preserved */
    in = mk_insn(I686_OP_SHLD_EvIb);
    in.len = 5U; /* 66 0F A4 /r ib */
    in.imm = 4U;
    in.imm_size = 1U;
    in.pfx_opsize = 1U;
    set_rr(&in, I686_REG_EBX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0xAA001234U;
    ctx.gpr[I686_REG_EBX] = 0x00005678U;
    CHECK(run(I686_OP_SHLD_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xAA002345U);
    CHECK((ctx.eflags & I686_EF_CF) != 0U); /* bit 28 of 0x12345678 */

    /* SHRD by 8: low half of (src:dest) >> 8 */
    in = mk_insn(I686_OP_SHRD_EvIb);
    in.len = 4U;
    in.imm = 8U;
    in.imm_size = 1U;
    set_rr(&in, I686_REG_EBX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x12345678U;
    ctx.gpr[I686_REG_EBX] = 0x9ABCDEF0U;
    CHECK(run(I686_OP_SHRD_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xF0123456U);
    CHECK((ctx.eflags & I686_EF_CF) == 0U); /* old bit 7 of 0x78 */
    CHECK((ctx.eflags & I686_EF_SF) != 0U);

    /* SHRD by 1: sign leaves the register, OF = MSB(old) XOR MSB(res) = 1 */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x80000000U;
    ctx.gpr[I686_REG_EBX] = 0U;
    in.imm = 1U;
    CHECK(run(I686_OP_SHRD_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x40000000U);
    CHECK((ctx.eflags & I686_EF_CF) == 0U); /* old bit 0 was 0 */
    CHECK((ctx.eflags & I686_EF_OF) != 0U); /* 1 XOR 0: sign change */

    /* SHRD by CL = 4 */
    in = mk_insn(I686_OP_SHRD_EvCL);
    in.len = 3U;
    set_rr(&in, I686_REG_EBX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x000000FFU;
    ctx.gpr[I686_REG_EBX] = 0xFFFFFFFFU;
    ctx.gpr[I686_REG_ECX] = 4U;
    CHECK(run(I686_OP_SHRD_EvCL, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xF000000FU);
    CHECK((ctx.eflags & I686_EF_CF) != 0U); /* old bit 3 of 0xFF */
    CHECK((ctx.eflags & I686_EF_SF) != 0U);

    /* SHRD by 32: masked to 0 -> untouched */
    in = mk_insn(I686_OP_SHRD_EvIb);
    in.len = 4U;
    in.imm = 32U;
    in.imm_size = 1U;
    set_rr(&in, I686_REG_EBX, I686_REG_EAX);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0x12345678U;
    ctx.eflags = I686_EF_CF;
    CHECK(run(I686_OP_SHRD_EvIb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x12345678U);
    CHECK(ctx.eflags == I686_EF_CF);
}

void test_int_trap(void)
{
    x86_insn_t in;

    /* int 0x80: syscall exit, eip past the instruction */
    in = mk_insn(I686_OP_INT_Ib);
    in.len = 2U;
    in.imm = 0x80U;
    in.imm_size = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_INT_Ib, &ctx, &in) == (int)I686_EXIT_SYSCALL);
    CHECK(ctx.exit_arg == 0x80U);
    CHECK(ctx.eip == 0x1002U);

    /* other vector: undefined exit, eip unchanged */
    reset_ctx();
    ctx.eip = 0x1000U;
    in.imm = 0x21U;
    CHECK(run(I686_OP_INT_Ib, &ctx, &in) == (int)I686_EXIT_UNDEF);
    CHECK(ctx.exit_arg == 0x21U);
    CHECK(ctx.eip == 0x1000U);

    /* int3: trap 3, eip past the one-byte trap */
    in = mk_insn(I686_OP_INT3);
    in.len = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_INT3, &ctx, &in) == (int)I686_EXIT_TRAP);
    CHECK(ctx.exit_arg == 3U);
    CHECK(ctx.eip == 0x1001U);

    /* INTO / IRET / UD2: undefined in v1, no state change */
    in = mk_insn(I686_OP_INTO);
    in.len = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_INTO, &ctx, &in) == (int)I686_EXIT_UNDEF);
    CHECK(ctx.eip == 0x1000U);

    in = mk_insn(I686_OP_IRET);
    in.len = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_IRET, &ctx, &in) == (int)I686_EXIT_UNDEF);
    CHECK(ctx.eip == 0x1000U);

    in = mk_insn(I686_OP_UD2);
    in.len = 2U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_UD2, &ctx, &in) == (int)I686_EXIT_UNDEF);
    CHECK(ctx.eip == 0x1000U);

    /* HLT stops with eip advanced */
    in = mk_insn(I686_OP_HLT);
    in.len = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_HLT, &ctx, &in) == (int)I686_EXIT_HLT);
    CHECK(ctx.eip == 0x1001U);

    /* WAIT / NOP: plain continuation */
    in = mk_insn(I686_OP_WAIT);
    in.len = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_WAIT, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x1001U);

    in = mk_insn(I686_OP_NOP);
    in.len = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_NOP, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x1001U);

    /* SYSENTER maps to int 0x80 per D12 */
    in = mk_insn(I686_OP_SYSENTER);
    in.len = 2U;
    reset_ctx();
    ctx.eip = 0x1000U;
    CHECK(run(I686_OP_SYSENTER, &ctx, &in) == (int)I686_EXIT_SYSCALL);
    CHECK(ctx.exit_arg == 0x80U);
    CHECK(ctx.eip == 0x1002U);
}

void test_registration(void)
{
    static const uint16_t ids[] = {
        I686_OP_JMP_Jb, I686_OP_JMP_Jz, I686_OP_JMP_Ev, I686_OP_JCC_Jb,
        I686_OP_JCC_Jz, I686_OP_CALL_Jz, I686_OP_CALL_Ev, I686_OP_RET,
        I686_OP_RET_Iw, I686_OP_SETcc_Eb, I686_OP_CMOVcc_Gv,
        I686_OP_LOOPNZ_Jb, I686_OP_LOOPZ_Jb, I686_OP_LOOP_Jb,
        I686_OP_JCXZ_Jb, I686_OP_BT_EvGv, I686_OP_BTS_EvGv,
        I686_OP_BTR_EvGv, I686_OP_BTC_EvGv, I686_OP_BT_EvIb,
        I686_OP_BTS_EvIb, I686_OP_BTR_EvIb, I686_OP_BTC_EvIb,
        I686_OP_BSF_GvEv, I686_OP_BSR_GvEv, I686_OP_SHLD_EvIb,
        I686_OP_SHLD_EvCL, I686_OP_SHRD_EvIb, I686_OP_SHRD_EvCL,
        I686_OP_INT_Ib, I686_OP_INT3, I686_OP_INTO, I686_OP_IRET,
        I686_OP_HLT, I686_OP_WAIT, I686_OP_UD2, I686_OP_SYSENTER,
        I686_OP_NOP,
    };
    unsigned i;

    for (i = 0U; i < sizeof ids / sizeof ids[0]; i++) {
        CHECK(ids[i] < TEST_MAX_OPS);
        CHECK(test_handlers[ids[i]] != NULL);
    }
}

