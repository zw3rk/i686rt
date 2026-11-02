/*
 * tests/unit/test_l1b_cases.c — Unit test cases for test_l1b
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_l1b_internal.h"

void t_sub_cmp(void)
{
    i686_ctx_t *c;
    x86_insn_t i;

    /* CMP_EvIz 32-bit: no writeback, SUB descriptor */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 5U;
    i = mk_rr(I686_OP_CMP_EvIz, 7U, 0U);
    i.imm = 7U;
    i.imm_size = 4U;
    run(c, I686_OP_CMP_EvIz, &i);
    CHECK(c->gpr[I686_REG_EAX] == 5U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_SUB);
    CHECK(c->lazy_src1 == 5U);
    CHECK(c->lazy_src2 == 7U);
    CHECK(c->lazy_res == 0xFFFFFFFEU);

    /* CMP_EvIz 16-bit: result masked to width */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 5U;
    i = mk_rr(I686_OP_CMP_EvIz, 7U, 0U);
    i.pfx_opsize = 1U;
    i.imm = 7U;
    i.imm_size = 2U;
    run(c, I686_OP_CMP_EvIz, &i);
    CHECK(c->lazy_res == 0xFFFEU);
    CHECK(c->gpr[I686_REG_EAX] == 5U);

    /* SUB_EvIbSX: 0x10 - sext(0xF0) = 0x10 + 16 */
    c = new_ctx();
    mem_write(c, 0x3008U, 32U, 0x10U);
    i = mk_mem(I686_OP_SUB_EvIbSX, 0U, 0x3008U);
    i.imm = 0xF0U;
    i.imm_size = 1U;
    run(c, I686_OP_SUB_EvIbSX, &i);
    CHECK(mem_read(c, 0x3008U, 32U) == 0x20U);
    CHECK(c->lazy_src2 == 0xFFFFFFF0U);
    CHECK(c->lazy_res == 0x20U);
}

void t_incdec_neg_not(void)
{
    i686_ctx_t *c;
    x86_insn_t i;

    /* INC_Ev wraps and preserves CF = 1 */
    c = new_ctx();
    c->eflags = 0x03U;
    mem_write(c, 0x4000U, 32U, 0xFFFFFFFFU);
    i = mk_mem(I686_OP_INC_Ev, 0U, 0x4000U);
    run(c, I686_OP_INC_Ev, &i);
    CHECK(mem_read(c, 0x4000U, 32U) == 0U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_INC);
    CHECK(c->lazy_src1 == 0xFFFFFFFFU);
    CHECK(c->lazy_res == 0U);
    CHECK((c->eflags & I686_EF_CF) != 0U); /* CF untouched by INC */

    /* DEC_Eb wraps and preserves CF = 0 */
    c = new_ctx();
    mem_write(c, 0x4004U, 8U, 0U);
    i = mk_mem(I686_OP_DEC_Eb, 0U, 0x4004U);
    i.opnd[0] = I686_OPND_RM8;
    run(c, I686_OP_DEC_Eb, &i);
    CHECK(mem_read(c, 0x4004U, 8U) == 0xFFU);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_DEC);
    CHECK(c->lazy_res == 0xFFU);
    CHECK((c->eflags & I686_EF_CF) == 0U);

    /* INC_Ev via a 40+r-style register operand (opnd[0] = R32) */
    c = new_ctx();
    c->eflags = 0x03U;
    c->gpr[I686_REG_EDX] = 0x7FFFFFFFU;
    i = mk(I686_OP_INC_Ev);
    i.has_modrm = 1U;
    i.modrm_mod = 3U;
    i.modrm_reg = 2U; /* EDX */
    i.modrm_rm = 0U;
    i.opnd[0] = I686_OPND_R32;
    run(c, I686_OP_INC_Ev, &i);
    CHECK(c->gpr[I686_REG_EDX] == 0x80000000U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_INC);
    CHECK(c->lazy_src1 == 0x7FFFFFFFU);
    CHECK((c->eflags & I686_EF_CF) != 0U);

    /* NEG_Ev: 0 - 5 */
    c = new_ctx();
    mem_write(c, 0x4008U, 32U, 5U);
    i = mk_mem(I686_OP_NEG_Ev, 0U, 0x4008U);
    run(c, I686_OP_NEG_Ev, &i);
    CHECK(mem_read(c, 0x4008U, 32U) == 0xFFFFFFFBU);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_NEG);
    CHECK(c->lazy_src1 == 5U);
    CHECK(c->lazy_res == 0xFFFFFFFBU);

    /* NOT_Eb: no flags at all */
    c = new_ctx();
    mem_write(c, 0x400CU, 8U, 0x0FU);
    i = mk_mem(I686_OP_NOT_Eb, 0U, 0x400CU);
    i.opnd[0] = I686_OPND_RM8;
    run(c, I686_OP_NOT_Eb, &i);
    CHECK(mem_read(c, 0x400CU, 8U) == 0xF0U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_NONE);
    CHECK(c->eflags == 0x02U);
}

void t_xchg(void)
{
    i686_ctx_t *c;
    x86_insn_t i;

    /* XCHG_EvGv reg */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 0x11U;
    c->gpr[I686_REG_EDX] = 0x22U;
    i = mk_rr(I686_OP_XCHG_EvGv, 2U, 0U);
    run(c, I686_OP_XCHG_EvGv, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0x22U);
    CHECK(c->gpr[I686_REG_EDX] == 0x11U);

    /* XCHG_eAXGv (90+r; register in modrm_reg) */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 0x33U;
    c->gpr[I686_REG_ECX] = 0x44U;
    i = mk(I686_OP_XCHG_eAXGv);
    i.has_modrm = 1U;
    i.modrm_mod = 3U;
    i.modrm_reg = 1U; /* ECX */
    i.opnd[0] = I686_OPND_R32;
    run(c, I686_OP_XCHG_eAXGv, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0x44U);
    CHECK(c->gpr[I686_REG_ECX] == 0x33U);

    /* XCHG_EbGb mem */
    c = new_ctx();
    mem_write(c, 0x4010U, 8U, 0xAAU);
    c->gpr[I686_REG_EBX] = 0x55U; /* BL */
    i = mk_mem(I686_OP_XCHG_EbGb, 3U, 0x4010U);
    i.opnd[0] = I686_OPND_RM8;
    i.opnd[1] = I686_OPND_R8;
    run(c, I686_OP_XCHG_EbGb, &i);
    CHECK(mem_read(c, 0x4010U, 8U) == 0x55U);
    CHECK((c->gpr[I686_REG_EBX] & 0xFFU) == 0xAAU);

    /* XCHG_EvGv mem with base register EA ([EDI+8]) */
    c = new_ctx();
    c->gpr[I686_REG_EDI] = 0x5000U;
    c->gpr[I686_REG_EAX] = 0x88U;
    mem_write(c, 0x5008U, 32U, 0x77U);
    i = mk_mem(I686_OP_XCHG_EvGv, 0U, 8U);
    i.ea_base = I686_REG_EDI;
    run(c, I686_OP_XCHG_EvGv, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0x77U);
    CHECK(mem_read(c, 0x5008U, 32U) == 0x88U);
}

void t_cmpxchg_xadd(void)
{
    i686_ctx_t *c;
    x86_insn_t i;

    /* CMPXCHG_EvGv hit: EAX == mem, mem <- reg, EAX/reg untouched */
    c = new_ctx();
    mem_write(c, 0x5000U, 32U, 0x42U);
    c->gpr[I686_REG_EAX] = 0x42U;
    c->gpr[I686_REG_EBX] = 0x99U;
    i = mk_mem(I686_OP_CMPXCHG_EvGv, 3U, 0x5000U);
    run(c, I686_OP_CMPXCHG_EvGv, &i);
    CHECK(mem_read(c, 0x5000U, 32U) == 0x99U);
    CHECK(c->gpr[I686_REG_EAX] == 0x42U);
    CHECK(c->gpr[I686_REG_EBX] == 0x99U); /* reg is never written */
    CHECK(c->lazy_op == (uint32_t)I686_FOP_SUB);
    CHECK(c->lazy_res == 0U);

    /* CMPXCHG_EvGv miss: EAX <- mem, mem untouched */
    c = new_ctx();
    mem_write(c, 0x5004U, 32U, 0x55U);
    c->gpr[I686_REG_EAX] = 0x42U;
    c->gpr[I686_REG_EBX] = 0x99U;
    i = mk_mem(I686_OP_CMPXCHG_EvGv, 3U, 0x5004U);
    run(c, I686_OP_CMPXCHG_EvGv, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0x55U);
    CHECK(mem_read(c, 0x5004U, 32U) == 0x55U);
    CHECK(c->lazy_res == 0xFFFFFFEDU); /* 0x42 - 0x55 */

    /* CMPXCHG_EbGb hit on bytes */
    c = new_ctx();
    mem_write(c, 0x500CU, 8U, 0x7FU);
    c->gpr[I686_REG_EAX] = 0x7FU; /* AL */
    c->gpr[I686_REG_ECX] = 1U;    /* CL */
    i = mk_mem(I686_OP_CMPXCHG_EbGb, 1U, 0x500CU);
    i.opnd[0] = I686_OPND_RM8;
    i.opnd[1] = I686_OPND_R8;
    run(c, I686_OP_CMPXCHG_EbGb, &i);
    CHECK(mem_read(c, 0x500CU, 8U) == 0x01U);
    CHECK(c->lazy_res == 0U);
    CHECK(c->lazy_src1 == 0x7FU);

    /* XADD_EvGv: mem <- old + reg, reg <- old, flags of the ADD */
    c = new_ctx();
    mem_write(c, 0x5010U, 32U, 10U);
    c->gpr[I686_REG_ECX] = 32U;
    i = mk_mem(I686_OP_XADD_EvGv, 1U, 0x5010U);
    run(c, I686_OP_XADD_EvGv, &i);
    CHECK(mem_read(c, 0x5010U, 32U) == 42U);
    CHECK(c->gpr[I686_REG_ECX] == 10U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_ADD);
    CHECK(c->lazy_src1 == 10U);
    CHECK(c->lazy_res == 42U);

    /* XADD_EbGb byte form */
    c = new_ctx();
    mem_write(c, 0x5014U, 8U, 0xF0U);
    c->gpr[I686_REG_EDX] = 0x10U; /* DL */
    i = mk_mem(I686_OP_XADD_EbGb, 2U, 0x5014U);
    i.opnd[0] = I686_OPND_RM8;
    i.opnd[1] = I686_OPND_R8;
    run(c, I686_OP_XADD_EbGb, &i);
    CHECK(mem_read(c, 0x5014U, 8U) == 0x00U);
    CHECK((c->gpr[I686_REG_EDX] & 0xFFU) == 0xF0U);
    CHECK(c->lazy_res == 0x00U);
}

void t_pushf_popf(void)
{
    i686_ctx_t *c;
    x86_insn_t i;

    /* PUSHF 32-bit */
    c = new_ctx();
    c->eflags = 0x202U; /* IF | bit1 */
    i = mk(I686_OP_PUSHF);
    i.len = 1U;
    run(c, I686_OP_PUSHF, &i);
    CHECK(c->gpr[I686_REG_ESP] == WIN_SIZE - 4U);
    CHECK(mem_read(c, WIN_SIZE - 4U, 32U) == 0x202U);
    CHECK(c->eip == 0x1001U);

    /* PUSHF 16-bit */
    c = new_ctx();
    c->eflags = 0x202U;
    i = mk(I686_OP_PUSHF);
    i.len = 1U;
    i.pfx_opsize = 1U;
    run(c, I686_OP_PUSHF, &i);
    CHECK(c->gpr[I686_REG_ESP] == WIN_SIZE - 2U);
    CHECK(mem_read(c, WIN_SIZE - 2U, 16U) == 0x0202U);

    /* PUSHF materializes a pending lazy descriptor (ADD carry) */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 0xFFFFFFFFU;
    i = mk(I686_OP_ADD_eAXIz);
    i.imm = 1U;
    i.imm_size = 4U;
    run(c, I686_OP_ADD_eAXIz, &i);
    i = mk(I686_OP_PUSHF);
    i.len = 1U;
    run(c, I686_OP_PUSHF, &i);
    CHECK(c->gpr[I686_REG_ESP] == WIN_SIZE - 4U);
    CHECK((mem_read(c, WIN_SIZE - 4U, 32U) & I686_EF_CF) != 0U);
    CHECK((mem_read(c, WIN_SIZE - 4U, 32U) & I686_EF_ZF) != 0U);

    /* POPF 32-bit: settable bits applied, IOPL kept, RF/VM ignored, and
     * any pending lazy descriptor is dropped (eflags authoritative). */
    c = new_ctx();
    mem_write(c, 0x8000U, 32U, 0x00033645U);
    c->gpr[I686_REG_ESP] = 0x8000U;
    c->lazy_op = I686_FOP_ADD; /* stale descriptor must be discarded */
    c->lazy_src1 = 5U;
    c->lazy_src2 = 7U;
    i = mk(I686_OP_POPF);
    i.len = 1U;
    run(c, I686_OP_POPF, &i);
    /* popped settable bits: CF|PF|ZF|IF|DF; IOPL/RF/VM bits masked out */
    CHECK(c->eflags == 0x647U);
    CHECK(c->gpr[I686_REG_ESP] == 0x8004U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_NONE);

    /* POPF 16-bit: only the low word is settable; ID, IOPL preserved */
    c = new_ctx();
    c->eflags = I686_EF_ID | 0x02U;
    mem_write(c, 0x8010U, 16U, 0x0047U); /* CF, bit1, PF, ZF */
    c->gpr[I686_REG_ESP] = 0x8010U;
    i = mk(I686_OP_POPF);
    i.len = 1U;
    i.pfx_opsize = 1U;
    run(c, I686_OP_POPF, &i);
    CHECK((c->eflags & (I686_EF_CF | I686_EF_PF | I686_EF_ZF)) ==
          (I686_EF_CF | I686_EF_PF | I686_EF_ZF));
    CHECK((c->eflags & I686_EF_IF) == 0U);
    CHECK((c->eflags & I686_EF_ID) != 0U);
    CHECK((c->eflags & I686_EF_IOPL) == 0U);
}

void t_flag_bits_sahf_lahf(void)
{
    i686_ctx_t *c;
    x86_insn_t i;

    /* CMC toggles CF both ways */
    c = new_ctx();
    c->eflags = 0x03U;
    i = mk(I686_OP_CMC);
    i.len = 1U;
    run(c, I686_OP_CMC, &i);
    CHECK((c->eflags & I686_EF_CF) == 0U);
    run(c, I686_OP_CMC, &i);
    CHECK((c->eflags & I686_EF_CF) != 0U);

    /* CLC/STC/CLI/STI/CLD/STD leave the other bits alone */
    c = new_ctx();
    c->eflags = I686_EF_CF | I686_EF_IF | I686_EF_DF | 0x02U;
    i = mk(I686_OP_CLC);
    i.len = 1U;
    run(c, I686_OP_CLC, &i);
    CHECK((c->eflags & I686_EF_CF) == 0U);
    CHECK((c->eflags & I686_EF_IF) != 0U);
    CHECK((c->eflags & I686_EF_DF) != 0U);
    i = mk(I686_OP_STC);
    run(c, I686_OP_STC, &i);
    CHECK((c->eflags & I686_EF_CF) != 0U);
    i = mk(I686_OP_CLI);
    run(c, I686_OP_CLI, &i);
    CHECK((c->eflags & I686_EF_IF) == 0U);
    CHECK((c->eflags & I686_EF_DF) != 0U);
    i = mk(I686_OP_STI);
    run(c, I686_OP_STI, &i);
    CHECK((c->eflags & I686_EF_IF) != 0U);
    i = mk(I686_OP_CLD);
    run(c, I686_OP_CLD, &i);
    CHECK((c->eflags & I686_EF_DF) == 0U);
    i = mk(I686_OP_STD);
    run(c, I686_OP_STD, &i);
    CHECK((c->eflags & I686_EF_DF) != 0U);
    CHECK(c->eip == 0x100BU); /* one 1-byte insn + five mk() defaults of 2 */

    /* SAHF: SF/ZF/AF/PF/CF from AH, OF and the rest preserved */
    c = new_ctx();
    c->eflags = I686_EF_OF | I686_EF_ZF | I686_EF_CF | 0x02U;
    c->gpr[I686_REG_EAX] = 0x8000U; /* AH = 0x80 -> SF only */
    i = mk(I686_OP_SAHF);
    run(c, I686_OP_SAHF, &i);
    CHECK((c->eflags & I686_EF_SF) != 0U);
    CHECK((c->eflags & I686_EF_ZF) == 0U);
    CHECK((c->eflags & I686_EF_CF) == 0U);
    CHECK((c->eflags & I686_EF_OF) != 0U);

    /* LAHF: AH <- SF ZF 0 AF 0 PF 1 CF, bit 1 always set */
    c = new_ctx();
    c->eflags = I686_EF_SF | I686_EF_ZF | I686_EF_PF | I686_EF_CF |
                I686_EF_OF | 0x02U;
    i = mk(I686_OP_LAHF);
    run(c, I686_OP_LAHF, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0xC700U); /* AH = 0xC7; OF not in AH */
}


