/*
 * tests/unit/test_l1b.c — host-native unit driver for the L1b handlers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Links only test_l1b.c + src/interp/h_alu.c + src/interp/h_flagsops.c:
 * decode.c, flags.c and interp.c are coordinator-owned and absent on this
 * lane, so this file provides minimal test doubles for the frozen decode,
 * flags and registry entry points.  Per docs/lanes/phase-1.md the
 * assertions target the lazy-flag descriptors (lazy_op/res/src1/src2/
 * cf_in), GPR/memory results and eflags effects — not flags.c equations.
 * The doubles record width-masked values exactly as the frozen flags.h
 * contract requires, so the handlers stay decoupled from flags.c.
 *
 * Compile (with the L1a header absent, -I/tmp/l1b_stub supplies the stub):
 *   clang -std=c11 -Wall -Wextra -Werror=vla -pedantic \
 *       -Isrc -Iinclude -I/tmp/l1b_stub -o /tmp/test_l1b \
 *       tests/unit/test_l1b.c src/interp/h_alu.c src/interp/h_flagsops.c
 */

#include "test_l1b_internal.h"



int g_fail;
int g_checks;


/* ---- double: handler registry (interp.c is not on this lane) ---------- */

i686_interp_fn g_fns[REGISTRY_MAX];
uint16_t g_ops[REGISTRY_MAX];
int g_nreg;

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    for (int i = 0; i < g_nreg; i++) {
        if (g_ops[i] == op) { /* idempotent */
            g_fns[i] = fn;
            return;
        }
    }
    if (g_nreg < REGISTRY_MAX) {
        g_ops[g_nreg] = op;
        g_fns[g_nreg] = fn;
        g_nreg++;
    }
}

void run(i686_ctx_t *ctx, uint16_t op, const x86_insn_t *insn)
{
    i686_interp_fn fn = NULL;
    for (int i = 0; i < g_nreg; i++) {
        if (g_ops[i] == op) {
            fn = g_fns[i];
            break;
        }
    }
    CHECK(fn != NULL);
    if (fn != NULL) {
        CHECK(fn(ctx, insn) == I686_INTERP_CONTINUE);
    }
}

/* ---- double: decode.c operand accessors -------------------------------- */

uint32_t mem_read(const i686_ctx_t *ctx, uint32_t va, unsigned width)
{
    const uint8_t *p = i686_guest_ptr(ctx, va);
    uint32_t v = 0U;
    for (unsigned i = 0U; i < width / 8U; i++) {
        v |= (uint32_t)p[i] << (8U * i);
    }
    return v;
}

void mem_write(i686_ctx_t *ctx, uint32_t va, unsigned width, uint32_t val)
{
    uint8_t *p = i686_guest_ptr(ctx, va);
    for (unsigned i = 0U; i < width / 8U; i++) {
        p[i] = (uint8_t)(val & 0xFFU);
        val >>= 8U;
    }
}

uint32_t x86_reg_read(const i686_ctx_t *ctx, uint8_t reg, unsigned width)
{
    if (width == 8U) { /* AL CL DL BL AH CH DH BH */
        if (reg < 4U) {
            return ctx->gpr[reg] & 0xFFU;
        }
        return (ctx->gpr[reg - 4U] >> 8U) & 0xFFU;
    }
    if (width == 16U) {
        return ctx->gpr[reg] & 0xFFFFU;
    }
    return ctx->gpr[reg];
}

void x86_reg_write(i686_ctx_t *ctx, uint8_t reg, unsigned width, uint32_t val)
{
    if (width == 8U) {
        if (reg < 4U) {
            ctx->gpr[reg] = (ctx->gpr[reg] & ~0xFFU) | (val & 0xFFU);
        } else {
            uint32_t g = reg - 4U;
            ctx->gpr[g] = (ctx->gpr[g] & ~0xFF00U) | ((val & 0xFFU) << 8U);
        }
        return;
    }
    if (width == 16U) { /* writes preserve the upper half */
        ctx->gpr[reg] = (ctx->gpr[reg] & ~0xFFFFU) | (val & 0xFFFFU);
        return;
    }
    ctx->gpr[reg] = val;
}

uint32_t x86_ea_compute(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t ea = insn->ea_disp;
    if (insn->ea_base != 0xFFU) {
        ea += ctx->gpr[insn->ea_base];
    }
    if (insn->ea_index != 0xFFU) {
        ea += ctx->gpr[insn->ea_index] << (uint32_t)insn->ea_scale;
    }
    return ea; /* wraps in 32 bits */
}

uint32_t x86_rm_read(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width)
{
    if (insn->modrm_mod == 3U) {
        return x86_reg_read(ctx, insn->modrm_rm, width);
    }
    return mem_read(ctx, x86_ea_compute(ctx, insn), width);
}

void x86_rm_write(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width,
                  uint32_t val)
{
    if (insn->modrm_mod == 3U) {
        x86_reg_write(ctx, insn->modrm_rm, width, val);
        return;
    }
    mem_write(ctx, x86_ea_compute(ctx, insn), width, val);
}

/* ---- double: lazy flags (flags.c is not on this lane) ------------------
 * Setters record the descriptor with width-masked values per the frozen
 * contract; materialize derives the arith bits so handlers that need the
 * previous value (ADC/SBB carry-in, INC/DEC CF, PUSHF) work.  The width is
 * kept in a test-only side variable; the real flags.c derives it from the
 * masked operands. */

unsigned g_lazy_width;

uint32_t wmask(unsigned width)
{
    if (width == 8U) {
        return 0xFFU;
    }
    if (width == 16U) {
        return 0xFFFFU;
    }
    return 0xFFFFFFFFU;
}

uint32_t wmsb(unsigned width)
{
    if (width == 8U) {
        return 0x80U;
    }
    if (width == 16U) {
        return 0x8000U;
    }
    return 0x80000000U;
}

void lazy_set(i686_ctx_t *ctx, uint32_t op, uint32_t res, uint32_t s1,
                     uint32_t s2, uint32_t cf, unsigned width)
{
    ctx->lazy_op = op;
    ctx->lazy_res = res;
    ctx->lazy_src1 = s1;
    ctx->lazy_src2 = s2;
    ctx->lazy_cf_in = cf;
    g_lazy_width = width;
}

void i686_flags_add(i686_ctx_t *ctx, uint32_t s1, uint32_t s2, unsigned width)
{
    lazy_set(ctx, I686_FOP_ADD, (s1 + s2) & wmask(width), s1, s2, 0U, width);
}

void i686_flags_adc(i686_ctx_t *ctx, uint32_t s1, uint32_t s2, uint32_t cf,
                    unsigned width)
{
    lazy_set(ctx, I686_FOP_ADC, (s1 + s2 + cf) & wmask(width), s1, s2, cf,
             width);
}

void i686_flags_sub(i686_ctx_t *ctx, uint32_t s1, uint32_t s2, unsigned width)
{
    lazy_set(ctx, I686_FOP_SUB, (s1 - s2) & wmask(width), s1, s2, 0U, width);
}

void i686_flags_sbb(i686_ctx_t *ctx, uint32_t s1, uint32_t s2, uint32_t cf,
                    unsigned width)
{
    lazy_set(ctx, I686_FOP_SBB, (s1 - s2 - cf) & wmask(width), s1, s2, cf,
             width);
}

void i686_flags_logic(i686_ctx_t *ctx, uint32_t res, unsigned width)
{
    lazy_set(ctx, I686_FOP_LOGIC, res & wmask(width), 0U, 0U, 0U, width);
}

void i686_flags_inc(i686_ctx_t *ctx, uint32_t s1, unsigned width)
{
    lazy_set(ctx, I686_FOP_INC, (s1 + 1U) & wmask(width), s1, 0U, 0U, width);
}

void i686_flags_dec(i686_ctx_t *ctx, uint32_t s1, unsigned width)
{
    lazy_set(ctx, I686_FOP_DEC, (s1 - 1U) & wmask(width), s1, 0U, 0U, width);
}

void i686_flags_neg(i686_ctx_t *ctx, uint32_t s1, unsigned width)
{
    lazy_set(ctx, I686_FOP_NEG, (0U - s1) & wmask(width), s1, 0U, 0U, width);
}

uint32_t parity_bit(uint8_t v)
{
    v ^= v >> 4;
    v ^= v >> 2;
    v ^= v >> 1;
    return (uint32_t)((~v) & 1U);
}

void i686_flags_materialize(i686_ctx_t *ctx)
{
    if (ctx->lazy_op == I686_FOP_NONE) {
        return;
    }
    uint32_t m = wmask(g_lazy_width);
    uint32_t msb = wmsb(g_lazy_width);
    uint32_t r = ctx->lazy_res;
    uint32_t s1 = ctx->lazy_src1;
    uint32_t s2 = ctx->lazy_src2;
    uint32_t cf = 0U, of = 0U, af = 0U;

    switch (ctx->lazy_op) {
    case I686_FOP_ADD:
        cf = ((uint64_t)s1 + (uint64_t)s2) > (uint64_t)m ? 1U : 0U;
        of = ((~(s1 ^ s2)) & (s1 ^ r)) & msb;
        af = (s1 ^ s2 ^ r) & 0x10U;
        break;
    case I686_FOP_ADC:
        cf = ((uint64_t)s1 + (uint64_t)s2 + (uint64_t)ctx->lazy_cf_in) >
                     (uint64_t)m
                 ? 1U
                 : 0U;
        of = ((~(s1 ^ s2)) & (s1 ^ r)) & msb;
        af = (s1 ^ s2 ^ r) & 0x10U;
        break;
    case I686_FOP_SUB:
        cf = (s1 < s2) ? 1U : 0U;
        of = ((s1 ^ s2) & (s1 ^ r)) & msb;
        af = (s1 ^ s2 ^ r) & 0x10U;
        break;
    case I686_FOP_SBB:
        cf = ((uint64_t)s1 < (uint64_t)s2 + (uint64_t)ctx->lazy_cf_in) ? 1U
                                                                        : 0U;
        of = ((s1 ^ s2) & (s1 ^ r)) & msb;
        af = (s1 ^ s2 ^ r) & 0x10U;
        break;
    case I686_FOP_LOGIC:
        break; /* CF = OF = 0 */
    case I686_FOP_INC:
        of = (r == msb) ? 1U : 0U;
        af = ((s1 & 0xFU) == 0xFU) ? 1U : 0U;
        cf = (ctx->eflags & I686_EF_CF) != 0U ? 1U : 0U; /* preserved */
        break;
    case I686_FOP_DEC:
        of = (s1 == msb) ? 1U : 0U;
        af = ((s1 & 0xFU) == 0U) ? 1U : 0U;
        cf = (ctx->eflags & I686_EF_CF) != 0U ? 1U : 0U; /* preserved */
        break;
    case I686_FOP_NEG:
        cf = (s1 != 0U) ? 1U : 0U;
        of = (s1 == msb) ? 1U : 0U;
        af = (s1 ^ r) & 0x10U;
        break;
    default:
        break;
    }

    uint32_t f = ctx->eflags & ~I686_EF_ARITH_MASK;
    if (cf != 0U) {
        f |= I686_EF_CF;
    }
    if (parity_bit((uint8_t)(r & 0xFFU)) != 0U) {
        f |= I686_EF_PF;
    }
    if (af != 0U) {
        f |= I686_EF_AF;
    }
    if (r == 0U) {
        f |= I686_EF_ZF;
    }
    if ((r & msb) != 0U) {
        f |= I686_EF_SF;
    }
    if (of != 0U) {
        f |= I686_EF_OF;
    }
    ctx->eflags = f;
    ctx->lazy_op = I686_FOP_NONE;
}

uint32_t i686_flags_read(i686_ctx_t *ctx)
{
    i686_flags_materialize(ctx);
    return ctx->eflags;
}

/* ---- fixture: fake guest window + hand-built insns --------------------- */


uint8_t *g_win;

i686_ctx_t *new_ctx(void)
{
    if (g_win == NULL) {
        g_win = calloc(1U, WIN_SIZE);
        if (g_win == NULL) {
            fprintf(stderr, "L1B FAILED: out of memory\n");
            exit(1);
        }
    }
    i686_ctx_t *ctx = calloc(1U, sizeof(*ctx));
    if (ctx == NULL) {
        fprintf(stderr, "L1B FAILED: out of memory\n");
        exit(1);
    }
    ctx->guest_base = (uint64_t)(uintptr_t)g_win;
    ctx->gpr[I686_REG_ESP] = WIN_SIZE; /* stack top, grows down */
    ctx->eip = 0x1000U;
    ctx->eflags = 0x02U; /* reserved bit 1; everything else clear */
    ctx->lazy_op = I686_FOP_NONE;
    g_lazy_width = 32U;
    return ctx;
}

x86_insn_t mk(uint16_t op)
{
    x86_insn_t i;
    memset(&i, 0, sizeof(i));
    i.op = op;
    i.len = 2U;
    i.pfx_seg = 0xFFU;
    i.ea_base = 0xFFU;
    i.ea_index = 0xFFU;
    return i;
}

/* modrm register-register form (mod == 3). */
x86_insn_t mk_rr(uint16_t op, uint8_t reg, uint8_t rm)
{
    x86_insn_t i = mk(op);
    i.has_modrm = 1U;
    i.modrm_mod = 3U;
    i.modrm_reg = reg;
    i.modrm_rm = rm;
    i.opnd[0] = I686_OPND_RM32;
    i.opnd[1] = I686_OPND_R32;
    return i;
}

/* modrm memory form at ea_disp (no base/index). */
x86_insn_t mk_mem(uint16_t op, uint8_t reg, uint32_t va)
{
    x86_insn_t i = mk(op);
    i.has_modrm = 1U;
    i.modrm_mod = 0U;
    i.modrm_reg = reg;
    i.modrm_rm = 0U;
    i.ea_has = 1U;
    i.ea_disp = va;
    i.opnd[0] = I686_OPND_RM32;
    i.opnd[1] = I686_OPND_R32;
    return i;
}

/* ---- scenarios ---------------------------------------------------------- */


static void t_add_forms(void)
{
    i686_ctx_t *c = new_ctx();
    x86_insn_t i;

    /* ADD_EbGb reg (00 /r): AL += BL */
    c->gpr[I686_REG_EAX] = 0x12340034U;
    c->gpr[I686_REG_EBX] = 0x00000012U;
    i = mk_rr(I686_OP_ADD_EbGb, 3U, 0U);
    i.opnd[0] = I686_OPND_RM8;
    i.opnd[1] = I686_OPND_R8;
    run(c, I686_OP_ADD_EbGb, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0x12340046U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_ADD);
    CHECK(c->lazy_src1 == 0x34U);
    CHECK(c->lazy_src2 == 0x12U);
    CHECK(c->lazy_res == 0x46U);
    CHECK(c->eip == 0x1002U);

    /* ADD_EbGb mem with LOCK (F0 is a no-op for the interpreter) */
    c = new_ctx();
    mem_write(c, 0x2000U, 8U, 0xFFU);
    c->gpr[I686_REG_ECX] = 1U;
    i = mk_mem(I686_OP_ADD_EbGb, 1U, 0x2000U);
    i.opnd[0] = I686_OPND_RM8;
    i.opnd[1] = I686_OPND_R8;
    i.pfx_lock = 1U;
    run(c, I686_OP_ADD_EbGb, &i);
    CHECK(mem_read(c, 0x2000U, 8U) == 0x00U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_ADD);
    CHECK(c->lazy_src1 == 0xFFU);
    CHECK(c->lazy_src2 == 0x01U);
    CHECK(c->lazy_res == 0x00U);

    /* ADD_EvGv reg, 32-bit: EAX = 0x7FFFFFFF + 1 */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 0x7FFFFFFFU;
    c->gpr[I686_REG_EDX] = 1U;
    i = mk_rr(I686_OP_ADD_EvGv, 2U, 0U);
    run(c, I686_OP_ADD_EvGv, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0x80000000U);
    CHECK(c->lazy_res == 0x80000000U);
    CHECK(c->lazy_src1 == 0x7FFFFFFFU);

    /* ADD_EvGv reg with 66 prefix: AX wraps, upper of EAX preserved */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 0x1234FFFFU;
    c->gpr[I686_REG_EDX] = 0xABCD0001U;
    i = mk_rr(I686_OP_ADD_EvGv, 2U, 0U);
    i.pfx_opsize = 1U;
    run(c, I686_OP_ADD_EvGv, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0x12340000U);
    CHECK(c->lazy_res == 0x0000U);
    CHECK(c->lazy_src1 == 0xFFFFU); /* width-masked operands */
    CHECK(c->lazy_src2 == 0x0001U);

    /* ADD_GvEv mem: EDI (wrap) += dword */
    c = new_ctx();
    mem_write(c, 0x3000U, 32U, 0x10U);
    c->gpr[I686_REG_EDI] = 0xFFFFFFFDU;
    i = mk_mem(I686_OP_ADD_GvEv, 7U, 0x3000U);
    run(c, I686_OP_ADD_GvEv, &i);
    CHECK(c->gpr[I686_REG_EDI] == 0x0000000DU);
    CHECK(c->lazy_res == 0x0000000DU);
    CHECK(c->lazy_src1 == 0xFFFFFFFDU);

    /* ADD_eAXIz with 66 prefix: imm16 into AX */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 0xFFFF0030U;
    i = mk(I686_OP_ADD_eAXIz);
    i.pfx_opsize = 1U;
    i.imm = 0x0010U;
    i.imm_size = 2U;
    run(c, I686_OP_ADD_eAXIz, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0xFFFF0040U);
    CHECK(c->lazy_res == 0x0040U);
    CHECK(c->lazy_src1 == 0x0030U);
    CHECK(c->lazy_src2 == 0x0010U);
}

static void t_logic_forms(void)
{
    i686_ctx_t *c = new_ctx();
    x86_insn_t i;

    /* OR_ALIb: 0xF0 | 0x0F */
    c->gpr[I686_REG_EAX] = 0xF0U;
    i = mk(I686_OP_OR_ALIb);
    i.imm = 0x0FU;
    i.imm_size = 1U;
    run(c, I686_OP_OR_ALIb, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0xFFU);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_LOGIC);
    CHECK(c->lazy_res == 0xFFU);

    /* XOR_EvIbSX: 0 ^ sext(0xFF) */
    mem_write(c, 0x3004U, 32U, 0U);
    i = mk_mem(I686_OP_XOR_EvIbSX, 0U, 0x3004U);
    i.imm = 0xFFU;
    i.imm_size = 1U;
    run(c, I686_OP_XOR_EvIbSX, &i);
    CHECK(mem_read(c, 0x3004U, 32U) == 0xFFFFFFFFU);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_LOGIC);
    CHECK(c->lazy_res == 0xFFFFFFFFU);

    /* AND_eAXIz */
    c->gpr[I686_REG_EAX] = 0xF0F0F0F0U;
    i = mk(I686_OP_AND_eAXIz);
    i.imm = 0x0F0F0F0FU;
    i.imm_size = 4U;
    run(c, I686_OP_AND_eAXIz, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_LOGIC);
    CHECK(c->lazy_res == 0U);

    /* TEST_EvIz: like AND but no writeback */
    c->gpr[I686_REG_EAX] = 0xF0F0F0F0U;
    i = mk(I686_OP_TEST_eAXIz);
    i.imm = 0x0F0F0F0FU;
    i.imm_size = 4U;
    run(c, I686_OP_TEST_eAXIz, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0xF0F0F0F0U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_LOGIC);
    CHECK(c->lazy_res == 0U);
}

static void t_adc_sbb_carry(void)
{
    i686_ctx_t *c;
    x86_insn_t i;

    /* ADC_ALIb with CF = 1 in eflags (lazy NONE) */
    c = new_ctx();
    c->eflags = 0x03U; /* CF | bit1 */
    c->gpr[I686_REG_EAX] = 0x10U;
    i = mk(I686_OP_ADC_ALIb);
    i.imm = 0xFFU;
    i.imm_size = 1U;
    run(c, I686_OP_ADC_ALIb, &i);
    CHECK((c->gpr[I686_REG_EAX] & 0xFFU) == 0x10U); /* 0x10+0xFF+1 wraps */
    CHECK(c->lazy_op == (uint32_t)I686_FOP_ADC);
    CHECK(c->lazy_cf_in == 1U);
    CHECK(c->lazy_res == 0x10U);
    CHECK(c->lazy_src2 == 0xFFU);

    /* ADC right after ADD: the carry-in must come from the pending ADD */
    c = new_ctx();
    c->gpr[I686_REG_EAX] = 0xFFFFFFFFU;
    i = mk(I686_OP_ADD_eAXIz);
    i.imm = 1U;
    i.imm_size = 4U;
    run(c, I686_OP_ADD_eAXIz, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0U);
    i = mk(I686_OP_ADC_eAXIz);
    i.imm = 0U;
    i.imm_size = 4U;
    run(c, I686_OP_ADC_eAXIz, &i);
    CHECK(c->gpr[I686_REG_EAX] == 1U);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_ADC);
    CHECK(c->lazy_cf_in == 1U); /* ADD 0xFFFFFFFF+1 materialized to CF=1 */
    CHECK(c->lazy_src1 == 0U);

    /* SBB_eAXIz with CF = 1: 0 - 0 - 1 */
    c = new_ctx();
    c->eflags = 0x03U;
    i = mk(I686_OP_SBB_eAXIz);
    i.imm = 0U;
    i.imm_size = 4U;
    run(c, I686_OP_SBB_eAXIz, &i);
    CHECK(c->gpr[I686_REG_EAX] == 0xFFFFFFFFU);
    CHECK(c->lazy_op == (uint32_t)I686_FOP_SBB);
    CHECK(c->lazy_cf_in == 1U);
    CHECK(c->lazy_res == 0xFFFFFFFFU);
}

int main(void)
{
    i686_interp_alu_init(); /* registers ALU + flag-op handlers */

    t_add_forms();
    t_logic_forms();
    t_adc_sbb_carry();
    t_sub_cmp();
    t_incdec_neg_not();
    t_xchg();
    t_cmpxchg_xadd();
    t_pushf_popf();
    t_flag_bits_sahf_lahf();

    if (g_fail != 0) {
        fprintf(stderr, "L1B FAILED: %d of %d checks failed\n", g_fail,
                g_checks);
        return 1;
    }
    puts("L1B OK");
    return 0;
}
