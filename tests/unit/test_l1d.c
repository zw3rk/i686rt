/*
 * tests/unit/test_l1d.c — host-native unit driver for Phase 1 L1d
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the h_branch.c / h_bit.c handlers directly against hand-built
 * x86_insn_t values over a fake 64 KiB guest window (guest VA N maps to
 * window[N]).  Every symbol those translation units import from
 * coordinator-owned files is provided here:
 *   - i686_interp_register (interp.c) — captured into a local table;
 *   - x86_reg_read/write, x86_rm_read/write, x86_ea_compute (decode.c) —
 *     test-side implementations of the frozen signatures;
 *   - i686_flags_* (flags.c) — TEST-ONLY duplicate of the SPEC D6 flag
 *     equations (O = S^S', S = msb, Z = res==0, C per op kind,
 *     A = (a^b^res)&0x10, P = parity); production flags.c lands with the
 *     coordinator at S1.
 *
 * Prints "L1D OK" and exits 0 when every check passes.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"
#include "x86/decode.h"

/* ------------------------------------------------------------------ */
/* Fake guest window + driver state                                    */
/* ------------------------------------------------------------------ */

static uint8_t window[0x10000U];
static i686_ctx_t ctx;
static int failures;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            (void)printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
        }                                                                    \
    } while (0)

static void reset_ctx(void)
{
    (void)memset(&ctx, 0, sizeof ctx);
    (void)memset(window, 0, sizeof window);
    ctx.guest_base = (uint64_t)(uintptr_t)&window[0];
    ctx.lazy_op = I686_FOP_NONE;
}

static uint32_t tload32(uint32_t va)
{
    uint32_t v = 0U;
    unsigned i;

    for (i = 0U; i < 4U; i++) {
        v |= (uint32_t)window[va + i] << (8U * i);
    }
    return v;
}

static void tstore32(uint32_t va, uint32_t v)
{
    unsigned i;

    for (i = 0U; i < 4U; i++) {
        window[va + i] = (uint8_t)(v >> (8U * i));
    }
}

/* ------------------------------------------------------------------ */
/* Test-side i686_interp_register (stand-in for src/interp/interp.c)   */
/* ------------------------------------------------------------------ */

#define TEST_MAX_OPS 512U
static i686_interp_fn test_handlers[TEST_MAX_OPS];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    test_handlers[op] = fn;
}

static int run(uint16_t op, i686_ctx_t *c, const x86_insn_t *in)
{
    CHECK(op < TEST_MAX_OPS);
    CHECK(test_handlers[op] != NULL);
    if (test_handlers[op] == NULL) {
        return -1;
    }
    return test_handlers[op](c, in);
}

/* ------------------------------------------------------------------ */
/* TEST-ONLY duplicate of src/interp/flags.c (SPEC D6 equations).      */
/* The units drive flags with lazy_op = I686_FOP_NONE; the lazy paths  */
/* below are computed at 32-bit width to satisfy the frozen API.       */
/* ------------------------------------------------------------------ */

static unsigned test_parity(uint8_t v)
{
    unsigned ones = 0U;
    unsigned i;

    for (i = 0U; i < 8U; i++) {
        ones += (v >> i) & 1U;
    }
    return (ones % 2U == 0U) ? 1U : 0U; /* PF set = even parity */
}

uint8_t i686_flags_parity(uint8_t v)
{
    return (uint8_t)test_parity(v);
}

static void test_set_arith(i686_ctx_t *c, unsigned cf, unsigned pf, unsigned af,
                           unsigned zf, unsigned sf, unsigned of)
{
    uint32_t fl = c->eflags & ~I686_EF_ARITH_MASK;

    if (cf != 0U) {
        fl |= I686_EF_CF;
    }
    if (pf != 0U) {
        fl |= I686_EF_PF;
    }
    if (af != 0U) {
        fl |= I686_EF_AF;
    }
    if (zf != 0U) {
        fl |= I686_EF_ZF;
    }
    if (sf != 0U) {
        fl |= I686_EF_SF;
    }
    if (of != 0U) {
        fl |= I686_EF_OF;
    }
    c->eflags = fl;
    c->lazy_op = I686_FOP_NONE;
}

void i686_flags_materialize(i686_ctx_t *c)
{
    uint32_t op = c->lazy_op;
    uint32_t res = c->lazy_res;
    uint32_t a = c->lazy_src1;
    uint32_t b = c->lazy_src2;
    unsigned cf = 0U, pf = 0U, af = 0U, zf = 0U, sf = 0U, of = 0U;

    if (op == I686_FOP_NONE) {
        return; /* eflags already authoritative */
    }

    pf = test_parity((uint8_t)res);
    zf = (res == 0U) ? 1U : 0U;
    sf = (res >> 31U) & 1U;

    switch (op) {
    case I686_FOP_ADD:
    case I686_FOP_ADC: {
        uint64_t s = (uint64_t)a + b +
                     ((op == I686_FOP_ADC) ? (uint64_t)(c->lazy_cf_in & 1U) : 0ULL);

        cf = (s >> 32U) != 0ULL ? 1U : 0U;
        of = (((a ^ res) & (b ^ res)) & 0x80000000U) != 0U ? 1U : 0U;
        af = (((a ^ b) ^ res) & 0x10U) != 0U ? 1U : 0U;
        break;
    }
    case I686_FOP_SUB:
    case I686_FOP_SBB: {
        uint64_t d = (uint64_t)a - b -
                     ((op == I686_FOP_SBB) ? (uint64_t)(c->lazy_cf_in & 1U) : 0ULL);

        cf = (d >> 63U) != 0ULL ? 1U : 0U; /* borrow out of bit 32 */
        of = (((a ^ b) & (a ^ res)) & 0x80000000U) != 0U ? 1U : 0U;
        af = (((a ^ b) ^ res) & 0x10U) != 0U ? 1U : 0U;
        break;
    }
    case I686_FOP_LOGIC:
        cf = 0U;
        of = 0U;
        af = 0U; /* undefined for logic; deterministic here */
        break;
    case I686_FOP_INC: /* ADD a,1; CF preserved */
        cf = (c->eflags & I686_EF_CF) != 0U ? 1U : 0U;
        of = (((a ^ res) & (1U ^ res)) & 0x80000000U) != 0U ? 1U : 0U;
        af = (((a ^ 1U) ^ res) & 0x10U) != 0U ? 1U : 0U;
        break;
    case I686_FOP_DEC: /* SUB a,1; CF preserved */
        cf = (c->eflags & I686_EF_CF) != 0U ? 1U : 0U;
        of = (((a ^ 1U) & (a ^ res)) & 0x80000000U) != 0U ? 1U : 0U;
        af = (((a ^ 1U) ^ res) & 0x10U) != 0U ? 1U : 0U;
        break;
    case I686_FOP_NEG: /* res = 0 - a */
        cf = (a != 0U) ? 1U : 0U;
        of = (a == 0x80000000U) ? 1U : 0U;
        af = ((a & 0xFU) != 0U) ? 1U : 0U;
        break;
    default:
        break; /* unreachable with the frozen FOP set */
    }

    test_set_arith(c, cf, pf, af, zf, sf, of);
}

uint32_t i686_flags_read(i686_ctx_t *c)
{
    i686_flags_materialize(c);
    return c->eflags;
}

uint8_t i686_flags_cc(i686_ctx_t *c, uint8_t cond)
{
    uint32_t fl = i686_flags_read(c);
    bool sf = (fl & I686_EF_SF) != 0U;
    bool of = (fl & I686_EF_OF) != 0U;
    bool zf = (fl & I686_EF_ZF) != 0U;
    bool cf = (fl & I686_EF_CF) != 0U;
    bool pf = (fl & I686_EF_PF) != 0U;

    switch (cond & 0xFU) {
    case 0U:  return (uint8_t)of;             /* O       */
    case 1U:  return (uint8_t)!of;            /* NO      */
    case 2U:  return (uint8_t)cf;             /* B       */
    case 3U:  return (uint8_t)!cf;            /* AE      */
    case 4U:  return (uint8_t)zf;             /* E       */
    case 5U:  return (uint8_t)!zf;            /* NE      */
    case 6U:  return (uint8_t)(cf || zf);     /* BE      */
    case 7U:  return (uint8_t)(!cf && !zf);   /* A       */
    case 8U:  return (uint8_t)sf;             /* S       */
    case 9U:  return (uint8_t)!sf;            /* NS      */
    case 10U: return (uint8_t)pf;             /* P       */
    case 11U: return (uint8_t)!pf;            /* PO      */
    case 12U: return (uint8_t)(sf != of);     /* L       */
    case 13U: return (uint8_t)(sf == of);     /* GE      */
    case 14U: return (uint8_t)(zf || (sf != of)); /* LE  */
    default:  return (uint8_t)(!zf && (sf == of)); /* G  */
    }
}

void i686_flags_logiczx(i686_ctx_t *c, uint32_t res, unsigned width)
{
    uint32_t mask = (width == 32U) ? 0xFFFFFFFFU
                   : (width == 16U) ? 0xFFFFU
                                    : 0xFFU;
    uint32_t v = res & mask;
    uint32_t fl;

    i686_flags_materialize(c); /* fold any pending lazy state first */
    fl = c->eflags & ~(I686_EF_CF | I686_EF_OF | I686_EF_ZF | I686_EF_SF |
                       I686_EF_PF);
    if (v == 0U) {
        fl |= I686_EF_ZF;
    }
    if ((v & (1U << (width - 1U))) != 0U) {
        fl |= I686_EF_SF;
    }
    if (test_parity((uint8_t)v) != 0U) {
        fl |= I686_EF_PF;
    }
    c->eflags = fl;
    c->lazy_op = I686_FOP_NONE;
}

/* ------------------------------------------------------------------ */
/* Test-side operand accessors (stand-ins for src/x86/decode.c; the   */
/* frozen signatures and semantics come from src/x86/decode.h).       */
/* ------------------------------------------------------------------ */

uint32_t x86_reg_read(const i686_ctx_t *c, uint8_t reg, unsigned width)
{
    uint32_t full = c->gpr[reg & 7U];

    if (width == 8U) {
        return (reg < 4U) ? (full & 0xFFU) : ((full >> 8U) & 0xFFU);
    }
    if (width == 16U) {
        return full & 0xFFFFU;
    }
    return full;
}

void x86_reg_write(i686_ctx_t *c, uint8_t reg, unsigned width, uint32_t val)
{
    if (width == 8U) {
        uint8_t b = (uint8_t)val;

        if (reg < 4U) {
            c->gpr[reg] = (c->gpr[reg] & ~0xFFU) | b;
        } else {
            c->gpr[reg - 4U] = (c->gpr[reg - 4U] & ~0xFF00U) | ((uint32_t)b << 8U);
        }
    } else if (width == 16U) {
        c->gpr[reg] = (c->gpr[reg] & 0xFFFF0000U) | (val & 0xFFFFU);
    } else {
        c->gpr[reg] = val;
    }
}

uint32_t x86_ea_compute(i686_ctx_t *c, const x86_insn_t *insn)
{
    uint32_t ea;

    if (insn->ea_has == 0U) {
        return 0U;
    }
    ea = insn->ea_disp;
    if (insn->ea_base != 0xFFU) {
        ea += c->gpr[insn->ea_base];
    }
    if (insn->ea_index != 0xFFU) {
        ea += c->gpr[insn->ea_index] << insn->ea_scale;
    }
    return ea; /* u32 wrap; unit tests keep all segment bases 0 */
}

static uint32_t test_rm_load(const i686_ctx_t *c, uint32_t va, unsigned width)
{
    const uint8_t *p = (const uint8_t *)i686_guest_ptr(c, va);
    uint32_t v = 0U;
    unsigned i;

    for (i = 0U; i < width / 8U; i++) {
        v |= (uint32_t)p[i] << (8U * i);
    }
    return v;
}

uint32_t x86_rm_read(i686_ctx_t *c, const x86_insn_t *insn, unsigned width)
{
    if (insn->modrm_mod == 3U) {
        return x86_reg_read(c, insn->modrm_rm, width);
    }
    return test_rm_load(c, x86_ea_compute(c, insn), width);
}

void x86_rm_write(i686_ctx_t *c, const x86_insn_t *insn, unsigned width, uint32_t val)
{
    if (insn->modrm_mod == 3U) {
        x86_reg_write(c, insn->modrm_rm, width, val);
        return;
    }
    {
        uint8_t *p = (uint8_t *)i686_guest_ptr(c, x86_ea_compute(c, insn));
        unsigned i;

        for (i = 0U; i < width / 8U; i++) {
            p[i] = (uint8_t)(val >> (8U * i));
        }
    }
}

/* ------------------------------------------------------------------ */
/* Hand-built instruction helpers                                     */
/* ------------------------------------------------------------------ */

static x86_insn_t mk_insn(uint16_t op)
{
    x86_insn_t in;

    (void)memset(&in, 0, sizeof in);
    in.op = op;
    in.pfx_seg = 0xFFU; /* no segment override */
    in.ea_base = 0xFFU; /* no base */
    in.ea_index = 0xFFU; /* no index */
    return in;
}

/* modrm register-register form: rm is operand[0]'s register. */
static void set_rr(x86_insn_t *in, uint8_t reg, uint8_t rm)
{
    in->has_modrm = 1U;
    in->modrm_mod = 3U;
    in->modrm_reg = reg;
    in->modrm_rm = rm;
}

/* modrm memory form: plain disp32 addressing inside the unit window. */
static void set_mem(x86_insn_t *in, uint8_t reg, uint32_t disp)
{
    in->has_modrm = 1U;
    in->modrm_mod = 0U;
    in->modrm_reg = reg;
    in->modrm_rm = 5U; /* disp32, no base */
    in->ea_has = 1U;
    in->ea_disp = disp;
    in->ea_base = 0xFFU;
    in->ea_index = 0xFFU;
    in->ea_scale = 0U;
}

/* ------------------------------------------------------------------ */
/* Groups                                                             */
/* ------------------------------------------------------------------ */

static void test_jmp(void)
{
    x86_insn_t in;

    /* JMP_Jz forward: eip + len + rel32 */
    reset_ctx();
    ctx.eip = 0x1000U;
    in = mk_insn(I686_OP_JMP_Jz);
    in.len = 5U;
    in.imm = 0x100U;
    in.imm_size = 4U;
    CHECK(run(I686_OP_JMP_Jz, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x1105U);

    /* JMP_Jb backward: eip + len + sign-extended rel8 */
    reset_ctx();
    ctx.eip = 0x1000U;
    in = mk_insn(I686_OP_JMP_Jb);
    in.len = 2U;
    in.imm = 0xF0U; /* -16 */
    in.imm_size = 1U;
    CHECK(run(I686_OP_JMP_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x0FF2U);

    /* JMP_Ev register form */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EDI] = 0x4000U;
    in = mk_insn(I686_OP_JMP_Ev);
    in.len = 2U;
    set_rr(&in, 0U, I686_REG_EDI);
    CHECK(run(I686_OP_JMP_Ev, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x4000U);

    /* JMP_Ev memory form */
    reset_ctx();
    ctx.eip = 0x1000U;
    tstore32(0x3000U, 0xB0000000U);
    in = mk_insn(I686_OP_JMP_Ev);
    in.len = 6U;
    set_mem(&in, 0U, 0x3000U);
    CHECK(run(I686_OP_JMP_Ev, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0xB0000000U);
}

static void test_jcc(void)
{
    /* Hardcoded oracle: taken/not-taken for conditions 0..15 under four
     * independent EFLAGS patterns (see flags.h encoding). */
    static const uint32_t pat[4] = {
        I686_EF_OF | I686_EF_ZF | I686_EF_SF | I686_EF_PF, /* A: CF=0 */
        I686_EF_CF | I686_EF_PF,                           /* B */
        0U,                                                 /* C: none */
        I686_EF_SF,                                         /* D */
    };
    static const uint8_t expect[4][16] = {
        { 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0 }, /* A */
        { 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1 }, /* B */
        { 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1 }, /* C */
        { 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0 }, /* D */
    };
    unsigned p, c;

    for (p = 0U; p < 4U; p++) {
        for (c = 0U; c < 16U; c++) {
            x86_insn_t in;

            reset_ctx();
            ctx.eip = 0x1000U;
            ctx.eflags = pat[p]; /* lazy_op = NONE from reset */
            in = mk_insn(I686_OP_JCC_Jz);
            in.len = 6U;
            in.imm = 8U;
            in.imm_size = 4U;
            in.modrm_reg = (uint8_t)c; /* family condition */
            CHECK(run(I686_OP_JCC_Jz, &ctx, &in) == I686_INTERP_CONTINUE);
            CHECK(ctx.eip == (expect[p][c] != 0U ? 0x100EU : 0x1006U));
        }
    }

    /* JCC_Jb short form, backward, taken (OF set) */
    reset_ctx();
    ctx.eip = 0x2000U;
    ctx.eflags = I686_EF_OF;
    {
        x86_insn_t in = mk_insn(I686_OP_JCC_Jb);

        in.len = 2U;
        in.imm = 0xFCU; /* -4 */
        in.imm_size = 1U;
        in.modrm_reg = 0U; /* JO */
        CHECK(run(I686_OP_JCC_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
        CHECK(ctx.eip == 0x1FFEU);
    }
}

static void test_call_ret(void)
{
    x86_insn_t in;

    /* CALL_Jz + RET pairing: return address pushed, stack restored */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ESP] = 0xFF00U;
    in = mk_insn(I686_OP_CALL_Jz);
    in.len = 5U;
    in.imm = 0x10U;
    in.imm_size = 4U;
    CHECK(run(I686_OP_CALL_Jz, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x1015U);
    CHECK(ctx.gpr[I686_REG_ESP] == 0xFEFCU);
    CHECK(tload32(0xFEFCU) == 0x1005U);

    in = mk_insn(I686_OP_RET);
    in.len = 1U;
    CHECK(run(I686_OP_RET, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x1005U);
    CHECK(ctx.gpr[I686_REG_ESP] == 0xFF00U);

    /* RET_Iw: pop, then esp += imm */
    reset_ctx();
    tstore32(0xFF00U, 0x777U);
    ctx.eip = 0x0U;
    ctx.gpr[I686_REG_ESP] = 0xFF00U;
    in = mk_insn(I686_OP_RET_Iw);
    in.len = 3U;
    in.imm = 0x12U;
    in.imm_size = 2U;
    CHECK(run(I686_OP_RET_Iw, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x777U);
    CHECK(ctx.gpr[I686_REG_ESP] == 0xFF16U); /* 0xFF00 + 4 + 0x12 */

    /* CALL_Ev memory form: target read, next_eip pushed */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ESP] = 0xFF00U;
    tstore32(0x3000U, 0x3000U);
    in = mk_insn(I686_OP_CALL_Ev);
    in.len = 6U;
    set_mem(&in, 0U, 0x3000U);
    CHECK(run(I686_OP_CALL_Ev, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x3000U);
    CHECK(ctx.gpr[I686_REG_ESP] == 0xFEFCU);
    CHECK(tload32(0xFEFCU) == 0x1006U);
}

static void test_loop_jcxz(void)
{
    x86_insn_t in;
    uint32_t taken = 0x0FFAU; /* 0x1000 + 2 - 8 */
    uint32_t next = 0x1002U;

    /* LOOP: dec then branch while ECX != 0 */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 2U;
    in = mk_insn(I686_OP_LOOP_Jb);
    in.len = 2U;
    in.imm = 0xF8U; /* -8 */
    in.imm_size = 1U;
    CHECK(run(I686_OP_LOOP_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_ECX] == 1U);
    CHECK(ctx.eip == taken);

    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 1U;
    CHECK(run(I686_OP_LOOP_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_ECX] == 0U);
    CHECK(ctx.eip == next);

    /* ECX = 0 wraps to 0xFFFFFFFF and the branch is taken */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 0U;
    CHECK(run(I686_OP_LOOP_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_ECX] == 0xFFFFFFFFU);
    CHECK(ctx.eip == taken);

    /* LOOPZ / LOOPNZ also gate on ZF */
    in = mk_insn(I686_OP_LOOPZ_Jb);
    in.len = 2U;
    in.imm = 0xF8U;
    in.imm_size = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 5U;
    ctx.eflags = I686_EF_ZF;
    CHECK(run(I686_OP_LOOPZ_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_ECX] == 4U);
    CHECK(ctx.eip == taken);

    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 5U; /* ZF clear: falls through */
    CHECK(run(I686_OP_LOOPZ_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == next);

    in = mk_insn(I686_OP_LOOPNZ_Jb);
    in.len = 2U;
    in.imm = 0xF8U;
    in.imm_size = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 5U; /* ZF clear: taken */
    CHECK(run(I686_OP_LOOPNZ_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == taken);

    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 5U;
    ctx.eflags = I686_EF_ZF; /* ZF set: falls through */
    CHECK(run(I686_OP_LOOPNZ_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == next);

    /* 16-bit operand size counts CX, not ECX */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 0x00010001U;
    in = mk_insn(I686_OP_LOOP_Jb);
    in.len = 3U; /* 66 E2 cb */
    in.imm = 0xF8U;
    in.imm_size = 1U;
    in.pfx_opsize = 1U;
    CHECK(run(I686_OP_LOOP_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_ECX] & 0xFFFFU) == 0U); /* CX hit zero */
    CHECK(ctx.eip == 0x1000U + 3U);

    /* JCXZ both ways, including the 16-bit CX view */
    in = mk_insn(I686_OP_JCXZ_Jb);
    in.len = 2U;
    in.imm = 0x10U;
    in.imm_size = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 0U;
    CHECK(run(I686_OP_JCXZ_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x1012U);

    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 3U;
    CHECK(run(I686_OP_JCXZ_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x1002U);

    in.len = 3U; /* 66 E3 cb */
    in.pfx_opsize = 1U;
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_ECX] = 0x00010000U; /* CX == 0 while ECX != 0 */
    CHECK(run(I686_OP_JCXZ_Jb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.eip == 0x1013U);
}

static void test_setcc_cmovcc(void)
{
    x86_insn_t in;

    /* SETcc to AL (register form), both flag polarities */
    in = mk_insn(I686_OP_SETcc_Eb);
    in.len = 3U; /* 0F 9x /r */
    set_rr(&in, 4U, I686_REG_EAX); /* rm = AL, cond E */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.eflags = I686_EF_ZF;
    CHECK(run(I686_OP_SETcc_Eb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EAX] & 0xFFU) == 1U);
    CHECK(ctx.eip == 0x1003U);

    reset_ctx();
    ctx.eip = 0x1000U; /* ZF clear: E false */
    CHECK(run(I686_OP_SETcc_Eb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EAX] & 0xFFU) == 0U);

    /* SETcc to AH (byte register 4) */
    set_rr(&in, 5U /*NE*/, 4U /*AH*/);
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0U;
    CHECK(run(I686_OP_SETcc_Eb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK((ctx.gpr[I686_REG_EAX] >> 8U) == 1U);

    /* SETcc to memory */
    set_mem(&in, 2U /*B*/, 0x2400U);
    in.len = 7U;
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.eflags = I686_EF_CF;
    CHECK(run(I686_OP_SETcc_Eb, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(window[0x2400U] == 1U);

    /* CMOVcc taken: full 32-bit move (cond NE rides in imm, dst is reg) */
    in = mk_insn(I686_OP_CMOVcc_Gv);
    in.len = 3U;
    set_rr(&in, I686_REG_EBX, I686_REG_EAX); /* dst EBX <- src EAX */
    in.imm = 5U; /* condition NE */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.gpr[I686_REG_EAX] = 0xDEADBEEFU;
    ctx.gpr[I686_REG_EBX] = 0x12345678U;
    CHECK(run(I686_OP_CMOVcc_Gv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0xDEADBEEFU);
    CHECK(ctx.eip == 0x1003U);

    /* CMOVcc not taken: destination untouched */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.eflags = I686_EF_ZF;
    ctx.gpr[I686_REG_EAX] = 0xDEADBEEFU;
    ctx.gpr[I686_REG_EBX] = 0x12345678U;
    CHECK(run(I686_OP_CMOVcc_Gv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0x12345678U);

    /* CMOVcc 16-bit: merge into the low half (cond E) */
    in.len = 4U; /* 66 0F 4x /r */
    in.pfx_opsize = 1U;
    set_rr(&in, I686_REG_EBX, I686_REG_EAX);
    in.imm = 4U; /* condition E */
    reset_ctx();
    ctx.eip = 0x1000U;
    ctx.eflags = I686_EF_ZF;
    ctx.gpr[I686_REG_EAX] = 0x0000ABCDU;
    ctx.gpr[I686_REG_EBX] = 0xFFFF1111U;
    CHECK(run(I686_OP_CMOVcc_Gv, &ctx, &in) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EBX] == 0xFFFFABCDU);
}

static void test_bt_regs(void)
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

static void test_bt_mem(void)
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

static void test_bsf_bsr(void)
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

static void test_shld_shrd(void)
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

static void test_int_trap(void)
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

static void test_registration(void)
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

int main(void)
{
    (void)memset(test_handlers, 0, sizeof test_handlers);
    reset_ctx();
    i686_interp_branch_init(); /* registers h_branch.c + h_bit.c ops */

    test_registration();
    test_jmp();
    test_jcc();
    test_call_ret();
    test_loop_jcxz();
    test_setcc_cmovcc();
    test_bt_regs();
    test_bt_mem();
    test_bsf_bsr();
    test_shld_shrd();
    test_int_trap();

    if (failures != 0) {
        (void)printf("L1D FAILED (%d)\n", failures);
        return 1;
    }
    (void)printf("L1D OK\n");
    return 0;
}
