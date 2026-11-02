/*
 * tests/unit/test_l1e.c — host-native unit driver for lane L1e
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Builds x86_insn_t values by hand against a fake guest window and
 * drives the h_muldiv.c / h_shift.c handlers through the registry.
 * src/interp/flags.c and src/x86/decode.c are NOT on this branch, so the
 * minimal flag equations and operand-access helpers they own are
 * duplicated below (every duplicate is marked TEST-ONLY; they are
 * deleted at S1 when the coordinator's files land).
 *
 * Prints "L1E OK" and exits 0 when every check passes.
 */

#include "test_l1e_internal.h"



/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

int g_pass;
int g_fail;


/* TEST-ONLY registry stand-in for src/interp/interp.c. */
i686_interp_fn g_tab[256];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    if (op < 256U) {
        g_tab[op] = fn;
    }
}

/* Fake guest window: guest_base + va lands inside this buffer
 * (little-endian host assumed — macOS arm64/x86_64). */
uint8_t g_window[0x8000];
i686_ctx_t ctx;

void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    /* Junk arithmetic bits (SF/PF/AF set, ZF/CF/OF clear) + IF, so
     * "undefined flags keep their previous eflags bits" is observable. */
    ctx.eflags = I686_EF_IF | I686_EF_SF | I686_EF_PF | I686_EF_AF;
    ctx.lazy_op = I686_FOP_NONE;
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
    memset(g_window, 0, sizeof g_window);
}

int run(const x86_insn_t *i)
{
    CHECK(i->op < 256U && g_tab[i->op] != NULL);
    if (i->op >= 256U || g_tab[i->op] == NULL) {
        return -1;
    }
    return g_tab[i->op](&ctx, i);
}

x86_insn_t mkinsn(uint16_t op, uint8_t o0, uint8_t o1)
{
    x86_insn_t i;

    memset(&i, 0, sizeof i);
    i.op = op;
    i.opnd[0] = o0;
    i.opnd[1] = o1;
    i.has_modrm = 1;
    i.modrm_mod = 3; /* register form; rm defaults to EBX */
    i.modrm_rm = I686_REG_EBX;
    return i;
}

void mkmem(x86_insn_t *i, uint32_t va)
{
    i->modrm_mod = 0;
    i->ea_has = 1;
    i->ea_base = 0xFF;
    i->ea_index = 0xFF;
    i->ea_disp = va;
}

/* w is the operand width in bits (8/16/32), matching the helper API. */
void mem_set(uint32_t va, uint32_t v, unsigned w)
{
    memcpy(&g_window[va], &v, w / 8U);
}

uint32_t mem_get(uint32_t va, unsigned w)
{
    uint32_t v = 0;

    memcpy(&v, &g_window[va], w / 8U);
    return v;
}

/* ------------------------------------------------------------------ */
/* TEST-ONLY duplicates of the coordinator-owned helpers (flags.c,     */
/* decode.c).  Deleted at S1.                                          */
/* ------------------------------------------------------------------ */

/* TEST-ONLY: standard x86 register access including AH/CH/DH/BH for
 * width 8 (reg 4..7 address the high byte of EAX/ECX/EDX/EBX). */
uint32_t x86_reg_read(const i686_ctx_t *c, uint8_t reg, unsigned w)
{
    uint32_t v = c->gpr[reg & 7U];

    if (w == 8U) {
        return (reg >= 4U) ? ((v >> 8) & 0xFFU) : (v & 0xFFU);
    }
    if (w == 16U) {
        return v & 0xFFFFU;
    }
    return v;
}

void x86_reg_write(i686_ctx_t *c, uint8_t reg, unsigned w, uint32_t val)
{
    uint32_t *g = &c->gpr[reg & 7U];

    if (w == 8U) {
        uint32_t shift = (reg >= 4U) ? 8U : 0U;
        *g = (*g & ~(0xFFU << shift)) | ((val & 0xFFU) << shift);
    } else if (w == 16U) {
        *g = (*g & 0xFFFF0000U) | (val & 0xFFFFU);
    } else {
        *g = val;
    }
}

/* TEST-ONLY: EA with optional base/index/scale, wrapping in 32 bits. */
uint32_t x86_ea_compute(i686_ctx_t *c, const x86_insn_t *i)
{
    uint32_t ea = i->ea_disp;

    if (i->ea_base != 0xFFU) {
        ea += x86_reg_read(c, i->ea_base, 32);
    }
    if (i->ea_index != 0xFFU) {
        ea += x86_reg_read(c, i->ea_index, 32) << i->ea_scale;
    }
    return ea;
}

/* TEST-ONLY: r/m access — register when mod == 3, window otherwise. */
uint32_t x86_rm_read(i686_ctx_t *c, const x86_insn_t *i, unsigned w)
{
    if (i->modrm_mod == 3U) {
        return x86_reg_read(c, i->modrm_rm, w);
    }
    return mem_get(x86_ea_compute(c, i), w);
}

void x86_rm_write(i686_ctx_t *c, const x86_insn_t *i, unsigned w, uint32_t val)
{
    if (i->modrm_mod == 3U) {
        x86_reg_write(c, i->modrm_rm, w, val);
        return;
    }
    memcpy(&g_window[x86_ea_compute(c, i)], &val, w / 8U);
}

/* TEST-ONLY flag equations (minimal duplicate of flags.c).  The lazy
 * descriptor in i686rt.h stores no width, so the test records the width
 * of the op it arms in g_twidth — handlers never look at it. */
unsigned g_twidth = 32;

uint32_t t_mask(unsigned w)
{
    if (w == 8U) {
        return 0xFFU;
    }
    if (w == 16U) {
        return 0xFFFFU;
    }
    return 0xFFFFFFFFU;
}

int64_t t_sext(uint32_t v, unsigned w)
{
    uint32_t m = t_mask(w);
    uint32_t x = v & m;

    if ((x & (m ^ (m >> 1U))) != 0U) {
        return (int64_t)x - ((int64_t)m + 1);
    }
    return (int64_t)x;
}

uint8_t i686_flags_parity(uint8_t v) /* PF set on even parity */
{
    unsigned p = 0;

    while (v != 0U) {
        p ^= (v & 1U);
        v = (uint8_t)(v >> 1U);
    }
    return (uint8_t)(p == 0U);
}

void i686_flags_logiczx(i686_ctx_t *c, uint32_t res, unsigned w)
{
    uint32_t m = t_mask(w);
    uint32_t r = res & m;

    c->lazy_op = I686_FOP_NONE;
    c->eflags &= ~(uint32_t)(I686_EF_CF | I686_EF_OF | I686_EF_ZF |
                             I686_EF_SF | I686_EF_PF);
    if (r == 0U) {
        c->eflags |= I686_EF_ZF;
    }
    if ((r & (m ^ (m >> 1U))) != 0U) {
        c->eflags |= I686_EF_SF;
    }
    if (i686_flags_parity((uint8_t)r) != 0U) {
        c->eflags |= I686_EF_PF;
    }
}

void i686_flags_materialize(i686_ctx_t *c)
{
    unsigned w = g_twidth;
    uint32_t m = t_mask(w);
    uint32_t r, s1, s2;

    switch (c->lazy_op) {
    case I686_FOP_NONE:
        return;
    case I686_FOP_ADD:
        r = c->lazy_res & m;
        s1 = c->lazy_src1 & m;
        s2 = c->lazy_src2 & m;
        c->eflags &= ~(uint32_t)I686_EF_ARITH_MASK;
        if ((uint64_t)s1 + s2 > m) {
            c->eflags |= I686_EF_CF;
        }
        if (r == 0U) {
            c->eflags |= I686_EF_ZF;
        }
        if ((r & (m ^ (m >> 1U))) != 0U) {
            c->eflags |= I686_EF_SF;
        }
        if (i686_flags_parity((uint8_t)r) != 0U) {
            c->eflags |= I686_EF_PF;
        }
        if (((s1 ^ s2 ^ r) >> 4) & 1U) {
            c->eflags |= I686_EF_AF;
        }
        if (t_sext(s1, w) + t_sext(s2, w) != t_sext(r, w)) {
            c->eflags |= I686_EF_OF;
        }
        break;
    case I686_FOP_SUB:
        r = c->lazy_res & m;
        s1 = c->lazy_src1 & m;
        s2 = c->lazy_src2 & m;
        c->eflags &= ~(uint32_t)I686_EF_ARITH_MASK;
        if (s1 < s2) {
            c->eflags |= I686_EF_CF;
        }
        if (r == 0U) {
            c->eflags |= I686_EF_ZF;
        }
        if ((r & (m ^ (m >> 1U))) != 0U) {
            c->eflags |= I686_EF_SF;
        }
        if (i686_flags_parity((uint8_t)r) != 0U) {
            c->eflags |= I686_EF_PF;
        }
        if (((s1 ^ s2 ^ r) >> 4) & 1U) {
            c->eflags |= I686_EF_AF;
        }
        if (t_sext(s1, w) - t_sext(s2, w) != t_sext(r, w)) {
            c->eflags |= I686_EF_OF;
        }
        break;
    case I686_FOP_LOGIC:
        i686_flags_logiczx(c, c->lazy_res, w);
        return;
    default:
        return; /* test driver never arms other ops */
    }
    c->lazy_op = I686_FOP_NONE;
}

/* Arm a pending lazy ADD exactly like a previous interpreter insn would
 * (eflags arith bits left stale, as the real engine does). */
void arm_add(uint32_t s1, uint32_t s2, unsigned w)
{
    ctx.lazy_op = I686_FOP_ADD;
    ctx.lazy_src1 = s1 & t_mask(w);
    ctx.lazy_src2 = s2 & t_mask(w);
    ctx.lazy_res = (ctx.lazy_src1 + ctx.lazy_src2) & t_mask(w);
    g_twidth = w;
}


/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */


static void t_registration(void)
{
    CHECK(g_tab[I686_OP_MUL_Eb] != NULL);
    CHECK(g_tab[I686_OP_MUL_Ev] != NULL);
    CHECK(g_tab[I686_OP_IMUL_Eb] != NULL);
    CHECK(g_tab[I686_OP_IMUL_Ev] != NULL);
    CHECK(g_tab[I686_OP_IMUL_GvEv] != NULL);
    CHECK(g_tab[I686_OP_DIV_Eb] != NULL);
    CHECK(g_tab[I686_OP_DIV_Ev] != NULL);
    CHECK(g_tab[I686_OP_IDIV_Eb] != NULL);
    CHECK(g_tab[I686_OP_IDIV_Ev] != NULL);
    CHECK(g_tab[I686_OP_CWDE] != NULL);
    CHECK(g_tab[I686_OP_CDQ] != NULL);
    CHECK(g_tab[I686_OP_ROL_Eb1] != NULL);
    CHECK(g_tab[I686_OP_ROR_EvCL] != NULL);
    CHECK(g_tab[I686_OP_RCL_EbIb] != NULL);
    CHECK(g_tab[I686_OP_RCR_Ev1] != NULL);
    CHECK(g_tab[I686_OP_SHL_EbCL] != NULL);
    CHECK(g_tab[I686_OP_SHR_EvIb] != NULL);
    CHECK(g_tab[I686_OP_SAR_Eb1] != NULL);
}

/* Oracle self-check: the TEST-ONLY materialize itself computes the
 * textbook ADD/SUB flags before the handlers are trusted to preserve or
 * drop them. */
static void t_oracle(void)
{
    reset();
    arm_add(0x8000U, 0x8000U, 16); /* -32768 + -32768 = -65536 */
    i686_flags_materialize(&ctx);
    CHECK(F_CF(ctx));
    CHECK(F_ZF(ctx));
    CHECK(!F_SF(ctx));
    CHECK(F_OF(ctx));
    CHECK(F_PF(ctx)); /* low byte 0x00: even parity */
    CHECK(ctx.lazy_op == I686_FOP_NONE);

    reset();
    ctx.lazy_op = I686_FOP_SUB;
    ctx.lazy_src1 = 5;
    ctx.lazy_src2 = 7;
    ctx.lazy_res = (5U - 7U) & 0xFFU; /* -2 */
    g_twidth = 8;
    i686_flags_materialize(&ctx);
    CHECK(F_CF(ctx));
    CHECK(F_SF(ctx));
    CHECK(!F_ZF(ctx));
}

static void t_mul(void)
{
    x86_insn_t i;

    /* 8-bit: 255 * 255 -> AX = 0xFE01, CF=OF=1 (AH != 0). */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x123400FF; /* AL = 0xFF */
    ctx.gpr[I686_REG_EBX] = 0xFF;
    i = mkinsn(I686_OP_MUL_Eb, I686_OPND_RM8, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0xFE01U);
    CHECK(F_CF(ctx) && F_OF(ctx));
    CHECK(ctx.lazy_op == I686_FOP_NONE);
    /* SF/ZF/PF/AF undefined: keep their previous eflags bits. */
    CHECK(F_SF(ctx) && F_PF(ctx) && F_AF(ctx) && !F_ZF(ctx));
    CHECK(F_IF(ctx));

    /* 8-bit small: 3 * 5 -> AX = 15, CF=OF=0. */
    reset();
    ctx.gpr[I686_REG_EAX] = 3;
    ctx.gpr[I686_REG_EBX] = 5;
    i = mkinsn(I686_OP_MUL_Eb, I686_OPND_RM8, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 15U);
    CHECK(!F_CF(ctx) && !F_OF(ctx));

    /* 32-bit memory form: 0xFFFFFFFF * 2 -> EDX:EAX = 1:0xFFFFFFFE. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0xFFFFFFFFU;
    mem_set(0x100, 2U, 32);
    i = mkinsn(I686_OP_MUL_Ev, I686_OPND_RM32, I686_OPND_NONE);
    mkmem(&i, 0x100);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xFFFFFFFEU);
    CHECK(ctx.gpr[I686_REG_EDX] == 1U);
    CHECK(F_CF(ctx) && F_OF(ctx));

    /* 32-bit no overflow: 0x10000 * 0xFFFF -> EDX = 0, CF=OF=0. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x10000U;
    ctx.gpr[I686_REG_EBX] = 0xFFFFU;
    i = mkinsn(I686_OP_MUL_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0xFFFF0000U);
    CHECK(ctx.gpr[I686_REG_EDX] == 0U);
    CHECK(!F_CF(ctx) && !F_OF(ctx));

    /* 16-bit: 0xFFFF * 0xFFFF -> DX:AX = 0xFFFE:0x0001, CF=OF=1. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0xFFFFU;
    ctx.gpr[I686_REG_EBX] = 0xFFFFU;
    i = mkinsn(I686_OP_MUL_Ev, I686_OPND_RM32, I686_OPND_NONE);
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0x0001U);
    CHECK(x86_reg_read(&ctx, I686_REG_EDX, 16) == 0xFFFEU);
    CHECK(F_CF(ctx) && F_OF(ctx));

    /* Pending lazy descriptor is dropped materialize-free by MUL. */
    reset();
    arm_add(2, 3, 32);
    ctx.gpr[I686_REG_EAX] = 7;
    ctx.gpr[I686_REG_EBX] = 6;
    i = mkinsn(I686_OP_MUL_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.lazy_op == I686_FOP_NONE);
    CHECK(ctx.gpr[I686_REG_EAX] == 42U);
    CHECK(!F_CF(ctx) && !F_OF(ctx));
}

static void t_imul1(void)
{
    x86_insn_t i;

    /* signed -1 * -1 = 1: EAX=1, EDX=0, CF=OF=0. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0xFFFFFFFFU;
    ctx.gpr[I686_REG_EBX] = 0xFFFFFFFFU;
    i = mkinsn(I686_OP_IMUL_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 1U);
    CHECK(ctx.gpr[I686_REG_EDX] == 0U);
    CHECK(!F_CF(ctx) && !F_OF(ctx));

    /* 0x40000000 * 2 = +2^31: exceeds INT32_MAX, so CF=OF=1; the full
     * 64-bit product is 0x00000000_80000000 -> EDX = 0. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x40000000U;
    ctx.gpr[I686_REG_EBX] = 2U;
    i = mkinsn(I686_OP_IMUL_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x80000000U);
    CHECK(ctx.gpr[I686_REG_EDX] == 0U);
    CHECK(F_CF(ctx) && F_OF(ctx));

    /* 0x40000000 * 4 = 2^32: does not fit -> CF=OF=1, EDX:EAX = 1:0. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x40000000U;
    ctx.gpr[I686_REG_EBX] = 4U;
    i = mkinsn(I686_OP_IMUL_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0U);
    CHECK(ctx.gpr[I686_REG_EDX] == 1U);
    CHECK(F_CF(ctx) && F_OF(ctx));

    /* 8-bit: -128 * -1 = +128 -> AX = 0x0080, CF=OF=1 (does not fit
     * signed 8). */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x80;
    ctx.gpr[I686_REG_EBX] = 0xFF;
    i = mkinsn(I686_OP_IMUL_Eb, I686_OPND_RM8, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0x0080U);
    CHECK(F_CF(ctx) && F_OF(ctx));

    /* 8-bit: -128 * 1 = -128 -> AX = 0xFF80, CF=OF=0. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0x80;
    ctx.gpr[I686_REG_EBX] = 1;
    i = mkinsn(I686_OP_IMUL_Eb, I686_OPND_RM8, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0xFF80U);
    CHECK(!F_CF(ctx) && !F_OF(ctx));
}

static void t_imul2(void)
{
    x86_insn_t i;

    /* ECX = 0x7FFFFFFF * 2 -> truncates, CF=OF=1. */
    reset();
    ctx.gpr[I686_REG_ECX] = 0x7FFFFFFFU;
    ctx.gpr[I686_REG_EBX] = 2U;
    i = mkinsn(I686_OP_IMUL_GvEv, I686_OPND_R32, I686_OPND_RM32);
    i.modrm_reg = I686_REG_ECX;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_ECX] == 0xFFFFFFFEU);
    CHECK(F_CF(ctx) && F_OF(ctx));

    /* ECX = -4 * 5 = -20 -> fits, CF=OF=0. */
    reset();
    ctx.gpr[I686_REG_ECX] = 0xFFFFFFFCU;
    ctx.gpr[I686_REG_EBX] = 5U;
    i = mkinsn(I686_OP_IMUL_GvEv, I686_OPND_R32, I686_OPND_RM32);
    i.modrm_reg = I686_REG_ECX;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_ECX] == 0xFFFFFFECU);
    CHECK(!F_CF(ctx) && !F_OF(ctx));

    /* 16-bit with 66: CX = -32768 * -1 = +32768 -> overflow, CF=OF=1,
     * CX = 0x8000. */
    reset();
    ctx.gpr[I686_REG_ECX] = 0x8000;
    ctx.gpr[I686_REG_EBX] = 0xFFFF;
    i = mkinsn(I686_OP_IMUL_GvEv, I686_OPND_R16, I686_OPND_RM16);
    i.modrm_reg = I686_REG_ECX;
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_ECX, 16) == 0x8000U);
    CHECK(F_CF(ctx) && F_OF(ctx));
}

static void t_div(void)
{
    x86_insn_t i;

    /* 2^32 / 10 -> EAX = 0x19999999, EDX = 6; flags untouched (lazy
     * descriptor still pending). */
    reset();
    ctx.gpr[I686_REG_EAX] = 0;
    ctx.gpr[I686_REG_EDX] = 1;
    ctx.gpr[I686_REG_EBX] = 10;
    arm_add(1, 1, 32);
    i = mkinsn(I686_OP_DIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 0x19999999U);
    CHECK(ctx.gpr[I686_REG_EDX] == 6U);
    CHECK(ctx.lazy_op == I686_FOP_ADD);
    CHECK(ctx.lazy_res == 2U);

    /* exact: 100 / 10 -> 10 r 0 */
    reset();
    ctx.gpr[I686_REG_EAX] = 100;
    ctx.gpr[I686_REG_EBX] = 10;
    i = mkinsn(I686_OP_DIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(ctx.gpr[I686_REG_EAX] == 10U);
    CHECK(ctx.gpr[I686_REG_EDX] == 0U);

    /* 16-bit: DX:AX = 0x00010000 / 3 -> AX = 0x5555, DX = 1. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0;
    ctx.gpr[I686_REG_EDX] = 1;
    ctx.gpr[I686_REG_EBX] = 3;
    i = mkinsn(I686_OP_DIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    i.pfx_opsize = 1;
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0x5555U);
    CHECK(x86_reg_read(&ctx, I686_REG_EDX, 16) == 1U);

    /* 8-bit: AX = 1000 / 10 -> AL = 100, AH = 0. */
    reset();
    ctx.gpr[I686_REG_EAX] = 1000;
    ctx.gpr[I686_REG_EBX] = 10;
    i = mkinsn(I686_OP_DIV_Eb, I686_OPND_RM8, I686_OPND_NONE);
    CHECK(run(&i) == I686_INTERP_CONTINUE);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 0x0064U);

    /* 8-bit quotient overflow: AX = 1000 / 3 -> fault, AX unchanged. */
    reset();
    ctx.gpr[I686_REG_EAX] = 1000;
    ctx.gpr[I686_REG_EBX] = 3;
    i = mkinsn(I686_OP_DIV_Eb, I686_OPND_RM8, I686_OPND_NONE);
    CHECK(run(&i) == I686_EXIT_FAULT);
    CHECK(ctx.exit_reason == I686_EXIT_FAULT);
    CHECK(ctx.exit_arg == 0U);
    CHECK(x86_reg_read(&ctx, I686_REG_EAX, 16) == 1000U);

    /* divide by zero (32-bit) -> fault. */
    reset();
    ctx.gpr[I686_REG_EAX] = 42;
    ctx.gpr[I686_REG_EBX] = 0;
    i = mkinsn(I686_OP_DIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_EXIT_FAULT);
    CHECK(ctx.exit_arg == 0U);
    CHECK(ctx.gpr[I686_REG_EAX] == 42U);

    /* 32-bit quotient overflow: 0x1_00000000 / 1 -> fault. */
    reset();
    ctx.gpr[I686_REG_EAX] = 0;
    ctx.gpr[I686_REG_EDX] = 1;
    ctx.gpr[I686_REG_EBX] = 1;
    i = mkinsn(I686_OP_DIV_Ev, I686_OPND_RM32, I686_OPND_NONE);
    CHECK(run(&i) == I686_EXIT_FAULT);
}

int main(void)
{
    reset();
    i686_interp_muldiv_init(); /* also registers the shift/rotate set */

    t_registration();
    t_oracle();
    t_mul();
    t_imul1();
    t_imul2();
    t_div();
    t_idiv();
    t_cwde_cdq();
    t_shifts();
    t_rotates();
    t_rcl_rcr();
    t_mem_forms();

    if (g_fail != 0) {
        printf("L1E FAILED: %d check(s) failed (%d passed)\n", g_fail, g_pass);
        return 1;
    }
    printf("L1E OK\n");
    return 0;
}
