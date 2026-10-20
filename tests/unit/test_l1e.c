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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "i686rt.h"
#include "x86/decode.h"
#include "interp/interp.h"

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

/* TEST-ONLY registry stand-in for src/interp/interp.c. */
static i686_interp_fn g_tab[256];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    if (op < 256U) {
        g_tab[op] = fn;
    }
}

/* Fake guest window: guest_base + va lands inside this buffer
 * (little-endian host assumed — macOS arm64/x86_64). */
static uint8_t g_window[0x8000];
static i686_ctx_t ctx;

static void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    /* Junk arithmetic bits (SF/PF/AF set, ZF/CF/OF clear) + IF, so
     * "undefined flags keep their previous eflags bits" is observable. */
    ctx.eflags = I686_EF_IF | I686_EF_SF | I686_EF_PF | I686_EF_AF;
    ctx.lazy_op = I686_FOP_NONE;
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
    memset(g_window, 0, sizeof g_window);
}

static int run(const x86_insn_t *i)
{
    CHECK(i->op < 256U && g_tab[i->op] != NULL);
    if (i->op >= 256U || g_tab[i->op] == NULL) {
        return -1;
    }
    return g_tab[i->op](&ctx, i);
}

static x86_insn_t mkinsn(uint16_t op, uint8_t o0, uint8_t o1)
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

static void mkmem(x86_insn_t *i, uint32_t va)
{
    i->modrm_mod = 0;
    i->ea_has = 1;
    i->ea_base = 0xFF;
    i->ea_index = 0xFF;
    i->ea_disp = va;
}

/* w is the operand width in bits (8/16/32), matching the helper API. */
static void mem_set(uint32_t va, uint32_t v, unsigned w)
{
    memcpy(&g_window[va], &v, w / 8U);
}

static uint32_t mem_get(uint32_t va, unsigned w)
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
static unsigned g_twidth = 32;

static uint32_t t_mask(unsigned w)
{
    if (w == 8U) {
        return 0xFFU;
    }
    if (w == 16U) {
        return 0xFFFFU;
    }
    return 0xFFFFFFFFU;
}

static int64_t t_sext(uint32_t v, unsigned w)
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
static void arm_add(uint32_t s1, uint32_t s2, unsigned w)
{
    ctx.lazy_op = I686_FOP_ADD;
    ctx.lazy_src1 = s1 & t_mask(w);
    ctx.lazy_src2 = s2 & t_mask(w);
    ctx.lazy_res = (ctx.lazy_src1 + ctx.lazy_src2) & t_mask(w);
    g_twidth = w;
}

#define F_CF(ctx) (((ctx).eflags & I686_EF_CF) != 0U)
#define F_OF(ctx) (((ctx).eflags & I686_EF_OF) != 0U)
#define F_SF(ctx) (((ctx).eflags & I686_EF_SF) != 0U)
#define F_ZF(ctx) (((ctx).eflags & I686_EF_ZF) != 0U)
#define F_PF(ctx) (((ctx).eflags & I686_EF_PF) != 0U)
#define F_AF(ctx) (((ctx).eflags & I686_EF_AF) != 0U)
#define F_IF(ctx) (((ctx).eflags & I686_EF_IF) != 0U)

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

static void t_idiv(void)
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

static void t_cwde_cdq(void)
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

static void t_shifts(void)
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

static void t_rotates(void)
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

static void t_rcl_rcr(void)
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

static void t_mem_forms(void)
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
