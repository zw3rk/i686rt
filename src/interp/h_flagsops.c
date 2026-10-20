/*
 * src/interp/h_flagsops.c — EFLAGS read/modify and flag-stack handlers
 * (Phase 1, lane L1b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * CMC/CLC/STC/CLI/STI/CLD/STD/SAHF/LAHF/PUSHF/POPF per docs/lanes/phase-1.md.
 * Every handler first makes ctx->eflags authoritative via i686_flags_read
 * (SPEC D6) and leaves lazy_op = I686_FOP_NONE behind.  Stack accesses are
 * flat-model: guest memory at gpr[ESP] inside the window.  v1 POPF policy:
 * accept the settable architectural bits CF..ID as popped, keep the old
 * IOPL, and ignore VM/RF (signals revisit this in Phase 4); 16-bit POPF
 * only touches the low word.  CLI/STI simply write IF (no IOPL checks in
 * the interpreter's user-mode v1).
 */

#include <stdbool.h>
#include <stdint.h>

#include "flags.h"
#include "interp.h"

/* Bits POPF may set from the popped value: architectural CF..ID minus
 * IOPL (kept from the old flags), RF and VM (ignored in v1). */
#define FLAGOPS_POPF_SETTABLE                                                \
    (I686_EF_CF | I686_EF_PF | I686_EF_AF | I686_EF_ZF | I686_EF_SF |        \
     I686_EF_TF | I686_EF_IF | I686_EF_DF | I686_EF_OF | I686_EF_NT |        \
     I686_EF_AC | I686_EF_VIF | I686_EF_VIP | I686_EF_ID)

/* SAHF/LAHF move exactly the 8080 subset; its bit positions coincide with
 * the EFLAGS positions, so masking AH directly is exact. */
#define FLAGOPS_AH_MASK \
    (I686_EF_SF | I686_EF_ZF | I686_EF_AF | I686_EF_PF | I686_EF_CF)

/* ModRM byte-register index of AH (encoding order AL CL DL BL AH CH DH BH). */
#define FLAGOPS_REG_AH 4U

/* Bit 1 of EFLAGS is reserved and always reads as 1. */
#define FLAGOPS_BIT1 0x02U

static int step(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

/* Materialize, then set or clear a single bit; the lazy descriptor is
 * already I686_FOP_NONE after i686_flags_read. */
static int flag_bit(i686_ctx_t *ctx, const x86_insn_t *insn, uint32_t bit,
                    bool set)
{
    uint32_t f = i686_flags_read(ctx);
    ctx->eflags = set ? (f | bit) : (f & ~bit);
    return step(ctx, insn);
}

static int h_CMC(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t f = i686_flags_read(ctx);
    ctx->eflags = f ^ I686_EF_CF;
    return step(ctx, insn);
}

static int h_CLC(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return flag_bit(ctx, insn, I686_EF_CF, false);
}

static int h_STC(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return flag_bit(ctx, insn, I686_EF_CF, true);
}

static int h_CLI(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return flag_bit(ctx, insn, I686_EF_IF, false);
}

static int h_STI(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return flag_bit(ctx, insn, I686_EF_IF, true);
}

static int h_CLD(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return flag_bit(ctx, insn, I686_EF_DF, false);
}

static int h_STD(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return flag_bit(ctx, insn, I686_EF_DF, true);
}

static int h_SAHF(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t f = i686_flags_read(ctx);
    uint32_t ah = x86_reg_read(ctx, FLAGOPS_REG_AH, 8U);
    ctx->eflags = (f & ~FLAGOPS_AH_MASK) | (ah & FLAGOPS_AH_MASK);
    return step(ctx, insn);
}

static int h_LAHF(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t f = i686_flags_read(ctx);
    x86_reg_write(ctx, FLAGOPS_REG_AH, 8U, (f & FLAGOPS_AH_MASK) | FLAGOPS_BIT1);
    return step(ctx, insn);
}

/* Flat stack helpers: little-endian guest memory at gpr[ESP]. */
static void stack_push(i686_ctx_t *ctx, uint32_t val, unsigned width)
{
    uint32_t bytes = width / 8U;
    uint32_t sp = ctx->gpr[I686_REG_ESP] - bytes;
    uint8_t *p = i686_guest_ptr(ctx, sp);
    for (uint32_t i = 0U; i < bytes; i++) {
        p[i] = (uint8_t)(val & 0xFFU);
        val >>= 8U;
    }
    ctx->gpr[I686_REG_ESP] = sp;
}

static uint32_t stack_pop(i686_ctx_t *ctx, unsigned width)
{
    uint32_t bytes = width / 8U;
    uint32_t sp = ctx->gpr[I686_REG_ESP];
    const uint8_t *p = i686_guest_ptr(ctx, sp);
    uint32_t val = 0U;
    for (uint32_t i = 0U; i < bytes; i++) {
        val |= (uint32_t)p[i] << (8U * i);
    }
    ctx->gpr[I686_REG_ESP] = sp + bytes;
    return val;
}

static unsigned stack_width(const x86_insn_t *insn)
{
    return insn->pfx_opsize != 0U ? 16U : 32U;
}

static int h_PUSHF(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = stack_width(insn);
    uint32_t val = i686_flags_read(ctx) | FLAGOPS_BIT1;
    stack_push(ctx, val, width);
    return step(ctx, insn);
}

static int h_POPF(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = stack_width(insn);
    uint32_t popped = stack_pop(ctx, width);
    uint32_t settable =
        FLAGOPS_POPF_SETTABLE & (width == 16U ? 0xFFFFU : 0xFFFFFFFFU);
    uint32_t old = i686_flags_read(ctx); /* preserved bits come from here */
    ctx->eflags = (old & ~settable) | (popped & settable);
    ctx->lazy_op = I686_FOP_NONE; /* eflags is authoritative again */
    return step(ctx, insn);
}

/* Registered from i686_interp_alu_init (h_alu.c): the lane owns a single
 * module init and interp.h freezes the public name list. */
void i686_interp_flagsops_register(void)
{
    i686_interp_register(I686_OP_CMC, h_CMC);
    i686_interp_register(I686_OP_CLC, h_CLC);
    i686_interp_register(I686_OP_STC, h_STC);
    i686_interp_register(I686_OP_CLI, h_CLI);
    i686_interp_register(I686_OP_STI, h_STI);
    i686_interp_register(I686_OP_CLD, h_CLD);
    i686_interp_register(I686_OP_STD, h_STD);
    i686_interp_register(I686_OP_SAHF, h_SAHF);
    i686_interp_register(I686_OP_LAHF, h_LAHF);
    i686_interp_register(I686_OP_PUSHF, h_PUSHF);
    i686_interp_register(I686_OP_POPF, h_POPF);
}
