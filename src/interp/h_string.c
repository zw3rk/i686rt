/*
 * src/interp/h_string.c — string instruction handlers (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * MOVS/CMPS/STOS/LODS/SCAS with the REP/REPE/REPNE prefixes and DF-driven
 * direction.  Frozen-contract notes:
 *
 * - Widths: the "b" forms are always 1 byte; the "w" forms are the
 *   operand-size forms (32-bit plain, 16-bit under the 66 prefix).
 * - DF is read straight from ctx->eflags bit 10: DF lives in EFLAGS
 *   permanently and is NOT part of the lazy arith descriptor (D6), so no
 *   materialization is needed before a string op.
 * - Segments: the source side (ESI) defaults to DS and honors pfx_seg;
 *   the destination side (EDI) is always ES and never overridable (x86
 *   rule).  STOS/SCAS touch only the ES side; LODS only the DS side.
 * - REP (F3) / REPNE (F2): the count lives in ECX (CX under the 66
 *   prefix, zero-extended on decrement); a zero count executes nothing.
 *   REPE/REPNE termination conditions apply only to CMPS/SCAS and are
 *   evaluated from the ZF of the just-recorded lazy SUB (computed from
 *   the operands, which is exactly the materialized ZF derivation).
 *   MOVS/STOS/LODS never touch flags.
 * - 0x67 (16-bit addressing): ESI/EDI wrap at 64 KiB and write back
 *   zero-extended, matching SI/DI semantics.
 *
 * Handlers return I686_INTERP_CONTINUE and advance ctx->eip by insn->len
 * (frozen interp.h contract).  Registration rides i686_interp_mov_init
 * (h_mov.c): interp.h declares a single init for this module pair.
 */

#include <stdbool.h>
#include <stdint.h>

#include "interp/interp.h"
#include "interp/flags.h"

/* 0xFF sentinel in the frozen x86_insn_t ("no segment override"). */
#define I686_NONE 0xFFU

static int interp_done(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

/* "w"-form width: operand-size dependent. */
static unsigned str_width(const x86_insn_t *insn)
{
    return (insn->pfx_opsize != 0U) ? 2U : 4U;
}

static uint32_t width_mask(unsigned width)
{
    if (width == 1U) {
        return 0xffU;
    }
    if (width == 2U) {
        return 0xffffU;
    }
    return 0xffffffffU;
}

static uint32_t mem_read(const i686_ctx_t *ctx, uint32_t va, unsigned width)
{
    const uint8_t *p = (const uint8_t *)i686_guest_ptr(ctx, va);
    uint32_t v = 0;

    for (unsigned i = 0; i < width; i++) {
        v |= (uint32_t)p[i] << (8U * i);
    }
    return v;
}

static void mem_write(i686_ctx_t *ctx, uint32_t va, unsigned width, uint32_t val)
{
    uint8_t *p = (uint8_t *)i686_guest_ptr(ctx, va);

    for (unsigned i = 0; i < width; i++) {
        p[i] = (uint8_t)(val >> (8U * i));
    }
}

/* Source-side segment base: DS default, pfx_seg override. */
static uint32_t src_seg_base(const i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t seg = (insn->pfx_seg != I686_NONE) ? insn->pfx_seg : I686_SEG_DS;

    return ctx->seg_base[seg];
}

/* String index register as a linear address component. */
static uint32_t str_addr(const i686_ctx_t *ctx, uint8_t reg, uint32_t seg_base,
                         uint8_t addr16)
{
    uint32_t off = ctx->gpr[reg];

    if (addr16 != 0U) {
        off &= 0xffffU;
    }
    return off + seg_base; /* wraps at 32 bits (D4) */
}

static void str_bump(i686_ctx_t *ctx, uint8_t reg, int32_t delta, uint8_t addr16)
{
    uint32_t v = ctx->gpr[reg] + (uint32_t)delta;

    if (addr16 != 0U) {
        v &= 0xffffU;
    }
    ctx->gpr[reg] = v;
}

/* REP count and decrement: ECX plain, CX (low half, upper preserved)
 * under the 66 prefix.  Zero count => the loop body never runs. */
static uint32_t rep_count_get(const i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->pfx_opsize != 0U) {
        return ctx->gpr[I686_REG_ECX] & 0xffffU;
    }
    return ctx->gpr[I686_REG_ECX];
}

static void rep_count_dec(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->pfx_opsize != 0U) {
        ctx->gpr[I686_REG_ECX] = (ctx->gpr[I686_REG_ECX] & 0xffff0000U) |
                                 ((ctx->gpr[I686_REG_ECX] - 1U) & 0xffffU);
    } else {
        ctx->gpr[I686_REG_ECX] = ctx->gpr[I686_REG_ECX] - 1U;
    }
}

static int32_t str_step(const i686_ctx_t *ctx, unsigned width)
{
    return ((ctx->eflags & I686_EF_DF) != 0U) ? -(int32_t)width : (int32_t)width;
}

/* Iteration count for a plain (non-REP) execution. */
static uint32_t iteration_count(const i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return (insn->pfx_rep != 0U) ? rep_count_get(ctx, insn) : 1U;
}

/* ------------------------------------------------------------------ */
/* MOVS: [DS:ESI] -> [ES:EDI], both indices advance.  No flags.        */
/* ------------------------------------------------------------------ */

static void movs_core(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned w)
{
    uint8_t addr16 = insn->pfx_addrsize;
    uint32_t src_base = src_seg_base(ctx, insn);
    uint32_t dst_base = ctx->seg_base[I686_SEG_ES];
    int32_t step = str_step(ctx, w);
    bool is_rep = insn->pfx_rep != 0U;
    uint32_t remaining = iteration_count(ctx, insn);

    while (remaining > 0U) {
        uint32_t v = mem_read(ctx, str_addr(ctx, I686_REG_ESI, src_base, addr16), w);

        mem_write(ctx, str_addr(ctx, I686_REG_EDI, dst_base, addr16), w, v);
        str_bump(ctx, I686_REG_ESI, step, addr16);
        str_bump(ctx, I686_REG_EDI, step, addr16);
        if (is_rep) {
            rep_count_dec(ctx, insn);
        }
        remaining--;
    }
}

/* ------------------------------------------------------------------ */
/* CMPS: [DS:ESI] - [ES:EDI], flags via lazy SUB, both indices advance. */
/* ------------------------------------------------------------------ */

static void cmps_core(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned w)
{
    uint8_t addr16 = insn->pfx_addrsize;
    uint32_t src_base = src_seg_base(ctx, insn);
    uint32_t dst_base = ctx->seg_base[I686_SEG_ES];
    int32_t step = str_step(ctx, w);
    bool is_rep = insn->pfx_rep != 0U;
    uint32_t mask = width_mask(w);
    uint32_t remaining = iteration_count(ctx, insn);

    while (remaining > 0U) {
        uint32_t a = mem_read(ctx, str_addr(ctx, I686_REG_ESI, src_base, addr16), w);
        uint32_t b = mem_read(ctx, str_addr(ctx, I686_REG_EDI, dst_base, addr16), w);

        i686_flags_sub(ctx, a, b, w);
        str_bump(ctx, I686_REG_ESI, step, addr16);
        str_bump(ctx, I686_REG_EDI, step, addr16);
        if (is_rep) {
            rep_count_dec(ctx, insn);
            /* REPE (F3) stops on ZF=0, REPNE (F2) stops on ZF=1; the ZF
             * of the just-recorded lazy SUB equals (a - b) & mask == 0. */
            bool zf = ((a - b) & mask) == 0U;

            if (insn->pfx_rep == 1U) {
                if (!zf) {
                    break;
                }
            } else { /* pfx_rep == 2 (REPNE) */
                if (zf) {
                    break;
                }
            }
        }
        remaining--;
    }
}

/* ------------------------------------------------------------------ */
/* STOS: AL/eAX -> [ES:EDI], EDI advances.  No flags.                  */
/* ------------------------------------------------------------------ */

static void stos_core(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned w)
{
    uint8_t addr16 = insn->pfx_addrsize;
    uint32_t dst_base = ctx->seg_base[I686_SEG_ES];
    int32_t step = str_step(ctx, w);
    bool is_rep = insn->pfx_rep != 0U;
    uint32_t remaining = iteration_count(ctx, insn);
    uint32_t v = x86_reg_read(ctx, I686_REG_EAX, w);

    while (remaining > 0U) {
        mem_write(ctx, str_addr(ctx, I686_REG_EDI, dst_base, addr16), w, v);
        str_bump(ctx, I686_REG_EDI, step, addr16);
        if (is_rep) {
            rep_count_dec(ctx, insn);
        }
        remaining--;
    }
}

/* ------------------------------------------------------------------ */
/* LODS: [DS:ESI] -> AL/eAX, ESI advances.  No flags.  REP repeats it  */
/* (architecturally defined; only the last load stays visible).        */
/* ------------------------------------------------------------------ */

static void lods_core(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned w)
{
    uint8_t addr16 = insn->pfx_addrsize;
    uint32_t src_base = src_seg_base(ctx, insn);
    int32_t step = str_step(ctx, w);
    bool is_rep = insn->pfx_rep != 0U;
    uint32_t remaining = iteration_count(ctx, insn);

    while (remaining > 0U) {
        uint32_t v = mem_read(ctx, str_addr(ctx, I686_REG_ESI, src_base, addr16), w);

        x86_reg_write(ctx, I686_REG_EAX, w, v);
        str_bump(ctx, I686_REG_ESI, step, addr16);
        if (is_rep) {
            rep_count_dec(ctx, insn);
        }
        remaining--;
    }
}

/* ------------------------------------------------------------------ */
/* SCAS: AL/eAX - [ES:EDI], flags via lazy SUB, EDI advances.          */
/* ------------------------------------------------------------------ */

static void scas_core(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned w)
{
    uint8_t addr16 = insn->pfx_addrsize;
    uint32_t dst_base = ctx->seg_base[I686_SEG_ES];
    int32_t step = str_step(ctx, w);
    bool is_rep = insn->pfx_rep != 0U;
    uint32_t mask = width_mask(w);
    uint32_t remaining = iteration_count(ctx, insn);

    while (remaining > 0U) {
        uint32_t a = x86_reg_read(ctx, I686_REG_EAX, w);
        uint32_t b = mem_read(ctx, str_addr(ctx, I686_REG_EDI, dst_base, addr16), w);

        i686_flags_sub(ctx, a, b, w);
        str_bump(ctx, I686_REG_EDI, step, addr16);
        if (is_rep) {
            rep_count_dec(ctx, insn);
            bool zf = ((a - b) & mask) == 0U;

            if (insn->pfx_rep == 1U) {
                if (!zf) {
                    break;
                }
            } else { /* pfx_rep == 2 (REPNE) */
                if (zf) {
                    break;
                }
            }
        }
        remaining--;
    }
}

/* ------------------------------------------------------------------ */
/* Handlers                                                            */
/* ------------------------------------------------------------------ */

static int h_movsb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    movs_core(ctx, insn, 1U);
    return interp_done(ctx, insn);
}

static int h_movsw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    movs_core(ctx, insn, str_width(insn));
    return interp_done(ctx, insn);
}

static int h_cmpsb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    cmps_core(ctx, insn, 1U);
    return interp_done(ctx, insn);
}

static int h_cmpsw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    cmps_core(ctx, insn, str_width(insn));
    return interp_done(ctx, insn);
}

static int h_stosb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    stos_core(ctx, insn, 1U);
    return interp_done(ctx, insn);
}

static int h_stosw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    stos_core(ctx, insn, str_width(insn));
    return interp_done(ctx, insn);
}

static int h_lodsb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    lods_core(ctx, insn, 1U);
    return interp_done(ctx, insn);
}

static int h_lodsw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    lods_core(ctx, insn, str_width(insn));
    return interp_done(ctx, insn);
}

static int h_scasb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    scas_core(ctx, insn, 1U);
    return interp_done(ctx, insn);
}

static int h_scasw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    scas_core(ctx, insn, str_width(insn));
    return interp_done(ctx, insn);
}

/* Called from i686_interp_mov_init (src/interp/h_mov.c): interp.h
 * freezes one init declaration for the mov+string module pair. */
void i686_interp_string_register(void)
{
    i686_interp_register(I686_OP_MOVSb, h_movsb);
    i686_interp_register(I686_OP_MOVSw, h_movsw);
    i686_interp_register(I686_OP_CMPSb, h_cmpsb);
    i686_interp_register(I686_OP_CMPSw, h_cmpsw);
    i686_interp_register(I686_OP_STOSb, h_stosb);
    i686_interp_register(I686_OP_STOSw, h_stosw);
    i686_interp_register(I686_OP_LODSb, h_lodsb);
    i686_interp_register(I686_OP_LODSw, h_lodsw);
    i686_interp_register(I686_OP_SCASb, h_scasb);
    i686_interp_register(I686_OP_SCASw, h_scasw);
}
