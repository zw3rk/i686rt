/*
 * src/interp/flags.c — reference lazy-flags semantics (SPEC D6)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The lazy descriptor {op, res, src1, src2, cf_in} defers CF/PF/AF/ZF/SF/OF
 * materialization to reads.  This file is the single semantic authority:
 * the Phase 3 DBT must produce bit-identical results.
 */

#include "interp/flags.h"

static uint32_t width_mask(unsigned width)
{
    if (width == 8) {
        return 0xffU;
    }
    if (width == 16) {
        return 0xffffU;
    }
    return 0xffffffffU;
}

static unsigned width_msb(unsigned width)
{
    return width == 8 ? 7U : (width == 16 ? 15U : 31U);
}

uint8_t i686_flags_parity(uint8_t v)
{
    uint8_t p = 0;
    while (v != 0U) {
        p ^= (uint8_t)(v & 1U);
        v >>= 1;
    }
    return (uint8_t)(p == 0U ? 1U : 0U); /* 1 when EVEN parity (PF set) */
}

/* Write SF/ZF/PF from a width-masked result. */
static void set_szp(i686_ctx_t *ctx, uint32_t res, unsigned width)
{
    uint32_t m = width_mask(width);
    uint32_t r = res & m;
    ctx->eflags &= ~(I686_EF_ZF | I686_EF_SF | I686_EF_PF);
    if (r == 0U) {
        ctx->eflags |= I686_EF_ZF;
    }
    if ((r >> width_msb(width) & 1U) != 0U) {
        ctx->eflags |= I686_EF_SF;
    }
    if (i686_flags_parity((uint8_t)(r & 0xffU)) != 0U) {
        ctx->eflags |= I686_EF_PF;
    }
}

void i686_flags_materialize(i686_ctx_t *ctx)
{
    uint32_t res = ctx->lazy_res;
    uint32_t s1 = ctx->lazy_src1;
    uint32_t s2 = ctx->lazy_src2;
    unsigned w = ctx->lazy_width == 8U || ctx->lazy_width == 16U ||
                 ctx->lazy_width == 32U ? ctx->lazy_width : 32U;
    uint32_t m = width_mask(w);
    unsigned msb = width_msb(w);
    uint32_t sign = 1U << msb;
    uint64_t wide;

    switch (ctx->lazy_op) {
    case I686_FOP_NONE:
        return;
    case I686_FOP_ADD:
    case I686_FOP_ADC:
        wide = (uint64_t)s1 + (uint64_t)s2 +
               (uint64_t)(ctx->lazy_op == I686_FOP_ADC ? (ctx->lazy_cf_in & 1U) : 0U);
        res = (uint32_t)wide & m;
        ctx->eflags &= ~(I686_EF_ARITH_MASK | I686_EF_AF);
        if (wide > (uint64_t)m) {
            ctx->eflags |= I686_EF_CF;
        }
        if ((((s1 ^ res) & (s2 ^ res)) >> msb & 1U) != 0U) {
            ctx->eflags |= I686_EF_OF;
        }
        if ((((s1 ^ s2 ^ res) >> 4) & 1U) != 0U) {
            ctx->eflags |= I686_EF_AF;
        }
        set_szp(ctx, res, w);
        break;
    case I686_FOP_SUB:
    case I686_FOP_SBB:
        wide = (uint64_t)s2 +
               (uint64_t)(ctx->lazy_op == I686_FOP_SBB ? (ctx->lazy_cf_in & 1U) : 0U);
        res = (uint32_t)(s1 - (uint32_t)wide) & m;
        ctx->eflags &= ~(I686_EF_ARITH_MASK | I686_EF_AF);
        if ((uint64_t)s1 < wide) {
            ctx->eflags |= I686_EF_CF;
        }
        if ((((s1 ^ s2) & (s1 ^ res)) >> msb & 1U) != 0U) {
            ctx->eflags |= I686_EF_OF;
        }
        if ((((s1 ^ s2 ^ res) >> 4) & 1U) != 0U) {
            ctx->eflags |= I686_EF_AF;
        }
        set_szp(ctx, res, w);
        break;
    case I686_FOP_LOGIC:
        ctx->eflags &= ~(I686_EF_ARITH_MASK | I686_EF_AF);
        set_szp(ctx, res & m, w);
        break;
    case I686_FOP_INC:
        ctx->eflags &= ~(I686_EF_ZF | I686_EF_SF | I686_EF_PF | I686_EF_OF | I686_EF_AF);
        if (res == sign) {
            ctx->eflags |= I686_EF_OF;
        }
        if ((((s1 ^ 1U ^ res) >> 4) & 1U) != 0U) {
            ctx->eflags |= I686_EF_AF;
        }
        set_szp(ctx, res, w);
        break;
    case I686_FOP_DEC:
        ctx->eflags &= ~(I686_EF_ZF | I686_EF_SF | I686_EF_PF | I686_EF_OF | I686_EF_AF);
        if (s1 == sign) {
            ctx->eflags |= I686_EF_OF;
        }
        if ((((s1 ^ 1U ^ res) >> 4) & 1U) != 0U) {
            ctx->eflags |= I686_EF_AF;
        }
        set_szp(ctx, res, w);
        break;
    case I686_FOP_NEG:
        ctx->eflags &= ~(I686_EF_ARITH_MASK | I686_EF_AF);
        if (s1 != 0U) {
            ctx->eflags |= I686_EF_CF;
        }
        if (s1 == sign) {
            ctx->eflags |= I686_EF_OF;
        }
        if (((s1 ^ res) >> 4 & 1U) != 0U) {
            ctx->eflags |= I686_EF_AF;
        }
        set_szp(ctx, res, w);
        break;
    default:
        break;
    }
    ctx->lazy_op = I686_FOP_NONE;
}

uint32_t i686_flags_read(i686_ctx_t *ctx)
{
    i686_flags_materialize(ctx);
    return ctx->eflags;
}

uint8_t i686_flags_cc(i686_ctx_t *ctx, uint8_t cond)
{
    uint32_t f = i686_flags_read(ctx);
    uint8_t r = 0;

    switch (cond & 0xfU) {
    case 0x0: r = (f & I686_EF_OF) != 0; break;                 /* O  */
    case 0x1: r = (f & I686_EF_OF) == 0; break;                 /* NO */
    case 0x2: r = (f & I686_EF_CF) != 0; break;                 /* B  */
    case 0x3: r = (f & I686_EF_CF) == 0; break;                 /* AE */
    case 0x4: r = (f & I686_EF_ZF) != 0; break;                 /* E  */
    case 0x5: r = (f & I686_EF_ZF) == 0; break;                 /* NE */
    case 0x6: r = (f & (I686_EF_CF | I686_EF_ZF)) != 0; break;  /* BE */
    case 0x7: r = (f & (I686_EF_CF | I686_EF_ZF)) == 0; break;  /* A  */
    case 0x8: r = (f & I686_EF_SF) != 0; break;                 /* S  */
    case 0x9: r = (f & I686_EF_SF) == 0; break;                 /* NS */
    case 0xa: r = (f & I686_EF_PF) != 0; break;                 /* P  */
    case 0xb: r = (f & I686_EF_PF) == 0; break;                 /* NP */
    case 0xc: r = ((f & (I686_EF_SF)) != 0) != ((f & I686_EF_OF) != 0); break; /* L  */
    case 0xd: r = ((f & (I686_EF_SF)) != 0) == ((f & I686_EF_OF) != 0); break; /* GE */
    case 0xe: { /* LE */
        uint8_t zf = (f & I686_EF_ZF) != 0;
        uint8_t lt = ((f & I686_EF_SF) != 0) != ((f & I686_EF_OF) != 0);
        r = zf || lt;
        break;
    }
    case 0xf: { /* G */
        uint8_t zf = (f & I686_EF_ZF) != 0;
        uint8_t lt = ((f & I686_EF_SF) != 0) != ((f & I686_EF_OF) != 0);
        r = !zf && !lt;
        break;
    }
    default: r = 0; break;
    }
    return r;
}

static void set_lazy(i686_ctx_t *ctx, uint32_t op, uint32_t res,
                     uint32_t s1, uint32_t s2, uint32_t cf, unsigned width)
{
    ctx->lazy_op = op;
    ctx->lazy_res = res;
    ctx->lazy_src1 = s1;
    ctx->lazy_src2 = s2;
    ctx->lazy_cf_in = cf;
    ctx->lazy_width = width;
}

void i686_flags_add(i686_ctx_t *ctx, uint32_t src1, uint32_t src2, unsigned width)
{
    uint32_t m = width_mask(width);
    set_lazy(ctx, I686_FOP_ADD, (src1 + src2) & m, src1 & m, src2 & m, 0, width);
}

void i686_flags_adc(i686_ctx_t *ctx, uint32_t src1, uint32_t src2,
                    uint32_t cf_in, unsigned width)
{
    uint32_t m = width_mask(width);
    uint32_t c = cf_in & 1U;
    set_lazy(ctx, I686_FOP_ADC, (src1 + src2 + c) & m, src1 & m, src2 & m, c, width);
}

void i686_flags_sub(i686_ctx_t *ctx, uint32_t src1, uint32_t src2, unsigned width)
{
    uint32_t m = width_mask(width);
    set_lazy(ctx, I686_FOP_SUB, (src1 - src2) & m, src1 & m, src2 & m, 0, width);
}

void i686_flags_sbb(i686_ctx_t *ctx, uint32_t src1, uint32_t src2,
                    uint32_t cf_in, unsigned width)
{
    uint32_t m = width_mask(width);
    uint32_t c = cf_in & 1U;
    set_lazy(ctx, I686_FOP_SBB, (src1 - src2 - c) & m, src1 & m, src2 & m, c, width);
}

void i686_flags_logic(i686_ctx_t *ctx, uint32_t res, unsigned width)
{
    set_lazy(ctx, I686_FOP_LOGIC, res & width_mask(width), 0, 0, 0, width);
}

void i686_flags_inc(i686_ctx_t *ctx, uint32_t src1, unsigned width)
{
    uint32_t m = width_mask(width);
    set_lazy(ctx, I686_FOP_INC, (src1 + 1U) & m, src1 & m, 1, 0, width);
}

void i686_flags_dec(i686_ctx_t *ctx, uint32_t src1, unsigned width)
{
    uint32_t m = width_mask(width);
    set_lazy(ctx, I686_FOP_DEC, (src1 - 1U) & m, src1 & m, 1, 0, width);
}

void i686_flags_neg(i686_ctx_t *ctx, uint32_t src1, unsigned width)
{
    set_lazy(ctx, I686_FOP_NEG, (0U - src1) & width_mask(width), src1, 0, 0, width);
}

void i686_flags_logiczx(i686_ctx_t *ctx, uint32_t res, unsigned width)
{
    uint32_t r = res & width_mask(width);
    ctx->lazy_op = I686_FOP_NONE;
    ctx->eflags &= ~(I686_EF_ARITH_MASK | I686_EF_AF);
    set_szp(ctx, r, width);
}
