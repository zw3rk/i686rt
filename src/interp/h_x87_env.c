/*
 * src/interp/h_x87_env.c -- x87 environment/state images (legacy
 * FNSTENV/FLDENV/FNSAVE/FRSTOR plus FXSAVE/FXRSTOR)
 *
 * Split from h_x87_math.c for the 900-line gate; the fixed-form
 * arithmetic stays there.  Registration lives in h_x87.c.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interp/h_x87_internal.h"
#include "interp/sse.h"

/* ------------------------------------------------------------------ */
/* FPU environment (28-byte protected mode) and FXSAVE m512            */
/* ------------------------------------------------------------------ */

/* R7-29: legacy environment layouts.  op16 selects the 14-byte
 * 16-bit image (FCW@0, FSW@2, full FTW@4, FIP@6, FCS@8, opcode@10,
 * FDP@12); otherwise the 28-byte 32-bit image (FCW@0, FSW@4, full
 * FTW@8, FIP@12, FCS@16, opcode@18, FDP@20, FDS@24). */
static void env_save(i686_ctx_t *ctx, uint32_t va, unsigned op16)
{
    if (op16 != 0U) {
        for (unsigned i = 0; i < 14; i++) {
            mem_wr(ctx, va + i, 1, 0);
        }
        mem_wr(ctx, va + 0, 2, ctx->fctrl);
        mem_wr(ctx, va + 2, 2, ctx->fstat);
        mem_wr(ctx, va + 4, 2, ctx->ftag);
        mem_wr(ctx, va + 6, 2, (uint32_t)ctx->fpu_ip & 0xFFFFu);
        mem_wr(ctx, va + 8, 2, ctx->seg_sel[I686_SEG_CS]);
        mem_wr(ctx, va + 10, 2, ctx->fop);
        mem_wr(ctx, va + 12, 2, (uint32_t)ctx->fpu_dp & 0xFFFFu);
        return;
    }
    for (unsigned i = 0; i < 28; i++) {
        mem_wr(ctx, va + i, 1, 0);
    }
    mem_wr(ctx, va + 0, 2, ctx->fctrl);
    mem_wr(ctx, va + 4, 2, ctx->fstat);
    mem_wr(ctx, va + 8, 2, ctx->ftag);
    mem_wr(ctx, va + 12, 4, ctx->fpu_ip);
    mem_wr(ctx, va + 16, 2, ctx->seg_sel[I686_SEG_CS]);
    mem_wr(ctx, va + 18, 2, ctx->fop);
    mem_wr(ctx, va + 20, 4, ctx->fpu_dp);
    mem_wr(ctx, va + 24, 2, ctx->seg_sel[I686_SEG_DS]);
}

static void env_load(i686_ctx_t *ctx, uint32_t va, unsigned op16)
{
    if (op16 != 0U) {
        ctx->fctrl = (uint16_t)mem_rd(ctx, va + 0, 2);
        ctx->fstat = (uint16_t)mem_rd(ctx, va + 2, 2);
        ctx->ftag = (uint16_t)mem_rd(ctx, va + 4, 2);
        ctx->x87_top = (ctx->fstat >> 11) & 7U;
        ctx->fpu_ip = (uint32_t)mem_rd(ctx, va + 6, 2);
        ctx->fop = (uint16_t)mem_rd(ctx, va + 10, 2);
        ctx->fpu_dp = (uint32_t)mem_rd(ctx, va + 12, 2);
        return;
    }
    ctx->fctrl = (uint16_t)mem_rd(ctx, va + 0, 2);
    ctx->fstat = (uint16_t)mem_rd(ctx, va + 4, 2);
    ctx->ftag = (uint16_t)mem_rd(ctx, va + 8, 2);
    ctx->x87_top = (ctx->fstat >> 11) & 7U;
    ctx->fpu_ip = (uint32_t)mem_rd(ctx, va + 12, 4);
    ctx->fop = (uint16_t)mem_rd(ctx, va + 18, 2);
    ctx->fpu_dp = (uint32_t)mem_rd(ctx, va + 20, 4);
}

void i686_x87_op_fnstenv(i686_ctx_t *ctx, uint32_t va, unsigned op16)
{
    env_save(ctx, va, op16);
    /* FNSTENV masks all floating-point exceptions after saving. */
    ctx->fctrl |= 0x3fU;
}

void i686_x87_op_fldenv(i686_ctx_t *ctx, uint32_t va, unsigned op16)
{
    env_load(ctx, va, op16);
}

void i686_x87_op_fxsave(i686_ctx_t *ctx, uint32_t va)
{
    uint8_t *img = (uint8_t *)i686_guest_ptr(ctx, va);
    uint16_t atw = 0;

    memset(img, 0, 512);
    img_wr16(img, 0, ctx->fctrl);
    img_wr16(img, 2, ctx->fstat);
    for (unsigned p = 0; p < 8; p++) {
        /* R7-28: FTW polarity is 1 = non-empty (physical order);
         * the old code wrote 1 for empty. */
        if (((ctx->ftag >> (p * 2U)) & 3U) != 3U) {
            atw |= (uint16_t)(1U << p);
        }
    }
    img[4] = (uint8_t)atw; /* abridged tag: 1 = non-empty */
    img_wr16(img, 6, ctx->fop);
    img_wr32(img, 8, ctx->fpu_ip);
    img_wr16(img, 12, ctx->seg_sel[I686_SEG_CS]);
    img_wr32(img, 16, ctx->fpu_dp);
    img_wr16(img, 20, ctx->seg_sel[I686_SEG_DS]);
    img_wr32(img, 24, ctx->mxcsr);
    img_wr32(img, 28, ctx->mxcsr_mask);
    for (unsigned i = 0; i < 8; i++) {
        uint8_t b[10];

        x87_get_ext80(ctx, i, b); /* stack-relative ST(i) */
        memcpy(&img[32 + 16 * i], b, 10);
        memcpy(&img[160 + 16 * i], ctx->xmm[i], 16);
    }
}

void i686_x87_op_fxrstor(i686_ctx_t *ctx, uint32_t va)
{
    const uint8_t *img = (const uint8_t *)i686_guest_ptr(ctx, va);

    ctx->fctrl = img_rd16(img, 0);
    ctx->fstat = img_rd16(img, 2);
    ctx->x87_top = (ctx->fstat >> 11) & 7U;
    ctx->fop = img_rd16(img, 6);
    ctx->fpu_ip = img_rd32(img, 8);
    ctx->fpu_dp = img_rd32(img, 16);
    /* R7-37: MXCSR restores through the canonical setter, so DAZ
     * (bit 6) takes effect exactly as for LDMXCSR (applied to
     * subnormal sources via sse_daz); reserved high bits were
     * rejected with #GP(0) by the handler before any commit. */
    sse_set_mxcsr(ctx, img_rd32(img, 24));
    ctx->ftag = 0;
    for (unsigned i = 0; i < 8; i++) {
        /* Raw contents restore first (the setter classifies
         * every slot from its value). */
        x87_set_ext80(ctx, i, &img[32 + 16 * i]);
        memcpy(ctx->xmm[i], &img[160 + 16 * i], 16);
    }
    /* R7-28: FTW polarity is 1 = non-empty; empty slots are forced
     * AFTER the value restore so classification cannot resurrect
     * them (an empty save/restore round-trips to empty). */
    for (unsigned p = 0; p < 8; p++) {
        if ((img[4] & (1U << p)) == 0U) {
            ctx->ftag |= (uint16_t)(3U << (p * 2U)); /* empty */
        }
    }
}

/* R7-29: legacy state images reuse the environment header above
 * (status at 4, full tag at 8) with registers in physical order
 * after it (94 bytes for op16, 108 otherwise). */
void i686_x87_op_fnsave(i686_ctx_t *ctx, uint32_t va, unsigned op16)
{
    uint32_t rbase = (op16 != 0U) ? 14U : 28U;

    env_save(ctx, va, op16);
    for (unsigned p = 0; p < 8; p++) {
        uint8_t b[10];

        x87_get_ext80(ctx, (p - ctx->x87_top) & 7U, b); /* ST(i)=Rp */
        memcpy((uint8_t *)i686_guest_ptr(ctx, va) + rbase + 10 * p,
               b, 10);
    }
    /* FNSAVE reinitializes (FINIT semantics). */
    ctx->fctrl = 0x037fU;
    ctx->fstat = 0;
    ctx->ftag = 0xffffU;
    ctx->x87_top = 0;
    ctx->fop = 0;
    ctx->fpu_ip = 0;
    ctx->fpu_dp = 0;
}

void i686_x87_op_frstor(i686_ctx_t *ctx, uint32_t va, unsigned op16)
{
    const uint8_t *img = (const uint8_t *)i686_guest_ptr(ctx, va);
    uint32_t rbase = (op16 != 0U) ? 14U : 28U;
    uint16_t tag = img_rd16(img, (op16 != 0U) ? 4U : 8U);

    env_load(ctx, va, op16);
    for (unsigned p = 0; p < 8; p++) {
        uint8_t b[10];

        memcpy(b, &img[rbase + 10 * p], 10);
        x87_set_ext80(ctx, (p - ctx->x87_top) & 7U, b);
    }
    /* The full tag restores verbatim after the value loop so the
     * setters' classification cannot resurrect empty slots. */
    ctx->ftag = tag;
}
