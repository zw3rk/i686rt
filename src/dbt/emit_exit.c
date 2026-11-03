/*
 * src/dbt/emit_exit.c — shared DBT lifecycle, epilogue, and guest EA
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L3a (docs/lanes/phase-3.md): every block opens with
 * i686_emit_begin, ends through exactly one i686_emit_exit, and is sealed
 * by i686_emit_finish.  The epilogue stores the live guest GPRs w0..w7
 * back to ctx->gpr[0..7] (ABI-locked offsets, src/i686rt.h), writes the
 * exit triplet {reason, arg, dest}, mirrors dest into ctx->eip for
 * BRANCH so the engine loop can chain without re-deriving it, and
 * returns to the trampoline.
 *
 * i686_emit_ea materializes a decoded ModRM effective address into w21
 * as a 32-bit guest offset: disp + base + (index << scale), wrapped with
 * UXTW *before* the optional segment-base add, which wraps again (D4/D7:
 * effective addresses wrap in 32-bit W registers; never sign-extend).
 * The result feeds [x20, w21, uxtw] addressing (rt32_a64_emit guest
 * accessors), which applies the same wrap against xG.  The segment is
 * chosen exactly like decode.c's x86_ea_compute: a segment-override
 * prefix wins, else SS for BP-based EAs, else DS.  Clobbers w21..w22.
 */

#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

#include "dbt/emit.h"

_Atomic uint32_t g_i686_tso_enabled = 0U;

/* STP Wt1, Wt2, [Xn, #imm7*4] — 32-bit pair, unsigned offset form. */
static void emit_stp_w(a64_buf_t *b, unsigned rt1, unsigned rt2, unsigned rn_x,
                       unsigned imm7)
{
    a64_emit(b, 0x29000000U | ((imm7 & 0x7FU) << 15) | ((rt2 & 31U) << 10) |
                     ((rn_x & 31U) << 5) | (rt1 & 31U));
}

void i686_emit_begin(i686_emit_ctx_t *e, i686_ctx_t *ctx, uint8_t *code,
                     size_t cap, uint32_t guest_eip)
{
    memset(e, 0, sizeof(*e));
    a64_buf_init(&e->buf, (uint32_t *)(void *)code, cap / 4U);
    e->buf.guest_start_pc = guest_eip;
    e->ctx = ctx;
    e->guest_eip = guest_eip;
    e->insn_pc = guest_eip;
    e->tso = (atomic_load_explicit(&g_i686_tso_enabled,
                                   memory_order_relaxed) != 0U);
    e->block_open = true;
}

uint8_t *i686_emit_finish(i686_emit_ctx_t *e, size_t *out_len)
{
    uint8_t *base = (uint8_t *)(void *)e->buf.words;

    e->block_open = false;
    if (e->buf.overflow) {
        /* Buffer exhausted mid-block: the word stream is incomplete, so
         * hand the caller "nothing emittable" (header contract: the
         * engine falls back to the interpreter for this block). */
        *out_len = 0U;
        return NULL;
    }
    *out_len = e->buf.count * 4U;
    if (*out_len != 0U) {
        __builtin___clear_cache((char *)base, (char *)base + *out_len);
    }
    return base;
}

void i686_emit_exit(i686_emit_ctx_t *e, uint32_t reason, uint32_t arg,
                    uint32_t dest)
{
    a64_buf_t *b = &e->buf;

    /* w0..w7 -> ctx->gpr[0..7] (offsets 0..28, ABI-locked). */
    emit_stp_w(b, 0U, 1U, 19U, 0U);
    emit_stp_w(b, 2U, 3U, 19U, 2U);
    emit_stp_w(b, 4U, 5U, 19U, 4U);
    emit_stp_w(b, 6U, 7U, 19U, 6U);

    a64_emit_movz_w(b, 8U, (uint16_t)reason, 0U);
    a64_emit_str_imm_w(b, 8U, 19U, 120U);  /* ctx->exit_reason */
    a64_emit_mov_imm32(b, 9U, arg);        /* full 32-bit: may be a guest EIP */
    a64_emit_str_imm_w(b, 9U, 19U, 124U);  /* ctx->exit_arg  */
    a64_emit_mov_imm32(b, 10U, dest);
    a64_emit_str_imm_w(b, 10U, 19U, 132U); /* ctx->exit_dest */
    if (reason == I686_EXIT_BRANCH) {
        /* Also EIP = dest so the engine loop can chain directly. */
        a64_emit_str_imm_w(b, 10U, 19U, 32U);
    }
    a64_emit_ret(b);
    e->block_open = false;
}

/* Segment index for a data EA — mirrors decode.c's ea_default_seg plus
 * the override rule (pfx_seg wins; SS for BP/ESP-based EAs, else DS).
 * R7-4: the base register decides, not mod (SIB [ESP] and 16-bit
 * [BP+SI]/[BP+DI] with mod 00 are SS-based). */
static unsigned ea_seg_index(const x86_insn_t *insn)
{
    if (insn->pfx_seg != 0xFFU) {
        return insn->pfx_seg;
    }
    if (insn->pfx_addrsize != 0U) {
        return (insn->ea_base == I686_REG_EBP) ? I686_SEG_SS : I686_SEG_DS;
    }
    return (insn->ea_base == I686_REG_EBP || insn->ea_base == I686_REG_ESP)
               ? I686_SEG_SS
               : I686_SEG_DS;
}

void i686_emit_ea(i686_emit_ctx_t *e, const x86_insn_t *insn, int add_seg)
{
    a64_buf_t *b = &e->buf;

    if (insn->ea_base != 0xFFU) {
        /* Fast path: fold a small displacement into a single ADD/SUB
         * immediate off the base (every 32-bit W-register write already
         * zero-extends X21, so no UXTW is needed anywhere here). */
        unsigned wb = insn->ea_base & 7U;
        int32_t disp = (int32_t)insn->ea_disp;
        if (insn->ea_disp == 0U) {
            if (insn->ea_index != 0xFFU) {
                a64_emit_add_reg_w(b, false, 21U, wb, insn->ea_index & 7U,
                                   A64_SHIFT_LSL, insn->ea_scale & 3U);
            } else {
                a64_emit_mov_w(b, 21U, wb);
            }
        } else if (disp > 0 && disp <= 4095) {
            a64_emit_add_imm_w(b, false, 21U, wb, (uint16_t)disp, 0U);
            if (insn->ea_index != 0xFFU) {
                a64_emit_add_reg_w(b, false, 21U, 21U, insn->ea_index & 7U,
                                   A64_SHIFT_LSL, insn->ea_scale & 3U);
            }
        } else if (disp < 0 && -(int64_t)disp <= 4095) {
            a64_emit_sub_imm_w(b, false, 21U, wb, (uint16_t)(-disp), 0U);
            if (insn->ea_index != 0xFFU) {
                a64_emit_add_reg_w(b, false, 21U, 21U, insn->ea_index & 7U,
                                   A64_SHIFT_LSL, insn->ea_scale & 3U);
            }
        } else {
            a64_emit_mov_imm32(b, 21U, insn->ea_disp);
            a64_emit_add_reg_w(b, false, 21U, 21U, wb, A64_SHIFT_LSL, 0U);
            if (insn->ea_index != 0xFFU) {
                /* ea_scale is the shift amount itself (0..3 => x1/x2/x4/x8,
                 * decode.h); the shifted-ADD amount is a shift. */
                a64_emit_add_reg_w(b, false, 21U, 21U, insn->ea_index & 7U,
                                   A64_SHIFT_LSL, insn->ea_scale & 3U);
            }
        }
    } else {
        int started = 0;
        unsigned s;
        if (insn->ea_disp != 0U || insn->ea_index == 0xFFU) {
            a64_emit_mov_imm32(b, 21U, insn->ea_disp);
            started = 1;
        }
        if (insn->ea_index != 0xFFU) {
            unsigned wi = insn->ea_index & 7U;
            s = insn->ea_scale & 3U;
            if (started != 0) {
                a64_emit_add_reg_w(b, false, 21U, 21U, wi, A64_SHIFT_LSL, s);
            } else if (s != 0U) {
                a64_emit_ubfm_w(b, 21U, wi, (32U - s) & 31U,
                                31U - s); /* lsl #s */
                started = 1;
            } else {
                a64_emit_mov_w(b, 21U, wi);
                started = 1;
            }
        }
        if (started == 0) {
            a64_emit_movz_w(b, 21U, 0U, 0U);
        }
    }

    /* R7-5: 16-bit effective addresses wrap mod 64K before the segment
     * base is added (67 prefix; DBT otherwise uses full 32-bit regs). */
    if (insn->pfx_addrsize != 0U) {
        a64_emit_ubfm_w(b, 21U, 21U, 0U, 15U);
    }

    if (add_seg != 0) {
        unsigned seg = ea_seg_index(insn);
        if (seg < I686_SEG_COUNT) {
            /* Flat non-FS/GS segments read as zero at emit time: skip
             * the base load and add entirely. */
            if (e->ctx == NULL || seg == I686_SEG_FS ||
                seg == I686_SEG_GS || e->ctx->seg_base[seg] != 0U) {
                a64_emit_ldr_imm_w(b, 22U, 19U, 40U + 4U * seg);
                a64_emit_add_reg_w(b, false, 21U, 21U, 22U, A64_SHIFT_LSL,
                                   0U);
            }
        }
    }
}
