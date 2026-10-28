/*
 * tests/unit/ea_for_test.c — TEST-ONLY implementations of the frozen L3a
 * shared contracts (i686_emit_ea, i686_emit_exit) for the L3b lane check.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L3b's worktree does not carry src/dbt/emit_exit.c / emit_ea.c
 * (lane L3a owns them; they arrive at S3).  The coordinator stubs in
 * src/dbt/emit_stubs.c emit NOTHING for these, which is fine for the
 * shipped interpreter-only binary but makes translated blocks
 * unrunnable.  This file implements the FROZEN contracts from
 * docs/lanes/phase-3.md card L3a so test_l3b can execute real
 * translated code; it is linked BEFORE src/dbt/emit_stubs.o with
 * -Wl,--allow-multiple-definition, so these definitions override the
 * do-nothing stubs at link time (first definition wins).  This file is
 * never part of `make build` and merges away at S3.
 *
 * Frozen EA contract: compute base + (index << scale) + disp into w21
 * (32-bit wrapping guest EA; all adds in W registers wrap naturally),
 * and when add_seg != 0 add the segment base via
 * ldr w22, [x19, #40 + 4*seg] with the same default-segment rule as
 * src/x86/decode.c's x86_ea_compute (pfx_seg override, else SS for
 * BP/SP-based addressing at mod != 0, else DS).  Clobbers w21..w23.
 *
 * Frozen exit contract: store w0..w7 to [x19, #0..28] (stp pairs),
 * movz w8,#reason; str w8,[x19,#120]; w9=arg -> [x19,#124];
 * w10=dest -> [x19,#132]; for reason==BRANCH also store EIP (dest)
 * into [x19,#32]; ret.
 *
 * ESCALATION (bug in frozen src/trampoline.S): the guest GPR load
 * `ldp w0, w1, [x19, #0]` writes w1 — zeroing the upper half of x1 —
 * BEFORE `blr x1`, so the frozen trampoline jumps to guest ECX instead
 * of the translated block (observed: SIGSEGV at PC = initial ECX).
 * trampoline.S is outside lane ownership, so this test file also
 * defines a corrected i686_jit_run_block (identical body; the code
 * pointer is stashed in x23, the D7 chaining scratch, and the call is
 * `blr x23`).  With this object FIRST on the link line and
 * -Wl,--allow-multiple-definition, the corrected definition shadows
 * the frozen one for this test only; the shipped tree keeps the frozen
 * file untouched.  The coordinator needs the one-instruction fix in
 * src/trampoline.S before any DBT block can execute at S3.
 */

#include <stdint.h>

#include "dbt/emit.h"

/* TEST-ONLY corrected trampoline (see ESCALATION above). */
__asm__(
    ".text\n"
    ".align 4\n"
    ".globl i686_jit_run_block\n"
    ".type i686_jit_run_block, %function\n"
    "i686_jit_run_block:\n"
    "    stp     x29, x30, [sp, #-160]!\n"
    "    mov     x29, sp\n"
    "    stp     x19, x20, [sp, #16]\n"
    "    stp     x21, x22, [sp, #32]\n"
    "    stp     x23, x24, [sp, #48]\n"
    "    stp     x25, x26, [sp, #64]\n"
    "    stp     x27, x28, [sp, #80]\n"
    "    stp     d8,  d9,  [sp, #96]\n"
    "    stp     d10, d11, [sp, #112]\n"
    "    stp     d12, d13, [sp, #128]\n"
    "    stp     d14, d15, [sp, #144]\n"
    "    mov     x19, x0                 /* x19 = xCtx */\n"
    "    ldr     x20, [x19, #112]        /* x20 = xG  */\n"
    "    mov     x21, x2                 /* x21 = cur_entry */\n"
    "    mov     x22, x3                 /* x22 = &g_cache_epoch */\n"
    "    mov     x23, x1                 /* FIX: stash code_ptr */\n"
    "    ldp     w0,  w1,  [x19, #0]\n"
    "    ldp     w2,  w3,  [x19, #8]\n"
    "    ldp     w4,  w5,  [x19, #16]\n"
    "    ldp     w6,  w7,  [x19, #24]\n"
    "    blr     x23                     /* FIX: call the block */\n"
    "    stp     w0,  w1,  [x19, #0]\n"
    "    stp     w2,  w3,  [x19, #8]\n"
    "    stp     w4,  w5,  [x19, #16]\n"
    "    stp     w6,  w7,  [x19, #24]\n"
    "    ldp     d8,  d9,  [sp, #96]\n"
    "    ldp     d10, d11, [sp, #112]\n"
    "    ldp     d12, d13, [sp, #128]\n"
    "    ldp     d14, d15, [sp, #144]\n"
    "    ldp     x19, x20, [sp, #16]\n"
    "    ldp     x21, x22, [sp, #32]\n"
    "    ldp     x23, x24, [sp, #48]\n"
    "    ldp     x25, x26, [sp, #64]\n"
    "    ldp     x27, x28, [sp, #80]\n"
    "    ldp     x29, x30, [sp], #160\n"
    "    ret\n"
    ".size i686_jit_run_block, . - i686_jit_run_block\n"
);

#define NONE 0xFFU

/* Default segment for an EA (mirrors ea_default_seg in src/x86/decode.c). */
static uint8_t ea_def_seg(const x86_insn_t *insn)
{
    if (insn->pfx_addrsize != 0U) {
        if (insn->modrm_mod != 0U && insn->ea_base == I686_REG_EBP) {
            return I686_SEG_SS;
        }
        return I686_SEG_DS;
    }
    if (insn->modrm_mod != 0U && (insn->ea_base == I686_REG_EBP ||
                                  insn->ea_base == I686_REG_ESP)) {
        return I686_SEG_SS;
    }
    return I686_SEG_DS;
}

void i686_emit_ea(i686_emit_ctx_t *e, const x86_insn_t *insn, int add_seg)
{
    a64_buf_t *b = &e->buf;

    if (insn->ea_base != NONE) {
        /* Fast path (mirrors src/dbt/emit_exit.c): fold a small
         * displacement into a single ADD/SUB immediate off the base;
         * every 32-bit W-register write already zero-extends X21. */
        unsigned wb = i686_w(insn->ea_base);
        int32_t disp = (int32_t)insn->ea_disp;
        if (insn->ea_disp == 0U) {
            if (insn->ea_index != NONE) {
                a64_emit_add_reg_w(b, false, 21U, wb,
                                   i686_w(insn->ea_index), A64_SHIFT_LSL,
                                   insn->ea_scale & 3U);
            } else {
                a64_emit_mov_w(b, 21U, wb);
            }
        } else if (disp > 0 && disp <= 4095) {
            a64_emit_add_imm_w(b, false, 21U, wb, (uint16_t)disp, 0U);
            if (insn->ea_index != NONE) {
                a64_emit_add_reg_w(b, false, 21U, 21U,
                                   i686_w(insn->ea_index), A64_SHIFT_LSL,
                                   insn->ea_scale & 3U);
            }
        } else if (disp < 0 && -(int64_t)disp <= 4095) {
            a64_emit_sub_imm_w(b, false, 21U, wb, (uint16_t)(-disp), 0U);
            if (insn->ea_index != NONE) {
                a64_emit_add_reg_w(b, false, 21U, 21U,
                                   i686_w(insn->ea_index), A64_SHIFT_LSL,
                                   insn->ea_scale & 3U);
            }
        } else {
            a64_emit_mov_imm32(b, 21U, insn->ea_disp);
            a64_emit_add_reg_w(b, false, 21U, 21U, wb, A64_SHIFT_LSL, 0U);
            if (insn->ea_index != NONE) {
                a64_emit_add_reg_w(b, false, 21U, 21U,
                                   i686_w(insn->ea_index), A64_SHIFT_LSL,
                                   insn->ea_scale & 3U);
            }
        }
    } else {
        int started = 0;
        if (insn->ea_disp != 0U || insn->ea_index == NONE) {
            a64_emit_mov_imm32(b, 21U, insn->ea_disp);
            started = 1;
        }
        if (insn->ea_index != NONE) {
            if (insn->ea_scale != 0U) {
                a64_emit_ubfm_w(b, 22U, i686_w(insn->ea_index),
                                (32U - insn->ea_scale) & 31U,
                                31U - insn->ea_scale); /* w22 = index << scale */
                a64_emit_add_reg_w(b, false, 21U, 21U, 22U, A64_SHIFT_LSL,
                                   0U);
            } else if (started != 0) {
                a64_emit_add_reg_w(b, false, 21U, 21U,
                                   i686_w(insn->ea_index),
                                   A64_SHIFT_LSL, 0U);
            } else {
                a64_emit_mov_w(b, 21U, i686_w(insn->ea_index));
                started = 1;
            }
        }
        if (started == 0) {
            a64_emit_movz_w(b, 21U, 0U, 0U);
        }
    }
    if (add_seg != 0) {
        uint8_t seg = (insn->pfx_seg != NONE) ? insn->pfx_seg
                                              : ea_def_seg(insn);
        if (seg < I686_SEG_COUNT) {
            /* Flat non-FS/GS segments read as zero at emit time: skip
             * the base load and add entirely. */
            if (e->ctx == NULL || seg == I686_SEG_FS ||
                seg == I686_SEG_GS || e->ctx->seg_base[seg] != 0U) {
                a64_emit_ldr_imm_w(b, 22U, A64_XCTX,
                                   40U + 4U * (unsigned)seg);
                a64_emit_add_reg_w(b, false, 21U, 21U, 22U, A64_SHIFT_LSL,
                                   0U);
            }
        }
    }
}

/* STP Wt1, Wt2, [Xn, #off] (imm7 scaled by 4; off in 0..252 here). */
static void emit_stp_w(a64_buf_t *b, unsigned rt1, unsigned rt2,
                       unsigned rn, unsigned off)
{
    uint32_t imm7 = (off / 4U) & 0x7FU;

    a64_emit(b, 0x29000000U | (imm7 << 15) | ((rt2 & 31U) << 10) |
                    ((rn & 31U) << 5) | (rt1 & 31U));
}

void i686_emit_exit(i686_emit_ctx_t *e, uint32_t reason, uint32_t arg,
                    uint32_t dest)
{
    a64_buf_t *b = &e->buf;

    /* Store the guest GPRs (w0..w7) back to ctx->gpr[0..7]. */
    emit_stp_w(b, 0U, 1U, A64_XCTX, 0U);
    emit_stp_w(b, 2U, 3U, A64_XCTX, 8U);
    emit_stp_w(b, 4U, 5U, A64_XCTX, 16U);
    emit_stp_w(b, 6U, 7U, A64_XCTX, 24U);

    a64_emit_movz_w(b, 8U, (uint16_t)reason, 0U);
    a64_emit_str_imm_w(b, 8U, A64_XCTX, 120U); /* exit_reason */
    a64_emit_mov_imm32(b, 9U, arg);
    a64_emit_str_imm_w(b, 9U, A64_XCTX, 124U); /* exit_arg */
    a64_emit_mov_imm32(b, 10U, dest);
    a64_emit_str_imm_w(b, 10U, A64_XCTX, 132U); /* exit_dest */
    if (reason == I686_EXIT_BRANCH) {
        a64_emit_str_imm_w(b, 10U, A64_XCTX, 32U); /* ctx->eip = dest */
    }
    a64_emit_ret(b);
    e->block_open = false;
}
