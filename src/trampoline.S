/*
 * src/trampoline.S — host <-> guest context switch for the i686rt DBT
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
 *                             void *cur_entry, const void *epoch_ptr);
 *
 * Register contract with emitted code (D7, frozen in src/dbt/emit.h):
 *   x19 = xCtx, x20 = xG, w0..w7 = EAX..EDI, NZCV = guest arith flags
 *   when the block ends in A64NZCV lazy state. Emitted code returns with
 *   `ret` after storing exits into ctx. ABI-locked offsets per
 * src/i686rt.h: gpr@0, eip@32, eflags@36, exit_reason@120, exit_arg@124,
 * exit_dest@132, guest_base@112.
 */

    .text
    .align 4
    .globl i686_jit_run_block
    .type i686_jit_run_block, %function
i686_jit_run_block:
    stp     x29, x30, [sp, #-160]!
    mov     x29, sp
    stp     x19, x20, [sp, #16]
    stp     x21, x22, [sp, #32]
    stp     x23, x24, [sp, #48]
    stp     x25, x26, [sp, #64]
    stp     x27, x28, [sp, #80]
    stp     d8,  d9,  [sp, #96]
    stp     d10, d11, [sp, #112]
    stp     d12, d13, [sp, #128]
    stp     d14, d15, [sp, #144]

    mov     x19, x0                 /* x19 = xCtx */
    ldr     x20, [x19, #112]        /* x20 = xG (guest_base) */
    mov     x21, x2                 /* x21 = cur_entry */
    mov     x22, x3                 /* x22 = &g_cache_epoch */
    mov     x23, x1                 /* x23 = code_ptr (stash: the GPR load
                                       below writes w1, clobbering x1) */

    /* EFLAGS: DBT v1 keeps flags in NZCV only within a block; restore the
     * architectural EFLAGS copy is unnecessary — blocks materialize on
     * entry to flag-consuming code. Load guest GPRs. */
    ldp     w0,  w1,  [x19, #0]
    ldp     w2,  w3,  [x19, #8]
    ldp     w4,  w5,  [x19, #16]
    ldp     w6,  w7,  [x19, #24]

    /* v1 dispatch loop: single block per call; chaining/IBTC/RAS slots
     * (Phase 3.1 follow-up) integrate here. */
    blr     x23                     /* call emitted code (stashed ptr) */

    /* Store GPRs back (w0..w7 -> gpr[0..7]); exit state was written to
     * ctx by the emitted epilogue. */
    stp     w0,  w1,  [x19, #0]
    stp     w2,  w3,  [x19, #8]
    stp     w4,  w5,  [x19, #16]
    stp     w6,  w7,  [x19, #24]

    ldp     d8,  d9,  [sp, #96]
    ldp     d10, d11, [sp, #112]
    ldp     d12, d13, [sp, #128]
    ldp     d14, d15, [sp, #144]
    ldp     x19, x20, [sp, #16]
    ldp     x21, x22, [sp, #32]
    ldp     x23, x24, [sp, #48]
    ldp     x25, x26, [sp, #64]
    ldp     x27, x28, [sp, #80]
    ldp     x29, x30, [sp], #160
    ret

    .size i686_jit_run_block, . - i686_jit_run_block
