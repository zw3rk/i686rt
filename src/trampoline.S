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
 * exit_dest@132, guest_base@112, ibtc_hits@464, ibtc@2536 (C6b; engine.c
 * _Static_asserts pin what this loop assumes). Trampoline scratch:
 * x24 = dispatch-loop block budget (Lane P3, Wave P: reloaded to 4096
 * on every engine entry; the chaining path decrements it per linked
 * block and falls out of the loop at zero so async signals cannot
 * starve behind an unbounded IBTC chain). x25 accumulates the chained
 * ctx->ibtc_hits delta (bumped per link, flushed once at .Lexit).
 * Emitted code never touches x24/x25 (A64 temps are x15-x17/x21-x23),
 * and the prologue/epilogue preserve them for the C caller.
 */

    .text
    .align 4
    .globl i686_jit_run_block
    .globl _i686_jit_run_block
#ifndef __APPLE__
    .type i686_jit_run_block, %function
#endif
i686_jit_run_block:
_i686_jit_run_block:
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
    ldr     x20, [x19, #112]        /* x20 = xG (guest_base on both A1 and A2) */
    mov     x21, x2                 /* x21 = cur_entry (unused: IBTC links) */
    mov     x26, x3                 /* x26 = &g_dbt_cache_epoch */
    add     x27, x19, #2536         /* x27 = &ctx->ibtc[0] */
    mov     x23, x1                 /* x23 = code_ptr (stash: the GPR load
                                       below writes w1, clobbering x1) */

    /* EFLAGS: DBT v1 keeps flags in NZCV only within a block; restore the
     * architectural EFLAGS copy is unnecessary — blocks materialize on
     * entry to flag-consuming code. Load guest GPRs. */
    ldp     w0,  w1,  [x19, #0]
    ldp     w2,  w3,  [x19, #8]
    ldp     w4,  w5,  [x19, #16]
    ldp     w6,  w7,  [x19, #24]

    movz    x24, #0x1000            /* block budget: 4096 chained blocks
                                       per engine entry (Lane P3) */
    mov     x25, xzr                 /* chain-hit delta: flushed once at
                                       .Lexit instead of per link */
    cbz     x26, .Lcall_block
    ldr     w14, [x26]
    str     w14, [x19, #484]        /* cache initial epoch in pad_lock2 */
.Lcall_block:
    blr     x23                     /* call emitted code (lr = .Lstore_gprs) */

    /* C6b dispatch loop: link a BRANCH exit straight to the next block
     * through the per-ctx IBTC (direct-mapped slot at 0x9e8 + (dest & 1023)*32)
     * without the C engine loop. */
.Lstore_gprs:
    cmp     w8,  #1                 /* I686_EXIT_BRANCH: only plain
                                       branches chain; syscall, UNDEF,
                                       fault, trap, hlt return to C */
    b.ne    .Lexit
    and     w11, w10, #0x3ff        /* idx = exit_dest & 1023 */
    add     x11, x27, x11, lsl #5   /* &ctx->ibtc[idx] (32-byte stride) */
    ldp     w12, w13, [x11, #0]     /* w12 = slot->key, w13 = slot->epoch */
    cmp     w12, w10                /* key == exit_dest? */
    b.ne    .Lexit
    cbz     x26, 2f
    ldr     w14, [x26]              /* *epoch_ptr (g_dbt_cache_epoch) */
    cmp     w14, w13
    b.ne    .Lexit
2:
    ldr     x23, [x11, #8]          /* slot->host_code (key@0, epoch@4,
                                       host_code@8) */
    cbz     x23, .Lexit             /* cleared slot -> C epilogue */
    add     x25, x25, #1            /* one chained link: flush at .Lexit */
    subs    x24, x24, #1            /* block budget: check pending_signals
                                       every 4096 blocks */
    b.gt    .Lcall_block
    ldr     x14, [x19, #424]        /* ctx->pending_signals */
    cbnz    x14, .Lexit
    movz    x24, #0x1000
    b       .Lcall_block

.Lexit:
    stp     w8,  w9,  [x19, #120]   /* ctx->exit_reason, ctx->exit_arg */
    str     w10, [x19, #132]        /* ctx->exit_dest */
    str     w10, [x19, #32]         /* ctx->eip := resume */
    cbz     x25, 1f                 /* flush the accumulated ibtc_hits */
    ldr     x12, [x19, #464]
    add     x12, x12, x25
    str     x12, [x19, #464]
1:
    stp     w0,  w1,  [x19, #0]     /* spill live GPRs on exit to C */
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

#ifndef __APPLE__
    .size i686_jit_run_block, . - i686_jit_run_block
#endif
