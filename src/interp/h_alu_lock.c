/*
 * src/interp/h_alu_lock.c — LOCK/atomics helpers for the integer ALU
 *
 * Split from h_alu.c for the 900-line gate: HVA resolution, the C11
 * __atomic_* width wrappers, and the RC-U3-r2 unified LOCK
 * enter/leave.  mem_atomic_fetch_op stays in h_alu.c (it switches on
 * the file-local alu_kind_t).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>

#include "flags.h"
#include "interp.h"

extern uint32_t x86_ea_compute(i686_ctx_t *ctx, const x86_insn_t *insn);
extern uint8_t x86_ea_seg(const x86_insn_t *insn);
extern void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg, uint32_t linear,
                                unsigned bytes, unsigned write);
/* i686_guest_ptr arrives as a static inline via i686rt.h — no extern here. */
/* RC-U3 split lock + span validator (defined in src/dbt/aot/aot.c). */
extern void i686_split_lock_acquire(void);
extern void i686_split_lock_release(void);
extern bool i686_mem_is_unaligned(const void *p, unsigned width);
extern bool i686_span_mapped_writable(const i686_ctx_t *ctx, uint32_t ea,
                                      unsigned bytes);

void *alu_locked_hva(i686_ctx_t *ctx, const x86_insn_t *insn,
                     unsigned width)
{
    uint32_t ea = x86_ea_compute(ctx, insn);
    i686_seg_check_data(ctx, x86_ea_seg(insn), ea, width / 8U, 1u);
    return i686_guest_ptr(ctx, ea);
}

uint32_t mem_atomic_load_u(void *p, unsigned width)
{
    if (width == 8U) {
        return __atomic_load_n((const uint8_t *)p, __ATOMIC_SEQ_CST);
    }
    if (width == 16U) {
        return __atomic_load_n((const uint16_t *)p, __ATOMIC_SEQ_CST);
    }
    return __atomic_load_n((const uint32_t *)p, __ATOMIC_SEQ_CST);
}

uint32_t mem_atomic_exchange_u(void *p, unsigned width, uint32_t v)
{
    if (width == 8U) {
        return __atomic_exchange_n((uint8_t *)p, (uint8_t)v, __ATOMIC_SEQ_CST);
    }
    if (width == 16U) {
        return __atomic_exchange_n((uint16_t *)p, (uint16_t)v, __ATOMIC_SEQ_CST);
    }
    return __atomic_exchange_n((uint32_t *)p, v, __ATOMIC_SEQ_CST);
}

/* RC-U3-r2 unified LOCK entry: every LOCK RMW holds the split lock (0 =
 * aligned __atomic_*, 1 = unaligned valid plain bytes, 2 = invalid span
 * plain unlocked); faults with the lock held release it in the catches. */
unsigned alu_lock_enter(i686_ctx_t *ctx, const x86_insn_t *insn,
                        unsigned width)
{
    uint32_t ea = x86_ea_compute(ctx, insn);

    i686_seg_check_data(ctx, x86_ea_seg(insn), ea, width / 8U, 1u);
    if (!i686_mem_is_unaligned(i686_guest_ptr(ctx, ea), width)) {
        i686_split_lock_acquire(); /* unified: aligned no longer bypasses */
        return 0U;
    }
    if (i686_span_mapped_writable(ctx, ea, width / 8U)) {
        i686_split_lock_acquire();
        return 1U;
    }
    return 2U;
}

/* Release the split lock when alu_lock_enter held it (how == 0 or 1). */
void alu_lock_leave(unsigned how)
{
    if (how != 2U) {
        i686_split_lock_release();
    }
}
