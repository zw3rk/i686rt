/*
 * src/dbt/emit_mov_ext.c — DBT r/m stack + moffs emitters (SPEC §3.3, D2/D4/D7)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Hot-path extension of emit_mov.c (kept in a separate TU so both files
 * stay under the 900-line rule): FF /6 PUSH r/m32 and the A0-A3 moffs
 * forms (MOV AL/AX/EAX <-> moffs, incl. %fs:/%gs: segment overrides).
 * Together these cover ~88% of all EXIT_UNDEF bounces seen profiling
 * cc1plus (function-argument pushes, global loads/stores, and the
 * stack-protector %gs:0x14 prologue/epilogue).
 *
 * Register map, fault-site protocol and TSO barriers follow emit_mov.c
 * exactly (D7: w0..w7 = guest GPRs, x19 = xCtx, x20 = xG; w8/w9 are the
 * per-insn scratch pair, w21 is the EA scratch owned by i686_emit_ea).
 *
 * PUSH_Ev ordering (matches h_push_ev in src/interp/h_mov.c): the r/m
 * source is read FIRST using the pre-decrement ESP, then ESP is
 * decremented and the value stored.  Two fault sites are recorded: the
 * source load (SP intact on fault) and the stack store (Wave U3 site
 * with sp_rollback_delta = -bytes, via the shared i686_emit_push_store
 * from emit_mov.c).  A faulting `pushl (%esp)` therefore retries with
 * the original ESP, exactly like the interpreter.
 *
 * moffs EA reuses the frozen i686_emit_ea(e, insn, 1): with no
 * base/index registers the materialized offset is ea_disp (already
 * narrowed to 16 bits under 0x67 by the decoder) plus the segment base
 * selected by the standard DS-default / pfx_seg-override rule — the
 * same address moffs_va computes in the interpreter, including the
 * GDT-TLS base for %fs:/%gs: (i686_emit_ea never folds FS/GS at emit
 * time, so late set_thread_area bases stay correct).
 *
 * Declined forms (return -1; translate.c ends the block with UNDEF and
 * the engine interprets one insn, D2 — declining is always safe):
 * LOCK-prefixed forms (illegal LOCK reaches here only defensively;
 * translate.c already rejects it via x86_lock_legal), POP_Ev (its
 * ESP-relative destination semantics stay interpreter-only).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dbt/aot/aot.h"
#include "dbt/emit.h"

/* Free scratch registers inside one emitted insn (D7: w8/w9 sit below the
 * guest map and above the trampoline-reserved set, matching the frozen
 * exit epilogue's own w8/w9/w10 use). */
#define SCR0 8U
#define SCR1 9U

/* 0xFF sentinel in the frozen x86_insn_t (ea_base/ea_index/pfx_seg none). */
#define NONE 0xFFU

/* v/z operand size in BYTES: 66 selects the 16-bit form. */
static unsigned v_bytes(const x86_insn_t *insn)
{
    return (insn->pfx_opsize != 0U) ? 2U : 4U;
}

/* Per-insn guest_pc_delta from e->insn_pc (set by translate.c). */
static uint16_t site_pc_delta(const i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    (void)insn;
    if (e->insn_pc < e->guest_eip || e->insn_pc - e->guest_eip > 0xFFF0U) {
        return I686_SITE_PC_UNKNOWN;
    }
    return (uint16_t)(e->insn_pc - e->guest_eip);
}

/* Record one guest-memory access site for fault recovery (mirrors
 * em_note_mem_site in emit_mov.c): SP is intact on fault
 * (sp_rollback_delta = 0); the stack store itself is recorded by the
 * shared i686_emit_push_store with the Wave U3 rollback record. */
static void em_note_mem_site(i686_emit_ctx_t *e, const x86_insn_t *insn,
                             uint32_t seq, uint32_t mem, uint32_t cont,
                             unsigned width, unsigned val_reg,
                             unsigned base_reg, unsigned is_store)
{
    dbt_mem_site_t site;

    if (e->tso) {
        a64_emit(&e->buf, is_store != 0U ? 0xD5033BBFU : 0xD50339BFU);
        cont = (uint32_t)((uint64_t)e->buf.count * 4u);
    }
    memset(&site, 0, sizeof(site));
    site.seq_start_offset = (uint16_t)seq;
    site.host_insn_offset = (uint16_t)mem;
    site.cont_insn_offset = (uint16_t)cont;
    site.guest_pc_delta = site_pc_delta(e, insn);
    site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                     ((uint32_t)insn->pfx_lock << 16);
    site.sp_rollback_delta = 0;
    site.npc_mode = (uint8_t)I686_NPC_SEQUENTIAL;
    site.width = (uint8_t)width;
    site.flags = is_store != 0U ? (uint8_t)I686_SITE_STORE : 0u;
    site.val_or_dst_reg = (uint8_t)val_reg;
    site.addr_base_reg = (uint8_t)base_reg;
    (void)i686_aot_note_stack_site(&site);
}

/* EA base for site records (0xFF when the address is disp-only). */
static unsigned em_site_base(const x86_insn_t *insn)
{
    return insn->ea_base != NONE ? (unsigned)(insn->ea_base & 7U) : 0xFFu;
}

/* Bitfield alias: BFI Wd, Wn, #lsb, #width (mirrors emit_mov.c). */
static void emit_bfi_w(a64_buf_t *b, unsigned rd, unsigned rn,
                       unsigned lsb, unsigned width)
{
    a64_emit_bfm_w(b, rd, rn, (32U - lsb) & 31U, width - 1U);
}

/* ------------------------------------------------------------------ */
/* FF /6: PUSH r/m(v)                                                  */
/* ------------------------------------------------------------------ */

/* Shared PUSH store from emit_mov.c: SUB ESP first, then the store, with
 * the Wave U3 rollback site (declared in emit.h). */
extern void i686_emit_push_store(i686_emit_ctx_t *e, const x86_insn_t *insn,
                                 unsigned wsrc, unsigned bytes);

/* FF /6: push the r/m operand (register or memory) at the operand
 * size.  The source read faults with ESP intact (its own site below);
 * the stack store rolls ESP back on fault (push_store's site). */
static int em_push_ev(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned width = v_bytes(insn);
    unsigned bytes = width;

    if (insn->modrm_mod == 3U || insn->ea_has == 0U) {
        /* Register source (incl. PUSH ESP = pre-decrement value: the
         * register is read before the decrement runs). */
        unsigned src = (unsigned)(insn->modrm_rm & 7U);

        if (width == 4U) {
            a64_emit_mov_w(b, SCR0, src);
        } else {
            /* 16-bit: zero-extend the low half (strh stores it). */
            a64_emit_ubfm_w(b, SCR0, src, 0U, 15U);
        }
    } else {
        /* Memory source: EA from the PRE-decrement ESP (compute before
         * the push_store's SUB), fault site with SP intact. */
        uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t mem;
        uint32_t cont;
        unsigned base = em_site_base(insn);

        i686_emit_ea(e, insn, 1);
        mem = (uint32_t)((uint64_t)b->count * 4u);
        if (width == 4U) {
            a64_emit_guest_ldr_w(b, SCR0, 21U);
        } else {
            a64_emit_guest_ldrh_w(b, SCR0, 21U);
        }
        cont = (uint32_t)((uint64_t)b->count * 4u);
        em_note_mem_site(e, insn, seq, mem, cont, width, SCR0, base, 0U);
    }
    i686_emit_push_store(e, insn, SCR0, bytes);
    return 0;
}

/* ------------------------------------------------------------------ */
/* moffs: A0-A3 (MOV AL/AX/EAX <-> moffs, segment-aware)               */
/* ------------------------------------------------------------------ */

/* Shared moffs load into SCR0 (zero-extended), with fault site. */
static void em_moffs_load(i686_emit_ctx_t *e, const x86_insn_t *insn,
                          unsigned width)
{
    a64_buf_t *b = &e->buf;
    uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
    uint32_t mem;
    uint32_t cont;

    /* Disp-only EA + DS-default/override segment base (matches the
     * interpreter's moffs_va, incl. FS/GS TLS bases). */
    i686_emit_ea(e, insn, 1);
    mem = (uint32_t)((uint64_t)b->count * 4u);
    if (width == 1U) {
        a64_emit_guest_ldrb_w(b, SCR0, 21U);
    } else if (width == 2U) {
        a64_emit_guest_ldrh_w(b, SCR0, 21U);
    } else {
        a64_emit_guest_ldr_w(b, SCR0, 21U);
    }
    cont = (uint32_t)((uint64_t)b->count * 4u);
    em_note_mem_site(e, insn, seq, mem, cont, width, SCR0, 0xFFu, 0U);
}

/* Shared moffs store of SCR0 (caller materializes the value in SCR0;
 * for the EAX forms the low part of w0 is stored directly). */
static void em_moffs_store(i686_emit_ctx_t *e, const x86_insn_t *insn,
                           unsigned wsrc, unsigned width)
{
    a64_buf_t *b = &e->buf;
    uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
    uint32_t mem;
    uint32_t cont;

    i686_emit_ea(e, insn, 1);
    mem = (uint32_t)((uint64_t)b->count * 4u);
    if (width == 1U) {
        a64_emit_guest_strb_w(b, wsrc, 21U);
    } else if (width == 2U) {
        a64_emit_guest_strh_w(b, wsrc, 21U);
    } else {
        a64_emit_guest_str_w(b, wsrc, 21U);
    }
    cont = (uint32_t)((uint64_t)b->count * 4u);
    em_note_mem_site(e, insn, seq, mem, cont, width, wsrc, 0xFFu, 1U);
}

/* A0: AL <- moffs8. */
static int em_mov_alob(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    em_moffs_load(e, insn, 1U);
    /* AL is bits 7:0 of w0 (D7). */
    emit_bfi_w(b, 0U, SCR0, 0U, 8U);
    return 0;
}

/* A1: eAX <- moffs(v). */
static int em_mov_eaxov(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned width = v_bytes(insn);

    if (width == 4U) {
        /* Load straight into w0 (EAX); the fault site still names the
         * scratch convention via em_moffs_store symmetry — record the
         * load here to name w0 as the destination. */
        uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t mem;
        uint32_t cont;

        i686_emit_ea(e, insn, 1);
        mem = (uint32_t)((uint64_t)b->count * 4u);
        a64_emit_guest_ldr_w(b, 0U, 21U);
        cont = (uint32_t)((uint64_t)b->count * 4u);
        em_note_mem_site(e, insn, seq, mem, cont, width, 0U, 0xFFu, 0U);
    } else {
        em_moffs_load(e, insn, 2U);
        /* 16-bit: preserve the upper half of EAX. */
        emit_bfi_w(b, 0U, SCR0, 0U, 16U);
    }
    return 0;
}

/* A2: moffs8 <- AL.  strb stores the low byte of w0 = AL. */
static int em_mov_obal(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    em_moffs_store(e, insn, 0U, 1U);
    return 0;
}

/* A3: moffs(v) <- eAX. */
static int em_mov_oveax(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    em_moffs_store(e, insn, 0U, v_bytes(insn));
    return 0;
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                            */
/* ------------------------------------------------------------------ */

int i686_emit_mov_ext(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    /* Defensive: LOCK on these forms is #UD (x86_lock_legal rejects it
     * in translate.c before any emitter runs). */
    if (insn->pfx_lock != 0U) {
        return -1;
    }
    switch (insn->op) {
    case I686_OP_PUSH_Ev:
        return em_push_ev(e, insn);
    case I686_OP_MOV_ALOb:
        return em_mov_alob(e, insn);
    case I686_OP_MOV_eAXOv:
        return em_mov_eaxov(e, insn);
    case I686_OP_MOV_ObAL:
        return em_mov_obal(e, insn);
    case I686_OP_MOV_OveAX:
        return em_mov_oveax(e, insn);
    default:
        return -1;
    }
}
