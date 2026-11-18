/*
 * src/dbt/emit_bit.c — DBT bit-scan emitters (SPEC §3.3, D2/D6)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * BSF/BSR Gv,Ev (0F BC/BD): the destination is always a register; the
 * source is a register or faultable guest memory.  Both are full EFLAGS
 * writers lowered eagerly (no lazy descriptor), matching the
 * interpreter's bs_common in src/interp/h_bit.c exactly:
 *   src == 0 : ZF = 1, destination left UNCHANGED, every other flag kept.
 *   src != 0 : dst = bit index (BSF: least-significant set bit via
 *              RBIT+CLZ; BSR: most-significant via CLZ, index = 31-clz);
 *              SF/PF from the index (SF is always 0: the index never
 *              reaches the width MSB), CF/OF cleared, AF untouched,
 *              ZF forced 0 (index 0 must not read back as ZF=1).
 *
 * Flags-pending prologue: when e->flags_src is not I686_FLAGS_EFLAGS a
 * lazy descriptor may still be pending from an earlier in-block fused
 * producer (the zero path must OR ZF into the *current* flags, and the
 * nonzero path preserves AF from them).  The prelude below parks the
 * GPRs and runs the i686_dbt_flags_sync helper when ctx->lazy_op is
 * set — the same park/sync/reload shape as l3c_flags_to_nzcv in
 * emit_branch.c, minus the NZCV rebuild (these emitters publish eflags
 * directly).  After the prelude ctx->eflags is current and lazy_op is
 * NONE, so both paths converge on flags_src = I686_FLAGS_EFLAGS.
 * A faulting memory source retries with flags intact (all flag stores
 * run after the load, R7-15 ordering).
 *
 * Register map (D7): w0..w7 guest GPRs, x19 = xCtx, x20 = xG; this
 * module uses w8 (source), w9 (index), w10 (eflags copy), w11 (temp)
 * and w21 (EA scratch).  The helper BLR clobbers v16..v23, so the
 * prelude clears e->xmm_valid like the branch consumer does.
 *
 * Declined forms (return -1; D2 interpret-one, always safe):
 * LOCK (never legal on BSF/BSR), REP prefixes (F3 0F BC/BD is TZCNT/
 * LZCNT on BMI1 hardware; the interpreter runs them as BSF/BSR, so
 * declining keeps the oracle bit-identical).
 */

#include <stdint.h>
#include <string.h>

#include "dbt/aot/aot.h"
#include "dbt/emit.h"

/* In-block scratch (fixed). */
#define BS_SRC 8U  /* source value (width-masked, zero-extended) */
#define BS_IDX 9U  /* bit index */
#define BS_FL  10U /* eflags working copy */
#define BS_T   11U /* temp */
#define BS_EA  21U /* EA scratch (lane conventions) */

/* 0xFF sentinel in the frozen x86_insn_t (ea_base none). */
#define NONE 0xFFU

/* AND Wd, Wn, #0xFF (N=0, immr=0, imms=7) — the only AND-imm needed here. */
static void emit_and_ff_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x12000000U | (7U << 10) | ((rn & 31U) << 5) | (rd & 31U));
}

/* EOR Wd, Wn, #1. */
static void emit_eor_1_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x52000000U | ((rn & 31U) << 5) | (rd & 31U));
}

/* BFI Wd, Wn, #lsb, #width. */
static void emit_bfi_w(a64_buf_t *b, unsigned rd, unsigned rn,
                       unsigned lsb, unsigned width)
{
    a64_emit_bfm_w(b, rd, rn, (32U - lsb) & 31U, width - 1U);
}

/* Park the guest GPRs, materialize any pending lazy descriptor via the
 * flags-sync helper, and reload.  Post-condition: ctx->eflags is
 * current, ctx->lazy_op is NONE.  Clobbers w8/x17/x28 and the XMM
 * cache (caller clears xmm_valid). */
static void em_flags_sync(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;
    extern void i686_dbt_flags_sync(i686_ctx_t *);
    size_t to_done;

    a64_emit_ldr_imm_w(b, BS_SRC, A64_XCTX, 76U); /* lazy_op */
    to_done = a64_emit_cbz_w_placeholder(b, false, BS_SRC);
    a64_emit_str_imm_w(b, 0U, A64_XCTX, 0U);
    a64_emit_str_imm_w(b, 1U, A64_XCTX, 4U);
    a64_emit_str_imm_w(b, 2U, A64_XCTX, 8U);
    a64_emit_str_imm_w(b, 3U, A64_XCTX, 12U);
    a64_emit_str_imm_w(b, 4U, A64_XCTX, 16U);
    a64_emit_str_imm_w(b, 5U, A64_XCTX, 20U);
    a64_emit_str_imm_w(b, 6U, A64_XCTX, 24U);
    a64_emit_str_imm_w(b, 7U, A64_XCTX, 28U);
    /* Full 64-bit helper address into x17: raw X-form MOVZ/MOVK
     * (W-forms zero the upper half — fatal under static-PIE). */
    {
        uintptr_t fn = (uintptr_t)&i686_dbt_flags_sync;
        unsigned i;

        for (i = 0U; i < 4U; i++) {
            uint32_t hw = (uint32_t)((fn >> (16U * i)) & 0xFFFFU);
            uint32_t insn;

            if (i == 0U) {
                insn = 0xD2800000U; /* MOVZ Xd */
            } else if (hw != 0U) {
                insn = 0xF2800000U; /* MOVK Xd */
            } else {
                continue;
            }
            a64_emit(b, insn | (i << 21) | (hw << 5) | 17U);
        }
    }
    /* x0 = ctx (AAPCS arg0); park the block return address in
     * callee-saved x28 across the BLR and restore it after. */
    a64_emit(b, 0xAA1F0260U); /* x0 = x19 */
    a64_emit(b, 0xAA1F03DCU); /* x28 = x30 */
    a64_emit(b, 0xD63F0220U); /* blr x17 */
    a64_emit(b, 0xAA1F039EU); /* x30 = x28 */
    a64_emit_ldr_imm_w(b, 0U, A64_XCTX, 0U);
    a64_emit_ldr_imm_w(b, 1U, A64_XCTX, 4U);
    a64_emit_ldr_imm_w(b, 2U, A64_XCTX, 8U);
    a64_emit_ldr_imm_w(b, 3U, A64_XCTX, 12U);
    a64_emit_ldr_imm_w(b, 4U, A64_XCTX, 16U);
    a64_emit_ldr_imm_w(b, 5U, A64_XCTX, 20U);
    a64_emit_ldr_imm_w(b, 6U, A64_XCTX, 24U);
    a64_emit_ldr_imm_w(b, 7U, A64_XCTX, 28U);
    a64_patch_cbz_w(b, to_done, b->count);
}

/* Per-insn guest_pc_delta from e->insn_pc (set by translate.c). */
static uint16_t site_pc_delta(const i686_emit_ctx_t *e)
{
    if (e->insn_pc < e->guest_eip || e->insn_pc - e->guest_eip > 0xFFF0U) {
        return I686_SITE_PC_UNKNOWN;
    }
    return (uint16_t)(e->insn_pc - e->guest_eip);
}

/* BSF/BSR core.  reverse = 0 for BSF (RBIT+CLZ), 1 for BSR (CLZ). */
static int em_bs(i686_emit_ctx_t *e, const x86_insn_t *insn, int reverse)
{
    a64_buf_t *b = &e->buf;
    unsigned width = (insn->pfx_opsize != 0U) ? 16U : 32U;
    unsigned dst = (unsigned)(insn->modrm_reg & 7U);
    size_t to_zero;
    size_t to_done;

    /* Eager EFLAGS proof: materialize any pending lazy descriptor so
     * both paths below read current flags. */
    if (e->flags_src != I686_FLAGS_EFLAGS) {
        em_flags_sync(e);
        e->xmm_valid = 0u;
    }

    /* Load the source (width-masked, zero-extended). */
    if (insn->modrm_mod == 3U || insn->ea_has == 0U) {
        unsigned src = (unsigned)(insn->modrm_rm & 7U);

        if (width == 32U) {
            a64_emit_mov_w(b, BS_SRC, src);
        } else {
            a64_emit_ubfm_w(b, BS_SRC, src, 0U, 15U);
        }
    } else {
        uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t mem;
        uint32_t cont;
        dbt_mem_site_t site;

        i686_emit_ea(e, insn, 1);
        mem = (uint32_t)((uint64_t)b->count * 4u);
        if (width == 32U) {
            a64_emit_guest_ldr_w(b, BS_SRC, BS_EA);
        } else {
            a64_emit_guest_ldrh_w(b, BS_SRC, BS_EA); /* zero-extends */
        }
        if (e->tso) {
            a64_emit(b, 0xD50339BFU); /* dmb ishld */
            cont = (uint32_t)((uint64_t)b->count * 4u);
        } else {
            cont = (uint32_t)((uint64_t)b->count * 4u);
        }
        memset(&site, 0, sizeof(site));
        site.seq_start_offset = (uint16_t)seq;
        site.host_insn_offset = (uint16_t)mem;
        site.cont_insn_offset = (uint16_t)cont;
        site.guest_pc_delta = site_pc_delta(e);
        site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                         ((uint32_t)insn->pfx_lock << 16);
        site.sp_rollback_delta = 0;
        site.npc_mode = (uint8_t)I686_NPC_SEQUENTIAL;
        site.width = (uint8_t)(width / 8U);
        site.flags = 0u; /* load, SP intact on fault */
        site.val_or_dst_reg = (uint8_t)BS_SRC;
        site.addr_base_reg = (uint8_t)(insn->ea_base != NONE
                                           ? (insn->ea_base & 7U)
                                           : 0xFFu);
        (void)i686_aot_note_stack_site(&site);
    }

    /* src == 0 keeps the destination and sets ZF only. */
    to_zero = a64_emit_cbz_w_placeholder(b, false, BS_SRC);

    /* Nonzero path: index + full eager flag publish. */
    if (reverse == 0) {
        a64_emit_rbit_w(b, BS_IDX, BS_SRC);
        a64_emit_clz_w(b, BS_IDX, BS_IDX);
    } else {
        a64_emit_clz_w(b, BS_IDX, BS_SRC);
        a64_emit_movz_w(b, BS_T, 31U, 0U);
        a64_emit_sub_reg_w(b, false, BS_IDX, BS_T, BS_IDX,
                           A64_SHIFT_LSL, 0U);
    }
    if (width == 32U) {
        a64_emit_mov_w(b, dst, BS_IDX);
    } else {
        emit_bfi_w(b, dst, BS_IDX, 0U, 16U); /* upper half preserved */
    }

    /* logiczx(index, width) then ZF = 0: clear CF/PF/AF/ZF/SF/OF
     * (0x08D5), set PF from the index parity (SF is 0: the index never
     * reaches the width MSB; ZF stays 0). */
    a64_emit_ldr_imm_w(b, BS_FL, A64_XCTX, 36U); /* ctx->eflags */
    a64_emit_movz_w(b, BS_T, 0x08D5U, 0U);       /* CF|PF|AF|ZF|SF|OF */
    a64_emit_bic_reg_w(b, false, BS_FL, BS_FL, BS_T, A64_SHIFT_LSL, 0U);
    emit_and_ff_w(b, BS_T, BS_IDX); /* PF: even parity of index[7:0] */
    a64_emit_eor_reg_w(b, BS_T, BS_T, BS_T, A64_SHIFT_LSR, 4U);
    a64_emit_eor_reg_w(b, BS_T, BS_T, BS_T, A64_SHIFT_LSR, 2U);
    a64_emit_eor_reg_w(b, BS_T, BS_T, BS_T, A64_SHIFT_LSR, 1U);
    a64_emit_ubfm_w(b, BS_T, BS_T, 0U, 0U); /* odd parity bit */
    emit_eor_1_w(b, BS_T, BS_T);            /* -> even parity */
    emit_bfi_w(b, BS_FL, BS_T, 2U, 1U);
    a64_emit_str_imm_w(b, BS_FL, A64_XCTX, 36U);

    to_done = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, to_zero, b->count);

    /* Zero path: ZF = 1, destination and every other flag untouched. */
    a64_emit_ldr_imm_w(b, BS_FL, A64_XCTX, 36U);
    a64_emit_movz_w(b, BS_T, 0x40U, 0U); /* ZF */
    a64_emit_orr_reg_w(b, BS_FL, BS_FL, BS_T, A64_SHIFT_LSL, 0U);
    a64_emit_str_imm_w(b, BS_FL, A64_XCTX, 36U);

    a64_patch_b_cond(b, to_done, b->count);

    /* Eager-eflags producer: ctx->eflags current, lazy NONE. */
    a64_emit_str_imm_w(b, 31U, A64_XCTX, 76U); /* lazy_op = NONE */
    e->flags_src = I686_FLAGS_EFLAGS;
    e->insn_count++;
    return 0;
}

int i686_emit_bit(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    /* Defensive: LOCK is #UD on bit scans (translate.c rejects it via
     * x86_lock_legal); REP forms stay interpreter-only (TZCNT/LZCNT
     * aliasing, matching the oracle's BSF/BSR reading). */
    if (insn->pfx_lock != 0U || insn->pfx_rep != 0U) {
        return -1;
    }
    switch (insn->op) {
    case I686_OP_BSF_GvEv:
        return em_bs(e, insn, 0);
    case I686_OP_BSR_GvEv:
        return em_bs(e, insn, 1);
    default:
        return -1;
    }
}
