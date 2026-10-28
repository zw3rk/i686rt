/*
 * src/dbt/emit_branch.c — DBT control-flow emitters (Phase 3 lane L3c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Scope (docs/lanes/phase-3.md, card L3c): JMP rel8/32 + JMP Ev, Jcc
 * (NZCV fusion), CALL rel32, RET/RET imm16, SETcc/CMOVcc reg forms,
 * INT_Ib/INT3/HLT/UD2/SYSENTER/WAIT/NOP.  The LOOP family, JCXZ, and
 * the BT family are declined in v1 (return -1 -> D2 interpret-one,
 * always safe).
 *
 * Coordination notes (documented deviations, see the lane report):
 *
 * 1. Inline exits.  i686_emit_exit()/i686_emit_ea() are lane-L3a-owned
 *    and still emit nothing in this lane's tree (coordinator v1 stubs),
 *    so this module emits its own exit sequence per the frozen protocol
 *    (emit.h + trampoline.S): w8=reason, w9=arg, w10=dest stored to
 *    ctx->exit_reason/exit_arg/exit_dest (#120/#124/#132), and the
 *    resume EIP is stored to ctx->eip (#32) — dest IS the resume EIP
 *    for every reason (BRANCH target, post-int/int3/hlt PC, or the
 *    fault PC for UNDEF), mirroring the interpreter handlers exactly.
 *    Runtime-target exits (JMP Ev, RET) load the target straight into
 *    w10 and bypass the (stubbed) i686_emit_exit dest store per the
 *    card.  The trampoline persists w0..w7 itself, so no GPR stores
 *    are needed here.
 *
 * 2. Condition map (Jcc/SETcc/CMOVcc).  The consumer builds an NZCV
 *    image from ctx->eflags in NATURAL SUBS polarity — C := !CF (the
 *    carry an A64 SUBS/ADDS leaves), so a future in-block producer can
 *    fuse directly — and the map is:
 *      x86 O->vs NO->vc B->lo(CC) AE->hs(CS) E->eq NE->ne BE->ls A->hi
 *          S->mi NS->pl L->lt GE->ge LE->le G->gt
 *    The card's table lists B->hs / AE->lo, which belongs to a C:=CF
 *    image; that image has NO A64 encoding for BE (CF||ZF) or A
 *    (!CF&&!ZF), so the unsigned four are mapped per the natural
 *    polarity instead (BE->ls / A->hi as the card states them).  This
 *    is documented for coordinator ratification at S3.  The parity
 *    conditions P/NP (10/11) are declined (PF is not in NZCV).
 *    C6a seam: which prelude the consumer emits switches on
 *    e->flags_src (emit.h): NZCV consumes the fused image as-is and
 *    bumps ctx->flags_elided; EFLAGS silently rebuilds NZCV from
 *    ctx->eflags without the park/sync helper; DEAD runs the full
 *    sequence.  All three leave the same NZCV image, so a following
 *    same-block consumer may stay fused.
 *
 * 3. Per-insn PC recovery.  The frozen emitter API passes no PC (the
 *    decoded x86_insn_t has no address field and emit.h carries only
 *    the block-start EIP), so this module re-walks x86_decode from
 *    e->guest_eip summing lengths until the decoded op id matches.
 *    Sound in v1 because every PC-consuming op handled here also ends
 *    the block (translate.c stops emitting after it), so the first
 *    matching op id in walk order is this instruction.
 *
 * Scratch registers inside the block (D7): guest state lives only in
 * w0..w7; x19=xCtx, x20=xG; this module uses w8..w11 and w21 as
 * caller-saved scratch.  Emitted memory accesses are plain
 * (single-threaded, D5); TSO LDAPR/STLR classes arrive with Phase 4.
 */

#include <stdint.h>
#include <string.h>

#include "dbt/emit.h"
#include "dbt/aot/aot.h"

#define L3C_NONE 0xFFU /* decoder sentinel for "no base/index/segment" */

/* In-block scratch (fixed): reason/arg/dest hand-off + temps + EA. */
#define L3C_W8   8U   /* exit reason */
#define L3C_W9   9U   /* exit arg */
#define L3C_W10  10U  /* exit dest / runtime branch target */
#define L3C_W11  11U  /* temp */
#define L3C_EA   21U  /* EA scratch (lane conventions) */

/* x86 condition nibble -> A64 cond (NZCV image in natural SUBS
 * polarity: C := !CF).  Returns -1 for the parity conditions
 * (declined, PF not in NZCV). */
static int l3c_cond_map(uint8_t cc)
{
    switch (cc & 0xFU) {
    case 0U: return (int)A64_COND_VS; /* O  */
    case 1U: return (int)A64_COND_VC; /* NO */
    case 2U: return (int)A64_COND_CC; /* B  (CF=1 == C clear) */
    case 3U: return (int)A64_COND_CS; /* AE */
    case 4U: return (int)A64_COND_EQ; /* E  */
    case 5U: return (int)A64_COND_NE; /* NE */
    case 6U: return (int)A64_COND_LS; /* BE */
    case 7U: return (int)A64_COND_HI; /* A  */
    case 8U: return (int)A64_COND_MI; /* S  */
    case 9U: return (int)A64_COND_PL; /* NS */
    case 10U:
    case 11U: return -1;              /* P/NP: parity not in NZCV */
    case 12U: return (int)A64_COND_LT; /* L  */
    case 13U: return (int)A64_COND_GE; /* GE */
    case 14U: return (int)A64_COND_LE; /* LE */
    default: return (int)A64_COND_GT;  /* G  */
    }
}

/* Sign-extend insn->imm per the fetched size (interpreter semantics). */
static uint32_t l3c_sext_rel(const x86_insn_t *insn)
{
    if (insn->imm_size == 1U) {
        return (uint32_t)(int32_t)(int8_t)(uint8_t)insn->imm;
    }
    if (insn->imm_size == 2U) {
        return (uint32_t)(int32_t)(int16_t)(uint16_t)insn->imm;
    }
    return insn->imm;
}

/* 16-bit operand-size control transfers truncate the target to IP. */
static uint32_t l3c_trunc_ip(uint32_t v, const x86_insn_t *insn)
{
    return insn->pfx_opsize != 0U ? (v & 0xFFFFU) : v;
}

/* Recover this insn's guest PC (see coordination note 3).  Returns 0
 * when the walk fails (caller declines; cannot happen for ops that
 * reach here through translate.c's block flow). */
static bool l3c_pc_of(i686_emit_ctx_t *e, const x86_insn_t *insn,
                      uint32_t *out_pc)
{
    uint32_t pc = e->guest_eip;
    unsigned guard = 0U;

    while (guard++ < 64U) { /* I686_DBT_MAX_INSNS bound */
        x86_insn_t walk;
        if (x86_decode(e->ctx, pc, &walk) != 0) {
            return false;
        }
        if (walk.op == insn->op) {
            *out_pc = pc;
            return true;
        }
        pc += walk.len;
    }
    return false;
}

/* ---- inline exit (coordination note 1) ---------------------------- */

static void l3c_exit_seq(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;

    a64_emit_str_imm_w(b, L3C_W8, A64_XCTX, 120U); /* exit_reason */
    a64_emit_str_imm_w(b, L3C_W9, A64_XCTX, 124U); /* exit_arg   */
    a64_emit_str_imm_w(b, L3C_W10, A64_XCTX, 132U); /* exit_dest  */
    a64_emit_str_imm_w(b, L3C_W10, A64_XCTX, 32U);  /* eip := resume */
    a64_emit_ret(b);
    e->block_open = false;
}

/* Exit with compile-time reason/arg/dest. */
static void l3c_exit_const(i686_emit_ctx_t *e, uint32_t reason, uint32_t arg,
                           uint32_t dest)
{
    a64_buf_t *b = &e->buf;

    a64_emit_mov_imm32(b, L3C_W8, reason);
    a64_emit_mov_imm32(b, L3C_W9, arg);
    a64_emit_mov_imm32(b, L3C_W10, dest);
    l3c_exit_seq(e);
}

/* Exit whose dest is a runtime value already sitting in w10. */
static void l3c_exit_dest_w10(i686_emit_ctx_t *e, uint32_t reason,
                              uint32_t arg)
{
    a64_buf_t *b = &e->buf;

    a64_emit_mov_imm32(b, L3C_W8, reason);
    a64_emit_mov_imm32(b, L3C_W9, arg);
    l3c_exit_seq(e);
}

/* ---- NZCV from ctx->eflags (coordination note 2) ------------------ */

/* The DEAD path (C6a seam): park the guest GPRs, blr the helper so any
 * pending interpreter descriptor materializes, reload, rebuild NZCV
 * from ctx->eflags.  Exactly today's full sequence. */
static void l3c_flags_to_nzcv(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;

    /* S3 seam fix: L3a ops leave a pending lazy descriptor; materialize
     * it into ctx->eflags before rebuilding NZCV from memory. Guest
     * GPRs park in ctx->gpr[0..7] across the AAPCS call. */
    {
        extern void i686_dbt_flags_sync(i686_ctx_t *);
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
        /* x0 = ctx (AAPCS arg0; MOV X0,X19 = AA1F0260). BLR x17 clobbers
         * x30 (lr): park the block's return address in callee-saved x28
         * (MOV X28,X30 = AA1F03DC) and restore after (MOV X30,X28 =
         * AA1F039E), or the exit `ret` returns to the post-call insn. */
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
    }

    /* Rebuild NZCV from ctx->eflags (shared C6a helper; identical word
     * stream to the former inline tail). */
    {
        extern void i686_dbt_emit_rebuild_nzcv(i686_emit_ctx_t *);
        i686_dbt_emit_rebuild_nzcv(e);
    }
}

/* Consumer prelude on the frozen flags_src seam (emit.h, C6a): choose
 * the architecturally-identical cheapest path for this consumer.
 *   NZCV   -> the fused image is already live: consume it as-is and
 *             count the elided park/sync/rebuild (ctx->flags_elided).
 *   EFLAGS -> ctx->eflags is current (eager producer ran, lazy_op
 *             NONE): silent rebuild, no park, no helper call.
 *   DEAD   -> no proof: today's full sequence.
 * Every path leaves NZCV holding the architectural image, so a
 * following consumer may stay fused (setcc/cmovcc do not disturb NZCV;
 * jcc ends the block either way). */
static void l3c_flags_consume(i686_emit_ctx_t *e)
{
    switch (e->flags_src) {
    case I686_FLAGS_NZCV: {
        extern void i686_dbt_emit_elide_bump(i686_emit_ctx_t *);
        i686_dbt_emit_elide_bump(e);
        break;
    }
    case I686_FLAGS_EFLAGS: {
        extern void i686_dbt_emit_rebuild_nzcv(i686_emit_ctx_t *);
        i686_dbt_emit_rebuild_nzcv(e);
        break;
    }
    default: /* I686_FLAGS_DEAD: conservative full sequence */
        l3c_flags_to_nzcv(e);
        break;
    }
    e->flags_src = I686_FLAGS_NZCV;
}

/* CSET w11, cond (local CSINC encoding; the frozen encoder has none). */
static void l3c_emit_cset_w11(i686_emit_ctx_t *e, unsigned cond)
{
    a64_emit(&e->buf,
             0x1A800400U | (((cond ^ 1U) & 15U) << 12) | (31U << 16) |
                 (31U << 5) | L3C_W11);
}

/* ---- guest EA into w21: the shared L3a fast helper (add_seg=1) --- */

static void l3c_ea_w21(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    i686_emit_ea(e, insn, 1);
}

/* ------------------------------------------------------------------ */

int i686_emit_branch(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    uint32_t pc;

    switch (insn->op) {
    case I686_OP_JMP_Jb:
    case I686_OP_JMP_Jz:
        if (insn->pfx_rep != 0U) {
            return -1;
        }
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        l3c_exit_const(e, I686_EXIT_BRANCH, 0U,
                       l3c_trunc_ip(pc + insn->len + l3c_sext_rel(insn),
                                    insn));
        return 0;

    case I686_OP_JMP_Ev: {
        if (insn->pfx_lock != 0U || insn->pfx_rep != 0U) {
            return -1;
        }
        if (insn->modrm_mod == 3U || !insn->ea_has) { /* register form */
            unsigned rm = i686_w(insn->modrm_rm);
            if (insn->pfx_opsize != 0U) {
                a64_emit_ubfm_w(b, L3C_W10, rm, 0U, 15U); /* zero-extend AX */
            } else {
                a64_emit_mov_w(b, L3C_W10, rm);
            }
        } else { /* memory form: ldr w10, [x20, w21 uxtw] */
            l3c_ea_w21(e, insn);
            if (insn->pfx_opsize != 0U) {
                a64_emit_guest_ldrh_w(b, L3C_W10, L3C_EA);
            } else {
                a64_emit_guest_ldr_w(b, L3C_W10, L3C_EA);
            }
        }
        l3c_exit_dest_w10(e, I686_EXIT_BRANCH, 0U);
        return 0;
    }

    case I686_OP_JCC_Jb:
    case I686_OP_JCC_Jz: {
        int a64c = l3c_cond_map(insn->modrm_reg);
        size_t patch;
        uint32_t next;

        if (a64c < 0 || insn->pfx_rep != 0U) {
            return -1;
        }
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        next = pc + (uint32_t)insn->len;
        l3c_flags_consume(e);
        /* b.cond taken -> exit to target; fallthrough -> exit to next */
        patch = a64_emit_b_cond_placeholder(b, (unsigned)a64c);
        l3c_exit_const(e, I686_EXIT_BRANCH, 0U, next);
        a64_patch_b_cond(b, patch, b->count);
        l3c_exit_const(e, I686_EXIT_BRANCH, 0U,
                       l3c_trunc_ip(next + l3c_sext_rel(insn), insn));
        return 0;
    }

    case I686_OP_CALL_Jz: {
        uint32_t next;
        uint16_t bytes = insn->pfx_opsize != 0U ? 2U : 4U;
        uint32_t target;
        dbt_mem_site_t site;
        uint32_t seq;
        uint32_t mem;

        if (insn->pfx_rep != 0U || insn->pfx_lock != 0U) {
            return -1;
        }
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        next = pc + (uint32_t)insn->len;
        target = l3c_trunc_ip(next + l3c_sext_rel(insn), insn);
        /* push return EIP: ESP wraps in 32 bits (w4 arithmetic) */
        seq = (uint32_t)((uint64_t)b->count * 4u);
        a64_emit_sub_imm_w(b, false, I686_REG_ESP, I686_REG_ESP, bytes, 0U);
        a64_emit_mov_imm32(b, L3C_W11, next);
        /* RC-U3-r2 P1 #2: host_insn_offset must identify the faulting
         * store (the STR below), recorded after the MOVZ/MOVK pair, so
         * the engine's exact-offset recovery matches CALL faults. */
        mem = (uint32_t)((uint64_t)b->count * 4u);
        if (bytes == 2U) {
            a64_emit_guest_strh_w(b, L3C_W11, I686_REG_ESP);
        } else {
            a64_emit_guest_str_w(b, L3C_W11, I686_REG_ESP);
        }
        /* RC-U3 stack site: ESP commits before the store can fault. */
        memset(&site, 0, sizeof(site));
        site.seq_start_offset = (uint16_t)seq;
        site.host_insn_offset = (uint16_t)mem;
        site.cont_insn_offset = (uint16_t)((uint64_t)b->count * 4u);
        site.guest_pc_delta =
            (pc >= e->guest_eip && pc - e->guest_eip <= 0xFFF0U)
                ? (uint16_t)(pc - e->guest_eip)
                : I686_SITE_PC_UNKNOWN;
        site.npc_delta = (int32_t)(target - e->guest_eip);
        site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                         ((uint32_t)insn->pfx_lock << 16);
        site.sp_rollback_delta = (int16_t)(-(int32_t)bytes);
        site.npc_mode = (uint8_t)I686_NPC_STATIC_TARGET;
        site.width = (uint8_t)bytes;
        site.flags =
            (uint8_t)(I686_SITE_STORE | I686_SITE_PRE_COMMITTED_SP);
        site.val_or_dst_reg = (uint8_t)L3C_W11;
        site.addr_base_reg = 4U; /* ESP */
        (void)i686_aot_note_stack_site(&site);
        l3c_exit_const(e, I686_EXIT_BRANCH, 0U, target);
        return 0;
    }

    case I686_OP_CALL_Ev: {
        uint32_t next;
        uint16_t bytes = insn->pfx_opsize != 0U ? 2U : 4U;
        dbt_mem_site_t site;
        uint32_t seq;
        uint32_t seq_ld;
        uint32_t mem;

        if (insn->pfx_rep != 0U || insn->pfx_lock != 0U) {
            return -1;
        }
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        next = pc + (uint32_t)insn->len;
        /* Load the call target into w10 FIRST, before ESP moves: with
         * [%esp + disp] addressing the EA uses the pre-call ESP, and a
         * fault on the target load leaves ESP unmodified. */
        if (insn->modrm_mod == 3U || !insn->ea_has) { /* register form */
            unsigned rm = i686_w(insn->modrm_rm);
            if (insn->pfx_opsize != 0U) {
                a64_emit_ubfm_w(b, L3C_W10, rm, 0U, 15U); /* zero-extend */
            } else {
                a64_emit_mov_w(b, L3C_W10, rm);
            }
        } else { /* memory form: ldr w10, [x20, w21 uxtw] */
            l3c_ea_w21(e, insn);
            seq_ld = (uint32_t)((uint64_t)b->count * 4u);
            if (insn->pfx_opsize != 0U) {
                a64_emit_guest_ldrh_w(b, L3C_W10, L3C_EA);
            } else {
                a64_emit_guest_ldr_w(b, L3C_W10, L3C_EA);
            }
            /* Load site: the fault leaves ESP intact (still pre-call),
             * so no rollback (sp_rollback_delta = 0, flags = 0); width
             * stays 0 so the replay walk accounts no ESP effect before
             * the push site below. */
            memset(&site, 0, sizeof(site));
            site.seq_start_offset = (uint16_t)seq_ld;
            site.host_insn_offset = (uint16_t)seq_ld;
            site.cont_insn_offset = (uint16_t)((uint64_t)b->count * 4u);
            site.guest_pc_delta =
                (pc >= e->guest_eip && pc - e->guest_eip <= 0xFFF0U)
                    ? (uint16_t)(pc - e->guest_eip)
                    : I686_SITE_PC_UNKNOWN;
            site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                             ((uint32_t)insn->pfx_lock << 16);
            site.sp_rollback_delta = 0;
            site.npc_mode = (uint8_t)I686_NPC_DYNAMIC_CTX;
            site.npc_delta = 0;
            site.width = 0U;
            site.flags = 0u; /* load, SP intact on fault */
            site.val_or_dst_reg = (uint8_t)L3C_W10;
            site.addr_base_reg = 21U; /* EA */
            (void)i686_aot_note_stack_site(&site);
        }
        /* push return EIP: ESP wraps in 32 bits (w4 arithmetic).
         * w10 stays live across the push: only w11 and ESP are used. */
        seq = (uint32_t)((uint64_t)b->count * 4u);
        a64_emit_sub_imm_w(b, false, I686_REG_ESP, I686_REG_ESP, bytes, 0U);
        a64_emit_mov_imm32(b, L3C_W11, next);
        /* RC-U3-r2 P1 #2: host_insn_offset must identify the faulting
         * store (the STR below), recorded after the MOVZ/MOVK pair, so
         * the engine's exact-offset recovery matches CALL faults. */
        mem = (uint32_t)((uint64_t)b->count * 4u);
        if (bytes == 2U) {
            a64_emit_guest_strh_w(b, L3C_W11, I686_REG_ESP);
        } else {
            a64_emit_guest_str_w(b, L3C_W11, I686_REG_ESP);
        }
        /* RC-U3 stack site: ESP commits before the store can fault.
         * The resume target is dynamic (w10 into the exit dest). */
        memset(&site, 0, sizeof(site));
        site.seq_start_offset = (uint16_t)seq;
        site.host_insn_offset = (uint16_t)mem;
        site.cont_insn_offset = (uint16_t)((uint64_t)b->count * 4u);
        site.guest_pc_delta =
            (pc >= e->guest_eip && pc - e->guest_eip <= 0xFFF0U)
                ? (uint16_t)(pc - e->guest_eip)
                : I686_SITE_PC_UNKNOWN;
        site.npc_delta = 0;
        site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                         ((uint32_t)insn->pfx_lock << 16);
        site.sp_rollback_delta = (int16_t)(-(int32_t)bytes);
        site.npc_mode = (uint8_t)I686_NPC_DYNAMIC_CTX;
        site.width = (uint8_t)bytes;
        site.flags =
            (uint8_t)(I686_SITE_STORE | I686_SITE_PRE_COMMITTED_SP);
        site.val_or_dst_reg = (uint8_t)L3C_W11;
        site.addr_base_reg = 4U; /* ESP */
        (void)i686_aot_note_stack_site(&site);
        l3c_exit_dest_w10(e, I686_EXIT_BRANCH, 0U);
        return 0;
    }

    case I686_OP_RET:
    case I686_OP_RET_Iw: {
        uint16_t bytes = insn->pfx_opsize != 0U ? 2U : 4U;
        dbt_mem_site_t site;
        uint32_t seq;

        if (insn->pfx_rep != 0U || insn->pfx_lock != 0U) {
            return -1;
        }
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        /* pop target into w10, then advance ESP (+ imm16, zero-extended).
         * The load faults before the ESP bump, so ESP needs no rollback
         * (sp_rollback_delta = 0), like POP in emit_mov.c. */
        seq = (uint32_t)((uint64_t)b->count * 4u);
        if (bytes == 2U) {
            a64_emit_guest_ldrh_w(b, L3C_W10, I686_REG_ESP);
        } else {
            a64_emit_guest_ldr_w(b, L3C_W10, I686_REG_ESP);
        }
        a64_emit_add_imm_w(b, false, I686_REG_ESP, I686_REG_ESP, bytes, 0U);
        if (insn->op == I686_OP_RET_Iw) {
            a64_emit_mov_imm32(b, L3C_W11, insn->imm);
            a64_emit_add_reg_w(b, false, I686_REG_ESP, I686_REG_ESP,
                               L3C_W11, A64_SHIFT_LSL, 0U);
        }
        /* RC-U3 stack site.  The resume target is dynamic (popped at
         * runtime into the exit dest), so npc carries DYNAMIC_CTX. */
        memset(&site, 0, sizeof(site));
        site.seq_start_offset = (uint16_t)seq;
        site.host_insn_offset = (uint16_t)seq;
        site.cont_insn_offset = (uint16_t)((uint64_t)b->count * 4u);
        site.guest_pc_delta =
            (pc >= e->guest_eip && pc - e->guest_eip <= 0xFFF0U)
                ? (uint16_t)(pc - e->guest_eip)
                : I686_SITE_PC_UNKNOWN;
        site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                         ((uint32_t)insn->pfx_lock << 16);
        site.sp_rollback_delta = 0;
        site.npc_mode = (uint8_t)I686_NPC_DYNAMIC_CTX;
        site.width = (uint8_t)bytes;
        site.flags = 0u; /* load, SP intact on fault */
        site.val_or_dst_reg = (uint8_t)L3C_W10;
        site.addr_base_reg = 4U; /* ESP */
        (void)i686_aot_note_stack_site(&site);
        l3c_exit_dest_w10(e, I686_EXIT_BRANCH, 0U);
        return 0;
    }

    case I686_OP_SETcc_Eb: {
        int a64c = l3c_cond_map(insn->modrm_reg);

        if (a64c < 0 || insn->modrm_mod != 3U || insn->pfx_lock != 0U ||
            insn->pfx_rep != 0U) {
            return -1; /* reg forms only in v1 */
        }
        l3c_flags_consume(e);
        l3c_emit_cset_w11(e, (unsigned)a64c);
        if (insn->modrm_rm < 4U) { /* low byte: bfi wReg, w11, #0, #8 */
            a64_emit_bfm_w(b, i686_w(insn->modrm_rm), L3C_W11, 0U, 7U);
        } else { /* AH..BH live in bits 15:8 of the same wN */
            a64_emit_bfm_w(b, i686_w(insn->modrm_rm - 4U), L3C_W11, 24U,
                           7U);
        }
        return 0;
    }

    case I686_OP_CMOVcc_Gv: {
        int a64c = l3c_cond_map((uint8_t)(insn->imm & 0xFU));
        unsigned rd = i686_w(insn->modrm_reg);
        unsigned rm = i686_w(insn->modrm_rm);

        if (a64c < 0 || insn->modrm_mod != 3U || insn->pfx_lock != 0U ||
            insn->pfx_rep != 0U) {
            return -1; /* reg forms only in v1 */
        }
        l3c_flags_consume(e);
        if (insn->pfx_opsize != 0U) {
            /* 16-bit: keep the destination's upper half */
            a64_emit_csel_w(b, L3C_W11, rm, rd, (unsigned)a64c);
            a64_emit_bfm_w(b, rd, L3C_W11, 0U, 15U);
        } else {
            a64_emit_csel_w(b, rd, rm, rd, (unsigned)a64c);
        }
        return 0;
    }

    case I686_OP_INT_Ib:
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        if ((insn->imm & 0xFFU) == 0x80U) {
            /* int 0x80: D12 syscall gate, resume past the insn */
            l3c_exit_const(e, I686_EXIT_SYSCALL, 0x80U,
                           pc + (uint32_t)insn->len);
        } else {
            /* Other vectors never execute (interpreter: fatal UNDEF,
             * EIP unchanged); exit UNDEF in the D2 shape so the
             * engine's interpret-one reproduces that exactly. */
            l3c_exit_const(e, I686_EXIT_UNDEF, insn->len, pc);
        }
        return 0;

    case I686_OP_INT3:
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        l3c_exit_const(e, I686_EXIT_TRAP, 3U, pc + (uint32_t)insn->len);
        return 0;

    case I686_OP_HLT:
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        l3c_exit_const(e, I686_EXIT_HLT, 0U, pc + (uint32_t)insn->len);
        return 0;

    case I686_OP_UD2:
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        /* EIP stays at the ud2 (interpreter h_ud2 leaves it). */
        l3c_exit_const(e, I686_EXIT_UNDEF, insn->len, pc);
        return 0;

    case I686_OP_SYSENTER:
        if (!l3c_pc_of(e, insn, &pc)) {
            return -1;
        }
        /* D12: sysenter == int 0x80. */
        l3c_exit_const(e, I686_EXIT_SYSCALL, 0x80U,
                       pc + (uint32_t)insn->len);
        return 0;

    case I686_OP_NOP:
    case I686_OP_WAIT:
        (void)insn;
        return 0; /* block continues; translate.c advances pc */

    case I686_OP_LOOPNZ_Jb:
    case I686_OP_LOOPZ_Jb:
    case I686_OP_LOOP_Jb:
    case I686_OP_JCXZ_Jb:
        return -1; /* declined v1 (card): D2 interpret-one */

    case I686_OP_BT_EvGv:
    case I686_OP_BTS_EvGv:
    case I686_OP_BTR_EvGv:
    case I686_OP_BTC_EvGv:
    case I686_OP_BT_EvIb:
    case I686_OP_BTS_EvIb:
    case I686_OP_BTR_EvIb:
    case I686_OP_BTC_EvIb:
        return -1; /* declined v1 (card): D2 interpret-one */

    default:
        return -1; /* not this module's op */
    }
}
