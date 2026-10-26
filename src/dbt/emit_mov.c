/*
 * src/dbt/emit_mov.c — DBT data-movement emitters (lane L3b, Phase 3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * MOV reg/mem all widths, MOV immediates, MOVZX/MOVSX, XCHG (reg forms),
 * PUSH/POP (reg + immediate), BSWAP and LEA, per docs/lanes/phase-3.md
 * card L3b.  Register map per D7 (frozen src/dbt/emit.h): w0..w7 =
 * EAX..EDI, x19 = xCtx, x20 = xG; w8/w9 are free scratch within one
 * insn (the exit epilogue owns them after the last insn); w21..w23
 * belong to i686_emit_ea (lane L3a, frozen signature).
 *
 * Byte registers: x86 reg 0..3 = AL..BL (bits 7:0 of wN), 4..7 = AH..BH
 * (bits 15:8 of the SAME wN, D7).  16-bit writes preserve the upper
 * half (BFI); 32-bit writes replace.  Memory operands compute the EA
 * through the frozen extern i686_emit_ea and then access [x20, w21,
 * uxtw] — the uxtw re-zero-extension implements the D4 guest-EA wrap.
 * Stack ops are flat-SS v1: ESP arithmetic wraps in w4 and accesses go
 * to [x20, w4, uxtw] (seg_base[SS] is 0 in the v1 flat contract; Phase
 * 7 lifts that with the LDT work).
 *
 * Wave U3 (lane u3-i686, UNIFICATION-PLAN 4.3.3): every PUSH/POP records
 * a 24-byte relative dbt_mem_site_t (dbt/aot/aot.h) with sp_rollback_delta
 * so the shared fault landing pad (i686_emit_fault_landing below) can undo
 * the pre-store ESP decrement before the guest signal is raised
 * (No-Double-Side-Effect rule). CALL/RET sites use the same record shape
 * and landing pad; their emitters live in emit_branch.c (owning lane fills
 * npc_delta / NPC_STATIC_TARGET there).
 *
 * Declined forms (return -1; translate.c ends the block with UNDEF and
 * the engine interprets one insn, D2 — declining is always safe):
 * PUSHA/POPA/ENTER/LEAVE in v1, XCHG with a memory operand, segment
 * moves (MOV_EwSw/SwEw, PUSH/POP sreg), the moffs forms A0-A3, and
 * PUSH_Ev/POP_Ev (r/m stack forms).
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dbt/aot/aot.h"
#include "dbt/emit.h"

/* ctx->dbt_fault_nzcv must be reachable via MOVZ (off>>3) + ADD LSL#3,
 * the same far-tail shape as the flags_elided bump (flags_dbt.c). */
_Static_assert((offsetof(i686_ctx_t, dbt_fault_nzcv) & 7U) == 0U,
               "dbt_fault_nzcv must be 8-aligned for the LSL #3 form");
_Static_assert((offsetof(i686_ctx_t, dbt_fault_nzcv) >> 3) <= 0xFFFFU,
               "dbt_fault_nzcv offset must fit the MOVZ imm16");
_Static_assert(offsetof(i686_ctx_t, dbt_fault_w21) ==
                   offsetof(i686_ctx_t, dbt_fault_nzcv) + 4U,
               "dbt_fault_w21 must follow dbt_fault_nzcv");

/* STP Wt1, Wt2, [Xn, #imm7*4] (same shape as the exit epilogue). */
static void emit_stp_w(a64_buf_t *b, unsigned rt1, unsigned rt2,
                       unsigned rn_x, unsigned imm7)
{
    a64_emit(b, 0x29000000U | ((imm7 & 0x7FU) << 15) | ((rt2 & 31U) << 10) |
                     ((rn_x & 31U) << 5) | (rt1 & 31U));
}

/* Shared fault landing pad: flush the cached guest GPRs w0..w7, the
 * faulting EA scratch w21, and live NZCV into ctx before the C slow path
 * (vm_tlb_miss_helper / interp_step) inspects state. Clobbers w8/w11/x12,
 * which are scratch under D7; w0..w7 are restored from ctx on resume.
 * x18 is never touched. */
void i686_emit_fault_landing(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;
    size_t fault_off = offsetof(i686_ctx_t, dbt_fault_nzcv);

    emit_stp_w(b, 0U, 1U, 19U, 0U); /* w0..w7 -> ctx->gpr[0..7] */
    emit_stp_w(b, 2U, 3U, 19U, 2U);
    emit_stp_w(b, 4U, 5U, 19U, 4U);
    emit_stp_w(b, 6U, 7U, 19U, 6U);
    a64_emit_mrs_nzcv(b, 8U); /* X8 = NZCV */
    /* X12 = &ctx->dbt_fault_nzcv. */
    a64_emit_movz_w(b, 11U, (uint16_t)(fault_off >> 3), 0U);
    a64_emit(b, 0x8B0B0E6CU); /* ADD X12, X19, X11, LSL #3 */
    a64_emit_str_imm_w(b, 8U, 12U, 0U);  /* ctx->dbt_fault_nzcv = NZCV */
    a64_emit_str_imm_w(b, 21U, 12U, 4U); /* ctx->dbt_fault_w21 = w21 */
}

/* Free scratch registers inside one emitted insn (D7: x21+ is scratch;
 * w8/w9 sit below the guest map and above the trampoline-reserved set,
 * matching the frozen exit epilogue's own w8/w9/w10 use). */
#define SCR0 8U
#define SCR1 9U

/* 0xFF sentinel in the frozen x86_insn_t (ea_base/ea_index/pfx_seg none). */
#define NONE 0xFFU

/* v/z operand size in BYTES: 66 selects the 16-bit form. */
static unsigned v_bytes(const x86_insn_t *insn)
{
    return (insn->pfx_opsize != 0U) ? 2U : 4U;
}

/* x86 8-bit register number -> host wN holding it (AH..BH alias EAX..EBX). */
static unsigned b8_base(unsigned r)
{
    return (r < 4U) ? r : (r - 4U);
}

/* LSB of the byte inside that wN: AL..BL at 0, AH..BH at 8. */
static unsigned b8_lsb(unsigned r)
{
    return (r < 4U) ? 0U : 8U;
}

/*
 * Bitfield encodings (ARMv8-A aliases, 32-bit W):
 *   BFI  Wd, Wn, #lsb, #width == BFM  Wd, Wn, #(-lsb mod 32), #(width-1)
 *   UBFX Wd, Wn, #lsb, #width == UBFM Wd, Wn, #lsb, #(lsb+width-1)
 *   SBFX                        == SBFM #lsb, #(lsb+width-1)
 *   UXTB/UXTH                   == UBFM #0, #7 / #0, #15
 *   SXTB/SXTH                   == SBFM #0, #7 / #0, #15
 *   LSL  Wd, Wn, #s (s != 0)    == UBFM Wd, Wn, #(-s mod 32), #(31-s)
 * (mirrors a64_emit_bfi_x in src/rt32/rt32_a64_emit.c).
 */
static void emit_bfi_w(a64_buf_t *b, unsigned rd, unsigned rn,
                       unsigned lsb, unsigned width)
{
    a64_emit_bfm_w(b, rd, rn, (32U - lsb) & 31U, width - 1U);
}

static void emit_ubfx_w(a64_buf_t *b, unsigned rd, unsigned rn,
                        unsigned lsb, unsigned width)
{
    a64_emit_ubfm_w(b, rd, rn, lsb, lsb + width - 1U);
}

static void emit_sbfx_w(a64_buf_t *b, unsigned rd, unsigned rn,
                        unsigned lsb, unsigned width)
{
    a64_emit_sbfm_w(b, rd, rn, lsb, lsb + width - 1U);
}

static void emit_uxth_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit_ubfm_w(b, rd, rn, 0U, 15U);
}

static void emit_lsl_imm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned s)
{
    if (s == 0U) {
        a64_emit_mov_w(b, rd, rn);
    } else {
        a64_emit_ubfm_w(b, rd, rn, (32U - s) & 31U, 31U - s);
    }
}

/* Read an x86 byte register (high-byte aware) into wtmp, zero-extended. */
static void emit_read_b8(a64_buf_t *b, unsigned wtmp, unsigned x86_r)
{
    emit_ubfx_w(b, wtmp, i686_w(b8_base(x86_r)), b8_lsb(x86_r), 8U);
}

/* Write the low byte of wsrc into an x86 byte register (high-byte aware,
 * other bits of the wN preserved). */
static void emit_write_b8(a64_buf_t *b, unsigned x86_r, unsigned wsrc)
{
    emit_bfi_w(b, i686_w(b8_base(x86_r)), wsrc, b8_lsb(x86_r), 8U);
}

/* 16-bit register write of wsrc's low half (upper half preserved). */
static void emit_write_w16(a64_buf_t *b, unsigned wdst, unsigned wsrc)
{
    emit_bfi_w(b, wdst, wsrc, 0U, 16U);
}

/* r/m operand is a memory access (mirrors x86_rm_read/write). */
static int rm_is_mem(const x86_insn_t *insn)
{
    return insn->modrm_mod != 3U && insn->ea_has != 0U;
}

/* Guest EA into w21 via the frozen L3a helper (adds the segment base,
 * matching x86_ea_compute; clobbers w21..w23). */
static void emit_ea(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    i686_emit_ea(e, insn, 1);
}

/* ------------------------------------------------------------------ */
/* MOV reg/mem and immediate forms                                     */
/* ------------------------------------------------------------------ */

/* 88 /r: r/m8 <- r8. */
static int em_mov_ebgb(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (rm_is_mem(insn)) {
        emit_ea(e, insn);
        if (insn->modrm_reg < 4U) {
            a64_emit_guest_strb_w(b, i686_w(insn->modrm_reg), 21U);
        } else {
            emit_read_b8(b, SCR0, insn->modrm_reg);
            a64_emit_guest_strb_w(b, SCR0, 21U);
        }
    } else {
        emit_read_b8(b, SCR0, insn->modrm_reg);
        emit_write_b8(b, insn->modrm_rm, SCR0);
    }
    return 0;
}

/* 89 /r: r/m(v) <- r(v). */
static int em_mov_evgv(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned src = i686_w(insn->modrm_reg);

    if (rm_is_mem(insn)) {
        emit_ea(e, insn);
        if (v_bytes(insn) == 4U) {
            a64_emit_guest_str_w(b, src, 21U);
        } else {
            a64_emit_guest_strh_w(b, src, 21U);
        }
    } else if (v_bytes(insn) == 4U) {
        a64_emit_mov_w(b, i686_w(insn->modrm_rm), src);
    } else {
        emit_write_w16(b, i686_w(insn->modrm_rm), src);
    }
    return 0;
}

/* 8A /r: r8 <- r/m8. */
static int em_mov_gbeb(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (rm_is_mem(insn)) {
        emit_ea(e, insn);
        a64_emit_guest_ldrb_w(b, SCR0, 21U); /* zero-extends */
        emit_write_b8(b, insn->modrm_reg, SCR0);
    } else {
        emit_read_b8(b, SCR0, insn->modrm_rm);
        emit_write_b8(b, insn->modrm_reg, SCR0);
    }
    return 0;
}

/* 8B /r: r(v) <- r/m(v). */
static int em_mov_gvev(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (rm_is_mem(insn)) {
        emit_ea(e, insn);
        if (v_bytes(insn) == 4U) {
            a64_emit_guest_ldr_w(b, i686_w(insn->modrm_reg), 21U);
        } else {
            a64_emit_guest_ldrh_w(b, SCR0, 21U);
            emit_write_w16(b, i686_w(insn->modrm_reg), SCR0);
        }
    } else if (v_bytes(insn) == 4U) {
        a64_emit_mov_w(b, i686_w(insn->modrm_reg), i686_w(insn->modrm_rm));
    } else {
        emit_write_w16(b, i686_w(insn->modrm_reg), i686_w(insn->modrm_rm));
    }
    return 0;
}

/* B0-B7: r8 <- imm8 (reg rides the opcode in modrm_reg; AH..BH included). */
static int em_mov_gbib(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    a64_emit_movz_w(b, SCR0, (uint16_t)(insn->imm & 0xFFU), 0U);
    emit_write_b8(b, insn->modrm_reg, SCR0);
    return 0;
}

/* B8-BF: r(v) <- Iv (reg rides the opcode in modrm_reg). */
static int em_mov_gviv(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (v_bytes(insn) == 4U) {
        a64_emit_mov_imm32(b, i686_w(insn->modrm_reg), insn->imm);
    } else {
        a64_emit_movz_w(b, SCR0, (uint16_t)(insn->imm & 0xFFFFU), 0U);
        emit_write_w16(b, i686_w(insn->modrm_reg), SCR0);
    }
    return 0;
}

/* C6 /0: r/m8 <- imm8. */
static int em_mov_ebib(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    a64_emit_movz_w(b, SCR0, (uint16_t)(insn->imm & 0xFFU), 0U);
    if (rm_is_mem(insn)) {
        emit_ea(e, insn);
        a64_emit_guest_strb_w(b, SCR0, 21U);
    } else {
        emit_write_b8(b, insn->modrm_rm, SCR0);
    }
    return 0;
}

/* C7 /0: r/m(v) <- Iz. */
static int em_mov_eviz(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    if (rm_is_mem(insn)) {
        emit_ea(e, insn);
        if (v_bytes(insn) == 4U) {
            a64_emit_mov_imm32(b, SCR0, insn->imm);
            a64_emit_guest_str_w(b, SCR0, 21U);
        } else {
            a64_emit_movz_w(b, SCR0, (uint16_t)(insn->imm & 0xFFFFU), 0U);
            a64_emit_guest_strh_w(b, SCR0, 21U);
        }
    } else if (v_bytes(insn) == 4U) {
        a64_emit_mov_imm32(b, i686_w(insn->modrm_rm), insn->imm);
    } else {
        a64_emit_movz_w(b, SCR0, (uint16_t)(insn->imm & 0xFFFFU), 0U);
        emit_write_w16(b, i686_w(insn->modrm_rm), SCR0);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* MOVZX / MOVSX                                                       */
/* ------------------------------------------------------------------ */

/*
 * Shared shape: materialize the (zero- or sign-extended) source into
 * SCR0, then write the destination at the operand size (32-bit replaces,
 * 16-bit preserves the upper half — the interpreter's x86_reg_write).
 * src_bits: 8 or 16; sext: MOVSX semantics.
 */
static int em_extend(i686_emit_ctx_t *e, const x86_insn_t *insn,
                     unsigned src_bits, int sext)
{
    a64_buf_t *b = &e->buf;
    unsigned dst = i686_w(insn->modrm_reg);

    if (rm_is_mem(insn)) {
        emit_ea(e, insn);
        if (src_bits == 8U) {
            if (sext != 0) {
                a64_emit_guest_ldrsb_w(b, SCR0, 21U);
            } else {
                a64_emit_guest_ldrb_w(b, SCR0, 21U);
            }
        } else {
            if (sext != 0) {
                a64_emit_guest_ldrsh_w(b, SCR0, 21U);
            } else {
                a64_emit_guest_ldrh_w(b, SCR0, 21U);
            }
        }
    } else if (src_bits == 8U) {
        if (sext != 0) {
            emit_sbfx_w(b, SCR0, i686_w(b8_base(insn->modrm_rm)),
                        b8_lsb(insn->modrm_rm), 8U);
        } else {
            emit_read_b8(b, SCR0, insn->modrm_rm);
        }
    } else {
        if (sext != 0) {
            a64_emit_sbfm_w(b, SCR0, i686_w(insn->modrm_rm), 0U, 15U);
        } else {
            emit_uxth_w(b, SCR0, i686_w(insn->modrm_rm));
        }
    }

    if (v_bytes(insn) == 4U) {
        a64_emit_mov_w(b, dst, SCR0);
    } else {
        emit_write_w16(b, dst, SCR0);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* XCHG (register forms; memory forms decline — D2 fallback)           */
/* ------------------------------------------------------------------ */

/* 90+r (rm==0 decodes as NOP, so r != 0 here): eAX <-> r(v). */
static int em_xchg_eaxgv(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned r = i686_w(insn->modrm_reg);

    if (v_bytes(insn) == 4U) {
        a64_emit_mov_w(b, SCR0, 0U);
        a64_emit_mov_w(b, SCR1, r);
        a64_emit_mov_w(b, 0U, SCR1);
        a64_emit_mov_w(b, r, SCR0);
    } else {
        emit_uxth_w(b, SCR0, 0U);
        emit_uxth_w(b, SCR1, r);
        emit_write_w16(b, 0U, SCR1);
        emit_write_w16(b, r, SCR0);
    }
    return 0;
}

/* 86 /87 reg forms: r/m <-> r at width. */
static int em_xchg_rmi(i686_emit_ctx_t *e, const x86_insn_t *insn,
                       unsigned bytes)
{
    a64_buf_t *b = &e->buf;
    unsigned r = i686_w(insn->modrm_reg);
    unsigned m = i686_w(insn->modrm_rm);

    if (bytes == 1U) {
        emit_read_b8(b, SCR0, insn->modrm_rm);
        emit_read_b8(b, SCR1, insn->modrm_reg);
        emit_write_b8(b, insn->modrm_rm, SCR1);
        emit_write_b8(b, insn->modrm_reg, SCR0);
    } else if (bytes == 4U) {
        a64_emit_mov_w(b, SCR0, m);
        a64_emit_mov_w(b, SCR1, r);
        a64_emit_mov_w(b, m, SCR1);
        a64_emit_mov_w(b, r, SCR0);
    } else {
        emit_uxth_w(b, SCR0, m);
        emit_uxth_w(b, SCR1, r);
        emit_write_w16(b, m, SCR1);
        emit_write_w16(b, r, SCR0);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Stack: PUSH/POP (flat SS, ESP arithmetic in w4, accesses [x20, w4]) */
/* ------------------------------------------------------------------ */

/* Decrement ESP and store wsrc at the new ESP: sub w4,w4,#bytes;
 * str/strh wsrc, [x20, w4, uxtw]. Records the Wave U3 site: ESP moves
 * BEFORE the store, so a fault between the two must roll ESP back by
 * +bytes (sp_rollback_delta = -bytes, undone by the landing pad). */
static void emit_push_store(i686_emit_ctx_t *e, const x86_insn_t *insn,
                            unsigned wsrc, unsigned bytes)
{
    a64_buf_t *b = &e->buf;
    dbt_mem_site_t site;
    uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
    uint32_t mem;
    uint32_t cont;

    a64_emit_sub_imm_w(b, false, 4U, 4U, (uint16_t)bytes, 0U);
    mem = (uint32_t)((uint64_t)b->count * 4u);
    if (bytes == 4U) {
        a64_emit_guest_str_w(b, wsrc, 4U);
    } else {
        a64_emit_guest_strh_w(b, wsrc, 4U);
    }
    cont = (uint32_t)((uint64_t)b->count * 4u);

    memset(&site, 0, sizeof(site));
    site.seq_start_offset = (uint16_t)seq;
    site.host_insn_offset = (uint16_t)mem;
    site.cont_insn_offset = (uint16_t)cont;
    site.guest_pc_delta = I686_SITE_PC_UNKNOWN; /* patched by translate lane */
    site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                     ((uint32_t)insn->pfx_lock << 16);
    site.sp_rollback_delta = (int16_t)(-(int32_t)bytes);
    site.npc_mode = (uint8_t)I686_NPC_SEQUENTIAL;
    site.width = (uint8_t)bytes;
    site.flags = (uint8_t)(I686_SITE_STORE | I686_SITE_PRE_COMMITTED_SP);
    site.val_or_dst_reg = (uint8_t)wsrc;
    site.addr_base_reg = 4U; /* ESP */
    (void)i686_aot_note_stack_site(&site);
}

/* 50+r: PUSH r(v).  PUSH ESP stores the PRE-decrement value. */
static int em_push_gv(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned r = i686_w(insn->modrm_reg);

    if (r == 4U) {
        a64_emit_mov_w(b, SCR0, 4U); /* old ESP */
        emit_push_store(e, insn, SCR0, v_bytes(insn));
    } else {
        emit_push_store(e, insn, r, v_bytes(insn));
    }
    return 0;
}

/* 68: PUSH Iz. */
static int em_push_iz(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    a64_emit_mov_imm32(b, SCR0, insn->imm); /* 16-bit Iz: low half used */
    emit_push_store(e, insn, SCR0, v_bytes(insn));
    return 0;
}

/* 6A: PUSH imm8, SIGN-EXTENDED to the operand size (I8SX). */
static int em_push_ib(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;

    a64_emit_movz_w(b, SCR0, (uint16_t)(insn->imm & 0xFFU), 0U);
    emit_sbfx_w(b, SCR0, SCR0, 0U, 8U); /* sext8 -> 32; strh takes low 16 */
    emit_push_store(e, insn, SCR0, v_bytes(insn));
    return 0;
}

/* 58+r: POP r(v).  POP ESP: the popped value wins over the increment;
 * 16-bit POP writes the low half AFTER the ESP bump (popped value wins
 * for r==ESP there too). */
static int em_pop_gv(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned r = i686_w(insn->modrm_reg);
    dbt_mem_site_t site;
    uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
    uint32_t cont;
    unsigned bytes = v_bytes(insn);

    /* The load faults BEFORE the ESP bump, so ESP needs no rollback
     * (sp_rollback_delta = 0); the site still identifies the access width
     * and destination for the shared landing pad. The single-word load is
     * both the sequence start and the faulting instruction. */
    if (bytes == 4U) {
        if (r == 4U) {
            a64_emit_guest_ldr_w(b, SCR0, 4U);
            a64_emit_mov_w(b, 4U, SCR0);
        } else {
            a64_emit_guest_ldr_w(b, r, 4U);
            a64_emit_add_imm_w(b, false, 4U, 4U, 4U, 0U);
        }
    } else {
        a64_emit_guest_ldrh_w(b, SCR0, 4U);
        a64_emit_add_imm_w(b, false, 4U, 4U, 2U, 0U);
        emit_write_w16(b, r, SCR0);
    }
    cont = (uint32_t)((uint64_t)b->count * 4u);

    memset(&site, 0, sizeof(site));
    site.seq_start_offset = (uint16_t)seq;
    site.host_insn_offset = (uint16_t)seq;
    site.cont_insn_offset = (uint16_t)cont;
    site.guest_pc_delta = I686_SITE_PC_UNKNOWN; /* patched by translate lane */
    site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                     ((uint32_t)insn->pfx_lock << 16);
    site.sp_rollback_delta = 0;
    site.npc_mode = (uint8_t)I686_NPC_SEQUENTIAL;
    site.width = (uint8_t)bytes;
    site.flags = 0u; /* load, SP intact on fault */
    site.val_or_dst_reg = (uint8_t)r;
    site.addr_base_reg = 4U; /* ESP */
    (void)i686_aot_note_stack_site(&site);
    return 0;
}

/* ------------------------------------------------------------------ */
/* BSWAP and LEA                                                       */
/* ------------------------------------------------------------------ */

/* 0F C8+r: 32-bit byte reversal (a 66-prefixed BSWAP executes the 32-bit
 * reversal too, mirroring h_bswap_gv). */
static int em_bswap(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_emit_rev_w(&e->buf, i686_w(insn->modrm_reg),
                   i686_w(insn->modrm_reg));
    return 0;
}

/*
 * 8D /r: dst(v) <- EA offset WITHOUT the segment base (LEA ignores
 * segment overrides).  Computed in w21: disp + base + (index << scale),
 * components at address-size width under 0x67 with the final sum
 * masked to 16 bits (mirrors h_lea_gvm); mov wDst, w21 / bfi for 16.
 */
static int em_lea(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned dst = i686_w(insn->modrm_reg);

    if (insn->ea_has == 0U) {
        /* mod==3 (architecturally invalid): the oracle materializes a
         * zero offset; mirror it rather than diverge. */
        a64_emit_movz_w(b, 21U, 0U, 0U);
    } else {
        a64_emit_mov_imm32(b, 21U, insn->ea_disp);
        if (insn->pfx_addrsize != 0U) {
            if (insn->ea_base != NONE) {
                emit_uxth_w(b, 22U, i686_w(insn->ea_base));
                a64_emit_add_reg_w(b, false, 21U, 21U, 22U,
                                   A64_SHIFT_LSL, 0U);
            }
            if (insn->ea_index != NONE) {
                emit_uxth_w(b, 22U, i686_w(insn->ea_index));
                emit_lsl_imm_w(b, 22U, 22U, insn->ea_scale);
                a64_emit_add_reg_w(b, false, 21U, 21U, 22U,
                                   A64_SHIFT_LSL, 0U);
            }
            emit_uxth_w(b, 21U, 21U); /* sum wraps at 64 KiB */
        } else {
            if (insn->ea_base != NONE) {
                a64_emit_add_reg_w(b, false, 21U, 21U,
                                   i686_w(insn->ea_base),
                                   A64_SHIFT_LSL, 0U);
            }
            if (insn->ea_index != NONE) {
                a64_emit_add_reg_w(b, false, 21U, 21U,
                                   i686_w(insn->ea_index),
                                   A64_SHIFT_LSL, insn->ea_scale);
            }
        }
    }

    if (v_bytes(insn) == 4U) {
        a64_emit_mov_w(b, dst, 21U);
    } else {
        emit_write_w16(b, dst, 21U);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Dispatch                                                            */
/* ------------------------------------------------------------------ */

int i686_emit_mov(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    switch (insn->op) {
    case I686_OP_MOV_EbGb:
        return em_mov_ebgb(e, insn);
    case I686_OP_MOV_EvGv:
        return em_mov_evgv(e, insn);
    case I686_OP_MOV_GbEb:
        return em_mov_gbeb(e, insn);
    case I686_OP_MOV_GvEv:
        return em_mov_gvev(e, insn);
    case I686_OP_MOV_GbIb: /* B0+r incl. AH..BH; the card's AL,Ib form */
        return em_mov_gbib(e, insn);
    case I686_OP_MOV_GvIv: /* B8+r; the card's eAX,Iz form */
        return em_mov_gviv(e, insn);
    case I686_OP_MOV_EbIb:
        return em_mov_ebib(e, insn);
    case I686_OP_MOV_EvIz:
        return em_mov_eviz(e, insn);

    case I686_OP_MOVZX_GvEb:
        return em_extend(e, insn, 8U, 0);
    case I686_OP_MOVZX_GvEw:
        return em_extend(e, insn, 16U, 0);
    case I686_OP_MOVSX_GvEb:
        return em_extend(e, insn, 8U, 1);
    case I686_OP_MOVSX_GvEw:
        return em_extend(e, insn, 16U, 1);

    case I686_OP_XCHG_EbGb:
        if (rm_is_mem(insn)) {
            return -1; /* v1: reg forms only (D2 handles memory) */
        }
        return em_xchg_rmi(e, insn, 1U);
    case I686_OP_XCHG_EvGv:
        if (rm_is_mem(insn)) {
            return -1;
        }
        return em_xchg_rmi(e, insn, v_bytes(insn));
    case I686_OP_XCHG_eAXGv:
        return em_xchg_eaxgv(e, insn);

    case I686_OP_PUSH_Gv:
        return em_push_gv(e, insn);
    case I686_OP_PUSH_Iz:
        return em_push_iz(e, insn);
    case I686_OP_PUSH_Ib:
        return em_push_ib(e, insn);
    case I686_OP_POP_Gv:
        return em_pop_gv(e, insn);

    case I686_OP_BSWAP_Gv:
        return em_bswap(e, insn);
    case I686_OP_LEA_GvM:
        return em_lea(e, insn);

    /* Declined in v1 (card L3b): PUSHA/POPA/ENTER/LEAVE. */
    case I686_OP_PUSHA:
    case I686_OP_POPA:
    case I686_OP_ENTER:
    case I686_OP_LEAVE:
        return -1;

    default:
        /* Not a MOV-family op for this lane (segment moves, moffs,
         * PUSHF/POPF, sreg pushes, r/m stack forms, XLAT, CPUID ...):
         * another lane or the D2 fallback owns them. */
        return -1;
    }
}
