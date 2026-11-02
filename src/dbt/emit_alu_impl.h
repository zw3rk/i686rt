/*
 * src/dbt/emit_alu_impl.h — shared helpers for the Lane P3 extended ALU
 * emitters (emit_alu_ext.c, emit_alu_ext2.c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Scratch map (same as emit_alu.c): w8 = dest, w9 = src, w10 = result,
 * w11..w15 = temps, x11..x13 = 64-bit temps.  w21 survives each
 * load...store pair (the EA), so flag sequences never touch w21/w22.
 * NZCV polarity follows the emit_alu.c convention (C = !CF) except
 * transiently around ADCS/SBCS.  All helpers are static inline so the
 * two extension TUs share them without linkage or size overhead.
 */

#ifndef I686RT_DBT_EMIT_ALU_IMPL_H
#define I686RT_DBT_EMIT_ALU_IMPL_H

#include <stdint.h>
#include <string.h>

#include "dbt/aot/aot.h"
#include "dbt/emit.h"

#define XALU_A    8U  /* destination operand value (width-masked) */
#define XALU_B    9U  /* source operand value / immediate         */
#define XALU_RES 10U  /* result                                    */
#define XALU_T0  11U
#define XALU_T1  12U
#define XALU_T2  13U
#define XALU_T3  14U
#define XALU_T4  15U

/* ---- width-trivial raw encoders (mirrors emit_alu.c) ---------------- */

/* AND Wd, Wn, #imm — only 0xFF / 0xFFFF are needed (N=0, immr=0). */
static inline void xalu_and_imm_w(a64_buf_t *b, unsigned rd, unsigned rn,
                           uint32_t imm)
{
    unsigned imms = (imm == 0xFFFFU) ? 15U : 7U;
    a64_emit(b, 0x12000000U | ((imms & 31U) << 10) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

/* CSET Wd, cond = CSINC Wd, WZR, WZR, invert(cond). */
static inline void xalu_cset_w(a64_buf_t *b, unsigned rd, unsigned cond)
{
    a64_emit(b, 0x1A800400U | (31U << 16) | (((cond ^ 1U) & 15U) << 12) |
                     (31U << 5) | (rd & 31U));
}

/* EOR Wd, Wn, #1 (parity fold). */
static inline void xalu_eor_imm1_w(a64_buf_t *b, unsigned rd, unsigned rn)
{
    a64_emit(b, 0x52000000U | ((rn & 31U) << 5) | (rd & 31U));
}

/* BFI Wd, Wn, #lsb, #width = BFM Wd, Wn, #(32-lsb)&31, #(width-1). */
static inline void xalu_bfi_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned lsb,
                       unsigned width)
{
    a64_emit_bfm_w(b, rd, rn, (32U - lsb) & 31U, width - 1U);
}

/* LSL Wd, Wn, #s (1..31) = UBFM #(32-s)&31, #(31-s). */
static inline void xalu_lsl_imm_w(a64_buf_t *b, unsigned rd, unsigned rn,
                           unsigned s)
{
    a64_emit_ubfm_w(b, rd, rn, (32U - s) & 31U, 31U - s);
}

/* LSR Wd, Wn, #s (1..31) = UBFM #s, #31. */
static inline void xalu_lsr_imm_w(a64_buf_t *b, unsigned rd, unsigned rn,
                           unsigned s)
{
    a64_emit_ubfm_w(b, rd, rn, s, 31U);
}

/* SUBS XZR, Xn, Xm (64-bit compare). */
static inline void xalu_subs_x(a64_buf_t *b, unsigned rn_x, unsigned rm_x)
{
    a64_emit(b, 0xEB000000U | ((rm_x & 31U) << 16) | ((rn_x & 31U) << 5) |
                     31U);
}

/* SBFX Xd, Xn, #lsb, #width (signed extract; width>=1). */
static inline void xalu_sbfx_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x,
                        unsigned lsb, unsigned width)
{
    a64_emit(b, 0x93400000U | ((lsb & 63U) << 16) |
                     (((width - 1U) & 63U) << 10) | ((rn_x & 31U) << 5) |
                     (rd_x & 31U));
}

/* LSL Xd, Xn, #sh (1..63) = UBFM #64-sh, #63-sh. */
static inline void xalu_lsl_x_imm(a64_buf_t *b, unsigned rd_x, unsigned rn_x,
                           unsigned sh)
{
    a64_emit(b, 0xD3400000U | (((64U - sh) & 63U) << 16) |
                     (((63U - sh) & 63U) << 10) | ((rn_x & 31U) << 5) |
                     (rd_x & 31U));
}

/* LSR Xd, Xn, #sh (1..63) = UBFM #sh, #63. */
static inline void xalu_lsr_x_imm(a64_buf_t *b, unsigned rd_x, unsigned rn_x,
                           unsigned sh)
{
    a64_emit(b, 0xD3400000U | ((sh & 63U) << 16) | (63U << 10) |
                     ((rn_x & 31U) << 5) | (rd_x & 31U));
}

/* ORR Xd, Xn, Xm (plain register OR). */
static inline void xalu_orr_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x,
                       unsigned rm_x)
{
    a64_emit(b, 0xAA000000U | ((rm_x & 31U) << 16) | ((rn_x & 31U) << 5) |
                     (rd_x & 31U));
}

/* LSLV/LSRV/ASRV/RORV Xd, Xn, Xm (register-count shifts). */
static inline void xalu_lslv_x(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm)
{
    a64_emit(b, 0x9AC02000U | ((rm & 31U) << 16) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

static inline void xalu_lsrv_x(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm)
{
    a64_emit(b, 0x9AC02400U | ((rm & 31U) << 16) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

/* UDIV/SDIV Xd, Xn, Xm (no trap: /0 yields 0, INT_MIN/-1 wraps). */
static inline void xalu_udiv_x(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm)
{
    a64_emit(b, 0x9AC00800U | ((rm & 31U) << 16) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

static inline void xalu_sdiv_x(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm)
{
    a64_emit(b, 0x9AC00C00U | ((rm & 31U) << 16) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

/* MSUB Xd, Xn, Xm, Xa: Xd = Xa - Xn*Xm (o0, bit 15, selects
 * subtract; verified against the assembler's `msub x10,x11,x12,x13`
 * = 0x9b0cb56a). */
static inline void xalu_msub_x(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm,
                        unsigned ra)
{
    a64_emit(b, 0x9B008000U | ((rm & 31U) << 16) | ((ra & 31U) << 10) |
                     ((rn & 31U) << 5) | (rd & 31U));
}

/* CBZ/CBNZ X placeholder + patch (word offsets, like the W helpers). */
static inline size_t xalu_cbz_x_placeholder(a64_buf_t *b, int is_cbnz, unsigned rt)
{
    size_t idx = b->count;
    uint32_t base = (is_cbnz != 0) ? 0xB5000000U : 0xB4000000U;
    a64_emit(b, base | (rt & 31U));
    return idx;
}

static inline void xalu_patch_cbz_x(a64_buf_t *b, size_t patch_idx,
                             size_t target_idx)
{
    int32_t disp;
    uint32_t op_rt;

    if (patch_idx >= b->count) {
        return;
    }
    disp = (int32_t)target_idx - (int32_t)patch_idx;
    op_rt = b->words[patch_idx] & 0xFF00001FU;
    b->words[patch_idx] = op_rt | (((uint32_t)disp & 0x7FFFFU) << 5);
}

/* B #off26 placeholder + patch (forward only). */
static inline size_t xalu_b_placeholder(a64_buf_t *b)
{
    size_t idx = b->count;
    a64_emit(b, 0x14000000U);
    return idx;
}

static inline void xalu_patch_b(a64_buf_t *b, size_t patch_idx, size_t target_idx)
{
    int32_t disp;

    if (patch_idx >= b->count) {
        return;
    }
    disp = (int32_t)target_idx - (int32_t)patch_idx;
    b->words[patch_idx] =
        0x14000000U | ((uint32_t)disp & 0x03FFFFFFU);
}

/* ---- guest memory (w21 = EA from i686_emit_ea) ------------------------ */

/* RC-U3 recovery site for a non-LOCK ALU memory access (shared with
 * emit_alu.c's load/store-rm pair).  Without it a fault in a load or
 * store resumes at the block base and re-executes the (non-idempotent)
 * prefix, corrupting registers the same way the missing atomic sites
 * did (C2-2 flock).  mem is the LDR/STR offset itself (+4 into the TSO
 * pair when e->tso, mirroring emit_mov.c).  Delta comes from
 * translate.c's per-insn e->insn_pc. */
static inline void xalu_note_mem_site(i686_emit_ctx_t *e,
                                      const x86_insn_t *insn, uint32_t seq,
                                      uint32_t mem, uint32_t cont,
                                      unsigned width, unsigned val_reg,
                                      unsigned is_store)
{
    dbt_mem_site_t site;

    memset(&site, 0, sizeof(site));
    site.seq_start_offset = (uint16_t)seq;
    site.host_insn_offset = (uint16_t)mem;
    site.cont_insn_offset = (uint16_t)cont;
    if (e->insn_pc >= e->guest_eip &&
        e->insn_pc - e->guest_eip <= 0xFFF0U) {
        site.guest_pc_delta = (uint16_t)(e->insn_pc - e->guest_eip);
    } else {
        site.guest_pc_delta = I686_SITE_PC_UNKNOWN;
    }
    site.insn_word = ((uint32_t)insn->op & 0xFFFFU) |
                     ((uint32_t)insn->pfx_lock << 16);
    site.sp_rollback_delta = 0;
    site.npc_mode = (uint8_t)I686_NPC_SEQUENTIAL;
    site.width = (uint8_t)width;
    site.flags = is_store != 0U ? (uint8_t)I686_SITE_STORE : 0u;
    site.val_or_dst_reg = (uint8_t)val_reg;
    /* 0xFF sentinel in the frozen x86_insn_t (ea_base none). */
    site.addr_base_reg = (uint8_t)(insn->ea_base != 0xFFU
                                       ? i686_w(insn->ea_base)
                                       : 0xFFu);
    (void)i686_aot_note_stack_site(&site);
}

static inline void xalu_guest_load(i686_emit_ctx_t *e, unsigned rt, unsigned width)
{
    a64_buf_t *b = &e->buf;

    if (width == 8U) {
        a64_emit_guest_ldrb_w(b, rt, 21U);
    } else if (width == 16U) {
        a64_emit_guest_ldrh_w(b, rt, 21U);
    } else {
        a64_emit_guest_ldr_w(b, rt, 21U);
    }
    if (e->tso) {
        a64_emit(b, 0xD50339BFU); /* dmb ishld */
    }
}

static inline void xalu_guest_store(i686_emit_ctx_t *e, unsigned rt, unsigned width)
{
    a64_buf_t *b = &e->buf;

    if (width == 8U) {
        a64_emit_guest_strb_w(b, rt, 21U);
    } else if (width == 16U) {
        a64_emit_guest_strh_w(b, rt, 21U);
    } else {
        a64_emit_guest_str_w(b, rt, 21U);
    }
    if (e->tso) {
        a64_emit(b, 0xD5033BBFU); /* dmb ish */
    }
}

/* ---- x86 register file on the fixed w0..w7 map ----------------------- */

/* 8-bit high halves (AH..BH) live in bits 15:8 of EAX..EBX (D7). */
static inline unsigned xalu_byte_pos(uint8_t reg)
{
    return (reg >= 4U) ? 8U : 0U;
}

static inline unsigned xalu_byte_host(uint8_t reg)
{
    return (reg >= 4U) ? (unsigned)(reg - 4U) : (unsigned)reg;
}

static inline void xalu_load_reg(a64_buf_t *b, unsigned dst, uint8_t reg,
                          unsigned width)
{
    if (width == 32U) {
        a64_emit_mov_w(b, dst, i686_w(reg));
    } else if (width == 16U) {
        a64_emit_ubfm_w(b, dst, i686_w(reg), 0U, 15U);
    } else {
        a64_emit_ubfm_w(b, dst, xalu_byte_host(reg), xalu_byte_pos(reg),
                        xalu_byte_pos(reg) + 7U);
    }
}

static inline void xalu_store_reg(a64_buf_t *b, unsigned src, uint8_t reg,
                           unsigned width)
{
    if (width == 32U) {
        a64_emit_mov_w(b, i686_w(reg), src);
    } else if (width == 16U) {
        xalu_bfi_w(b, i686_w(reg), src, 0U, 16U);
    } else {
        xalu_bfi_w(b, i686_w(xalu_byte_host(reg)), src,
                   xalu_byte_pos(reg), 8U);
    }
}

/* r/m operand: mod==3 (or no EA) is a register, else guest memory via
 * i686_emit_ea; w21 survives the load for the matching store. */
static inline void xalu_load_rm(i686_emit_ctx_t *e, const x86_insn_t *insn,
                         unsigned dst, unsigned width)
{
    if (insn->modrm_mod == 3U || insn->ea_has == 0U) {
        xalu_load_reg(&e->buf, dst, insn->modrm_rm, width);
        return;
    }
    {
        a64_buf_t *b = &e->buf;
        uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t mem;
        uint32_t cont;
        i686_emit_ea(e, insn, 1);
        mem = (uint32_t)((uint64_t)b->count * 4u);
        xalu_guest_load(e, dst, width);
        cont = (uint32_t)((uint64_t)b->count * 4u);
        xalu_note_mem_site(e, insn, seq, mem, cont, width, dst, 0U);
    }
}

static inline void xalu_store_rm(i686_emit_ctx_t *e, const x86_insn_t *insn,
                          unsigned src, unsigned width)
{
    if (insn->modrm_mod == 3U || insn->ea_has == 0U) {
        xalu_store_reg(&e->buf, src, insn->modrm_rm, width);
        return;
    }
    /* Nothing between load and store touched w21. */
    {
        a64_buf_t *b = &e->buf;
        uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t mem = (uint32_t)((uint64_t)b->count * 4u);
        uint32_t cont;
        xalu_guest_store(e, src, width);
        cont = (uint32_t)((uint64_t)b->count * 4u);
        xalu_note_mem_site(e, insn, seq, mem, cont, width, src, 1U);
    }
}

/* ---- pending-flags materialization (no-op when already EFLAGS) ------- */

/* Park the guest GPRs, call i686_dbt_flags_sync so a pending lazy
 * descriptor materializes into ctx->eflags, reload.  Mirrors the
 * emit_branch.c helper-call sequence exactly (x0-x7 park, x17 target,
 * x28 parks lr).  Must run before any operand lands in w8..w15: the
 * AAPCS call clobbers x0-x18. */
static inline void xalu_sync_eflags(i686_emit_ctx_t *e)
{
    a64_buf_t *b = &e->buf;
    extern void i686_dbt_flags_sync(i686_ctx_t *ctx);
    uintptr_t fn = (uintptr_t)&i686_dbt_flags_sync;
    unsigned i;

    if (e->flags_src == I686_FLAGS_EFLAGS) {
        return; /* ctx->eflags already architecturally current */
    }
    if (e->flags_src == I686_FLAGS_NZCV) {
        /* Fused image in NZCV (SUBS polarity: N=SF, Z=ZF, C=!CF, V=OF)
         * plus lazy_res/src1/src2 in ctx: materialize inline with zero
         * helper call or GPR spills. */
        size_t to_done;
        a64_emit_mrs_nzcv(b, XALU_T1);
        a64_emit_ldr_imm_w(b, XALU_T0, 19U, 76U); /* lazy_op */
        to_done = xalu_cbz_x_placeholder(b, 0, XALU_T0);
        a64_emit_ldr_imm_w(b, XALU_T0, 19U, 36U); /* eflags */
        a64_emit_movz_w(b, XALU_T2, 0x08D5U, 0U); /* CF|PF|AF|ZF|SF|OF */
        a64_emit_bic_reg_w(b, false, XALU_T0, XALU_T0, XALU_T2,
                           A64_SHIFT_LSL, 0U);
        a64_emit_ubfm_w(b, XALU_T2, XALU_T1, 31U, 31U); /* N -> SF */
        xalu_bfi_w(b, XALU_T0, XALU_T2, 7U, 1U);
        a64_emit_ubfm_w(b, XALU_T2, XALU_T1, 30U, 30U); /* Z -> ZF */
        xalu_bfi_w(b, XALU_T2, XALU_T2, 0U, 1U);
        xalu_bfi_w(b, XALU_T0, XALU_T2, 6U, 1U);
        a64_emit_ubfm_w(b, XALU_T2, XALU_T1, 29U, 29U); /* C = !CF */
        xalu_eor_imm1_w(b, XALU_T2, XALU_T2);
        xalu_bfi_w(b, XALU_T0, XALU_T2, 0U, 1U);
        a64_emit_ubfm_w(b, XALU_T2, XALU_T1, 28U, 28U); /* V -> OF */
        xalu_bfi_w(b, XALU_T0, XALU_T2, 11U, 1U);
        a64_emit_ldr_imm_w(b, XALU_T2, 19U, 80U); /* lazy_res */
        xalu_and_imm_w(b, XALU_T3, XALU_T2, 0xFFU);
        a64_emit_eor_reg_w(b, XALU_T3, XALU_T3, XALU_T3, A64_SHIFT_LSR, 4U);
        a64_emit_eor_reg_w(b, XALU_T3, XALU_T3, XALU_T3, A64_SHIFT_LSR, 2U);
        a64_emit_eor_reg_w(b, XALU_T3, XALU_T3, XALU_T3, A64_SHIFT_LSR, 1U);
        a64_emit_ubfm_w(b, XALU_T3, XALU_T3, 0U, 0U);
        xalu_eor_imm1_w(b, XALU_T4, XALU_T3);
        xalu_bfi_w(b, XALU_T0, XALU_T4, 2U, 1U); /* PF */
        a64_emit_ldr_imm_w(b, XALU_T3, 19U, 84U); /* lazy_src1 */
        a64_emit_ldr_imm_w(b, XALU_T4, 19U, 88U); /* lazy_src2 */
        a64_emit_eor_reg_w(b, XALU_T2, XALU_T2, XALU_T3, A64_SHIFT_LSL, 0U);
        a64_emit_eor_reg_w(b, XALU_T2, XALU_T2, XALU_T4, A64_SHIFT_LSL, 0U);
        a64_emit_ubfm_w(b, XALU_T2, XALU_T2, 4U, 4U);
        xalu_bfi_w(b, XALU_T0, XALU_T2, 4U, 1U); /* AF */
        a64_emit_str_imm_w(b, XALU_T0, 19U, 36U);
        a64_emit_str_imm_w(b, 31U, 19U, 76U);
        xalu_patch_cbz_x(b, to_done, b->count);
        a64_emit_msr_nzcv(b, XALU_T1);
        e->flags_src = I686_FLAGS_EFLAGS;
        return;
    }
    a64_emit_str_imm_w(b, 0U, 19U, 0U);
    a64_emit_str_imm_w(b, 1U, 19U, 4U);
    a64_emit_str_imm_w(b, 2U, 19U, 8U);
    a64_emit_str_imm_w(b, 3U, 19U, 12U);
    a64_emit_str_imm_w(b, 4U, 19U, 16U);
    a64_emit_str_imm_w(b, 5U, 19U, 20U);
    a64_emit_str_imm_w(b, 6U, 19U, 24U);
    a64_emit_str_imm_w(b, 7U, 19U, 28U);
    for (i = 0U; i < 4U; i++) {
        uint32_t hw = (uint32_t)((fn >> (16U * i)) & 0xFFFFU);
        uint32_t word;
        if (i == 0U) {
            word = 0xD2800000U; /* MOVZ X17, hw */
        } else if (hw != 0U) {
            word = 0xF2800000U; /* MOVK X17, hw, LSL #16i */
        } else {
            continue;
        }
        a64_emit(b, word | (i << 21) | (hw << 5) | 17U);
    }
    a64_emit(b, 0xAA1F0260U); /* x0 = x19 */
    a64_emit(b, 0xAA1F03DCU); /* x28 = x30 (park lr) */
    a64_emit(b, 0xD63F0220U); /* blr x17 */
    a64_emit(b, 0xAA1F039EU); /* x30 = x28 */
    a64_emit_ldr_imm_w(b, 0U, 19U, 0U);
    a64_emit_ldr_imm_w(b, 1U, 19U, 4U);
    a64_emit_ldr_imm_w(b, 2U, 19U, 8U);
    a64_emit_ldr_imm_w(b, 3U, 19U, 12U);
    a64_emit_ldr_imm_w(b, 4U, 19U, 16U);
    a64_emit_ldr_imm_w(b, 5U, 19U, 20U);
    a64_emit_ldr_imm_w(b, 6U, 19U, 24U);
    a64_emit_ldr_imm_w(b, 7U, 19U, 28U);
}

/* ---- carry-in for ADC/SBB -------------------------------------------- */

/* wTc = CF (0/1); NZCV.C := CF (true polarity for ADCS/SBCS).
 * From the fused image (NZCV, C = !CF): flip the live bit.  From
 * ctx->eflags (EFLAGS, or DEAD after the sync above): build NZCV with
 * C = CF (only C is read by ADCS/SBCS; N/Z/V are overwritten). */
static inline void xalu_carry_in(i686_emit_ctx_t *e, unsigned wTc)
{
    a64_buf_t *b = &e->buf;

    if (e->flags_src == I686_FLAGS_NZCV) {
        a64_emit_mrs_nzcv(b, XALU_T0);
        a64_emit_ubfm_w(b, wTc, XALU_T0, 29U, 29U); /* C_img = !CF */
        xalu_eor_imm1_w(b, wTc, wTc);               /* CF = !C_img */
        xalu_bfi_w(b, XALU_T0, wTc, 29U, 1U);       /* NZCV.C := CF */
        a64_emit_msr_nzcv(b, XALU_T0);
        return;
    }
    a64_emit_ldr_imm_w(b, XALU_T0, 19U, 36U);      /* ctx->eflags */
    a64_emit_ubfm_w(b, wTc, XALU_T0, 0U, 0U);      /* CF */
    a64_emit_movz_w(b, XALU_T0, 0U, 0U);
    xalu_bfi_w(b, XALU_T0, wTc, 29U, 1U);
    a64_emit_msr_nzcv(b, XALU_T0);
}

/* ---- eager flag tails ------------------------------------------------- */

/* Fold Z/S/P from the width-masked result wResM into the eflags image
 * wE (flags.c set_szp shape; the cmp clobbers NZCV, which is fine for
 * eager producers).  Clobbers T1/T2/T4. */
static inline void xalu_fold_zsp(i686_emit_ctx_t *e, unsigned wResM, unsigned msb,
                          unsigned wE)
{
    a64_buf_t *b = &e->buf;

    a64_emit_sub_imm_w(b, true, 31U, wResM, 0U, 0U); /* cmp res, #0 */
    xalu_cset_w(b, XALU_T1, A64_COND_EQ);            /* ZF */
    xalu_bfi_w(b, wE, XALU_T1, 6U, 1U);
    a64_emit_ubfm_w(b, XALU_T1, wResM, msb, msb);    /* SF */
    xalu_bfi_w(b, wE, XALU_T1, 7U, 1U);
    xalu_and_imm_w(b, XALU_T2, wResM, 0xFFU);        /* PF: even parity */
    a64_emit_eor_reg_w(b, XALU_T2, XALU_T2, XALU_T2, A64_SHIFT_LSR, 4U);
    a64_emit_eor_reg_w(b, XALU_T2, XALU_T2, XALU_T2, A64_SHIFT_LSR, 2U);
    a64_emit_eor_reg_w(b, XALU_T2, XALU_T2, XALU_T2, A64_SHIFT_LSR, 1U);
    a64_emit_ubfm_w(b, XALU_T2, XALU_T2, 0U, 0U);    /* odd parity bit */
    xalu_eor_imm1_w(b, XALU_T4, XALU_T2);            /* -> even parity */
    xalu_bfi_w(b, wE, XALU_T4, 2U, 1U);
}

/* Commit an eager eflags image: store ctx->eflags, clear the lazy
 * descriptor, mark the EFLAGS proof. */
static inline void xalu_commit_eflags(i686_emit_ctx_t *e, unsigned wE)
{
    a64_buf_t *b = &e->buf;

    a64_emit_str_imm_w(b, wE, 19U, 36U);
    a64_emit_str_imm_w(b, 31U, 19U, 76U); /* lazy_op = NONE */
    e->flags_src = I686_FLAGS_EFLAGS;
}

static inline uint32_t xalu_sext_imm8(uint32_t imm)
{
    return ((imm & 0xFFU) ^ 0x80U) - 0x80U;
}

enum { XFRM_EbGb, XFRM_EvGv, XFRM_GbEb, XFRM_GvEv, XFRM_ALIb, XFRM_eAXIz,
       XFRM_EbIb, XFRM_EvIz, XFRM_EvIbSX };

enum { XSHK_SHL, XSHK_SHR, XSHK_SAR };

/* Extension emitters (defined in emit_alu_ext.c / emit_alu_ext2.c). */
int xalu_adc_sbb(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_sbb,
                 unsigned form);
int xalu_incdec(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_inc);
int xalu_rolror(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_ror,
                uint32_t count, int count_is_reg);
int xalu_shift_cl(i686_emit_ctx_t *e, const x86_insn_t *insn, unsigned kind);
int xalu_mul1(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_imul);
int xalu_divide(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_idiv);
int xalu_shxd(i686_emit_ctx_t *e, const x86_insn_t *insn, int is_shrd,
              uint32_t count, int count_is_reg);

#endif /* I686RT_DBT_EMIT_ALU_IMPL_H */
