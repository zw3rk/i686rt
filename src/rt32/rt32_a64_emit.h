/*
 * src/rt32/rt32_a64_emit.h — Direct 32-bit AArch64 instruction encoder (integer + FP/SIMD)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from a32rt/src/a64_emit.h @ d84feb3 (D13): renamed a32_→rt32_,
 * retyped on i686_ctx_t, and stripped of A32-guest-specific pieces (VFP
 * register-file cache, CPSR/Q-flag/GE helpers, CP15/TLS access, LDM/STM,
 * interworking exits) that have no x86 counterpart; the x87/SSE state
 * accessors and x86 lowering arrive with the Phase 3/4 DBT (SPEC D6, D10).
 */

#ifndef A64_EMIT_H
#define A64_EMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "i686rt.h"

/*
 * Host AArch64 register allocation inside translated fragments (i686 DBT):
 *   w0..w7   : Guest EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI when live in registers;
 *              callee-saved w19..w26 hold them across the trampoline (D7)
 *   w15/x15  : Scratch 0 / exit guest EIP
 *   w16/x16  : Scratch 1 / exit reason (I686_EXIT_*)
 *   w17/x17  : Scratch 2
 *   x19      : Pointer to `i686_ctx_t` (xCtx)
 *   x20      : Guest window base `G` (xG)
 *   w21/x21  : Scratch 3 / epoch & key scratch
 *   w22/x22  : Guest effective address scratch
 *   x23      : Chaining / IBTC / RAS target entry scratch
 *   x24      : Accumulated in-trampoline chain_hits delta
 *   x27      : Current block cache entry pointer (cur_entry)
 *   x28      : Pointer to `g_cache_epoch` (&g_cache_epoch)
 *   x30      : Host link register (points back to the block runner)
 *   v0..v7   : Scratch FP/SIMD registers for x87/SSE lowering
 * a32rt's guest r0..r14 window, w25 PC-alignment mask, w26 Thumb-state flag
 * and the v8..v31 VFP cache slots were dropped (no x86 counterpart).
 */
#define A64_TMP0 15U
#define A64_TMP1 16U
#define A64_TMP2 17U
#define A64_XCTX 19U
#define A64_XG   20U
#define A64_TMP3 21U
#define A64_ADDR 22U
#define A64_ZR   31U

/* Shift types */
#define A64_SHIFT_LSL 0U
#define A64_SHIFT_LSR 1U
#define A64_SHIFT_ASR 2U
#define A64_SHIFT_ROR 3U

/* Condition codes (identical between A32/T32 and A64) */
#define A64_COND_EQ 0U
#define A64_COND_NE 1U
#define A64_COND_CS 2U
#define A64_COND_CC 3U
#define A64_COND_MI 4U
#define A64_COND_PL 5U
#define A64_COND_VS 6U
#define A64_COND_VC 7U
#define A64_COND_HI 8U
#define A64_COND_LS 9U
#define A64_COND_GE 10U
#define A64_COND_LT 11U
#define A64_COND_GT 12U
#define A64_COND_LE 13U
#define A64_COND_AL 14U

/* a32rt's A64_VFP_CACHE_SLOTS / A64_VFP_KIND_* (v8..v31 VFP register cache)
 * were dropped: i686_ctx_t has no vfp_d register file (D10). */

#define A64_MAX_EXIT_SLOTS  8U

typedef struct a64_buf {
    uint32_t *words;
    size_t    count;
    size_t    cap;
    bool      overflow;
    unsigned  cond_branch_depth;
    uint32_t  guest_start_pc;
    uint32_t  guest_end_pc;
    bool      is_call;
    bool      lr_written_from_pc;
    bool      has_self_loop;
    size_t    loop_body_offset;
    uint32_t  exit_slot_pcs[A64_MAX_EXIT_SLOTS];
    unsigned  exit_slot_count;
} a64_buf_t;

static inline void a64_buf_init(a64_buf_t *b, uint32_t *storage, size_t cap)
{
    memset(b, 0, sizeof(*b));
    b->words = storage;
    b->cap   = cap;
}

/* a32rt's a64_buf_start_self_loop() / a64_vfp_cache_flush() were dropped
 * together with the VFP register cache; the self-loop peeling hook returns
 * with the Phase 3 DBT if needed. */

static inline void a64_emit(a64_buf_t *b, uint32_t insn)
{
    if (b->count < b->cap) {
        b->words[b->count++] = insn;
    } else {
        b->overflow = true;
    }
}

/* Move immediate & register moves */
void a64_emit_movz_w(a64_buf_t *b, unsigned rd, uint16_t imm16, unsigned hw);
void a64_emit_movk_w(a64_buf_t *b, unsigned rd, uint16_t imm16, unsigned hw);
void a64_emit_mov_imm32(a64_buf_t *b, unsigned rd, uint32_t val);
void a64_emit_mov_pc32(a64_buf_t *b, unsigned rd, uint32_t pc_val);
void a64_emit_mov_w(a64_buf_t *b, unsigned rd, unsigned rm);
void a64_emit_mvn_reg_w(a64_buf_t *b, unsigned rd, unsigned rm, unsigned shift, unsigned amount);

static inline uint32_t rt32_ror32(uint32_t val, unsigned rot)
{
    rot &= 31U;
    if (rot == 0U) {
        return val;
    }
    return (val >> rot) | (val << (32U - rot));
}

static inline unsigned rt32_load_reg(a64_buf_t *b, unsigned reg, uint32_t pc_val, unsigned scratch)
{
    if (reg == 15U) {
        a64_emit_mov_pc32(b, scratch, pc_val);
        return scratch;
    }
    return reg;
}

/* Arithmetic (32-bit W) */
void a64_emit_add_imm_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, uint16_t imm12, unsigned sh);
void a64_emit_sub_imm_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, uint16_t imm12, unsigned sh);
void a64_emit_add_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_sub_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_adc_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_sbc_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_add_uxtw_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned rm_w);

/* Logical (32-bit W) */
void a64_emit_and_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_bic_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_orr_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_orn_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_eor_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);

/* Shifts, bitfields, multiply/divide */
void a64_emit_shift_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift_type);
void a64_emit_arm_shift_reg_w(a64_buf_t *b, unsigned dst_w, unsigned src_m, unsigned src_s,
                              unsigned shift_type, bool want_carry);
void a64_emit_shift_imm_w(a64_buf_t *b, unsigned dst_w, unsigned src_m, unsigned shift_type,
                          unsigned imm5, bool want_carry, unsigned *out_carry_reg);
void a64_emit_ubfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_sbfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_bfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_ubfx_x_to_w(a64_buf_t *b, unsigned rd_w, unsigned rn_x, unsigned lsb, unsigned width);
void a64_emit_bfi_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned lsb, unsigned width);
void a64_emit_clz_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rbit_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rev_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rev16_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_madd_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra);
void a64_emit_msub_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra);
void a64_emit_umaddl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_smaddl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_smsubl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_udiv_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_sdiv_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_crc32_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned sz, unsigned c_bit);

/* Conditional select & flags */
void a64_emit_csel_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned cond);
void a64_emit_csneg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned cond);
void a64_emit_mrs_nzcv(a64_buf_t *b, unsigned rt);
void a64_emit_msr_nzcv(a64_buf_t *b, unsigned rt);

/*
 * Flag helpers for A32/T32 logical operations with S=1:
 *   - a64_emit_update_nz_keep_cv: updates N and Z from `res_reg`, preserves C and V.
 *   - a64_emit_update_nzc_keep_v_imm: updates N and Z from `res_reg`, sets C = `carry_bit`, preserves V.
 *   - a64_emit_update_nzc_keep_v_reg: updates N and Z from `res_reg`, sets C = `carry_reg[0]`, preserves V.
 */
void a64_emit_update_nz_keep_cv(a64_buf_t *b, unsigned res_reg);
void a64_emit_update_nzc_keep_v_imm(a64_buf_t *b, unsigned res_reg, unsigned carry_bit);
void a64_emit_update_nzc_keep_v_reg(a64_buf_t *b, unsigned res_reg, unsigned carry_reg);
void a64_emit_logical_flags(a64_buf_t *b, unsigned res_reg, bool has_imm_carry,
                            unsigned imm_carry, unsigned shift_carry_reg);

/* DSP/bitfield helpers without CPSR entanglement (kept from a32rt) */
void a64_emit_xt_add(a64_buf_t *b, bool is_signed, bool is_16, bool is_dual8,
                     unsigned rd, unsigned rn, unsigned rm, unsigned rot);
void a64_emit_pkh(a64_buf_t *b, bool is_tb, unsigned rd, unsigned rn, unsigned rm, unsigned shift_imm);
void a64_emit_usad8(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra);
void a64_emit_smlal_xy(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm,
                       bool n_top, bool m_top);
void a64_emit_smlald(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm,
                     bool is_sub, bool m_swap);
void a64_emit_smmla(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra,
                    bool is_sub, bool round);
void a64_emit_umaal(a64_buf_t *b, unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm);
void a64_emit_mull(a64_buf_t *b, bool is_signed, bool accumulate, bool set_flags,
                   unsigned rd_lo, unsigned rd_hi, unsigned rn, unsigned rm);
/* a32rt's A32-only lowering helpers were dropped: a64_emit_set_q_cond,
 * a64_emit_parallel_addsub (+A32_PADD_*), a64_emit_ssat/usat/sat16/qaddsub,
 * a64_emit_sel, a64_emit_smla_xy/smlaw_y/smlad (all CPSR Q/GE-flag users),
 * a64_emit_mrs_cpsr/msr_cpsr_reg, a64_emit_cp15 (CP15 TLS via tls_tp), and
 * a64_emit_ldm_stm (LDM/STM register masks); x86 lowering is Phase 4. */

/* Guest memory loads/stores via [xG, wAddr, uxtw] */
void a64_emit_guest_ldr_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_str_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrd_w(a64_buf_t *b, unsigned rt, unsigned rt2, unsigned addr_w);
void a64_emit_guest_strd_w(a64_buf_t *b, unsigned rt, unsigned rt2, unsigned addr_w);
void a64_emit_guest_ldrb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrsb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_strb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrsh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_strh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);

/* Host context loads/stores via [Xn, #byte_offset] */
void a64_emit_ldrb_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_strb_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_ldrh_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_strh_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_ldr_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_str_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);

/* a32rt's ctx VFP accessor family (a64_emit_ldr/str_{s,d,q}_ctx over the
 * vfp_d register file at A32_CTX_VFP_OFFSET) was dropped (D10): the Phase 4
 * DBT emits x87_st/xmm accessors for the i686_ctx_t layout itself. */

/* Guest memory FP loads/stores via [xG, wAddr, uxtw] */
void a64_emit_guest_ldr_s(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_str_s(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_ldr_d(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_str_d(a64_buf_t *b, unsigned vt, unsigned addr_w);

/* Scalar FP instructions */
void a64_emit_fmov_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_fmov_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvt_s_to_d(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_fcvt_d_to_s(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_fcvtzs_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzu_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzs_d_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzu_d_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_scvtf_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_ucvtf_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_scvtf_w_to_d(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_ucvtf_w_to_d(a64_buf_t *b, unsigned vd, unsigned rn_w);

/* ARMv8-A Crypto extensions (AES, PMULL, SHA1, SHA256) */
void a64_emit_aese(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_aesd(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_aesmc(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_aesimc(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_pmull_1q(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1c(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1p(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1m(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1su0(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha1h(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_sha1su1(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_sha256h(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha256h2(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);
void a64_emit_sha256su0(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_sha256su1(a64_buf_t *b, unsigned vd, unsigned vn, unsigned vm);

/* Exclusives & barriers */
void a64_emit_ldxr_b(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_b(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_h(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_h(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_w(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_w(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_x(a64_buf_t *b, unsigned rt_x, unsigned rn_x);
void a64_emit_stxr_x(a64_buf_t *b, unsigned rs_w, unsigned rt_x, unsigned rn_x);
void a64_emit_clrex(a64_buf_t *b);
void a64_emit_dmb_ish(a64_buf_t *b);
void a64_emit_dsb_ish(a64_buf_t *b);
void a64_emit_isb(a64_buf_t *b);

/* Branches & block exits */
size_t a64_emit_b_cond_placeholder(a64_buf_t *b, unsigned cond);
void   a64_patch_b_cond(a64_buf_t *b, size_t patch_idx, size_t target_idx);
size_t a64_emit_cbz_w_placeholder(a64_buf_t *b, bool is_cbnz, unsigned rt);
void   a64_patch_cbz_w(a64_buf_t *b, size_t patch_idx, size_t target_idx);
void   a64_emit_ret(a64_buf_t *b);

/* Standard fragment exit sequences */
void a64_emit_exit_branch(a64_buf_t *b, uint32_t target_pc);
/* a32rt's a64_emit_exit_branch_imm()/interworking exits were dropped: x86 has
 * a single instruction set (no CPSR.T bit); every indirect branch goes through
 * a64_emit_exit_branch_reg()'s RAS/IBTC dispatch. */
void a64_emit_exit_branch_reg(a64_buf_t *b, unsigned target_reg);
void a64_emit_exit_syscall(a64_buf_t *b, uint32_t next_pc, uint32_t syscall_nr);
void a64_emit_exit_undef(a64_buf_t *b, uint32_t fault_pc);
void a64_emit_exit_trap(a64_buf_t *b, uint32_t trap_pc);

/* a32rt's decoder entry points (a32_translate_a32_block &c) were dropped:
 * the x86 decoders arrive with the Phase 3/4 DBT (src/interp/, src/dbt/). */

#endif /* A64_EMIT_H */
