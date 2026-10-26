/*
 * src/interp/h_bit.c — bit-test, bit-scan, double-shift handlers (Phase 1 L1d)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Registered from i686_interp_branch_init (h_branch.c).  Flags policy
 * (documented choices for values the architecture leaves undefined):
 *   - BT/BTS/BTR/BTC: CF = old bit; SF/ZF/OF/AF/PF unchanged.
 *   - BSF/BSR: ZF defined (source zero); on a hit SF/PF come from the index
 *     and CF/OF are cleared (logic-op values), AF unchanged.
 *   - SHLD/SHRD: count &= 31; count 0 is a full no-op (no write, no flags);
 *     CF = last bit shifted out, OF defined only for count 1, SF/ZF/PF from
 *     the result, AF unchanged.
 */

#include <stdint.h>

#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"
#include "x86/decode.h"

/* Operand size in bits: 66 selects 16-bit operands in flat 32-bit code. */
static unsigned opnd_width(const x86_insn_t *insn)
{
    return insn->pfx_opsize != 0U ? 16U : 32U;
}

static uint32_t width_mask(unsigned width)
{
    return (width == 32U) ? 0xFFFFFFFFU : 0xFFFFU;
}

/* ------------------------------------------------------------------ */
/* BT / BTS / BTR / BTC                                                */
/* ------------------------------------------------------------------ */

enum bt_mode { BT_TEST = 0, BT_SET, BT_RESET, BT_COMPLEMENT };

/*
 * x86 bit addressing (per the frozen contract): the index is taken modulo
 * the operand width.  For a register destination it picks the bit directly;
 * for a memory destination the high bits select a byte offset from the
 * r/m effective address, bitnr>>3, and index&7 the bit inside that byte
 * (for a 32-bit operand this equals the SDM's DIV 32 / MOD 32 formula).
 */
static int bt_common(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned mode,
                     uint32_t raw_index)
{
    unsigned width = opnd_width(insn);
    unsigned index = (unsigned)(raw_index & (width - 1U));
    uint32_t bit;

    if (insn->modrm_mod == 3U) {
        /* Register destination: one width-sized read-modify-write. */
        uint32_t val = x86_reg_read(ctx, insn->modrm_rm, width);

        bit = (val >> index) & 1U;
        if (mode != (unsigned)BT_TEST) {
            uint32_t nb;

            if (mode == (unsigned)BT_SET) {
                nb = val | (1U << index);
            } else if (mode == (unsigned)BT_RESET) {
                nb = val & ~(1U << index);
            } else {
                nb = val ^ (1U << index);
            }
            x86_reg_write(ctx, insn->modrm_rm, width, nb);
        }
    } else {
        /* Memory destination: byte-granular RMW at EA + byte offset. */
        uint32_t ea = x86_ea_compute(ctx, insn);
        uint32_t byte_off = (uint32_t)(index >> 3); /* 0..width/8-1 */
        uint8_t *p = (uint8_t *)i686_guest_ptr(ctx, ea + byte_off);
        unsigned bitpos = index & 7U;

        if (insn->pfx_lock != 0U && mode != (unsigned)BT_TEST) {
            /* RC-U3 P1: LOCK BTS/BTR/BTC are atomic SEQ_CST RMWs;
             * CF extracts the old bit.  Single-byte: always aligned. */
            uint8_t mask = (uint8_t)(1U << bitpos);
            uint8_t old;
            if (mode == (unsigned)BT_SET) {
                old = __atomic_fetch_or(p, mask, __ATOMIC_SEQ_CST);
            } else if (mode == (unsigned)BT_RESET) {
                old = __atomic_fetch_and(p, (uint8_t)~mask,
                                         __ATOMIC_SEQ_CST);
            } else {
                old = __atomic_fetch_xor(p, mask, __ATOMIC_SEQ_CST);
            }
            bit = (uint32_t)(old >> bitpos) & 1U;
        } else if (insn->pfx_lock != 0U) {
            bit = (uint32_t)(__atomic_load_n(p, __ATOMIC_SEQ_CST) >>
                             bitpos) & 1U;
        } else {
            bit = (uint32_t)(*p >> bitpos) & 1U;
            if (mode == (unsigned)BT_SET) {
                *p = (uint8_t)(*p | (uint8_t)(1U << bitpos));
            } else if (mode == (unsigned)BT_RESET) {
                *p = (uint8_t)(*p & (uint8_t)~(uint8_t)(1U << bitpos));
            } else if (mode == (unsigned)BT_COMPLEMENT) {
                *p = (uint8_t)(*p ^ (uint8_t)(1U << bitpos));
            }
        }
    }

    /* CF = the tested bit; the other arithmetic flags stay untouched. */
    {
        uint32_t fl = i686_flags_read(ctx); /* materializes; lazy now NONE */

        fl = (bit != 0U) ? (fl | I686_EF_CF) : (fl & ~I686_EF_CF);
        ctx->eflags = fl;
    }

    ctx->eip += (uint32_t)insn->len;
    return I686_INTERP_CONTINUE;
}

/* _EvGv forms: the bit index is the reg-field register (its low bits are
 * all that survive the modulo, so a full 32-bit read is equivalent). */
static int h_bt_evgy(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bt_common(ctx, insn, (unsigned)BT_TEST,
                     x86_reg_read(ctx, insn->modrm_reg, 32U));
}

static int h_bts_evgy(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bt_common(ctx, insn, (unsigned)BT_SET,
                     x86_reg_read(ctx, insn->modrm_reg, 32U));
}

static int h_btr_evgy(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bt_common(ctx, insn, (unsigned)BT_RESET,
                     x86_reg_read(ctx, insn->modrm_reg, 32U));
}

static int h_btc_evgy(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bt_common(ctx, insn, (unsigned)BT_COMPLEMENT,
                     x86_reg_read(ctx, insn->modrm_reg, 32U));
}

/* _EvIb forms (0F BA /4../7): immediate index, same modulo rule. */
static int h_bt_evib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bt_common(ctx, insn, (unsigned)BT_TEST, insn->imm);
}

static int h_bts_evib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bt_common(ctx, insn, (unsigned)BT_SET, insn->imm);
}

static int h_btr_evib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bt_common(ctx, insn, (unsigned)BT_RESET, insn->imm);
}

static int h_btc_evib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bt_common(ctx, insn, (unsigned)BT_COMPLEMENT, insn->imm);
}

/* ------------------------------------------------------------------ */
/* BSF / BSR                                                           */
/* ------------------------------------------------------------------ */

static int bs_common(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned reverse)
{
    unsigned width = opnd_width(insn);
    uint32_t src = x86_rm_read(ctx, insn, width);

    if (src == 0U) {
        /* ZF = 1; the destination is undefined and left unchanged.
         * Remaining flags are undefined: keep them, set ZF only. */
        uint32_t fl = i686_flags_read(ctx);

        ctx->eflags = fl | I686_EF_ZF;
        ctx->eip += (uint32_t)insn->len;
        return I686_INTERP_CONTINUE;
    }

    /* src != 0: bounded scans (the guard also bounds the BSR underflow). */
    unsigned index;

    if (reverse == 0U) { /* BSF: least significant set bit */
        index = 0U;
        while ((index < width) && (((src >> index) & 1U) == 0U)) {
            index++;
        }
    } else { /* BSR: most significant set bit */
        index = width - 1U;
        while ((index != 0U) && (((src >> index) & 1U) == 0U)) {
            index--;
        }
    }

    x86_reg_write(ctx, insn->modrm_reg, width, (uint32_t)index);

    /* Documented choice: SF/PF from the index, CF/OF cleared (logic values),
     * AF untouched; then force ZF = 0 — ZF tracks "source was zero", not
     * "index is zero" (which logiczx would get wrong for index 0). */
    i686_flags_logiczx(ctx, (uint32_t)index, width);
    ctx->eflags &= ~I686_EF_ZF;

    ctx->eip += (uint32_t)insn->len;
    return I686_INTERP_CONTINUE;
}

static int h_bsf(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bs_common(ctx, insn, 0U);
}

static int h_bsr(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return bs_common(ctx, insn, 1U);
}

/* ------------------------------------------------------------------ */
/* SHLD / SHRD                                                         */
/* ------------------------------------------------------------------ */

/*
 * Both double shifts operate on the 2*width-bit concatenation of the two
 * operands: SHLD on dest:src (dest in the high half), SHRD on src:dest
 * (dest in the low half).  Counting windows off the concatenation keeps
 * every shift amount in [0, 63] — no negative or width-wide shifts — and
 * reproduces the SDM formulas for counts below the width.
 */
static int dshift_common(i686_ctx_t *ctx, const x86_insn_t *insn,
                         unsigned is_shrd, unsigned count)
{
    unsigned width = opnd_width(insn);
    unsigned cnt = count & 31U; /* CountMask = 31 at both operand sizes */

    uint32_t dest = x86_rm_read(ctx, insn, width);
    uint32_t src = x86_reg_read(ctx, insn->modrm_reg, width);

    if (cnt == 0U) {
        /* No-op: destination and flags are untouched (SDM). */
        ctx->eip += (uint32_t)insn->len;
        return I686_INTERP_CONTINUE;
    }

    {
        uint64_t v = is_shrd != 0U
                         ? (((uint64_t)src << width) | dest)  /* src:dest */
                         : (((uint64_t)dest << width) | src); /* dest:src */
        /* SHRD keeps the low half of the right shift; SHLD the high half
         * of the left shift. */
        uint64_t res64 = (is_shrd != 0U) ? (v >> cnt) : ((v << cnt) >> width);
        uint32_t res = (uint32_t)(res64 & width_mask(width));
        uint32_t cf = (uint32_t)((is_shrd != 0U) ? ((v >> (cnt - 1U)) & 1U)
                                                 : ((v >> (2U * width - cnt)) & 1U));
        uint32_t msb = 1U << (width - 1U);
        uint32_t fl;

        x86_rm_write(ctx, insn, width, res);

        /* SF/ZF/PF from the result, CF set below; OF only for count 1:
         * SHLD: OF = MSB(result) XOR CF; SHRD: OF = MSB(old dest) XOR
         * MSB(result).  AF is undefined and stays untouched. */
        i686_flags_logiczx(ctx, res, width);
        fl = ctx->eflags;
        if (cf != 0U) {
            fl |= I686_EF_CF;
        }
        if (cnt == 1U) {
            uint32_t of = (is_shrd != 0U) ? (((dest & msb) != 0U) ^ ((res & msb) != 0U))
                                          : ((((res & msb) != 0U) ^ (cf != 0U)));
            if (of != 0U) {
                fl |= I686_EF_OF;
            }
        }
        ctx->eflags = fl;
    }

    ctx->eip += (uint32_t)insn->len;
    return I686_INTERP_CONTINUE;
}

static int h_shld_ib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return dshift_common(ctx, insn, 0U, insn->imm);
}

static int h_shld_cl(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return dshift_common(ctx, insn, 0U,
                         x86_reg_read(ctx, (uint8_t)I686_REG_ECX, 8U));
}

static int h_shrd_ib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return dshift_common(ctx, insn, 1U, insn->imm);
}

static int h_shrd_cl(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return dshift_common(ctx, insn, 1U,
                         x86_reg_read(ctx, (uint8_t)I686_REG_ECX, 8U));
}

/* ------------------------------------------------------------------ */
/* Registration (called from i686_interp_branch_init)                  */
/* ------------------------------------------------------------------ */

void i686_interp_bit_init(void)
{
    i686_interp_register(I686_OP_BT_EvGv, h_bt_evgy);
    i686_interp_register(I686_OP_BTS_EvGv, h_bts_evgy);
    i686_interp_register(I686_OP_BTR_EvGv, h_btr_evgy);
    i686_interp_register(I686_OP_BTC_EvGv, h_btc_evgy);
    i686_interp_register(I686_OP_BT_EvIb, h_bt_evib);
    i686_interp_register(I686_OP_BTS_EvIb, h_bts_evib);
    i686_interp_register(I686_OP_BTR_EvIb, h_btr_evib);
    i686_interp_register(I686_OP_BTC_EvIb, h_btc_evib);
    i686_interp_register(I686_OP_BSF_GvEv, h_bsf);
    i686_interp_register(I686_OP_BSR_GvEv, h_bsr);
    i686_interp_register(I686_OP_SHLD_EvIb, h_shld_ib);
    i686_interp_register(I686_OP_SHLD_EvCL, h_shld_cl);
    i686_interp_register(I686_OP_SHRD_EvIb, h_shrd_ib);
    i686_interp_register(I686_OP_SHRD_EvCL, h_shrd_cl);
}
