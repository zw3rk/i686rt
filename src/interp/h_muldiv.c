/*
 * src/interp/h_muldiv.c — MUL/IMUL/DIV/IDIV + CWDE/CDQ interpreter handlers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L1e (docs/lanes/phase-1.md).  All handlers are registered from
 * i686_interp_muldiv_init(), which also calls i686_interp_shift_init()
 * (src/interp/h_shift.c) so one module init brings up the whole L1e set.
 *
 * Flag policy (SPEC D6, src/interp/flags.h):
 *  - MUL/IMUL define only CF and OF (CF = OF).  They are set
 *    materialize-free: lazy_op is forced to I686_FOP_NONE and CF/OF are
 *    written straight into ctx->eflags; SF/ZF/PF/AF are architecturally
 *    undefined after MUL/IMUL and simply keep whatever stale bits
 *    ctx->eflags held (any instantiation is legal — this is the cheapest).
 *  - DIV/IDIV leave all six arithmetic flags undefined: neither the lazy
 *    descriptor nor ctx->eflags is touched at all.
 *
 * Divide errors (zero divisor, unsigned quotient overflow, or signed
 * quotient overflow including the INT_MIN/-1 corner) return
 * I686_EXIT_FAULT with ctx->exit_reason = I686_EXIT_FAULT and
 * ctx->exit_arg = 0 (SIGFPE; Phase 4 turns this into a real guest
 * signal).  The fault path modifies no guest register, no memory, and no
 * flag state.
 *
 * Handlers never modify ctx->eip — the interpreter loop owns control flow
 * (it decodes at ctx->eip and advances by insn->len on CONTINUE).
 *
 * Widths come from the descriptor operand kinds: an _Eb form has
 * I686_OPND_RM8 in opnd[0]; an _Ev form is 32-bit, 16-bit with a 66
 * prefix.  Divide numerators are the double-width pairs DX:AX / EDX:EAX
 * (AX for the byte form); results are placed exactly as the i386 ISA
 * defines them (SPEC §3.4).
 */

#include <stdint.h>
#include <string.h>

#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"

/* Defined in src/interp/h_shift.c; registered from our module init. */
void i686_interp_shift_init(void);

/* Width of the single r/m operand (or Gv for IMUL_GvEv) from the frozen
 * descriptor conventions: RM8 marks the byte forms, v-forms track the 66
 * prefix. */
static unsigned md_width(const x86_insn_t *insn)
{
    if (insn->opnd[0] == I686_OPND_RM8) {
        return 8U;
    }
    return insn->pfx_opsize ? 16U : 32U;
}

static uint32_t md_mask(unsigned w)
{
    if (w == 8U) {
        return 0xFFU;
    }
    if (w == 16U) {
        return 0xFFFFU;
    }
    return 0xFFFFFFFFU;
}

/* Sign-extend the low w bits of v without any implementation-defined
 * signed conversions (Curated C11). */
static int64_t md_sext(uint32_t v, unsigned w)
{
    uint32_t m = md_mask(w);
    uint32_t x = v & m;
    if ((x & (m ^ (m >> 1U))) != 0U) {
        return (int64_t)x - ((int64_t)m + 1);
    }
    return (int64_t)x;
}

/* MUL/IMUL flags: only CF and OF are defined (always equal).  Drop the
 * lazy descriptor and write CF/OF eagerly; SF/ZF/PF/AF stay untouched in
 * ctx->eflags (architecturally undefined — documented choice). */
static void md_set_cf_of(i686_ctx_t *ctx, int set)
{
    ctx->lazy_op = I686_FOP_NONE;
    if (set) {
        ctx->eflags |= I686_EF_CF | I686_EF_OF;
    } else {
        ctx->eflags &= ~(I686_EF_CF | I686_EF_OF);
    }
}

/* Divide error: #DE → SIGFPE.  Phase 4 synthesizes the guest signal from
 * exit_reason/exit_arg; nothing else is modified here. */
static int md_divide_fault(i686_ctx_t *ctx)
{
    ctx->exit_reason = I686_EXIT_FAULT;
    ctx->exit_arg = 0U;
    return I686_EXIT_FAULT;
}

/* F6 /4, F7 /4 — unsigned multiply into the double-width accumulator. */
static int h_mul(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = md_width(insn);
    uint64_t p;

    if (w == 8U) {
        p = (uint64_t)x86_reg_read(ctx, I686_REG_EAX, 8) *
            x86_rm_read(ctx, insn, 8);
        x86_reg_write(ctx, I686_REG_EAX, 16, (uint32_t)(p & 0xFFFFU));
    } else {
        p = (uint64_t)x86_reg_read(ctx, I686_REG_EAX, w) *
            x86_rm_read(ctx, insn, w);
        x86_reg_write(ctx, I686_REG_EAX, w, (uint32_t)p);
        x86_reg_write(ctx, I686_REG_EDX, w, (uint32_t)(p >> w));
    }
    /* CF = OF = (upper half of the product != 0). */
    md_set_cf_of(ctx, (p >> w) != 0U);
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* F6 /5, F7 /5 — one-operand signed multiply into the double-width
 * accumulator. */
static int h_imul1(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = md_width(insn);
    int64_t a, b, p;

    if (w == 8U) {
        a = md_sext(x86_reg_read(ctx, I686_REG_EAX, 8), 8);
        b = md_sext(x86_rm_read(ctx, insn, 8), 8);
        p = a * b;
        x86_reg_write(ctx, I686_REG_EAX, 16, (uint32_t)p & 0xFFFFU);
    } else {
        a = md_sext(x86_reg_read(ctx, I686_REG_EAX, w), w);
        b = md_sext(x86_rm_read(ctx, insn, w), w);
        p = a * b;
        x86_reg_write(ctx, I686_REG_EAX, w, (uint32_t)p);
        x86_reg_write(ctx, I686_REG_EDX, w, (uint32_t)((uint64_t)p >> w));
    }
    /* CF = OF = 1 iff the signed product does not fit the lower half,
     * i.e. the upper half is not the sign extension of the lower half. */
    md_set_cf_of(ctx, p != md_sext((uint32_t)p, w));
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* 0F AF — two-operand signed multiply, result truncated to Gv. */

/* S1 ratified amendment: three-operand IMUL (0x69 Iz / 0x6B IbSX) —
 * dest = dest * rm * imm, truncated, with the two-operand overflow rule. */
static int h_imul3(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = insn->pfx_opsize ? 16U : 32U;
    uint32_t imm = insn->opnd[2] == I686_OPND_I8SX
                       ? (uint32_t)md_sext(insn->imm & 0xFFU, 8)
                       : (insn->pfx_opsize ? (insn->imm & 0xFFFFU) : insn->imm);
    /* dst(Gv) is the DESTINATION only: Gv = Ev * imm (two-factor product;
     * the old three-factor product poisoned every SWAR string scan). */
    int64_t p = md_sext(x86_rm_read(ctx, insn, w), w) * md_sext(imm, w);
    uint32_t res = (uint32_t)p;

    x86_reg_write(ctx, insn->modrm_reg, w, res);
    md_set_cf_of(ctx, p != md_sext(res, w));
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

static int h_imul2(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = insn->pfx_opsize ? 16U : 32U;
    int64_t p = md_sext(x86_reg_read(ctx, insn->modrm_reg, w), w) *
                md_sext(x86_rm_read(ctx, insn, w), w);
    uint32_t res = (uint32_t)p;

    x86_reg_write(ctx, insn->modrm_reg, w, res);
    md_set_cf_of(ctx, p != md_sext(res, w));
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* F6 /6, F7 /6 — unsigned divide; quotient overflow or /0 faults. */
static int h_div(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = md_width(insn);

    if (w == 8U) {
        uint32_t tmp = x86_reg_read(ctx, I686_REG_EAX, 16); /* AX */
        uint32_t d = x86_rm_read(ctx, insn, 8);
        uint32_t q, r;
        if (d == 0U) {
            return md_divide_fault(ctx);
        }
        q = tmp / d;
        if (q > 0xFFU) {
            return md_divide_fault(ctx);
        }
        r = tmp % d;
        /* AL = quotient, AH = remainder (one 16-bit write covers both). */
        x86_reg_write(ctx, I686_REG_EAX, 16, (q & 0xFFU) | ((r & 0xFFU) << 8));
    } else if (w == 16U) {
        uint32_t tmp = (x86_reg_read(ctx, I686_REG_EDX, 16) << 16) |
                       x86_reg_read(ctx, I686_REG_EAX, 16);
        uint32_t d = x86_rm_read(ctx, insn, 16);
        uint32_t q;
        if (d == 0U) {
            return md_divide_fault(ctx);
        }
        q = tmp / d;
        if (q > 0xFFFFU) {
            return md_divide_fault(ctx);
        }
        x86_reg_write(ctx, I686_REG_EAX, 16, q);
        x86_reg_write(ctx, I686_REG_EDX, 16, tmp % d);
    } else {
        uint64_t tmp = ((uint64_t)x86_reg_read(ctx, I686_REG_EDX, 32) << 32) |
                       x86_reg_read(ctx, I686_REG_EAX, 32);
        uint64_t d = x86_rm_read(ctx, insn, 32);
        uint64_t q;
        if (d == 0U) {
            return md_divide_fault(ctx);
        }
        q = tmp / d;
        if (q > 0xFFFFFFFFULL) {
            return md_divide_fault(ctx);
        }
        x86_reg_write(ctx, I686_REG_EAX, 32, (uint32_t)q);
        x86_reg_write(ctx, I686_REG_EDX, 32, (uint32_t)(tmp % d));
    }
    /* All arithmetic flags are architecturally undefined: untouched. */
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* F6 /7, F7 /7 — signed divide (quotients truncate toward zero,
 * remainder takes the sign of the dividend, as in C99 and the i386). */
static int h_idiv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = md_width(insn);
    int64_t tmp, d, q, r, qmin, qmax;

    if (w == 8U) {
        tmp = md_sext(x86_reg_read(ctx, I686_REG_EAX, 16), 16); /* AX */
        d = md_sext(x86_rm_read(ctx, insn, 8), 8);
        qmin = -128;
        qmax = 127;
    } else if (w == 16U) {
        tmp = md_sext((x86_reg_read(ctx, I686_REG_EDX, 16) << 16) |
                          x86_reg_read(ctx, I686_REG_EAX, 16),
                      32);
        d = md_sext(x86_rm_read(ctx, insn, 16), 16);
        qmin = -32768;
        qmax = 32767;
    } else {
        uint64_t u = ((uint64_t)x86_reg_read(ctx, I686_REG_EDX, 32) << 32) |
                     x86_reg_read(ctx, I686_REG_EAX, 32);
        memcpy(&tmp, &u, sizeof tmp); /* u64 -> i64, no conversions */
        d = md_sext(x86_rm_read(ctx, insn, 32), 32);
        qmin = INT64_C(-2147483648);
        qmax = INT64_C(2147483647);
    }
    if (d == 0) {
        return md_divide_fault(ctx);
    }
    if (tmp == INT64_MIN && d == -1) {
        return md_divide_fault(ctx); /* INT64_MIN/-1 overflows i64 itself */
    }
    q = tmp / d;
    r = tmp % d;
    if (q < qmin || q > qmax) {
        return md_divide_fault(ctx); /* quotient does not fit signed w */
    }
    if (w == 8U) {
        /* AL = quotient, AH = remainder (one 16-bit write covers both). */
        x86_reg_write(ctx, I686_REG_EAX, 16,
                      ((uint32_t)q & 0xFFU) | (((uint32_t)r & 0xFFU) << 8));
    } else if (w == 16U) {
        x86_reg_write(ctx, I686_REG_EAX, 16, (uint32_t)q & 0xFFFFU);
        x86_reg_write(ctx, I686_REG_EDX, 16, (uint32_t)r & 0xFFFFU);
    } else {
        x86_reg_write(ctx, I686_REG_EAX, 32, (uint32_t)q);
        x86_reg_write(ctx, I686_REG_EDX, 32, (uint32_t)r);
    }
    /* All arithmetic flags are architecturally undefined: untouched. */
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* 98 — CWDE: widen half of the accumulator by sign (EAX = sext(AX); with
 * a 66 prefix the 8086 CBW placement AX = sext(AL) — same handler, the
 * width picks the halves). */
static int h_cwde(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->pfx_opsize) {
        uint32_t al = x86_reg_read(ctx, I686_REG_EAX, 8);
        x86_reg_write(ctx, I686_REG_EAX, 16, (uint32_t)md_sext(al, 8) & 0xFFFFU);
    } else {
        uint32_t ax = x86_reg_read(ctx, I686_REG_EAX, 16);
        x86_reg_write(ctx, I686_REG_EAX, 32, (uint32_t)md_sext(ax, 16));
    }
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* 99 — CDQ: EDX = (EAX < 0) ? ~0 : 0 (with a 66 prefix the CWD placement
 * DX = sext(AX<0)).  No flags. */
static int h_cdq(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = insn->pfx_opsize ? 16U : 32U;
    uint32_t v = x86_reg_read(ctx, I686_REG_EAX, w);

    if ((v >> (w - 1U)) & 1U) {
        x86_reg_write(ctx, I686_REG_EDX, w, 0xFFFFFFFFU >> (32U - w));
    } else {
        x86_reg_write(ctx, I686_REG_EDX, w, 0U);
    }
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

void i686_interp_muldiv_init(void)
{
    i686_interp_register(I686_OP_MUL_Eb, h_mul);
    i686_interp_register(I686_OP_MUL_Ev, h_mul);
    i686_interp_register(I686_OP_IMUL_Eb, h_imul1);
    i686_interp_register(I686_OP_IMUL_Ev, h_imul1);
    i686_interp_register(I686_OP_IMUL_GvEv, h_imul2);
    i686_interp_register(I686_OP_IMUL_GvEvIz, h_imul3);
    i686_interp_register(I686_OP_IMUL_GvEvIb, h_imul3);
    i686_interp_register(I686_OP_DIV_Eb, h_div);
    i686_interp_register(I686_OP_DIV_Ev, h_div);
    i686_interp_register(I686_OP_IDIV_Eb, h_idiv);
    i686_interp_register(I686_OP_IDIV_Ev, h_idiv);
    i686_interp_register(I686_OP_CWDE, h_cwde);
    i686_interp_register(I686_OP_CDQ, h_cdq);
    i686_interp_shift_init(); /* rest of the L1e set (src/interp/h_shift.c) */
}
