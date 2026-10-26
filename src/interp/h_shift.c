/*
 * src/interp/h_shift.c — ROL/ROR/RCL/RCR/SHL(SAL)/SHR/SAR interpreter
 * handlers (lane L1e, docs/lanes/phase-1.md).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * One handler per operation; each covers all six encoding forms because
 * the operand kinds carry everything the handler needs:
 *   opnd[0] = I686_OPND_RM8 -> 8-bit form, otherwise 16-bit with a 66
 *   prefix, 32-bit without (opnd[0] = RM32/RM16 per the descriptor).
 *   opnd[1] = I686_OPND_ONE (shift by 1), I686_OPND_CL (count in CL),
 *   I686_OPND_I8 (count in insn->imm).
 * The count is masked to 5 bits for every width (i686 legacy rule), so a
 * masked count of 0 (explicit 0, or 32/64 wrapping to 0) is a full no-op:
 * no result write and no flag change.
 *
 * Flag policy (SPEC D6; these ops set flags EAGERLY, never via the lazy
 * descriptor):
 *  - SHL/SHR/SAR: CF = last bit shifted out; OF defined only for
 *    count==1 (SHL: CF ^ MSB(result), SHR: MSB(operand), SAR: 0);
 *    SF/ZF/PF from the result via i686_flags_logiczx (which also drops
 *    the lazy descriptor); AF is architecturally undefined and is left
 *    as-is in ctx->eflags.
 *  - ROL/ROR: CF = LSB/MSB of the result (defined for every count != 0,
 *    even when the value is unchanged, e.g. ROL16 by 16); OF only for
 *    count==1 (ROL: CF ^ MSB(result), ROR: two MSBs of the result);
 *    SF/ZF/PF/AF are architecturally undefined and preserved — the
 *    previous architectural values are materialized first so only CF/OF
 *    change.
 *  - RCL/RCR: rotate the (CF | operand) entity of width+1 bits by the
 *    masked count (mod width+1); CF = the entity's CF bit afterwards
 *    (the last bit rotated through), OF only for count==1 (RCL:
 *    MSB(result) ^ CF, RCR: two MSBs of the result); the other flags are
 *    preserved as for ROL/ROR.
 *
 * LOCK on a memory operand selects a true C11 atomic RMW on the HVA
 * (Wave U3, UNIFICATION-PLAN 4.4): a SEQ_CST load / strong-CAS retry loop
 * around the same pure result function, so concurrent LOCK peers on
 * sibling threads (DBT or interpreter) never lose an update.
 * Handlers never modify ctx->eip; the interpreter loop owns control flow.
 */

#include <stdbool.h>
#include <stdint.h>

#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"

extern uint8_t x86_ea_seg(const x86_insn_t *insn);
extern void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg, uint32_t linear,
                                unsigned bytes);
/* RC-U3 split lock (defined in src/dbt/aot/aot.c). */
extern void i686_split_lock_acquire(void);
extern void i686_split_lock_release(void);
extern bool i686_mem_is_unaligned(const void *p, unsigned width);
extern bool i686_span_mapped_writable(const i686_ctx_t *ctx, uint32_t ea,
                                      unsigned bytes);

/* RC-U3 unaligned entry: NULL = run the __atomic_* CAS path; otherwise
 * the split lock is held (0/1 encoded in *held) and the caller runs the
 * byte-wise plain path, then calls sh_lock_leave. */
static void *sh_lock_enter(i686_ctx_t *ctx, const x86_insn_t *insn,
                           unsigned w, int *held)
{
    uint32_t ea = x86_ea_compute(ctx, insn);
    void *hva;

    *held = 0;
    i686_seg_check_data(ctx, x86_ea_seg(insn), ea, w / 8U);
    hva = i686_guest_ptr(ctx, ea);
    if (!i686_mem_is_unaligned(hva, w)) {
        return hva;
    }
    if (i686_span_mapped_writable(ctx, ea, w / 8U)) {
        i686_split_lock_acquire();
        *held = 1;
    }
    return NULL;
}

static void sh_lock_leave(int held)
{
    if (held != 0) {
        i686_split_lock_release();
    }
}

static bool sh_locked_mem(const x86_insn_t *insn)
{
    return insn->pfx_lock != 0U && insn->modrm_mod != 3U && insn->ea_has != 0U;
}

static uint32_t sh_atomic_load_u(void *p, unsigned w)
{
    if (w == 8U) {
        return __atomic_load_n((const uint8_t *)p, __ATOMIC_SEQ_CST);
    }
    if (w == 16U) {
        return __atomic_load_n((const uint16_t *)p, __ATOMIC_SEQ_CST);
    }
    return __atomic_load_n((const uint32_t *)p, __ATOMIC_SEQ_CST);
}

static bool sh_atomic_cas_u(void *p, unsigned w, uint32_t expected,
                            uint32_t desired)
{
    if (w == 8U) {
        uint8_t e = (uint8_t)expected;
        return __atomic_compare_exchange_n((uint8_t *)p, &e, (uint8_t)desired,
                                           false, __ATOMIC_SEQ_CST,
                                           __ATOMIC_SEQ_CST);
    }
    if (w == 16U) {
        uint16_t e = (uint16_t)expected;
        return __atomic_compare_exchange_n((uint16_t *)p, &e,
                                           (uint16_t)desired, false,
                                           __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }
    {
        uint32_t e = expected;
        return __atomic_compare_exchange_n((uint32_t *)p, &e, desired, false,
                                           __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }
}

static unsigned sh_width(const x86_insn_t *insn)
{
    if (insn->opnd[0] == I686_OPND_RM8) {
        return 8U;
    }
    return insn->pfx_opsize ? 16U : 32U;
}

static uint32_t sh_mask(unsigned w)
{
    if (w == 8U) {
        return 0xFFU;
    }
    if (w == 16U) {
        return 0xFFFFU;
    }
    return 0xFFFFFFFFU;
}

/* Shift count from the operand kind, masked to 5 bits (i686 rule). */
static uint32_t sh_count(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t c;

    switch (insn->opnd[1]) {
    case I686_OPND_ONE:
        c = 1U;
        break;
    case I686_OPND_CL:
        c = x86_reg_read(ctx, I686_REG_ECX, 8);
        break;
    default: /* I686_OPND_I8 */
        c = insn->imm & 0xFFU;
        break;
    }
    return c & 31U;
}

/* Rotate the low `bits` bits of x left by n (n taken mod bits; a
 * rotation of the whole entity is the identity).  bits <= 33. */
static uint64_t sh_rotl(uint64_t x, uint32_t n, unsigned bits)
{
    uint64_t mask = (UINT64_C(1) << bits) - UINT64_C(1);

    n %= bits;
    if (n == 0U) {
        return x & mask;
    }
    return ((x << n) | (x >> (bits - n))) & mask;
}

static void sh_set_cf(i686_ctx_t *ctx, unsigned cf)
{
    if (cf != 0U) {
        ctx->eflags |= I686_EF_CF;
    } else {
        ctx->eflags &= ~(uint32_t)I686_EF_CF;
    }
}

static void sh_set_of(i686_ctx_t *ctx, unsigned of)
{
    if (of != 0U) {
        ctx->eflags |= I686_EF_OF;
    } else {
        ctx->eflags &= ~(uint32_t)I686_EF_OF;
    }
}

/* C0-C3 /0 — SHL/SAL. */
static int h_shl(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = sh_width(insn);
    uint32_t cnt = sh_count(ctx, insn);
    uint32_t val, res;
    void *lp;
    unsigned cf;

    if (cnt == 0U) {
        { ctx->eip += insn->len; return I686_INTERP_CONTINUE; } /* no write, no flags */
    }
    int held = 0;
    lp = sh_locked_mem(insn) ? sh_lock_enter(ctx, insn, w, &held) : NULL;
    if (lp == NULL) {
        val = x86_rm_read(ctx, insn, w);
        res = (uint32_t)(((uint64_t)val << cnt) & sh_mask(w));
        x86_rm_write(ctx, insn, w, res);
    } else {
        for (;;) {
            val = sh_atomic_load_u(lp, w);
            res = (uint32_t)(((uint64_t)val << cnt) & sh_mask(w));
            if (sh_atomic_cas_u(lp, w, val, res)) {
                break;
            }
        }
    }
    /* Z/S/P from the result; CF=OF=0 (OF patched below); AF undefined. */
    i686_flags_logiczx(ctx, res, w);
    cf = (cnt <= w) ? ((val >> (w - cnt)) & 1U) : 0U;
    sh_set_cf(ctx, cf);
    if (cnt == 1U) {
        sh_set_of(ctx, cf ^ ((res >> (w - 1U)) & 1U));
    }
    sh_lock_leave(held);
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* C0-C3 /5 — SHR. */
static int h_shr(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = sh_width(insn);
    uint32_t cnt = sh_count(ctx, insn);
    uint32_t val, res;
    void *lp;

    if (cnt == 0U) {
        { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
    }
    int held = 0;
    lp = sh_locked_mem(insn) ? sh_lock_enter(ctx, insn, w, &held) : NULL;
    if (lp == NULL) {
        val = x86_rm_read(ctx, insn, w);
        res = (val >> cnt) & sh_mask(w); /* val is zero-extended: logical */
        x86_rm_write(ctx, insn, w, res);
    } else {
        for (;;) {
            val = sh_atomic_load_u(lp, w);
            res = (val >> cnt) & sh_mask(w);
            if (sh_atomic_cas_u(lp, w, val, res)) {
                break;
            }
        }
    }
    i686_flags_logiczx(ctx, res, w);
    sh_set_cf(ctx, (val >> (cnt - 1U)) & 1U);
    if (cnt == 1U) {
        sh_set_of(ctx, (val >> (w - 1U)) & 1U); /* OF = MSB(operand) */
    }
    sh_lock_leave(held);
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* C0-C3 /7 — SAR (sign fill; no implementation-defined right shift of
 * negative values — the fill is computed explicitly). */
static uint32_t sh_sar_value(uint32_t v, unsigned w, uint32_t cnt)
{
    uint32_t m = sh_mask(w);
    uint32_t res;

    if ((v >> (w - 1U)) & 1U) {
        if (cnt >= w) {
            return m; /* all sign bits */
        }
        res = (v >> cnt) & m;
        res |= m & ~(m >> cnt); /* sign-fill the top cnt bits */
        return res;
    }
    if (cnt >= w) {
        return 0U;
    }
    return (v >> cnt) & m;
}

static int h_sar(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = sh_width(insn);
    uint32_t cnt = sh_count(ctx, insn);
    uint32_t val, res;
    void *lp;

    if (cnt == 0U) {
        { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
    }
    int held = 0;
    lp = sh_locked_mem(insn) ? sh_lock_enter(ctx, insn, w, &held) : NULL;
    if (lp == NULL) {
        val = x86_rm_read(ctx, insn, w);
        res = sh_sar_value(val, w, cnt);
        x86_rm_write(ctx, insn, w, res);
    } else {
        for (;;) {
            val = sh_atomic_load_u(lp, w);
            res = sh_sar_value(val, w, cnt);
            if (sh_atomic_cas_u(lp, w, val, res)) {
                break;
            }
        }
    }
    i686_flags_logiczx(ctx, res, w);
    if (cnt <= w) {
        sh_set_cf(ctx, (val >> (cnt - 1U)) & 1U);
    } else {
        sh_set_cf(ctx, (val >> (w - 1U)) & 1U); /* sign bit repeats */
    }
    /* count==1: OF = 0 — already cleared by i686_flags_logiczx. */
    sh_lock_leave(held);
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* C0-C3 /0 with rotate semantics — ROL. */
static int h_rol(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = sh_width(insn);
    uint32_t cnt = sh_count(ctx, insn);
    uint32_t res;
    void *lp;

    if (cnt == 0U) {
        { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
    }
    int held = 0;
    lp = sh_locked_mem(insn) ? sh_lock_enter(ctx, insn, w, &held) : NULL;
    if (lp == NULL) {
        res = (uint32_t)sh_rotl(x86_rm_read(ctx, insn, w), cnt, w);
        x86_rm_write(ctx, insn, w, res);
    } else {
        for (;;) {
            uint32_t v = sh_atomic_load_u(lp, w);
            res = (uint32_t)sh_rotl(v, cnt, w);
            if (sh_atomic_cas_u(lp, w, v, res)) {
                break;
            }
        }
    }
    /* Undefined SF/ZF/PF/AF are preserved: materialize first, then only
     * CF (and OF for count 1) change. */
    i686_flags_materialize(ctx);
    sh_set_cf(ctx, res & 1U);
    if (cnt == 1U) {
        sh_set_of(ctx, ((res >> (w - 1U)) ^ res) & 1U); /* MSB ^ CF */
    }
    sh_lock_leave(held);
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* C0-C3 /1 — ROR. */
static int h_ror(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = sh_width(insn);
    uint32_t cnt = sh_count(ctx, insn);
    uint32_t res;
    void *lp;

    if (cnt == 0U) {
        { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
    }
    int held = 0;
    lp = sh_locked_mem(insn) ? sh_lock_enter(ctx, insn, w, &held) : NULL;
    if (lp == NULL) {
        res = (uint32_t)sh_rotl(x86_rm_read(ctx, insn, w), w - (cnt % w), w);
        x86_rm_write(ctx, insn, w, res);
    } else {
        for (;;) {
            uint32_t v = sh_atomic_load_u(lp, w);
            res = (uint32_t)sh_rotl(v, w - (cnt % w), w);
            if (sh_atomic_cas_u(lp, w, v, res)) {
                break;
            }
        }
    }
    i686_flags_materialize(ctx);
    sh_set_cf(ctx, (res >> (w - 1U)) & 1U);
    if (cnt == 1U) {
        sh_set_of(ctx, ((res >> (w - 1U)) ^ (res >> (w - 2U))) & 1U);
    }
    sh_lock_leave(held);
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* C0-C3 /2 — RCL: rotate the (CF | operand) entity of w+1 bits. */
static int h_rcl(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = sh_width(insn);
    uint32_t cnt = sh_count(ctx, insn);
    uint64_t entity, rotd;
    uint32_t res;
    unsigned cf_in, cf_out;
    void *lp;

    if (cnt == 0U) {
        { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
    }
    /* CF in can live in the lazy descriptor: materialize before use. */
    i686_flags_materialize(ctx);
    cf_in = (ctx->eflags & I686_EF_CF) ? 1U : 0U;
    int held = 0;
    lp = sh_locked_mem(insn) ? sh_lock_enter(ctx, insn, w, &held) : NULL;
    if (lp == NULL) {
        entity = ((uint64_t)cf_in << w) | x86_rm_read(ctx, insn, w);
        rotd = sh_rotl(entity, cnt, w + 1U);
        res = (uint32_t)(rotd & sh_mask(w));
        cf_out = (unsigned)((rotd >> w) & 1U);
        x86_rm_write(ctx, insn, w, res);
    } else {
        for (;;) {
            uint32_t v = sh_atomic_load_u(lp, w);
            entity = ((uint64_t)cf_in << w) | v;
            rotd = sh_rotl(entity, cnt, w + 1U);
            res = (uint32_t)(rotd & sh_mask(w));
            cf_out = (unsigned)((rotd >> w) & 1U);
            if (sh_atomic_cas_u(lp, w, v, res)) {
                break;
            }
        }
    }
    sh_set_cf(ctx, cf_out);
    if (cnt == 1U) {
        sh_set_of(ctx, ((res >> (w - 1U)) & 1U) ^ cf_out); /* MSB ^ CF */
    }
    sh_lock_leave(held);
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* C0-C3 /3 — RCR. */
static int h_rcr(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = sh_width(insn);
    uint32_t cnt = sh_count(ctx, insn);
    uint64_t entity, rotd;
    uint32_t res;
    unsigned cf_in, cf_out;
    void *lp;

    if (cnt == 0U) {
        { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
    }
    i686_flags_materialize(ctx);
    cf_in = (ctx->eflags & I686_EF_CF) ? 1U : 0U;
    int held = 0;
    lp = sh_locked_mem(insn) ? sh_lock_enter(ctx, insn, w, &held) : NULL;
    if (lp == NULL) {
        entity = ((uint64_t)cf_in << w) | x86_rm_read(ctx, insn, w);
        rotd = sh_rotl(entity, (w + 1U) - (cnt % (w + 1U)), w + 1U);
        res = (uint32_t)(rotd & sh_mask(w));
        cf_out = (unsigned)((rotd >> w) & 1U);
        x86_rm_write(ctx, insn, w, res);
    } else {
        for (;;) {
            uint32_t v = sh_atomic_load_u(lp, w);
            entity = ((uint64_t)cf_in << w) | v;
            rotd = sh_rotl(entity, (w + 1U) - (cnt % (w + 1U)), w + 1U);
            res = (uint32_t)(rotd & sh_mask(w));
            cf_out = (unsigned)((rotd >> w) & 1U);
            if (sh_atomic_cas_u(lp, w, v, res)) {
                break;
            }
        }
    }
    sh_set_cf(ctx, cf_out);
    if (cnt == 1U) {
        sh_set_of(ctx, ((res >> (w - 1U)) ^ (res >> (w - 2U))) & 1U);
    }
    sh_lock_leave(held);
    { ctx->eip += insn->len; return I686_INTERP_CONTINUE; }
}

/* Registered from i686_interp_muldiv_init() (h_muldiv.c): the whole G2
 * shift/rotate family lives on this lane. */
void i686_interp_shift_init(void)
{
    i686_interp_register(I686_OP_ROL_Eb1, h_rol);
    i686_interp_register(I686_OP_ROL_Ev1, h_rol);
    i686_interp_register(I686_OP_ROL_EbCL, h_rol);
    i686_interp_register(I686_OP_ROL_EvCL, h_rol);
    i686_interp_register(I686_OP_ROL_EbIb, h_rol);
    i686_interp_register(I686_OP_ROL_EvIb, h_rol);
    i686_interp_register(I686_OP_ROR_Eb1, h_ror);
    i686_interp_register(I686_OP_ROR_Ev1, h_ror);
    i686_interp_register(I686_OP_ROR_EbCL, h_ror);
    i686_interp_register(I686_OP_ROR_EvCL, h_ror);
    i686_interp_register(I686_OP_ROR_EbIb, h_ror);
    i686_interp_register(I686_OP_ROR_EvIb, h_ror);
    i686_interp_register(I686_OP_RCL_Eb1, h_rcl);
    i686_interp_register(I686_OP_RCL_Ev1, h_rcl);
    i686_interp_register(I686_OP_RCL_EbCL, h_rcl);
    i686_interp_register(I686_OP_RCL_EvCL, h_rcl);
    i686_interp_register(I686_OP_RCL_EbIb, h_rcl);
    i686_interp_register(I686_OP_RCL_EvIb, h_rcl);
    i686_interp_register(I686_OP_RCR_Eb1, h_rcr);
    i686_interp_register(I686_OP_RCR_Ev1, h_rcr);
    i686_interp_register(I686_OP_RCR_EbCL, h_rcr);
    i686_interp_register(I686_OP_RCR_EvCL, h_rcr);
    i686_interp_register(I686_OP_RCR_EbIb, h_rcr);
    i686_interp_register(I686_OP_RCR_EvIb, h_rcr);
    i686_interp_register(I686_OP_SHL_Eb1, h_shl);
    i686_interp_register(I686_OP_SHL_Ev1, h_shl);
    i686_interp_register(I686_OP_SHL_EbCL, h_shl);
    i686_interp_register(I686_OP_SHL_EvCL, h_shl);
    i686_interp_register(I686_OP_SHL_EbIb, h_shl);
    i686_interp_register(I686_OP_SHL_EvIb, h_shl);
    i686_interp_register(I686_OP_SHR_Eb1, h_shr);
    i686_interp_register(I686_OP_SHR_Ev1, h_shr);
    i686_interp_register(I686_OP_SHR_EbCL, h_shr);
    i686_interp_register(I686_OP_SHR_EvCL, h_shr);
    i686_interp_register(I686_OP_SHR_EbIb, h_shr);
    i686_interp_register(I686_OP_SHR_EvIb, h_shr);
    i686_interp_register(I686_OP_SAR_Eb1, h_sar);
    i686_interp_register(I686_OP_SAR_Ev1, h_sar);
    i686_interp_register(I686_OP_SAR_EbCL, h_sar);
    i686_interp_register(I686_OP_SAR_EvCL, h_sar);
    i686_interp_register(I686_OP_SAR_EbIb, h_sar);
    i686_interp_register(I686_OP_SAR_EvIb, h_sar);
}
