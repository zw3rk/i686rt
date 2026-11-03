/*
 * src/interp/h_alu.c — integer ALU interpreter handlers (Phase 1, lane L1b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * ADD/OR/ADC/SBB/AND/SUB/XOR/CMP in all nine frozen forms plus TEST, XCHG,
 * INC/DEC (CF preserved), NEG, NOT, CMPXCHG and XADD, per the opcode-id
 * contract in docs/lanes/phase-1.md.  Flags stay lazy (SPEC D6): handlers
 * only record descriptors via src/interp/flags.h and force materialization
 * exactly where the architecture needs the previous value (ADC/SBB carry-in,
 * INC/DEC carry preservation).  LOCK (and implicit XCHG/CMPXCHG/XADD
 * mem forms) selects true C11 __atomic_* RMWs on the HVA (4.4).  All
 * operand values are masked to the operand width before use, so the
 * lazy descriptor stays width-faithful.
 */

#include <stdbool.h>
#include <stdint.h>

#include "flags.h"
#include "interp.h"

/* Operand forms of the frozen ALU contract (dest, src in Intel order). */
typedef enum {
    FORM_EbGb,  /* r/m8      <- r8                      */
    FORM_EvGv,  /* r/m       <- r16/32                 */
    FORM_GbEb,  /* r8        <- r/m8                   */
    FORM_GvEv,  /* r16/32    <- r/m                    */
    FORM_ALIb,  /* AL        <- imm8                   */
    FORM_eAXIz, /* eAX       <- imm (16 when 66)       */
    FORM_EbIb,  /* r/m8      <- imm8                   */
    FORM_EvIz,  /* r/m       <- imm (z)                */
    FORM_EvIbSX /* r/m       <- imm8 sign-extended     */
} alu_form_t;

/* CMP is SUB without writeback; TEST is its own kind (AND, no writeback). */
typedef enum {
    ALU_ADD,
    ALU_ADC,
    ALU_AND,
    ALU_CMP,
    ALU_OR,
    ALU_SBB,
    ALU_SUB,
    ALU_TEST,
    ALU_XOR
} alu_kind_t;

static uint32_t width_mask(unsigned width)
{
    if (width == 8U) {
        return 0xFFU;
    }
    if (width == 16U) {
        return 0xFFFFU;
    }
    return 0xFFFFFFFFU;
}

/* v-form width: 66 prefix selects 16-bit operands. */
static unsigned v_width(const x86_insn_t *insn)
{
    return insn->pfx_opsize != 0U ? 16U : 32U;
}

/* imm8 sign-extended to 32 bits without implementation-defined conversions:
 * xor/sub on the biased value wraps in unsigned arithmetic. */
static uint32_t sext_imm8(uint32_t imm)
{
    return ((imm & 0xFFU) ^ 0x80U) - 0x80U;
}

/* True when the descriptor marks operand 0 as a plain register (the 40+r
 * style single-register encodings share ids with the FE/FF rm forms; the
 * register then lives in modrm_reg rather than modrm_rm). */
static bool opnd0_is_reg(const x86_insn_t *insn)
{
    return insn->opnd[0] == I686_OPND_R8 || insn->opnd[0] == I686_OPND_R16 ||
           insn->opnd[0] == I686_OPND_R32;
}

/* Advance to the next instruction (every handler below is non-terminal). */
static int step(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

/* Wave U3 LOCK-atomics: LOCK mem RMWs use __atomic_* SEQ_CST on the
 * HVA; mem-form XCHG/CMPXCHG/XADD are implicitly locked. */

extern uint8_t x86_ea_seg(const x86_insn_t *insn);
extern void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg, uint32_t linear,
                                unsigned bytes, unsigned write);
/* RC-U3 split lock + span validator (defined in src/dbt/aot/aot.c). */
extern void i686_split_lock_acquire(void);
extern void i686_split_lock_release(void);
extern bool i686_mem_is_unaligned(const void *p, unsigned width);
extern bool i686_span_mapped_writable(const i686_ctx_t *ctx, uint32_t ea,
                                      unsigned bytes);
extern int h_CMPXCHG8B(i686_ctx_t *ctx, const x86_insn_t *insn);

static bool alu_locked_mem(const x86_insn_t *insn, bool dst_is_rm)
{
    return dst_is_rm && insn->pfx_lock != 0U && insn->modrm_mod != 3U &&
           insn->ea_has != 0U;
}

static bool alu_mem_operand(const x86_insn_t *insn)
{
    return insn->modrm_mod != 3U && insn->ea_has != 0U;
}

/* LOCK/atomics helpers (h_alu_lock.c, split for the 900-line gate). */
extern void *alu_locked_hva(i686_ctx_t *ctx, const x86_insn_t *insn,
                            unsigned width);
extern uint32_t mem_atomic_load_u(void *p, unsigned width);

/* Unified fetch-op for the aligned LOCK path (every caller holds the
 * lane split lock; the hardware op stays atomic against DBT CASAL peers
 * while the lock orders interpreter peers). */
static uint32_t mem_atomic_fetch_op(void *p, unsigned width, uint32_t v,
                                    alu_kind_t op)
{
    if (width == 8U) {
        uint8_t *q = (uint8_t *)p;
        uint8_t vv = (uint8_t)v;
        switch (op) {
        case ALU_SUB: return __atomic_fetch_sub(q, vv, __ATOMIC_SEQ_CST);
        case ALU_AND: return __atomic_fetch_and(q, vv, __ATOMIC_SEQ_CST);
        case ALU_OR:  return __atomic_fetch_or(q, vv, __ATOMIC_SEQ_CST);
        case ALU_XOR: return __atomic_fetch_xor(q, vv, __ATOMIC_SEQ_CST);
        default:      return __atomic_fetch_add(q, vv, __ATOMIC_SEQ_CST);
        }
    }
    if (width == 16U) {
        uint16_t *q = (uint16_t *)p;
        uint16_t vv = (uint16_t)v;
        switch (op) {
        case ALU_SUB: return __atomic_fetch_sub(q, vv, __ATOMIC_SEQ_CST);
        case ALU_AND: return __atomic_fetch_and(q, vv, __ATOMIC_SEQ_CST);
        case ALU_OR:  return __atomic_fetch_or(q, vv, __ATOMIC_SEQ_CST);
        case ALU_XOR: return __atomic_fetch_xor(q, vv, __ATOMIC_SEQ_CST);
        default:      return __atomic_fetch_add(q, vv, __ATOMIC_SEQ_CST);
        }
    }
    switch (op) {
    case ALU_SUB: return __atomic_fetch_sub((uint32_t *)p, v, __ATOMIC_SEQ_CST);
    case ALU_AND: return __atomic_fetch_and((uint32_t *)p, v, __ATOMIC_SEQ_CST);
    case ALU_OR:  return __atomic_fetch_or((uint32_t *)p, v, __ATOMIC_SEQ_CST);
    case ALU_XOR: return __atomic_fetch_xor((uint32_t *)p, v, __ATOMIC_SEQ_CST);
    default:      return __atomic_fetch_add((uint32_t *)p, v, __ATOMIC_SEQ_CST);
    }
}

extern uint32_t mem_atomic_exchange_u(void *p, unsigned width, uint32_t v);
extern unsigned alu_lock_enter(i686_ctx_t *ctx, const x86_insn_t *insn,
                               unsigned width);
extern void alu_lock_leave(unsigned how);

/* Strong CAS: true exactly when *p == expected (then *p = desired). */
static bool mem_atomic_cas(void *p, unsigned width, uint32_t expected,
                           uint32_t desired)
{
    uint8_t e8;
    uint16_t e16;
    uint32_t e32;
    if (width == 8U) {
        e8 = (uint8_t)expected;
        return __atomic_compare_exchange_n((uint8_t *)p, &e8, (uint8_t)desired,
                                           false, __ATOMIC_SEQ_CST,
                                           __ATOMIC_SEQ_CST);
    }
    if (width == 16U) {
        e16 = (uint16_t)expected;
        return __atomic_compare_exchange_n((uint16_t *)p, &e16,
                                           (uint16_t)desired, false,
                                           __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    }
    e32 = expected;
    return __atomic_compare_exchange_n((uint32_t *)p, &e32, desired, false,
                                       __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
}

/* ---- binary ALU executor -------------------------------------------- */

/* LOCK-prefixed mem-dst ALU op (EbGb/EvGv/EbIb/EvIz/EvIbSX): C11 RMW on the HVA. */
static int alu_exec_locked(i686_ctx_t *ctx, const x86_insn_t *insn,
                           alu_kind_t kind, alu_form_t form)
{
    unsigned width = (form == FORM_EbGb || form == FORM_EbIb) ? 8U
                                                             : v_width(insn);
    uint32_t mask = width_mask(width);
    uint32_t b;
    void *hva;
    uint32_t old;
    uint32_t res;
    switch (form) {
    case FORM_EbGb:
        b = x86_reg_read(ctx, insn->modrm_reg, 8U) & 0xFFU;
        break;
    case FORM_EvGv:
        b = x86_reg_read(ctx, insn->modrm_reg, width) & mask;
        break;
    case FORM_EbIb:
        b = insn->imm & 0xFFU;
        break;
    case FORM_EvIz:
        b = insn->imm & mask;
        break;
    default: /* FORM_EvIbSX */
        b = sext_imm8(insn->imm) & mask;
        break;
    }
    hva = alu_locked_hva(ctx, insn, width);
    switch (kind) {
    case ALU_ADD:
        old = mem_atomic_fetch_op(hva, width, b, ALU_ADD);
        res = (old + b) & mask;
        i686_flags_add(ctx, old & mask, b, width);
        break;
    case ALU_ADC: {
        uint32_t cf = (i686_flags_read(ctx) & I686_EF_CF) != 0U ? 1U : 0U;
        for (;;) {
            old = mem_atomic_load_u(hva, width) & mask;
            res = (old + b + cf) & mask;
            if (mem_atomic_cas(hva, width, old, res)) {
                break;
            }
        }
        i686_flags_adc(ctx, old, b, cf, width);
        break;
    }
    case ALU_AND:
        old = mem_atomic_fetch_op(hva, width, b, ALU_AND);
        res = (old & b) & mask;
        i686_flags_logic(ctx, res, width);
        break;
    case ALU_OR:
        old = mem_atomic_fetch_op(hva, width, b, ALU_OR);
        res = (old | b) & mask;
        i686_flags_logic(ctx, res, width);
        break;
    case ALU_XOR:
        old = mem_atomic_fetch_op(hva, width, b, ALU_XOR);
        res = (old ^ b) & mask;
        i686_flags_logic(ctx, res, width);
        break;
    case ALU_TEST:
        old = mem_atomic_load_u(hva, width) & mask;
        res = (old & b) & mask;
        i686_flags_logic(ctx, res, width);
        return step(ctx, insn);
    case ALU_SBB: {
        uint32_t cf = (i686_flags_read(ctx) & I686_EF_CF) != 0U ? 1U : 0U;
        for (;;) {
            old = mem_atomic_load_u(hva, width) & mask;
            res = (old - b - cf) & mask;
            if (mem_atomic_cas(hva, width, old, res)) {
                break;
            }
        }
        i686_flags_sbb(ctx, old, b, cf, width);
        break;
    }
    case ALU_SUB:
    case ALU_CMP:
        if (kind == ALU_CMP) {
            old = mem_atomic_load_u(hva, width) & mask;
            res = (old - b) & mask;
            i686_flags_sub(ctx, old, b, width);
            return step(ctx, insn);
        }
        old = mem_atomic_fetch_op(hva, width, b, ALU_SUB);
        res = (old - b) & mask;
        i686_flags_sub(ctx, old & mask, b, width);
        break;
    default: /* unreachable: kinds are exhaustive */
        return I686_INTERP_CONTINUE;
    }
    (void)res;
    return step(ctx, insn);
}

static int alu_exec(i686_ctx_t *ctx, const x86_insn_t *insn, alu_kind_t kind,
                    alu_form_t form)
{
    unsigned width;
    unsigned how = 2U;
    switch (form) {
    case FORM_EbGb:
    case FORM_GbEb:
    case FORM_ALIb:
    case FORM_EbIb:
        width = 8U;
        break;
    default:
        width = v_width(insn);
        break;
    }
    /* LOCK + memory destination: true C11 RMW (UNIFICATION-PLAN 4.4).
     * RC-U3: unaligned EAs run the plain byte path below, split-locked. */
    if (insn->pfx_lock != 0U &&
        (form == FORM_EbGb || form == FORM_EvGv || form == FORM_EbIb ||
         form == FORM_EvIz || form == FORM_EvIbSX) &&
        insn->modrm_mod != 3U && insn->ea_has != 0U) {
        how = alu_lock_enter(ctx, insn, width);
        if (how == 0U) {
            int locked_rc = alu_exec_locked(ctx, insn, kind, form);
            alu_lock_leave(how);
            return locked_rc;
        }
    }
    uint32_t mask = width_mask(width);

    uint32_t a = 0U;      /* destination value, width-masked   */
    uint32_t b = 0U;      /* source value, width-masked        */
    bool dst_is_rm = false;
    uint8_t dst_reg = insn->modrm_reg;

    switch (form) {
    case FORM_EbGb:
    case FORM_EvGv:
        a = x86_rm_read(ctx, insn, width) & mask;
        b = x86_reg_read(ctx, insn->modrm_reg, width) & mask;
        dst_is_rm = true;
        break;
    case FORM_GbEb:
    case FORM_GvEv:
        a = x86_reg_read(ctx, insn->modrm_reg, width) & mask;
        b = x86_rm_read(ctx, insn, width) & mask;
        break;
    case FORM_ALIb:
    case FORM_eAXIz:
        a = x86_reg_read(ctx, I686_REG_EAX, width) & mask;
        b = (form == FORM_ALIb) ? (insn->imm & 0xFFU) : (insn->imm & mask);
        dst_reg = I686_REG_EAX;
        break;
    case FORM_EbIb:
        a = x86_rm_read(ctx, insn, width) & mask;
        b = insn->imm & 0xFFU;
        dst_is_rm = true;
        break;
    case FORM_EvIz:
        a = x86_rm_read(ctx, insn, width) & mask;
        b = insn->imm & mask;
        dst_is_rm = true;
        break;
    case FORM_EvIbSX:
        a = x86_rm_read(ctx, insn, width) & mask;
        b = sext_imm8(insn->imm) & mask;
        dst_is_rm = true;
        break;
    }

    /* R7-15: the result is computed first, the faultable store commits
     * second, and flags publish last — a faulting store leaves the
     * pre-instruction flags intact for the retry. */
    uint32_t res;
    uint32_t adc_cf = 0U;
    bool writeback = true;
    switch (kind) {
    case ALU_ADD:
        res = (a + b) & mask;
        break;
    case ALU_ADC:
        adc_cf = (i686_flags_read(ctx) & I686_EF_CF) != 0U ? 1U : 0U;
        res = (a + b + adc_cf) & mask;
        break;
    case ALU_AND:
        res = (a & b) & mask;
        break;
    case ALU_OR:
        res = (a | b) & mask;
        break;
    case ALU_XOR:
        res = (a ^ b) & mask;
        break;
    case ALU_TEST:
        res = (a & b) & mask;
        writeback = false;
        break;
    case ALU_SBB:
        adc_cf = (i686_flags_read(ctx) & I686_EF_CF) != 0U ? 1U : 0U;
        res = (a - b - adc_cf) & mask;
        break;
    case ALU_SUB:
    case ALU_CMP:
        res = (a - b) & mask;
        writeback = (kind == ALU_SUB); /* CMP: no writeback */
        break;
    default: /* unreachable: kinds are exhaustive */
        res = 0U;
        writeback = false;
        break;
    }

    if (writeback) {
        if (dst_is_rm) {
            x86_rm_write(ctx, insn, width, res);
        } else {
            x86_reg_write(ctx, dst_reg, width, res);
        }
    }
    switch (kind) {
    case ALU_ADD:
        i686_flags_add(ctx, a, b, width);
        break;
    case ALU_ADC:
        i686_flags_adc(ctx, a, b, adc_cf, width);
        break;
    case ALU_AND:
    case ALU_OR:
    case ALU_XOR:
    case ALU_TEST:
        i686_flags_logic(ctx, res, width);
        break;
    case ALU_SBB:
        i686_flags_sbb(ctx, a, b, adc_cf, width);
        break;
    case ALU_SUB:
    case ALU_CMP:
        i686_flags_sub(ctx, a, b, width);
        break;
    default: /* unreachable: kinds are exhaustive */
        break;
    }
    alu_lock_leave(how);
    return step(ctx, insn);
}

/* One handler per (mnemonic, form) id; the bodies only bind the executor. */
#define DEF_ALU_FAMILY(mn, K)                                              \
    static int h_##mn##_EbGb(i686_ctx_t *c, const x86_insn_t *i)           \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_EbGb);                             \
    }                                                                      \
    static int h_##mn##_EvGv(i686_ctx_t *c, const x86_insn_t *i)           \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_EvGv);                             \
    }                                                                      \
    static int h_##mn##_GbEb(i686_ctx_t *c, const x86_insn_t *i)           \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_GbEb);                             \
    }                                                                      \
    static int h_##mn##_GvEv(i686_ctx_t *c, const x86_insn_t *i)           \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_GvEv);                             \
    }                                                                      \
    static int h_##mn##_ALIb(i686_ctx_t *c, const x86_insn_t *i)           \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_ALIb);                             \
    }                                                                      \
    static int h_##mn##_eAXIz(i686_ctx_t *c, const x86_insn_t *i)          \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_eAXIz);                            \
    }                                                                      \
    static int h_##mn##_EbIb(i686_ctx_t *c, const x86_insn_t *i)           \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_EbIb);                             \
    }                                                                      \
    static int h_##mn##_EvIz(i686_ctx_t *c, const x86_insn_t *i)           \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_EvIz);                             \
    }                                                                      \
    static int h_##mn##_EvIbSX(i686_ctx_t *c, const x86_insn_t *i)         \
    {                                                                      \
        return alu_exec(c, i, (K), FORM_EvIbSX);                           \
    }

DEF_ALU_FAMILY(ADD, ALU_ADD)
DEF_ALU_FAMILY(ADC, ALU_ADC)
DEF_ALU_FAMILY(AND, ALU_AND)
DEF_ALU_FAMILY(CMP, ALU_CMP)
DEF_ALU_FAMILY(OR, ALU_OR)
DEF_ALU_FAMILY(SBB, ALU_SBB)
DEF_ALU_FAMILY(SUB, ALU_SUB)
DEF_ALU_FAMILY(XOR, ALU_XOR)

static int h_TEST_EbGb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return alu_exec(ctx, insn, ALU_TEST, FORM_EbGb);
}

static int h_TEST_EvGv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return alu_exec(ctx, insn, ALU_TEST, FORM_EvGv);
}

static int h_TEST_ALIb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return alu_exec(ctx, insn, ALU_TEST, FORM_ALIb);
}

static int h_TEST_eAXIz(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return alu_exec(ctx, insn, ALU_TEST, FORM_eAXIz);
}

static int h_TEST_EbIb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return alu_exec(ctx, insn, ALU_TEST, FORM_EbIb);
}

static int h_TEST_EvIz(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return alu_exec(ctx, insn, ALU_TEST, FORM_EvIz);
}

/* ---- unary rm ops ----------------------------------------------------- */

static int not_exec(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width)
{
    uint32_t mask = width_mask(width);
    unsigned how = 2U;
    if (alu_locked_mem(insn, true)) {
        how = alu_lock_enter(ctx, insn, width);
        if (how == 0U) {
            void *hva = alu_locked_hva(ctx, insn, width);
            for (;;) {
                uint32_t a = mem_atomic_load_u(hva, width) & mask;
                if (mem_atomic_cas(hva, width, a, (~a) & mask)) {
                    break;
                }
            }
            alu_lock_leave(how);
            return step(ctx, insn);
        }
    }
    {
        uint32_t a = x86_rm_read(ctx, insn, width) & mask;
        x86_rm_write(ctx, insn, width, (~a) & mask); /* NOT sets no flags */
    }
    alu_lock_leave(how);
    return step(ctx, insn);
}

static int neg_exec(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width)
{
    uint32_t mask = width_mask(width);
    unsigned how = 2U;
    if (alu_locked_mem(insn, true)) {
        how = alu_lock_enter(ctx, insn, width);
        if (how == 0U) {
            void *hva = alu_locked_hva(ctx, insn, width);
            for (;;) {
                uint32_t a = mem_atomic_load_u(hva, width) & mask;
                if (mem_atomic_cas(hva, width, a, (0U - a) & mask)) {
                    i686_flags_neg(ctx, a, width);
                    break;
                }
            }
            alu_lock_leave(how);
            return step(ctx, insn);
        }
    }
    {
        uint32_t a = x86_rm_read(ctx, insn, width) & mask;
        i686_flags_neg(ctx, a, width); /* res = 0 - a is derived by flags.c */
        x86_rm_write(ctx, insn, width, (0U - a) & mask);
    }
    alu_lock_leave(how);
    return step(ctx, insn);
}

/* INC/DEC modify every arith flag except CF.  Pin the current CF into
 * ctx->eflags before recording the lazy INC/DEC descriptor so the previous
 * descriptor (which still owns CF) is materialized first. */
static int incdec_exec(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width,
                       bool is_inc)
{
    uint32_t mask = width_mask(width);
    unsigned how = 2U;
    (void)i686_flags_read(ctx);
    if (!opnd0_is_reg(insn) && alu_locked_mem(insn, true)) {
        how = alu_lock_enter(ctx, insn, width);
        if (how == 0U) {
            void *hva = alu_locked_hva(ctx, insn, width);
            for (;;) {
                uint32_t a = mem_atomic_load_u(hva, width) & mask;
                uint32_t res = (is_inc ? (a + 1U) : (a - 1U)) & mask;
                if (mem_atomic_cas(hva, width, a, res)) {
                    if (is_inc) {
                        i686_flags_inc(ctx, a, width);
                    } else {
                        i686_flags_dec(ctx, a, width);
                    }
                    break;
                }
            }
            alu_lock_leave(how);
            return step(ctx, insn);
        }
    }
    uint32_t a;
    if (opnd0_is_reg(insn)) { /* 40+r / FE-FF mod=3 share these ids */
        a = x86_reg_read(ctx, insn->modrm_reg, width) & mask;
    } else {
        a = x86_rm_read(ctx, insn, width) & mask;
    }
    uint32_t res = (is_inc ? (a + 1U) : (a - 1U)) & mask;
    if (is_inc) {
        i686_flags_inc(ctx, a, width);
    } else {
        i686_flags_dec(ctx, a, width);
    }
    if (opnd0_is_reg(insn)) {
        x86_reg_write(ctx, insn->modrm_reg, width, res);
    } else {
        x86_rm_write(ctx, insn, width, res);
    }
    alu_lock_leave(how);
    return step(ctx, insn);
}

static int h_NOT_Eb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return not_exec(ctx, insn, 8U);
}

static int h_NOT_Ev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return not_exec(ctx, insn, v_width(insn));
}

static int h_NEG_Eb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return neg_exec(ctx, insn, 8U);
}

static int h_NEG_Ev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return neg_exec(ctx, insn, v_width(insn));
}

static int h_INC_Eb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return incdec_exec(ctx, insn, 8U, true);
}

static int h_INC_Ev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return incdec_exec(ctx, insn, v_width(insn), true);
}

static int h_DEC_Eb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return incdec_exec(ctx, insn, 8U, false);
}

static int h_DEC_Ev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return incdec_exec(ctx, insn, v_width(insn), false);
}

/* ---- exchange and compare-and-swap ------------------------------------ */

static int xchg_exec(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width)
{
    uint32_t mask = width_mask(width);
    unsigned how = 2U;
    if (alu_mem_operand(insn)) {
        how = alu_lock_enter(ctx, insn, width);
        if (how == 0U) {
            /* Implicitly locked: single atomic exchange on the HVA. */
            void *hva = alu_locked_hva(ctx, insn, width);
            uint32_t b = x86_reg_read(ctx, insn->modrm_reg, width) & mask;
            uint32_t t = mem_atomic_exchange_u(hva, width, b) & mask;
            x86_reg_write(ctx, insn->modrm_reg, width, t);
            alu_lock_leave(how);
            return step(ctx, insn);
        }
    }
    {
        uint32_t t = x86_rm_read(ctx, insn, width) & mask;
        x86_rm_write(ctx, insn, width,
                     x86_reg_read(ctx, insn->modrm_reg, width) & mask);
        x86_reg_write(ctx, insn->modrm_reg, width, t);
    }
    alu_lock_leave(how);
    return step(ctx, insn);
}

static int h_XCHG_EbGb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return xchg_exec(ctx, insn, 8U);
}

static int h_XCHG_EvGv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return xchg_exec(ctx, insn, v_width(insn));
}

/* 90+r with the other register in modrm_reg (rm==0 decodes to NOP). */
static int h_XCHG_eAXGv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = v_width(insn);
    uint32_t mask = width_mask(width);
    uint32_t t = x86_reg_read(ctx, I686_REG_EAX, width) & mask;
    x86_reg_write(ctx, I686_REG_EAX, width,
                  x86_reg_read(ctx, insn->modrm_reg, width) & mask);
    x86_reg_write(ctx, insn->modrm_reg, width, t);
    return step(ctx, insn);
}

/* R7-17: the architectural destination write cycle happens on either
 * CMPXCHG outcome, so a mismatching compare against read-only memory
 * must fault.  The probe writes back the value just read (invisible on
 * writable memory, which takes no store here at all) before any flag
 * or register commit, so the fault leaves pre-instruction state. */
static void cmpxchg_probe_write(i686_ctx_t *ctx, const x86_insn_t *insn,
                                unsigned width, uint32_t rmv)
{
    uint32_t ea = x86_ea_compute(ctx, insn);

    if (!i686_span_mapped_writable(ctx, ea, width / 8U)) {
        x86_rm_write(ctx, insn, width, rmv);
    }
}

/* CMPXCHG r/m, r: compare the accumulator with r/m (flags as CMP); if
 * equal, r/m <- r; otherwise accumulator <- r/m.  The reg operand is never
 * written.  R7-15: flags publish after the faultable store/probe. */
static int cmpxchg_exec(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width)
{
    uint32_t mask = width_mask(width);
    uint32_t acc = x86_reg_read(ctx, I686_REG_EAX, width) & mask;
    unsigned how = 2U;
    if (alu_mem_operand(insn)) {
        how = alu_lock_enter(ctx, insn, width);
        if (how == 0U) {
            /* Implicitly locked: strong-CAS retry on the HVA. */
            void *hva = alu_locked_hva(ctx, insn, width);
            uint32_t src = x86_reg_read(ctx, insn->modrm_reg, width) & mask;
            for (;;) {
                uint32_t rmv = mem_atomic_load_u(hva, width) & mask;
                if (acc != rmv) {
                    cmpxchg_probe_write(ctx, insn, width, rmv);
                    i686_flags_sub(ctx, acc, rmv, width);
                    x86_reg_write(ctx, I686_REG_EAX, width, rmv);
                    break;
                }
                i686_flags_sub(ctx, acc, rmv, width);
                if (mem_atomic_cas(hva, width, rmv, src)) {
                    break;
                }
            }
            alu_lock_leave(how);
            return step(ctx, insn);
        }
    }
    {
        uint32_t rmv = x86_rm_read(ctx, insn, width) & mask;
        if (acc == rmv) {
            x86_rm_write(ctx, insn, width,
                         x86_reg_read(ctx, insn->modrm_reg, width) & mask);
        } else if (alu_mem_operand(insn)) {
            cmpxchg_probe_write(ctx, insn, width, rmv);
        }
        i686_flags_sub(ctx, acc, rmv, width);
        if (acc != rmv) {
            x86_reg_write(ctx, I686_REG_EAX, width, rmv);
        }
    }
    alu_lock_leave(how);
    return step(ctx, insn);
}

static int h_CMPXCHG_EbGb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return cmpxchg_exec(ctx, insn, 8U);
}

static int h_CMPXCHG_EvGv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return cmpxchg_exec(ctx, insn, v_width(insn));
}

/* XADD r/m, r: flags of the ADD, r/m <- old(r/m) + r, r <- old(r/m). */
static int xadd_exec(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width)
{
    uint32_t mask = width_mask(width);
    uint32_t src = x86_reg_read(ctx, insn->modrm_reg, width) & mask;
    unsigned how = 2U;
    if (alu_mem_operand(insn)) {
        how = alu_lock_enter(ctx, insn, width);
        if (how == 0U) {
            /* Implicitly locked: fetch-add returns old value atomically. */
            void *hva = alu_locked_hva(ctx, insn, width);
            uint32_t old_rm = mem_atomic_fetch_op(hva, width, src, ALU_ADD) & mask;
            i686_flags_add(ctx, old_rm, src, width);
            x86_reg_write(ctx, insn->modrm_reg, width, old_rm);
            alu_lock_leave(how);
            return step(ctx, insn);
        }
    }
    /* R7-15: flags publish after the faultable store.  R7-18: when
     * both operands name the same register, Intel order (TEMP=SRC+DEST;
     * SRC=DEST; DEST=TEMP, DEST last) leaves the sum in the register —
     * the naive second assignment would destroy it. */
    uint32_t old_rm = x86_rm_read(ctx, insn, width) & mask;
    if (insn->modrm_mod == 3U && insn->modrm_rm == insn->modrm_reg) {
        x86_reg_write(ctx, insn->modrm_reg, width, (old_rm + src) & mask);
    } else {
        x86_rm_write(ctx, insn, width, (old_rm + src) & mask);
        x86_reg_write(ctx, insn->modrm_reg, width, old_rm);
    }
    i686_flags_add(ctx, old_rm, src, width);
    alu_lock_leave(how);
    return step(ctx, insn);
}

static int h_XADD_EbGb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return xadd_exec(ctx, insn, 8U);
}

static int h_XADD_EvGv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return xadd_exec(ctx, insn, v_width(insn));
}

/* CMPXCHG8B m64 lives in src/interp/interp.c beside the fault
 * checkpoint (lane rc-u3-i686 line discipline): the split-lock lifecycle
 * and its fault-safe release share that file.  Registered below. */

/* ---- module init ------------------------------------------------------ */

/* Flag-op handlers live in h_flagsops.c and register from this single init
 * (interp.h freezes the public *_init list, so this stays file-local). */
void i686_interp_flagsops_register(void);

void i686_interp_alu_init(void)
{
#define REG_ALU_FAMILY(mn)                                                  \
    do {                                                                    \
        i686_interp_register(I686_OP_##mn##_EbGb, h_##mn##_EbGb);           \
        i686_interp_register(I686_OP_##mn##_EvGv, h_##mn##_EvGv);           \
        i686_interp_register(I686_OP_##mn##_GbEb, h_##mn##_GbEb);           \
        i686_interp_register(I686_OP_##mn##_GvEv, h_##mn##_GvEv);           \
        i686_interp_register(I686_OP_##mn##_ALIb, h_##mn##_ALIb);           \
        i686_interp_register(I686_OP_##mn##_eAXIz, h_##mn##_eAXIz);         \
        i686_interp_register(I686_OP_##mn##_EbIb, h_##mn##_EbIb);           \
        i686_interp_register(I686_OP_##mn##_EvIz, h_##mn##_EvIz);           \
        i686_interp_register(I686_OP_##mn##_EvIbSX, h_##mn##_EvIbSX);       \
    } while (0)

    REG_ALU_FAMILY(ADD);
    REG_ALU_FAMILY(ADC);
    REG_ALU_FAMILY(AND);
    REG_ALU_FAMILY(CMP);
    REG_ALU_FAMILY(OR);
    REG_ALU_FAMILY(SBB);
    REG_ALU_FAMILY(SUB);
    REG_ALU_FAMILY(XOR);
#undef REG_ALU_FAMILY

    i686_interp_register(I686_OP_TEST_EbGb, h_TEST_EbGb);
    i686_interp_register(I686_OP_TEST_EvGv, h_TEST_EvGv);
    i686_interp_register(I686_OP_TEST_ALIb, h_TEST_ALIb);
    i686_interp_register(I686_OP_TEST_eAXIz, h_TEST_eAXIz);
    i686_interp_register(I686_OP_TEST_EbIb, h_TEST_EbIb);
    i686_interp_register(I686_OP_TEST_EvIz, h_TEST_EvIz);

    i686_interp_register(I686_OP_NOT_Eb, h_NOT_Eb);
    i686_interp_register(I686_OP_NOT_Ev, h_NOT_Ev);
    i686_interp_register(I686_OP_NEG_Eb, h_NEG_Eb);
    i686_interp_register(I686_OP_NEG_Ev, h_NEG_Ev);
    i686_interp_register(I686_OP_INC_Eb, h_INC_Eb);
    i686_interp_register(I686_OP_INC_Ev, h_INC_Ev);
    i686_interp_register(I686_OP_DEC_Eb, h_DEC_Eb);
    i686_interp_register(I686_OP_DEC_Ev, h_DEC_Ev);

    i686_interp_register(I686_OP_XCHG_EbGb, h_XCHG_EbGb);
    i686_interp_register(I686_OP_XCHG_EvGv, h_XCHG_EvGv);
    i686_interp_register(I686_OP_XCHG_eAXGv, h_XCHG_eAXGv);
    i686_interp_register(I686_OP_CMPXCHG_EbGb, h_CMPXCHG_EbGb);
    i686_interp_register(I686_OP_CMPXCHG_EvGv, h_CMPXCHG_EvGv);
    i686_interp_register(I686_OP_XADD_EbGb, h_XADD_EbGb);
    i686_interp_register(I686_OP_XADD_EvGv, h_XADD_EvGv);
    i686_interp_register(I686_OP_CMPXCHG8B, h_CMPXCHG8B);

    i686_interp_flagsops_register();
}
