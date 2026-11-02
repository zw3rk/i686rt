/*
 * src/dbt/emit_atomic.c — LOCK-prefixed RMW via ARMv8.1 LSE atomics (L4c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * translate.c routes every F0-prefixed instruction here (frozen dispatch
 * hook).  Forms emitted natively (memory destination only, flat segment
 * model, 8/16/32-bit operand widths):
 *
 *   LOCK ADD  r/m, r8/r16/r32   -> LDADDAL   Ws=src,          Wt=old
 *   LOCK ADD  r/m, imm          -> LDADDAL   Ws=imm
 *   LOCK SUB  r/m, r | imm      -> LDADDAL   Ws=-src (NEG; imm folded)
 *   LOCK AND  r/m, r | imm      -> LDCLRAL   Ws=~src (MVN; imm folded):
 *                                   LDCLR stores old AND NOT Ws, so the
 *                                   complement of the x86 source performs
 *                                   mem AND src (ARM ARM LDCLR semantics)
 *   LOCK OR   r/m, r | imm      -> LDSETAL   Ws=src
 *   LOCK XOR  r/m, r | imm      -> LDEORAL   Ws=src
 *   LOCK XADD r/m, r            -> LDADDAL   Ws=Rt=reg: memory becomes
 *                                   old+src and the register receives the
 *                                   returned old value in one step (SWPAL
 *                                   alone would store src, not old+src,
 *                                   so LDADD is the faithful lowering)
 *   LOCK XCHG r/m, r            -> SWPAL     Ws=Rt=reg
 *   LOCK CMPXCHG r/m, r         -> CASAL     Rs=AL/AX/EAX, Rt=reg: the
 *                                   store of Rt happens only when memory
 *                                   equals Rs, and Rs ALWAYS receives the
 *                                   loaded old value (Rt is never
 *                                   written — ARM ARM CompareAndSwap
 *                                   pseudocode, re-verified on hardware),
 *                                   so an unconditional width-merged
 *                                   writeback of Rs into the accumulator
 *                                   implements both x86 outcomes (on
 *                                   success Rs == the accumulator already)
 *
 * Byte/word widths use the B/H forms (LDADDALB/LDADDALH etc.), whose
 * loaded old value zero-extends into the Wt register like LDRB/LDRH.
 * Rs/Rt fields are built so the atomic reads/writes the low width bits
 * only; two's-complement low bits are width-invariant, so the 32-bit
 * NEG/MVN source transforms need no extra masking.
 *
 * Encodings (verified against the LLVM assembler disassembly; field
 * layout per ARM ARM "Atomic memory operations" / "Compare and swap"):
 *   LDADDAL-family: 31:30 size, 29:24 111000, 23 A=1, 22 L=1, 21 1,
 *     20:16 Rs, 15:12 opc (0 ADD, 1 CLR, 2 EOR, 3 SET, 8 SWP), 9:5 Rn,
 *     4:0 Rt; size 00/01/10 give the B/H/word forms
 *   CASAL: 31:30 size, 29:23 1110001, 22 A=1, 20:16 Rs, 15 L=1,
 *     14:10 11111, 9:5 Rn, 4:0 Rt
 *
 * Flags (D6 lazy descriptor, bit-identical to h_alu.c):
 *   ADD/XADD: FOP_ADD  {res=old+src, src1=old, src2=src}   (x86 ADD rule;
 *             XADD flags come from the sum, which this gives exactly)
 *   SUB:      FOP_SUB  {res=old-src, src1=old, src2=src}
 *   AND/OR/XOR: FOP_LOGIC {res=old OP src}  (CF=OF=0)
 *   CMPXCHG:  FOP_SUB  {res=acc-old, src1=acc, src2=old} (flags as CMP,
 *             ZF=1 exactly on CAS success)
 *   XCHG sets no flags (descriptor untouched); the flag-writing classes
 *   downgrade e->flags_src to I686_FLAGS_DEAD (C6a seam, emit.h) since
 *   NZCV no longer holds the architectural image after them
 *
 * Declined in v1 (return -1 -> translate.c emits the UNDEF exit; the
 * engine interpret-one via the interpreter, always D2-safe):
 *   - LOCK ADC/SBB: need the x86 carry-in fused into the RMW; LSE cannot
 *     consume it without an eager materializer round-trip
 *   - LOCK INC/DEC/NEG/NOT r/m (FE/FF/F6/F7 groups): LDADDAL by +/-1 or
 *     LDCLR by 0xFFFFFFFF could express the memory effect, flag rules
 *     (CF-preserving INC/DEC, NEG) are deferred with the flags_dbt.h work
 *   - LOCK BTS/BTR/BTC r/m, r/imm (0F AB/B3/BB/BA): CF must sample the
 *     old bit, which the lazy descriptor cannot express
 *   - LOCK TEST/CMP (no memory write; falls through to the plain emitters)
 *   - every non-whitelisted op and every register-destination LOCK form
 *     (LOCK on r,r is undefined on hardware anyway)
 *
 * Alignment: LSE atomics require natural alignment of the accessed
 * element; a misaligned guest EA takes a host alignment fault rather
 * than a guest exception (split-lock #AC emulation is a later phase).
 * FEAT_LSE is assumed (any ARMv8.1+ host; the HWCAP_ATOMICS runtime
 * check plus an LDXR/STXR fallback path is Phase H per the card).
 * TSO (D5): the AL variants are acquire+release. e->tso is not read
 * here; i686_emit_begin leaves it false.
 *
 * Scratch map (w0..w7 guest GPRs, x19 ctx, x20 xG, w21/w22 EA per
 * i686_emit_ea): w8 = LSE source operand (transformed), w9 = old value
 * (LSE Wt), w10 = lazy res, w11 = CMPXCHG accumulator (old value after
 * the CASAL), w12 = original source (descriptor src2), w13 = lazy-store
 * temp, w14 = CMPXCHG accumulator copy (descriptor src1), x23 =
 * xG+uxtw(w21).
 */

#include <stdint.h>
#include <string.h>

#include "dbt/aot/aot.h"
#include "dbt/emit.h"

#define SCR_W    8U  /* LSE Rs: transformed source operand            */
#define SCR_OLD  9U  /* LSE Rt: pre-op memory value (zero-extended)   */
#define SCR_RES 10U  /* lazy descriptor res                           */
#define SCR_ACC 11U  /* CMPXCHG accumulator; old value after CASAL    */
#define SCR_SRC 12U  /* original source value (descriptor src2)       */
#define SCR_T   13U  /* lazy descriptor store temp                    */
#define SCR_ACC2 14U /* CMPXCHG accumulator copy (descriptor src1)    */
#define SCR_ADDR 23U /* x23 = xG + uxtw(w21) host address             */

/* LSE opc field: LDADD=0, LDCLR=1, LDEOR=2, LDSET=3, SWP=8. */
#define LSE_OPC_ADD 0U
#define LSE_OPC_CLR 1U
#define LSE_OPC_EOR 2U
#define LSE_OPC_SET 3U
#define LSE_OPC_SWP 8U

/* 0xFF sentinel in the frozen x86_insn_t (ea_base none). */
#define AT_NONE 0xFFU

/* RC-U3 recovery site for the single LSE/CASAL access.  A fault in a
 * LOCK RMW without a site resumes at the block base and re-executes
 * the (non-idempotent) prefix: the classic shape is call-get_pc_thunk
 * + add-GOT followed by pushes and the atomic, where re-running the
 * add corrupts the EA base and the atomic faults on a wild address
 * (two-threaded C2-2 flock).  The site pins the fault to this insn so
 * recovery emulates exactly once.  Delta comes from translate.c's
 * per-insn e->insn_pc (no cursor walk: cursor state is shared while
 * e->insn_pc is per-emission).  mem is the LSE/CASAL offset itself;
 * AL atomics carry their own acquire-release ordering so no extra TSO
 * barrier precedes them and no +4 offset adjustment is needed. */
static void em_atomic_site(i686_emit_ctx_t *e, const x86_insn_t *insn,
                           uint32_t seq, uint32_t mem, uint32_t cont,
                           unsigned width)
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
    site.flags = (uint8_t)I686_SITE_STORE;
    site.val_or_dst_reg = (uint8_t)SCR_SRC;
    site.addr_base_reg = (uint8_t)(insn->ea_base != AT_NONE
                                       ? i686_w(insn->ea_base)
                                       : 0xFFu);
    (void)i686_aot_note_stack_site(&site);
}

/* ---- width-trivial raw encoders ------------------------------------- */

/* LDADDAL/LDCLRAL/LDEORAL/LDSETAL/SWPAL Rs, Rt, [Xn] (A=1, L=1). */
static uint32_t lse_base(unsigned width)
{
    if (width == 8U) {
        return 0x38E00000U; /* LDADDALB-class size=00 */
    }
    if (width == 16U) {
        return 0x78E00000U; /* LDADDALH-class size=01 */
    }
    return 0xB8E00000U;     /* LDADDAL-class   size=10 */
}

static void emit_lse(a64_buf_t *b, unsigned opc, unsigned width, unsigned rs,
                     unsigned rt, unsigned rn)
{
    a64_emit(b, lse_base(width) | ((rs & 31U) << 16) | ((opc & 15U) << 12) |
                     ((rn & 31U) << 5) | (rt & 31U));
}

/* CASAL Rs, Rt, [Xn] (A=1 at bit 22, L=1 at bit 15, 14:10 = 11111). */
static uint32_t casal_base(unsigned width)
{
    if (width == 8U) {
        return 0x08E0FC00U;
    }
    if (width == 16U) {
        return 0x48E0FC00U;
    }
    return 0x88E0FC00U;
}

static void emit_casal(a64_buf_t *b, unsigned width, unsigned rs, unsigned rt,
                       unsigned rn)
{
    a64_emit(b, casal_base(width) | ((rs & 31U) << 16) | ((rn & 31U) << 5) |
                     (rt & 31U));
}

/* Site-wrapping LSE/CASAL: capture the faulting access offset around the
 * single atomic instruction so recovery pins the fault to this insn. */
static void emit_lse_site(i686_emit_ctx_t *e, const x86_insn_t *insn,
                           uint32_t seq, unsigned opc, unsigned width,
                           unsigned rs, unsigned rt, unsigned rn)
{
    a64_buf_t *b = &e->buf;
    uint32_t mem = (uint32_t)((uint64_t)b->count * 4u);
    uint32_t cont;
    emit_lse(b, opc, width, rs, rt, rn);
    cont = (uint32_t)((uint64_t)b->count * 4u);
    em_atomic_site(e, insn, seq, mem, cont, width);
}

static void emit_casal_site(i686_emit_ctx_t *e, const x86_insn_t *insn,
                            uint32_t seq, unsigned width, unsigned rs,
                            unsigned rt, unsigned rn)
{
    a64_buf_t *b = &e->buf;
    uint32_t mem = (uint32_t)((uint64_t)b->count * 4u);
    uint32_t cont;
    emit_casal(b, width, rs, rt, rn);
    cont = (uint32_t)((uint64_t)b->count * 4u);
    em_atomic_site(e, insn, seq, mem, cont, width);
}

/* AND Wd, Wn, #0xFF / #0xFFFF (N=0, immr=0) — descriptor masking. */
static void emit_and_imm_w(a64_buf_t *b, unsigned rd, unsigned rn, uint32_t imm)
{
    unsigned imms = (imm == 0xFFFFU) ? 15U : 7U;

    a64_emit(b, 0x12000000U | ((uint32_t)imms << 10) | ((rn & 31U) << 5) |
                     (rd & 31U));
}

/* BFI Wd, Wn, #lsb, #width = BFM Wd, Wn, #(32-lsb)&31, #(width-1). */
static void emit_bfi_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned lsb,
                       unsigned width)
{
    a64_emit_bfm_w(b, rd, rn, (32U - lsb) & 31U, width - 1U);
}

/* ---- x86 register file on the fixed w0..w7 map ----------------------- */

/* 8-bit high halves (AH..BH) live in bits 15:8 of EAX..EBX (D7). */
static unsigned byte_pos(uint8_t reg)
{
    return (reg >= 4U) ? 8U : 0U;
}

static unsigned byte_host(uint8_t reg)
{
    return (reg >= 4U) ? (unsigned)(reg - 4U) : (unsigned)reg;
}

static void load_reg_w(a64_buf_t *b, unsigned dst, uint8_t reg,
                       unsigned width)
{
    if (width == 32U) {
        a64_emit_mov_w(b, dst, i686_w(reg));
    } else if (width == 16U) {
        a64_emit_ubfm_w(b, dst, i686_w(reg), 0U, 15U);
    } else {
        a64_emit_ubfm_w(b, dst, byte_host(reg), byte_pos(reg),
                        byte_pos(reg) + 7U);
    }
}

static void store_reg_w(a64_buf_t *b, unsigned src, uint8_t reg,
                        unsigned width)
{
    if (width == 32U) {
        a64_emit_mov_w(b, i686_w(reg), src);
    } else if (width == 16U) {
        emit_bfi_w(b, i686_w(reg), src, 0U, 16U);
    } else {
        emit_bfi_w(b, byte_host(reg), src, byte_pos(reg), 8U);
    }
}

/* ---- lazy descriptor (bit-identical to emit_alu.c's emit_lazy) ------- */

static void emit_lazy(i686_emit_ctx_t *e, uint32_t fop, unsigned res,
                      unsigned s1, unsigned s2, unsigned width)
{
    a64_buf_t *b = &e->buf;

    a64_emit_movz_w(b, SCR_T, (uint16_t)fop, 0U);
    a64_emit_str_imm_w(b, SCR_T, 19U, 76U);  /* lazy_op   */
    a64_emit_str_imm_w(b, res, 19U, 80U);    /* lazy_res  */
    a64_emit_str_imm_w(b, s1, 19U, 84U);     /* lazy_src1 */
    a64_emit_str_imm_w(b, s2, 19U, 88U);     /* lazy_src2 */
    a64_emit_str_imm_w(b, 31U, 19U, 92U);    /* lazy_cf_in = 0 (WZR) */
    a64_emit_movz_w(b, SCR_T, (uint16_t)width, 0U);
    a64_emit_str_imm_w(b, SCR_T, 19U, 104U); /* lazy_width */
}

/* Mask the lazy res to the operand width (src operands are loaded
 * width-masked; ADD/SUB results are not). */
static void mask_res(a64_buf_t *b, unsigned width)
{
    if (width == 8U) {
        emit_and_imm_w(b, SCR_RES, SCR_RES, 0xFFU);
    } else if (width == 16U) {
        emit_and_imm_w(b, SCR_RES, SCR_RES, 0xFFFFU);
    }
}

/* ---- dispatcher ------------------------------------------------------ */

enum {
    AT_ADD,
    AT_SUB,
    AT_AND,
    AT_OR,
    AT_XOR,
    AT_XADD,
    AT_XCHG,
    AT_CMPXCHG
};

static uint32_t sext_imm8(uint32_t imm)
{
    return ((imm & 0xFFU) ^ 0x80U) - 0x80U;
}

int i686_emit_atomic(i686_emit_ctx_t *e, const x86_insn_t *insn)
{
    a64_buf_t *b = &e->buf;
    unsigned width;
    uint32_t mask;
    int kind = -1;
    int src_imm = 0;
    uint32_t imm = 0U;

    /* Whitelisted LOCK forms only (EbGb/EvGv reg source, EbIb/EvIz/
     * EvIbSX immediate source, XADD/XCHG/CMPXCHG r/m,reg).  Everything
     * else declines to the D2 fallback or the plain emitters. */
    switch (insn->op) {
#define ATOMIC_RMW5(mn, K)                                                     \
    case I686_OP_##mn##_EbGb:                                                  \
    case I686_OP_##mn##_EvGv: kind = (K); break;                               \
    case I686_OP_##mn##_EbIb:                                                  \
    case I686_OP_##mn##_EvIz:                                                  \
    case I686_OP_##mn##_EvIbSX: kind = (K); src_imm = 1; break

        ATOMIC_RMW5(ADD, AT_ADD);
        ATOMIC_RMW5(SUB, AT_SUB);
        ATOMIC_RMW5(AND, AT_AND);
        ATOMIC_RMW5(OR, AT_OR);
        ATOMIC_RMW5(XOR, AT_XOR);
#undef ATOMIC_RMW5
    case I686_OP_XADD_EbGb:
    case I686_OP_XADD_EvGv:
        kind = AT_XADD;
        break;
    case I686_OP_XCHG_EbGb:
    case I686_OP_XCHG_EvGv:
        kind = AT_XCHG;
        break;
    case I686_OP_CMPXCHG_EbGb:
    case I686_OP_CMPXCHG_EvGv:
        kind = AT_CMPXCHG;
        break;
    default:
        return -1;
    }

    /* LOCK only locks a memory destination (opnd[0] is the r/m). */
    if (insn->modrm_mod == 3U || insn->ea_has == 0U) {
        return -1;
    }

    width = (insn->opnd[0] == I686_OPND_RM8)
                ? 8U
                : (insn->pfx_opsize != 0U ? 16U : 32U);
    mask = (width == 32U) ? 0xFFFFFFFFU : ((1U << width) - 1U);
    if (src_imm != 0) {
        imm = insn->imm;
        if (insn->opnd[1] == I686_OPND_I8SX) {
            imm = sext_imm8(imm);
        }
        imm &= mask;
    }

    /* EA -> w21 (32-bit guest offset, segment base added); the LSE base
     * register must be a full X: x23 = xG + uxtw(w21). */
    uint32_t seq = (uint32_t)((uint64_t)b->count * 4u);
    i686_emit_ea(e, insn, 1);
    a64_emit_add_uxtw_x(b, SCR_ADDR, 20U, 21U);

    /* w12 = original source value, width-masked (descriptor src2). */
    if (src_imm != 0) {
        a64_emit_mov_imm32(b, SCR_SRC, imm);
    } else {
        load_reg_w(b, SCR_SRC, insn->modrm_reg, width);
    }

    switch (kind) {
    case AT_ADD:
    case AT_SUB:
    case AT_AND:
    case AT_OR:
    case AT_XOR:
        /* w8 = LSE source operand per the op mapping. */
        if (kind == AT_SUB) {
            a64_emit_sub_reg_w(b, false, SCR_W, 31U, SCR_SRC,
                               A64_SHIFT_LSL, 0U); /* neg w8, w12 */
        } else if (kind == AT_AND) {
            a64_emit_mvn_reg_w(b, SCR_W, SCR_SRC, A64_SHIFT_LSL, 0U);
        } else {
            a64_emit_mov_w(b, SCR_W, SCR_SRC);
        }
        if (kind == AT_ADD) {
            emit_lse_site(e, insn, seq, LSE_OPC_ADD, width, SCR_W,
                          SCR_OLD, SCR_ADDR);
            a64_emit_add_reg_w(b, false, SCR_RES, SCR_OLD, SCR_SRC,
                               A64_SHIFT_LSL, 0U);
            mask_res(b, width);
            emit_lazy(e, I686_FOP_ADD, SCR_RES, SCR_OLD, SCR_SRC, width);
        } else if (kind == AT_SUB) {
            emit_lse_site(e, insn, seq, LSE_OPC_ADD, width, SCR_W,
                          SCR_OLD, SCR_ADDR);
            a64_emit_sub_reg_w(b, false, SCR_RES, SCR_OLD, SCR_SRC,
                               A64_SHIFT_LSL, 0U);
            mask_res(b, width);
            emit_lazy(e, I686_FOP_SUB, SCR_RES, SCR_OLD, SCR_SRC, width);
        } else if (kind == AT_AND) {
            emit_lse_site(e, insn, seq, LSE_OPC_CLR, width, SCR_W,
                          SCR_OLD, SCR_ADDR);
            a64_emit_and_reg_w(b, false, SCR_RES, SCR_OLD, SCR_SRC,
                               A64_SHIFT_LSL, 0U);
            emit_lazy(e, I686_FOP_LOGIC, SCR_RES, 31U, 31U, width);
        } else if (kind == AT_OR) {
            emit_lse_site(e, insn, seq, LSE_OPC_SET, width, SCR_W,
                          SCR_OLD, SCR_ADDR);
            a64_emit_orr_reg_w(b, SCR_RES, SCR_OLD, SCR_SRC, A64_SHIFT_LSL,
                               0U);
            emit_lazy(e, I686_FOP_LOGIC, SCR_RES, 31U, 31U, width);
        } else { /* AT_XOR */
            emit_lse_site(e, insn, seq, LSE_OPC_EOR, width, SCR_W,
                          SCR_OLD, SCR_ADDR);
            a64_emit_eor_reg_w(b, SCR_RES, SCR_OLD, SCR_SRC, A64_SHIFT_LSL,
                               0U);
            emit_lazy(e, I686_FOP_LOGIC, SCR_RES, 31U, 31U, width);
        }
        break;
    case AT_XADD:
        /* LDADDAL Ws=src, Wt=old: mem = old+src, w9 = old. */
        emit_lse_site(e, insn, seq, LSE_OPC_ADD, width, SCR_SRC,
                      SCR_OLD, SCR_ADDR);
        store_reg_w(b, SCR_OLD, insn->modrm_reg, width);
        a64_emit_add_reg_w(b, false, SCR_RES, SCR_OLD, SCR_SRC,
                           A64_SHIFT_LSL, 0U);
        mask_res(b, width);
        emit_lazy(e, I686_FOP_ADD, SCR_RES, SCR_OLD, SCR_SRC, width);
        break;
    case AT_XCHG:
        /* SWPAL Ws=src, Wt=old: mem = src, w9 = old.  No flags. */
        emit_lse_site(e, insn, seq, LSE_OPC_SWP, width, SCR_SRC,
                      SCR_OLD, SCR_ADDR);
        store_reg_w(b, SCR_OLD, insn->modrm_reg, width);
        break;
    default: /* AT_CMPXCHG */
        /* w11 = AL/AX/EAX (implicit accumulator; AL is bits 7:0 of EAX,
         * never the AH position), w14 = a second copy for the flags
         * descriptor.  CASAL Rs=acc, Rt=new stores new atomically only
         * when memory equals acc, and — per the ARM ARM CompareAndSwap
         * pseudocode and verified on hardware — ALWAYS writes the
         * loaded old value into Rs (Rt is never written).  The
         * unconditional width-merged writeback of Rs into the
         * accumulator is therefore exactly x86 semantics: a no-op on
         * success (Rs == acc), the old memory value on failure. */
        load_reg_w(b, SCR_ACC, I686_REG_EAX, width);
        load_reg_w(b, SCR_ACC2, I686_REG_EAX, width);
        emit_casal_site(e, insn, seq, width, SCR_ACC, SCR_SRC, SCR_ADDR);
        store_reg_w(b, SCR_ACC, I686_REG_EAX, width);
        a64_emit_sub_reg_w(b, false, SCR_RES, SCR_ACC2, SCR_ACC,
                           A64_SHIFT_LSL, 0U);
        mask_res(b, width);
        emit_lazy(e, I686_FOP_SUB, SCR_RES, SCR_ACC2, SCR_ACC, width);
        break;
    }

    /* C6a flags_src seam (emit.h): every RMW class except XCHG moves the
     * x86 flag state into a pending lazy descriptor (the sequences emit
     * no flag-setting A64, so NZCV keeps a PREVIOUS op's image).
     * Consumers must not fuse on it — downgrade to the full sequence. */
    if (kind != AT_XCHG) {
        e->flags_src = I686_FLAGS_DEAD;
    }

    e->insn_count++;
    return 0;
}
