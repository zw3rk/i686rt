/*
 * src/interp/h_branch.c — control-flow and interrupt handlers (Phase 1 L1d)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * SPEC D2/D4/D7/D12: the interpreter executes branches by writing ctx->eip
 * and returning CONTINUE; non-branch handlers advance eip by insn->len.
 * Guest addresses wrap in 32 bits and are never sign-extended or truncated
 * except where the architecture demands it (16-bit IP targets).  int 0x80
 * and sysenter leave as I686_EXIT_SYSCALL with exit_arg 0x80.
 */

#include <stdint.h>

#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"
#include "x86/decode.h"

/* Bit-test family handlers live in h_bit.c but register from here. */
void i686_interp_bit_init(void); /* src/interp/h_bit.c */

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

/* Operand size in bits: 66 selects 16-bit operands in flat 32-bit code. */
static unsigned opnd_width(const x86_insn_t *insn)
{
    return insn->pfx_opsize != 0U ? 16U : 32U;
}

/* Address of the first byte after this instruction (wraps in 32 bits). */
static uint32_t next_eip_of(const i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return ctx->eip + (uint32_t)insn->len;
}

/* Sign-extend insn->imm to a 32-bit displacement per its fetched size. */
static uint32_t sext_rel(const x86_insn_t *insn)
{
    if (insn->imm_size == 1U) {
        return (uint32_t)(int32_t)(int8_t)(uint8_t)insn->imm;
    }
    if (insn->imm_size == 2U) {
        return (uint32_t)(int32_t)(int16_t)(uint16_t)insn->imm;
    }
    return insn->imm; /* imm_size 4 */
}

/* A 16-bit operand-size control transfer truncates EIP to 16 bits (IP). */
static void set_eip(i686_ctx_t *ctx, uint32_t target, unsigned width)
{
    ctx->eip = (width == 16U) ? (target & 0xFFFFU) : target;
}

/* Little-endian guest-window accesses; byte-wise so unaligned guest
 * operands stay well-defined on any host. */
static void mem_store(i686_ctx_t *ctx, uint32_t va, uint32_t val, unsigned width)
{
    uint8_t *p = (uint8_t *)i686_guest_ptr(ctx, va);
    unsigned n = width / 8U;
    unsigned i;

    for (i = 0U; i < n; i++) {
        p[i] = (uint8_t)(val >> (8U * i));
    }
}

static uint32_t mem_load(const i686_ctx_t *ctx, uint32_t va, unsigned width)
{
    const uint8_t *p = (const uint8_t *)i686_guest_ptr(ctx, va);
    unsigned n = width / 8U;
    uint32_t v = 0U;
    unsigned i;

    for (i = 0U; i < n; i++) {
        v |= (uint32_t)p[i] << (8U * i);
    }
    return v;
}

/* Near CALL/RET run against SS like PUSH/POP (h_mov.c): the stack
 * pointer is an offset from the SS base, wrapping in 32 bits. */
static void stack_push(i686_ctx_t *ctx, uint32_t val, unsigned width)
{
    unsigned bytes = width / 8U;
    uint32_t sp = ctx->gpr[I686_REG_ESP] - bytes; /* wraps in 32 bits */

    mem_store(ctx, ctx->seg_base[I686_SEG_SS] + sp, val, width);
    ctx->gpr[I686_REG_ESP] = sp;
}

static uint32_t stack_pop(i686_ctx_t *ctx, unsigned width)
{
    unsigned bytes = width / 8U;
    uint32_t sp = ctx->gpr[I686_REG_ESP];
    uint32_t v = mem_load(ctx, ctx->seg_base[I686_SEG_SS] + sp, width);

    ctx->gpr[I686_REG_ESP] = sp + bytes;
    return v;
}

/* ------------------------------------------------------------------ */
/* JMP / JCC                                                           */
/* ------------------------------------------------------------------ */

static int h_jmp_rel(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);

    set_eip(ctx, next_eip_of(ctx, insn) + sext_rel(insn), width);
    return I686_INTERP_CONTINUE;
}

static int h_jmp_ev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t target = x86_rm_read(ctx, insn, width);

    set_eip(ctx, target, width);
    return I686_INTERP_CONTINUE;
}

static int h_jcc(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t next = next_eip_of(ctx, insn);

    /* Family id: the condition (0..15) rides in modrm_reg.  i686_flags_cc
     * materializes lazy flags, which is exactly the contract. */
    if (i686_flags_cc(ctx, insn->modrm_reg) != 0U) {
        set_eip(ctx, next + sext_rel(insn), width);
    } else {
        ctx->eip = next; /* fall through keeps the full 32-bit EIP */
    }
    return I686_INTERP_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* CALL / RET                                                          */
/* ------------------------------------------------------------------ */

static int h_call_rel(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t next = next_eip_of(ctx, insn);

    stack_push(ctx, next, width);
    set_eip(ctx, next + sext_rel(insn), width);
    return I686_INTERP_CONTINUE;
}

static int h_call_ev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t next = next_eip_of(ctx, insn);
    uint32_t target = x86_rm_read(ctx, insn, width); /* read before push */

    stack_push(ctx, next, width);
    set_eip(ctx, target, width);
    return I686_INTERP_CONTINUE;
}

static int h_ret(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t target = stack_pop(ctx, width);

    set_eip(ctx, target, width);
    return I686_INTERP_CONTINUE;
}

static int h_ret_iw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t target = stack_pop(ctx, width);

    /* imm (I16, zero-extended) adjusts ESP only after the pop. */
    ctx->gpr[I686_REG_ESP] += insn->imm;
    set_eip(ctx, target, width);
    return I686_INTERP_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* LOOP* / JCXZ                                                        */
/* ------------------------------------------------------------------ */

enum loop_kind { LOOP_PLAIN = 0, LOOP_Z, LOOP_NZ };

static int do_loop(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned kind)
{
    /* The count register follows the ADDRESS size (67): CX under a 16-bit
     * address size (upper ECX preserved), ECX otherwise. */
    unsigned addr_w = (insn->pfx_addrsize != 0U) ? 16U : 32U;
    uint32_t count;
    bool taken;
    uint32_t next = next_eip_of(ctx, insn);

    if (addr_w == 16U) {
        ctx->gpr[I686_REG_ECX] =
            (ctx->gpr[I686_REG_ECX] & 0xFFFF0000U) |
            ((ctx->gpr[I686_REG_ECX] - 1U) & 0xFFFFU);
        count = ctx->gpr[I686_REG_ECX] & 0xFFFFU;
    } else {
        ctx->gpr[I686_REG_ECX] -= 1U;
        count = ctx->gpr[I686_REG_ECX];
    }

    taken = count != 0U;
    if (kind != (unsigned)LOOP_PLAIN) {
        bool zf = (i686_flags_read(ctx) & I686_EF_ZF) != 0U;

        taken = taken && (kind == (unsigned)LOOP_Z ? zf : !zf);
    }

    /* rel8 branch: taken or fall through to next_eip (full 32-bit EIP). */
    ctx->eip = taken ? (next + sext_rel(insn)) : next;
    return I686_INTERP_CONTINUE;
}

static int h_loop(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_loop(ctx, insn, (unsigned)LOOP_PLAIN);
}

static int h_loopz(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_loop(ctx, insn, (unsigned)LOOP_Z);
}

static int h_loopnz(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_loop(ctx, insn, (unsigned)LOOP_NZ);
}

static int h_jcxz(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    /* JCXZ/JECXZ test CX vs ECX by address size (67), not operand size. */
    unsigned addr_w = (insn->pfx_addrsize != 0U) ? 16U : 32U;
    uint32_t count = (addr_w == 16U) ? (ctx->gpr[I686_REG_ECX] & 0xFFFFU)
                                    : ctx->gpr[I686_REG_ECX];
    uint32_t next = next_eip_of(ctx, insn);

    ctx->eip = (count == 0U) ? (next + sext_rel(insn)) : next;
    return I686_INTERP_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* SETcc / CMOVcc                                                      */
/* ------------------------------------------------------------------ */

static int h_setcc(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t val = (i686_flags_cc(ctx, insn->modrm_reg) != 0U) ? 1U : 0U;

    x86_rm_write(ctx, insn, 8U, val); /* opnd[0] is the r/m byte */
    ctx->eip = next_eip_of(ctx, insn);
    return I686_INTERP_CONTINUE;
}

static int h_cmovcc(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);

    /* Source is always read (fault semantics); the store is conditional.
     *
     * Condition routing (S1 coordination note): phase-1.md puts family
     * conditions in modrm_reg, which is exact for Jcc (no modrm) and
     * SETcc (reg field unused).  CMOVcc cannot follow it: its descriptor
     * opnd[0] is R32, i.e. modrm_reg IS the destination register, so the
     * condition (which no longer fits anywhere in modrm) rides in
     * insn->imm, which CMOVcc otherwise does not use. */
    uint8_t cond = (uint8_t)(insn->imm & 0xFU);
    uint32_t src = x86_rm_read(ctx, insn, width);

    if (i686_flags_cc(ctx, cond) != 0U) {
        x86_reg_write(ctx, insn->modrm_reg, width, src);
    }
    ctx->eip = next_eip_of(ctx, insn);
    return I686_INTERP_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* INT / trap / halt / misc                                            */
/* ------------------------------------------------------------------ */

static int h_int(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t vector = (uint8_t)insn->imm;

    if (vector == 0x80U) {
        ctx->eip = next_eip_of(ctx, insn); /* resume past the int 0x80 */
        ctx->exit_arg = 0x80U;
        return I686_EXIT_SYSCALL; /* D12 */
    }
    ctx->exit_arg = vector; /* not executed: EIP stays at the int */
    return I686_EXIT_UNDEF;
}

static int h_int3(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip = next_eip_of(ctx, insn); /* trap reported past the 1-byte int3 */
    ctx->exit_arg = 3U;
    return I686_EXIT_TRAP;
}

static int h_into(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)insn;
    ctx->exit_arg = 4U; /* its vector, diagnostics only */
    return I686_EXIT_UNDEF; /* v1: INTO not implemented, never executes */
}

static int h_iret(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)ctx;
    (void)insn;
    return I686_EXIT_UNDEF; /* Phase 4 lands signal-frame iret */
}

static int h_hlt(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip = next_eip_of(ctx, insn);
    return I686_EXIT_HLT; /* diagnostic stop */
}

static int h_wait(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip = next_eip_of(ctx, insn); /* fwait: no-op in v1 */
    return I686_INTERP_CONTINUE;
}

static int h_ud2(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)ctx;
    (void)insn;
    return I686_EXIT_UNDEF; /* never executes: EIP unchanged */
}

static int h_sysenter(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip = next_eip_of(ctx, insn);
    ctx->exit_arg = 0x80U;
    return I686_EXIT_SYSCALL; /* D12: fast syscall == int 0x80 */
}

static int h_nop(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip = next_eip_of(ctx, insn);
    return I686_INTERP_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

void i686_interp_branch_init(void)
{
    i686_interp_register(I686_OP_JMP_Jb, h_jmp_rel);
    i686_interp_register(I686_OP_JMP_Jz, h_jmp_rel);
    i686_interp_register(I686_OP_JMP_Ev, h_jmp_ev);
    i686_interp_register(I686_OP_JCC_Jb, h_jcc);
    i686_interp_register(I686_OP_JCC_Jz, h_jcc);
    i686_interp_register(I686_OP_CALL_Jz, h_call_rel);
    i686_interp_register(I686_OP_CALL_Ev, h_call_ev);
    i686_interp_register(I686_OP_RET, h_ret);
    i686_interp_register(I686_OP_RET_Iw, h_ret_iw);
    i686_interp_register(I686_OP_LOOPNZ_Jb, h_loopnz);
    i686_interp_register(I686_OP_LOOPZ_Jb, h_loopz);
    i686_interp_register(I686_OP_LOOP_Jb, h_loop);
    i686_interp_register(I686_OP_JCXZ_Jb, h_jcxz);
    i686_interp_register(I686_OP_SETcc_Eb, h_setcc);
    i686_interp_register(I686_OP_CMOVcc_Gv, h_cmovcc);
    i686_interp_register(I686_OP_INT_Ib, h_int);
    i686_interp_register(I686_OP_INT3, h_int3);
    i686_interp_register(I686_OP_INTO, h_into);
    i686_interp_register(I686_OP_IRET, h_iret);
    i686_interp_register(I686_OP_HLT, h_hlt);
    i686_interp_register(I686_OP_WAIT, h_wait);
    i686_interp_register(I686_OP_UD2, h_ud2);
    i686_interp_register(I686_OP_SYSENTER, h_sysenter);
    i686_interp_register(I686_OP_NOP, h_nop);

    i686_interp_bit_init(); /* bit-test family lives in h_bit.c */
}
