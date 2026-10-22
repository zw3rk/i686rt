/*
 * src/interp/h_seg.c — segment-register and far-transfer interpreter
 * handlers (Phase 7 card L7a; SPEC D8, §4 7.1; E09 verdict)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Owns:
 *   - MOV sreg (8E) and pops 07/17/1F/0F A1/0F A9 via i686_seg_load
 *     (full descriptor validation: #GP(sel)/#NP(sel), D8),
 *   - les/lds/lss/lfs/lgs (C4/C5/0F B2/B4/B5),
 *   - far call/jmp (9A/EA), lret (CB, incl. the 0x66 cross-size matrix
 *     per E09 gap 4), non-v86 iret (CF),
 *   - int NN (CD) in non-flat code as a resolvable #GP fault with EIP at
 *     the int (E09 gap 5; flat int 0x80 syscall and Phase-1 behaviour
 *     unchanged),
 *   - privileged-instruction faults (cli/sti/hlt overrides + the
 *     synthetic IN/OUT/MOV CR,DR id) in 16-bit code (E09 gap 6).
 *
 * Fault model: seg_fault() sets ctx->exit_arg = trapno
 * (13 #GP / 11 #NP / 12 #SS), stashes the error code (selector bits) in
 * ctx->exit_dest for the S7 delivery wiring, and returns I686_EXIT_FAULT.
 * The interpreter loop delivers guest SIGSEGV and resumes with EIP at
 * the faulting instruction, so every fault here is resumable by a guest
 * handler that advances uc_mcontext.eip (the test_p4 pattern).
 *
 * Flat-process compatibility: for a flat CS the overrides reproduce the
 * v1 behaviour exactly (int 0x80 syscall exit, flat int NN UNDEF,
 * cli/sti/hlt as before); iret (previously UNDEF everywhere) and the far
 * transfers (previously undecodable everywhere) now execute per SDM —
 * the Phase 7 delta.
 *
 * Registration is lazy and idempotent through i686_interp_seg_init();
 * decode.c calls it on every decode (one static-guard branch) because
 * the frozen interp.c init list is closed — the coordinator may move the
 * call into i686_interp_init_all() at S7 (see docs/lanes/phase-7.md).
 */

#include <stdint.h>

#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"

/* seg.h (frozen) re-spells its FAULT codes over i686rt.h's segment-
 * register index macros: I686_SEG_SS is 3 (fault #SS) there vs 2U (the
 * SS register index) in i686rt.h.  The frozen headers cannot change:
 * pre-clear the macro so seg.h's #define is fresh (no redefinition
 * warning), then restore the register index and use collision-free
 * local names for the fault codes. */
#undef I686_SEG_SS
#include "interp/seg.h"
#undef I686_SEG_SS
#define I686_SEG_SS 2u /* register index (i686rt.h contract) */
#define SEG_F_OK 0
#define SEG_F_GP 1
#define SEG_F_NP 2
#define SEG_F_SS 3

#include "x86/decode.h"

/* decode.c / seg.c EA plumbing (not part of a frozen header). */
extern uint8_t x86_ea_seg(const x86_insn_t *insn);
extern void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg, uint32_t linear,
                                unsigned bytes);

/* Synthetic opcode ids for bytes whose generated insn_tab rows are
 * INVALID.  The interp registry holds 512 slots and the enum ends
 * at I686_OP_COUNT (359 after the RC7b T1 union extension); ids
 * 460..469 are Phase-7 private (moved up from 350 by the sanctioned
 * union extension — docs/lanes/phase-7.md T1 record).  MUST match
 * the identical table in src/x86/decode.c (decode.c synthesizes, this
 * file registers the handlers). */
enum {
    I686_OP7_POP_SS = 460, /* 17                       */
    I686_OP7_CALLF  = 461, /* 9A Ap (m16:16 / m16:32)  */
    I686_OP7_JMPF   = 462, /* EA Ap                    */
    I686_OP7_LES    = 463, /* C4 r,mp16:16/32          */
    I686_OP7_LDS    = 464, /* C5 r,mp                  */
    I686_OP7_RETF   = 465, /* CB                       */
    I686_OP7_LSS    = 466, /* 0F B2 r,mp               */
    I686_OP7_LFS    = 467, /* 0F B4 r,mp               */
    I686_OP7_LGS    = 468, /* 0F B5 r,mp               */
    I686_OP7_PRIV   = 469  /* E4-E7/EC-EF, 0F 20-23 (16-bit code) */
};

_Static_assert(I686_OP_COUNT <= 460u, "Phase-7 synthetic op ids collide with the frozen enum");

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

static unsigned opnd_width(const x86_insn_t *insn)
{
    /* decode.c normalizes pfx_opsize to the EFFECTIVE operand size
     * (66 prefix XOR CS D-bit), which is exactly this convention. */
    return insn->pfx_opsize != 0U ? 16U : 32U;
}

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

/* Stack helpers add the SS base (flat SS: +0, unchanged). */
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

/* Fault mapping SEG_* -> trapno; error code (selector bits) rides
 * exit_dest for the S7 delivery wiring.  EIP is NOT advanced: the fault
 * is resumable at the faulting instruction (E09). */
static int seg_fault(i686_ctx_t *ctx, int f, uint16_t sel)
{
    switch (f) {
    case SEG_F_NP: ctx->exit_arg = 11u; break; /* #NP */
    case SEG_F_SS: ctx->exit_arg = 12u; break; /* #SS */
    default:          ctx->exit_arg = 13u; break; /* #GP */
    }
    ctx->exit_dest = sel;
    ctx->fault_addr = 0u;
    return I686_EXIT_FAULT;
}

static bool non_flat_cs(const i686_ctx_t *ctx)
{
    return !i686_seg_flat_cs(ctx);
}

/* ------------------------------------------------------------------ */
/* MOV sreg (8E) and pops (07/17/1F/0F A1/0F A9)                       */
/* ------------------------------------------------------------------ */

static int h_seg_mov_swew(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_reg < I686_SEG_COUNT) {
        uint16_t sel = (uint16_t)x86_rm_read(ctx, insn, 16U);
        int f;

        if (insn->modrm_reg == I686_SEG_CS) {
            return seg_fault(ctx, SEG_F_GP, 0); /* mov to CS: #GP(0) */
        }
        f = i686_seg_load(ctx, insn->modrm_reg, sel);
        if (f != SEG_F_OK) {
            return seg_fault(ctx, f, sel);
        }
    }
    ctx->eip += (uint32_t)insn->len;
    return I686_INTERP_CONTINUE;
}

static int h_seg_pop_sreg(i686_ctx_t *ctx, const x86_insn_t *insn, uint8_t seg)
{
    unsigned width = opnd_width(insn);
    uint16_t sel = (uint16_t)stack_pop(ctx, width);
    int f = i686_seg_load(ctx, seg, sel);

    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel);
    }
    ctx->eip += (uint32_t)insn->len;
    return I686_INTERP_CONTINUE;
}

static int h_seg_pop_es(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_pop_sreg(ctx, insn, I686_SEG_ES);
}
static int h_seg_pop_ss(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_pop_sreg(ctx, insn, I686_SEG_SS);
}
static int h_seg_pop_ds(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_pop_sreg(ctx, insn, I686_SEG_DS);
}
static int h_seg_pop_fs(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_pop_sreg(ctx, insn, I686_SEG_FS);
}
static int h_seg_pop_gs(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_pop_sreg(ctx, insn, I686_SEG_GS);
}

/* ------------------------------------------------------------------ */
/* Far transfers                                                       */
/* ------------------------------------------------------------------ */

/* Far pointer rides insn->imm: offset (low, operand-size wide) | selector
 * (high, 16 bits) — the decode.c packing for 9A/EA. */
static void far_target(const x86_insn_t *insn, uint32_t *off, uint16_t *sel)
{
    unsigned bytes = opnd_width(insn) / 8U;

    *off = (bytes == 2u) ? (insn->imm & 0xFFFFu) : insn->imm;
    *sel = (uint16_t)(insn->imm >> (bytes * 8U));
}

static int h_seg_callf(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t off;
    uint16_t sel;
    uint16_t old_cs = ctx->seg_sel[I686_SEG_CS];
    uint32_t next = ctx->eip + (uint32_t)insn->len;
    int f;

    far_target(insn, &off, &sel);
    f = i686_seg_load(ctx, I686_SEG_CS, sel);
    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel); /* nothing pushed */
    }
    /* SDM: CS pushed first (padded to the operand size), then EIP. */
    stack_push(ctx, old_cs, (width == 16U) ? 16U : 32U);
    stack_push(ctx, (width == 16U) ? (next & 0xFFFFu) : next, width);
    ctx->eip = (width == 16U) ? (off & 0xFFFFu) : off;
    if (ctx->cs_d == 0U) {
        ctx->eip &= 0xFFFFu; /* EIP truncated for D=0 targets (E09 gap 4) */
    }
    return I686_INTERP_CONTINUE;
}

static int h_seg_jmpf(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t off;
    uint16_t sel;
    int f;

    far_target(insn, &off, &sel);
    f = i686_seg_load(ctx, I686_SEG_CS, sel);
    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel);
    }
    ctx->eip = (width == 16U) ? (off & 0xFFFFu) : off;
    if (ctx->cs_d == 0U) {
        ctx->eip &= 0xFFFFu;
    }
    return I686_INTERP_CONTINUE;
}

/* lret/retf (CB): pops EIP then CS at the instruction operand size; the
 * popped EIP is truncated to 16 bits when the returned-to CS has D=0.
 * 0x66 in 16-bit code (or no 66 in 32-bit code) selects 32-bit pops —
 * the thunk cross-size matrix Wine's CallTo16 depends on (E09 gap 4). */
static int h_seg_retf(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    uint32_t new_eip = stack_pop(ctx, width);
    uint16_t sel = (uint16_t)stack_pop(ctx, width);
    int f = i686_seg_load(ctx, I686_SEG_CS, sel);

    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel);
    }
    ctx->eip = (width == 16U) ? (new_eip & 0xFFFFu) : new_eip;
    if (ctx->cs_d == 0U) {
        ctx->eip &= 0xFFFFu;
    }
    return I686_INTERP_CONTINUE;
}

/* iret (CF), non-v86: pops EIP, CS, EFLAGS at the operand size.  v86 owns
 * iret (Phase 8). */
static int h_seg_iret(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width;
    uint32_t new_eip;
    uint32_t flg;
    uint16_t sel;
    int f;

    if (ctx->v86 != 0u) {
        return I686_EXIT_UNDEF;
    }
    width = opnd_width(insn);
    new_eip = stack_pop(ctx, width);
    sel = (uint16_t)stack_pop(ctx, width);
    flg = stack_pop(ctx, width);
    f = i686_seg_load(ctx, I686_SEG_CS, sel);
    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel);
    }
    ctx->eip = (width == 16U) ? (new_eip & 0xFFFFu) : new_eip;
    if (ctx->cs_d == 0U) {
        ctx->eip &= 0xFFFFu;
    }
    ctx->eflags = (flg & 0x00FDFFFFu) | 0x2u; /* bit 1 always set */
    ctx->lazy_op = I686_FOP_NONE;
    return I686_INTERP_CONTINUE;
}

/* ------------------------------------------------------------------ */
/* les/lds/lss/lfs/lgs                                                 */
/* ------------------------------------------------------------------ */

static int h_seg_lxs(i686_ctx_t *ctx, const x86_insn_t *insn, uint8_t sreg)
{
    unsigned width = opnd_width(insn);
    unsigned bytes = width / 8U;
    uint32_t ea = x86_ea_compute(ctx, insn);
    uint32_t off;
    uint16_t sel;
    int f;

    /* Limit-check the whole far-pointer extent (offset + selector) with
     * the EA's effective segment before either load commits. */
    i686_seg_check_data(ctx, x86_ea_seg(insn), ea, bytes + 2u);
    off = mem_load(ctx, ea, bytes);
    sel = (uint16_t)mem_load(ctx, ea + bytes, 2u);

    /* SDM: the segment register load is validated first; on fault the
     * destination register is unchanged (LSS stays atomic). */
    f = i686_seg_load(ctx, sreg, sel);
    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel);
    }
    x86_reg_write(ctx, insn->modrm_reg, width, off);
    ctx->eip += (uint32_t)insn->len;
    return I686_INTERP_CONTINUE;
}

static int h_seg_les(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_lxs(ctx, insn, I686_SEG_ES);
}
static int h_seg_lds(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_lxs(ctx, insn, I686_SEG_DS);
}
static int h_seg_lss(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_lxs(ctx, insn, I686_SEG_SS);
}
static int h_seg_lfs(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_lxs(ctx, insn, I686_SEG_FS);
}
static int h_seg_lgs(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return h_seg_lxs(ctx, insn, I686_SEG_GS);
}

/* ------------------------------------------------------------------ */
/* int NN / privileged instructions                                    */
/* ------------------------------------------------------------------ */

static int h_seg_int(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t vec = (uint8_t)insn->imm;

    if (vec == 0x80U) {
        ctx->eip += (uint32_t)insn->len; /* resume past the int 0x80 */
        ctx->exit_arg = 0x80U;
        return I686_EXIT_SYSCALL; /* D12, v1 behaviour unchanged */
    }
    if (ctx->v86 == 0u && non_flat_cs(ctx)) {
        /* E09: int NN (NN != 0x80) in non-flat code is a resolvable
         * fault with EIP at the int (Wine's INSTR/DOSVM/DPMI hook). */
        return seg_fault(ctx, SEG_F_GP, 0);
    }
    return I686_EXIT_UNDEF; /* flat: Phase-1 behaviour unchanged */
}

static int h_seg_cli(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (ctx->v86 == 0u && non_flat_cs(ctx)) {
        return seg_fault(ctx, SEG_F_GP, 0); /* E09 gap 6 */
    }
    ctx->eflags = i686_flags_read(ctx) & ~I686_EF_IF;
    ctx->lazy_op = I686_FOP_NONE;
    ctx->eip += (uint32_t)insn->len;
    return I686_INTERP_CONTINUE;
}

static int h_seg_sti(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (ctx->v86 == 0u && non_flat_cs(ctx)) {
        return seg_fault(ctx, SEG_F_GP, 0);
    }
    ctx->eflags = i686_flags_read(ctx) | I686_EF_IF;
    ctx->lazy_op = I686_FOP_NONE;
    ctx->eip += (uint32_t)insn->len;
    return I686_INTERP_CONTINUE;
}

static int h_seg_hlt(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (ctx->v86 == 0u && non_flat_cs(ctx)) {
        return seg_fault(ctx, SEG_F_GP, 0);
    }
    ctx->eip += (uint32_t)insn->len;
    return I686_EXIT_HLT; /* v1 behaviour unchanged */
}

/* Synthetic privileged set (IN/OUT imm8/DX, MOV CR/DR): only synthesized
 * by decode.c in 16-bit (cs_d == 0) code; resumable #GP(0), E09 gap 6. */
static int h_seg_priv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)insn;
    if (ctx->v86 != 0u) {
        return I686_EXIT_UNDEF; /* Phase 8 owns v86 I/O */
    }
    return seg_fault(ctx, SEG_F_GP, 0);
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

void i686_interp_seg_init(void)
{
    static int s_done;
    if (s_done) {
        return;
    }
    s_done = 1;

    i686_interp_register(I686_OP_MOV_SwEw, h_seg_mov_swew);
    i686_interp_register(I686_OP_POP_ES, h_seg_pop_es);
    i686_interp_register(I686_OP_POP_DS, h_seg_pop_ds);
    i686_interp_register(I686_OP_POP_FS, h_seg_pop_fs);
    i686_interp_register(I686_OP_POP_GS, h_seg_pop_gs);
    i686_interp_register(I686_OP_IRET, h_seg_iret);
    i686_interp_register(I686_OP_INT_Ib, h_seg_int);
    i686_interp_register(I686_OP_CLI, h_seg_cli);
    i686_interp_register(I686_OP_STI, h_seg_sti);
    i686_interp_register(I686_OP_HLT, h_seg_hlt);

    i686_interp_register(I686_OP7_POP_SS, h_seg_pop_ss);
    i686_interp_register(I686_OP7_CALLF, h_seg_callf);
    i686_interp_register(I686_OP7_JMPF, h_seg_jmpf);
    i686_interp_register(I686_OP7_LES, h_seg_les);
    i686_interp_register(I686_OP7_LDS, h_seg_lds);
    i686_interp_register(I686_OP7_RETF, h_seg_retf);
    i686_interp_register(I686_OP7_LSS, h_seg_lss);
    i686_interp_register(I686_OP7_LFS, h_seg_lfs);
    i686_interp_register(I686_OP7_LGS, h_seg_lgs);
    i686_interp_register(I686_OP7_PRIV, h_seg_priv);

    {
        /* Syscall registration for the descriptor model (src/os/ldt.c):
         * called here because the frozen syscalls.c init list is closed;
         * the coordinator moves this into i686_syscalls_init_once at S7
         * (exact snippet in docs/lanes/phase-7.md).  modify_ldt(123) and
         * get_thread_area(244) have no v1 handler; set_thread_area(243)
         * is re-registered here and later overwritten by the v1
         * syscalls.c init at the first syscall (order documented in the
         * L7a record). */
        extern void i686_syscalls_ldt_init(void);
        i686_syscalls_ldt_init();
    }
}
