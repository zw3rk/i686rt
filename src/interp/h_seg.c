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
                                unsigned bytes, unsigned write);

/* Synthetic opcode ids (I686_OP7_*) are declared in x86/decode.h. */
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

/* Stack helpers add the SS base (flat SS: +0, unchanged).  R7-11: the
 * pointer width follows SS.B (16-bit stacks wrap SP mod 64K, upper ESP
 * preserved) and every access is SS-limit-checked. */
static uint32_t stack_get_sp(i686_ctx_t *ctx)
{
    uint32_t esp = ctx->gpr[I686_REG_ESP];

    return (ctx->ss_b != 0u) ? esp : (esp & 0xFFFFu);
}

static void stack_set_sp(i686_ctx_t *ctx, uint32_t sp)
{
    if (ctx->ss_b != 0u) {
        ctx->gpr[I686_REG_ESP] = sp;
    } else {
        ctx->gpr[I686_REG_ESP] =
            (ctx->gpr[I686_REG_ESP] & 0xFFFF0000u) | (sp & 0xFFFFu);
    }
}

/* Fault mapping SEG_* -> trapno; error code (selector bits) rides
 * exit_dest for the S7 delivery wiring.  EIP is NOT advanced: the fault
 * is resumable at the faulting instruction (E09).  C3f: the fault rides
 * no checkpoint, so it records its channel — deliver_sync classifies by
 * the recorded host signal first, and a stale value from an earlier
 * handled fault would misroute these exits. */
static int seg_fault(i686_ctx_t *ctx, int f, uint16_t sel)
{
    extern void i686_fault_sig_record(int sig);
    switch (f) {
    case SEG_F_NP: ctx->exit_arg = 11u; break; /* #NP */
    case SEG_F_SS: ctx->exit_arg = 12u; break; /* #SS */
    default:          ctx->exit_arg = 13u; break; /* #GP */
    }
    i686_fault_sig_record(11); /* SIGSEGV */
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

/* R7-13: faulting pops stage the whole transfer before committing:
 * peek the selector and validate it while ESP still points at the
 * slot; ESP advances only after the load succeeds. */
static int h_seg_pop_sreg(i686_ctx_t *ctx, const x86_insn_t *insn, uint8_t seg)
{
    unsigned width = opnd_width(insn);
    unsigned bytes = width / 8U;
    uint32_t sp = stack_get_sp(ctx);
    uint32_t linear = ctx->seg_base[I686_SEG_SS] + sp;
    uint16_t sel;
    uint32_t next = sp + bytes;
    int f;

    if (ctx->ss_b == 0u) {
        next &= 0xFFFFu;
    }
    i686_seg_check_data(ctx, I686_SEG_SS, linear, bytes, 0u);
    sel = (uint16_t)mem_load(ctx, linear, width);
    f = i686_seg_load(ctx, seg, sel);
    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel);
    }
    stack_set_sp(ctx, next);
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

/* Far pointer rides insn->far_off/far_sel (R7-3): the 48-bit 16:32
 * target never fit insn->imm. */
static void far_target(const x86_insn_t *insn, uint32_t *off, uint16_t *sel)
{
    unsigned bytes = opnd_width(insn) / 8U;

    *off = (bytes == 2u) ? (insn->far_off & 0xFFFFu) : insn->far_off;
    *sel = insn->far_sel;
}

/* R7-13: the faultable pushes are staged against locals and the new
 * CS validated+loaded only after; a fault anywhere leaves CS/ESP/EIP
 * exactly as the instruction found them. */
static int h_seg_callf(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    unsigned bytes = width / 8U;
    uint32_t off;
    uint16_t sel;
    uint16_t old_cs = ctx->seg_sel[I686_SEG_CS];
    uint32_t next = ctx->eip + (uint32_t)insn->len;
    uint32_t ss = ctx->seg_base[I686_SEG_SS];
    uint32_t mask = (ctx->ss_b != 0u) ? 0xFFFFFFFFu : 0xFFFFu;
    uint32_t sp = (stack_get_sp(ctx) - bytes) & mask;
    uint32_t sp2 = (sp - bytes) & mask;
    int f;

    far_target(insn, &off, &sel);
    /* SDM: CS pushed first (padded to the operand size), then EIP. */
    i686_seg_check_data(ctx, I686_SEG_SS, ss + sp, bytes, 1u);
    i686_seg_check_data(ctx, I686_SEG_SS, ss + sp2, bytes, 1u);
    mem_store(ctx, ss + sp, old_cs, width);
    mem_store(ctx, ss + sp2, (width == 16U) ? (next & 0xFFFFu) : next,
              width);
    f = i686_seg_load(ctx, I686_SEG_CS, sel);
    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel); /* stack/ESP untouched */
    }
    stack_set_sp(ctx, sp2);
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
/* R7-13: both slots are peeked and the incoming CS validated before
 * ESP/EIP commit; a fault leaves the stack and CS untouched. */
static int h_seg_retf(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned width = opnd_width(insn);
    unsigned bytes = width / 8U;
    uint32_t mask = (ctx->ss_b != 0u) ? 0xFFFFFFFFu : 0xFFFFu;
    uint32_t ss = ctx->seg_base[I686_SEG_SS];
    uint32_t sp = stack_get_sp(ctx);
    uint32_t sp2 = (sp + bytes) & mask;
    uint32_t new_eip;
    uint16_t sel;
    uint32_t next = (sp2 + bytes) & mask;
    int f;

    i686_seg_check_data(ctx, I686_SEG_SS, ss + sp, bytes, 0u);
    i686_seg_check_data(ctx, I686_SEG_SS, ss + sp2, bytes, 0u);
    new_eip = mem_load(ctx, ss + sp, width);
    sel = (uint16_t)mem_load(ctx, ss + sp2, width);
    f = i686_seg_load(ctx, I686_SEG_CS, sel);
    if (f != SEG_F_OK) {
        return seg_fault(ctx, f, sel);
    }
    stack_set_sp(ctx, next);
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
    /* R7-13: all three slots peeked and CS validated before anything
     * commits; a fault leaves ESP/CS/EFLAGS untouched. */
    width = opnd_width(insn);
    {
        unsigned bytes = width / 8U;
        uint32_t mask = (ctx->ss_b != 0u) ? 0xFFFFFFFFu : 0xFFFFu;
        uint32_t ss = ctx->seg_base[I686_SEG_SS];
        uint32_t sp = stack_get_sp(ctx);
        uint32_t sp2 = (sp + bytes) & mask;
        uint32_t sp3 = (sp2 + bytes) & mask;
        uint32_t next = (sp3 + bytes) & mask;

        i686_seg_check_data(ctx, I686_SEG_SS, ss + sp, bytes, 0u);
        i686_seg_check_data(ctx, I686_SEG_SS, ss + sp2, bytes, 0u);
        i686_seg_check_data(ctx, I686_SEG_SS, ss + sp3, bytes, 0u);
        new_eip = mem_load(ctx, ss + sp, width);
        sel = (uint16_t)mem_load(ctx, ss + sp2, width);
        flg = mem_load(ctx, ss + sp3, width);
        f = i686_seg_load(ctx, I686_SEG_CS, sel);
        if (f != SEG_F_OK) {
            return seg_fault(ctx, f, sel);
        }
        stack_set_sp(ctx, next);
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

    /* Register-form LES etc. are #UD (R7-2); the far pointer is only
     * a memory operand. */
    if (insn->modrm_mod == 3U || insn->ea_has == 0U) {
        return I686_EXIT_UNDEF;
    }
    /* Limit-check the whole far-pointer extent (offset + selector) with
     * the EA's effective segment before either load commits. */
    i686_seg_check_data(ctx, x86_ea_seg(insn), ea, bytes + 2u, 0u);
    /* R7-2: the local mem_load takes a BIT width; byte counts execute
     * zero loop iterations and return zero. */
    off = mem_load(ctx, ea, width);
    sel = (uint16_t)mem_load(ctx, ea + bytes, 16u);

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

/* R7-23: the runtime models CPL=3 (IOPL=0), so CLI/STI/HLT fault
 * with #GP(0) in protected mode regardless of CS flatness; v86 traps
 * to the Phase-8 owner instead of executing. */
static int h_seg_cli(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)insn;
    if (ctx->v86 != 0u) {
        return I686_EXIT_UNDEF;
    }
    return seg_fault(ctx, SEG_F_GP, 0);
}

static int h_seg_sti(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)insn;
    if (ctx->v86 != 0u) {
        return I686_EXIT_UNDEF;
    }
    return seg_fault(ctx, SEG_F_GP, 0);
}

static int h_seg_hlt(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    (void)insn;
    if (ctx->v86 != 0u) {
        return I686_EXIT_UNDEF;
    }
    return seg_fault(ctx, SEG_F_GP, 0);
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
