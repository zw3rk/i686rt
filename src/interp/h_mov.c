/*
 * src/interp/h_mov.c — MOV, data movement, stack, CPUID handlers (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Handlers follow the frozen contract in src/interp/interp.h: each returns
 * I686_INTERP_CONTINUE and advances ctx->eip by insn->len.  Register and
 * r/m operands go through the frozen decode.c helpers (x86_reg_read/write,
 * x86_rm_read/write); direct memory accesses (moffs, stack, XLAT, ENTER
 * frame copies) resolve through ctx->seg_base[] + i686_guest_ptr() with
 * 32-bit wrapping linear addresses (D4: never sign-extend a guest address).
 *
 * This file's init (i686_interp_mov_init) also registers the string ops
 * from src/interp/h_string.c: interp.h freezes one init declaration per
 * handler module and only declares i686_interp_mov_init for this pair.
 */

#include <stdint.h>

#include "interp/interp.h"

/* Defined in src/interp/h_string.c. */
void i686_interp_string_register(void);

/* 0xFF sentinel in the frozen x86_insn_t (pfx_seg "none", ea_base/index
 * "none") — no named macro exists in the frozen headers. */
#define I686_NONE 0xFFU

/* Shared epilogue: advance EIP, continue (frozen handler contract). */
static int interp_done(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

/* Operand size in bytes for "v"/"z" operands: the 66 prefix selects the
 * 16-bit forms (v1 flat 32-bit code, so both ride these handlers). */
static unsigned opsz(const x86_insn_t *insn)
{
    return (insn->pfx_opsize != 0U) ? 16U : 32U;
}

/* Segment used for a direct memory access: explicit override else the
 * caller's default (DS for data references, SS for the stack). */
static uint8_t seg_used(const x86_insn_t *insn, uint8_t defseg)
{
    return (insn->pfx_seg != I686_NONE) ? insn->pfx_seg : defseg;
}

/* Little-endian guest memory access at a 32-bit wrapping linear address.
 * The window mapping guarantees [va, va+width) is mapped (Phase 0 rt32 VM);
 * the unit test window keeps addresses well inside its 64 KiB slab. */
static uint32_t mem_read(const i686_ctx_t *ctx, uint32_t va, unsigned width)
{
    const uint8_t *p = (const uint8_t *)i686_guest_ptr(ctx, va);
    uint32_t v = 0;

    for (unsigned i = 0; i < width; i++) {
        v |= (uint32_t)p[i] << (8U * i);
    }
    return v;
}

static void mem_write(i686_ctx_t *ctx, uint32_t va, unsigned width, uint32_t val)
{
    uint8_t *p = (uint8_t *)i686_guest_ptr(ctx, va);

    for (unsigned i = 0; i < width; i++) {
        p[i] = (uint8_t)(val >> (8U * i));
    }
}

/*
 * Segment load (MOV_SwEw, POP sreg).  Flat model v1 (D8): selector 0
 * gives base 0; a nonzero FS/GS selector resolves through the emulated
 * GDT TLS slots (entries 6..8 -> selectors 0x33/0x3b/0x43, installed by
 * set_thread_area); every other selector keeps base 0 for now.
 * TODO Phase 7: full GDT/LDT descriptor walk (modify_ldt, Wine %fs).
 */
static uint32_t tls_base_for_sel(const i686_ctx_t *ctx, uint16_t sel)
{
    uint32_t idx = (uint32_t)sel >> 3;

    if ((sel & 0x4U) != 0U) {
        return 0U; /* TI=1: LDT selectors resolve in Phase 7. */
    }
    if (idx >= 6U && idx <= 8U) {
        return ctx->gdt_tls_slots[idx - 6U];
    }
    return 0U;
}

static void seg_load(i686_ctx_t *ctx, uint8_t seg, uint16_t sel)
{
    uint32_t base = 0U;

    if (sel != 0U && (seg == I686_SEG_FS || seg == I686_SEG_GS)) {
        base = tls_base_for_sel(ctx, sel);
    }
    ctx->seg_sel[seg] = sel;
    ctx->seg_base[seg] = base;
}

/* ------------------------------------------------------------------ */
/* MOV, register/memory forms                                          */
/* ------------------------------------------------------------------ */

static int h_mov_ebgb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_rm_write(ctx, insn, 8U, x86_reg_read(ctx, insn->modrm_reg, 8U));
    return interp_done(ctx, insn);
}

static int h_mov_evgv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_rm_write(ctx, insn, opsz(insn),
                 x86_reg_read(ctx, insn->modrm_reg, opsz(insn)));
    return interp_done(ctx, insn);
}

static int h_mov_gbeb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, insn->modrm_reg, 8U, x86_rm_read(ctx, insn, 8U));
    return interp_done(ctx, insn);
}

static int h_mov_gvev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, insn->modrm_reg, opsz(insn), x86_rm_read(ctx, insn, opsz(insn)));
    return interp_done(ctx, insn);
}

/*
 * moffs forms (A0–A3) have no ModRM byte.  Assumption (coordinated with
 * the decoder contract): the frozen decoder puts the full offset into
 * insn->ea_disp (mirrored in imm) and leaves segmentation to the standard
 * DS-default / pfx_seg-override rule applied here.  67 narrows moffs to
 * 16 bits at decode time, so ea_disp is already the right offset.
 */
static uint32_t moffs_va(const i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return insn->ea_disp + ctx->seg_base[seg_used(insn, I686_SEG_DS)];
}

static int h_mov_alob(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, I686_REG_EAX, 8U, mem_read(ctx, moffs_va(ctx, insn), 1U));
    return interp_done(ctx, insn);
}

static int h_mov_eaxov(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, I686_REG_EAX, opsz(insn),
                   mem_read(ctx, moffs_va(ctx, insn), opsz(insn) / 8U));
    return interp_done(ctx, insn);
}

static int h_mov_obal(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    mem_write(ctx, moffs_va(ctx, insn), 1U, x86_reg_read(ctx, I686_REG_EAX, 8U));
    return interp_done(ctx, insn);
}

static int h_mov_oveax(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    mem_write(ctx, moffs_va(ctx, insn), opsz(insn) / 8U,
              x86_reg_read(ctx, I686_REG_EAX, opsz(insn)));
    return interp_done(ctx, insn);
}

/* Immediate forms.  B0–BF put the destination in modrm_reg; C6/C7 /0
 * target the r/m operand.  imm is right-aligned raw per decode.h. */
static int h_mov_gbib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, insn->modrm_reg, 8U, insn->imm);
    return interp_done(ctx, insn);
}

static int h_mov_gviv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, insn->modrm_reg, opsz(insn), insn->imm);
    return interp_done(ctx, insn);
}

static int h_mov_ebib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_rm_write(ctx, insn, 8U, insn->imm);
    return interp_done(ctx, insn);
}

static int h_mov_eviz(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_rm_write(ctx, insn, opsz(insn), insn->imm);
    return interp_done(ctx, insn);
}

/* MOV r/m16, Sreg (8C /r) and MOV Sreg, r/m16 (8E /r): the operand size
 * is fixed 16-bit regardless of the 66 prefix.  reg field 6/7 have no
 * segment encoding: architecturally invalid forms change no state (D2:
 * never assert). */
static int h_mov_ewsw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_reg < I686_SEG_COUNT) {
        x86_rm_write(ctx, insn, 16U, ctx->seg_sel[insn->modrm_reg]);
    }
    return interp_done(ctx, insn);
}

static int h_mov_swew(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_reg < I686_SEG_COUNT) {
        seg_load(ctx, insn->modrm_reg, (uint16_t)x86_rm_read(ctx, insn, 16U));
    }
    return interp_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* LEA / MOVZX / MOVSX / BSWAP / CPUID / XLAT                          */
/* ------------------------------------------------------------------ */

/*
 * LEA_GvM: the destination is the EA *offset* — the segment base is NOT
 * added (x86 LEA ignores segment overrides), so x86_ea_compute (which
 * includes the segment base per decode.h) cannot be used.  Components
 * are read at address-size width; under the 0x67 prefix the 16-bit
 * components wrap the sum at 64 KiB.
 */
static int h_lea_gvm(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t off = insn->ea_disp;
    unsigned addr_w = (insn->pfx_addrsize != 0U) ? 2U : 4U;

    if (insn->ea_base != I686_NONE) {
        off += x86_reg_read(ctx, insn->ea_base, addr_w);
    }
    if (insn->ea_index != I686_NONE) {
        off += x86_reg_read(ctx, insn->ea_index, addr_w) << insn->ea_scale;
    }
    if (insn->pfx_addrsize != 0U) {
        off &= 0xffffU;
    }
    x86_reg_write(ctx, insn->modrm_reg, opsz(insn), off);
    return interp_done(ctx, insn);
}

static int h_movzx_gveb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, insn->modrm_reg, opsz(insn), x86_rm_read(ctx, insn, 8U));
    return interp_done(ctx, insn);
}

static int h_movzx_gvew(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, insn->modrm_reg, opsz(insn), x86_rm_read(ctx, insn, 16U));
    return interp_done(ctx, insn);
}

static int h_movsx_gveb(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v = (uint32_t)(int32_t)(int8_t)x86_rm_read(ctx, insn, 8U);

    x86_reg_write(ctx, insn->modrm_reg, opsz(insn), v);
    return interp_done(ctx, insn);
}

static int h_movsx_gvew(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v = (uint32_t)(int32_t)(int16_t)x86_rm_read(ctx, insn, 16U);

    x86_reg_write(ctx, insn->modrm_reg, opsz(insn), v);
    return interp_done(ctx, insn);
}

/* 0F C8+r.  A 66-prefixed BSWAP is architecturally undefined; we execute
 * the 32-bit reversal rather than faulting (D2: never assert). */
static int h_bswap_gv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t r = insn->modrm_reg & 7U;
    uint32_t v = ctx->gpr[r];
    uint32_t res = ((v & 0x000000ffU) << 24) | ((v & 0x0000ff00U) << 8) |
                   ((v & 0x00ff0000U) >> 8) | ((v & 0xff000000U) >> 24);

    ctx->gpr[r] = res;
    return interp_done(ctx, insn);
}

/*
 * CPUID per SPEC D10: vendor "GenuineIntel", family 6, exactly the v1
 * feature set in leaf 1 EDX (ECX = 0: no SSE3+).  Leaf 0 reports max
 * basic leaf 1 (leaf 2 is not synthesized); leaf 0x80000000 reports max
 * extended leaf 0x80000001; every other leaf reads as zero.
 */
#define CPUID_EDX_FPU  (1U << 0)
#define CPUID_EDX_TSC  (1U << 4)
#define CPUID_EDX_CX8  (1U << 8)
#define CPUID_EDX_CMOV (1U << 15)
#define CPUID_EDX_MMX  (1U << 23)
#define CPUID_EDX_FXSR (1U << 24)
#define CPUID_EDX_SSE  (1U << 25)
#define CPUID_EDX_SSE2 (1U << 26)
#define CPUID_FEATURE_EDX                                                        \
    (CPUID_EDX_FPU | CPUID_EDX_TSC | CPUID_EDX_CX8 | CPUID_EDX_CMOV |            \
     CPUID_EDX_MMX | CPUID_EDX_FXSR | CPUID_EDX_SSE | CPUID_EDX_SSE2) /* 0x07808111 */

static int h_cpuid(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t leaf = ctx->gpr[I686_REG_EAX];
    uint32_t a = 0U, b = 0U, c = 0U, d = 0U;

    if (leaf == 0U) {
        a = 1U;          /* max basic leaf (leaf 2 not synthesized) */
        b = 0x756e6547U; /* EBX = "Genu" */
        d = 0x49656e69U; /* EDX = "ineI" */
        c = 0x6c65746eU; /* ECX = "ntel" */
    } else if (leaf == 1U) {
        a = 0x00000600U; /* family 6, model 0, stepping 0 */
        d = CPUID_FEATURE_EDX;
    } else if (leaf == 0x80000000U) {
        a = 0x80000001U; /* max extended leaf */
    } else if (leaf == 0x80000001U) {
        /* Minimal extended features: nothing advertised in v1. */
    }
    ctx->gpr[I686_REG_EAX] = a;
    ctx->gpr[I686_REG_EBX] = b;
    ctx->gpr[I686_REG_ECX] = c;
    ctx->gpr[I686_REG_EDX] = d;
    return interp_done(ctx, insn);
}

/* XLAT: AL <- [DS:EBX + AL], DS overridable.  67 uses the 16-bit BX
 * offset (masked here); the +AL part stays 8-bit either way. */
static int h_xlat(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t base = ctx->gpr[I686_REG_EBX];

    if (insn->pfx_addrsize != 0U) {
        base &= 0xffffU;
    }
    x86_reg_write(ctx, I686_REG_EAX, 8U,
                  mem_read(ctx, base + x86_reg_read(ctx, I686_REG_EAX, 8U) +
                                   ctx->seg_base[seg_used(insn, I686_SEG_DS)], 1U));
    return interp_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Stack                                                               */
/* ------------------------------------------------------------------ */

/* All pushes/pops run against SS.  ESP arithmetic wraps at 32 bits; the
 * 66 prefix narrows the pushed/pop width to 2 bytes but ESP stays the
 * full 32-bit register (32-bit mode stack). */
/* width in BITS (8/16/32), consistent with the frozen accessors. */
static void push_val(i686_ctx_t *ctx, uint32_t val, unsigned width)
{
    unsigned bytes = width / 8U;
    uint32_t esp = ctx->gpr[I686_REG_ESP] - bytes;

    ctx->gpr[I686_REG_ESP] = esp;
    mem_write(ctx, ctx->seg_base[I686_SEG_SS] + esp, bytes, val);
}

static uint32_t pop_val(i686_ctx_t *ctx, unsigned width)
{
    unsigned bytes = width / 8U;
    uint32_t esp = ctx->gpr[I686_REG_ESP];
    uint32_t v = mem_read(ctx, ctx->seg_base[I686_SEG_SS] + esp, bytes);

    ctx->gpr[I686_REG_ESP] = esp + bytes;
    return v;
}

/* 50+r.  PUSH ESP pushes the pre-decrement value: the register read is
 * evaluated before push_val executes. */
static int h_push_gv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = opsz(insn);

    push_val(ctx, x86_reg_read(ctx, insn->modrm_reg, w), w);
    return interp_done(ctx, insn);
}

/* 58+r.  POP ESP: the popped value wins over the increment (pop_val
 * runs first, the register write second). */
static int h_pop_gv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    x86_reg_write(ctx, insn->modrm_reg, opsz(insn), pop_val(ctx, opsz(insn)));
    return interp_done(ctx, insn);
}

static int h_push_iz(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    push_val(ctx, insn->imm, opsz(insn));
    return interp_done(ctx, insn);
}

/* 6A: the immediate byte is sign-extended to the operand size (I8SX). */
static int h_push_ib(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v = (uint32_t)(int32_t)(int8_t)(insn->imm & 0xffU);

    push_val(ctx, v, opsz(insn));
    return interp_done(ctx, insn);
}

/* FF /6. */
static int h_push_ev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = opsz(insn);

    push_val(ctx, x86_rm_read(ctx, insn, w), w);
    return interp_done(ctx, insn);
}

/* 8F /0.  POP r/m: ESP is incremented before the r/m operand is written
 * (the x86 rule for esp-relative destinations); x86_rm_write computes
 * the EA from register state at that point. */
static int h_pop_ev(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = opsz(insn);

    x86_rm_write(ctx, insn, w, pop_val(ctx, w));
    return interp_done(ctx, insn);
}

/* 60: push AX,CX,DX,BX,SP,BP,SI,DI — the SP slot gets the ORIGINAL
 * value from before any of the eight pushes. */
static int h_pusha(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = opsz(insn);
    uint32_t orig_sp = ctx->gpr[I686_REG_ESP];

    push_val(ctx, x86_reg_read(ctx, I686_REG_EAX, w), w);
    push_val(ctx, x86_reg_read(ctx, I686_REG_ECX, w), w);
    push_val(ctx, x86_reg_read(ctx, I686_REG_EDX, w), w);
    push_val(ctx, x86_reg_read(ctx, I686_REG_EBX, w), w);
    push_val(ctx, orig_sp, w);
    push_val(ctx, x86_reg_read(ctx, I686_REG_EBP, w), w);
    push_val(ctx, x86_reg_read(ctx, I686_REG_ESI, w), w);
    push_val(ctx, x86_reg_read(ctx, I686_REG_EDI, w), w);
    return interp_done(ctx, insn);
}

/* 61: pop DI,SI,BP,skip SP,BX,DX,CX,AX.  The popped SP value is
 * architecturally discarded, but the stack slot is consumed. */
static int h_popa(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = opsz(insn);

    x86_reg_write(ctx, I686_REG_EDI, w, pop_val(ctx, w));
    x86_reg_write(ctx, I686_REG_ESI, w, pop_val(ctx, w));
    x86_reg_write(ctx, I686_REG_EBP, w, pop_val(ctx, w));
    (void)pop_val(ctx, w); /* SP slot: discarded */
    x86_reg_write(ctx, I686_REG_EBX, w, pop_val(ctx, w));
    x86_reg_write(ctx, I686_REG_EDX, w, pop_val(ctx, w));
    x86_reg_write(ctx, I686_REG_ECX, w, pop_val(ctx, w));
    x86_reg_write(ctx, I686_REG_EAX, w, pop_val(ctx, w));
    return interp_done(ctx, insn);
}

/*
 * ENTER imm16, imm8 (C8).  Decoder assumption (documented for S1
 * alignment): the two immediates are packed right-aligned in insn->imm
 * as imm16 | (imm8 << 16) with imm_size = 3.  The level is masked to
 * 5 bits per the architecture.  Full frame-copy semantics (any level):
 *   push EBP; frame := ESP;
 *   for i = 1..level-1: EBP -= w; push [SS:EBP];   (copy of the caller
 *   display, read from the ORIGINAL EBP minus i*w)
 *   push frame; EBP := frame; ESP -= imm16.
 */
static int h_enter(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = opsz(insn);
    uint32_t size = insn->imm & 0xffffU;
    uint32_t level = (insn->imm >> 16) & 0x1fU;
    uint32_t ebp = ctx->gpr[I686_REG_EBP];
    uint32_t ss = ctx->seg_base[I686_SEG_SS];
    uint32_t frame;

    push_val(ctx, ebp, w);
    frame = ctx->gpr[I686_REG_ESP];
    for (uint32_t i = 1U; i < level; i++) {
        ebp -= w;
        push_val(ctx, mem_read(ctx, ss + ebp, w), w);
    }
    if (level > 0U) {
        push_val(ctx, frame, w);
    }
    ctx->gpr[I686_REG_EBP] = frame;
    ctx->gpr[I686_REG_ESP] -= size;
    return interp_done(ctx, insn);
}

/* C9: MOV SP/ESP, BP/EBP then POP BP/EBP (writes at operand-size width,
 * preserving the upper register bits in the 16-bit form). */
static int h_leave(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned w = opsz(insn);

    x86_reg_write(ctx, I686_REG_ESP, w, x86_reg_read(ctx, I686_REG_EBP, w));
    x86_reg_write(ctx, I686_REG_EBP, w, pop_val(ctx, w));
    return interp_done(ctx, insn);
}

/* 06/0E/0F A0/A8: push the 16-bit selector, zero-extended to the
 * operand-size push width (4 bytes plain, 2 under 66). */
static int h_push_sreg(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t seg;

    switch (insn->op) {
    case I686_OP_PUSH_ES: seg = I686_SEG_ES; break;
    case I686_OP_PUSH_DS: seg = I686_SEG_DS; break;
    case I686_OP_PUSH_FS: seg = I686_SEG_FS; break;
    default:              seg = I686_SEG_GS; break;
    }
    push_val(ctx, ctx->seg_sel[seg], opsz(insn));
    return interp_done(ctx, insn);
}

/* 07/17/0F A1/A9: pop the selector (low 16 bits of the popped slot) and
 * reload the segment base with the same rules as MOV_SwEw. */
static int h_pop_sreg(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint8_t seg;

    switch (insn->op) {
    case I686_OP_POP_ES: seg = I686_SEG_ES; break;
    case I686_OP_POP_DS: seg = I686_SEG_DS; break;
    case I686_OP_POP_FS: seg = I686_SEG_FS; break;
    default:             seg = I686_SEG_GS; break;
    }
    seg_load(ctx, seg, (uint16_t)pop_val(ctx, opsz(insn)));
    return interp_done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Registration                                                        */
/* ------------------------------------------------------------------ */

void i686_interp_mov_init(void)
{
    i686_interp_register(I686_OP_MOV_EbGb, h_mov_ebgb);
    i686_interp_register(I686_OP_MOV_EvGv, h_mov_evgv);
    i686_interp_register(I686_OP_MOV_GbEb, h_mov_gbeb);
    i686_interp_register(I686_OP_MOV_GvEv, h_mov_gvev);
    i686_interp_register(I686_OP_MOV_ALOb, h_mov_alob);
    i686_interp_register(I686_OP_MOV_eAXOv, h_mov_eaxov);
    i686_interp_register(I686_OP_MOV_ObAL, h_mov_obal);
    i686_interp_register(I686_OP_MOV_OveAX, h_mov_oveax);
    i686_interp_register(I686_OP_MOV_GbIb, h_mov_gbib);
    i686_interp_register(I686_OP_MOV_GvIv, h_mov_gviv);
    i686_interp_register(I686_OP_MOV_EbIb, h_mov_ebib);
    i686_interp_register(I686_OP_MOV_EvIz, h_mov_eviz);
    i686_interp_register(I686_OP_MOV_EwSw, h_mov_ewsw);
    i686_interp_register(I686_OP_MOV_SwEw, h_mov_swew);

    i686_interp_register(I686_OP_LEA_GvM, h_lea_gvm);
    i686_interp_register(I686_OP_MOVZX_GvEb, h_movzx_gveb);
    i686_interp_register(I686_OP_MOVZX_GvEw, h_movzx_gvew);
    i686_interp_register(I686_OP_MOVSX_GvEb, h_movsx_gveb);
    i686_interp_register(I686_OP_MOVSX_GvEw, h_movsx_gvew);
    i686_interp_register(I686_OP_BSWAP_Gv, h_bswap_gv);
    i686_interp_register(I686_OP_CPUID, h_cpuid);
    i686_interp_register(I686_OP_XLAT, h_xlat);

    i686_interp_register(I686_OP_PUSH_Gv, h_push_gv);
    i686_interp_register(I686_OP_POP_Gv, h_pop_gv);
    i686_interp_register(I686_OP_PUSH_Iz, h_push_iz);
    i686_interp_register(I686_OP_PUSH_Ib, h_push_ib);
    i686_interp_register(I686_OP_PUSH_Ev, h_push_ev);
    i686_interp_register(I686_OP_POP_Ev, h_pop_ev);
    i686_interp_register(I686_OP_PUSHA, h_pusha);
    i686_interp_register(I686_OP_POPA, h_popa);
    i686_interp_register(I686_OP_ENTER, h_enter);
    i686_interp_register(I686_OP_LEAVE, h_leave);
    i686_interp_register(I686_OP_PUSH_ES, h_push_sreg);
    i686_interp_register(I686_OP_POP_ES, h_pop_sreg);
    i686_interp_register(I686_OP_PUSH_DS, h_push_sreg);
    i686_interp_register(I686_OP_POP_DS, h_pop_sreg);
    i686_interp_register(I686_OP_PUSH_FS, h_push_sreg);
    i686_interp_register(I686_OP_POP_FS, h_pop_sreg);
    i686_interp_register(I686_OP_PUSH_GS, h_push_sreg);
    i686_interp_register(I686_OP_POP_GS, h_pop_sreg);

    /* String ops (src/interp/h_string.c) ride this module's init. */
    i686_interp_string_register();
}
