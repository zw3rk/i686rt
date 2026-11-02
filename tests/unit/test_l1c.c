/*
 * tests/unit/test_l1c.c — host-native unit driver for the L1c handlers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Builds hand-made x86_insn_t values and drives the handlers in
 * src/interp/h_mov.c and src/interp/h_string.c against a fake 64 KiB
 * guest window (guest_base = malloc'ed slab).  The coordinator-owned
 * translation units (decode.c, flags.c, interp.c) are represented by
 * minimal reference implementations of exactly the frozen symbols the
 * handlers import: x86_reg_read/write, x86_rm_read/write, the lazy
 * i686_flags_sub recording, and i686_interp_register itself.
 *
 * Flag effects are asserted on the lazy descriptor (lazy_op/src1/src2/
 * res), not on materialized EFLAGS — flags.c is deliberately absent.
 * DF is driven directly through ctx->eflags (bit 10 lives outside the
 * lazy descriptor per SPEC D6).  Prints "L1C OK" on success.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interp/interp.h"
#include "interp/flags.h"

#define T_WIN_SIZE 0x10000U

static uint8_t *t_win;
static int t_fails;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            t_fails++;                                                       \
            printf("FAIL %d: %s\n", __LINE__, #cond);                        \
        }                                                                    \
    } while (0)

/* Direct guest-window access (endian-independent byte math). */
static uint32_t t_gm_read(const i686_ctx_t *ctx, uint32_t va, unsigned width)
{
    const uint8_t *p = (const uint8_t *)i686_guest_ptr(ctx, va);
    uint32_t v = 0;

    for (unsigned i = 0; i < width; i++) {
        v |= (uint32_t)p[i] << (8U * i);
    }
    return v;
}

static void t_gm_write(i686_ctx_t *ctx, uint32_t va, unsigned width, uint32_t val)
{
    uint8_t *p = (uint8_t *)i686_guest_ptr(ctx, va);

    for (unsigned i = 0; i < width; i++) {
        p[i] = (uint8_t)(val >> (8U * i));
    }
}

/* ------------------------------------------------------------------ */
/* interp.c stand-in: registry + invocation                            */
/* ------------------------------------------------------------------ */

static i686_interp_fn t_tab[65536];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    t_tab[op] = fn;
}

static int run(i686_ctx_t *ctx, x86_insn_t *insn)
{
    i686_interp_fn fn = t_tab[insn->op];

    if (fn == NULL) {
        t_fails++;
        printf("FAIL %d: no handler registered for op %u\n", __LINE__,
               (unsigned)insn->op);
        return -1;
    }
    return fn(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* decode.c stand-ins (frozen signatures)                              */
/* ------------------------------------------------------------------ */

/* x86 partial-register semantics: byte writes to 0-3 touch bits 7:0 of
 * EAX..EBX, to 4-7 bits 15:8; word writes preserve bits 31:16. */
uint32_t x86_reg_read(const i686_ctx_t *ctx, uint8_t reg, unsigned width)
{
    uint32_t full;

    if (width == 1U) {
        if (reg < 4U) {
            return ctx->gpr[reg] & 0xffU;
        }
        return (ctx->gpr[reg - 4U] >> 8) & 0xffU;
    }
    full = ctx->gpr[reg & 7U];
    if (width == 2U) {
        return full & 0xffffU;
    }
    return full;
}

void x86_reg_write(i686_ctx_t *ctx, uint8_t reg, unsigned width, uint32_t val)
{
    if (width == 1U) {
        if (reg < 4U) {
            ctx->gpr[reg] = (ctx->gpr[reg] & 0xffffff00U) | (val & 0xffU);
        } else {
            uint8_t r = (uint8_t)(reg - 4U);
            ctx->gpr[r] = (ctx->gpr[r] & 0xffff00ffU) | ((val & 0xffU) << 8);
        }
    } else if (width == 2U) {
        uint8_t r = reg & 7U;
        ctx->gpr[r] = (ctx->gpr[r] & 0xffff0000U) | (val & 0xffffU);
    } else {
        ctx->gpr[reg & 7U] = val;
    }
}

static uint32_t t_ea_off(const i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t off = insn->ea_disp;

    if (insn->ea_base != 0xFFU) {
        off += ctx->gpr[insn->ea_base & 7U];
    }
    if (insn->ea_index != 0xFFU) {
        off += ctx->gpr[insn->ea_index & 7U] << insn->ea_scale;
    }
    return off; /* 32-bit wrap; tests stay inside the window anyway */
}

static uint8_t t_ea_seg(const x86_insn_t *insn)
{
    if (insn->pfx_seg != 0xFFU) {
        return insn->pfx_seg;
    }
    /* SS default when the base register is EBP/ESP (x86 rule). */
    if (insn->ea_base == I686_REG_EBP || insn->ea_base == I686_REG_ESP) {
        return I686_SEG_SS;
    }
    return I686_SEG_DS;
}

uint32_t x86_rm_read(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width)
{
    if (insn->has_modrm != 0U && insn->modrm_mod == 3U) {
        return x86_reg_read(ctx, insn->modrm_rm, width);
    }
    return t_gm_read(ctx, t_ea_off(ctx, insn) + ctx->seg_base[t_ea_seg(insn)], width);
}

void x86_rm_write(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width, uint32_t val)
{
    if (insn->has_modrm != 0U && insn->modrm_mod == 3U) {
        x86_reg_write(ctx, insn->modrm_rm, width, val);
        return;
    }
    t_gm_write(ctx, t_ea_off(ctx, insn) + ctx->seg_base[t_ea_seg(insn)], width, val);
}

/* ------------------------------------------------------------------ */
/* flags.c stand-in: lazy SUB recording per the frozen flags.h text    */
/* ------------------------------------------------------------------ */

void i686_flags_sub(i686_ctx_t *ctx, uint32_t src1, uint32_t src2, unsigned width)
{
    uint32_t mask = (width <= 1U) ? 0xffU : (width == 2U) ? 0xffffU : 0xffffffffU;

    ctx->lazy_op = I686_FOP_SUB;
    ctx->lazy_src1 = src1 & mask;
    ctx->lazy_src2 = src2 & mask;
    ctx->lazy_res = (src1 - src2) & mask;
}

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

static void t_reset(i686_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
    memset(t_win, 0, T_WIN_SIZE);
    ctx->guest_base = (uintptr_t)t_win;
    ctx->eflags = 0x202U; /* reserved bit 1 + IF */
    ctx->gpr[I686_REG_ESP] = 0x8000U;
}

static x86_insn_t mk_insn(uint16_t op)
{
    x86_insn_t i;

    memset(&i, 0, sizeof(i));
    i.op = op;
    i.len = 2;
    i.pfx_seg = 0xFFU;
    i.ea_base = 0xFFU;
    i.ea_index = 0xFFU;
    return i;
}

/* Memory r/m insn: EA = [base + disp] (mod=0, no SIB). */
static x86_insn_t mk_rm(uint16_t op, uint8_t reg, uint8_t base, uint32_t disp)
{
    x86_insn_t i = mk_insn(op);

    i.has_modrm = 1;
    i.modrm_mod = 0;
    i.modrm_reg = reg;
    i.modrm_rm = base;
    i.ea_base = base;
    i.ea_has = 1;
    i.ea_disp = disp;
    return i;
}

/* Register-register insn (mod=3). */
static x86_insn_t mk_rr(uint16_t op, uint8_t reg, uint8_t rm)
{
    x86_insn_t i = mk_insn(op);

    i.has_modrm = 1;
    i.modrm_mod = 3;
    i.modrm_reg = reg;
    i.modrm_rm = rm;
    return i;
}

static void seed(i686_ctx_t *ctx, uint32_t va, unsigned w, uint32_t v)
{
    t_gm_write(ctx, va, w, v);
}

/* ------------------------------------------------------------------ */
/* Cases                                                               */
/* ------------------------------------------------------------------ */

static void test_mov_rm(i686_ctx_t *ctx)
{
    x86_insn_t i;

    /* EvGv to memory; also checks the handler contract (rc + eip). */
    i = mk_rm(I686_OP_MOV_EvGv, I686_REG_EDX, I686_REG_EBX, 0x40);
    ctx->gpr[I686_REG_EBX] = 0x1000;
    ctx->gpr[I686_REG_EDX] = 0xdeadbeef;
    ctx->eip = 0x100;
    CHECK(run(ctx, &i) == I686_INTERP_CONTINUE);
    CHECK(ctx->eip == 0x102);
    CHECK(t_gm_read(ctx, 0x1040, 4) == 0xdeadbeef);

    /* GvEv from memory. */
    i = mk_rm(I686_OP_MOV_GvEv, I686_REG_EAX, I686_REG_EBX, 0x40);
    seed(ctx, 0x1040, 4, 0x11223344);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x11223344);

    /* GvEv register-register. */
    i = mk_rr(I686_OP_MOV_GvEv, I686_REG_ECX, I686_REG_EDX);
    ctx->gpr[I686_REG_EDX] = 0x55667788;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ECX] == 0x55667788);

    /* 16-bit move preserves the destination's upper half. */
    i = mk_rr(I686_OP_MOV_GvEv, I686_REG_EAX, I686_REG_EBX);
    i.pfx_opsize = 1;
    ctx->gpr[I686_REG_EAX] = 0x11223344;
    ctx->gpr[I686_REG_EBX] = 0xaabbccdd;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x1122ccdd);

    /* EbGb to memory: only one byte stored. */
    i = mk_rm(I686_OP_MOV_EbGb, I686_REG_EDX, I686_REG_EBX, 4);
    ctx->gpr[I686_REG_EBX] = 0x200;
    ctx->gpr[I686_REG_EDX] = 0x89abcdef;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x204, 1) == 0xef);
    CHECK(t_gm_read(ctx, 0x205, 1) == 0);

    /* GbEb from memory into AH (partial high byte). */
    i = mk_rm(I686_OP_MOV_GbEb, 4, I686_REG_EBX, 4);
    seed(ctx, 0x204, 1, 0x5a);
    ctx->gpr[I686_REG_EAX] = 0x12345678;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x12345a78);

    /* EbIb / EvIz immediates to memory. */
    i = mk_rm(I686_OP_MOV_EbIb, 0, I686_REG_EBX, 8);
    i.imm = 0xab;
    ctx->gpr[I686_REG_EBX] = 0x200;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x208, 1) == 0xab);

    i = mk_rm(I686_OP_MOV_EvIz, 0, I686_REG_EBX, 0x40);
    i.imm = 0x98765432;
    ctx->gpr[I686_REG_EBX] = 0x1000;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x1040, 4) == 0x98765432);

    i = mk_rm(I686_OP_MOV_EvIz, 0, I686_REG_EBX, 0x40);
    i.imm = 0xbeef;
    i.pfx_opsize = 1;
    seed(ctx, 0x1042, 2, 0x1234);
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x1040, 2) == 0xbeef);
    CHECK(t_gm_read(ctx, 0x1042, 2) == 0x1234); /* neighbour untouched */

    /* GbIb / GvIv into registers (B0+r / B8+r: dest in modrm_reg). */
    i = mk_insn(I686_OP_MOV_GbIb);
    i.has_modrm = 1;
    i.modrm_mod = 3;
    i.modrm_reg = 5; /* CH */
    i.imm = 0x7e;
    ctx->gpr[I686_REG_ECX] = 0x01020304;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ECX] == 0x01027e04);

    i = mk_insn(I686_OP_MOV_GvIv);
    i.has_modrm = 1;
    i.modrm_mod = 3;
    i.modrm_reg = I686_REG_ESI;
    i.imm = 0xcafebabe;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ESI] == 0xcafebabe);
}

static void test_mov_moffs(i686_ctx_t *ctx)
{
    x86_insn_t i;

    i = mk_insn(I686_OP_MOV_ALOb);
    i.ea_disp = 0x3000;
    seed(ctx, 0x3000, 1, 0x77);
    ctx->gpr[I686_REG_EAX] = 0xffffffff;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0xffffff77);

    i = mk_insn(I686_OP_MOV_eAXOv);
    i.ea_disp = 0x3004;
    seed(ctx, 0x3004, 4, 0x11223344);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x11223344);

    i = mk_insn(I686_OP_MOV_ObAL);
    i.ea_disp = 0x3008;
    ctx->gpr[I686_REG_EAX] = 0x99;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x3008, 1) == 0x99);

    i = mk_insn(I686_OP_MOV_OveAX);
    i.ea_disp = 0x3010;
    ctx->gpr[I686_REG_EAX] = 0xaabbccdd;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x3010, 4) == 0xaabbccdd);

    /* Segment override on the moffs source. */
    i = mk_insn(I686_OP_MOV_ALOb);
    i.ea_disp = 0x3000;
    i.pfx_seg = I686_SEG_FS;
    ctx->seg_base[I686_SEG_FS] = 0x100;
    seed(ctx, 0x3100, 1, 0x42);
    CHECK(run(ctx, &i) == 0);
    CHECK((ctx->gpr[I686_REG_EAX] & 0xffU) == 0x42); /* AL only */
}

static void test_movx(i686_ctx_t *ctx)
{
    x86_insn_t i;

    i = mk_rm(I686_OP_MOVZX_GvEb, I686_REG_EAX, I686_REG_EBX, 0x40);
    seed(ctx, 0x1040, 1, 0x80);
    ctx->gpr[I686_REG_EBX] = 0x1000;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x80); /* zero-extended */

    i.pfx_opsize = 1;
    ctx->gpr[I686_REG_EAX] = 0x11223344;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x11220080); /* 16-bit dest, preserved top */

    i = mk_rm(I686_OP_MOVZX_GvEw, I686_REG_EAX, I686_REG_EBX, 0x40);
    seed(ctx, 0x1040, 2, 0x8000);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x8000);

    i = mk_rm(I686_OP_MOVSX_GvEb, I686_REG_EAX, I686_REG_EBX, 0x40);
    seed(ctx, 0x1040, 1, 0x80);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0xffffff80); /* sign-extended */

    seed(ctx, 0x1040, 1, 0x7f);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x7f);

    i = mk_rm(I686_OP_MOVSX_GvEw, I686_REG_EAX, I686_REG_EBX, 0x40);
    seed(ctx, 0x1040, 2, 0x8000);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0xffff8000);

    seed(ctx, 0x1040, 2, 0x7fff);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x7fff);
}

static void test_lea_bswap_xlat(i686_ctx_t *ctx)
{
    x86_insn_t i;

    /* lea eax, [ebx + ecx*4 + 8] */
    i = mk_insn(I686_OP_LEA_GvM);
    i.has_modrm = 1;
    i.modrm_mod = 0;
    i.modrm_reg = I686_REG_EAX;
    i.modrm_rm = I686_REG_EBX;
    i.ea_base = I686_REG_EBX;
    i.ea_index = I686_REG_ECX;
    i.ea_scale = 2; /* *4 */
    i.ea_has = 1;
    i.ea_disp = 8;
    ctx->gpr[I686_REG_EBX] = 0x1000;
    ctx->gpr[I686_REG_ECX] = 0x37;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x1000 + 0x37 * 4 + 8);

    /* LEA ignores the segment override (no FS base added). */
    i.pfx_seg = I686_SEG_FS;
    ctx->seg_base[I686_SEG_FS] = 0x40000;
    ctx->gpr[I686_REG_EAX] = 0;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x1000 + 0x37 * 4 + 8);

    /* BSWAP r32. */
    i = mk_insn(I686_OP_BSWAP_Gv);
    i.has_modrm = 1;
    i.modrm_mod = 3;
    i.modrm_reg = I686_REG_EAX;
    ctx->gpr[I686_REG_EAX] = 0x11223344;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x44332211);

    /* XLAT: al = [ebx + al], DS overridable. */
    i = mk_insn(I686_OP_XLAT);
    ctx->gpr[I686_REG_EBX] = 0x4000;
    seed(ctx, 0x4003, 1, 0x5c);
    ctx->gpr[I686_REG_EAX] = 3;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x5c);

    i.pfx_seg = I686_SEG_FS;
    ctx->seg_base[I686_SEG_FS] = 0x200;
    seed(ctx, 0x4203, 1, 0x99); /* 0x200 + 0x4000 + 3 */
    ctx->gpr[I686_REG_EAX] = 3;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x99);
}

static void test_cpuid(i686_ctx_t *ctx)
{
    x86_insn_t i = mk_insn(I686_OP_CPUID);
    unsigned char vendor[13];

    ctx->gpr[I686_REG_EAX] = 0;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 1); /* max basic leaf */
    memcpy(vendor + 0, &ctx->gpr[I686_REG_EBX], 4);
    memcpy(vendor + 4, &ctx->gpr[I686_REG_EDX], 4);
    memcpy(vendor + 8, &ctx->gpr[I686_REG_ECX], 4);
    vendor[12] = '\0';
    CHECK(strcmp((const char *)vendor, "GenuineIntel") == 0);

    ctx->gpr[I686_REG_EAX] = 1;
    CHECK(run(ctx, &i) == 0);
    CHECK(((ctx->gpr[I686_REG_EAX] >> 8) & 0xfU) == 6); /* family */
    CHECK(ctx->gpr[I686_REG_ECX] == 0);                 /* no SSE3+ */
    CHECK(ctx->gpr[I686_REG_EDX] == ((1U << 0) | (1U << 4) | (1U << 8) |
                                     (1U << 15) | (1U << 23) | (1U << 24) |
                                     (1U << 25) | (1U << 26))); /* 0x07808111 */
    CHECK(ctx->gpr[I686_REG_EDX] == 0x07808111U);

    ctx->gpr[I686_REG_EAX] = 0x80000000;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x80000001);

    ctx->gpr[I686_REG_EAX] = 5; /* unsynthesized leaf reads as zero */
    ctx->gpr[I686_REG_EBX] = 0xeeeeeeee;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0 && ctx->gpr[I686_REG_EBX] == 0 &&
          ctx->gpr[I686_REG_ECX] == 0 && ctx->gpr[I686_REG_EDX] == 0);
}

static void test_stack(i686_ctx_t *ctx)
{
    x86_insn_t i;

    /* push/pop register pairing + esp math. */
    i = mk_insn(I686_OP_PUSH_Gv);
    i.has_modrm = 1;
    i.modrm_mod = 3;
    i.modrm_reg = I686_REG_EAX;
    ctx->gpr[I686_REG_EAX] = 0xdeadbeef;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000 - 4);
    CHECK(t_gm_read(ctx, 0x7ffc, 4) == 0xdeadbeef);

    i.modrm_reg = I686_REG_EBX;
    i.op = I686_OP_POP_Gv;
    CHECK(run(ctx, &i) == 0); /* pop into EBX */
    CHECK(ctx->gpr[I686_REG_EBX] == 0xdeadbeef);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000);

    /* PUSH ESP stores the pre-decrement value. */
    i.modrm_reg = I686_REG_ESP;
    i.op = I686_OP_PUSH_Gv;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x7ffc);
    CHECK(t_gm_read(ctx, 0x7ffc, 4) == 0x8000);
    i.op = I686_OP_POP_Gv;
    CHECK(run(ctx, &i) == 0); /* POP ESP: the popped value wins */
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000);

    /* PUSH Ib sign-extends; PUSH Iz under 66 narrows the slot. */
    i = mk_insn(I686_OP_PUSH_Ib);
    i.imm = 0xff;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x7ffc, 4) == 0xffffffff);

    i = mk_insn(I686_OP_PUSH_Iz);
    i.imm = 0x1234;
    i.pfx_opsize = 1;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x7ffc - 2); /* continues after PUSH_Ib */
    CHECK(t_gm_read(ctx, 0x7ffa, 2) == 0x1234);

    /* PUSH_Ev/POP_Ev through memory. */
    t_reset(ctx);
    seed(ctx, 0x5000, 4, 0x13572468);
    i = mk_rm(I686_OP_PUSH_Ev, 6, I686_REG_EBX, 0);
    ctx->gpr[I686_REG_EBX] = 0x5000;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x7ffc, 4) == 0x13572468);
    i = mk_rm(I686_OP_POP_Ev, 0, I686_REG_EDI, 0);
    ctx->gpr[I686_REG_EDI] = 0x6000;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x6000, 4) == 0x13572468);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000);

    /* PUSHA/POPA roundtrip (SP slot holds the original ESP). */
    t_reset(ctx);
    ctx->gpr[I686_REG_EAX] = 0x11111111;
    ctx->gpr[I686_REG_ECX] = 0x22222222;
    ctx->gpr[I686_REG_EDX] = 0x33333333;
    ctx->gpr[I686_REG_EBX] = 0x44444444;
    ctx->gpr[I686_REG_EBP] = 0x55555555;
    ctx->gpr[I686_REG_ESI] = 0x66666666;
    ctx->gpr[I686_REG_EDI] = 0x77777777;
    i = mk_insn(I686_OP_PUSHA);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000 - 32);
    CHECK(t_gm_read(ctx, 0x7ffc, 4) == 0x11111111); /* first push */
    CHECK(t_gm_read(ctx, 0x7fec, 4) == 0x8000);     /* original SP */
    CHECK(t_gm_read(ctx, 0x7fe0, 4) == 0x77777777); /* last push */
    ctx->gpr[I686_REG_EAX] = 1;
    ctx->gpr[I686_REG_ECX] = 2;
    ctx->gpr[I686_REG_EDX] = 3;
    ctx->gpr[I686_REG_EBX] = 4;
    ctx->gpr[I686_REG_EBP] = 5;
    ctx->gpr[I686_REG_ESI] = 6;
    ctx->gpr[I686_REG_EDI] = 7;
    i = mk_insn(I686_OP_POPA);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x11111111);
    CHECK(ctx->gpr[I686_REG_ECX] == 0x22222222);
    CHECK(ctx->gpr[I686_REG_EDX] == 0x33333333);
    CHECK(ctx->gpr[I686_REG_EBX] == 0x44444444);
    CHECK(ctx->gpr[I686_REG_EBP] == 0x55555555);
    CHECK(ctx->gpr[I686_REG_ESI] == 0x66666666);
    CHECK(ctx->gpr[I686_REG_EDI] == 0x77777777);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000);

    /* ENTER level 0 + LEAVE roundtrip. */
    t_reset(ctx);
    ctx->gpr[I686_REG_EBP] = 0x7000;
    i = mk_insn(I686_OP_ENTER);
    i.imm = 0x40; /* size 0x40, level 0 */
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x7ffc, 4) == 0x7000);
    CHECK(ctx->gpr[I686_REG_EBP] == 0x7ffc);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000 - 4 - 0x40);
    i = mk_insn(I686_OP_LEAVE);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EBP] == 0x7000);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000);

    /* ENTER level 2: display copy + frame pointer push. */
    t_reset(ctx);
    ctx->gpr[I686_REG_EBP] = 0x7000;
    seed(ctx, 0x6ffc, 4, 0x12345678); /* caller display at [ebp-4] */
    i = mk_insn(I686_OP_ENTER);
    i.imm = 0x20 | (2U << 16); /* size 0x20, level 2 */
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x7ffc, 4) == 0x7000);     /* saved ebp */
    CHECK(t_gm_read(ctx, 0x7ff8, 4) == 0x12345678); /* copied display */
    CHECK(t_gm_read(ctx, 0x7ff4, 4) == 0x7ffc);     /* frame pointer */
    CHECK(ctx->gpr[I686_REG_EBP] == 0x7ffc);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000 - 12 - 0x20);
    i = mk_insn(I686_OP_LEAVE);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EBP] == 0x7000);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000);

    /* PUSH/POP FS roundtrip reloads the base from the TLS slot. */
    t_reset(ctx);
    ctx->seg_sel[I686_SEG_FS] = 0x33;
    ctx->gdt_tls_slots[0] = 0x12340000;
    ctx->seg_base[I686_SEG_FS] = 0x12340000;
    i = mk_insn(I686_OP_PUSH_FS);
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x7ffc, 4) == 0x33);
    ctx->seg_sel[I686_SEG_FS] = 0x99;
    ctx->seg_base[I686_SEG_FS] = 0xdead0000;
    i = mk_insn(I686_OP_POP_FS);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->seg_sel[I686_SEG_FS] == 0x33);
    CHECK(ctx->seg_base[I686_SEG_FS] == 0x12340000);
    CHECK(ctx->gpr[I686_REG_ESP] == 0x8000);
}

static void test_segments(i686_ctx_t *ctx)
{
    x86_insn_t i;

    /* MOV Ew, Sw: 16-bit selector store, upper reg bits preserved. */
    i = mk_rr(I686_OP_MOV_EwSw, I686_SEG_FS, I686_REG_EBX);
    ctx->seg_sel[I686_SEG_FS] = 0x33;
    ctx->gpr[I686_REG_EBX] = 0xffff1234;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EBX] == 0xffff0033);

    i = mk_rm(I686_OP_MOV_EwSw, I686_SEG_GS, I686_REG_EBX, 0x60);
    ctx->gpr[I686_REG_EBX] = 0x1000;
    ctx->seg_sel[I686_SEG_GS] = 0x3b;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x1060, 2) == 0x3b);

    /* MOV Sw, Ew: FS from a TLS selector picks up the slot base. */
    i = mk_rm(I686_OP_MOV_SwEw, I686_SEG_FS, I686_REG_EBX, 0x60);
    ctx->gpr[I686_REG_EBX] = 0x1000;
    ctx->gdt_tls_slots[0] = 0x99990000;
    seed(ctx, 0x1060, 2, 0x33);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->seg_sel[I686_SEG_FS] == 0x33);
    CHECK(ctx->seg_base[I686_SEG_FS] == 0x99990000);

    /* Selector 0 -> base 0. */
    seed(ctx, 0x1060, 2, 0);
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->seg_sel[I686_SEG_FS] == 0);
    CHECK(ctx->seg_base[I686_SEG_FS] == 0);

    /* Non-TLS nonzero selector to a flat segment: base 0 (v1). */
    i = mk_rr(I686_OP_MOV_SwEw, I686_SEG_ES, I686_REG_EAX);
    ctx->gpr[I686_REG_EAX] = 0x2b;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->seg_sel[I686_SEG_ES] == 0x2b);
    CHECK(ctx->seg_base[I686_SEG_ES] == 0);
}

static void test_strings(i686_ctx_t *ctx)
{
    x86_insn_t i;
    static const unsigned char pat[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /* rep movsb forward. */
    t_reset(ctx);
    memcpy(t_win + 0x1000, pat, 16);
    i = mk_insn(I686_OP_MOVSb);
    i.pfx_rep = 1;
    ctx->gpr[I686_REG_ESI] = 0x1000;
    ctx->gpr[I686_REG_EDI] = 0x2000;
    ctx->gpr[I686_REG_ECX] = 16;
    ctx->lazy_op = I686_FOP_ADD; /* MOVS must not disturb the descriptor */
    CHECK(run(ctx, &i) == 0);
    CHECK(memcmp(t_win + 0x2000, pat, 16) == 0);
    CHECK(ctx->gpr[I686_REG_ESI] == 0x1010);
    CHECK(ctx->gpr[I686_REG_EDI] == 0x2010);
    CHECK(ctx->gpr[I686_REG_ECX] == 0);
    CHECK(ctx->lazy_op == I686_FOP_ADD);

    /* rep movsb backward under DF. */
    t_reset(ctx);
    memcpy(t_win + 0x1000, pat, 16);
    i = mk_insn(I686_OP_MOVSb);
    i.pfx_rep = 1;
    ctx->eflags |= I686_EF_DF; /* DF lives in eflags, outside the lazy set */
    ctx->gpr[I686_REG_ESI] = 0x100f;
    ctx->gpr[I686_REG_EDI] = 0x200f;
    ctx->gpr[I686_REG_ECX] = 16;
    CHECK(run(ctx, &i) == 0);
    CHECK(memcmp(t_win + 0x2000, pat, 16) == 0);
    CHECK(ctx->gpr[I686_REG_ESI] == 0x0fff); /* 0x100f - 16 */
    CHECK(ctx->gpr[I686_REG_EDI] == 0x1fff);

    /* Plain movsd (no rep): one dword. */
    t_reset(ctx);
    seed(ctx, 0x1010, 4, 0x13572468);
    i = mk_insn(I686_OP_MOVSw);
    ctx->gpr[I686_REG_ESI] = 0x1010;
    ctx->gpr[I686_REG_EDI] = 0x2010;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x2010, 4) == 0x13572468);
    CHECK(ctx->gpr[I686_REG_ESI] == 0x1014);
    CHECK(ctx->gpr[I686_REG_EDI] == 0x2014);

    /* rep movsw under 66+67: word width, CX count, upper ECX preserved. */
    t_reset(ctx);
    seed(ctx, 0x1000, 4, 0x89abcdef);
    seed(ctx, 0x1004, 4, 0x01234567);
    i = mk_insn(I686_OP_MOVSw);
    i.pfx_rep = 1;
    i.pfx_opsize = 1;
    i.pfx_addrsize = 1;
    ctx->gpr[I686_REG_ESI] = 0x1000;
    ctx->gpr[I686_REG_EDI] = 0x2000;
    ctx->gpr[I686_REG_ECX] = 0x00050003; /* count = 3 */
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x2000, 4) == 0x89abcdef);
    CHECK(t_gm_read(ctx, 0x2004, 2) == 0x4567); /* 3rd word copied */
    CHECK(t_gm_read(ctx, 0x2006, 2) == 0); /* 4th word not copied */
    CHECK(ctx->gpr[I686_REG_EDI] == 0x2006);
    CHECK(ctx->gpr[I686_REG_ECX] == 0x00050000);

    /* rep stosb fill. */
    t_reset(ctx);
    i = mk_insn(I686_OP_STOSb);
    i.pfx_rep = 1;
    ctx->gpr[I686_REG_EAX] = 0xaa;
    ctx->gpr[I686_REG_EDI] = 0x3000;
    ctx->gpr[I686_REG_ECX] = 8;
    CHECK(run(ctx, &i) == 0);
    for (int k = 0; k < 8; k++) {
        CHECK(t_gm_read(ctx, 0x3000 + (uint32_t)k, 1) == 0xaa);
    }
    CHECK(t_gm_read(ctx, 0x3008, 1) == 0);
    CHECK(ctx->gpr[I686_REG_EDI] == 0x3008);

    /* rep stosd with a dword pattern. */
    t_reset(ctx);
    i = mk_insn(I686_OP_STOSw);
    i.pfx_rep = 1;
    ctx->gpr[I686_REG_EAX] = 0xdeadbeef;
    ctx->gpr[I686_REG_EDI] = 0x3000;
    ctx->gpr[I686_REG_ECX] = 4;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x3000, 4) == 0xdeadbeef);
    CHECK(t_gm_read(ctx, 0x300c, 4) == 0xdeadbeef);
    CHECK(t_gm_read(ctx, 0x3010, 4) == 0);

    /* lodsb / lodsd. */
    t_reset(ctx);
    seed(ctx, 0x1000, 1, 0x5a);
    i = mk_insn(I686_OP_LODSb);
    ctx->gpr[I686_REG_ESI] = 0x1000;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x5a);
    CHECK(ctx->gpr[I686_REG_ESI] == 0x1001);

    seed(ctx, 0x1004, 4, 0x10203040);
    i = mk_insn(I686_OP_LODSw);
    ctx->gpr[I686_REG_ESI] = 0x1004;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EAX] == 0x10203040);
    CHECK(ctx->gpr[I686_REG_ESI] == 0x1008);

    /* repne scasb finds the byte and leaves the lazy SUB descriptor. */
    t_reset(ctx);
    seed(ctx, 0x4000, 4, 0x07000000); /* bytes 00 00 00 07 */
    i = mk_insn(I686_OP_SCASb);
    i.pfx_rep = 2; /* REPNE */
    ctx->gpr[I686_REG_EAX] = 7;
    ctx->gpr[I686_REG_EDI] = 0x4000;
    ctx->gpr[I686_REG_ECX] = 8;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_EDI] == 0x4004);
    CHECK(ctx->gpr[I686_REG_ECX] == 4);
    CHECK(ctx->lazy_op == I686_FOP_SUB);
    CHECK(ctx->lazy_src1 == 7 && ctx->lazy_src2 == 7);
    CHECK(ctx->lazy_res == 0);

    /* repe cmpsb early-exits at the first mismatch. */
    t_reset(ctx);
    memcpy(t_win + 0x1000, "AAAABBBB", 8);
    memcpy(t_win + 0x2000, "AAAAXXXX", 8);
    i = mk_insn(I686_OP_CMPSb);
    i.pfx_rep = 1; /* REPE */
    ctx->gpr[I686_REG_ESI] = 0x1000;
    ctx->gpr[I686_REG_EDI] = 0x2000;
    ctx->gpr[I686_REG_ECX] = 8;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ECX] == 3); /* 5 iterations consumed */
    CHECK(ctx->gpr[I686_REG_ESI] == 0x1005);
    CHECK(ctx->gpr[I686_REG_EDI] == 0x2005);
    CHECK(ctx->lazy_op == I686_FOP_SUB);
    CHECK(ctx->lazy_src1 == 0x42 && ctx->lazy_src2 == 0x58);

    /* Plain cmpsb records one lazy SUB. */
    t_reset(ctx);
    seed(ctx, 0x1000, 1, 0x10);
    seed(ctx, 0x2000, 1, 0x20);
    i = mk_insn(I686_OP_CMPSb);
    ctx->gpr[I686_REG_ESI] = 0x1000;
    ctx->gpr[I686_REG_EDI] = 0x2000;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->lazy_src1 == 0x10 && ctx->lazy_src2 == 0x20);
    CHECK(ctx->lazy_res == 0xf0); /* width-masked borrow per flags.h */

    /* Segment rules: FS overrides the MOVS source; the destination stays
     * on ES and is not overridable. */
    t_reset(ctx);
    ctx->seg_base[I686_SEG_FS] = 0x100;
    ctx->seg_base[I686_SEG_ES] = 0x200;
    seed(ctx, 0x130, 1, 0x7e); /* 0x100 + esi(0x30) */
    i = mk_insn(I686_OP_MOVSb);
    i.pfx_seg = I686_SEG_FS;
    ctx->gpr[I686_REG_ESI] = 0x30;
    ctx->gpr[I686_REG_EDI] = 0x40;
    CHECK(run(ctx, &i) == 0);
    CHECK(t_gm_read(ctx, 0x240, 1) == 0x7e); /* ES base + edi */
    CHECK(t_gm_read(ctx, 0x140, 1) == 0);    /* not FS + edi */

    /* REP with a zero count does nothing. */
    t_reset(ctx);
    i = mk_insn(I686_OP_MOVSb);
    i.pfx_rep = 1;
    ctx->gpr[I686_REG_ECX] = 0;
    ctx->gpr[I686_REG_ESI] = 0x1000;
    ctx->gpr[I686_REG_EDI] = 0x2000;
    CHECK(run(ctx, &i) == 0);
    CHECK(ctx->gpr[I686_REG_ESI] == 0x1000);
    CHECK(ctx->gpr[I686_REG_EDI] == 0x2000);
    CHECK(ctx->gpr[I686_REG_ECX] == 0);
}

int main(void)
{
    i686_ctx_t ctx;

    t_win = malloc(T_WIN_SIZE);
    if (t_win == NULL) {
        fprintf(stderr, "test_l1c: window allocation failed\n");
        return 2;
    }
    memset(t_win, 0, T_WIN_SIZE);

    i686_interp_mov_init(); /* also registers the string ops */

    t_reset(&ctx);
    test_mov_rm(&ctx);
    t_reset(&ctx);
    test_mov_moffs(&ctx);
    t_reset(&ctx);
    test_movx(&ctx);
    t_reset(&ctx);
    test_lea_bswap_xlat(&ctx);
    t_reset(&ctx);
    test_cpuid(&ctx);
    t_reset(&ctx);
    test_stack(&ctx);
    t_reset(&ctx);
    test_segments(&ctx);
    t_reset(&ctx);
    test_strings(&ctx);

    free(t_win);
    if (t_fails != 0) {
        printf("L1C FAILED: %d check(s)\n", t_fails);
        return 1;
    }
    printf("L1C OK\n");
    return 0;
}
