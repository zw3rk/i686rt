/*
 * src/x86/decode.c — prefix/ModRM/SIB decoder core (SPEC §3.2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Table-driven via the generated src/x86/insn_tab.h (lane L1a).  Unknown
 * opcodes return -1 — never an abort (D2).  All arithmetic below wraps in
 * 32 bits (D4/D7): guest linear = (base + index*scale + disp + seg_base)
 * mod 2^32.  Group opcodes (80–83, C0–D3, F6, F7, FE, FF, 0F BA) resolve
 * the /r reg field to a concrete op through i686_group_tab_1b/_0f.
 *
 * Phase 7 (card L7a, bounded edits; SPEC D8, freeze in docs/lanes/
 * phase-7.md):
 *   - Instruction fetch is CS-relative: fetch addresses are
 *     (uint32_t)(seg_base[CS] + eip_offset); flat CS (base 0) is
 *     unchanged.  EIP stays a CS-relative offset everywhere.
 *   - Operand/address defaults come from ctx->cs_d (1 = 32-bit); the
 *     66/67 prefixes XOR against it.  insn->pfx_opsize/pfx_addrsize are
 *     NORMALIZED to "effective 16-bit" after the prefix loop — the
 *     frozen handler convention (pfx_opsize ? 16 : 32) then yields the
 *     effective width in both flat and D=0 code without handler edits.
 *   - 16-bit effective addresses wrap mod 64K before the segment base is
 *     added; linear32 = (uint32_t)(seg_base[seg] + offset) after.
 *   - LDT (TI=1) data accesses enforce the descriptor byte limit along
 *     x86_rm_read/x86_rm_write (interp/seg.c i686_seg_check_data); flat
 *     and GDT accesses are never limit-checked (v1 behaviour).
 *   - Bytes whose generated table rows are INVALID but which Phase 7
 *     must execute (pops/far transfers/les-family/privileged ops)
 *     decode here into synthetic registry ids (460..469) handled by
 *     src/interp/h_seg.c; see far_op_decode below.
 */

#include <stdio.h>
#include <string.h>

#include "x86/decode.h"

#define SEG_NONE 0xffU
#define REG_NONE 0xffU

/* Effective CS default size: 16-bit only once the descriptor model is
 * initialized (ctx->ldt != NULL) AND the loaded CS descriptor said D=0.
 * A flat process before any descriptor activity has cs_d still 0 (memset
 * startup state); it must decode 32-bit — seg_init sets cs_d=1 and any
 * far transfer into D=0 code necessarily went through a descriptor. */
static uint8_t eff_default16(const i686_ctx_t *ctx)
{
    return (ctx->ldt != NULL && ctx->cs_d == 0U) ? 1u : 0u;
}

/*
 * Phase-7 synthetic opcode ids (registry-only; the enum ends at
 * I686_OP_COUNT = 359 after the RC7b T1 union extension, the interp
 * registry holds 512 slots; the block moved up from 350 with that
 * extension — docs/lanes/phase-7.md T1 record).  MUST match the
 * identical table in src/interp/h_seg.c (which registers handlers).
 */
enum {
    I686_OP7_POP_SS = 460, /* 17                                      */
    I686_OP7_CALLF  = 461, /* 9A Ap: m16:16 / m16:32 far pointer      */
    I686_OP7_JMPF   = 462, /* EA Ap                                   */
    I686_OP7_LES    = 463, /* C4 Gv,mp                                */
    I686_OP7_LDS    = 464, /* C5 Gv,mp                                */
    I686_OP7_RETF   = 465, /* CB                                      */
    I686_OP7_LSS    = 466, /* 0F B2 Gv,mp                             */
    I686_OP7_LFS    = 467, /* 0F B4 Gv,mp                             */
    I686_OP7_LGS    = 468, /* 0F B5 Gv,mp                             */
    I686_OP7_PRIV   = 469, /* E4-E7/EC-EF, 0F 20-23 (16-bit code)     */
    I686_OP7_UNPCKLPS = 470, /* 0F 14 Vps,Wps / 66 Vpd,Wpd            */
    I686_OP7_UNPCKHPS = 471, /* 0F 15 Vps,Wps / 66 Vpd,Wpd            */
    I686_OP7_PACKUSWB = 472, /* 0F 67 Pq,Qd / 66 Vdq,Wdq              */
    I686_OP7_SHUFPS   = 473  /* 0F C6 Vps,Wps,Ib / 66 Vpd,Wpd,Ib      */
};

static uint8_t fetch8(i686_ctx_t *ctx, uint32_t va)
{
    const volatile uint8_t *p =
        (const volatile uint8_t *)i686_guest_ptr(ctx, va);
    return *p;
}

/* 8-bit register file mapping: 0..3 = AL,CL,DL,BL (low bytes of
 * EAX..EBX); 4..7 = AH,CH,DH,BH (HIGH bytes of EAX,ECX,EDX,EBX — NOT
 * of ESP..EDI).  S2 fix: the old `gpr[reg & 7]` high-byte mapping sent
 * AH-class accesses into ESP/EBP/ESI/EDI, corrupting the guest stack. */
uint32_t x86_reg_read(const i686_ctx_t *ctx, uint8_t reg, unsigned width)
{
    uint32_t v;
    if (width == 8U && reg >= 4U) {
        v = ctx->gpr[reg - 4U];
        return (v >> 8) & 0xffU;
    }
    v = ctx->gpr[reg & 7U];
    if (width == 8) {
        return v & 0xffU;
    }
    if (width == 16) {
        return v & 0xffffU;
    }
    return v;
}

void x86_reg_write(i686_ctx_t *ctx, uint8_t reg, unsigned width, uint32_t val)
{
    uint32_t old;
    uint32_t v;
    if (width == 8U && reg >= 4U) {
        old = ctx->gpr[reg - 4U];
        v = (old & ~0xff00U) | ((val & 0xffU) << 8);
        ctx->gpr[reg - 4U] = v;
        return;
    }
    old = ctx->gpr[reg & 7U];
    if (width == 8) {
        v = (old & ~0xffU) | (val & 0xffU);
    } else if (width == 16) {
        v = (old & 0xffff0000U) | (val & 0xffffU);
    } else {
        v = val;
    }
    ctx->gpr[reg & 7U] = v;
}

/* Effective segment of the current memory operand: override prefix, else
 * the default segment for the EA (SS when BP/ESP-based, DS otherwise).
 * Phase 7 also exposes this to the les/lds/lss handlers (h_seg.c). */
static uint8_t ea_default_seg(const x86_insn_t *insn)
{
    if (insn->pfx_addrsize) {
        if (insn->modrm_mod != 0U && insn->ea_base == I686_REG_EBP) {
            return I686_SEG_SS;
        }
        return I686_SEG_DS;
    }
    if (insn->modrm_mod != 0U && (insn->ea_base == I686_REG_EBP ||
                                   insn->ea_base == I686_REG_ESP)) {
        return I686_SEG_SS;
    }
    return I686_SEG_DS;
}

uint8_t x86_ea_seg(const x86_insn_t *insn)
{
    return (insn->pfx_seg != SEG_NONE) ? (uint8_t)insn->pfx_seg
                                       : ea_default_seg(insn);
}

uint32_t x86_ea_compute(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t ea = insn->ea_disp;
    if (insn->ea_base != REG_NONE) {
        ea += x86_reg_read(ctx, insn->ea_base, 32);
    }
    if (insn->ea_index != REG_NONE) {
        ea += x86_reg_read(ctx, insn->ea_index, 32) << insn->ea_scale;
    }
    if (insn->pfx_addrsize) {
        ea &= 0xFFFFU; /* 16-bit effective address wraps mod 64K (D8) */
    }
    {
        uint8_t seg = x86_ea_seg(insn);
        if (seg < I686_SEG_COUNT) {
            ea += ctx->seg_base[seg]; /* linear32, 32-bit wrap (D4/D7) */
        }
    }
    return ea;
}

/* LDT data-limit enforcement on the EA path (interp/seg.c); flat and
 * GDT selectors are never checked (i686_seg_check_data filters). */
static void seg_limit_check(i686_ctx_t *ctx, const x86_insn_t *insn,
                            uint32_t ea, unsigned bytes)
{
    extern void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg,
                                    uint32_t linear, unsigned bytes);
    if (bytes != 0U) {
        i686_seg_check_data(ctx, x86_ea_seg(insn), ea, bytes);
    }
}

static uint32_t mem_load(i686_ctx_t *ctx, uint32_t va, unsigned width)
{
#ifdef I686RT_STRTRACE
    if ((va >= 0xdffffc00U && va < 0xdfffff80U) || (va >= 0x40001000U && va < 0x40005000U) || (va >= 0x8150000U && va < 0x8160000U)) {
        fprintf(stderr, "R %08x w%u at eip=%08x\n", va, width, ctx->eip);
    }
#endif
    const volatile uint8_t *p =
        (const volatile uint8_t *)i686_guest_ptr(ctx, va);
    uint8_t buf[4];
    memcpy(buf, (const void *)p, width);
    if (width == 1) {
        return buf[0];
    }
    if (width == 2) {
        return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8);
    }
    return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
           ((uint32_t)buf[2] << 16) | ((uint32_t)buf[3] << 24);
}

static void mem_store(i686_ctx_t *ctx, uint32_t va, unsigned width, uint32_t val)
{
    volatile uint8_t *p = (volatile uint8_t *)i686_guest_ptr(ctx, va);
    uint8_t buf[4];
    buf[0] = (uint8_t)(val & 0xff);
    buf[1] = (uint8_t)((val >> 8) & 0xff);
    buf[2] = (uint8_t)((val >> 16) & 0xff);
    buf[3] = (uint8_t)((val >> 24) & 0xff);
    memcpy((void *)p, buf, width);
}

/* width is in BITS (8/16/32) per the frozen contract; mem helpers take
 * bytes. */
uint32_t x86_rm_read(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width)
{
    if (insn->modrm_mod == 3U || !insn->ea_has) {
        return x86_reg_read(ctx, insn->modrm_rm, width);
    }
    {
        uint32_t ea = x86_ea_compute(ctx, insn);
        seg_limit_check(ctx, insn, ea, width / 8U);
        return mem_load(ctx, ea, width / 8U);
    }
}

void x86_rm_write(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width,
                  uint32_t val)
{
    if (insn->modrm_mod == 3U || !insn->ea_has) {
        x86_reg_write(ctx, insn->modrm_rm, width, val);
        return;
    }
    {
        uint32_t ea = x86_ea_compute(ctx, insn);
        seg_limit_check(ctx, insn, ea, width / 8U);
        mem_store(ctx, ea, width / 8U, val);
    }
}

/* Decode ModRM + optional SIB/displacement; advances *pc.  cs_base is
 * the CS base for instruction-stream fetches (displacements/immediates
 * live in the code stream, Phase 7). */
static void decode_modrm(i686_ctx_t *ctx, uint32_t *pc, x86_insn_t *out,
                         uint32_t cs_base)
{
    uint8_t m = fetch8(ctx, cs_base + *pc);
    (*pc)++;

    out->has_modrm = 1;
    out->modrm_mod = (m >> 6) & 3U;
    out->modrm_reg = (m >> 3) & 7U;
    out->modrm_rm = m & 7U;
    out->ea_base = REG_NONE;
    out->ea_index = REG_NONE;
    out->ea_scale = 0;
    out->ea_disp = 0;

    if (out->modrm_mod == 3U) {
        out->ea_has = 0;
        return;
    }
    out->ea_has = 1;

    if (!out->pfx_addrsize) {
        /* 32-bit addressing. */
        static const uint8_t base_map[8] = {
            I686_REG_EAX, I686_REG_ECX, I686_REG_EDX, I686_REG_EBX,
            I686_REG_ESP, I686_REG_EBP, I686_REG_ESI, I686_REG_EDI
        };
        if (out->modrm_rm == 4U) { /* SIB */
            uint8_t sib = fetch8(ctx, cs_base + *pc);
            uint8_t base;
            (*pc)++;
            out->ea_scale = (sib >> 6) & 3U;
            out->ea_index = ((sib >> 3) & 7U) == 4U
                                ? (uint8_t)REG_NONE
                                : (uint8_t)((sib >> 3) & 7U);
            base = sib & 7U;
            if (base == 5U && out->modrm_mod == 0U) {
                out->ea_base = REG_NONE; /* disp32-only SIB base */
                out->ea_disp = mem_load(ctx, cs_base + *pc, 4);
                *pc += 4;
            } else {
                out->ea_base = base_map[base]; /* SIB base 4 = ESP */
            }
        } else if (out->modrm_rm == 5U && out->modrm_mod == 0U) {
            out->ea_base = REG_NONE; /* absolute disp32 (no rip-rel on i386) */
            out->ea_disp = mem_load(ctx, cs_base + *pc, 4);
            *pc += 4;
        } else {
            out->ea_base = base_map[out->modrm_rm]; /* rm 4 never reaches here */
        }
        if (out->modrm_mod == 1U) {
            out->ea_disp = (uint32_t)(int32_t)(int8_t)fetch8(ctx, cs_base + *pc);
            (*pc)++;
        } else if (out->modrm_mod == 2U) {
            out->ea_disp = mem_load(ctx, cs_base + *pc, 4);
            *pc += 4;
        }
    } else {
        /* 16-bit addressing (interpreter-supported, §3.2). */
        static const uint8_t base16[8] = {
            I686_REG_EBX, I686_REG_EBX, I686_REG_EBP, I686_REG_EBP,
            I686_REG_ESI, I686_REG_EDI, I686_REG_EBP, I686_REG_EBX
        };
        static const uint8_t index16[8] = {
            I686_REG_ESI, I686_REG_EDI, I686_REG_ESI, I686_REG_EDI,
            REG_NONE,     REG_NONE,     REG_NONE,     REG_NONE
        };
        if (out->modrm_rm == 6U && out->modrm_mod == 0U) {
            out->ea_base = REG_NONE; /* disp16 absolute */
            out->ea_disp = mem_load(ctx, cs_base + *pc, 2);
            *pc += 2;
        } else {
            out->ea_base = base16[out->modrm_rm];
            out->ea_index = index16[out->modrm_rm];
        }
        out->ea_scale = 0;
        if (out->modrm_mod == 1U) {
            out->ea_disp = (uint32_t)(int32_t)(int8_t)fetch8(ctx, cs_base + *pc);
            (*pc)++;
        } else if (out->modrm_mod == 2U) {
            out->ea_disp = mem_load(ctx, cs_base + *pc, 2);
            *pc += 2;
        }
    }
}

static unsigned opnd_is_mem(uint8_t k)
{
    return k == I686_OPND_RM8 || k == I686_OPND_RM16 || k == I686_OPND_RM32;
}

/* Resolve a group opcode row (flat i686_group_tab, 15 entries). */
static const i686_group_t *group_lookup(int is_0f, uint8_t opcode)
{
    size_t i;
    for (i = 0; i < sizeof(i686_group_tab) / sizeof(i686_group_tab[0]); i++) {
        if (i686_group_tab[i].map0f == (unsigned)is_0f &&
            i686_group_tab[i].opcode == opcode) {
            return &i686_group_tab[i];
        }
    }
    return NULL;
}

/* Single-register encodings with no modrm byte in the stream (40+r INC/DEC,
 * 50+r PUSH/POP, 90+r XCHG eAX,r (90 itself is NOP), B0+r/B8+r MOV r,imm):
 * the register rides the opcode. */
static unsigned synth_reg_opcode(uint8_t b1)
{
    return (b1 >= 0x40U && b1 <= 0x5fU) || (b1 >= 0x90U && b1 <= 0x97U) ||
           (b1 >= 0xb0U && b1 <= 0xbfU);
}

/* 0F C8+r BSWAP r32: register rides the second opcode byte. */
static unsigned synth_reg_opcode_0f(uint8_t b2)
{
    return b2 >= 0xc8U && b2 <= 0xcfU;
}

/* Phase 7: decode bytes whose generated table rows are INVALID but which
 * 16-bit/LDT code must execute (docs/lanes/phase-7.md card L7a).  Fills
 * *out (op, operands, len) and returns 0, or -1 when the byte stays
 * INVALID (D2: the caller reports UNDEF, never asserts).
 *
 * Far pointers (9A/EA) pack into insn->imm as offset | (selector << 8*w)
 * with imm_size = w + 2 (the ENTER-style multi-immediate convention). */
static int far_op_decode(i686_ctx_t *ctx, uint8_t b1, uint8_t b2,
                         uint32_t *pc, x86_insn_t *out, uint32_t eip,
                         uint32_t cs_base)
{
    unsigned key = (b1 == 0x0fU) ? (0x0f00u | (unsigned)b2) : (unsigned)b1;
    unsigned o = (out->pfx_opsize != 0U) ? 2u : 4u; /* effective bytes */

    switch (key) {
    case 0x17u: /* POP SS */
        out->op = I686_OP7_POP_SS;
        break;
    case 0x9Au:
        out->op = I686_OP7_CALLF;
        goto far_ptr;
    case 0xEAu:
        out->op = I686_OP7_JMPF;
        goto far_ptr;
    far_ptr:
        out->imm = mem_load(ctx, cs_base + *pc, o);
        *pc += o;
        out->imm |= (uint32_t)mem_load(ctx, cs_base + *pc, 2) << (o * 8u);
        *pc += 2;
        out->imm_size = (uint8_t)(o + 2u);
        break;
    case 0xC4u:
        out->op = I686_OP7_LES;
        decode_modrm(ctx, pc, out, cs_base);
        break;
    case 0xC5u:
        out->op = I686_OP7_LDS;
        decode_modrm(ctx, pc, out, cs_base);
        break;
    case 0xCBu: /* RETF */
        out->op = I686_OP7_RETF;
        break;
    case 0x0FB2u:
        out->op = I686_OP7_LSS;
        decode_modrm(ctx, pc, out, cs_base);
        break;
    case 0x0FB4u:
        out->op = I686_OP7_LFS;
        decode_modrm(ctx, pc, out, cs_base);
        break;
    case 0x0FB5u:
        out->op = I686_OP7_LGS;
        decode_modrm(ctx, pc, out, cs_base);
        break;
    case 0x0F14u:
        out->op = I686_OP7_UNPCKLPS;
        out->opnd[0] = I686_OPND_R32;
        out->opnd[1] = I686_OPND_RM32;
        decode_modrm(ctx, pc, out, cs_base);
        break;
    case 0x0F15u:
        out->op = I686_OP7_UNPCKHPS;
        out->opnd[0] = I686_OPND_R32;
        out->opnd[1] = I686_OPND_RM32;
        decode_modrm(ctx, pc, out, cs_base);
        break;
    case 0x0F67u:
        out->op = I686_OP7_PACKUSWB;
        out->opnd[0] = I686_OPND_R32;
        out->opnd[1] = I686_OPND_RM32;
        decode_modrm(ctx, pc, out, cs_base);
        break;
    case 0x0FC6u:
        out->op = I686_OP7_SHUFPS;
        out->opnd[0] = I686_OPND_R32;
        out->opnd[1] = I686_OPND_RM32;
        out->opnd[2] = I686_OPND_I8;
        decode_modrm(ctx, pc, out, cs_base);
        out->imm = fetch8(ctx, cs_base + *pc);
        out->imm_size = 1u;
        (*pc)++;
        break;
    case 0x0F20u: /* MOV Cd,Rd / MOV Rd,Cd families: privileged */
    case 0x0F21u:
    case 0x0F22u:
    case 0x0F23u:
    case 0xE4u: /* IN/OUT imm8 and DX forms */
    case 0xE5u:
    case 0xE6u:
    case 0xE7u:
    case 0xECu:
    case 0xEDu:
    case 0xEEu:
    case 0xEFu:
        if (eff_default16(ctx) == 0u) {
            return -1; /* flat code keeps its v1 UNDEF behaviour */
        }
        out->op = I686_OP7_PRIV;
        if (key >= 0x0F20u && key <= 0x0F23u) {
            decode_modrm(ctx, pc, out, cs_base);
        } else if (key <= 0xE7u) {
            (*pc)++; /* imm8 forms */
        }
        break;
    default:
        return -1;
    }
    out->len = (uint8_t)(*pc - eip);
    if (out->len < 1u || out->len > 15u) {
        return -1;
    }
    return 0;
}

int x86_decode(i686_ctx_t *ctx, uint32_t eip, x86_insn_t *out)
{
    uint32_t pc = eip;
    uint32_t cs_base = ctx->seg_base[I686_SEG_CS]; /* fetches are CS-relative */
    const i686_insn_desc_t *desc;
    uint8_t b1;
    uint8_t b2;
    unsigned n;

    {
        /* Phase 7 lazy registration (src/interp/h_seg.c; idempotent,
         * one static-guard branch after the first call).  The frozen
         * interp.c init list is closed; the coordinator may move this
         * into i686_interp_init_all at S7. */
        extern void i686_interp_seg_init(void);
        i686_interp_seg_init();
    }

    memset(out, 0, sizeof(*out));
    out->pfx_seg = SEG_NONE;

    /* Legacy prefixes: take the last of each class. */
    for (n = 0; n < 12; n++) {
        uint8_t b = fetch8(ctx, cs_base + pc);
        if (b == 0x66U) {
            out->pfx_opsize = 1;
        } else if (b == 0x67U) {
            out->pfx_addrsize = 1;
        } else if (b == 0xf0U) {
            out->pfx_lock = 1;
        } else if (b == 0xf3U) {
            out->pfx_rep = 1;
        } else if (b == 0xf2U) {
            out->pfx_rep = 2;
        } else {
            switch (b) {
            case 0x26: out->pfx_seg = I686_SEG_ES; break;
            case 0x2e: out->pfx_seg = I686_SEG_CS; break;
            case 0x36: out->pfx_seg = I686_SEG_SS; break;
            case 0x3e: out->pfx_seg = I686_SEG_DS; break;
            case 0x64: out->pfx_seg = I686_SEG_FS; break;
            case 0x65: out->pfx_seg = I686_SEG_GS; break;
            default: goto prefixes_done;
            }
        }
        pc++;
    }
prefixes_done:;

    /* cs_d-driven defaults (freeze 7.1): effective size = prefix XOR the
     * CS D-bit.  Normalized into the flags the handlers already read
     * ("flag set" == effective 16-bit), so flat code is unchanged and
     * D=0 code runs through the existing width-parameterised handlers. */
    if (eff_default16(ctx) != 0u) {
        out->pfx_opsize = (uint8_t)(out->pfx_opsize ^ 1u);
        out->pfx_addrsize = (uint8_t)(out->pfx_addrsize ^ 1u);
    }

    b1 = fetch8(ctx, cs_base + pc);
    pc++;
    if (b1 == 0x0fU) {
        b2 = fetch8(ctx, cs_base + pc);
        pc++;
        desc = &i686_insn_tab_0f[b2];
    } else {
        b2 = 0;
        desc = &i686_insn_tab_1b[b1];
    }
    if (desc->group_op) {
        const i686_group_t *g;
        decode_modrm(ctx, &pc, out, cs_base); /* fills reg field, advances pc */
        g = group_lookup(b1 == 0x0fU, b1 == 0x0fU ? b2 : b1);
        if (g == NULL || g->reg[out->modrm_reg] == I686_OP_INVALID) {
            return -1;
        }
        out->op = g->reg[out->modrm_reg];
        out->opnd[0] = g->opnd[out->modrm_reg][0];
        out->opnd[1] = g->opnd[out->modrm_reg][1];
        out->opnd[2] = g->opnd[out->modrm_reg][2];
        desc = NULL; /* group rows carry no further modrm/immediates */
    } else if (b1 == 0x90U) {
        /* XCHG eAX,eAX with rm==0 is the canonical one-byte NOP. */
        out->op = I686_OP_NOP;
        out->opnd[0] = I686_OPND_NONE;
        out->len = (uint8_t)(pc - eip);
        return 0;
    } else {
        if (desc->op == I686_OP_INVALID) {
            return far_op_decode(ctx, b1, b2, &pc, out, eip, cs_base);
        }
        out->op = desc->op;
        out->opnd[0] = desc->opnd[0];
        out->opnd[1] = desc->opnd[1];
        out->opnd[2] = desc->opnd[2];
        if (synth_reg_opcode(b1) || (b1 == 0x0fU && synth_reg_opcode_0f(b2))) {
            uint8_t r = (uint8_t)((b1 == 0x0fU ? b2 : b1) & 7U);
            out->has_modrm = 1; /* synthesized, not fetched */
            out->modrm_mod = 3;
            out->modrm_reg = r;
            out->modrm_rm = r;
            out->ea_has = 0;
        } else if (desc->modrm) {
            decode_modrm(ctx, &pc, out, cs_base);
        }
    }

    /* moffs forms (A0–A3): absolute address, no modrm.  Loads (A0/A1)
     * carry the memory operand in opnd[1] (register destination is
     * opnd[0]); stores (A2/A3) in opnd[0].  The moffs offset size
     * follows the ADDRESS-size attribute (SDM MOV moffs: 66 A1 in flat
     * code is a 4-byte offset with a 16-bit load), NOT the operand
     * size.  The bytes live in the code stream (CS-relative fetch). */
    if ((opnd_is_mem(out->opnd[0]) || opnd_is_mem(out->opnd[1])) &&
        !out->has_modrm) {
        unsigned w = out->pfx_addrsize ? 2U : 4U;
        out->ea_has = 1;
        out->ea_base = REG_NONE;
        out->ea_index = REG_NONE;
        out->ea_disp = mem_load(ctx, cs_base + pc, w);
        pc += w;
    }

    /* Family opcodes: condition nibble placement (S1 convention).
     * JCC_*: cond in synthesized modrm_reg (no modrm byte in stream).
     * SETcc_Eb: real modrm present but its reg field is don't-care —
     *           cond from the opcode nibble, parked in modrm_reg.
     * CMOVcc_Gv: reg field is the destination; cond parked in imm&0xF. */
    switch (out->op) {
    case I686_OP_JCC_Jb:
    case I686_OP_JCC_Jz:
        out->modrm_reg = (uint8_t)((b1 == 0x0fU ? b2 : b1) & 0x0fU);
        break;
    case I686_OP_SETcc_Eb:
        out->modrm_reg = (uint8_t)(b2 & 0x0fU);
        break;
    case I686_OP_CMOVcc_Gv:
        out->imm = (uint32_t)(b2 & 0x0fU);
        break;
    default:
        break;
    }

    /* Immediates per operand kinds (Iz/RELz follow the operand size).
     * Immediate bytes live in the code stream (CS-relative fetch).
     * Multiple immediates accumulate: ENTER packs imm16 | (imm8 << 16)
     * with imm_size = 3 (handler convention). */
    for (n = 0; n < 3; n++) {
        unsigned w;
        uint32_t v = 0;
        unsigned vsz = 0;
        switch (out->opnd[n]) {
        case I686_OPND_I8:
        case I686_OPND_I8SX:
            v = fetch8(ctx, cs_base + pc);
            vsz = 1;
            break;
        case I686_OPND_I16:
            v = mem_load(ctx, cs_base + pc, 2);
            vsz = 2;
            break;
        case I686_OPND_I32:
        case I686_OPND_REL32:
            w = out->pfx_opsize ? 2U : 4U;
            v = mem_load(ctx, cs_base + pc, w);
            vsz = w;
            break;
        case I686_OPND_REL8:
            v = (uint32_t)(int32_t)(int8_t)fetch8(ctx, cs_base + pc);
            vsz = 1;
            break;
        default:
            break;
        }
        if (vsz != 0U) {
            out->imm |= v << (out->imm_size * 8U);
            out->imm_size = (uint8_t)(out->imm_size + vsz);
            pc += vsz;
        }
    }

    out->len = (uint8_t)(pc - eip);
    if (out->len < 1U || out->len > 15U) {
        return -1;
    }
    return 0;
}
