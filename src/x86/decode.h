/*
 * src/x86/decode.h — frozen decoder interface (Phase 1 freeze, SPEC §4.C)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The opcode-id enum (i686_op_t) and the table descriptors are GENERATED
 * into src/x86/insn_tab.h by tools/gen_insn_tab.py (lane L1a); the exact
 * identifier list and descriptor format are frozen in
 * docs/lanes/phase-1.md and must match this header's use.
 */

#ifndef I686RT_X86_DECODE_H
#define I686RT_X86_DECODE_H

#include <stdint.h>

#include "i686rt.h"
#include "x86/insn_tab.h" /* generated: i686_op_t, i686_insn_desc_t, tables */

/* Operand kinds (frozen).  Order in i686_insn_desc_t.opnd[] is Intel
 * convention: [0] = destination, [1], [2] = sources. */
enum {
    I686_OPND_NONE = 0,
    I686_OPND_R8,    /* register byte      (reg field)            */
    I686_OPND_R16,   /* register word      (reg field)            */
    I686_OPND_R32,   /* register dword     (reg field)            */
    I686_OPND_RM8,   /* r/m byte           (modrm rm, mod!=3 mem) */
    I686_OPND_RM16,
    I686_OPND_RM32,
    I686_OPND_I8,    /* immediate byte, zero-extended at use       */
    I686_OPND_I8SX,  /* immediate byte, sign-extended at use       */
    I686_OPND_I16,
    I686_OPND_I32,
    I686_OPND_REL8,  /* branch relative, sign-extended             */
    I686_OPND_REL32,
    I686_OPND_M1616, /* far pointer m16:16 (Phase 7; decode only)  */
    I686_OPND_ONE,   /* implicit 1 (shifts by one)                 */
    I686_OPND_CL,    /* implicit CL                                */
    I686_OPND_SREG   /* segment register (reg field)               */
};

/* Decoded instruction (frozen layout; consumed by interp handlers, the
 * Phase 3 translator, and the differential tracer). */
typedef struct x86_insn {
    uint16_t op;           /* i686_op_t */
    uint8_t  opnd[3];      /* I686_OPND_* copied from the descriptor     */
    uint8_t  len;          /* total instruction length in bytes          */
    uint8_t  pfx_opsize;   /* 1 if 66 present                            */
    uint8_t  pfx_addrsize; /* 1 if 67 present (16-bit addressing, interp) */
    uint8_t  pfx_rep;      /* 0 none, 1 F3, 2 F2                         */
    uint8_t  pfx_seg;      /* I686_SEG_* override, 0xFF if none          */
    uint8_t  pfx_lock;     /* 1 if F0 present                            */
    uint8_t  has_modrm;
    uint8_t  modrm_mod, modrm_reg, modrm_rm;
    /* Effective address when mod != 3 (or table says memory):
     * base/index are I686_REG_* or 0xFF (none); scale 0,1,2,3 => 1,2,4,8.
     * With pfx_addrsize the decoder fills 16-bit addressing rm slots the
     * same way (base/index/displacement per the 16-bit table). */
    uint8_t  ea_base, ea_index, ea_scale, ea_has;
    uint32_t ea_disp;      /* zero- or sign-extended displacement         */
    uint32_t imm;          /* raw immediate, right-aligned               */
    uint8_t  imm_size;     /* 0, 1, 2, or 4 bytes fetched                */
} x86_insn_t;

/* Decode one instruction at guest EIP (fetch via CS base + window).
 * Returns 0 on success (out filled, out->len >= 1), -1 if the opcode has
 * no table entry (caller treats as I686_EXIT_UNDEF per D2 — never assert).
 * Segments: fetch and EA honor ctx->seg_base[pfx_seg ?: DS|SS] (D8). */
int x86_decode(i686_ctx_t *ctx, uint32_t eip, x86_insn_t *out);

/* Operand access helpers shared by interp and DBT (implemented in
 * decode.c; frozen signatures). */
uint32_t x86_reg_read(const i686_ctx_t *ctx, uint8_t reg, unsigned width);
void     x86_reg_write(i686_ctx_t *ctx, uint8_t reg, unsigned width, uint32_t val);
uint32_t x86_rm_read(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width);
void     x86_rm_write(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned width, uint32_t val);
/* EA (post segment-base addition, still a 32-bit wrapping guest VA). */
uint32_t x86_ea_compute(i686_ctx_t *ctx, const x86_insn_t *insn);

#endif /* I686RT_X86_DECODE_H */
