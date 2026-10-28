/*
 * src/dbt/translate.c — block translator core (SPEC §3.3, D2, D6, D7)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Block = straight line until branch/int/hlt/unknown/page end, max 64
 * insns. Unknown opcode -> I686_EXIT_UNDEF with insn length stored so
 * the engine interprets one insn then resumes (D2, never an abort).
 *
 * Lane P3 (Wave P) pre-scan: before emitting, the block's instructions
 * are decoded into an array and classified for the fault-barrier-safe
 * skip analysis.  A fused lazy producer (ADD/SUB/CMP/AND/OR/XOR/TEST/
 * NEG, register or memory, no LOCK) gets skip[i] when a later full flag
 * writer (fused, imm-shift with nonzero count, or register IMUL)
 * overwrites OSZAPC before any barrier.  Barriers: DIV/IDIV (#DE),
 * helper calls, CL-count shifts/SHLD/SHRD, 1-op MUL/IMUL, ADC/SBB
 * (carry readers), flag readers (consumers), traps and exits.  Memory
 * MOV/MOVZX/MOVSX never touch flags (transparent); memory ALU, TEST,
 * NEG, INC/DEC, ROL/ROR and nonzero shifts join the skip analysis
 * because the fault path recovers only eip/esp (GPRs and lazy flags
 * materialize at block exit).  Whitelisted instructions provably never
 * decline and never close the block, so a skip can only span emitted
 * code.  The emit phase below is otherwise byte-identical to the v1
 * flow (same exits, same order, same UNDEF shapes).
 */

#include <stdint.h>
#include <string.h>

#include "dbt/emit.h"
#include "interp/interp.h"
#include "rt32/rt32_a64_emit.h"

#define I686_DBT_MAX_INSNS 64U

/* Pre-scan classes (see header comment). */
enum {
    TRC_BARRIER = 0,     /* ends the current skip segment */
    TRC_PARTICIPANT = 1, /* fused full writer: skippable, valid j */
    TRC_JONLY = 2,       /* full writer, never skipped: valid j */
    TRC_TRANSPARENT = 3, /* no flags, never declines/closes */
    TRC_PARTIAL = 4      /* partial writer (ROL/ROR/INC/DEC): skippable if seen_j */
};

static int tr_is_regonly(const x86_insn_t *insn)
{
    return (insn->modrm_mod == 3U || insn->ea_has == 0U) ? 1 : 0;
}

static int tr_is_fused9(unsigned op)
{
    switch (op) {
    case I686_OP_ADD_EbGb: case I686_OP_ADD_EvGv:
    case I686_OP_ADD_GbEb: case I686_OP_ADD_GvEv:
    case I686_OP_ADD_ALIb: case I686_OP_ADD_eAXIz:
    case I686_OP_ADD_EbIb: case I686_OP_ADD_EvIz:
    case I686_OP_ADD_EvIbSX:
    case I686_OP_SUB_EbGb: case I686_OP_SUB_EvGv:
    case I686_OP_SUB_GbEb: case I686_OP_SUB_GvEv:
    case I686_OP_SUB_ALIb: case I686_OP_SUB_eAXIz:
    case I686_OP_SUB_EbIb: case I686_OP_SUB_EvIz:
    case I686_OP_SUB_EvIbSX:
    case I686_OP_CMP_EbGb: case I686_OP_CMP_EvGv:
    case I686_OP_CMP_GbEb: case I686_OP_CMP_GvEv:
    case I686_OP_CMP_ALIb: case I686_OP_CMP_eAXIz:
    case I686_OP_CMP_EbIb: case I686_OP_CMP_EvIz:
    case I686_OP_CMP_EvIbSX:
    case I686_OP_AND_EbGb: case I686_OP_AND_EvGv:
    case I686_OP_AND_GbEb: case I686_OP_AND_GvEv:
    case I686_OP_AND_ALIb: case I686_OP_AND_eAXIz:
    case I686_OP_AND_EbIb: case I686_OP_AND_EvIz:
    case I686_OP_AND_EvIbSX:
    case I686_OP_OR_EbGb: case I686_OP_OR_EvGv:
    case I686_OP_OR_GbEb: case I686_OP_OR_GvEv:
    case I686_OP_OR_ALIb: case I686_OP_OR_eAXIz:
    case I686_OP_OR_EbIb: case I686_OP_OR_EvIz:
    case I686_OP_OR_EvIbSX:
    case I686_OP_XOR_EbGb: case I686_OP_XOR_EvGv:
    case I686_OP_XOR_GbEb: case I686_OP_XOR_GvEv:
    case I686_OP_XOR_ALIb: case I686_OP_XOR_eAXIz:
    case I686_OP_XOR_EbIb: case I686_OP_XOR_EvIz:
    case I686_OP_XOR_EvIbSX:
    case I686_OP_TEST_EbGb: case I686_OP_TEST_EvGv:
    case I686_OP_TEST_ALIb: case I686_OP_TEST_eAXIz:
    case I686_OP_TEST_EbIb: case I686_OP_TEST_EvIz:
        return 1;
    default:
        return 0;
    }
}

static unsigned tr_classify(const x86_insn_t *insn)
{
    unsigned op = insn->op;
    int regonly = tr_is_regonly(insn);

    /* Fused full writers (no LOCK): skippable, valid j.  Register and
     * memory forms alike: a faulting memory op recovers only eip/esp
     * (engine.c fault path; GPRs and lazy flags materialize at block
     * exit), so a skipped lazy store is never observed. */
    if (insn->pfx_lock == 0U &&
        (tr_is_fused9(op) != 0 ||
         op == (unsigned)I686_OP_NEG_Eb || op == (unsigned)I686_OP_NEG_Ev)) {
        return TRC_PARTICIPANT;
    }
    /* Eager full writers with a static nonzero count (no LOCK): valid j,
     * never skipped (their stores always run).  SHL/SHR/SAR by 1 or by a
     * nonzero imm count are full writers for register and memory dests
     * alike (LOCKed memory declines to the interpreter). */
    if (insn->pfx_lock == 0U) {
        switch (op) {
        case I686_OP_SHL_Eb1: case I686_OP_SHL_Ev1:
        case I686_OP_SHR_Eb1: case I686_OP_SHR_Ev1:
        case I686_OP_SAR_Eb1: case I686_OP_SAR_Ev1:
            return TRC_JONLY;
        case I686_OP_SHL_EbIb: case I686_OP_SHL_EvIb:
        case I686_OP_SHR_EbIb: case I686_OP_SHR_EvIb:
        case I686_OP_SAR_EbIb: case I686_OP_SAR_EvIb:
            if (((insn->imm & 0xFFU) & 31U) != 0U) {
                return TRC_JONLY;
            }
            return TRC_TRANSPARENT; /* static no-op */
        case I686_OP_IMUL_GvEv:
        case I686_OP_IMUL_GvEvIz:
        case I686_OP_IMUL_GvEvIb:
            if (regonly != 0) {
                return TRC_JONLY;
            }
            break;
        default:
            break;
        }
    }
    /* Static no-op rotates/shifts: no write, no flags, never decline. */
    switch (op) {
    case I686_OP_ROL_EbIb: case I686_OP_ROL_EvIb:
    case I686_OP_ROR_EbIb: case I686_OP_ROR_EvIb:
    case I686_OP_SHLD_EvIb: case I686_OP_SHRD_EvIb:
        if (((insn->imm & 0xFFU) & 31U) == 0U) {
            return TRC_TRANSPARENT;
        }
        if (insn->pfx_lock == 0U) {
            return TRC_PARTIAL;
        }
        break;
    case I686_OP_ROL_Eb1: case I686_OP_ROL_Ev1:
    case I686_OP_ROR_Eb1: case I686_OP_ROR_Ev1:
    case I686_OP_ROL_EbCL: case I686_OP_ROL_EvCL:
    case I686_OP_ROR_EbCL: case I686_OP_ROR_EvCL:
    case I686_OP_INC_Eb: case I686_OP_INC_Ev:
    case I686_OP_DEC_Eb: case I686_OP_DEC_Ev:
        if (insn->pfx_lock == 0U) {
            return TRC_PARTIAL;
        }
        break;
    default:
        break;
    }
    /* Flag-transparent, provably never declining/closing.  MOV (all
     * forms, register or memory) and MOVZX/MOVSX never touch flags. */
    switch (op) {
    case I686_OP_NOP:
    case I686_OP_WAIT:
    case I686_OP_BSWAP_Gv:
    case I686_OP_LEA_GvM:
        return TRC_TRANSPARENT;
    case I686_OP_NOT_Eb:
    case I686_OP_NOT_Ev:
        if (regonly != 0) {
            return TRC_TRANSPARENT;
        }
        break;
    case I686_OP_MOV_EbGb: case I686_OP_MOV_EvGv:
    case I686_OP_MOV_GbEb: case I686_OP_MOV_GvEv:
    case I686_OP_MOV_ALOb: case I686_OP_MOV_eAXOv:
    case I686_OP_MOV_ObAL: case I686_OP_MOV_OveAX:
    case I686_OP_MOV_EbIb: case I686_OP_MOV_EvIz:
    case I686_OP_MOV_GbIb: case I686_OP_MOV_GvIv:
    case I686_OP_MOVZX_GvEb: case I686_OP_MOVZX_GvEw:
    case I686_OP_MOVSX_GvEb: case I686_OP_MOVSX_GvEw:
        return TRC_TRANSPARENT;
    case I686_OP_XCHG_EbGb: case I686_OP_XCHG_EvGv:
    case I686_OP_XCHG_eAXGv:
        if (regonly != 0) {
            return TRC_TRANSPARENT;
        }
        break;
    default:
        break;
    }
    /* Everything else is a fault/reader/partial/exit barrier:
     * DIV/IDIV, ADC/SBB (carry readers), CL-count shifts, MUL/IMUL-1op,
     * LOCKed forms, all branches/syscalls/traps/string/SSE/x87/unknown
     * rows, and any remaining memory access. */
    return TRC_BARRIER;
}

/* Fallback table: the interpreter registry is authoritative; for ops the
 * emitter modules decline (return -1), we end the block with UNDEF and
 * the engine loop single-steps via the interpreter. */
int i686_dbt_enabled(void)
{
    return 1;
}

/* Translate one block starting at guest EIP into `code` (cap bytes).
 * Returns bytes emitted, or 0 when nothing could be emitted (engine
 * falls back to the interpreter for this block permanently). */
size_t i686_dbt_translate(i686_ctx_t *ctx, uint32_t eip, uint8_t *code,
                          size_t cap)
{
    i686_emit_ctx_t e;
    uint32_t pc = eip;
    x86_insn_t insns[I686_DBT_MAX_INSNS];
    unsigned char cls[I686_DBT_MAX_INSNS];
    uint8_t skip[I686_DBT_MAX_INSNS];
    unsigned m = 0U;
    unsigned n;
    unsigned i;
    int failed = 0;
    uint32_t fail_pc = 0U;

    /* Phase 1: decode at most one page worth of instructions.  The walk
     * stays on the block-start page (mapped by construction), so it is
     * fault-safe; it stops where the v1 loop would (fail/page/64). */
    for (i = 0U; i < I686_DBT_MAX_INSNS; i++) {
        if (x86_decode(ctx, pc, &insns[m]) != 0) {
            failed = 1;
            fail_pc = pc;
            break;
        }
        m++;
        pc += insns[m - 1U].len;
        if (i686_page_down(pc) != i686_page_down(eip)) {
            break;
        }
    }
    /* Phase 2: fault-barrier-safe skip analysis.  Segments end at
     * barriers; the backward pass sets skip[i] for a fused producer
     * when a full flag writer follows in the same segment. */
    for (i = 0U; i < m; i++) {
        cls[i] = (unsigned char)tr_classify(&insns[i]);
        skip[i] = 0U;
    }
    {
        unsigned char seen_j = 0;
        for (i = m; i-- > 0U;) {
            if (cls[i] == (unsigned char)TRC_BARRIER) {
                seen_j = 0;
                continue;
            }
            if ((cls[i] == (unsigned char)TRC_PARTICIPANT ||
                 cls[i] == (unsigned char)TRC_PARTIAL) && seen_j != 0) {
                skip[i] = 1U;
            }
            if (cls[i] == (unsigned char)TRC_PARTICIPANT ||
                cls[i] == (unsigned char)TRC_JONLY) {
                seen_j = 1;
            }
        }
    }

    /* Phase 3: emit (v1 flow, over the decoded array). */
    i686_emit_begin(&e, ctx, code, cap, eip);
    pc = eip;

    for (n = 0U; n < m; n++) {
        x86_insn_t *insn = &insns[n];
        int rc;

        e.insn_pc = pc;
        e.skip_lazy = skip[n];
        /* Category dispatch (lane modules). Order matters only for
         * testing; ids are disjoint. */
        if (insn->pfx_lock != 0U) {
            extern int i686_emit_atomic(i686_emit_ctx_t *,
                                        const x86_insn_t *);
            rc = i686_emit_atomic(&e, insn);
        } else {
            rc = i686_emit_alu(&e, insn);
        }
        if (rc < 0) {
            rc = i686_emit_mov(&e, insn);
        }
        if (rc < 0) {
            rc = i686_emit_branch(&e, insn);
        }
        if (rc < 0) {
            rc = i686_emit_string(&e, insn);
        }
        if (rc < 0) {
            extern int i686_emit_sse(i686_emit_ctx_t *, const x86_insn_t *);
            rc = i686_emit_sse(&e, insn);
        }
        if (rc < 0) {
            /* Not emittable: end block; the engine interprets ONE insn
             * (the D2 fallback) and re-enters translation at pc+len. */
            i686_emit_exit(&e, I686_EXIT_UNDEF, insn->len, pc);
            break;
        }

        pc += insn->len;

        /* Block terminators: branch/trap/syscall exits are emitted by
         * the branch module (it returns 0 after emitting an exit). */
        if (e.block_open == false) {
            break;
        }
        if (i686_page_down(pc) != i686_page_down(eip)) {
            i686_emit_exit(&e, I686_EXIT_BRANCH, 0U, pc);
            break;
        }
    }
    if (n == m && e.block_open) {
        if (failed != 0) {
            /* v1 decode-fail shape: UNDEF with arg 0 at the fail PC. */
            i686_emit_exit(&e, I686_EXIT_UNDEF, 0U, fail_pc);
        } else if (m == I686_DBT_MAX_INSNS) {
            i686_emit_exit(&e, I686_EXIT_BRANCH, 0U, pc);
        }
    }

    {
        size_t len;
        (void)i686_emit_finish(&e, &len);
        return len;
    }
}
