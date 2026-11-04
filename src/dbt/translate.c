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

#include "dbt/aot/aot.h"
#include "dbt/emit.h"
#include "interp/interp.h"
#include "rt32/rt32_a64_emit.h"
#include "vm/vm_file.h"

#define I686_DBT_MAX_INSNS 256U

/* Pre-scan classes (see header comment). */
enum {
    TRC_BARRIER = 0,     /* ends the current skip segment */
    TRC_PARTICIPANT = 1, /* fused full writer: skippable, valid j */
    TRC_JONLY = 2,       /* full writer, never skipped: valid j */
    TRC_TRANSPARENT = 3, /* no flags, never declines/closes */
    TRC_PARTIAL = 4,     /* partial writer (ROL/ROR/INC/DEC): skippable if seen_j */
    TRC_NZCV_READER = 5  /* reg-only CMOVcc/SETcc: reads NZCV only */
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

static int tr_is_block_end(const x86_insn_t *insn)
{
    switch (insn->op) {
    case I686_OP_JMP_Jb:
    case I686_OP_JMP_Jz:
    case I686_OP_JMP_Ev:
    case I686_OP_JCC_Jb:
    case I686_OP_JCC_Jz:
    case I686_OP_LOOPNZ_Jb:
    case I686_OP_LOOPZ_Jb:
    case I686_OP_LOOP_Jb:
    case I686_OP_JCXZ_Jb:
    case I686_OP_CALL_Jz:
    case I686_OP_CALL_Ev:
    case I686_OP_RET:
    case I686_OP_RET_Iw:
    case I686_OP_IRET:
    case I686_OP_INT_Ib:
    case I686_OP_INT3:
    case I686_OP_INTO:
    case I686_OP_HLT:
    case I686_OP_UD2:
    case I686_OP_SYSENTER:
        return 1;
    default:
        return 0;
    }
}

static int tr_page_readable(const i686_ctx_t *ctx, uint32_t va)
{
    extern void rt32_vm_sync_ctx_if_stale(i686_ctx_t *);
    uint32_t page = va & ~0xFFFu;
    size_t i;

    if (ctx->vm_reserved[0] != 0U) {
        if ((i686_vm_file_flags(page) & 0x80u) != 0u) {
            return (i686_vm_file_prot(page) & 0x05u) != 0u ? 1 : 0;
        }
        rt32_vm_sync_ctx_if_stale((i686_ctx_t *)(uintptr_t)ctx);
        if (ctx->region_count == 0U) {
            return 1;
        }
        return 0;
    }
    if (ctx->region_count == 0U && !ctx->is_thread_clone) {
        return 1;
    }
    for (i = 0U; i < ctx->region_count; i++) {
        uint32_t start = ctx->regions[i].start;
        uint32_t end = ctx->regions[i].end;
        if (end > start && page >= start && page < end) {
            return (ctx->regions[i].prot & 0x05U) != 0U ? 1 : 0;
        }
    }
    return 0;
}

static int tr_is_static_rolror(unsigned op)
{
    switch (op) {
    case I686_OP_ROL_Eb1:
    case I686_OP_ROL_Ev1:
    case I686_OP_ROR_Eb1:
    case I686_OP_ROR_Ev1:
    case I686_OP_ROL_EbIb:
    case I686_OP_ROL_EvIb:
    case I686_OP_ROR_EbIb:
    case I686_OP_ROR_EvIb:
        return 1;
    default:
        return 0;
    }
}

static int tr_is_rolror_cnt1(const x86_insn_t *insn)
{
    unsigned op = insn->op;
    if (op == (unsigned)I686_OP_ROL_Eb1 || op == (unsigned)I686_OP_ROL_Ev1 ||
        op == (unsigned)I686_OP_ROR_Eb1 || op == (unsigned)I686_OP_ROR_Ev1) {
        return 1;
    }
    if (tr_is_static_rolror(op) != 0 && ((insn->imm & 31U) == 1U)) {
        return 1;
    }
    return 0;
}

static int tr_is_incdec(unsigned op)
{
    return (op == (unsigned)I686_OP_INC_Eb || op == (unsigned)I686_OP_INC_Ev ||
            op == (unsigned)I686_OP_DEC_Eb || op == (unsigned)I686_OP_DEC_Ev)
               ? 1
               : 0;
}

static int tr_is_mem_ro32(unsigned op)
{
    switch (op) {
    case I686_OP_MOV_GvEv:
    case I686_OP_ADD_GvEv: case I686_OP_SUB_GvEv: case I686_OP_CMP_GvEv:
    case I686_OP_AND_GvEv: case I686_OP_OR_GvEv:  case I686_OP_XOR_GvEv:
    case I686_OP_CMP_EvGv: case I686_OP_CMP_EvIz: case I686_OP_CMP_EvIbSX:
    case I686_OP_TEST_EvGv: case I686_OP_TEST_EvIz:
    case I686_OP_IMUL_GvEv: case I686_OP_IMUL_GvEvIz: case I686_OP_IMUL_GvEvIb:
        return 1;
    default:
        return 0;
    }
}

static int tr_is_mem_rw32(unsigned op)
{
    switch (op) {
    case I686_OP_MOV_EvGv: case I686_OP_MOV_EvIz:
    case I686_OP_ADD_EvGv: case I686_OP_ADD_EvIz: case I686_OP_ADD_EvIbSX:
    case I686_OP_SUB_EvGv: case I686_OP_SUB_EvIz: case I686_OP_SUB_EvIbSX:
    case I686_OP_AND_EvGv: case I686_OP_AND_EvIz: case I686_OP_AND_EvIbSX:
    case I686_OP_OR_EvGv:  case I686_OP_OR_EvIz:  case I686_OP_OR_EvIbSX:
    case I686_OP_XOR_EvGv: case I686_OP_XOR_EvIz: case I686_OP_XOR_EvIbSX:
    case I686_OP_NEG_Ev:   case I686_OP_NOT_Ev:
    case I686_OP_INC_Ev:   case I686_OP_DEC_Ev:
    case I686_OP_SHL_Ev1:  case I686_OP_SHL_EvIb:
    case I686_OP_SHR_Ev1:  case I686_OP_SHR_EvIb:
    case I686_OP_SAR_Ev1:  case I686_OP_SAR_EvIb:
    case I686_OP_ROL_Ev1:  case I686_OP_ROL_EvIb:
    case I686_OP_ROR_Ev1:  case I686_OP_ROR_EvIb:
        return 1;
    default:
        return 0;
    }
}

static unsigned tr_classify(const x86_insn_t *insn)
{
    unsigned op = insn->op;
    int regonly = tr_is_regonly(insn);

    if (insn->pfx_lock != 0U) {
        return TRC_BARRIER;
    }
    if (op == (unsigned)I686_OP_LEA_GvM) {
        return TRC_TRANSPARENT;
    }
    if ((op == (unsigned)I686_OP_CMOVcc_Gv ||
         op == (unsigned)I686_OP_SETcc_Eb) &&
        regonly != 0 && insn->pfx_rep == 0U &&
        ((insn->imm & 0xEU) != 10U)) {
        return TRC_NZCV_READER;
    }

    /* Fused full writers (no LOCK): skippable, valid j. */
    if (tr_is_fused9(op) != 0 ||
        op == (unsigned)I686_OP_NEG_Eb || op == (unsigned)I686_OP_NEG_Ev) {
        return TRC_PARTICIPANT;
    }
    /* Eager full writers with a static nonzero count (no LOCK): valid j,
     * skippable when followed by a register-only full writer. */
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
        return TRC_PARTIAL;
    default:
        break;
    }
    /* Static no-op rotates/shifts: no write, no flags, never decline. */
    switch (op) {
    case I686_OP_ROL_EbIb: case I686_OP_ROL_EvIb:
    case I686_OP_ROR_EbIb: case I686_OP_ROR_EvIb:
    case I686_OP_SHLD_EvIb: case I686_OP_SHRD_EvIb:
        if (((insn->imm & 0xFFU) & 31U) == 0U) {
            return TRC_TRANSPARENT;
        }
        return TRC_PARTIAL;
    case I686_OP_ROL_Eb1: case I686_OP_ROL_Ev1:
    case I686_OP_ROR_Eb1: case I686_OP_ROR_Ev1:
    case I686_OP_ROL_EbCL: case I686_OP_ROL_EvCL:
    case I686_OP_ROR_EbCL: case I686_OP_ROR_EvCL:
    case I686_OP_INC_Eb: case I686_OP_INC_Ev:
    case I686_OP_DEC_Eb: case I686_OP_DEC_Ev:
        return TRC_PARTIAL;
    case I686_OP_BT_EvGv: case I686_OP_BTS_EvGv:
    case I686_OP_BTR_EvGv: case I686_OP_BTC_EvGv:
    case I686_OP_BT_EvIb: case I686_OP_BTS_EvIb:
    case I686_OP_BTR_EvIb: case I686_OP_BTC_EvIb:
        return (insn->modrm_mod == 3U) ? TRC_PARTIAL : TRC_BARRIER;
    default:
        break;
    }
    /* Flag-transparent ops. */
    switch (op) {
    case I686_OP_NOP:
    case I686_OP_BSWAP_Gv:
    case I686_OP_NOT_Eb:
    case I686_OP_NOT_Ev:
    case I686_OP_MOV_EbGb: case I686_OP_MOV_EvGv:
    case I686_OP_MOV_GbEb: case I686_OP_MOV_GvEv:
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
    int stopped_early = 0;
    uint32_t fail_pc = 0U;

    /* Phase 1: decode at most one page worth of instructions, stopping
     * immediately at block terminators or before crossing into an
     * unmapped page (I686-6). */
    for (i = 0U; i < I686_DBT_MAX_INSNS; i++) {
        uint32_t fetch_va = ctx->seg_base[I686_SEG_CS] + pc;
        int drc;
        if (i > 0U && (fetch_va & 0xFFFu) > 0xFF0u &&
            tr_page_readable(ctx, (fetch_va & ~0xFFFu) + 0x1000u) == 0) {
            stopped_early = 1;
            break;
        }
        drc = x86_decode(ctx, pc, &insns[m]);
        if (drc != 0) {
            failed = 1;
            fail_pc = pc;
            break;
        }
        m++;
        pc += insns[m - 1U].len;
        if (tr_is_block_end(&insns[m - 1U]) != 0) {
            break;
        }
        if (i686_page_down(pc) != i686_page_down(eip)) {
            break;
        }
    }
    /* Phase 2: fault-barrier-safe skip analysis.  Segments end at
     * barriers; the backward pass sets skip[i] for a fused producer
     * when a full flag writer follows in the same segment. */
    {
        uint8_t non_faulting[I686_DBT_MAX_INSNS];
        uint32_t esp_r = 0U;
        uint32_t esp_w = 0U;
        unsigned char seen_reg_j = 0U;
        unsigned char seen_mem_j = 0U;
        unsigned char seen_rol1 = 0U;
        unsigned char seen_reg_incdec = 0U;
        unsigned char seen_nzcv_only = 0U;

        for (i = 0U; i < m; i++) {
            const x86_insn_t *in = &insns[i];
            cls[i] = (unsigned char)tr_classify(in);
            skip[i] = 0U;
            if (in->op == I686_OP_LEA_GvM || tr_is_regonly(in) != 0) {
                non_faulting[i] = 1U;
            } else {
                non_faulting[i] = 0U;
                if (in->pfx_opsize == 0U && in->pfx_addrsize == 0U &&
                    in->ea_has != 0U && in->ea_base == I686_REG_ESP &&
                    in->ea_index == 0xFFU && in->pfx_seg == 0xFFU &&
                    ((uint32_t)in->ea_disp & 3U) == 0U &&
                    (uint32_t)in->ea_disp < 128U) {
                    uint32_t bit = 1U << ((uint32_t)in->ea_disp >> 2U);
                    if (tr_is_mem_ro32(in->op) != 0) {
                        if (((esp_r | esp_w) & bit) != 0U) {
                            non_faulting[i] = 1U;
                        }
                        esp_r |= bit;
                    } else if (tr_is_mem_rw32(in->op) != 0) {
                        if ((esp_w & bit) != 0U) {
                            non_faulting[i] = 1U;
                        }
                        esp_w |= bit;
                        esp_r |= bit;
                    }
                }
            }
            if (cls[i] == (unsigned char)TRC_BARRIER ||
                in->modrm_reg == I686_REG_ESP ||
                (in->modrm_mod == 3U && in->modrm_rm == I686_REG_ESP)) {
                esp_r = 0U;
                esp_w = 0U;
            }
        }
        for (i = m; i-- > 0U;) {
            int regonly = (int)non_faulting[i];
            if (cls[i] == (unsigned char)TRC_BARRIER) {
                seen_reg_j = 0U;
                seen_mem_j = 0U;
                seen_rol1 = 0U;
                seen_reg_incdec = 0U;
                seen_nzcv_only = 0U;
                continue;
            }
            if (cls[i] == (unsigned char)TRC_NZCV_READER) {
                seen_nzcv_only =
                    (seen_reg_j != 0U || seen_reg_incdec != 0U ||
                     seen_nzcv_only != 0U)
                        ? 1U
                        : 0U;
                seen_reg_j = 0U;
                seen_mem_j = 0U;
                seen_rol1 = 0U;
                seen_reg_incdec = 0U;
                continue;
            }
            if ((cls[i] == (unsigned char)TRC_PARTICIPANT ||
                 cls[i] == (unsigned char)TRC_JONLY ||
                 cls[i] == (unsigned char)TRC_PARTIAL) &&
                (seen_reg_j != 0U ||
                 (tr_is_incdec(insns[i].op) != 0 && seen_reg_incdec != 0U))) {
                skip[i] = 1U;
            } else if (cls[i] == (unsigned char)TRC_PARTICIPANT &&
                       seen_nzcv_only != 0U) {
                skip[i] = 3U;
            } else if (seen_mem_j != 0U) {
                if (cls[i] == (unsigned char)TRC_PARTICIPANT ||
                    tr_is_static_rolror(insns[i].op) != 0 ||
                    (tr_is_incdec(insns[i].op) != 0 && seen_rol1 == 0U)) {
                    skip[i] = 2U;
                }
            } else if (tr_is_incdec(insns[i].op) != 0 && i >= 2U &&
                       cls[i - 1U] == (unsigned char)TRC_PARTIAL &&
                       tr_is_static_rolror(insns[i - 1U].op) != 0 &&
                       tr_is_regonly(&insns[i - 1U]) != 0) {
                unsigned q = i - 1U;
                while (q > 0U && cls[q - 1U] == (unsigned char)TRC_TRANSPARENT) {
                    q--;
                }
                if (q > 0U && cls[q - 1U] == (unsigned char)TRC_PARTICIPANT) {
                    if (insns[i].opnd[0] != I686_OPND_RM8 &&
                        insns[i].pfx_opsize == 0U && i + 2U == m &&
                        (insns[i + 1U].op == I686_OP_JCC_Jb ||
                         insns[i + 1U].op == I686_OP_JCC_Jz) &&
                        (insns[i + 1U].modrm_reg & 0xEU) != 2U &&
                        (insns[i + 1U].modrm_reg & 0xEU) != 6U &&
                        (insns[i + 1U].modrm_reg & 0xEU) != 10U) {
                        skip[i] = 5U;
                    } else {
                        skip[i] = 4U;
                    }
                }
            }
            if (cls[i] == (unsigned char)TRC_PARTICIPANT ||
                cls[i] == (unsigned char)TRC_JONLY) {
                seen_reg_j = (regonly != 0) ? 1U : 0U;
                seen_reg_incdec = 0U;
                seen_nzcv_only = 0U;
                seen_rol1 = 0U;
                seen_mem_j = 1U;
            } else {
                if (cls[i] == (unsigned char)TRC_PARTIAL) {
                    int is_id = tr_is_incdec(insns[i].op);
                    seen_reg_incdec = (is_id != 0 && regonly != 0) ? 1U : 0U;
                    seen_nzcv_only = (is_id != 0 && regonly != 0 &&
                                      insns[i].opnd[0] != I686_OPND_RM8 &&
                                      insns[i].pfx_opsize == 0U &&
                                      skip[i] == 0U)
                                         ? 1U
                                         : 0U;
                    if (skip[i] == 4U || skip[i] == 5U) {
                        seen_mem_j = 1U;
                        seen_rol1 = 0U;
                    } else if (skip[i] == 0U ||
                               (skip[i] == 1U && regonly == 0)) {
                        seen_mem_j = 0U;
                        seen_rol1 = 0U;
                    } else if (skip[i] == 2U &&
                               tr_is_rolror_cnt1(&insns[i]) != 0) {
                        seen_rol1 = 1U;
                    }
                }
                if (regonly == 0) {
                    seen_reg_j = 0U;
                    seen_reg_incdec = 0U;
                    seen_nzcv_only = 0U;
                }
            }
        }
    }

    /* Phase 3: emit (v1 flow, over the decoded array). */
    i686_emit_begin(&e, ctx, code, cap, eip);
    pc = eip;

    for (n = 0U; n < m; n++) {
        x86_insn_t *insn = &insns[n];
        size_t ring_insn = i686_aot_ring_count();
        size_t w_start = e.buf.count;
        int rc;

        e.insn_pc = pc;
        e.skip_lazy = skip[n];
        /* Category dispatch (lane modules). Order matters only for
         * testing; ids are disjoint. */
        if (insn->pfx_lock != 0U) {
            /* R7-7: illegal LOCK forms never reach the emitters (which
             * would lower them to plain non-atomic code); the block
             * ends with UNDEF and the interpreter delivers #UD. */
            if (!x86_lock_legal(insn)) {
                i686_emit_exit(&e, I686_EXIT_UNDEF, insn->len, pc);
                break;
            }
            {
                extern int i686_emit_atomic(i686_emit_ctx_t *,
                                            const x86_insn_t *);
                rc = i686_emit_atomic(&e, insn);
            }
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
            if (rc == 0 && e.tso && tr_is_regonly(insn) == 0) {
                a64_emit(&e.buf, 0xD5033BBFU); /* dmb ish (I686-R2-8) */
            }
        }
        if (rc < 0) {
            /* Not emittable: end block; the engine interprets ONE insn
             * (the D2 fallback) and re-enters translation at pc+len. */
            i686_emit_exit(&e, I686_EXIT_UNDEF, insn->len, pc);
            break;
        }
        if (i686_aot_ring_count() == ring_insn && e.buf.count > w_start &&
            (tr_is_regonly(insn) == 0 ||
             (insn->op >= I686_OP_MOVSb && insn->op <= I686_OP_SCASw))) {
            dbt_mem_site_t site;
            memset(&site, 0, sizeof(site));
            site.seq_start_offset = (uint16_t)(w_start * 4U);
            site.host_insn_offset = (uint16_t)((e.buf.count - 1U) * 4U);
            site.cont_insn_offset = (uint16_t)(e.buf.count * 4U);
            site.guest_pc_delta = (uint16_t)(pc - eip);
            site.insn_word = (uint32_t)insn->op & 0xFFFFU;
            (void)i686_aot_note_stack_site(&site);
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
        } else if (m == I686_DBT_MAX_INSNS || stopped_early != 0) {
            i686_emit_exit(&e, I686_EXIT_BRANCH, 0U, pc);
        }
    }

    {
        size_t len;
        (void)i686_emit_finish(&e, &len);
        return len;
    }
}
