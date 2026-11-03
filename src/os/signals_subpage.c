/*
 * src/os/signals_subpage.c — Regime A2 4 KiB sub-page fault validation & emulation
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * On Regime A2 hosts (H > 4096, e.g. 16 KiB macOS Apple Silicon or 16K/64K
 * Linux), each host page covering guest memory carries the intersection (AND)
 * of its 4 KiB sub-page protections via i686_vm32_widen_prot. When a guest
 * instruction accesses a 4 KiB sub-page that shares a host page with a more
 * restricted neighbour sub-page (such as PROT_NONE or PROT_READ), the host
 * MMU faults.
 *
 * i686_spurious_allow and i686_spurious_emulate validate that every 4 KiB
 * sub-page spanned by the instruction fetch and by all memory accesses of the
 * faulting instruction holds the required guest permissions in both the region
 * table and the per-4 KiB i686_vm_file mirror. Legitimate accesses are
 * single-stepped under i686_vm32_subpage_lock() while temporarily opening the
 * covering host page(s) to i686_vm32_union_prot, and immediately re-widened
 * before returning. No host page is ever left permanently open.
 */

#include <setjmp.h>
#include <stdint.h>
#include <string.h>

#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"
#include "vm/vm32.h"
#include "vm/vm_file.h"
#include "x86/decode.h"

extern int i686_fault_region_prot(const i686_ctx_t *ctx, uint32_t ga,
                                  uint32_t *out_prot, uint32_t *out_flags);
extern void i686_fault_arm(sigjmp_buf *jb);
extern void i686_fault_disarm(void);
extern sigjmp_buf *i686_fault_save(void);
extern uint64_t i686_fault_addr(void);
#ifndef I686RT_NO_DBT
extern void i686_dbt_invalidate_range(i686_ctx_t *ctx, uint32_t start,
                                      uint32_t end);
#endif

typedef struct {
    uint32_t va;
    uint32_t len;
    uint8_t  need;
} subpage_span_t;

typedef struct {
    subpage_span_t spans[4];
    unsigned       count;
    int            is_rep_str;
    uint32_t       str_unit;
    int            str_has_esi;
    int            str_has_edi;
    uint8_t        str_edi_need;
} subpage_access_t;

int i686_subpage_range_ok(const i686_ctx_t *ctx, uint32_t start_va,
                          uint64_t byte_len, uint8_t need_prot);
int i686_subpage_range_ok(const i686_ctx_t *ctx, uint32_t start_va,
                          uint64_t byte_len, uint8_t need_prot)
{
    uint64_t first_off;
    uint64_t pages;
    uint64_t k;

    if (ctx == NULL) {
        return 0;
    }
    if (byte_len == 0u) {
        return 1;
    }
    first_off = (uint64_t)(start_va & 0xFFFu);
    pages = (first_off + byte_len + 0xFFFu) >> 12;
    if (pages > (1ULL << 20)) {
        pages = (1ULL << 20);
    }
    for (k = 0u; k < pages; k++) {
        uint32_t sub = (start_va & ~0xFFFu) + (uint32_t)(k << 12);
        uint32_t rprot = 0u;
        uint8_t mprot;
        if (i686_fault_region_prot(ctx, sub, &rprot, NULL) == 0) {
            return 0;
        }
        if (((uint8_t)rprot & need_prot) != need_prot) {
            return 0;
        }
        mprot = (uint8_t)(i686_vm_file_prot(sub) & 0x03u);
        if ((mprot & need_prot) != need_prot) {
            return 0;
        }
    }
    return 1;
}

static void span_add(subpage_access_t *acc, uint32_t va, uint32_t len,
                     uint8_t need)
{
    if (len != 0u && acc->count < 4u) {
        acc->spans[acc->count].va = va;
        acc->spans[acc->count].len = len;
        acc->spans[acc->count].need = need;
        acc->count++;
    }
}

static int span_touches_page(const subpage_span_t *s, uint32_t page_va)
{
    uint64_t first_off = (uint64_t)(s->va & 0xFFFu);
    uint64_t pages = (first_off + (uint64_t)s->len + 0xFFFu) >> 12;
    uint64_t k;
    for (k = 0u; k < pages; k++) {
        uint32_t sub = (s->va & ~0xFFFu) + (uint32_t)(k << 12);
        if (sub == (page_va & ~0xFFFu)) {
            return 1;
        }
    }
    return 0;
}

/* Safely decode the instruction at ctx->eip, temporarily opening the
 * covering host page(s) under the subpage lock if the code sub-page is
 * readable in the mirror but its host cover is widened shut.
 * An inner sigsetjmp guard ensures any decode fault restores widened
 * pages and releases the subpage lock (I686-R2-3). */
static int safe_decode_eip(i686_ctx_t *ctx, x86_insn_t *out,
                           uint8_t out_bytes[16])
{
    uint32_t fetch_va = ctx->seg_base[I686_SEG_CS] + ctx->eip;
    uint32_t max_len = 15u;
    uint32_t hps = (ctx->vm_host_page != 0u) ? ctx->vm_host_page : 4096u;
    volatile int rc = -1;

    memset(out_bytes, 0, 16u);
    if (!i686_subpage_range_ok(ctx, fetch_va, 1u, 0x01u)) {
        return -1;
    }
    if (((fetch_va & 0xFFFu) + max_len) > 0x1000u &&
        !i686_subpage_range_ok(ctx, (fetch_va & ~0xFFFu) + 0x1000u, 1u, 0x01u)) {
        max_len = 0x1000u - (fetch_va & 0xFFFu);
    }
    if (ctx->vm_regime == I686_VM_REGIME_A2 && hps > 4096u) {
        uint32_t p0 = fetch_va & ~(hps - 1u);
        uint32_t p1 = (fetch_va + max_len - 1u) & ~(hps - 1u);
        sigjmp_buf *outer = i686_fault_save();
        sigjmp_buf inner;
        i686_vm32_subpage_lock();
        if (i686_vm32_union_prot(ctx, p0, p1 + hps) != 0) {
            i686_vm32_subpage_unlock();
            return -1;
        }
        if (sigsetjmp(inner, 1) != 0) {
            if (outer != NULL) {
                i686_fault_arm(outer);
            } else {
                i686_fault_disarm();
            }
            (void)i686_vm32_widen_prot(ctx, p0, p1 + hps);
            i686_vm32_subpage_unlock();
            return -1;
        }
        i686_fault_arm(&inner);
        rc = x86_decode(ctx, ctx->eip, out);
        if (rc == 0 && out->len > 0u && out->len <= max_len) {
            uint32_t k;
            for (k = 0u; k < out->len && k < 15u; k++) {
                out_bytes[k] =
                    *(const uint8_t *)i686_guest_ptr(ctx, fetch_va + k);
            }
        }
        if (outer != NULL) {
            i686_fault_arm(outer);
        } else {
            i686_fault_disarm();
        }
        (void)i686_vm32_widen_prot(ctx, p0, p1 + hps);
        i686_vm32_subpage_unlock();
    } else {
        sigjmp_buf *outer = i686_fault_save();
        sigjmp_buf inner;
        if (sigsetjmp(inner, 1) != 0) {
            if (outer != NULL) {
                i686_fault_arm(outer);
            } else {
                i686_fault_disarm();
            }
            return -1;
        }
        i686_fault_arm(&inner);
        rc = x86_decode(ctx, ctx->eip, out);
        if (rc == 0 && out->len > 0u && out->len <= max_len) {
            uint32_t k;
            for (k = 0u; k < out->len && k < 15u; k++) {
                out_bytes[k] =
                    *(const uint8_t *)i686_guest_ptr(ctx, fetch_va + k);
            }
        }
        if (outer != NULL) {
            i686_fault_arm(outer);
        } else {
            i686_fault_disarm();
        }
    }
    if (rc != 0 || out->len == 0u || out->len > max_len) {
        return -1;
    }
    if (!i686_subpage_range_ok(ctx, fetch_va, out->len, 0x01u)) {
        return -1;
    }
    return 0;
}

static void classify_sse_x87_modrm(const x86_insn_t *insn,
                                   const uint8_t insn_bytes[16],
                                   uint32_t ea, uint32_t op_bytes,
                                   subpage_access_t *acc)
{
    uint16_t op = insn->op;
    /* x87 memory ops */
    if (op == I686_OP_FLDCW || op == I686_OP_FILD_m16) {
        span_add(acc, ea, 2u, 0x01u);
        return;
    }
    if (op == I686_OP_FNSTCW || op == I686_OP_FNSTSW_m16 ||
        op == I686_OP_FIST_m16 || op == I686_OP_FISTP_m16 ||
        op == I686_OP_FISTTP_m16) {
        span_add(acc, ea, 2u, 0x02u);
        return;
    }
    if ((op >= I686_OP_FADD_m32 && op <= I686_OP_FDIVR_m32) ||
        op == I686_OP_FLD_m32 || op == I686_OP_FILD_m32) {
        span_add(acc, ea, 4u, 0x01u);
        return;
    }
    if (op == I686_OP_FST_m32 || op == I686_OP_FSTP_m32 ||
        op == I686_OP_FIST_m32 || op == I686_OP_FISTP_m32 ||
        op == I686_OP_FISTTP_m32) {
        span_add(acc, ea, 4u, 0x02u);
        return;
    }
    if ((op >= I686_OP_FADD_m64 && op <= I686_OP_FDIVR_m64) ||
        op == I686_OP_FLD_m64 || op == I686_OP_FILD_m64) {
        span_add(acc, ea, 8u, 0x01u);
        return;
    }
    if (op == I686_OP_FST_m64 || op == I686_OP_FSTP_m64 ||
        op == I686_OP_FISTP_m64 || op == I686_OP_FISTTP_m64) {
        span_add(acc, ea, 8u, 0x02u);
        return;
    }
    if (op == I686_OP_FLD_m80) {
        span_add(acc, ea, 10u, 0x01u);
        return;
    }
    if (op == I686_OP_FSTP_m80) {
        span_add(acc, ea, 10u, 0x02u);
        return;
    }
    if (op == I686_OP_FLDENV) {
        span_add(acc, ea, 28u, 0x01u);
        return;
    }
    if (op == I686_OP_FNSTENV) {
        span_add(acc, ea, 28u, 0x02u);
        return;
    }
    if (op == I686_OP_FUCOM) { /* DD /4 memory form is FRSTOR m108 */
        span_add(acc, ea, 108u, 0x01u);
        return;
    }
    if (op == I686_OP_FNSAVE) {
        span_add(acc, ea, 108u, 0x02u);
        return;
    }
    if (op == I686_OP_FXRSTOR) {
        span_add(acc, ea, 512u, 0x01u);
        return;
    }
    if (op == I686_OP_FXSAVE) {
        span_add(acc, ea, 512u, 0x02u);
        return;
    }
    if (op == I686_OP_CMPXCHG8B) {
        span_add(acc, ea, 8u, 0x03u);
        return;
    }
    if (op == I686_OP7_LES || op == I686_OP7_LDS ||
        op == I686_OP7_LSS || op == I686_OP7_LFS ||
        op == I686_OP7_LGS) {
        span_add(acc, ea, op_bytes + 2u, 0x01u);
        return;
    }
    /* SSE / MMX memory ops */
    if (op == I686_OP_PREFETCH || op == I686_OP_SFENCE || op == I686_OP_EMMS) {
        return;
    }
    if (op == I686_OP_LDMXCSR) {
        span_add(acc, ea, 4u, 0x01u);
        return;
    }
    if (op == I686_OP_STMXCSR) {
        span_add(acc, ea, 4u, 0x02u);
        return;
    }
    if ((op >= I686_OP_MOVUPS && op <= I686_OP_PMOVMSKB) ||
        (op >= I686_OP7_UNPCKLPS && op <= I686_OP7_SHUFPS)) {
        /* Determine SSE/MMX store vs load and width. */
        uint32_t w = 16u;
        uint8_t need = 0x01u;
        /* Inspect the opcode byte after 0x0F from the captured insn_bytes. */
        uint32_t b_idx;
        uint8_t op_byte = 0u;
        for (b_idx = 0u; b_idx + 1u < insn->len && b_idx + 1u < 16u; b_idx++) {
            uint8_t b = insn_bytes[b_idx];
            if (b == 0x0Fu) {
                op_byte = insn_bytes[b_idx + 1u];
                break;
            }
        }
        if (op_byte == 0x11u || op_byte == 0x13u || op_byte == 0x17u ||
            op_byte == 0x29u || op_byte == 0x7Eu || op_byte == 0x7Fu ||
            op_byte == 0xD6u || op_byte == 0xE7u) {
            need = 0x02u;
        }
        if (op == I686_OP_UCOMISS || op == I686_OP_COMISS) {
            w = (insn->pfx_opsize != 0u) ? 8u : 4u;
        } else if (insn->pfx_rep == 1u) { /* F3 */
            /* R7-1: packed F3 converts/shuffles read whole vectors —
             * CVTTPS2DQ (0x5B) reads m128 and the PSHUFHW handler
             * fetches 16 bytes; the rest are scalar dwords. */
            if (op == I686_OP_MOVQ_xmm || op == I686_OP_MOVDQA) {
                w = (op_byte == 0x7Eu) ? 8u : 16u;
            } else if (op_byte == 0x5Bu || op_byte == 0x70u) {
                w = 16u;
            } else {
                w = 4u;
            }
        } else if (insn->pfx_rep == 2u) { /* F2 */
            /* R7-1: the old ternary was a tautology (always 8).
             * PSHUFLW (0x70) fetches 16 bytes in its handler and
             * 0x5B has no F2 form (executes the 16-byte plain path). */
            if (op_byte == 0x70u || op_byte == 0x5Bu) {
                w = 16u;
            } else {
                w = 8u;
            }
        } else if (op == I686_OP_MOVLPS || op == I686_OP_MOVHPS ||
                   op == I686_OP_MOVQ2DQ || op == I686_OP_CVTPI2PS ||
                   (op == I686_OP_CVTPS2PD && insn->pfx_opsize == 0u)) {
            w = 8u;
        } else if (op == I686_OP_MOVQ_xmm) {
            w = 4u; /* 0F 6E / 0F 7E MOVD */
        } else if (insn->pfx_opsize == 0u &&
                   (op == I686_OP_MOVDQA || op == I686_OP_MOVNTDQ ||
                    op == I686_OP_PSHUFW ||
                    (op >= I686_OP_PUNPCKLBW && op <= I686_OP_PUNPCKHDQ) ||
                    (op >= I686_OP_PCMPGTB && op <= I686_OP_PSUBB) ||
                    op == I686_OP7_PACKUSWB)) {
            w = (op >= I686_OP_PUNPCKLBW && op <= I686_OP_PUNPCKLDQ) ? 4u : 8u;
        }
        span_add(acc, ea, w, need);
    }
}

static int build_insn_access(i686_ctx_t *ctx, const x86_insn_t *insn,
                             const uint8_t insn_bytes[16],
                             subpage_access_t *acc)
{
    uint32_t op_bytes = (insn->pfx_opsize != 0u) ? 2u : 4u;
    uint32_t ss = ctx->seg_base[I686_SEG_SS];
    uint32_t esp = ctx->gpr[I686_REG_ESP];
    uint16_t op = insn->op;

    memset(acc, 0, sizeof(*acc));
    span_add(acc, ctx->seg_base[I686_SEG_CS] + ctx->eip, insn->len, 0x01u);

    if (op == I686_OP_LEA_GvM) {
        return 0;
    }

    /* 1. String instructions */
    switch (op) {
    case I686_OP_MOVSb: case I686_OP_MOVSw:
    case I686_OP_CMPSb: case I686_OP_CMPSw:
    case I686_OP_STOSb: case I686_OP_STOSw:
    case I686_OP_LODSb: case I686_OP_LODSw:
    case I686_OP_SCASb: case I686_OP_SCASw: {
        uint32_t unit = (op == I686_OP_MOVSb || op == I686_OP_CMPSb ||
                         op == I686_OP_STOSb || op == I686_OP_LODSb ||
                         op == I686_OP_SCASb) ? 1u : op_bytes;
        uint32_t count = (insn->pfx_rep != 0u)
                             ? (insn->pfx_addrsize != 0u
                                    ? (ctx->gpr[I686_REG_ECX] & 0xFFFFu)
                                    : ctx->gpr[I686_REG_ECX])
                             : 1u;
        uint32_t esi_off = (insn->pfx_addrsize != 0u)
                               ? (ctx->gpr[I686_REG_ESI] & 0xFFFFu)
                               : ctx->gpr[I686_REG_ESI];
        uint32_t edi_off = (insn->pfx_addrsize != 0u)
                               ? (ctx->gpr[I686_REG_EDI] & 0xFFFFu)
                               : ctx->gpr[I686_REG_EDI];
        uint8_t src_seg = (insn->pfx_seg != 0xFFu) ? insn->pfx_seg : I686_SEG_DS;
        uint32_t src_va = ctx->seg_base[src_seg] + esi_off;
        uint32_t dst_va = ctx->seg_base[I686_SEG_ES] + edi_off;
        if (count == 0u) {
            return 0;
        }
        acc->is_rep_str = (insn->pfx_rep != 0u && count > 1u) ? 1 : 0;
        acc->str_unit = unit;
        if (op != I686_OP_STOSb && op != I686_OP_STOSw &&
            op != I686_OP_SCASb && op != I686_OP_SCASw) {
            acc->str_has_esi = 1;
            span_add(acc, src_va, unit, 0x01u);
        }
        if (op != I686_OP_LODSb && op != I686_OP_LODSw) {
            acc->str_has_edi = 1;
            acc->str_edi_need = (op == I686_OP_MOVSb || op == I686_OP_MOVSw ||
                                 op == I686_OP_STOSb || op == I686_OP_STOSw)
                                    ? 0x02u
                                    : 0x01u;
            span_add(acc, dst_va, unit, acc->str_edi_need);
        }
        return 0;
    }
    default:
        break;
    }

    /* 2. Direct moffs and XLAT */
    if (op >= I686_OP_MOV_ALOb && op <= I686_OP_MOV_OveAX) {
        uint8_t seg = (insn->pfx_seg != 0xFFu) ? insn->pfx_seg : I686_SEG_DS;
        uint32_t va = ctx->seg_base[seg] + insn->ea_disp;
        uint32_t w = (op == I686_OP_MOV_ALOb || op == I686_OP_MOV_ObAL)
                         ? 1u
                         : op_bytes;
        uint8_t need = (op == I686_OP_MOV_ALOb || op == I686_OP_MOV_eAXOv)
                           ? 0x01u
                           : 0x02u;
        span_add(acc, va, w, need);
        return 0;
    }
    if (op == I686_OP_XLAT) {
        uint8_t seg = (insn->pfx_seg != 0xFFu) ? insn->pfx_seg : I686_SEG_DS;
        uint32_t base = (insn->pfx_addrsize != 0u)
                            ? (ctx->gpr[I686_REG_EBX] & 0xFFFFu)
                            : ctx->gpr[I686_REG_EBX];
        uint32_t va = ctx->seg_base[seg] + base + (ctx->gpr[I686_REG_EAX] & 0xFFu);
        span_add(acc, va, 1u, 0x01u);
        return 0;
    }

    /* 3. Stack instructions */
    switch (op) {
    case I686_OP_PUSH_Gv:
    case I686_OP_PUSH_Iz:
    case I686_OP_PUSH_Ib:
    case I686_OP_PUSHF:
    case I686_OP_PUSH_ES:
    case I686_OP_PUSH_DS:
    case I686_OP_PUSH_FS:
    case I686_OP_PUSH_GS:
    case I686_OP_CALL_Jz:
        span_add(acc, ss + esp - op_bytes, op_bytes, 0x02u);
        return 0;
    case I686_OP7_CALLF:
        span_add(acc, ss + esp - 2u * op_bytes, 2u * op_bytes, 0x02u);
        return 0;
    case I686_OP_PUSHA:
        span_add(acc, ss + esp - 8u * op_bytes, 8u * op_bytes, 0x02u);
        return 0;
    case I686_OP_POP_Gv:
    case I686_OP_POPF:
    case I686_OP_POP_ES:
    case I686_OP_POP_DS:
    case I686_OP_POP_FS:
    case I686_OP_POP_GS:
    case I686_OP7_POP_SS:
    case I686_OP_RET:
    case I686_OP_RET_Iw:
        span_add(acc, ss + esp, op_bytes, 0x01u);
        return 0;
    case I686_OP7_RETF:
        span_add(acc, ss + esp, 2u * op_bytes, 0x01u);
        return 0;
    case I686_OP_IRET:
        span_add(acc, ss + esp, 3u * op_bytes, 0x01u);
        return 0;
    case I686_OP_POPA:
        span_add(acc, ss + esp, 8u * op_bytes, 0x01u);
        return 0;
    case I686_OP_LEAVE:
        span_add(acc, ss + ctx->gpr[I686_REG_EBP], op_bytes, 0x01u);
        return 0;
    case I686_OP_ENTER: {
        uint32_t level = (insn->imm >> 16) & 0x1Fu;
        uint32_t pushes = (level > 0u) ? (level + 1u) : 1u;
        span_add(acc, ss + esp - pushes * op_bytes, pushes * op_bytes, 0x02u);
        if (level > 1u) {
            span_add(acc, ss + ctx->gpr[I686_REG_EBP] - (level - 1u) * op_bytes,
                     (level - 1u) * op_bytes, 0x01u);
        }
        return 0;
    }
    case I686_OP_PUSH_Ev:
    case I686_OP_CALL_Ev:
        span_add(acc, ss + esp - op_bytes, op_bytes, 0x02u);
        if (insn->has_modrm && insn->modrm_mod != 3u) {
            span_add(acc, x86_ea_compute(ctx, insn), op_bytes, 0x01u);
        }
        return 0;
    case I686_OP_POP_Ev:
        span_add(acc, ss + esp, op_bytes, 0x01u);
        if (insn->has_modrm && insn->modrm_mod != 3u) {
            uint32_t ea;
            ctx->gpr[I686_REG_ESP] = esp + op_bytes;
            ea = x86_ea_compute(ctx, insn);
            ctx->gpr[I686_REG_ESP] = esp;
            span_add(acc, ea, op_bytes, 0x02u);
        }
        return 0;
    default:
        break;
    }

    /* 4. ModRM memory instructions */
    if (insn->has_modrm && insn->modrm_mod != 3u) {
        uint32_t ea = x86_ea_compute(ctx, insn);
        uint32_t w = 0u;
        uint8_t need = 0u;
        int i;

        for (i = 0; i < 3; i++) {
            unsigned k = insn->opnd[i];
            uint32_t kw = 0u;
            if (k == I686_OPND_RM8) {
                kw = 1u;
            } else if (k == I686_OPND_RM16) {
                kw = 2u;
            } else if (k == I686_OPND_RM32) {
                kw = op_bytes;
            } else if (k == I686_OPND_M1616) {
                kw = op_bytes + 2u;
            }
            if (kw == 0u) {
                continue;
            }
            w = kw;
            if (i == 0) {
                if (op == I686_OP_CMP_EbGb || op == I686_OP_CMP_EvGv ||
                    op == I686_OP_CMP_EbIb || op == I686_OP_CMP_EvIz ||
                    op == I686_OP_CMP_EvIbSX || op == I686_OP_TEST_EbGb ||
                    op == I686_OP_TEST_EvGv || op == I686_OP_TEST_EbIb ||
                    op == I686_OP_TEST_EvIz || op == I686_OP_BT_EvGv ||
                    op == I686_OP_BT_EvIb || op == I686_OP_JMP_Ev ||
                    (op >= I686_OP_MUL_Eb && op <= I686_OP_IDIV_Ev)) {
                    need |= 0x01u;
                } else if (op == I686_OP_MOV_EbGb || op == I686_OP_MOV_EvGv ||
                           op == I686_OP_MOV_EbIb || op == I686_OP_MOV_EvIz ||
                           op == I686_OP_MOV_EwSw || op == I686_OP_SETcc_Eb) {
                    need |= 0x02u;
                } else {
                    need |= 0x03u; /* RMW */
                }
            } else {
                need |= 0x01u;
            }
        }
        if (op == I686_OP_BT_EvGv || op == I686_OP_BTS_EvGv ||
            op == I686_OP_BTR_EvGv || op == I686_OP_BTC_EvGv) {
            int32_t bit_off = (insn->pfx_opsize != 0u)
                                  ? (int32_t)(int16_t)x86_reg_read(ctx, insn->modrm_reg, 16u)
                                  : (int32_t)x86_reg_read(ctx, insn->modrm_reg, 32u);
            if (insn->pfx_opsize != 0u) {
                ea += (uint32_t)((bit_off >> 4) * 2);
            } else {
                ea += (uint32_t)((bit_off >> 5) * 4);
            }
        }
        if (w != 0u && need != 0u && op < I686_OP_MOVUPS) {
            span_add(acc, ea, w, need);
            return 0;
        }
        classify_sse_x87_modrm(insn, insn_bytes, ea, op_bytes, acc);
    }
    return 0;
}

int i686_spurious_allow(i686_ctx_t *ctx, uint32_t ga)
{
    x86_insn_t insn;
    uint8_t insn_bytes[16];
    subpage_access_t acc;
    unsigned i;
    int matched = 0;

    if (ctx == NULL) {
        return 0;
    }
    if (i686_fault_region_prot(ctx, ga, NULL, NULL) == 0 ||
        (i686_vm_file_prot(ga & ~0xFFFu) & 0x03u) == 0u) {
        return 0;
    }
    if (safe_decode_eip(ctx, &insn, insn_bytes) != 0) {
        return 0;
    }
    (void)build_insn_access(ctx, &insn, insn_bytes, &acc);
    for (i = 0u; i < acc.count; i++) {
        if (!i686_subpage_range_ok(ctx, acc.spans[i].va, acc.spans[i].len,
                                   acc.spans[i].need)) {
            return 0;
        }
        if (span_touches_page(&acc.spans[i], ga)) {
            matched = 1;
        }
    }
    return matched;
}

/* Open the host covers of every validated span in acc. */
static int open_acc_covers(i686_ctx_t *ctx, const subpage_access_t *acc,
                           uint32_t hps)
{
    unsigned i;
    for (i = 0u; i < acc->count; i++) {
        uint32_t start = acc->spans[i].va & ~(hps - 1u);
        uint32_t end = ((acc->spans[i].va + acc->spans[i].len - 1u) & ~(hps - 1u)) + hps;
        if (i686_vm32_union_prot(ctx, start, end) != 0) {
            return -1;
        }
    }
    return 0;
}

static void widen_acc_covers(i686_ctx_t *ctx, const subpage_access_t *acc,
                             uint32_t hps)
{
    unsigned i;
    for (i = 0u; i < acc->count; i++) {
        uint32_t start = acc->spans[i].va & ~(hps - 1u);
        uint32_t end = ((acc->spans[i].va + acc->spans[i].len - 1u) & ~(hps - 1u)) + hps;
        (void)i686_vm32_widen_prot(ctx, start, end);
    }
}

/* Step a REP string instruction one element at a time under the subpage
 * lock so crossing into a restricted 4 KiB sub-page stops at the exact
 * offending element and delivers SIGSEGV without corrupting the neighbour. */
static int emulate_rep_string(i686_ctx_t *ctx, const x86_insn_t *insn,
                              const subpage_access_t *acc, uint32_t hps)
{
    uint32_t orig_eip = ctx->eip;
    uint32_t rem = (insn->pfx_addrsize != 0u)
                       ? (ctx->gpr[I686_REG_ECX] & 0xFFFFu)
                       : ctx->gpr[I686_REG_ECX];
    uint8_t src_seg = (insn->pfx_seg != 0xFFu) ? insn->pfx_seg : I686_SEG_DS;
    uint32_t fetch_p0 = (ctx->seg_base[I686_SEG_CS] + orig_eip) & ~(hps - 1u);
    uint32_t fetch_p1 = ((ctx->seg_base[I686_SEG_CS] + orig_eip + insn->len - 1u) &
                         ~(hps - 1u)) + hps;

    if (i686_vm32_union_prot(ctx, fetch_p0, fetch_p1) != 0) {
        return -1;
    }
    while (rem > 0u) {
        uint32_t esi_off = (insn->pfx_addrsize != 0u)
                               ? (ctx->gpr[I686_REG_ESI] & 0xFFFFu)
                               : ctx->gpr[I686_REG_ESI];
        uint32_t edi_off = (insn->pfx_addrsize != 0u)
                               ? (ctx->gpr[I686_REG_EDI] & 0xFFFFu)
                               : ctx->gpr[I686_REG_EDI];
        uint32_t src_va = ctx->seg_base[src_seg] + esi_off;
        uint32_t dst_va = ctx->seg_base[I686_SEG_ES] + edi_off;
        uint32_t s_p0 = src_va & ~(hps - 1u);
        uint32_t s_p1 = ((src_va + acc->str_unit - 1u) & ~(hps - 1u)) + hps;
        uint32_t d_p0 = dst_va & ~(hps - 1u);
        uint32_t d_p1 = ((dst_va + acc->str_unit - 1u) & ~(hps - 1u)) + hps;
        sigjmp_buf *outer;
        sigjmp_buf inner;
        int ir;

        if (acc->str_has_esi &&
            !i686_subpage_range_ok(ctx, src_va, acc->str_unit, 0x01u)) {
            uint32_t b;
            for (b = 0u; b < acc->str_unit; b++) {
                if (!i686_subpage_range_ok(ctx, src_va + b, 1u, 0x01u)) {
                    ctx->fault_addr = src_va + b;
                    break;
                }
            }
            (void)i686_vm32_widen_prot(ctx, fetch_p0, fetch_p1);
            return -1;
        }
        if (acc->str_has_edi &&
            !i686_subpage_range_ok(ctx, dst_va, acc->str_unit, acc->str_edi_need)) {
            uint32_t b;
            for (b = 0u; b < acc->str_unit; b++) {
                if (!i686_subpage_range_ok(ctx, dst_va + b, 1u, acc->str_edi_need)) {
                    ctx->fault_addr = dst_va + b;
                    break;
                }
            }
            (void)i686_vm32_widen_prot(ctx, fetch_p0, fetch_p1);
            return -1;
        }
        if (acc->str_has_esi && i686_vm32_union_prot(ctx, s_p0, s_p1) != 0) {
            (void)i686_vm32_widen_prot(ctx, fetch_p0, fetch_p1);
            return -1;
        }
        if (acc->str_has_edi && i686_vm32_union_prot(ctx, d_p0, d_p1) != 0) {
            if (acc->str_has_esi) {
                (void)i686_vm32_widen_prot(ctx, s_p0, s_p1);
            }
            (void)i686_vm32_widen_prot(ctx, fetch_p0, fetch_p1);
            return -1;
        }
        if (insn->pfx_addrsize != 0u) {
            ctx->gpr[I686_REG_ECX] = (ctx->gpr[I686_REG_ECX] & 0xFFFF0000u) | 1u;
        } else {
            ctx->gpr[I686_REG_ECX] = 1u;
        }
        ctx->eip = orig_eip;
        outer = i686_fault_save();
        if (sigsetjmp(inner, 1) != 0) {
            if (outer != NULL) {
                i686_fault_arm(outer);
            } else {
                i686_fault_disarm();
            }
            if (insn->pfx_addrsize != 0u) {
                ctx->gpr[I686_REG_ECX] =
                    (ctx->gpr[I686_REG_ECX] & 0xFFFF0000u) | (rem & 0xFFFFu);
            } else {
                ctx->gpr[I686_REG_ECX] = rem;
            }
            if (acc->str_has_edi) {
                (void)i686_vm32_widen_prot(ctx, d_p0, d_p1);
            }
            if (acc->str_has_esi) {
                (void)i686_vm32_widen_prot(ctx, s_p0, s_p1);
            }
            (void)i686_vm32_widen_prot(ctx, fetch_p0, fetch_p1);
            return -1;
        }
        i686_fault_arm(&inner);
        ir = i686_interp_step(ctx);
        if (outer != NULL) {
            i686_fault_arm(outer);
        } else {
            i686_fault_disarm();
        }
        if (acc->str_has_edi && (acc->str_edi_need & 0x02u) != 0u) {
            /* Emulated store commit (I686-R9-6): divert the MAP_PRIVATE
             * file page before a later pwrite can refresh it. */
            (void)i686_vm_file_promote_cow(dst_va, acc->str_unit);
#ifndef I686RT_NO_DBT
            i686_dbt_invalidate_range(ctx, dst_va, dst_va + acc->str_unit);
#endif
        }
        if (acc->str_has_edi) {
            (void)i686_vm32_widen_prot(ctx, d_p0, d_p1);
        }
        if (acc->str_has_esi) {
            (void)i686_vm32_widen_prot(ctx, s_p0, s_p1);
        }
        rem--;
        if (insn->pfx_addrsize != 0u) {
            ctx->gpr[I686_REG_ECX] = (ctx->gpr[I686_REG_ECX] & 0xFFFF0000u) |
                                     (rem & 0xFFFFu);
        } else {
            ctx->gpr[I686_REG_ECX] = rem;
        }
        if (ir != I686_INTERP_CONTINUE) {
            (void)i686_vm32_widen_prot(ctx, fetch_p0, fetch_p1);
            return -1;
        }
        if (insn->op == I686_OP_CMPSb || insn->op == I686_OP_CMPSw ||
            insn->op == I686_OP_SCASb || insn->op == I686_OP_SCASw) {
            uint32_t fl = i686_flags_read(ctx);
            int zf = (fl & I686_EF_ZF) != 0u;
            if ((insn->pfx_rep == 1u && !zf) || (insn->pfx_rep == 2u && zf)) {
                break;
            }
        }
    }
    (void)i686_vm32_widen_prot(ctx, fetch_p0, fetch_p1);
    return 0;
}

int i686_spurious_emulate(i686_ctx_t *ctx, uint32_t ga)
{
    x86_insn_t insn;
    uint8_t insn_bytes[16];
    subpage_access_t acc;
    uint32_t hps;
    unsigned i;
    int matched = 0;
    int ir;

    if (ctx == NULL || ctx->vm_regime != I686_VM_REGIME_A2 ||
        ctx->vm_host_page <= 4096u) {
        return -1;
    }
    if (i686_fault_region_prot(ctx, ga, NULL, NULL) == 0 ||
        (i686_vm_file_prot(ga & ~0xFFFu) & 0x03u) == 0u) {
        return -1;
    }
    if (safe_decode_eip(ctx, &insn, insn_bytes) != 0) {
        return -1;
    }
    (void)build_insn_access(ctx, &insn, insn_bytes, &acc);
    for (i = 0u; i < acc.count; i++) {
        if (!i686_subpage_range_ok(ctx, acc.spans[i].va, acc.spans[i].len,
                                   acc.spans[i].need)) {
            return -1;
        }
        if (span_touches_page(&acc.spans[i], ga)) {
            matched = 1;
        }
    }
    if (!matched) {
        return -1;
    }
    if (insn.op == I686_OP_SYSENTER ||
        (insn.op == I686_OP_INT_Ib && (uint8_t)insn.imm == 0x80u)) {
        extern long i686_handle_syscall(i686_ctx_t *);
        extern int i686_syscall_is_exit(long);
        long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
        long rv;
        ctx->eip += insn.len;
        ctx->exit_arg = 0x80u;
        ctx->blocks_executed++;
        rv = i686_handle_syscall(ctx);
        if (i686_syscall_is_exit(nr)) {
            ctx->exit_reason = I686_EXIT_SYSCALL;
            ctx->exit_arg = (uint32_t)rv;
        }
        return 0;
    }
    hps = ctx->vm_host_page;
    i686_vm32_subpage_lock();
    if (acc.is_rep_str) {
        int rc = emulate_rep_string(ctx, &insn, &acc, hps);
        i686_vm32_subpage_unlock();
        return rc;
    }
    if (open_acc_covers(ctx, &acc, hps) != 0) {
        widen_acc_covers(ctx, &acc, hps);
        i686_vm32_subpage_unlock();
        return -1;
    }
    {
        sigjmp_buf *outer = i686_fault_save();
        sigjmp_buf inner;
        if (sigsetjmp(inner, 1) != 0) {
            widen_acc_covers(ctx, &acc, hps);
            i686_vm32_subpage_unlock();
            if (outer != NULL) {
                i686_fault_arm(outer);
                siglongjmp(*outer, 1);
            }
            i686_fault_disarm();
            return -1;
        }
        i686_fault_arm(&inner);
        ir = i686_interp_step(ctx);
        if (outer != NULL) {
            i686_fault_arm(outer);
        } else {
            i686_fault_disarm();
        }
    }
    if (ir == I686_INTERP_CONTINUE) {
        for (i = 0u; i < acc.count; i++) {
            if ((acc.spans[i].need & 0x02u) != 0u) {
                /* Emulated store commit (I686-R9-6). */
                (void)i686_vm_file_promote_cow(acc.spans[i].va,
                                               acc.spans[i].len);
#ifndef I686RT_NO_DBT
                i686_dbt_invalidate_range(ctx, acc.spans[i].va,
                                          acc.spans[i].va + acc.spans[i].len);
#endif
            }
        }
    }
    widen_acc_covers(ctx, &acc, hps);
    i686_vm32_subpage_unlock();
    return (ir == I686_INTERP_CONTINUE) ? 0 : -1;
}
