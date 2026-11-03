/*
 * src/interp/seg.c — descriptor model: LDT/GDT lookup, segment loads,
 * flat defaults (Phase 7 card L7a; SPEC D8, §4 7.1/7.2; E09 verdict)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the frozen src/interp/seg.h contract:
 *   - per-process shadow LDT (8192 decoded descriptors, entries 0..31
 *     pre-reserved per the E09 Wine policy) + three GDT TLS slots,
 *   - selector decode (null / GDT flat aliases + TLS / LDT) and
 *     validated segment-register loads (mov/pop/les..lss/far transfers),
 *   - the D8 engine predicate i686_seg_flat_cs,
 *   - data-limit enforcement for LDT selectors along the decode.c EA
 *     path, and
 *   - the sigcontext segment round-trip helpers.
 *
 * Flat-process compatibility (Phase 1-6 behaviour is unchanged): GDT
 * selectors behave exactly as the v1 stubs did — CS/SS/DS/ES flat with
 * base 0, FS/GS resolving GDT TLS entries 6..8 from ctx->gdt_tls_slots
 * (written by set_thread_area/CLONE_SETTLS), everything else base 0 —
 * and limit enforcement applies ONLY to LDT (TI=1) selectors, so DBT-
 * eligible flat code never takes a descriptor walk on its data path.
 *
 * Faults use the sync fault channel: handlers (and the decode.c limit
 * check) set ctx->exit_arg = trapno (13 #GP / 11 #NP / 12 #SS) and
 * return I686_EXIT_FAULT; the interpreter loop's i686_deliver_sync maps
 * any nonzero exit_arg to guest SIGSEGV with the guest IP at the
 * faulting instruction (resumable, E09).  The error code (selector
 * bits) rides ctx->exit_dest for the S7 delivery wiring; the current
 * signals_i386.c delivery writes sc.err = 0 until the coordinator wires
 * it through.
 */

#include <stdlib.h>
#include <string.h>

#include "i686rt.h"

/* seg.h (frozen) re-spells its FAULT codes over i686rt.h's segment-
 * register index macros: I686_SEG_SS is 3 (fault #SS) there vs 2U (the
 * SS register index) in i686rt.h.  The frozen headers cannot change:
 * pre-clear the macro so seg.h's #define is fresh (no redefinition
 * warning), then restore the register index and use collision-free
 * local names for the fault codes.  The exported functions still return
 * exactly the seg.h I686_SEG_* values. */
#undef I686_SEG_SS
#include "interp/seg.h"
#undef I686_SEG_SS
#define I686_SEG_SS 2u /* register index (i686rt.h contract) */
#define SEG_F_OK 0
#define SEG_F_GP 1
#define SEG_F_NP 2
#define SEG_F_SS 3

/* ------------------------------------------------------------------ */
/* State                                                               */
/* ------------------------------------------------------------------ */

void i686_seg_init(i686_ctx_t *ctx)
{
    i686_segstate_t *st;

    if (ctx->ldt != NULL) {
        return;
    }
    st = calloc(1U, sizeof(*st));
    if (st == NULL) {
        return; /* stays flat: LDT lookups fault #GP(0) via the NULL check */
    }
    st->ldt_bm[0] = 0xFFFFFFFFu; /* entries 0..31 reserved (E09 Wine policy) */
    st->gen = 1u;
    ctx->ldt = st;
    ctx->ldt_entries = I686_LDT_ENTRIES;
    ctx->cs_d = 1u; /* flat process default (phase-7.md freeze) */
    ctx->ss_b = 1u; /* R7-11: flat stack default follows SS */
}

/* Lazy state accessor: flat processes never pay for the descriptor
 * model until the first LDT/TLS selector is decoded.  Also the mount
 * point clone.c uses implicitly (ctx->ldt is copied verbatim: the
 * segstate is per-process, matching CLONE_VM sharing). */
static i686_segstate_t *seg_state(i686_ctx_t *ctx)
{
    if (ctx->ldt == NULL) {
        i686_seg_init(ctx);
    }
    return (i686_segstate_t *)ctx->ldt;
}

/* ------------------------------------------------------------------ */
/* Selector decode                                                     */
/* ------------------------------------------------------------------ */

static void desc_flat_code(i686_desc_t *d)
{
    memset(d, 0, sizeof(*d));
    d->base = 0u;
    d->limit = 0xFFFFFFFFu;
    d->type = 0x1Bu; /* code, readable, accessed */
    d->dpl = 3u;
    d->d_bit = 1u;
    d->flags = I686_DESC_PRESENT;
}

static void desc_flat_data(i686_desc_t *d)
{
    memset(d, 0, sizeof(*d));
    d->base = 0u;
    d->limit = 0xFFFFFFFFu;
    d->type = 0x13u; /* data, read/write, accessed */
    d->dpl = 3u;
    d->d_bit = 1u;
    d->flags = I686_DESC_PRESENT;
}

/* R7-8: the null selector is index 0 with TI=0 (sel 0..3, RPL
 * ignored); loads into data regs succeed, use faults later, loads into
 * CS/SS fault now (enforced in seg_load). */
static unsigned is_null_sel(uint16_t sel)
{
    return (sel & 0xFFFCu) == 0u;
}

int i686_seg_lookup(const i686_ctx_t *ctx, uint16_t sel, i686_desc_t *out)
{
    uint32_t idx;

    if (out == NULL) {
        return SEG_F_GP;
    }
    memset(out, 0, sizeof(*out));
    if (is_null_sel(sel)) {
        return SEG_F_OK; /* null: zero descriptor, use faults later */
    }
    idx = (uint32_t)sel >> 3;

    if ((sel & 0x4u) != 0u) { /* TI = 1: LDT */
        const i686_segstate_t *st = seg_state((i686_ctx_t *)ctx);
        if (st == NULL) {
            return SEG_F_GP;
        }
        if (idx >= (uint32_t)I686_LDT_ENTRIES) {
            return SEG_F_GP; /* beyond table limit: #GP(sel) */
        }
        *out = st->ldt[idx];
        if ((out->flags & I686_DESC_PRESENT) == 0u) {
            return SEG_F_NP; /* freed / never written: #NP(sel), E09 */
        }
        return SEG_F_OK;
    }

    /* GDT: TLS slots 6..8 (Phase 4 contract: ctx->gdt_tls_slots[i] holds
     * the installed base, 0 = free), __USER_CS alias (0x23, idx 4),
     * flat data alias for every other nonzero index — v1 base-0
     * behaviour preserved exactly. */
    if (idx >= (uint32_t)I686_GDT_TLS_FIRST &&
        idx < (uint32_t)(I686_GDT_TLS_FIRST + I686_GDT_TLS_SLOTS)) {
        uint32_t slot = idx - (uint32_t)I686_GDT_TLS_FIRST;
        /* Per-thread descriptor first (kernel tls_array, RC7b T4b);
         * fall back to the v1 bare-base for slots installed before
         * the descriptor path existed. */
        {
            const i686_desc_t *ts =
                (const i686_desc_t *)(const void *)ctx->tls_desc[slot];

            if ((ts->flags & I686_DESC_PRESENT) != 0u) {
                *out = *ts;
                return SEG_F_OK;
            }
        }
        if (ctx->gdt_tls_slots[slot] == 0u) {
            return SEG_F_NP; /* free TLS slot */
        }
        out->base = ctx->gdt_tls_slots[slot];
        out->limit = 0xFFFFFFFFu;
        out->type = 0x13u;
        out->dpl = 3u;
        out->d_bit = 1u;
        out->flags = I686_DESC_PRESENT;
        return SEG_F_OK;
    }
    /* R7-8: only the known flat aliases exist (idx 4 = __USER_CS, idx 5
     * = flat data); any other nonzero GDT index is nonexistent -> #GP. */
    if (idx == 4u) {
        desc_flat_code(out);
    } else if (idx == 5u) {
        desc_flat_data(out);
    } else {
        return SEG_F_GP;
    }
    return SEG_F_OK;
}

/* ------------------------------------------------------------------ */
/* Segment-register loads                                              */
/* ------------------------------------------------------------------ */

/* CPL is always 3 (user mode); RPL rides the selector. */
#define SEG_CPL 3u

int i686_seg_load(i686_ctx_t *ctx, unsigned reg, uint16_t sel)
{
    i686_desc_t d;
    int f;
    uint32_t rpl = (uint32_t)sel & 3u;

    if (reg >= I686_SEG_COUNT) {
        return SEG_F_GP;
    }
    f = i686_seg_lookup(ctx, sel, &d);
    if (f != SEG_F_OK) {
        return f;
    }
    /* R7-8: a null selector never loads into CS/SS (#GP(0)); data
     * registers accept it and fault on use. */
    if (is_null_sel(sel)) {
        if (reg == I686_SEG_CS || reg == I686_SEG_SS) {
            return SEG_F_GP;
        }
    } else {
        bool code = ((d.type & 0x18u) == 0x18u);
        bool system = ((d.type & 0x10u) == 0u);

        if (system) {
            return SEG_F_GP; /* gates/TSS: no call gates in scope */
        }
        if (reg == I686_SEG_CS) {
            bool conforming = ((d.type & 0x04u) != 0u);
            if (!code) {
                return SEG_F_GP;
            }
            /* far transfer: non-conforming needs DPL == CPL == RPL;
             * conforming needs DPL <= CPL (SDM 5.8.1) */
            if (conforming) {
                if (d.dpl > SEG_CPL) {
                    return SEG_F_GP;
                }
            } else {
                if (d.dpl != SEG_CPL || rpl != SEG_CPL) {
                    return SEG_F_GP;
                }
            }
        } else if (reg == I686_SEG_SS) {
            /* writable data only, DPL == max(CPL, RPL) (SDM 5.8.2) */
            if (code || (d.type & 0x02u) == 0u) {
                return SEG_F_GP;
            }
            if (d.dpl != SEG_CPL || rpl != SEG_CPL) {
                return SEG_F_GP;
            }
        } else {
            /* data, or readable code loaded into a data register */
            if (code && (d.type & 0x02u) == 0u) {
                return SEG_F_GP; /* unreadable code */
            }
            if (d.dpl < SEG_CPL) {
                return SEG_F_GP; /* max(CPL,RPL)=3 > DPL */
            }
        }
    }

    ctx->seg_sel[reg] = sel;
    ctx->seg_base[reg] = is_null_sel(sel) ? 0u : d.base;
    if (reg == I686_SEG_CS) {
        ctx->cs_d = (d.d_bit != 0u) ? 1u : 0u; /* D8: default size follows CS */
    }
    if (reg == I686_SEG_SS) {
        ctx->ss_b = (d.d_bit != 0u) ? 1u : 0u; /* R7-11: stack size follows SS */
    }
    return SEG_F_OK;
}

/* exec resets the thread's TLS bookkeeping (kernel start_thread: the
 * new image's glibc auto-allocates GDT 6/7/8 again).  RC7b: without
 * this, the Nth exec exhausts the three slots -> set_thread_area
 * -ESRCH -> "Cannot allocate TLS block". */
void i686_seg_exec_reset_tls(i686_ctx_t *ctx)
{
    i686_segstate_t *st = (ctx->ldt != NULL) ? (i686_segstate_t *)ctx->ldt
                                            : NULL;
    unsigned i;

    for (i = 0U; i < 3U; i++) {
        ctx->gdt_tls_slots[i] = 0U;
        memset(ctx->tls_desc[i], 0, sizeof(ctx->tls_desc[i]));
        if (st != NULL) {
            st->gdt_used[i] = false;
        }
    }
    if (st != NULL) {
        st->gen++;
    }
}

bool i686_seg_flat_cs(const i686_ctx_t *ctx)
{
    /* 0x23 = __USER_CS alias installed at process start and execve;
     * anything else (LDT selector, other GDT) is D8 interpreter-only. */
    return ctx->seg_sel[I686_SEG_CS] == 0x23u;
}

/* R7-9: DBT eligibility covers every segment assumption the emitted code
 * bakes in (emitted accesses skip limit/null checks): flat CS (the
 * existing rule), GDT-only data selectors, non-null stack/data
 * selectors, and a 32-bit stack.  Anything else runs in the
 * interpreter until equivalent checks exist in emitted code. */
bool i686_seg_dbt_eligible(const i686_ctx_t *ctx)
{
    static const uint8_t regs[] = {
        I686_SEG_DS, I686_SEG_ES, I686_SEG_SS, I686_SEG_FS, I686_SEG_GS
    };
    unsigned i;

    if (!i686_seg_flat_cs(ctx)) {
        return false;
    }
    if (ctx->ss_b == 0u) {
        return false; /* R7-11: 16-bit stacks are interpreter-only */
    }
    for (i = 0u; i < sizeof(regs); i++) {
        i686_desc_t d;
        uint16_t sel = ctx->seg_sel[regs[i]];
        if ((sel & 0x4u) != 0u) {
            return false; /* LDT-limited: interpreter enforces limits */
        }
        /* R7-8: null uses fault and invalid selectors fail their next
         * use in the interpreter; emitted code checks neither. */
        if (is_null_sel(sel)) {
            return false;
        }
        if (i686_seg_lookup(ctx, sel, &d) != SEG_F_OK) {
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------ */
/* Data-limit enforcement (LDT selectors; decode.c EA path)            */
/* ------------------------------------------------------------------ */

/*
 * Raise the guest #GP(0) for a data-limit violation at linear address
 * `linear`.  The sync fault rides the interpreter's host-fault
 * checkpoint: ctx->exit_arg = trapno 13 survives the SIGSEGV resume
 * (the host path does not touch exit_arg), and touching the offending
 * guest address first gives si_addr == G + linear whenever that page is
 * PROT_NONE (the common case at a segment edge) so ctx->fault_addr --
 * and the sigcontext cr2 -- is the exact offending linear address.  If
 * the address happens to be mapped, the guaranteed second touch at
 * guest VA 0 (always PROT_NONE: mappings below the 64 KiB low guard are
 * refused) still delivers the resumable SIGSEGV, with cr2 degraded to 0.
 * Either way execution never returns: the interpreter resumes at the
 * guest handler with EIP at the faulting instruction.
 */
static void raise_seg_fault(i686_ctx_t *ctx, uint32_t linear, uint32_t trapno)
{
    ctx->exit_arg = trapno; /* nonzero -> deliver_sync: SIGSEGV */
    ctx->fault_addr = linear;
    ctx->exit_dest = 0u; /* error code 0 (SDM: limit violation = #GP(0)) */
    (void)*(volatile uint8_t *)i686_guest_ptr(ctx, linear);
    (void)*(volatile uint8_t *)i686_guest_ptr(ctx, 0u);
}

static void raise_limit_fault(i686_ctx_t *ctx, uint32_t linear)
{
    raise_seg_fault(ctx, linear, 13u); /* #GP trapno */
}

void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg, uint32_t linear,
                         unsigned bytes, unsigned write)
{
    uint16_t sel;
    i686_desc_t d;
    uint32_t off;

    if (seg >= I686_SEG_COUNT || bytes == 0u) {
        return;
    }
    sel = ctx->seg_sel[seg];
    if (is_null_sel(sel)) {
        raise_limit_fault(ctx, linear); /* R7-8: null use is #GP(0) */
        return;
    }
    if ((sel & 0x4u) == 0u) {
        return; /* GDT/flat: v1-compatible, never limit-checked (D8) */
    }
    {
        int f = i686_seg_lookup(ctx, sel, &d);
        if (f != SEG_F_OK) {
            /* Load-time validation normally covers this, but the blind
             * sigcontext reload can install an invalid selector, which
             * faults on its next use (R7-8) — #NP for not-present LDT
             * entries, #GP otherwise. */
            raise_seg_fault(ctx, linear, (f == SEG_F_NP) ? 11u : 13u);
            return;
        }
    }
    /* R7-9: writes need a writable data segment; code segments (even
     * readable ones loaded into data regs) never accept writes. */
    if (write != 0u) {
        if (((d.type & 0x08u) != 0u) || ((d.type & 0x02u) == 0u)) {
            raise_limit_fault(ctx, linear);
            return;
        }
    }
    off = linear - ctx->seg_base[seg];
    /* R7-10: expand-down is E set on a data descriptor (the stored type
     * folds in bit 0x10, so the old 0x18 mask never matched).  Valid
     * offsets are (limit, upper] with the upper bound from D/B, and the
     * whole access extent must fit. */
    if (((d.type & 0x08u) == 0u) && ((d.type & 0x04u) != 0u)) {
        uint32_t upper = (d.d_bit != 0u) ? 0xFFFFFFFFu : 0xFFFFu;
        uint64_t last = (uint64_t)off + (uint64_t)bytes - 1u;
        if (off <= d.limit || last > (uint64_t)upper) {
            raise_limit_fault(ctx, linear);
        }
        return;
    }
    if (d.limit < (uint32_t)(bytes - 1u) ||
        off > d.limit - (uint32_t)(bytes - 1u)) {
        raise_limit_fault(ctx, linear);
    }
}

/* R7-43: instruction-specific alignment (#GP(0) before any memory or
 * architectural-state side effect).  Aligned SIMD moves (MOVAPS,
 * MOVAPD, MOVDQA) and FXSAVE/FXRSTOR require 16-byte operands. */
void i686_seg_check_align(i686_ctx_t *ctx, uint32_t linear, unsigned align)
{
    if (align > 1u && (linear & (uint32_t)(align - 1u)) != 0u) {
        raise_seg_fault(ctx, linear, 13u); /* #GP(0) */
    }
}

/* ------------------------------------------------------------------ */
/* Sigcontext segment round-trip (wired into signals_i386.c at S7)     */
/* ------------------------------------------------------------------ */

void i686_seg_sc_encode(const i686_ctx_t *ctx, uint8_t out[12])
{
    static const uint8_t order[I686_SEG_COUNT] = {
        I686_SEG_GS, I686_SEG_FS, I686_SEG_ES,
        I686_SEG_DS, I686_SEG_CS, I686_SEG_SS
    };
    unsigned i;

    for (i = 0u; i < I686_SEG_COUNT; i++) {
        uint16_t sel = ctx->seg_sel[order[i]];
        out[2u * i] = (uint8_t)(sel & 0xFFu);
        out[2u * i + 1u] = (uint8_t)(sel >> 8);
    }
}

void i686_seg_sc_decode(i686_ctx_t *ctx, const uint8_t in[12])
{
    static const uint8_t order[I686_SEG_COUNT] = {
        I686_SEG_GS, I686_SEG_FS, I686_SEG_ES,
        I686_SEG_DS, I686_SEG_CS, I686_SEG_SS
    };
    unsigned i;

    for (i = 0u; i < I686_SEG_COUNT; i++) {
        uint16_t sel = (uint16_t)(in[2u * i] | ((uint16_t)in[2u * i + 1u] << 8));
        /* Kernel reloads blindly; an invalid selector never faults here
         * — it records with base 0 and (for LDT selectors) faults on
         * next use through the limit/lookup path. */
        if (i686_seg_load(ctx, order[i], sel) != SEG_F_OK) {
            ctx->seg_sel[order[i]] = sel;
            ctx->seg_base[order[i]] = 0u;
        }
    }
}
