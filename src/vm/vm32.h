/*
 * src/vm/vm32.h — Two-regime Class-A 32-bit VM interface (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4, section 4.6: Regime A1 (H == 4096, 1-insn
 * [x20, wAddr, uxtw] over a MAP_PRIVATE | MAP_ANONYMOUS 4 GiB window
 * [G, G + 4 GiB)) vs Regime A2 (H > 4096, 7-insn Soft-TLB with
 * x20 = &ctx->tlb[0] over a MAP_PRIVATE | MAP_ANONYMOUS 4 GiB arena
 * mapped with union host protections, never PROT_EXEC).
 *
 * Regime A2 preserves native fork() COW (fable C1), keeps in-place fixed
 * HVA = G + gva on PAGE_COW_CLEAN -> PAGE_COW_DIRTY promotion (fable C2),
 * and eliminates RELRO + .data SIGSEGV trap storms (fable M3): the host
 * 16 KiB page carries the union PROT_READ | PROT_WRITE while the RELRO
 * sub-page keeps write_tag == ~0ULL so stores trap in software.
 */

#ifndef I686RT_VM_VM32_H
#define I686RT_VM_VM32_H

#include <stddef.h>
#include <stdint.h>

#include "i686rt.h"

/* Soft-TLB geometry: 4096 entries x 32 bytes = 128 KiB per thread. */
#define I686_TLB_BITS 12u
#define I686_TLB_SIZE (1u << I686_TLB_BITS)
#define I686_TLB_INVALID_TAG (~UINT64_C(0))

/* Guest ABI page granule (4 KiB; Class-A i686, UNIFICATION-PLAN 4.2). */
#define I686_GUEST_PAGE_SIZE 4096u
#define I686_GUEST_PAGE_MASK 0xFFFu

/* Per-sub-page backing state (Provider A, UNIFICATION-PLAN 5.1). */
typedef enum {
    I686_PAGE_ANON = 0,      /* private anonymous, fully writable when prot allows */
    I686_PAGE_COW_CLEAN = 1, /* MAP_PRIVATE file image, not yet dirtied (write_tag off) */
    I686_PAGE_COW_DIRTY = 2, /* promoted in place at the same HVA (write_tag on) */
    I686_PAGE_SHARED = 3     /* MAP_SHARED: shared backing, fork-visible */
} i686_page_state_t;

/* Per-sub-page flags. */
#define I686_PAGE_HAS_CODE 0x01u           /* live DBT blocks translated from this page */
#define I686_PAGE_HAS_SW_RESERVATION 0x02u /* active cross-block LL reservation */

/* 32-byte Soft-TLB entry (UNIFICATION-PLAN 4.3.1). */
typedef struct {
    uint64_t read_tag;       /* (gva & ~0xFFF) when readable and below EOF, else ~0 */
    uintptr_t addend;        /* host_page_base - (gva & ~0xFFF); constant G on A2 */
    uint64_t write_tag;      /* (gva & ~0xFFF) iff writable, !cow_clean, !code, !rsv */
    uint64_t flags_reserved; /* zero-initialized, keeps 32B cache alignment */
} i686_tlb_entry_t;

_Static_assert(sizeof(i686_tlb_entry_t) == 32, "Soft-TLB entry must be 32 bytes");

/* Regime selection: pure function of the host page size (4.6). */
static inline uint32_t i686_vm_regime_for_host_page(size_t host_page)
{
    return (host_page == 4096u) ? I686_VM_REGIME_A1 : I686_VM_REGIME_A2;
}

/* Current regime of an initialized context (0 when uninitialized). */
static inline uint32_t i686_vm_regime(const i686_ctx_t *ctx)
{
    return ctx->vm_regime;
}

/* True when the DBT must emit the 7-instruction Soft-TLB (Regime A2). */
static inline bool i686_vm_needs_soft_tlb(const i686_ctx_t *ctx)
{
    return ctx->vm_regime == I686_VM_REGIME_A2;
}

/* Initialize the VM: reserves the 4 GiB window via rt32_vm_init, selects
 * the regime from rt_host_page_size(), and allocates the Soft-TLB array
 * (ctx->vm_tlb) on Regime A2. Returns 0 on success, -1 on failure. */
int i686_vm32_init(i686_ctx_t *ctx, uint64_t requested_window);

/* Release Regime A2 Soft-TLB storage (no-op on A1 / uninitialized). */
void i686_vm32_fini(i686_ctx_t *ctx);

/* Recompute one Soft-TLB entry for guest VPN after a VMA / COW / SMC /
 * reservation transition (4.4: write_tag is set iff writable, promoted,
 * codeless, and reservation-free). */
void i686_vm32_tlb_fill(i686_ctx_t *ctx, uint32_t gva);

/* Invalidate TLB coverage for [start, end): range-selective below 512
 * pages, else the full 128 KiB array (UNIFICATION-PLAN 4.5 step 5). */
void i686_vm32_tlb_invalidate(i686_ctx_t *ctx, uint32_t start, uint32_t end);

/* Union host protection of one host page covering guest [start, end):
 * PROT_READ | PROT_WRITE when any sub-page is writable, never PROT_EXEC
 * (fable M3: RELRO + .data share one host page without trap storms). */
int i686_vm32_union_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end);

/* Widened (most-restrictive) host protection of every host page covering
 * guest [start, end): each host page carries the AND of its sub-page
 * mirror protections, so a guest PROT_NONE/PROT_READ sub-page traps on
 * the host even when RW neighbours share the page (C2-2: p3/tcg
 * mprotect/munmap immediacy on 16 KiB hosts).  Neighbour sub-pages that
 * stay guest-accessible fault spuriously; the fault paths emulate those
 * via interpret-one and re-widen, so widening is never a silent
 * permission loss.  Never PROT_EXEC. */
int i686_vm32_widen_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end);

/* Canonical host address of a guest VA (HVA = arena_base + gva; stable
 * across COW promotion, fable C2). */
static inline void *i686_vm32_hva(const i686_ctx_t *ctx, uint32_t gva)
{
    return (void *)(uintptr_t)(ctx->guest_base + (uint64_t)gva);
}

#endif /* I686RT_VM_VM32_H */
