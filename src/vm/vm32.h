/*
 * src/vm/vm32.h — Two-regime Class-A 32-bit VM interface (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4, section 4.6: Regime A1 (H == 4096, 1-insn
 * [x20, wAddr, uxtw] over a MAP_PRIVATE | MAP_ANONYMOUS 4 GiB window
 * [G, G + 4 GiB)) vs Regime A2 (H > 4096, x20 = G direct window with
 * per-4 KiB sub-page permission mirrors in i686_vm_file, widened host-page
 * protection via i686_vm32_widen_prot, and fault-checked single-step
 * emulation for neighbour sub-pages sharing a partially restricted host page).
 *
 * Regime A2 preserves native fork() COW (fable C1), keeps in-place fixed
 * HVA = G + gva on PAGE_COW_CLEAN -> PAGE_COW_DIRTY promotion (fable C2),
 * and enforces strict 4 KiB sub-page protections without mapping guest
 * pages PROT_EXEC.
 */

#ifndef I686RT_VM_VM32_H
#define I686RT_VM_VM32_H

#include <stddef.h>
#include <stdint.h>

#include "i686rt.h"

/* Guest ABI page granule (4 KiB; Class-A i686, UNIFICATION-PLAN 4.2). */
#define I686_GUEST_PAGE_SIZE 4096u
#define I686_GUEST_PAGE_MASK 0xFFFu

/* Per-sub-page backing state (Provider A, UNIFICATION-PLAN 5.1). */
typedef enum {
    I686_PAGE_ANON = 0,      /* private anonymous, fully writable when prot allows */
    I686_PAGE_COW_CLEAN = 1, /* MAP_PRIVATE file image, not yet dirtied */
    I686_PAGE_COW_DIRTY = 2, /* promoted in place at the same HVA */
    I686_PAGE_SHARED = 3     /* MAP_SHARED: shared backing, fork-visible */
} i686_page_state_t;

/* Per-sub-page flags. */
#define I686_PAGE_HAS_CODE 0x01u           /* live DBT blocks translated from this page */
#define I686_PAGE_HAS_SW_RESERVATION 0x02u /* active cross-block LL reservation */

/* 32-byte Soft-TLB entry ABI descriptor (UNIFICATION-PLAN 4.3.1). */
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

/* Initialize the VM: reserves the 4 GiB window via rt32_vm_init, selects
 * the regime from rt_host_page_size(), and initializes the Regime A2
 * per-4 KiB sub-page mirror tables. Returns 0 on success, -1 on failure. */
int i686_vm32_init(i686_ctx_t *ctx, uint64_t requested_window);

/* Release Regime A2 sub-page mirror tables (no-op on A1 / uninitialized). */
void i686_vm32_fini(i686_ctx_t *ctx);

/* Serialize temporary Regime A2 union_prot -> emulate/copy -> widen_prot
 * transitions across threads, pausing guest execution on sibling threads
 * while a mixed-permission host page is widened. */
void i686_vm32_fork_prepare(void);
void i686_vm32_fork_parent(void);
void i686_vm32_fork_child(void);
void i686_vm32_subpage_lock(void);
void i686_vm32_subpage_unlock(void);
void i686_vm32_exec_enter(const i686_ctx_t *ctx);
void i686_vm32_exec_leave(void);

/* Union host protection of one host page covering guest [start, end):
 * PROT_READ | PROT_WRITE when any sub-page is writable, never PROT_EXEC. */
int i686_vm32_union_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end);

/* Widened (most-restrictive) host protection of every host page covering
 * guest [start, end): each host page carries the AND of its sub-page
 * mirror protections, so a guest PROT_NONE/PROT_READ sub-page traps on
 * the host even when RW neighbours share the page (C2-2: p3/tcg
 * mprotect/munmap immediacy on 16 KiB hosts).  Neighbour sub-pages that
 * stay guest-accessible fault spuriously; the fault paths verify every
 * accessed 4 KiB sub-page, emulate one instruction under the subpage
 * lock, and immediately re-widen.  Never PROT_EXEC. */
int i686_vm32_widen_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end);

struct timespec;
long i686_vm32_futex(i686_ctx_t *ctx, uint32_t uaddr, uint32_t op,
                     uint32_t val, const struct timespec *timeout,
                     uint32_t val2, uint32_t uaddr2, uint32_t val3);
long i686_vm32_futex_wake(i686_ctx_t *ctx, uint32_t uaddr, uint32_t max_wake,
                          uint32_t bitset);

/* Canonical host address of a guest VA (HVA = arena_base + gva; stable
 * across COW promotion, fable C2). */
static inline void *i686_vm32_hva(const i686_ctx_t *ctx, uint32_t gva)
{
    return (void *)(uintptr_t)(ctx->guest_base + (uint64_t)gva);
}

#endif /* I686RT_VM_VM32_H */
