/*
 * src/vm/vm32.c — Two-regime Class-A 32-bit VM (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4, section 4.6.
 *
 * Regime A1 (H == 4096, native 4 KiB Linux kernels and every hyper-linux
 * run, where Stage-1 EL1 page tables are 4 KiB): the rt32 4 GiB window
 * [G, G + 4 GiB) maps 1:1, x20 = G, and the DBT emits the 1-instruction
 * [x20, wAddr, uxtw] form. Guest fork() is native kernel MAP_PRIVATE COW.
 *
 * Regime A2 (H > 4096: 16 KiB Standalone macOS Mach-O backend_darwin.c,
 * 16K/64K Linux without /dev/a32host): the same 4 GiB window is kept as a
 * single MAP_PRIVATE | MAP_ANONYMOUS arena whose active host pages carry
 * the union of their 4 KiB sub-page protections (PROT_READ | PROT_WRITE,
 * never PROT_EXEC). x20 = &ctx->tlb[0] and the DBT emits the 7-instruction
 * Soft-TLB (caller zero-extends the 32-bit EA into w1 first). HVA stays
 * G + gva on both regimes, so DBT, interp_step, futex, and syscall
 * copyin/copyout share one coherent address per page (M3/C2 fixed).
 *
 * Curated C11, no VLAs, no x18 (pure C11 file).
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "os/backend.h"
#include "rt32.h"
#include "vm/vm_file.h"

int i686_vm32_init(i686_ctx_t *ctx, uint64_t requested_window)
{
    size_t host_page;
    i686_tlb_entry_t *tlb;
    uint32_t i;
    if (ctx == NULL) {
        return -1;
    }
    if (rt32_vm_init(ctx, requested_window) != 0) {
        return -1;
    }
    host_page = rt_host_page_size();
    ctx->vm_host_page = (uint32_t)host_page;
    ctx->vm_regime = i686_vm_regime_for_host_page(host_page);
    ctx->vm_tlb = NULL;
    ctx->dbt_fault_nzcv = 0u;
    ctx->dbt_fault_w21 = 0u;
    if (ctx->vm_regime != I686_VM_REGIME_A2) {
        return 0;
    }
    tlb = calloc(I686_TLB_SIZE, sizeof(*tlb));
    if (tlb == NULL) {
        return -1;
    }
    /* calloc zeroes tags (== VPN 0 readable), which would alias guest
     * page zero: force every entry invalid up front. */
    for (i = 0u; i < I686_TLB_SIZE; i++) {
        tlb[i].read_tag = I686_TLB_INVALID_TAG;
        tlb[i].write_tag = I686_TLB_INVALID_TAG;
        tlb[i].addend = (uintptr_t)ctx->guest_base;
        tlb[i].flags_reserved = 0u;
    }
    if (i686_vm_file_init(ctx->guest_base) != 0) {
        free(tlb);
        return -1;
    }
    ctx->vm_tlb = tlb;
    return 0;
}

void i686_vm32_fini(i686_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    free(ctx->vm_tlb);
    ctx->vm_tlb = NULL;
    ctx->vm_regime = 0u;
    i686_vm_file_fini();
}

/* Write_tag is set iff ALL FOUR hold (UNIFICATION-PLAN 4.4.1):
 * writable, promoted (!COW_CLEAN), codeless, reservation-free. */
void i686_vm32_tlb_fill(i686_ctx_t *ctx, uint32_t gva)
{
    i686_tlb_entry_t *tlb;
    uint32_t vpn;
    uint32_t idx;
    uint8_t prot;
    uint8_t state;
    uint8_t flags;
    if (ctx == NULL || ctx->vm_regime != I686_VM_REGIME_A2 ||
        ctx->vm_tlb == NULL) {
        return;
    }
    tlb = ctx->vm_tlb;
    vpn = gva & ~(uint32_t)I686_GUEST_PAGE_MASK;
    idx = (gva >> I686_FILE_SUBPAGE_BITS) & (I686_TLB_SIZE - 1u);
    prot = i686_vm_file_prot(gva);
    state = i686_vm_file_state(gva);
    flags = i686_vm_file_flags(gva);
    if ((prot & 0x01u) != 0u) {
        tlb[idx].read_tag = (uint64_t)vpn;
    } else {
        tlb[idx].read_tag = I686_TLB_INVALID_TAG;
    }
    if ((prot & 0x02u) != 0u && state != 1u &&
        (flags & 0x01u) == 0u && (flags & 0x02u) == 0u) {
        tlb[idx].write_tag = (uint64_t)vpn;
    } else {
        tlb[idx].write_tag = I686_TLB_INVALID_TAG;
    }
    tlb[idx].addend = (uintptr_t)ctx->guest_base;
}

void i686_vm32_tlb_invalidate(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    i686_tlb_entry_t *tlb;
    uint64_t pages;
    uint32_t a;
    if (ctx == NULL || ctx->vm_regime != I686_VM_REGIME_A2 ||
        ctx->vm_tlb == NULL || end <= start) {
        return;
    }
    tlb = ctx->vm_tlb;
    pages = ((uint64_t)end - (uint64_t)start + 0xFFFULL) >> 12;
    if (pages >= 512u) {
        for (a = 0u; a < I686_TLB_SIZE; a++) {
            tlb[a].read_tag = I686_TLB_INVALID_TAG;
            tlb[a].write_tag = I686_TLB_INVALID_TAG;
        }
        return;
    }
    for (a = start & ~0xFFFu; a < end; a += 0x1000u) {
        uint32_t idx = (a >> 12) & (I686_TLB_SIZE - 1u);
        tlb[idx].read_tag = I686_TLB_INVALID_TAG;
        tlb[idx].write_tag = I686_TLB_INVALID_TAG;
    }
}

int i686_vm32_union_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    uint64_t host_page;
    uint64_t hva_start;
    uint64_t hva_end;
    uint64_t page;
    int prot;
    uint32_t a;
    if (ctx == NULL || end <= start) {
        return -1;
    }
    host_page = (ctx->vm_host_page != 0u) ? (uint64_t)ctx->vm_host_page : 4096u;
    hva_start = ctx->guest_base + (uint64_t)(start & ~(uint32_t)(host_page - 1u));
    hva_end = ctx->guest_base + (((uint64_t)end + host_page - 1u) & ~(host_page - 1u));
    for (page = hva_start; page < hva_end; page += host_page) {
        prot = 0;
        for (a = 0u; (uint64_t)a < host_page; a += 0x1000u) {
            uint32_t gva = (uint32_t)((page + (uint64_t)a) - ctx->guest_base);
            prot |= (int)(i686_vm_file_prot(gva) & 0x03u);
        }
        /* Union of sub-page protections; EXEC is never mapped (W^X). */
        if (rt_host_protect((void *)(uintptr_t)page, (size_t)host_page, prot) != 0) {
            return -1;
        }
    }
    return 0;
}

/* Most-restrictive cover: the host page denies whatever any sub-page
 * denies.  Untracked (never-mapped) sub-pages read prot 0 and therefore
 * restrict, which keeps munmap-created holes trapping (C2-2). */
int i686_vm32_widen_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    uint64_t host_page;
    uint64_t hva_start;
    uint64_t hva_end;
    uint64_t page;
    if (ctx == NULL || end <= start) {
        return -1;
    }
    host_page = (ctx->vm_host_page != 0u) ? (uint64_t)ctx->vm_host_page : 4096u;
    hva_start = ctx->guest_base + (uint64_t)(start & ~(uint32_t)(host_page - 1u));
    hva_end = ctx->guest_base + (((uint64_t)end + host_page - 1u) & ~(host_page - 1u));
    for (page = hva_start; page < hva_end; page += host_page) {
        int prot = 0x03;
        uint32_t a;
        for (a = 0u; (uint64_t)a < host_page; a += 0x1000u) {
            uint32_t gva = (uint32_t)((page + (uint64_t)a) - ctx->guest_base);
            prot &= (int)(i686_vm_file_prot(gva) & 0x03u);
        }
        /* AND of sub-page protections; EXEC is never mapped (W^X). */
        if (rt_host_protect((void *)(uintptr_t)page, (size_t)host_page, prot) != 0) {
            return -1;
        }
    }
    return 0;
}
