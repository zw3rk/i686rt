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
 * single MAP_PRIVATE | MAP_ANONYMOUS arena with x20 = G. Per-4 KiB sub-page
 * protections are tracked in i686_vm_file; host pages with mixed sub-page
 * permissions carry the intersection (AND) of their sub-page protections via
 * i686_vm32_widen_prot (never PROT_EXEC), and accesses to accessible
 * neighbour sub-pages on a restricted host page are verified per-4 KiB
 * sub-page and single-stepped under the subpage lock before re-widening.
 * HVA stays G + gva on both regimes, so DBT, interp_step, futex, and syscall
 * copyin/copyout share one coherent address per page.
 *
 * Curated C11, no VLAs, no x18 (pure C11 file).
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "os/backend.h"
#include "rt32.h"
#include "vm/vm_file.h"

#define I686_VM32_MAX_PINS 64u

struct vm32_page_pin {
    _Atomic uint64_t page;
    _Atomic uint32_t count;
};

static pthread_mutex_t s_subpage_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct vm32_page_pin s_page_pins[I686_VM32_MAX_PINS];

static int vm32_page_is_pinned(uint64_t page)
{
    unsigned i;
    for (i = 0u; i < I686_VM32_MAX_PINS; i++) {
        if (atomic_load(&s_page_pins[i].count) > 0u &&
            atomic_load(&s_page_pins[i].page) == page) {
            return 1;
        }
    }
    return 0;
}

void i686_vm32_subpage_lock(void)
{
    (void)pthread_mutex_lock(&s_subpage_mtx);
}

void i686_vm32_subpage_unlock(void)
{
    (void)pthread_mutex_unlock(&s_subpage_mtx);
}

int i686_vm32_init(i686_ctx_t *ctx, uint64_t requested_window)
{
    size_t host_page;
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
    if (i686_vm_file_init(ctx->guest_base) != 0) {
        return -1;
    }
    return 0;
}

void i686_vm32_fini(i686_ctx_t *ctx)
{
    unsigned i;
    if (ctx == NULL) {
        return;
    }
    for (i = 0u; i < I686_VM32_MAX_PINS; i++) {
        atomic_store(&s_page_pins[i].count, 0u);
        atomic_store(&s_page_pins[i].page, 0u);
    }
    ctx->vm_tlb = NULL;
    ctx->vm_regime = 0u;
    i686_vm_file_fini();
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
        int pinned = vm32_page_is_pinned(page);
        int prot = pinned ? 0 : 0x03;
        uint32_t a;
        for (a = 0u; (uint64_t)a < host_page; a += 0x1000u) {
            uint32_t gva = (uint32_t)((page + (uint64_t)a) - ctx->guest_base);
            if (pinned) {
                prot |= (int)(i686_vm_file_prot(gva) & 0x03u);
            } else {
                prot &= (int)(i686_vm_file_prot(gva) & 0x03u);
            }
        }
        /* AND of sub-page protections (or union when pinned); EXEC is never mapped (W^X). */
        if (rt_host_protect((void *)(uintptr_t)page, (size_t)host_page, prot) != 0) {
            return -1;
        }
    }
    return 0;
}

int i686_vm32_pin_page(i686_ctx_t *ctx, uint32_t gva)
{
    uint32_t hps;
    uint32_t gbase;
    uint64_t page;
    unsigned i;
    int free_idx = -1;
    int rc;

    if (ctx == NULL || ctx->vm_regime != I686_VM_REGIME_A2 ||
        ctx->vm_host_page <= 4096u) {
        return 0;
    }
    hps = ctx->vm_host_page;
    gbase = gva & ~(hps - 1u);
    page = ctx->guest_base + (uint64_t)gbase;
    i686_vm32_subpage_lock();
    for (i = 0u; i < I686_VM32_MAX_PINS; i++) {
        uint32_t c = atomic_load(&s_page_pins[i].count);
        if (c > 0u && atomic_load(&s_page_pins[i].page) == page) {
            atomic_store(&s_page_pins[i].count, c + 1u);
            free_idx = (int)i;
            break;
        }
        if (c == 0u && free_idx < 0) {
            free_idx = (int)i;
        }
    }
    if (free_idx >= 0 &&
        atomic_load(&s_page_pins[(unsigned)free_idx].count) == 0u) {
        atomic_store(&s_page_pins[(unsigned)free_idx].page, page);
        atomic_store(&s_page_pins[(unsigned)free_idx].count, 1u);
    }
    rc = i686_vm32_union_prot(ctx, gbase, gbase + hps);
    i686_vm32_subpage_unlock();
    return rc;
}

void i686_vm32_unpin_page(i686_ctx_t *ctx, uint32_t gva)
{
    uint32_t hps;
    uint32_t gbase;
    uint64_t page;
    unsigned i;

    if (ctx == NULL || ctx->vm_regime != I686_VM_REGIME_A2 ||
        ctx->vm_host_page <= 4096u) {
        return;
    }
    hps = ctx->vm_host_page;
    gbase = gva & ~(hps - 1u);
    page = ctx->guest_base + (uint64_t)gbase;
    i686_vm32_subpage_lock();
    for (i = 0u; i < I686_VM32_MAX_PINS; i++) {
        uint32_t c = atomic_load(&s_page_pins[i].count);
        if (c > 0u && atomic_load(&s_page_pins[i].page) == page) {
            if (c == 1u) {
                atomic_store(&s_page_pins[i].count, 0u);
                atomic_store(&s_page_pins[i].page, 0u);
                (void)i686_vm32_widen_prot(ctx, gbase, gbase + hps);
            } else {
                atomic_store(&s_page_pins[i].count, c - 1u);
            }
            break;
        }
    }
    i686_vm32_subpage_unlock();
}
