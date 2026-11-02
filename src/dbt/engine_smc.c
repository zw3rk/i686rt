/*
 * src/dbt/engine_smc.c — DBT self-modifying code (D11) & cross-thread invalidation
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "dbt/engine_internal.h"
#include "vm/vm32.h"
#include "vm/vm_file.h"

extern int i686_fault_region_prot(const i686_ctx_t *ctx, uint32_t ga,
                                  uint32_t *out_prot, uint32_t *out_flags);

static _Atomic uint32_t s_code_pages[SMC_WORDS];
_Atomic uint64_t g_dbt_smc_window_base;
_Atomic uint64_t g_dbt_smc_window_end;
_Atomic uint32_t g_dbt_cache_epoch = 1U;
_Atomic uint32_t g_dbt_flush_epoch = 1U;
_Atomic uint32_t g_dbt_page_gen[1U << 20];

void dbt_bump_cache_epoch(void)
{
    uint32_t next = atomic_fetch_add_explicit(&g_dbt_cache_epoch, 1U,
                                              memory_order_acq_rel) + 1U;
    if (next == 0U) {
        atomic_fetch_add_explicit(&g_dbt_cache_epoch, 1U, memory_order_acq_rel);
    }
}

void smc_clear_code_pages(void)
{
    size_t i;
    for (i = 0U; i < SMC_WORDS; i++) {
        atomic_store_explicit(&s_code_pages[i], 0U, memory_order_relaxed);
    }
}

static int smc_page_marked(uint32_t guest_page)
{
    uint32_t idx = guest_page / SMC_PAGE;
    uint32_t mask = 1U << (idx & 31U);
    return (atomic_load_explicit(&s_code_pages[idx >> 5U],
                                 memory_order_acquire) & mask) != 0U;
}

int i686_dbt_smc_page_marked(uint32_t guest_page)
{
    return smc_page_marked(guest_page);
}

static void smc_page_mark(uint32_t guest_page)
{
    uint32_t idx = guest_page / SMC_PAGE;
    uint32_t mask = 1U << (idx & 31U);
    (void)atomic_fetch_or_explicit(&s_code_pages[idx >> 5U], mask,
                                   memory_order_release);
}

static void smc_page_unmark(uint32_t guest_page)
{
    uint32_t idx = guest_page / SMC_PAGE;
    uint32_t mask = 1U << (idx & 31U);
    (void)atomic_fetch_and_explicit(&s_code_pages[idx >> 5U], ~mask,
                                    memory_order_release);
}

static uint32_t smc_host_page(const i686_ctx_t *ctx)
{
    uint32_t h = (ctx != NULL) ? ctx->vm_host_page : 0U;

    if (h < SMC_PAGE || (h & (h - 1U)) != 0U) {
        h = SMC_PAGE;
    }
    return h;
}

static int smc_in_span(uint32_t eip, uint32_t start, uint32_t len)
{
    uint64_t end64 = (uint64_t)start + (uint64_t)len;

    if (end64 <= UINT64_C(0x100000000)) {
        return (eip >= start && (uint64_t)eip < end64) ? 1 : 0;
    }
    if (eip >= start) {
        return 1;
    }
    return ((uint64_t)eip < end64 - UINT64_C(0x100000000)) ? 1 : 0;
}

/* Restore the host page at hbase to its current guest VMA protection
 * (never hardcoding PROT_READ | PROT_WRITE on read-only VMAs, I686-3)
 * and unmark all its 4 KiB sub-pages. */
static void smc_unprotect_host(i686_ctx_t *ctx, uint32_t hbase, uint32_t h)
{
    uint64_t host;
    uint32_t off;

    for (off = 0U; off < h; off += SMC_PAGE) {
        smc_page_unmark(hbase + off);
    }
    if (ctx != NULL && ctx->vm_regime == I686_VM_REGIME_A2 &&
        ctx->vm_host_page > 4096U) {
        (void)i686_vm32_widen_prot(ctx, hbase, hbase + h);
        return;
    }
    if (ctx != NULL) {
        host = ctx->guest_base + (uint64_t)hbase;
    } else {
        host = atomic_load_explicit(&g_dbt_smc_window_base,
                                    memory_order_relaxed) + (uint64_t)hbase;
    }
    for (off = 0U; off < h; off += SMC_PAGE) {
        uint32_t gva = hbase + off;
        uint32_t rprot = 0U;
        int hprot = PROT_NONE;
        if (ctx != NULL) {
            if (i686_fault_region_prot(ctx, gva, &rprot, NULL) != 0) {
                if ((rprot & 0x01U) != 0U) {
                    hprot |= PROT_READ;
                }
                if ((rprot & 0x02U) != 0U) {
                    hprot |= PROT_WRITE;
                }
            }
        } else {
            hprot = PROT_READ | PROT_WRITE;
        }
        (void)mprotect((void *)(uintptr_t)(host + (uint64_t)off),
                       SMC_PAGE, hprot);
    }
}

/* Called when compiling a block from eip: write-protect its source host page
 * so stores into a code page trap into i686_dbt_smc_write_fault.
 * On Regime A2 (16K/64K host pages), never widen any PROT_NONE/unmapped
 * neighbor 4 KiB sub-page to PROT_READ (I686-R2-2). */
void smc_protect(i686_ctx_t *ctx, uint32_t eip)
{
    uint32_t h = smc_host_page(ctx);
    uint32_t hbase = eip & ~(h - 1U);
    uint32_t off;

    for (off = 0U; off < h; off += SMC_PAGE) {
        smc_page_mark(hbase + off);
    }
    if (ctx != NULL && ctx->vm_regime == I686_VM_REGIME_A2 && h > SMC_PAGE) {
        (void)i686_vm32_widen_prot(ctx, hbase, hbase + h);
        return;
    }
    (void)mprotect(i686_guest_ptr(ctx, hbase), (size_t)h, PROT_READ);
}

static void smc_sites_clear_span(uint32_t hbase, uint32_t h)
{
    uint64_t end64 = (uint64_t)hbase + (uint64_t)h;
    uint32_t i;

    if (end64 <= UINT64_C(0xFFFFFFFF)) {
        dbt_sites_clear_range(hbase, (uint32_t)end64);
        return;
    }
    dbt_sites_clear_range(hbase, 0xFFFFFFFFU);
    if (end64 > UINT64_C(0x100000000)) {
        dbt_sites_clear_range(0U,
                              (uint32_t)(end64 - UINT64_C(0x100000000)));
    }
    for (i = 0U; i < DBT_HT_SIZE; i++) {
        if (g_dbt_site_end[i] > g_dbt_site_start[i] &&
            g_dbt_site_eip[i] == 0xFFFFFFFFU) {
            g_dbt_site_start[i] = 0U;
            g_dbt_site_end[i] = 0U;
            g_dbt_site_eip[i] = 0xFFFFFFFFU;
        }
    }
}

static void smc_drop_host(i686_ctx_t *ctx, uint32_t hbase, uint32_t h)
{
    size_t i;
    uint32_t off;

    for (off = 0U; off < h; off += SMC_PAGE) {
        uint32_t vpn = (hbase + off) >> 12U;
        (void)atomic_fetch_add_explicit(&g_dbt_page_gen[vpn], 1U,
                                        memory_order_release);
    }
    dbt_bump_cache_epoch();
    smc_sites_clear_span(hbase, h);
    for (i = 0U; i < DBT_HT_SIZE; i++) {
        if (g_dbt_ht[i].len != 0U &&
            smc_in_span(g_dbt_ht[i].eip, hbase, h) != 0) {
            g_dbt_ht[i].eip = 0xFFFFFFFFU;
            dbt_graveyard_push(g_dbt_ht[i].code, g_dbt_ht[i].cap);
            g_dbt_ht[i].code = NULL;
            g_dbt_ht[i].cap = 0U;
            g_dbt_ht[i].len = 0U;
        }
    }
    if (ctx != NULL) {
        for (i = 0U; i < I686_IBTC_SIZE; i++) {
            if (ctx->ibtc[i].key != 0U &&
                smc_in_span(ctx->ibtc[i].key, hbase, h) != 0) {
                ctx->ibtc[i].key = 0U;
                ctx->ibtc[i].epoch = 0U;
                ctx->ibtc[i].host_code = NULL;
                ctx->ibtc[i].entry = NULL;
            }
        }
        for (i = 0U; i < I686_RAS_SIZE; i++) {
            if (smc_in_span(ctx->ras[i].key, hbase, h) != 0) {
                ctx->ras[i].key = 0U;
                ctx->ras[i].epoch = 0U;
            }
        }
    }
}

void i686_dbt_invalidate_range(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    uint32_t page;
    uint32_t h = smc_host_page(ctx);
    uint32_t last_hbase = 0U;
    int have_last = 0;

    if (end <= start) {
        return;
    }
    dbt_sites_clear_range(start, end);
    for (page = start & ~(SMC_PAGE - 1U); page < end; page += SMC_PAGE) {
        uint32_t hbase;

        (void)atomic_fetch_add_explicit(&g_dbt_page_gen[page >> 12U], 1U,
                                        memory_order_release);
        if (!smc_page_marked(page)) {
            continue;
        }
        hbase = page & ~(h - 1U);
        if (have_last != 0 && hbase == last_hbase) {
            continue;
        }
        have_last = 1;
        last_hbase = hbase;
        smc_unprotect_host(ctx, hbase, h);
        smc_drop_host(ctx, hbase, h);
    }
    dbt_bump_cache_epoch();
    for (size_t i = 0U; i < DBT_HT_SIZE; i++) {
        if (g_dbt_ht[i].len != 0U && g_dbt_ht[i].eip >= start &&
            g_dbt_ht[i].eip < end) {
            g_dbt_ht[i].eip = 0xFFFFFFFFU;
            dbt_graveyard_push(g_dbt_ht[i].code, g_dbt_ht[i].cap);
            g_dbt_ht[i].code = NULL;
            g_dbt_ht[i].cap = 0U;
            g_dbt_ht[i].len = 0U;
        }
    }
    if (ctx != NULL) {
        for (size_t i = 0U; i < I686_IBTC_SIZE; i++) {
            if (ctx->ibtc[i].key != 0U &&
                ctx->ibtc[i].key >= start && ctx->ibtc[i].key < end) {
                ctx->ibtc[i].key = 0U;
                ctx->ibtc[i].epoch = 0U;
                ctx->ibtc[i].host_code = NULL;
                ctx->ibtc[i].entry = NULL;
            }
        }
        for (size_t i = 0U; i < I686_RAS_SIZE; i++) {
            if (ctx->ras[i].key >= start && ctx->ras[i].key < end) {
                ctx->ras[i].key = 0U;
                ctx->ras[i].epoch = 0U;
            }
        }
    }
}

/* Host-fault query (interp.c SIGSEGV/SIGBUS path): a write fault inside a
 * code-protected window page -> verify that the guest VMA is actually
 * writable (I686-3), then invalidate + restore protection so the handler
 * returns and the store re-executes.  Returns 1 if handled as SMC, 0 if
 * the guest page is not writable (caller delivers SIGSEGV). */
int i686_dbt_smc_write_fault(uint64_t host_addr)
{
    uint64_t win_base = atomic_load_explicit(&g_dbt_smc_window_base,
                                             memory_order_relaxed);
    uint64_t win_end = atomic_load_explicit(&g_dbt_smc_window_end,
                                            memory_order_relaxed);
    uint32_t ga;
    uint32_t page;
    uint32_t h;
    uint32_t hbase;

    if (host_addr < win_base || host_addr >= win_end) {
        return 0;
    }
    ga = (uint32_t)(host_addr - win_base);
    page = ga & ~(SMC_PAGE - 1U);
    if (!smc_page_marked(page)) {
        return 0;
    }
    /* I686-3: verify that the faulting guest page actually has PROT_WRITE
     * before treating the fault as SMC. A write to a read-only code page
     * must deliver SIGSEGV to the guest rather than making the page RW. */
    if (g_dbt_run_ctx != NULL) {
        uint32_t rprot = 0U;
        if (i686_fault_region_prot(g_dbt_run_ctx, page, &rprot, NULL) == 0 ||
            (rprot & 0x02U) == 0U) {
            return 0;
        }
        if (g_dbt_run_ctx->vm_regime == I686_VM_REGIME_A2 &&
            (i686_vm_file_prot(page) & 0x02U) == 0U) {
            return 0;
        }
    }
    h = smc_host_page(g_dbt_run_ctx);
    hbase = page & ~(h - 1U);
    smc_unprotect_host(g_dbt_run_ctx, hbase, h);
    smc_drop_host(g_dbt_run_ctx, hbase, h);
    if (g_dbt_run_ctx != NULL &&
        g_dbt_run_ctx->vm_regime == I686_VM_REGIME_A2 && h > SMC_PAGE) {
        uint32_t off;
        for (off = 0U; off < h; off += SMC_PAGE) {
            if ((i686_vm_file_flags(hbase + off) & 0x80u) == 0u ||
                (i686_vm_file_prot(hbase + off) & 0x03u) != 0x03u) {
                /* Host page stays restricted because a sibling 4 KiB
                 * sub-page is not RW; let the checkpointed fault handler
                 * single-step the write via i686_spurious_emulate. */
                return 0;
            }
        }
    }
    return 1;
}

/* Enable TSO barrier emission when the guest transitions to multi-threaded
 * execution (CLONE_VM, I686-4) and flush all previously compiled non-TSO
 * blocks across all threads. */
void i686_dbt_enable_tso(void)
{
    uint32_t prev = atomic_exchange_explicit(&g_i686_tso_enabled, 1U,
                                             memory_order_acq_rel);
    if (prev == 0U) {
        (void)atomic_fetch_add_explicit(&g_dbt_flush_epoch, 1U,
                                        memory_order_acq_rel);
        dbt_bump_cache_epoch();
    }
}
