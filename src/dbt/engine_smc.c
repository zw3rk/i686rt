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
/* Process-global "this guest page ever held a translated block" marks.
 * Set on compile (dbt_get_or_compile); consulted by
 * i686_dbt_invalidate_range so a thread without its own blocks (interp
 * mode, exiting) still invalidates code compiled by sibling DBT threads
 * and still bumps page generations for unmarked (never write-protected)
 * code pages. Never cleared: a set bit is a conservative may-hold-code. */
_Atomic uint8_t g_dbt_compiled_page[1U << 20];

/* Cached VM geometry for NULL-ctx paths (M1). smc_protect and
 * i686_dbt_invalidate_range record the live ctx's host page size,
 * regime and window base whenever ctx != NULL, so smc_host_page and
 * smc_unprotect_host still know the true geometry when a caller
 * passes ctx == NULL. Plain values only, never a ctx pointer: the
 * owning thread's stack ctx may be gone by the time a later fault
 * reads them. */
static _Atomic uint32_t g_smc_host_page = SMC_PAGE;
static _Atomic uint32_t g_smc_regime = 0U;
static _Atomic uint64_t g_smc_win_base = 0U;

static void smc_note_ctx(const i686_ctx_t *ctx)
{
    uint32_t h;

    if (ctx == NULL) {
        return;
    }
    h = ctx->vm_host_page;
    if (h < SMC_PAGE || (h & (h - 1U)) != 0U) {
        h = SMC_PAGE;
    }
    atomic_store_explicit(&g_smc_host_page, h, memory_order_release);
    atomic_store_explicit(&g_smc_regime, ctx->vm_regime,
                          memory_order_release);
    atomic_store_explicit(&g_smc_win_base, ctx->guest_base,
                          memory_order_release);
}

/* Process-wide SMC spinlock (M3). Serializes {mark + mprotect} in
 * smc_protect against {re-check + sibling probe + unprotect + drop}
 * in i686_dbt_smc_write_fault and unprotect in
 * i686_dbt_invalidate_range, so a concurrent protect vs unprotect
 * cannot leave a host page PROT_READ while unmarked (a later store
 * would SIGSEGV with no mark to route it to the SMC path).
 * Lock order: the A2 subpage mutex stays OUTER, this lock INNER
 * (engine.c holds the subpage lock across smc_protect; no path takes
 * the subpage lock while holding this one, and widen_prot takes
 * none). Same-thread signal re-entry can never self-deadlock: the
 * per-thread depth makes it detectable, and the fault handler
 * returns 0 instead of blocking when it is already held. */
static _Atomic uint32_t g_smc_lock = 0U;
static _Thread_local int g_smc_lock_depth = 0;

static void smc_lock_acquire(void)
{
    uint32_t exp;

    if (g_smc_lock_depth > 0) {
        g_smc_lock_depth++;
        return;
    }
    exp = 0U;
    while (!atomic_compare_exchange_weak_explicit(&g_smc_lock, &exp, 1U,
                                                 memory_order_acquire,
                                                 memory_order_relaxed)) {
        exp = 0U;
    }
    g_smc_lock_depth = 1;
}

static void smc_lock_release(void)
{
    if (g_smc_lock_depth > 1) {
        g_smc_lock_depth--;
        return;
    }
    g_smc_lock_depth = 0;
    atomic_store_explicit(&g_smc_lock, 0U, memory_order_release);
}

/* Exclusive-end clamp for i686_vm32_widen_prot (M2). hbase + h in
 * 32 bits wraps to 0 when hbase is the top host page (0xFFFFC000 on
 * 16 KiB, 0xFFFF0000 on 64 KiB). widen_prot treats end <= start as an
 * error and would cover nothing; clamping to 0xFFFFFFFF still covers
 * the last sub-page (0xFFFFF000) because widen rounds the exclusive
 * end up to a host multiple. */
static uint32_t smc_span_end(uint32_t hbase, uint32_t h)
{
    uint64_t end64 = (uint64_t)hbase + (uint64_t)h;

    if (end64 > UINT64_C(0xFFFFFFFF)) {
        return 0xFFFFFFFFU;
    }
    return (uint32_t)end64;
}

void dbt_bump_cache_epoch(void)
{
    DBT_STAT(DBT_STAT_EPOCH_BUMP);
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
    uint32_t h = (ctx != NULL)
                     ? ctx->vm_host_page
                     : atomic_load_explicit(&g_smc_host_page,
                                            memory_order_acquire);

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

/* Block guest span [eip, eip + guest_len) overlaps [start, end)?
 * Wrap-aware: (start - eip) mod 2^32 < guest_len iff start lies inside
 * the block's span, which also covers a block wrapping past 4 GiB.
 * Host-span form: a block whose head sits on the preceding host page
 * while guest_len crosses into [hbase, hbase + h) overlaps it. h
 * divides 4 GiB and hbase is h-aligned, so hbase + h either stays
 * below 4 GiB or lands exactly on it. */
static int smc_span_overlaps(uint32_t eip, uint32_t guest_len, uint32_t start,
                             uint32_t end)
{
    if (end <= start) {
        return 0;
    }
    if (eip >= start && (uint64_t)eip < (uint64_t)end) {
        return 1;
    }
    if (guest_len == 0U) {
        return 0;
    }
    return ((uint32_t)(start - eip) < guest_len) ? 1 : 0;
}

static int smc_block_overlaps_host(uint32_t eip, uint32_t guest_len,
                                   uint32_t hbase, uint32_t h)
{
    uint64_t end64 = (uint64_t)hbase + (uint64_t)h;
    if (end64 <= UINT64_C(0xFFFFFFFF)) {
        return smc_span_overlaps(eip, guest_len, hbase, (uint32_t)end64);
    }
    return (eip >= hbase ||
            (uint64_t)eip + (uint64_t)guest_len > (uint64_t)hbase) ? 1 : 0;
}

/* Restore the host page at hbase to its current guest VMA protection
 * (never hardcoding PROT_READ | PROT_WRITE on read-only VMAs, I686-3)
 * and unmark all its 4 KiB sub-pages. With ctx == NULL the cached
 * regime / window base recorded by smc_note_ctx stand in, and the
 * per-sub-page mirror (i686_vm_file_prot, most-restrictive AND across
 * the span, mirroring widen_prot) supplies the protection; widen
 * itself needs a live ctx and is never called with NULL. */
static void smc_unprotect_host(i686_ctx_t *ctx, uint32_t hbase, uint32_t h)
{
    uint64_t host;
    uint32_t regime;
    uint32_t off;

    for (off = 0U; off < h; off += SMC_PAGE) {
        smc_page_unmark(hbase + off);
    }
    regime = (ctx != NULL)
                 ? ctx->vm_regime
                 : atomic_load_explicit(&g_smc_regime,
                                        memory_order_acquire);
    if (regime == I686_VM_REGIME_A2 && h > SMC_PAGE && ctx != NULL) {
        (void)i686_vm32_widen_prot(ctx, hbase, smc_span_end(hbase, h));
        return;
    }
    host = ((ctx != NULL)
                ? ctx->guest_base
                : atomic_load_explicit(&g_smc_win_base,
                                       memory_order_acquire)) +
           (uint64_t)hbase;
    if (ctx == NULL) {
        /* No live ctx: restore the AND of the sub-page mirror across
         * the span (a single mprotect covers the whole host page, so
         * per-4 KiB mprotects would leave only the last sub-page's
         * prot in effect). Unmapped/unknown sub-pages read prot 0 and
         * therefore restrict, matching widen_prot. */
        uint32_t and_prot = 0x03U;
        int hprot = PROT_NONE;

        for (off = 0U; off < h; off += SMC_PAGE) {
            and_prot &= (uint32_t)(i686_vm_file_prot(hbase + off) & 0x03U);
        }
        if ((and_prot & 0x01U) != 0U) {
            hprot |= PROT_READ;
        }
        if ((and_prot & 0x02U) != 0U) {
            hprot |= PROT_WRITE;
        }
        (void)mprotect((void *)(uintptr_t)host, (size_t)h, hprot);
        return;
    }
    for (off = 0U; off < h; off += SMC_PAGE) {
        uint32_t gva = hbase + off;
        uint32_t rprot = 0U;
        int hprot = PROT_NONE;
        if (i686_fault_region_prot(ctx, gva, &rprot, NULL) != 0) {
            if ((rprot & 0x01U) != 0U) {
                hprot |= PROT_READ;
            }
            if ((rprot & 0x02U) != 0U) {
                hprot |= PROT_WRITE;
            }
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
    uint32_t h;
    uint32_t hbase;
    uint32_t off;
    void *addr;

    smc_note_ctx(ctx);
    h = smc_host_page(ctx);
    hbase = eip & ~(h - 1U);
    smc_lock_acquire();
    for (off = 0U; off < h; off += SMC_PAGE) {
        smc_page_mark(hbase + off);
    }
    if (ctx != NULL && ctx->vm_regime == I686_VM_REGIME_A2 && h > SMC_PAGE) {
        (void)i686_vm32_widen_prot(ctx, hbase, smc_span_end(hbase, h));
        smc_lock_release();
        return;
    }
    addr = (ctx != NULL)
               ? i686_guest_ptr(ctx, hbase)
               : (void *)(uintptr_t)(atomic_load_explicit(&g_smc_win_base,
                                                          memory_order_acquire) +
                                     (uint64_t)hbase);
    (void)mprotect(addr, (size_t)h, PROT_READ);
    smc_lock_release();
}

static void smc_sites_clear_span(uint32_t hbase, uint32_t h)
{
    uint64_t end64 = (uint64_t)hbase + (uint64_t)h;
    uint32_t idx;

    if (g_dbt_ht == NULL) {
        return;
    }
    if (end64 <= UINT64_C(0xFFFFFFFF)) {
        dbt_sites_clear_range(hbase, (uint32_t)end64);
        return;
    }
    dbt_sites_clear_range(hbase, 0xFFFFFFFFU);
    if (end64 > UINT64_C(0x100000000)) {
        dbt_sites_clear_range(0U,
                              (uint32_t)(end64 - UINT64_C(0x100000000)));
    }
    for (idx = 0U; idx < g_dbt_nactive; idx++) {
        uint32_t i = g_dbt_active[idx];
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
    uint32_t idx;
    uint32_t w = 0U;
    uint32_t off;

    for (off = 0U; off < h; off += SMC_PAGE) {
        uint32_t vpn = (hbase + off) >> 12U;
        (void)atomic_fetch_add_explicit(&g_dbt_page_gen[vpn], 1U,
                                        memory_order_acq_rel);
    }
    dbt_bump_cache_epoch();
    smc_sites_clear_span(hbase, h);
    for (idx = 0U; idx < g_dbt_nactive; idx++) {
        uint32_t i = g_dbt_active[idx];
        if (g_dbt_ht != NULL && g_dbt_ht[i].len != 0U &&
            smc_block_overlaps_host(g_dbt_ht[i].eip, g_dbt_ht[i].guest_len,
                                    hbase, h) != 0) {
            g_dbt_ht[i].eip = 0xFFFFFFFFU;
            dbt_graveyard_push(g_dbt_ht[i].code, g_dbt_ht[i].cap);
            g_dbt_ht[i].code = NULL;
            g_dbt_ht[i].cap = 0U;
            g_dbt_ht[i].len = 0U;
        }
        if (g_dbt_ht == NULL || g_dbt_ht[i].len != 0U) {
            g_dbt_active[w++] = i;
        } else {
            dbt_sites_clear_hash(i);
            g_dbt_in_active[i] = 0U;
        }
    }
    g_dbt_nactive = w;
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
    uint32_t h;
    uint32_t last_hbase = 0U;
    uint32_t first;
    int have_last = 0;
    int any_marked = 0;
    int any_compiled = 0;

    smc_note_ctx(ctx);
    /* Deliberately no gate on the thread-local g_dbt_ht: an interp-mode
     * or exiting thread owns no blocks itself but must still invalidate
     * code compiled by sibling DBT threads and bump page generations. */
    if (end <= start) {
        /* A caller-computed va + len that wrapped to exactly 4 GiB
         * (end == 0) names the tail [start, 0xFFFFFFFF]; anything
         * else empty stays a no-op. */
        if (start == 0U || end != 0U) {
            return;
        }
        end = 0xFFFFFFFFU;
    }
    h = smc_host_page(ctx);
    first = start & ~(SMC_PAGE - 1U);
    /* A block starting on the preceding page may cross into [start, end);
     * its head mark / compiled bit alone must keep the slow path alive. */
    /* Unconditional generation bumps BEFORE consulting compiled_page:
     * a sibling may have sampled pgen and read guest bytes but not yet
     * published its compiled_page mark; only the bump makes its
     * post-translate PGEN_RETRY check observe this invalidation. */
    if (first >= SMC_PAGE) {
        uint32_t prev = first - SMC_PAGE;
        (void)atomic_fetch_add_explicit(&g_dbt_page_gen[prev >> 12U],
                                        1U, memory_order_acq_rel);
        if (smc_page_marked(prev) != 0) {
            any_marked = 1;
        }
        if (atomic_load_explicit(&g_dbt_compiled_page[prev >> 12U],
                                 memory_order_acquire) != 0U) {
            any_compiled = 1;
        }
    }
    for (page = first; page < end;) {
        (void)atomic_fetch_add_explicit(&g_dbt_page_gen[page >> 12U],
                                        1U, memory_order_acq_rel);
        if (atomic_load_explicit(&g_dbt_compiled_page[page >> 12U],
                                 memory_order_acquire) != 0U) {
            any_compiled = 1;
        }
        if (smc_page_marked(page) != 0) {
            any_marked = 1;
        }
        if (page + SMC_PAGE < page) {
            break;
        }
        page += SMC_PAGE;
    }
    if (any_compiled == 0 && any_marked == 0) {
        /* Pure data page: never held a translated block on any thread. */
        return;
    }
    if (any_marked != 0) {
        smc_lock_acquire();
        for (page = first; page < end;) {
            uint32_t hbase;

            if (smc_page_marked(page) == 0) {
                if (page + SMC_PAGE < page) {
                    break;
                }
                page += SMC_PAGE;
                continue;
            }
            hbase = page & ~(h - 1U);
            if (have_last != 0 && hbase == last_hbase) {
                if (page + SMC_PAGE < page) {
                    break;
                }
                page += SMC_PAGE;
                continue;
            }
            have_last = 1;
            last_hbase = hbase;
            smc_unprotect_host(ctx, hbase, h);
            smc_drop_host(ctx, hbase, h);
            if (page + SMC_PAGE < page) {
                break;
            }
            page += SMC_PAGE;
        }
        smc_lock_release();
    }
    /* Always: sibling threads (and this thread's IBTC/RAS fast paths)
     * revalidate through the epoch, even for unmarked code pages. */
    dbt_bump_cache_epoch();
    if (g_dbt_ht == NULL) {
        return;
    }
    dbt_sites_clear_range(start, end);
    {
        /* Compact the dense active list exactly like smc_drop_host:
         * dropped slots leave the list and clear their in-active bit
         * instead of lingering as len == 0 entries. */
        uint32_t w = 0U;
        for (uint32_t idx = 0U; idx < g_dbt_nactive; idx++) {
            uint32_t i = g_dbt_active[idx];
            if (g_dbt_ht[i].len != 0U &&
                smc_span_overlaps(g_dbt_ht[i].eip, g_dbt_ht[i].guest_len,
                                  start, end) != 0) {
                g_dbt_ht[i].eip = 0xFFFFFFFFU;
                dbt_graveyard_push(g_dbt_ht[i].code, g_dbt_ht[i].cap);
                g_dbt_ht[i].code = NULL;
                g_dbt_ht[i].cap = 0U;
                g_dbt_ht[i].len = 0U;
                dbt_sites_clear_hash(i);
            }
            if (g_dbt_ht[i].len != 0U) {
                g_dbt_active[w++] = i;
            } else {
                g_dbt_in_active[i] = 0U;
            }
        }
        g_dbt_nactive = w;
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
    uint32_t rprot;
    uint32_t off;

    if (host_addr < win_base || host_addr >= win_end) {
        return 0;
    }
    /* An SMC write fault from JIT code only happens while a DBT run ctx
     * is live on this thread. With none, never fall through to
     * smc_unprotect_host(NULL, ...): that path cannot run the I686-3
     * writability or A2 restrictive-sibling checks. */
    if (g_dbt_run_ctx == NULL) {
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
    rprot = 0U;
    if (i686_fault_region_prot(g_dbt_run_ctx, page, &rprot, NULL) == 0 ||
        (rprot & 0x02U) == 0U) {
        return 0;
    }
    if (g_dbt_run_ctx->vm_regime == I686_VM_REGIME_A2 &&
        (i686_vm_file_prot(page) & 0x02U) == 0U) {
        return 0;
    }
    h = smc_host_page(g_dbt_run_ctx);
    hbase = page & ~(h - 1U);
    /* A2 restrictive-sibling probe BEFORE mutating anything: when a
     * sibling 4 KiB sub-page of this host span is not present+RW, the
     * host page must stay restricted and the checkpointed fault handler
     * single-steps the write via i686_spurious_emulate. That path needs
     * the live block and its fault sites to recover the faulting eip,
     * so return 0 here with blocks, marks, sites and covers untouched
     * (a dropped block + cleared sites misdirect eip at the block head
     * and the guest dies on the re-decode, e.g. test_h1_smc case 2).
     * NOTE: that single-step path stays coherent because
     * i686_spurious_emulate (signals_subpage.c:766,891) calls
     * i686_dbt_invalidate_range(ctx, va, va + len) after emulating
     * the store. */
    if (g_dbt_run_ctx->vm_regime == I686_VM_REGIME_A2 && h > SMC_PAGE) {
        for (off = 0U; off < h; off += SMC_PAGE) {
            if ((i686_vm_file_flags(hbase + off) & 0x80u) == 0u ||
                (i686_vm_file_prot(hbase + off) & 0x03u) != 0x03u) {
                return 0;
            }
        }
    }
    /* Same-thread re-entry (a signal arriving mid-critical-section on
     * this thread): never block on our own lock; the store cannot be
     * an SMC fault we can resolve here, so let the outer handler run. */
    if (g_smc_lock_depth > 0) {
        return 0;
    }
    smc_lock_acquire();
    if (smc_page_marked(page) == 0) {
        /* Lost race: a sibling thread just unprotected this host page
         * and dropped its own blocks. This thread's cache still holds
         * stale blocks, so re-verify writability (I686-3 + A2
         * siblings), restore + drop locally, and let the store retry
         * cleanly instead of faulting again spuriously. */
        uint32_t rwprot = 0U;
        int ok = 0;

        if (i686_fault_region_prot(g_dbt_run_ctx, page, &rwprot, NULL) != 0 &&
            (rwprot & 0x02U) != 0U) {
            ok = 1;
            if (g_dbt_run_ctx->vm_regime == I686_VM_REGIME_A2 &&
                h > SMC_PAGE) {
                for (off = 0U; off < h; off += SMC_PAGE) {
                    if ((i686_vm_file_flags(hbase + off) & 0x80u) == 0u ||
                        (i686_vm_file_prot(hbase + off) & 0x03u) != 0x03u) {
                        ok = 0;
                        break;
                    }
                }
            }
        }
        if (ok == 0) {
            smc_lock_release();
            return 0;
        }
    } else if (g_dbt_run_ctx->vm_regime == I686_VM_REGIME_A2 &&
               h > SMC_PAGE) {
        /* Still marked: re-run the sibling probe under the lock so a
         * concurrent unprotect cannot slip in between the pre-lock
         * probe above and the mutation below. */
        for (off = 0U; off < h; off += SMC_PAGE) {
            if ((i686_vm_file_flags(hbase + off) & 0x80u) == 0u ||
                (i686_vm_file_prot(hbase + off) & 0x03u) != 0x03u) {
                smc_lock_release();
                return 0;
            }
        }
    }
    smc_unprotect_host(g_dbt_run_ctx, hbase, h);
    smc_drop_host(g_dbt_run_ctx, hbase, h);
    /* SMC write commit (I686-R9-6): the re-executed store diverts the
     * MAP_PRIVATE file page(s), so mark them DIRTY before returning.
     * promote_cow is a safe no-op on anonymous/non-COW sub-pages; the
     * whole host span is covered so a store straddling page + 4096
     * inside the same host page still promotes its second half. */
    for (off = 0U; off < h; off += SMC_PAGE) {
        (void)i686_vm_file_promote_cow(hbase + off, SMC_PAGE);
    }
    smc_lock_release();
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
