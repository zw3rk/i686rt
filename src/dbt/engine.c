/*
 * src/dbt/engine.c — DBT engine loop with a per-EIP translate cache
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#ifndef MAP_JIT
#define MAP_JIT 0x0800
#endif
#endif

#include "dbt/aot/aot.h"
#include "dbt/emit.h"
#include "dbt/engine_internal.h"
#include "interp/interp.h"

extern uint64_t i686_fault_host_pc(void);

uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                            void *cur_entry, const void *epoch_ptr);

#ifdef __APPLE__
static pthread_mutex_t s_jit_toggle_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread bool s_jit_toggle_locked = false;
#endif

_Static_assert(I686_EXIT_BRANCH == 1U,
               "trampoline pins I686_EXIT_BRANCH == 1");
_Static_assert(offsetof(i686_ctx_t, exit_reason) == 120,
               "trampoline pins exit_reason @0x78");
_Static_assert(offsetof(i686_ctx_t, exit_dest) == 132,
               "trampoline pins exit_dest @0x84");
_Static_assert(offsetof(i686_ctx_t, ibtc) == 2536,
               "trampoline pins ibtc @0x9e8 (2536)");
_Static_assert(sizeof(i686_ibtc_entry_t) == 32,
               "trampoline pins the 32-byte IBTC entry stride");
_Static_assert(offsetof(i686_ibtc_entry_t, key) == 0,
               "trampoline pins ibtc entry.key @0");
_Static_assert(offsetof(i686_ibtc_entry_t, epoch) == 4,
               "trampoline pins ibtc entry.epoch @4");
_Static_assert(offsetof(i686_ibtc_entry_t, host_code) == 8,
               "trampoline pins ibtc entry.host_code @8");
_Static_assert(offsetof(i686_ctx_t, ibtc_hits) == 464,
               "trampoline pins ibtc_hits @0x1d0 (464)");

__thread i686_ctx_t *g_dbt_run_ctx;

static __thread uint32_t s_local_cache_epoch;
static __thread uint32_t s_local_flush_epoch;

static int s_trace_dbt;
static int s_trace_blocks;

static __thread struct {
    uint8_t *code;
    size_t cap;
} s_graveyard[256];
static __thread size_t s_graveyard_n;

static __thread uint64_t s_last_remap_ga = UINT64_C(0xFFFFFFFFFFFFFFFF);
static __thread volatile sig_atomic_t s_in_dbt_step;
static __thread uint32_t s_step_esp;
static __thread uint32_t s_step_ebp;
static __thread uint32_t s_step_eip;
static __thread uint32_t s_step_eflags;
static __thread uint32_t s_step_lazy[6];

void dbt_graveyard_push(uint8_t *code, size_t cap)
{
    size_t j;

    if (s_graveyard_n == 256U) {
        munmap(s_graveyard[0].code, s_graveyard[0].cap);
        for (j = 1U; j < s_graveyard_n; j++) {
            s_graveyard[j - 1U] = s_graveyard[j];
        }
        s_graveyard_n--;
    }
    s_graveyard[s_graveyard_n].code = code;
    s_graveyard[s_graveyard_n].cap = cap;
    s_graveyard_n++;
}

void dbt_graveyard_drain(void)
{
    size_t i;

    for (i = 0U; i < s_graveyard_n; i++) {
        munmap(s_graveyard[i].code, s_graveyard[i].cap);
    }
    s_graveyard_n = 0U;
}

static void dbt_ibtc_sever(i686_ctx_t *ctx, uint32_t eip)
{
    i686_ibtc_entry_t *slot = &ctx->ibtc[i686_ibtc_hash(eip)];

    if (slot->key == eip) {
        slot->key = 0U;
        slot->epoch = 0U;
        slot->host_code = NULL;
        slot->entry = NULL;
    }
}

void dbt_sites_clear_hash(uint32_t h)
{
    g_dbt_site_start[h] = 0U;
    g_dbt_site_end[h] = 0U;
    g_dbt_site_eip[h] = 0xFFFFFFFFU;
}

void dbt_sites_clear_range(uint32_t start, uint32_t end)
{
    uint32_t idx;
    if (g_dbt_ht == NULL) {
        return;
    }
    for (idx = 0U; idx < g_dbt_nactive; idx++) {
        uint32_t h = g_dbt_active[idx];
        if (g_dbt_site_end[h] > g_dbt_site_start[h] &&
            g_dbt_site_eip[h] >= start && g_dbt_site_eip[h] < end) {
            dbt_sites_clear_hash(h);
        }
    }
}

void dbt_sites_clear_all(void)
{
    uint32_t idx;
    if (g_dbt_ht == NULL) {
        return;
    }
    for (idx = 0U; idx < g_dbt_nactive; idx++) {
        dbt_sites_clear_hash(g_dbt_active[idx]);
    }
}

/* Synchronize the calling thread's private s_ht / IBTC / RAS against
 * cross-thread SMC, range invalidation, or full-cache flushes (I686-2). */
static void dbt_sync_thread_cache(i686_ctx_t *ctx)
{
    uint32_t cur_epoch = atomic_load_explicit(&g_dbt_cache_epoch,
                                              memory_order_acquire);
    uint32_t cur_flush;
    size_t i;
    uint32_t idx;

    uint64_t t0 = 0U;

    if (s_local_cache_epoch == cur_epoch) {
        return;
    }
    if (g_dbt_stats_on) {
        t0 = dbt_stat_now_ns();
    }
    cur_flush = atomic_load_explicit(&g_dbt_flush_epoch, memory_order_acquire);
    if (g_dbt_ht == NULL) {
        s_local_flush_epoch = cur_flush; /* empty cache: nothing to drop */
    } else if (s_local_flush_epoch != cur_flush) {
        DBT_STAT(DBT_STAT_SYNC_FLUSH);
        for (idx = 0U; idx < g_dbt_nactive; idx++) {
            uint32_t h = g_dbt_active[idx];
            dbt_sites_clear_hash(h);
            if (g_dbt_ht[h].len != 0U) {
                g_dbt_ht[h].eip = 0xFFFFFFFFU;
                dbt_graveyard_push(g_dbt_ht[h].code, g_dbt_ht[h].cap);
                g_dbt_ht[h].code = NULL;
                g_dbt_ht[h].cap = 0U;
                g_dbt_ht[h].len = 0U;
            }
            g_dbt_in_active[h] = 0U;
        }
        g_dbt_nactive = 0U;
        s_local_flush_epoch = cur_flush;
    } else {
        uint32_t w = 0U;
        DBT_STAT(DBT_STAT_SYNC_SCAN);
        for (idx = 0U; idx < g_dbt_nactive; idx++) {
            uint32_t h = g_dbt_active[idx];
            if (g_dbt_ht[h].len != 0U) {
                uint32_t vpn0 = g_dbt_ht[h].eip >> 12U;
                uint32_t vpn1 = (vpn0 + 1U) & 0xFFFFFU;
                uint32_t pgen0 = atomic_load_explicit(&g_dbt_page_gen[vpn0],
                                                      memory_order_acquire);
                uint32_t pgen1 = atomic_load_explicit(&g_dbt_page_gen[vpn1],
                                                      memory_order_acquire);
                if (pgen0 != g_dbt_ht[h].page_gen ||
                    pgen1 != g_dbt_ht[h].page_gen1) {
                    dbt_sites_clear_hash(h);
                    g_dbt_ht[h].eip = 0xFFFFFFFFU;
                    dbt_graveyard_push(g_dbt_ht[h].code, g_dbt_ht[h].cap);
                    g_dbt_ht[h].code = NULL;
                    g_dbt_ht[h].cap = 0U;
                    g_dbt_ht[h].len = 0U;
                }
            }
            if (g_dbt_ht[h].len != 0U) {
                g_dbt_active[w++] = h;
            } else {
                dbt_sites_clear_hash(h);
                g_dbt_in_active[h] = 0U;
            }
        }
        g_dbt_nactive = w;
    }
    if (ctx != NULL) {
        for (i = 0U; i < I686_IBTC_SIZE; i++) {
            ctx->ibtc[i].key = 0U;
            ctx->ibtc[i].epoch = 0U;
            ctx->ibtc[i].host_code = NULL;
            ctx->ibtc[i].entry = NULL;
        }
        for (i = 0U; i < I686_RAS_SIZE; i++) {
            ctx->ras[i].key = 0U;
            ctx->ras[i].epoch = 0U;
        }
    }
    s_local_cache_epoch = cur_epoch;
    if (g_dbt_stats_on) {
        dbt_stat_add(DBT_STAT_SYNC_NS, dbt_stat_now_ns() - t0);
    }
}

void i686_dbt_trace_enable(int on)
{
    s_trace_dbt = on;
    s_trace_blocks = on && getenv("I686RT_DBTTRACE") != NULL;
    dbt_stats_init();
}

void i686_dbt_fork_child(void)
{
    /* s_tcache_map and the g_dbt_* views (including g_dbt_active /
     * g_dbt_in_active) survive fork via MAP_PRIVATE CoW, so the slot
     * list stays coherent without re-init. */
#ifdef __APPLE__
    (void)pthread_mutex_destroy(&s_jit_toggle_mutex);
    (void)pthread_mutex_init(&s_jit_toggle_mutex, NULL);
    s_jit_toggle_locked = false;
#else
    (void)0;
#endif
}

void i686_dbt_flush_all(void)
{
    uint32_t idx;
    DBT_STAT(DBT_STAT_FLUSH_ALL);
    dbt_sites_clear_all();
    if (g_dbt_ht != NULL) {
        for (idx = 0U; idx < g_dbt_nactive; idx++) {
            uint32_t h = g_dbt_active[idx];
            if (g_dbt_ht[h].len != 0U) {
                munmap(g_dbt_ht[h].code, g_dbt_ht[h].cap);
                g_dbt_ht[h].code = NULL;
                g_dbt_ht[h].cap = 0U;
                g_dbt_ht[h].len = 0U;
            }
            g_dbt_in_active[h] = 0U;
        }
        g_dbt_nactive = 0U;
    }
    smc_clear_code_pages();
    (void)atomic_fetch_add_explicit(&g_dbt_flush_epoch, 1U,
                                    memory_order_acq_rel);
    dbt_bump_cache_epoch();
    s_local_flush_epoch = atomic_load_explicit(&g_dbt_flush_epoch,
                                               memory_order_relaxed);
    s_local_cache_epoch = atomic_load_explicit(&g_dbt_cache_epoch,
                                               memory_order_relaxed);
    if (g_dbt_run_ctx != NULL) {
        for (size_t i = 0U; i < I686_IBTC_SIZE; i++) {
            g_dbt_run_ctx->ibtc[i].key = 0U;
            g_dbt_run_ctx->ibtc[i].epoch = 0U;
            g_dbt_run_ctx->ibtc[i].host_code = NULL;
            g_dbt_run_ctx->ibtc[i].entry = NULL;
        }
    }
    dbt_graveyard_drain();
}

static uint32_t dbt_hash(uint32_t eip)
{
    /* Multiplicative (Fibonacci) hash.  The old eip ^ (eip >> 12) sent
     * every 4 KiB code page onto one 4096-slot bucket (only 2^bits/4096
     * hot pages fit), which thrashed cc1plus into ~15x re-translation. */
    return (eip * 0x9E3779B1U) >> (32U - DBT_HT_BITS);
}

static void i686_dbt_recover_fault(i686_ctx_t *ctx, uint64_t host_pc)
{
    uint32_t h = DBT_HT_SIZE;
    uint32_t idx;
    uint32_t base;
    uint64_t start;
    uint64_t end;
    uint64_t seq;
    uint32_t esp;
    uint32_t fault_off;
    dbt_mem_site_t fault_site;
    bool have_site = false;
#if (defined(__linux__) || defined(__APPLE__)) && defined(__aarch64__)
    bool have_live_esp = true;
#else
    bool have_live_esp = false;
#endif
    uint32_t live_esp = 0U;

    if (host_pc == 0U || g_dbt_ht == NULL) {
        return;
    }
    for (idx = 0U; idx < g_dbt_nactive; idx++) {
        uint32_t i = g_dbt_active[idx];
        uint64_t lo = (uint64_t)(uintptr_t)g_dbt_ht[i].code;
        if (g_dbt_ht[i].len != 0U && host_pc >= lo &&
            host_pc < lo + (uint64_t)g_dbt_ht[i].len) {
            h = i;
            break;
        }
    }
    if (h == DBT_HT_SIZE) {
        return;
    }
    if (have_live_esp) {
        extern uint64_t i686_fault_esp(void);
        live_esp = (uint32_t)i686_fault_esp();
    }
    {
        extern uint64_t i686_fault_gpr(unsigned);
        unsigned r;
        for (r = 0U; r < 8U; r++) {
            ctx->gpr[r] = (uint32_t)i686_fault_gpr(r);
        }
    }
    base = g_dbt_ht[h].eip;
    ctx->eip = base;
    start = g_dbt_site_start[h];
    end = g_dbt_site_end[h];
    if (end <= start || g_dbt_site_eip[h] != base) {
        if (have_live_esp) {
            ctx->gpr[I686_REG_ESP] = live_esp;
        }
        return;
    }
    fault_off = (uint32_t)(host_pc - (uint64_t)(uintptr_t)g_dbt_ht[h].code);
    esp = have_live_esp ? live_esp : ctx->gpr[I686_REG_ESP];
    memset(&fault_site, 0, sizeof(fault_site));
    for (seq = start; seq < end; seq++) {
        dbt_mem_site_t s;
        if (i686_aot_ring_at((size_t)seq, &s) == 0) {
            break;
        }
        if ((uint32_t)s.host_insn_offset < fault_off) {
            if ((uint32_t)s.seq_start_offset <= fault_off &&
                fault_off < (uint32_t)s.cont_insn_offset) {
                fault_site = s;
                have_site = true;
            } else if (!have_live_esp) {
                if ((s.flags & I686_SITE_PRE_COMMITTED_SP) != 0U) {
                    esp = (uint32_t)((int64_t)(int32_t)esp +
                                     (int64_t)s.sp_rollback_delta);
                } else {
                    esp += (uint32_t)s.width;
                }
            }
            continue;
        }
        if ((uint32_t)s.host_insn_offset == fault_off) {
            fault_site = s;
            have_site = true;
        } else if (!have_site && (uint32_t)s.seq_start_offset <= fault_off &&
                   fault_off < (uint32_t)s.cont_insn_offset) {
            fault_site = s;
            have_site = true;
        }
        break;
    }
    if (!have_site) {
        if (have_live_esp) {
            ctx->gpr[I686_REG_ESP] = live_esp;
        }
        return;
    }
    if (fault_site.guest_pc_delta != I686_SITE_PC_UNKNOWN) {
        ctx->eip = base + (uint32_t)fault_site.guest_pc_delta;
    }
    if ((fault_site.flags & I686_SITE_PRE_COMMITTED_SP) != 0U) {
        uint32_t live = have_live_esp
                            ? live_esp
                            : (uint32_t)((int64_t)(int32_t)esp +
                                         (int64_t)fault_site.sp_rollback_delta);
        ctx->gpr[I686_REG_ESP] =
            i686_aot_apply_rollback(live, fault_site.sp_rollback_delta);
    } else {
        ctx->gpr[I686_REG_ESP] = esp;
    }
}

static dbt_entry_t *dbt_get_or_compile(i686_ctx_t *ctx, uint32_t eip)
{
    dbt_entry_t *e;
    size_t cap = 8192U;
    uint32_t vpn0 = eip >> 12U;
    uint32_t vpn1 = (vpn0 + 1U) & 0xFFFFFU;
    uint32_t cur_epoch;
    uint32_t cur_pgen0;
    uint32_t cur_pgen1;
    uint64_t t0 = 0U;

    if (dbt_tcache_ensure() != 0) {
        return NULL;
    }
    dbt_sync_thread_cache(ctx);
    e = &g_dbt_ht[dbt_hash(eip)];
    cur_epoch = atomic_load_explicit(&g_dbt_cache_epoch, memory_order_acquire);
    cur_pgen0 = atomic_load_explicit(&g_dbt_page_gen[vpn0],
                                     memory_order_acquire);
    cur_pgen1 = atomic_load_explicit(&g_dbt_page_gen[vpn1],
                                     memory_order_acquire);
    if (e->len != 0U) {
        if (e->eip == eip && e->page_gen == cur_pgen0 &&
            e->page_gen1 == cur_pgen1) {
            i686_ibtc_entry_t *slot = &ctx->ibtc[i686_ibtc_hash(eip)];
            if (slot->key != eip || slot->epoch != cur_epoch) {
                slot->key = eip;
                slot->epoch = cur_epoch;
                slot->host_code = e->code;
                slot->entry = e->code;
            }
            return e;
        }
        DBT_STAT(e->eip == eip ? DBT_STAT_EVICT_STALE : DBT_STAT_EVICT_COLL);
        dbt_ibtc_sever(ctx, e->eip);
        munmap(e->code, e->cap);
        e->code = NULL;
        e->cap = 0U;
        e->len = 0U;
    }
    if (g_dbt_stats_on) {
        t0 = dbt_stat_now_ns();
    }
    for (;;) {
#ifdef __APPLE__
        uint8_t *code = mmap(NULL, cap, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
        /* I686-11: W^X discipline on Linux — map RW during translation,
         * flush icache, then flip to RX before publishing. */
        uint8_t *code = mmap(NULL, cap, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
        size_t len;
        uint32_t guest_len, tail_pg;
        size_t ring_before;
        uint32_t pre_pgen0;
        uint32_t pre_pgen1;
        uint32_t pre_flush;
        bool smc_on = (getenv("I686RT_SMC_OFF") == NULL);
        if (code == MAP_FAILED) {
            DBT_STAT(DBT_STAT_MMAP_FAIL);
            return NULL;
        }
        /* Sample page_gen BEFORE arming SMC protection and decoding so
         * a concurrent store/VMA-invalidate during translation is caught
         * by the post-translate PGEN_RETRY check (I686-R2-4). On A2
         * host pages hold the sub-page lock with union_prot applied. */
        {
            extern int i686_fault_region_prot(const i686_ctx_t *, uint32_t,
                                              uint32_t *, uint32_t *);
            extern void i686_vm32_subpage_lock(void);
            extern void i686_vm32_subpage_unlock(void);
            extern int i686_vm32_union_prot(i686_ctx_t *, uint32_t, uint32_t);
            extern int i686_vm32_widen_prot(i686_ctx_t *, uint32_t, uint32_t);
            bool a2_subpage = (ctx->vm_regime == I686_VM_REGIME_A2 &&
                               ctx->vm_host_page > 4096U);
            uint32_t rprot0 = 0U;
            uint32_t rprot1 = 0U;
            bool p0_ok = (i686_fault_region_prot(ctx, vpn0 << 12U, &rprot0,
                                                 NULL) != 0 &&
                          (rprot0 & 0x05U) != 0U);
            bool p1_ok = ((eip & 0xFFFU) >= 0xC00U &&
                          i686_fault_region_prot(ctx, vpn1 << 12U, &rprot1,
                                                 NULL) != 0 &&
                          (rprot1 & 0x05U) != 0U);

            pre_pgen0 = atomic_load_explicit(&g_dbt_page_gen[vpn0],
                                             memory_order_acquire);
            pre_pgen1 = atomic_load_explicit(&g_dbt_page_gen[vpn1],
                                             memory_order_acquire);
            pre_flush = atomic_load_explicit(&g_dbt_flush_epoch,
                                             memory_order_acquire);
            if (a2_subpage && p0_ok) {
                i686_vm32_subpage_lock();
                (void)i686_vm32_union_prot(ctx, vpn0 << 12U,
                                           (vpn0 << 12U) + 0x1000U);
                if (p1_ok) {
                    (void)i686_vm32_union_prot(ctx, vpn1 << 12U,
                                               (vpn1 << 12U) + 0x1000U);
                }
            } else if (smc_on && p0_ok) {
                smc_protect(ctx, eip);
                if (p1_ok) {
                    smc_protect(ctx, vpn1 << 12U);
                }
            }
#ifdef __APPLE__
            (void)pthread_mutex_lock(&s_jit_toggle_mutex);
            s_jit_toggle_locked = true;
            pthread_jit_write_protect_np(0);
#endif
            ring_before = i686_aot_ring_count();
            len = i686_dbt_translate(ctx, eip, code, cap);
            guest_len = i686_dbt_last_guest_len();
            tail_pg = (eip + (guest_len > 0U ? guest_len - 1U : 0U)) &
                ~(SMC_PAGE - 1U);
#ifdef __APPLE__
            pthread_jit_write_protect_np(1);
            s_jit_toggle_locked = false;
            (void)pthread_mutex_unlock(&s_jit_toggle_mutex);
#endif
            if (len == 0U) {
                if (a2_subpage && p0_ok) {
                    (void)i686_vm32_widen_prot(ctx, vpn0 << 12U,
                                               (vpn0 << 12U) + 0x1000U);
                    if (p1_ok) {
                        (void)i686_vm32_widen_prot(ctx, vpn1 << 12U,
                                                   (vpn1 << 12U) + 0x1000U);
                    }
                    i686_vm32_subpage_unlock();
                }
                DBT_STAT(DBT_STAT_XLATE_FAIL);
                munmap(code, cap);
                dbt_sites_clear_hash(dbt_hash(eip));
                return NULL;
            }
            if (a2_subpage && p0_ok) {
                if (smc_on && len > 0U && len < cap) {
                    smc_protect(ctx, eip);
                    if (p1_ok) {
                        smc_protect(ctx, vpn1 << 12U);
                    }
                    if (tail_pg != (eip & ~0xFFFU) &&
                        tail_pg != (vpn1 << 12U)) {
                        smc_protect(ctx, tail_pg);
                    }
                } else {
                    (void)i686_vm32_widen_prot(ctx, vpn0 << 12U,
                                               (vpn0 << 12U) + 0x1000U);
                    if (p1_ok) {
                        (void)i686_vm32_widen_prot(ctx, vpn1 << 12U,
                                                   (vpn1 << 12U) + 0x1000U);
                    }
                }
                i686_vm32_subpage_unlock();
            }
            /* Non-A2: also write-protect a tail page the block crossed into. */
            if (!a2_subpage && smc_on && p0_ok && len > 0U && len < cap) {
                if (tail_pg != (eip & ~(SMC_PAGE - 1U))) {
                    uint32_t rprotT = 0U;
                    if (i686_fault_region_prot(ctx, tail_pg, &rprotT,
                                              NULL) != 0 &&
                        (rprotT & 0x05U) != 0U) {
                        smc_protect(ctx, tail_pg);
                    }
                }
            }
        }
        if (len < cap) {
            uint32_t h = dbt_hash(eip);
            /* Ever-compiled marks BEFORE the PGEN re-check (seq_cst). */
            atomic_store_explicit(&g_dbt_compiled_page[vpn0], 1U,
                                  memory_order_seq_cst);
            atomic_store_explicit(&g_dbt_compiled_page[tail_pg >> 12U], 1U,
                                  memory_order_seq_cst);
            uint32_t post_pgen0 = atomic_load_explicit(&g_dbt_page_gen[vpn0],
                                                       memory_order_acquire);
            uint32_t post_pgen1 = atomic_load_explicit(&g_dbt_page_gen[vpn1],
                                                       memory_order_acquire);
            uint32_t post_flush = atomic_load_explicit(&g_dbt_flush_epoch,
                                                       memory_order_acquire);
            if (post_pgen0 != pre_pgen0 || post_pgen1 != pre_pgen1 ||
                post_flush != pre_flush) {
                DBT_STAT(DBT_STAT_PGEN_RETRY);
                munmap(code, cap);
                dbt_sites_clear_hash(h);
                dbt_sync_thread_cache(ctx);
                continue;
            }
#ifdef __APPLE__
            sys_icache_invalidate(code, len);
#else
            __builtin___clear_cache((char *)code, (char *)(code + len));
            if (mprotect(code, cap, PROT_READ | PROT_EXEC) != 0) {
                munmap(code, cap);
                dbt_sites_clear_hash(h);
                return NULL;
            }
#endif
            ctx->wx_transitions++;
            if (g_dbt_stats_on) {
                dbt_stat_add(DBT_STAT_COMPILES, 1U);
                dbt_stats_compiled(eip);
                dbt_stat_add(DBT_STAT_COMPILE_NS, dbt_stat_now_ns() - t0);
            }
            cur_epoch = atomic_load_explicit(&g_dbt_cache_epoch,
                                             memory_order_acquire);
            dbt_active_record(h);
            e->eip = eip;
            e->len = (uint32_t)len;
            e->guest_len = guest_len;
            e->page_gen = pre_pgen0;
            e->page_gen1 = pre_pgen1;
            e->code = code;
            e->cap = cap;
            g_dbt_site_start[h] = (uint64_t)ring_before;
            g_dbt_site_end[h] = (uint64_t)i686_aot_ring_count();
            g_dbt_site_eip[h] = eip;
            ctx->ibtc[i686_ibtc_hash(eip)] = (i686_ibtc_entry_t){
                .key = eip,
                .epoch = cur_epoch,
                .host_code = code,
                .entry = code
            };
            return e;
        }
        DBT_STAT(DBT_STAT_GROW);
        munmap(code, cap);
        cap *= 2U;
        if (cap > 1U << 20) {
            return NULL;
        }
    }
}

int i686_dbt_run(i686_ctx_t *ctx)
{
    extern void i686_host_faults_install(void);
    extern void i686_fault_arm(sigjmp_buf *jb);
    extern void i686_fault_disarm(void);
    extern uint64_t i686_fault_addr(void);
    static int s_dbt_faults_installed;
    sigjmp_buf fj;

    if (!s_dbt_faults_installed) {
        s_dbt_faults_installed = 1;
        i686_host_faults_install();
    }
    g_dbt_run_ctx = ctx;
    atomic_store_explicit(&g_dbt_smc_window_base, ctx->guest_base,
                          memory_order_relaxed);
    atomic_store_explicit(&g_dbt_smc_window_end,
                          ctx->guest_base + 0x100000000ULL,
                          memory_order_relaxed);
    if (sigsetjmp(fj, 1) != 0) {
        extern void i686_vm32_exec_leave(void);
        uint64_t fa = i686_fault_addr();
        extern int i686_deliver_sync(i686_ctx_t *, int);
        extern int i686_fault_region_prot(const i686_ctx_t *, uint32_t,
                                          uint32_t *, uint32_t *);

        i686_vm32_exec_leave();
        i686_split_lock_release_if_held();
#ifdef __APPLE__
        /* I686-12: only unlock s_jit_toggle_mutex when this thread owns it. */
        if (s_jit_toggle_locked) {
            pthread_jit_write_protect_np(1);
            s_jit_toggle_locked = false;
            (void)pthread_mutex_unlock(&s_jit_toggle_mutex);
        }
#endif
        i686_fault_arm(&fj);
        if (fa >= ctx->guest_base &&
            fa < ctx->guest_base + 0x100000000ULL) {
            ctx->fault_addr = (uint32_t)(fa - ctx->guest_base);
        } else {
            ctx->fault_addr = (uint32_t)fa;
        }
        if (s_in_dbt_step != 0) {
            s_in_dbt_step = 0;
            ctx->gpr[I686_REG_ESP] = s_step_esp;
            ctx->gpr[I686_REG_EBP] = s_step_ebp;
            ctx->eip = s_step_eip;
            ctx->eflags = s_step_eflags;
            ctx->lazy_op = s_step_lazy[0];
            ctx->lazy_res = s_step_lazy[1];
            ctx->lazy_src1 = s_step_lazy[2];
            ctx->lazy_src2 = s_step_lazy[3];
            ctx->lazy_cf_in = s_step_lazy[4];
            ctx->lazy_width = s_step_lazy[5];
        } else {
            i686_dbt_recover_fault(ctx, i686_fault_host_pc());
        }
        if (fa >= ctx->guest_base &&
            fa < ctx->guest_base + 0x100000000ULL) {
            extern int i686_vm32_widen_prot(i686_ctx_t *, uint32_t, uint32_t);
            extern int i686_spurious_emulate(i686_ctx_t *, uint32_t);
            extern int i686_spurious_allow(i686_ctx_t *, uint32_t);
            uint32_t rga = (uint32_t)(fa - ctx->guest_base);
            if (rga != (uint32_t)s_last_remap_ga &&
                i686_fault_region_prot(ctx, rga, NULL, NULL) != 0) {
                ctx->exit_reason = I686_EXIT_NONE;
                if (i686_spurious_emulate(ctx, rga) == 0) {
                    if (ctx->exit_reason == I686_EXIT_SYSCALL) {
                        i686_fault_disarm();
                        return I686_EXIT_SYSCALL;
                    }
                    goto dispatch;
                }
                if ((ctx->vm_regime != I686_VM_REGIME_A2 ||
                     ctx->vm_host_page <= 4096u) &&
                    i686_spurious_allow(ctx, rga) != 0 &&
                    i686_vm32_widen_prot(ctx, rga & ~0xFFFU,
                                         (rga & ~0xFFFU) + 0x1000U) == 0) {
                    s_last_remap_ga = (uint64_t)rga;
                    goto dispatch;
                }
            }
        }
        s_last_remap_ga = UINT64_C(0xFFFFFFFFFFFFFFFF);
        if (i686_deliver_sync(ctx, I686_EXIT_FAULT) == 0) {
            goto dispatch;
        }
        {
            extern void i686_diag_fault(i686_ctx_t *ctx);
            i686_diag_fault(ctx);
        }
        ctx->exit_reason = I686_EXIT_FAULT;
        return I686_EXIT_FAULT;
    }
    i686_fault_arm(&fj);
dispatch:
    for (;;) {
        extern void i686_vm32_exec_enter(const i686_ctx_t *);
        extern void i686_vm32_exec_leave(void);
        dbt_sync_thread_cache(ctx);
        dbt_graveyard_drain();
        {
            /* R7-9: every segment assumption baked into emitted code is
             * gated here (CS flatness, GDT-only data, live stack/data
             * selectors, 32-bit stack); the interpreter enforces the
             * rest until emitted checks exist. */
            extern bool i686_seg_dbt_eligible(const i686_ctx_t *ctx);
            if (!i686_seg_dbt_eligible(ctx) || ctx->v86 != 0U) {
                i686_fault_disarm();
                return i686_interp_run(ctx);
            }
        }
        if (ctx->pending_signals != 0U) {
            extern int i686_deliver_pending(i686_ctx_t *);
            if (i686_deliver_pending(ctx) == 0) {
                continue;
            }
        }
        if (g_dbt_stats_on) {
            dbt_stats_tick();
        }
        i686_vm32_exec_enter(ctx);
        dbt_entry_t *e = dbt_get_or_compile(ctx, ctx->eip);
        int r;

        if (e == NULL) {
            /* Untranslatable block: interpret one insn, then resume (D2).
             * Publish the same exit fields the translated path sets so
             * handle_exit never reads a stale reason/arg. */
            DBT_STAT(DBT_STAT_INTERP_FALLBACK);
            i686_vm32_exec_leave();
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = 0U;
            ctx->exit_dest = ctx->eip;
            r = I686_EXIT_UNDEF;
            goto handle_exit;
        }
        ctx->exit_reason = I686_EXIT_NONE;
        ctx->exit_arg = 0U;
        if (s_trace_blocks) {
            (void)fprintf(stderr, "B %08x\n", ctx->eip);
        }
        (void)i686_jit_run_block(ctx, e->code, NULL,
                                 (const void *)&g_dbt_cache_epoch);
        i686_vm32_exec_leave();
        ctx->blocks_executed++;

        r = (int)ctx->exit_reason;
        if (g_dbt_stats_on) {
            if (r == I686_EXIT_UNDEF) {
                dbt_stat_add(DBT_STAT_EXIT_UNDEF, 1U);
                dbt_stats_undef(ctx, ctx->exit_dest);
            } else if (r == I686_EXIT_SYSCALL) {
                dbt_stat_add(DBT_STAT_EXIT_SYSCALL, 1U);
            }
        }
handle_exit:
        switch (r) {
        case I686_EXIT_BRANCH:
            ctx->eip = ctx->exit_dest;
            continue;
        case I686_EXIT_SYSCALL: {
            extern long i686_handle_syscall(i686_ctx_t *);
            extern int i686_syscall_is_exit(long);
            long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
            long rv = i686_handle_syscall(ctx);
            if (s_trace_dbt) {
                (void)fprintf(stderr, "S %ld -> %ld\n", nr, rv);
            }
            if (i686_syscall_is_exit(nr)) {
                ctx->exit_arg = (uint32_t)rv;
                return I686_EXIT_SYSCALL;
            }
            continue;
        }
        case I686_EXIT_UNDEF: {
            extern int i686_interp_step(i686_ctx_t *ctx);
            int ir;
            ctx->eip = ctx->exit_dest;
            s_step_esp = ctx->gpr[I686_REG_ESP];
            s_step_ebp = ctx->gpr[I686_REG_EBP];
            s_step_eip = ctx->eip;
            s_step_eflags = ctx->eflags;
            s_step_lazy[0] = ctx->lazy_op;
            s_step_lazy[1] = ctx->lazy_res;
            s_step_lazy[2] = ctx->lazy_src1;
            s_step_lazy[3] = ctx->lazy_src2;
            s_step_lazy[4] = ctx->lazy_cf_in;
            s_step_lazy[5] = ctx->lazy_width;
            s_in_dbt_step = 1;
            ir = i686_interp_step(ctx);
            s_in_dbt_step = 0;
            if (ir == I686_INTERP_CONTINUE) {
                continue;
            }
            if (ir == I686_EXIT_SYSCALL) {
                extern long i686_handle_syscall(i686_ctx_t *);
                extern int i686_syscall_is_exit(long);
                long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
                long rv = i686_handle_syscall(ctx);
                if (s_trace_dbt) {
                    (void)fprintf(stderr, "S %ld -> %ld\n", nr, rv);
                }
                if (i686_syscall_is_exit(nr)) {
                    ctx->exit_arg = (uint32_t)rv;
                    i686_fault_disarm();
                    return I686_EXIT_SYSCALL;
                }
                continue;
            }
            /* R7-22: the stepped UNDEF joins FAULT/TRAP on the
             * single delivery path (step leaves eip at the
             * faulting insn, or past it for traps). */
            if (ir == I686_EXIT_FAULT || ir == I686_EXIT_TRAP ||
                ir == I686_EXIT_UNDEF) {
                extern int i686_deliver_sync(i686_ctx_t *, int);
                extern void i686_diag_fault(i686_ctx_t *);
                if (i686_deliver_sync(ctx, ir) == 0) {
                    goto dispatch;
                }
                i686_diag_fault(ctx);
                i686_fault_disarm();
                return ir;
            }
            i686_fault_disarm();
            return ir;
        }
        case I686_EXIT_TRAP:
        case I686_EXIT_FAULT: {
            /* R7-22: direct DBT traps/faults deliver guest
             * signals (SIGTRAP/SIGSEGV/...); exit_dest carries
             * the fault-vs-trap EIP (at vs past the insn). */
            extern int i686_deliver_sync(i686_ctx_t *, int);
            extern void i686_diag_fault(i686_ctx_t *);
            ctx->eip = ctx->exit_dest;
            if (i686_deliver_sync(ctx, r) == 0) {
                goto dispatch;
            }
            i686_diag_fault(ctx);
            i686_fault_disarm();
            return r;
        }
        case I686_EXIT_HLT:
            i686_fault_disarm();
            return r;
        default:
            i686_fault_disarm();
            return r;
        }
    }
}
