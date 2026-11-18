/*
 * src/dbt/engine_internal.h — internal state shared between engine.c and engine_smc.c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_DBT_ENGINE_INTERNAL_H
#define I686RT_DBT_ENGINE_INTERNAL_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "i686rt.h"

#define DBT_HT_BITS 18U /* per-thread slots (engine_tcache.c) */
#define DBT_HT_SIZE (1U << DBT_HT_BITS)

#define SMC_PAGE  4096U
#define SMC_WORDS (0x100000000ULL / SMC_PAGE / 32U)

typedef struct dbt_entry {
    uint32_t eip;
    uint32_t len;       /* 0 = empty (host AArch64 code bytes) */
    /* Decoded x86 guest span (end_eip - eip); valid iff len != 0.
     * Written together with len at publish; evict sites leave a
     * stale-but-unread span, and every reader gates on len != 0.
     * Full 32-bit width: must never truncate the block span. */
    uint32_t guest_len;
    uint32_t page_gen;  /* snapshot of g_dbt_page_gen[eip >> 12] */
    uint32_t page_gen1; /* snapshot of g_dbt_page_gen[((eip >> 12) + 1) & 0xFFFFF] */
    uint8_t *code;      /* mmap RX */
    size_t   cap;
} dbt_entry_t;

/* Per-thread DBT_HT_SIZE arrays, NULL until dbt_tcache_ensure(). */
extern __thread dbt_entry_t *g_dbt_ht;
extern __thread uint64_t    *g_dbt_site_start;
extern __thread uint64_t    *g_dbt_site_end;
extern __thread uint32_t    *g_dbt_site_eip;
/* Dense list of ever-populated slots: scans walk
 * g_dbt_active[0 .. g_dbt_nactive) instead of all DBT_HT_SIZE slots.
 * g_dbt_in_active[h] is 1 iff h is currently listed. Both live in the
 * same s_tcache_map allocation; NULL until dbt_tcache_ensure(). */
extern __thread uint32_t *g_dbt_active;
extern __thread uint8_t  *g_dbt_in_active;
extern __thread uint32_t  g_dbt_nactive;
static inline void dbt_active_record(uint32_t h)
{
    if (g_dbt_in_active[h] == 0U) {
        g_dbt_in_active[h] = 1U;
        g_dbt_active[g_dbt_nactive++] = h;
    }
}
int dbt_tcache_ensure(void);
/* Release the calling thread's translation cache (translated blocks,
 * fault-site tables and the backing region). Idempotent; safe when the
 * thread never entered the DBT. Runs at guest thread exit
 * (i686_thread_exit_teardown) and as the pthread-key destructor. */
void dbt_tcache_fini(void);
extern __thread i686_ctx_t *g_dbt_run_ctx;

extern _Atomic uint64_t g_dbt_smc_window_base;
extern _Atomic uint64_t g_dbt_smc_window_end;
extern _Atomic uint32_t g_dbt_cache_epoch;
extern _Atomic uint32_t g_dbt_flush_epoch;
extern _Atomic uint32_t g_dbt_page_gen[1U << 20];
/* Process-global per-guest-page "ever compiled" marks (engine_smc.c):
 * set on a block's guest head and tail pages whenever ANY thread compiles
 * a block, even when smc_protect was skipped (I686RT_SMC_OFF / !p0_ok).
 * Lets an interp-mode or exiting thread's invalidate_range() detect pages
 * that hold translated code on sibling threads without consulting its own
 * (possibly NULL) thread-local g_dbt_ht. */
extern _Atomic uint8_t g_dbt_compiled_page[1U << 20];
extern _Atomic uint32_t g_i686_tso_enabled;

void dbt_graveyard_push(uint8_t *code, size_t cap);
void dbt_graveyard_drain(void);
void dbt_sites_clear_hash(uint32_t h);
void dbt_sites_clear_range(uint32_t start, uint32_t end);
void dbt_sites_clear_all(void);
void smc_protect(i686_ctx_t *ctx, uint32_t eip);
void smc_clear_code_pages(void);
void dbt_bump_cache_epoch(void);
void i686_dbt_enable_tso(void);

/* Default-off counters (engine_stats.c, I686RT_STATS). */
enum {
    DBT_STAT_COMPILES, DBT_STAT_EVICT_STALE, DBT_STAT_EVICT_COLL,
    DBT_STAT_MMAP_FAIL, DBT_STAT_XLATE_FAIL, DBT_STAT_PGEN_RETRY,
    DBT_STAT_GROW, DBT_STAT_INTERP_FALLBACK, DBT_STAT_SYNC_FLUSH,
    DBT_STAT_SYNC_SCAN, DBT_STAT_COMPILE_NS, DBT_STAT_SYNC_NS,
    DBT_STAT_DISPATCH, DBT_STAT_EXIT_UNDEF, DBT_STAT_EXIT_SYSCALL,
    DBT_STAT_HOST_FAULT, DBT_STAT_EPOCH_BUMP, DBT_STAT_FLUSH_ALL,
    DBT_STAT_RECOMPILE,
    DBT_STAT_COUNT
};
extern int g_dbt_stats_on;
void dbt_stats_init(void);
void dbt_stat_add(int which, uint64_t n);
uint64_t dbt_stat_now_ns(void);
void i686_dbt_stats_dump(void);
void dbt_stats_tick(void);
void dbt_stats_compiled(uint32_t eip);
void dbt_stats_undef(const i686_ctx_t *ctx, uint32_t eip);
#define DBT_STAT(which) \
    do { if (g_dbt_stats_on) dbt_stat_add((which), 1U); } while (0)

#endif /* I686RT_DBT_ENGINE_INTERNAL_H */
