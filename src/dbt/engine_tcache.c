/*
 * src/dbt/engine_tcache.c — per-thread translation-cache storage
 *
 * The per-thread cache arrays (g_dbt_ht and the fault-site side tables)
 * live in one lazily mmap'd anonymous region instead of static TLS: the
 * AArch64 local-exec TLS model caps .tbss at 16 MiB, and a big C++
 * front end (cc1plus) has far more hot blocks than a TLS-sized table
 * holds.  Untouched pages stay zero-fill, so RSS grows with use.  A
 * pthread-key destructor unmaps the region and the thread's translated
 * blocks when a guest thread exits.  The pointers are NULL until the
 * thread first enters the DBT; every scan treats NULL as an empty cache.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>

#include "dbt/engine_internal.h"

__thread dbt_entry_t *g_dbt_ht;
__thread uint64_t    *g_dbt_site_start;
__thread uint64_t    *g_dbt_site_end;
__thread uint32_t    *g_dbt_site_eip;
__thread uint32_t    *g_dbt_active;
__thread uint8_t     *g_dbt_in_active;
__thread uint32_t     g_dbt_nactive;

static __thread void *s_tcache_map;
static pthread_key_t s_tcache_key;
static pthread_once_t s_tcache_once = PTHREAD_ONCE_INIT;
static int s_tcache_key_ok;

static size_t dbt_tcache_bytes(void)
{
    return (size_t)DBT_HT_SIZE *
           (sizeof(dbt_entry_t) + 2U * sizeof(uint64_t) +
            2U * sizeof(uint32_t) + sizeof(uint8_t));
}

static void dbt_tcache_release(void *map)
{
    if (map == NULL || map != s_tcache_map) {
        return;
    }
    dbt_tcache_fini();
}

void dbt_tcache_fini(void)
{
    void *map = s_tcache_map;
    dbt_entry_t *ht = g_dbt_ht;
    uint32_t *act = g_dbt_active;
    uint32_t nact = g_dbt_nactive;
    uint32_t idx;

    if (map == NULL) {
        return;
    }
    /* Publish the teardown first: an async-signal fault scan must observe
     * NULL/zero (an empty cache) rather than half-unmapped memory. */
    g_dbt_nactive = 0U;
    s_tcache_map = NULL;
    g_dbt_ht = NULL;
    g_dbt_active = NULL;
    g_dbt_in_active = NULL;
    g_dbt_site_start = NULL;
    g_dbt_site_end = NULL;
    g_dbt_site_eip = NULL;
    atomic_signal_fence(memory_order_seq_cst);
    for (idx = 0U; idx < nact; idx++) {
        uint32_t h = act[idx];
        if (ht[h].len != 0U) {
            (void)munmap(ht[h].code, ht[h].cap);
        }
    }
    /* s_graveyard is __thread (engine.c): draining here retires only this
     * thread's own evicted blocks, never a sibling's live ones. */
    dbt_graveyard_drain();
    (void)munmap(map, dbt_tcache_bytes());
    /* Drop the key value so the pthread-key destructor (if it still
     * runs for this thread) sees a NULL value and stays a no-op. */
    if (s_tcache_key_ok) {
        (void)pthread_setspecific(s_tcache_key, NULL);
    }
}

static void dbt_tcache_make_key(void)
{
    s_tcache_key_ok =
        (pthread_key_create(&s_tcache_key, dbt_tcache_release) == 0);
}

int dbt_tcache_ensure(void)
{
    uint8_t *p;
    size_t n = DBT_HT_SIZE;

    if (g_dbt_ht != NULL) {
        return 0;
    }
    p = mmap(NULL, dbt_tcache_bytes(), PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        return -1;
    }
    s_tcache_map = p;
    /* Layout: entries, site_start, site_end, site_eip, active, in_active.
     * n * 48 is 4-aligned, so the u32 views stay aligned. */
    g_dbt_ht = (dbt_entry_t *)(void *)p;
    g_dbt_site_start = (uint64_t *)(void *)(p + n * sizeof(dbt_entry_t));
    g_dbt_site_end = g_dbt_site_start + n;
    g_dbt_site_eip = (uint32_t *)(void *)(g_dbt_site_end + n);
    g_dbt_active = g_dbt_site_eip + n;
    g_dbt_in_active = (uint8_t *)(void *)(g_dbt_active + n);
    (void)pthread_once(&s_tcache_once, dbt_tcache_make_key);
    if (s_tcache_key_ok) {
        (void)pthread_setspecific(s_tcache_key, p);
    }
    return 0;
}
