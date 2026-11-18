/*
 * src/dbt/engine_stats.c — default-off DBT cache/compile counters
 *
 * Enabled by I686RT_STATS (non-"0"), read once by dbt_stats_init().  When
 * off, every probe is one predictable branch on g_dbt_stats_on.  Counters
 * are process-wide relaxed atomics (guest threads share them); the
 * timers sum CLOCK_MONOTONIC nanoseconds spent in the measured phase.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dbt/engine_internal.h"

int g_dbt_stats_on;
static _Atomic uint64_t s_dbt_stat[DBT_STAT_COUNT];

static const char *const s_dbt_stat_name[] = {
    "compiles", "evict_stale", "evict_coll", "mmap_fail", "xlate_fail",
    "pgen_retry", "grow", "interp_fallback", "sync_flush", "sync_scan",
    "compile_ns", "sync_ns", "dispatch", "exit_undef", "exit_syscall",
    "host_fault", "epoch_bump", "flush_all", "recompile"
};

/* The dump indexes this table by DBT_STAT_*; a new counter without a
 * name must break the build instead of printing a NULL name. */
_Static_assert(sizeof(s_dbt_stat_name) / sizeof(s_dbt_stat_name[0]) ==
                   (size_t)DBT_STAT_COUNT,
               "s_dbt_stat_name must match DBT_STAT_COUNT");

/* UNDEF-exit opcode histogram: index = primary opcode byte, 0x100 |
 * second byte for the 0F map, 0x200 | reg for the FF group; +0x400 when
 * an FS/GS segment prefix was present (prefixes otherwise skipped). */
#define UNDEF_HIST 0x800
static _Atomic uint64_t s_dbt_undef_op[UNDEF_HIST];
static _Atomic uint64_t s_dbt_last_dump_ns;

void dbt_stats_init(void)
{
    const char *s = getenv("I686RT_STATS");
    g_dbt_stats_on = (s != NULL && strcmp(s, "0") != 0) ? 1 : 0;
}

void dbt_stat_add(int which, uint64_t n)
{
    if (which >= 0 && which < (int)DBT_STAT_COUNT) {
        atomic_fetch_add_explicit(&s_dbt_stat[which], n,
                                  memory_order_relaxed);
    }
}

uint64_t dbt_stat_now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0U;
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

/* Seen-EIP set (open addressing, stats-only, allocated on first use):
 * distinguishes re-translation of an evicted block from a first compile. */
#define SEEN_BITS 22U
static uint32_t *s_dbt_seen;

void dbt_stats_compiled(uint32_t eip)
{
    uint32_t key = eip + 1U; /* 0 marks an empty slot */
    uint32_t mask = (1U << SEEN_BITS) - 1U;
    uint32_t h = (key * 0x9E3779B1U) >> (32U - SEEN_BITS);
    uint32_t probes;

    if (s_dbt_seen == NULL) {
        s_dbt_seen = calloc((size_t)1U << SEEN_BITS, sizeof(uint32_t));
        if (s_dbt_seen == NULL) {
            return;
        }
    }
    for (probes = 0U; probes <= mask; probes++) {
        if (s_dbt_seen[h] == key) {
            dbt_stat_add(DBT_STAT_RECOMPILE, 1U);
            return;
        }
        if (s_dbt_seen[h] == 0U) {
            s_dbt_seen[h] = key;
            return;
        }
        h = (h + 1U) & mask;
    }
}

/* Stats-only fetch of the bytes the undef histogram classifies: a block
 * can exit with UNDEF on an instruction straddling the end of a mapping,
 * so every byte is gated on a readable guest page first and the histogram
 * simply sees a truncated prefix instead of faulting host code. */
#define UNDEF_FETCH_MAX 17U
static unsigned stats_fetch_undef(const i686_ctx_t *ctx, uint32_t eip,
                                  uint8_t out[UNDEF_FETCH_MAX])
{
    extern int i686_fault_region_prot(const i686_ctx_t *, uint32_t,
                                      uint32_t *, uint32_t *);
    unsigned n = 0U;

    if (ctx == NULL) {
        return 0U;
    }
    for (n = 0U; n < UNDEF_FETCH_MAX; n++) {
        uint32_t va = eip + (uint32_t)n;
        uint32_t prot = 0U;

        if (i686_fault_region_prot(ctx, va, &prot, NULL) == 0 ||
            (prot & 0x01U) == 0U) {
            break;
        }
        out[n] = *(const uint8_t *)i686_guest_ptr(ctx, va);
    }
    return n;
}

/* Record the opcode of an instruction a translated block bailed on.
 * Only called for block exits, whose bytes the translator just decoded. */
void dbt_stats_undef(const i686_ctx_t *ctx, uint32_t eip)
{
    uint8_t buf[UNDEF_FETCH_MAX];
    unsigned avail = stats_fetch_undef(ctx, eip, buf);
    unsigned k;
    unsigned n;
    unsigned b = 0U;
    unsigned fsgs = 0U;

    if (avail == 0U) {
        return;
    }
    for (n = 0U; n < 15U && n < avail; n++) {
        b = buf[n];
        if (b == 0x64U || b == 0x65U) {
            fsgs = 0x400U;
        }
        if (b != 0x66U && b != 0xF2U && b != 0xF3U && b != 0xF0U &&
            b != 0x2EU && b != 0x36U && b != 0x3EU && b != 0x26U &&
            b != 0x64U && b != 0x65U) {
            break;
        }
    }
    k = b;
    if (b == 0x0FU) {
        if (n + 1U >= avail) {
            return;
        }
        k = 0x100U | buf[n + 1U];
    } else if (b == 0xFFU) {
        if (n + 1U >= avail) {
            return;
        }
        k = 0x200U | ((buf[n + 1U] >> 3) & 7U);
    }
    k |= fsgs;
    atomic_fetch_add_explicit(&s_dbt_undef_op[k], 1U, memory_order_relaxed);
}

void i686_dbt_stats_dump(void)
{
    int i;
    int top;
    uint64_t seen[UNDEF_HIST];

    if (!g_dbt_stats_on) {
        return;
    }
    (void)fprintf(stderr, "i686rt-dbt[%ld]:", (long)getpid());
    for (i = 0; i < (int)DBT_STAT_COUNT; i++) {
        (void)fprintf(stderr, " %s=%llu", s_dbt_stat_name[i],
                      (unsigned long long)atomic_load_explicit(
                          &s_dbt_stat[i], memory_order_relaxed));
    }
    for (i = 0; i < UNDEF_HIST; i++) {
        seen[i] = atomic_load_explicit(&s_dbt_undef_op[i],
                                       memory_order_relaxed);
    }
    /* Top-8 UNDEF-exit opcodes, largest first. */
    for (top = 0; top < 8; top++) {
        int best = -1;
        for (i = 0; i < UNDEF_HIST; i++) {
            if (seen[i] != 0U && (best < 0 || seen[i] > seen[best])) {
                best = i;
            }
        }
        if (best < 0) {
            break;
        }
        (void)fprintf(stderr, " undef[%s%s%02x]=%llu",
                      (best & 0x400) != 0 ? "seg:" : "",
                      (best & 0x300) == 0x100 ? "0f"
                      : (best & 0x300) == 0x200 ? "ff/" : "",
                      (unsigned)(best & 0xFF),
                      (unsigned long long)seen[best]);
        seen[best] = 0U;
    }
    (void)fprintf(stderr, "\n");
}

/* Per-dispatch probe: counts dispatches and, at most once per second,
 * dumps the counters so killed or hung runs still report. */
void dbt_stats_tick(void)
{
    uint64_t n = atomic_fetch_add_explicit(&s_dbt_stat[DBT_STAT_DISPATCH],
                                           1U, memory_order_relaxed);
    if ((n & 0xFFFFU) == 0U) {
        uint64_t now = dbt_stat_now_ns();
        uint64_t last = atomic_load_explicit(&s_dbt_last_dump_ns,
                                             memory_order_relaxed);
        if (last == 0U) {
            atomic_store_explicit(&s_dbt_last_dump_ns, now,
                                  memory_order_relaxed);
        } else if (now - last >= UINT64_C(1000000000)) {
            atomic_store_explicit(&s_dbt_last_dump_ns, now,
                                  memory_order_relaxed);
            i686_dbt_stats_dump();
        }
    }
}
