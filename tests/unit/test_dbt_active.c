/*
 * tests/unit/test_dbt_active.c — DBT dense active-slot host check
 *
 * Portable host test (macOS arm64 and aarch64 Linux): exercises the
 * per-thread dense active-slot tracking in src/dbt/engine_tcache.c —
 * ensure/fini lifecycle, dbt_active_record dedup, the single-mapping
 * layout (span + alignment), and fini-reset/refill. Expected final line:
 * DBT-ACTIVE OK.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "dbt/engine_internal.h"

/* Stubs for the engine.c graveyard (not linked into this host check). */
void dbt_graveyard_push(uint8_t *code, size_t cap)
{
    (void)code;
    (void)cap;
}
void dbt_graveyard_drain(void)
{
}

static int s_fail;

#define CHECK(cond, name)                                                  \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL: %s (line %d)\n", name, __LINE__);                 \
            s_fail++;                                                      \
        }                                                                  \
    } while (0)

static void t_lifecycle(void)
{
    size_t i;
    int allzero = 1;

    dbt_tcache_fini(); /* safe before first ensure */
    CHECK(dbt_tcache_ensure() == 0, "ensure ok");
    CHECK(g_dbt_ht != NULL, "ht mapped");
    CHECK(g_dbt_site_start != NULL, "site_start mapped");
    CHECK(g_dbt_site_end != NULL, "site_end mapped");
    CHECK(g_dbt_site_eip != NULL, "site_eip mapped");
    CHECK(g_dbt_active != NULL, "active mapped");
    CHECK(g_dbt_in_active != NULL, "in_active mapped");
    CHECK(g_dbt_nactive == 0U, "nactive zero");
    for (i = 0U; i < DBT_HT_SIZE; i++) {
        if (g_dbt_in_active[i] != 0U) {
            allzero = 0;
            break;
        }
    }
    CHECK(allzero, "in_active zero-fill");
    CHECK(dbt_tcache_ensure() == 0, "re-ensure ok");
    CHECK(g_dbt_nactive == 0U, "re-ensure keeps nactive");
    dbt_tcache_fini();
}

static void t_layout(void)
{
    const uint8_t *base;
    const uint8_t *top;
    size_t span;
    size_t want;

    CHECK(dbt_tcache_ensure() == 0, "ensure ok");
    base = (const uint8_t *)(const void *)g_dbt_ht;
    top = (const uint8_t *)(const void *)(g_dbt_in_active + DBT_HT_SIZE);
    span = (size_t)(top - base);
    want = (size_t)DBT_HT_SIZE *
           (sizeof(dbt_entry_t) + 2U * sizeof(uint64_t) +
            2U * sizeof(uint32_t) + sizeof(uint8_t));
    CHECK(span == want, "single-mapping span");
    CHECK(((uintptr_t)g_dbt_active & 3U) == 0U, "active u32 aligned");
    CHECK(g_dbt_site_start == (uint64_t *)(void *)(base +
               (size_t)DBT_HT_SIZE * sizeof(dbt_entry_t)),
          "site_start offset");
    dbt_tcache_fini();
}

static void t_record(void)
{
    uint32_t i;

    CHECK(dbt_tcache_ensure() == 0, "ensure ok");
    dbt_active_record(5U);
    dbt_active_record(5U); /* duplicate: no second entry */
    dbt_active_record(7U);
    CHECK(g_dbt_nactive == 2U, "dedup count");
    CHECK(g_dbt_active[0] == 5U, "first slot");
    CHECK(g_dbt_active[1] == 7U, "second slot");
    CHECK(g_dbt_in_active[5] == 1U, "flag set 5");
    CHECK(g_dbt_in_active[7] == 1U, "flag set 7");
    CHECK(g_dbt_in_active[6] == 0U, "flag clear 6");
    for (i = 0U; i < 1000U; i++) {
        dbt_active_record(i);
    }
    CHECK(g_dbt_nactive == 1000U, "bulk count");
    CHECK(g_dbt_in_active[999] == 1U, "bulk flag");
    dbt_tcache_fini();
    CHECK(g_dbt_ht == NULL, "fini clears ht");
    CHECK(g_dbt_active == NULL, "fini clears active");
    CHECK(g_dbt_in_active == NULL, "fini clears in_active");
    CHECK(g_dbt_nactive == 0U, "fini resets nactive");
    dbt_tcache_fini(); /* idempotent */
    CHECK(dbt_tcache_ensure() == 0, "refill ok");
    CHECK(g_dbt_nactive == 0U, "refill starts empty");
    dbt_active_record(5U);
    CHECK(g_dbt_nactive == 1U, "refill records");
    CHECK(g_dbt_active[0] == 5U, "refill slot");
    dbt_tcache_fini();
}

int main(void)
{
    t_lifecycle();
    t_layout();
    t_record();
    if (s_fail != 0) {
        printf("DBT-ACTIVE FAIL (%d)\n", s_fail);
        return 1;
    }
    printf("DBT-ACTIVE OK\n");
    return 0;
}
