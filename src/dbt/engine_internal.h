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

#define DBT_HT_BITS 12U
#define DBT_HT_SIZE (1U << DBT_HT_BITS)

#define SMC_PAGE  4096U
#define SMC_WORDS (0x100000000ULL / SMC_PAGE / 32U)

typedef struct dbt_entry {
    uint32_t eip;
    uint32_t len;       /* 0 = empty */
    uint32_t page_gen;  /* snapshot of g_dbt_page_gen[eip >> 12] */
    uint32_t page_gen1; /* snapshot of g_dbt_page_gen[((eip >> 12) + 1) & 0xFFFFF] */
    uint8_t *code;      /* mmap RX */
    size_t   cap;
} dbt_entry_t;

extern __thread dbt_entry_t g_dbt_ht[DBT_HT_SIZE];
extern __thread uint64_t    g_dbt_site_start[DBT_HT_SIZE];
extern __thread uint64_t    g_dbt_site_end[DBT_HT_SIZE];
extern __thread uint32_t    g_dbt_site_eip[DBT_HT_SIZE];
extern __thread i686_ctx_t *g_dbt_run_ctx;

extern _Atomic uint64_t g_dbt_smc_window_base;
extern _Atomic uint64_t g_dbt_smc_window_end;
extern _Atomic uint32_t g_dbt_cache_epoch;
extern _Atomic uint32_t g_dbt_flush_epoch;
extern _Atomic uint32_t g_dbt_page_gen[1U << 20];
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

#endif /* I686RT_DBT_ENGINE_INTERNAL_H */
