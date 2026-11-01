/*
 * src/dbt/engine.c — DBT engine loop with a per-EIP translate cache
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * v1 (Phase 3): direct-mapped cache keyed on EIP (no T bit, SPEC 3.3),
 * each entry a malloc'd executable block. UNDEF exits carry the insn
 * length in exit_arg: the engine interprets ONE insn (D2) and resumes
 * translation at pc+len. Blocks run through i686_jit_run_block
 * (src/trampoline.S), which since C6b links BRANCH exits through the
 * per-ctx IBTC (filled here on install) without returning to C; every
 * path that frees or dead-marks a block severs its IBTC entry first.
 * C6c: the host-fault checkpoint arms once per run (re-armed only in
 * the fault path, interp.c style) and a cache hit heals a collided
 * IBTC slot.
 */

#include <setjmp.h>
#include <signal.h>
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
#include "interp/interp.h"

extern uint64_t i686_fault_host_pc(void);

uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                            void *cur_entry, const void *epoch_ptr);

#ifdef __APPLE__
/* The JIT write-protect toggle is process-global, not per-thread: two
 * threads translating concurrently would re-protect each other's MAP_JIT
 * mappings mid-emit (the faulting translator's crash is then
 * misdelivered as a guest fault — the probe_cxxD pthread_exit LOCK
 * CMPXCHG crash).  Toggle+emit is serialized on this process-wide
 * mutex (deliberately NOT __thread). */
static pthread_mutex_t s_jit_toggle_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* C6b: the dispatch loop in src/trampoline.S is hand-assembled against
 * these ABI facts; the C side pins them so a struct or constant drift
 * breaks the build here instead of guest execution. */
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

#define DBT_HT_BITS 12U
#define DBT_HT_SIZE (1U << DBT_HT_BITS)

typedef struct dbt_entry {
    uint32_t eip;
    uint32_t len;      /* 0 = empty */
    uint8_t *code;     /* mmap RWX */
    size_t cap;
} dbt_entry_t;

/* Thread-local (clone/Phase 4): every host thread owns its direct-mapped
 * cache, so one thread's eviction can never free/reuse a mapping another
 * thread's IBTC still chains into.  Diagnostics stay process-global. */
static __thread dbt_entry_t s_ht[DBT_HT_SIZE];
static int s_trace_dbt;   /* S lines (I686RT_TRACE) */
static int s_trace_blocks; /* B lines (I686RT_DBTTRACE, diagnostics) */

/* C7: dead-marked blocks are never munmapped at the dead-mark site
 * (mid-flight use-after-free is what H1 fixed); instead their mapping
 * parks in this bounded graveyard until a safe point where no emitted
 * block can still be on the host stack.  Drain happens ONLY at the top
 * of the i686_dbt_run dispatch loop and in i686_dbt_flush_all.  When
 * the graveyard is full the oldest entry is munmapped immediately, so
 * a SMC storm parks at most 255 blocks between two safe points. */
static __thread struct {
    uint8_t *code;
    size_t cap;
} s_graveyard[256];
static __thread size_t s_graveyard_n;

/* D11 SMC (Phase H H1): guest pages the DBT translated from are
 * write-protected in the host window; a guest store faults, we drop
 * the page's blocks, restore RW, and the handler returns so the store
 * re-executes (a32rt g_code_page_bitmap model).  Bitmap over the 4 GiB
 * window: 1 Mi pages / 32 = 32 Ki words (128 KiB BSS). */
#define SMC_PAGE 4096U
#define SMC_WORDS (0x100000000ULL / SMC_PAGE / 32U)
static uint32_t s_code_pages[SMC_WORDS];
static uint64_t s_smc_window_base;
static uint64_t s_smc_window_end;
static __thread i686_ctx_t *s_run_ctx; /* for IBTC/RAS clears in the
                                        * signal-unsafe fault path */
/* RC-U3-r2 P1 #4: last guest address remapped-and-redispatched by the
 * catch below; a fault at the same address twice in a row is not
 * healing, so it is delivered. Reset on delivery. */
static __thread uint64_t s_last_remap_ga = UINT64_C(0xFFFFFFFFFFFFFFFF);

static int smc_page_marked(uint32_t guest_page)
{
    uint32_t idx = guest_page / SMC_PAGE;
    return (s_code_pages[idx >> 5U] & (1u << (idx & 31U))) != 0u;
}

static void smc_page_mark(uint32_t guest_page)
{
    uint32_t idx = guest_page / SMC_PAGE;
    s_code_pages[idx >> 5U] |= 1u << (idx & 31U);
}

static void smc_page_unmark(uint32_t guest_page)
{
    uint32_t idx = guest_page / SMC_PAGE;
    s_code_pages[idx >> 5U] &= ~(1u << (idx & 31U));
}

/* Host page size for SMC protection (the mprotect granule).  On 4 KiB
 * hosts this is one guest page; on 16 KiB/64 KiB hosts (Darwin arm64)
 * one host page covers several guest pages and the whole host page is
 * protected/unprotected as a unit (D11).  Falls back to 4 KiB when the
 * cached size is unset or not a page power of two. */
static uint32_t smc_host_page(const i686_ctx_t *ctx)
{
    uint32_t h = (ctx != NULL) ? ctx->vm_host_page : 0U;

    if (h < SMC_PAGE || (h & (h - 1U)) != 0U) {
        h = SMC_PAGE;
    }
    return h;
}

/* Half-open [start, start+len) match that stays exact when the span
 * touches the top of the 32-bit guest window (end == 2^32 is not a
 * uint32_t). */
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

/* Restore RW on the host page at hbase and unmark all its 4 KiB
 * sub-pages (protection is host-page granular). */
static void smc_unprotect_host(i686_ctx_t *ctx, uint32_t hbase, uint32_t h)
{
    uint64_t host;
    uint32_t off;

    if (ctx != NULL) {
        host = ctx->guest_base + (uint64_t)hbase;
    } else {
        host = s_smc_window_base + (uint64_t)hbase;
    }
    (void)mprotect((void *)(uintptr_t)host, (size_t)h,
                   PROT_READ | PROT_WRITE);
    for (off = 0U; off < h; off += SMC_PAGE) {
        smc_page_unmark(hbase + off);
    }
}

/* Called after a block compiled from eip: protect its source host page. */
static void smc_protect(i686_ctx_t *ctx, uint32_t eip)
{
    uint32_t h = smc_host_page(ctx);
    uint32_t hbase = eip & ~(h - 1U);
    uint32_t off;

    for (off = 0U; off < h; off += SMC_PAGE) {
        if (smc_page_marked(hbase + off)) {
            return; /* host page already protected */
        }
    }
    if (mprotect(i686_guest_ptr(ctx, hbase), (size_t)h, PROT_READ) == 0) {
        for (off = 0U; off < h; off += SMC_PAGE) {
            smc_page_mark(hbase + off);
        }
    }
}

/* Park a dead-marked block's mapping in the graveyard (oldest entry
 * munmapped on overflow; munmap here is safe: on overflow the victim
 * has been parked across at least 255 later dead-marks). */
static void dbt_graveyard_push(uint8_t *code, size_t cap)
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

/* Munmap every parked dead block and reset the graveyard.  Safe point
 * ONLY: no emitted block may be on the host stack here. */
static void dbt_graveyard_drain(void)
{
    size_t i;

    for (i = 0U; i < s_graveyard_n; i++) {
        munmap(s_graveyard[i].code, s_graveyard[i].cap);
    }
    s_graveyard_n = 0U;
}

/* C6b: the trampoline chain decision follows a ctx->ibtc entry only when
 * key == guest EIP AND host_code != NULL.  Sever the entry the moment
 * its block mapping dies so a chain can never enter freed code: key=0
 * alone would still collide for a branch to EIP 0. */
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

/* D11: drop every translated block with eip in [start,end), unprotect
 * the pages, and clear IBTC/RAS entries that may chain into the freed
 * code (use-after-free guard). */
/* RC-U3 stack-site index (lane rc-u3-i686): each translated block's
 * ring slice, so the fault path maps host PC -> site.  Forward decls;
 * definitions sit beside dbt_get_or_compile below. */
static void dbt_sites_clear_range(uint32_t start, uint32_t end);
static void dbt_sites_clear_all(void);

/* Stack-site table (defined beside dbt_get_or_compile); tentative
 * declarations so the SMC span clearer below can cover eip == top. */
static __thread uint64_t s_site_start[DBT_HT_SIZE];
static __thread uint64_t s_site_end[DBT_HT_SIZE];
static __thread uint32_t s_site_eip[DBT_HT_SIZE];

/* Clear stack-site entries for [hbase, hbase+h), exact when the span
 * touches the top of the 32-bit guest window. */
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
    /* eip == 0xFFFFFFFF is the one address neither half covers. */
    for (i = 0U; i < DBT_HT_SIZE; i++) {
        if (s_site_end[i] > s_site_start[i] &&
            s_site_eip[i] == 0xFFFFFFFFU) {
            s_site_start[i] = 0U;
            s_site_end[i] = 0U;
            s_site_eip[i] = 0xFFFFFFFFU;
        }
    }
}

/* Drop every translated block with eip in the host page [hbase, hbase+h)
 * plus any IBTC/RAS entries chaining into them (wrap-safe at the top of
 * the guest window).  The mapping itself parks in the graveyard (C7). */
static void smc_drop_host(i686_ctx_t *ctx, uint32_t hbase, uint32_t h)
{
    size_t i;

    smc_sites_clear_span(hbase, h);
    for (i = 0U; i < DBT_HT_SIZE; i++) {
        if (s_ht[i].len != 0U && smc_in_span(s_ht[i].eip, hbase, h) != 0) {
            s_ht[i].eip = 0xFFFFFFFFU;
            dbt_graveyard_push(s_ht[i].code, s_ht[i].cap);
            s_ht[i].code = NULL;
            s_ht[i].cap = 0U;
            s_ht[i].len = 0U;
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

    dbt_sites_clear_range(start, end);
    /* Unprotect every protected host page intersecting [start, end).
     * Writability is host-page granular, so the whole host page goes
     * RW and every block translated from it is dropped (otherwise a
     * later write to a sibling sub-page would run stale code). */
    for (page = start & ~(SMC_PAGE - 1U); page < end; page += SMC_PAGE) {
        uint32_t hbase;

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
    for (size_t i = 0U; i < DBT_HT_SIZE; i++) {
        if (s_ht[i].len != 0U && s_ht[i].eip >= start &&
            s_ht[i].eip < end) {
            /* Dead-mark, never munmap mid-flight: the syscall that
             * triggered this invalidation exited from this very block
             * and the engine's post-syscall path may still reference
             * its code (H1: instant SIGSEGV otherwise).  C7: the
             * mapping parks in the bounded graveyard instead of
             * leaking until direct-mapped eviction. */
            s_ht[i].eip = 0xFFFFFFFFU;
            dbt_graveyard_push(s_ht[i].code, s_ht[i].cap);
            s_ht[i].code = NULL;
            s_ht[i].cap = 0U;
            s_ht[i].len = 0U; /* slot empty: eviction and flush_all
                               * must not munmap the parked mapping */
        }
    }
    if (ctx != NULL) {
        for (size_t i = 0U; i < I686_IBTC_SIZE; i++) {
            if (ctx->ibtc[i].key != 0U &&
                ctx->ibtc[i].key >= start && ctx->ibtc[i].key < end) {
                ctx->ibtc[i].key = 0U;
                ctx->ibtc[i].epoch = 0U;
                /* C6b: the chain check needs key AND host_code; NULL it
                 * so even a branch to EIP 0 cannot follow this entry. */
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

/* Host-fault query (interp.c SIGSEGV path): a write fault inside a
 * code-protected window page -> invalidate + reprotect-off so the
 * handler may return and the store re-executes.  Returns 1 handled. */
int i686_dbt_smc_write_fault(uint64_t host_addr)
{
    uint32_t page;
    uint32_t h;
    uint32_t hbase;

    if (host_addr < s_smc_window_base || host_addr >= s_smc_window_end) {
        return 0;
    }
    page = (uint32_t)(host_addr - s_smc_window_base) & ~(SMC_PAGE - 1U);
    if (!smc_page_marked(page)) {
        return 0;
    }
    /* Protection is host-page granular: restore RW on the whole host
     * page and drop every block translated from it, so the next
     * dispatch recompiles from the new bytes (stale entries would
     * otherwise be served from s_ht or chain into freed code).  The
     * faulting store may itself run inside a dropped block
     * (same-block SMC), so mappings park in the graveyard (C7). */
    h = smc_host_page(s_run_ctx);
    hbase = page & ~(h - 1U);
    smc_unprotect_host(s_run_ctx, hbase, h);
    smc_drop_host(s_run_ctx, hbase, h);
    return 1;
}

/* Called from main before the engine loop (mirrors I686RT_TRACE). */
void i686_dbt_trace_enable(int on)
{
    s_trace_dbt = on;
    s_trace_blocks = on && getenv("I686RT_DBTTRACE") != NULL;
}

/* Kernel exec semantics (RC7b T4b): a guest execve must invalidate the
 * whole translation cache — fork-spawned children inherit the parent's
 * COW cache, and a new image loaded at the same EIPs would otherwise
 * execute the previous image's stale blocks. */
void i686_dbt_flush_all(void)
{
    dbt_sites_clear_all();
    for (size_t i = 0U; i < DBT_HT_SIZE; i++) {
        if (s_ht[i].len != 0U) {
            munmap(s_ht[i].code, s_ht[i].cap);
            s_ht[i].len = 0U;
        }
    }
    memset(s_code_pages, 0, sizeof(s_code_pages)); /* pages die with the
        image (exec teardown munmaps the window anyway) */
    /* C6b: every freed block's IBTC entry must be severed BEFORE the
     * next dispatch — exec may reload overlapping EIPs, and a stale
     * {key, host_code} pair would chain into munmapped code. */
    if (s_run_ctx != NULL) {
        for (size_t i = 0U; i < I686_IBTC_SIZE; i++) {
            s_run_ctx->ibtc[i].key = 0U;
            s_run_ctx->ibtc[i].epoch = 0U;
            s_run_ctx->ibtc[i].host_code = NULL;
            s_run_ctx->ibtc[i].entry = NULL;
        }
    }
    dbt_graveyard_drain(); /* dead blocks from this image's SMC history */
}

static uint32_t dbt_hash(uint32_t eip)
{
    return (eip ^ (eip >> 12U)) & (DBT_HT_SIZE - 1U);
}

/* RC-U3 stack-site index: the ring slice [start, end) (sequence numbers
 * from i686_aot_ring_count) recorded by the last translation cached in
 * each direct-mapped slot, plus that block's base EIP.  (Storage
 * tentative-declared beside the SMC helpers above.) */

static void dbt_sites_clear_hash(uint32_t h)
{
    s_site_start[h] = 0U;
    s_site_end[h] = 0U;
    s_site_eip[h] = 0xFFFFFFFFU;
}

static void dbt_sites_clear_range(uint32_t start, uint32_t end)
{
    uint32_t h;
    for (h = 0U; h < DBT_HT_SIZE; h++) {
        if (s_site_end[h] > s_site_start[h] && s_site_eip[h] >= start &&
            s_site_eip[h] < end) {
            dbt_sites_clear_hash(h);
        }
    }
}

static void dbt_sites_clear_all(void)
{
    uint32_t h;
    for (h = 0U; h < DBT_HT_SIZE; h++) {
        dbt_sites_clear_hash(h);
    }
}

/* Fault recovery (RC-U3 P1): map the faulting host PC to its stack site
 * and recover.  ctx->eip becomes the faulting guest PC (block base +
 * guest_pc_delta).  ctx ESP is the LIVE value captured from the
 * faulting host register state (w4, the dedicated guest-ESP register):
 * ctx GPRs are only spilled on clean exits to C, so across chained
 * blocks ctx ESP is stale by the outstanding call depth and replaying
 * the current block's sites onto it misplaces signal frames and
 * sigreturn resumes.  The pre-fault sites' effects are already in the
 * live ESP, so the walk only locates the exact site (for eip and the
 * pre-commit undo); without a matching site ESP is still corrected
 * while eip stays at the block base.  Outside translated blocks (helper
 * or C faults, where w4 is host scratch) the legacy ctx-base replay is
 * kept as best effort. */
static void i686_dbt_recover_fault(i686_ctx_t *ctx, uint64_t host_pc)
{
    uint32_t h = DBT_HT_SIZE;
    uint32_t i;
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

    if (host_pc == 0U) {
        return;
    }
    for (i = 0U; i < DBT_HT_SIZE; i++) {
        uint64_t lo = (uint64_t)(uintptr_t)s_ht[i].code;
        if (s_ht[i].len != 0U && host_pc >= lo &&
            host_pc < lo + (uint64_t)s_ht[i].len) {
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
    /* RC-U3: the fault interrupted a block mid-flight, so ctx GPRs
     * predate the block (spills happen only at clean exits).  Sync the
     * live host w0..w7 before the heal/emulate/deliver paths below,
     * which all read ctx: without this, emulate runs the faulting insn
     * with stale operands (observed: ECX from the caller, fatal). */
    {
        extern uint64_t i686_fault_gpr(unsigned);
        unsigned r;
        for (r = 0U; r < 8U; r++) {
            ctx->gpr[r] = (uint32_t)i686_fault_gpr(r);
        }
    }
    base = s_ht[h].eip;
    start = s_site_start[h];
    end = s_site_end[h];
    if (end <= start || s_site_eip[h] != base) {
        if (have_live_esp) {
            ctx->gpr[I686_REG_ESP] = live_esp;
        }
        return;
    }
    fault_off = (uint32_t)(host_pc - (uint64_t)(uintptr_t)s_ht[h].code);
    esp = have_live_esp ? live_esp : ctx->gpr[I686_REG_ESP];
    memset(&fault_site, 0, sizeof(fault_site));
    for (seq = start; seq < end; seq++) {
        dbt_mem_site_t s;
        if (i686_aot_ring_at((size_t)seq, &s) == 0) {
            break; /* recycled: stop rather than misapply */
        }
        if ((uint32_t)s.host_insn_offset < fault_off) {
            /* Committed before the fault.  On the live base their
             * effects are already in ESP; on the legacy ctx base replay
             * the post-success effect (PUSH/CALL decremented by the
             * delta; POP/RET bumped by the width). */
            if (!have_live_esp) {
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
        /* The faulting access ran after this site's pre-commit
         * decrement, so the live ESP includes it; undo explicitly to
         * restore the pre-instruction ESP.  (On the legacy base the
         * same expression reconstructs then undoes the decrement.) */
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
    dbt_entry_t *e = &s_ht[dbt_hash(eip)];
    size_t cap = 8192U;

    if (e->len != 0U) {
        if (e->eip == eip) {
            /* C6c: heal a collided IBTC slot on a cache hit.  Hot EIPs
             * outnumber the 1024 direct-mapped slots; a slot stolen by
             * a colliding key used to stay lost forever (slots were
             * refilled only on a fresh compile), so the victim
             * C-dispatched on every execution.  Refill here — a
             * between-blocks safe point, with a live mapping — and the
             * trampoline links this block again; the clobbered
             * colliding key merely falls back to this loop on its next
             * branch (the eviction-path contract). */
            i686_ibtc_entry_t *slot = &ctx->ibtc[i686_ibtc_hash(eip)];
            if (slot->key != eip) {
                slot->key = eip;
                slot->epoch = 1U;
                slot->host_code = e->code;
                slot->entry = e->code;
            }
            return e;
        }
        dbt_ibtc_sever(ctx, e->eip); /* before the munmap: the victim's
            IBTC entry must not chain into freed code (C6b) */
        munmap(e->code, e->cap); /* direct-mapped eviction */
        e->len = 0U;
    }
    for (;;) {
#ifdef __APPLE__
        uint8_t *code = mmap(NULL, cap, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
        uint8_t *code = mmap(NULL, cap, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
        size_t len;
        size_t ring_before;
        if (code == MAP_FAILED) {
            return NULL;
        }
#ifdef __APPLE__
        (void)pthread_mutex_lock(&s_jit_toggle_mutex);
        pthread_jit_write_protect_np(0);
#endif
        ring_before = i686_aot_ring_count();
        len = i686_dbt_translate(ctx, eip, code, cap);
#ifdef __APPLE__
        pthread_jit_write_protect_np(1);
        (void)pthread_mutex_unlock(&s_jit_toggle_mutex);
#endif
        if (len == 0U) {
            munmap(code, cap);
            dbt_sites_clear_hash(dbt_hash(eip));
            return NULL;
        }
        if (len < cap) {
            uint32_t h = dbt_hash(eip);
#ifdef __APPLE__
            sys_icache_invalidate(code, len);
#endif
            e->eip = eip;
            e->len = (uint32_t)len;
            e->code = code;
            e->cap = cap;
            /* RC-U3: index this block's stack-site ring slice. */
            s_site_start[h] = (uint64_t)ring_before;
            s_site_end[h] = (uint64_t)i686_aot_ring_count();
            s_site_eip[h] = eip;
            /* C6b: publish the IBTC slot so the trampoline links BRANCH
             * exits straight into this block.  epoch=1 marks a live
             * install; dead-marked slots refill only here (a fresh
             * successful compile). */
            ctx->ibtc[i686_ibtc_hash(eip)] = (i686_ibtc_entry_t){
                .key = eip, .epoch = 1U, .host_code = code, .entry = code};
            /* H1-DEBUG */ if (getenv("I686RT_SMC_OFF") == NULL) smc_protect(ctx, eip);
            return e;
        }
        munmap(code, cap);
        cap *= 2U; /* block bigger than the page: grow and retry */
        if (cap > 1U << 20) {
            return NULL;
        }
    }
}

int i686_dbt_run(i686_ctx_t *ctx)
{
    /* Host-fault checkpoint (H1): the SIGSEGV handler must be installed
     * and armed for DBT execution too — SMC write faults return via the
     * handler's D11 branch, and genuine guest faults convert to guest
     * exits like the interpreter loop does. */
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
    s_run_ctx = ctx;
    s_smc_window_base = ctx->guest_base;
    s_smc_window_end = ctx->guest_base + 0x100000000ULL;
    /* C6c: arm the checkpoint ONCE per run and re-arm ONLY in the fault
     * path after a longjmp — the interpreter's arm-once structure
     * (interp.c, RC7b T4d).  The previous per-dispatch sigsetjmp cost
     * one rt_sigprocmask host syscall per loop iteration (musl's
     * savemask sigsetjmp), which dominated wall time on CoreMark.  The
     * fault path's re-arm restores the checkpoint after the handler's
     * pre-jump disarm (nested faults must not re-jump into a stale
     * context), so the NEXT fault still lands here.  H1 invariant: the
     * checkpoint is armed whenever emitted code runs — dispatch starts
     * armed, and every exit that leaves guest execution disarms. */
    if (sigsetjmp(fj, 1) != 0) {
        uint64_t fa = i686_fault_addr();
        extern int i686_deliver_sync(i686_ctx_t *, int);
        extern int i686_fault_sig(void);
        extern int i686_fault_code(void);
        extern int i686_fault_region_prot(const i686_ctx_t *, uint32_t,
                                          uint32_t *, uint32_t *);

        /* RC-U3-r2 P1 #4: a fault after a split-lock acquisition (the
         * DBT interpret-one fallback runs LOCK RMWs inline) must not
         * strand the lock; release it when this thread holds it. */
        i686_split_lock_release_if_held();
#ifdef __APPLE__
        /* A fault during translation longjmps past the mutex unlock in
         * dbt_get_or_compile; release best-effort (not-owned and
         * not-locked unlocks fail harmlessly) so later compiles in any
         * thread don't deadlock.  The faulting block is discarded. */
        (void)pthread_mutex_unlock(&s_jit_toggle_mutex);
#endif
        i686_fault_arm(&fj); /* re-arm: nested faults disarm */
        if (fa >= ctx->guest_base &&
            fa < ctx->guest_base + 0x100000000ULL) {
            ctx->fault_addr = (uint32_t)(fa - ctx->guest_base);
        } else {
            ctx->fault_addr = (uint32_t)fa;
        }
        /* RC-U3 P1: recover the faulting guest PC and ESP from the
         * block's stack-site table (undoes pre-commit SP adjustments). */
        i686_dbt_recover_fault(ctx, i686_fault_host_pc());
        /* C2-2 mirror-consulting classification (interp.c twin): a
         * fully-R|W-mirrored page faulted spuriously (widen neighbour)
         * or stale — emulate via interpret-one, else widen-and-retry
         * once; mirror-denying and unmapped faults deliver below. */
        if (fa >= ctx->guest_base &&
            fa < ctx->guest_base + 0x100000000ULL) {
            extern int i686_vm32_widen_prot(i686_ctx_t *, uint32_t,
                                            uint32_t);
            extern int i686_spurious_emulate(i686_ctx_t *, uint32_t);
            extern int i686_spurious_allow(i686_ctx_t *, uint32_t);
            uint32_t rga = (uint32_t)(fa - ctx->guest_base);
            if (rga != (uint32_t)s_last_remap_ga &&
                i686_fault_region_prot(ctx, rga, NULL, NULL) != 0 &&
                i686_spurious_allow(ctx, rga) != 0) {
                if (i686_spurious_emulate(ctx, rga) == 0) {
                    goto dispatch; /* emulated; resume past the insn */
                }
                if (i686_vm32_widen_prot(ctx, rga & ~0xFFFU,
                                        (rga & ~0xFFFU) + 0x1000U) == 0) {
                    s_last_remap_ga = (uint64_t)rga;
                    goto dispatch; /* cover re-asserted; retry */
                }
            }
        }
        s_last_remap_ga = UINT64_C(0xFFFFFFFFFFFFFFFF);
        if (i686_deliver_sync(ctx, I686_EXIT_FAULT) == 0) {
            goto dispatch; /* guest handler installed; resume at it */
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
        /* C7 safe point (frozen call site): dispatch boundary — no
         * emitted block is on the host stack, so dead-marked blocks
         * can be reclaimed here. */
        dbt_graveyard_drain();
        {   /* D8 guard (phase-7.md freeze): non-flat CS (any LDT selector
             * or D=0 code) or active v86 runs interpreter-only, checked
             * per block dispatch.  A far transfer single-stepped through
             * the UNDEF path can flip CS at any block boundary. */
            extern bool i686_seg_flat_cs(const i686_ctx_t *ctx);
            if (!i686_seg_flat_cs(ctx) || ctx->v86 != 0U) {
                i686_fault_disarm();
                return i686_interp_run(ctx);
            }
        }
        /* C2-2: async-signal poll at the C dispatch boundary.  Chained
         * blocks stay in asm; every C exit (syscall, self-loop sig_check
         * bail, IBTC miss, fault) lands here, so a pending raise/alarm
         * delivers before the next block runs — the interp loop's safe
         * point (interp.c) mirrored for the DBT.  A delivered handler
         * re-dispatches at its entry; no handler keeps executing. */
        if (ctx->pending_signals != 0U) {
            extern int i686_deliver_pending(i686_ctx_t *);
            if (i686_deliver_pending(ctx) == 0) {
                continue;
            }
        }
        dbt_entry_t *e = dbt_get_or_compile(ctx, ctx->eip);
        int r;

        if (e == NULL) {
            /* Translation impossible here: run the interpreter. */
            (void)fprintf(stderr, "DBTFALL eip=%08x\n", ctx->eip);
            i686_fault_disarm();
            return i686_interp_run(ctx);
        }
        ctx->exit_reason = I686_EXIT_NONE;
        ctx->exit_arg = 0U; /* C3f: a stale arg must not classify a
                             * checkpoint fault (deliver_sync's legacy
                             * fallback reads it) */
        if (s_trace_blocks) {
            (void)fprintf(stderr, "B %08x\n", ctx->eip);
        }
        (void)i686_jit_run_block(ctx, e->code, NULL, NULL);
        ctx->blocks_executed++;

        r = (int)ctx->exit_reason;
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
                ctx->exit_arg = (uint32_t)rv; /* process exit status */
                return I686_EXIT_SYSCALL;
            }
            continue;
        }
        case I686_EXIT_UNDEF: {
            /* D2: interpret ONE insn, then resume translation. The exit
             * carries the faulting pc in exit_dest (stored by the exit
             * sequence for every reason; eip itself is only written for
             * BRANCH) — set it before stepping or we re-execute the
             * block start forever.  A non-continue single step takes
             * the interpreter's exit switch semantics: syscalls are
             * served like translated SYSCALL exits, and FAULT/TRAP
             * goes through signal delivery (a divide error's SIGFPE
             * arrives here, not via the host-fault checkpoint). */
            extern int i686_interp_step(i686_ctx_t *ctx);
            int ir;
            ctx->eip = ctx->exit_dest;
            ir = i686_interp_step(ctx);
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
                    ctx->exit_arg = (uint32_t)rv; /* exit status */
                    i686_fault_disarm();
                    return I686_EXIT_SYSCALL;
                }
                continue;
            }
            if (ir == I686_EXIT_FAULT || ir == I686_EXIT_TRAP) {
                extern int i686_deliver_sync(i686_ctx_t *, int);
                extern void i686_diag_fault(i686_ctx_t *);
                if (i686_deliver_sync(ctx, ir) == 0) {
                    goto dispatch; /* handler installed; resume at it */
                }
                i686_diag_fault(ctx);
                i686_fault_disarm();
                return ir;
            }
            i686_fault_disarm();
            return ir;
        }
        case I686_EXIT_TRAP:
        case I686_EXIT_FAULT:
        case I686_EXIT_HLT:
            i686_fault_disarm();
            return r;
        default:
            i686_fault_disarm();
            return r;
        }
    }
}
