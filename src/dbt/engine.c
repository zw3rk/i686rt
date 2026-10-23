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
 * the fault path, interp.c style).
 */

#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "dbt/emit.h"
#include "interp/interp.h"

uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                            void *cur_entry, const void *epoch_ptr);

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

static dbt_entry_t s_ht[DBT_HT_SIZE];
static int s_trace_dbt;   /* S lines (I686RT_TRACE) */
static int s_trace_blocks; /* B lines (I686RT_DBTTRACE, diagnostics) */

/* C7: dead-marked blocks are never munmapped at the dead-mark site
 * (mid-flight use-after-free is what H1 fixed); instead their mapping
 * parks in this bounded graveyard until a safe point where no emitted
 * block can still be on the host stack.  Drain happens ONLY at the top
 * of the i686_dbt_run dispatch loop and in i686_dbt_flush_all.  When
 * the graveyard is full the oldest entry is munmapped immediately, so
 * a SMC storm parks at most 255 blocks between two safe points. */
static struct {
    uint8_t *code;
    size_t cap;
} s_graveyard[256];
static size_t s_graveyard_n;

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

/* Called after a block compiled from eip: protect its source page. */
static void smc_protect(i686_ctx_t *ctx, uint32_t eip)
{
    uint32_t page = eip & ~(SMC_PAGE - 1U);

    if (!smc_page_marked(page)) {
        void *host = i686_guest_ptr(ctx, page);
        if (mprotect(host, SMC_PAGE, PROT_READ) == 0) {
            smc_page_mark(page);
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
void i686_dbt_invalidate_range(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    uint32_t page;

    for (page = start & ~(SMC_PAGE - 1U); page < end; page += SMC_PAGE) {
        if (!smc_page_marked(page)) {
            continue;
        }
        (void)mprotect(i686_guest_ptr(ctx, page), SMC_PAGE,
                       PROT_READ | PROT_WRITE);
        smc_page_unmark(page);
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

    if (host_addr < s_smc_window_base || host_addr >= s_smc_window_end) {
        return 0;
    }
    page = (uint32_t)(host_addr - s_smc_window_base) & ~(SMC_PAGE - 1U);
    if (!smc_page_marked(page)) {
        return 0;
    }
    smc_page_unmark(page);
    (void)mprotect((void *)(uintptr_t)(s_smc_window_base + page), SMC_PAGE,
                   PROT_READ | PROT_WRITE);
    /* Drop this page's translated blocks AND any IBTC/RAS entries that
     * chain into them, so the next dispatch recompiles from the new
     * bytes (the stale entries would otherwise be served from s_ht or
     * chain into freed code). */
    {
        uint32_t end = page + SMC_PAGE;
        for (size_t i = 0U; i < DBT_HT_SIZE; i++) {
            if (s_ht[i].len != 0U && s_ht[i].eip >= page &&
                s_ht[i].eip < end) {
                /* Mark dead WITHOUT freeing: the faulting store may
                 * itself run inside this block (same-block SMC), and
                 * the host PC must stay mapped until it exits.  C7:
                 * the mapping parks in the bounded graveyard instead
                 * of leaking until direct-mapped eviction. */
                s_ht[i].eip = 0xFFFFFFFFU;
                dbt_graveyard_push(s_ht[i].code, s_ht[i].cap);
                s_ht[i].code = NULL;
                s_ht[i].cap = 0U;
                s_ht[i].len = 0U; /* slot empty: eviction and
                                   * flush_all must not munmap the
                                   * parked mapping */
            }
        }
        if (s_run_ctx != NULL) {
            for (size_t i = 0U; i < I686_IBTC_SIZE; i++) {
                if (s_run_ctx->ibtc[i].key != 0U &&
                    s_run_ctx->ibtc[i].key >= page &&
                    s_run_ctx->ibtc[i].key < end) {
                    s_run_ctx->ibtc[i].key = 0U;
                    s_run_ctx->ibtc[i].epoch = 0U;
                    /* C6b: NULL the pointers too (see invalidate_range). */
                    s_run_ctx->ibtc[i].host_code = NULL;
                    s_run_ctx->ibtc[i].entry = NULL;
                }
            }
            for (size_t i = 0U; i < I686_RAS_SIZE; i++) {
                if (s_run_ctx->ras[i].key >= page &&
                    s_run_ctx->ras[i].key < end) {
                    s_run_ctx->ras[i].key = 0U;
                    s_run_ctx->ras[i].epoch = 0U;
                }
            }
        }
    }
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
    return (eip >> 2U) & (DBT_HT_SIZE - 1U);
}

static dbt_entry_t *dbt_get_or_compile(i686_ctx_t *ctx, uint32_t eip)
{
    dbt_entry_t *e = &s_ht[dbt_hash(eip)];
    size_t cap = 8192U;

    if (e->len != 0U) {
        if (e->eip == eip) {
            return e;
        }
        dbt_ibtc_sever(ctx, e->eip); /* before the munmap: the victim's
            IBTC entry must not chain into freed code (C6b) */
        munmap(e->code, e->cap); /* direct-mapped eviction */
        e->len = 0U;
    }
    for (;;) {
        uint8_t *code = mmap(NULL, cap, PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        size_t len;
        if (code == MAP_FAILED) {
            return NULL;
        }
        len = i686_dbt_translate(ctx, eip, code, cap);
        if (len == 0U) {
            munmap(code, cap);
            return NULL;
        }
        if (len < cap) {
            e->eip = eip;
            e->len = (uint32_t)len;
            e->code = code;
            e->cap = cap;
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

        i686_fault_arm(&fj); /* re-arm: nested faults disarm */
        if (fa >= ctx->guest_base &&
            fa < ctx->guest_base + 0x100000000ULL) {
            ctx->fault_addr = (uint32_t)(fa - ctx->guest_base);
        } else {
            ctx->fault_addr = (uint32_t)fa;
        }
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
        dbt_entry_t *e = dbt_get_or_compile(ctx, ctx->eip);
        int r;

        if (e == NULL) {
            /* Translation impossible here: run the interpreter. */
            (void)fprintf(stderr, "DBTFALL eip=%08x\n", ctx->eip);
            i686_fault_disarm();
            return i686_interp_run(ctx);
        }
        ctx->exit_reason = I686_EXIT_NONE;
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
             * block start forever. */
            extern int i686_interp_step(i686_ctx_t *ctx);
            ctx->eip = ctx->exit_dest;
            if (i686_interp_step(ctx) != 0) {
                i686_fault_disarm();
                return I686_EXIT_UNDEF;
            }
            continue;
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
