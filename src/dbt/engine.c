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
 * (src/trampoline.S).
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "dbt/emit.h"
#include "interp/interp.h"

uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                            void *cur_entry, const void *epoch_ptr);

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
    for (;;) {
        {   /* D8 guard (phase-7.md freeze): non-flat CS (any LDT selector
             * or D=0 code) or active v86 runs interpreter-only, checked
             * per block dispatch.  A far transfer single-stepped through
             * the UNDEF path can flip CS at any block boundary. */
            extern bool i686_seg_flat_cs(const i686_ctx_t *ctx);
            if (!i686_seg_flat_cs(ctx) || ctx->v86 != 0U) {
                return i686_interp_run(ctx);
            }
        }
        dbt_entry_t *e = dbt_get_or_compile(ctx, ctx->eip);
        int r;

        if (e == NULL) {
            /* Translation impossible here: run the interpreter. */
            (void)fprintf(stderr, "DBTFALL eip=%08x\n", ctx->eip);
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
                return I686_EXIT_UNDEF;
            }
            continue;
        }
        case I686_EXIT_TRAP:
        case I686_EXIT_FAULT:
        case I686_EXIT_HLT:
            return r;
        default:
            return r;
        }
    }
}
