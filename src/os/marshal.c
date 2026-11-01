/*
 * src/os/marshal.c — guest copy helpers + syscall registry core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <setjmp.h>
#include <string.h>

#include "marshal.h"
#include "vm/vm32.h"
#include "vm/vm_file.h"

#define I686_SYS_MAX 480U

static i686_sys_fn s_sys[I686_SYS_MAX];

/* EFAULT sentinel copied from the i386 table build. */
#define I686_EFAULT 14

extern void i686_fault_arm(sigjmp_buf *jb);
extern sigjmp_buf *i686_fault_save(void);
extern uint64_t i686_fault_addr(void);
extern int i686_fault_region_prot(const i686_ctx_t *ctx, uint32_t ga,
                                  uint32_t *out_prot, uint32_t *out_flags);

/* Syscall-copy fault tolerance (C2-2 thread-hang root cause).  A guest
 * copy inside a syscall implementation (clone tid words, path
 * strings, ...) runs with ctx->eip parked PAST the syscall insn, so a
 * spurious host fault on a widen-closed page must not escape to the
 * interp/DBT fault path: that path single-steps the parked
 * (non-memory) insn and resumes past it, silently abandoning the rest
 * of the syscall (hung pthread_create: the thread is never created
 * but the guest proceeds to join it).  Instead run each copy under an
 * inner checkpoint: on a fault the mirror allows (mapped region, full
 * R|W mirror grant), unrestrict the covering host page to the union
 * cover and retry — mirroring i686_spurious_emulate's union cover
 * without the step (there is no guest insn to step: eip is parked
 * past the syscall).  Unlike emulate there is deliberately no
 * re-widen: a spanning copy heals pages cumulatively and re-closing
 * between retries would re-fault pages the in-progress copy still
 * needs.  Healed covers stay at union, exactly like the leave-open
 * table's post-probation pages.  A fault the mirror denies, a fault
 * that makes no progress, or more than a bounded run of faulting
 * pages is re-raised to the outer checkpoint for normal guest
 * delivery.  Returns 0 when copy_op ran clean; genuine faults never
 * return (they are re-raised). */
static int s_copy_fault_page(i686_ctx_t *ctx, uint32_t *out_page)
{
    uint64_t fa;
    uint32_t rga;
    uint32_t hps;
    if (ctx == NULL || ctx->vm_regime != I686_VM_REGIME_A2 ||
        ctx->vm_host_page <= 4096u) {
        return -1;
    }
    fa = i686_fault_addr();
    if (fa < ctx->guest_base ||
        fa >= ctx->guest_base + 0x100000000ULL) {
        return -1;
    }
    rga = (uint32_t)(fa - ctx->guest_base);
    /* Only the faulting page heals: the copy range may span pages, but
     * each spurious fault opens exactly its own cover. */
    if (i686_fault_region_prot(ctx, rga, NULL, NULL) == 0 ||
        (i686_vm_file_prot(rga & ~0xFFFU) & 0x03u) != 0x03u) {
        return -1; /* genuine fault: deliver it */
    }
    hps = ctx->vm_host_page;
    *out_page = rga & ~(hps - 1u);
    return 0;
}

typedef void (*copy_op_fn)(void);
static int s_copy_tolerant(i686_ctx_t *ctx, uint32_t va, copy_op_fn copy_op)
{
    sigjmp_buf *outer = i686_fault_save();
    (void)va;
    if (outer == NULL) {
        copy_op();
        return 0;
    }
    {
        sigjmp_buf inner;
        volatile int tries = 0;
        volatile uint32_t healed = 0xFFFFFFFFu;
        if (sigsetjmp(inner, 1) != 0) {
            uint32_t page = 0xFFFFFFFFu;
            uint32_t hps;
            /* Fault inside copy_op.  Restore the outer checkpoint
             * first so the union/widen below faults outward. */
            i686_fault_arm(outer);
            if (tries >= 64 || s_copy_fault_page(ctx, &page) != 0 ||
                page == healed) {
                siglongjmp(*outer, 1); /* genuine or stuck: deliver */
            }
            healed = page;
            tries++;
            hps = ctx->vm_host_page;
            if (i686_vm32_union_prot(ctx, page, page + hps) != 0) {
                siglongjmp(*outer, 1);
            }
            i686_fault_arm(&inner);
            copy_op(); /* retry under union cover */
            i686_fault_arm(outer);
            return 0;
        }
        i686_fault_arm(&inner);
        copy_op();
        i686_fault_arm(outer);
        return 0;
    }
}

/* Closure state for the op callbacks below: __thread because a
 * syscall owns its host thread while a copy is armed. */
static __thread struct {
    i686_ctx_t *ctx;
    uint32_t va;
    void *dst;
    const void *src;
    size_t len;
} s_copy_args;

static void s_copy_to_run(void)
{
    memcpy(i686_guest_ptr(s_copy_args.ctx, s_copy_args.va),
           s_copy_args.src, s_copy_args.len);
}

static void s_copy_from_run(void)
{
    memcpy(s_copy_args.dst,
           i686_guest_ptr(s_copy_args.ctx, s_copy_args.va), s_copy_args.len);
}

int i686_copy_from_guest(i686_ctx_t *ctx, void *dst, uint32_t va, size_t len)
{
    if (len == 0U) {
        return 0;
    }
    if ((uint64_t)va + (uint64_t)len > 0x100000000ULL) {
        return -I686_EFAULT;
    }
    s_copy_args.ctx = ctx;
    s_copy_args.va = va;
    s_copy_args.dst = dst;
    s_copy_args.len = len;
    s_copy_tolerant(ctx, va, s_copy_from_run);
    return 0;
}

int i686_copy_to_guest(i686_ctx_t *ctx, uint32_t va, const void *src, size_t len)
{
    if (len == 0U) {
        return 0;
    }
    if ((uint64_t)va + (uint64_t)len > 0x100000000ULL) {
        return -I686_EFAULT;
    }
    s_copy_args.ctx = ctx;
    s_copy_args.va = va;
    s_copy_args.src = src;
    s_copy_args.len = len;
    s_copy_tolerant(ctx, va, s_copy_to_run);
    return 0;
}

static __thread int s_fetch_rc;

static void s_fetch_run(void)
{
    /* Pure re-readable scan: a fault retries the whole string, which
     * is idempotent.  Unterminated-within-buflen reports -EFAULT the
     * same as an unmapped tail (the kernel faults the same way). */
    size_t i;
    size_t buflen = s_copy_args.len;
    char *buf = (char *)s_copy_args.dst;
    uint32_t va = s_copy_args.va;
    i686_ctx_t *ctx = s_copy_args.ctx;
    s_fetch_rc = -I686_EFAULT;
    for (i = 0U; i < buflen; i++) {
        const char *p = (const char *)i686_guest_ptr(ctx, va + (uint32_t)i);
        buf[i] = *p;
        if (*p == '\0') {
            s_fetch_rc = 0;
            return;
        }
    }
    buf[buflen - 1U] = '\0';
}

int i686_fetch_cstr(i686_ctx_t *ctx, uint32_t va, char *buf, size_t buflen)
{
    if (buflen == 0U) {
        return -I686_EFAULT;
    }
    s_copy_args.ctx = ctx;
    s_copy_args.va = va;
    s_copy_args.dst = buf;
    s_copy_args.len = buflen;
    s_fetch_rc = -I686_EFAULT;
    s_copy_tolerant(ctx, va, s_fetch_run);
    return s_fetch_rc;
}

void i686_sys_register(long nr, i686_sys_fn fn)
{
    if (nr >= 0 && (unsigned long)nr < I686_SYS_MAX) {
        s_sys[nr] = fn;
    }
}

int64_t i686_sys_dispatch(i686_ctx_t *ctx, long nr)
{
    if (nr < 0 || (unsigned long)nr >= I686_SYS_MAX || s_sys[nr] == NULL) {
        return -38; /* -ENOSYS */
    }
    return s_sys[nr](ctx);
}
