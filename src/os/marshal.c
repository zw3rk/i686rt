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

extern void i686_host_faults_install(void);
extern void i686_fault_arm(sigjmp_buf *jb);
extern sigjmp_buf *i686_fault_save(void);
extern uint64_t i686_fault_addr(void);
extern int i686_fault_region_prot(const i686_ctx_t *ctx, uint32_t ga,
                                  uint32_t *out_prot, uint32_t *out_flags);
extern int i686_subpage_range_ok(const i686_ctx_t *ctx, uint32_t start_va,
                                 uint64_t byte_len, uint8_t need_prot);

/* Closure state for the op callbacks below: __thread because a
 * syscall owns its host thread while a copy is armed. */
static __thread struct {
    i686_ctx_t *ctx;
    uint32_t va;
    void *dst;
    const void *src;
    size_t len;
    uint8_t need_prot;
    int is_cstr;
} s_copy_args;

/* Syscall-copy fault tolerance on Regime A2 widened host pages.
 * Runs each copy under an inner checkpoint: when a host fault hits a
 * widened host page whose 4 KiB sub-page mirror grants s_copy_args.need_prot,
 * acquires the subpage lock, opens the covering host page to union_prot,
 * retries the copy, and ALWAYS re-widens every opened host page before
 * returning. Syscall copies never propagate to the outer engine
 * checkpoint: unrecoverable faults return -EFAULT so callers run their
 * cleanup (I686-R3-6). Guest-instruction fault propagation uses the
 * separate interfaces in signals_subpage.c. */
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
    if (!i686_subpage_range_ok(ctx, rga & ~0xFFFU, 0x1000u,
                               s_copy_args.need_prot)) {
        return -1; /* genuine fault: deliver it */
    }
    if (!s_copy_args.is_cstr &&
        !i686_subpage_range_ok(ctx, s_copy_args.va, s_copy_args.len,
                               s_copy_args.need_prot)) {
        return -1; /* cross-sub-page span hits a restricted sub-page */
    }
    hps = ctx->vm_host_page;
    *out_page = rga & ~(hps - 1u);
    return 0;
}

typedef void (*copy_op_fn)(void);
static __thread uint32_t s_opened[64];

static int s_copy_tolerant(i686_ctx_t *ctx, uint32_t va, copy_op_fn copy_op)
{
    sigjmp_buf *outer = i686_fault_save();
    (void)va;
    if (ctx == NULL && outer == NULL) {
        copy_op();
        return 0;
    }
    if (outer == NULL) {
        i686_host_faults_install();
    }
    {
        sigjmp_buf inner;
        volatile int tries = 0;
        volatile int locked = 0;
        volatile uint32_t healed = 0xFFFFFFFFu;
        if (sigsetjmp(inner, 1) != 0) {
            uint32_t page = 0xFFFFFFFFu;
            uint32_t hps = (ctx != NULL) ? ctx->vm_host_page : 4096u;
            int k;
            i686_fault_arm(outer);
            if (tries >= 64 || s_copy_fault_page(ctx, &page) != 0 ||
                page == healed) {
                for (k = 0; k < tries; k++) {
                    (void)i686_vm32_widen_prot(ctx, s_opened[k], s_opened[k] + hps);
                }
                if (locked) {
                    i686_vm32_subpage_unlock();
                }
                return -I686_EFAULT;
            }
            if (!locked) {
                i686_vm32_subpage_lock();
                locked = 1;
            }
            healed = page;
            s_opened[tries] = page;
            tries++;
            if (i686_vm32_union_prot(ctx, page, page + hps) != 0) {
                for (k = 0; k < tries; k++) {
                    (void)i686_vm32_widen_prot(ctx, s_opened[k], s_opened[k] + hps);
                }
                i686_vm32_subpage_unlock();
                return -I686_EFAULT;
            }
            i686_fault_arm(&inner);
            copy_op();
            i686_fault_arm(outer);
            for (k = 0; k < tries; k++) {
                (void)i686_vm32_widen_prot(ctx, s_opened[k], s_opened[k] + hps);
            }
            i686_vm32_subpage_unlock();
            return 0;
        }
        i686_fault_arm(&inner);
        copy_op();
        i686_fault_arm(outer);
        return 0;
    }
}

static void s_copy_to_run(void)
{
    memcpy(i686_guest_ptr(s_copy_args.ctx, s_copy_args.va),
           s_copy_args.src, s_copy_args.len);
    /* Guest store (I686-R9-6): a write to a MAP_PRIVATE file page flips
     * PAGE_COW_CLEAN to DIRTY so a later pwrite refresh cannot clobber it. */
    (void)i686_vm_file_promote_cow(s_copy_args.va, s_copy_args.len);
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
    s_copy_args.need_prot = 0x01u;
    s_copy_args.is_cstr = 0;
    return s_copy_tolerant(ctx, va, s_copy_from_run);
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
    s_copy_args.need_prot = 0x02u;
    s_copy_args.is_cstr = 0;
    return s_copy_tolerant(ctx, va, s_copy_to_run);
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
        uint32_t cur_va = va + (uint32_t)i;
        const char *p;
        if (cur_va < va) {
            /* 32-bit wrap (I686-R9-1): va=0xFFFFFFF0 must not wrap to VA 0. */
            s_fetch_rc = -I686_EFAULT;
            return;
        }
        if (ctx != NULL && ctx->vm_regime == I686_VM_REGIME_A2 &&
            (i == 0U || (cur_va & 0xFFFu) == 0u) &&
            !i686_subpage_range_ok(ctx, cur_va & ~0xFFFu, 0x1000u, 0x01u)) {
            sigjmp_buf *jb = i686_fault_save();
            if (jb != NULL) {
                siglongjmp(*jb, 1);
            }
            return;
        }
        p = (const char *)i686_guest_ptr(ctx, cur_va);
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
    s_copy_args.need_prot = 0x01u;
    s_copy_args.is_cstr = 1;
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
