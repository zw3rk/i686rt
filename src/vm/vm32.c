/*
 * src/vm/vm32.c — Two-regime Class-A 32-bit VM (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4, section 4.6.
 *
 * Regime A1 (H == 4096, native 4 KiB Linux kernels and every hyper-linux
 * run, where Stage-1 EL1 page tables are 4 KiB): the rt32 4 GiB window
 * [G, G + 4 GiB) maps 1:1, x20 = G, and the DBT emits the 1-instruction
 * [x20, wAddr, uxtw] form. Guest fork() is native kernel MAP_PRIVATE COW.
 *
 * Regime A2 (H > 4096: 16 KiB Standalone macOS Mach-O backend_darwin.c,
 * 16K/64K Linux without /dev/a32host): the same 4 GiB window is kept as a
 * single MAP_PRIVATE | MAP_ANONYMOUS arena with x20 = G. Per-4 KiB sub-page
 * protections are tracked in i686_vm_file; host pages with mixed sub-page
 * permissions carry the intersection (AND) of their sub-page protections via
 * i686_vm32_widen_prot (never PROT_EXEC), and accesses to accessible
 * neighbour sub-pages on a restricted host page are verified per-4 KiB
 * sub-page and single-stepped under the subpage lock before re-widening.
 * HVA stays G + gva on both regimes, so DBT, interp_step, futex, and syscall
 * copyin/copyout share one coherent address per page.
 *
 * Curated C11, no VLAs, no x18 (pure C11 file).
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>

#include "os/backend.h"
#include "rt32.h"
#include "vm/vm_file.h"

#define I686_VM32_FUTEX_SLOTS 64u

struct vm32_futex_slot {
    uint32_t gva;
    uint32_t bitset;
    _Atomic uint32_t woken;
    int in_use;
};

static pthread_mutex_t s_subpage_mtx = PTHREAD_MUTEX_INITIALIZER;
static _Atomic uint32_t s_subpage_writers;
static _Atomic uint32_t s_exec_readers;
static __thread volatile int s_in_guest_exec;
static __thread volatile int s_holds_subpage_lock;
static __thread volatile int s_subpage_dropped_exec;

static pthread_mutex_t s_futex_mtx = PTHREAD_MUTEX_INITIALIZER;
static struct vm32_futex_slot s_futex_slots[I686_VM32_FUTEX_SLOTS];

/* Child-state reset for the coordinated fork handlers in src/os/clone.c
 * (I686-R3-8): fork_prepare locks the runtime-owned mutexes in the
 * parent, fork_parent releases them, and fork_child reaches this reset
 * via i686_vm32_fork_child. There is deliberately no standalone
 * pthread_atfork registration here; a child-only handler would run
 * outside that coordination (and twice, alongside fork_child). */
static void vm32_atfork_child(void)
{
    unsigned i;
    /* fork_prepare locked both mutexes in the forking (surviving) thread;
     * release them before reinitializing: destroying a locked mutex is
     * undefined behaviour (I686-R9-9). Unlock order is inner-first. */
    (void)pthread_mutex_unlock(&s_subpage_mtx);
    (void)pthread_mutex_unlock(&s_futex_mtx);
    (void)pthread_mutex_destroy(&s_subpage_mtx);
    (void)pthread_mutex_destroy(&s_futex_mtx);
    (void)pthread_mutex_init(&s_subpage_mtx, NULL);
    (void)pthread_mutex_init(&s_futex_mtx, NULL);
    atomic_store_explicit(&s_subpage_writers, 0u, memory_order_relaxed);
    atomic_store_explicit(&s_exec_readers, 0u, memory_order_relaxed);
    s_in_guest_exec = 0;
    s_holds_subpage_lock = 0;
    s_subpage_dropped_exec = 0;
    for (i = 0u; i < I686_VM32_FUTEX_SLOTS; i++) {
        s_futex_slots[i].in_use = 0;
        s_futex_slots[i].gva = 0u;
        atomic_store_explicit(&s_futex_slots[i].woken, 0u, memory_order_relaxed);
    }
}

/* Lock order (I686-R4-1): the futex mutex is OUTER, the subpage mutex
 * INNER (VM spinlock > registry > futex > subpage globally).  FUTEX_WAIT
 * and FUTEX_CMP_REQUEUE hold s_futex_mtx across vm32_futex_load_u32(),
 * which takes the subpage lock for its A2 healing window; fork_prepare
 * must nest the same way or a concurrent waiter deadlocks the fork. */
void i686_vm32_fork_prepare(void)
{
    (void)pthread_mutex_lock(&s_futex_mtx);
    (void)pthread_mutex_lock(&s_subpage_mtx);
}

void i686_vm32_fork_parent(void)
{
    (void)pthread_mutex_unlock(&s_subpage_mtx);
    (void)pthread_mutex_unlock(&s_futex_mtx);
}

void i686_vm32_fork_child(void)
{
    vm32_atfork_child();
}

/* I686-R10-2: the execve success path drops orphaned FUTEX_WAIT slots so
 * the new image starts with an empty table. */
void i686_vm32_futex_reset(void);
void i686_vm32_futex_reset(void)
{
    unsigned i;
    (void)pthread_mutex_lock(&s_futex_mtx);
    for (i = 0u; i < I686_VM32_FUTEX_SLOTS; i++) {
        s_futex_slots[i].in_use = 0;
        s_futex_slots[i].gva = 0u;
        atomic_store_explicit(&s_futex_slots[i].woken, 0u,
                              memory_order_relaxed);
    }
    (void)pthread_mutex_unlock(&s_futex_mtx);
}

static void vm32_register_reader(void)
{
    for (;;) {
        while (atomic_load_explicit(&s_subpage_writers,
                                    memory_order_acquire) != 0u) {
            (void)pthread_mutex_lock(&s_subpage_mtx);
            (void)pthread_mutex_unlock(&s_subpage_mtx);
        }
        atomic_fetch_add_explicit(&s_exec_readers, 1u, memory_order_seq_cst);
        if (atomic_load_explicit(&s_subpage_writers,
                                 memory_order_seq_cst) == 0u) {
            s_in_guest_exec = 1;
            return;
        }
        atomic_fetch_sub_explicit(&s_exec_readers, 1u, memory_order_seq_cst);
    }
}

void i686_vm32_exec_enter(const i686_ctx_t *ctx)
{
    if (ctx == NULL || ctx->vm_regime != I686_VM_REGIME_A2 ||
        ctx->vm_host_page <= 4096u || s_in_guest_exec != 0 ||
        s_holds_subpage_lock != 0) {
        return;
    }
    vm32_register_reader();
}

void i686_vm32_exec_leave(void)
{
    if (s_in_guest_exec != 0) {
        s_in_guest_exec = 0;
        atomic_fetch_sub_explicit(&s_exec_readers, 1u, memory_order_release);
    }
}

void i686_vm32_subpage_lock(void)
{
    /* I686-R2-1 follow-up: remember whether this thread dropped its own
     * exec-reader registration so unlock can restore it. Without the
     * restore, the first execution of every freshly compiled A2 block
     * runs unregistered and a sibling's transient union_prot window is
     * visible to it. */
    s_subpage_dropped_exec = (s_in_guest_exec != 0) ? 1 : 0;
    if (s_in_guest_exec != 0) {
        s_in_guest_exec = 0;
        atomic_fetch_sub_explicit(&s_exec_readers, 1u, memory_order_release);
    }
    atomic_fetch_add_explicit(&s_subpage_writers, 1u, memory_order_seq_cst);
    (void)pthread_mutex_lock(&s_subpage_mtx);
    s_holds_subpage_lock = 1;
    while (atomic_load_explicit(&s_exec_readers, memory_order_acquire) != 0u) {
        (void)sched_yield();
    }
}

void i686_vm32_subpage_unlock(void)
{
    int dropped = s_subpage_dropped_exec;
    s_subpage_dropped_exec = 0;
    s_holds_subpage_lock = 0;
    (void)pthread_mutex_unlock(&s_subpage_mtx);
    atomic_fetch_sub_explicit(&s_subpage_writers, 1u, memory_order_release);
    if (dropped != 0) {
        vm32_register_reader();
    }
}

int i686_vm32_init(i686_ctx_t *ctx, uint64_t requested_window)
{
    size_t host_page;
    if (ctx == NULL) {
        return -1;
    }
    if (rt32_vm_init(ctx, requested_window) != 0) {
        return -1;
    }
    host_page = rt_host_page_size();
    ctx->vm_host_page = (uint32_t)host_page;
    ctx->vm_regime = i686_vm_regime_for_host_page(host_page);
    ctx->vm_tlb = NULL;
    ctx->dbt_fault_nzcv = 0u;
    ctx->dbt_fault_w21 = 0u;
    if (i686_vm_file_init(ctx->guest_base) != 0) {
        return -1;
    }
    return 0;
}

void i686_vm32_fini(i686_ctx_t *ctx)
{
    unsigned i;
    if (ctx == NULL) {
        return;
    }
    i686_vm32_exec_leave();
    for (i = 0u; i < I686_VM32_FUTEX_SLOTS; i++) {
        s_futex_slots[i].in_use = 0;
        s_futex_slots[i].gva = 0u;
        atomic_store_explicit(&s_futex_slots[i].woken, 0u, memory_order_relaxed);
    }
    ctx->vm_tlb = NULL;
    ctx->vm_regime = 0u;
    i686_vm_file_fini();
}

int i686_vm32_union_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    uint64_t host_page;
    uint64_t hva_start;
    uint64_t hva_end;
    uint64_t page;
    int prot;
    uint32_t a;
    if (ctx == NULL || end <= start) {
        return -1;
    }
    host_page = (ctx->vm_host_page != 0u) ? (uint64_t)ctx->vm_host_page : 4096u;
    hva_start = ctx->guest_base + (uint64_t)(start & ~(uint32_t)(host_page - 1u));
    hva_end = ctx->guest_base + (((uint64_t)end + host_page - 1u) & ~(host_page - 1u));
    for (page = hva_start; page < hva_end; page += host_page) {
        prot = 0;
        for (a = 0u; (uint64_t)a < host_page; a += 0x1000u) {
            uint32_t gva = (uint32_t)((page + (uint64_t)a) - ctx->guest_base);
            prot |= (int)(i686_vm_file_prot(gva) & 0x03u);
        }
        /* Union of sub-page protections; EXEC is never mapped (W^X). */
        if (rt_host_protect((void *)(uintptr_t)page, (size_t)host_page, prot) != 0) {
            return -1;
        }
    }
    return 0;
}

#ifndef I686RT_NO_DBT
extern int i686_dbt_smc_page_marked(uint32_t guest_page);
#endif

/* Most-restrictive cover: the host page denies whatever any sub-page
 * denies.  Untracked (never-mapped) sub-pages read prot 0 and therefore
 * restrict, which keeps munmap-created holes trapping (C2-2). */
int i686_vm32_widen_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    uint64_t host_page;
    uint64_t hva_start;
    uint64_t hva_end;
    uint64_t page;
    if (ctx == NULL || end <= start) {
        return -1;
    }
    host_page = (ctx->vm_host_page != 0u) ? (uint64_t)ctx->vm_host_page : 4096u;
    hva_start = ctx->guest_base + (uint64_t)(start & ~(uint32_t)(host_page - 1u));
    hva_end = ctx->guest_base + (((uint64_t)end + host_page - 1u) & ~(host_page - 1u));
    for (page = hva_start; page < hva_end; page += host_page) {
        int prot = 0x03;
        int smc_code = 0;
        uint32_t a;
        for (a = 0u; (uint64_t)a < host_page; a += 0x1000u) {
            uint32_t gva = (uint32_t)((page + (uint64_t)a) - ctx->guest_base);
            prot &= (int)(i686_vm_file_prot(gva) & 0x03u);
#ifndef I686RT_NO_DBT
            if (i686_dbt_smc_page_marked(gva)) {
                smc_code = 1;
            }
#endif
        }
        if (smc_code) {
            prot &= ~0x02;
        }
        /* Strict AND of sub-page protections; EXEC is never mapped (W^X). */
        if (rt_host_protect((void *)(uintptr_t)page, (size_t)host_page, prot) != 0) {
            return -1;
        }
    }
    return 0;
}

static int vm32_futex_load_u32(i686_ctx_t *ctx, uint32_t gva, uint32_t *out)
{
    if (ctx == NULL || out == NULL || (gva & 3u) != 0u) {
        return -1;
    }
    if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u) {
        uint32_t hps = ctx->vm_host_page;
        uint32_t gbase = gva & ~(hps - 1u);
        if ((i686_vm_file_flags(gva) & 0x80u) == 0u ||
            (i686_vm_file_prot(gva) & 0x01u) == 0u) {
            return -1;
        }
        i686_vm32_subpage_lock();
        (void)i686_vm32_union_prot(ctx, gbase, gbase + hps);
        *out = atomic_load((const _Atomic uint32_t *)i686_guest_ptr(ctx, gva));
        (void)i686_vm32_widen_prot(ctx, gbase, gbase + hps);
        i686_vm32_subpage_unlock();
        return 0;
    }
    *out = atomic_load((const _Atomic uint32_t *)i686_guest_ptr(ctx, gva));
    return 0;
}

long i686_vm32_futex_wake(i686_ctx_t *ctx, uint32_t uaddr, uint32_t max_wake,
                          uint32_t bitset)
{
    unsigned i;
    long woken = 0;
    uint32_t limit = max_wake;
    (void)ctx;
    if (bitset == 0u) {
        return -EINVAL;
    }
    (void)pthread_mutex_lock(&s_futex_mtx);
    for (i = 0u; i < I686_VM32_FUTEX_SLOTS && (uint32_t)woken < limit; i++) {
        if (s_futex_slots[i].in_use != 0 &&
            s_futex_slots[i].gva == uaddr &&
            (s_futex_slots[i].bitset & bitset) != 0u) {
            atomic_store(&s_futex_slots[i].woken, 1u);
            s_futex_slots[i].gva = 0u;
            (void)rt_host_futex_wake_bitset(&s_futex_slots[i].woken, NULL, 1,
                                            0xFFFFFFFFu);
            woken++;
        }
    }
    (void)pthread_mutex_unlock(&s_futex_mtx);
    return woken;
}

long i686_vm32_futex(i686_ctx_t *ctx, uint32_t uaddr, uint32_t op,
                     uint32_t val, const struct timespec *timeout,
                     uint32_t val2, uint32_t uaddr2, uint32_t val3)
{
    uint32_t cmd = op & 0x7Fu;
    switch (cmd) {
    case 0u:   /* FUTEX_WAIT */
    case 9u: { /* FUTEX_WAIT_BITSET */
        uint32_t bitset = (cmd == 9u) ? val3 : 0xFFFFFFFFu;
        int abs_time = (cmd == 9u) ? 1 : 0;
        int clk_rt = ((op & 256u) != 0u) ? 1 : 0;
        uint32_t cur = 0u;
        unsigned i;
        int slot = -1;
        long rc;
        uint32_t was_woken;
        if (bitset == 0u) {
            return -EINVAL;
        }
        if (timeout != NULL &&
            (timeout->tv_sec < 0 || timeout->tv_nsec < 0 ||
             timeout->tv_nsec >= 1000000000L)) {
            return -EINVAL;
        }
        (void)pthread_mutex_lock(&s_futex_mtx);
        if (vm32_futex_load_u32(ctx, uaddr, &cur) != 0) {
            (void)pthread_mutex_unlock(&s_futex_mtx);
            return -EFAULT;
        }
        if (cur != val) {
            (void)pthread_mutex_unlock(&s_futex_mtx);
            return -EAGAIN;
        }
        for (i = 0u; i < I686_VM32_FUTEX_SLOTS; i++) {
            if (s_futex_slots[i].in_use == 0) {
                slot = (int)i;
                break;
            }
        }
        if (slot < 0) {
            (void)pthread_mutex_unlock(&s_futex_mtx);
            return -ENOMEM;
        }
        s_futex_slots[(unsigned)slot].gva = uaddr;
        s_futex_slots[(unsigned)slot].bitset = bitset;
        atomic_store(&s_futex_slots[(unsigned)slot].woken, 0u);
        s_futex_slots[(unsigned)slot].in_use = 1;
        (void)pthread_mutex_unlock(&s_futex_mtx);

        rc = (long)rt_host_futex_wait_bitset(
            &s_futex_slots[(unsigned)slot].woken, NULL, 0u, timeout, abs_time,
            clk_rt, 0xFFFFFFFFu, NULL, 0u);

        (void)pthread_mutex_lock(&s_futex_mtx);
        was_woken = atomic_load(&s_futex_slots[(unsigned)slot].woken);
        s_futex_slots[(unsigned)slot].in_use = 0;
        s_futex_slots[(unsigned)slot].gva = 0u;
        (void)pthread_mutex_unlock(&s_futex_mtx);
        return (was_woken != 0u) ? 0 : rc;
    }
    case 1u:  /* FUTEX_WAKE */
    case 10u: /* FUTEX_WAKE_BITSET */
        return i686_vm32_futex_wake(ctx, uaddr, val,
                                    (cmd == 10u) ? val3 : 0xFFFFFFFFu);
    case 3u:   /* FUTEX_REQUEUE */
    case 4u: { /* FUTEX_CMP_REQUEUE */
        unsigned i;
        long woken = 0;
        long requeued = 0;
        (void)pthread_mutex_lock(&s_futex_mtx);
        if (cmd == 4u) {
            uint32_t cur = 0u;
            if (vm32_futex_load_u32(ctx, uaddr, &cur) != 0) {
                (void)pthread_mutex_unlock(&s_futex_mtx);
                return -EFAULT;
            }
            if (cur != val3) {
                (void)pthread_mutex_unlock(&s_futex_mtx);
                return -EAGAIN;
            }
        }
        for (i = 0u; i < I686_VM32_FUTEX_SLOTS; i++) {
            if (s_futex_slots[i].in_use == 0 ||
                s_futex_slots[i].gva != uaddr) {
                continue;
            }
            if ((uint32_t)woken < val) {
                atomic_store(&s_futex_slots[i].woken, 1u);
                s_futex_slots[i].gva = 0u;
                (void)rt_host_futex_wake_bitset(&s_futex_slots[i].woken, NULL,
                                                1, 0xFFFFFFFFu);
                woken++;
            } else if ((uint32_t)requeued < val2) {
                s_futex_slots[i].gva = uaddr2;
                requeued++;
            }
        }
        (void)pthread_mutex_unlock(&s_futex_mtx);
        return (cmd == 4u) ? (woken + requeued) : woken;
    }
    default:
        return -ENOSYS;
    }
}
