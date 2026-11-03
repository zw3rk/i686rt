/*
 * src/os/clone.c — guest thread creation (SPEC §3.6)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * v1 (single host thread per guest process): CLONE_VM without
 * CLONE_THREAD is -EINVAL. CLONE_THREAD without CLONE_VM takes the
 * fork path. CLONE_VM|CLONE_THREAD guest threads run
 * cooperatively on the interpreter's safe points when the host is
 * single-threaded — under fork() semantics CLONE_VM is impossible, so
 * glibc pthread_create paths in v1 actually take the fork-per-thread
 * approximation ONLY for CLONE_VM|CLONE_THREADS without shared memory
 * expectations... which breaks POSIX. Correct approach for RC4:
 * pthreads under dynamic glibc need TRUE shared memory. We therefore
 * implement clone(CLONE_VM|...) with a real host thread + ctx copy and
 * a private interpreter instance per thread, sharing the window (the
 * window mappings are MAP_SHARED see vm.c) — the interpreter touches
 * only its own ctx (stack-allocated), so true parallelism is safe.
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <sys/syscall.h>
long syscall(long, ...);
#endif
#include <unistd.h>

#include "i686rt.h"
#include "os/backend.h"
#include "os/marshal.h"
#include "os/threads.h"

static uint32_t clone_host_gettid(void)
{
#ifdef __linux__
    return (uint32_t)syscall(SYS_gettid);
#elif defined(__APPLE__)
    uint64_t tid = 0;
    (void)pthread_threadid_np(NULL, &tid);
    return (uint32_t)tid;
#else
    return (uint32_t)getpid();
#endif
}

static i686_ctx_t *s_thread_ctx; /* per-host-thread ctx (TLS via host) */
static pthread_key_t s_ctx_key;
static pthread_once_t s_once = PTHREAD_ONCE_INIT;

i686_ctx_t *i686_current_ctx(void);
i686_ctx_t *i686_current_ctx(void)
{
    return (i686_ctx_t *)pthread_getspecific(s_ctx_key);
}

static void make_key(void)
{
    (void)pthread_key_create(&s_ctx_key, NULL);
}

/* ---- guest tid registry (fix-campaign C1b) ----------------------------
 * tkill(238)/tgkill(270)/get_robust_list(312) route by guest tid, so a
 * tid -> ctx table lives next to the tid allocation in r_clone.  The
 * main ctx is found under its live process pid (the kernel main-thread
 * tid == pid convention, and the same value sys_getpid reports:
 * host_tid when a fork child, else the flat-model 1000); clone(2)
 * threads register under their synthetic tids.  Cross-thread signal
 * delivery means one host thread can lookup while another registers,
 * so the table is mutex-protected.  Entries of exited threads are
 * removed before the exit cleartid, so tkill to a dead tid reports
 * -ESRCH like the kernel.  Contexts are never freed in v1 (heap ctx
 * per thread, existing behavior), so a pointer handed out by
 * i686_thread_registry_find stays valid for the process lifetime.
 *
 * Each entry also carries the HOST tid of the interpreter thread that
 * runs the guest ctx (fix-campaign C2): the blocked-target wake sends
 * the dedicated host signal to it (thread_entry records it before the
 * engine runs; the main ctx is always the process's initial host
 * thread, whose tid == getpid()).
 */
#define I686_THREAD_REGISTRY_MAX 64U

static struct {
    uint32_t    tid;
    int         host_tid; /* 0 until thread_entry records it */
    i686_ctx_t *ctx;
} s_registry[I686_THREAD_REGISTRY_MAX];
static size_t       s_registry_n;
static size_t       s_registry_reserved;
static pthread_mutex_t s_registry_lock = PTHREAD_MUTEX_INITIALIZER;
static i686_ctx_t  *s_main_ctx;

static uint32_t thread_registry_main_pid_locked(void)
{
    if (s_main_ctx == NULL) {
        return 0U;
    }
    /* Must stay in lockstep with sys_getpid (src/os/syscalls.c). */
    return (s_main_ctx->host_tid > 0) ? (uint32_t)s_main_ctx->host_tid
                                      : 1000U;
}

void i686_thread_registry_main(i686_ctx_t *ctx);
void i686_thread_registry_main(i686_ctx_t *ctx)
{
    (void)pthread_mutex_lock(&s_registry_lock);
    s_main_ctx = ctx;
    (void)pthread_mutex_unlock(&s_registry_lock);
}

/* Main-ctx accessor for the async host-signal bridge (signals_i386.c):
 * the bridge targets process-directed host timers at the main thread.
 * Set once at startup before any clone; plain load is race-free. */
i686_ctx_t *i686_thread_registry_main_ctx(void);
i686_ctx_t *i686_thread_registry_main_ctx(void)
{
    return s_main_ctx;
}

/* r_exit runs the thread-exit teardown only for cloned threads; the
 * main thread's SYS_exit stays a process exit. */
int i686_thread_is_main(i686_ctx_t *ctx);
int i686_thread_is_main(i686_ctx_t *ctx)
{
    (void)pthread_mutex_lock(&s_registry_lock);
    int is_main = (s_main_ctx == ctx);
    (void)pthread_mutex_unlock(&s_registry_lock);
    return is_main;
}

/* Slot reservation for r_clone: claim the slot under the lock
 * before pthread_create so concurrent clones cannot race past a
 * shared space check. The reservation converts into a live entry
 * once the child publishes its tid; a failed create releases it. */
static int thread_registry_reserve(void);
static int thread_registry_reserve(void)
{
    int ok = 0;
    (void)pthread_mutex_lock(&s_registry_lock);
    if (s_registry_n + s_registry_reserved <
        I686_THREAD_REGISTRY_MAX) {
        s_registry_reserved++;
        ok = 1;
    }
    (void)pthread_mutex_unlock(&s_registry_lock);
    return ok;
}

static void thread_registry_unreserve(void);
static void thread_registry_unreserve(void)
{
    (void)pthread_mutex_lock(&s_registry_lock);
    if (s_registry_reserved > 0U) {
        s_registry_reserved--;
    }
    (void)pthread_mutex_unlock(&s_registry_lock);
}

static void thread_registry_commit(i686_ctx_t *ctx, uint32_t tid);
static void thread_registry_commit(i686_ctx_t *ctx, uint32_t tid)
{
    (void)pthread_mutex_lock(&s_registry_lock);
    if (s_registry_reserved > 0U) {
        s_registry_reserved--;
    }
    if (s_registry_n < I686_THREAD_REGISTRY_MAX) {
        s_registry[s_registry_n].tid = tid;
        s_registry[s_registry_n].host_tid = (int)tid;
        s_registry[s_registry_n].ctx = ctx;
        s_registry_n++;
    }
    (void)pthread_mutex_unlock(&s_registry_lock);
}

void i686_thread_registry_add(i686_ctx_t *ctx, uint32_t tid);
void i686_thread_registry_add(i686_ctx_t *ctx, uint32_t tid)
{
    (void)pthread_mutex_lock(&s_registry_lock);
    if (s_registry_n < I686_THREAD_REGISTRY_MAX) {
        s_registry[s_registry_n].tid = tid;
        s_registry[s_registry_n].host_tid = (int)tid;
        s_registry[s_registry_n].ctx = ctx;
        s_registry_n++;
    }
    /* Over the bound: the tid stays unregistered, tkill reports -ESRCH
     * for it (bounded table, v1 thread count is small). */
    (void)pthread_mutex_unlock(&s_registry_lock);
}

void i686_thread_registry_remove(uint32_t tid);
void i686_thread_registry_remove(uint32_t tid)
{
    size_t i;
    (void)pthread_mutex_lock(&s_registry_lock);
    for (i = 0U; i < s_registry_n; i++) {
        if (s_registry[i].tid == tid) {
            s_registry[i] = s_registry[s_registry_n - 1U];
            s_registry_n--;
            break;
        }
    }
    (void)pthread_mutex_unlock(&s_registry_lock);
}

i686_ctx_t *i686_thread_registry_find(uint32_t tid);
i686_ctx_t *i686_thread_registry_find(uint32_t tid)
{
    i686_ctx_t *found = NULL;
    size_t i;
    (void)pthread_mutex_lock(&s_registry_lock);
    for (i = 0U; i < s_registry_n; i++) {
        if (s_registry[i].tid == tid) {
            found = s_registry[i].ctx;
            break;
        }
    }
    if (found == NULL && tid == thread_registry_main_pid_locked()) {
        found = s_main_ctx;
    }
    (void)pthread_mutex_unlock(&s_registry_lock);
    return found;
}

/* The process id every thread clone shares (tgkill checks it). */
uint32_t i686_thread_registry_tgid(void);
uint32_t i686_thread_registry_tgid(void)
{
    uint32_t tgid;
    (void)pthread_mutex_lock(&s_registry_lock);
    tgid = thread_registry_main_pid_locked();
    (void)pthread_mutex_unlock(&s_registry_lock);
    return tgid;
}

/* The caller's own guest tid (set_tid_address's kernel return value).
 * find() compares pointers, so threads that share no ctx cannot alias. */
uint32_t i686_thread_registry_self_tid(const i686_ctx_t *ctx);
uint32_t i686_thread_registry_self_tid(const i686_ctx_t *ctx)
{
    uint32_t tid = 0U;
    size_t i;
    (void)pthread_mutex_lock(&s_registry_lock);
    for (i = 0U; i < s_registry_n; i++) {
        if (s_registry[i].ctx == ctx) {
            tid = s_registry[i].tid;
            break;
        }
    }
    if (tid == 0U && s_main_ctx == ctx) {
        tid = thread_registry_main_pid_locked();
    }
    (void)pthread_mutex_unlock(&s_registry_lock);
    return tid;
}

struct clone_arg {
    i686_ctx_t *ctx;          /* child's private ctx copy (heap) */
    uint32_t parent_tid_va;   /* PARENT_SETTID word (musl's self->tid) */
    uint32_t child_tid_va;    /* CHILD_SETTID word (glibc's tid slot) */
    pthread_mutex_t mtx;      /* startup handshake: child publishes host tid */
    pthread_cond_t cond;      /* parent registers it before clone returns */
    uint32_t host_tid;        /* child's host tid (guest tid namespace) */
    int ready;                /* child published host_tid */
    int registered;           /* parent registered host_tid */
};

/* ---- blocked-target wake (fix-campaign C2) ----------------------------
 * A guest thread sleeping in a host futex (pthread_cond_wait and
 * friends) never reaches an interpreter safe point, so a pending
 * signal bit set by another thread's tkill/tgkill is never polled and
 * pthread_cancel/timers targeting it hang.  A raise with a deliverable
 * (unmasked) bit therefore interrupts the target's host futex with a
 * dedicated host signal: the futex returns -EINTR, the guest re-checks
 * its futex value in interpreted code and reaches the safe-point poll,
 * which delivers the pending signal.
 *
 * Host SIGUSR1 only: the guest's own signal namespace never touches
 * host signal state, and the host-fault checkpoint (interp.c) is armed
 * on the SIGSEGV/SIGBUS/SIGILL/SIGFPE family with its own handler — a
 * second signal with an empty handler cannot interact with that jump
 * buffer.  No SA_RESTART, deliberately: the EINTR is the point (the
 * same EINTR a native kernel produces for an interrupting guest
 * signal). */

#define I686RT_HOST_WAKE_SIG SIGUSR1

static pthread_once_t s_wake_once = PTHREAD_ONCE_INIT;

static void wake_sig_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig; (void)si; (void)uc; /* empty: the EINTR is the effect */
}

static void wake_sig_install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = wake_sig_handler;
    sa.sa_flags = SA_SIGINFO; /* NO SA_RESTART: the EINTR is the point */
    (void)sigaction(I686RT_HOST_WAKE_SIG, &sa, NULL);
}

/* Interrupt target's host futex wait.  Called with the pending bit
 * already set; errors ignored (a dead host tid simply raced an exit).
 * No-op for the caller's own ctx: it is running and polls at its own
 * safe points. */
void i686_thread_registry_wake(i686_ctx_t *target);
void i686_thread_registry_wake(i686_ctx_t *target)
{
    int host_tid = 0;
    size_t i;

    if (target == NULL || target == i686_current_ctx()) {
        return;
    }
    (void)pthread_once(&s_wake_once, wake_sig_install);
    (void)pthread_mutex_lock(&s_registry_lock);
    for (i = 0; i < s_registry_n; i++) {
        if (s_registry[i].ctx == target) {
            host_tid = s_registry[i].host_tid;
            break;
        }
    }
    if (host_tid == 0 && target == s_main_ctx) {
        host_tid = (int)getpid(); /* main thread: tid == pid */
    }
    (void)pthread_mutex_unlock(&s_registry_lock);
    if (host_tid > 0) {
#ifdef __linux__
        (void)syscall(SYS_tgkill, (pid_t)getpid(), (pid_t)host_tid,
                      I686RT_HOST_WAKE_SIG);
#else
        (void)rt_host_tgkill((int)getpid(), host_tid, I686RT_HOST_WAKE_SIG);
#endif
    }
}

/* ---- robust-list walk at thread exit (fix-campaign C2) ----------------
 * The kernel walks the dying thread's robust list (exit_robust_list)
 * when the guest never got to release its robust mutexes: every word
 * still owned by this tid gains FUTEX_OWNER_DIED and, when the
 * WAITERS bit shows a queued waiter, one waiter is futex-woken (it
 * then observes EOWNERDEAD).  The translator walks the list itself:
 * the guest head holds 32-bit guest pointers the host kernel cannot
 * dereference.  musl sets the mutex word tid to the guest tid handed
 * out by set_tid_address/gettid, so the ownership check uses the same
 * registry tid that r_clone allocated. */

#define FUTEX_WAITERS_BIT_      0x80000000u
#define FUTEX_OWNER_DIED_BIT_   0x40000000u
#define FUTEX_TID_MASK_         0x3fffffffu
#define ROBUST_WALK_LIMIT_      1024u

static int robust_fetch_u32(i686_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    return i686_copy_from_guest(ctx, out, va, 4U);
}

/* kernel handle_futex_death: cmpxchg OWNER_DIED into the word while it
 * still names this tid; wake one waiter when WAITERS is set (never for
 * the list_op_pending entry, which may name a word under acquisition).
 * The cmpxchg interlocks with guest LOCK-CMPXCHG executions on other
 * interpreter threads; the window word is shared host memory. */
static void robust_handle_death(i686_ctx_t *ctx, uint32_t futex_va,
                                uint32_t tid, int pending)
{
    extern int i686_subpage_range_ok(const i686_ctx_t *, uint32_t, uint64_t, uint8_t);
    extern int i686_vm32_union_prot(i686_ctx_t *, uint32_t, uint32_t);
    extern int i686_vm32_widen_prot(i686_ctx_t *, uint32_t, uint32_t);
    extern void i686_vm32_subpage_lock(void);
    extern void i686_vm32_subpage_unlock(void);
    extern long i686_vm32_futex_wake(i686_ctx_t *, uint32_t, uint32_t, uint32_t);
    volatile void *hp;
    uint32_t uval;
    uint32_t after = 0u;
    int tries;

    if (robust_fetch_u32(ctx, futex_va, &uval) != 0) {
        return; /* faulted word: kernel stops the walk too */
    }
    if ((uval & FUTEX_TID_MASK_) != tid) {
        return; /* not ours (or already recovered) */
    }
    if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u) {
        uint32_t hps = ctx->vm_host_page;
        uint32_t gbase = futex_va & ~(hps - 1u);
        if (i686_subpage_range_ok(ctx, futex_va, 4u, 0x03u) == 0) {
            return;
        }
        i686_vm32_subpage_lock();
        (void)i686_vm32_union_prot(ctx, gbase, gbase + hps);
        hp = i686_guest_ptr(ctx, futex_va);
        for (tries = 0; tries < 8; tries++) {
            uint32_t cur = uval;
            if (atomic_compare_exchange_strong((_Atomic uint32_t *)hp, &cur,
                                               uval | FUTEX_OWNER_DIED_BIT_)) {
                break;
            }
            uval = cur;
        }
        after = atomic_load((_Atomic uint32_t *)hp);
        {
            /* I686-R4-1: release the subpage lock BEFORE the futex wake.
             * Lock order is futex-outer/subpage-inner everywhere; waking
             * while holding the subpage lock inverts FUTEX_WAIT's nesting
             * (futex -> subpage) and can deadlock a concurrent fork. */
            int need_wake =
                (!pending && (after & FUTEX_WAITERS_BIT_) != 0u) ? 1 : 0;
            (void)i686_vm32_widen_prot(ctx, gbase, gbase + hps);
            i686_vm32_subpage_unlock();
            if (need_wake) {
                (void)i686_vm32_futex_wake(ctx, futex_va, 1u, 0xFFFFFFFFu);
            }
        }
        return;
    }
    hp = i686_guest_ptr(ctx, futex_va);
    for (tries = 0; tries < 8; tries++) {
        uint32_t cur = uval;
        if (atomic_compare_exchange_strong((_Atomic uint32_t *)hp, &cur,
                                           uval | FUTEX_OWNER_DIED_BIT_)) {
            break;
        }
        uval = cur; /* raced; retry like the kernel cmpxchg loop */
    }
    if (!pending) {
        if (robust_fetch_u32(ctx, futex_va, &after) == 0 &&
            (after & FUTEX_WAITERS_BIT_) != 0u) {
#ifdef __linux__
            long hcmd = 1 /*FUTEX_WAKE*/ + 128 /*PRIVATE*/;
            (void)syscall(SYS_futex, (void *)hp, hcmd, 1, NULL, NULL, 0);
#else
            (void)i686_vm32_futex_wake(ctx, futex_va, 1u, 0xFFFFFFFFu);
#endif
        }
    }
}

static void robust_exit_walk(i686_ctx_t *ctx, uint32_t tid)
{
    struct {
        uint32_t list;        /* struct robust_list __user *next */
        int32_t  futex_offset;
        uint32_t list_op_pending;
    } head;
    uint32_t entry, pending;
    size_t n;

    if (ctx->robust_list_head == 0U) {
        return;
    }
    if (i686_copy_from_guest(ctx, &head, ctx->robust_list_head,
                             sizeof(head)) != 0) {
        return;
    }
    pending = head.list_op_pending;
    entry = head.list;
    for (n = 0; n < ROBUST_WALK_LIMIT_; n++) {
        uint32_t next;
        if (entry == 0U || entry == ctx->robust_list_head) {
            break; /* empty or end of the circular list */
        }
        if (robust_fetch_u32(ctx, entry, &next) != 0) {
            break; /* faulted next pointer: stop the walk */
        }
        robust_handle_death(ctx, entry + (uint32_t)head.futex_offset,
                            tid, 0);
        entry = next;
    }
    if (pending != 0U) {
        robust_handle_death(ctx, pending + (uint32_t)head.futex_offset,
                            tid, 1);
    }
}

static void *thread_entry(void *arg)
{
    struct clone_arg *ca = arg;
    i686_ctx_t *ctx = ca->ctx;
    uint32_t parent_tid_va = ca->parent_tid_va;
    uint32_t child_tid_va = ca->child_tid_va;
    uint32_t tid;

    (void)pthread_once(&s_once, make_key);
    (void)pthread_setspecific(s_ctx_key, ctx);
    s_thread_ctx = ctx;
    (void)pthread_once(&s_wake_once, wake_sig_install);

    /* I686-R3-1: the guest tid namespace is the host one throughout.
     * Publish this thread's host tid to the parent, wait until the
     * parent has registered it (so clone's return value, gettid,
     * tkill/tgkill, and both SETTID words agree), then publish the
     * CHILD_SETTID word before any guest code runs. The parent writes
     * the PARENT_SETTID word itself before clone returns, so it is
     * visible on return. musl's self->tid is the PARENT_SETTID word
     * (shared TLS); glibc's is CHILD_SETTID. */
    tid = clone_host_gettid();
    (void)pthread_mutex_lock(&ca->mtx);
    ca->host_tid = tid;
    ca->ready = 1;
    (void)pthread_cond_signal(&ca->cond);
    while (ca->registered == 0) {
        (void)pthread_cond_wait(&ca->cond, &ca->mtx);
    }
    tid = ca->host_tid;
    parent_tid_va = ca->parent_tid_va;
    child_tid_va = ca->child_tid_va;
    ctx = ca->ctx;
    (void)pthread_mutex_unlock(&ca->mtx);
    (void)pthread_mutex_destroy(&ca->mtx);
    (void)pthread_cond_destroy(&ca->cond);
    free(ca);
    if (child_tid_va != 0U) {
        (void)i686_copy_to_guest(ctx, child_tid_va, &tid, 4U);
    }
    (void)parent_tid_va;

    /* Interpreter runs until the thread exits. The engine entry point
     * is provided by the coordinator glue (interp loop over the copy);
     * for v1 the interp run function is invoked directly. */
    {
        extern int i686_interp_run(i686_ctx_t *);
#ifndef I686RT_NO_DBT
        extern int i686_dbt_run(i686_ctx_t *);
        if (ctx->engine == I686_ENGINE_DBT) {
            (void)i686_dbt_run(ctx);
        } else {
#else
        {
#endif
            (void)i686_interp_run(ctx);
        }
    }
    /* Normally the exit syscall ran the teardown already (see
     * i686_thread_exit_teardown — kernel do_exit completes it inside
     * the dying thread's last syscall, before the guest-side joiner
     * wake can free the stack); the guard keeps this tail idempotent
     * for exits that skip the syscall path.  After the teardown the
     * thread must touch NO guest memory: musl's exit wakes the joiner
     * in guest code BEFORE SYS_exit, and every guest write past that
     * point lands in the recycled range (the C2 rt32 stack-overlap
     * defect). */
    i686_thread_exit_teardown(ctx);
    return NULL;
}

/* Kernel do_exit tail for a guest thread, run at the exit syscall (see
 * r_exit): robust-list recovery BEFORE the exit cleartid, in kernel
 * do_exit order — a waiter woken EOWNERDEAD may join behind us, and the
 * cleartid is the join-release event.  Once this returns, the dying
 * thread must never write guest memory again. */
void i686_thread_exit_teardown(i686_ctx_t *ctx)
{
    /* C2-2: split the idempotence guard per phase.  The cleartid
     * memcpy can host-fault (widened guard page); the fault path
     * emulates it via interpret-one, which re-runs the exit syscall
     * and re-enters this function.  A single s_done set before the
     * clear would skip the clear AND the joiner wake on re-entry,
     * hanging the joiner forever.  Robust recovery stays at-most-once
     * (a faulted walk simply degrades, as before); the clear+wake is
     * idempotent and retried until it completes. */
    extern void i686_vm32_exec_leave(void);
    static __thread int s_robust_done;
    static __thread int s_clear_done;
    uint32_t tid;

    i686_vm32_exec_leave();
    if (s_robust_done == 0) {
        s_robust_done = 1;
        tid = clone_host_gettid();
        robust_exit_walk(ctx, tid);
    } else {
        tid = clone_host_gettid();
    }
    /* CLONE_CHILD_CLEARTID: clear the tid word and futex-wake it
     * (kernel exit_mm/exit_notify behavior).  The registry entry is
     * removed first, so a concurrent tkill sees -ESRCH for this dead
     * tid rather than signaling a ctx no thread will ever poll. */
    i686_thread_registry_remove(tid);
    if (ctx->clear_child_tid != 0U && s_clear_done == 0) {
        uint32_t zero = 0U;
        uint32_t ctid_va = ctx->clear_child_tid;
        extern int i686_vm32_union_prot(i686_ctx_t *, uint32_t, uint32_t);
        extern int i686_vm32_widen_prot(i686_ctx_t *, uint32_t, uint32_t);
        extern void i686_vm32_subpage_lock(void);
        extern void i686_vm32_subpage_unlock(void);
        extern long i686_vm32_futex_wake(i686_ctx_t *, uint32_t, uint32_t,
                                         uint32_t);
        i686_vm32_subpage_lock();
        {
            uint32_t hps = (ctx->vm_host_page != 0u) ?
                ctx->vm_host_page : 4096u;
            uint32_t cpage = ctid_va & ~(hps - 1u);
            (void)i686_vm32_union_prot(ctx, cpage, cpage + hps);
            memcpy(i686_guest_ptr(ctx, ctid_va), &zero, 4U);
            s_clear_done = 1;
            (void)i686_vm32_widen_prot(ctx, cpage, cpage + hps);
        }
        i686_vm32_subpage_unlock();
        if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u) {
            (void)i686_vm32_futex_wake(ctx, ctid_va, 1u, 0xFFFFFFFFu);
        } else {
#ifdef __linux__
            (void)syscall(SYS_futex, i686_guest_ptr(ctx, ctid_va),
                          1 /*FUTEX_WAKE*/ + 128 /*PRIVATE*/, 1,
                          NULL, NULL, 0);
            (void)syscall(SYS_futex, i686_guest_ptr(ctx, ctid_va),
                          1 /*FUTEX_WAKE*/, 1, NULL, NULL, 0);
#else
            (void)i686_vm32_futex_wake(ctx, ctid_va, 1u, 0xFFFFFFFFu);
#endif
        }
        ctx->clear_child_tid = 0U;
    }
}

/* CLONE_SETTLS: kernel copy_thread semantics — the descriptor lives in
 * src/os/ldt.c (i686_ldt_clone_settls, per-thread tls_desc[3] from RC7b
 * triage-6).  The desc's entry_number (6..8, glibc passes the parent's
 * GS entry) is honored verbatim: no -1 auto-alloc, no write-back, no
 * slot recycling.  Returns 0 or a negative errno; the caller must fail
 * the clone on error, like the kernel does. */
int i686_tls_install(i686_ctx_t *ctx, uint32_t ud_va)
{
    extern long i686_ldt_clone_settls(i686_ctx_t *ctx, uint32_t ua);

    return (int)i686_ldt_clone_settls(ctx, ud_va);
}

static int64_t r_clone(i686_ctx_t *ctx)
{
    uint32_t flags = ctx->gpr[I686_REG_EBX];
    uint32_t newsp = ctx->gpr[I686_REG_ECX];
    uint32_t parent_tid = ctx->gpr[I686_REG_EDX];
    uint32_t tls_va = ctx->gpr[I686_REG_ESI];
    uint32_t child_tid = ctx->gpr[I686_REG_EDI];
    i686_ctx_t *child;
    struct clone_arg *ca;
    pthread_t th;
    uint32_t r_val = 0U;
    uint32_t child_eip = ctx->eip; /* engine sets exit_dest at clone */

    {
    }

    if ((flags & I686_CLONE_VM) == 0U) {
        /* Process-style clone == fork semantics: the window is private
         * COW, so host fork() gives exactly this. */
        extern int64_t i686_sys_call_nr(long nr, i686_ctx_t *ctx);
        return i686_sys_call_nr(2 /* fork */, ctx);
    }
    if ((flags & I686_CLONE_THREAD) == 0U && (flags & I686_CLONE_VM) != 0U) {
        /* CLONE_VM|CLONE_VFORK (glibc posix_spawn — wine's wineserver
         * launch, RC7b): the child only ever execve()s or _exit()s.
         * Under the translator a host fork() copy gives exactly that
         * observable behavior (the exec discards the copied memory);
         * the parent's waitpid reaps the exec'd image's status.
         * Kernel ABI: with CLONE_VM the child's ESP is the requested
         * newsp.  The glibc clone wrapper pre-stores flags/fake-ret/
         * fn/arg at [newsp..newsp+12] and its child path (EAX==0)
         * pops fn into EBX and calls *EBX — resuming the child on the
         * parent's ESP pops the parent's callee-saves instead and
         * calls through garbage (RC7b T4: `call *%ebx` with
         * EBX=0xffffffff, fault eip=0xffffffff in the spawn child).
         * Without CLONE_VM (plain fork/vfork) the kernel ignores
         * newsp and the child keeps the parent's ESP. */
        pid_t pid = fork();
        if (pid < 0) {
            return -errno;
        }
        if (pid == 0) {
            ctx->host_tid = (int)getpid();
            if (newsp != 0U) {
                ctx->gpr[I686_REG_ESP] = newsp;
            }
            return 0;
        }
        return (int64_t)pid;
    }

    child = malloc(sizeof(*child));
    ca = malloc(sizeof(*ca));
    if (child == NULL || ca == NULL) {
        free(child); free(ca);
        return -ENOMEM;
    }
    memcpy(child, ctx, sizeof(*child));
    /* A copied ctx must not inherit the parent's exit coordination: the
     * child starts with no pending signals, no robust list, and a
     * clear_child_tid only when CLONE_CHILD_CLEARTID was passed (else
     * the child would clear the parent's TID word on exit). */
    child->pending_signals = 0U;
    child->robust_list_head = 0U;
    child->robust_list_len = 0U;
    child->clear_child_tid =
        ((flags & I686_CLONE_CHILD_CLEARTID) != 0U) ? child_tid : 0U;
    /* C2-2: the parent's IBTC/RAS cache host pointers must not leak into
     * the child.  The child owns a separate __thread translation cache
     * and IBTC epoch space; an inherited {key, host_code, entry} tuple
     * would dispatch the child into a parent block that a later parent
     * eviction munmaps (and the host address may be reused for an
     * unrelated block).  Start the child with cold predictor state. */
    memset(child->ibtc, 0, sizeof(child->ibtc));
    memset(child->ras, 0, sizeof(child->ras));
    child->ras_top = 0U;
    child->is_thread_clone = true;
    child->gpr[I686_REG_ESP] = newsp;
    child->gpr[I686_REG_EAX] = 0U;
    child->eip = child_eip;
    /* Threads share the thread group: getpid() reports the tgid (the
     * process's live pid), not the thread's tid. */
    child->host_tid = (int)getpid();
    ca->ctx = child;
    ca->parent_tid_va = 0U;
    ca->child_tid_va = 0U;
    ca->host_tid = 0U;
    ca->ready = 0;
    ca->registered = 0;
    if (pthread_mutex_init(&ca->mtx, NULL) != 0 ||
        pthread_cond_init(&ca->cond, NULL) != 0) {
        free(child);
        free(ca);
        return -ENOMEM;
    }

    if ((flags & I686_CLONE_SETTLS) != 0U && tls_va != 0U) {
        /* Kernel-faithful (RC7b T4c): a bad TLS descriptor fails the
         * clone (-EINVAL/-EFAULT), it is not ignored. */
        long terr = i686_tls_install(child, tls_va);
        if (terr != 0) {
            (void)pthread_mutex_destroy(&ca->mtx);
            (void)pthread_cond_destroy(&ca->cond);
            free(child); free(ca);
            return terr;
        }
    }
    if ((flags & I686_CLONE_PARENT_SETTID) != 0U && parent_tid != 0U) {
        ca->parent_tid_va = parent_tid;
    }
    if ((flags & I686_CLONE_CHILD_SETTID) != 0U && child_tid != 0U) {
        ca->child_tid_va = child_tid;
    }
    /* child->clear_child_tid was reset right after the memcpy above:
     * present only when CLONE_CHILD_CLEARTID was passed. */

    if (!thread_registry_reserve()) {
        (void)pthread_mutex_destroy(&ca->mtx);
        (void)pthread_cond_destroy(&ca->cond);
        free(child); free(ca);
        return -EAGAIN;
    }

#ifndef I686RT_NO_DBT
    {
        extern void i686_dbt_enable_tso(void);
        i686_dbt_enable_tso();
    }
#endif
    {
        int crc;
        crc = pthread_create(&th, NULL, thread_entry, ca);
        if (crc != 0) {
            thread_registry_unreserve();
            (void)pthread_mutex_destroy(&ca->mtx);
            (void)pthread_cond_destroy(&ca->cond);
            free(child); free(ca);
            return -ENOMEM;
        }
    }
    (void)pthread_mutex_lock(&ca->mtx);
    while (ca->ready == 0) {
        (void)pthread_cond_wait(&ca->cond, &ca->mtx);
    }
    r_val = ca->host_tid;
    thread_registry_commit(child, r_val);
    if (ca->parent_tid_va != 0U) {
        (void)i686_copy_to_guest(ctx, ca->parent_tid_va, &r_val, 4U);
    }
    ca->registered = 1;
    (void)pthread_cond_signal(&ca->cond);
    (void)pthread_mutex_unlock(&ca->mtx);
    pthread_detach(th);
    return (int64_t)r_val; /* parent sees the child's host tid */
}

/* Global fork lock order (I686-R4-1): VM spinlock > registry >
 * futex > subpage. fork_prepare nests in that order; the futex and
 * subpage pair inside i686_vm32_fork_prepare nests futex-outer to match
 * FUTEX_WAIT/FUTEX_CMP_REQUEUE (futex held across the subpage healing
 * window). Truncate/pwrite paths nest VM-outer/subpage-inner and never
 * take the futex lock, so no cycle exists. */
static void fork_prepare(void)
{
    extern void rt32_vm_fork_prepare(void);
    extern void i686_vm32_fork_prepare(void);
    rt32_vm_fork_prepare();
    (void)pthread_mutex_lock(&s_registry_lock);
    i686_vm32_fork_prepare();
}

static void fork_parent(void)
{
    extern void rt32_vm_fork_parent(void);
    extern void i686_vm32_fork_parent(void);
    i686_vm32_fork_parent();
    (void)pthread_mutex_unlock(&s_registry_lock);
    rt32_vm_fork_parent();
}

static void fork_child(void)
{
    extern void rt32_vm_fork_child(void);
    extern void i686_vm32_fork_child(void);
    extern void i686_aot_fork_child(void);
    extern void i686_gsig_fork_child(void);
#ifndef I686RT_NO_DBT
    extern void i686_dbt_fork_child(void);
#endif
    i686_ctx_t *surviving;
    rt32_vm_fork_child();
    i686_vm32_fork_child();
    /* The signal-action mutex may be held by a dead thread; reinitialize
     * it like the other runtime-owned mutexes (I686-R4-6). */
    i686_gsig_fork_child();
#ifndef I686RT_NO_DBT
    i686_dbt_fork_child();
#endif
    i686_aot_fork_child();
    (void)pthread_mutex_destroy(&s_registry_lock);
    (void)pthread_mutex_init(&s_registry_lock, NULL);
    surviving = i686_current_ctx();
    if (surviving == NULL) {
        surviving = s_thread_ctx;
    }
    if (surviving == NULL) {
        surviving = s_main_ctx;
    }
    (void)pthread_mutex_lock(&s_registry_lock);
    s_registry_n = 0;
    s_registry_reserved = 0;
    if (surviving != NULL) {
        s_main_ctx = surviving;
        surviving->host_tid = (int)getpid();
        surviving->is_thread_clone = false;
        if (s_registry_n < I686_THREAD_REGISTRY_MAX) {
            s_registry[s_registry_n].tid = (uint32_t)surviving->host_tid;
            s_registry[s_registry_n].host_tid = surviving->host_tid;
            s_registry[s_registry_n].ctx = surviving;
            s_registry_n++;
        }
    }
    (void)pthread_mutex_unlock(&s_registry_lock);
}

static pthread_once_t s_fork_once = PTHREAD_ONCE_INIT;

static void fork_register(void)
{
    (void)pthread_atfork(fork_prepare, fork_parent, fork_child);
}

void i686_threads_main_init(i686_ctx_t *ctx)
{
    extern void i686_sys_register(long, int64_t (*)(i686_ctx_t *));
    (void)pthread_once(&s_once, make_key);
    (void)pthread_once(&s_fork_once, fork_register);
    s_thread_ctx = ctx;
    (void)pthread_setspecific(s_ctx_key, ctx);
    /* The main thread's host tid IS the process pid (kernel main-thread
     * tid == pid convention): sys_getpid's lockstep rule reads this
     * field, and set_tid_address/gettid return it — the tid namespace
     * is the host one so kernel-owned futex words (PI ops, robust-list
     * recovery, cleartid wakes) agree with the guest's view. */
    ctx->host_tid = (int)getpid();
    i686_thread_registry_main(ctx);
    i686_sys_register(120 /* clone */, r_clone);
}

void i686_threads_init(void)
{
    extern void i686_sys_register(long, int64_t (*)(i686_ctx_t *));
    (void)pthread_once(&s_once, make_key);
    (void)pthread_once(&s_fork_once, fork_register);
    if (s_thread_ctx != NULL) {
        (void)pthread_setspecific(s_ctx_key, s_thread_ctx);
    }
    i686_sys_register(120 /* clone */, r_clone);
}
