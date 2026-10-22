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
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
long syscall(long, ...);
#include <unistd.h>

#include "i686rt.h"
#include "os/marshal.h"
#include "os/threads.h"

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

struct clone_arg {
    i686_ctx_t *ctx;   /* child's private ctx copy (heap) */
};

static void *thread_entry(void *arg)
{
    struct clone_arg *ca = arg;
    i686_ctx_t *ctx = ca->ctx;
    free(ca);

    (void)pthread_once(&s_once, make_key);
    (void)pthread_setspecific(s_ctx_key, ctx);
    s_thread_ctx = ctx;

    /* Interpreter runs until the thread exits. The engine entry point
     * is provided by the coordinator glue (interp loop over the copy);
     * for v1 the interp run function is invoked directly. */
    {
        extern int i686_interp_run(i686_ctx_t *);
        extern int i686_dbt_run(i686_ctx_t *);
        if (ctx->engine == I686_ENGINE_DBT) {
            (void)i686_dbt_run(ctx);
        } else {
            (void)i686_interp_run(ctx);
        }
    }
    /* CLONE_CHILD_CLEARTID: clear the tid word and futex-wake it
     * (kernel exit_mm/exit_notify behavior). */
    if (ctx->clear_child_tid != 0U) {
        uint32_t zero = 0U;
        memcpy(i686_guest_ptr(ctx, ctx->clear_child_tid), &zero, 4U);
        {
            long hcmd = 1 /*FUTEX_WAKE*/ + 128 /*PRIVATE*/;
            (void)syscall(SYS_futex,
                          i686_guest_ptr(ctx, ctx->clear_child_tid),
                          hcmd, 1, NULL, NULL, 0);
        }
        ctx->clear_child_tid = 0U;
    }
    return NULL;
}

int i686_tls_install(i686_ctx_t *ctx, uint32_t ud_va)
{
    i686_user_desc_t ud;
    int slot;

    if (i686_copy_from_guest(ctx, &ud.entry_number, ud_va, 4U) != 0) {
        return -EFAULT;
    }
    if (ud.entry_number == 0xFFFFFFFFU || ud.entry_number > 2U) {
        for (slot = 0; slot < 3; slot++) {
            if (ctx->gdt_tls_slots[slot] == 0U) {
                break;
            }
        }
        if (slot == 3) {
            slot = 0; /* recycle slot 0 (v1: one TLS per thread) */
        }
        ud.entry_number = (uint32_t)(6 + slot);
        if (i686_copy_to_guest(ctx, ud_va, &ud.entry_number, 4U) != 0) {
            return -EFAULT;
        }
    } else {
        slot = (int)ud.entry_number - 6;
        if (slot < 0 || slot > 2) {
            return -EINVAL;
        }
    }
    if (i686_copy_from_guest(ctx, &ud.base_addr, ud_va + 4U, 4U) != 0) {
        return -EFAULT;
    }
    ctx->gdt_tls_slots[slot] = ud.base_addr;
    ctx->seg_base[I686_SEG_GS] = ud.base_addr;
    ctx->seg_sel[I686_SEG_GS] = (uint32_t)(0x33 + 8 * slot);
    return (int)ctx->seg_sel[I686_SEG_GS];
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
    child->is_thread_clone = true;
    child->gpr[I686_REG_ESP] = newsp;
    child->gpr[I686_REG_EAX] = 0U;
    child->eip = child_eip;
    child->host_tid = 0;

    if ((flags & I686_CLONE_SETTLS) != 0U && tls_va != 0U) {
        (void)i686_tls_install(child, tls_va);
    }
    {
        /* small positive tids (i386 pid_t); the raw heap pointer
         * truncates to unpredictable 32-bit garbage. */
        static uint32_t s_next_tid = 101U;
        uint32_t tid = s_next_tid++;
        if ((flags & I686_CLONE_PARENT_SETTID) != 0U && parent_tid != 0U) {
            (void)i686_copy_to_guest(ctx, parent_tid, &tid, 4U);
        }
        if ((flags & I686_CLONE_CHILD_SETTID) != 0U && child_tid != 0U) {
            (void)i686_copy_to_guest(child, child_tid, &tid, 4U);
        }
        if ((flags & I686_CLONE_CHILD_CLEARTID) != 0U && child_tid != 0U) {
            child->clear_child_tid = child_tid;
        }
        r_val = tid;
    }

    ca->ctx = child;
    if (pthread_create(&th, NULL, thread_entry, ca) != 0) {
        free(child); free(ca);
        return -ENOMEM;
    }
    pthread_detach(th);
    return (int64_t)r_val; /* parent sees the positive tid */
}

void i686_threads_main_init(i686_ctx_t *ctx)
{
    extern void i686_sys_register(long, int64_t (*)(i686_ctx_t *));
    (void)pthread_once(&s_once, make_key);
    s_thread_ctx = ctx;
    (void)pthread_setspecific(s_ctx_key, ctx);
    i686_sys_register(120 /* clone */, r_clone);
}

void i686_threads_init(void)
{
    extern void i686_sys_register(long, int64_t (*)(i686_ctx_t *));
    (void)pthread_once(&s_once, make_key);
    if (s_thread_ctx != NULL) {
        (void)pthread_setspecific(s_ctx_key, s_thread_ctx);
    }
    i686_sys_register(120 /* clone */, r_clone);
}
