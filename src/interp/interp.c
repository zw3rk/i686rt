/*
 * src/interp/interp.c — interpreter loop and handler registry (SPEC D2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The interpreter is the correctness oracle: decode → dispatch → repeat.
 * Handlers advance EIP themselves (branches set it directly); exit codes
 > 0 return to this loop for reason-specific handling.  Unknown opcodes
 * stop with a diagnostic — never an abort (D2).
 */

#if defined(__linux__) && !defined(_GNU_SOURCE)
/* The faulting host PC lives in ucontext_t->uc_mcontext.pc, which musl
 * only exposes under _GNU_SOURCE (same guarded pattern as
 * src/vm/vm_file.c). */
#define _GNU_SOURCE 1
#endif

#include <setjmp.h>
#include <string.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#if defined(__linux__) && defined(__aarch64__)
#include <sys/ucontext.h>
#endif

#include "dbt/aot/aot.h"
#include "interp/flags.h"
#include "interp/interp.h"
#include "os/marshal.h"

/* x86 helpers owned by sibling lanes (same extern pattern as h_alu.c). */
extern uint8_t x86_ea_seg(const x86_insn_t *insn);
extern void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg, uint32_t linear,
                                unsigned bytes);

/* Host-fault -> guest-fault checkpoint (Phase 4).  The handler runs on
 * the faulting host thread; sigsetjmp/siglongjmp restores the interp
 * loop with the fault recorded.  The jump target lives in the frame of
 * the i686_interp_run call that armed it — one per host thread, via
 * the __thread pointer below (the previous file-static buffer let a
 * fault in one guest thread siglongjmp through whichever guest thread
 * armed it last, resuming on a foreign stack: RC7b T4d). */
static __thread sigjmp_buf *s_fault_jmp;
static volatile sig_atomic_t s_in_run;
static volatile uint64_t s_fault_addr;
static volatile uint64_t s_fault_host_pc;

/* Pre-instruction ESP/EBP checkpoint (RC-U3): a faulting stack op must
 * not leave ESP/EBP mutated (No-Double-Side-Effect).  Only stack ops
 * mutate them mid-instruction, so restoring on fault is exact. */
static __thread uint32_t s_saved_esp;
static __thread uint32_t s_saved_ebp;

static volatile sig_atomic_t s_fault_sig;

static void host_fault_handler(int sig, siginfo_t *si, void *uc_)
{
    sigjmp_buf *jb = s_fault_jmp;
#if defined(__linux__) && defined(__aarch64__)
    {
        ucontext_t *uc = (ucontext_t *)uc_;
        s_fault_host_pc = (uc != NULL) ? (uint64_t)uc->uc_mcontext.pc : 0u;
    }
#else
    (void)uc_;
    s_fault_host_pc = 0u;
#endif
    if (sig == SIGSEGV && si->si_code == SEGV_ACCERR) {
#ifndef I686RT_NO_DBT
        /* D11 SMC: a write to a DBT code-protected window page.  The
         * engine drops the page's blocks and restores RW; returning
         * re-executes the store. */
        extern int i686_dbt_smc_write_fault(uint64_t host_addr);
        if (i686_dbt_smc_write_fault((uint64_t)(uintptr_t)si->si_addr)) {
            return;
        }
#endif
    }
    if (s_in_run && jb != NULL) {
        s_fault_jmp = NULL; /* disarm: a nested fault must not re-jump */
        s_fault_addr = (uint64_t)(uintptr_t)si->si_addr;
        s_fault_sig = sig;
        siglongjmp(*jb, 1);
    }
    _exit(128 + sig);
}

void i686_host_faults_install(void); /* engine.c uses the same checkpoint */

void i686_fault_arm(sigjmp_buf *jb)
{
    s_fault_jmp = jb;
    s_in_run = 1;
}

void i686_diag_fault(i686_ctx_t *ctx)
{
    (void)fprintf(stderr,
                  "i686rt: dbt: guest fault (host) pid=%d at eip=0x%08x, "
                  "fault_addr=0x%08x\n",
                  (int)getpid(), ctx->eip, ctx->fault_addr);
    if (ctx->region_count > 0U) {
        size_t i;
        for (i = 0U; i < ctx->region_count; i++) {
            const i686_region_t *rg = &ctx->regions[i];
            (void)fprintf(stderr, "MAP %08x-%08x %c%c%c %s\n",
                          rg->start, rg->end,
                          (rg->prot & 0x1U) ? 'r' : '-',
                          (rg->prot & 0x2U) ? 'w' : '-',
                          (rg->prot & 0x4U) ? 'x' : '-',
                          rg->name[0] != '\0' ? rg->name : "");
        }
    }
}

void i686_fault_disarm(void)
{
    s_fault_jmp = NULL;
}

uint64_t i686_fault_addr(void)
{
    return s_fault_addr;
}

int i686_fault_sig(void)
{
    return (int)s_fault_sig;
}

/* Faulting host PC (DBT site recovery in engine.c; 0 when unknown). */
uint64_t i686_fault_host_pc(void)
{
    return (uint64_t)s_fault_host_pc;
}

/* C3f: synthetic fault exits (h_muldiv's #DE) pin the channel the same
 * way the host handler does, so deliver_sync classifies them by signal
 * instead of by a stale ctx->exit_arg. */
void i686_fault_sig_record(int sig)
{
    s_fault_sig = (sig_atomic_t)sig;
}

static void host_faults_install(void); /* fwd (below) */

void i686_host_faults_install(void)
{
    /* idempotent wrap for the DBT engine loop (H1). */
    static int s_installed;
    if (!s_installed) {
        s_installed = 1;
        host_faults_install();
    }
}

static void host_faults_install(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = host_fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    (void)sigaction(SIGSEGV, &sa, NULL);
    (void)sigaction(SIGBUS, &sa, NULL);
    (void)sigaction(SIGILL, &sa, NULL);
    (void)sigaction(SIGFPE, &sa, NULL);
}

/* Long i686_handle_syscall / int i686_syscall_is_exit (src/os/syscalls.c) */
long i686_handle_syscall(i686_ctx_t *ctx);
int  i686_syscall_is_exit(long nr);

#define I686_REGISTRY_MAX 512U

static i686_interp_fn s_registry[I686_REGISTRY_MAX];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    if ((unsigned)op < I686_REGISTRY_MAX) {
        s_registry[op] = fn;
    }
}

static int s_trace;

void i686_interp_init_all(void)
{
    static int s_done;
    if (s_done) {
        return;
    }
    s_done = 1;
    s_trace = getenv("I686RT_TRACE") != NULL;
    i686_interp_alu_init();
    i686_interp_mov_init();
    i686_interp_branch_init();
    i686_interp_muldiv_init();
    {
        extern void i686_interp_x87_init(void);
        extern void i686_interp_sse_init(void);
        extern void i686_interp_seg_init(void);
        i686_interp_x87_init();
        i686_interp_sse_init();
        i686_interp_seg_init();
    }
}

const char *i686_op_name(uint16_t op)
{
    static char buf[24];
    (void)snprintf(buf, sizeof(buf), "op:%u", (unsigned)op);
    return buf;
}

static void diag(const char *what, const i686_ctx_t *ctx, uint16_t op)
{
    (void)fprintf(stderr,
                  "i686rt: interp: %s at eip=0x%08x (%s), esp=0x%08x\n",
                  what, ctx->eip, i686_op_name(op), ctx->gpr[I686_REG_ESP]);
    /* Region map on any fatal diagnostics: shows which mapping the
     * eip/fault_addr landed in and its neighbours (RC7b triage). */
    if (ctx->region_count > 0U) {
        size_t i;
        for (i = 0U; i < ctx->region_count; i++) {
            const i686_region_t *rg = &ctx->regions[i];
            (void)fprintf(stderr,
                          "MAP %08x-%08x %c%c%c %s\n",
                          rg->start, rg->end,
                          (rg->prot & 0x1U) ? 'r' : '-',
                          (rg->prot & 0x2U) ? 'w' : '-',
                          (rg->prot & 0x4U) ? 'x' : '-',
                          rg->name[0] != '\0' ? rg->name : "");
        }
    }
}

/* DBT fallback hook: execute exactly ONE guest insn via the interpreter
 * handlers (D2). Returns 0 on success, or the terminal exit reason. */
int i686_interp_step(i686_ctx_t *ctx)
{
    x86_insn_t insn;
    i686_interp_fn fn;
    int r;

    if (x86_decode(ctx, ctx->eip, &insn) != 0) {
        uint32_t b;
        ctx->exit_reason = I686_EXIT_UNDEF;
        ctx->exit_arg = 0;
        diag("undecodable instruction", ctx, 0);
        (void)fprintf(stderr, "BYTES %08x:", ctx->eip);
        for (b = 0U; b < 16U; b++) {
            (void)fprintf(stderr, " %02x",
                          *(const volatile uint8_t *)i686_guest_ptr(ctx,
                                                                    ctx->eip + b));
        }
        (void)fprintf(stderr, "\n");
        return I686_EXIT_UNDEF;
    }
    fn = (unsigned)insn.op < I686_REGISTRY_MAX ? s_registry[insn.op] : NULL;
    if (fn == NULL) {
        ctx->exit_reason = I686_EXIT_UNDEF;
        ctx->exit_arg = insn.op;
        diag("unimplemented opcode", ctx, insn.op);
        return I686_EXIT_UNDEF;
    }
    r = fn(ctx, &insn);
    ctx->blocks_executed++;
    if (r == I686_INTERP_CONTINUE) {
        return 0;
    }
    switch (r) {
    case I686_EXIT_SYSCALL: {
        long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
        long rv = i686_handle_syscall(ctx);
        if (i686_syscall_is_exit(nr)) {
            ctx->exit_reason = I686_EXIT_SYSCALL;
            ctx->exit_arg = (uint32_t)rv;
            return I686_EXIT_SYSCALL;
        }
        return 0;
    }
    default:
        ctx->exit_reason = (uint32_t)r;
        return r;
    }
}

int i686_interp_run(i686_ctx_t *ctx)
{
    static int s_faults_installed;
    sigjmp_buf fault_jmp;
    int faulted;

    if (!s_faults_installed) {
        s_faults_installed = 1;
        host_faults_install();
    }
    s_in_run = 1;

    /* Arm the host-fault checkpoint ONCE per run (RC7b T4d).  The
     * previous per-instruction sigsetjmp saved the signal mask on
     * every guest instruction — a host rt_sigprocmask syscall from
     * musl's __sigsetjmp_tail each time — which dominated wall time
     * on the wine boot (gdb stack samples landed in __sigsetjmp_tail
     * repeatedly).  savemask=1 keeps the siglongjmp semantics: the
     * faulting signal is unblocked again on resume.  The buffer is
     * frame-local, so each host thread checkpoints its own stack. */
    faulted = sigsetjmp(fault_jmp, 1);
    s_fault_jmp = &fault_jmp;
    if (faulted != 0) {
        /* Host fault inside guest execution: map to a guest exit. */
        uint64_t fa = (uint64_t)s_fault_addr;

        /* RC-U3: a fault inside a split-locked unaligned section must
         * not strand the lock, and a faulting stack op must not leave
         * ESP/EBP mutated (restored to the pre-instruction values). */
        i686_split_lock_release_if_held();
        ctx->gpr[I686_REG_ESP] = s_saved_esp;
        ctx->gpr[I686_REG_EBP] = s_saved_ebp;
        s_in_run = 1;
        if (fa >= ctx->guest_base &&
            fa < ctx->guest_base + 0x100000000ULL) {
            ctx->fault_addr = (uint32_t)(fa - ctx->guest_base);
        } else {
            ctx->fault_addr = (uint32_t)fa;
        }
        {
            extern int i686_deliver_sync(i686_ctx_t *, int);
            if (i686_deliver_sync(ctx, I686_EXIT_FAULT) == 0) {
                goto run_loop; /* guest handler installed; resume at it */
            }
            (void)fprintf(stderr,
                          "i686rt: interp: guest fault (host) pid=%d at "
                          "eip=0x%08x, fault_addr=0x%08x\n",
                          (int)getpid(), ctx->eip, ctx->fault_addr);
            diag("guest fault (host)", ctx, 0);
            ctx->exit_reason = I686_EXIT_FAULT;
            return I686_EXIT_FAULT;
        }
    }
run_loop:
    for (;;) {
        x86_insn_t insn;
        i686_interp_fn fn;
        int r;

        if (x86_decode(ctx, ctx->eip, &insn) != 0) {
            uint32_t b;
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = 0;
            diag("undecodable instruction", ctx, 0);
            (void)fprintf(stderr, "BYTES %08x:", ctx->eip);
            for (b = 0U; b < 16U; b++) {
                (void)fprintf(stderr, " %02x",
                              *(const volatile uint8_t *)i686_guest_ptr(ctx,
                                                                        ctx->eip + b));
            }
            (void)fprintf(stderr, "\n");
            return I686_EXIT_UNDEF;
        }
        fn = (unsigned)insn.op < I686_REGISTRY_MAX ? s_registry[insn.op] : NULL;
        if (fn == NULL) {
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = insn.op;
            diag("unimplemented opcode", ctx, insn.op);
            return I686_EXIT_UNDEF;
        }
        if (s_trace) {
            uint32_t b;
            char tl[80];
            int tn = 0;

            tn = snprintf(tl, sizeof tl, "T %d %08x op=%u len=%u b=",
                          (int)getpid(), ctx->eip, (unsigned)insn.op,
                          insn.len);
            for (b = 0U; b < insn.len && b < 8U && tn < (int)sizeof tl - 3;
                 b++) {
                const volatile uint8_t *p =
                    (const volatile uint8_t *)i686_guest_ptr(ctx, ctx->eip + b);
                tn += snprintf(tl + tn, sizeof tl - (size_t)tn, "%02x", *p);
            }
            snprintf(tl + tn, sizeof tl - (size_t)tn, " esp=%08x\n",
                     ctx->gpr[I686_REG_ESP]);
            (void)write(2, tl, strlen(tl));
        }
        /* RC-U3 checkpoint for the fault path above. */
        s_saved_esp = ctx->gpr[I686_REG_ESP];
        s_saved_ebp = ctx->gpr[I686_REG_EBP];
        r = fn(ctx, &insn);
        ctx->blocks_executed++;

        if (r == I686_INTERP_CONTINUE) {
            if (ctx->pending_signals != 0U) {
                /* Async delivery: lowest pending, unblocked signal. */
                extern int i686_deliver_pending(i686_ctx_t *);
                (void)i686_deliver_pending(ctx);
            }
            continue;
        }
        switch (r) {
        case I686_EXIT_SYSCALL: {
            long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
            long rv = i686_handle_syscall(ctx);
            if (s_trace) {
                if (nr == 4 || nr == 3) {
                    (void)fprintf(stderr, "S %ld(%u,%08x,%u) -> %ld\n", nr,
                                  ctx->gpr[I686_REG_EBX],
                                  ctx->gpr[I686_REG_ECX],
                                  ctx->gpr[I686_REG_EDX], rv);
                } else if (nr == 5 || nr == 195 || nr == 196 || nr == 383 ||
                           nr == 11) {
                    /* Raw arg only: fetching the string can fault on
                     * garbage pointers until Phase 4 installs the
                     * fault-to-EFAULT machinery. */
                    (void)fprintf(stderr, "S %ld(%08x) -> %ld\n", nr,
                                  ctx->gpr[I686_REG_EBX], rv);
                } else {
                    (void)fprintf(stderr, "S %ld -> %ld\n", nr, rv);
                }
            }
            if (i686_syscall_is_exit(nr)) {
                ctx->exit_reason = I686_EXIT_SYSCALL;
                ctx->exit_arg = (uint32_t)rv; /* process exit status */
                return I686_EXIT_SYSCALL;
            }
            break;
        }
        case I686_EXIT_HLT:
            diag("guest hlt", ctx, insn.op);
            ctx->exit_reason = I686_EXIT_HLT;
            return I686_EXIT_HLT;
        case I686_EXIT_TRAP:
        case I686_EXIT_FAULT:
        case I686_EXIT_UNDEF: {
            /* Phase 4: map the fault to a guest signal and deliver
             * (SIGSEGV/SIGFPE/SIGILL per the kernel table). If no
             * handler is installed the diag+stop path stands. */
            extern int i686_deliver_sync(i686_ctx_t *, int reason);
            int rs = i686_deliver_sync(ctx, r);
            if (rs == 0) {
                continue; /* handler installed; resume at it */
            }
            diag(r == I686_EXIT_TRAP  ? "debug trap"
               : r == I686_EXIT_FAULT ? "guest fault"
                                      : "opcode refused",
                 ctx, insn.op);
            ctx->exit_reason = (uint32_t)r;
            if (r != I686_EXIT_UNDEF) {
                ctx->exit_arg = insn.op;
            }
            return r;
        }
        default:
            ctx->exit_reason = (uint32_t)r;
            return r;
        }
    }
}

/* ------------------------------------------------------------------ */
/* CMPXCHG8B m64 (moved from h_alu.c, lane rc-u3-i686 line discipline) */
/* ------------------------------------------------------------------ */

/* CMPXCHG8B m64 (0F C7 /1): compare EDX:EAX with [EA]; on match ZF=1
 * and [EA] <- ECX:EBX, else ZF=0 and EDX:EAX <- [EA].  All other flags
 * are untouched (SDM).  mod=3 and reg != /1 are #UD.  The memory form
 * is implicitly locked: an aligned 8-byte __atomic_compare_exchange on
 * the HVA; unaligned EAs pre-validate both 4-byte spans before taking
 * the lane split lock (RC-U3 P1: the lock must never strand on fault),
 * and the locked region is byte-wise so no host alignment fault can
 * fire inside it.  The run-loop fault path releases a stranded lock. */
int h_CMPXCHG8B(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t ea, alo, ahi;
    uint64_t *q;
    uint32_t fl;

    if (insn->modrm_mod == 3U || insn->modrm_reg != 1U) {
        return I686_EXIT_UNDEF;
    }
    ea = x86_ea_compute(ctx, insn);
    i686_seg_check_data(ctx, x86_ea_seg(insn), ea, 8U);
    q = (uint64_t *)i686_guest_ptr(ctx, ea);
    alo = ctx->gpr[I686_REG_EAX];
    ahi = ctx->gpr[I686_REG_EDX];
    if ((((uintptr_t)q) & 7u) == 0u) {
        uint64_t expected =
            ((uint64_t)ahi << 32) | (uint64_t)alo;
        uint64_t desired = ((uint64_t)ctx->gpr[I686_REG_ECX] << 32) |
                           (uint64_t)ctx->gpr[I686_REG_EBX];
        bool ok = __atomic_compare_exchange_n(q, &expected, desired, false,
                                              __ATOMIC_SEQ_CST,
                                              __ATOMIC_SEQ_CST);
        if (ok) {
            fl = i686_flags_read(ctx) | I686_EF_ZF;
        } else {
            ctx->gpr[I686_REG_EAX] = (uint32_t)expected;
            ctx->gpr[I686_REG_EDX] = (uint32_t)(expected >> 32);
            fl = i686_flags_read(ctx) & ~I686_EF_ZF;
        }
        ctx->eflags = fl;
        ctx->eip += insn->len;
        return I686_INTERP_CONTINUE;
    }
    /* Unaligned EA: validate the full 8-byte span BEFORE the lock.  An
     * invalid span runs the byte sequence unlocked so the genuine fault
     * fires with no lock held; the locked path then only sees mapped
     * memory (a racing munmap still faults into the run-loop catch,
     * which releases the lock). */
    {
        bool valid = i686_span_mapped_writable(ctx, ea, 8U);
        uint8_t *p = (uint8_t *)q;
        uint32_t mlo, mhi;
        if (valid) {
            i686_split_lock_acquire();
        }
        mlo = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
              ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        mhi = (uint32_t)p[4] | ((uint32_t)p[5] << 8) |
              ((uint32_t)p[6] << 16) | ((uint32_t)p[7] << 24);
        if (alo == mlo && ahi == mhi) {
            p[0] = (uint8_t)(ctx->gpr[I686_REG_EBX] & 0xFFu);
            p[1] = (uint8_t)((ctx->gpr[I686_REG_EBX] >> 8) & 0xFFu);
            p[2] = (uint8_t)((ctx->gpr[I686_REG_EBX] >> 16) & 0xFFu);
            p[3] = (uint8_t)((ctx->gpr[I686_REG_EBX] >> 24) & 0xFFu);
            p[4] = (uint8_t)(ctx->gpr[I686_REG_ECX] & 0xFFu);
            p[5] = (uint8_t)((ctx->gpr[I686_REG_ECX] >> 8) & 0xFFu);
            p[6] = (uint8_t)((ctx->gpr[I686_REG_ECX] >> 16) & 0xFFu);
            p[7] = (uint8_t)((ctx->gpr[I686_REG_ECX] >> 24) & 0xFFu);
            fl = i686_flags_read(ctx) | I686_EF_ZF;
        } else {
            ctx->gpr[I686_REG_EAX] = mlo;
            ctx->gpr[I686_REG_EDX] = mhi;
            fl = i686_flags_read(ctx) & ~I686_EF_ZF;
        }
        ctx->eflags = fl;
        if (valid) {
            i686_split_lock_release();
        }
        ctx->eip += insn->len;
        return I686_INTERP_CONTINUE;
    }
}
