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

#include <setjmp.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "interp/interp.h"
#include "os/marshal.h"

/* Host-fault -> guest-fault checkpoint (Phase 4).  The handler runs on
 * the faulting host thread; sigsetjmp/siglongjmp restores the interp
 * loop with the fault recorded. */
static sigjmp_buf s_fault_jmp;
static volatile sig_atomic_t s_in_run;
static volatile uint64_t s_fault_addr;

static volatile sig_atomic_t s_fault_sig;

static void host_fault_handler(int sig, siginfo_t *si, void *uc_)
{
    (void)uc_;
    if (s_in_run) {
        s_fault_addr = (uint64_t)(uintptr_t)si->si_addr;
        s_fault_sig = sig;
        siglongjmp(s_fault_jmp, 1);
    }
    _exit(128 + sig);
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
    if (!s_faults_installed) {
        s_faults_installed = 1;
        host_faults_install();
    }
    s_in_run = 1;
    for (;;) {
        if (sigsetjmp(s_fault_jmp, 1) != 0) {
            /* Host fault inside guest execution: map to a guest exit. */
            uint64_t fa = (uint64_t)s_fault_addr;
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
                    continue; /* guest handler installed; resume at it */
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
