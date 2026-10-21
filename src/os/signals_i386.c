/*
 * src/os/signals_i386.c — i386 signal delivery core (SPEC §3.5, §3.6)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * v1 (interp engine): host signals are routed via the safe-point check
 * (interp loop already reads ctx->pending_signals). Async delivery pops
 * the lowest pending, unblocked sig; sync faults (SIGSEGV/SIGFPE/SIGILL/
 * SIGTRAP from UNDEF/FAULT/HLT exits) deliver immediately with cr2 /
 * trapno / err filled per the kernel's mapping.
 */

#include <errno.h>
#include <signal.h>
#include <string.h>

#include "i686rt.h"
#include "os/marshal.h"
#include "os/sigframe_i386.h"
#include "os/threads.h"

/* Guest sigaction table (frozen in sys_pass.c Phase 2 v1: single static).
 * Phase 4 moves it here per-thread via the ctx tail. */
struct i686_gsigaction {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer;
    uint32_t mask[2];
};
extern struct i686_gsigaction *i686_gsig_tab(int signum); /* sys_pass.c */

static const uint8_t retcode_nonrt[8] = {
    0x58, 0xb8, 0x77, 0x00, 0x00, 0x00, 0xcd, 0x80
}; /* pop eax; mov 119,eax; int 0x80 */
static const uint8_t retcode_rt[8] = {
    0x58, 0xb8, 0xad, 0x00, 0x00, 0x00, 0xcd, 0x80
}; /* pop eax; mov 173,eax; int 0x80 */

#define SA_RESTORER_ 0x04000000U
#define SA_SIGINFO_  0x00000004U

static uint32_t push_bytes(i686_ctx_t *ctx, uint32_t *sp, const void *b,
                           size_t n)
{
    *sp -= (uint32_t)n;
    memcpy(i686_guest_ptr(ctx, *sp), b, n);
    return *sp;
}

int i686_sigframe_build(i686_ctx_t *ctx, int sig, uint32_t handler,
                        uint32_t restorer, int sa_siginfo, uint32_t info_va,
                        uint32_t uc_va)
{
    i686_sigcontext_t sc;
    i686_fpstate_32_t fp;
    uint32_t sp = ctx->gpr[I686_REG_ESP];
    uint32_t fp_va, frame_va;
    struct i686_gsigaction *ga = i686_gsig_tab(sig);
    int i;

    if (ga == NULL || ga->handler == 0U || ga->handler == 1U) {
        return -1; /* SIG_DFL: caller terminates */
    }

    /* fpstate on the guest stack (fxsr image: magic1 per E05). */
    memset(&fp, 0, sizeof(fp));
    fp.cwd = ctx->fctrl;
    fp.swd = ctx->fstat;
    fp.twd = ctx->ftag;
    fp.mxcsr = ctx->mxcsr;
    memcpy(&fp.st_space, ctx->x87_st, sizeof(ctx->x87_st));
    memcpy(&fp.xmm_space, ctx->xmm, sizeof(ctx->xmm));
    fp.sw_reserved[0] = 0x46505853U; /* FP_XSTATE_MAGIC1 */
    fp_va = push_bytes(ctx, &sp, &fp, sizeof(fp));
    sp &= ~7U;

    if (sa_siginfo) {
        i686_rt_sigframe_t rt;
        memset(&rt, 0, sizeof(rt));
        rt.sig = sig;
        rt.pinfo = sp + 0x10;   /* info immediately after header */
        rt.puc = sp + 0x90;     /* kernel: uc at +0x90 */
        frame_va = push_bytes(ctx, &sp, &rt, sizeof(rt));
        /* fill sigcontext inside ucontext (uc@+0x90, sc at uc+20) */
    } else {
        i686_sigframe_t sf;
        memset(&sf, 0, sizeof(sf));
        sf.sig = sig;
        frame_va = push_bytes(ctx, &sp, &sf, sizeof(sf));
    }

    /* sigcontext (both frames share the layout). */
    memset(&sc, 0, sizeof(sc));
    sc.gs = ctx->seg_sel[I686_SEG_GS]; sc.fs = ctx->seg_sel[I686_SEG_FS];
    sc.es = ctx->seg_sel[I686_SEG_ES]; sc.ds = ctx->seg_sel[I686_SEG_DS];
    sc.edi = ctx->gpr[I686_REG_EDI]; sc.esi = ctx->gpr[I686_REG_ESI];
    sc.ebp = ctx->gpr[I686_REG_EBP]; sc.esp = ctx->gpr[I686_REG_ESP];
    sc.ebx = ctx->gpr[I686_REG_EBX]; sc.edx = ctx->gpr[I686_REG_EDX];
    sc.ecx = ctx->gpr[I686_REG_ECX]; sc.eax = ctx->gpr[I686_REG_EAX];
    sc.trapno = ctx->exit_arg; /* fault exit stores trapno in arg */
    sc.err = 0;
    sc.eip = ctx->eip;
    sc.cs = ctx->seg_sel[I686_SEG_CS];
    sc.eflags = ctx->eflags;
    sc.esp_at_signal = ctx->gpr[I686_REG_ESP];
    sc.ss = ctx->seg_sel[I686_SEG_SS];
    sc.fpstate = fp_va;
    sc.cr2 = ctx->fault_addr;

    if (sa_siginfo) {
        /* rt frame: sc lives in ucontext at frame+0x90+20 */
        memcpy(i686_guest_ptr(ctx, frame_va + 0x90 + 20), &sc, sizeof(sc));
        memcpy(i686_guest_ptr(ctx, frame_va + sizeof(i686_rt_sigframe_t) - 8),
               retcode_rt, 8);
        *(uint32_t *)i686_guest_ptr(ctx, frame_va) =
            frame_va + sizeof(i686_rt_sigframe_t) - 8;
        /* handler args (sig, info, uc): info/uc point into the frame
         * (kernel: pinfo=frame+0x10, puc=frame+0x90) — fixed VAs. */
        *(uint32_t *)i686_guest_ptr(ctx, frame_va + 8) = frame_va + 0x10;
        *(uint32_t *)i686_guest_ptr(ctx, frame_va + 12) = frame_va + 0x90;
        sp -= 4; *(uint32_t *)i686_guest_ptr(ctx, sp) = frame_va + 0x90;
        sp -= 4; *(uint32_t *)i686_guest_ptr(ctx, sp) = frame_va + 0x10;
        sp -= 4; *(uint32_t *)i686_guest_ptr(ctx, sp) = (uint32_t)sig;
    } else {
        memcpy(i686_guest_ptr(ctx, frame_va + 4), &sc, sizeof(sc));
        memcpy(i686_guest_ptr(ctx, frame_va + sizeof(i686_sigframe_t) - 8),
               retcode_nonrt, 8);
        *(uint32_t *)i686_guest_ptr(ctx, frame_va) =
            frame_va + sizeof(i686_sigframe_t) - 8;
        sp -= 4; *(uint32_t *)i686_guest_ptr(ctx, sp) = (uint32_t)sig;
    }

    /* return address for the guest handler -> restorer (or retcode) */
    {
        uint32_t ret_to = (ga->flags & SA_RESTORER_)
            ? ga->restorer
            : frame_va + ((sa_siginfo) ? (uint32_t)sizeof(i686_rt_sigframe_t) - 8
                                       : (uint32_t)sizeof(i686_sigframe_t) - 8);
        sp -= 4; *(uint32_t *)i686_guest_ptr(ctx, sp) = ret_to;
    }

    ctx->gpr[I686_REG_ESP] = sp & ~0xFU;
    ctx->eip = ga->handler;
    (void)handler; (void)restorer; (void)info_va; (void)uc_va; (void)i;
    return 0;
}

int i686_sigreturn(i686_ctx_t *ctx, int rt)
{
    /* Kernel esp convention at the restorer: non-RT frame + 4 (pretcode
     * was popped as the handler's return address); RT frame + 0 (the
     * restorer is called with esp pointing at the frame base because the
     * handler-return popped pretcode leaving sig at [esp]).  We detect
     * the frame by scanning: our builder pushed handler args + retaddr
     * BELOW the frame, so at sigreturn time esp = frame_va (args and
     * retaddr were popped by the handler's own ret/leave sequence only
     * if the guest stub did `pop eax` first — the retcode does). */
    uint32_t sp = ctx->gpr[I686_REG_ESP];
    i686_sigcontext_t sc;
    uint32_t base = rt ? sp + 0x90 + 20 : sp + 8;
    if (i686_copy_from_guest(ctx, &sc, base, sizeof(sc)) != 0) {
        return -1;
    }
    ctx->gpr[I686_REG_EDI] = sc.edi; ctx->gpr[I686_REG_ESI] = sc.esi;
    ctx->gpr[I686_REG_EBP] = sc.ebp; ctx->gpr[I686_REG_ESP] = sc.esp;
    ctx->gpr[I686_REG_EBX] = sc.ebx; ctx->gpr[I686_REG_EDX] = sc.edx;
    ctx->gpr[I686_REG_ECX] = sc.ecx; ctx->gpr[I686_REG_EAX] = sc.eax;
    ctx->eip = sc.eip;
    ctx->eflags = sc.eflags;
    ctx->fault_addr = sc.cr2;
    /* fpstate restore */
    if (sc.fpstate != 0U) {
        i686_fpstate_32_t fp;
        if (i686_copy_from_guest(ctx, &fp, sc.fpstate, sizeof(fp)) == 0) {
            ctx->fctrl = fp.cwd; ctx->fstat = fp.swd; ctx->ftag = fp.twd;
            ctx->mxcsr = fp.mxcsr;
            memcpy(ctx->x87_st, &fp.st_space, sizeof(ctx->x87_st));
            memcpy(ctx->xmm, &fp.xmm_space, sizeof(ctx->xmm));
        }
    }
    /* non-RT: the frame pushed sc.esp as the resume esp implicitly via
     * sigcontext; the 4-byte sig + pretcode slots were consumed by the
     * retcode's `pop eax`. RT: sigreturn cleans its own frame. */
    return 0;
}

void i686_signals_i386_init(void)
{
    /* Host-signal registration for async delivery lands with Phase 4
     * S4 integration (host_sig_handler + pending bit set); v1 delivers
     * sync exits (FAULT/FPE/TRAP) directly at the engine exit switch. */
}

/* Sync-fault delivery hook for the engine exit switch.
 * Map: FAULT(div-by-zero exit_arg==0) -> SIGFPE(8); FAULT(other) ->
 * SIGSEGV(11, cr2=fault_addr, trapno=14); TRAP -> SIGTRAP(5);
 * UNDEF -> SIGILL(4). Returns 0 when a guest handler was installed
 * (frame pushed, eip=handler), -1 otherwise. */
int i686_deliver_sync(i686_ctx_t *ctx, int reason)
{
    int sig;
    switch (reason) {
    case I686_EXIT_FAULT:
        sig = (ctx->exit_arg == 0U) ? 8 : 11; /* div0 -> SIGFPE */
        break;
    case I686_EXIT_TRAP: sig = 5; break;
    default:             sig = 4; break; /* SIGILL */
    }
    {
        struct i686_gsigaction *ga = i686_gsig_tab(sig);
        if (ga == NULL || ga->handler == 0U || ga->handler == 1U) {
            return -1;
        }
    }
    if (sig == 11) {
        ctx->exit_arg = 14; /* trapno = #GP(13)/#PF(14): page fault */
    }
    {
        int rt = 0; /* SA_SIGINFO detection via flags */
        struct i686_gsigaction *ga = i686_gsig_tab(sig);
        rt = (ga->flags & SA_SIGINFO_) ? 1 : 0;
        return i686_sigframe_build(ctx, sig, ga->handler, ga->restorer,
                                   rt, 0U, 0U);
    }
}

/* Deliver the lowest pending, unblocked signal at an interpreter safe
 * point.  Unblock check against the guest mask in sys_pass.c v1 store. */
int i686_deliver_pending(i686_ctx_t *ctx)
{
    struct i686_gsigaction *ga;
    int sig;
    for (sig = 1; sig <= 64; sig++) {
        if ((ctx->pending_signals & (1ULL << (sig - 1))) == 0ULL) {
            continue;
        }
        ga = i686_gsig_tab(sig);
        if (ga == NULL || ga->handler == 0U || ga->handler == 1U) {
            continue;
        }
        {
            extern uint64_t i686_sigmask_get(void);
            if (i686_sigmask_get() & (1ULL << (sig - 1))) {
                continue; /* blocked */
            }
        }
        ctx->pending_signals &= ~(1ULL << (sig - 1));
        ctx->exit_arg = 0; /* no trapno for async */
        return i686_sigframe_build(ctx, sig, ga->handler, ga->restorer,
                                   (ga->flags & 0x4U) ? 1 : 0, 0U, 0U);
    }
    /* unhandled pending bits: drop them (v1) */
    ctx->pending_signals = 0ULL;
    return -1;
}

/* Syscall adapters (registered from syscalls.c). */
int64_t i686_sys_sigreturn(i686_ctx_t *ctx);
int64_t i686_sys_sigreturn(i686_ctx_t *ctx)
{
    return i686_sigreturn(ctx, 0) == 0 ? 0 : -14;
}
int64_t i686_sys_rt_sigreturn(i686_ctx_t *ctx);
int64_t i686_sys_rt_sigreturn(i686_ctx_t *ctx)
{
    return i686_sigreturn(ctx, 1) == 0 ? 0 : -14;
}
