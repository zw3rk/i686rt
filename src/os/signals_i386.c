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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <sys/syscall.h>
long syscall(long, ...);
#endif
#include <unistd.h>

static long sig_host_gettid(void)
{
#ifdef __linux__
    return (long)syscall(SYS_gettid);
#else
    return (long)getpid();
#endif
}

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

/* Last frame base pushed on this thread (v1 single-threaded): the
 * sigreturn entry reads the sigcontext from the EXACT address we
 * built, immune to esp-convention drift at the restorer. */
#define SA_ONSTACK_ 0x08000000U /* i386 sa_flags bit (kernel uapi) */
#define SIGFRAME_MAX_NEED                                                      \
    (sizeof(i686_fpstate_32_t) + 16U + sizeof(i686_rt_sigframe_t) + 32U)

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

    /* Handler double-fault (RC7b T4b): when the same signal's handler is
     * already running (a live, not-yet-sigreturned frame) and a fault
     * re-enters delivery, the kernel's force_sigsegv() clears the handler
     * and kills instead of recursing.  Before this check, wine's fault
     * path re-entered save_context forever (SA_ONSTACK rewinds to the
     * altstack top, so the guard never fired).  A DIFFERENT signal's
     * handler may nest legitimately, so only the same-signal case is
     * forced to the default action.  Both frame layouts keep sig at +4. */
    if (ctx->sig_last_frame_va != 0U) {
        int32_t live = 0;
        memcpy(&live, i686_guest_ptr(ctx, ctx->sig_last_frame_va + 4U),
               sizeof(live));
        if (live == sig) {
            return -1;
        }
    }

    /* SA_ONSTACK delivery (RC7b): wine's fault handlers install an
     * alternative stack precisely so the frame never lands on the
     * faulting (guard-adjacent) stack.  Deliver from its top when
     * active and we are not already inside it. */
    if ((ga->flags & SA_ONSTACK_) != 0U && ctx->altstack_sp != 0U &&
        (ctx->altstack_flags & 0x2U /* SS_DISABLE */) == 0U &&
        (sp < ctx->altstack_sp ||
         sp >= ctx->altstack_sp + ctx->altstack_size)) {
        sp = ctx->altstack_sp + ctx->altstack_size;
    }

    /* Guard pre-check (RC7b): a frame crossing into the stack guard
     * previously host-faulted inside push_bytes and the host-fault
     * path re-entered delivery forever (a real kernel force-kills).
     * Refuse instead; the caller treats it as undeliverable. */
    {
        uint32_t floor = ctx->altstack_sp;

        if (sp >= ctx->stack_base && sp < ctx->stack_top) {
            floor = ctx->stack_base; /* main stack */
        }
        if (sp - floor < SIGFRAME_MAX_NEED) {
            return -1;
        }
    }

    /* fpstate on the guest stack (fxsr image: magic1 per E05). */
    memset(&fp, 0, sizeof(fp));
    fp.cwd = ctx->fctrl;
    fp.swd = ctx->fstat;
    fp.twd = ctx->ftag;
    fp.mxcsr = ctx->mxcsr;
    /* D34: st_space is 8 x 10-byte x87 registers (80 bytes); ctx->x87_st
     * is 8 x 16-byte slots.  A bulk copy ran 48 bytes past st_space,
     * clobbering __pad0/the FXSAVE header/mxcsr on every fpstate-bearing
     * delivery — copy each register's 10 significant bytes instead. */
    for (unsigned st_i = 0U; st_i < 8U; st_i++) {
        memcpy((uint8_t *)fp.st_space + st_i * 10U, &ctx->x87_st[st_i][0],
               10U);
    }
    memcpy(&fp.xmm_space, ctx->xmm, sizeof(ctx->xmm));
    fp.sw_reserved[0] = 0x46505853U; /* FP_XSTATE_MAGIC1 */
    fp_va = push_bytes(ctx, &sp, &fp, sizeof(fp));
    sp &= ~7U;

    sp &= ~0xFU; /* before the push. The 268-byte rt frame then leaves ESP 4 mod 16. */
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
    sc.err = (sig == 11) ? (uint32_t)ctx->exit_dest : 0; /* seg error code */
    sc.eip = ctx->eip;
    sc.cs = ctx->seg_sel[I686_SEG_CS];
    sc.eflags = ctx->eflags;
    sc.esp_at_signal = ctx->gpr[I686_REG_ESP];
    sc.ss = ctx->seg_sel[I686_SEG_SS];
    sc.fpstate = fp_va;
    sc.cr2 = ctx->fault_addr;

    /* siginfo bytes for the rt frame (frame+0x10..0x90).  The handler
     * return address ([frame]) is the SA_RESTORER trampoline when the
     * guest registered one — the kernel uses it too.  The embedded
     * on-stack retcode is only the no-restorer fallback: the window
     * stack is rw-, so executing it would fault (musl libc-test found
     * this — every musl sigaction carries SA_RESTORER).
     *
     * The blocked mask rides IN the frame (kernel semantics): the
     * handler runs under sig_mask | sig | sa_mask and sigreturn
     * restores it.  musl's SIGCANCEL handler depends on this — it
     * edits uc_sigmask and re-raises itself so the signal stays masked
     * until the next cancellation point; without the frame mask the
     * pending re-raise delivered at a random pc. */
    {
        /* The frame carries the PRE-DELIVERY mask (the kernel saves
         * current->blocked unmodified; the sig | sa_mask blocking is
         * live task state for the handler's duration and sigreturn
         * restores the frame's copy — that is how a handler's own
         * uc_sigmask edit (musl's SIGCANCEL re-raise) survives). */
        uint64_t pre = ctx->sig_mask;
        uint64_t blocked = pre | (1ULL << (uint32_t)(sig - 1));

        blocked |= ((uint64_t)ga->mask[1] << 32) | (uint64_t)ga->mask[0];
        ctx->sig_mask = blocked;
        if (sa_siginfo) {
            /* uc_sigmask: ucontext@frame+0x90, +0x14 mcontext(88) -> +0x6c */
            uint8_t m[8];
            memcpy(m, &pre, sizeof(m));
            memcpy(i686_guest_ptr(ctx, frame_va + 0x90 + 0x6c), m, sizeof(m));
        } else {
            sc.oldmask = (uint32_t)pre;
        }
    }
    if (sa_siginfo) {
        /* rt frame: sc lives in ucontext at frame+0x90+20 */
        memcpy(i686_guest_ptr(ctx, frame_va + 0x90 + 20), &sc, sizeof(sc));
        memcpy(i686_guest_ptr(ctx, frame_va + sizeof(i686_rt_sigframe_t) - 8),
               retcode_rt, 8);
        *(uint32_t *)i686_guest_ptr(ctx, frame_va) =
            ((ga->flags & SA_RESTORER_) != 0U) ? ga->restorer
                : frame_va + sizeof(i686_rt_sigframe_t) - 8;
        *(uint32_t *)i686_guest_ptr(ctx, frame_va + 8) = frame_va + 0x10;
        *(uint32_t *)i686_guest_ptr(ctx, frame_va + 12) = frame_va + 0x90;
        {
            /* si_signo, si_errno, si_code(+8), si_addr(12 for SEGV) */
            uint8_t si[16];
            memset(si, 0, sizeof(si));
            si[0] = (uint8_t)sig; si[1] = (uint8_t)(sig >> 8);
            si[8] = (sig == 11) ? 1 : ((sig == 8) ? 1 : 0); /* SEGV_MAPERR / FPE_INTDIV */
            if (sig == 11) {
                uint32_t a = sc.cr2;
                memcpy(si + 12, &a, 4);
            }
            memcpy(i686_guest_ptr(ctx, frame_va + 0x10), si, sizeof(si));
        }
    } else {
        memcpy(i686_guest_ptr(ctx, frame_va + 8), &sc, sizeof(sc));
        memcpy(i686_guest_ptr(ctx, frame_va + sizeof(i686_sigframe_t) - 8),
               retcode_nonrt, 8);
        *(uint32_t *)i686_guest_ptr(ctx, frame_va) =
            ((ga->flags & SA_RESTORER_) != 0U) ? ga->restorer
                : frame_va + sizeof(i686_sigframe_t) - 8;
    }

    /* Kernel-contiguous handler entry (i386): esp = frame base;
     * [esp]=pretcode is the handler return address, [esp+4]=sig,
     * [esp+8]=pinfo, [esp+0xc]=puc — the frame fields ARE the args. */
    (void)sp;
    {
        /* Delivery forensics (RC7b T4b): sig/trapno/eip/cr2 per
         * delivery, env-gated like I686RT_TRACE. */
        extern int i686_sigtrace_on(void);
        if (i686_sigtrace_on()) {
            uint32_t ret = 0U;
            uint32_t sysinfo = 0U;
            uint8_t tcbdump[16];
            memset(tcbdump, 0, sizeof(tcbdump));

            memcpy(&ret, i686_guest_ptr(ctx, ctx->gpr[I686_REG_ESP]),
                   sizeof(ret));
            if (ctx->seg_base[I686_SEG_GS] != 0U) {
                memcpy(&sysinfo,
                       i686_guest_ptr(ctx, ctx->seg_base[I686_SEG_GS] + 0x10U),
                       sizeof(sysinfo));
                memcpy(&tcbdump,
                       i686_guest_ptr(ctx, ctx->seg_base[I686_SEG_GS]), 16U);
            }
            (void)fprintf(stderr,
                          "SIG tid=%ld sig=%d trapno=%u eip=%08x cr2=%08x "
                          "esp=%08x frame=%08x gs=%04x/%08x ret=%08x "
                          "sys=%08x tcb=%08x %08x %08x %08x\n"
                          "SIGGPR ax=%08x bx=%08x cx=%08x dx=%08x "
                          "si=%08x di=%08x bp=%08x\n",
                          sig_host_gettid(), sig, sc.trapno, sc.eip,
                          sc.cr2, ctx->gpr[I686_REG_ESP], frame_va,
                          ctx->seg_sel[I686_SEG_GS],
                          ctx->seg_base[I686_SEG_GS], ret, sysinfo,
                          *(const uint32_t *)(const void *)(tcbdump + 0),
                          *(const uint32_t *)(const void *)(tcbdump + 4),
                          *(const uint32_t *)(const void *)(tcbdump + 8),
                          *(const uint32_t *)(const void *)(tcbdump + 12),
                          sc.eax, sc.ebx, sc.ecx, sc.edx, sc.esi, sc.edi,
                          sc.ebp);
        }
    }
    ctx->gpr[I686_REG_ESP] = frame_va;
    ctx->sig_last_frame_va = frame_va;
    ctx->sig_last_frame_rt = (uint32_t)sa_siginfo;
    ctx->eip = ga->handler;
    (void)handler; (void)restorer; (void)info_va; (void)uc_va; (void)i;
    return 0;
}

int i686_sigreturn(i686_ctx_t *ctx, int rt)
{
    i686_sigcontext_t sc;
    uint32_t base, frame;
    extern int i686_sigtrace_on(void);

    /* The kernel locates the frame from the stack, not from bookkeeping
     * (fs/signal.c): at the restorer's int 0x80 the SA_RESTORER of the
     * guest has already consumed the frame header — musl/glibc's non-rt
     * __restore pops the sig word (esp = frame + 8), the rt __restore_rt
     * does not (esp = frame + 4; kernel rt_sigreturn computes sp - 4).
     * Derived frames make NESTED delivery (the kernel delivers a second
     * unmasked signal inside a running handler) unwind in the right
     * LIFO order — a single recorded frame slot unwound the inner
     * sigreturn and then failed the outer one with EFAULT (musl's
     * __restore crash path).  The recorded frame stays as the fallback
     * for a restorer that shifted esp. */
    frame = ctx->gpr[I686_REG_ESP] - (rt ? 4U : 8U);
    if (ctx->sig_last_frame_va != 0U && frame != ctx->sig_last_frame_va) {
        frame = ctx->sig_last_frame_va;
    }
    ctx->sig_last_frame_va = 0U;
    base = frame + (rt ? (0x90U + 20U) : 8U);
    if (i686_copy_from_guest(ctx, &sc, base, sizeof(sc)) != 0) {
        return -1;
    }
    if (i686_sigtrace_on()) {
        (void)fprintf(stderr,
                      "SIGRET rt=%d esp=%08x frame=%08x rec=%08x "
                      "ax=%08x bp=%08x eip=%08x\n",
                      rt, ctx->gpr[I686_REG_ESP], frame,
                      ctx->sig_last_frame_va, sc.eax, sc.ebp, sc.eip);
    }
    /* Restore the blocked mask from the frame (the delivery blocked
     * sig | sa_mask; the handler may have edited uc_sigmask — musl's
     * SIGCANCEL re-raise relies on the edit surviving). */
    if (rt) {
        uint8_t m[8];
        memcpy(m, i686_guest_ptr(ctx, frame + 0x90U + 0x6cU), sizeof(m));
        memcpy(&ctx->sig_mask, m, sizeof(ctx->sig_mask));
    } else {
        ctx->sig_mask = (uint64_t)sc.oldmask;
    }
    ctx->gpr[I686_REG_EDI] = sc.edi; ctx->gpr[I686_REG_ESI] = sc.esi;
    ctx->gpr[I686_REG_EBP] = sc.ebp; ctx->gpr[I686_REG_ESP] = sc.esp;
    ctx->gpr[I686_REG_EBX] = sc.ebx; ctx->gpr[I686_REG_EDX] = sc.edx;
    ctx->gpr[I686_REG_ECX] = sc.ecx; ctx->gpr[I686_REG_EAX] = sc.eax;
    ctx->eip = sc.eip;
    ctx->eflags = sc.eflags;
    ctx->fault_addr = sc.cr2;
    /* Segment-register round-trip (phase-7.md freeze): kernel reloads
     * blindly from the sigcontext; invalid selectors fault on next use.
     * i686_seg_sc_decode revalidates bases/cs_d without faulting. */
    {
        uint8_t segs[12];

        memcpy(segs + 0, &sc.gs, 2);
        memcpy(segs + 2, &sc.fs, 2);
        memcpy(segs + 4, &sc.es, 2);
        memcpy(segs + 6, &sc.ds, 2);
        memcpy(segs + 8, &sc.cs, 2);
        memcpy(segs + 10, &sc.ss, 2);
        {
            extern void i686_seg_sc_decode(i686_ctx_t *ctx,
                                           const uint8_t in[12]);
            i686_seg_sc_decode(ctx, segs);
        }
    }
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

/* Delivery/thread forensics gate (RC7b T4b). */
int i686_sigtrace_on(void);
int i686_sigtrace_on(void)
{
    static int s_on = -1;
    if (s_on < 0) {
        s_on = getenv("I686RT_SIGTRACE") != NULL;
    }
    return s_on;
}

/* Sync-fault delivery hook for the engine exit switch.
 * Classification (C3f): a fault that rode the host-fault checkpoint
 * carries its real host signal (i686_fault_sig) — SIGFPE -> 8,
 * SIGILL -> 4, SIGSEGV/SIGBUS -> 11 — which no longer depends on
 * possibly-stale ctx->exit_arg (the DBT writes exit_arg = 0 on every
 * BRANCH exit, so a plain guest page fault used to arrive as an
 * unhandleable divide error at a stale EIP).  Faults synthesized
 * without a checkpoint (the interpreter's #DE) record their signal
 * via i686_fault_sig_record; the exit_arg==0 convention survives only
 * as the legacy fallback for unrecorded channels.
 * TRAP -> SIGTRAP(5); UNDEF -> SIGILL(4). Returns 0 when a guest
 * handler was installed (frame pushed, eip=handler), -1 otherwise. */
int i686_deliver_sync(i686_ctx_t *ctx, int reason)
{
    int sig;
    extern int i686_fault_sig(void);
    switch (reason) {
    case I686_EXIT_FAULT: {
        int hsig = i686_fault_sig();
        if (hsig == 8 /*SIGFPE*/) {
            sig = 8;
        } else if (hsig == 4 /*SIGILL*/) {
            sig = 4;
        } else if (hsig == 11 /*SIGSEGV*/ || hsig == 7 /*SIGBUS*/) {
            sig = 11;
        } else {
            sig = (ctx->exit_arg == 0U) ? 8 : 11; /* legacy convention */
        }
        break;
    }
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
        /* Segment faults (#GP 13 / #NP 11 / #SS 12, seg.c/h_seg.c) carry
         * their trapno in exit_arg and the error code in exit_dest;
         * every other FAULT is a page fault (#PF 14). */
        if (ctx->exit_arg != 11U && ctx->exit_arg != 12U &&
            ctx->exit_arg != 13U) {
            ctx->exit_arg = 14; /* trapno = #PF: page fault */
        }
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
 * point.  Unblock check against the guest mask (ctx->sig_mask, the
 * sys_rt_sigprocmask store).
 *
 * Kernel pending semantics (fix-campaign C1b handoff): a bit stays
 * pending while MASKED and delivers when the mask is lifted — musl's
 * raise() blocks all signals, tkills itself and restores, so the poll
 * runs inside the blocked window and MUST NOT drop the bit.  The v1
 * core wiped every pending bit after each poll, dropping exactly those
 * raise() signals ("handler did not run").  Now only a bit that is
 * actually delivered is cleared; blocked bits (and, for v1's lack of
 * default-action machinery, unblocked SIG_DFL/SIG_IGN-disposition
 * bits) survive the poll. */
int i686_deliver_pending(i686_ctx_t *ctx)
{
    uint64_t pend = ctx->pending_signals;
    while (pend != 0ULL) {
        uint64_t bit = pend & (~pend + 1ULL); /* lowest set bit */
        struct i686_gsigaction *ga;
        int sig = 1;
        uint64_t scan;

        pend ^= bit;
        for (scan = bit; scan > 1ULL; scan >>= 1) {
            sig++;
        }
        ga = i686_gsig_tab(sig);
        if (ga == NULL || ga->handler == 0U || ga->handler == 1U) {
            if ((ctx->sig_mask & bit) == 0ULL) {
                /* unblocked with no guest handler: v1 has no
                 * default-action machinery; keep v1's drop semantics
                 * so the bit cannot wedge the scan forever */
                ctx->pending_signals &= ~bit;
            }
            continue;
        }
        if ((ctx->sig_mask & bit) != 0ULL) {
            continue; /* blocked: stays pending until unmasked */
        }
        ctx->pending_signals &= ~bit;
        ctx->exit_arg = 0; /* no trapno for async */
        return i686_sigframe_build(ctx, sig, ga->handler, ga->restorer,
                                   (ga->flags & 0x4U) ? 1 : 0, 0U, 0U);
    }
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
