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
#include "interp/flags.h"
#include "interp/interp.h"
#include "interp/x87.h"
#include "os/marshal.h"
#include "os/sigframe_i386.h"
#include "os/threads.h"

/* The host bridge below uses sa_sigaction + SA_SIGINFO throughout
 * (matching interp.c and backend_linux.c): portable across Darwin,
 * glibc, and musl under strict POSIX, where sa_handler is a macro on
 * some platforms and absent on others (musl hides it).  The kernel
 * reads the handler value through the SA_SIGINFO-selected union
 * member, so a cast SIG_DFL stores the same zero value either way. */

/* Guest sigaction table (owned by sys_pass.c). Delivery takes a coherent
 * snapshot into caller-owned storage (I686-R4-6): the old static scratch
 * action was overwritten by concurrent deliveries mid-frame-build.
 * i686_gsig_consume_oneshot additionally applies the SA_RESETHAND reset
 * BEFORE the frame is built, returning the pre-reset handler for EIP. */
struct i686_gsigaction {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer;
    uint32_t mask[2];
};
extern int i686_gsig_snapshot(int signum,
                              struct i686_gsigaction *out); /* sys_pass.c */
extern int i686_gsig_consume_oneshot(int signum,
                                     struct i686_gsigaction *out);

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
    (void)i686_copy_to_guest(ctx, *sp, b, n);
    return *sp;
}

/* Snapshot-carrying frame builder (I686-R4-6): the delivery path
 * consumes one action snapshot and this builder uses exactly that copy
 * for handler, flags, mask, and restorer — no re-fetch mid-build. */
static int sigframe_build_snapshot(i686_ctx_t *ctx, int sig,
                                   const struct i686_gsigaction *ga,
                                   int sa_siginfo, uint32_t info_va,
                                   uint32_t uc_va)
{
    i686_sigcontext_t sc;
    i686_fpstate_32_t fp;
    uint32_t sp = ctx->gpr[I686_REG_ESP];
    uint32_t fp_va, frame_va;
    uint32_t saved_sp = 0U, saved_flags = 0U, saved_size = 0U;
    int disarm_altstack = 0;
    int i;

    if (ga == NULL || ga->handler == 0U || ga->handler == 1U) {
        return -1; /* SIG_DFL: caller terminates */
    }
    (void)fp_va; (void)i;

    /* Handler double-fault (RC7b T4b): when the same signal's handler is
     * already running (a live, not-yet-sigreturned frame) and a fault
     * re-enters delivery, the kernel's force_sigsegv() clears the handler
     * and kills instead of recursing.  Before this check, wine's fault
     * path re-entered save_context forever (SA_ONSTACK rewinds to the
     * altstack top, so the guard never fired).  A DIFFERENT signal's
     * handler may nest legitimately, so only the same-signal case is
     * forced to the default action.  Both frame layouts keep sig at +4.
     * C2-2: a stale slot must not kill a legitimate re-delivery.  The
     * guest may unwind out of the handler with siglongjmp (no sigreturn
     * syscall marks the exit, but the stack pointer is restored past the
     * frame).  Delivery always parks ESP at the frame base, and handler
     * code only pushes down, so a current ESP above the live frame base
     * proves the handler already exited: drop the stale slot and deliver
     * instead of killing. */
    if (ctx->sig_last_frame_va != 0U) {
        int32_t live = 0;
        (void)i686_copy_from_guest(ctx, &live, ctx->sig_last_frame_va + 4U,
                                   sizeof(live));
        if (live == sig) {
            if (sp > ctx->sig_last_frame_va) {
                ctx->sig_last_frame_va = 0U; /* unwound via longjmp */
            } else {
                return -1;
            }
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
        if ((ctx->altstack_flags & 0x80000000U /* SS_AUTODISARM */) != 0U) {
            saved_sp = ctx->altstack_sp;
            saved_flags = ctx->altstack_flags;
            saved_size = ctx->altstack_size;
            disarm_altstack = 1;
        }
        sp = ctx->altstack_sp + ctx->altstack_size;
        ctx->altstack_onstack = 1U; /* entered on the alternate stack */
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
    fp.fip = ctx->fpu_ip;
    fp.foo = ctx->fpu_dp;
    fp.fop = ctx->fop;
    fp.fpu_ip2 = ctx->fpu_ip;
    fp.fpu_dp2 = ctx->fpu_dp;
    fp.mxcsr = ctx->mxcsr;
    /* D34 / I686-10: st_space is 8 x 10-byte x87 registers (80 bytes);
     * ctx->x87_st is 8 x 16-byte slots holding IEEE binary64 in default
     * mode (!ctx->x87_80) or 10-byte ext80 in --x87-80 mode. Convert
     * binary64 slots to 80-bit extended precision in default mode. */
    for (unsigned st_i = 0U; st_i < 8U; st_i++) {
        uint8_t ext[10];
        if (ctx->x87_80 != 0U) {
            memcpy(ext, &ctx->x87_st[st_i][0], 10U);
        } else {
            double d;
            memcpy(&d, &ctx->x87_st[st_i][0], sizeof(d));
            x87_f64_to_ext80(d, ext);
        }
        memcpy((uint8_t *)fp.st_space + st_i * 10U, ext, 10U);
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
    /* R7-19: materialize lazy arithmetic flags — the raw field is stale
     * whenever lazy_op is live (pushed stale ZF/CF/SF/OF/PF/AF). */
    sc.eflags = i686_flags_read(ctx);
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
        uint64_t pre =
            __atomic_load_n(&ctx->sig_mask, __ATOMIC_SEQ_CST);
        uint64_t blocked = pre | (1ULL << (uint32_t)(sig - 1));

        blocked |= ((uint64_t)ga->mask[1] << 32) | (uint64_t)ga->mask[0];
        __atomic_store_n(&ctx->sig_mask, blocked, __ATOMIC_SEQ_CST);
        if (sa_siginfo) {
            /* uc_sigmask: ucontext@frame+0x90, +0x14 mcontext(88) -> +0x6c */
            uint8_t m[8];
            memcpy(m, &pre, sizeof(m));
            (void)i686_copy_to_guest(ctx, frame_va + 0x90U + 0x6cU, m,
                                     sizeof(m));
        } else {
            sc.oldmask = (uint32_t)pre;
        }
    }
    if (sa_siginfo) {
        uint32_t hdr[4];
        /* rt frame: sc lives in ucontext at frame+0x90+20 */
        (void)i686_copy_to_guest(ctx, frame_va + 0x90U + 20U, &sc, sizeof(sc));
        (void)i686_copy_to_guest(
            ctx, frame_va + (uint32_t)sizeof(i686_rt_sigframe_t) - 8U,
            retcode_rt, 8U);
        hdr[0] = ((ga->flags & SA_RESTORER_) != 0U)
                     ? ga->restorer
                     : frame_va + (uint32_t)sizeof(i686_rt_sigframe_t) - 8U;
        /* [frame+4] is the handler's signo argument (it previously held
         * whatever the abandoned stack had there; signal-number checks
         * in handlers read garbage without this store). */
        hdr[1] = (uint32_t)sig;
        hdr[2] = frame_va + 0x10U;
        hdr[3] = frame_va + 0x90U;
        (void)i686_copy_to_guest(ctx, frame_va, hdr, sizeof(hdr));
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
            (void)i686_copy_to_guest(ctx, frame_va + 0x10U, si, sizeof(si));
        }
    } else {
        uint32_t hdr[2];
        (void)i686_copy_to_guest(ctx, frame_va + 8U, &sc, sizeof(sc));
        (void)i686_copy_to_guest(
            ctx, frame_va + (uint32_t)sizeof(i686_sigframe_t) - 8U,
            retcode_nonrt, 8U);
        hdr[0] = ((ga->flags & SA_RESTORER_) != 0U)
                     ? ga->restorer
                     : frame_va + (uint32_t)sizeof(i686_sigframe_t) - 8U;
        /* [frame+4] is the handler's signo argument (see rt branch). */
        hdr[1] = (uint32_t)sig;
        (void)i686_copy_to_guest(ctx, frame_va, hdr, sizeof(hdr));
    }

    /* SS_AUTODISARM delivery: the pre-delivery stack rides in
     * uc.uc_stack and the live stack disarms for the handler's
     * duration; sigreturn restores it from the frame. */
    if (disarm_altstack != 0) {
        if (sa_siginfo != 0) {
            uint8_t ss[12];
            memcpy(ss + 0U, &saved_sp, 4U);
            memcpy(ss + 4U, &saved_flags, 4U);
            memcpy(ss + 8U, &saved_size, 4U);
            (void)i686_copy_to_guest(ctx, frame_va + 0x90U + 8U, ss,
                                     sizeof ss);
        }
        ctx->altstack_sp = 0U;
        ctx->altstack_size = 0U;
        ctx->altstack_flags = 2U; /* SS_DISABLE */
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
            uint32_t tcb_w[4];
            memset(tcbdump, 0, sizeof(tcbdump));

            (void)i686_copy_from_guest(ctx, &ret, ctx->gpr[I686_REG_ESP],
                                       sizeof(ret));
            if (ctx->seg_base[I686_SEG_GS] != 0U) {
                (void)i686_copy_from_guest(
                    ctx, &sysinfo, ctx->seg_base[I686_SEG_GS] + 0x10U,
                    sizeof(sysinfo));
                (void)i686_copy_from_guest(ctx, &tcbdump,
                                           ctx->seg_base[I686_SEG_GS], 16U);
            }
            memcpy(tcb_w, tcbdump, sizeof(tcb_w));
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
                          tcb_w[0], tcb_w[1], tcb_w[2], tcb_w[3],
                          sc.eax, sc.ebx, sc.ecx, sc.edx, sc.esi, sc.edi,
                          sc.ebp);
        }
    }
    /* i386 ABI: DF=0 at handler entry; sc already holds the
     * pre-delivery eflags. DF lives in eflags, not the lazy word. */
    ctx->eflags &= ~I686_EF_DF;
    ctx->gpr[I686_REG_ESP] = frame_va;
    ctx->sig_last_frame_va = frame_va;
    ctx->sig_last_frame_rt = (uint32_t)sa_siginfo;
    ctx->eip = ga->handler;
    (void)info_va; (void)uc_va; (void)i;
    return 0;
}

/* Frozen exported entry (sigframe_i386.h): snapshots the current action
 * and delegates. In-tree delivery uses sigframe_build_snapshot with the
 * already-consumed (possibly RESETHAND-reset) snapshot instead. */
int i686_sigframe_build(i686_ctx_t *ctx, int sig, uint32_t handler,
                        uint32_t restorer, int sa_siginfo, uint32_t info_va,
                        uint32_t uc_va)
{
    struct i686_gsigaction ga;
    (void)handler; (void)restorer;
    if (i686_gsig_snapshot(sig, &ga) != 0) {
        return -1;
    }
    return sigframe_build_snapshot(ctx, sig, &ga, sa_siginfo, info_va,
                                   uc_va);
}

int i686_sigreturn(i686_ctx_t *ctx, int rt)
{
    i686_sigcontext_t sc;
    uint32_t base, frame, was_onstack;
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
    was_onstack = ctx->altstack_onstack;
    ctx->altstack_onstack = 0U; /* sigreturn leaves the alternate stack */
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
        uint64_t restored = 0ULL;
        if (i686_copy_from_guest(ctx, m, frame + 0x90U + 0x6cU, sizeof(m)) != 0) {
            return -1;
        }
        memcpy(&restored, m, sizeof(restored));
        __atomic_store_n(&ctx->sig_mask, restored, __ATOMIC_SEQ_CST);
        /* SS_AUTODISARM: re-arm the pre-delivery stack saved in
         * uc.uc_stack at delivery time. */
        {
            uint8_t ss[12];
            uint32_t s_sp, s_flags, s_size;
            if (i686_copy_from_guest(ctx, ss, frame + 0x90U + 8U,
                                     sizeof(ss)) == 0) {
                memcpy(&s_sp, ss + 0U, 4U);
                memcpy(&s_flags, ss + 4U, 4U);
                memcpy(&s_size, ss + 8U, 4U);
                if ((s_flags & 0x80000000U) != 0U) {
                    if (was_onstack == 0U) {
                        s_flags &= ~1U; /* not on it: clear SS_ONSTACK */
                    }
                    ctx->altstack_sp = s_sp;
                    ctx->altstack_flags = s_flags;
                    ctx->altstack_size = s_size;
                }
            }
        }
    } else {
        __atomic_store_n(&ctx->sig_mask, (uint64_t)sc.oldmask,
                         __ATOMIC_SEQ_CST);
    }
    ctx->gpr[I686_REG_EDI] = sc.edi; ctx->gpr[I686_REG_ESI] = sc.esi;
    ctx->gpr[I686_REG_EBP] = sc.ebp; ctx->gpr[I686_REG_ESP] = sc.esp;
    ctx->gpr[I686_REG_EBX] = sc.ebx; ctx->gpr[I686_REG_EDX] = sc.edx;
    ctx->gpr[I686_REG_ECX] = sc.ecx; ctx->gpr[I686_REG_EAX] = sc.eax;
    ctx->eip = sc.eip;
    /* R7-19: the restored eflags are authoritative — drop any stale
     * lazy descriptor, same as the CLI/STI paths. */
    ctx->eflags = sc.eflags;
    ctx->lazy_op = I686_FOP_NONE;
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
            ctx->fop = fp.fop;
            ctx->fpu_ip = (fp.fpu_ip2 != 0U) ? fp.fpu_ip2 : fp.fip;
            ctx->fpu_dp = (fp.fpu_dp2 != 0U) ? fp.fpu_dp2 : fp.foo;
            /* R7-21: phys_of() indexes the stack by ctx->x87_top, not
             * by the status word — resync TOP from SWD bits 11-13 or
             * every post-sigreturn access hits the wrong register. */
            x87_set_top(ctx, (uint8_t)((fp.swd >> 11) & 7u));
            ctx->mxcsr = fp.mxcsr;
            for (unsigned st_i = 0U; st_i < 8U; st_i++) {
                const uint8_t *ext = (const uint8_t *)fp.st_space + st_i * 10U;
                if (ctx->x87_80 != 0U) {
                    memcpy(&ctx->x87_st[st_i][0], ext, 10U);
                    memset(&ctx->x87_st[st_i][10], 0, 6U);
                } else {
                    double d = x87_ext80_to_f64(ext);
                    memcpy(&ctx->x87_st[st_i][0], &d, sizeof(d));
                    memset(&ctx->x87_st[st_i][8], 0, 8U);
                }
            }
            memcpy(ctx->xmm, &fp.xmm_space, sizeof(ctx->xmm));
        }
    }
    /* non-RT: the frame pushed sc.esp as the resume esp implicitly via
     * sigcontext; the 4-byte sig + pretcode slots were consumed by the
     * retcode's `pop eax`. RT: sigreturn cleans its own frame. */
    return 0;
}

/* Async host-signal bridge (Wave C2 p3_torture): the guest arms a real
 * host alarm(2) through sys_alarm. Without a host handler the 1s SIGALRM
 * kills the runner whenever translation runs slower than native (the FP
 * loop beats 1s natively but not under interp). The bridge converts the
 * host SIGALRM into a pending_signals bit on the main ctx, which both
 * engine loops already poll at safe points (interp.c, engine.c) and
 * i686_deliver_pending delivers honoring mask and disposition.
 * One-shot semantics: the armed flag clears at the first fire. With no
 * guest alarm armed (suite perl-alarm watchdog, stray timers) the handler
 * restores SIG_DFL and re-raises so hang protection still kills. */
static volatile sig_atomic_t s_alarm_armed = 0;
static volatile sig_atomic_t s_alarm_repeat = 0;

static void host_sigalrm_handler(int sig, siginfo_t *info, void *ucontext)
{
    extern i686_ctx_t *i686_thread_registry_main_ctx(void);
    extern uint32_t i686_gsig_handler_raw(int signum);
    i686_ctx_t *target;
    uint32_t disp;

    (void)sig;
    (void)info;
    (void)ucontext;
    if (s_alarm_armed == 0) {
        /* Not ours (watchdog): die with the default disposition. */
        (void)signal(SIGALRM, SIG_DFL);
        (void)raise(SIGALRM);
        return;
    }
    if (s_alarm_repeat == 0) {
        s_alarm_armed = 0; /* one-shot consumed */
    } /* interval timers stay armed across fires */
    target = i686_thread_registry_main_ctx();
    if (target == NULL) {
        (void)signal(SIGALRM, SIG_DFL);
        (void)raise(SIGALRM);
        return;
    }
    if ((__atomic_load_n(&target->sig_mask, __ATOMIC_SEQ_CST) &
         ((uint64_t)1U << 13)) != 0ULL) {
        /* Blocked: queue (kernel keeps it pending until unmasked). */
        __atomic_fetch_or(&target->pending_signals, (uint64_t)1U << 13,
                          __ATOMIC_SEQ_CST); /* SIGALRM = 14 */
        return;
    }
    disp = i686_gsig_handler_raw(14);
    if (disp == 1U) {
        return; /* SIG_IGN */
    }
    if (disp == 0U) {
        /* SIG_DFL: Linux default action terminates. */
        (void)signal(SIGALRM, SIG_DFL);
        (void)raise(SIGALRM);
        return;
    }
    __atomic_fetch_or(&target->pending_signals, (uint64_t)1U << 13,
                      __ATOMIC_SEQ_CST); /* SIGALRM = 14 */
}

/* Host alarm(2) wrapper that tracks the armed state for the bridge.
 * Called by sys_alarm (sys_time.c) instead of alarm() directly. */
unsigned i686_host_alarm(unsigned seconds);
unsigned i686_host_alarm(unsigned seconds)
{
    s_alarm_armed = (seconds != 0U) ? 1 : 0;
    s_alarm_repeat = 0;
    return alarm(seconds);
}

/* ITIMER_REAL arming for the bridge (sys_setitimer path: musl's
 * alarm() uses setitimer, not the alarm syscall).  repeat is nonzero
 * when it_interval is nonzero: interval timers stay armed across
 * fires, one-shot timers disarm at the first fire. */
void i686_host_alarm_set(int armed, int repeat);
void i686_host_alarm_set(int armed, int repeat)
{
    s_alarm_armed = (armed != 0) ? 1 : 0;
    s_alarm_repeat = (repeat != 0) ? 1 : 0;
}

void i686_signals_i386_init(void)
{
    /* Host-signal registration for async delivery: SA_RESTART keeps host
     * blocking syscalls (futex waits) across the timer; the pending bit
     * delivers at the next engine safe point. v1 still delivers sync
     * exits (FAULT/FPE/TRAP) directly at the engine exit switch. */
    struct sigaction sa;
    (void)memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = host_sigalrm_handler;
    (void)sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART | SA_SIGINFO;
    (void)sigaction(SIGALRM, &sa, NULL);
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
        } else if (hsig == 11 /*SIGSEGV*/ || hsig == SIGBUS /* 7 on Linux,
                                                           10 on Darwin */) {
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
        /* One consumed snapshot for the whole delivery (I686-R4-6): the
         * IGN/DFL decision, the SA_RESETHAND reset, and the frame below
         * all use this copy, so a concurrent rt_sigaction cannot swap
         * the action mid-delivery. */
        struct i686_gsigaction ga;
        int rt;
        if (i686_gsig_consume_oneshot(sig, &ga) != 0 ||
            ga.handler == 0U || ga.handler == 1U) {
            return -1;
        }
        if (sig == 11) {
            /* Segment faults (#GP 13 / #NP 11 / #SS 12, seg.c/h_seg.c)
             * carry their trapno in exit_arg and the error code in
             * exit_dest; every other FAULT is a page fault (#PF 14). */
            if (ctx->exit_arg != 11U && ctx->exit_arg != 12U &&
                ctx->exit_arg != 13U) {
                ctx->exit_arg = 14; /* trapno = #PF: page fault */
            }
        }
        rt = (ga.flags & SA_SIGINFO_) ? 1 : 0;
        return sigframe_build_snapshot(ctx, sig, &ga, rt, 0U, 0U);
    }
}

/* Deliver the lowest pending, unblocked signal at an engine safe point.
 * Unblock check against the guest mask (ctx->sig_mask, the
 * sys_rt_sigprocmask store).
 *
 * Kernel pending semantics (fix-campaign C1b handoff): a bit stays
 * pending while MASKED and delivers when the mask is lifted — musl's
 * raise() blocks all signals, tkills itself and restores, so the poll
 * runs inside the blocked window and MUST NOT drop the bit.  Only an
 * unblocked signal is consumed from ctx->pending_signals:
 *  - SIG_IGN (handler == 1U): dropped.
 *  - SIG_DFL (ga == NULL || handler == 0U): executes the Linux default
 *    disposition (ignore for SIGCHLD/SIGURG/SIGWINCH, continue for
 *    SIGCONT, stop for SIGSTOP/SIGTSTP/SIGTTIN/SIGTTOU, and process
 *    termination for all other signals).
 *  - Installed handler: builds a guest signal frame and redirects EIP. */
int i686_deliver_pending(i686_ctx_t *ctx)
{
    uint64_t pend =
        __atomic_load_n(&ctx->pending_signals, __ATOMIC_SEQ_CST);
    while (pend != 0ULL) {
        uint64_t bit = pend & (~pend + 1ULL); /* lowest set bit */
        struct i686_gsigaction ga;
        int sig = 1;
        uint64_t scan;
        uint64_t mask;

        pend ^= bit;
        for (scan = bit; scan > 1ULL; scan >>= 1) {
            sig++;
        }
        mask = __atomic_load_n(&ctx->sig_mask, __ATOMIC_SEQ_CST);
        if ((mask & bit) != 0ULL && sig != 9 && sig != 19) {
            continue; /* blocked: stays pending until unmasked */
        }
        /* One consumed snapshot per signal (I686-R4-6): the IGN/DFL
         * decision, the SA_RESETHAND reset, and the frame below all use
         * this copy. The snapshot's handler is the installed EIP even
         * after the reset flips the table back to SIG_DFL. */
        if (i686_gsig_consume_oneshot(sig, &ga) != 0) {
            __atomic_fetch_and(&ctx->pending_signals, ~bit,
                               __ATOMIC_SEQ_CST);
            continue;
        }
        if (ga.handler == 1U && sig != 9 && sig != 19) {
            /* SIG_IGN: drop */
            __atomic_fetch_and(&ctx->pending_signals, ~bit,
                               __ATOMIC_SEQ_CST);
            continue;
        }
        if (ga.handler == 0U || sig == 9 || sig == 19) {
            __atomic_fetch_and(&ctx->pending_signals, ~bit,
                               __ATOMIC_SEQ_CST);
            if (sig == 17 || sig == 18 || sig == 23 || sig == 28) {
                continue; /* Ign / Cont */
            }
            if (sig == 19 || sig == 20 || sig == 21 || sig == 22) {
                (void)kill(getpid(), SIGSTOP);
                continue;
            }
            if (sig > 0 && sig < 32) {
                (void)signal(sig, SIG_DFL);
                (void)raise(sig);
            }
            _exit(128 + sig);
        }
        __atomic_fetch_and(&ctx->pending_signals, ~bit,
                           __ATOMIC_SEQ_CST);
        ctx->exit_arg = 0; /* no trapno for async */
        return sigframe_build_snapshot(ctx, sig, &ga,
                                       (ga.flags & 0x4U) ? 1 : 0, 0U, 0U);
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
