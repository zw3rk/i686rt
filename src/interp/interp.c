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
#if (defined(__linux__) || defined(__APPLE__)) && defined(__aarch64__)
#include <sys/ucontext.h>
#endif

#include "dbt/aot/aot.h"
#include "interp/flags.h"
#include "interp/interp.h"
#include "os/marshal.h"
#include "vm/vm_file.h"

/* x86 helpers owned by sibling lanes (same extern pattern as h_alu.c). */
extern uint8_t x86_ea_seg(const x86_insn_t *insn);
extern void i686_seg_check_data(i686_ctx_t *ctx, uint8_t seg, uint32_t linear,
                                unsigned bytes, unsigned write);

/* Host-fault -> guest-fault checkpoint (Phase 4).  The handler runs on
 * the faulting host thread; sigsetjmp/siglongjmp restores the interp
 * loop with the fault recorded.  The jump target lives in the frame of
 * the i686_interp_run call that armed it — one per host thread, via
 * the __thread pointer below (the previous file-static buffer let a
 * fault in one guest thread siglongjmp through whichever guest thread
 * armed it last, resuming on a foreign stack: RC7b T4d). */
static __thread sigjmp_buf *s_fault_jmp;
static volatile sig_atomic_t s_in_run;
/* C2-2: all fault capture state is per-thread.  It was process-global,
 * so two threads faulting concurrently clobbered each other's
 * addr/host_pc/esp/regs/sig/code and recovered with the wrong thread's
 * values (heap corruption under thread contention).  The handler runs
 * on the faulting thread and the checkpoint is per-thread, so
 * __thread is exactly right. */
static __thread volatile uint64_t s_fault_addr;
static __thread volatile uint64_t s_fault_host_pc;
/* Live guest ESP (host w4/x4) at the fault: in DBT-emitted code w4 is
 * the dedicated guest-ESP register, while ctx->gpr[ESP] is only synced
 * on clean exits to C and goes stale across chained blocks.  Captured
 * for every fault; meaningful only when the fault PC is inside a
 * translated block (helper/C faults leave w4 as host scratch). */
static __thread volatile uint64_t s_fault_esp;
/* Live host x0..x28 at fault (DBT site recovery reads w0..w7). */
__thread volatile uint64_t g_fault_x[29];

/* Pre-instruction ESP/EBP checkpoint (RC-U3): a faulting stack op must
 * not leave ESP/EBP mutated (No-Double-Side-Effect).  Only stack ops
 * mutate them mid-instruction, so restoring on fault is exact. */
static __thread uint32_t s_saved_esp;
static __thread uint32_t s_saved_ebp;
/* R7-15: pre-instruction lazy-flag checkpoint.  Handlers commit flags
 * after their faultable stores, but a fault between the two (or inside
 * x87/SSE flag updates) must not leak the half-published descriptor
 * into the retry: the whole EFLAGS state is restored with ESP/EBP. */
static __thread uint32_t s_saved_eflags;
static __thread uint32_t s_saved_lazy_op;
static __thread uint32_t s_saved_lazy_res;
static __thread uint32_t s_saved_lazy_src1;
static __thread uint32_t s_saved_lazy_src2;
static __thread uint32_t s_saved_lazy_cf_in;
static __thread uint32_t s_saved_lazy_width;
/* Last guest address remapped-and-resumed by the #4 path below: a fault
 * at the same address twice in a row is not healing, so deliver it.
 * The delivery path resets it to "none", so a later transient may heal. */
static __thread uint64_t s_last_remap_ga = UINT64_C(0xFFFFFFFFFFFFFFFF);

static __thread volatile sig_atomic_t s_fault_sig;
static __thread volatile sig_atomic_t s_fault_code;

static void host_fault_handler(int sig, siginfo_t *si, void *uc_)
{
    sigjmp_buf *jb = s_fault_jmp;
#if defined(__linux__) && defined(__aarch64__)
    {
        ucontext_t *uc = (ucontext_t *)uc_;
        int r;
        s_fault_host_pc = (uc != NULL) ? (uint64_t)uc->uc_mcontext.pc : 0u;
        s_fault_esp = (uc != NULL) ? (uint64_t)uc->uc_mcontext.regs[4] : 0u;
        for (r = 0; r < 29; r++) {
            g_fault_x[r] =
                (uc != NULL) ? (uint64_t)uc->uc_mcontext.regs[r] : 0u;
        }
    }
#elif defined(__APPLE__) && defined(__aarch64__)
    {
        ucontext_t *uc = (ucontext_t *)uc_;
        int r;
        s_fault_host_pc = (uc != NULL && uc->uc_mcontext != NULL)
                              ? (uint64_t)uc->uc_mcontext->__ss.__pc
                              : 0u;
        s_fault_esp = (uc != NULL && uc->uc_mcontext != NULL)
                              ? (uint64_t)uc->uc_mcontext->__ss.__x[4]
                              : 0u;
        for (r = 0; r < 29; r++) {
            g_fault_x[r] = (uc != NULL && uc->uc_mcontext != NULL)
                               ? (uint64_t)uc->uc_mcontext->__ss.__x[r]
                               : 0u;
        }
    }
#else
    (void)uc_;
    s_fault_host_pc = 0u;
    s_fault_esp = 0u;
#endif
    /* D11 SMC: a write to a DBT code-protected window page.  The
     * engine drops the page's blocks and restores RW; returning
     * re-executes the store.  Linux raises SIGSEGV+SEGV_ACCERR; Darwin
     * raises SIGBUS for the same store (verified on arm64: a write to
     * a PROT_READ private page arrives as SIGBUS, code BUS_ADRALN).
     * The marking check inside i686_dbt_smc_write_fault keeps this
     * precise: unmarked pages return 0 and fall through to guest
     * delivery below. */
    if (sig == SIGSEGV && si->si_code == SEGV_ACCERR) {
#ifndef I686RT_NO_DBT
        extern int i686_dbt_smc_write_fault(uint64_t host_addr);
        if (i686_dbt_smc_write_fault((uint64_t)(uintptr_t)si->si_addr)) {
            return;
        }
#endif
    }
#if defined(__APPLE__) && !defined(I686RT_NO_DBT)
    if (sig == SIGBUS) {
        extern int i686_dbt_smc_write_fault(uint64_t host_addr);
        if (i686_dbt_smc_write_fault((uint64_t)(uintptr_t)si->si_addr)) {
            return;
        }
    }
#endif
    if (s_in_run && jb != NULL) {
        s_fault_jmp = NULL; /* disarm: a nested fault must not re-jump */
        s_fault_addr = (uint64_t)(uintptr_t)si->si_addr;
        s_fault_sig = sig;
        s_fault_code = (sig_atomic_t)si->si_code;
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

/* Outer checkpoint for syscall-copy fault tolerance (marshal.c): a
 * copy runs its own inner checkpoint and restores this on every
 * outcome, re-raising genuine faults to it. */
sigjmp_buf *i686_fault_save(void)
{
    return s_fault_jmp;
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

/* Host siginfo code of the checkpointed fault (SEGV_MAPERR vs
 * SEGV_ACCERR selects remap-and-resume vs deliver in the catches). */
int i686_fault_code(void)
{
    return (int)s_fault_code;
}

/* Validate a faulting guest address against the region mirror: returns
 * 1 with the covering region's prot/flags when mapped, 0 when the
 * address falls in no region (genuine unmapped fault). */
int i686_fault_region_prot(const i686_ctx_t *ctx, uint32_t ga,
                            uint32_t *out_prot, uint32_t *out_flags)
{
    size_t i;
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->vm_reserved[0] != 0U && out_flags == NULL) {
        if ((i686_vm_file_flags(ga) & 0x80u) == 0u) {
            return 0;
        }
        if (out_prot != NULL) {
            *out_prot = (uint32_t)i686_vm_file_prot(ga);
        }
        return 1;
    }
    for (i = 0U; i < ctx->region_count; i++) {
        const i686_region_t *r = &ctx->regions[i];
        if (r->start <= ga && ga < r->end) {
            if (out_prot != NULL) {
                *out_prot = r->prot;
            }
            if (out_flags != NULL) {
                *out_flags = r->flags;
            }
            return 1;
        }
    }
    return 0;
}

/* Faulting host PC (DBT site recovery in engine.c; 0 when unknown). */
uint64_t i686_fault_host_pc(void)
{
    return (uint64_t)s_fault_host_pc;
}

/* Live guest ESP captured from the faulting host register state
 * (DBT site recovery in engine.c; meaningful only for faults inside
 * translated blocks). */
uint64_t i686_fault_esp(void)
{
    return (uint64_t)s_fault_esp;
}

/* Live guest GPRs (host w0..w7) captured at a checkpointed fault (DBT
 * site recovery in engine.c; meaningful only when the fault PC is
 * inside a translated block, like i686_fault_esp).  Blocks spill GPRs
 * to ctx only at clean exits, so on a mid-block fault ctx predates the
 * block; the heal/emulate/deliver paths all read ctx and need live. */
uint64_t i686_fault_gpr(unsigned r)
{
    return (r < 29u) ? (uint64_t)g_fault_x[r] : 0u;
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

/* R7-7: LOCK legality is decided centrally in the decoder
 * (x86_lock_legal, SDM Vol 2A whitelist + memory destination); the
 * shift-only check it replaces lives on in h_shift.c as a backstop. */

static i686_interp_fn s_registry[I686_REGISTRY_MAX];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    if ((unsigned)op < I686_REGISTRY_MAX) {
        s_registry[op] = fn;
    }
}

/* R7-30: FP/WAIT op marking for the pending-#MF check.  The x87 init
 * functions mark their registered ops (interp.c owns the bits, so
 * frozen interp.h needs no new entry; handler TU's declare the
 * marker via interp/h_x87_internal.h). */
static uint64_t s_fp_ops[I686_REGISTRY_MAX / 64U];

void i686_interp_mark_fp(uint16_t op)
{
    if ((unsigned)op < I686_REGISTRY_MAX) {
        s_fp_ops[(unsigned)op / 64U] |=
            (uint64_t)1 << ((unsigned)op % 64U);
    }
}

static int i686_interp_is_fp(uint16_t op)
{
    if ((unsigned)op >= I686_REGISTRY_MAX) {
        return 0;
    }
    return ((s_fp_ops[(unsigned)op / 64U] >>
             ((unsigned)op % 64U)) & 1U) != 0U;
}

/* R7-30/N3: a pending unmasked x87 exception (ES) raises #MF before
 * the next FP/WAIT instruction executes; EIP stays at it (fault).
 * N3: the no-wait control/save forms (FNCLEX, FNINIT, FNSTSW,
 * FNSTCW, FNSTENV, FNSAVE, FXSAVE, FXRSTOR) execute despite ES so a
 * SIGFPE handler can clear with FNCLEX without re-faulting. */
static int fp_pending_trap(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    extern void i686_fault_sig_record(int sig);
    extern int i686_x87_is_nowait(const x86_insn_t *insn);

    if (!i686_interp_is_fp(insn->op) || (ctx->fstat & 0x80U) == 0U) {
        return I686_INTERP_CONTINUE;
    }
    if (i686_x87_is_nowait(insn)) {
        return I686_INTERP_CONTINUE;
    }
    ctx->exit_reason = I686_EXIT_FAULT;
    ctx->exit_arg = 16U; /* #MF trapno */
    i686_fault_sig_record(8); /* SIGFPE */
    return I686_EXIT_FAULT;
}

static int s_trace;
/* Per-insn T lines flood heavy guests (p3 FP loop: 1e8+ insns) while
 * difftest only compares the S sequence (compare_native: the DBT side
 * never emits T).  I686RT_TRACE_NO_T keeps S lines and drops T lines
 * so long-loop guests stay feasible under differential tracing. */
static int s_trace_no_t;

void i686_trace_insn(const i686_ctx_t *ctx, const x86_insn_t *insn,
                     const uint8_t *bytes);
void i686_trace_insn(const i686_ctx_t *ctx, const x86_insn_t *insn,
                     const uint8_t *bytes)
{
    uint32_t b;
    char tl[80];
    int tn;
    if (!s_trace || s_trace_no_t || ctx->engine == I686_ENGINE_DBT) {
        return;
    }
    tn = snprintf(tl, sizeof tl, "T %d %08x op=%u len=%u b=",
                  (int)getpid(), ctx->eip, (unsigned)insn->op, insn->len);
    for (b = 0U; b < insn->len && b < 8U && tn < (int)sizeof tl - 3; b++) {
        uint8_t v = (bytes != NULL)
                        ? bytes[b]
                        : *(const volatile uint8_t *)i686_guest_ptr(
                              ctx, ctx->eip + b);
        tn += snprintf(tl + tn, sizeof tl - (size_t)tn, "%02x", v);
    }
    snprintf(tl + tn, sizeof tl - (size_t)tn, " esp=%08x\n",
             ctx->gpr[I686_REG_ESP]);
    (void)write(2, tl, strlen(tl));
}

void i686_trace_syscall(const i686_ctx_t *ctx, long nr, long rv);
void i686_trace_syscall(const i686_ctx_t *ctx, long nr, long rv)
{
    if (!s_trace) {
        return;
    }
    if (nr == 4 || nr == 3) {
        (void)fprintf(stderr, "S %ld(%u,%08x,%u) -> %ld\n", nr,
                      ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                      ctx->gpr[I686_REG_EDX], rv);
    } else if (nr == 5 || nr == 195 || nr == 196 || nr == 383 || nr == 11) {
        (void)fprintf(stderr, "S %ld(%08x) -> %ld\n", nr,
                      ctx->gpr[I686_REG_EBX], rv);
    } else {
        (void)fprintf(stderr, "S %ld -> %ld\n", nr, rv);
    }
}

void i686_interp_init_all(void)
{
    static int s_done;
    if (s_done) {
        return;
    }
    s_done = 1;
    s_trace = getenv("I686RT_TRACE") != NULL;
    s_trace_no_t = getenv("I686RT_TRACE_NO_T") != NULL;
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
    extern void i686_vm32_exec_enter(const i686_ctx_t *);
    extern void i686_vm32_exec_leave(void);
    x86_insn_t insn;
    i686_interp_fn fn;
    int r;

    i686_vm32_exec_enter(ctx);
    if (x86_decode(ctx, ctx->eip, &insn) != 0) {
        uint32_t b;
        i686_vm32_exec_leave();
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
    if (insn.pfx_lock != 0U && !x86_lock_legal(&insn)) {
        i686_vm32_exec_leave();
        ctx->exit_reason = I686_EXIT_UNDEF;
        ctx->exit_arg = insn.op;
        return I686_EXIT_UNDEF;
    }
    /* R7-30: pending unmasked x87 exception (the engine delivers
     * the FAULT it returns). */
    if (fp_pending_trap(ctx, &insn) != I686_INTERP_CONTINUE) {
        i686_vm32_exec_leave();
        return I686_EXIT_FAULT;
    }
    fn = (unsigned)insn.op < I686_REGISTRY_MAX ? s_registry[insn.op] : NULL;
    if (fn == NULL) {
        i686_vm32_exec_leave();
        ctx->exit_reason = I686_EXIT_UNDEF;
        ctx->exit_arg = insn.op;
        diag("unimplemented opcode", ctx, insn.op);
        return I686_EXIT_UNDEF;
    }
    r = fn(ctx, &insn);
    i686_vm32_exec_leave();
    ctx->blocks_executed++;
    if (r == I686_INTERP_CONTINUE) {
        return 0;
    }
    switch (r) {
    case I686_EXIT_SYSCALL: {
        long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
        long rv = i686_handle_syscall(ctx);
        i686_trace_syscall(ctx, nr, rv);
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
    extern void i686_vm32_exec_enter(const i686_ctx_t *);
    extern void i686_vm32_exec_leave(void);
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
        i686_vm32_exec_leave();
        i686_split_lock_release_if_held();
        ctx->gpr[I686_REG_ESP] = s_saved_esp;
        ctx->gpr[I686_REG_EBP] = s_saved_ebp;
        /* R7-15: restore the pre-instruction EFLAGS state with ESP/EBP
         * so the retry observes the flags the faulting instruction
         * found (STC; ADC [ro],0 retries with its entry carry). */
        ctx->eflags = s_saved_eflags;
        ctx->lazy_op = s_saved_lazy_op;
        ctx->lazy_res = s_saved_lazy_res;
        ctx->lazy_src1 = s_saved_lazy_src1;
        ctx->lazy_src2 = s_saved_lazy_src2;
        ctx->lazy_cf_in = s_saved_lazy_cf_in;
        ctx->lazy_width = s_saved_lazy_width;
        s_in_run = 1;
        if (fa >= ctx->guest_base &&
            fa < ctx->guest_base + 0x100000000ULL) {
            ctx->fault_addr = (uint32_t)(fa - ctx->guest_base);
        } else {
            ctx->fault_addr = (uint32_t)fa;
        }
        /* C2-2 mirror-consulting fault classification (replaces the
         * RC-U3-r2 SEGV_MAPERR-only validate-then-map).  On Regime A2
         * the host mapping is widened (most-restrictive), and on Darwin
         * protection faults arrive as SIGBUS, so si_code alone cannot
         * classify: consult the fine-grained mirror instead.
         *  - Mapped page, mirror fully R|W: the host cover went stale
         *    (or the touch is a spurious widen neighbour).  Emulate
         *    via interpret-one (unprotect, step, re-widen); when the
         *    step takes its own exit, fall through to the plain
         *    widen-and-retry below, bounded once by s_last_remap_ga.
         *  - Mapped page, mirror denies: genuine PROT_NONE/RO fault.
         *  - Unmapped: genuine unmapped fault (backing-file SIGBUS
         *    truncation included).  Both deliver below.
         * The s_last_remap_ga guard bounds a non-healing fault to a
         * single retry. */
        if (fa >= ctx->guest_base &&
            fa < ctx->guest_base + 0x100000000ULL) {
            extern int i686_vm32_widen_prot(i686_ctx_t *, uint32_t,
                                            uint32_t);
            extern int i686_spurious_emulate(i686_ctx_t *, uint32_t);
            extern int i686_spurious_allow(i686_ctx_t *, uint32_t);
            uint32_t rga = (uint32_t)(fa - ctx->guest_base);
            if (rga != (uint32_t)s_last_remap_ga &&
                i686_fault_region_prot(ctx, rga, NULL, NULL) != 0) {
                ctx->exit_reason = I686_EXIT_NONE;
                if (i686_spurious_emulate(ctx, rga) == 0) {
                    if (ctx->exit_reason == I686_EXIT_SYSCALL) {
                        return I686_EXIT_SYSCALL;
                    }
                    i686_fault_arm(&fault_jmp); /* re-arm: resume may fault */
                    goto run_loop; /* emulated; resume past the insn */
                }
                if ((ctx->vm_regime != I686_VM_REGIME_A2 ||
                     ctx->vm_host_page <= 4096u) &&
                    i686_spurious_allow(ctx, rga) != 0 &&
                    i686_vm32_widen_prot(ctx, rga & ~0xFFFU,
                                         (rga & ~0xFFFU) + 0x1000U) == 0) {
                    s_last_remap_ga = (uint64_t)rga;
                    i686_fault_arm(&fault_jmp);
                    goto run_loop; /* cover re-asserted; retry */
                }
            }
        }
        /* A fault that reaches delivery clears the remap guard, so a
         * later transient at an old address may heal again. */
        s_last_remap_ga = UINT64_C(0xFFFFFFFFFFFFFFFF);
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

        /* RC-U3 checkpoint for the fault path above (must precede
         * x86_decode so an instruction-fetch fault on a widened page
         * never restores a stale ESP/EBP from the previous insn).
         * R7-15: the EFLAGS descriptor rides the same checkpoint. */
        s_saved_esp = ctx->gpr[I686_REG_ESP];
        s_saved_ebp = ctx->gpr[I686_REG_EBP];
        s_saved_eflags = ctx->eflags;
        s_saved_lazy_op = ctx->lazy_op;
        s_saved_lazy_res = ctx->lazy_res;
        s_saved_lazy_src1 = ctx->lazy_src1;
        s_saved_lazy_src2 = ctx->lazy_src2;
        s_saved_lazy_cf_in = ctx->lazy_cf_in;
        s_saved_lazy_width = ctx->lazy_width;
        i686_vm32_exec_enter(ctx);
        if (x86_decode(ctx, ctx->eip, &insn) != 0) {
            uint32_t b;
            i686_vm32_exec_leave();
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = 0;
            /* R7-22: undecodable bytes are #UD (a fault: eip still
             * addresses them) — deliver SIGILL before diagnosing. */
            {
                extern int i686_deliver_sync(i686_ctx_t *, int reason);
                if (i686_deliver_sync(ctx, (int)I686_EXIT_UNDEF) == 0) {
                    continue;
                }
            }
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
        if (insn.pfx_lock != 0U && !x86_lock_legal(&insn)) {
            i686_vm32_exec_leave();
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = insn.op;
            {
                extern int i686_deliver_sync(i686_ctx_t *, int reason);
                if (i686_deliver_sync(ctx, (int)I686_EXIT_UNDEF) == 0) {
                    continue;
                }
            }
            diag("opcode refused", ctx, insn.op);
            return I686_EXIT_UNDEF;
        }
        /* R7-30: pending unmasked x87 exception raises #MF
         * before the next FP/WAIT instruction (delivered like
         * any synchronous fault below). */
        if (fp_pending_trap(ctx, &insn) != I686_INTERP_CONTINUE) {
            int fpr;

            i686_vm32_exec_leave();
            {
                extern int i686_deliver_sync(i686_ctx_t *, int reason);
                fpr = i686_deliver_sync(ctx, (int)I686_EXIT_FAULT);
            }
            if (fpr == 0) {
                continue;
            }
            diag("x87 pending exception (#MF)", ctx, insn.op);
            return I686_EXIT_FAULT;
        }
        fn = (unsigned)insn.op < I686_REGISTRY_MAX ? s_registry[insn.op] : NULL;
        if (fn == NULL) {
            i686_vm32_exec_leave();
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = insn.op;
            /* R7-22: unhandled opcodes are #UD — deliver SIGILL
             * (eip still addresses the faulting insn). */
            {
                extern int i686_deliver_sync(i686_ctx_t *, int reason);
                if (i686_deliver_sync(ctx, (int)I686_EXIT_UNDEF) == 0) {
                    continue;
                }
            }
            diag("unimplemented opcode", ctx, insn.op);
            return I686_EXIT_UNDEF;
        }
        i686_trace_insn(ctx, &insn, NULL);
        r = fn(ctx, &insn);
        i686_vm32_exec_leave();
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
            i686_trace_syscall(ctx, nr, rv);
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
 * is implicitly locked: aligned 8-byte __atomic_compare_exchange on
 * HVA; unaligned EAs pre-validate both 4-byte spans before taking the
 * lane split lock (RC-U3 P1: never strand on fault). */
int h_CMPXCHG8B(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t ea, alo, ahi;
    uint64_t *q;
    uint32_t fl;

    if (insn->modrm_mod == 3U || insn->modrm_reg != 1U) {
        return I686_EXIT_UNDEF;
    }
    ea = x86_ea_compute(ctx, insn);
    i686_seg_check_data(ctx, x86_ea_seg(insn), ea, 8U, 1u);
    /* R7-17: probe host writability before any load/flag/register commit
     * so a mismatching compare against read-only memory faults. */
    if (!i686_span_mapped_writable(ctx, ea, 8U)) {
        uint8_t *pb = (uint8_t *)i686_guest_ptr(ctx, ea);
        uint8_t b0 = pb[0];
        pb[0] = b0;
    }
    q = (uint64_t *)i686_guest_ptr(ctx, ea);
    alo = ctx->gpr[I686_REG_EAX];
    ahi = ctx->gpr[I686_REG_EDX];
    if ((((uintptr_t)q) & 7u) == 0u) {
        uint64_t expected;
        uint64_t desired;
        bool ok;
        /* RC-U3-r2 P1 #5: aligned word-CAS also serializes under the
         * lane split lock so aligned/unaligned LOCK RMWs are atomic. */
        i686_split_lock_acquire();
        expected = ((uint64_t)ahi << 32) | (uint64_t)alo;
        desired = ((uint64_t)ctx->gpr[I686_REG_ECX] << 32) |
                  (uint64_t)ctx->gpr[I686_REG_EBX];
        ok = __atomic_compare_exchange_n(q, &expected, desired, false,
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
        i686_split_lock_release();
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
