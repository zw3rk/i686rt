/*
 * tests/test_p4_threads_signals.c — freestanding i386 Phase 4
 * threads/signals self-test (docs/lanes/phase-4.md, card L4a)
 *
 * A no-libc, no-headers i386 static ELF (own _start, raw int $0x80,
 * fixed-width typedefs; i386 gcc without musl-dev cannot include
 * <stdint.h>, so nothing is included) exercising the Phase 4 os
 * surface against the frozen ABI contracts (src/os/sigframe_i386.h,
 * src/os/threads.h):
 *
 *   (1a) rt_sigaction(SIGSEGV) with SA_SIGINFO|SA_RESTORER pointing at
 *        a guest retcode stub (mov $173,%eax; int $0x80 — the i386
 *        rt_sigreturn restorer; the rt frame is parsed from esp-4, so
 *        unlike the non-RT retcode it takes no `pop %eax`); the fault
 *        is *(volatile int *)0 = 1 via a 6-byte `movl $1,(%eax)` with
 *        eax=0.  The handler verifies sigcontext eip/cr2/trapno and
 *        siginfo si_code/si_addr through its SA_SIGINFO args (rt frame
 *        built with uc at +0x90, sigcontext at uc+20), fixes nothing
 *        and recovers siglongjmp-style by advancing uc_mcontext.eip
 *        past the faulting store, then returns through
 *        rt_sigreturn(173); the code after the fault checks flags.
 *   (1b) non-RT minimal variant: handler(int sig) installed without
 *        SA_SIGINFO/SA_RESTORER so delivery uses the non-RT sigframe
 *        whose embedded retcode is `pop %eax; mov $119,%eax; int $0x80`
 *        (sigreturn(119) parses the frame from esp-8, past the pop).
 *        The handler walks the frame (sigcontext at &sig+4 == esp+8),
 *        checks cr2 and skips the faulting insn the same way.
 *   (2)  rt_sigaction(SIGFPE) with SA_SIGINFO + SA_RESTORER; an
 *        `idiv %ecx` with ecx=0 raises #DE; the handler checks
 *        si_code == FPE_INTDIV, sigcontext eip/trapno == 0, defines
 *        eax/edx (idiv leaves them unwritten), skips the 2-byte idiv
 *        and returns through sigreturn; execution continues to exit 0.
 *   (3)  set_thread_area(user_desc{entry -1 auto-alloc, base = static
 *        .data TLS block}) + `mov %ax,%gs` to establish the process
 *        TLS slot (i386 TLS: process-wide selector index, per-thread
 *        descriptor content), then clone(CLONE_VM|CLONE_FS|CLONE_FILES|
 *        CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|
 *        CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID) — the standard
 *        pthread flag word — with a user_desc
 *        { entry_number = -1 (auto-alloc), base = static .data TLS
 *        block, limit 4 GB, 32-bit, page-granular, useable }.  The
 *        child writes/reads gs:0 and gs:8 through its TLS block,
 *        publishes the read-back plus a linear view through shared
 *        memory, does futex(FUTEX_WAKE, &child_tidptr) and exits; the
 *        parent futex(FUTEX_WAIT)s on child_tidptr until cleared and
 *        verifies the child's TLS values.
 *   (4)  fork() + wait4(): child exits 42, parent checks
 *        WIFEXITED && WEXITSTATUS == 42.
 *
 * Kernel-exact layout mirrors below must stay in lockstep with the
 * frozen src/os/sigframe_i386.h (sigcontext 88 B, ucontext 116 B with
 * uc_mcontext at +20, rt frame uc at +0x90).  Oracle check (must print
 * PASS):
 *   docker run --rm -v "$PWD":/w --platform linux/386 alpine:3.20 \
 *       sh -c 'apk add -q gcc && cc -nostdlib -static -march=i686 \
 *       -mno-mmx -mno-sse -mno-sse2 -fno-pie \
 *       -o /w/_build/test_p4 /w/tests/test_p4_threads_signals.c \
 *       && /w/_build/test_p4'
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/* i386 ILP32: these are the fixed-width types; no headers included. */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef int            s32;

/* ------------------------------------------------------------------ */
/* raw int 0x80 syscalls (i386 numbers, args in ebx,ecx,edx,esi,edi)   */
/* ------------------------------------------------------------------ */

static long sys_write(int fd, const void *buf, unsigned long len)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(4L), "b"((long)fd), "c"(buf), "d"((long)len)
                      : "memory");
    return r;
}

__attribute__((noreturn))
static void sys_exit(long code)
{
    __asm__ volatile ("int $0x80" : : "a"(1L), "b"(code));
    __builtin_unreachable();
}

static long sys_fork(void)
{
    long r;
    __asm__ volatile ("int $0x80" : "=a"(r) : "a"(2L) : "memory");
    return r;
}

static long sys_wait4(int pid, u32 *status, int options)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(114L), "b"((long)pid), "c"(status),
                        "d"((long)options), "S"(0L)
                      : "memory");
    return r;
}

static long sys_rt_sigaction(int sig, const void *act, void *oact)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(174L), "b"((long)sig), "c"(act), "d"(oact),
                        "S"(8L) /* sigsetsize = NSIG/8 on i386 */
                      : "memory");
    return r;
}

static long sys_futex(volatile u32 *uaddr, int op, u32 val)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(240L), "b"((long)uaddr),
                        "c"((long)op), "d"((long)val)
                      : "memory");
    return r;
}

static long sys_set_thread_area(void *ud)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(243L), "b"(ud)
                      : "memory");
    return r;
}

#define FUTEX_WAIT_ 0
#define FUTEX_WAKE_ 1

/* ------------------------------------------------------------------ */
/* print helpers + TEST(name, got, want): on mismatch print           */
/* "FAIL <name> got=0x.. want=0x.." and exit(1).                      */
/* ------------------------------------------------------------------ */

static void put(const char *s, unsigned n)
{
    sys_write(1, s, (unsigned long)n);
}

static void puts_(const char *s)
{
    unsigned n = 0u;
    while (s[n] != '\0') {
        n++;
    }
    put(s, n);
}

static void phex(u32 v)
{
    static const char hx[16] = "0123456789abcdef";
    char b[8];
    int i;
    for (i = 7; i >= 0; i--) {
        b[i] = hx[v & 0xfu];
        v >>= 4;
    }
    put(b, 8);
}

#define TEST(name, got, want)                            \
    do {                                                 \
        u32 g_ = (u32)(got);                             \
        u32 w_ = (u32)(want);                            \
        if (g_ != w_) {                                  \
            puts_("FAIL ");                              \
            puts_(name);                                 \
            puts_(" got=0x");                            \
            phex(g_);                                    \
            puts_(" want=0x");                           \
            phex(w_);                                    \
            put("\n", 1);                                \
            sys_exit(1);                                 \
        }                                                \
    } while (0)

/* ------------------------------------------------------------------ */
/* kernel-exact i386 signal-ABI mirrors (frozen sigframe_i386.h)       */
/* ------------------------------------------------------------------ */

/* struct sigcontext_32 — 88 B, cr2 at 0x54 (kernel uapi). */
struct sc_x {
    u16 gs, gsh, fs, fsh, es, esh, ds, dsh;      /* 0x00 */
    u32 edi, esi, ebp, esp, ebx, edx, ecx, eax;  /* 0x10 */
    u32 trapno, err, eip;                        /* 0x30 */
    u16 cs, csh;                                 /* 0x3c */
    u32 eflags, esp_at_signal;                   /* 0x40 */
    u16 ss, ssh;                                 /* 0x48 */
    u32 fpstate, oldmask, cr2;                   /* 0x4c,0x50,0x54 */
} __attribute__((packed));

/* ucontext_ia32 — 116 B; uc_mcontext (sigcontext) at +20. */
struct ucontext_x {
    u32 uc_flags;                                /* 0  */
    u32 uc_link;                                 /* 4  */
    u32 ss_sp, ss_flags, ss_size;                /* 8  */
    struct sc_x uc_mcontext;                     /* 20 */
    u32 uc_sigmask[2];                           /* 108 */
} __attribute__((packed));

/* siginfo payload: si_code at +8, si_addr at +12 for SIGSEGV/SIGFPE. */
struct siginfo_x {
    s32 si_signo;
    s32 si_errno;
    s32 si_code;
    u32 si_addr;
    u8 __pad[112];
} __attribute__((packed));

/* kernel i386 sigaction (20 B): handler, flags, restorer, mask[2]. */
struct sa_x {
    u32 handler;
    u32 flags;
    u32 restorer;
    u32 mask[2];
} __attribute__((packed));

#define SA_SIGINFO_  0x00000004u
#define SA_RESTORER_ 0x04000000u

/* struct user_desc — 16 B; the flags word packs the kernel bitfields:
 * bit0 seg_32bit, bits1-2 contents, bit3 read_exec_only,
 * bit4 limit_in_pages, bit5 seg_not_present, bit6 useable. */
struct user_desc_x {
    u32 entry_number;
    u32 base_addr;
    u32 limit;
    u32 flags;
} __attribute__((packed));

/* clone flags (kernel values, i386 == generic).  The full pthread
 * set is required: the kernel mandates CLONE_THREAD -> CLONE_SIGHAND
 * -> CLONE_VM, and CLONE_FS|CLONE_FILES|CLONE_SYSVSEM complete the
 * standard pthread_create flag word (what musl/glibc pass and the
 * qemu-user oracle enforces via its CLONE_THREAD_FLAGS mask). */
#define CLONE_VM_              0x00000100u
#define CLONE_FS_              0x00000200u
#define CLONE_FILES_           0x00000400u
#define CLONE_SIGHAND_         0x00000800u
#define CLONE_THREAD_          0x00010000u
#define CLONE_SYSVSEM_         0x00040000u
#define CLONE_SETTLS_          0x00080000u
#define CLONE_PARENT_SETTID_   0x00100000u
#define CLONE_CHILD_CLEARTID_  0x00200000u

_Static_assert(sizeof(struct sc_x) == 88u, "sigcontext_32 must be 88 B");
_Static_assert(sizeof(struct ucontext_x) == 116u, "ucontext_32 must be 116 B");
_Static_assert(sizeof(struct sa_x) == 20u, "sigaction_32 must be 20 B");
_Static_assert(sizeof(struct user_desc_x) == 16u, "user_desc must be 16 B");
_Static_assert(sizeof(u32) == 4u, "i386 build expected");
_Static_assert(sizeof(void *) == 4u, "i386 build expected");

/* ------------------------------------------------------------------ */
/* exact-encoded guest helpers (.text, byte-exact so the handlers can  */
/* skip them by a fixed length; addresses taken from C)                */
/* ------------------------------------------------------------------ */

/* 6-byte `movl $1,(%eax)' + ret: *(volatile int *)0 = 1 with eax = 0.
 * Fault eip = l4a_fault6 + 0, resume at l4a_fault6 + 6 (the ret). */
__asm__(
    ".text\n"
    ".globl l4a_fault6\n"
    ".type l4a_fault6,@function\n"
    "l4a_fault6:\n"
    ".byte 0xc7, 0x00, 0x01, 0x00, 0x00, 0x00\n" /* movl $1,(%eax) */
    ".byte 0xc3\n"                               /* ret            */
);

/* `idiv %ecx' with ecx = 0: divide error (#DE -> SIGFPE) on a 2-byte
 * insn; fault eip = l4a_div0 + 6, resume at l4a_div0 + 8 (the ret). */
__asm__(
    ".text\n"
    ".globl l4a_div0\n"
    ".type l4a_div0,@function\n"
    "l4a_div0:\n"
    ".byte 0x31, 0xc9\n"                         /* xor %ecx,%ecx */
    ".byte 0x31, 0xd2\n"                         /* xor %edx,%edx */
    ".byte 0x31, 0xc0\n"                         /* xor %eax,%eax */
    ".byte 0xf7, 0xf1\n"                         /* idiv %ecx     */
    ".byte 0xc3\n"                               /* ret           */
);

/* SA_RESTORER stub for the rt (SA_SIGINFO) path: the i386 kernel's
 * rt_sigreturn parses the rt_sigframe from esp-4 (glibc's restorer
 * shape — NO pop), so this is `mov $173,%eax; int $0x80'.  The
 * non-RT sigreturn(119) retcode (which does pop %eax first) lives in
 * the non-RT sigframe itself and is exercised by sub-test (1b). */
__asm__(
    ".text\n"
    ".globl l4a_restore_rt\n"
    ".type l4a_restore_rt,@function\n"
    "l4a_restore_rt:\n"
    ".byte 0xb8, 0xad, 0x00, 0x00, 0x00\n"       /* mov $173,%eax */
    ".byte 0xcd, 0x80\n"                         /* int $0x80     */
);

extern void l4a_fault6(void);
extern void l4a_div0(void);
extern void l4a_restore_rt(void);

/* clone(120) wrapper: i386 clone ABI takes flags/newsp/parent_tidptr/
 * tls/child_tidptr in ebx/ecx/edx/esi/edi; the child resumes on newsp
 * with all registers intact except eax = 0, so the entry fn travels in
 * ebp.  Child: call fn, exit(r).  Parent: return child tid. */
__asm__(
    ".text\n"
    ".globl l4a_clone\n"
    ".type l4a_clone,@function\n"
    "l4a_clone:\n"
    "    pushl %ebp\n"
    "    pushl %ebx\n"
    "    pushl %esi\n"
    "    pushl %edi\n"
    "    movl 40(%esp), %ebp\n"   /* arg6 fn: survives the syscall  */
    "    movl 20(%esp), %ebx\n"   /* arg1 flags                     */
    "    movl 24(%esp), %ecx\n"   /* arg2 newsp                     */
    "    movl 28(%esp), %edx\n"   /* arg3 parent_tidptr             */
    "    movl 32(%esp), %esi\n"   /* arg4 tls (user_desc *)         */
    "    movl 36(%esp), %edi\n"   /* arg5 child_tidptr              */
    "    movl $120, %eax\n"       /* __NR_clone                     */
    "    int $0x80\n"
    "    testl %eax, %eax\n"
    "    jnz 2f\n"
    /* child: esp = newsp */
    "    call *%ebp\n"
    "    movl %eax, %ebx\n"       /* exit code = fn() result        */
    "    movl $1, %eax\n"         /* __NR_exit (thread exit)        */
    "    int $0x80\n"
    "1:  jmp 1b\n"                /* not reached                    */
    "2:  popl %edi\n"             /* parent                         */
    "    popl %esi\n"
    "    popl %ebx\n"
    "    popl %ebp\n"
    "    ret\n"
);

extern long l4a_clone(u32 flags, void *newsp, void *parent_tidptr,
                      void *tls, void *child_tidptr, void (*fn)(void));

static void trigger_null_store(void)
{
    __asm__ volatile (
        "xorl %%eax, %%eax\n\t"
        "call *%0\n\t"
        :
        : "r"((u32)l4a_fault6)
        : "eax", "cc", "memory");
}

static void trigger_div0(void)
{
    __asm__ volatile (
        "call *%0\n\t"
        :
        : "r"((u32)l4a_div0)
        : "eax", "ecx", "edx", "cc", "memory");
}

/* ------------------------------------------------------------------ */
/* shared state (.data, shared with the CLONE_VM child)                */
/* ------------------------------------------------------------------ */

static u32 g_segv_sig, g_segv_code, g_segv_addr;
static u32 g_segv_eip, g_segv_cr2, g_segv_trapno;
static u32 g_segv2_sig, g_segv2_eip, g_segv2_cr2;
static u32 g_fpe_sig, g_fpe_code, g_fpe_eip, g_fpe_trapno;

static u32 g_tls[16];            /* the child's TLS block (GS base)  */
static u32 g_child_gs0, g_child_gs8, g_child_ran;
static u32 g_parent_tid;
static volatile u32 g_child_tid;

static u8 g_child_stack[0x4000] __attribute__((aligned(16)));

#define TLS_MAGIC0 0x544c5300u   /* "TLS\0" */
#define TLS_MAGIC8 0x0badc0deu
#define CHILD_TID_PRE 0x9abcdef0u /* nonzero pre-clone cleartid value */

/* ------------------------------------------------------------------ */
/* signal handlers                                                     */
/* ------------------------------------------------------------------ */

/* (1a) SA_SIGINFO SIGSEGV: verify sigcontext/siginfo through the args,
 * fix nothing, recover by advancing uc_mcontext.eip past the 6-byte
 * store, return through the SA_RESTORER stub -> rt_sigreturn(173). */
static void segv_rt_handler(int sig, struct siginfo_x *info,
                            struct ucontext_x *uc)
{
    g_segv_sig = (u32)sig;
    g_segv_code = (u32)info->si_code;
    g_segv_addr = info->si_addr;
    g_segv_eip = uc->uc_mcontext.eip;
    g_segv_cr2 = uc->uc_mcontext.cr2;
    g_segv_trapno = uc->uc_mcontext.trapno;
    uc->uc_mcontext.eip += 6u;
}

/* (1b) non-RT minimal handler(int sig): the non-RT sigframe doubles as
 * the handler's arg area — [esp]=pretcode (-> the frame's own
 * `pop %eax; mov $119,%eax; int $0x80' retcode), [esp+4]=sig,
 * [esp+8]=sigcontext — so the context sits at &sig + 4. */
static void segv_plain_handler(int sig)
{
    struct sc_x *sc = (struct sc_x *)((u8 *)&sig + 4u);

    g_segv2_sig = (u32)sig;
    g_segv2_eip = sc->eip;
    g_segv2_cr2 = sc->cr2;
    sc->eip += 6u;
}

/* (2) SA_SIGINFO SIGFPE from `idiv %ecx', ecx=0: record, define the
 * unwritten idiv outputs, skip the 2-byte idiv, sigreturn, continue. */
static void fpe_handler(int sig, struct siginfo_x *info,
                        struct ucontext_x *uc)
{
    g_fpe_sig = (u32)sig;
    g_fpe_code = (u32)info->si_code;
    g_fpe_eip = uc->uc_mcontext.eip;
    g_fpe_trapno = uc->uc_mcontext.trapno;
    uc->uc_mcontext.eax = 0u;
    uc->uc_mcontext.edx = 0u;
    uc->uc_mcontext.eip += 2u;
}

/* (3) child thread: write/read its TLS block through GS (base = g_tls
 * via the CLONE_SETTLS user_desc), publish through shared memory, wake
 * the parent on child_tidptr, then exit (CHILD_CLEARTID clears + wakes
 * again). */
static void l4a_child(void)
{
    u32 v0, v8;

    __asm__ volatile ("movl %0, %%gs:0" : : "r"(TLS_MAGIC0) : "memory");
    __asm__ volatile ("movl %0, %%gs:8" : : "r"(TLS_MAGIC8) : "memory");
    __asm__ volatile ("movl %%gs:0, %k0" : "=r"(v0));
    __asm__ volatile ("movl %%gs:8, %k0" : "=r"(v8));
    g_child_gs0 = v0;
    g_child_gs8 = v8;
    g_child_ran = 1u;
    (void)sys_futex(&g_child_tid, FUTEX_WAKE_, 1u);
}

/* ------------------------------------------------------------------ */
/* body                                                                */
/* ------------------------------------------------------------------ */

static void run_tests(void)
{
    /* ---------------- (1a) SIGSEGV, SA_SIGINFO + SA_RESTORER ------ */
    {
        struct sa_x sa;

        sa.handler = (u32)segv_rt_handler;
        sa.flags = SA_SIGINFO_ | SA_RESTORER_;
        sa.restorer = (u32)l4a_restore_rt;
        sa.mask[0] = 0u;
        sa.mask[1] = 0u;
        TEST("sigact_segv_rt", sys_rt_sigaction(11, &sa, 0), 0u);

        trigger_null_store(); /* faults into segv_rt_handler */

        TEST("segv_rt_sig", g_segv_sig, 11u);
        TEST("segv_rt_code", g_segv_code, 1u);   /* SEGV_MAPERR */
        TEST("segv_rt_addr", g_segv_addr, 0u);   /* the null page */
        TEST("segv_rt_eip", g_segv_eip, (u32)l4a_fault6);
        TEST("segv_rt_cr2", g_segv_cr2, 0u);
        /* trapno: the real i386 kernel (and i686rt's frozen delivery,
         * signals_i386.c) fills 14 (#PF); the qemu-user oracle raises
         * guest SIGSEGV from a host fault and reports -1 — both are
         * accepted, garbage is not (same policy as the p1 cpuid
         * vendor check). */
        TEST("segv_rt_trapno",
             (g_segv_trapno == 14u || g_segv_trapno == 0xffffffffu), 1u);
        /* reaching here at all means the eip-advance + rt_sigreturn
         * recovery resumed after the faulting insn; flag it explicitly */
        TEST("segv_rt_cont", 1u, 1u);
    }

    /* ---------------- (1b) SIGSEGV, non-RT frame retcode ----------- */
    {
        struct sa_x sa;

        sa.handler = (u32)segv_plain_handler;
        sa.flags = 0u; /* no SA_SIGINFO, no SA_RESTORER: the frame's
                        * embedded `pop %eax; mov $119,%eax; int $0x80'
                        * retcode is the return path */
        sa.restorer = 0u;
        sa.mask[0] = 0u;
        sa.mask[1] = 0u;
        TEST("sigact_segv_plain", sys_rt_sigaction(11, &sa, 0), 0u);

        trigger_null_store();

        TEST("segv_plain_sig", g_segv2_sig, 11u);
        TEST("segv_plain_eip", g_segv2_eip, (u32)l4a_fault6);
        TEST("segv_plain_cr2", g_segv2_cr2, 0u);
        TEST("segv_plain_cont", 1u, 1u);
    }

    /* ---------------- (2) SIGFPE via idiv 0 ------------------------ */
    {
        struct sa_x sa;

        sa.handler = (u32)fpe_handler;
        sa.flags = SA_SIGINFO_ | SA_RESTORER_;
        sa.restorer = (u32)l4a_restore_rt;
        sa.mask[0] = 0u;
        sa.mask[1] = 0u;
        TEST("sigact_fpe", sys_rt_sigaction(8, &sa, 0), 0u);

        trigger_div0();

        TEST("fpe_sig", g_fpe_sig, 8u);
        TEST("fpe_code", g_fpe_code, 1u);       /* FPE_INTDIV */
        TEST("fpe_eip", g_fpe_eip, (u32)l4a_div0 + 6u);
        /* trapno: real kernel fills 0 (#DE); the qemu-user oracle
         * reports -1 (see the SIGSEGV trapno note above). */
        TEST("fpe_trapno",
             (g_fpe_trapno == 0u || g_fpe_trapno == 0xffffffffu), 1u);
        TEST("fpe_cont", 1u, 1u);
    }

    /* ---------------- (3) clone CLONE_THREAD|CLONE_SETTLS ---------- */
    {
        struct user_desc_x ud;
        u32 newsp, sel;
        long r;
        u32 spin;

        /* reset SIGSEGV/SIGFPE to default so a later crash is loud */
        {
            struct sa_x dfl;
            dfl.handler = 0u; /* SIG_DFL */
            dfl.flags = 0u;
            dfl.restorer = 0u;
            dfl.mask[0] = 0u;
            dfl.mask[1] = 0u;
            (void)sys_rt_sigaction(11, &dfl, 0);
            (void)sys_rt_sigaction(8, &dfl, 0);
        }

        g_child_tid = CHILD_TID_PRE;
        g_parent_tid = 0u;
        g_child_ran = 0u;
        g_child_gs0 = 0u;
        g_child_gs8 = 0u;
        g_tls[0] = 0u;
        g_tls[2] = 0u;

        /* Establish the process TLS slot the way pthread libs do:
         * set_thread_area with entry_number -1 auto-allocates one of
         * the i386 GDT TLS entries (6..8) and writes the index back;
         * load GS with (entry << 3) | 3.  CLONE_SETTLS then installs
         * the child's descriptor under the same process-wide selector
         * index (the child inherits the GS selector; the descriptor
         * content is per-thread). */
        ud.entry_number = 0xFFFFFFFFu; /* -1: kernel auto-allocates */
        ud.base_addr = (u32)g_tls;
        ud.limit = 0xFFFFFu;
        ud.flags = (1u << 0) /* seg_32bit */ |
                   (1u << 4) /* limit_in_pages */ |
                   (1u << 6) /* useable */;
        TEST("set_thread_area", sys_set_thread_area(&ud), 0u);
        TEST("sta_entry", (ud.entry_number >= 6u && ud.entry_number <= 8u),
             1u);
        sel = (ud.entry_number << 3) | 3u;
        __asm__ volatile ("movw %w0, %%gs" : : "r"(sel) : "memory");
        /* parent-side sanity: a GS write lands in the static block */
        __asm__ volatile ("movl %0, %%gs:0" : : "r"(0x70707070u) : "memory");
        TEST("sta_gs0_lin", g_tls[0], 0x70707070u);

        newsp = (u32)(g_child_stack + sizeof g_child_stack);

        r = l4a_clone(CLONE_VM_ | CLONE_FS_ | CLONE_FILES_ |
                          CLONE_SIGHAND_ | CLONE_THREAD_ |
                          CLONE_SYSVSEM_ | CLONE_SETTLS_ |
                          CLONE_PARENT_SETTID_ | CLONE_CHILD_CLEARTID_,
                      (void *)newsp,
                      (void *)&g_parent_tid,
                      (void *)&ud,
                      (void *)&g_child_tid, l4a_child);
        TEST("clone_tid", r > 0, 1);
        TEST("clone_ptid", g_parent_tid, (u32)r);

        /* The child FUTEX_WAKEs child_tidptr and CHILD_CLEARTID clears
         * it to 0 (with another wake) at thread exit; wait until the
         * value changes.  Bounded spin: the kernel guarantees the
         * clear, the cap keeps a non-cleartid engine from hanging. */
        for (spin = 0u;; spin++) {
            if (g_child_tid == 0u) {
                break;
            }
            (void)sys_futex(&g_child_tid, FUTEX_WAIT_, CHILD_TID_PRE);
            if (g_child_tid == 0u || spin >= 2000000u) {
                break;
            }
        }

        TEST("clone_cleartid", g_child_tid, 0u);
        TEST("clone_ran", g_child_ran, 1u);
        TEST("clone_gs0", g_child_gs0, TLS_MAGIC0); /* GS read-back */
        TEST("clone_gs8", g_child_gs8, TLS_MAGIC8);
        TEST("clone_tls0", g_tls[0], TLS_MAGIC0); /* linear view of the
                                                   * same TLS block */
        TEST("clone_tls8", g_tls[2], TLS_MAGIC8);
    }

    /* ---------------- (4) fork + wait4 ----------------------------- */
    {
        long r;
        u32 st = 0xDEADBEEFu;

        r = sys_fork();
        if (r == 0) {
            sys_exit(42); /* child */
        }
        TEST("fork_pid", r > 0, 1);
        TEST("wait4_pid", sys_wait4((int)r, &st, 0), (u32)r);
        TEST("wait4_wifexited", st & 0x7fu, 0u);
        TEST("wait4_status", (st >> 8) & 0xffu, 42u);
    }
}

__attribute__((noreturn))
void _start(void)
{
    run_tests();
    put("PASS\n", 5);
    sys_exit(0);
}
