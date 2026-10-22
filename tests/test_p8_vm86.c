/*
 * tests/test_p8_vm86.c — freestanding i386 Phase 8 vm86 self-test (card L8a)
 *
 * A no-libc, no-headers i386 static ELF (own _start, raw int $0x80,
 * fixed-width typedefs) exercising the vm86(166)/vm86old(113) contract
 * against the kernel ABI pins (E10, docs/lanes/phase-8.md freeze,
 * src/interp/v86.c + src/os/vm86.c):
 *
 *   (0) plain mmap(90) MAP_FIXED brings in the real-mode page
 *       [0x17000, 0x18000) of the v86 low megabyte (implemented by the
 *       existing L2e old_mmap path, src/os/sys_misc.c).
 *   (1) vm86old(113) + vm86(166, VM86_ENTER) with int 0x10 revectored:
 *       the real-mode stub at 0x1000:0x7c00 sets AX/BX/CX, then
 *       `int 0x10` -> cannot_handle -> return == VM86_INTx(0x10)
 *       (raw 0x1002) with IP PAST the int (0x7c0a), regs as set by the
 *       stub, eflags sanitized ((x & 0xDD5) == 0, VM|IF|bit1 kept),
 *       screen_bitmap preserved, __null_ds/orig_eax untouched.
 *   (2) vm86(166) IVT vectoring: the stub installs an IVT entry for
 *       int 0x21 (ds:0x84), executes `int 0x21`; the kernel do_int
 *       protocol vectors in-guest and pushes flags/cs/ip with IP past
 *       the int (0x7211); the handler copies the pushed frame plus DX
 *       (regs preserved through vectoring) to a mailbox, iret's back,
 *       the stub marks continuation, and a final revectored `int 0x10`
 *       exits VM86_INTx(0x10) again.
 *   (3) vm86(166) VM86_SIGNAL on a faulting opcode (ud2 at
 *       0x1000:0x7d00): the syscall returns VM86_SIGNAL (0) with the
 *       32-bit SIGILL pending; the guest SIGILL handler installed with
 *       SA_SIGINFO|SA_RESTORER observes the delivery.
 *   (4) vm86(166) pins: VM86_PLUS_INSTALL_CHECK -> 0;
 *       REQUEST_IRQ -> -ENOSYS; FREE_IRQ/GET_IRQ_BITS/GET_AND_RESET_IRQ
 *       -> -EINVAL.
 *
 * Segment note: the stub lives at 0x1000:0x7c00 (linear 0x17c00) so the
 * fixture stays window-base-agnostic: under a zero-base guest window the
 * host range [0, 0x8000) is unmappable (mmap_min_addr), so linear
 * 0x7c00 is only fixture-reachable in offset mode.  0x17c00 is inside
 * the always-shared window part [0x10000, 0x100000) of the v86 megabyte
 * and exercises the identical seg<<4+off rule.
 *
 * Build + oracle (must print PASS):
 *   tools/build_fixture.sh tests/test_p8_vm86.c _build/test_p8_vm86
 * Acceptance (RC8 stand-in, arm64 docker):
 *   timeout 60 /w/i686rt -- /w/test_p8_vm86
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

/* i386 ILP32: fixed-width types; no headers included. */
typedef unsigned char  u8;
typedef unsigned short u16;
typedef unsigned int   u32;
typedef int            s32;

/* ------------------------------------------------------------------ */
/* raw int 0x80 syscalls (i386: args in ebx, ecx, edx, esi, edi)       */
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

/* [90] {"mmap"}: plain mmap, v86 low-megabyte domain (src/os/vm86.c).
 * struct mmap_arg_struct { u32 addr, len, prot, flags, fd, offset; }. */
static long sys_mmap90(void *args)
{
    long r;
    __asm__ volatile ("int $0x80" : "=a"(r) : "a"(90L), "b"(args) : "memory");
    return r;
}

/* [113] {"vm86old"}: EBX = struct vm86_struct *. */
static long sys_vm86old(void *v86)
{
    long r;
    __asm__ volatile ("int $0x80" : "=a"(r) : "a"(113L), "b"(v86) : "memory");
    return r;
}

/* [166] {"vm86"}: EBX = cmd, ECX = arg. */
static long sys_vm86(long cmd, void *arg)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(166L), "b"(cmd), "c"(arg)
                      : "memory");
    return r;
}

static long sys_rt_sigaction(int sig, const void *act, void *oact)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(174L), "b"((long)sig), "c"(act), "d"(oact),
                        "S"(8L) /* sigsetsize = 8 on i386 */
                      : "memory");
    return r;
}

/* ------------------------------------------------------------------ */
/* print helpers + TEST(): mismatch prints FAIL and exits 1            */
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
/* kernel-exact vm86 ABI mirrors (uapi asm/vm86.h, i386 long = u32)    */
/* ------------------------------------------------------------------ */

/* u16 segment fields are accessed as their u32 (seg + pad-half) pair:
 * the i686rt Phase-1 decoder sizes a 66-prefixed moffs (66 a1/a3) by
 * operand instead of address size, so plain u16 global/struct stores
 * would hit the wrong address.  Wide accesses are ABI-identical (the
 * pad half stays 0). */
struct vm86_regs_x {          /* 84 B */
    u32 ebx, ecx, edx, esi, edi, ebp, eax;      /* 0x00 */
    u32 null_ds, null_es, null_fs, null_gs;     /* 0x1c */
    u32 orig_eax;                               /* 0x2c */
    u32 eip;                                    /* 0x30 */
    u32 cs_wide;                                /* 0x34 cs | __csh */
    u32 eflags;                                 /* 0x38 */
    u32 esp;                                    /* 0x3c */
    u32 ss_wide;                                /* 0x40 ss | __ssh */
    u32 es_wide, ds_wide, fs_wide, gs_wide;     /* 0x44 */
} __attribute__((packed));

struct revectored_x {         /* 32 B: 256 bits */
    u32 map[8];
} __attribute__((packed));

struct vm86_struct_x {        /* 160 B */
    struct vm86_regs_x regs;          /* 0x00 */
    u32 flags;                        /* 0x54 */
    u32 screen_bitmap;                /* 0x58 */
    u32 cpu_type;                     /* 0x5c */
    struct revectored_x int_revectored;   /* 0x60 */
    struct revectored_x int21_revectored; /* 0x80 */
} __attribute__((packed));

struct vm86plus_info_x {      /* 36 B: 4-byte bitfield + 32-byte tab */
    u32 bits;                 /* bit0 force_return_for_pic, bit1 active,
                               * bit2 TFpendig, bit31 is_vm86pus */
    u8  intxxtab[32];         /* 0x24 */
} __attribute__((packed));

struct vm86plus_struct_x {    /* 196 B */
    struct vm86_struct_x v;             /* 0x000 */
    struct vm86plus_info_x plus;        /* 0x0a0 */
} __attribute__((packed));

struct mmap_arg_x {           /* 24 B */
    u32 addr, len, prot, flags, fd, offset;
} __attribute__((packed));

struct sigaction_x {          /* kernel i386 sigaction, 20 B */
    u32 handler;
    u32 flags;
    u32 restorer;
    u32 mask[2];
} __attribute__((packed));

#define VM86_SIGNAL 0
#define VM86_INTX   2
#define VM86_ARG(r) ((r) >> 8)
#define VM86_TYPE(r) ((r) & 0xffu)

#define VM86_INSTALL_CHECK    0L
#define VM86_ENTER            1L
#define VM86_ENTER_NO_BYPASS  2L
#define VM86_REQUEST_IRQ      3L
#define VM86_FREE_IRQ         4L
#define VM86_GET_IRQ_BITS     5L
#define VM86_GET_AND_RESET_IRQ 6L

#define MAP_PRIVATE_  0x02u
#define MAP_FIXED_    0x10u
#define MAP_ANON_     0x20u
#define PROT_RW       0x03u

#define SA_SIGINFO_  0x00000004u
#define SA_RESTORER_ 0x04000000u

#define ENOSYS_ 38u
#define EINVAL_ 22u

_Static_assert(sizeof(struct vm86_struct_x) == 160u, "vm86_struct 160 B");
_Static_assert(sizeof(struct vm86plus_struct_x) == 196u, "vm86plus 196 B");
_Static_assert(sizeof(struct vm86_regs_x) == 84u, "vm86_regs 84 B");
_Static_assert(sizeof(u32) == 4u, "i386 build expected");
_Static_assert(sizeof(void *) == 4u, "i386 build expected");

/* ------------------------------------------------------------------ */
/* real-mode page layout (mmap90 MAP_FIXED [0x17000, 0x18000))         */
/*   linear 0x17000 mailbox        0x17100 int21 handler               */
/*   linear 0x17200 stub2          0x17c00 stub1   0x17d00 stub3        */
/* entered as seg 0x1000: ip (linear = 0x10000 + ip)                   */
/* ------------------------------------------------------------------ */

#define RM_SEG         0x1000u
#define MAILBOX_LIN    0x17000u /* linear 0x17000 == seg RM_SEG:0x7000 */
#define RM_PAGE_BASE_IP 0x7000u
#define HANDLER_IP  0x7100u
#define STUB2_IP    0x7200u
#define STUB1_IP    0x7c00u
#define STUB3_IP    0x7d00u

static volatile u32 *g_mail = (volatile u32 *)MAILBOX_LIN;

/* stub1 at 0x1000:0x7c00 (linear 0x17c00): mov ax; mov bx; mov cx, ax;
 * int 0x10 (revectored); hlt pad.  IP past the int = 0x7c0a. */
static const u8 g_stub1[] = {
    0xb8, 0x34, 0x12,              /* mov ax, 0x1234 */
    0xbb, 0x78, 0x56,              /* mov bx, 0x5678 */
    0x89, 0xc1,                    /* mov cx, ax */
    0xcd, 0x10,                    /* int 0x10 */
    0xf4,                          /* hlt (not reached) */
};

/* int 0x21 handler at 0x1000:0x7100: copy the pushed frame ([sp]=ip,
 * [sp+2]=cs, [sp+4]=flags) plus DX to the mailbox (es:[0x7000..]), iret. */
static const u8 g_handler21[] = {
    0x89, 0xe5,                    /* mov bp, sp */
    0x8b, 0x46, 0x00,              /* mov ax, [bp+0]  ; pushed ip   */
    0x26, 0x89, 0x06, 0x00, 0x70,  /* mov es:[0x7000], ax */
    0x8b, 0x46, 0x02,              /* mov ax, [bp+2]  ; pushed cs   */
    0x26, 0x89, 0x06, 0x02, 0x70,  /* mov es:[0x7002], ax */
    0x8b, 0x46, 0x04,              /* mov ax, [bp+4]  ; pushed flags */
    0x26, 0x89, 0x06, 0x04, 0x70,  /* mov es:[0x7004], ax */
    0x8b, 0xc2,                    /* mov ax, dx      ; regs survive vectoring */
    0x26, 0x89, 0x06, 0x06, 0x70,  /* mov es:[0x7006], ax */
    0xcf,                          /* iret */
};

/* stub2 at 0x1000:0x7200: install the IVT entry for int 0x21 (ds:0x84),
 * set DX, int 0x21 (vectored; handler runs + irets), mark continuation,
 * int 0x10 (revectored) exits. */
static const u8 g_stub2[] = {
    0xc7, 0x06, 0x84, 0x00, 0x00, 0x71,       /* mov word [0x84], 0x7100 */
    0xc7, 0x06, 0x86, 0x00, 0x00, 0x10,       /* mov word [0x86], 0x1000 */
    0xba, 0xef, 0xbe,                         /* mov dx, 0xbeef */
    0xcd, 0x21,                               /* int 0x21 (vectored) */
    0x26, 0xc7, 0x06, 0x08, 0x70, 0x47, 0x47, /* mov word es:[0x7008],0x4747 */
    0xcd, 0x10,                               /* int 0x10 -> VM86_INTx(0x10) */
    0xf4,                                     /* hlt (not reached) */
};

/* stub3 at 0x1000:0x7d00: ud2 -> v86 opcode fault -> VM86_SIGNAL with
 * the 32-bit SIGILL pending. */
static const u8 g_stub3[] = {
    0x0f, 0x0b,                    /* ud2 */
    0xf4,                          /* hlt (not reached) */
};

/* SA_RESTORER stub for the rt path: mov $173,%eax; int $0x80. */
__asm__(
    ".text\n"
    ".globl l8a_restore_rt\n"
    ".type l8a_restore_rt,@function\n"
    "l8a_restore_rt:\n"
    ".byte 0xb8, 0xad, 0x00, 0x00, 0x00\n"
    ".byte 0xcd, 0x80\n"
);
extern void l8a_restore_rt(void);

static u32 g_sigill_ran, g_sigill_sig;

/* SIGILL delivery after the VM86_SIGNAL return (SA_SIGINFO). */
static void l8a_sigill_handler(int sig, void *info, void *uc)
{
    (void)info;
    (void)uc;
    g_sigill_sig = (u32)sig;
    g_sigill_ran = 1u;
}

/* ------------------------------------------------------------------ */
/* vm86_struct fill + run helpers                                      */
/* ------------------------------------------------------------------ */

#define GARBAGE_A 0xdeadc0deu /* __null_ds / __null_gs sentinel */
#define GARBAGE_B 0xfeedfaceu /* orig_eax sentinel (not written on exit) */

static void fill_vm86(struct vm86plus_struct_x *v, u32 ip)
{
    u32 i;
    for (i = 0U; i < sizeof(*v) / 4U; i++) {
        ((volatile u32 *)v)[i] = 0U;
    }
    v->v.regs.eip = ip;
    v->v.regs.cs_wide = RM_SEG;
    v->v.regs.esp = 0xff00u;
    v->v.regs.ss_wide = 0u;
    v->v.regs.es_wide = RM_SEG; /* mailbox overrides use es */
    /* IF + reserved bit 1 + VIF (0x80000): v86 guests run with the
     * virtual IF set; get_vflags maps VIF -> the pushed frames' IF. */
    v->v.regs.eflags = 0x80202u;
    v->v.regs.null_ds = GARBAGE_A;
    v->v.regs.null_gs = GARBAGE_A;
    v->v.regs.orig_eax = GARBAGE_B;
    v->v.flags = 0u;
    v->v.screen_bitmap = 0xdeadbeefu; /* must be preserved on exit */
    v->v.cpu_type = 5u;               /* 586: full veflags mask */
    v->v.int_revectored.map[0x10u >> 5] = 1u << (0x10u & 31u);
    /* int21_revectored stays empty: AH = 0 is not revectored. */
}

static void run_rm(const u8 *code, u32 len, u32 ip)
{
    u8 *dst = (u8 *)(MAILBOX_LIN + (ip - RM_PAGE_BASE_IP));
    u32 i;
    for (i = 0U; i < len; i++) {
        dst[i] = code[i];
    }
}

/* ------------------------------------------------------------------ */
/* body                                                                */
/* ------------------------------------------------------------------ */

static void run_tests(void)
{
    static struct vm86plus_struct_x vms;
    static struct vm86_struct_x vold;
    static struct mmap_arg_x margs;
    long r;
    u32 i;

    /* ---------------- (0) plain mmap(90), v86 domain ---------------- */
    margs.addr = MAILBOX_LIN;
    margs.len = 0x1000u;
    margs.prot = PROT_RW;
    margs.flags = MAP_PRIVATE_ | MAP_FIXED_ | MAP_ANON_;
    margs.fd = 0xffffffffu;
    margs.offset = 0u;
    TEST("mmap90", (u32)sys_mmap90(&margs), MAILBOX_LIN);

    for (i = 0U; i < 16U; i++) {
        g_mail[i] = 0u;
    }

    /* ---------------- (1) vm86old + vm86: revectored int 0x10 ------- */
    fill_vm86(&vms, STUB1_IP);
    run_rm(g_stub1, (u32)sizeof(g_stub1), STUB1_IP);

    /* vm86old(113) over the same page and entry state. */
    for (i = 0U; i < sizeof(vold) / 4U; i++) {
        ((volatile u32 *)&vold)[i] = ((volatile u32 *)&vms)[i];
    }
    r = sys_vm86old(&vold);
    TEST("vm86old_int10", (u32)r, VM86_INTX | (0x10u << 8));
    TEST("vm86old_ax", vold.regs.eax & 0xffffu, 0x1234u);
    TEST("vm86old_bx", vold.regs.ebx & 0xffffu, 0x5678u);
    TEST("vm86old_cx", vold.regs.ecx & 0xffffu, 0x1234u);
    TEST("vm86old_ip", vold.regs.eip, STUB1_IP + 10u); /* past `int 0x10` */
    TEST("vm86old_cs", vold.regs.cs_wide & 0xffffu, RM_SEG);
    TEST("vm86old_eflags_safe", vold.regs.eflags & 0xdd5u, 0u);
    TEST("vm86old_eflags_vmif", vold.regs.eflags & 0x20202u, 0x20202u);

    r = sys_vm86(VM86_ENTER, &vms);
    TEST("vm86_int10", (u32)r, VM86_INTX | (0x10u << 8));
    TEST("vm86_type", VM86_TYPE(r), 2u);
    TEST("vm86_arg", VM86_ARG(r), 0x10u);
    TEST("vm86_ax", vms.v.regs.eax & 0xffffu, 0x1234u);
    TEST("vm86_bx", vms.v.regs.ebx & 0xffffu, 0x5678u);
    TEST("vm86_cx", vms.v.regs.ecx & 0xffffu, 0x1234u);
    TEST("vm86_ip", vms.v.regs.eip, STUB1_IP + 10u);
    TEST("vm86_cs", vms.v.regs.cs_wide & 0xffffu, RM_SEG);
    /* eflags writeback is the RAW sanitized image: (0x80202 & 0xDD5)
     * | (pm & ~0xDD5) | VM = 0x2 | IF(0x200) | VM(0x20000) = 0x20202
     * (VIF/IOPL live in VEFLAGS, not here). */
    TEST("vm86_eflags_safe", vms.v.regs.eflags & 0xdd5u, 0u);
    TEST("vm86_eflags_vmif", vms.v.regs.eflags & 0x20202u, 0x20202u);
    /* screen_bitmap preserved; flags not written back. */
    TEST("vm86_screen_bitmap", vms.v.screen_bitmap, 0xdeadbeefu);
    TEST("vm86_flags_untouched", vms.v.flags, 0u);
    /* __null_* / orig_eax ignored on entry AND not written on exit. */
    TEST("vm86_null_ds", vms.v.regs.null_ds, GARBAGE_A);
    TEST("vm86_null_gs", vms.v.regs.null_gs, GARBAGE_A);
    TEST("vm86_orig_eax", vms.v.regs.orig_eax, GARBAGE_B);

    /* NO_BYPASS behaves like VM86_ENTER (kernel treats both as plus). */
    fill_vm86(&vms, STUB1_IP);
    run_rm(g_stub1, (u32)sizeof(g_stub1), STUB1_IP);
    TEST("vm86_nobypass", (u32)sys_vm86(VM86_ENTER_NO_BYPASS, &vms),
         VM86_INTX | (0x10u << 8));

    /* ---------------- (2) vm86: IVT vectoring + iret ---------------- */
    fill_vm86(&vms, STUB2_IP);
    run_rm(g_stub2, (u32)sizeof(g_stub2), STUB2_IP);
    run_rm(g_handler21, (u32)sizeof(g_handler21), HANDLER_IP);
    r = sys_vm86(VM86_ENTER, &vms);
    TEST("vm86_vec_exit", (u32)r, VM86_INTX | (0x10u << 8));
    /* Pushed IVT frame, copied by the in-guest handler as 16-bit words
     * at mailbox +0/+2/+4/+6 (ip, cs, flags, dx) and +8 (marker):
     * flags = the RETURN_MASK view with IOPL forced 3 (0x202 | 0x3000
     * = 0x3202); cs = 0x1000; ip PAST the `int 0x21` at 0x720f. */
    TEST("vec_pushed_ip", g_mail[0] & 0xffffu, STUB2_IP + 17u);
    TEST("vec_pushed_cs", g_mail[0] >> 16, RM_SEG);
    TEST("vec_pushed_flags", g_mail[1] & 0xffffu, 0x3202u);
    TEST("vec_dx", g_mail[1] >> 16, 0xbeefu);
    TEST("vec_iret_continued", g_mail[2] & 0xffffu, 0x4747u);
    TEST("vec_final_ip", vms.v.regs.eip, STUB2_IP + 26u);
    TEST("vec_final_cs", vms.v.regs.cs_wide & 0xffffu, RM_SEG);

    /* ---------------- (3) vm86: VM86_SIGNAL on a faulting opcode ---- */
    {
        struct sigaction_x sa;

        g_sigill_ran = 0u;
        g_sigill_sig = 0u;
        sa.handler = (u32)l8a_sigill_handler;
        sa.flags = SA_SIGINFO_ | SA_RESTORER_;
        sa.restorer = (u32)l8a_restore_rt;
        sa.mask[0] = 0u;
        sa.mask[1] = 0u;
        TEST("sigact_sigill", sys_rt_sigaction(4, &sa, 0), 0u);

        fill_vm86(&vms, STUB3_IP);
        run_rm(g_stub3, (u32)sizeof(g_stub3), STUB3_IP);
        r = sys_vm86(VM86_ENTER, &vms);
        TEST("vm86_signal", (u32)r, VM86_SIGNAL); /* 0: signal pending */
        /* The pending SIGILL was delivered to this (32-bit) context. */
        TEST("vm86_signal_delivered", g_sigill_ran, 1u);
        TEST("vm86_signal_sig", g_sigill_sig, 4u);
    }

    /* ---------------- (4) vm86 command pins ------------------------- */
    TEST("vm86_install_check", (u32)sys_vm86(VM86_INSTALL_CHECK, (void *)0xdeadbeefu), 0u);
    TEST("vm86_request_irq", (u32)sys_vm86(VM86_REQUEST_IRQ, (void *)3L),
         0u - ENOSYS_);
    TEST("vm86_free_irq", (u32)sys_vm86(VM86_FREE_IRQ, (void *)3L),
         0u - EINVAL_);
    TEST("vm86_get_irq_bits", (u32)sys_vm86(VM86_GET_IRQ_BITS, (void *)3L),
         0u - EINVAL_);
    TEST("vm86_get_and_reset_irq",
         (u32)sys_vm86(VM86_GET_AND_RESET_IRQ, (void *)3L), 0u - EINVAL_);
}

__attribute__((noreturn))
void _start(void)
{
    run_tests();
    put("PASS\n", 5);
    sys_exit(0);
}
