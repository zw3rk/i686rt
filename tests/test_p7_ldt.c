/*
 * tests/test_p7_ldt.c — freestanding i386 Phase 7 LDT self-test
 * (docs/lanes/phase-7.md, card L7a; SPEC §4 7.2, D8, E09 verdict)
 *
 * A no-libc, no-headers i386 static ELF (own _start, raw int $0x80,
 * fixed-width typedefs) exercising the Phase 7 descriptor model:
 *
 *   (1) modify_ldt(123) func 0x11 installs four descriptors: a 32-bit
 *       RW data segment over a static buffer (limit 0xFF bytes, the
 *       Wine TEB shape), a 32-bit RW data segment at 0xF0000000 (the
 *       guest mmap/stack ceiling, guaranteed unmapped above it, limit
 *       0xFFF), a 16-bit (D=0) readable non-conforming code segment
 *       over a built code buffer, and an all-zero not-present (free)
 *       entry.  Func 0 reads the data entry back and checks the base.
 *   (2) mov %fs/%es from the LDT data selectors; store/load through
 *       the %fs base lands in the static buffer (segment base added to
 *       the EA; limit honoured).
 *   (3) m16:16 far call (66 9A) into the 16-bit code segment and back:
 *       the callee proves 16-bit default execution (mov $0xffff,%ax;
 *       inc %ax wraps to 0), reconstructs the 32-bit return address
 *       (pop %bx / xor %ebx,%ebx / add hi16 / push %ebx) and returns
 *       through 66 CB — the 0x66 far-ret cross-size rule Wine's
 *       CallTo16 thunks depend on (E09 gap 4).  A thunk stores %ecx
 *       after the far return; the C caller checks the marker.
 *   (4) limit overrun: movl %es:0x1000, %ebx with limit 0xFFF raises
 *       #GP(0) — guest SIGSEGV with the handler observing si_code,
 *       si_addr == 0xF0001000 (exact cr2 from the faulting access),
 *       sigcontext eip at the faulting instruction and cs == 0x23,
 *       then skips the 7-byte instruction and resumes.
 *   (5) loading the not-present (free) selector raises #NP — guest
 *       SIGSEGV, resumable at the faulting mov (E09 gap 7).
 *   (6) set_thread_area(243) with entry_number -1 auto-allocates one
 *       of the GDT TLS entries 6..8, %gs is loaded with the returned
 *       selector and %gs:0 lands in the TLS block; get_thread_area(244)
 *       reads the same descriptor back.
 *
 * Fault-evidence policy (test_p4 precedent): trapno is accepted as 13
 * (architecturally correct #GP once the S7 delivery wiring preserves
 * the lane's exit_arg), 14 (the pre-S7 signals_i386.c delivery), or
 * -1 (oracle variance); si_code 1 is the lane's delivery contract for
 * GP-class faults.  The fixture targets i686rt delivery semantics.
 *
 * Oracle check (must print PASS under i686rt):
 *   ./i686rt -- ./test_p7_ldt        (RC7: engine=interp default)
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
/* raw int 0x80 syscalls                                               */
/* ------------------------------------------------------------------ */

static long sys_write(int fd, const void *buf, unsigned long len)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(4L), "b"((long)fd), "c"(buf), "d"(len)
                      : "memory");
    return r;
}

__attribute__((noreturn))
static void sys_exit(long code)
{
    __asm__ volatile ("int $0x80" : : "a"(1L), "b"(code));
    __builtin_unreachable();
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

static long sys_modify_ldt(int func, void *ptr, unsigned long bytecount)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(123L), "b"((long)func), "c"(ptr), "d"(bytecount)
                      : "memory");
    return r;
}

static long sys_set_thread_area(void *ud)
{
    long r;
    __asm__ volatile ("int $0x80" : "=a"(r) : "a"(243L), "b"(ud) : "memory");
    return r;
}

static long sys_get_thread_area(void *ud)
{
    long r;
    __asm__ volatile ("int $0x80" : "=a"(r) : "a"(244L), "b"(ud) : "memory");
    return r;
}

/* ------------------------------------------------------------------ */
/* print helpers + TEST (test_p4 pattern)                              */
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

struct sc_x {
    u16 gs, gsh, fs, fsh, es, esh, ds, dsh;      /* 0x00 */
    u32 edi, esi, ebp, esp, ebx, edx, ecx, eax;  /* 0x10 */
    u32 trapno, err, eip;                        /* 0x30 */
    u16 cs, csh;                                 /* 0x3c */
    u32 eflags, esp_at_signal;                   /* 0x40 */
    u16 ss, ssh;                                 /* 0x48 */
    u32 fpstate, oldmask, cr2;                   /* 0x4c,0x50,0x54 */
} __attribute__((packed));

struct ucontext_x {
    u32 uc_flags;                                /* 0  */
    u32 uc_link;                                 /* 4  */
    u32 ss_sp, ss_flags, ss_size;                /* 8  */
    struct sc_x uc_mcontext;                     /* 20 */
    u32 uc_sigmask[2];                           /* 108 */
} __attribute__((packed));

struct siginfo_x {
    s32 si_signo;
    s32 si_errno;
    s32 si_code;
    u32 si_addr;
    u8 __pad[112];
} __attribute__((packed));

struct sa_x {
    u32 handler;
    u32 flags;
    u32 restorer;
    u32 mask[2];
} __attribute__((packed));

#define SA_SIGINFO_  0x00000004u
#define SA_RESTORER_ 0x04000000u

/* struct user_desc — 16 B; flags word: bit0 seg_32bit, bits1-2 contents,
 * bit3 read_exec_only, bit4 limit_in_pages, bit5 seg_not_present,
 * bit6 useable. */
struct user_desc_x {
    u32 entry_number;
    u32 base_addr;
    u32 limit;
    u32 flags;
} __attribute__((packed));

_Static_assert(sizeof(struct sc_x) == 88u, "sigcontext_32 must be 88 B");
_Static_assert(sizeof(struct ucontext_x) == 116u, "ucontext_32 must be 116 B");
_Static_assert(sizeof(struct sa_x) == 20u, "sigaction_32 must be 20 B");
_Static_assert(sizeof(struct user_desc_x) == 16u, "user_desc must be 16 B");
_Static_assert(sizeof(u32) == 4u, "i386 build expected");

/* LDT entries used (0..31 are reserved; E09 Wine policy). */
#define LDT_IDX_FS    0x40u
#define LDT_IDX_ES    0x41u
#define LDT_IDX_CS16  0x42u
#define LDT_IDX_NP    0x43u
#define LDT_SEL(idx)  ((u16)(((idx) << 3) | 7u))   /* TI=1, RPL 3 */

#define UD_32BIT      0x01u
#define UD_CONTENTS_C 0x04u               /* contents 2 (<<1): code non-conf */
#define UD_NOTPRESENT 0x20u
#define UD_USEABLE    0x40u

/* Guaranteed-unmapped guest VA: the i686rt mmap ceiling is 0xDF000000
 * and the stack tops out at 0xE0000000, so [0xE0000000, 0xFFFFE000) is
 * PROT_NONE reservation. */
#define LDT_ES_BASE   0xF0000000u

/* ------------------------------------------------------------------ */
/* exact-encoded guest blobs (addresses taken from C)                  */
/* ------------------------------------------------------------------ */

__asm__(
    ".text\n"
    /* void l7a_fs_store(u32 v): mov %eax, %fs:0 (7-byte store). */
    ".globl l7a_fs_store\n"
    ".type l7a_fs_store,@function\n"
    "l7a_fs_store:\n"
    "    movl 4(%esp), %eax\n"
    "    .byte 0x64, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00\n"
    "    ret\n"
    /* u32 l7a_fs_load(void): mov %fs:4, %eax. */
    ".globl l7a_fs_load\n"
    ".type l7a_fs_load,@function\n"
    "l7a_fs_load:\n"
    "    .byte 0x64, 0x8b, 0x05, 0x04, 0x00, 0x00, 0x00\n"
    "    ret\n"
    /* Limit overrun: mov %es:0x1000, %ebx (7 bytes) — faults #GP(0),
     * EIP at the blob start; the handler skips exactly 7. */
    ".globl l7a_es_overrun\n"
    ".type l7a_es_overrun,@function\n"
    "l7a_es_overrun:\n"
    "    .byte 0x26, 0x8b, 0x1d, 0x00, 0x10, 0x00, 0x00\n"
    "    ret\n"
    /* #NP load: mov $selNP,%ax (66 b8 iw); mov %ax,%fs — faults #NP at
     * +4; the handler skips 2. */
    ".globl l7a_np_load\n"
    ".type l7a_np_load,@function\n"
    "l7a_np_load:\n"
    "    .byte 0x66, 0xb8, 0x1f, 0x02\n"    /* mov $0x21f, %ax */
    "    .byte 0x8e, 0xe0\n"                /* mov %ax, %fs    */
    "    ret\n"
    /* SA_RESTORER stub: mov $173,%eax; int $0x80 (rt_sigreturn). */
    ".globl l7a_restore_rt\n"
    ".type l7a_restore_rt,@function\n"
    "l7a_restore_rt:\n"
    "    .byte 0xb8, 0xad, 0x00, 0x00, 0x00\n"
    "    .byte 0xcd, 0x80\n"
);

extern void l7a_fs_store(u32 v);
extern u32  l7a_fs_load(void);
extern void l7a_es_overrun(void);
extern void l7a_np_load(void);
extern void l7a_restore_rt(void);

/* ------------------------------------------------------------------ */
/* shared state                                                        */
/* ------------------------------------------------------------------ */

static u32 g_ldtdata[16];       /* %fs segment backing store */
static u32 g_tls[16];           /* %gs TLS block             */
static u32 g_cx_far;            /* far-call marker (thunk store) */

/* 16-bit code buffer (the LDT code descriptor points here; entry at
 * offset 0).  Layout (see build_callee16):
 *   0: b8 ff ff       mov $0xffff,%ax
 *   3: 40             inc %ax                (16-bit wrap -> 0)
 *   4: 75 08          jnz fail(+8)
 *   6: b9 34 12       mov $0x1234,%cx        (ok marker)
 *   9: eb 03          jmp commit(+3)
 *  11: b9 56 34       mov $0x3456,%cx        (fail marker)
 *  14: 66 31 db       xor %ebx,%ebx
 *  17: 5b             pop %bx                (return ip16; esp += 2)
 *  18: 66 81 c3 h32   add $hi32,%ebx         (rebuild the 32-bit return)
 *  25: 66 53          push %ebx              (4-byte return address)
 *  27: 66 cb          lret (32-bit)          (E09 gap 4 cross-size)   */
static u8 code16[64] __attribute__((aligned(16)));

/* 32-bit thunk: the m16:16 far call (6 bytes), then the far return
 * lands at +6:
 *   0: 66 9a 00 00 s16   lcall sel16:0x0000      (pushes cs16, ip16)
 *   6: 66 83 ec 02       sub $2,%esp             (absorb the stale cs slot)
 *  10: 89 0d <&marker>   mov %ecx,marker
 *  15: c3                ret                                             */
static u8 thunk32[24] __attribute__((aligned(16)));

/* fault evidence (one slot set, copied out after each trigger) */
static u32 g_sig, g_code, g_addr, g_eip, g_cr2, g_trapno, g_cs;
static u32 g_segv_skip;

static void segv_handler(int sig, struct siginfo_x *info,
                         struct ucontext_x *uc)
{
    g_sig = (u32)sig;
    g_code = (u32)info->si_code;
    g_addr = info->si_addr;
    g_eip = uc->uc_mcontext.eip;
    g_cr2 = uc->uc_mcontext.cr2;
    g_trapno = uc->uc_mcontext.trapno;
    g_cs = uc->uc_mcontext.cs;
    uc->uc_mcontext.eip += g_segv_skip; /* resume past the faulting insn */
}

/* ------------------------------------------------------------------ */
/* 16-bit callee + thunk builders                                      */
/* ------------------------------------------------------------------ */

static void store32(u8 *p, u32 v)
{
    p[0] = (u8)(v & 0xffu);
    p[1] = (u8)((v >> 8) & 0xffu);
    p[2] = (u8)((v >> 16) & 0xffu);
    p[3] = (u8)((v >> 24) & 0xffu);
}

static void build_callee16(u32 ret_addr)
{
    int i = 0;
    code16[i++] = 0xb8u; code16[i++] = 0xffu; code16[i++] = 0xffu;
    code16[i++] = 0x40u;
    code16[i++] = 0x75u; code16[i++] = 0x08u;
    code16[i++] = 0xb9u; code16[i++] = 0x34u; code16[i++] = 0x12u;
    code16[i++] = 0xebu; code16[i++] = 0x03u;
    code16[i++] = 0xb9u; code16[i++] = 0x56u; code16[i++] = 0x34u;
    code16[i++] = 0x66u; code16[i++] = 0x31u; code16[i++] = 0xdbu;
    code16[i++] = 0x5bu;
    code16[i++] = 0x66u; code16[i++] = 0x81u; code16[i++] = 0xc3u;
    store32(code16 + i, ret_addr & 0xFFFF0000u); i += 4; /* add hi16 */
    code16[i++] = 0x66u; code16[i++] = 0x53u;
    code16[i++] = 0x66u; code16[i++] = 0xcbu;
    while (i < 64) {
        code16[i++] = 0x90u; /*nop padding inside the descriptor limit */
    }
}

static void build_thunk(u16 sel16, u32 marker_va)
{
    thunk32[0] = 0x66u; thunk32[1] = 0x9au;
    thunk32[2] = 0x00u; thunk32[3] = 0x00u;           /* target offset 0 */
    thunk32[4] = (u8)(sel16 & 0xffu);
    thunk32[5] = (u8)(sel16 >> 8);                    /* lcall = 6 bytes */
    thunk32[6] = 0x66u; thunk32[7] = 0x83u; thunk32[8] = 0xecu;
    thunk32[9] = 0x02u;                               /* sub $2,%esp */
    thunk32[10] = 0x89u; thunk32[11] = 0x0du;         /* mov %ecx,(m32) */
    store32(thunk32 + 12, marker_va);
    thunk32[16] = 0xc3u; /* ret — thunk32 spans 17 bytes */
}

/* ------------------------------------------------------------------ */
/* body                                                                */
/* ------------------------------------------------------------------ */

static void run_tests(void)
{
    struct sa_x sa;
    struct user_desc_x ud;
    static u8 ldtbuf[0x48u * 8u]; /* func 0 readback: entries 0..0x47 */
    const u8 *fs_raw = ldtbuf + LDT_IDX_FS * 8u;
    u16 sel;

    /* ---------------- SIGSEGV handler (rt, SA_RESTORER) ----------- */
    sa.handler = (u32)segv_handler;
    sa.flags = SA_SIGINFO_ | SA_RESTORER_;
    sa.restorer = (u32)l7a_restore_rt;
    sa.mask[0] = 0u;
    sa.mask[1] = 0u;
    TEST("sigact_segv", sys_rt_sigaction(11, &sa, 0), 0u);

    /* ---------------- (1) LDT installs + func 0 read-back --------- */
    ud.entry_number = LDT_IDX_FS;
    ud.base_addr = (u32)g_ldtdata;
    ud.limit = 0xFFu;
    ud.flags = UD_32BIT;                        /* data RW, byte limit */
    TEST("ldt_fs", sys_modify_ldt(0x11, &ud, 16u), 0u);

    ud.entry_number = LDT_IDX_ES;
    ud.base_addr = LDT_ES_BASE;
    ud.limit = 0xFFFu;
    ud.flags = UD_32BIT;
    TEST("ldt_es", sys_modify_ldt(0x11, &ud, 16u), 0u);

    ud.entry_number = LDT_IDX_CS16;
    ud.base_addr = (u32)code16;
    ud.limit = 63u;
    ud.flags = UD_CONTENTS_C;                   /* 16-bit readable code */
    TEST("ldt_cs16", sys_modify_ldt(0x11, &ud, 16u), 0u);

    ud.entry_number = LDT_IDX_NP;
    ud.base_addr = 0u;
    ud.limit = 0u;
    ud.flags = UD_NOTPRESENT;                   /* the all-zero free entry */
    TEST("ldt_np", sys_modify_ldt(0x11, &ud, 16u), 0u);

    /* func 0 read: kernel reads from LDT entry 0; byte count capped by
     * the caller.  Check the FS entry's base (raw[2..4] | raw[7]<<24). */
    TEST("ldt_read_count",
         (sys_modify_ldt(0, ldtbuf, (u32)sizeof(ldtbuf)) ==
          (long)sizeof(ldtbuf)) ? 1u : 0u, 1u);
    TEST("ldt_read_base",
         (u32)fs_raw[2] | ((u32)fs_raw[3] << 8) | ((u32)fs_raw[4] << 16) |
         ((u32)fs_raw[7] << 24),
         (u32)g_ldtdata);

    /* ---------------- (2) %fs/%es loads + %fs-base access --------- */
    sel = LDT_SEL(LDT_IDX_FS);
    __asm__ volatile ("movw %w0, %%fs" : : "r"(sel) : "memory");
    sel = LDT_SEL(LDT_IDX_ES);
    __asm__ volatile ("movw %w0, %%es" : : "r"(sel) : "memory");

    g_ldtdata[0] = 0u;
    g_ldtdata[1] = 0x0badf00du; /* byte offset 4 == %fs:4 */
    l7a_fs_store(0x5a5aa5a5u);
    TEST("fs_store", g_ldtdata[0], 0x5a5aa5a5u);
    TEST("fs_load", l7a_fs_load(), 0x0badf00du);

    /* ---------------- (3) m16:16 far call into 16-bit code -------- */
    build_callee16((u32)thunk32 + 6u);           /* far return address */
    build_thunk(LDT_SEL(LDT_IDX_CS16), (u32)&g_cx_far);
    g_cx_far = 0u;
    ((void (*)(void))thunk32)();
    TEST("far16_cx", g_cx_far, 0x1234u);

    /* ---------------- (4) limit overrun -> SIGSEGV ---------------- */
    g_sig = 0u; g_code = 0u; g_addr = 0u; g_eip = 0u; g_cr2 = 0u;
    g_trapno = 0u; g_cs = 0u;
    g_segv_skip = 7u;
    l7a_es_overrun();
    TEST("lim_sig", g_sig, 11u);
    TEST("lim_code", g_code, 1u);               /* SEGV_MAPERR (delivery) */
    TEST("lim_addr", g_addr, LDT_ES_BASE + 0x1000u); /* exact cr2 */
    TEST("lim_eip", g_eip, (u32)l7a_es_overrun);
    TEST("lim_cr2", g_cr2, LDT_ES_BASE + 0x1000u);
    TEST("lim_cs", g_cs, 0x23u);
    /* trapno: 13 = architecturally correct #GP (post-S7 delivery), 14 =
     * the pre-S7 delivery default, -1 = oracle variance (test_p4 rule). */
    TEST("lim_trapno",
         (g_trapno == 13u || g_trapno == 14u || g_trapno == 0xffffffffu), 1u);

    /* ---------------- (5) not-present selector -> #NP ------------- */
    g_sig = 0u; g_code = 0u; g_addr = 0u; g_eip = 0u; g_cr2 = 0u;
    g_trapno = 0u; g_cs = 0u;
    g_segv_skip = 2u;
    l7a_np_load();
    TEST("np_sig", g_sig, 11u);
    TEST("np_addr", g_addr, 0u);                /* #NP: cr2 == 0 */
    TEST("np_eip", g_eip, (u32)l7a_np_load + 4u);
    TEST("np_cs", g_cs, 0x23u);
    TEST("np_trapno",
         (g_trapno == 11u || g_trapno == 14u || g_trapno == 0xffffffffu), 1u);

    /* ---------------- (6) set_thread_area(-1) + %gs --------------- */
    ud.entry_number = 0xFFFFFFFFu;              /* -1: kernel auto-alloc */
    ud.base_addr = (u32)g_tls;
    ud.limit = 0xFFFu;
    ud.flags = UD_32BIT | UD_USEABLE;
    TEST("sta", sys_set_thread_area(&ud), 0u);
    TEST("sta_entry", (ud.entry_number >= 6u && ud.entry_number <= 8u), 1u);
    sel = (u16)((ud.entry_number << 3) | 3u);
    __asm__ volatile ("movw %w0, %%gs" : : "r"(sel) : "memory");
    __asm__ volatile ("movl %0, %%gs:0" : : "r"(0x70707070u) : "memory");
    TEST("sta_gs0", g_tls[0], 0x70707070u);

    /* get_thread_area(244) on the allocated slot reports the same
     * descriptor (entry_number rides the struct as passed). */
    TEST("gta", sys_get_thread_area(&ud), 0u);
    TEST("gta_base", ud.base_addr, (u32)g_tls);

    puts_("PASS\n");
}

void _start(void)
{
    run_tests();
    sys_exit(0);
}
