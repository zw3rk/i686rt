/*
 * tests/test_c7_smc_rss.c — fix campaign C7: SMC dead-mark reclamation
 * RSS fixture (DEFECTS.md C7)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The guest rewrites immediates in its own code page SMC_EVENTS times.
 * The page is a sled of SLED_CELLS distinct `mov eax, imm32; ret`
 * entry points; every event patches the next cell (one byte store per
 * imm32 byte) and calls it, so the DBT dispatches a fresh eip each
 * time: every compiled cell block is dead-marked by a later store
 * fault and dies in a hash slot that no dispatch re-compiles until the
 * next pass — exactly the per-event leak shape C7 fixes (dead-marked
 * blocks previously stayed mapped until direct-mapped eviction; a
 * whole sled pass parks ~680 x 8 KiB until then).
 *
 * Each event's return value proves the NEW bytes executed (a stale
 * served block would return the previous pass's imm).
 *
 * The fixture samples VmRSS of /proc/self/status — the i686rt process
 * itself, seen from the guest via syscall passthrough — before and
 * after the loop: growth must stay under 1 MiB.
 *
 * freestanding i386: own _start, raw int 0x80.
 */

typedef unsigned int u32;
typedef int i32;

#define SLED_CELLS 680u   /* 680 * 6 = 4080 bytes: one full code page */
#define SMC_PASSES 15u    /* 15 * 680 = 10200 events >= 10000 */
#define RSS_BUDGET_KB 1024u

__asm__(".text\n"
        ".globl _start\n"
        "_start:\n"
        "  call cmain\n"
        "  movl %eax, %ebx\n"
        "  movl $1, %eax\n"
        "  int  $0x80\n"
        /* Sled page: SLED_CELLS identical 6-byte cells, each a valid
         * entry point (mov eax, imm32; ret) whose imm32 is patched by
         * the event loop.  .balign keeps the sled alone on its page. */
        ".balign 4096\n"
        ".globl smc_sled\n"
        "smc_sled:\n"
        ".rept " "680" "\n"
        "  movl $0x11111111, %eax\n"
        "  ret\n"
        ".endr\n");

extern void smc_sled(void);

static u32 g_fail;
static char g_buf[8192];

static void puts_(const char *s)
{
    const char *p = s;
    while (*p) {
        p++;
    }
    __asm__ volatile("int $0x80" ::"a"((u32)4), "b"((u32)1), "c"(s),
                     "d"((u32)(p - s)));
}

static void puts_num(i32 v)
{
    char b[13];
    u32 u;
    int i = (int)sizeof(b) - 1;

    b[i] = '\0';
    if (v < 0) {
        u = (u32)(-(v + 1)) + 1u;
    } else {
        u = (u32)v;
    }
    do {
        b[--i] = (char)('0' + (u % 10u));
        u /= 10u;
    } while (u != 0u);
    if (v < 0) {
        b[--i] = '-';
    }
    puts_(&b[i]);
}

static void puts_hex8(u32 v)
{
    char b[9];
    int i;

    for (i = 7; i >= 0; i--) {
        u32 d = v & 0xFu;
        b[i] = (char)(d < 0xAu ? '0' + d : 'a' + d - 0xAu);
        v >>= 4;
    }
    b[8] = '\0';
    puts_(b);
}

static i32 sys_open(const char *path)
{
    i32 r;
    __asm__ volatile("int $0x80"
                     : "=a"(r)
                     : "a"((u32)5), "b"((u32)path), "c"((u32)0),
                       "d"((u32)0));
    return r;
}

static i32 sys_read(i32 fd, void *buf, u32 len)
{
    i32 r;
    __asm__ volatile("int $0x80"
                     : "=a"(r)
                     : "a"((u32)3), "b"((u32)fd), "c"((u32)buf),
                       "d"(len));
    return r;
}

static void sys_close(i32 fd)
{
    __asm__ volatile("int $0x80" ::"a"((u32)6), "b"((u32)fd));
}

static i32 sys_mprotect(void *addr, u32 len, u32 prot)
{
    i32 r;
    __asm__ volatile("int $0x80"
                     : "=a"(r)
                     : "a"((u32)125), "b"((u32)addr), "c"(len), "d"(prot));
    return r;
}

/* VmRSS of this process in kB — under i686rt this IS the translator
 * process' RSS (guest syscalls pass /proc through to the host). */
static i32 read_vmrss_kb(void)
{
    i32 fd = sys_open("/proc/self/status");
    i32 n, i;
    i32 kb;
    char *p;

    if (fd < 0) {
        return -1;
    }
    n = sys_read(fd, g_buf, sizeof(g_buf) - 1u);
    sys_close(fd);
    if (n <= 0) {
        return -1;
    }
    g_buf[n] = '\0';
    p = g_buf;
    for (i = 0; i < n - 6; i++) {
        if (p[i] == 'V' && p[i + 1] == 'm' && p[i + 2] == 'R' &&
            p[i + 3] == 'S' && p[i + 4] == 'S' && p[i + 5] == ':') {
            break;
        }
    }
    if (i >= n - 6) {
        return -1;
    }
    i += 6;
    while (p[i] == ' ' || p[i] == '\t') {
        i++;
    }
    kb = 0;
    while (p[i] >= '0' && p[i] <= '9') {
        kb = kb * 10 + (p[i] - '0');
        i++;
    }
    return kb;
}

i32 cmain(void)
{
    volatile unsigned char *sled = (volatile unsigned char *)&smc_sled;
    i32 before, after, growth;
    u32 pass, cell;

    /* Real self-modifying code makes its code page writable first —
     * the guest text is mapped r-x, so a raw store would fault the
     * interpreter (the mprotect path also invalidates any translated
     * blocks via the vm_invalidate_jit wiring).  Under the DBT the
     * first call below then translates the sled page and protects it
     * (smc_protect); every later store faults, dead-marks the page's
     * live blocks into the graveyard, and the call re-compiles and
     * re-protects — one full fault -> dead-mark -> graveyard -> drain
     * -> re-compile -> re-protect SMC event per cell. */
    {
        u32 page = (u32)sled & ~4095u;
        volatile i32 r = sys_mprotect((void *)page, 4096u,
                                      3u /* PROT_READ|PROT_WRITE */);
        __asm__ volatile("" ::: "memory");
        if (r != 0) {
            puts_("smc-mprotect FAIL\n");
            return 1;
        }
    }

    before = read_vmrss_kb();
    if (before < 0) {
        puts_("vmrss-read FAIL\n");
        return 1;
    }
    puts_("VMRSS_BEFORE_KB ");
    puts_num(before);
    puts_("\nSMC_EVENTS ");
    puts_num((i32)(SLED_CELLS * SMC_PASSES));
    puts_("\n");

    for (pass = 0u; pass < SMC_PASSES; pass++) {
        for (cell = 0u; cell < SLED_CELLS; cell++) {
            volatile unsigned char *f = sled + 6u * cell;
            u32 imm = 0x44000000u + pass * SLED_CELLS + cell;
            u32 (*callfn)(void) = (u32 (*)(void))(sled + 6u * cell);
            u32 v;

            f[1] = (unsigned char)imm;      /* imm32 is little-endian */
            f[2] = (unsigned char)(imm >> 8);
            f[3] = (unsigned char)(imm >> 16);
            f[4] = (unsigned char)(imm >> 24);
            v = callfn();
            if (v != imm) {
                puts_("smc-value FAIL pass ");
                puts_num((i32)pass);
                puts_(" cell ");
                puts_num((i32)cell);
                puts_(" got ");
                puts_hex8(v);
                puts_(" want ");
                puts_hex8(imm);
                puts_("\n");
                return 1;
            }
        }
    }

    after = read_vmrss_kb();
    if (after < 0) {
        puts_("vmrss-read FAIL\n");
        return 1;
    }
    puts_("VMRSS_AFTER_KB ");
    puts_num(after);
    puts_("\nRSS_GROWTH_KB ");
    growth = after - before;
    puts_num(growth);
    puts_("\n");
    puts_("rss-stable");
    puts_(growth < (i32)RSS_BUDGET_KB ? " ok\n" : " FAIL\n");
    if (growth >= (i32)RSS_BUDGET_KB) {
        g_fail++;
    }

    puts_(g_fail == 0u ? "PASS\n" : "FAIL\n");
    return (i32)g_fail;
}
