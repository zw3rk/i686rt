/*
 * tests/test_h1_smc.c — Phase H H1: self-modifying code fixture (D11)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The guest patches its own executable code and must observe the NEW
 * bytes on the next execution — under the interpreter trivially, and
 * under the DBT only if D11 write-protection invalidates the stale
 * translated block (engine smc_protect / smc_write_fault).
 *
 * freestanding i386: own _start, raw int 0x80.
 */

typedef unsigned int u32;
typedef int i32;

__asm__(".text\n"
        ".globl _start\n"
        "_start:\n"
        "  call cmain\n"
        "  movl %eax, %ebx\n"
        "  movl $1, %eax\n"
        "  int  $0x80\n"
        /* fn1: mov eax, 0x11111111; ret  (patched to 0x22222222 later) */
        ".globl smc_fn1\n"
        "smc_fn1:\n"
        "  movl $0x11111111, %eax\n"
        "  ret\n"
        /* fn2 on the same page: mov eax, 0x33333333; ret */
        ".globl smc_fn2\n"
        "smc_fn2:\n"
        "  movl $0x33333333, %eax\n"
        "  ret\n");

extern void smc_fn1(void);
extern void smc_fn2(void);

static u32 g_fail;
static char g_stub[4096] __attribute__((aligned(4096)));

static void puts_(const char *s)
{
    const char *p = s;
    while (*p) {
        p++;
    }
    __asm__ volatile("int $0x80" ::"a"((u32)4), "b"((u32)1), "c"(s),
                     "d"((u32)(p - s)));
}

static void report(const char *name, i32 ok)
{
    puts_(name);
    puts_(ok ? " ok\n" : " FAIL\n");
    if (!ok) {
        g_fail++;
    }
}

static i32 sys_mprotect(void *addr, u32 len, u32 prot)
{
    i32 r;
    __asm__ volatile("int $0x80"
                     : "=a"(r)
                     : "a"((u32)125), "b"((u32)addr), "c"(len), "d"(prot));
    return r;
}

i32 cmain(void)
{
    /* Real self-modifying code makes its page writable first (and the
     * mprotect path must also invalidate any translated blocks — the
     * vm_invalidate_jit wiring). */
    {
        u32 page = ((u32)&smc_fn1) & ~4095u;
        volatile i32 r = sys_mprotect((void *)page, 4096u, 3u /* RW */);
        __asm__ volatile("" ::: "memory");
        if (r != 0) {
            puts_("smc-mprotect FAIL\n");
            return 1;
        }
    }

    /* case 1: patch an imm32 inside live code (same page as fn2). */
    {
        volatile unsigned char *f = (volatile unsigned char *)&smc_fn1;
        u32 a = ((u32 (*)(void))f)();
        f[1] = 0x22; f[2] = 0x22; f[3] = 0x22; f[4] = 0x22;
        u32 b = ((u32 (*)(void))f)();
        report("smc-patch-imm",
               a == 0x11111111u && b == 0x22222222u);
    }

    /* case 2: rewrite a stub on a data page between executions. */
    {
        volatile unsigned char *s = (volatile unsigned char *)g_stub;
        u32 (*call)(void) = (u32 (*)(void))g_stub;
        s[0] = 0xb8; s[1] = 0xaa; s[2] = 0xaa; s[3] = 0xaa; s[4] = 0xaa;
        s[5] = 0xc3;
        u32 a = call();
        s[1] = 0xbb; s[2] = 0xbb; s[3] = 0xbb; s[4] = 0xbb;
        u32 b = call();
        report("smc-rewrite-stub",
               a == 0xaaaaaaaau && b == 0xbbbbbbbbu);
    }

    /* case 3: a same-page neighbour stays valid across a patch. */
    {
        volatile unsigned char *f1 = (volatile unsigned char *)&smc_fn1;
        u32 c = ((u32 (*)(void))&smc_fn2)();
        f1[1] = 0x33; f1[2] = 0x33; f1[3] = 0x33; f1[4] = 0x33;
        u32 d = ((u32 (*)(void))f1)();
        u32 e = ((u32 (*)(void))&smc_fn2)();
        report("smc-same-page",
               c == 0x33333333u && d == 0x33333333u && e == 0x33333333u);
    }

    puts_(g_fail == 0u ? "PASS\n" : "FAIL\n");
    return (i32)g_fail;
}
