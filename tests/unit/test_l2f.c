/*
 * tests/unit/test_l2f.c — host-native unit driver for lane L2f
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure-function tests for the L2f marshalling pieces (open(2) O_ flag
 * translation i386->aarch64, getcwd buffer semantics, kernel i386 rusage
 * layout, setgroups gid marshalling, and the Phase 4 futex stopgap via
 * the syscall registry) against a fake guest window.  Expected numbers
 * are literals pinned to the kernel uapi citations in sys_pass.c, NOT
 * host macros, so the checks mean the same thing on every build host.
 *
 * Prints "L2F OK" and exits 0 when every check passes.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>

#include "i686rt.h"
#include "os/marshal.h"

/* Module-internal helpers under test (src/os/sys_pass.c; declarations
 * intentionally live here — marshal.h is frozen this phase). */
long i686_open_flags_to_host(uint32_t guest_flags);
long i686_getcwd_store(i686_ctx_t *ctx, uint32_t buf_va, uint32_t size,
                       const char *cwd, size_t cwd_len);
int  i686_rusage_to_guest(i686_ctx_t *ctx, uint32_t ru_va, const struct rusage *ru);
int  i686_groups_from_guest(i686_ctx_t *ctx, uint32_t list_va, uint32_t n, gid_t **out);
int  i686_groups16_from_guest(i686_ctx_t *ctx, uint32_t list_va, uint32_t n, gid_t **out);

/* TEST-ONLY shims: r_mprotect/r_munmap/r_mremap delegate to rt32_vm.c,
 * which is not on this driver's link line (the lane card allows a
 * test-local shim; the vm handlers themselves are not under test here). */
int      rt32_vm_mprotect(i686_ctx_t *c, uint32_t a, uint32_t l, uint32_t p);
int      rt32_vm_munmap(i686_ctx_t *c, uint32_t a, uint32_t l);
uint32_t rt32_vm_mremap(i686_ctx_t *c, uint32_t oa, uint32_t ol, uint32_t nl,
                        uint32_t f, uint32_t na);

int rt32_vm_mprotect(i686_ctx_t *c, uint32_t a, uint32_t l, uint32_t p)
{
    (void)c; (void)a; (void)l; (void)p;
    return 0;
}

int rt32_vm_munmap(i686_ctx_t *c, uint32_t a, uint32_t l)
{
    (void)c; (void)a; (void)l;
    return 0;
}

uint32_t rt32_vm_mremap(i686_ctx_t *c, uint32_t oa, uint32_t ol, uint32_t nl,
                        uint32_t f, uint32_t na)
{
    (void)c; (void)oa; (void)ol; (void)nl; (void)f; (void)na;
    return 0;
}

static int g_pass;
static int g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

/* Fake guest window: guest_base + va lands inside this buffer
 * (little-endian host assumed — macOS arm64/x86_64). */
static uint8_t g_window[0x12000];
static i686_ctx_t ctx;

static uint32_t rd32(uint32_t va)
{
    uint32_t v;
    memcpy(&v, &g_window[va], 4);
    return v;
}

static void wr32(uint32_t va, uint32_t v)
{
    memcpy(&g_window[va], &v, 4);
}

static void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
    memset(g_window, 0, sizeof g_window);
}

/* ------------------------------------------------------------------ */
/* i386 O_ flag values (kernel citations in sys_pass.c file header)     */
/* ------------------------------------------------------------------ */
#define G_O_WRONLY     0x1u
#define G_O_RDWR       0x2u
#define G_O_EXCL       0x80u
#define G_O_CREAT      0x40u
#define G_O_TRUNC      0x200u
#define G_O_APPEND     0x400u
#define G_O_NONBLOCK   0x800u
#define G_O_DSYNC      0x1000u
#define G_O_DIRECT     0x4000u     /* i386; aarch64 host 0x10000 */
#define G_O_LARGEFILE  0x8000u     /* i386; no-op on 64-bit host */
#define G_O_DIRECTORY  0x10000u    /* i386; aarch64 host 0x4000  */
#define G_O_NOFOLLOW   0x20000u    /* i386; aarch64 host 0x8000  */
#define G_O_CLOEXEC    0x80000u
#define G_O_SYNC       0x101000u   /* __O_SYNC|O_DSYNC, both arches */
#define G_O_PATH       0x200000u
#define G_O_TMPFILE    0x410000u   /* __O_TMPFILE|O_DIRECTORY (i386) */

static void t_open_flags(void)
{
    /* Access mode and all numerically identical bits pass through. */
    CHECK(i686_open_flags_to_host(0) == 0); /* O_RDONLY */
    CHECK(i686_open_flags_to_host(G_O_WRONLY | G_O_CREAT | G_O_TRUNC) == 0x241);
    CHECK(i686_open_flags_to_host(G_O_RDWR | G_O_APPEND | G_O_NONBLOCK |
                                  G_O_CLOEXEC | G_O_EXCL | G_O_CREAT) ==
          (0x2u | 0x400u | 0x800u | 0x80000u | 0x80u | 0x40u));

    /* The four arch-specific bits land on their ARM32-derived values
     * (arch/arm64/include/uapi/asm/fcntl.h overriding asm-generic). */
    CHECK(i686_open_flags_to_host(G_O_DIRECTORY) == 0x4000);
    CHECK(i686_open_flags_to_host(G_O_NOFOLLOW) == 0x8000);
    CHECK(i686_open_flags_to_host(G_O_DIRECT) == 0x10000);

    /* O_LARGEFILE is dropped, not translated (no-op on 64-bit hosts). */
    CHECK(i686_open_flags_to_host(G_O_WRONLY | G_O_LARGEFILE | G_O_CREAT) == 0x41);

    /* O_SYNC keeps its 04010000 shape on both arches. */
    CHECK(i686_open_flags_to_host(G_O_SYNC) == 0x101000);
    CHECK(i686_open_flags_to_host(G_O_DSYNC) == 0x1000);

    /* O_PATH passthrough; O_TMPFILE reassembles from its parts:
     * guest __O_TMPFILE(0x400000)|O_DIRECTORY(0x10000) -> host
     * 0x400000|0x4000 = 020040000. */
    CHECK(i686_open_flags_to_host(G_O_PATH) == 0x200000);
    CHECK(i686_open_flags_to_host(G_O_TMPFILE) == 0x404000);

    /* Unknown bits are rejected like the kernel's build_open_flags. */
    CHECK(i686_open_flags_to_host(0x8000000u) == -EINVAL);
    CHECK(i686_open_flags_to_host(G_O_WRONLY | 0x40000000u) == -EINVAL);

    /* A busybox-shaped directory open composes correctly. */
    CHECK(i686_open_flags_to_host(G_O_DIRECTORY | G_O_LARGEFILE | G_O_CLOEXEC) ==
          (0x4000u | 0x80000u));
}

static void t_getcwd(void)
{
    reset();

    /* "/" with room: length incl NUL returned, bytes stored. */
    long r = i686_getcwd_store(&ctx, 0x1000, 64, "/", 2);
    CHECK(r == 2);
    CHECK(g_window[0x1000] == '/' && g_window[0x1001] == '\0');

    /* Longer path: exact fit ok, one byte short is ERANGE. */
    r = i686_getcwd_store(&ctx, 0x1100, 7, "/tmp/x", 7);
    CHECK(r == 7);
    CHECK(memcmp(&g_window[0x1100], "/tmp/x", 7) == 0);
    CHECK(i686_getcwd_store(&ctx, 0x1100, 6, "/tmp/x", 7) == -ERANGE);
    CHECK(i686_getcwd_store(&ctx, 0x1100, 0, "/tmp/x", 7) == -EINVAL);

    /* Bad pointers: null page and 32-bit wrap (va 0xFFFFFFFF + 2 bytes). */
    CHECK(i686_getcwd_store(&ctx, 0x800, 64, "/", 2) == -EFAULT);
    CHECK(i686_getcwd_store(&ctx, 0xFFFFFFFFu, 64, "/", 2) == -EFAULT);
}

static void t_rusage(void)
{
    struct rusage ru;

    reset();
    memset(&ru, 0, sizeof ru);
    ru.ru_utime.tv_sec = 11;
    ru.ru_utime.tv_usec = 222222;
    ru.ru_stime.tv_sec = 3;
    ru.ru_stime.tv_usec = 44;
    ru.ru_maxrss = 1000;
    ru.ru_ixrss = 1;
    ru.ru_idrss = 2;
    ru.ru_isrss = 3;
    ru.ru_minflt = 40;
    ru.ru_majflt = 5;
    ru.ru_nswap = 6;
    ru.ru_inblock = 7;
    ru.ru_oublock = 8;
    ru.ru_msgsnd = 9;
    ru.ru_msgrcv = 10;
    ru.ru_nsignals = 11;
    ru.ru_nvcsw = 12;
    ru.ru_nivcsw = 13;

    CHECK(i686_rusage_to_guest(&ctx, 0x2000, &ru) == 0);
    /* Kernel i386 layout: 2 x {u32 sec, u32 usec} + 14 x u32 = 72 B. */
    CHECK(rd32(0x2000 + 0) == 11);          /* ru_utime.tv_sec   */
    CHECK(rd32(0x2000 + 4) == 222222);      /* ru_utime.tv_usec  */
    CHECK(rd32(0x2000 + 8) == 3);           /* ru_stime.tv_sec   */
    CHECK(rd32(0x2000 + 12) == 44);         /* ru_stime.tv_usec  */

    /* The 14 longs, in kernel field order. */
    CHECK(rd32(0x2000 + 16) == 1000);       /* ru_maxrss         */
    CHECK(rd32(0x2000 + 20) == 1);          /* ru_ixrss          */
    CHECK(rd32(0x2000 + 24) == 2);          /* ru_idrss          */
    CHECK(rd32(0x2000 + 28) == 3);          /* ru_isrss          */
    CHECK(rd32(0x2000 + 32) == 40);         /* ru_minflt         */
    CHECK(rd32(0x2000 + 36) == 5);          /* ru_majflt         */
    CHECK(rd32(0x2000 + 40) == 6);          /* ru_nswap          */
    CHECK(rd32(0x2000 + 44) == 7);          /* ru_inblock        */
    CHECK(rd32(0x2000 + 48) == 8);          /* ru_oublock        */
    CHECK(rd32(0x2000 + 52) == 9);          /* ru_msgsnd         */
    CHECK(rd32(0x2000 + 56) == 10);         /* ru_msgrcv         */
    CHECK(rd32(0x2000 + 60) == 11);         /* ru_nsignals       */
    CHECK(rd32(0x2000 + 64) == 12);         /* ru_nvcsw          */
    CHECK(rd32(0x2000 + 68) == 13);         /* ru_nivcsw         */

    /* 64-bit fields truncate to the i386 32-bit width. */
    memset(&ru, 0, sizeof ru);
    ru.ru_utime.tv_sec = (time_t)0x100000123LL;
    ru.ru_maxrss = 0x7FFFFFFF;
    CHECK(i686_rusage_to_guest(&ctx, 0x2100, &ru) == 0);
    CHECK(rd32(0x2100 + 0) == 0x123u);
    CHECK(rd32(0x2100 + 16) == 0x7FFFFFFFu);

    /* Bad pointer rejected. */
    CHECK(i686_rusage_to_guest(&ctx, 0x800, &ru) == -EFAULT);
}

static void t_groups(void)
{
    gid_t *g = NULL;

    reset();

    /* setgroups32: u32 entries copied verbatim. */
    wr32(0x3000 + 0, 5);
    wr32(0x3000 + 4, 65534);
    wr32(0x3000 + 8, 0xFFFFFFFFu);
    CHECK(i686_groups_from_guest(&ctx, 0x3000, 3, &g) == 0);
    CHECK(g != NULL);
    if (g != NULL) {
        CHECK(g[0] == 5 && g[1] == 65534 && g[2] == (gid_t)0xFFFFFFFFu);
        free(g);
    }

    /* setgroups (old, nr 81): entries are old_gid_t (u16). */
    g_window[0x3100 + 0] = 0x78; g_window[0x3100 + 1] = 0x56; /* 0x5678 */
    g_window[0x3100 + 2] = 0x34; g_window[0x3100 + 3] = 0x12; /* 0x1234 */
    CHECK(i686_groups16_from_guest(&ctx, 0x3100, 2, &g) == 0);
    CHECK(g != NULL);
    if (g != NULL) {
        CHECK(g[0] == 0x5678 && g[1] == 0x1234);
        free(g);
    }

    /* n == 0 is valid and needs no list. */
    g = (gid_t *)0x1;
    CHECK(i686_groups_from_guest(&ctx, 0, 0, &g) == 0);
    CHECK(g == NULL);

    /* Bounds: above NGROUPS_MAX, null page, 32-bit wrap. */
    CHECK(i686_groups_from_guest(&ctx, 0x3000, 65537, &g) == -EINVAL);
    CHECK(i686_groups_from_guest(&ctx, 0x800, 1, &g) == -EFAULT);
    CHECK(i686_groups16_from_guest(&ctx, 0xFFFFFFFEu, 2, &g) == -EFAULT);
}

static void t_futex(void)
{
    reset();
    i686_syscalls_pass_init();

    /* FUTEX_WAIT(0) with a mismatched word -> -EAGAIN (kernel
     * futex_wait_setup).  A matching word would block the unit run, so
     * the timeout path is exercised with a zero relative timespec. */
    wr32(0x4000, 7);
    ctx.gpr[I686_REG_EBX] = 0x4000;
    ctx.gpr[I686_REG_ECX] = 0;  /* FUTEX_WAIT */
    ctx.gpr[I686_REG_EDX] = 9;
    CHECK(i686_sys_dispatch(&ctx, 240) == -EAGAIN);

    /* Timeout path: utime is ESI (i386 arg4); timespec32 {0,0} times
     * out immediately. */
    wr32(0x4100, 7);
    wr32(0x4200, 0);
    wr32(0x4204, 0);
    ctx.gpr[I686_REG_EBX] = 0x4100;
    ctx.gpr[I686_REG_ECX] = 0;
    ctx.gpr[I686_REG_EDX] = 7;
    ctx.gpr[I686_REG_ESI] = 0x4200;
    CHECK(i686_sys_dispatch(&ctx, 240) == -ETIMEDOUT);

    /* FUTEX_WAIT_BITSET(9)|FUTEX_CLOCK_REALTIME(256) with a zero
     * bitset (EBP, i386 arg6) -> kernel -EINVAL.  RC7b T4d: dropping
     * val3 made every glibc clockwait spin at -EINVAL. */
    wr32(0x4300, 7);
    ctx.gpr[I686_REG_EBX] = 0x4300;
    ctx.gpr[I686_REG_ECX] = 9u | 256u;
    ctx.gpr[I686_REG_EDX] = 7;
    ctx.gpr[I686_REG_ESI] = 0;
    ctx.gpr[I686_REG_EBP] = 0;
    CHECK(i686_sys_dispatch(&ctx, 240) == -EINVAL);

    /* FUTEX_WAKE(1): no waiters -> 0; PRIVATE (128) passes through. */
    ctx.gpr[I686_REG_EBX] = 0x4000;
    ctx.gpr[I686_REG_ECX] = 1;
    CHECK(i686_sys_dispatch(&ctx, 240) == 0);
    ctx.gpr[I686_REG_ECX] = 128u + 1u; /* WAKE|PRIVATE */
    CHECK(i686_sys_dispatch(&ctx, 240) == 0);

    /* FUTEX_FD(2): removed by the kernel -> -ENOSYS (verbatim op). */
    ctx.gpr[I686_REG_ECX] = 2;
    CHECK(i686_sys_dispatch(&ctx, 240) == -ENOSYS);

    /* WAKE_OP(5) without uaddr2 (EDI, i386 arg5) -> -EFAULT, like the
     * kernel's access_ok on the second futex word. */
    ctx.gpr[I686_REG_ECX] = 5;
    ctx.gpr[I686_REG_EDI] = 0;
    CHECK(i686_sys_dispatch(&ctx, 240) == -EFAULT);

    /* Bad uaddr -> EFAULT. */
    ctx.gpr[I686_REG_EBX] = 0x100;
    ctx.gpr[I686_REG_ECX] = 0;
    ctx.gpr[I686_REG_EDX] = 7;
    CHECK(i686_sys_dispatch(&ctx, 240) == -EFAULT);
}

int main(void)
{
    t_open_flags();
    t_getcwd();
    t_rusage();
    t_groups();
    t_futex();

    if (g_fail != 0) {
        printf("L2F FAILED: %d check(s) failed (%d passed)\n", g_fail, g_pass);
        return 1;
    }
    printf("L2F OK\n");
    return 0;
}
