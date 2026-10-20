/*
 * tests/unit/test_l2e.c — host-native unit driver for lane L2e
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the pure converters of src/os/sys_misc.c byte-exactly
 * (epoll packing, flock/flock64 conversion, rlimit infinity mapping,
 * sysinfo mem_unit scaling, fcntl O_/cmd mapping) and exercises the
 * registered old-mmap(90), old select(82) and _newselect(142) handlers
 * against a fake guest window with a test-local rt32_vm_mmap2 stub.
 * Little-endian host assumed (macOS arm64/x86_64).
 *
 * Prints "L2E OK" and exits 0 when every check passes.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "i686rt.h"
#include "os/marshal.h"
#include "os/structs_i386.h"

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

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

/* Exports of src/os/sys_misc.c (no shared internal header exists — the
 * declarations mirror the definitions byte-for-byte). */
extern void i686_fdset_g2h(uint8_t *host128, const uint8_t *guest, uint32_t n);
extern void i686_fdset_h2g(uint8_t *guest, const uint8_t *host128, uint32_t n);
extern void i686_epoll_pack_guest(uint8_t *dst, const uint8_t *src, int n);
extern void i686_epoll_unpack_guest(uint8_t *dst, const uint8_t *src, int n);
extern void i686_flock32_to_host(uint8_t *host32, const uint8_t *guest16);
extern void i686_flock32_from_host(uint8_t *guest16, const uint8_t *host32);
extern void i686_flock64_to_host(uint8_t *host32, const i686_flock64_t *g);
extern void i686_flock64_from_host(i686_flock64_t *g, const uint8_t *host32);
extern void i686_rlimit_g2h(const i686_rlimit_t *g, uint64_t *cur, uint64_t *max);
extern void i686_rlimit_h2g(i686_rlimit_t *g, uint64_t cur, uint64_t max);
extern void i686_sysinfo_to_guest(i686_sysinfo_t *g, const uint8_t *host112);
extern uint32_t i686_oflags_g2h(uint32_t g);
extern uint32_t i686_oflags_h2g(uint32_t h);
extern uint32_t i686_setfl_to_host(uint32_t g);
extern int i686_fcntl_cmd_to_host(uint32_t cmd, int fcntl64_entry,
                                  int *flock_bytes);

/* Fake guest window: guest_base + va lands inside this buffer. */
static uint8_t g_window[0x10000];
static i686_ctx_t ctx;

static void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
    memset(g_window, 0, sizeof g_window);
}

static void w32(uint32_t va, uint32_t v)
{
    memcpy(&g_window[va], &v, 4);
}

static uint32_t r32(uint32_t va)
{
    uint32_t v;
    memcpy(&v, &g_window[va], 4);
    return v;
}

/* Test-local rt32_vm_mmap2 stub (signature mirrors src/rt32/rt32.h). */
static uint32_t s_mm_addr, s_mm_len, s_mm_prot, s_mm_flags, s_mm_pgoff;
static int s_mm_fd;
static int s_mm_calls;

uint32_t rt32_vm_mmap2(i686_ctx_t *c, uint32_t addr, uint32_t len,
                       uint32_t prot, uint32_t flags, int fd, uint32_t pgoffset)
{
    (void)c;
    s_mm_addr = addr;
    s_mm_len = len;
    s_mm_prot = prot;
    s_mm_flags = flags;
    s_mm_fd = fd;
    s_mm_pgoff = pgoffset;
    s_mm_calls++;
    return 0x40000000u;
}

/* ------------------------------------------------------------------ */
/* fd_set re-packing                                                   */
/* ------------------------------------------------------------------ */

static void t_fdset(void)
{
    uint8_t guest[128], host[128], back[128];

    /* fds 0,31,32,33,63,64,69 set on the guest; fd 95 (>= n=70) also
     * set in the last guest word must be dropped.  Guest words (LE):
     * w0=0x80000001 (fds 0,31) w1=0x80000003 (fds 32,33,63)
     * w2=0x80000021 (fds 64,69,95). */
    memset(guest, 0, sizeof guest);
    memset(host, 0xEE, sizeof host);
    memset(back, 0, sizeof back);
    {
        uint32_t w0 = 0x80000001u, w1 = 0x80000003u, w2 = 0x80000021u;
        memcpy(guest, &w0, 4);
        memcpy(guest + 4, &w1, 4);
        memcpy(guest + 8, &w2, 4);
    }

    i686_fdset_g2h(host, guest, 70);
    {
        uint64_t h0, h1;
        memcpy(&h0, host, 8);
        memcpy(&h1, host + 8, 8);
        CHECK(h0 == ((UINT64_C(1) << 0) | (UINT64_C(1) << 31) |
                     (UINT64_C(1) << 32) | (UINT64_C(1) << 33) |
                     (UINT64_C(1) << 63)));
        CHECK(h1 == ((UINT64_C(1) << 0) | (UINT64_C(1) << 5))); /* fds 64,69 */
        CHECK(h0 == 0x8000000380000001ull);
    }

    i686_fdset_h2g(back, host, 70);
    CHECK(memcmp(back, guest, 8) == 0);  /* words 0,1 identical */
    CHECK(back[8] == 0x21 && back[9] == 0 && back[10] == 0 && back[11] == 0);
    CHECK(back[12] == 0 && back[13] == 0 && back[14] == 0 && back[15] == 0);

    /* n = 0: nothing is read or written. */
    memset(back, 0xAA, sizeof back);
    i686_fdset_h2g(back, host, 0);
    CHECK(back[0] == 0xAA && back[1] == 0xAA && back[2] == 0xAA && back[3] == 0xAA);
}

/* ------------------------------------------------------------------ */
/* epoll packing                                                       */
/* ------------------------------------------------------------------ */

static void t_epoll(void)
{
    uint8_t host[48], guest[36], back[48];
    const uint32_t ev[3] = {0x00000035u, 0x80000001u, 0x00000004u};
    const uint64_t dat[3] = {0x1122334455667788ull, 0ull, 0x00000000FFFFFFFFull};
    uint8_t expect[36];

    memset(host, 0, sizeof host);
    for (int i = 0; i < 3; i++) {
        memcpy(host + i * 16, &ev[i], 4);
        memcpy(host + i * 16 + 8, &dat[i], 8);
        /* inter-member padding must not leak into the guest copy */
        memset(host + i * 16 + 4, 0xAB, 4);
    }
    memset(expect, 0, sizeof expect);
    for (int i = 0; i < 3; i++) {
        memcpy(expect + i * 12, &ev[i], 4);
        memcpy(expect + i * 12 + 4, &dat[i], 8);
    }

    i686_epoll_pack_guest(guest, host, 3);
    CHECK(memcmp(guest, expect, 36) == 0);
    CHECK(guest[0] == (uint8_t)0x35 && guest[4] == (uint8_t)0x88 &&
          guest[5] == (uint8_t)0x77);

    memset(back, 0xFF, sizeof back);
    i686_epoll_unpack_guest(back, guest, 3);
    for (int i = 0; i < 3; i++) {
        CHECK(memcmp(back + i * 16, host + i * 16, 4) == 0);  /* events */
        CHECK(memcmp(back + i * 16 + 8, host + i * 16 + 8, 8) == 0); /* data */
        CHECK(back[i * 16 + 4] == 0 && back[i * 16 + 5] == 0 &&
              back[i * 16 + 6] == 0 && back[i * 16 + 7] == 0); /* pad */
    }
}

/* ------------------------------------------------------------------ */
/* flock conversions                                                   */
/* ------------------------------------------------------------------ */

static void t_flock(void)
{
    uint8_t guest16[16], host32[32], back16[16];
    i686_flock64_t g64;

    /* flock (16-byte, i32 offsets sign-extended). */
    memset(guest16, 0, sizeof guest16);
    {
        uint16_t t = 1, w = 2; /* F_WRLCK, SEEK_END */
        int32_t s = -100, l = 200, p = 0;
        memcpy(guest16, &t, 2);
        memcpy(guest16 + 2, &w, 2);
        memcpy(guest16 + 4, &s, 4);
        memcpy(guest16 + 8, &l, 4);
        memcpy(guest16 + 12, &p, 4);
    }
    memset(host32, 0, sizeof host32);
    i686_flock32_to_host(host32, guest16);
    {
        uint16_t t, w;
        uint64_t s, l;
        memcpy(&t, host32, 2);
        memcpy(&w, host32 + 2, 2);
        memcpy(&s, host32 + 8, 8);
        memcpy(&l, host32 + 16, 8);
        CHECK(t == 1 && w == 2);
        CHECK(s == 0xFFFFFFFFFFFFFF9Cull); /* sign-extended -100 */
        CHECK(l == 200);
    }
    memset(back16, 0, sizeof back16);
    i686_flock32_from_host(back16, host32);
    CHECK(memcmp(back16, guest16, 16) == 0);

    /* flock64 (24-byte frozen layout) round trip + pinned host offsets. */
    memset(&g64, 0, sizeof g64);
    g64.l_type = 2; /* F_UNLCK */
    g64.l_whence = 1;
    g64.l_start = 0x1122334455667788ull;
    g64.l_len = 0x8877665544332211ull;
    g64.l_pid = 1234;
    memset(host32, 0, sizeof host32);
    i686_flock64_to_host(host32, &g64);
    {
        uint16_t t, w;
        uint64_t s, l;
        int32_t p;
        memcpy(&t, host32, 2);
        memcpy(&w, host32 + 2, 2);
        memcpy(&s, host32 + 8, 8);
        memcpy(&l, host32 + 16, 8);
        memcpy(&p, host32 + 24, 4);
        CHECK(t == 2 && w == 1);
        CHECK(s == 0x1122334455667788ull);
        CHECK(l == 0x8877665544332211ull);
        CHECK(p == 1234);
        CHECK(host32[4] == 0 && host32[5] == 0 && host32[6] == 0 && host32[7] == 0);
    }
    {
        i686_flock64_t back64;
        memset(&back64, 0xEE, sizeof back64);
        i686_flock64_from_host(&back64, host32);
        CHECK(back64.l_type == 2 && back64.l_whence == 1);
        CHECK(back64.l_start == 0x1122334455667788ull);
        CHECK(back64.l_len == 0x8877665544332211ull);
        CHECK(back64.l_pid == 1234);
    }
}

/* ------------------------------------------------------------------ */
/* rlimit mapping                                                      */
/* ------------------------------------------------------------------ */

static void t_rlimit(void)
{
    i686_rlimit_t g;
    uint64_t cur, max;

    g.rlim_cur = 0xFFFFFFFFu; /* guest infinity */
    g.rlim_max = 100u;
    i686_rlimit_g2h(&g, &cur, &max);
    CHECK(cur == 0xFFFFFFFFFFFFFFFFull);
    CHECK(max == 100u);

    /* Host values above 32 bits clamp to guest infinity. */
    i686_rlimit_h2g(&g, 0x100000000ull, 0xFFFFFFFFull);
    CHECK(g.rlim_cur == 0xFFFFFFFFu);
    CHECK(g.rlim_max == 0xFFFFFFFFu);
    i686_rlimit_h2g(&g, 100u, 200u);
    CHECK(g.rlim_cur == 100u && g.rlim_max == 200u);
    i686_rlimit_g2h(&g, &cur, &max);
    CHECK(cur == 100u && max == 200u);
}

/* ------------------------------------------------------------------ */
/* sysinfo scaling                                                     */
/* ------------------------------------------------------------------ */

static void si_put64(uint8_t *h, size_t off, uint64_t v)
{
    memcpy(h + off, &v, 8);
}

static void t_sysinfo(void)
{
    uint8_t host[112];
    i686_sysinfo_t g;

    /* Counters above 32 bits trigger the kernel compat scaling:
     * mem_unit 1 -> 4096 (12 shifts), counters >> 12. */
    memset(host, 0, sizeof host);
    si_put64(host, 0, 12345);                 /* uptime */
    si_put64(host, 8, 0x00000F00ull);          /* loads[0] */
    si_put64(host, 16, 0x100000999ull);        /* loads[1] (truncated) */
    si_put64(host, 24, 9ull);                  /* loads[2] */
    si_put64(host, 32, 0x200001000ull);        /* totalram */
    si_put64(host, 40, 0x100000400ull);        /* freeram */
    si_put64(host, 48, 3ull);                  /* sharedram -> 0 after >>12 */
    si_put64(host, 56, 4ull);                  /* bufferram -> 0 */
    si_put64(host, 64, 0ull);                  /* totalswap */
    si_put64(host, 72, 0ull);                  /* freeswap */
    {
        uint16_t procs = 777;
        memcpy(host + 80, &procs, 2);
    }
    si_put64(host, 88, 0x100000200ull);        /* totalhigh */
    si_put64(host, 96, 0ull);                  /* freehigh */
    {
        uint32_t mu = 1;
        memcpy(host + 104, &mu, 4);
    }

    i686_sysinfo_to_guest(&g, host);
    CHECK(g.uptime == 12345);
    CHECK(g.loads[0] == 0x00000F00u);
    CHECK(g.loads[1] == 0x00000999u);
    CHECK(g.loads[2] == 9u);
    CHECK(g.totalram == 0x200001000ull >> 12);
    CHECK(g.freeram == 0x100000400ull >> 12);
    CHECK(g.sharedram == 0u && g.bufferram == 0u);
    CHECK(g.totalswap == 0u && g.freeswap == 0u);
    CHECK(g.procs == 777);
    CHECK(g.totalhigh == 0x100000200ull >> 12);
    CHECK(g.freehigh == 0u);
    CHECK(g.mem_unit == 4096u);
    for (size_t i = 0; i < sizeof(g._f); i++) {
        CHECK(g._f[i] == 0);
    }

    /* Small counters: no scaling, mem_unit untouched. */
    si_put64(host, 32, 4096ull);
    si_put64(host, 88, 0ull);
    i686_sysinfo_to_guest(&g, host);
    CHECK(g.totalram == 4096u);
    CHECK(g.mem_unit == 1u);

    /* Only totalswap large: still scales (totalram 4096 >> 12 == 1). */
    si_put64(host, 32, 4096ull);
    si_put64(host, 64, 0x100000000ull);
    i686_sysinfo_to_guest(&g, host);
    CHECK(g.totalram == 1u);
    CHECK(g.totalswap == 0x100000000ull >> 12);
    CHECK(g.mem_unit == 4096u);
}

/* ------------------------------------------------------------------ */
/* O_ flag / fcntl cmd mapping                                         */
/* ------------------------------------------------------------------ */

static void t_oflags(void)
{
    /* O_RDWR|O_NONBLOCK|O_LARGEFILE -> drop LARGEFILE. */
    CHECK(i686_oflags_g2h(0x0000802u) == 0x000802u);
    /* O_LARGEFILE|O_CREAT -> O_CREAT only. */
    CHECK(i686_oflags_g2h(0x0008040u) == 0x00040u);
    /* O_NONBLOCK|O_CREAT pass through. */
    CHECK(i686_oflags_g2h(0x0000840u) == 0x000840u);
    /* O_PATH|O_CLOEXEC pass through. */
    CHECK(i686_oflags_g2h(0x280000u) == 0x280000u);
    /* Unknown high bits masked. */
    CHECK(i686_oflags_g2h(0x80000000u) == 0u);
    /* h2g is the identity over the known mask. */
    CHECK(i686_oflags_h2g(0x000802u) == 0x000802u);
    CHECK(i686_oflags_h2g(0x008000u) == 0x008000u);
    /* F_SETFL keeps APPEND|NONBLOCK|DIRECT|NOATIME|FASYNC only. */
    CHECK(i686_setfl_to_host(0x0008800u) == 0x000800u);
    CHECK(i686_setfl_to_host(0x0002400u) == 0x0002400u);
    CHECK(i686_setfl_to_host(0x0004800u) == 0x0004800u);
}

static void t_fcntl_cmd(void)
{
    int fb = -1;

    CHECK(i686_fcntl_cmd_to_host(0u, 0, &fb) == 0 && fb == 0);   /* F_DUPFD */
    CHECK(i686_fcntl_cmd_to_host(1u, 0, &fb) == 1 && fb == 0);   /* F_GETFD */
    CHECK(i686_fcntl_cmd_to_host(4u, 0, &fb) == 4 && fb == 0);   /* F_SETFL */
    CHECK(i686_fcntl_cmd_to_host(1030u, 0, &fb) == 1030 && fb == 0);
    CHECK(i686_fcntl_cmd_to_host(5u, 0, &fb) == 5 && fb == 16);  /* F_GETLK */
    CHECK(i686_fcntl_cmd_to_host(7u, 1, &fb) == 7 && fb == 16);
    /* Plain fcntl(55) rejects the 64-bit and OFD cmds (kernel compat). */
    CHECK(i686_fcntl_cmd_to_host(12u, 0, &fb) == -1);
    CHECK(i686_fcntl_cmd_to_host(13u, 0, &fb) == -1);
    CHECK(i686_fcntl_cmd_to_host(36u, 0, &fb) == -1);
    /* fcntl64(221): *64 cmds map down to F_GETLK/SETLK/SETLKW with
     * 24-byte flock64; OFD cmds pass with 24 bytes. */
    CHECK(i686_fcntl_cmd_to_host(12u, 1, &fb) == 5 && fb == 24);
    CHECK(i686_fcntl_cmd_to_host(13u, 1, &fb) == 6 && fb == 24);
    CHECK(i686_fcntl_cmd_to_host(14u, 1, &fb) == 7 && fb == 24);
    CHECK(i686_fcntl_cmd_to_host(36u, 1, &fb) == 36 && fb == 24);
    CHECK(i686_fcntl_cmd_to_host(37u, 1, &fb) == 37 && fb == 24);
    CHECK(i686_fcntl_cmd_to_host(38u, 1, &fb) == 38 && fb == 24);
    CHECK(i686_fcntl_cmd_to_host(999u, 1, &fb) == -1);
}

/* ------------------------------------------------------------------ */
/* Handlers through the registry                                       */
/* ------------------------------------------------------------------ */

static void t_old_mmap(void)
{
    int64_t ret;

    reset();
    s_mm_calls = 0;
    /* addr=0 len=0x1000 prot=3 flags=FIXED|ANON|PRIVATE|MAP_32BIT(0x72)
     * fd=-1 offset=0x12345000 (pages). */
    w32(0x100, 0u);
    w32(0x104, 0x1000u);
    w32(0x108, 3u);
    w32(0x10c, 0x72u);
    w32(0x110, 0xFFFFFFFFu);
    w32(0x114, 0x12345000u);
    ctx.gpr[I686_REG_EBX] = 0x100;
    ret = i686_sys_dispatch(&ctx, 90);
    CHECK(ret == (int64_t)0x40000000u);
    CHECK(s_mm_calls == 1);
    CHECK(s_mm_len == 0x1000u && s_mm_prot == 3u);
    CHECK(s_mm_flags == 0x32u); /* MAP_32BIT stripped */
    CHECK(s_mm_fd == -1);
    CHECK(s_mm_pgoff == 0x12345u);

    /* Unaligned byte offset -> -EINVAL (kernel ia32_mmap). */
    w32(0x114, 0x12345001u);
    ret = i686_sys_dispatch(&ctx, 90);
    CHECK(ret == -EINVAL);

    /* Arg struct wrapping the window -> -EFAULT. */
    ctx.gpr[I686_REG_EBX] = 0xFFFFFFF8u;
    ret = i686_sys_dispatch(&ctx, 90);
    CHECK(ret == -EFAULT);
}

static void t_select(void)
{
    int64_t ret;

    /* old select(82): five-word struct {n, inp, outp, exp, tvp}; a
     * 200 ms timeout with no fds must come back with the remaining
     * time written into the guest timeval. */
    reset();
    w32(0x200, 1u);   /* n */
    w32(0x204, 0u);   /* inp */
    w32(0x208, 0u);   /* outp */
    w32(0x20c, 0u);   /* exp */
    w32(0x210, 0x300u); /* tvp */
    w32(0x300, 0u);   /* tv_sec */
    w32(0x304, 200000u); /* tv_usec */
    ctx.gpr[I686_REG_EBX] = 0x200;
    ret = i686_sys_dispatch(&ctx, 82);
    CHECK(ret == 0);
    CHECK(r32(0x300) == 0u);
    CHECK(r32(0x304) < 200000u); /* ~0 after the full wait */

    /* _newselect(142) with a zero timeout: immediate return, no
     * writeback (kernel "No update for zero timeout"). */
    reset();
    w32(0x300, 0u);
    w32(0x304, 0u);
    ctx.gpr[I686_REG_EBX] = 1; /* n */
    ctx.gpr[I686_REG_ECX] = 0;
    ctx.gpr[I686_REG_EDX] = 0;
    ctx.gpr[I686_REG_ESI] = 0;
    ctx.gpr[I686_REG_EDI] = 0x300;
    ret = i686_sys_dispatch(&ctx, 142);
    CHECK(ret == 0);

    /* Bad timeval (usec >= 1e6) -> -EINVAL before any host call. */
    w32(0x304, 1000000u);
    ret = i686_sys_dispatch(&ctx, 142);
    CHECK(ret == -EINVAL);

    /* Negative n -> -EINVAL. */
    ctx.gpr[I686_REG_EBX] = 0xFFFFFFFFu;
    ctx.gpr[I686_REG_EDI] = 0;
    ret = i686_sys_dispatch(&ctx, 142);
    CHECK(ret == -EINVAL);

    /* Timeout pointer wrapping the window -> -EFAULT. */
    reset();
    ctx.gpr[I686_REG_EBX] = 1;
    ctx.gpr[I686_REG_ECX] = 0;
    ctx.gpr[I686_REG_EDX] = 0;
    ctx.gpr[I686_REG_ESI] = 0;
    ctx.gpr[I686_REG_EDI] = 0xFFFFFFFCu;
    ret = i686_sys_dispatch(&ctx, 142);
    CHECK(ret == -EFAULT);
}

static void t_registration(void)
{
    /* fcntl(55) with an unknown cmd rejects before any host call. */
    reset();
    ctx.gpr[I686_REG_EBX] = 0;
    ctx.gpr[I686_REG_ECX] = 999u;
    ctx.gpr[I686_REG_EDX] = 0;
    CHECK(i686_sys_dispatch(&ctx, 55) == -EINVAL);

    /* fcntl64(221) F_GETLK64 on the plain entry path is invalid, and
     * getrlimit(76) validates the resource number. */
    ctx.gpr[I686_REG_ECX] = 12u;
    CHECK(i686_sys_dispatch(&ctx, 55) == -EINVAL);
    ctx.gpr[I686_REG_EBX] = 999u;
    CHECK(i686_sys_dispatch(&ctx, 76) == -EINVAL);
    CHECK(i686_sys_dispatch(&ctx, 191) == -EINVAL);
    CHECK(i686_sys_dispatch(&ctx, 75) == -EINVAL);
    /* prlimit64(340): resource rides in ECX (pid in EBX). */
    ctx.gpr[I686_REG_EBX] = 1u;
    ctx.gpr[I686_REG_ECX] = 999u;
    CHECK(i686_sys_dispatch(&ctx, 340) == -EINVAL);

    /* epoll_create(254) rejects non-positive size. */
    ctx.gpr[I686_REG_EBX] = 0u;
    CHECK(i686_sys_dispatch(&ctx, 254) == -EINVAL);
}

int main(void)
{
    reset();
    i686_syscalls_misc_init();

    t_fdset();
    t_epoll();
    t_flock();
    t_rlimit();
    t_sysinfo();
    t_oflags();
    t_fcntl_cmd();
    t_old_mmap();
    t_select();
    t_registration();

    if (g_fail != 0) {
        printf("L2E FAILED: %d check(s) failed (%d passed)\n", g_fail, g_pass);
        return 1;
    }
    printf("L2E OK\n");
    return 0;
}
