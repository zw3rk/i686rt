/*
 * tests/unit/test_l2d.c — host-native unit driver for lane L2d
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the factored pure converters of src/os/sys_time.c against a
 * fake guest window:
 *   - byte-exact host timespec64 -> guest i686_timespec_t (and the
 *     16-byte time64 image, which must NOT truncate),
 *   - the card-mandated year-2038 saturation of 32-bit tv_sec,
 *   - i686_itimerval_t pair conversion,
 *   - timex 32 <-> 64 field mapping (tai drop, pad zeroing, kernel-
 *     exact truncation of the time pair),
 *   - the clock_gettime store path with a fake injected host time,
 *   - registration + pointer-validation EFAULT paths for the whole
 *     registered set (host syscalls are compile-checked; the Linux-only
 *     adapters run on the lima/aarch64 hosts).
 *
 * TEST-ONLY mirrors of the two timex layouts are defined below with
 * their own static asserts (kernel uapi citations in sys_time.c); they
 * are deleted if the layouts ever move into a shared header.
 *
 * Prints "L2D OK" and exits 0 when every check passes.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

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

/* Fake guest window: guest_base + va lands inside this buffer
 * (little-endian host assumed — macOS arm64/x86_64). */
static uint8_t g_window[0x8000];
static i686_ctx_t ctx;

static void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
    memset(g_window, 0, sizeof g_window);
}

static void put_bytes(uint32_t va, const void *p, size_t n)
{
    memcpy(&g_window[va], p, n);
}

static uint32_t get_le32(uint32_t va)
{
    uint32_t v;

    memcpy(&v, &g_window[va], sizeof v);
    return v;
}

static uint64_t get_le64(uint32_t va)
{
    uint64_t v;

    memcpy(&v, &g_window[va], sizeof v);
    return v;
}

/* sys_time.c factored API (TEST-local declarations). */
void i686_time_ts_host_to_guest(const struct timespec *h, i686_timespec_t *g);
void i686_time_ts_guest_to_host(i686_timespec_t g, struct timespec *h);
void i686_time_tv_host_to_guest(const struct timeval *h, i686_timeval_t *g);
void i686_time_tv_guest_to_host(i686_timeval_t g, struct timeval *h);
void i686_time_itimerval_host_to_guest(const struct itimerval *h,
                                       i686_itimerval_t *g);
void i686_time_itimerval_guest_to_host(const i686_itimerval_t *g,
                                       struct itimerval *h);
int  i686_time_store_ts32(i686_ctx_t *c, uint32_t va, const struct timespec *h);
int  i686_time_fetch_ts32(i686_ctx_t *c, uint32_t va, struct timespec *h);
int  i686_time_store_ts64(i686_ctx_t *c, uint32_t va, const struct timespec *h);
int  i686_time_fetch_ts64(i686_ctx_t *c, uint32_t va, struct timespec *h);
int  i686_time_store_tv32(i686_ctx_t *c, uint32_t va, const struct timeval *h);
int  i686_time_store_itimerval(i686_ctx_t *c, uint32_t va,
                               const struct itimerval *h);
int  i686_time_fetch_itimerval(i686_ctx_t *c, uint32_t va, struct itimerval *h);
int  i686_time_store_timex32(i686_ctx_t *c, uint32_t va,
                             const void *host_timex_bytes);
int  i686_time_fetch_timex32(i686_ctx_t *c, uint32_t va,
                             void *host_timex_bytes);

/* ------------------------------------------------------------------ */
/* TEST-ONLY timex layout mirrors (uapi/linux/timex.h; see sys_time.c) */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t modes;     /*  0 */
    int32_t  offset;    /*  4 */
    int32_t  freq;      /*  8 */
    int32_t  maxerror;  /* 12 */
    int32_t  esterror;  /* 16 */
    int32_t  status;    /* 20 */
    int32_t  constant;  /* 24 */
    int32_t  precision; /* 28 */
    int32_t  tolerance; /* 32 */
    int32_t  time_sec;  /* 36 */
    int32_t  time_usec; /* 40 */
    int32_t  tick;      /* 44 */
    int32_t  ppsfreq;   /* 48 */
    int32_t  jitter;    /* 52 */
    int32_t  shift;     /* 56 */
    int32_t  stabil;    /* 60 */
    int32_t  jitcnt;    /* 64 */
    int32_t  calcnt;    /* 68 */
    int32_t  errcnt;    /* 72 */
    int32_t  stbcnt;    /* 76 */
    int32_t  tai;       /* 80 */
    uint32_t __pad[11]; /* 84 */
} t_timex32_t;

typedef struct {
    uint32_t modes;     /*   0 */
    uint32_t __pad0;    /*   4 */
    int64_t  offset;    /*   8 */
    int64_t  freq;      /*  16 */
    int64_t  maxerror;  /*  24 */
    int64_t  esterror;  /*  32 */
    int32_t  status;    /*  40 */
    uint32_t __pad1;    /*  44 */
    int64_t  constant;  /*  48 */
    int64_t  precision; /*  56 */
    int64_t  tolerance; /*  64 */
    int64_t  time_sec;  /*  72 */
    int64_t  time_usec; /*  80 */
    int64_t  tick;      /*  88 */
    int64_t  ppsfreq;   /*  96 */
    int64_t  jitter;    /* 104 */
    int32_t  shift;     /* 112 */
    uint32_t __pad2;    /* 116 */
    int64_t  stabil;    /* 120 */
    int64_t  jitcnt;    /* 128 */
    int64_t  calcnt;    /* 136 */
    int64_t  errcnt;    /* 144 */
    int64_t  stbcnt;    /* 152 */
    int32_t  tai;       /* 160 */
    uint32_t __pad[11]; /* 164 */
} t_timex64_t;

_Static_assert(sizeof(t_timex32_t) == 128, "mirror timex32 must be 128 bytes");
_Static_assert(sizeof(t_timex64_t) == 208, "mirror __kernel_timex must be 208");
_Static_assert(offsetof(t_timex64_t, offset) == 8, "mirror offset @8");
_Static_assert(offsetof(t_timex64_t, time_sec) == 72, "mirror time @72");
_Static_assert(offsetof(t_timex64_t, tai) == 160, "mirror tai @160");

/* ------------------------------------------------------------------ */
/* Registration + EFAULT pointer validation                            */
/* ------------------------------------------------------------------ */

/* Every registered handler must reject a wrapping guest pointer with
 * -EFAULT at the fetch stage (before any host call), proving both the
 * registration and the layering deterministically on every host. */
static int64_t disp(long nr, uint32_t ebx, uint32_t ecx, uint32_t edx,
                    uint32_t esi)
{
    reset();
    ctx.gpr[I686_REG_EBX] = ebx;
    ctx.gpr[I686_REG_ECX] = ecx;
    ctx.gpr[I686_REG_EDX] = edx;
    ctx.gpr[I686_REG_ESI] = esi;
    return i686_sys_dispatch(&ctx, nr);
}

static void t_registration(void)
{
    /* nrs from src/os/syscalls_i386.h rows (see sys_time.c macros). */
    CHECK(disp(13,  0xFFFFFFFEU, 0, 0, 0) == -14);  /* time tloc wraps */
    CHECK(disp(25,  0xFFFFFFFEU, 0, 0, 0) == -14);  /* stime tptr */
    CHECK(disp(27,  0, 0, 0, 0) == 0);              /* alarm(0) */
    CHECK(disp(78,  0xFFFFFFFDU, 0, 0, 0) == -14);  /* gettimeofday tv */
    CHECK(disp(79,  0xFFFFFFFDU, 0, 0, 0) == -14);  /* settimeofday tv */
    CHECK(disp(104, 0, 0xFFFFFFFEU, 0, 0) == -14);  /* setitimer new */
    CHECK(disp(105, 0, 0xFFFFFFFAU, 0, 0) == -14);  /* getitimer val */
    CHECK(disp(124, 0xFFFFFF81U, 0, 0, 0) == -14);  /* adjtimex utx */
    CHECK(disp(162, 0xFFFFFFFBU, 0, 0, 0) == -14);  /* nanosleep req */
    CHECK(disp(264, 0, 0xFFFFFFFAU, 0, 0) == -14);  /* clock_settime tp */
    CHECK(disp(265, 0, 0xFFFFFFFAU, 0, 0) == -14);  /* clock_gettime tp */
    CHECK(disp(266, 0, 0xFFFFFFFAU, 0, 0) == -14);  /* clock_getres tp */
    CHECK(disp(267, 0, 0, 0xFFFFFFFBU, 0) == -14);  /* clock_nanosleep req */
    CHECK(disp(403, 0, 0xFFFFFFF2U, 0, 0) == -14);  /* clock_gettime64 tp */
    CHECK(disp(404, 0, 0xFFFFFFF2U, 0, 0) == -14);  /* clock_settime64 tp */
    CHECK(disp(405, 0, 0xFFFFFF31U, 0, 0) == -14);  /* clock_adjtime64 utx */
    CHECK(disp(406, 0, 0xFFFFFFF2U, 0, 0) == -14);  /* clock_getres_time64 */
    CHECK(disp(407, 0, 0, 0xFFFFFFF2U, 0) == -14);  /* clock_nanosleep_time64 */

    /* NULL tolerance that the kernel allows: gettimeofday(tv=NULL,
     * tz=NULL) returns success without touching the window. */
    CHECK(disp(78, 0, 0, 0, 0) == 0);
    /* Low-guard non-NULL pointers are EFAULT, not NULL. */
    CHECK(disp(78, 1, 0, 0, 0) == -14);
    /* Unregistered neighbour nr stays -ENOSYS. */
    CHECK(disp(43, 0, 0, 0, 0) == -38);
}

/* ------------------------------------------------------------------ */
/* timespec/timeval conversion byte-exactness + saturation             */
/* ------------------------------------------------------------------ */

static void t_ts32_convert(void)
{
    i686_timespec_t g;
    struct timespec h;

    /* Exact values pass through unchanged. */
    h.tv_sec = 1700000000;
    h.tv_nsec = 123456789;
    i686_time_ts_host_to_guest(&h, &g);
    CHECK(g.tv_sec == 1700000000 && g.tv_nsec == 123456789);

    /* Year-2038 saturation: INT32_MAX cap (card L2d). */
    h.tv_sec = (time_t)0x80000000LL;
    i686_time_ts_host_to_guest(&h, &g);
    CHECK(g.tv_sec == INT32_MAX);

    h.tv_sec = (time_t)0x7FFFFFFFFFFFFFFFLL;
    i686_time_ts_host_to_guest(&h, &g);
    CHECK(g.tv_sec == INT32_MAX);
    CHECK(g.tv_nsec == 123456789); /* untouched by the clamp */

    /* INT32_MIN floor and in-range negatives. */
    h.tv_sec = (time_t)-0x80000001LL;
    i686_time_ts_host_to_guest(&h, &g);
    CHECK(g.tv_sec == INT32_MIN);

    h.tv_sec = -1;
    i686_time_ts_host_to_guest(&h, &g);
    CHECK(g.tv_sec == -1);

    /* Guest -> host widening is exact. */
    g.tv_sec = INT32_MIN;
    g.tv_nsec = 5;
    i686_time_ts_guest_to_host(g, &h);
    CHECK((int64_t)h.tv_sec == -2147483648LL && h.tv_nsec == 5);
}

static void t_ts32_store_fetch(void)
{
    struct timespec h;

    /* Byte-exact store: 0x6553F100 s / 0x3B9AC9FF ns little-endian. */
    reset();
    h.tv_sec = 0x6553F100LL;
    h.tv_nsec = 0x3B9AC9FFL;
    CHECK(i686_time_store_ts32(&ctx, 0x100, &h) == 0);
    CHECK(get_le32(0x100) == 0x6553F100U);
    CHECK(get_le32(0x104) == 0x3B9AC9FFU);

    /* Saturated store writes the exact clamped byte pattern. */
    h.tv_sec = (time_t)0x100000000LL;
    CHECK(i686_time_store_ts32(&ctx, 0x100, &h) == 0);
    CHECK(get_le32(0x100) == 0x7FFFFFFFU);

    /* Fetch round-trips through the window. */
    h.tv_sec = -7;
    h.tv_nsec = 42;
    CHECK(i686_time_store_ts32(&ctx, 0x200, &h) == 0);
    {
        struct timespec out;

        CHECK(i686_time_fetch_ts32(&ctx, 0x200, &out) == 0);
        CHECK((int64_t)out.tv_sec == -7 && out.tv_nsec == 42);
    }

    /* Wrap-around va is rejected by the marshal bounds check. */
    CHECK(i686_time_store_ts32(&ctx, 0xFFFFFFFCU, &h) == -14);
    CHECK(i686_time_fetch_ts32(&ctx, 0xFFFFFFFCU, &h) == -14);
}

static void t_ts64_store_fetch(void)
{
    struct timespec h;

    /* time64: full 64-bit seconds, no truncation. */
    reset();
    h.tv_sec = (time_t)0x0123456789ABCLL;
    h.tv_nsec = 987654321L;
    CHECK(i686_time_store_ts64(&ctx, 0x100, &h) == 0);
    CHECK(get_le64(0x100) == 0x0123456789ABCLL);
    CHECK(get_le64(0x108) == 987654321ULL);

    /* INT64_MAX survives; nothing saturates on the 64-bit path. */
    h.tv_sec = (time_t)0x7FFFFFFFFFFFFFFFLL;
    CHECK(i686_time_store_ts64(&ctx, 0x120, &h) == 0);
    CHECK(get_le64(0x120) == 0x7FFFFFFFFFFFFFFFULL);

    {
        struct timespec out;

        CHECK(i686_time_fetch_ts64(&ctx, 0x100, &out) == 0);
        CHECK((uint64_t)out.tv_sec == 0x0123456789ABCLL &&
              out.tv_nsec == 987654321L);
    }
    CHECK(i686_time_store_ts64(&ctx, 0xFFFFFFF8U, &h) == -14);
}

static void t_timeval_itimerval(void)
{
    struct timeval h;
    i686_timeval_t g;

    h.tv_sec = 1700000000;
    h.tv_usec = 123456;
    i686_time_tv_host_to_guest(&h, &g);
    CHECK(g.tv_sec == 1700000000 && g.tv_usec == 123456);

    h.tv_sec = (time_t)0x80000000LL;
    i686_time_tv_host_to_guest(&h, &g);
    CHECK(g.tv_sec == INT32_MAX);

    h.tv_sec = (time_t)-0x80000001LL;
    i686_time_tv_host_to_guest(&h, &g);
    CHECK(g.tv_sec == INT32_MIN);

    i686_time_tv_guest_to_host(g, &h);
    CHECK((int64_t)h.tv_sec == -2147483648LL && h.tv_usec == 123456);

    /* itimerval pair, both members, byte-exact into the window. */
    reset();
    {
        struct itimerval hi;
        i686_itimerval_t gi;

        hi.it_interval.tv_sec = 2;
        hi.it_interval.tv_usec = 200;
        hi.it_value.tv_sec = 3;
        hi.it_value.tv_usec = 300;
        CHECK(i686_time_store_itimerval(&ctx, 0x100, &hi) == 0);
        CHECK(get_le32(0x100) == 2U && get_le32(0x104) == 200U);
        CHECK(get_le32(0x108) == 3U && get_le32(0x10C) == 300U);

        CHECK(i686_time_fetch_itimerval(&ctx, 0x100, &hi) == 0);
        CHECK(hi.it_interval.tv_sec == 2 && hi.it_interval.tv_usec == 200);
        CHECK(hi.it_value.tv_sec == 3 && hi.it_value.tv_usec == 300);

        /* Saturation applies per member: interval sec clamped, value
         * usec untouched. */
        hi.it_interval.tv_sec = (time_t)0x100000000LL;
        hi.it_interval.tv_usec = 999999;
        hi.it_value.tv_sec = 0;
        hi.it_value.tv_usec = 1;
        i686_time_itimerval_host_to_guest(&hi, &gi);
        CHECK(gi.it_interval.tv_sec == INT32_MAX);
        CHECK(gi.it_interval.tv_usec == 999999);
        CHECK(gi.it_value.tv_sec == 0 && gi.it_value.tv_usec == 1);
    }
}

/* ------------------------------------------------------------------ */
/* timex 32 <-> 64 field mapping                                       */
/* ------------------------------------------------------------------ */

static void t_timex_map(void)
{
    t_timex64_t h64;
    t_timex32_t h32;

    /* host -> guest: every field truncated into a zeroed 128-byte
     * image; junk host tail pads must not leak into the guest. */
    memset(&h64, 0xDD, sizeof h64);
    h64.modes = 0x8011U;
    h64.offset = -1200;
    h64.freq = 0x00010000LL;
    h64.maxerror = 16000000;
    h64.esterror = 1600;
    h64.status = 0x245;
    h64.constant = 10;
    h64.precision = 1;
    h64.tolerance = 32768000;
    h64.time_sec = 0x100000000LL; /* kernel-exact truncation -> 0 */
    h64.time_usec = 500000;
    h64.tick = 10000;
    h64.ppsfreq = 0x2000;
    h64.jitter = 3;
    h64.shift = 2;
    h64.stabil = 0x120;
    h64.jitcnt = 4;
    h64.calcnt = 5;
    h64.errcnt = 6;
    h64.stbcnt = 7;
    h64.tai = 37;

    reset();
    CHECK(i686_time_store_timex32(&ctx, 0x300, &h64) == 0);

    memset(&h32, 0, sizeof h32);
    h32.modes = 0x8011U;
    h32.offset = -1200;
    h32.freq = 0x00010000;
    h32.maxerror = 16000000;
    h32.esterror = 1600;
    h32.status = 0x245;
    h32.constant = 10;
    h32.precision = 1;
    h32.tolerance = 32768000;
    h32.time_sec = 0; /* 0x100000000 truncated (put_old_timex32) */
    h32.time_usec = 500000;
    h32.tick = 10000;
    h32.ppsfreq = 0x2000;
    h32.jitter = 3;
    h32.shift = 2;
    h32.stabil = 0x120;
    h32.jitcnt = 4;
    h32.calcnt = 5;
    h32.errcnt = 6;
    h32.stbcnt = 7;
    h32.tai = 37;
    CHECK(memcmp(&g_window[0x300], &h32, sizeof h32) == 0);

    /* guest -> host: sign-extended copies, tai dropped, pads zeroed. */
    memset(&h32, 0, sizeof h32);
    h32.modes = 0x0001U;
    h32.offset = -500;
    h32.freq = -100;
    h32.maxerror = 1;
    h32.esterror = 2;
    h32.status = 0x11;
    h32.constant = 7;
    h32.precision = 3;
    h32.tolerance = 4;
    h32.time_sec = 1234567890;
    h32.time_usec = 42;
    h32.tick = 10000;
    h32.ppsfreq = 5;
    h32.jitter = 6;
    h32.shift = 1;
    h32.stabil = 7;
    h32.jitcnt = 8;
    h32.calcnt = 9;
    h32.errcnt = 10;
    h32.stbcnt = 11;
    h32.tai = 0x55; /* must NOT reach the host image */
    h32.__pad[3] = 0xDEADBEEF;

    put_bytes(0x340, &h32, sizeof h32);
    memset(&h64, 0xEE, sizeof h64);
    CHECK(i686_time_fetch_timex32(&ctx, 0x340, &h64) == 0);

    CHECK(h64.modes == 0x0001U);
    CHECK(h64.offset == -500);
    CHECK(h64.freq == -100);
    CHECK(h64.maxerror == 1);
    CHECK(h64.esterror == 2);
    CHECK(h64.status == 0x11);
    CHECK(h64.constant == 7);
    CHECK(h64.precision == 3);
    CHECK(h64.tolerance == 4);
    CHECK(h64.time_sec == 1234567890LL);
    CHECK(h64.time_usec == 42LL);
    CHECK(h64.tick == 10000LL);
    CHECK(h64.ppsfreq == 5LL);
    CHECK(h64.jitter == 6LL);
    CHECK(h64.shift == 1);
    CHECK(h64.stabil == 7LL);
    CHECK(h64.jitcnt == 8LL);
    CHECK(h64.calcnt == 9LL);
    CHECK(h64.errcnt == 10LL);
    CHECK(h64.stbcnt == 11LL);
    CHECK(h64.tai == 0); /* dropped like get_old_timex32 */
    CHECK(h64.__pad0 == 0 && h64.__pad1 == 0 && h64.__pad2 == 0);
    for (size_t i = 0; i < 11; i++) {
        CHECK(h64.__pad[i] == 0);
    }

    /* Wrap-around va (va + 128 strictly beyond the 4 GiB window). */
    CHECK(i686_time_store_timex32(&ctx, 0xFFFFFF81U, &h64) == -14);
    CHECK(i686_time_fetch_timex32(&ctx, 0xFFFFFF81U, &h64) == -14);
}

/* ------------------------------------------------------------------ */
/* clock_gettime path with fake injected host time                     */
/* ------------------------------------------------------------------ */

static void t_clock_gettime_path(void)
{
    struct timespec fake;

    /* The factored store step of clock_gettime(265): inject a fake
     * host time; the window must hold the exact guest bytes. */
    reset();
    fake.tv_sec = 0x6553F100LL; /* 2015-11-14T22:13:20Z */
    fake.tv_nsec = 1L;
    CHECK(i686_time_store_ts32(&ctx, 0x400, &fake) == 0);
    CHECK(get_le32(0x400) == 0x6553F100U);
    CHECK(get_le32(0x404) == 1U);

    /* ... and the time64 variant of the same step keeps 64-bit secs. */
    CHECK(i686_time_store_ts64(&ctx, 0x410, &fake) == 0);
    CHECK(get_le64(0x410) == 0x6553F100ULL);

    /* Live sanity (host-agnostic clocks): CLOCK_MONOTONIC read
     * succeeds with an in-range nsec; the guest bytes then decode
     * back consistently.  (Handler vas must clear the 0x1000 low
     * guard, like syscalls.c's read/write.) */
    {
        int64_t r = disp(265, CLOCK_MONOTONIC, 0x1420, 0, 0);

        CHECK(r == 0);
        CHECK(get_le32(0x1424) < 1000000000U);
        CHECK((int64_t)(int32_t)get_le32(0x1420) >= 0);
    }
    {
        int64_t r = disp(403, CLOCK_MONOTONIC, 0x1430, 0, 0);

        CHECK(r == 0);
        CHECK(get_le64(0x1438) < 1000000000ULL);
        CHECK((int64_t)get_le64(0x1430) >= 0);
    }
}

/* ------------------------------------------------------------------ */
/* Live host-clock syscalls that work on every build host              */
/* ------------------------------------------------------------------ */

static void t_live_misc(void)
{
    /* time(13) with NULL tloc: truncated seconds, ~now. */
    {
        int64_t r = disp(13, 0, 0, 0, 0);
        int32_t now = (int32_t)time(NULL);

        CHECK(r >= 0);
        CHECK((int64_t)((int32_t)r - now) <= 1 && (int32_t)r - now >= -1);
    }

    /* time(13) with tloc: stored seconds equal the return value. */
    {
        int64_t r = disp(13, 0x1500, 0, 0, 0);
        uint32_t stored = get_le32(0x1500);

        CHECK(r >= 0);
        CHECK(stored == (uint32_t)r);
    }

    /* gettimeofday(78): usec in range, seconds ~now, sane tz. */
    {
        int64_t r = disp(78, 0x1510, 0x1520, 0, 0);
        int32_t now = (int32_t)time(NULL);

        CHECK(r == 0);
        CHECK(get_le32(0x1514) < 1000000U);
        CHECK((int32_t)get_le32(0x1510) - now >= -1);
        CHECK((int32_t)get_le32(0x1510) - now <= 1);
        CHECK((int32_t)get_le32(0x1520) >= -1440); /* tz_minuteswest */
        CHECK((int32_t)get_le32(0x1520) <= 1440);
    }

    /* nanosleep(162) of 0s returns immediately. */
    {
        i686_timespec_t g;

        g.tv_sec = 0;
        g.tv_nsec = 0;
        reset();
        put_bytes(0x1530, &g, sizeof g);
        ctx.gpr[I686_REG_EBX] = 0x1530;
        CHECK(i686_sys_dispatch(&ctx, 162) == 0);
    }

    /* clock_getres(266) on CLOCK_MONOTONIC: sub-second resolution. */
    {
        int64_t r = disp(266, CLOCK_MONOTONIC, 0x1540, 0, 0);

        CHECK(r == 0);
        CHECK(get_le32(0x1540) == 0);
        CHECK(get_le32(0x1544) < 1000000000U);
    }

    /* getitimer(105)/setitimer(104) query on a fresh process: the
     * whole 16-byte guest itimerval stays zero. */
    {
        int64_t r = disp(105, 0, 0x1550, 0, 0);

        CHECK(r == 0);
        CHECK(get_le32(0x1550) == 0 && get_le32(0x1554) == 0);
        CHECK(get_le32(0x1558) == 0 && get_le32(0x155C) == 0);

        r = disp(104, 0, 0, 0x1560, 0); /* new = NULL: pure query */
        CHECK(r == 0);
        CHECK(get_le32(0x1560) == 0 && get_le32(0x1564) == 0);
        CHECK(get_le32(0x1568) == 0 && get_le32(0x156C) == 0);
    }
}

int main(void)
{
    reset();
    i686_syscalls_time_init();

    t_registration();
    t_ts32_convert();
    t_ts32_store_fetch();
    t_ts64_store_fetch();
    t_timeval_itimerval();
    t_timex_map();
    t_clock_gettime_path();
    t_live_misc();

    if (g_fail != 0) {
        printf("L2D FAILED: %d check(s) failed (%d passed)\n", g_fail, g_pass);
        return 1;
    }
    printf("L2D OK\n");
    return 0;
}
