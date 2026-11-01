/*
 * src/os/sys_time.c — time32/time64 syscall marshalling (Phase 2, lane L2d)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the i386 time syscall set against native 64-bit Linux host
 * calls (kernel v6.1 uapi citations inline):
 *
 *   time32 set (32-bit timespec/timeval/timex):
 *     time(13), stime(25), alarm(27), gettimeofday(78), settimeofday(79),
 *     setitimer(104), getitimer(105), adjtimex(124), nanosleep(162),
 *     clock_settime(264), clock_gettime(265), clock_getres(266),
 *     clock_nanosleep(267)
 *   time64 set (nr >= 403, __kernel_timespec / __kernel_timex layouts):
 *     clock_gettime64(403), clock_settime64(404), clock_adjtime64(405),
 *     clock_getres_time64(406), clock_nanosleep_time64(407)
 *
 * clockid_t values are ABI-identical i386 <-> aarch64
 * (include/uapi/linux/time.h:49-62: CLOCK_REALTIME=0 .. CLOCK_TAI=11;
 * ITIMER_* at :42-44), so clock ids and TIMER_ABSTIME (= 1) pass through
 * untranslated.  The i386 table maps 403-407 to the native 64-bit
 * implementations (arch/x86/entry/syscalls/syscall_32.tbl:411-415), e.g.
 * 405 -> sys_clock_adjtime taking struct __kernel_timex.
 *
 * Year-2038 policy (card L2d): host 64-bit seconds stored into a guest
 * i686_timespec_t/i686_timeval_t SATURATE at INT32_MAX (floored at
 * INT32_MIN), while the raw kernel compat path (put_old_timespec32,
 * include/linux/time32.h) silently truncates; the lane card pins the
 * saturating behaviour.  Two spots stay kernel-exact instead: time(13)
 * returns/stores the truncated second count exactly like sys_time32
 * (kernel/time/time.c), and the timex time pair truncates exactly like
 * put_old_timex32 (kernel/time/time.c:318-347) so adjtimex consumers
 * (ntpd) see kernel-identical field semantics.  The time64 syscalls
 * store full 64-bit seconds — no truncation, that is their purpose.
 *
 * Host calls that exist on every build host (time, alarm, nanosleep,
 * clock_gettime/getres/settime, *itimer) go through libc directly.
 * Linux-only behind __linux__ + raw syscall(2) (musl/glibc hide
 * syscall(2) and struct timezone under strict POSIX feature macros,
 * musl's gettimeofday ignores tz, aarch64 has no stime(2), and darwin
 * lacks clock_nanosleep entirely): gettimeofday, stime (via
 * clock_settime, like the i386 compat handler), settimeofday, adjtimex,
 * clock_adjtime64, clock_nanosleep.  Off Linux (unit-test host) those
 * return -ENOSYS after the guest fetch stage, which keeps the
 * marshalling path test-covered and compile-checked.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "i686rt.h"
#include "os/marshal.h"
#include "os/structs_i386.h"
#include "os/syscalls_i386.h"

#if defined(__linux__)
#include <sys/syscall.h>
/* syscall(2) is not POSIX; musl/glibc hide it without _DEFAULT_SOURCE. */
extern long syscall(long, ...);
#endif

/* Guest errno values (host-OS independent; same scheme as marshal.c's
 * I686_EFAULT copy).  Linux generic errno ABI, identical i386/aarch64. */
#define I686_EFAULT 14
#define I686_ENOSYS 38

/* TIMER_ABSTIME: include/uapi/linux/time.h (== 1 everywhere). */
#define I686_TIMER_ABSTIME 1

/* Syscall numbers: the generated table only #defines the Phase 1 smoke
 * set, so this module pins its own names to the table rows (values are
 * citations from src/os/syscalls_i386.h, not re-derived). */
#define I686__NR_time                  13U /* [13]  syscalls_i386.h:35  */
#define I686__NR_stime                 25U /* [25]  syscalls_i386.h:47  */
#define I686__NR_alarm                 27U /* [27]  syscalls_i386.h:49  */
#define I686__NR_gettimeofday          78U /* [78]  syscalls_i386.h:100 */
#define I686__NR_settimeofday          79U /* [79]  syscalls_i386.h:101 */
#define I686__NR_setitimer            104U /* [104] syscalls_i386.h:126 */
#define I686__NR_getitimer            105U /* [105] syscalls_i386.h:127 */
#define I686__NR_adjtimex             124U /* [124] syscalls_i386.h:146 */
#define I686__NR_nanosleep            162U /* [162] syscalls_i386.h:199 */
#define I686__NR_clock_settime        264U /* [264] syscalls_i386.h:283 */
#define I686__NR_clock_gettime        265U /* [265] syscalls_i386.h:284 */
#define I686__NR_clock_getres         266U /* [266] syscalls_i386.h:285 */
#define I686__NR_clock_nanosleep      267U /* [267] syscalls_i386.h:286 */
#define I686__NR_clock_gettime64      403U /* [403] syscalls_i386.h:415 */
#define I686__NR_clock_settime64      404U /* [404] syscalls_i386.h:416 */
#define I686__NR_clock_adjtime64      405U /* [405] syscalls_i386.h:417 */
#define I686__NR_clock_getres_time64  406U /* [406] syscalls_i386.h:418 */
#define I686__NR_clock_nanosleep_time64 407U /* [407] syscalls_i386.h:419 */

/*
 * Guest timex layouts, defined locally per kernel uapi (the frozen
 * structs header intentionally omits them, like the L2c ipc64 structs).
 *
 * i686_timex32_t: struct timex as compiled for i386 —
 * include/uapi/linux/timex.h:65-94 with __kernel_long_t = 32 bits and
 * the old 32-bit timeval, i.e. every field 4 bytes (uapi tail padding
 * ":32 x11" at :91-93), 128 bytes total.  This is the kernel's
 * struct old_timex32 (kernel/time/time.c:286) used by adjtimex(124).
 */
typedef struct {
    uint32_t modes;     /*  0  uapi timex.h:66 */
    int32_t  offset;    /*  4  :67 */
    int32_t  freq;      /*  8  :68 */
    int32_t  maxerror;  /* 12  :69 */
    int32_t  esterror;  /* 16  :70 */
    int32_t  status;    /* 20  :71 */
    int32_t  constant;  /* 24  :72 */
    int32_t  precision; /* 28  :73 */
    int32_t  tolerance; /* 32  :74 */
    int32_t  time_sec;  /* 36  :77 struct timeval (i386: 2 x s32) */
    int32_t  time_usec; /* 40  :77 */
    int32_t  tick;      /* 44  :78 */
    int32_t  ppsfreq;   /* 48  :80 */
    int32_t  jitter;    /* 52  :81 */
    int32_t  shift;     /* 56  :82 */
    int32_t  stabil;    /* 60  :83 */
    int32_t  jitcnt;    /* 64  :84 */
    int32_t  calcnt;    /* 68  :85 */
    int32_t  errcnt;    /* 72  :86 */
    int32_t  stbcnt;    /* 76  :87 */
    int32_t  tai;       /* 80  :89 */
    uint32_t __pad[11]; /* 84  :91-93 (uapi tail padding) */
} i686_timex32_t;

/*
 * i686_timex64_t: struct __kernel_timex —
 * include/uapi/linux/timex.h:102-134 (explicit `int :32` pads after
 * modes/status/shift make the long long layout identical on i386 and
 * aarch64), with __kernel_timex_timeval (:97-100) inlined.  208 bytes.
 * This is what adjtimex/clock_adjtime exchange with the 64-bit kernel
 * (aarch64 libc `struct timex` has the same layout) and what i386
 * passes to clock_adjtime64(405).
 */
typedef struct {
    uint32_t modes;     /*   0  uapi timex.h:103 */
    uint32_t __pad0;    /*   4  :104 int :32 */
    int64_t  offset;    /*   8  :105 */
    int64_t  freq;      /*  16  :106 */
    int64_t  maxerror;  /*  24  :107 */
    int64_t  esterror;  /*  32  :108 */
    int32_t  status;    /*  40  :109 */
    uint32_t __pad1;    /*  44  :110 int :32 */
    int64_t  constant;  /*  48  :111 */
    int64_t  precision; /*  56  :112 */
    int64_t  tolerance; /*  64  :113 */
    int64_t  time_sec;  /*  72  :116 struct __kernel_timex_timeval */
    int64_t  time_usec; /*  80  :116 */
    int64_t  tick;      /*  88  :117 */
    int64_t  ppsfreq;   /*  96  :119 */
    int64_t  jitter;    /* 104  :120 */
    int32_t  shift;     /* 112  :121 */
    uint32_t __pad2;    /* 116  :122 int :32 */
    int64_t  stabil;    /* 120  :123 */
    int64_t  jitcnt;    /* 128  :124 */
    int64_t  calcnt;    /* 136  :125 */
    int64_t  errcnt;    /* 144  :126 */
    int64_t  stbcnt;    /* 152  :127 */
    int32_t  tai;       /* 160  :129 */
    uint32_t __pad[11]; /* 164  :131-133 */
} i686_timex64_t;

_Static_assert(sizeof(i686_timex32_t) == 128, "i686 timex32 must be 128 bytes");
_Static_assert(sizeof(i686_timex64_t) == 208, "__kernel_timex must be 208 bytes");
_Static_assert(offsetof(i686_timex64_t, offset) == 8, "__kernel_timex offset @8");
_Static_assert(offsetof(i686_timex64_t, constant) == 48, "__kernel_timex constant @48");
_Static_assert(offsetof(i686_timex64_t, time_sec) == 72, "__kernel_timex time @72");
_Static_assert(offsetof(i686_timex64_t, time_usec) == 80, "__kernel_timex time.tv_usec @80");
_Static_assert(offsetof(i686_timex64_t, stabil) == 120, "__kernel_timex stabil @120");
_Static_assert(offsetof(i686_timex64_t, tai) == 160, "__kernel_timex tai @160");

/* struct timezone: { int tz_minuteswest; int tz_dsttime; } — 8 bytes,
 * identical guest/host layout (include/uapi/linux/time.h:33-36). */
typedef struct {
    int32_t tz_minuteswest; /* 0 */
    int32_t tz_dsttime;     /* 4 */
} i686_timezone_t;

_Static_assert(sizeof(i686_timezone_t) == 8, "struct timezone must be 8 bytes");

/* Host timespec view for the 16-byte __kernel_timespec (time64 set):
 * { s64 tv_sec @0, s64 tv_nsec @8 } — byte-identical to the aarch64
 * (and LP64 host) struct timespec; converted field-wise anyway so the
 * module never depends on host struct timeval packing (darwin packs
 * tv_usec as 4 bytes). */
typedef struct {
    int64_t sec;
    int64_t nsec;
} i686_ts64_t;

/* ------------------------------------------------------------------ */
/* Factored pure converters (external linkage: unit-test surface)      */
/* ------------------------------------------------------------------ */

/*
 * Saturate host 64-bit seconds into the guest 32-bit second fields
 * (card L2d: INT32_MAX cap = year-2038 saturation; INT32_MIN floor for
 * symmetric pre-1901 clamping; the raw kernel compat code truncates).
 */
static int32_t sec32_saturate(int64_t s)
{
    if (s > (int64_t)INT32_MAX) {
        return INT32_MAX;
    }
    if (s < (int64_t)INT32_MIN) {
        return INT32_MIN;
    }
    return (int32_t)s;
}

/* Host struct timespec -> guest i686_timespec_t (saturation policy). */
void i686_time_ts_host_to_guest(const struct timespec *h, i686_timespec_t *g)
{
    g->tv_sec  = sec32_saturate((int64_t)h->tv_sec);
    g->tv_nsec = (int32_t)h->tv_nsec; /* valid range [0, 999999999] fits */
}

/* Guest i686_timespec_t -> host struct timespec (widening; the host
 * syscall validates tv_nsec exactly like the kernel would). */
void i686_time_ts_guest_to_host(i686_timespec_t g, struct timespec *h)
{
    h->tv_sec  = (time_t)(int64_t)g.tv_sec;
    h->tv_nsec = (long)g.tv_nsec;
}

/* Host struct timeval -> guest i686_timeval_t (saturation policy). */
void i686_time_tv_host_to_guest(const struct timeval *h, i686_timeval_t *g)
{
    g->tv_sec  = sec32_saturate((int64_t)h->tv_sec);
    g->tv_usec = (int32_t)h->tv_usec; /* [0, 999999] fits */
}

/* Guest i686_timeval_t -> host struct timeval. */
void i686_time_tv_guest_to_host(i686_timeval_t g, struct timeval *h)
{
    h->tv_sec  = (time_t)(int64_t)g.tv_sec;
    h->tv_usec = (suseconds_t)g.tv_usec;
}

/* i686_itimerval_t <-> host struct itimerval (both members converted). */
void i686_time_itimerval_host_to_guest(const struct itimerval *h, i686_itimerval_t *g)
{
    i686_time_tv_host_to_guest(&h->it_interval, &g->it_interval);
    i686_time_tv_host_to_guest(&h->it_value, &g->it_value);
}

void i686_time_itimerval_guest_to_host(const i686_itimerval_t *g, struct itimerval *h)
{
    i686_time_tv_guest_to_host(g->it_interval, &h->it_interval);
    i686_time_tv_guest_to_host(g->it_value, &h->it_value);
}

/*
 * timex32 -> __kernel_timex, mirroring get_old_timex32
 * (kernel/time/time.c:286-316): sign-extended field copies; the guest
 * tai field is NOT copied (kernel reads it only via ADJ_TAI mode
 * handling) and the host tail pads are zeroed.
 */
void i686_time_timex_guest32_to_host(const i686_timex32_t *g, i686_timex64_t *h)
{
    memset(h, 0, sizeof(*h));
    h->modes     = g->modes;
    h->offset    = (int64_t)g->offset;
    h->freq      = (int64_t)g->freq;
    h->maxerror  = (int64_t)g->maxerror;
    h->esterror  = (int64_t)g->esterror;
    h->status    = g->status;
    h->constant  = (int64_t)g->constant;
    h->precision = (int64_t)g->precision;
    h->tolerance = (int64_t)g->tolerance;
    h->time_sec  = (int64_t)g->time_sec;
    h->time_usec = (int64_t)g->time_usec;
    h->tick      = (int64_t)g->tick;
    h->ppsfreq   = (int64_t)g->ppsfreq;
    h->jitter    = (int64_t)g->jitter;
    h->shift     = g->shift;
    h->stabil    = (int64_t)g->stabil;
    h->jitcnt    = (int64_t)g->jitcnt;
    h->calcnt    = (int64_t)g->calcnt;
    h->errcnt    = (int64_t)g->errcnt;
    h->stbcnt    = (int64_t)g->stbcnt;
    /* g->tai deliberately dropped, like get_old_timex32. */
}

/*
 * __kernel_timex -> timex32, mirroring put_old_timex32
 * (kernel/time/time.c:318-347): truncated field copies into a
 * zeroed 128-byte image, tai included, tail padding zero.
 * timex time.tv_sec truncates (kernel-exact), not saturates.
 */
void i686_time_timex_host_to_guest32(const i686_timex64_t *h, i686_timex32_t *g)
{
    memset(g, 0, sizeof(*g));
    g->modes     = h->modes;
    g->offset    = (int32_t)h->offset;
    g->freq      = (int32_t)h->freq;
    g->maxerror  = (int32_t)h->maxerror;
    g->esterror  = (int32_t)h->esterror;
    g->status    = h->status;
    g->constant  = (int32_t)h->constant;
    g->precision = (int32_t)h->precision;
    g->tolerance = (int32_t)h->tolerance;
    g->time_sec  = (int32_t)h->time_sec; /* kernel-exact truncation */
    g->time_usec = (int32_t)h->time_usec;
    g->tick      = (int32_t)h->tick;
    g->ppsfreq   = (int32_t)h->ppsfreq;
    g->jitter    = (int32_t)h->jitter;
    g->shift     = h->shift;
    g->stabil    = (int32_t)h->stabil;
    g->jitcnt    = (int32_t)h->jitcnt;
    g->calcnt    = (int32_t)h->calcnt;
    g->errcnt    = (int32_t)h->errcnt;
    g->stbcnt    = (int32_t)h->stbcnt;
    g->tai       = h->tai;
}

/* ------------------------------------------------------------------ */
/* Factored fetch/store helpers (conversion + marshal copy; unit-test
 * surface for the fake-injected-host-time clock_gettime path).        */
/* ------------------------------------------------------------------ */

int i686_time_store_ts32(i686_ctx_t *ctx, uint32_t va, const struct timespec *h)
{
    i686_timespec_t g;

    i686_time_ts_host_to_guest(h, &g);
    return i686_copy_to_guest(ctx, va, &g, sizeof(g));
}

int i686_time_fetch_ts32(i686_ctx_t *ctx, uint32_t va, struct timespec *h)
{
    i686_timespec_t g;

    int r = i686_copy_from_guest(ctx, &g, va, sizeof(g));
    if (r != 0) {
        return r;
    }
    i686_time_ts_guest_to_host(g, h);
    return 0;
}

/* time64 (16-byte __kernel_timespec): full 64-bit seconds, no truncation. */
int i686_time_store_ts64(i686_ctx_t *ctx, uint32_t va, const struct timespec *h)
{
    i686_ts64_t g;

    g.sec  = (int64_t)h->tv_sec;
    g.nsec = (int64_t)h->tv_nsec;
    return i686_copy_to_guest(ctx, va, &g, sizeof(g));
}

int i686_time_fetch_ts64(i686_ctx_t *ctx, uint32_t va, struct timespec *h)
{
    i686_ts64_t g;

    int r = i686_copy_from_guest(ctx, &g, va, sizeof(g));
    if (r != 0) {
        return r;
    }
    h->tv_sec  = (time_t)g.sec;
    h->tv_nsec = (long)g.nsec;
    return 0;
}

int i686_time_store_tv32(i686_ctx_t *ctx, uint32_t va, const struct timeval *h)
{
    i686_timeval_t g;

    i686_time_tv_host_to_guest(h, &g);
    return i686_copy_to_guest(ctx, va, &g, sizeof(g));
}

int i686_time_store_itimerval(i686_ctx_t *ctx, uint32_t va, const struct itimerval *h)
{
    i686_itimerval_t g;

    i686_time_itimerval_host_to_guest(h, &g);
    return i686_copy_to_guest(ctx, va, &g, sizeof(g));
}

int i686_time_fetch_itimerval(i686_ctx_t *ctx, uint32_t va, struct itimerval *h)
{
    i686_itimerval_t g;

    int r = i686_copy_from_guest(ctx, &g, va, sizeof(g));
    if (r != 0) {
        return r;
    }
    i686_time_itimerval_guest_to_host(&g, h);
    return 0;
}

/*
 * Guest timex32 window buffer (128 B) <-> host __kernel_timex image
 * (208 B).  Byte-buffer interface: the layouts are module-private, the
 * unit driver mirrors them with its own static-asserted copies.  The
 * byte images are little-endian on both sides (i386 guest, aarch64
 * host) and field-converted through the structs above, never aliased.
 */
int i686_time_store_timex32(i686_ctx_t *ctx, uint32_t va,
                            const void *host_timex_bytes)
{
    i686_timex64_t h;
    i686_timex32_t g;

    memcpy(&h, host_timex_bytes, sizeof(h));
    i686_time_timex_host_to_guest32(&h, &g);
    return i686_copy_to_guest(ctx, va, &g, sizeof(g));
}

int i686_time_fetch_timex32(i686_ctx_t *ctx, uint32_t va,
                            void *host_timex_bytes)
{
    i686_timex32_t g;
    i686_timex64_t h;

    int r = i686_copy_from_guest(ctx, &g, va, sizeof(g));
    if (r != 0) {
        return r;
    }
    i686_time_timex_guest32_to_host(&g, &h);
    memcpy(host_timex_bytes, &h, sizeof(h));
    return 0;
}

/* ------------------------------------------------------------------ */
/* Pointer validation (syscalls.c low-guard convention)                */
/* ------------------------------------------------------------------ */

/* Guest pointer < 0x1000 (low guard page) or wrapping the 4 GiB window
 * is EFAULT; the marshal helpers double-check the wrap. */
static int bad_ptr(uint32_t va, size_t len)
{
    return (va < 0x1000U) ||
           ((uint64_t)va + (uint64_t)len > 0x100000000ULL);
}

/* Optional (may-be-NULL) guest pointer: exactly 0 means NULL. */
static int opt_ptr(uint32_t va, size_t len, uint32_t *out)
{
    if (va == 0U) {
        *out = 0U;
        return 0;
    }
    if (bad_ptr(va, len)) {
        return -I686_EFAULT;
    }
    *out = va;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Handlers (core logic + registry adapters)                           */
/* ------------------------------------------------------------------ */

static int64_t sys_time(i686_ctx_t *ctx, uint32_t tloc)
{
    int32_t t = (int32_t)time(NULL); /* sys_time32 truncates into EAX/tloc */

    if (tloc != 0U) {
        if (bad_ptr(tloc, sizeof(t))) {
            return -I686_EFAULT;
        }
        int r = i686_copy_to_guest(ctx, tloc, &t, sizeof(t));
        if (r != 0) {
            return r;
        }
    }
    return (int64_t)t;
}

static int64_t sys_stime(i686_ctx_t *ctx, uint32_t tptr)
{
    int32_t t;

    if (bad_ptr(tptr, sizeof(t))) {
        return -I686_EFAULT;
    }
    int r = i686_copy_from_guest(ctx, &t, tptr, sizeof(t));
    if (r != 0) {
        return r;
    }

#if defined(__linux__)
    {
        /* aarch64 has no stime(2) in the generic syscall table; the
         * i386 compat handler sets the realtime clock to {sec, 0}
         * (sys_stime32 -> do_sys_settimeofday64), so clock_settime
         * is the kernel-equivalent host call. */
        struct timespec ht = { .tv_sec = (time_t)(int64_t)t, .tv_nsec = 0 };

        if (clock_settime(CLOCK_REALTIME, &ht) != 0) {
            return -(long)errno;
        }
        return 0;
    }
#else
    return -I686_ENOSYS;
#endif
}

static int64_t sys_alarm(uint32_t seconds)
{
    /* Route through the async host-signal bridge (signals_i386.c) so a
     * guest-armed timer delivers to the guest handler instead of killing
     * the runner when translation outlasts the 1s host timer. */
    extern unsigned i686_host_alarm(unsigned seconds);
    return (int64_t)i686_host_alarm((unsigned)seconds);
}

static int64_t sys_gettimeofday(i686_ctx_t *ctx, uint32_t tv_va, uint32_t tz_va)
{
    i686_timezone_t htz = { 0, 0 };
    struct timeval htv = { 0, 0 };
    uint32_t tv, tz;

    if (opt_ptr(tv_va, sizeof(i686_timeval_t), &tv) != 0) {
        return -I686_EFAULT;
    }
    if (opt_ptr(tz_va, sizeof(i686_timezone_t), &tz) != 0) {
        return -I686_EFAULT;
    }
    if (tv == 0U && tz == 0U) {
        return 0; /* kernel fills only what is requested */
    }

#if defined(__linux__)
    {
        /* musl's gettimeofday(3) ignores the tz argument entirely, so
         * go through the raw syscall, which fills both exactly like
         * compat_sys_gettimeofday.  aarch64 timeval = { s64, s64 } is
         * byte-identical to the pair below. */
        struct {
            int64_t sec;
            int64_t usec;
        } h64 = { 0, 0 };

        if (syscall(SYS_gettimeofday, (tv != 0U) ? &h64 : NULL,
                    (tz != 0U) ? &htz : NULL) < 0) {
            return -(long)errno;
        }
        htv.tv_sec  = (time_t)h64.sec;
        htv.tv_usec = (suseconds_t)h64.usec;
    }
#else
    if (gettimeofday((tv != 0U) ? &htv : NULL,
                     (tz != 0U) ? &htz : NULL) != 0) {
        return -(long)errno;
    }
#endif

    if (tv != 0U) {
        int r = i686_time_store_tv32(ctx, tv, &htv);
        if (r != 0) {
            return r;
        }
    }
    if (tz != 0U) {
        int r = i686_copy_to_guest(ctx, tz, &htz, sizeof(htz));
        if (r != 0) {
            return r;
        }
    }
    return 0;
}

static int64_t sys_settimeofday(i686_ctx_t *ctx, uint32_t tv_va, uint32_t tz_va)
{
    i686_timeval_t gtv;
    i686_timezone_t gtz;
    uint32_t tv, tz;

    if (opt_ptr(tv_va, sizeof(gtv), &tv) != 0) {
        return -I686_EFAULT;
    }
    if (opt_ptr(tz_va, sizeof(gtz), &tz) != 0) {
        return -I686_EFAULT;
    }
    if (tv != 0U) {
        int r = i686_copy_from_guest(ctx, &gtv, tv, sizeof(gtv));
        if (r != 0) {
            return r;
        }
    }
    if (tz != 0U) {
        int r = i686_copy_from_guest(ctx, &gtz, tz, sizeof(gtz));
        if (r != 0) {
            return r;
        }
    }

#if defined(__linux__)
    {
        /* aarch64 timeval is two 64-bit fields. htz is two host longs.
         * Linux struct timezone is 8 bytes, so the kernel reads htz[0] only. */
        long long htv[2];
        long htz[2];

        if (tv != 0U) {
            htv[0] = (long long)(int64_t)gtv.tv_sec;
            htv[1] = (long long)(int64_t)gtv.tv_usec;
        }
        if (tz != 0U) {
            htz[0] = (long)gtz.tz_minuteswest;
            htz[1] = (long)gtz.tz_dsttime;
        }
        long r = syscall(SYS_settimeofday,
                         (tv != 0U) ? (const void *)htv : NULL,
                         (tz != 0U) ? (const void *)htz : NULL);
        if (r < 0) {
            return -(long)errno;
        }
        return (int64_t)r;
    }
#else
    return -I686_ENOSYS;
#endif
}

static int64_t sys_setitimer(i686_ctx_t *ctx, uint32_t which, uint32_t new_va,
                             uint32_t old_va)
{
    struct itimerval hnew, hold;
    uint32_t old;

    if (opt_ptr(old_va, sizeof(i686_itimerval_t), &old) != 0) {
        return -I686_EFAULT;
    }
    if (new_va != 0U) {
        if (bad_ptr(new_va, sizeof(i686_itimerval_t))) {
            return -I686_EFAULT;
        }
        int r = i686_time_fetch_itimerval(ctx, new_va, &hnew);
        if (r != 0) {
            return r;
        }
    }
    if (setitimer((int)(int32_t)which, (new_va != 0U) ? &hnew : NULL,
                  (old != 0U) ? &hold : NULL) != 0) {
        return -(long)errno;
    }
    if (which == 0U && new_va != 0U) {
        /* ITIMER_REAL drives host SIGALRM: arm the bridge (musl's
         * alarm() arrives here, not via the alarm syscall).  A zero
         * it_value disarms; a nonzero it_interval repeats. */
        extern void i686_host_alarm_set(int armed, int repeat);
        int armed = (hnew.it_value.tv_sec != 0 ||
                     hnew.it_value.tv_usec != 0) ? 1 : 0;
        int repeat = (hnew.it_interval.tv_sec != 0 ||
                      hnew.it_interval.tv_usec != 0) ? 1 : 0;
        i686_host_alarm_set(armed, repeat);
    }
    if (old != 0U) {
        int r = i686_time_store_itimerval(ctx, old, &hold);
        if (r != 0) {
            return r;
        }
    }
    return 0;
}

static int64_t sys_getitimer(i686_ctx_t *ctx, uint32_t which, uint32_t val_va)
{
    struct itimerval h;

    if (bad_ptr(val_va, sizeof(i686_itimerval_t))) {
        return -I686_EFAULT;
    }
    if (getitimer((int)(int32_t)which, &h) != 0) {
        return -(long)errno;
    }
    return i686_time_store_itimerval(ctx, val_va, &h);
}

/*
 * adjtimex(124): guest old_timex32 (128 B) -> host __kernel_timex
 * (208 B) -> host adjtimex -> back, exactly the
 * get/put_old_timex32 + do_adjtimex dance of sys_adjtimex_time32
 * (kernel/time/time.c:286-365).  The return is the clock state
 * (TIME_OK..TIME_ERROR >= 0) or -errno.
 */
static int64_t sys_adjtimex(i686_ctx_t *ctx, uint32_t utx_va)
{
    i686_timex64_t htx;

    if (bad_ptr(utx_va, sizeof(i686_timex32_t))) {
        return -I686_EFAULT;
    }
    int r = i686_time_fetch_timex32(ctx, utx_va, &htx);
    if (r != 0) {
        return r;
    }

#if defined(__linux__)
    {
        long r2 = syscall(SYS_adjtimex, &htx);
        if (r2 < 0) {
            return -(long)errno;
        }
        r = i686_time_store_timex32(ctx, utx_va, &htx);
        if (r != 0) {
            return r;
        }
        return (int64_t)r2;
    }
#else
    return -I686_ENOSYS;
#endif
}

static int64_t sys_nanosleep(i686_ctx_t *ctx, uint32_t req_va, uint32_t rem_va)
{
    struct timespec req, rem;
    uint32_t remv;

    if (bad_ptr(req_va, sizeof(i686_timespec_t))) {
        return -I686_EFAULT;
    }
    if (opt_ptr(rem_va, sizeof(i686_timespec_t), &remv) != 0) {
        return -I686_EFAULT;
    }
    int r = i686_time_fetch_ts32(ctx, req_va, &req);
    if (r != 0) {
        return r;
    }
    if (nanosleep(&req, (remv != 0U) ? &rem : NULL) == 0) {
        return 0;
    }
    /* EINTR (and every other errno) passes through unchanged; the
     * kernel writes the remaining time only on EINTR. */
    if (errno == EINTR && remv != 0U) {
        (void)i686_time_store_ts32(ctx, remv, &rem);
    }
    return -(long)errno;
}

static clockid_t host_clk_id(uint32_t clk, int *valid)
{
    *valid = 1;
#ifdef __APPLE__
    switch (clk) {
    case 0U: /* CLOCK_REALTIME */
    case 5U: /* CLOCK_REALTIME_COARSE */
        return CLOCK_REALTIME;
    case 1U: /* CLOCK_MONOTONIC */
    case 6U: /* CLOCK_MONOTONIC_COARSE */
    case 7U: /* CLOCK_BOOTTIME */
        return CLOCK_MONOTONIC;
    case 2U: /* CLOCK_PROCESS_CPUTIME_ID */
        return CLOCK_PROCESS_CPUTIME_ID;
    case 3U: /* CLOCK_THREAD_CPUTIME_ID */
        return CLOCK_THREAD_CPUTIME_ID;
    case 4U: /* CLOCK_MONOTONIC_RAW */
        return CLOCK_MONOTONIC_RAW;
    default:
        *valid = 0;
        return (clockid_t)-1;
    }
#else
    return (clockid_t)(int32_t)clk;
#endif
}

/* Shared core for clock_gettime(265)/clock_getres(266) — 32-bit tp. */
static int64_t clock_get_common(i686_ctx_t *ctx, uint32_t clk, uint32_t tp_va,
                                int is_res)
{
    struct timespec ts;
    int valid = 1;
    clockid_t hclk;

    if (is_res == 0 && bad_ptr(tp_va, sizeof(i686_timespec_t))) {
        return -I686_EFAULT; /* clock_gettime dereferences tp */
    }
    if (is_res != 0 && tp_va != 0U &&
        bad_ptr(tp_va, sizeof(i686_timespec_t))) {
        return -I686_EFAULT; /* clock_getres tolerates NULL tp */
    }
    hclk = host_clk_id(clk, &valid);
    if (!valid) {
        return -(long)EINVAL;
    }
    int r = (is_res != 0) ? clock_getres(hclk, &ts)
                          : clock_gettime(hclk, &ts);
    if (r != 0) {
        return -(long)errno;
    }
    if (is_res != 0 && tp_va == 0U) {
        return 0; /* validity probe only */
    }
    return i686_time_store_ts32(ctx, tp_va, &ts);
}

/* Shared core for the time64 variants — 16-byte __kernel_timespec tp. */
static int64_t clock_get_common64(i686_ctx_t *ctx, uint32_t clk, uint32_t tp_va,
                                  int is_res)
{
    struct timespec ts;
    int valid = 1;
    clockid_t hclk;

    if (is_res == 0 && bad_ptr(tp_va, sizeof(i686_ts64_t))) {
        return -I686_EFAULT;
    }
    if (is_res != 0 && tp_va != 0U && bad_ptr(tp_va, sizeof(i686_ts64_t))) {
        return -I686_EFAULT;
    }
    hclk = host_clk_id(clk, &valid);
    if (!valid) {
        return -(long)EINVAL;
    }
    int r = (is_res != 0) ? clock_getres(hclk, &ts)
                          : clock_gettime(hclk, &ts);
    if (r != 0) {
        return -(long)errno;
    }
    if (is_res != 0 && tp_va == 0U) {
        return 0;
    }
    return i686_time_store_ts64(ctx, tp_va, &ts);
}

static int64_t sys_clock_settime(i686_ctx_t *ctx, uint32_t clk, uint32_t tp_va)
{
    struct timespec ts;

    if (bad_ptr(tp_va, sizeof(i686_timespec_t))) {
        return -I686_EFAULT;
    }
    int r = i686_time_fetch_ts32(ctx, tp_va, &ts);
    if (r != 0) {
        return r;
    }
    if (clock_settime((clockid_t)(int32_t)clk, &ts) != 0) {
        return -(long)errno;
    }
    return 0;
}

static int64_t sys_clock_settime64(i686_ctx_t *ctx, uint32_t clk, uint32_t tp_va)
{
    struct timespec ts;

    if (bad_ptr(tp_va, sizeof(i686_ts64_t))) {
        return -I686_EFAULT;
    }
    int r = i686_time_fetch_ts64(ctx, tp_va, &ts);
    if (r != 0) {
        return r;
    }
    if (clock_settime((clockid_t)(int32_t)clk, &ts) != 0) {
        return -(long)errno;
    }
    return 0;
}

/*
 * clock_nanosleep(267/407): raw SYS_clock_nanosleep (libc wrappers are
 * absent on darwin — link coverage of the unit driver — and the raw
 * syscall already follows the kernel -errno contract).  The kernel
 * NULLs rmtp under TIMER_ABSTIME (kernel/time/posix-timers.c:1268-1269
 * /1303-1304), so the remaining-time buffer is only honoured for
 * relative sleeps; the kernel fills the host rem buffer itself on
 * EINTR via the restart block.
 */
static int64_t clock_nanosleep_common(i686_ctx_t *ctx, uint32_t clk,
                                      uint32_t flags, uint32_t req_va,
                                      uint32_t rem_va, int is64)
{
    struct timespec req, rem;
    size_t tsz = (is64 != 0) ? sizeof(i686_ts64_t) : sizeof(i686_timespec_t);
    uint32_t rm;
    int r;

    if (bad_ptr(req_va, tsz)) {
        return -I686_EFAULT;
    }
    if ((flags & (uint32_t)I686_TIMER_ABSTIME) != 0U) {
        rm = 0U; /* ABSTIME: kernel ignores rmtp */
    } else if (opt_ptr(rem_va, tsz, &rm) != 0) {
        return -I686_EFAULT;
    }

    r = (is64 != 0) ? i686_time_fetch_ts64(ctx, req_va, &req)
                    : i686_time_fetch_ts32(ctx, req_va, &req);
    if (r != 0) {
        return r;
    }

#if defined(__linux__)
    {
        long r2 = syscall(SYS_clock_nanosleep, (int)(int32_t)clk,
                          (int)(int32_t)flags, &req,
                          (rm != 0U) ? &rem : NULL);
        if (r2 < 0) {
            /* EINTR (and every other errno) passes through unchanged;
             * rem is stored only on EINTR of a relative sleep. */
            if (errno == EINTR && rm != 0U) {
                (void)((is64 != 0) ? i686_time_store_ts64(ctx, rm, &rem)
                                   : i686_time_store_ts32(ctx, rm, &rem));
            }
            return -(long)errno;
        }
        return (int64_t)r2;
    }
#else
    (void)clk;
    (void)rem;
    return -I686_ENOSYS;
#endif
}

/*
 * clock_adjtime64(405): guest buffer is struct __kernel_timex (208 B,
 * layout-identical to the aarch64 host), so this is a byte passthrough
 * around host SYS_clock_adjtime — mirroring sys_clock_adjtime
 * (kernel/time/posix-timers.c:1121-1132).
 */
static int64_t sys_clock_adjtime64(i686_ctx_t *ctx, uint32_t clk, uint32_t utx_va)
{
    i686_timex64_t htx;

    if (bad_ptr(utx_va, sizeof(htx))) {
        return -I686_EFAULT;
    }
    int r = i686_copy_from_guest(ctx, &htx, utx_va, sizeof(htx));
    if (r != 0) {
        return r;
    }

#if defined(__linux__)
    {
        long r2 = syscall(SYS_clock_adjtime, (int)(int32_t)clk, &htx);
        if (r2 < 0) {
            return -(long)errno;
        }
        r = i686_copy_to_guest(ctx, utx_va, &htx, sizeof(htx));
        if (r != 0) {
            return r;
        }
        return (int64_t)r2;
    }
#else
    (void)clk;
    return -I686_ENOSYS;
#endif
}

/* ---- registry adapters: args from EBX..EBP ------------------------- */

static int64_t r_time(i686_ctx_t *ctx)
{
    return sys_time(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_stime(i686_ctx_t *ctx)
{
    return sys_stime(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_alarm(i686_ctx_t *ctx)
{
    return sys_alarm(ctx->gpr[I686_REG_EBX]);
}

static int64_t r_gettimeofday(i686_ctx_t *ctx)
{
    return sys_gettimeofday(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_settimeofday(i686_ctx_t *ctx)
{
    return sys_settimeofday(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_setitimer(i686_ctx_t *ctx)
{
    return sys_setitimer(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX]);
}

static int64_t r_getitimer(i686_ctx_t *ctx)
{
    return sys_getitimer(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_adjtimex(i686_ctx_t *ctx)
{
    return sys_adjtimex(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_nanosleep(i686_ctx_t *ctx)
{
    return sys_nanosleep(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_clock_gettime(i686_ctx_t *ctx)
{
    return clock_get_common(ctx, ctx->gpr[I686_REG_EBX],
                            ctx->gpr[I686_REG_ECX], 0);
}

static int64_t r_clock_getres(i686_ctx_t *ctx)
{
    return clock_get_common(ctx, ctx->gpr[I686_REG_EBX],
                            ctx->gpr[I686_REG_ECX], 1);
}

static int64_t r_clock_settime(i686_ctx_t *ctx)
{
    return sys_clock_settime(ctx, ctx->gpr[I686_REG_EBX],
                             ctx->gpr[I686_REG_ECX]);
}

static int64_t r_clock_nanosleep(i686_ctx_t *ctx)
{
    return clock_nanosleep_common(ctx, ctx->gpr[I686_REG_EBX],
                                  ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                                  ctx->gpr[I686_REG_ESI], 0);
}

static int64_t r_clock_gettime64(i686_ctx_t *ctx)
{
    return clock_get_common64(ctx, ctx->gpr[I686_REG_EBX],
                              ctx->gpr[I686_REG_ECX], 0);
}

static int64_t r_clock_settime64(i686_ctx_t *ctx)
{
    return sys_clock_settime64(ctx, ctx->gpr[I686_REG_EBX],
                               ctx->gpr[I686_REG_ECX]);
}

static int64_t r_clock_adjtime64(i686_ctx_t *ctx)
{
    return sys_clock_adjtime64(ctx, ctx->gpr[I686_REG_EBX],
                               ctx->gpr[I686_REG_ECX]);
}

static int64_t r_clock_getres_time64(i686_ctx_t *ctx)
{
    return clock_get_common64(ctx, ctx->gpr[I686_REG_EBX],
                              ctx->gpr[I686_REG_ECX], 1);
}

static int64_t r_clock_nanosleep_time64(i686_ctx_t *ctx)
{
    return clock_nanosleep_common(ctx, ctx->gpr[I686_REG_EBX],
                                  ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                                  ctx->gpr[I686_REG_ESI], 1);
}

void i686_syscalls_time_init(void)
{
    i686_sys_register(I686__NR_time, r_time);
    i686_sys_register(I686__NR_stime, r_stime);
    i686_sys_register(I686__NR_alarm, r_alarm);
    i686_sys_register(I686__NR_gettimeofday, r_gettimeofday);
    i686_sys_register(I686__NR_settimeofday, r_settimeofday);
    i686_sys_register(I686__NR_setitimer, r_setitimer);
    i686_sys_register(I686__NR_getitimer, r_getitimer);
    i686_sys_register(I686__NR_adjtimex, r_adjtimex);
    i686_sys_register(I686__NR_nanosleep, r_nanosleep);
    i686_sys_register(I686__NR_clock_settime, r_clock_settime);
    i686_sys_register(I686__NR_clock_gettime, r_clock_gettime);
    i686_sys_register(I686__NR_clock_getres, r_clock_getres);
    i686_sys_register(I686__NR_clock_nanosleep, r_clock_nanosleep);
    i686_sys_register(I686__NR_clock_gettime64, r_clock_gettime64);
    i686_sys_register(I686__NR_clock_settime64, r_clock_settime64);
    i686_sys_register(I686__NR_clock_adjtime64, r_clock_adjtime64);
    i686_sys_register(I686__NR_clock_getres_time64, r_clock_getres_time64);
    i686_sys_register(I686__NR_clock_nanosleep_time64, r_clock_nanosleep_time64);
}
