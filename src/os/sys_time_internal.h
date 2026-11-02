/*
 * Internal definitions and marshalling declarations for i386 time syscalls
 * (src/os/sys_time.c and src/os/sys_time_conv.c).
 */

#ifndef I686RT_OS_SYS_TIME_INTERNAL_H
#define I686RT_OS_SYS_TIME_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>

#include "i686rt.h"
#include "os/marshal.h"
#include "os/structs_i386.h"
#include "os/syscalls_i386.h"

/* Guest errno values (host-OS independent; same scheme as marshal.c's
 * I686_EFAULT copy).  Linux generic errno ABI, identical i386/aarch64. */
#define I686_EFAULT 14
#define I686_ENOSYS 38

/* TIMER_ABSTIME: include/uapi/linux/time.h (== 1 everywhere). */
#define I686_TIMER_ABSTIME 1

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

/*Guest pointer < 0x1000 (low guard page) or wrapping the 4 GiB window
 * is EFAULT; the marshal helpers double-check the wrap. */
static inline int bad_ptr(uint32_t va, size_t len)
{
    return (va < 0x1000U) ||
           ((uint64_t)va + (uint64_t)len > 0x100000000ULL);
}

/* Optional (may-be-NULL) guest pointer: exactly 0 means NULL. */
static inline int opt_ptr(uint32_t va, size_t len, uint32_t *out)
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

void i686_time_ts_host_to_guest(const struct timespec *h, i686_timespec_t *g);
void i686_time_ts_guest_to_host(i686_timespec_t g, struct timespec *h);
void i686_time_tv_host_to_guest(const struct timeval *h, i686_timeval_t *g);
void i686_time_tv_guest_to_host(i686_timeval_t g, struct timeval *h);
void i686_time_itimerval_host_to_guest(const struct itimerval *h,
                                       i686_itimerval_t *g);
void i686_time_itimerval_guest_to_host(const i686_itimerval_t *g,
                                       struct itimerval *h);
void i686_time_timex_guest32_to_host(const i686_timex32_t *g,
                                     i686_timex64_t *h);
void i686_time_timex_host_to_guest32(const i686_timex64_t *h,
                                     i686_timex32_t *g);

int i686_time_store_ts32(i686_ctx_t *ctx, uint32_t va,
                         const struct timespec *h);
int i686_time_fetch_ts32(i686_ctx_t *ctx, uint32_t va, struct timespec *h);
int i686_time_store_ts64(i686_ctx_t *ctx, uint32_t va,
                         const struct timespec *h);
int i686_time_fetch_ts64(i686_ctx_t *ctx, uint32_t va, struct timespec *h);
int i686_time_store_tv32(i686_ctx_t *ctx, uint32_t va,
                         const struct timeval *h);
int i686_time_store_itimerval(i686_ctx_t *ctx, uint32_t va,
                              const struct itimerval *h);
int i686_time_fetch_itimerval(i686_ctx_t *ctx, uint32_t va,
                              struct itimerval *h);
int i686_time_store_timex32(i686_ctx_t *ctx, uint32_t va,
                            const void *host_timex_bytes);
int i686_time_fetch_timex32(i686_ctx_t *ctx, uint32_t va,
                            void *host_timex_bytes);

#endif /* I686RT_OS_SYS_TIME_INTERNAL_H */
