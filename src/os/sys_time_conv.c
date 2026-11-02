/*
 * Pure converters and guest memory fetch/store helpers for i386 time syscalls
 * (Phase 2, lane L2d; split from src/os/sys_time.c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <limits.h>
#include <string.h>

#include "os/sys_time_internal.h"

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
void i686_time_itimerval_host_to_guest(const struct itimerval *h,
                                       i686_itimerval_t *g)
{
    i686_time_tv_host_to_guest(&h->it_interval, &g->it_interval);
    i686_time_tv_host_to_guest(&h->it_value, &g->it_value);
}

void i686_time_itimerval_guest_to_host(const i686_itimerval_t *g,
                                       struct itimerval *h)
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

int i686_time_store_itimerval(i686_ctx_t *ctx, uint32_t va,
                              const struct itimerval *h)
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
