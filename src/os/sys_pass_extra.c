/*
 * src/os/sys_pass_extra.c — assorted syscalls forwarded to the host
 *
 * faccessat2, fchmodat2, getrandom, fadvise64, and the process-group,
 * sync, truncate and scheduling calls that coreutils, bash, make, git
 * and CPython use.  Scalar arguments only; struct-carrying calls convert
 * to the i386 layout.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "os/sys_pass_internal.h"

#ifdef __linux__
#include <sched.h>
#include <sys/random.h>
#endif
#include <sys/resource.h>
#include <sys/times.h>

/* Not exposed under strict _POSIX_C_SOURCE=200809L on every libc. */
void sync(void);
int fdatasync(int);
int truncate(const char *, off_t);
pid_t getsid(pid_t);

#define X_NR_faccessat2       439U
#define X_NR_fchmodat2        452U
#define X_NR_getrandom        355U
#define X_NR_fadvise64        250U
#define X_NR_fadvise64_64     272U
#define X_NR_getpgid          132U

static int64_t r_faccessat2(i686_ctx_t *ctx)
{
    char path[PATH_BUF];
    char host[PATH_BUF];
    int flags;

    if (fetch_path(ctx, ctx->gpr[I686_REG_ECX], path) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    flags = i686_at_eaccess_to_host((int)ctx->gpr[I686_REG_ESI]) |
            i686_at_no_follow_to_host((int)ctx->gpr[I686_REG_ESI]);
    return host_ret_int(faccessat(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]),
                                  host, (int)ctx->gpr[I686_REG_EDX],
                                  flags));
}

static int64_t r_fchmodat2(i686_ctx_t *ctx)
{
    char path[PATH_BUF];
    char host[PATH_BUF];

    if (fetch_path(ctx, ctx->gpr[I686_REG_ECX], path) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    return host_ret_int(
        fchmodat(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]), host,
                 (mode_t)ctx->gpr[I686_REG_EDX],
                 i686_at_no_follow_to_host((int)ctx->gpr[I686_REG_ESI])));
}

static int64_t r_getpgid(i686_ctx_t *ctx)
{
    return host_ret_int(getpgid((pid_t)ctx->gpr[I686_REG_EBX]));
}

/* Advice only: a successful no-op is always a legal answer. */
static int64_t r_fadvise(i686_ctx_t *ctx)
{
    (void)ctx;
    return 0;
}

/* getrandom(buf, len, flags): fill in bounded host chunks, copy out. */
static int64_t r_getrandom(i686_ctx_t *ctx)
{
    uint32_t va = ctx->gpr[I686_REG_EBX];
    uint32_t len = ctx->gpr[I686_REG_ECX];
    unsigned flags = (unsigned)ctx->gpr[I686_REG_EDX];
    uint32_t done = 0U;
    uint8_t buf[256];

    if ((flags & ~7U) != 0U) { /* GRND_NONBLOCK|GRND_RANDOM|GRND_INSECURE */
        return -EINVAL;
    }
    while (done < len) {
        uint32_t n = (len - done > sizeof buf) ? (uint32_t)sizeof buf : len - done;
#ifdef __linux__
        ssize_t got = getrandom(buf, n, flags);
#else
        ssize_t got = (arc4random_buf(buf, n), (ssize_t)n);
#endif

        if (got < 0) {
            return (done != 0U) ? (int64_t)done : -(int64_t)errno;
        }
        if (i686_copy_to_guest(ctx, va + done, buf, (size_t)got) != 0) {
            return (done != 0U) ? (int64_t)done : -EFAULT;
        }
        done += (uint32_t)got;
        if ((uint32_t)got < n) {
            break;
        }
    }
    return (int64_t)done;
}

/* Scalar pass-through table: nr -> host call on (ebx, ecx, edx). */
static int64_t r_kill(i686_ctx_t *ctx)
{
    return host_ret_int(kill((pid_t)(int32_t)ctx->gpr[I686_REG_EBX],
                             (int)ctx->gpr[I686_REG_ECX]));
}

static int64_t r_setpgid(i686_ctx_t *ctx)
{
    return host_ret_int(setpgid((pid_t)ctx->gpr[I686_REG_EBX],
                                (pid_t)ctx->gpr[I686_REG_ECX]));
}

static int64_t r_getpgrp(i686_ctx_t *ctx)
{
    (void)ctx;
    return host_ret_int(getpgrp());
}

static int64_t r_setsid(i686_ctx_t *ctx)
{
    (void)ctx;
    return host_ret_int(setsid());
}

static int64_t r_getsid(i686_ctx_t *ctx)
{
    return host_ret_int(getsid((pid_t)ctx->gpr[I686_REG_EBX]));
}

static int64_t r_sync(i686_ctx_t *ctx)
{
    (void)ctx;
    sync();
    return 0;
}

static int64_t r_fsync(i686_ctx_t *ctx)
{
    return host_ret_int(
        fsync(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX])));
}

static int64_t r_fdatasync(i686_ctx_t *ctx)
{
#ifdef __linux__
    return host_ret_int(
        fdatasync(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX])));
#else
    return host_ret_int(fsync(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX])));
#endif
}

static int64_t r_sched_yield(i686_ctx_t *ctx)
{
    (void)ctx;
#ifdef __linux__
    return host_ret_int(sched_yield());
#else
    return 0;
#endif
}

/* truncate(path, len32) / ftruncate(fd, len32): length is sign-extended. */
static int64_t r_truncate(i686_ctx_t *ctx)
{
    char path[PATH_BUF];
    char host[PATH_BUF];

    if (fetch_path(ctx, ctx->gpr[I686_REG_EBX], path) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    return host_ret_int(truncate(host,
                                 (off_t)(int32_t)ctx->gpr[I686_REG_ECX]));
}

static int64_t r_ftruncate(i686_ctx_t *ctx)
{
    return host_ret_int(ftruncate(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]),
                                  (off_t)(int32_t)ctx->gpr[I686_REG_ECX]));
}

/* truncate64(path, lo, hi) */
static int64_t r_truncate64(i686_ctx_t *ctx)
{
    char path[PATH_BUF];
    char host[PATH_BUF];
    uint64_t len = ((uint64_t)ctx->gpr[I686_REG_EDX] << 32) |
                   (uint64_t)ctx->gpr[I686_REG_ECX];

    if (fetch_path(ctx, ctx->gpr[I686_REG_EBX], path) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    return host_ret_int(truncate(host, (off_t)len));
}

/* times(struct tms *): four 32-bit clock_t. */
static int64_t r_times(i686_ctx_t *ctx)
{
    struct tms t;
    clock_t r = times(&t);
    uint32_t out[4];

    if (r == (clock_t)-1) {
        return -(int64_t)errno;
    }
    out[0] = (uint32_t)t.tms_utime;
    out[1] = (uint32_t)t.tms_stime;
    out[2] = (uint32_t)t.tms_cutime;
    out[3] = (uint32_t)t.tms_cstime;
    if (ctx->gpr[I686_REG_EBX] != 0U &&
        i686_copy_to_guest(ctx, ctx->gpr[I686_REG_EBX], out, sizeof out) != 0) {
        return -EFAULT;
    }
    return (int64_t)(int32_t)(uint32_t)r;
}

/* getrusage(who, struct rusage *): 2 x {sec,usec} then 14 longs, all 32-bit.
 * The canonical i386 layout lives in i686_rusage_to_guest (sys_pass_fs.c);
 * this entry only fetches the host counters. */
static int64_t r_getrusage(i686_ctx_t *ctx)
{
    struct rusage ru;

    if (getrusage((int)(int32_t)ctx->gpr[I686_REG_EBX], &ru) != 0) {
        return -(int64_t)errno;
    }
    return i686_rusage_to_guest(ctx, ctx->gpr[I686_REG_ECX], &ru);
}

void i686_syscalls_extra_init(void)
{
    i686_sys_register(X_NR_faccessat2, r_faccessat2);
    i686_sys_register(X_NR_fchmodat2, r_fchmodat2);
    i686_sys_register(X_NR_getpgid, r_getpgid);
    i686_sys_register(X_NR_getrandom, r_getrandom);
    i686_sys_register(X_NR_fadvise64, r_fadvise);
    i686_sys_register(X_NR_fadvise64_64, r_fadvise);
    i686_sys_register(37, r_kill);
    i686_sys_register(57, r_setpgid);
    i686_sys_register(65, r_getpgrp);
    i686_sys_register(66, r_setsid);
    i686_sys_register(147, r_getsid);
    i686_sys_register(36, r_sync);
    i686_sys_register(118, r_fsync);
    i686_sys_register(148, r_fdatasync);
    i686_sys_register(158, r_sched_yield);
    i686_sys_register(92, r_truncate);
    i686_sys_register(93, r_ftruncate);
    i686_sys_register(193, r_truncate64);
    i686_sys_register(43, r_times);
    i686_sys_register(77, r_getrusage);
}
