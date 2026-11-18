/*
 * src/os/sys_pass_at.c — *at() path syscalls (dirfd-relative)
 *
 * Passes the i386 *at family to the host: unlinkat, mkdirat, mknodat,
 * renameat, renameat2, linkat, symlinkat, readlinkat, utimensat and
 * utimensat_time64.
 * The guest dirfd is a host fd (fds are not remapped); guest AT_FDCWD
 * (-100) and the guest AT and UTIME constants translate to host values
 * (sys_pass_internal.h: identical on Linux, mapped on Darwin).
 * Absolute guest paths resolve under --sysroot (fail closed); relative
 * paths stay dirfd-relative.  Only symlinkat's target is exempt: link
 * content is stored verbatim.
 * Used by coreutils rm/mv/cp/ls (fts + openat/unlinkat walks).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "os/sys_pass_internal.h"

#include <sys/time.h>
#include <time.h>

/* Not exposed under strict _POSIX_C_SOURCE=200809L. */
int mknodat(int, const char *, mode_t, dev_t);

#define AT_NR_mknod             14U
#define AT_NR_mknodat          297U
#define AT_NR_mkdirat          296U
#define AT_NR_unlinkat         301U
#define AT_NR_renameat         302U
#define AT_NR_linkat           303U
#define AT_NR_symlinkat        304U
#define AT_NR_readlinkat       305U
#define AT_NR_utimensat        320U
#define AT_NR_renameat2        353U
#define AT_NR_utimensat_time64 412U

static int64_t r_unlinkat(i686_ctx_t *ctx)
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
        unlinkat(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]), host,
                 i686_at_removedir_to_host((int)ctx->gpr[I686_REG_EDX])));
}

static int64_t r_mkdirat(i686_ctx_t *ctx)
{
    char path[PATH_BUF];
    char host[PATH_BUF];

    if (fetch_path(ctx, ctx->gpr[I686_REG_ECX], path) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    return host_ret_int(mkdirat(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]),
                                host, (mode_t)ctx->gpr[I686_REG_EDX]));
}

static int64_t r_mknodat(i686_ctx_t *ctx)
{
    char path[PATH_BUF];
    char host[PATH_BUF];

    if (fetch_path(ctx, ctx->gpr[I686_REG_ECX], path) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    /* i386 dev_t is old-style 32-bit (major<<8|minor in 16 bits here). */
    return host_ret_int(mknodat(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]),
                                host, (mode_t)ctx->gpr[I686_REG_EDX],
                                (dev_t)ctx->gpr[I686_REG_ESI]));
}

static int64_t r_mknod(i686_ctx_t *ctx)
{
    char path[PATH_BUF];
    char host[PATH_BUF];

    if (fetch_path(ctx, ctx->gpr[I686_REG_EBX], path) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    return host_ret_int(mknodat(AT_FDCWD, host,
                                (mode_t)ctx->gpr[I686_REG_ECX],
                                (dev_t)ctx->gpr[I686_REG_EDX]));
}

static int64_t rename_common(i686_ctx_t *ctx, uint32_t flags)
{
    char oldp[PATH_BUF];
    char newp[PATH_BUF];
    char oldh[PATH_BUF];
    char newh[PATH_BUF];
    int ofd = i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]);
    int nfd = i686_at_fd_to_host(ctx->gpr[I686_REG_EDX]);

    if (fetch_path(ctx, ctx->gpr[I686_REG_ECX], oldp) != 0 ||
        fetch_path(ctx, ctx->gpr[I686_REG_ESI], newp) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, oldp, oldh) != 0 ||
        i686_at_path_to_host(ctx, newp, newh) != 0) {
        return -(int64_t)errno;
    }
    if (flags == 0U) {
        return host_ret_int(renameat(ofd, oldh, nfd, newh));
    }
#ifdef __linux__
    return host_ret_int(syscall(SYS_renameat2, ofd, oldh, nfd, newh, flags));
#else
    return -EINVAL;
#endif
}

static int64_t r_renameat(i686_ctx_t *ctx)
{
    return rename_common(ctx, 0U);
}

static int64_t r_renameat2(i686_ctx_t *ctx)
{
    return rename_common(ctx, ctx->gpr[I686_REG_EDI]);
}

static int64_t r_linkat(i686_ctx_t *ctx)
{
    char oldp[PATH_BUF];
    char newp[PATH_BUF];
    char oldh[PATH_BUF];
    char newh[PATH_BUF];

    if (fetch_path(ctx, ctx->gpr[I686_REG_ECX], oldp) != 0 ||
        fetch_path(ctx, ctx->gpr[I686_REG_ESI], newp) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, oldp, oldh) != 0 ||
        i686_at_path_to_host(ctx, newp, newh) != 0) {
        return -(int64_t)errno;
    }
    return host_ret_int(
        linkat(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]), oldh,
               i686_at_fd_to_host(ctx->gpr[I686_REG_EDX]), newh,
               i686_at_follow_to_host((int)ctx->gpr[I686_REG_EDI])));
}

static int64_t r_symlinkat(i686_ctx_t *ctx)
{
    char target[PATH_BUF];
    char linkp[PATH_BUF];
    char linkh[PATH_BUF];

    if (fetch_path(ctx, ctx->gpr[I686_REG_EBX], target) != 0 ||
        fetch_path(ctx, ctx->gpr[I686_REG_EDX], linkp) != 0) {
        return -EFAULT;
    }
    /* The target is link content: stored verbatim, never sysroot-joined. */
    if (i686_at_path_to_host(ctx, linkp, linkh) != 0) {
        return -(int64_t)errno;
    }
    return host_ret_int(symlinkat(target,
                                  i686_at_fd_to_host(ctx->gpr[I686_REG_ECX]),
                                  linkh));
}

static int64_t r_readlinkat(i686_ctx_t *ctx)
{
    char path[PATH_BUF];
    char host[PATH_BUF];
    char out[PATH_BUF];
    uint32_t cap = ctx->gpr[I686_REG_ESI];
    ssize_t n;
    int64_t rc;

    if (fetch_path(ctx, ctx->gpr[I686_REG_ECX], path) != 0) {
        return -EFAULT;
    }
    if (i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    if (cap > sizeof out) {
        cap = (uint32_t)sizeof out;
    }
    n = readlinkat(i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]), host, out,
                   cap);
    if (n < 0) {
        return -(int64_t)errno;
    }
    rc = i686_copy_to_guest(ctx, ctx->gpr[I686_REG_EDX], out, (size_t)n);
    return (rc != 0) ? rc : (int64_t)n;
}

/*
 * utimensat: two timespecs of {tv_sec, tv_nsec}; 32-bit fields for the
 * legacy entry, 64-bit seconds (+64-bit nsec slot) for the _time64 one.
 */
static int64_t utimens_common(i686_ctx_t *ctx, int is64)
{
    char path[PATH_BUF];
    char host[PATH_BUF];
    struct timespec ts[2];
    uint32_t tva = ctx->gpr[I686_REG_EDX];
    int fd = i686_at_fd_to_host(ctx->gpr[I686_REG_EBX]);
    int flags =
        i686_at_no_follow_to_host((int)ctx->gpr[I686_REG_ESI]);
    int has_path = (ctx->gpr[I686_REG_ECX] != 0U);

    if (has_path && fetch_path(ctx, ctx->gpr[I686_REG_ECX], path) != 0) {
        return -EFAULT;
    }
    if (has_path && i686_at_path_to_host(ctx, path, host) != 0) {
        return -(int64_t)errno;
    }
    if (tva != 0U) {
        uint8_t raw[32];
        size_t esz = is64 ? 16U : 8U;
        int64_t rc = i686_copy_from_guest(ctx, raw, tva, 2U * esz);

        if (rc != 0) {
            return -EFAULT;
        }
        for (size_t i = 0; i < 2U; i++) {
            const uint8_t *p = raw + i * esz;
            int64_t sec;
            int64_t nsec;

            if (is64) {
                /* i386 __timespec64 is {int64 sec; int32 nsec; int32 pad}
                 * with uninitialized padding at +12; the kernel compat
                 * path sign-extends tv_nsec from the 32-bit word. */
                int32_t n32;
                memcpy(&sec, p, 8);
                memcpy(&n32, p + 8, 4);
                nsec = (int64_t)n32;
            } else {
                int32_t s32;
                int32_t n32;

                memcpy(&s32, p, 4);
                memcpy(&n32, p + 4, 4);
                sec = s32;
                nsec = n32;
            }
            if (nsec != I686_UTIME_NOW_GUEST &&
                nsec != I686_UTIME_OMIT_GUEST &&
                (nsec < 0 || nsec >= 1000000000L)) {
                return -EINVAL;
            }
            ts[i].tv_sec = (time_t)sec;
            ts[i].tv_nsec = i686_utime_nsec_to_host((long)nsec);
        }
    }
    if (!has_path) {
        return host_ret_int(futimens(fd, tva != 0U ? ts : NULL));
    }
    return host_ret_int(utimensat(fd, host, tva != 0U ? ts : NULL, flags));
}

static int64_t r_utimensat(i686_ctx_t *ctx)
{
    return utimens_common(ctx, 0);
}

static int64_t r_utimensat64(i686_ctx_t *ctx)
{
    return utimens_common(ctx, 1);
}

void i686_syscalls_at_init(void)
{
    i686_sys_register(AT_NR_mkdirat, r_mkdirat);
    i686_sys_register(AT_NR_mknod, r_mknod);
    i686_sys_register(AT_NR_mknodat, r_mknodat);
    i686_sys_register(AT_NR_unlinkat, r_unlinkat);
    i686_sys_register(AT_NR_renameat, r_renameat);
    i686_sys_register(AT_NR_renameat2, r_renameat2);
    i686_sys_register(AT_NR_linkat, r_linkat);
    i686_sys_register(AT_NR_symlinkat, r_symlinkat);
    i686_sys_register(AT_NR_readlinkat, r_readlinkat);
    i686_sys_register(AT_NR_utimensat, r_utimensat);
    i686_sys_register(AT_NR_utimensat_time64, r_utimensat64);
}
