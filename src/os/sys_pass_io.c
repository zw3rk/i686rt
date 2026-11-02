/*
 * src/os/sys_pass_io.c — Identity, FD, I/O, ioctl & VM passthroughs (L2f)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sys_pass_internal.h"

static long sys_setgroups32(i686_ctx_t *ctx, uint32_t n, uint32_t list_va)
{
    gid_t *g = NULL;
    int rc = i686_groups_from_guest(ctx, list_va, n, &g);
    if (rc != 0) {
        return rc;
    }
    long r = host_ret_int(setgroups((int)n, g));
    free(g);
    return r;
}

static long sys_setgroups16(i686_ctx_t *ctx, uint32_t n, uint32_t list_va)
{
    gid_t *g = NULL;
    int rc = i686_groups16_from_guest(ctx, list_va, n, &g);
    if (rc != 0) {
        return rc;
    }
    long r = host_ret_int(setgroups((int)n, g));
    free(g);
    return r;
}

static long sys_getgroups32(i686_ctx_t *ctx, uint32_t size, uint32_t list_va)
{
    if (size == 0U) {
        return host_ret_int(getgroups(0, NULL));
    }
    if (size > NGROUPS_MAX_) {
        return -EINVAL;
    }
    gid_t *g = malloc((size_t)size * sizeof *g);
    if (g == NULL) {
        return -ENOMEM;
    }
    int r = getgroups((int)size, g);
    if (r < 0) {
        free(g);
        return -errno;
    }
    if (guest_ptr_bad(list_va) ||
        i686_copy_to_guest(ctx, list_va, g, (size_t)r * sizeof *g) != 0) {
        free(g);
        return -EFAULT;
    }
    free(g);
    return r;
}

static long sys_getgroups16(i686_ctx_t *ctx, uint32_t size, uint32_t list_va)
{
    if (size == 0U) {
        return host_ret_int(getgroups(0, NULL));
    }
    if (size > NGROUPS_MAX_) {
        return -EINVAL;
    }
    gid_t *g = malloc((size_t)size * sizeof *g);
    if (g == NULL) {
        return -ENOMEM;
    }
    int r = getgroups((int)size, g);
    if (r < 0) {
        free(g);
        return -errno;
    }
    uint8_t *out = malloc((size_t)r * 2U);
    if (out == NULL) {
        free(g);
        return -ENOMEM;
    }
    for (int i = 0; i < r; i++) {
        wr_le16(out + 2U * (size_t)i, (uint16_t)g[i]);
    }
    free(g);
    if (guest_ptr_bad(list_va) ||
        i686_copy_to_guest(ctx, list_va, out, (size_t)r * 2U) != 0) {
        free(out);
        return -EFAULT;
    }
    free(out);
    return r;
}

static long sys_dup3(uint32_t oldfd, uint32_t newfd, uint32_t flags)
{
    if ((flags & ~(uint32_t)0x80000u) != 0U) {
        return -EINVAL;
    }
#ifdef __APPLE__
    {
        int fd = dup2((int)oldfd, (int)newfd);
        if (fd < 0) {
            return -errno;
        }
        if ((flags & 0x80000u) != 0U) {
            (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        return fd;
    }
#else
    return host_ret_(dup3((int)oldfd, (int)newfd,
                          (int)((flags & 0x80000u) ? 0x80000 : 0)));
#endif
}

static long sys_pipe2(i686_ctx_t *ctx, uint32_t fds_va, uint32_t flags)
{
    int fds[2];

    if ((flags & ~(uint32_t)(HOST_O_NONBLOCK | HOST_O_CLOEXEC)) != 0U) {
        return -EINVAL;
    }
#ifdef __APPLE__
    if (pipe(fds) < 0) {
        return -errno;
    }
    if ((flags & HOST_O_NONBLOCK) != 0U) {
        if (fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0 ||
            fcntl(fds[1], F_SETFL, O_NONBLOCK) < 0) {
            int e = errno;
            (void)close(fds[0]);
            (void)close(fds[1]);
            return -e;
        }
    }
    if ((flags & HOST_O_CLOEXEC) != 0U) {
        (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    }
#else
    if (pipe2(fds, (int)flags) < 0) {
        return -errno;
    }
#endif
    if (guest_ptr_bad(fds_va) ||
        i686_copy_to_guest(ctx, fds_va, fds, sizeof fds) != 0) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return -EFAULT;
    }
    return 0;
}

static long ioctl_buf(i686_ctx_t *ctx, uint32_t fd, uint32_t req, uint32_t arg,
                      size_t len, int set_direction)
{
    uint8_t buf[K_TERMIOS_SZ];

    if (guest_ptr_bad(arg)) {
        return -EFAULT;
    }
    if (set_direction) {
        if (i686_copy_from_guest(ctx, buf, arg, len) != 0) {
            return -EFAULT;
        }
    }
    long r = ioctl((int)fd, (unsigned long)req, buf);
    if (r < 0) {
        return -errno;
    }
    if (!set_direction) {
        if (i686_copy_to_guest(ctx, arg, buf, len) != 0) {
            return -EFAULT;
        }
    }
    return r;
}

static long sys_ioctl(i686_ctx_t *ctx, uint32_t fd, uint32_t req, uint32_t arg)
{
    switch (req) {
    case REQ_TCGETS:
        return ioctl_buf(ctx, fd, req, arg, K_TERMIOS_SZ, 0);
    case REQ_TCSETS:
    case REQ_TCSETSW:
    case REQ_TCSETSF:
        return ioctl_buf(ctx, fd, req, arg, K_TERMIOS_SZ, 1);
    case REQ_TCGETA:
        return ioctl_buf(ctx, fd, req, arg, K_TERMIO_SZ, 0);
    case REQ_TCSETA:
    case REQ_TCSETAW:
    case REQ_TCSETAF:
        return ioctl_buf(ctx, fd, req, arg, K_TERMIO_SZ, 1);
    case REQ_TIOCGWINSZ:
        return ioctl_buf(ctx, fd, req, arg, K_WINSIZE_SZ, 0);
    case REQ_TIOCSWINSZ:
        return ioctl_buf(ctx, fd, req, arg, K_WINSIZE_SZ, 1);
    case REQ_FIONREAD:
        return ioctl_buf(ctx, fd, req, arg, K_INT_SZ, 0);
    case REQ_TCSBRK:
    case REQ_TCSBRKP:
    case REQ_TCXONC:
    case REQ_TCFLSH:
    case REQ_TIOCEXCL:
    case REQ_TIOCNXCL:
    case REQ_TIOCNOTTY:
    case REQ_TIOCSBRK:
    case REQ_TIOCCBRK:
    case REQ_FIONCLEX:
    case REQ_FIOCLEX:
        return host_ret_int(ioctl((int)fd, (unsigned long)req, (unsigned long)arg));
    default:
        return -ENOTTY;
    }
}

struct i686_iov_local {
    uint32_t base;
    uint32_t len;
};

int64_t i686_pass_r_writev(i686_ctx_t *ctx)
{
    int fd = (int)ctx->gpr[I686_REG_EBX];
    uint32_t iov_va = ctx->gpr[I686_REG_ECX];
    uint32_t cnt = ctx->gpr[I686_REG_EDX];
    int64_t total = 0;
    uint32_t i;

    if (cnt > 1024U) {
        return -EINVAL;
    }
    for (i = 0U; i < cnt; i++) {
        struct i686_iov_local iov;
        char stk[512];
        uint32_t off;
        if (i686_copy_from_guest(ctx, &iov, iov_va + 8U * i, sizeof(iov)) != 0) {
            return -EFAULT;
        }
        for (off = 0U; off < iov.len; off += sizeof(stk)) {
            uint32_t chunk = iov.len - off;
            ssize_t n;
            if (chunk > sizeof(stk)) {
                chunk = (uint32_t)sizeof(stk);
            }
            if (i686_copy_from_guest(ctx, stk, iov.base + off, chunk) != 0) {
                return -EFAULT;
            }
            n = write(fd, stk, chunk);
            if (n < 0) {
                return (total > 0) ? total : -(int64_t)errno;
            }
            total += n;
            if ((size_t)n < chunk) {
                return total;
            }
        }
    }
    return total;
}

int64_t i686_pass_r_readv(i686_ctx_t *ctx)
{
    int fd = (int)ctx->gpr[I686_REG_EBX];
    uint32_t iov_va = ctx->gpr[I686_REG_ECX];
    uint32_t cnt = ctx->gpr[I686_REG_EDX];
    int64_t total = 0;
    uint32_t i;

    if (cnt > 1024U) {
        return -EINVAL;
    }
    for (i = 0U; i < cnt; i++) {
        struct i686_iov_local iov;
        uint8_t stk[512];
        uint32_t off;
        if (i686_copy_from_guest(ctx, &iov, iov_va + 8U * i, sizeof(iov)) != 0) {
            return (total > 0) ? total : -EFAULT;
        }
        for (off = 0U; off < iov.len; off += sizeof(stk)) {
            uint32_t chunk = iov.len - off;
            ssize_t n;
            if (chunk > sizeof(stk)) {
                chunk = (uint32_t)sizeof(stk);
            }
            n = read(fd, stk, chunk);
            if (n < 0) {
                return (total > 0) ? total : -(int64_t)errno;
            }
            if (i686_copy_to_guest(ctx, iov.base + off, stk, (size_t)n) != 0) {
                return (total > 0) ? total : -EFAULT;
            }
            total += n;
            if ((size_t)n < chunk) {
                return total;
            }
        }
    }
    return total;
}

int64_t i686_pass_r_getppid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)getppid();
}

int64_t i686_pass_r_getuid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)((uint32_t)getuid() & 0xFFFFu);
}

int64_t i686_pass_r_getuid32(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)getuid();
}

int64_t i686_pass_r_getgid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)((uint32_t)getgid() & 0xFFFFu);
}

int64_t i686_pass_r_getgid32(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)getgid();
}

int64_t i686_pass_r_geteuid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)((uint32_t)geteuid() & 0xFFFFu);
}

int64_t i686_pass_r_geteuid32(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)geteuid();
}

int64_t i686_pass_r_getegid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)((uint32_t)getegid() & 0xFFFFu);
}

int64_t i686_pass_r_getegid32(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)getegid();
}

int64_t i686_pass_r_setuid(i686_ctx_t *ctx)
{
    return host_ret_(setuid((uid_t)(ctx->gpr[I686_REG_EBX] & 0xFFFFu)));
}

int64_t i686_pass_r_setuid32(i686_ctx_t *ctx)
{
    return host_ret_(setuid((uid_t)ctx->gpr[I686_REG_EBX]));
}

int64_t i686_pass_r_setgid(i686_ctx_t *ctx)
{
    return host_ret_(setgid((gid_t)(ctx->gpr[I686_REG_EBX] & 0xFFFFu)));
}

int64_t i686_pass_r_setgid32(i686_ctx_t *ctx)
{
    return host_ret_(setgid((gid_t)ctx->gpr[I686_REG_EBX]));
}

int64_t i686_pass_r_setgroups32(i686_ctx_t *ctx)
{
    return sys_setgroups32(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_setgroups16(i686_ctx_t *ctx)
{
    return sys_setgroups16(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_getgroups32(i686_ctx_t *ctx)
{
    return sys_getgroups32(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_getgroups16(i686_ctx_t *ctx)
{
    return sys_getgroups16(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_umask(i686_ctx_t *ctx)
{
    return (int64_t)umask((mode_t)ctx->gpr[I686_REG_EBX]);
}

int64_t i686_pass_r_dup(i686_ctx_t *ctx)
{
    return host_ret_(dup((int)ctx->gpr[I686_REG_EBX]));
}

int64_t i686_pass_r_dup2(i686_ctx_t *ctx)
{
    return host_ret_(dup2((int)ctx->gpr[I686_REG_EBX], (int)ctx->gpr[I686_REG_ECX]));
}

int64_t i686_pass_r_dup3(i686_ctx_t *ctx)
{
    return sys_dup3(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                    ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_pipe(i686_ctx_t *ctx)
{
    return sys_pipe2(ctx, ctx->gpr[I686_REG_EBX], 0U);
}

int64_t i686_pass_r_pipe2(i686_ctx_t *ctx)
{
    return sys_pipe2(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static long sys_pread64(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va,
                        uint32_t count, uint32_t pos_lo, uint32_t pos_hi)
{
    off_t pos = (off_t)(((uint64_t)pos_hi << 32) | (uint64_t)pos_lo);

    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    return host_ret_(pread((int)fd, i686_guest_ptr(ctx, buf_va),
                           (size_t)count, pos));
}

static long sys_pwrite64(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va,
                         uint32_t count, uint32_t pos_lo, uint32_t pos_hi)
{
    off_t pos = (off_t)(((uint64_t)pos_hi << 32) | (uint64_t)pos_lo);

    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    {
        long rc = host_ret_(pwrite((int)fd, i686_guest_ptr(ctx, buf_va),
                                   (size_t)count, pos));
        if (rc > 0) {
            i686_vm_file_note_pwrite((int)fd, (uint64_t)pos, (size_t)rc);
        }
        return rc;
    }
}

int64_t i686_pass_r_pread64(i686_ctx_t *ctx)
{
    return sys_pread64(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                       ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                       ctx->gpr[I686_REG_EDI]);
}

int64_t i686_pass_r_pwrite64(i686_ctx_t *ctx)
{
    return sys_pwrite64(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                        ctx->gpr[I686_REG_EDI]);
}

int64_t i686_pass_r_ftruncate64(i686_ctx_t *ctx)
{
    off_t len = (off_t)(((uint64_t)ctx->gpr[I686_REG_EDX] << 32) |
                        (uint64_t)ctx->gpr[I686_REG_ECX]);
    long rc = host_ret_(ftruncate((int)ctx->gpr[I686_REG_EBX], len));
    if (rc == 0 && len >= 0) {
        i686_vm_file_note_ftruncate((int)ctx->gpr[I686_REG_EBX],
                                    (uint64_t)len);
    }
    return (int64_t)rc;
}

int64_t i686_pass_r_ioctl(i686_ctx_t *ctx)
{
    return sys_ioctl(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_munmap(i686_ctx_t *ctx)
{
    return rt32_vm_munmap(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_mprotect(i686_ctx_t *ctx)
{
    return rt32_vm_mprotect(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                            ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_mremap(i686_ctx_t *ctx)
{
    uint32_t r = rt32_vm_mremap(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                                ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                                ctx->gpr[I686_REG_EDI]);
    return (long)(int32_t)r;
}

int64_t i686_pass_r_msync(i686_ctx_t *ctx)
{
    uint32_t flags = ctx->gpr[I686_REG_EDX];

    if ((flags & ~(I686_MS_ASYNC | I686_MS_INVALIDATE | I686_MS_SYNC)) != 0U) {
        return -EINVAL;
    }
    return host_ret_int(msync(i686_guest_ptr(ctx, ctx->gpr[I686_REG_EBX]),
                              (size_t)ctx->gpr[I686_REG_ECX], (int)flags));
}
