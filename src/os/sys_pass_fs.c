/*
 * src/os/sys_pass_fs.c — Filesystem & marshalling helpers for sys_pass (L2f)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sys_pass_internal.h"

long i686_open_flags_to_host(uint32_t guest_flags)
{
    static const struct { uint32_t guest, host; } map[] = {
        { I686_O_CREAT,     HOST_O_CREAT },
        { I686_O_EXCL,      HOST_O_EXCL },
        { I686_O_NOCTTY,    HOST_O_NOCTTY },
        { I686_O_TRUNC,     HOST_O_TRUNC },
        { I686_O_APPEND,    HOST_O_APPEND },
        { I686_O_NONBLOCK,  HOST_O_NONBLOCK },
        { I686_O_DSYNC,     HOST_O_DSYNC },
        { I686_O_FASYNC,    HOST_O_FASYNC },
        { I686_O_DIRECT,    HOST_O_DIRECT },
        { I686_O_DIRECTORY, HOST_O_DIRECTORY },
        { I686_O_NOFOLLOW,  HOST_O_NOFOLLOW },
        { I686_O_NOATIME,   HOST_O_NOATIME },
        { I686_O_CLOEXEC,   HOST_O_CLOEXEC },
        { I686_O__SYNC,     HOST_O__SYNC },
        { I686_O_PATH,      HOST_O_PATH },
        { I686_O__TMPFILE,  HOST_O__TMPFILE },
    };

    uint32_t host = guest_flags & I686_O_ACCMODE;

    guest_flags &= ~I686_O_ACCMODE;
    if ((guest_flags & I686_O_LARGEFILE) != 0U) {
        guest_flags &= ~I686_O_LARGEFILE;
    }
    for (size_t i = 0U; i < sizeof map / sizeof map[0]; i++) {
        if ((guest_flags & map[i].guest) != 0U) {
            host |= map[i].host;
            guest_flags &= ~map[i].guest;
        }
    }
    if (guest_flags != 0U) {
        return -EINVAL;
    }
    return (long)host;
}

long i686_getcwd_store(i686_ctx_t *ctx, uint32_t buf_va, uint32_t size,
                       const char *cwd, size_t cwd_len)
{
    if (size == 0U) {
        return -EINVAL;
    }
    if (guest_ptr_bad(buf_va) ||
        (uint64_t)buf_va + (uint64_t)cwd_len > 0x100000000ULL) {
        return -EFAULT;
    }
    if ((size_t)size < cwd_len) {
        return -ERANGE;
    }
    int rc = i686_copy_to_guest(ctx, buf_va, cwd, cwd_len);
    return (rc != 0) ? rc : (long)cwd_len;
}

int i686_rusage_to_guest(i686_ctx_t *ctx, uint32_t ru_va, const struct rusage *ru)
{
    uint8_t out[72];
    const long fields[14] = {
        ru->ru_maxrss, ru->ru_ixrss, ru->ru_idrss, ru->ru_isrss,
        ru->ru_minflt, ru->ru_majflt, ru->ru_nswap, ru->ru_inblock,
        ru->ru_oublock, ru->ru_msgsnd, ru->ru_msgrcv, ru->ru_nsignals,
        ru->ru_nvcsw, ru->ru_nivcsw,
    };

    wr_le32(out + 0U, (uint32_t)ru->ru_utime.tv_sec);
    wr_le32(out + 4U, (uint32_t)ru->ru_utime.tv_usec);
    wr_le32(out + 8U, (uint32_t)ru->ru_stime.tv_sec);
    wr_le32(out + 12U, (uint32_t)ru->ru_stime.tv_usec);
    for (size_t i = 0U; i < 14U; i++) {
        wr_le32(out + 16U + 4U * i, (uint32_t)fields[i]);
    }

    if (guest_ptr_bad(ru_va)) {
        return -EFAULT;
    }
    return i686_copy_to_guest(ctx, ru_va, out, sizeof out);
}

int i686_groups_from_guest(i686_ctx_t *ctx, uint32_t list_va, uint32_t n, gid_t **out)
{
    *out = NULL;
    if (n == 0U) {
        return 0;
    }
    if (n > NGROUPS_MAX_) {
        return -EINVAL;
    }
    gid_t *g = malloc((size_t)n * sizeof *g);
    if (g == NULL) {
        return -ENOMEM;
    }
    if (guest_ptr_bad(list_va) ||
        i686_copy_from_guest(ctx, g, list_va, (size_t)n * sizeof *g) != 0) {
        free(g);
        return -EFAULT;
    }
    for (uint32_t i = 0U; i < n; i++) {
        uint32_t v = rd_le32((const uint8_t *)&g[i]);
        g[i] = (gid_t)v;
    }
    *out = g;
    return 0;
}

int i686_groups16_from_guest(i686_ctx_t *ctx, uint32_t list_va, uint32_t n, gid_t **out)
{
    *out = NULL;
    if (n == 0U) {
        return 0;
    }
    if (n > NGROUPS_MAX_) {
        return -EINVAL;
    }
    gid_t *g = malloc((size_t)n * sizeof *g);
    uint8_t *raw = (g != NULL) ? malloc((size_t)n * 2U) : NULL;
    if (g == NULL || raw == NULL) {
        free(g);
        free(raw);
        return -ENOMEM;
    }
    if (guest_ptr_bad(list_va) ||
        i686_copy_from_guest(ctx, raw, list_va, (size_t)n * 2U) != 0) {
        free(g);
        free(raw);
        return -EFAULT;
    }
    for (uint32_t i = 0U; i < n; i++) {
        g[i] = (gid_t)((uint16_t)raw[2U * i] | ((uint16_t)raw[2U * i + 1U] << 8));
    }
    free(raw);
    *out = g;
    return 0;
}

static long open_guest(const i686_ctx_t *ctx, const char *path, int flags,
                       mode_t mode)
{
    char buf[PATH_BUF];
    if (path[0] == '/' && ctx->sysroot != NULL &&
        ctx->sysroot[0] != '\0') {
        size_t n = strlen(ctx->sysroot);
        size_t pl = strlen(path);
        if (n + pl < sizeof buf) {
            memcpy(buf, ctx->sysroot, n);
            memcpy(buf + n, path, pl + 1U);
            {
                int fd = open(buf, flags, mode);
                if (fd >= 0) {
                    return fd;
                }
            }
        }
    }
    return open(path, flags, mode);
}

static long sys_open(i686_ctx_t *ctx, uint32_t path_va, uint32_t flags, uint32_t mode)
{
    char path[PATH_BUF];
    long hf = i686_open_flags_to_host(flags);
    long pfd;
    if (hf < 0) {
        return hf;
    }
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    {
        extern int i686_systrace_on(void);
        if (i686_systrace_on()) {
            (void)fprintf(stderr, "OPEN %s\n", path);
        }
    }
    pfd = i686_proc_open_at(ctx, path);
    if (pfd != I686_PROC_NOT_MATCHED) {
        return pfd;
    }
    return host_ret_(open_guest(ctx, path, (int)hf, (mode_t)mode));
}

static long sys_unlink(i686_ctx_t *ctx, uint32_t path_va)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(unlink(path));
}

static long sys_rmdir(i686_ctx_t *ctx, uint32_t path_va)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(rmdir(path));
}

static long sys_mkdir(i686_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(mkdir(path, (mode_t)mode));
}

static long sys_rename(i686_ctx_t *ctx, uint32_t old_va, uint32_t new_va)
{
    char oldp[PATH_BUF], newp[PATH_BUF];
    if (fetch_path(ctx, old_va, oldp) != 0 || fetch_path(ctx, new_va, newp) != 0) {
        return -EFAULT;
    }
    return host_ret_(rename(oldp, newp));
}

static long sys_link(i686_ctx_t *ctx, uint32_t old_va, uint32_t new_va)
{
    char oldp[PATH_BUF], newp[PATH_BUF];
    if (fetch_path(ctx, old_va, oldp) != 0 || fetch_path(ctx, new_va, newp) != 0) {
        return -EFAULT;
    }
    return host_ret_(link(oldp, newp));
}

static long sys_symlink(i686_ctx_t *ctx, uint32_t target_va, uint32_t link_va)
{
    char target[PATH_BUF], linkp[PATH_BUF];
    if (fetch_path(ctx, target_va, target) != 0 ||
        fetch_path(ctx, link_va, linkp) != 0) {
        return -EFAULT;
    }
    return host_ret_(symlink(target, linkp));
}

static int is_own_proc_exe(const char *linkp)
{
    const char *p;
    long pid;
    char *end;

    if (strncmp(linkp, "/proc/", 6) != 0) {
        return 0;
    }
    p = linkp + 6;
    pid = strtol(p, &end, 10);
    if (end == p || strcmp(end, "/exe") != 0) {
        return 0;
    }
    return pid == (long)getpid();
}

static long sys_readlink(i686_ctx_t *ctx, uint32_t link_va, uint32_t buf_va,
                         uint32_t bufsiz)
{
    char linkp[PATH_BUF];
    char target[PATH_BUF];
    ssize_t n;

    if (fetch_path(ctx, link_va, linkp) != 0) {
        return -EFAULT;
    }
    {
        extern int i686_systrace_on(void);
        if (i686_systrace_on()) {
            (void)fprintf(stderr, "READLINK %s\n", linkp);
        }
    }
    if (bufsiz == 0U) {
        return -EINVAL;
    }
    if (strcmp(linkp, "/proc/self/exe") == 0 || is_own_proc_exe(linkp)) {
        const char *ep = (ctx->exec_path != NULL && ctx->exec_path[0] != '\0')
                             ? ctx->exec_path
                             : ((ctx->guest_argv != NULL &&
                                 ctx->guest_argv[0] != NULL)
                                    ? ctx->guest_argv[0]
                                    : NULL);
        if (ep == NULL || ep[0] == '\0') {
            return -ENOENT;
        }
        n = (ssize_t)strlen(ep);
        if (n > (ssize_t)bufsiz) {
            n = (ssize_t)bufsiz;
        }
        if (i686_copy_to_guest(ctx, buf_va, ep, (size_t)n) != 0) {
            return -EFAULT;
        }
        return (long)n;
    }
    if (linkp[0] == '/' && ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        char sp[PATH_BUF];
        size_t sl = strlen(ctx->sysroot);
        size_t ll = strlen(linkp);

        if (sl + ll < sizeof sp) {
            memcpy(sp, ctx->sysroot, sl);
            memcpy(sp + sl, linkp, ll + 1U);
            n = readlink(sp, target, sizeof target - 1U);
            if (n >= 0) {
                if ((size_t)n > bufsiz) {
                    n = (ssize_t)bufsiz;
                }
                if (i686_copy_to_guest(ctx, buf_va, target, (size_t)n) != 0) {
                    return -EFAULT;
                }
                return (long)n;
            }
        }
    }
    n = readlink(linkp, target, sizeof target - 1U);
    if (n < 0) {
        return -errno;
    }
    if ((size_t)n > bufsiz) {
        n = (ssize_t)bufsiz;
    }
    if (i686_copy_to_guest(ctx, buf_va, target, (size_t)n) != 0) {
        return -EFAULT;
    }
    return (long)n;
}

static long sys_chmod(i686_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(chmod(path, (mode_t)mode));
}

static long sys_fchmod(uint32_t fd, uint32_t mode)
{
    return host_ret_(fchmod((int)fd, (mode_t)mode));
}

static long sys_chown(i686_ctx_t *ctx, uint32_t path_va, uint32_t uid, uint32_t gid)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(chown(path, (uid_t)uid, (gid_t)gid));
}

static long sys_lchown(i686_ctx_t *ctx, uint32_t path_va, uint32_t uid, uint32_t gid)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(lchown(path, (uid_t)uid, (gid_t)gid));
}

static long sys_fchown(uint32_t fd, uint32_t uid, uint32_t gid)
{
    return host_ret_(fchown((int)fd, (uid_t)uid, (gid_t)gid));
}

static long sys_fchmodat(i686_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
                         uint32_t mode, uint32_t flags)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_int(fchmodat((int)(int32_t)dirfd, path, (mode_t)mode, (int)flags));
}

static long sys_fchownat(i686_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
                         uint32_t uid, uint32_t gid, uint32_t flags)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_int(fchownat((int)(int32_t)dirfd, path, (uid_t)uid,
                                 (gid_t)gid, (int)flags));
}

static long sys_access(i686_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    {
        extern int i686_systrace_on(void);
        if (i686_systrace_on()) {
            (void)fprintf(stderr, "ACCESS %s %x\n", path, mode);
        }
    }
    if (path[0] == '/' && ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        char sp[PATH_BUF];
        size_t sl = strlen(ctx->sysroot);
        size_t pl = strlen(path);

        if (sl + pl < sizeof sp) {
            memcpy(sp, ctx->sysroot, sl);
            memcpy(sp + sl, path, pl + 1U);
            if (access(sp, (int)mode) == 0) {
                return 0;
            }
        }
    }
    return host_ret_(access(path, (int)mode));
}

static long sys_faccessat(i686_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
                          uint32_t mode)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    if (path[0] == '/' || (int32_t)dirfd == -100 /* AT_FDCWD */) {
        if (path[0] == '/' && ctx->sysroot != NULL &&
            ctx->sysroot[0] != '\0') {
            char sp[PATH_BUF];
            size_t sl = strlen(ctx->sysroot);
            size_t pl = strlen(path);

            if (sl + pl < sizeof sp) {
                memcpy(sp, ctx->sysroot, sl);
                memcpy(sp + sl, path, pl + 1U);
                if (faccessat(AT_FDCWD, sp, (int)mode, 0) == 0) {
                    return 0;
                }
            }
        }
        return host_ret_int(faccessat(AT_FDCWD, path, (int)mode, 0));
    }
    return host_ret_int(faccessat((int)(int32_t)dirfd, path, (int)mode, 0));
}

static long sys_chdir(i686_ctx_t *ctx, uint32_t path_va)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(chdir(path));
}

static long sys_getcwd(i686_ctx_t *ctx, uint32_t buf_va, uint32_t size)
{
    char cwd[PATH_BUF];
    if (getcwd(cwd, sizeof cwd) == NULL) {
        return -errno;
    }
    return i686_getcwd_store(ctx, buf_va, size, cwd, strlen(cwd) + 1U);
}

int64_t i686_pass_r_openat(i686_ctx_t *ctx)
{
    int32_t dirfd = (int32_t)ctx->gpr[I686_REG_EBX];
    char path[PATH_BUF];
    long hf = i686_open_flags_to_host(ctx->gpr[I686_REG_EDX]);
    long pfd;
    if (hf < 0) {
        return hf;
    }
    if (i686_fetch_cstr(ctx, ctx->gpr[I686_REG_ECX], path, sizeof path) != 0) {
        return -EFAULT;
    }
    {
        extern int i686_systrace_on(void);
        if (i686_systrace_on()) {
            (void)fprintf(stderr, "OPENAT %s\n", path);
        }
    }
    if (path[0] == '/' || dirfd == -100 /* AT_FDCWD */) {
        pfd = i686_proc_open_at(ctx, path);
        if (pfd != I686_PROC_NOT_MATCHED) {
            return pfd;
        }
        return host_ret_(open_guest(ctx, path, (int)hf,
                                    (mode_t)ctx->gpr[I686_REG_ESI]));
    }
    return -EINVAL;
}

int64_t i686_pass_r_open(i686_ctx_t *ctx)
{
    return sys_open(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                    ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_close(i686_ctx_t *ctx)
{
    return host_ret_(close((int)ctx->gpr[I686_REG_EBX]));
}

int64_t i686_pass_r_readlink(i686_ctx_t *ctx)
{
    return sys_readlink(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_lseek(i686_ctx_t *ctx)
{
    return host_ret_(lseek((int)ctx->gpr[I686_REG_EBX],
                           (off_t)(int32_t)ctx->gpr[I686_REG_ECX],
                           (int)ctx->gpr[I686_REG_EDX]));
}

int64_t i686_pass_r_llseek(i686_ctx_t *ctx)
{
    uint64_t off = ((uint64_t)ctx->gpr[I686_REG_ECX] << 32) |
                   (uint64_t)ctx->gpr[I686_REG_EDX];
    uint32_t res_va = ctx->gpr[I686_REG_ESI];
    uint32_t whence = ctx->gpr[I686_REG_EDI];
    off_t pos;
    uint64_t res64;

    if (whence > 2U) {
        return -EINVAL;
    }
    pos = lseek((int)ctx->gpr[I686_REG_EBX], (off_t)off, (int)whence);
    if (pos < 0) {
        return -(int64_t)errno;
    }
    res64 = (uint64_t)pos;
    if (guest_ptr_bad(res_va) ||
        i686_copy_to_guest(ctx, res_va, &res64, sizeof(res64)) != 0) {
        return -EFAULT;
    }
    return 0;
}

int64_t i686_pass_r_unlink(i686_ctx_t *ctx)
{
    return sys_unlink(ctx, ctx->gpr[I686_REG_EBX]);
}

int64_t i686_pass_r_rmdir(i686_ctx_t *ctx)
{
    return sys_rmdir(ctx, ctx->gpr[I686_REG_EBX]);
}

int64_t i686_pass_r_mkdir(i686_ctx_t *ctx)
{
    return sys_mkdir(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_rename(i686_ctx_t *ctx)
{
    return sys_rename(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_link(i686_ctx_t *ctx)
{
    return sys_link(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_symlink(i686_ctx_t *ctx)
{
    return sys_symlink(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_chmod(i686_ctx_t *ctx)
{
    return sys_chmod(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_fchmod(i686_ctx_t *ctx)
{
    return sys_fchmod(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_chown(i686_ctx_t *ctx)
{
    return sys_chown(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_lchown(i686_ctx_t *ctx)
{
    return sys_lchown(ctx, ctx->gpr[I686_REG_EBX],
                      ctx->gpr[I686_REG_ECX] & 0xFFFFu,
                      ctx->gpr[I686_REG_EDX] & 0xFFFFu);
}

int64_t i686_pass_r_fchown(i686_ctx_t *ctx)
{
    return sys_fchown(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX] & 0xFFFFu,
                      ctx->gpr[I686_REG_EDX] & 0xFFFFu);
}

int64_t i686_pass_r_chown32(i686_ctx_t *ctx)
{
    return sys_chown(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_lchown32(i686_ctx_t *ctx)
{
    return sys_lchown(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                      ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_fchown32(i686_ctx_t *ctx)
{
    return sys_fchown(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                      ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_fchmodat(i686_ctx_t *ctx)
{
    return sys_fchmodat(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

int64_t i686_pass_r_fchownat(i686_ctx_t *ctx)
{
    return sys_fchownat(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                        ctx->gpr[I686_REG_EDI]);
}

int64_t i686_pass_r_access(i686_ctx_t *ctx)
{
    return sys_access(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

int64_t i686_pass_r_faccessat(i686_ctx_t *ctx)
{
    return sys_faccessat(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX]);
}

int64_t i686_pass_r_chdir(i686_ctx_t *ctx)
{
    return sys_chdir(ctx, ctx->gpr[I686_REG_EBX]);
}

int64_t i686_pass_r_fchdir(i686_ctx_t *ctx)
{
    return host_ret_(fchdir((int)ctx->gpr[I686_REG_EBX]));
}

int64_t i686_pass_r_getcwd(i686_ctx_t *ctx)
{
    return sys_getcwd(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}
