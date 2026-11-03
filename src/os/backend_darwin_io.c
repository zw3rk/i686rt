/*
 * src/os/backend_darwin_io.c - Darwin file and descriptor operations (contract section 5) (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from backend_darwin.c for the <= 900-line rule; same guard.
 * Curated C11, no VLAs, no x18 (pure C11 file).
 */

#if defined(__APPLE__)

#if !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <poll.h>

static bool lease_valid(const rt_worker_sync_t *ws, uint32_t expected_seq)
{
    return ws == NULL || atomic_load(&ws->sig_seq) == expected_seq;
}

/* Wait until fd is ready (or the wake pipe fires, or timeout_ms elapses).
 * Returns 1 when fd is ready, 0 on timeout/signal, -errno on error. */
static int darwin_wait_fd(int fd, int for_write, rt_worker_sync_t *ws,
                          uint32_t expected_seq, int timeout_ms)
{
    struct pollfd pf[2];
    int n = 0;
    int rc;
    if (!lease_valid(ws, expected_seq)) {
        return 0;
    }
    pf[0].fd = fd;
    pf[0].events = (short)(for_write ? POLLOUT : POLLIN);
    pf[0].revents = 0;
    n = 1;
    if (ws != NULL && ws->wake_pipe_rd >= 0) {
        pf[1].fd = ws->wake_pipe_rd;
        pf[1].events = POLLIN;
        pf[1].revents = 0;
        n = 2;
    }
    rc = poll(pf, (nfds_t)n, timeout_ms);
    if (rc < 0) {
        return -errno;
    }
    if (rc == 0 || !lease_valid(ws, expected_seq)) {
        return 0;
    }
    if (n == 2 && (pf[1].revents & POLLIN) != 0) {
        return 0;
    }
    return ((pf[0].revents & (POLLIN | POLLOUT | POLLHUP | POLLERR)) != 0) ? 1 : 0;
}

int64_t rt_host_openat(int dirfd, const char *path, int linux_flags, uint32_t mode,
                       rt_worker_sync_t *ws, uint32_t expected_seq)
{
    /* Linux -> Darwin flag translation for the portable subset. Linux-only
     * creation modes (O_TMPFILE, O_PATH, O_DIRECT, ...) are rejected, not
     * silently reinterpreted. */
    int flags = linux_flags & 0x03; /* O_ACCMODE coincides */
    int cloexec = (linux_flags & 02000000) != 0; /* O_CLOEXEC */
    int fd;
    (void)ws;
    (void)expected_seq;
    if ((linux_flags & 0100) != 0) { /* O_CREAT */
        flags |= O_CREAT;
    }
    if ((linux_flags & 0200) != 0) { /* O_EXCL */
        flags |= O_EXCL;
    }
    if ((linux_flags & 01000) != 0) { /* O_TRUNC */
        flags |= O_TRUNC;
    }
    if ((linux_flags & 02000) != 0) { /* O_APPEND */
        flags |= O_APPEND;
    }
    if ((linux_flags & 04000) != 0) { /* O_NONBLOCK */
        flags |= O_NONBLOCK;
    }
    /* Accepted: O_ACCMODE | O_CREAT | O_EXCL | O_TRUNC | O_APPEND |
     * O_NONBLOCK | O_CLOEXEC = 0x80EC3. */
    if ((linux_flags & ~0x80EC3) != 0) {
        return -EINVAL;
    }
    fd = openat(dirfd, path, flags, (mode_t)mode);
    if (fd < 0) {
        return (int64_t)-errno;
    }
    /* O_CLOEXEC is applied post-open: portability across SDKs. */
    if (cloexec != 0) {
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    return (int64_t)fd;
}

int64_t rt_host_close(int fd)
{
    return (close(fd) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_read(int fd, void *buf, size_t count,
                     rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int w = darwin_wait_fd(fd, 0, ws, expected_seq, 30000);
    ssize_t n;
    if (w < 0) {
        return (int64_t)w;
    }
    if (w == 0) {
        return -EINTR;
    }
    n = read(fd, buf, count);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_write(int fd, const void *buf, size_t count,
                      rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int w = darwin_wait_fd(fd, 1, ws, expected_seq, 30000);
    ssize_t n;
    if (w < 0) {
        return (int64_t)w;
    }
    if (w == 0) {
        return -EINTR;
    }
    n = write(fd, buf, count);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_pread64(int fd, void *buf, size_t count, int64_t offset)
{
    ssize_t n = pread(fd, buf, count, (off_t)offset);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_pwrite64(int fd, const void *buf, size_t count, int64_t offset)
{
    ssize_t n = pwrite(fd, buf, count, (off_t)offset);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_readv(int fd, const struct iovec *iov, int iovcnt,
                      rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int w = darwin_wait_fd(fd, 0, ws, expected_seq, 30000);
    ssize_t n;
    if (w < 0) {
        return (int64_t)w;
    }
    if (w == 0) {
        return -EINTR;
    }
    n = readv(fd, iov, iovcnt);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_writev(int fd, const struct iovec *iov, int iovcnt,
                       rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int w = darwin_wait_fd(fd, 1, ws, expected_seq, 30000);
    ssize_t n;
    if (w < 0) {
        return (int64_t)w;
    }
    if (w == 0) {
        return -EINTR;
    }
    n = writev(fd, iov, iovcnt);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_lseek(int fd, int64_t offset, int linux_whence)
{
    off_t rc = lseek(fd, (off_t)offset, linux_whence);
    return (rc == (off_t)-1) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_fstatat(int dirfd, const char *path, void *linux_statx_out,
                        int linux_flags)
{
    /* No statx(2) on Darwin; the Linux statx layout translation belongs to
     * the syscall marshal lane, which reads host struct stat itself. */
    (void)dirfd;
    (void)path;
    (void)linux_statx_out;
    (void)linux_flags;
    return -ENOSYS;
}

int64_t rt_host_ftruncate(int fd, int64_t length)
{
    return (ftruncate(fd, (off_t)length) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_fallocate(int fd, int mode, int64_t offset, int64_t len)
{
    (void)mode;
    /* F_ALLOCATECONTIG/F_ALLOCATEALL as zero-fill reservation. */
    if (ftruncate(fd, (off_t)(offset + len)) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_sendfile(int out_fd, int in_fd, int64_t *offset, size_t count)
{
    /* Portable pread/pwrite loop (Darwin sendfile targets sockets only). */
    uint8_t chunk[8192];
    size_t done = 0u;
    off_t off = (offset != NULL) ? (off_t)*offset : lseek(in_fd, 0, SEEK_CUR);
    while (done < count) {
        size_t want = count - done;
        ssize_t n;
        ssize_t w;
        size_t wdone = 0u;
        if (want > sizeof(chunk)) {
            want = sizeof(chunk);
        }
        n = pread(in_fd, chunk, want, off + (off_t)done);
        if (n < 0) {
            return (int64_t)-errno;
        }
        if (n == 0) {
            break;
        }
        while (wdone < (size_t)n) {
            w = write(out_fd, chunk + wdone, (size_t)n - wdone);
            if (w < 0) {
                return (int64_t)-errno;
            }
            wdone += (size_t)w;
        }
        done += (size_t)n;
    }
    if (offset != NULL) {
        *offset = (int64_t)(off + (off_t)done);
    }
    return (int64_t)done;
}

int64_t rt_host_copy_file_range(int fd_in, int64_t *off_in, int fd_out,
                                int64_t *off_out, size_t len, unsigned int flags)
{
    /* Clone/extent sharing is advisory; plain copy preserves semantics.
     * I686-R4-9: honour an explicit output offset with positioned writes
     * so the descriptor position is left unchanged; a NULL output offset
     * keeps write(2) semantics (use and advance the position). */
    uint8_t chunk[8192];
    int64_t in = (off_in != NULL) ? *off_in : lseek(fd_in, 0, SEEK_CUR);
    int64_t out = (off_out != NULL) ? *off_out : lseek(fd_out, 0, SEEK_CUR);
    int64_t done = 0;
    if (flags != 0u) {
        return (int64_t)-EINVAL;
    }
    if (in < 0 || out < 0) {
        return (int64_t)-errno;
    }
    while ((size_t)done < len) {
        size_t want = len - (size_t)done;
        ssize_t n;
        size_t wdone = 0u;
        if (want > sizeof(chunk)) {
            want = sizeof(chunk);
        }
        n = pread(fd_in, chunk, want, (off_t)(in + done));
        if (n < 0) {
            return (int64_t)-errno;
        }
        if (n == 0) {
            break;
        }
        while (wdone < (size_t)n) {
            ssize_t w;
            if (off_out != NULL) {
                w = pwrite(fd_out, chunk + wdone, (size_t)n - wdone,
                           (off_t)(out + done + (int64_t)wdone));
            } else {
                w = write(fd_out, chunk + wdone, (size_t)n - wdone);
            }
            if (w < 0) {
                return (int64_t)-errno;
            }
            wdone += (size_t)w;
        }
        done += (int64_t)n;
    }
    if (off_in != NULL) {
        *off_in = in + done;
    } else if (done != 0) {
        (void)lseek(fd_in, in + done, SEEK_SET);
    }
    if (off_out != NULL) {
        *off_out = out + done;
    }
    return done;
}

int64_t rt_host_fsync(int fd, int datasync_only)
{
    int rc = (datasync_only != 0) ? fcntl(fd, F_FULLFSYNC) : fsync(fd);
    if (rc != 0 && datasync_only != 0) {
        rc = fsync(fd);
    }
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_getdents64(int fd, void *linux_dirent64_buf, size_t buf_size)
{
    /* Darwin getdirentries64 uses a different record layout; translation
     * belongs to the syscall marshal lane. */
    (void)fd;
    (void)linux_dirent64_buf;
    (void)buf_size;
    return -ENOSYS;
}

int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg)
{
    /* Linux F_* numbers differ; the marshal lane translates. Direct
     * pass-through for the handful that coincide (F_DUPFD, F_GETFL...). */
    int rc = fcntl(fd, linux_cmd, (int)arg);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_ioctl(int fd, uint64_t linux_req, void *arg)
{
    int rc = ioctl(fd, (unsigned long)linux_req, arg);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_dup(int oldfd)
{
    int fd = dup(oldfd);
    return (fd < 0) ? (int64_t)-errno : (int64_t)fd;
}

int64_t rt_host_dup3(int oldfd, int newfd, int linux_flags)
{
    int fd;
    (void)linux_flags;
    fd = dup2(oldfd, newfd);
    if (fd < 0) {
        return (int64_t)-errno;
    }
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    return (int64_t)fd;
}

int64_t rt_host_pipe2(int fds[2], int linux_flags)
{
    if (pipe(fds) != 0) {
        return (int64_t)-errno;
    }
    if ((linux_flags & 02000000) != 0) { /* O_CLOEXEC */
        (void)fcntl(fds[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    }
    if ((linux_flags & 04000) != 0) { /* O_NONBLOCK */
        (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
        (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    }
    return 0;
}

int64_t rt_host_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
{
    ssize_t n = readlinkat(dirfd, path, buf, bufsiz);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_unlinkat(int dirfd, const char *path, int linux_flags)
{
    int flags = (linux_flags & 0x200) ? AT_REMOVEDIR : 0;
    return (unlinkat(dirfd, path, flags) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_mkdirat(int dirfd, const char *path, uint32_t mode)
{
    return (mkdirat(dirfd, path, (mode_t)mode) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                          const char *newpath, unsigned int flags)
{
    if (flags != 0u) {
        return -EINVAL; /* RENAME_* flags have no Darwin equivalent */
    }
    return (renameat(olddirfd, oldpath, newdirfd, newpath) == 0)
               ? 0
               : (int64_t)-errno;
}

int64_t rt_host_symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    return (symlinkat(target, newdirfd, linkpath) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_linkat(int olddirfd, const char *oldpath, int newdirfd,
                       const char *newpath, int flags)
{
    return (linkat(olddirfd, oldpath, newdirfd, newpath, flags) == 0)
               ? 0
               : (int64_t)-errno;
}

int64_t rt_host_faccessat2(int dirfd, const char *path, int mode, int flags)
{
    return (faccessat(dirfd, path, mode, flags) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_fchmodat(int dirfd, const char *path, uint32_t mode, int flags)
{
    (void)flags;
    return (fchmodat(dirfd, path, (mode_t)mode, 0) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_fchownat(int dirfd, const char *path, uint32_t uid, uint32_t gid,
                         int flags)
{
    return (fchownat(dirfd, path, (uid_t)uid, (gid_t)gid, flags) == 0)
               ? 0
               : (int64_t)-errno;
}

int64_t rt_host_utimensat(int dirfd, const char *path,
                          const struct timespec times[2], int flags)
{
    struct timeval tv[2];
    if (flags != 0) {
        return -EINVAL;
    }
    if (times != NULL) {
        tv[0].tv_sec = times[0].tv_sec;
        tv[0].tv_usec = (suseconds_t)(times[0].tv_nsec / 1000L);
        tv[1].tv_sec = times[1].tv_sec;
        tv[1].tv_usec = (suseconds_t)(times[1].tv_nsec / 1000L);
        return (lutimes(path, tv) == 0) ? 0 : (int64_t)-errno;
    }
    (void)dirfd;
    return (lutimes(path, NULL) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_getcwd(char *buf, size_t size)
{
    return (getcwd(buf, size) == NULL) ? (int64_t)-errno : 0;
}

int64_t rt_host_chdir(const char *path)
{
    return (chdir(path) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_fchdir(int fd)
{
    return (fchdir(fd) == 0) ? 0 : (int64_t)-errno;
}


#else /* !defined(__APPLE__) */

typedef int i686_rt_darwin_absent;

#endif
