/*
 * src/os/backend_linux_sys.c - Linux file, net, futex, clock backends (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Contract sections 5-7 of src/os/backend.h on static-PIE aarch64-linux.
 * Split from backend_linux.c for the <= 900-line rule; same guard.
 * Blocking syscalls check the worker sig_seq lease before sleeping; the
 * signal-window EINTR rewind (safe_syscall [.L_check .. .L_svc]) lands
 * with the trampoline lane and is documented at each wrapper.
 * Curated C11, no VLAs, no x18 (pure C11 file).
 */

#if defined(__linux__)

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "os/backend.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


/* Futex opcodes (private-process variants keep Rank-1 -> Rank-7 order). */
#define I686_FUTEX_WAIT_BITSET 9
#define I686_FUTEX_WAKE_BITSET 10
#define I686_FUTEX_CMP_REQUEUE 4
#define I686_FUTEX_PRIVATE_FLAG 128
#define I686_FUTEX_CLOCK_REALTIME 256


/* Lease check: bail out before sleeping when a signal already landed.
 * (One static copy per backend TU; see backend.h section 4.) */
static bool lease_valid(const rt_worker_sync_t *ws, uint32_t expected_seq)
{
    return ws == NULL ||
           atomic_load(&ws->sig_seq) == expected_seq;
}

int64_t rt_host_openat(int dirfd, const char *path, int linux_flags, uint32_t mode,
                       rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int fd;
    (void)ws;
    (void)expected_seq;
    fd = openat(dirfd, path, linux_flags, (mode_t)mode);
    return (fd < 0) ? (int64_t)-errno : (int64_t)fd;
}

int64_t rt_host_close(int fd)
{
    return (close(fd) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_read(int fd, void *buf, size_t count,
                     rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t n;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    n = read(fd, buf, count);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_write(int fd, const void *buf, size_t count,
                      rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t n;
    if (!lease_valid(ws, expected_seq)) {
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
    ssize_t n;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    n = readv(fd, iov, iovcnt);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_writev(int fd, const struct iovec *iov, int iovcnt,
                       rt_worker_sync_t *ws, uint32_t expected_seq)
{
    ssize_t n;
    if (!lease_valid(ws, expected_seq)) {
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
    /* STATX_BASIC_STATS (0xfff); fills the kernel struct statx for the
     * caller, which owns its layout. */
    long rc = syscall(SYS_statx, dirfd, path, linux_flags, 0xfffu,
                      linux_statx_out);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_ftruncate(int fd, int64_t length)
{
    long rc = syscall(SYS_ftruncate, fd, length);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_fallocate(int fd, int mode, int64_t offset, int64_t len)
{
    long rc = syscall(SYS_fallocate, fd, mode, offset, len);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_sendfile(int out_fd, int in_fd, int64_t *offset, size_t count)
{
    ssize_t n = sendfile(out_fd, in_fd, (off_t *)offset, count);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_copy_file_range(int fd_in, int64_t *off_in, int fd_out,
                                int64_t *off_out, size_t len, unsigned int flags)
{
    ssize_t n = copy_file_range(fd_in, (loff_t *)off_in, fd_out,
                                (loff_t *)off_out, len, flags);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_fsync(int fd, int datasync_only)
{
    int rc = (datasync_only != 0) ? fdatasync(fd) : fsync(fd);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_getdents64(int fd, void *linux_dirent64_buf, size_t buf_size)
{
    long n = syscall(SYS_getdents64, fd, linux_dirent64_buf, buf_size);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_fcntl(int fd, int linux_cmd, uint64_t arg)
{
    errno = 0;
    {
        long rc = syscall(SYS_fcntl, fd, linux_cmd, arg);
        return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
    }
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
    int fd = dup3(oldfd, newfd, linux_flags);
    return (fd < 0) ? (int64_t)-errno : (int64_t)fd;
}

int64_t rt_host_pipe2(int fds[2], int linux_flags)
{
    return (pipe2(fds, linux_flags) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_readlinkat(int dirfd, const char *path, char *buf, size_t bufsiz)
{
    ssize_t n = readlinkat(dirfd, path, buf, bufsiz);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_unlinkat(int dirfd, const char *path, int linux_flags)
{
    return (unlinkat(dirfd, path, linux_flags) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_mkdirat(int dirfd, const char *path, uint32_t mode)
{
    return (mkdirat(dirfd, path, (mode_t)mode) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_renameat2(int olddirfd, const char *oldpath, int newdirfd,
                          const char *newpath, unsigned int flags)
{
    long rc = syscall(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
    return (rc == 0) ? 0 : (int64_t)-errno;
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
    long rc = syscall(SYS_faccessat2, dirfd, path, mode, flags);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_fchmodat(int dirfd, const char *path, uint32_t mode, int flags)
{
    long rc = syscall(SYS_fchmodat, dirfd, path, mode, flags);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_fchownat(int dirfd, const char *path, uint32_t uid, uint32_t gid,
                         int flags)
{
    long rc = syscall(SYS_fchownat, dirfd, path, uid, gid, flags);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_utimensat(int dirfd, const char *path,
                          const struct timespec times[2], int flags)
{
    long rc = syscall(SYS_utimensat, dirfd, path, times, flags);
    return (rc == 0) ? 0 : (int64_t)-errno;
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

int64_t rt_host_socket(int linux_domain, int linux_type, int protocol)
{
    int fd = (int)syscall(SYS_socket, linux_domain, linux_type, protocol);
    return (fd < 0) ? (int64_t)-errno : (int64_t)fd;
}

int64_t rt_host_socketpair(int linux_domain, int linux_type, int protocol,
                           int sv[2])
{
    long rc = syscall(SYS_socketpair, linux_domain, linux_type, protocol, sv);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_bind(int fd, const void *linux_addr, uint32_t addrlen)
{
    long rc = syscall(SYS_bind, fd, linux_addr, addrlen);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_connect(int fd, const void *linux_addr, uint32_t addrlen,
                        rt_worker_sync_t *ws, uint32_t expected_seq)
{
    long rc;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = syscall(SYS_connect, fd, linux_addr, addrlen);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_listen(int fd, int backlog)
{
    long rc = syscall(SYS_listen, fd, backlog);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_accept4(int fd, void *linux_addr_out, uint32_t *addrlen_inout,
                        int linux_flags, rt_worker_sync_t *ws,
                        uint32_t expected_seq)
{
    long rc;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = syscall(SYS_accept4, fd, linux_addr_out, addrlen_inout, linux_flags);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_sendto(int fd, const void *buf, size_t len, int linux_flags,
                       const void *linux_dest_addr, uint32_t addrlen,
                       rt_worker_sync_t *ws, uint32_t expected_seq)
{
    long rc;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = syscall(SYS_sendto, fd, buf, len, linux_flags, linux_dest_addr, addrlen);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_recvfrom(int fd, void *buf, size_t len, int linux_flags,
                         void *linux_src_addr_out, uint32_t *addrlen_inout,
                         rt_worker_sync_t *ws, uint32_t expected_seq)
{
    long rc;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = syscall(SYS_recvfrom, fd, buf, len, linux_flags, linux_src_addr_out,
                 addrlen_inout);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_getsockname(int fd, void *linux_addr_out, uint32_t *addrlen_inout)
{
    long rc = syscall(SYS_getsockname, fd, linux_addr_out, addrlen_inout);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_getpeername(int fd, void *linux_addr_out, uint32_t *addrlen_inout)
{
    long rc = syscall(SYS_getpeername, fd, linux_addr_out, addrlen_inout);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_setsockopt(int fd, int linux_level, int linux_optname,
                           const void *optval, uint32_t optlen)
{
    long rc = syscall(SYS_setsockopt, fd, linux_level, linux_optname, optval,
                      optlen);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_getsockopt(int fd, int linux_level, int linux_optname,
                           void *optval, uint32_t *optlen_inout)
{
    long rc = syscall(SYS_getsockopt, fd, linux_level, linux_optname, optval,
                      optlen_inout);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_shutdown(int fd, int how)
{
    long rc = syscall(SYS_shutdown, fd, how);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_ppoll(void *linux_pollfds, size_t nfds,
                      const struct timespec *rel_timeout,
                      const uint64_t *linux_sigmask, rt_worker_sync_t *ws,
                      uint32_t expected_seq)
{
    long rc;
    (void)linux_sigmask;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = syscall(SYS_ppoll, linux_pollfds, nfds, rel_timeout, NULL, 0);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_epoll_create1(int linux_flags)
{
    int fd = epoll_create1(linux_flags);
    return (fd < 0) ? (int64_t)-errno : (int64_t)fd;
}

int64_t rt_host_epoll_ctl(int64_t epfd, int op, int fd,
                          const void *linux_epoll_event)
{
    long rc = syscall(SYS_epoll_ctl, (int)epfd, op, fd, linux_epoll_event);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_epoll_pwait(int64_t epfd, void *linux_epoll_events_out,
                            int maxevents, int timeout_ms,
                            const uint64_t *linux_sigmask,
                            rt_worker_sync_t *ws, uint32_t expected_seq)
{
    long rc;
    (void)linux_sigmask;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = syscall(SYS_epoll_pwait, (int)epfd, linux_epoll_events_out, maxevents,
                 timeout_ms, NULL, 0);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

/* Futex admission here is the sleep itself: the caller has already pinned
 * (COW-promoted + futex_pin_count bumped) under a short VM lease, which it
 * released before entering (Rank-1 -> Rank-7 safe). */
int64_t rt_host_futex_wait_bitset(_Atomic uint32_t *pinned_host_uaddr,
                                  const rt_futex_key_t *key,
                                  uint32_t host_endian_val,
                                  const struct timespec *timeout,
                                  int is_abs_timeout, int clock_realtime,
                                  uint32_t bitset, rt_worker_sync_t *ws,
                                  uint32_t expected_seq)
{
    int op = I686_FUTEX_WAIT_BITSET | I686_FUTEX_PRIVATE_FLAG;
    struct timespec rel;
    struct timespec now;
    long rc;
    (void)key;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    if (atomic_load(pinned_host_uaddr) != host_endian_val) {
        return -EAGAIN;
    }
    if (timeout != NULL) {
        if (is_abs_timeout != 0) {
            clockid_t clk = (clock_realtime != 0) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
            clock_gettime(clk, &now);
            rel.tv_sec = timeout->tv_sec - now.tv_sec;
            rel.tv_nsec = timeout->tv_nsec - now.tv_nsec;
            if (rel.tv_nsec < 0) {
                rel.tv_sec--;
                rel.tv_nsec += 1000000000L;
            }
            if (rel.tv_sec < 0) {
                return -ETIMEDOUT;
            }
            timeout = &rel;
        }
        if (clock_realtime != 0) {
            op |= I686_FUTEX_CLOCK_REALTIME;
        }
    }
    rc = syscall(SYS_futex, pinned_host_uaddr, op, host_endian_val, timeout,
                 NULL, bitset);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_futex_wake_bitset(_Atomic uint32_t *pinned_host_uaddr,
                                  const rt_futex_key_t *key, int count,
                                  uint32_t bitset)
{
    long rc;
    (void)key;
    rc = syscall(SYS_futex, pinned_host_uaddr,
                 I686_FUTEX_WAKE_BITSET | I686_FUTEX_PRIVATE_FLAG, count, NULL,
                 NULL, bitset);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_futex_requeue(_Atomic uint32_t *pinned_host_uaddr1,
                              const rt_futex_key_t *key1, int wake_count,
                              _Atomic uint32_t *pinned_host_uaddr2,
                              const rt_futex_key_t *key2, int requeue_count,
                              const uint32_t *host_endian_cmp_val)
{
    /* FUTEX_CMP_REQUEUE(uaddr1, op, wake_nr, cmpval, uaddr2, requeue_nr). */
    long rc;
    (void)key1;
    (void)key2;
    rc = syscall(SYS_futex, pinned_host_uaddr1,
                 I686_FUTEX_CMP_REQUEUE | I686_FUTEX_PRIVATE_FLAG, wake_count,
                 host_endian_cmp_val, pinned_host_uaddr2, requeue_count);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp)
{
    return (clock_gettime((clockid_t)linux_clk_id, tp) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_clock_getres(int linux_clk_id, struct timespec *res)
{
    return (clock_getres((clockid_t)linux_clk_id, res) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags,
                                const struct timespec *req, struct timespec *rem,
                                rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int rc;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = clock_nanosleep((clockid_t)linux_clk_id, linux_flags, req, rem);
    return (rc == 0) ? 0 : (int64_t)-rc;
}

int64_t rt_host_getrandom(void *buf, size_t buflen, unsigned int linux_flags)
{
    ssize_t n = getrandom(buf, buflen, linux_flags);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}


#else /* !defined(__linux__) */

typedef int i686_rt_linux_sys_absent;

#endif
