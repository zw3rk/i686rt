/*
 * src/os/backend_darwin_net.c - Darwin net, epoll, futex, clocks (contract sections 6-7) (Wave U3, lane u3-i686)
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
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
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

/* libSystem ulock SPI (no public header; signatures verified by probe). */
extern int __ulock_wait(uint32_t operation, void *addr, uint64_t value,
                        uint32_t timeout);
extern int __ulock_wake(uint32_t operation, void *addr, uint64_t wake_value);

#define I686_UL_COMPARE_AND_WAIT 1u
#define I686_ULF_WAKE_ALL 0x100u

/* Linux epoll constants mirrored for the kqueue emulation. */
#define I686_EPOLLIN 0x001u
#define I686_EPOLLOUT 0x004u
#define I686_EPOLLERR 0x008u
#define I686_EPOLLHUP 0x010u
#define I686_EPOLL_CTL_ADD 1
#define I686_EPOLL_CTL_DEL 2
#define I686_EPOLL_CTL_MOD 3
#define I686_EPOLL_MAX 64

typedef struct {
    uint32_t events;
    uint32_t pad;
    uint64_t data;
} i686_epoll_event_t;

_Static_assert(sizeof(i686_epoll_event_t) == 16, "epoll_event is 16 bytes");

typedef struct {
    int used;
    int fd;
    uint32_t events;
    uint64_t data;
} i686_epoll_slot_t;

typedef struct {
    int kq;
    i686_epoll_slot_t slots[I686_EPOLL_MAX];
} i686_epoll_set_t;


/* Lease check: bail out before sleeping when a signal already landed.
 * (One static copy per backend TU; see backend.h section 4.) */
static bool lease_valid(const rt_worker_sync_t *ws, uint32_t expected_seq)
{
    return ws == NULL || atomic_load(&ws->sig_seq) == expected_seq;
}

/* I686-R5-10: readiness wait shared from backend_darwin_io.c
 * (i686_darwin_wait_fd, declared in backend.h). */

int64_t rt_host_socket(int linux_domain, int linux_type, int protocol)
{
    int fd = socket(linux_domain, linux_type & 0xff, protocol);
    if (fd < 0) {
        return (int64_t)-errno;
    }
    if ((linux_type & 02000000) != 0) { /* SOCK_CLOEXEC */
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    if ((linux_type & 04000) != 0) { /* SOCK_NONBLOCK */
        (void)fcntl(fd, F_SETFL, O_NONBLOCK);
    }
    return (int64_t)fd;
}

int64_t rt_host_socketpair(int linux_domain, int linux_type, int protocol,
                           int sv[2])
{
    if (socketpair(linux_domain, linux_type & 0xff, protocol, sv) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_bind(int fd, const void *linux_addr, uint32_t addrlen)
{
    return (bind(fd, linux_addr, (socklen_t)addrlen) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_connect(int fd, const void *linux_addr, uint32_t addrlen,
                        rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int w = i686_darwin_wait_fd(fd, 1, ws, expected_seq, 30000);
    int rc;
    if (w < 0) {
        return (int64_t)w;
    }
    if (w == 0) {
        return -EINTR;
    }
    rc = connect(fd, linux_addr, (socklen_t)addrlen);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_listen(int fd, int backlog)
{
    return (listen(fd, backlog) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_accept4(int fd, void *linux_addr_out, uint32_t *addrlen_inout,
                        int linux_flags, rt_worker_sync_t *ws,
                        uint32_t expected_seq)
{
    int w = i686_darwin_wait_fd(fd, 0, ws, expected_seq, 30000);
    int cfd;
    socklen_t len = (addrlen_inout != NULL) ? (socklen_t)*addrlen_inout : 0u;
    (void)linux_flags;
    if (w < 0) {
        return (int64_t)w;
    }
    if (w == 0) {
        return -EINTR;
    }
    cfd = accept(fd, linux_addr_out, (addrlen_inout != NULL) ? &len : NULL);
    if (cfd < 0) {
        return (int64_t)-errno;
    }
    if (addrlen_inout != NULL) {
        *addrlen_inout = (uint32_t)len;
    }
    return (int64_t)cfd;
}

int64_t rt_host_sendto(int fd, const void *buf, size_t len, int linux_flags,
                       const void *linux_dest_addr, uint32_t addrlen,
                       rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int w = i686_darwin_wait_fd(fd, 1, ws, expected_seq, 30000);
    ssize_t n;
    if (w < 0) {
        return (int64_t)w;
    }
    if (w == 0) {
        return -EINTR;
    }
    n = sendto(fd, buf, len, linux_flags, linux_dest_addr, (socklen_t)addrlen);
    return (n < 0) ? (int64_t)-errno : (int64_t)n;
}

int64_t rt_host_recvfrom(int fd, void *buf, size_t len, int linux_flags,
                         void *linux_src_addr_out, uint32_t *addrlen_inout,
                         rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int w = i686_darwin_wait_fd(fd, 0, ws, expected_seq, 30000);
    ssize_t n;
    socklen_t len2 = (addrlen_inout != NULL) ? (socklen_t)*addrlen_inout : 0u;
    if (w < 0) {
        return (int64_t)w;
    }
    if (w == 0) {
        return -EINTR;
    }
    n = recvfrom(fd, buf, len, linux_flags, linux_src_addr_out,
                 (addrlen_inout != NULL) ? &len2 : NULL);
    if (n < 0) {
        return (int64_t)-errno;
    }
    if (addrlen_inout != NULL) {
        *addrlen_inout = (uint32_t)len2;
    }
    return (int64_t)n;
}

int64_t rt_host_getsockname(int fd, void *linux_addr_out, uint32_t *addrlen_inout)
{
    socklen_t len = (socklen_t)*addrlen_inout;
    int rc = getsockname(fd, linux_addr_out, &len);
    if (rc != 0) {
        return (int64_t)-errno;
    }
    *addrlen_inout = (uint32_t)len;
    return 0;
}

int64_t rt_host_getpeername(int fd, void *linux_addr_out, uint32_t *addrlen_inout)
{
    socklen_t len = (socklen_t)*addrlen_inout;
    int rc = getpeername(fd, linux_addr_out, &len);
    if (rc != 0) {
        return (int64_t)-errno;
    }
    *addrlen_inout = (uint32_t)len;
    return 0;
}

int64_t rt_host_setsockopt(int fd, int linux_level, int linux_optname,
                           const void *optval, uint32_t optlen)
{
    int rc = setsockopt(fd, linux_level, linux_optname, optval, (socklen_t)optlen);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_getsockopt(int fd, int linux_level, int linux_optname,
                           void *optval, uint32_t *optlen_inout)
{
    socklen_t len = (socklen_t)*optlen_inout;
    int rc = getsockopt(fd, linux_level, linux_optname, optval, &len);
    if (rc != 0) {
        return (int64_t)-errno;
    }
    *optlen_inout = (uint32_t)len;
    return 0;
}

int64_t rt_host_shutdown(int fd, int how)
{
    return (shutdown(fd, how) == 0) ? 0 : (int64_t)-errno;
}

/* ppoll scratch: bounded copy so the wake pipe can join the set
 * without a VLA (Curated C11) and without touching caller memory. */
#define I686_PPOLL_MAX 64

int64_t rt_host_ppoll(void *linux_pollfds, size_t nfds,
                      const struct timespec *rel_timeout,
                      const uint64_t *linux_sigmask, rt_worker_sync_t *ws,
                      uint32_t expected_seq)
{
    /* Darwin has no atomic sigmask-swap poll; swap around poll instead
     * (documented approximation; the wake pipe still breaks the wait). */
    struct pollfd copy[I686_PPOLL_MAX + 1];
    struct pollfd *pf = linux_pollfds;
    nfds_t n = (nfds_t)nfds;
    sigset_t old;
    int have_mask = 0;
    int ms = -1;
    int rc;
    size_t i;
    if (linux_sigmask != NULL) {
        if (pthread_sigmask(SIG_SETMASK, (const sigset_t *)(const void *)linux_sigmask,
                            &old) != 0) {
            return (int64_t)-errno;
        }
        have_mask = 1;
    }
    if (rel_timeout != NULL) {
        uint64_t us = (uint64_t)rel_timeout->tv_sec * 1000000u +
                      (uint64_t)rel_timeout->tv_nsec / 1000u;
        ms = (us > (uint64_t)INT_MAX) ? INT_MAX : (int)(us / 1000u);
    }
    if (ws != NULL && ws->wake_pipe_rd >= 0 && nfds <= I686_PPOLL_MAX) {
        for (i = 0u; i < nfds; i++) {
            copy[i] = pf[i];
        }
        copy[nfds].fd = ws->wake_pipe_rd;
        copy[nfds].events = POLLIN;
        copy[nfds].revents = 0;
        pf = copy;
        n = (nfds_t)(nfds + 1u);
    }
    rc = poll(pf, n, ms);
    if (pf == copy) {
        for (i = 0u; i < nfds; i++) {
            ((struct pollfd *)linux_pollfds)[i].revents = copy[i].revents;
        }
        if (rc > 0 && (copy[nfds].revents & POLLIN) != 0) {
            rc--; /* the wake pipe itself is not a guest event */
        }
    }
    if (have_mask != 0) {
        (void)pthread_sigmask(SIG_SETMASK, &old, NULL);
    }
    if (rc < 0) {
        return (int64_t)-errno;
    }
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    return (int64_t)rc;
}

int64_t rt_host_epoll_create1(int linux_flags)
{
    i686_epoll_set_t *set;
    (void)linux_flags;
    set = calloc(1u, sizeof(*set));
    if (set == NULL) {
        return -ENOMEM;
    }
    set->kq = kqueue();
    if (set->kq < 0) {
        int e = errno;
        free(set);
        return -e;
    }
    return (int64_t)(intptr_t)set; /* opaque handle, not a host fd */
}

static i686_epoll_slot_t *epoll_find(i686_epoll_set_t *set, int fd)
{
    size_t i;
    for (i = 0u; i < I686_EPOLL_MAX; i++) {
        if (set->slots[i].used != 0 && set->slots[i].fd == fd) {
            return &set->slots[i];
        }
    }
    return NULL;
}

int64_t rt_host_epoll_ctl(int64_t epfd, int op, int fd,
                          const void *linux_epoll_event)
{
    i686_epoll_set_t *set = (i686_epoll_set_t *)(intptr_t)epfd;
    const i686_epoll_event_t *ev = linux_epoll_event;
    i686_epoll_slot_t *slot;
    struct kevent kev[2];
    int n = 0;
    if (set == NULL) {
        return -EINVAL;
    }
    if (op == I686_EPOLL_CTL_ADD) {
        size_t i;
        if (ev == NULL || epoll_find(set, fd) != NULL) {
            return -EEXIST;
        }
        slot = NULL;
        for (i = 0u; i < I686_EPOLL_MAX; i++) {
            if (set->slots[i].used == 0) {
                slot = &set->slots[i];
                break;
            }
        }
        if (slot == NULL) {
            return -ENOSPC;
        }
        slot->used = 1;
        slot->fd = fd;
        slot->events = ev->events;
        slot->data = ev->data;
    } else if (op == I686_EPOLL_CTL_MOD) {
        if (ev == NULL) {
            return -EINVAL;
        }
        slot = epoll_find(set, fd);
        if (slot == NULL) {
            return -ENOENT;
        }
        slot->events = ev->events;
        slot->data = ev->data;
    } else if (op == I686_EPOLL_CTL_DEL) {
        slot = epoll_find(set, fd);
        if (slot == NULL) {
            return -ENOENT;
        }
        EV_SET(&kev[0], (uintptr_t)fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[1], (uintptr_t)fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        (void)kevent(set->kq, kev, 2, NULL, 0, NULL);
        slot->used = 0;
        return 0;
    } else {
        return -EINVAL;
    }
    if ((slot->events & I686_EPOLLIN) != 0u) {
        EV_SET(&kev[n], (uintptr_t)fd, EVFILT_READ, EV_ADD, 0, 0, slot);
        n++;
    }
    if ((slot->events & I686_EPOLLOUT) != 0u) {
        EV_SET(&kev[n], (uintptr_t)fd, EVFILT_WRITE, EV_ADD, 0, 0, slot);
        n++;
    }
    if (n > 0 && kevent(set->kq, kev, n, NULL, 0, NULL) != 0) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_epoll_pwait(int64_t epfd, void *linux_epoll_events_out,
                            int maxevents, int timeout_ms,
                            const uint64_t *linux_sigmask,
                            rt_worker_sync_t *ws, uint32_t expected_seq)
{
    i686_epoll_set_t *set = (i686_epoll_set_t *)(intptr_t)epfd;
    i686_epoll_event_t *out = linux_epoll_events_out;
    struct kevent evts[I686_EPOLL_MAX];
    struct timespec ts;
    struct timespec *tsp = NULL;
    int n;
    int got = 0;
    int i;
    (void)linux_sigmask;
    if (set == NULL || out == NULL || maxevents <= 0) {
        return -EINVAL;
    }
    if (maxevents > (int)I686_EPOLL_MAX) {
        maxevents = (int)I686_EPOLL_MAX;
    }
    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        tsp = &ts;
    }
    n = kevent(set->kq, NULL, 0, evts, maxevents, tsp);
    if (n < 0) {
        return (int64_t)-errno;
    }
    for (i = 0; i < n && got < maxevents; i++) {
        i686_epoll_slot_t *slot = (i686_epoll_slot_t *)evts[i].udata;
        uint32_t re = 0u;
        if (slot == NULL) {
            continue;
        }
        if (evts[i].filter == EVFILT_READ) {
            re |= I686_EPOLLIN;
        }
        if (evts[i].filter == EVFILT_WRITE) {
            re |= I686_EPOLLOUT;
        }
        if ((evts[i].flags & EV_ERROR) != 0) {
            re |= I686_EPOLLERR;
        }
        if ((evts[i].flags & EV_EOF) != 0) {
            re |= I686_EPOLLHUP;
        }
        out[got].events = re & slot->events;
        if ((re & (I686_EPOLLERR | I686_EPOLLHUP)) != 0u) {
            out[got].events |= re & (I686_EPOLLERR | I686_EPOLLHUP);
        }
        out[got].pad = 0u;
        out[got].data = slot->data;
        got++;
    }
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    return (int64_t)got;
}

int64_t rt_host_futex_wait_bitset(_Atomic uint32_t *pinned_host_uaddr,
                                  const rt_futex_key_t *key,
                                  uint32_t host_endian_val,
                                  const struct timespec *timeout,
                                  int is_abs_timeout, int clock_realtime,
                                  uint32_t bitset, rt_worker_sync_t *ws,
                                  uint32_t expected_seq)
{
    uint32_t timeout_us = 0u;
    int have_timeout = 0;
    int rc;
    (void)key;
    (void)bitset;
    if (ws != NULL && atomic_load(&ws->sig_seq) != expected_seq) {
        return -EINTR;
    }
    if (atomic_load(pinned_host_uaddr) != host_endian_val) {
        return -EAGAIN;
    }
    if (timeout != NULL) {
        if (is_abs_timeout != 0) {
            struct timespec now;
            clockid_t clk =
                (clock_realtime != 0) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
            uint64_t target;
            uint64_t cur;
            clock_gettime(clk, &now);
            target = (uint64_t)timeout->tv_sec * 1000000u +
                     (uint64_t)timeout->tv_nsec / 1000u;
            cur = (uint64_t)now.tv_sec * 1000000u +
                  (uint64_t)now.tv_nsec / 1000u;
            if (target <= cur) {
                return -ETIMEDOUT;
            }
            target -= cur;
            timeout_us = (target > 0xFFFFFFEu) ? 0xFFFFFFEu : (uint32_t)target;
        } else {
            uint64_t us = (uint64_t)timeout->tv_sec * 1000000u +
                          (uint64_t)timeout->tv_nsec / 1000u;
            timeout_us = (us > 0xFFFFFFEu) ? 0xFFFFFFEu : (uint32_t)us;
        }
        have_timeout = 1;
    }
    if (ws != NULL) {
        atomic_store(&ws->ulock_wait_addr, (uintptr_t)pinned_host_uaddr);
    }
    rc = __ulock_wait(I686_UL_COMPARE_AND_WAIT, (void *)pinned_host_uaddr,
                      host_endian_val, have_timeout ? timeout_us : 0u);
    if (ws != NULL) {
        atomic_store(&ws->ulock_wait_addr, 0u);
    }
    if (rc == 0) {
        if (ws != NULL && atomic_load(&ws->sig_seq) != expected_seq) {
            return -EINTR;
        }
        return 0;
    }
    if (errno == ETIMEDOUT) {
        return -ETIMEDOUT;
    }
    if (errno == EINTR) {
        return -EINTR;
    }
    return (int64_t)-errno;
}

int64_t rt_host_futex_wake_bitset(_Atomic uint32_t *pinned_host_uaddr,
                                  const rt_futex_key_t *key, int count,
                                  uint32_t bitset)
{
    int rc;
    (void)key;
    (void)bitset;
    if (count <= 0) {
        count = INT_MAX;
    }
    rc = __ulock_wake(I686_UL_COMPARE_AND_WAIT | I686_ULF_WAKE_ALL,
                      (void *)pinned_host_uaddr, (uint64_t)(uint32_t)count);
    if (rc != 0 && errno != ENOENT) {
        return (int64_t)-errno;
    }
    return 0;
}

int64_t rt_host_futex_requeue(_Atomic uint32_t *pinned_host_uaddr1,
                              const rt_futex_key_t *key1, int wake_count,
                              _Atomic uint32_t *pinned_host_uaddr2,
                              const rt_futex_key_t *key2, int requeue_count,
                              const uint32_t *host_endian_cmp_val)
{
    /* No kernel requeue on Darwin: wake the first queue; waiters re-sleep
     * on the second queue via the futex idiom (value re-check). */
    int64_t rc;
    (void)pinned_host_uaddr2;
    (void)key1;
    (void)key2;
    (void)requeue_count;
    (void)host_endian_cmp_val;
    rc = rt_host_futex_wake_bitset(pinned_host_uaddr1, key1, wake_count, 0u);
    return rc;
}

int64_t rt_host_clock_gettime(int linux_clk_id, struct timespec *tp)
{
    clockid_t clk = CLOCK_REALTIME;
    if (linux_clk_id == 1) { /* CLOCK_MONOTONIC */
        clk = CLOCK_MONOTONIC;
    }
    return (clock_gettime(clk, tp) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_clock_getres(int linux_clk_id, struct timespec *res)
{
    clockid_t clk = CLOCK_REALTIME;
    if (linux_clk_id == 1) {
        clk = CLOCK_MONOTONIC;
    }
    return (clock_getres(clk, res) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_clock_nanosleep(int linux_clk_id, int linux_flags,
                                const struct timespec *req, struct timespec *rem,
                                rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int kq;
    struct kevent kev;
    struct kevent out;
    struct timespec ts;
    int rc;
    (void)linux_clk_id;
    (void)linux_flags;
    (void)rem;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    kq = (ws != NULL && ws->kqueue_fd >= 0) ? ws->kqueue_fd : kqueue();
    ts = *req;
    EV_SET(&kev, 1, EVFILT_TIMER, EV_ADD | EV_ONESHOT, NOTE_NSECONDS,
           (intptr_t)((int64_t)ts.tv_sec * 1000000000L + (int64_t)ts.tv_nsec),
           NULL);
    if (ws != NULL && ws->wake_pipe_rd >= 0) {
        struct kevent kev2;
        EV_SET(&kev2, (uintptr_t)ws->wake_pipe_rd, EVFILT_READ, EV_ADD, 0, 0,
               NULL);
        (void)kevent(kq, &kev2, 1, NULL, 0, NULL);
    }
    rc = kevent(kq, &kev, 1, &out, 1, NULL);
    if (kq != ((ws != NULL) ? ws->kqueue_fd : -1)) {
        (void)close(kq);
    }
    if (rc < 0) {
        return (int64_t)-errno;
    }
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    return 0;
}

int64_t rt_host_getrandom(void *buf, size_t buflen, unsigned int linux_flags)
{
    (void)linux_flags;
    arc4random_buf(buf, buflen);
    return (int64_t)buflen;
}


#else /* !defined(__APPLE__) */

typedef int i686_rt_darwin_absent;

#endif
