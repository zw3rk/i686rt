/*
 * src/os/backend_darwin.c - Darwin core: identity, memory, JIT, worker sync, process, signals (Wave U3, lane u3-i686)
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

#ifndef MAP_JIT
#define MAP_JIT 0x0800
#endif


#define I686_SIG_PREEMPT SIGUSR2

rt_backend_kind_t rt_host_backend_kind(void)
{
    return RT_BACKEND_DARWIN;
}

int rt_host_is_hyper_linux(void)
{
    return 0;
}

size_t rt_host_page_size(void)
{
    static size_t cached;
    long v;
    if (cached != 0u) {
        return cached;
    }
    v = sysconf(_SC_PAGESIZE);
    cached = (v > 0) ? (size_t)v : 16384u;
    return cached;
}

int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot, int fixed,
                     int noreplace, void **out_host_addr)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    int prot = linux_prot & ~RT_PROT_EXEC;
    void *p;
    (void)noreplace;
    if (out_host_addr == NULL || len == 0u) {
        return -EINVAL;
    }
    if (fixed != 0) {
        flags |= MAP_FIXED;
    }
    p = mmap(hint_addr, len, prot, flags, -1, 0);
    if (p == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = p;
    return 0;
}

int rt_host_map_file(void *hint_addr, size_t len, int linux_prot, int shared,
                     int fixed, int host_fd, uint64_t aligned_file_offset,
                     void **out_host_addr)
{
    int flags = shared ? MAP_SHARED : MAP_PRIVATE;
    void *p;
    if (out_host_addr == NULL || len == 0u || host_fd < 0) {
        return -EINVAL;
    }
    if (fixed != 0) {
        flags |= MAP_FIXED;
    }
    p = mmap(hint_addr, len, linux_prot & ~RT_PROT_EXEC, flags, host_fd,
             (off_t)aligned_file_offset);
    if (p == MAP_FAILED) {
        return -errno;
    }
    *out_host_addr = p;
    return 0;
}

int rt_host_create_shared_mem(const char *name, size_t size, int *out_host_fd)
{
    char path[64];
    int fd;
    static unsigned seq;
    if (out_host_fd == NULL || size == 0u) {
        return -EINVAL;
    }
    /* memfd_create is Linux-only: shm_open with a unique name instead.
     * The name is unlinked immediately so the object is anonymous. */
    snprintf(path, sizeof(path), "/i686rt-%d-%u-%s", (int)getpid(), seq++,
             name ? name : "shm");
    fd = shm_open(path, O_RDWR | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        return -errno;
    }
    (void)shm_unlink(path);
    if (ftruncate(fd, (off_t)size) != 0) {
        int e = errno;
        (void)close(fd);
        return -e;
    }
    *out_host_fd = fd;
    return 0;
}

int rt_host_protect(void *host_addr, size_t len, int linux_prot)
{
    if (mprotect(host_addr, len, linux_prot & ~RT_PROT_EXEC) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_unmap(void *host_addr, size_t len)
{
    if (munmap(host_addr, len) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_msync(void *host_addr, size_t len, int linux_flags)
{
    /* Linux MS_ASYNC=1/MS_INVALIDATE=2/MS_SYNC=4 vs Darwin
     * MS_ASYNC=1/MS_INVALIDATE=2/MS_SYNC=0x10: translate exactly. */
    int flags = 0;
    if ((linux_flags & 0x04) != 0) {
        flags |= MS_SYNC;
    } else if ((linux_flags & 0x01) != 0) {
        flags |= MS_ASYNC;
    } else {
        flags |= MS_SYNC;
    }
    if ((linux_flags & 0x02) != 0) {
        flags |= MS_INVALIDATE;
    }
    if (msync(host_addr, len, flags) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_madvise(void *host_addr, size_t len, int linux_advice)
{
    int advice = MADV_NORMAL;
    (void)linux_advice;
    if (madvise(host_addr, len, advice) != 0) {
        return -errno;
    }
    return 0;
}

/* MAP_JIT allocation carries a fallback flag in the page header word so
 * seal/free take the matching path. Header: 0 = MAP_JIT, 1 = plain. */
#define I686_JIT_HDR 16u

void *rt_host_jit_alloc(size_t size)
{
    size_t total = size + I686_JIT_HDR;
    void *p = mmap(NULL, total, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    if (p == MAP_FAILED) {
        p = mmap(NULL, total, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) {
            return NULL;
        }
        *(uint64_t *)p = 1u;
    } else {
        *(uint64_t *)p = 0u;
    }
    return (uint8_t *)p + I686_JIT_HDR;
}

void rt_host_jit_thread_init(void)
{
    pthread_jit_write_protect_np(1);
}

void rt_host_jit_begin_write(void *buf, size_t size)
{
    uint64_t hdr;
    (void)size;
    if (buf == NULL) {
        return;
    }
    hdr = *(const uint64_t *)((const uint8_t *)buf - I686_JIT_HDR);
    if (hdr == 0u) {
        pthread_jit_write_protect_np(0);
    }
}

int rt_host_jit_seal_rx(void *buf, size_t size)
{
    uint64_t hdr;
    if (buf == NULL) {
        return -EINVAL;
    }
    hdr = *(const uint64_t *)((const uint8_t *)buf - I686_JIT_HDR);
    if (hdr == 0u) {
        pthread_jit_write_protect_np(1);
    } else if (mprotect((uint8_t *)buf - I686_JIT_HDR, size + I686_JIT_HDR,
                        PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
    __builtin___clear_cache((char *)buf, (char *)buf + size);
    return 0;
}

void rt_host_jit_free(void *buf, size_t size)
{
    if (buf != NULL) {
        (void)munmap((uint8_t *)buf - I686_JIT_HDR, size + I686_JIT_HDR);
    }
}

int rt_host_worker_sync_init(rt_worker_sync_t *ws)
{
    int fds[2];
    if (ws == NULL) {
        return -EINVAL;
    }
    atomic_store(&ws->sig_seq, 0u);
    atomic_store(&ws->in_commit_window, 0u);
    atomic_store(&ws->ulock_wait_addr, 0u);
    ws->host_tid = (uint64_t)(uintptr_t)pthread_self();
    if (pipe(fds) != 0) {
        return -errno;
    }
    (void)fcntl(fds[0], F_SETFL, O_NONBLOCK);
    (void)fcntl(fds[1], F_SETFL, O_NONBLOCK);
    ws->wake_pipe_rd = fds[0];
    ws->wake_pipe_wr = fds[1];
    ws->kqueue_fd = kqueue();
    if (ws->kqueue_fd < 0) {
        int e = errno;
        (void)close(fds[0]);
        (void)close(fds[1]);
        return -e;
    }
    return 0;
}

void rt_host_worker_sync_destroy(rt_worker_sync_t *ws)
{
    if (ws == NULL) {
        return;
    }
    (void)close(ws->wake_pipe_rd);
    (void)close(ws->wake_pipe_wr);
    (void)close(ws->kqueue_fd);
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
    ws->kqueue_fd = -1;
}

void rt_host_worker_notify_signal(rt_worker_sync_t *ws)
{
    uint8_t one = 1u;
    atomic_fetch_add(&ws->sig_seq, 1u);
    (void)write(ws->wake_pipe_wr, &one, 1u);
}

int rt_host_preempt_worker(uint64_t host_tid)
{
    pthread_t th = (pthread_t)(uintptr_t)host_tid;
    int rc = pthread_kill(th, I686_SIG_PREEMPT);
    return (rc == 0) ? 0 : -rc;
}


/* Lease check: bail out before sleeping when a signal already landed.
 * (One static copy per backend TU; see backend.h section 4.) */
static bool lease_valid(const rt_worker_sync_t *ws, uint32_t expected_seq)
{
    return ws == NULL || atomic_load(&ws->sig_seq) == expected_seq;
}

int rt_host_worker_altstack_init(void **out_stack_mem, size_t *out_stack_size)
{
    void *p;
    if (out_stack_mem == NULL || out_stack_size == NULL) {
        return -EINVAL;
    }
    p = mmap(NULL, 65536u, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
             -1, 0);
    if (p == MAP_FAILED) {
        return -errno;
    }
    *out_stack_mem = p;
    *out_stack_size = 65536u;
    return 0;
}

void rt_host_worker_altstack_destroy(void *stack_mem, size_t stack_size)
{
    if (stack_mem != NULL && stack_size != 0u) {
        (void)munmap(stack_mem, stack_size);
    }
}

struct worker_start {
    void *(*fn)(void *);
    void *arg;
};

static void *worker_trampoline(void *arg)
{
    struct worker_start *s = arg;
    void *(*fn)(void *) = s->fn;
    void *a = s->arg;
    free(s);
    return fn(a);
}

int rt_host_spawn_worker(void *(*fn)(void *), void *arg, uint64_t *out_host_tid)
{
    struct worker_start *s;
    pthread_t th;
    if (fn == NULL) {
        return -EINVAL;
    }
    s = malloc(sizeof(*s));
    if (s == NULL) {
        return -ENOMEM;
    }
    s->fn = fn;
    s->arg = arg;
    if (pthread_create(&th, NULL, worker_trampoline, s) != 0) {
        free(s);
        return -errno;
    }
    pthread_detach(th);
    if (out_host_tid != NULL) {
        *out_host_tid = (uint64_t)(uintptr_t)th;
    }
    return 0;
}

int64_t rt_host_fork(void)
{
    pid_t p = fork();
    return (p < 0) ? (int64_t)-errno : (int64_t)p;
}

int64_t rt_host_execve(const char *path, char *const argv[], char *const envp[])
{
    (void)execve(path, argv, envp);
    return (int64_t)-errno;
}

int64_t rt_host_wait4(int64_t pid, int *linux_status_out, int linux_options,
                      void *rusage_out, rt_worker_sync_t *ws,
                      uint32_t expected_seq)
{
    int kq = (ws != NULL) ? ws->kqueue_fd : -1;
    int mine = 0;
    struct kevent kev;
    int status = 0;
    pid_t got;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    if ((linux_options & 1) != 0) { /* WNOHANG: single non-blocking reap */
        got = waitpid((pid_t)pid, &status, WNOHANG);
        if (got < 0) {
            return (int64_t)-errno;
        }
        if (got == 0) {
            return 0;
        }
        if (linux_status_out != NULL) {
            *linux_status_out = status;
        }
        return (int64_t)got;
    }
    if (pid < 0) {
        /* Any-child blocking wait: EVFILT_PROC needs one pid, so reap in
         * a wake-pipe-broken poll loop (10 ms quantum, lease-checked). */
        for (;;) {
            struct pollfd pf;
            got = waitpid((pid_t)-1, &status, WNOHANG);
            if (got != 0) {
                break;
            }
            if (!lease_valid(ws, expected_seq)) {
                return -EINTR;
            }
            pf.fd = (ws != NULL) ? ws->wake_pipe_rd : -1;
            pf.events = POLLIN;
            pf.revents = 0;
            if (pf.fd >= 0 && poll(&pf, 1, 10) > 0) {
                return -EINTR;
            }
            if (pf.fd < 0) {
                struct timespec ten_ms = { 0, 10000000L };
                (void)nanosleep(&ten_ms, NULL);
            }
        }
        if (got < 0) {
            return (int64_t)-errno;
        }
        if (linux_status_out != NULL) {
            *linux_status_out = status;
        }
        return (int64_t)got;
    }
    if (kq < 0) {
        kq = kqueue();
        if (kq < 0) {
            return (int64_t)-errno;
        }
        mine = 1;
    }
    EV_SET(&kev, (uintptr_t)pid, EVFILT_PROC, EV_ADD | EV_ONESHOT, NOTE_EXIT,
           0, NULL);
    if (kevent(kq, &kev, 1, NULL, 0, NULL) != 0) {
        if (mine != 0) {
            (void)close(kq);
        }
        return (int64_t)-errno;
    }
    for (;;) {
        struct kevent out;
        int rc = kevent(kq, NULL, 0, &out, 1, NULL);
        if (rc < 0) {
            if (mine != 0) {
                (void)close(kq);
            }
            return (int64_t)-errno;
        }
        if (ws != NULL && ws->wake_pipe_rd >= 0) {
            struct pollfd pf;
            pf.fd = ws->wake_pipe_rd;
            pf.events = POLLIN;
            pf.revents = 0;
            if (poll(&pf, 1, 0) > 0 || !lease_valid(ws, expected_seq)) {
                if (mine != 0) {
                    (void)close(kq);
                }
                return -EINTR;
            }
        }
        if (out.filter == EVFILT_PROC) {
            break;
        }
    }
    if (mine != 0) {
        (void)close(kq);
    }
    (void)rusage_out;
    got = waitpid((pid_t)pid, &status, 0);
    if (got < 0) {
        return (int64_t)-errno;
    }
    if (linux_status_out != NULL) {
        *linux_status_out = status;
    }
    return (int64_t)got;
}

int64_t rt_host_waitid(int idtype, int64_t id, void *linux_siginfo_out,
                       int linux_options, void *rusage_out,
                       rt_worker_sync_t *ws, uint32_t expected_seq)
{
    int status = 0;
    int64_t rc;
    int *out = linux_siginfo_out;
    (void)idtype;
    (void)rusage_out;
    rc = rt_host_wait4(id, &status, linux_options, NULL, ws, expected_seq);
    if (rc < 0) {
        return rc;
    }
    if (out != NULL) {
        out[0] = status;
    }
    return 0;
}

int64_t rt_host_kill(int64_t pid, int linux_sig)
{
    return (kill((pid_t)pid, linux_sig) == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig)
{
    /* Darwin pthread_t convention (see rt_host_preempt_worker). Signal
     * numbers 1..31 coincide with Linux. */
    pthread_t target;
    int rc;
    (void)tgid;
    target = (tid != 0)
                 ? (pthread_t)(uintptr_t)(uint64_t)tid
                 : pthread_self();
    rc = pthread_kill(target, linux_sig);
    return (rc == 0) ? 0 : (int64_t)-rc;
}

int rt_host_sigprocmask(int linux_how, const uint64_t *new_set, uint64_t *old_set)
{
    /* Darwin and Linux signal numbers coincide for 1..31; real-time
     * signals have no Darwin equivalent and are masked to the low word. */
    sigset_t n, o, *np = NULL, *op = NULL;
    int i;
    if (new_set != NULL) {
        uint64_t w = *new_set;
        sigemptyset(&n);
        for (i = 1; i <= 31; i++) {
            if ((w & (UINT64_C(1) << (unsigned)i)) != 0u) {
                sigaddset(&n, i);
            }
        }
        np = &n;
    }
    if (old_set != NULL) {
        op = &o;
    }
    if (pthread_sigmask(linux_how, np, op) != 0) {
        return -errno;
    }
    if (old_set != NULL) {
        uint64_t w = 0u;
        for (i = 1; i <= 31; i++) {
            if (sigismember(&o, i) != 0) {
                w |= UINT64_C(1) << (unsigned)i;
            }
        }
        *old_set = w;
    }
    return 0;
}

void rt_host_exit_thread(int status)
{
    _exit(status);
}

void rt_host_exit_group(int status)
{
    exit(status);
}

static rt_host_sync_fault_fn s_on_sync;
static rt_host_async_sig_fn s_on_async;
static rt_host_preempt_fn s_on_preempt;

static void darwin_sync_handler(int sig, siginfo_t *si, void *uc)
{
    rt_host_sync_fault_t f;
    (void)sig;
    if (s_on_sync == NULL) {
        return;
    }
    f.linux_si_signo = si->si_signo;
    f.linux_si_code = si->si_code;
    f.fault_addr = (uintptr_t)si->si_addr;
    f.host_pc = 0u;
    f.is_write = 0;
    f.host_ucontext = uc;
    s_on_sync(&f);
}

static void darwin_async_handler(int sig, siginfo_t *si, void *uc)
{
    rt_host_async_siginfo_t a;
    (void)uc;
    if (s_on_async == NULL) {
        return;
    }
    a.linux_si_signo = sig;
    a.linux_si_code = si->si_code;
    a.sender_pid = si->si_pid;
    a.sender_uid = si->si_uid;
    a.exit_status_or_sig = si->si_status;
    a.timer_overrun = 0;
    a.sigval_u64 = 0u;
    s_on_async(&a);
}

static void darwin_preempt_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)si;
    if (s_on_preempt != NULL) {
        s_on_preempt(uc);
    }
}

static int install_one(int sig, void (*fn)(int, siginfo_t *, void *))
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fn;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    return sigaction(sig, &sa, NULL);
}

int rt_host_install_signal_handlers(rt_host_sync_fault_fn on_sync_fault,
                                    rt_host_async_sig_fn on_async_sig,
                                    rt_host_preempt_fn on_preempt)
{
    s_on_sync = on_sync_fault;
    s_on_async = on_async_sig;
    s_on_preempt = on_preempt;
    if (install_one(SIGSEGV, darwin_sync_handler) != 0 ||
        install_one(SIGBUS, darwin_sync_handler) != 0 ||
        install_one(SIGCHLD, darwin_async_handler) != 0 ||
        install_one(SIGUSR1, darwin_async_handler) != 0 ||
        install_one(I686_SIG_PREEMPT, darwin_preempt_handler) != 0) {
        return -errno;
    }
    return 0;
}


#else /* !defined(__APPLE__) */

typedef int i686_rt_darwin_absent;

#endif
