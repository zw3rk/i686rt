/*
 * src/os/backend_linux.c — Host backend for static-PIE aarch64-linux (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Covers native 4 KiB kernels and hyper-linux (where Stage-1 EL1 tables
 * are 4 KiB, so Regime A1 applies): contract sections 1-4 (identity,
 * memory, JIT, worker sync/preemption) and 8 (process, signals).
 * Sections 5-7 (files, net, futex, clocks) live in backend_linux_sys.c;
 * the file was split for the <= 900-line rule. Linux PROT values match
 * the RT_PROT_* contract 1:1. JIT W^X: RW staging flipped to R+RX via
 * mprotect, never W+X simultaneously; guest data pages are never
 * PROT_EXEC.
 *
 * Non-Linux hosts: this TU contributes no symbols (see the guard).
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

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* Futex opcodes (private-process variants keep Rank-1 -> Rank-7 order). */
#define I686_FUTEX_WAIT_BITSET 9
#define I686_FUTEX_WAKE_BITSET 10
#define I686_FUTEX_CMP_REQUEUE 4
#define I686_FUTEX_PRIVATE_FLAG 128
#define I686_FUTEX_CLOCK_REALTIME 256

/* Reserved DBT-preemption signal (UNIFICATION-PLAN 4.5 step 2). */
#define I686_SIG_PREEMPT (SIGRTMIN + 1)

rt_backend_kind_t rt_host_backend_kind(void)
{
    return RT_BACKEND_LINUX;
}

int rt_host_is_hyper_linux(void)
{
    /* hyper-linux exposes the translator handshake device. */
    return (access("/dev/a32host", F_OK) == 0) ? 1 : 0;
}

size_t rt_host_page_size(void)
{
    return rt_host_page_size_query(4096u);
}

int rt_host_map_anon(void *hint_addr, size_t len, int linux_prot, int fixed,
                     int noreplace, void **out_host_addr)
{
    int flags = MAP_PRIVATE | MAP_ANONYMOUS;
    void *p;
    if (out_host_addr == NULL || len == 0u) {
        return -EINVAL;
    }
    if (fixed != 0) {
        flags |= noreplace ? MAP_FIXED_NOREPLACE : MAP_FIXED;
    }
    p = mmap(hint_addr, len, linux_prot, flags, -1, 0);
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
    int fd;
    int rc;
    if (out_host_fd == NULL || size == 0u) {
        return -EINVAL;
    }
    fd = memfd_create(name ? name : "i686rt-shm", MFD_CLOEXEC);
    if (fd < 0) {
        return -errno;
    }
    rc = (int)syscall(SYS_ftruncate, fd, (int64_t)size);
    if (rc != 0) {
        rc = -errno;
        (void)close(fd);
        return rc;
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
    if (msync(host_addr, len, linux_flags) != 0) {
        return -errno;
    }
    return 0;
}

int rt_host_madvise(void *host_addr, size_t len, int linux_advice)
{
    if (madvise(host_addr, len, linux_advice) != 0) {
        return -errno;
    }
    return 0;
}

void *rt_host_jit_alloc(size_t size)
{
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
}

void rt_host_jit_thread_init(void)
{
    /* No APRR on Linux. */
}

void rt_host_jit_begin_write(void *buf, size_t size)
{
    (void)buf;
    (void)size;
}

int rt_host_jit_seal_rx(void *buf, size_t size)
{
    if (mprotect(buf, size, PROT_READ | PROT_EXEC) != 0) {
        return -errno;
    }
    __builtin___clear_cache((char *)buf, (char *)buf + size);
    return 0;
}

void rt_host_jit_free(void *buf, size_t size)
{
    (void)munmap(buf, size);
}

static uint64_t linux_gettid(void)
{
    return (uint64_t)syscall(SYS_gettid);
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
    ws->kqueue_fd = -1;
    ws->host_tid = linux_gettid();
    if (pipe2(fds, O_NONBLOCK | O_CLOEXEC) != 0) {
        return -errno;
    }
    ws->wake_pipe_rd = fds[0];
    ws->wake_pipe_wr = fds[1];
    return 0;
}

void rt_host_worker_sync_destroy(rt_worker_sync_t *ws)
{
    if (ws == NULL) {
        return;
    }
    (void)close(ws->wake_pipe_rd);
    (void)close(ws->wake_pipe_wr);
    ws->wake_pipe_rd = -1;
    ws->wake_pipe_wr = -1;
}

void rt_host_worker_notify_signal(rt_worker_sync_t *ws)
{
    uint8_t one = 1u;
    atomic_fetch_add(&ws->sig_seq, 1u);
    (void)write(ws->wake_pipe_wr, &one, 1u);
}

int rt_host_preempt_worker(uint64_t host_tid)
{
    long rc = syscall(SYS_tgkill, (int64_t)getpid(), (int64_t)host_tid,
                      I686_SIG_PREEMPT);
    return (rc == 0) ? 0 : -errno;
}

/* Lease check: bail out before sleeping when a signal already landed. */

/* Lease check: bail out before sleeping when a signal already landed.
 * (One static copy per backend TU; see backend.h section 4.) */
static bool lease_valid(const rt_worker_sync_t *ws, uint32_t expected_seq)
{
    return ws == NULL ||
           atomic_load(&ws->sig_seq) == expected_seq;
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
        *out_host_tid = 0u; /* tid is known in-thread via rt_host tid query */
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
    (void)syscall(SYS_execve, path, argv, envp);
    return (int64_t)-errno;
}

int64_t rt_host_wait4(int64_t pid, int *linux_status_out, int linux_options,
                      void *rusage_out, rt_worker_sync_t *ws,
                      uint32_t expected_seq)
{
    pid_t rc;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = wait4((pid_t)pid, linux_status_out, linux_options,
               (struct rusage *)rusage_out);
    return (rc < 0) ? (int64_t)-errno : (int64_t)rc;
}

int64_t rt_host_waitid(int idtype, int64_t id, void *linux_siginfo_out,
                       int linux_options, void *rusage_out,
                       rt_worker_sync_t *ws, uint32_t expected_seq)
{
    siginfo_t *si = linux_siginfo_out;
    int rc;
    (void)rusage_out;
    if (!lease_valid(ws, expected_seq)) {
        return -EINTR;
    }
    rc = waitid((idtype_t)idtype, (id_t)id, si, linux_options);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_kill(int64_t pid, int linux_sig)
{
    long rc = syscall(SYS_kill, (pid_t)pid, linux_sig);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int64_t rt_host_tgkill(int64_t tgid, int64_t tid, int linux_sig)
{
    long rc = syscall(SYS_tgkill, (pid_t)tgid, (pid_t)tid, linux_sig);
    return (rc == 0) ? 0 : (int64_t)-errno;
}

int rt_host_sigprocmask(int linux_how, const uint64_t *new_set, uint64_t *old_set)
{
    /* The wire format is one uint64_t (low 64 signals); the host sigset_t
     * is wider, so copy exactly 8 bytes after zeroing. */
    sigset_t n, o, *np = NULL, *op = NULL;
    if (new_set != NULL) {
        memset(&n, 0, sizeof(n));
        memcpy(&n, new_set, sizeof(*new_set));
        np = &n;
    }
    if (old_set != NULL) {
        op = &o;
    }
    if (pthread_sigmask(linux_how, np, op) != 0) {
        return -errno;
    }
    if (old_set != NULL) {
        memcpy(old_set, &o, sizeof(*old_set));
    }
    return 0;
}

void rt_host_exit_thread(int status)
{
    _exit(status);
}

void rt_host_exit_group(int status)
{
    syscall(SYS_exit_group, status);
    __builtin_unreachable();
}

/* Installed dispatch triple (set once before worker spawn). */
static rt_host_sync_fault_fn s_on_sync;
static rt_host_async_sig_fn s_on_async;
static rt_host_preempt_fn s_on_preempt;

static void linux_sync_handler(int sig, siginfo_t *si, void *uc)
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

static void linux_async_handler(int sig, siginfo_t *si, void *uc)
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

static void linux_preempt_handler(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)si;
    if (s_on_preempt != NULL) {
        s_on_preempt(uc);
    }
}

static int install_one(int sig, void (*fn)(int, siginfo_t *, void *), int flags)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = fn;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | flags;
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
    if (install_one(SIGSEGV, linux_sync_handler, 0) != 0 ||
        install_one(SIGBUS, linux_sync_handler, 0) != 0 ||
        install_one(SIGCHLD, linux_async_handler, 0) != 0 ||
        install_one(SIGRTMIN, linux_async_handler, 0) != 0 ||
        install_one(I686_SIG_PREEMPT, linux_preempt_handler, 0) != 0) {
        return -errno;
    }
    return 0;
}

#else /* !defined(__linux__) */

typedef int i686_rt_linux_backend_absent;

#endif
