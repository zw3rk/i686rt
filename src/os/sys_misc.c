/*
 * src/os/sys_misc.c — Phase 2 lane L2e syscall marshalling module
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Owns the misc set: select(82)/_newselect(142), epoll_create(254)/
 * epoll_ctl(255)/epoll_wait(256)/epoll_pwait(319), flock(143),
 * fcntl(55)/fcntl64(221), getrlimit(76)/setrlimit(75)/ugetrlimit(191)/
 * prlimit64(340), sysinfo(116), old mmap(90) and madvise(219).
 */

#include "sys_misc_internal.h"
#include "rt32/rt32_vm_internal.h"

/* Guest MAP_* -> host MAP_*: identical bits; x86-only hints stripped.
 * File-local for now (shared export deferred per the lane card). */
static uint32_t mmap_flags_to_host(uint32_t flags)
{
    return flags & ~(uint32_t)(I686_GM_32BIT_X86 | I686_GM_ABOVE4G_X86);
}

/* ------------------------------------------------------------------ */
/* Host call shims.  The Linux-only set (epoll, sysinfo, prlimit64) has */
/* macOS stand-ins so the module links into the host-native unit test;  */
/* those paths are never exercised by the test driver.                 */
/* ------------------------------------------------------------------ */

#ifdef __linux__

static int64_t host_epoll_create(int size)
{
    return fixup((int64_t)epoll_create(size));
}

static int64_t host_epoll_ctl(int epfd, int op, int fd, uint8_t *host_ev16)
{
    return fixup((int64_t)epoll_ctl(epfd, op, fd, (struct epoll_event *)(void *)host_ev16));
}

static int64_t host_epoll_wait(int epfd, uint8_t *host_ev16, int maxevents,
                               int timeout_ms)
{
    return fixup((int64_t)epoll_wait(epfd, (struct epoll_event *)(void *)host_ev16,
                                     maxevents, timeout_ms));
}

static int64_t host_epoll_pwait(int epfd, uint8_t *host_ev16, int maxevents,
                                int timeout_ms, const uint8_t *mask8)
{
    return fixup((int64_t)epoll_pwait(epfd, (struct epoll_event *)(void *)host_ev16,
                                      maxevents, timeout_ms,
                                      (const sigset_t *)(const void *)mask8));
}

static int64_t host_sysinfo(uint8_t *out112)
{
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        return -(int64_t)errno;
    }
    memcpy(out112, &si, I686_HOST_SYSINFO_SZ);
    return 0;
}

static int64_t host_prlimit64(int64_t pid, int resource, const uint8_t *new16,
                              uint8_t *old16)
{
    return fixup((int64_t)prlimit((pid_t)pid, resource,
                                  (const struct rlimit *)(const void *)new16,
                                  (struct rlimit *)(void *)old16));
}

#else /* !__linux__ (unit-test build host) */

static int64_t host_epoll_create(int size)
{
    (void)size;
    errno = ENOSYS;
    return -1;
}

static int64_t host_epoll_ctl(int epfd, int op, int fd, uint8_t *host_ev16)
{
    (void)epfd;
    (void)op;
    (void)fd;
    (void)host_ev16;
    errno = ENOSYS;
    return -1;
}

static int64_t host_epoll_wait(int epfd, uint8_t *host_ev16, int maxevents,
                               int timeout_ms)
{
    (void)epfd;
    (void)host_ev16;
    (void)maxevents;
    (void)timeout_ms;
    errno = ENOSYS;
    return -1;
}

static int64_t host_epoll_pwait(int epfd, uint8_t *host_ev16, int maxevents,
                                int timeout_ms, const uint8_t *mask8)
{
    (void)epfd;
    (void)host_ev16;
    (void)maxevents;
    (void)timeout_ms;
    (void)mask8;
    errno = ENOSYS;
    return -1;
}

static int64_t host_sysinfo(uint8_t *out112)
{
    (void)out112;
    errno = ENOSYS;
    return -1;
}

static int64_t host_prlimit64(int64_t pid, int resource, const uint8_t *new16,
                              uint8_t *old16)
{
    (void)pid;
    (void)resource;
    (void)new16;
    (void)old16;
    errno = ENOSYS;
    return -1;
}

#endif /* __linux__ */

/* ------------------------------------------------------------------ */
/* select / _newselect                                                  */
/* ------------------------------------------------------------------ */

static int64_t do_select(i686_ctx_t *ctx, uint32_t n, uint32_t in_va,
                         uint32_t out_va, uint32_t exc_va, uint32_t tv_va)
{
    uint8_t gin[I686_FD_BYTES], gout[I686_FD_BYTES], gexc[I686_FD_BYTES];
    uint64_t hin[16], hout[16], hexc[16];
    struct timespec ts = {0, 0}, start = {0, 0};
    uint32_t orig_sec = 0u, orig_usec = 0u;
    int have_tv = (tv_va != 0u);
    int rc;
    int64_t ret;

    if ((int32_t)n < 0) {
        return -EINVAL;
    }
    if (n > I686_FD_SETSIZE) {
        n = I686_FD_SETSIZE; /* kernel clamps n to files->max_fds */
    }
    uint32_t nbytes = ((n + 31u) / 32u) * 4u; /* guest words covering n */

    if (in_va != 0u) {
        int e = i686_copy_from_guest(ctx, gin, in_va, nbytes);
        if (e != 0) return e;
    }
    if (out_va != 0u) {
        int e = i686_copy_from_guest(ctx, gout, out_va, nbytes);
        if (e != 0) return e;
    }
    if (exc_va != 0u) {
        int e = i686_copy_from_guest(ctx, gexc, exc_va, nbytes);
        if (e != 0) return e;
    }

    if (have_tv) {
        i686_timeval_t gtv;
        int e = i686_copy_from_guest(ctx, &gtv, tv_va, sizeof(gtv));
        if (e != 0) return e;
        if (gtv.tv_sec < 0 || gtv.tv_usec < 0 || gtv.tv_usec > 999999) {
            return -EINVAL;
        }
        orig_sec = (uint32_t)gtv.tv_sec;
        orig_usec = (uint32_t)gtv.tv_usec;
        ts.tv_sec = (time_t)gtv.tv_sec;
        ts.tv_nsec = (long)gtv.tv_usec * 1000L;
    }

    if (in_va != 0u) i686_fdset_g2h((uint8_t *)hin, gin, n);
    if (out_va != 0u) i686_fdset_g2h((uint8_t *)hout, gout, n);
    if (exc_va != 0u) i686_fdset_g2h((uint8_t *)hexc, gexc, n);

    if (have_tv && (orig_sec != 0u || orig_usec != 0u)) {
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
    }
    rc = pselect((int)n,
                 (in_va != 0u) ? (fd_set *)(void *)hin : NULL,
                 (out_va != 0u) ? (fd_set *)(void *)hout : NULL,
                 (exc_va != 0u) ? (fd_set *)(void *)hexc : NULL,
                 have_tv ? &ts : NULL, NULL);
    ret = (rc < 0) ? -(int64_t)errno : (int64_t)rc;

    /* fd_set writeback: only on success (kernel skips it on error). */
    if (ret >= 0) {
        if (in_va != 0u) {
            i686_fdset_h2g(gin, (const uint8_t *)hin, n);
            (void)i686_copy_to_guest(ctx, in_va, gin, nbytes);
        }
        if (out_va != 0u) {
            i686_fdset_h2g(gout, (const uint8_t *)hout, n);
            (void)i686_copy_to_guest(ctx, out_va, gout, nbytes);
        }
        if (exc_va != 0u) {
            i686_fdset_h2g(gexc, (const uint8_t *)hexc, n);
            (void)i686_copy_to_guest(ctx, exc_va, gexc, nbytes);
        }
    }

    /* Timeout writeback: remaining time, skipped for a zero timeout,
     * EFAULT-tolerant (kernel poll_select_finish). */
    if (have_tv && (orig_sec != 0u || orig_usec != 0u) &&
        (ret >= 0 || ret == -(int64_t)EINTR)) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            int64_t elapsed_us = (int64_t)(now.tv_sec - start.tv_sec) * 1000000 +
                                 (int64_t)(now.tv_nsec - start.tv_nsec) / 1000;
            int64_t orig_us = (int64_t)orig_sec * 1000000 + (int64_t)orig_usec;
            int64_t rem = orig_us - elapsed_us;
            i686_timeval_t gtv;
            if (rem < 0) {
                rem = 0;
            }
            gtv.tv_sec = (int32_t)(rem / 1000000);
            gtv.tv_usec = (int32_t)(rem % 1000000);
            (void)i686_copy_to_guest(ctx, tv_va, &gtv, sizeof(gtv));
        }
    }
    return ret;
}

static int64_t r_old_select(i686_ctx_t *ctx)
{
    i686_sel_args_t a;
    int e = i686_copy_from_guest(ctx, &a, ctx->gpr[I686_REG_EBX], sizeof(a));
    if (e != 0) return e;
    return do_select(ctx, a.n, a.inp, a.outp, a.exp, a.tvp);
}

static int64_t r_newselect(i686_ctx_t *ctx)
{
    return do_select(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                     ctx->gpr[I686_REG_EDI]);
}

/* ------------------------------------------------------------------ */
/* poll                                                                 */
/* ------------------------------------------------------------------ */

static int64_t r_poll(i686_ctx_t *ctx)
{
    uint32_t fds_va = ctx->gpr[I686_REG_EBX];
    uint32_t nfds = ctx->gpr[I686_REG_ECX];
    int32_t timeout = (int32_t)ctx->gpr[I686_REG_EDX];
    int r;

    if (nfds > 0U && fds_va < 0x1000U) {
        return -EFAULT;
    }
    if ((uint64_t)fds_va + (uint64_t)nfds * 8U > 0x100000000ULL) {
        return -EFAULT;
    }
    r = poll((struct pollfd *)(void *)i686_guest_ptr(ctx, fds_va),
             (nfds_t)nfds, (int)timeout);
    return (r < 0) ? -(long)errno : (int64_t)r;
}

/* ------------------------------------------------------------------ */
/* epoll                                                                */
/* ------------------------------------------------------------------ */

static int64_t r_epoll_create(i686_ctx_t *ctx)
{
    int32_t size = (int32_t)ctx->gpr[I686_REG_EBX];
    if (size <= 0) {
        return -EINVAL; /* kernel SYSCALL_DEFINE1(epoll_create, size) */
    }
    return host_epoll_create((int)size);
}

static int64_t r_epoll_ctl(i686_ctx_t *ctx)
{
    uint32_t op = ctx->gpr[I686_REG_ECX];
    uint32_t ev_va = ctx->gpr[I686_REG_ESI];
    uint8_t host_ev[I686_HOST_EPOLL_SZ] = {0};
    uint8_t guest_ev[12];
    int opv;

    switch (op) {
    case (uint32_t)I686_EPOLL_CTL_ADD:
        opv = I686_EPOLL_CTL_ADD;
        break;
    case (uint32_t)I686_EPOLL_CTL_DEL:
        opv = I686_EPOLL_CTL_DEL;
        break;
    case (uint32_t)I686_EPOLL_CTL_MOD:
        opv = I686_EPOLL_CTL_MOD;
        break;
    default:
        return -EINVAL;
    }

    /* The kernel copies the event only for ADD/MOD (ep_op_has_event). */
    if (opv != I686_EPOLL_CTL_DEL) {
        int e = i686_copy_from_guest(ctx, guest_ev, ev_va, sizeof(guest_ev));
        if (e != 0) return e;
        i686_epoll_unpack_guest(host_ev, guest_ev, 1);
    }
    return host_epoll_ctl((int)ctx->gpr[I686_REG_EBX], opv,
                          (int)ctx->gpr[I686_REG_EDX], host_ev);
}

static int64_t do_epoll_wait(i686_ctx_t *ctx, uint32_t epfd, uint32_t ev_va,
                             uint32_t maxevents, int32_t timeout_ms,
                             uint32_t mask_va, uint32_t sigsetsize)
{
    uint8_t *host_arr = NULL;
    uint8_t *guest_arr = NULL;
    uint8_t mask8[8];
    int64_t r;

    if ((int32_t)maxevents <= 0 || maxevents > (0x7FFFFFFFu / 16u)) {
        return -EINVAL;
    }
    if (mask_va != 0u) {
        if (sigsetsize != 8u) {
            return -EINVAL;
        }
        {
            int e = i686_copy_from_guest(ctx, mask8, mask_va, sizeof(mask8));
            if (e != 0) return e;
        }
    }

    host_arr = (uint8_t *)malloc((size_t)maxevents * I686_HOST_EPOLL_SZ);
    if (host_arr == NULL) {
        return -ENOMEM;
    }
    if (mask_va != 0u) {
        r = host_epoll_pwait((int)epfd, host_arr, (int)maxevents,
                             (int)timeout_ms, mask8);
    } else {
        r = host_epoll_wait((int)epfd, host_arr, (int)maxevents, (int)timeout_ms);
    }
    if (r > 0) {
        guest_arr = (uint8_t *)malloc((size_t)r * 12u);
        if (guest_arr == NULL) {
            free(host_arr);
            return -ENOMEM;
        }
        i686_epoll_pack_guest(guest_arr, host_arr, (int)r);
        {
            int e = i686_copy_to_guest(ctx, ev_va, guest_arr, (size_t)r * 12u);
            if (e != 0) {
                r = e;
            }
        }
    }
    free(guest_arr);
    free(host_arr);
    return r;
}

static int64_t r_epoll_wait(i686_ctx_t *ctx)
{
    return do_epoll_wait(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX],
                         (int32_t)ctx->gpr[I686_REG_ESI], 0u, 0u);
}

static int64_t r_epoll_pwait(i686_ctx_t *ctx)
{
    return do_epoll_wait(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX],
                         (int32_t)ctx->gpr[I686_REG_ESI],
                         ctx->gpr[I686_REG_EDI], ctx->gpr[I686_REG_EBP]);
}

/* ------------------------------------------------------------------ */
/* flock / fcntl / fcntl64                                              */
/* ------------------------------------------------------------------ */

static int64_t r_flock(i686_ctx_t *ctx)
{
    return fixup((int64_t)flock((int)ctx->gpr[I686_REG_EBX],
                                (int)ctx->gpr[I686_REG_ECX]));
}

static int64_t do_fcntl(i686_ctx_t *ctx, int fcntl64_entry)
{
    uint32_t fd = ctx->gpr[I686_REG_EBX];
    uint32_t cmd = ctx->gpr[I686_REG_ECX];
    uint32_t arg = ctx->gpr[I686_REG_EDX];
    int flock_bytes;
    int hcmd = i686_fcntl_cmd_to_host(cmd, fcntl64_entry, &flock_bytes);
    int64_t r;

    if (hcmd < 0) {
        return -EINVAL;
    }

    if (flock_bytes != 0) {
        uint8_t host_fl[I686_HOST_FLOCK_SZ];
        uint8_t guest_fl[24];
        int e = i686_copy_from_guest(ctx, guest_fl, arg, (size_t)flock_bytes);
        if (e != 0) return e;
        if (flock_bytes == 16) {
            i686_flock32_to_host(host_fl, guest_fl);
        } else {
            i686_flock64_to_host(host_fl, (const i686_flock64_t *)(const void *)guest_fl);
        }
        r = fixup((int64_t)fcntl((int)fd, hcmd, host_fl));
        if (r >= 0) {
            if (flock_bytes == 16) {
                i686_flock32_from_host(guest_fl, host_fl);
            } else {
                i686_flock64_from_host((i686_flock64_t *)(void *)guest_fl, host_fl);
            }
            (void)i686_copy_to_guest(ctx, arg, guest_fl, (size_t)flock_bytes);
        }
        return r;
    }

    switch (cmd) {
    case I686_FC_GETFL:
        r = fixup((int64_t)fcntl((int)fd, hcmd, 0));
        return (r >= 0) ? (int64_t)i686_oflags_h2g((uint32_t)r) : r;
    case I686_FC_SETFL:
        return fixup((int64_t)fcntl((int)fd, hcmd, i686_setfl_to_host(arg)));
    case I686_FC_SETOWN:
        return fixup((int64_t)fcntl((int)fd, hcmd, (int)(int32_t)arg));
    case I686_FC_GETOWN_EX:
    case I686_FC_GETOWNER_UIDS: {
        uint8_t out8[8];
        r = fixup((int64_t)fcntl((int)fd, hcmd, out8));
        if (r >= 0) {
            (void)i686_copy_to_guest(ctx, arg, out8, sizeof(out8));
        }
        return r;
    }
    case I686_FC_SETOWN_EX: {
        uint8_t in8[8];
        int e = i686_copy_from_guest(ctx, in8, arg, sizeof(in8));
        if (e != 0) return e;
        return fixup((int64_t)fcntl((int)fd, hcmd, in8));
    }
    default:
        return fixup((int64_t)fcntl((int)fd, hcmd, arg));
    }
}

static int64_t r_fcntl(i686_ctx_t *ctx)
{
    return do_fcntl(ctx, 0);
}

static int64_t r_fcntl64(i686_ctx_t *ctx)
{
    return do_fcntl(ctx, 1);
}

/* ------------------------------------------------------------------ */
/* rlimits                                                              */
/* ------------------------------------------------------------------ */

static int64_t do_getrlimit(i686_ctx_t *ctx)
{
    uint32_t resource = ctx->gpr[I686_REG_EBX];
    uint32_t rlim_va = ctx->gpr[I686_REG_ECX];
    struct rlimit hr;
    i686_rlimit_t gr;

    if (resource >= I686_RLIM_NLIMITS) {
        return -EINVAL;
    }
    if (getrlimit((int)resource, &hr) != 0) {
        return -(int64_t)errno;
    }
    i686_rlimit_h2g(&gr, (uint64_t)hr.rlim_cur, (uint64_t)hr.rlim_max);
    return i686_copy_to_guest(ctx, rlim_va, &gr, sizeof(gr));
}

static int64_t r_getrlimit(i686_ctx_t *ctx)
{
    return do_getrlimit(ctx);
}

static int64_t r_ugetrlimit(i686_ctx_t *ctx)
{
    return do_getrlimit(ctx);
}

static int64_t r_setrlimit(i686_ctx_t *ctx)
{
    uint32_t resource = ctx->gpr[I686_REG_EBX];
    uint32_t rlim_va = ctx->gpr[I686_REG_ECX];
    i686_rlimit_t gr;
    struct rlimit hr;
    uint64_t cur, max;

    if (resource >= I686_RLIM_NLIMITS) {
        return -EINVAL;
    }
    {
        int e = i686_copy_from_guest(ctx, &gr, rlim_va, sizeof(gr));
        if (e != 0) return e;
    }
    i686_rlimit_g2h(&gr, &cur, &max);
    hr.rlim_cur = (rlim_t)cur;
    hr.rlim_max = (rlim_t)max;
    if (setrlimit((int)resource, &hr) != 0) {
        return -(int64_t)errno;
    }
    return 0;
}

static int64_t r_prlimit64(i686_ctx_t *ctx)
{
    uint32_t resource = ctx->gpr[I686_REG_ECX];
    uint32_t new_va = ctx->gpr[I686_REG_EDX];
    uint32_t old_va = ctx->gpr[I686_REG_ESI];
    uint8_t new16[16], old16[16];

    if (resource >= I686_RLIM_NLIMITS) {
        return -EINVAL;
    }
    if (new_va != 0u) {
        int e = i686_copy_from_guest(ctx, new16, new_va, sizeof(new16));
        if (e != 0) return e;
    }
    {
        int64_t r = host_prlimit64((int64_t)(int32_t)ctx->gpr[I686_REG_EBX],
                                   (int)resource, new_va != 0u ? new16 : NULL,
                                   old_va != 0u ? old16 : NULL);
        if (r < 0) {
            return r;
        }
    }
    if (old_va != 0u) {
        return i686_copy_to_guest(ctx, old_va, old16, sizeof(old16));
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* sysinfo / old mmap / madvise                                         */
/* ------------------------------------------------------------------ */

static int64_t r_sysinfo(i686_ctx_t *ctx)
{
    uint8_t host112[I686_HOST_SYSINFO_SZ];
    i686_sysinfo_t g;
    int64_t r = host_sysinfo(host112);
    if (r < 0) {
        return r;
    }
    i686_sysinfo_to_guest(&g, host112);
    return i686_copy_to_guest(ctx, ctx->gpr[I686_REG_EBX], &g, sizeof(g));
}

static int64_t r_old_mmap(i686_ctx_t *ctx)
{
    i686_mmap_arg_struct_t a;
    int e = i686_copy_from_guest(ctx, &a, ctx->gpr[I686_REG_EBX], sizeof(a));
    if (e != 0) return e;

    if ((a.offset & (uint32_t)(I686_PAGE_SIZE - 1u)) != 0u) {
        return -EINVAL;
    }
    {
        uint32_t r = rt32_vm_mmap2(ctx, a.addr, a.len, a.prot,
                                   mmap_flags_to_host(a.flags), (int)a.fd,
                                   a.offset >> 12);
        return (int64_t)(int32_t)r;
    }
}

static int64_t r_madvise(i686_ctx_t *ctx)
{
    /* Validated madvise (I686-R9-3): reject wrap/escape past the 4 GiB
     * window, require page alignment and a fully mapped range, and drop
     * stale translations when discarding executable pages. */
    uint32_t addr = ctx->gpr[I686_REG_EBX];
    uint32_t len = ctx->gpr[I686_REG_ECX];
    int32_t behavior = (int32_t)ctx->gpr[I686_REG_EDX];
    uint64_t end64;
    bool mapped;
    int64_t r;

    if ((addr & (uint32_t)(I686_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    if (len == 0U) {
        return 0;
    }
    end64 = (uint64_t)addr + rt32_page_align_up((uint64_t)len);
    if (addr < I686_LOW_GUARD_SIZE || end64 > (uint64_t)I686_TASK_SIZE_TOP) {
        return -ENOMEM;
    }
    rt32_vm_lock_acquire();
    rt32_vm_sync_from_ctx(ctx);
    mapped = rt32_vm_check_mapped_range_locked(addr, (uint32_t)end64,
                                              NULL, NULL, NULL, 0U);
    rt32_vm_sync_to_ctx(ctx);
    rt32_vm_lock_release();
    if (!mapped) {
        return -ENOMEM;
    }
    r = fixup((int64_t)madvise(i686_guest_ptr(ctx, addr), (size_t)len,
                               (int)behavior));
    if (r == 0 && (behavior == 4U || behavior == 8U || behavior == 9U)) {
        rt32_vm_invalidate_jit(ctx, addr, (uint32_t)end64);
    }
    return r;
}

/* ------------------------------------------------------------------ */
/* registration                                                         */
/* ------------------------------------------------------------------ */

void i686_syscalls_misc_init(void)
{
    i686_sys_register((long)L2E_NR_fcntl, r_fcntl);
    i686_sys_register((long)L2E_NR_setrlimit, r_setrlimit);
    i686_sys_register((long)L2E_NR_getrlimit, r_getrlimit);
    i686_sys_register((long)L2E_NR_ugetrlimit, r_ugetrlimit);
    i686_sys_register((long)L2E_NR_select, r_old_select);
    i686_sys_register((long)L2E_NR_poll, r_poll);
    i686_sys_register((long)L2E_NR_mmap, r_old_mmap);
    i686_sys_register((long)L2E_NR_sysinfo, r_sysinfo);
    i686_sys_register((long)L2E_NR_newselect, r_newselect);
    i686_sys_register((long)L2E_NR_flock, r_flock);
    i686_sys_register((long)L2E_NR_madvise, r_madvise);
    i686_sys_register((long)L2E_NR_fcntl64, r_fcntl64);
    i686_sys_register((long)L2E_NR_epoll_create, r_epoll_create);
    i686_sys_register((long)L2E_NR_epoll_ctl, r_epoll_ctl);
    i686_sys_register((long)L2E_NR_epoll_wait, r_epoll_wait);
    i686_sys_register((long)L2E_NR_epoll_pwait, r_epoll_pwait);
    i686_sys_register((long)L2E_NR_prlimit64, r_prlimit64);
}
