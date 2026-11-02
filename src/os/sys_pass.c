/*
 * src/os/sys_pass.c — process syscalls + layout-neutral passthroughs (L2f)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sys_pass_internal.h"

/* rt_sigaction store: guest kernel sigaction (20 B, structs_i386.h
 * i686_sigaction_t) per signum 1..64. */
static struct {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer;
    uint64_t mask;
} s_sigact[65];

uint64_t i686_sigmask_get(void);

struct i686_gsigaction {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer;
    uint32_t mask[2];
};
struct i686_gsigaction *i686_gsig_tab(int signum)
{
    static struct i686_gsigaction v;
    if (signum < 1 || signum > 64) {
        return NULL;
    }
    v.handler = s_sigact[signum].handler;
    v.flags = s_sigact[signum].flags;
    v.restorer = s_sigact[signum].restorer;
    memcpy(v.mask, &s_sigact[signum].mask, sizeof(v.mask));
    return &v;
}

int i686_gsig_is_ignored(int signum);
int i686_gsig_is_ignored(int signum)
{
    return (signum >= 1 && signum <= 64 && s_sigact[signum].handler == 1U);
}

uint32_t i686_gsig_handler_raw(int signum);
uint32_t i686_gsig_handler_raw(int signum)
{
    if (signum < 1 || signum > 64) {
        return 0U;
    }
    return s_sigact[signum].handler;
}

void i686_gsig_exec_reset(void);
void i686_gsig_exec_reset(void)
{
    int s;
    for (s = 1; s <= 64; s++) {
        if (s_sigact[s].handler == 1U) {
            continue;
        }
        s_sigact[s].handler = 0U;
        s_sigact[s].flags = 0U;
        s_sigact[s].restorer = 0U;
        s_sigact[s].mask = 0ULL;
    }
}

/* prctl PR_{GET,SET}_NAME: TASK_COMM_LEN = 16 NUL-padded bytes. */
static char s_comm[16];

static long sys_rt_sigaction(i686_ctx_t *ctx, uint32_t sig, uint32_t act_va,
                             uint32_t oldact_va, uint32_t sigsetsize)
{
    uint8_t staged[20];
    int have_staged = 0;
    if (sigsetsize != 8U || sig == 0U || sig > 64U) {
        return -EINVAL;
    }
    if (act_va != 0U) {
        if (guest_ptr_bad(act_va) ||
            i686_copy_from_guest(ctx, staged, act_va, sizeof staged) != 0) {
            return -EFAULT;
        }
        have_staged = 1;
    }
    if (oldact_va != 0U) {
        uint8_t old[20];
        wr_le32(old + 0U, s_sigact[sig].handler);
        wr_le32(old + 4U, s_sigact[sig].flags);
        wr_le32(old + 8U, s_sigact[sig].restorer);
        memcpy(old + 12U, &s_sigact[sig].mask, 8U);
        if (guest_ptr_bad(oldact_va) ||
            i686_copy_to_guest(ctx, oldact_va, old, sizeof old) != 0) {
            return -EFAULT;
        }
    }
    if (have_staged) {
        s_sigact[sig].handler  = rd_le32(staged + 0U);
        s_sigact[sig].flags    = rd_le32(staged + 4U);
        s_sigact[sig].restorer = rd_le32(staged + 8U);
        memcpy(&s_sigact[sig].mask, staged + 12U, 8U);
    }
    return 0;
}

static long sys_rt_sigprocmask(i686_ctx_t *ctx, uint32_t how, uint32_t set_va,
                               uint32_t oldset_va, uint32_t sigsetsize)
{
    uint8_t staged[8];
    int have_staged = 0;
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (set_va != 0U) {
        if (guest_ptr_bad(set_va) ||
            i686_copy_from_guest(ctx, staged, set_va, sizeof staged) != 0) {
            return -EFAULT;
        }
        have_staged = 1;
    }
    if (oldset_va != 0U) {
        uint8_t old[8];
        memcpy(old, &ctx->sig_mask, 8U);
        if (guest_ptr_bad(oldset_va) ||
            i686_copy_to_guest(ctx, oldset_va, old, sizeof old) != 0) {
            return -EFAULT;
        }
    }
    if (have_staged) {
        uint64_t m;
        memcpy(&m, staged, 8U);
        switch (how) {
        case 0U: /* SIG_BLOCK */
            ctx->sig_mask |= m;
            break;
        case 1U: /* SIG_UNBLOCK */
            ctx->sig_mask &= ~m;
            break;
        case 2U: /* SIG_SETMASK */
            ctx->sig_mask = m;
            break;
        default:
            return -EINVAL;
        }
    }
    return 0;
}

static long sys_rt_sigpending(i686_ctx_t *ctx, uint32_t set_va, uint32_t sigsetsize)
{
    uint8_t zeros[8] = { 0 };

    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (guest_ptr_bad(set_va) ||
        i686_copy_to_guest(ctx, set_va, zeros, sizeof zeros) != 0) {
        return -EFAULT;
    }
    return 0;
}

static long sys_sigaltstack(i686_ctx_t *ctx, uint32_t ss_va, uint32_t old_ss_va)
{
    uint8_t staged[SS_];
    int have_staged = 0;
    if (ss_va != 0U) {
        if (guest_ptr_bad(ss_va) ||
            i686_copy_from_guest(ctx, staged, ss_va, sizeof staged) != 0) {
            return -EFAULT;
        }
        have_staged = 1;
    }
    if (old_ss_va != 0U) {
        uint8_t old[SS_];
        uint32_t oflags = ctx->altstack_flags;
        if (ctx->altstack_onstack != 0U) {
            oflags |= 0x1U;
        }
        wr_le32(old + 0U, ctx->altstack_sp);
        wr_le32(old + 4U, oflags);
        wr_le32(old + 8U, ctx->altstack_size);
        if (guest_ptr_bad(old_ss_va) ||
            i686_copy_to_guest(ctx, old_ss_va, old, sizeof old) != 0) {
            return -EFAULT;
        }
    }
    if (have_staged) {
        ctx->altstack_sp    = rd_le32(staged + 0U);
        ctx->altstack_flags = rd_le32(staged + 4U);
        ctx->altstack_size  = rd_le32(staged + 8U);
    }
    return 0;
}

static long sys_prctl(i686_ctx_t *ctx, uint32_t option, uint32_t arg2)
{
    if (option == (uint32_t)PR_SET_NAME_) {
        if (guest_ptr_bad(arg2) ||
            i686_copy_from_guest(ctx, s_comm, arg2, sizeof s_comm) != 0) {
            return -EFAULT;
        }
        return 0;
    }
    if (option == (uint32_t)PR_GET_NAME_) {
        char name[16];
        memcpy(name, s_comm, sizeof name);
        if (guest_ptr_bad(arg2) ||
            i686_copy_to_guest(ctx, arg2, name, sizeof name) != 0) {
            return -EFAULT;
        }
        return 0;
    }
    return -EINVAL;
}

static long sys_set_tid_address(i686_ctx_t *ctx, uint32_t tidptr_va)
{
    uint32_t prev = ctx->clear_child_tid;
    ctx->clear_child_tid = tidptr_va;
    return (long)prev;
}

static long sys_personality(i686_ctx_t *ctx, uint32_t persona)
{
    (void)ctx;
    return (persona == 0U) ? 0 : -EINVAL;
}

static long sys_futex(i686_ctx_t *ctx, uint32_t uaddr, uint32_t op, uint32_t val)
{
    extern int i686_subpage_range_ok(const i686_ctx_t *, uint32_t, uint64_t, uint8_t);
    extern long i686_vm32_futex(i686_ctx_t *, uint32_t, uint32_t, uint32_t,
                                const struct timespec *, uint32_t, uint32_t,
                                uint32_t);
    static const uint32_t timeout_cmds =
        (1u << FUTEX_WAIT_) | (1u << FUTEX_LOCK_PI_) |
        (1u << FUTEX_WAIT_BITSET_) | (1u << FUTEX_WAIT_REQUEUE_PI_);
    static const uint32_t uaddr2_cmds =
        (1u << FUTEX_REQUEUE_) | (1u << FUTEX_CMP_REQUEUE_) |
        (1u << FUTEX_WAKE_OP_) | (1u << FUTEX_WAIT_REQUEUE_PI_) |
        (1u << FUTEX_CMP_REQUEUE_PI_);
    static const uint32_t val2_cmds =
        (1u << FUTEX_REQUEUE_) | (1u << FUTEX_CMP_REQUEUE_) |
        (1u << FUTEX_WAKE_OP_) | (1u << FUTEX_CMP_REQUEUE_PI_);
    uint32_t cmd = op & FUTEX_CMD_MASK_;
    uint32_t utime_va = ctx->gpr[I686_REG_ESI];
    uint32_t uaddr2_va = ctx->gpr[I686_REG_EDI];
    uint32_t val3 = ctx->gpr[I686_REG_EBP];
    struct timespec ts;
    void *arg4;
    void *huaddr2 = NULL;
    long rc;

    if (guest_ptr_bad(uaddr)) {
        return -EFAULT;
    }
    if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u &&
        i686_subpage_range_ok(ctx, uaddr, 4u, 0x01u) == 0) {
        return -EFAULT;
    }
    arg4 = NULL;
    if (cmd < 32u && ((timeout_cmds >> cmd) & 1u) != 0u && utime_va != 0U) {
        struct { int32_t sec; uint32_t nsec; } gts;
        if (i686_copy_from_guest(ctx, &gts, utime_va, sizeof gts) != 0) {
            return -EFAULT;
        }
        ts.tv_sec = (time_t)gts.sec;
        ts.tv_nsec = (long)gts.nsec;
        arg4 = &ts;
    } else if (cmd < 32u && ((val2_cmds >> cmd) & 1u) != 0u) {
        arg4 = (void *)(uintptr_t)ctx->gpr[I686_REG_ESI];
    }
    if (cmd < 32u && ((uaddr2_cmds >> cmd) & 1u)) {
        if (guest_ptr_bad(uaddr2_va)) {
            return -EFAULT;
        }
        if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u &&
            i686_subpage_range_ok(ctx, uaddr2_va, 4u, 0x01u) == 0) {
            return -EFAULT;
        }
        huaddr2 = i686_guest_ptr(ctx, uaddr2_va);
    }
#ifdef __linux__
    if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u) {
        const struct timespec *tp =
            (cmd < 32u && ((timeout_cmds >> cmd) & 1u) != 0u && utime_va != 0U)
                ? &ts
                : NULL;
        rc = i686_vm32_futex(ctx, uaddr, op, val, tp,
                             ctx->gpr[I686_REG_ESI], uaddr2_va, val3);
    } else {
        rc = (long)syscall(SYS_futex, i686_guest_ptr(ctx, uaddr),
                           (unsigned int)op, (unsigned int)val, arg4,
                           huaddr2, (unsigned int)val3);
        if (rc < 0) {
            rc = (errno == EWOULDBLOCK) ? -EAGAIN : -errno;
        }
    }
#else
    (void)huaddr2;
    (void)arg4; /* timeout/val2 words are consumed via ts/ESI above */
    {
        const struct timespec *tp =
            (cmd < 32u && ((timeout_cmds >> cmd) & 1u) != 0u && utime_va != 0U)
                ? &ts
                : NULL;
        rc = i686_vm32_futex(ctx, uaddr, op, val, tp,
                             ctx->gpr[I686_REG_ESI], uaddr2_va, val3);
    }
#endif
    return rc;
}

static int64_t r_rt_sigaction(i686_ctx_t *ctx)
{
    return sys_rt_sigaction(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                            ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_rt_sigprocmask(i686_ctx_t *ctx)
{
    return sys_rt_sigprocmask(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                              ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_rt_sigpending(i686_ctx_t *ctx)
{
    return sys_rt_sigpending(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_sigaltstack(i686_ctx_t *ctx)
{
    return sys_sigaltstack(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_prctl(i686_ctx_t *ctx)
{
    return sys_prctl(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_set_tid_address(i686_ctx_t *ctx)
{
    return sys_set_tid_address(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_personality(i686_ctx_t *ctx)
{
    return sys_personality(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_futex(i686_ctx_t *ctx)
{
    return sys_futex(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

void i686_syscalls_pass_init(void)
{
    i686_sys_register(NR_open, i686_pass_r_open);
    i686_sys_register(NR_openat, i686_pass_r_openat);
    i686_sys_register(NR_writev, i686_pass_r_writev);
    i686_sys_register(NR_readv, i686_pass_r_readv);
    i686_sys_register(NR_close, i686_pass_r_close);
    i686_sys_register(NR_readlink, i686_pass_r_readlink);
    i686_sys_register(NR_lseek, i686_pass_r_lseek);
    i686_sys_register(NR__llseek, i686_pass_r_llseek);
    i686_sys_register(NR_unlink, i686_pass_r_unlink);
    i686_sys_register(NR_rmdir, i686_pass_r_rmdir);
    i686_sys_register(NR_mkdir, i686_pass_r_mkdir);
    i686_sys_register(NR_rename, i686_pass_r_rename);
    i686_sys_register(NR_link, i686_pass_r_link);
    i686_sys_register(NR_symlink, i686_pass_r_symlink);
    i686_sys_register(NR_chmod, i686_pass_r_chmod);
    i686_sys_register(NR_fchmod, i686_pass_r_fchmod);
    i686_sys_register(NR_lchown, i686_pass_r_lchown);
    i686_sys_register(NR_chown, i686_pass_r_chown);
    i686_sys_register(NR_fchown, i686_pass_r_fchown);
    i686_sys_register(NR_lchown32, i686_pass_r_lchown32);
    i686_sys_register(NR_chown32, i686_pass_r_chown32);
    i686_sys_register(NR_fchown32, i686_pass_r_fchown32);
    i686_sys_register(NR_fchmodat, i686_pass_r_fchmodat);
    i686_sys_register(NR_fchownat, i686_pass_r_fchownat);
    i686_sys_register(NR_access, i686_pass_r_access);
    i686_sys_register(NR_faccessat, i686_pass_r_faccessat);
    i686_sys_register(NR_chdir, i686_pass_r_chdir);
    i686_sys_register(NR_fchdir, i686_pass_r_fchdir);
    i686_sys_register(NR_getcwd, i686_pass_r_getcwd);
    i686_sys_register(NR_getppid, i686_pass_r_getppid);
    i686_sys_register(NR_getuid, i686_pass_r_getuid);
    i686_sys_register(NR_getuid32, i686_pass_r_getuid32);
    i686_sys_register(NR_getgid, i686_pass_r_getgid);
    i686_sys_register(NR_getgid32, i686_pass_r_getgid32);
    i686_sys_register(NR_geteuid, i686_pass_r_geteuid);
    i686_sys_register(NR_geteuid32, i686_pass_r_geteuid32);
    i686_sys_register(NR_getegid, i686_pass_r_getegid);
    i686_sys_register(NR_getegid32, i686_pass_r_getegid32);
    i686_sys_register(NR_setuid, i686_pass_r_setuid);
    i686_sys_register(NR_setuid32, i686_pass_r_setuid32);
    i686_sys_register(NR_setgid, i686_pass_r_setgid);
    i686_sys_register(NR_setgid32, i686_pass_r_setgid32);
    i686_sys_register(NR_setgroups, i686_pass_r_setgroups16);
    i686_sys_register(NR_setgroups32, i686_pass_r_setgroups32);
    i686_sys_register(NR_getgroups, i686_pass_r_getgroups16);
    i686_sys_register(NR_getgroups32, i686_pass_r_getgroups32);
    i686_sys_register(NR_umask, i686_pass_r_umask);
    i686_sys_register(NR_dup, i686_pass_r_dup);
    i686_sys_register(NR_dup2, i686_pass_r_dup2);
    i686_sys_register(NR_dup3, i686_pass_r_dup3);
    i686_sys_register(NR_pipe, i686_pass_r_pipe);
    i686_sys_register(NR_pipe2, i686_pass_r_pipe2);
    i686_sys_register(NR_pread64, i686_pass_r_pread64);
    i686_sys_register(NR_pwrite64, i686_pass_r_pwrite64);
    i686_sys_register(NR_ftruncate64, i686_pass_r_ftruncate64);
    i686_sys_register(NR_ioctl, i686_pass_r_ioctl);
    i686_sys_register(NR_munmap, i686_pass_r_munmap);
    i686_sys_register(NR_mprotect, i686_pass_r_mprotect);
    i686_sys_register(NR_mremap, i686_pass_r_mremap);
    i686_sys_register(NR_msync, i686_pass_r_msync);
    i686_sys_register(NR_rt_sigaction, r_rt_sigaction);
    i686_sys_register(NR_rt_sigprocmask, r_rt_sigprocmask);
    i686_sys_register(NR_rt_sigpending, r_rt_sigpending);
    i686_sys_register(NR_sigaltstack, r_sigaltstack);
    i686_sys_register(NR_prctl, r_prctl);
    i686_sys_register(NR_set_tid_address, r_set_tid_address);
    i686_sys_register(NR_personality, r_personality);
    i686_sys_register(NR_futex, r_futex);
}

uint64_t i686_sigmask_get(void)
{
    i686_ctx_t *ctx = i686_current_ctx();
    return (ctx != NULL) ? ctx->sig_mask : 0ULL;
}
