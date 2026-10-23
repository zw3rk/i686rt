/*
 * src/os/sys_thread.c — thread/sched syscall family registration seam
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Frozen by the coordinator before the fix-campaign fan-out: the
 * thread/sched class (tkill 238, tgkill 270, sched_getaffinity 242,
 * set_robust_list 311, get_robust_list 312) registers from this file
 * so the file-descriptor class keeps exclusive ownership of
 * sys_pass.c (DEFECTS.md C1a/C1b lane split).  C1b also registers the
 * tid-namespace pair this family leans on: set_tid_address 258 and
 * gettid 224 (see the handlers below).  Empty until C1b landed.
 *
 * Signal delivery model (fix-campaign C1b, C2 follows later): raising
 * on another guest thread only sets the target ctx's pending_signals
 * bit; the target's own engine loop polls it at interpreter safe
 * points and builds the sigframe (i686_deliver_pending,
 * src/os/signals_i386.c).  No futex-blocked wakeup, no robust-list
 * walking at thread exit here — that is C2 scope.
 */

#include <errno.h>

#include "os/syscalls_i386.h"
#include "os/marshal.h"

/* Guest tid registry (tid -> ctx, plus the main-ctx live pid rule),
 * implemented next to the tid allocation in r_clone (src/os/clone.c). */
void    i686_thread_registry_main(i686_ctx_t *ctx);
i686_ctx_t *i686_thread_registry_find(uint32_t tid);
uint32_t i686_thread_registry_tgid(void);
uint32_t i686_thread_registry_self_tid(const i686_ctx_t *ctx);

/* i386 struct robust_list_head (include/uapi/linux/futex.h): a
 * robust_list (one pointer), a long futex_offset, and one pending
 * pointer — 3 x 4 B on i386.  set_robust_list's len must match. */
struct i686_robust_list_head {
    uint32_t list;             /* struct robust_list __user *next */
    int32_t  futex_offset;     /* long on i386 */
    uint32_t list_op_pending;  /* struct robust_list __user * */
};

_Static_assert(sizeof(struct i686_robust_list_head) == 12U,
               "i386 robust_list_head must be 12 bytes");

static void guest_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xffU);
    p[1] = (uint8_t)((v >> 8) & 0xffU);
    p[2] = (uint8_t)((v >> 16) & 0xffU);
    p[3] = (uint8_t)((v >> 24) & 0xffU);
}

/* Resolve a guest tid to the target ctx, applying the kernel's
 * "pid 0 means the caller" rule (get_robust_list).  NULL -> -ESRCH. */
static i686_ctx_t *sys_thread_resolve_tid(i686_ctx_t *ctx, int32_t tid)
{
    if (tid == 0) {
        return ctx;
    }
    return i686_thread_registry_find((uint32_t)tid);
}

/* set the pending bit exactly as an in-guest raise would (interp/v86.c
 * set the same bit shape); sig has been range-checked by the caller.
 *
 * Kernel raise semantics (fix-campaign C2): an ignored, unblocked
 * signal is discarded at generation (sig_ignored); the pending bit of
 * a MASKED signal stays set and delivers at unmask.  A target asleep
 * in a host futex never reaches a safe point to poll the bit, so a
 * deliverable bit is followed by the blocked-target wake (clone.c:
 * host SIGUSR1, empty handler, interrupts the futex with EINTR).  A
 * masked bit must NOT wake the target — the kernel keeps it sleeping
 * too. */
static long sys_thread_raise(i686_ctx_t *target, int32_t sig)
{
    extern int i686_gsig_is_ignored(int signum);
    extern void i686_thread_registry_wake(i686_ctx_t *target);
    uint64_t bit;

    if (sig == 0) {
        return 0; /* existence probe: kernel delivers nothing */
    }
    bit = (uint64_t)1U << (uint32_t)(sig - 1);
    if ((target->sig_mask & bit) == 0ULL && i686_gsig_is_ignored(sig)) {
        return 0;
    }
    target->pending_signals |= bit;
    if ((target->sig_mask & bit) == 0ULL) {
        i686_thread_registry_wake(target);
    }
    return 0;
}

/* tkill(238) — sys_tkill(pid_t pid, int sig): EBX=tid, ECX=sig.  The
 * kernel fails pid <= 0 and invalid signals with -EINVAL, unknown tids
 * with -ESRCH, and treats sig 0 as a permissions/existence probe. */
static long sys_tkill(int32_t tid, int32_t sig)
{
    i686_ctx_t *target;
    if (tid <= 0 || sig < 0 || sig > 64) {
        return -EINVAL;
    }
    target = i686_thread_registry_find((uint32_t)tid);
    if (target == NULL) {
        return -ESRCH;
    }
    return sys_thread_raise(target, sig);
}

/* tgkill(270) — sys_tgkill(pid_t tgid, pid_t pid, int sig): EBX=tgid,
 * ECX=tid, EDX=sig.  Kernel do_tkill resolves the tid first (-ESRCH)
 * and then requires the target's thread group to match tgid (-ESRCH);
 * under the translator all guest threads of a process share the one
 * tgid i686_thread_registry_tgid reports.  glibc's raise() arrives
 * here (musl's raise() uses tkill) — this is what makes raise() work. */
static long sys_tgkill(int32_t tgid, int32_t tid, int32_t sig)
{
    i686_ctx_t *target;
    if (tgid <= 0 || tid <= 0 || sig < 0 || sig > 64) {
        return -EINVAL;
    }
    target = i686_thread_registry_find((uint32_t)tid);
    if (target == NULL) {
        return -ESRCH;
    }
    if (tgid != (int32_t)i686_thread_registry_tgid()) {
        return -ESRCH; /* target lives in another thread group */
    }
    return sys_thread_raise(target, sig);
}

/* sched_getaffinity(242) — sys_sched_getaffinity(pid_t pid, unsigned
 * int len, unsigned long __user *user_mask_ptr): EBX=pid, ECX=len,
 * EDX=mask.  Kernel semantics: the caller's buffer receives
 * min(len, kernel mask size) bytes and the return value is that byte
 * count.  v1 exposes a single CPU: the i386 kernel mask is 4 bytes
 * (NR_CPUS 8, 32-bit longs), with CPU 0 set as byte 0.  len < 4 is
 * -EINVAL; unknown pids are -ESRCH (pid 0 = the caller). */
static long sys_sched_getaffinity(i686_ctx_t *ctx, int32_t pid, uint32_t len,
                                  uint32_t mask_va)
{
    static const uint8_t cpu0_mask[4] = { 0x01U, 0x00U, 0x00U, 0x00U };
    uint32_t copy_len;
    int rc;

    if (pid < 0) {
        return -EINVAL;
    }
    if (len < 4U) {
        return -EINVAL; /* smaller than one i386 unsigned long */
    }
    if (pid != 0 && i686_thread_registry_find((uint32_t)pid) == NULL) {
        return -ESRCH;
    }
    copy_len = (len < (uint32_t)sizeof(cpu0_mask)) ? len
                                                   : (uint32_t)sizeof(cpu0_mask);
    rc = i686_copy_to_guest(ctx, mask_va, cpu0_mask, copy_len);
    if (rc != 0) {
        return rc; /* -EFAULT */
    }
    return (long)copy_len;
}

/* set_robust_list(311) — sys_set_robust_list(struct robust_list_head
 * __user *head, size_t len): EBX=head, ECX=len.  The kernel stores the
 * pair per thread and fails any len != sizeof(head) with -EINVAL; the
 * head/len live on the ctx (i686rt.h tail fields).  No walking at
 * thread exit here (C2 scope). */
static long sys_set_robust_list(i686_ctx_t *ctx, uint32_t head_va,
                                uint32_t len)
{
    if (len != (uint32_t)sizeof(struct i686_robust_list_head)) {
        return -EINVAL;
    }
    ctx->robust_list_head = head_va;
    ctx->robust_list_len = len;
    return 0;
}

/* get_robust_list(312) — sys_get_robust_list(int pid, struct
 * robust_list_head __user **head_ptr, size_t __user *len_ptr):
 * EBX=tid, ECX=head_ptr, EDX=len_ptr.  pid 0 means the caller; other
 * tids resolve through the registry (-ESRCH when unknown, v1: own
 * process only).  The head pointer and the length are stored through
 * the two guest pointers. */
static long sys_get_robust_list(i686_ctx_t *ctx, int32_t tid,
                                uint32_t head_ptr_va, uint32_t len_ptr_va)
{
    i686_ctx_t *target;
    uint8_t le[4];
    int rc;

    if (tid < 0) {
        return -EINVAL;
    }
    target = sys_thread_resolve_tid(ctx, tid);
    if (target == NULL) {
        return -ESRCH;
    }
    guest_store_le32(le, target->robust_list_head);
    rc = i686_copy_to_guest(ctx, head_ptr_va, le, sizeof(le));
    if (rc != 0) {
        return rc;
    }
    guest_store_le32(le, target->robust_list_len);
    return i686_copy_to_guest(ctx, len_ptr_va, le, sizeof(le));
}

/* set_tid_address(258) — supersedes the pass-family v1 stub (which
 * returned the previous clear_child_tid, i.e. 0 on the first call).
 * Linux returns the CALLER's thread id, and musl's __init_tp uses
 * exactly that return value as the main thread's tid — without a real
 * tid namespace raise()'s tkill/tgkill cannot address any thread.
 * Registration is last-wins (the same mechanism that lets ldt.c
 * supersede the v1 set_thread_area stub), and this init runs after
 * i686_syscalls_pass_init. */
static long sys_set_tid_address(i686_ctx_t *ctx, uint32_t tidptr_va)
{
    ctx->clear_child_tid = tidptr_va;
    return (long)i686_thread_registry_self_tid(ctx);
}

/* gettid(224) — no register arguments; returns the caller's own guest
 * tid (the same value set_tid_address handed out).  Unregistered
 * before C1b; guests address tkill/tgkill by it. */
static long sys_gettid(i686_ctx_t *ctx)
{
    return (long)i686_thread_registry_self_tid(ctx);
}

/* Register-argument adapters: i386 int 0x80 args ride EBX, ECX, EDX,
 * ESI, EDI in order (verified against syscall_32.tbl rows 224, 238,
 * 242, 258, 270, 311, 312; gettid takes none). */
static int64_t r_tkill(i686_ctx_t *ctx)
{
    return sys_tkill((int32_t)ctx->gpr[I686_REG_EBX],
                     (int32_t)ctx->gpr[I686_REG_ECX]);
}

static int64_t r_tgkill(i686_ctx_t *ctx)
{
    return sys_tgkill((int32_t)ctx->gpr[I686_REG_EBX],
                      (int32_t)ctx->gpr[I686_REG_ECX],
                      (int32_t)ctx->gpr[I686_REG_EDX]);
}

static int64_t r_sched_getaffinity(i686_ctx_t *ctx)
{
    return sys_sched_getaffinity(ctx, (int32_t)ctx->gpr[I686_REG_EBX],
                                 ctx->gpr[I686_REG_ECX],
                                 ctx->gpr[I686_REG_EDX]);
}

static int64_t r_set_robust_list(i686_ctx_t *ctx)
{
    return sys_set_robust_list(ctx, ctx->gpr[I686_REG_EBX],
                               ctx->gpr[I686_REG_ECX]);
}

static int64_t r_get_robust_list(i686_ctx_t *ctx)
{
    return sys_get_robust_list(ctx, (int32_t)ctx->gpr[I686_REG_EBX],
                               ctx->gpr[I686_REG_ECX],
                               ctx->gpr[I686_REG_EDX]);
}

static int64_t r_set_tid_address(i686_ctx_t *ctx)
{
    return sys_set_tid_address(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_gettid(i686_ctx_t *ctx)
{
    return sys_gettid(ctx);
}

void i686_syscalls_thread_init(void)
{
    i686_sys_register(I686__NR_set_tid_address, r_set_tid_address);
    i686_sys_register(I686__NR_gettid, r_gettid);
    i686_sys_register(I686__NR_tkill, r_tkill);
    i686_sys_register(I686__NR_tgkill, r_tgkill);
    i686_sys_register(I686__NR_sched_getaffinity, r_sched_getaffinity);
    i686_sys_register(I686__NR_set_robust_list, r_set_robust_list);
    i686_sys_register(I686__NR_get_robust_list, r_get_robust_list);
}
