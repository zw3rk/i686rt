/*
 * src/os/sys_sock.c — Phase 2 socket syscalls (lane L2b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the i386 socket multiplexer socketcall(102) plus the direct
 * (non-multiplexed) socket syscall numbers the generated table names
 * standalone.  Kernel citations (verified against torvalds/linux):
 *
 *  - Subcall numbers SYS_SOCKET(1) .. SYS_SENDMMSG(20):
 *    include/uapi/linux/net.h ("#define SYS_SOCKET 1" .. SYS_ACCEPT4 18,
 *    SYS_RECVMMSG 19, SYS_SENDMMSG 20; unchanged since the historic split
 *    out of include/linux/net.h).
 *  - Per-subcall argument word counts and dispatch shapes:
 *    net/socket.c sys_socketcall (__ARCH_WANT_SYS_SOCKETCALL block):
 *    nargs = {0,3,3,3,2,3,3,3,4,4,4,6,6,2,5,5,3,3,4,5,4} unsigned-long
 *    words for ops 0..20; socketcall(EBX=call, ECX=args) copies
 *    nargs[call] words from user and returns the subcall result directly.
 *    Out-of-range call answers -EINVAL natively; this module returns
 *    -ENOSYS instead per docs/lanes/phase-2.md so support can be probed.
 *  - Syscall numbers 102/337/345/359..373/417: arch/x86/entry/syscalls/
 *    syscall_32.tbl (master) mirrored by the generated, authoritative
 *    src/os/syscalls_i386.h entries [102] socketcall, [337] recvmmsg,
 *    [345] sendmmsg, [359] socket .. [373] shutdown (the direct set is a
 *    recent addition; older kernels multiplexed everything through 102 —
 *    both paths are registered so any guest libc works), [417]
 *    recvmmsg_time64.  There is no direct "accept"/"send"/"recv" on i386:
 *    accept maps to accept4(364)/SYS_ACCEPT4 with flags 0, and
 *    send/recv map to sendto/recvfrom with a NULL address.
 *  - SO_/SOL_/MSG_/AF_ option and flag numbers are ABI-identical between
 *    i386 and aarch64: since Linux 5.1 x86 uses include/uapi/asm-generic/
 *    socket.h verbatim (per-arch copies deleted by the y2038 socket
 *    series), and arm64 always did.  The only bitness-conditional family
 *    (the SO_TIMESTAMP set plus SO_RCVTIMEO/SO_SNDTIMEO) resolves through
 *    sizeof(time_t): an i386 process with 32-bit time_t (musl/glibc i386
 *    today) picks the OLD numbers 20/21/29/35/37 — numerically equal to
 *    the 64-bit pick — while the buffer is a 32-bit timeval (8 B) where
 *    the host expects 16 B; that size conversion is done here.  The NEW
 *    numbers 66/67 carry struct __kernel_sock_timeval {s64,s64} with an
 *    identical layout on both sides and pass through untouched.
 *  - SO_RCVTIMEO_OLD/SO_SNDTIMEO_OLD semantics: net/core/sock.c
 *    sock_set_timeout — optlen < 8 -> -EINVAL, tv_usec < 0 or >= 10^6 ->
 *    -EDOM, negative tv_sec clamps to "no timeout" and returns 0.
 *  - msg_iovlen > UIO_MAXIOV -> -EMSGSIZE and msg_namelen clamped to
 *    sizeof(struct sockaddr_storage): net/compat.c get_compat_msghdr.
 *    UIO_MAXIOV == 1024: include/uapi/linux/uio.h.  sendmmsg/recvmmsg
 *    clamp vlen to UIO_MAXIOV: net/socket.c __sys_sendmmsg/__sys_recvmmsg.
 *  - On recvmsg control truncation the kernel sets MSG_CTRUNC and drops
 *    (closes) fds of SCM_RIGHTS control that did not fit; conversion
 *    overflow on the guest side mirrors that (net/compat.c put_cmsg_
 *    compat sets MSG_CTRUNC when controllen < cmsg_len).
 *
 * Layout conversions (32-bit x86 guest -> 64-bit host):
 *   sockaddr  byte-identical, passed in-window (never sign-extended);
 *   socklen_t unsigned int on both;
 *   iovec     {u32 base,u32 len} -> {host base, host len} walk;
 *   msghdr    28 B i686_msghdr_t -> struct msghdr;
 *   cmsghdr   12 B header, cmsg_len u32, 4-byte CMSG alignment on i386
 *             vs 16 B header, cmsg_len u64, 8-byte alignment on the
 *             host — walked and repacked in both directions.
 *
 * Known v1 limitations (documented, busybox-neutral): control payloads
 * are copied verbatim, so SO_TIMESTAMP*_OLD ancillary payloads arrive in
 * host (16 B timeval) width instead of the compat 8 B form; the host-side
 * recvmsg control staging buffer is capped at 2x the guest buffer (max
 * 4096 B) with MSG_CTRUNC beyond; recvmmsg's overall timeout budget is
 * emulated per message via a temporary SO_RCVTIMEO rather than a single
 * kernel-side wait.
 *
 * Conversion helpers are non-static so tests/unit/test_l2b.c can drive
 * them directly against a fake window.
 */

/* Local headers first: structs_i386.h declares a struct member named
 * sa_handler, which system <signal.h> headers may reach through stdlib
 * (darwin: sys/wait.h -> sys/signal.h) rewrite with a macro; the frozen
 * struct must parse before any of that lands. */
#include "marshal.h"
#include "os/backend.h"
#include "os/sys_sock_internal.h"
#include "structs_i386.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h> /* struct timeval, suseconds_t (SO_RCVTIMEO) */
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* Argument word counts per op 0..20 (net/socket.c sys_socketcall nargs,
 * in unsigned-long = u32 words on i386). */
static const uint8_t s_sc_nargs[I686_SC_MAX + 1U] = {
    0U, 3U, 3U, 3U, 2U, 3U, 3U, 3U, 4U, 4U, 4U,
    6U, 6U, 2U, 5U, 5U, 3U, 3U, 4U, 5U, 4U,
};

/* I686-R5-11: guest socket syscalls route through the rt_host_* backend
 * wrappers (backend.h section 6), which cover both static-PIE aarch64-Linux
 * and macOS arm64 (Darwin) hosts. Flags are folded by callers that can
 * (flags 0 -> accept(2) path inside the backend). */

/* ---- subcall cores (shared by socketcall and direct numbers) ---------- */

static int64_t sock_socket(uint32_t domain, uint32_t type, uint32_t protocol)
{
    /* I686-R5-11: via backend wrapper (covers Linux + Darwin). */
    return rt_host_socket((int)domain, (int)type, (int)protocol);
}

/* sockaddrs are byte-identical between i386 and the host; the kernel reads
 * at most sizeof(struct sockaddr_storage) bytes (net/compat.c clamps
 * msg_namelen; move_addr_to_kernel copies min(len, 128)), so the bounds
 * pre-check uses that clamp. */
static int64_t sock_bind(i686_ctx_t *ctx, uint32_t fd, uint32_t addr_va,
                         uint32_t len)
{
    const struct sockaddr *sa = NULL;

    if (addr_va != 0U) {
        uint32_t nlen = (len > I686_SOCKADDR_MAX) ? I686_SOCKADDR_MAX : len;
        if (!va_ok(addr_va, nlen)) {
            return -EFAULT;
        }
        sa = (const struct sockaddr *)i686_guest_ptr(ctx, addr_va);
    }
    return rt_host_bind((int)fd, sa, len);
}

static int64_t sock_connect(i686_ctx_t *ctx, uint32_t fd, uint32_t addr_va,
                            uint32_t len)
{
    const struct sockaddr *sa = NULL;

    if (addr_va != 0U) {
        uint32_t nlen = (len > I686_SOCKADDR_MAX) ? I686_SOCKADDR_MAX : len;
        if (!va_ok(addr_va, nlen)) {
            return -EFAULT;
        }
        sa = (const struct sockaddr *)i686_guest_ptr(ctx, addr_va);
    }
    return rt_host_connect((int)fd, sa, len, NULL, 0U);
}

static int64_t sock_listen(uint32_t fd, uint32_t backlog)
{
    return rt_host_listen((int)fd, (int)backlog);
}

/* accept/accept4: the out sockaddr (bounded by the guest-supplied socklen,
 * u32 on both sides) and the length field live in the window and are handed
 * to the host directly — the kernel copies min(*len, addr) bytes back and
 * stores the real length (compat move_addr_to_user). */
static int64_t sock_accept4(i686_ctx_t *ctx, uint32_t fd, uint32_t addr_va,
                            uint32_t lenp_va, uint32_t flags)
{
    struct sockaddr *sa  = NULL;
    socklen_t       *sl  = NULL;

    if (addr_va != 0U) {
        if (lenp_va == 0U) {
            return -EFAULT;
        }
        if (lenp_va < 0x1000U || lenp_va > UINT32_MAX - 3U) {
            return -EFAULT;
        }
        if (!va_ok(addr_va, I686_SOCKADDR_MAX)) {
            return -EFAULT;
        }
        sa  = (struct sockaddr *)i686_guest_ptr(ctx, addr_va);
        sl  = (socklen_t *)i686_guest_ptr(ctx, lenp_va);
    }
    if (flags == 0U) {
        return rt_host_accept4((int)fd, sa, (uint32_t *)sl, 0, NULL, 0U);
    }
    return rt_host_accept4((int)fd, sa, (uint32_t *)sl, (int)flags, NULL, 0U);
}

/* getsockname/getpeername share the staging: in-window sockaddr (bounded
 * by the 128-byte clamp) plus an in-place u32 length the host updates. */
static int64_t sock_getname(i686_ctx_t *ctx, uint32_t fd, uint32_t addr_va,
                            uint32_t lenp_va, int peer)
{
    struct sockaddr *sa = NULL;
    socklen_t       *sl = NULL;

    if (addr_va != 0U) {
        if (!va_ok(addr_va, I686_SOCKADDR_MAX)) {
            return -EFAULT;
        }
        sa = (struct sockaddr *)i686_guest_ptr(ctx, addr_va);
    }
    if (lenp_va != 0U) {
        if (lenp_va < 0x1000U || lenp_va > UINT32_MAX - 3U) {
            return -EFAULT;
        }
        sl = (socklen_t *)i686_guest_ptr(ctx, lenp_va);
    }
    if (peer) {
        return rt_host_getpeername((int)fd, sa, (uint32_t *)sl);
    }
    return rt_host_getsockname((int)fd, sa, (uint32_t *)sl);
}

static int64_t sock_getsockname(i686_ctx_t *ctx, uint32_t fd, uint32_t addr_va,
                                uint32_t lenp_va)
{
    return sock_getname(ctx, fd, addr_va, lenp_va, 0);
}

static int64_t sock_getpeername(i686_ctx_t *ctx, uint32_t fd, uint32_t addr_va,
                                uint32_t lenp_va)
{
    return sock_getname(ctx, fd, addr_va, lenp_va, 1);
}

static int64_t sock_socketpair(i686_ctx_t *ctx, uint32_t domain,
                               uint32_t type, uint32_t protocol,
                               uint32_t sv_va)
{
    if (sv_va < 0x1000U || sv_va > UINT32_MAX - 7U) {
        return -EFAULT;
    }
    return rt_host_socketpair((int)domain, (int)type, (int)protocol,
                              (int *)(void *)i686_guest_ptr(ctx, sv_va));
}

/* sendto covers SYS_SEND (addr == 0) and the direct nr 369. */
static int64_t sock_sendto(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va,
                           uint32_t len, uint32_t flags, uint32_t addr_va,
                           uint32_t addrlen)
{
    const struct sockaddr *sa = NULL;

    if (!va_ok(buf_va, len)) {
        return -EFAULT;
    }
    if (addr_va != 0U) {
        uint32_t nlen =
            (addrlen > I686_SOCKADDR_MAX) ? I686_SOCKADDR_MAX : addrlen;
        if (!va_ok(addr_va, nlen)) {
            return -EFAULT;
        }
        sa = (const struct sockaddr *)i686_guest_ptr(ctx, addr_va);
    }
    return rt_host_sendto((int)fd,
                            (len != 0U) ? i686_guest_ptr(ctx, buf_va) : NULL,
                            (size_t)len, (int)flags, sa, addrlen, NULL, 0U);
}

/* recvfrom covers SYS_RECV (from == 0) and the direct nr 371. */
static int64_t sock_recvfrom(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va,
                             uint32_t len, uint32_t flags, uint32_t from_va,
                             uint32_t fromlenp_va)
{
    struct sockaddr *sa = NULL;
    socklen_t       *sl = NULL;

    if (!va_ok(buf_va, len)) {
        return -EFAULT;
    }
    if (from_va != 0U) {
        if (fromlenp_va == 0U) {
            return -EFAULT;
        }
        if (fromlenp_va < 0x1000U || fromlenp_va > UINT32_MAX - 3U) {
            return -EFAULT;
        }
        if (!va_ok(from_va, I686_SOCKADDR_MAX)) {
            return -EFAULT;
        }
        sa = (struct sockaddr *)i686_guest_ptr(ctx, from_va);
        sl = (socklen_t *)i686_guest_ptr(ctx, fromlenp_va);
    }
    return rt_host_recvfrom((int)fd,
                              (len != 0U) ? i686_guest_ptr(ctx, buf_va) : NULL,
                              (size_t)len, (int)flags, sa, (uint32_t *)sl,
                              NULL, 0U);
}

static int64_t sock_shutdown(uint32_t fd, uint32_t how)
{
    return rt_host_shutdown((int)fd, (int)how);
}

/* setsockopt: only SO_RCVTIMEO_OLD/SO_SNDTIMEO_OLD under SOL_SOCKET carry
 * a 32-bit timeval (8 B) that the host interprets as 16 B; everything
 * else (including the NEW 66/67 __kernel_sock_timeval options) is
 * layout-identical and passes in place. */
static int64_t sock_setsockopt(i686_ctx_t *ctx, uint32_t fd, uint32_t level,
                               uint32_t optname, uint32_t val_va,
                               uint32_t optlen)
{
    if (level == I686_SOL_SOCKET &&
        (optname == I686_SO_RCVTIMEO_OLD || optname == I686_SO_SNDTIMEO_OLD)) {
        if (optlen < (uint32_t)sizeof(i686_timeval_t)) {
            return -EINVAL; /* net/core/sock.c sock_copy_user_timeval */
        }
        if (!va_ok(val_va, (uint64_t)sizeof(i686_timeval_t))) {
            return -EFAULT;
        }
        i686_timeval_t g;
        if (i686_copy_from_guest(ctx, &g, val_va, sizeof(g)) != 0) {
            return -EFAULT;
        }
        if (g.tv_usec < 0 || g.tv_usec >= 1000000) {
            return -EDOM; /* net/core/sock.c sock_set_timeout */
        }
        struct timeval tv;
        /* negative tv_sec clamps to "no timeout" and succeeds (kernel
         * warns and stores 0) */
        tv.tv_sec  = (g.tv_sec < 0) ? 0 : (time_t)g.tv_sec;
        tv.tv_usec = (suseconds_t)g.tv_usec;
        int host_opt = (optname == I686_SO_RCVTIMEO_OLD) ? SO_RCVTIMEO
                                                         : SO_SNDTIMEO;
        return rt_host_setsockopt((int)fd, SOL_SOCKET, host_opt, &tv,
                                  (uint32_t)sizeof(tv));
    }
    if (val_va != 0U && !va_ok(val_va, optlen)) {
        return -EFAULT;
    }
    return rt_host_setsockopt((int)fd, (int)level, (int)optname,
                              (val_va != 0U) ? i686_guest_ptr(ctx, val_va)
                                             : NULL,
                              optlen);
}

static int64_t sock_getsockopt(i686_ctx_t *ctx, uint32_t fd, uint32_t level,
                               uint32_t optname, uint32_t val_va,
                               uint32_t lenp_va)
{
    if (level == I686_SOL_SOCKET &&
        (optname == I686_SO_RCVTIMEO_OLD || optname == I686_SO_SNDTIMEO_OLD) &&
        val_va != 0U) {
        if (lenp_va < 0x1000U || lenp_va > UINT32_MAX - 3U) {
            return -EFAULT;
        }
        uint32_t glen = 0U;
        if (i686_copy_from_guest(ctx, &glen, lenp_va, sizeof(glen)) != 0) {
            return -EFAULT;
        }
        if (glen < (uint32_t)sizeof(i686_timeval_t)) {
            return -EINVAL;
        }
        struct timeval tv;
        uint32_t       hlen = (uint32_t)sizeof(tv);
        int host_opt = (optname == I686_SO_RCVTIMEO_OLD) ? SO_RCVTIMEO
                                                         : SO_SNDTIMEO;
        {
            int64_t grc =
                rt_host_getsockopt((int)fd, SOL_SOCKET, host_opt, &tv, &hlen);
            if (grc < 0) {
                return grc;
            }
        }
        i686_timeval_t g;
        g.tv_sec  = (int32_t)tv.tv_sec;
        g.tv_usec = (int32_t)tv.tv_usec;
        uint32_t copy = (glen < (uint32_t)sizeof(g)) ? glen
                                                     : (uint32_t)sizeof(g);
        if (i686_copy_to_guest(ctx, val_va, &g, copy) != 0 ||
            i686_copy_to_guest(ctx, lenp_va, &copy, sizeof(copy)) != 0) {
            return -EFAULT;
        }
        return 0;
    }
    if (val_va != 0U && val_va < 0x1000U) {
        return -EFAULT;
    }
    if (lenp_va != 0U &&
        (lenp_va < 0x1000U || lenp_va > UINT32_MAX - 3U)) {
        return -EFAULT;
    }
    return rt_host_getsockopt((int)fd, (int)level, (int)optname,
                              (val_va != 0U) ? i686_guest_ptr(ctx, val_va)
                                             : NULL,
                              (lenp_va != 0U)
                                  ? (uint32_t *)i686_guest_ptr(ctx, lenp_va)
                                  : NULL);
}

/* ---- registry adapters ------------------------------------------------ */

static int64_t r_socketcall(i686_ctx_t *ctx)
{
    uint32_t call    = ctx->gpr[I686_REG_EBX];
    uint32_t args_va = ctx->gpr[I686_REG_ECX];
    uint32_t a[6]    = {0U, 0U, 0U, 0U, 0U, 0U};

    if (call < 1U || call > I686_SC_MAX) {
        return -(int64_t)I686_ENOSYS; /* lane card rule (kernel: -EINVAL) */
    }
    if (!va_ok(args_va, (uint64_t)s_sc_nargs[call] * 4U)) {
        return -EFAULT; /* truncated args array (u32 wrap) */
    }
    if (i686_copy_from_guest(ctx, a, args_va,
                             (size_t)s_sc_nargs[call] * 4U) != 0) {
        return -EFAULT;
    }
    switch (call) {
    case I686_SC_SOCKET:
        return sock_socket(a[0], a[1], a[2]);
    case I686_SC_BIND:
        return sock_bind(ctx, a[0], a[1], a[2]);
    case I686_SC_CONNECT:
        return sock_connect(ctx, a[0], a[1], a[2]);
    case I686_SC_LISTEN:
        return sock_listen(a[0], a[1]);
    case I686_SC_ACCEPT:
        return sock_accept4(ctx, a[0], a[1], a[2], 0U);
    case I686_SC_GETSOCKNAME:
        return sock_getsockname(ctx, a[0], a[1], a[2]);
    case I686_SC_GETPEERNAME:
        return sock_getpeername(ctx, a[0], a[1], a[2]);
    case I686_SC_SOCKETPAIR:
        return sock_socketpair(ctx, a[0], a[1], a[2], a[3]);
    case I686_SC_SEND:
        return sock_sendto(ctx, a[0], a[1], a[2], a[3], 0U, 0U);
    case I686_SC_SENDTO:
        return sock_sendto(ctx, a[0], a[1], a[2], a[3], a[4], a[5]);
    case I686_SC_RECV:
        return sock_recvfrom(ctx, a[0], a[1], a[2], a[3], 0U, 0U);
    case I686_SC_RECVFROM:
        return sock_recvfrom(ctx, a[0], a[1], a[2], a[3], a[4], a[5]);
    case I686_SC_SHUTDOWN:
        return sock_shutdown(a[0], a[1]);
    case I686_SC_SETSOCKOPT:
        return sock_setsockopt(ctx, a[0], a[1], a[2], a[3], a[4]);
    case I686_SC_GETSOCKOPT:
        return sock_getsockopt(ctx, a[0], a[1], a[2], a[3], a[4]);
    case I686_SC_SENDMSG:
        return i686_sock_sendmsg(ctx, a[0], a[1], a[2]);
    case I686_SC_RECVMSG:
        return i686_sock_recvmsg(ctx, a[0], a[1], a[2]);
    case I686_SC_ACCEPT4:
        return sock_accept4(ctx, a[0], a[1], a[2], a[3]);
    case I686_SC_RECVMMSG:
        return i686_sock_recvmmsg(ctx, a[0], a[1], a[2], a[3], a[4], 0);
    case I686_SC_SENDMMSG:
        return i686_sock_sendmmsg(ctx, a[0], a[1], a[2], a[3]);
    default:
        return -(int64_t)I686_ENOSYS;
    }
}

static int64_t r_socket(i686_ctx_t *ctx)
{
    return sock_socket(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                       ctx->gpr[I686_REG_EDX]);
}

static int64_t r_socketpair(i686_ctx_t *ctx)
{
    return sock_socketpair(ctx, ctx->gpr[I686_REG_EBX],
                           ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                           ctx->gpr[I686_REG_ESI]);
}

static int64_t r_bind(i686_ctx_t *ctx)
{
    return sock_bind(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

static int64_t r_connect(i686_ctx_t *ctx)
{
    return sock_connect(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX]);
}

static int64_t r_listen(i686_ctx_t *ctx)
{
    return sock_listen(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_accept4(i686_ctx_t *ctx)
{
    return sock_accept4(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_getsockopt(i686_ctx_t *ctx)
{
    return sock_getsockopt(ctx, ctx->gpr[I686_REG_EBX],
                           ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                           ctx->gpr[I686_REG_ESI], ctx->gpr[I686_REG_EDI]);
}

static int64_t r_setsockopt(i686_ctx_t *ctx)
{
    return sock_setsockopt(ctx, ctx->gpr[I686_REG_EBX],
                           ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                           ctx->gpr[I686_REG_ESI], ctx->gpr[I686_REG_EDI]);
}

static int64_t r_getsockname(i686_ctx_t *ctx)
{
    return sock_getsockname(ctx, ctx->gpr[I686_REG_EBX],
                            ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX]);
}

static int64_t r_getpeername(i686_ctx_t *ctx)
{
    return sock_getpeername(ctx, ctx->gpr[I686_REG_EBX],
                            ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX]);
}

static int64_t r_sendto(i686_ctx_t *ctx)
{
    return sock_sendto(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                       ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                       ctx->gpr[I686_REG_EDI], ctx->gpr[I686_REG_EBP]);
}

static int64_t r_sendmsg(i686_ctx_t *ctx)
{
    return i686_sock_sendmsg(ctx, ctx->gpr[I686_REG_EBX],
                             ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX]);
}

static int64_t r_recvfrom(i686_ctx_t *ctx)
{
    return sock_recvfrom(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                         ctx->gpr[I686_REG_EDI], ctx->gpr[I686_REG_EBP]);
}

static int64_t r_recvmsg(i686_ctx_t *ctx)
{
    return i686_sock_recvmsg(ctx, ctx->gpr[I686_REG_EBX],
                             ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX]);
}

static int64_t r_shutdown(i686_ctx_t *ctx)
{
    return sock_shutdown(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_recvmmsg(i686_ctx_t *ctx)
{
    return i686_sock_recvmmsg(ctx, ctx->gpr[I686_REG_EBX],
                              ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                              ctx->gpr[I686_REG_ESI], ctx->gpr[I686_REG_EDI], 0);
}

static int64_t r_sendmmsg(i686_ctx_t *ctx)
{
    return i686_sock_sendmmsg(ctx, ctx->gpr[I686_REG_EBX],
                              ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                              ctx->gpr[I686_REG_ESI]);
}

static int64_t r_recvmmsg_time64(i686_ctx_t *ctx)
{
    return i686_sock_recvmmsg(ctx, ctx->gpr[I686_REG_EBX],
                              ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                              ctx->gpr[I686_REG_ESI], ctx->gpr[I686_REG_EDI], 1);
}

void i686_syscalls_sock_init(void)
{
    i686_sys_register(I686_SOCK_NR_SOCKETCALL, r_socketcall);
    i686_sys_register(I686_SOCK_NR_RECVMMSG, r_recvmmsg);
    i686_sys_register(I686_SOCK_NR_SENDMMSG, r_sendmmsg);
    i686_sys_register(I686_SOCK_NR_SOCKET, r_socket);
    i686_sys_register(I686_SOCK_NR_SOCKETPAIR, r_socketpair);
    i686_sys_register(I686_SOCK_NR_BIND, r_bind);
    i686_sys_register(I686_SOCK_NR_CONNECT, r_connect);
    i686_sys_register(I686_SOCK_NR_LISTEN, r_listen);
    i686_sys_register(I686_SOCK_NR_ACCEPT4, r_accept4);
    i686_sys_register(I686_SOCK_NR_GETSOCKOPT, r_getsockopt);
    i686_sys_register(I686_SOCK_NR_SETSOCKOPT, r_setsockopt);
    i686_sys_register(I686_SOCK_NR_GETSOCKNAME, r_getsockname);
    i686_sys_register(I686_SOCK_NR_GETPEERNAME, r_getpeername);
    i686_sys_register(I686_SOCK_NR_SENDTO, r_sendto);
    i686_sys_register(I686_SOCK_NR_SENDMSG, r_sendmsg);
    i686_sys_register(I686_SOCK_NR_RECVFROM, r_recvfrom);
    i686_sys_register(I686_SOCK_NR_RECVMSG, r_recvmsg);
    i686_sys_register(I686_SOCK_NR_SHUTDOWN, r_shutdown);
    i686_sys_register(I686_SOCK_NR_RECVMMSG_T64, r_recvmmsg_time64);
}
