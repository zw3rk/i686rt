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

/* ---- syscall numbers (generated table + arch/x86 syscall_32.tbl) ----- */

#define I686_SOCK_NR_SOCKETCALL   102L
#define I686_SOCK_NR_RECVMMSG     337L
#define I686_SOCK_NR_SENDMMSG     345L
#define I686_SOCK_NR_SOCKET       359L
#define I686_SOCK_NR_SOCKETPAIR   360L
#define I686_SOCK_NR_BIND         361L
#define I686_SOCK_NR_CONNECT      362L
#define I686_SOCK_NR_LISTEN       363L
#define I686_SOCK_NR_ACCEPT4      364L
#define I686_SOCK_NR_GETSOCKOPT   365L
#define I686_SOCK_NR_SETSOCKOPT   366L
#define I686_SOCK_NR_GETSOCKNAME  367L
#define I686_SOCK_NR_GETPEERNAME  368L
#define I686_SOCK_NR_SENDTO       369L
#define I686_SOCK_NR_SENDMSG      370L
#define I686_SOCK_NR_RECVFROM     371L
#define I686_SOCK_NR_RECVMSG      372L
#define I686_SOCK_NR_SHUTDOWN     373L
#define I686_SOCK_NR_RECVMMSG_T64 417L

/* ---- socketcall subcall ops (include/uapi/linux/net.h) --------------- */

#define I686_SC_SOCKET      1U
#define I686_SC_BIND        2U
#define I686_SC_CONNECT     3U
#define I686_SC_LISTEN      4U
#define I686_SC_ACCEPT      5U
#define I686_SC_GETSOCKNAME 6U
#define I686_SC_GETPEERNAME 7U
#define I686_SC_SOCKETPAIR  8U
#define I686_SC_SEND        9U
#define I686_SC_RECV        10U
#define I686_SC_SENDTO      11U
#define I686_SC_RECVFROM    12U
#define I686_SC_SHUTDOWN    13U
#define I686_SC_SETSOCKOPT  14U
#define I686_SC_GETSOCKOPT  15U
#define I686_SC_SENDMSG     16U
#define I686_SC_RECVMSG     17U
#define I686_SC_ACCEPT4     18U
#define I686_SC_RECVMMSG    19U
#define I686_SC_SENDMMSG    20U
#define I686_SC_MAX         20U

/* Argument word counts per op 0..20 (net/socket.c sys_socketcall nargs,
 * in unsigned-long = u32 words on i386). */
static const uint8_t s_sc_nargs[I686_SC_MAX + 1U] = {
    0U, 3U, 3U, 3U, 2U, 3U, 3U, 3U, 4U, 4U, 4U,
    6U, 6U, 2U, 5U, 5U, 3U, 3U, 4U, 5U, 4U,
};

/* ---- ABI constants ---------------------------------------------------- */

/* include/uapi/linux/uio.h; also net/compat.c get_compat_msghdr. */
#define I686_UIO_MAXIOV 1024U

/* errno numbers are ABI-identical across Linux arches (asm-generic/errno
 * .h); the synthesized ENOSYS below must be the Linux value 38 even when
 * the unit-test host (darwin) renumbers its own <errno.h>. */
#define I686_ENOSYS 38

/* Guest-side (i386 Linux ABI) constants that differ from or are absent on
 * the unit-test host. */
#define I686_SOL_SOCKET       1U   /* asm-generic/socket.h SOL_SOCKET */
#define I686_SO_RCVTIMEO_OLD  20U
#define I686_SO_SNDTIMEO_OLD  21U
#define I686_MSG_WAITFORONE   0x10000U /* asm-generic/socket.h */

/* i386 struct cmsghdr: u32 cmsg_len + int level + int type, 4-byte align
 * (CMSG_COMPAT_* in arch/x86/include/asm/compat.h). */
#define I686_CMSG32_HDR         12U
#define I686_CMSG32_ALIGN(len)  (((uint32_t)(len) + 3U) & ~3U)

/* Linux uapi CMSG_ALIGN; darwin's headers (unit-test host only) lack it. */
#ifndef CMSG_ALIGN
#define CMSG_ALIGN(len) (((len) + sizeof(size_t) - 1U) & ~(sizeof(size_t) - 1U))
#endif

#define I686_SOCKADDR_MAX  ((uint32_t)sizeof(struct sockaddr_storage))

/* Stack capacities; larger control/iov marshals fall back to the heap. */
#define I686_CMSG_STACK   256U
#define I686_IOV_STACK    16U
/* Host-side recvmsg control staging: worst-case repack of a guest buffer
 * G needs < 2*G bytes; beyond 4096 we let MSG_CTRUNC speak. */
#define I686_CMSG_HOST_MAX 4096U

/* i686_mmsghdr_t: i386 struct mmsghdr = 28 B msghdr + u32 msg_len.  The
 * frozen structs header carries the msghdr; the mmsg wrapper is local. */
typedef struct {
    i686_msghdr_t msg_hdr;
    uint32_t      msg_len;
} i686_mmsghdr_t;

_Static_assert(sizeof(i686_mmsghdr_t) == 32U, "i686_mmsghdr_t 32 bytes");
_Static_assert(offsetof(i686_mmsghdr_t, msg_len) == 28U, "mmsg msg_len at 28");

/* ---- small helpers ---------------------------------------------------- */

static uint32_t guest_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void guest_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

/* Host call result -> guest convention: value, or -errno. */
static int64_t sret(int64_t r)
{
    return (r < 0) ? -(int64_t)errno : r;
}

/* [va, va+len) fully inside the 4 GiB guest window without u32 wrap and
 * clear of the low guard page (len 0 needs no backing). */
static int va_ok(uint32_t va, uint64_t len)
{
    if (len == 0U) {
        return 1;
    }
    if (va < 0x1000U) {
        return 0;
    }
    return (va + len <= 0x100000000ULL);
}

/* darwin is never a runtime host (aarch64 Linux only); the shim exists so
 * the macOS-native unit driver links.  Flags are folded by callers that
 * can (flags 0 -> accept(2)); flags != 0 on darwin is untested. */
#ifdef __APPLE__
static int hs_accept4(int fd, struct sockaddr *sa, socklen_t *sl, int flags)
{
    (void)fd;
    (void)sa;
    (void)sl;
    (void)flags;
    errno = I686_ENOSYS;
    return -1;
}
#else
static int hs_accept4(int fd, struct sockaddr *sa, socklen_t *sl, int flags)
{
    return accept4(fd, sa, sl, flags);
}
#endif

/* ---- cmsghdr conversion (i386 <-> host) -------------------------------
 * Non-static: driven directly by tests/unit/test_l2b.c.
 *
 * i686_sock_cmsg32_to_64: walk the guest control buffer (12-byte i386
 * cmsghdr headers, cmsg_len u32, 4-byte alignment) and emit host-layout
 * cmsghdrs.  hbuf == NULL performs a size-only pass (out_hlen receives
 * the exact host size).  Returns -EINVAL for a malformed guest cmsg
 * (cmsg_len < 12 or past the end), 0 otherwise.
 */
int i686_sock_cmsg32_to_64(const uint8_t *gctl, uint32_t glen, uint8_t *hbuf,
                           size_t hcap, size_t *out_hlen)
{
    uint32_t off32 = 0U;
    size_t   off64 = 0U;

    if (gctl == NULL || out_hlen == NULL) {
        return -EINVAL;
    }
    while ((uint64_t)off32 + (uint64_t)I686_CMSG32_HDR <= (uint64_t)glen) {
        uint32_t len32 = guest_le32(gctl + off32);
        if (len32 < I686_CMSG32_HDR || len32 > glen - off32) {
            return -EINVAL; /* net/socket.c __sys_sendmsg compat walk */
        }
        uint32_t payload = len32 - I686_CMSG32_HDR;
        size_t   space   = CMSG_SPACE((size_t)payload);
        if (hbuf != NULL) {
            if (off64 + space > hcap) {
                break; /* caller undersized (cannot happen after sizing pass) */
            }
            struct cmsghdr *cm = (struct cmsghdr *)(void *)(hbuf + off64);
            cm->cmsg_len   = CMSG_LEN((size_t)payload);
            cm->cmsg_level = (int)guest_le32(gctl + off32 + 4U);
            cm->cmsg_type  = (int)guest_le32(gctl + off32 + 8U);
            if (payload != 0U) {
                memcpy(CMSG_DATA(cm), gctl + off32 + I686_CMSG32_HDR,
                       (size_t)payload);
            }
        }
        off64 += space;
        off32 += I686_CMSG32_ALIGN(len32);
    }
    *out_hlen = off64;
    return 0;
}

/*
 * i686_sock_cmsg64_to_32: walk host-layout cmsghdrs and pack them into a
 * guest buffer (12-byte headers, u32 cmsg_len, 4-byte alignment).  A cmsg
 * that no longer fits set MSG_CTRUNC in *out_add_flags; when close_dropped
 * is set the fds of a dropped SCM_RIGHTS cmsg are closed (kernel compat
 * behaviour on truncation).  Malformed host entries stop the walk.
 */
void i686_sock_cmsg64_to_32(const uint8_t *hctl, size_t hlen, uint8_t *gbuf,
                            uint32_t gcap, uint32_t *out_glen,
                            uint32_t *out_add_flags, int close_dropped)
{
    uint32_t off32 = 0U;
    size_t   off64 = 0U;

    if (out_glen != NULL) {
        *out_glen = 0U;
    }
    if (out_add_flags != NULL) {
        *out_add_flags = 0U;
    }
    if (hctl == NULL || gbuf == NULL) {
        return;
    }
    while (off64 + sizeof(struct cmsghdr) <= hlen) {
        const struct cmsghdr *cm =
            (const struct cmsghdr *)(const void *)(hctl + off64);
        size_t clen = (size_t)cm->cmsg_len;
        if (clen < sizeof(struct cmsghdr) || clen > hlen - off64) {
            break;
        }
        size_t payload = clen - sizeof(struct cmsghdr);
        if ((uint64_t)I686_CMSG32_HDR + (uint64_t)payload <=
            (uint64_t)gcap - off32) {
            uint32_t len32   = I686_CMSG32_HDR + (uint32_t)payload;
            uint32_t space32 = I686_CMSG32_ALIGN(len32);
            guest_store_le32(gbuf + off32, len32);
            guest_store_le32(gbuf + off32 + 4U, (uint32_t)cm->cmsg_level);
            guest_store_le32(gbuf + off32 + 8U, (uint32_t)cm->cmsg_type);
            if (payload != 0U) {
                memcpy(gbuf + off32 + I686_CMSG32_HDR, CMSG_DATA(cm), payload);
            }
            off32 += ((uint64_t)off32 + space32 <= (uint64_t)gcap) ? space32
                                                                   : len32;
        } else {
            if (out_add_flags != NULL) {
                *out_add_flags = (uint32_t)MSG_CTRUNC;
            }
            if (close_dropped && cm->cmsg_level == SOL_SOCKET &&
                cm->cmsg_type == SCM_RIGHTS) {
                size_t      nfds = payload / sizeof(int);
                const int  *fds  = (const int *)(const void *)CMSG_DATA(cm);
                for (size_t i = 0U; i < nfds; i++) {
                    (void)close(fds[i]);
                }
            }
        }
        off64 += CMSG_ALIGN(clen);
    }
    if (out_glen != NULL) {
        *out_glen = off32;
    }
}

/*
 * i686_sock_translate_iov: walk the guest i686_iovec_t array and build the
 * host iovec[] pointing straight into the window.  iovcnt 0 uses the
 * caller's stack array; above stack_cap a heap array is returned for the
 * caller to free (a32rt translate_guest_iov pattern).  Returns 0 or
 * -errno (EINVAL above UIO_MAXIOV, EFAULT for low/wrapping buffers).
 */
int i686_sock_translate_iov(i686_ctx_t *ctx, uint32_t iov_va, uint32_t iovcnt,
                            struct iovec *stack_iov, uint32_t stack_cap,
                            struct iovec **out_iov)
{
    struct iovec *hiov;

    if (out_iov == NULL) {
        return -EINVAL;
    }
    if ((int32_t)iovcnt < 0 || iovcnt > I686_UIO_MAXIOV) {
        return -EINVAL;
    }
    if (iovcnt == 0U) {
        *out_iov = stack_iov;
        return 0;
    }
    if (!va_ok(iov_va, (uint64_t)iovcnt * (uint64_t)sizeof(i686_iovec_t))) {
        return -EFAULT;
    }
    hiov = stack_iov;
    if (iovcnt > stack_cap) {
        hiov = (struct iovec *)calloc((size_t)iovcnt, sizeof(*hiov));
        if (hiov == NULL) {
            return -ENOMEM;
        }
    }
    for (uint32_t i = 0U; i < iovcnt; i++) {
        i686_iovec_t g;
        memcpy(&g, (const void *)i686_guest_ptr(
                       ctx, iov_va + i * (uint32_t)sizeof(i686_iovec_t)),
               sizeof(g));
        if (g.iov_len != 0U) {
            if (g.iov_base < 0x1000U ||
                (uint64_t)g.iov_base + (uint64_t)g.iov_len >
                    0x100000000ULL) {
                if (hiov != stack_iov) {
                    free(hiov);
                }
                return -EFAULT;
            }
            hiov[i].iov_base = i686_guest_ptr(ctx, g.iov_base);
        } else {
            hiov[i].iov_base = NULL;
        }
        hiov[i].iov_len = (size_t)g.iov_len;
    }
    *out_iov = hiov;
    return 0;
}

/* ---- subcall cores (shared by socketcall and direct numbers) ---------- */

static int64_t sock_socket(uint32_t domain, uint32_t type, uint32_t protocol)
{
    return sret(socket((int)domain, (int)type, (int)protocol));
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
    return sret(bind((int)fd, sa, (socklen_t)len));
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
    return sret(connect((int)fd, sa, (socklen_t)len));
}

static int64_t sock_listen(uint32_t fd, uint32_t backlog)
{
    return sret(listen((int)fd, (int)backlog));
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
        return sret(accept((int)fd, sa, sl));
    }
    return sret(hs_accept4((int)fd, sa, sl, (int)flags));
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
    return sret(peer ? getpeername((int)fd, sa, sl)
                     : getsockname((int)fd, sa, sl));
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
    return sret(socketpair((int)domain, (int)type, (int)protocol,
                           (int *)(void *)i686_guest_ptr(ctx, sv_va)));
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
    return sret(sendto((int)fd,
                       (len != 0U) ? i686_guest_ptr(ctx, buf_va) : NULL,
                       (size_t)len, (int)flags, sa, (socklen_t)addrlen));
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
    return sret(recvfrom((int)fd,
                         (len != 0U) ? i686_guest_ptr(ctx, buf_va) : NULL,
                         (size_t)len, (int)flags, sa, sl));
}

static int64_t sock_shutdown(uint32_t fd, uint32_t how)
{
    return sret(shutdown((int)fd, (int)how));
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
        return sret(setsockopt((int)fd, SOL_SOCKET, host_opt, &tv,
                               (socklen_t)sizeof(tv)));
    }
    if (val_va != 0U && !va_ok(val_va, optlen)) {
        return -EFAULT;
    }
    return sret(setsockopt((int)fd, (int)level, (int)optname,
                           (val_va != 0U) ? i686_guest_ptr(ctx, val_va) : NULL,
                           (socklen_t)optlen));
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
        socklen_t      hlen = (socklen_t)sizeof(tv);
        int host_opt = (optname == I686_SO_RCVTIMEO_OLD) ? SO_RCVTIMEO
                                                         : SO_SNDTIMEO;
        if (getsockopt((int)fd, SOL_SOCKET, host_opt, &tv, &hlen) < 0) {
            return -(int64_t)errno;
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
    return sret(getsockopt((int)fd, (int)level, (int)optname,
                           (val_va != 0U) ? i686_guest_ptr(ctx, val_va) : NULL,
                           (lenp_va != 0U)
                               ? (socklen_t *)i686_guest_ptr(ctx, lenp_va)
                               : NULL));
}

/* Build the host msghdr for one sendmsg/recvmsg; returns 0 with *hm, the
 * guest msghdr copy in *gm, and the heap pointers to release, or -errno
 * (callers release iovp/ctlp on failure too — translate_iov frees its own
 * allocations internally).  dir_recv selects the control staging
 * direction. */
static int msghdr_build(i686_ctx_t *ctx, uint32_t msg_va, int dir_recv,
                        struct msghdr *hm, i686_msghdr_t *gm,
                        struct iovec **iovp, uint8_t **ctlp,
                        uint8_t *stack_ctl, uint32_t stack_ctl_len,
                        struct iovec *stack_iov, uint32_t stack_iov_len)
{
    size_t ctl_len = 0U;

    memset(hm, 0, sizeof(*hm));
    if (!va_ok(msg_va, (uint64_t)sizeof(*gm)) ||
        i686_copy_from_guest(ctx, gm, msg_va, sizeof(*gm)) != 0) {
        return -EFAULT;
    }
    if (gm->msg_iovlen > I686_UIO_MAXIOV) {
        return -EMSGSIZE; /* net/compat.c get_compat_msghdr */
    }
    if (!dir_recv && gm->msg_controllen != 0U &&
        gm->msg_controllen < I686_CMSG32_HDR) {
        return -EINVAL; /* send-side control shorter than a cmsg header */
    }
    hm->msg_flags = (int)gm->msg_flags;
    if (gm->msg_name != 0U) {
        uint32_t nlen = (gm->msg_namelen > I686_SOCKADDR_MAX)
                            ? I686_SOCKADDR_MAX
                            : gm->msg_namelen;
        if (!va_ok(gm->msg_name, nlen)) {
            return -EFAULT;
        }
        hm->msg_name    = i686_guest_ptr(ctx, gm->msg_name);
        hm->msg_namelen = gm->msg_namelen;
    } else if (dir_recv) {
        hm->msg_namelen = 0U;
    }
    if (gm->msg_control != 0U && gm->msg_controllen != 0U) {
        if (!va_ok(gm->msg_control, gm->msg_controllen)) {
            return -EFAULT;
        }
        if (!dir_recv) {
            /* exact sizing pass, then build */
            const uint8_t *gctl =
                (const uint8_t *)i686_guest_ptr(ctx, gm->msg_control);
            int rc = i686_sock_cmsg32_to_64(gctl, gm->msg_controllen, NULL, 0U,
                                            &ctl_len);
            if (rc != 0) {
                return rc;
            }
            if (ctl_len != 0U) {
                *ctlp = (ctl_len <= stack_ctl_len) ? stack_ctl
                                                   : (uint8_t *)malloc(ctl_len);
                if (*ctlp == NULL) {
                    return -ENOMEM;
                }
                rc = i686_sock_cmsg32_to_64(gctl, gm->msg_controllen, *ctlp,
                                            ctl_len, &ctl_len);
                if (rc != 0) {
                    if (*ctlp != stack_ctl) {
                        free(*ctlp);
                        *ctlp = NULL;
                    }
                    return rc;
                }
                hm->msg_control    = *ctlp;
                hm->msg_controllen = ctl_len;
            }
        } else {
            /* host staging: worst-case repack of a G-byte guest buffer
             * stays under 2*G bytes; cap and let MSG_CTRUNC speak. */
            uint64_t cap = (uint64_t)gm->msg_controllen * 2U;
            if (cap > I686_CMSG_HOST_MAX) {
                cap = I686_CMSG_HOST_MAX;
            }
            *ctlp = (cap <= stack_ctl_len) ? stack_ctl
                                           : (uint8_t *)malloc((size_t)cap);
            if (*ctlp == NULL) {
                return -ENOMEM;
            }
            hm->msg_control    = *ctlp;
            hm->msg_controllen = (size_t)cap;
        }
    }
    int rc = i686_sock_translate_iov(ctx, gm->msg_iov, gm->msg_iovlen,
                                     stack_iov, stack_iov_len, iovp);
    if (rc != 0) {
        return rc;
    }
    hm->msg_iov    = (gm->msg_iovlen != 0U) ? *iovp : NULL;
    hm->msg_iovlen = (size_t)gm->msg_iovlen;
    return 0;
}

static int64_t sock_sendmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t msg_va,
                            uint32_t flags)
{
    struct msghdr  hm;
    i686_msghdr_t  gm;
    struct iovec   stack_iov[I686_IOV_STACK];
    _Alignas(8) uint8_t stack_ctl[I686_CMSG_STACK];
    struct iovec  *hiov = NULL;
    uint8_t       *hctl = NULL;
    int64_t        r;
    int            rc;

    rc = msghdr_build(ctx, msg_va, 0, &hm, &gm, &hiov, &hctl, stack_ctl,
                      (uint32_t)sizeof(stack_ctl), stack_iov,
                      (uint32_t)(sizeof(stack_iov) / sizeof(stack_iov[0])));
    if (rc != 0) {
        if (hctl != NULL && hctl != stack_ctl) {
            free(hctl); /* staging leftovers from a later-stage failure */
        }
        return (int64_t)rc;
    }
    r = sendmsg((int)fd, &hm, (int)flags);
    if (r < 0) {
        r = -(int64_t)errno;
    }
    if (hiov != NULL && hiov != stack_iov) {
        free(hiov);
    }
    if (hctl != NULL && hctl != stack_ctl) {
        free(hctl);
    }
    return r;
}

static int64_t sock_recvmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t msg_va,
                            uint32_t flags)
{
    struct msghdr  hm;
    i686_msghdr_t  gm;
    struct iovec   stack_iov[I686_IOV_STACK];
    _Alignas(8) uint8_t stack_ctl[I686_CMSG_STACK];
    struct iovec  *hiov = NULL;
    uint8_t       *hctl = NULL;
    int64_t        r;
    int            rc;

    rc = msghdr_build(ctx, msg_va, 1, &hm, &gm, &hiov, &hctl, stack_ctl,
                      (uint32_t)sizeof(stack_ctl), stack_iov,
                      (uint32_t)(sizeof(stack_iov) / sizeof(stack_iov[0])));
    if (rc != 0) {
        if (hctl != NULL && hctl != stack_ctl) {
            free(hctl); /* sizing-pass leftovers */
        }
        return rc;
    }
    r = recvmsg((int)fd, &hm, (int)flags);
    if (r < 0) {
        rc = -(int)errno;
        goto out_free;
    }
    /* write back the fields the kernel updates (compat __sys_recvmsg
     * copies namelen/controllen/flags out) */
    uint32_t gcap = gm.msg_controllen;
    gm.msg_namelen    = (uint32_t)hm.msg_namelen;
    gm.msg_flags      = (uint32_t)hm.msg_flags;
    gm.msg_controllen = 0U;
    if (hctl != NULL) {
        uint32_t glen = 0U;
        uint32_t addf = 0U;
        i686_sock_cmsg64_to_32(hctl, hm.msg_controllen,
                               (uint8_t *)i686_guest_ptr(ctx, gm.msg_control),
                               gcap, &glen, &addf, 1);
        gm.msg_controllen = glen;
        gm.msg_flags |= addf;
    }
    if (i686_copy_to_guest(ctx, msg_va, &gm, sizeof(gm)) != 0) {
        rc = -EFAULT;
        goto out_free;
    }
    if (hiov != NULL && hiov != stack_iov) {
        free(hiov);
    }
    if (hctl != NULL && hctl != stack_ctl) {
        free(hctl);
    }
    return r;
out_free:
    if (hiov != NULL && hiov != stack_iov) {
        free(hiov);
    }
    if (hctl != NULL && hctl != stack_ctl) {
        free(hctl);
    }
    return (int64_t)rc;
}

/* sendmmsg: loop the per-message sendmsg conversion (host mmsghdr layout
 * differs); vlen is clamped to UIO_MAXIOV (net/socket.c __sys_sendmmsg).
 * Returns the number of messages sent, or the (first) error. */
static int64_t sock_sendmmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t vec_va,
                             uint32_t vlen, uint32_t flags)
{
    if (vlen > I686_UIO_MAXIOV) {
        vlen = I686_UIO_MAXIOV;
    }
    if (vlen == 0U) {
        return 0;
    }
    if (!va_ok(vec_va, (uint64_t)vlen * (uint64_t)sizeof(i686_mmsghdr_t))) {
        return -EFAULT;
    }
    uint32_t n = 0U;
    for (uint32_t i = 0U; i < vlen; i++) {
        uint32_t va = vec_va + i * (uint32_t)sizeof(i686_mmsghdr_t);
        int64_t  r  = sock_sendmsg(ctx, fd, va, flags);
        if (r < 0) {
            return (n == 0U) ? r : (int64_t)n;
        }
        uint32_t len32 = (uint32_t)r;
        (void)i686_copy_to_guest(
            ctx, va + (uint32_t)offsetof(i686_mmsghdr_t, msg_len), &len32,
            sizeof(len32));
        n++;
    }
    return (int64_t)n;
}

/* recvmmsg: loop the per-message recvmsg conversion.  The overall timeout
 * budget (old_timespec32 for 102/19 and 337, __kernel_timespec for 417)
 * is emulated with a temporary host SO_RCVTIMEO per message and a drain
 * pass once the budget is spent; MSG_WAITFORONE switches later messages
 * to non-blocking, as the kernel does. */
static int64_t sock_recvmmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t vec_va,
                             uint32_t vlen, uint32_t flags,
                             uint32_t timeout_va, int time64)
{
    struct timespec deadline;
    int             have_deadline = 0;
    int             saved_valid   = 0;
    struct timeval  saved_to;
    uint32_t        n    = 0U;
    int64_t         last = 0U;

    if (timeout_va != 0U) {
        int64_t sec;
        int64_t nsec;
        if (time64) {
            /* struct __kernel_timespec {s64, s64}: layout-identical */
            uint8_t raw[16];
            if (!va_ok(timeout_va, sizeof(raw)) ||
                i686_copy_from_guest(ctx, raw, timeout_va, sizeof(raw)) != 0) {
                return -EFAULT;
            }
            sec  = (int64_t)guest_le32(raw) | ((int64_t)guest_le32(raw + 4U) << 32);
            nsec = (int64_t)guest_le32(raw + 8U) |
                   ((int64_t)guest_le32(raw + 12U) << 32);
        } else {
            i686_timespec_t g;
            if (!va_ok(timeout_va, sizeof(g)) ||
                i686_copy_from_guest(ctx, &g, timeout_va, sizeof(g)) != 0) {
                return -EFAULT;
            }
            sec  = g.tv_sec;
            nsec = g.tv_nsec;
        }
        if (nsec < 0 || nsec >= 1000000000LL) {
            return -EINVAL; /* kernel get_old_timespec32 style validation */
        }
        if (sec < 0) {
            sec = 0; /* treat expired budget as zero */
        }
        struct timespec now;
        (void)clock_gettime(CLOCK_MONOTONIC, &now);
        deadline.tv_sec  = now.tv_sec + (time_t)sec;
        deadline.tv_nsec = now.tv_nsec + nsec;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_nsec -= 1000000000L;
            deadline.tv_sec++;
        }
        have_deadline = 1;
        socklen_t sl = (socklen_t)sizeof(saved_to);
        saved_valid =
            (getsockopt((int)fd, SOL_SOCKET, SO_RCVTIMEO, &saved_to, &sl) == 0);
    }
    if (vlen > I686_UIO_MAXIOV) {
        vlen = I686_UIO_MAXIOV;
    }
    if (vlen == 0U) {
        return 0;
    }
    if (!va_ok(vec_va, (uint64_t)vlen * (uint64_t)sizeof(i686_mmsghdr_t))) {
        return -EFAULT;
    }
    for (uint32_t i = 0U; i < vlen; i++) {
        uint32_t va = vec_va + i * (uint32_t)sizeof(i686_mmsghdr_t);
        uint32_t fl = flags & ~I686_MSG_WAITFORONE;
        int      set_to = 0;

        if (i > 0U && (flags & I686_MSG_WAITFORONE) != 0U) {
            fl |= (uint32_t)MSG_DONTWAIT;
        }
        if (have_deadline) {
            struct timespec now;
            (void)clock_gettime(CLOCK_MONOTONIC, &now);
            int64_t rem_s  = (int64_t)(deadline.tv_sec - now.tv_sec);
            int64_t rem_ns = (int64_t)(deadline.tv_nsec - now.tv_nsec);
            if (rem_ns < 0) {
                rem_ns += 1000000000LL;
                rem_s--;
            }
            if (rem_s < 0 || (rem_s == 0 && rem_ns < 1000)) {
                fl |= (uint32_t)MSG_DONTWAIT; /* budget spent: drain only */
            } else if (saved_valid) {
                struct timeval rt;
                rt.tv_sec  = (time_t)rem_s;
                rt.tv_usec = (suseconds_t)(rem_ns / 1000LL);
                (void)setsockopt((int)fd, SOL_SOCKET, SO_RCVTIMEO, &rt,
                                 (socklen_t)sizeof(rt));
                set_to = 1;
            }
        }
        int64_t r = sock_recvmsg(ctx, fd, va, fl);
        if (set_to) {
            (void)setsockopt((int)fd, SOL_SOCKET, SO_RCVTIMEO, &saved_to,
                             (socklen_t)sizeof(saved_to));
        }
        if (r < 0) {
            last = r;
            break;
        }
        uint32_t len32 = (uint32_t)r;
        (void)i686_copy_to_guest(
            ctx, va + (uint32_t)offsetof(i686_mmsghdr_t, msg_len), &len32,
            sizeof(len32));
        n++;
    }
    if (n == 0U) {
        return last; /* vlen > 0, so the loop ran at least once */
    }
    return (int64_t)n;
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
        return sock_sendmsg(ctx, a[0], a[1], a[2]);
    case I686_SC_RECVMSG:
        return sock_recvmsg(ctx, a[0], a[1], a[2]);
    case I686_SC_ACCEPT4:
        return sock_accept4(ctx, a[0], a[1], a[2], a[3]);
    case I686_SC_RECVMMSG:
        return sock_recvmmsg(ctx, a[0], a[1], a[2], a[3], a[4], 0);
    case I686_SC_SENDMMSG:
        return sock_sendmmsg(ctx, a[0], a[1], a[2], a[3]);
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
    return sock_sendmsg(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX]);
}

static int64_t r_recvfrom(i686_ctx_t *ctx)
{
    return sock_recvfrom(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                         ctx->gpr[I686_REG_EDI], ctx->gpr[I686_REG_EBP]);
}

static int64_t r_recvmsg(i686_ctx_t *ctx)
{
    return sock_recvmsg(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX]);
}

static int64_t r_shutdown(i686_ctx_t *ctx)
{
    return sock_shutdown(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_recvmmsg(i686_ctx_t *ctx)
{
    return sock_recvmmsg(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                         ctx->gpr[I686_REG_EDI], 0);
}

static int64_t r_sendmmsg(i686_ctx_t *ctx)
{
    return sock_sendmmsg(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_recvmmsg_time64(i686_ctx_t *ctx)
{
    return sock_recvmmsg(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                         ctx->gpr[I686_REG_EDI], 1);
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
