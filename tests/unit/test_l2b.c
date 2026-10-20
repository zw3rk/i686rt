/*
 * tests/unit/test_l2b.c — host-native unit driver for lane L2b
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives src/os/sys_sock.c against a fake guest window: the pure
 * conversion helpers (cmsghdr u32<->u64, iovec walk) are checked
 * byte-exact, and the socketcall(102) multiplexer plus the direct
 * 359..373/337/345/417 numbers run through the registry against real
 * host sockets (socketpair/bind/getsockname — no network traffic).
 * The host here is macOS/darwin: SOL_SOCKET differs from Linux, so the
 * SCM_RIGHTS test crafts the guest cmsg with the HOST level value (the
 * runtime host is aarch64 Linux where guest and host values agree).
 *
 * Prints "L2B OK" and exits 0 when every check passes.
 */

/* structs_i386.h first: its sa_handler struct member must parse before
 * darwin's <stdlib.h> chain (sys/wait.h -> sys/signal.h) defines the
 * sa_handler macro. */
#include "i686rt.h"
#include "os/marshal.h"
#include "os/structs_i386.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

/* Conversion helpers under test (non-static in sys_sock.c). */
extern int i686_sock_cmsg32_to_64(const uint8_t *gctl, uint32_t glen,
                                  uint8_t *hbuf, size_t hcap, size_t *out_hlen);
extern void i686_sock_cmsg64_to_32(const uint8_t *hctl, size_t hlen,
                                   uint8_t *gbuf, uint32_t gcap,
                                   uint32_t *out_glen, uint32_t *out_add_flags,
                                   int close_dropped);
extern int i686_sock_translate_iov(i686_ctx_t *ctx, uint32_t iov_va,
                                   uint32_t iovcnt, struct iovec *stack_iov,
                                   uint32_t stack_cap, struct iovec **out_iov);

/* Fake guest window: guest_base + va lands inside this buffer
 * (little-endian host assumed). */
static uint8_t   g_window[0x10000];
static i686_ctx_t ctx;

/* window offsets */
#define W_ARGS 0x1000U
#define W_SV   0x1040U
#define W_MSG  0x1080U
#define W_MSG2 0x10C0U
#define W_IOV  0x1100U
#define W_CTL  0x1400U
#define W_CTL2 0x1500U
#define W_NAME 0x1600U
#define W_NAME2 0x1610U
#define W_LENP 0x1630U
#define W_BUF  0x2000U
#define W_BUF2 0x3000U
#define W_MVEC 0x5000U
#define W_TO   0x5200U

static int g_pass;
static int g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

static void st32(uint32_t va, uint32_t v)
{
    memcpy(&g_window[va], &v, 4U);
}

static uint32_t ld32(uint32_t va)
{
    uint32_t v = 0U;

    memcpy(&v, &g_window[va], 4U);
    return v;
}

static void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
}

/* socketcall(call = EBX, args = ECX): the i386 args array is u32 words. */
static int64_t sc(uint32_t op, const uint32_t args[6])
{
    memcpy(&g_window[W_ARGS], args, 24U);
    memset(&ctx.gpr, 0, sizeof ctx.gpr);
    ctx.gpr[I686_REG_EBX] = op;
    ctx.gpr[I686_REG_ECX] = W_ARGS;
    return i686_sys_dispatch(&ctx, 102);
}

/* direct (non-multiplexed) i386 socket syscall */
static int64_t direct(long nr, uint32_t a0, uint32_t a1, uint32_t a2,
                      uint32_t a3, uint32_t a4, uint32_t a5)
{
    memset(&ctx.gpr, 0, sizeof ctx.gpr);
    ctx.gpr[I686_REG_EBX] = a0;
    ctx.gpr[I686_REG_ECX] = a1;
    ctx.gpr[I686_REG_EDX] = a2;
    ctx.gpr[I686_REG_ESI] = a3;
    ctx.gpr[I686_REG_EDI] = a4;
    ctx.gpr[I686_REG_EBP] = a5;
    return i686_sys_dispatch(&ctx, nr);
}

/* ------------------------------------------------------------------ */
/* dispatch wiring, args-array reads, EFAULT/ENOSYS                    */
/* ------------------------------------------------------------------ */

static void t_dispatch(void)
{
    static const uint32_t z6[6] = {0U, 0U, 0U, 0U, 0U, 0U};

    /* unknown subcalls answer the Linux -ENOSYS (38) per the lane card
     * (the native kernel would answer -EINVAL) */
    CHECK(sc(0U, z6) == -38);
    CHECK(sc(21U, z6) == -38);
    CHECK(sc(0x100U, z6) == -38);

    /* args pointer: low page, NULL, and a truncated (wrapping) array */
    reset();
    ctx.gpr[I686_REG_EBX] = 11U; /* sendto: 6 words = 24 bytes */
    ctx.gpr[I686_REG_ECX] = 0x800U;
    CHECK(i686_sys_dispatch(&ctx, 102) == -EFAULT);
    reset();
    ctx.gpr[I686_REG_EBX] = 11U;
    ctx.gpr[I686_REG_ECX] = 0U;
    CHECK(i686_sys_dispatch(&ctx, 102) == -EFAULT);
    reset();
    ctx.gpr[I686_REG_EBX] = 11U;
    ctx.gpr[I686_REG_ECX] = 0xFFFFFFF8U; /* +24 wraps the 4 GiB window */
    CHECK(i686_sys_dispatch(&ctx, 102) == -EFAULT);
}

/* ------------------------------------------------------------------ */
/* socket / socketpair / send / recv / sendto / recvfrom               */
/* ------------------------------------------------------------------ */

static void t_socket_datapath(void)
{
    uint32_t sv[2] = {0U, 0U};

    /* SYS_SOCKET(AF_UNIX, SOCK_STREAM, 0): result returned directly */
    int64_t fd = sc(1U, (const uint32_t[6]){AF_UNIX, SOCK_STREAM, 0U, 0U, 0U, 0U});
    CHECK(fd >= 3);
    CHECK(close((int)fd) == 0);

    /* SYS_SOCKETPAIR fills the guest sv[2] */
    memset(&g_window[W_SV], 0xAA, 8U);
    CHECK(sc(8U, (const uint32_t[6]){AF_UNIX, SOCK_STREAM, 0U, W_SV, 0U, 0U}) == 0);
    memcpy(sv, &g_window[W_SV], sizeof sv);
    CHECK(sv[0] >= 3 && sv[1] >= 3 && sv[0] != sv[1]);

    memcpy(&g_window[W_BUF], "hello", 5U);
    CHECK(sc(9U, (const uint32_t[6]){sv[0], W_BUF, 5U, 0U, 0U, 0U}) == 5);
    CHECK(sc(10U, (const uint32_t[6]){sv[1], W_BUF2, 64U, 0U, 0U, 0U}) == 5);
    CHECK(memcmp(&g_window[W_BUF2], "hello", 5U) == 0);

    /* sendto/recvfrom with NULL address (socketpair) */
    memcpy(&g_window[W_BUF], "bye!!", 5U);
    CHECK(sc(11U, (const uint32_t[6]){sv[0], W_BUF, 5U, 0U, 0U, 0U}) == 5);
    CHECK(sc(12U, (const uint32_t[6]){sv[1], W_BUF2, 64U, 0U, 0U, 0U}) == 5);
    CHECK(memcmp(&g_window[W_BUF2], "bye!!", 5U) == 0);

    /* low/wrapping data buffer */
    CHECK(sc(9U, (const uint32_t[6]){sv[0], 0U, 4U, 0U, 0U, 0U}) == -EFAULT);
    CHECK(sc(9U, (const uint32_t[6]){sv[0], 0xFFFFFF00U, 0x200U, 0U, 0U, 0U}) ==
          -EFAULT);

    (void)close((int)sv[0]);
    (void)close((int)sv[1]);
}

static void t_direct_nrs(void)
{
    /* direct socket(359)/listen(363): INET stream sockets may listen
     * unbound on every host; darwin refuses that for AF_UNIX. */
    int64_t fd = direct(359, AF_INET, SOCK_STREAM, 0U, 0U, 0U, 0U);
    CHECK(fd >= 3);
    CHECK(direct(363, (uint32_t)fd, 1U, 0U, 0U, 0U, 0U) == 0);
    CHECK(close((int)fd) == 0);

    /* shutdown(373) on a connected socketpair end (darwin rejects it on
     * unconnected sockets; Linux does not).  No send afterwards: writes
     * on a shut-down socket raise SIGPIPE. */
    CHECK(direct(360, AF_UNIX, SOCK_STREAM, 0U, W_SV, 0U, 0U) == 0);
    uint32_t sv[2];
    memcpy(sv, &g_window[W_SV], sizeof sv);
    CHECK(direct(373, sv[0], SHUT_RDWR, 0U, 0U, 0U, 0U) == 0);
    (void)close((int)sv[0]);
    (void)close((int)sv[1]);

    /* a fresh pair for the data path */
    CHECK(direct(360, AF_UNIX, SOCK_STREAM, 0U, W_SV, 0U, 0U) == 0);
    memcpy(sv, &g_window[W_SV], sizeof sv);
    memcpy(&g_window[W_BUF], "ping", 4U);
    CHECK(direct(369, sv[0], W_BUF, 4U, 0U, 0U, 0U) == 4);
    CHECK(direct(371, sv[1], W_BUF2, 16U, 0U, 0U, 0U) == 4);
    CHECK(memcmp(&g_window[W_BUF2], "ping", 4U) == 0);
    (void)close((int)sv[0]);
    (void)close((int)sv[1]);

    /* mmsg zero-length and bad-timeout edge cases */
    CHECK(direct(345, 0U, W_MVEC, 0U, 0U, 0U, 0U) == 0); /* sendmmsg vlen 0 */
    CHECK(sc(19U, (const uint32_t[6]){0U, W_MVEC, 0U, 0U, 0U, 0U}) == 0);
    st32(W_TO, 1U);
    st32(W_TO + 4U, 2000000000U); /* invalid nsec (>= 1e9) */
    CHECK(sc(19U, (const uint32_t[6]){0U, W_MVEC, 1U, 0U, W_TO, 0U}) == -EINVAL);
    /* time64 variant: struct __kernel_timespec {s64 sec, s64 nsec} */
    st32(W_TO, 0U);
    st32(W_TO + 4U, 0U);
    st32(W_TO + 8U, 0xFFFFFFFFU); /* nsec = 0xFFFFFFFF > 1e9 */
    st32(W_TO + 12U, 0U);
    CHECK(direct(417, 0U, W_MVEC, 1U, 0U, W_TO, 0U) == -EINVAL);
}

/* sockaddr in/out: bind(361) an AF_INET socket to 127.0.0.1:0, then read
 * the assigned address back with getsockname(367).  No packets. */
static void t_bind_getsockname(void)
{
    int64_t fd = sc(1U, (const uint32_t[6]){AF_INET, SOCK_DGRAM, 0U, 0U, 0U, 0U});
    CHECK(fd >= 3);

    memset(&g_window[W_NAME], 0, 16U);
    g_window[W_NAME] = (uint8_t)AF_INET;  /* sin_family */
    g_window[W_NAME + 2] = 0U;            /* sin_port = 0 (assign) */
    g_window[W_NAME + 4] = 127U;          /* 127.0.0.1 */
    g_window[W_NAME + 7] = 1U;
    CHECK(direct(361, (uint32_t)fd, W_NAME, 16U, 0U, 0U, 0U) == 0);

    st32(W_LENP, 16U);
    CHECK(direct(367, (uint32_t)fd, W_NAME2, W_LENP, 0U, 0U, 0U) == 0);
    CHECK(ld32(W_LENP) == 16U);
#ifdef __APPLE__
    /* darwin writes BSD sockaddrs with a sa_len byte first */
    CHECK(g_window[W_NAME2 + 1] == (uint8_t)AF_INET);
#else
    CHECK(g_window[W_NAME2] == (uint8_t)AF_INET);
    CHECK(g_window[W_NAME2 + 1] == 0U);
#endif
    CHECK(g_window[W_NAME2 + 4] == 127U && g_window[W_NAME2 + 7] == 1U);
    uint32_t port = ((uint32_t)g_window[W_NAME2 + 2] << 8) |
                    (uint32_t)g_window[W_NAME2 + 3];
    CHECK(port != 0U);

    /* socketcall subcalls 2/6 agree with the direct path */
    CHECK(sc(6U, (const uint32_t[6]){(uint32_t)fd, W_NAME2, W_LENP, 0U, 0U, 0U}) ==
          0);
    CHECK(ld32(W_LENP) == 16U);

    /* truncated sockaddr: 128-byte clamp at 0xFFFFFFF0 wraps the window */
    CHECK(sc(2U, (const uint32_t[6]){(uint32_t)fd, 0xFFFFFFF0U, 0x200U, 0U, 0U, 0U}) ==
          -EFAULT);

    (void)shutdown((int)fd, SHUT_RDWR);
    CHECK(close((int)fd) == 0);
}

/* ------------------------------------------------------------------ */
/* setsockopt/getsockopt SO_RCVTIMEO/SO_SNDTIMEO (timeval 8 <-> 16 B)  */
/* ------------------------------------------------------------------ */

static void t_sockopt_timeval(void)
{
    CHECK(sc(8U, (const uint32_t[6]){AF_UNIX, SOCK_STREAM, 0U, W_SV, 0U, 0U}) == 0);
    uint32_t sv[2];
    memcpy(sv, &g_window[W_SV], sizeof sv);

    /* guest 8-byte timeval {1, 500000} under guest opts SOL_SOCKET=1 /
     * SO_RCVTIMEO=20 converts to the host 16-byte form */
    st32(W_BUF, 1U);
    st32(W_BUF + 4U, 500000U);
    CHECK(sc(14U, (const uint32_t[6]){sv[0], 1U, 20U, W_BUF, 8U, 0U}) == 0);

    st32(W_LENP, 64U);
    CHECK(sc(15U, (const uint32_t[6]){sv[0], 1U, 20U, W_BUF2, W_LENP, 0U}) == 0);
    CHECK(ld32(W_LENP) == 8U);
    CHECK(ld32(W_BUF2) == 1U && ld32(W_BUF2 + 4U) == 500000U);

    /* SNDTIMEO round trip */
    st32(W_BUF, 0U);
    st32(W_BUF + 4U, 300000U);
    CHECK(sc(14U, (const uint32_t[6]){sv[0], 1U, 21U, W_BUF, 8U, 0U}) == 0);
    st32(W_LENP, 8U);
    CHECK(sc(15U, (const uint32_t[6]){sv[0], 1U, 21U, W_BUF2, W_LENP, 0U}) == 0);
    CHECK(ld32(W_BUF2) == 0U && ld32(W_BUF2 + 4U) == 300000U);

    /* kernel semantics: usec out of range -> -EDOM; short optlen ->
     * -EINVAL; bad optval pointer -> -EFAULT */
    st32(W_BUF, 1U);
    st32(W_BUF + 4U, 1500000U);
    CHECK(sc(14U, (const uint32_t[6]){sv[0], 1U, 20U, W_BUF, 8U, 0U}) == -EDOM);
    CHECK(sc(14U, (const uint32_t[6]){sv[0], 1U, 20U, W_BUF, 4U, 0U}) == -EINVAL);
    CHECK(sc(14U, (const uint32_t[6]){sv[0], 1U, 20U, 0U, 8U, 0U}) == -EFAULT);

    (void)close((int)sv[0]);
    (void)close((int)sv[1]);
}

/* ------------------------------------------------------------------ */
/* msghdr deep marshalling: iovec aggregation over sendmsg/recvmsg     */
/* ------------------------------------------------------------------ */

static void t_sendmsg_iov(void)
{
    CHECK(sc(8U, (const uint32_t[6]){AF_UNIX, SOCK_STREAM, 0U, W_SV, 0U, 0U}) == 0);
    uint32_t sv[2];
    memcpy(sv, &g_window[W_SV], sizeof sv);

    memcpy(&g_window[W_BUF], "L2b is cool", 12U);
    /* three guest iovs: 4 + 3 + 5 bytes */
    st32(W_IOV, W_BUF);
    st32(W_IOV + 4U, 4U);
    st32(W_IOV + 8U, W_BUF + 4U);
    st32(W_IOV + 12U, 3U);
    st32(W_IOV + 16U, W_BUF + 7U);
    st32(W_IOV + 20U, 5U);
    /* msghdr: name/controllen 0, iov W_IOV, 3 entries */
    uint32_t m[7] = {0U, 0U, W_IOV, 3U, 0U, 0U, 0U};
    memcpy(&g_window[W_MSG], m, sizeof m);
    CHECK(sc(16U, (const uint32_t[6]){sv[0], W_MSG, 0U, 0U, 0U, 0U}) == 12);

    /* single-iov recv; msghdr fields written back */
    st32(W_IOV, W_BUF2);
    st32(W_IOV + 4U, 64U);
    uint32_t m2[7] = {0U, 0U, W_IOV, 1U, 0U, 0U, 0U};
    memcpy(&g_window[W_MSG2], m2, sizeof m2);
    CHECK(sc(17U, (const uint32_t[6]){sv[1], W_MSG2, 0U, 0U, 0U, 0U}) == 12);
    CHECK(memcmp(&g_window[W_BUF2], "L2b is cool", 12U) == 0);
    memcpy(m2, &g_window[W_MSG2], sizeof m2);
    CHECK(m2[1] == 0U);        /* msg_namelen */
    CHECK(m2[5] == 0U);        /* msg_controllen */
    CHECK(m2[6] == 0U);        /* msg_flags: no MSG_TRUNC/CTRUNC */

    /* iov aggregation beyond the 16-entry stack cap (heap path) */
    for (uint32_t i = 0U; i < 20U; i++) {
        st32(W_IOV + i * 8U, W_BUF2 + 0x200U + i);
        st32(W_IOV + i * 8U + 4U, 1U);
        g_window[W_BUF2 + 0x200U + i] = (uint8_t)('a' + i);
    }
    memcpy(&g_window[W_MSG], (const uint32_t[7]){0U, 0U, W_IOV, 20U, 0U, 0U, 0U},
           28U);
    CHECK(sc(16U, (const uint32_t[6]){sv[0], W_MSG, 0U, 0U, 0U, 0U}) == 20);
    /* re-point the recv msghdr's iov at a single 64-byte buffer (the send
     * side already consumed the 20-entry array) */
    st32(W_IOV, W_BUF2);
    st32(W_IOV + 4U, 64U);
    CHECK(sc(17U, (const uint32_t[6]){sv[1], W_MSG2, 0U, 0U, 0U, 0U}) == 20);
    CHECK(memcmp(&g_window[W_BUF2], "abcdefghijklmnopqrst", 20U) == 0);

    /* msg_iovlen > UIO_MAXIOV -> -EMSGSIZE (net/compat.c) */
    memcpy(&g_window[W_MSG], (const uint32_t[7]){0U, 0U, W_IOV, 1025U, 0U, 0U, 0U},
           28U);
    CHECK(sc(16U, (const uint32_t[6]){sv[0], W_MSG, 0U, 0U, 0U, 0U}) == -EMSGSIZE);
    CHECK(sc(17U, (const uint32_t[6]){sv[1], W_MSG, 0U, 0U, 0U, 0U}) == -EMSGSIZE);

    /* bad iov array (2 entries at 0xFFFFFFF8 wrap the window) and a bad
     * iov entry (base+len wraps) */
    memcpy(&g_window[W_MSG], (const uint32_t[7]){0U, 0U, 0xFFFFFFF8U, 2U, 0U, 0U, 0U},
           28U);
    CHECK(sc(16U, (const uint32_t[6]){sv[0], W_MSG, 0U, 0U, 0U, 0U}) == -EFAULT);
    st32(W_IOV, 0xFFFFFF00U);
    st32(W_IOV + 4U, 0x200U);
    st32(W_IOV + 8U, W_BUF);
    st32(W_IOV + 12U, 4U);
    memcpy(&g_window[W_MSG], (const uint32_t[7]){0U, 0U, W_IOV, 2U, 0U, 0U, 0U},
           28U);
    CHECK(sc(16U, (const uint32_t[6]){sv[0], W_MSG, 0U, 0U, 0U, 0U}) == -EFAULT);

    /* bad msghdr pointer (28 bytes at 0xFFFFFFE8 wrap) */
    CHECK(sc(16U, (const uint32_t[6]){sv[0], 0xFFFFFFE8U, 0U, 0U, 0U, 0U}) ==
          -EFAULT);

    /* control < 12 bytes with nonzero controllen -> -EINVAL */
    memcpy(&g_window[W_MSG], (const uint32_t[7]){0U, 0U, W_IOV, 0U, W_CTL, 4U, 0U},
           28U);
    CHECK(sc(16U, (const uint32_t[6]){sv[0], W_MSG, 0U, 0U, 0U, 0U}) == -EINVAL);

    (void)close((int)sv[0]);
    (void)close((int)sv[1]);
}

/* ------------------------------------------------------------------ */
/* pure converters: cmsghdr u32 <-> u64                                */
/* ------------------------------------------------------------------ */

static void t_cmsg_pure(void)
{
    _Alignas(8) uint8_t hostbuf[128];
    uint8_t  *gctl = &g_window[W_CTL];
    uint8_t  *gctl2 = &g_window[W_CTL2];
    size_t    hlen = 0U;
    uint32_t  glen = 0U;
    uint32_t  addf = 0U;

    /* guest chain: cmsg{len 16, level 0x111, type 0x222, payload de ad be
     * ef} then cmsg{len 13, level 0x333, type 0x444, payload 01} — the
     * second advances by align4(13) = 16. */
    memset(gctl, 0xEE, 64U);
    st32(W_CTL, 16U);
    st32(W_CTL + 4U, 0x111U);
    st32(W_CTL + 8U, 0x222U);
    gctl[12] = 0xDEU; gctl[13] = 0xADU; gctl[14] = 0xBEU; gctl[15] = 0xEFU;
    st32(W_CTL + 16U, 13U);
    st32(W_CTL + 20U, 0x333U);
    st32(W_CTL + 24U, 0x444U);
    gctl[28] = 0x01U;

    /* size pass + build pass */
    CHECK(i686_sock_cmsg32_to_64(gctl, 32U, NULL, 0U, &hlen) == 0);
    CHECK(hlen == CMSG_SPACE(4U) + CMSG_SPACE(1U));
    memset(hostbuf, 0, sizeof hostbuf);
    size_t hlen2 = 0U;
    CHECK(i686_sock_cmsg32_to_64(gctl, 32U, hostbuf, sizeof hostbuf, &hlen2) == 0);
    CHECK(hlen2 == hlen);
    const struct cmsghdr *c1 = (const struct cmsghdr *)(const void *)hostbuf;
    CHECK(c1->cmsg_len == CMSG_LEN(4U));
    CHECK(c1->cmsg_level == 0x111 && c1->cmsg_type == 0x222);
    CHECK(memcmp(CMSG_DATA(c1), "\xde\xad\xbe\xef", 4U) == 0);
    const struct cmsghdr *c2 =
        (const struct cmsghdr *)(const void *)(hostbuf + CMSG_SPACE(4U));
    CHECK(c2->cmsg_len == CMSG_LEN(1U));
    CHECK(c2->cmsg_level == 0x333 && c2->cmsg_type == 0x444);
    CHECK(CMSG_DATA(c2)[0] == 0x01U);

    /* host -> guest round trip: byte-exact i386 layout */
    memset(gctl2, 0xDD, 64U);
    i686_sock_cmsg64_to_32(hostbuf, hlen2, gctl2, 64U, &glen, &addf, 0);
    CHECK(addf == 0U);
    CHECK(glen == 32U); /* 16 (cmsg1+pad) + align4(13)=16 (cmsg2) */
    CHECK(ld32(W_CTL2) == 16U);
    CHECK(ld32(W_CTL2 + 4U) == 0x111U);
    CHECK(ld32(W_CTL2 + 8U) == 0x222U);
    CHECK(memcmp(gctl2 + 12U, "\xde\xad\xbe\xef", 4U) == 0);
    CHECK(ld32(W_CTL2 + 16U) == 13U);
    CHECK(ld32(W_CTL2 + 20U) == 0x333U);
    CHECK(ld32(W_CTL2 + 24U) == 0x444U);
    CHECK(gctl2[28] == 0x01U && gctl2[29] == 0xDDU); /* payload verbatim, pad kept */

    /* truncation: gcap 20 fits cmsg1 only -> MSG_CTRUNC, len 16 */
    memset(gctl2, 0, 32U);
    addf = 0U;
    i686_sock_cmsg64_to_32(hostbuf, hlen2, gctl2, 20U, &glen, &addf, 0);
    CHECK(glen == 16U);
    CHECK(addf == (uint32_t)MSG_CTRUNC);
    CHECK(ld32(W_CTL2) == 16U && ld32(W_CTL2 + 16U) == 0U);

    /* malformed guest cmsg (len < 12) -> -EINVAL */
    st32(W_CTL2, 8U);
    size_t unused = 0U;
    CHECK(i686_sock_cmsg32_to_64(gctl2, 12U, NULL, 0U, &unused) == -EINVAL);
    /* cmsg_len past the end -> -EINVAL */
    st32(W_CTL2, 100U);
    CHECK(i686_sock_cmsg32_to_64(gctl2, 32U, NULL, 0U, &unused) == -EINVAL);
}

/* SCM_RIGHTS end-to-end through sendmsg/recvmsg: the guest cmsg carries
 * the HOST SOL_SOCKET value (darwin differs from Linux; the runtime host
 * is Linux where they agree).  darwin rejects zero-iov sendmsg/recvmsg,
 * so both sides carry a 1-byte iov. */
static void t_cmsg_rights(void)
{
    CHECK(sc(8U, (const uint32_t[6]){AF_UNIX, SOCK_STREAM, 0U, W_SV, 0U, 0U}) == 0);
    uint32_t sv[2];
    memcpy(sv, &g_window[W_SV], sizeof sv);

    st32(W_CTL, 16U); /* len32 = 12 + one int */
    st32(W_CTL + 4U, (uint32_t)SOL_SOCKET);
    st32(W_CTL + 8U, (uint32_t)SCM_RIGHTS);
    st32(W_CTL + 12U, sv[0]);
    st32(W_IOV, W_BUF);
    st32(W_IOV + 4U, 1U);
    g_window[W_BUF] = 'X';
    memcpy(&g_window[W_MSG], (const uint32_t[7]){0U, 0U, W_IOV, 1U, W_CTL, 16U, 0U},
           28U);
    CHECK(sc(16U, (const uint32_t[6]){sv[0], W_MSG, 0U, 0U, 0U, 0U}) == 1);

    st32(W_IOV, W_BUF2);
    st32(W_IOV + 4U, 4U);
    memcpy(&g_window[W_MSG2], (const uint32_t[7]){0U, 0U, W_IOV, 1U, W_CTL2, 64U, 0U},
           28U);
    CHECK(sc(17U, (const uint32_t[6]){sv[1], W_MSG2, 0U, 0U, 0U, 0U}) == 1);
    CHECK(g_window[W_BUF2] == 'X');
    uint32_t m2[7];
    memcpy(m2, &g_window[W_MSG2], sizeof m2);
    CHECK(m2[5] == 16U); /* msg_controllen: packed i386 cmsg */
    CHECK(m2[6] == 0U);  /* no truncation */
    CHECK(ld32(W_CTL2) == 16U);
    CHECK(ld32(W_CTL2 + 4U) == (uint32_t)SOL_SOCKET);
    CHECK(ld32(W_CTL2 + 8U) == (uint32_t)SCM_RIGHTS);
    int32_t got_fd = (int32_t)ld32(W_CTL2 + 12U);
    CHECK(got_fd >= 3);
    CHECK(close(got_fd) == 0);

    /* too-small guest control -> MSG_CTRUNC and the dropped fd closed
     * inside the adapter */
    memcpy(&g_window[W_MSG], (const uint32_t[7]){0U, 0U, W_IOV, 1U, W_CTL, 16U, 0U},
           28U);
    st32(W_IOV, W_BUF);
    st32(W_IOV + 4U, 1U);
    g_window[W_BUF] = 'Y';
    CHECK(sc(16U, (const uint32_t[6]){sv[0], W_MSG, 0U, 0U, 0U, 0U}) == 1);
    st32(W_IOV, W_BUF2);
    st32(W_IOV + 4U, 4U);
    memcpy(&g_window[W_MSG2], (const uint32_t[7]){0U, 0U, W_IOV, 1U, W_CTL2, 8U, 0U},
           28U);
    CHECK(sc(17U, (const uint32_t[6]){sv[1], W_MSG2, 0U, 0U, 0U, 0U}) == 1);
    memcpy(m2, &g_window[W_MSG2], sizeof m2);
    CHECK(m2[5] == 0U);
    CHECK((m2[6] & (uint32_t)MSG_CTRUNC) != 0U);

    (void)close((int)sv[0]);
    (void)close((int)sv[1]);
}

/* ------------------------------------------------------------------ */
/* pure iovec walk                                                     */
/* ------------------------------------------------------------------ */

static void t_iov_pure(void)
{
    struct iovec stack[4];
    struct iovec *hiov = NULL;

    st32(W_IOV, 0x2000U);
    st32(W_IOV + 4U, 10U);
    st32(W_IOV + 8U, 0x2000U + 100U);
    st32(W_IOV + 12U, 0U); /* zero-length entry: NULL base allowed */
    st32(W_IOV + 16U, 0x2000U + 200U);
    st32(W_IOV + 20U, 0x100000000U - (0x2000U + 200U)); /* max fitting len */

    CHECK(i686_sock_translate_iov(&ctx, W_IOV, 3U, stack, 4U, &hiov) == 0);
    CHECK(hiov == stack);
    CHECK(hiov[0].iov_base == (void *)&g_window[0x2000U]);
    CHECK(hiov[0].iov_len == 10U);
    CHECK(hiov[1].iov_base == NULL); /* zero-length entry carries NULL */
    CHECK(hiov[1].iov_len == 0U);
    CHECK(hiov[2].iov_len == 0x100000000U - (0x2000U + 200U));

    /* above UIO_MAXIOV -> -EINVAL */
    CHECK(i686_sock_translate_iov(&ctx, W_IOV, 1025U, stack, 4U, &hiov) == -EINVAL);
    /* wrapping iov array (2 entries = 16 B at 0xFFFFFFF8) -> -EFAULT */
    CHECK(i686_sock_translate_iov(&ctx, 0xFFFFFFF8U, 2U, stack, 4U, &hiov) ==
          -EFAULT);
    /* wrapping entry -> -EFAULT */
    st32(W_IOV, 0xFFFFFFF0U);
    st32(W_IOV + 4U, 0x20U);
    CHECK(i686_sock_translate_iov(&ctx, W_IOV, 1U, stack, 4U, &hiov) == -EFAULT);

    /* heap path above the stack cap */
    for (uint32_t i = 0U; i < 6U; i++) {
        st32(W_IOV + i * 8U, 0x2000U + i * 8U);
        st32(W_IOV + i * 8U + 4U, i);
    }
    CHECK(i686_sock_translate_iov(&ctx, W_IOV, 6U, stack, 4U, &hiov) == 0);
    CHECK(hiov != NULL && hiov != stack);
    CHECK(hiov[5].iov_base == (void *)&g_window[0x2000U + 40U]);
    CHECK(hiov[5].iov_len == 5U);
    free(hiov);
}

/* ------------------------------------------------------------------ */
/* sendmmsg/recvmmsg arrays                                            */
/* ------------------------------------------------------------------ */

static void t_mmsg(void)
{
    /* SOCK_DGRAM keeps message boundaries so the two 5-byte messages
     * arrive as two recvmmsg entries (a stream socket would coalesce;
     * darwin lacks AF_UNIX SOCK_SEQPACKET) */
    CHECK(sc(8U, (const uint32_t[6]){AF_UNIX, SOCK_DGRAM, 0U, W_SV, 0U, 0U}) == 0);
    uint32_t sv[2];
    memcpy(sv, &g_window[W_SV], sizeof sv);

    /* two 5-byte messages; msghdr fields: msg_iov at +8, msg_iovlen at
     * +12, msg_len of the mmsghdr wrapper at +28 */
    memcpy(&g_window[W_BUF], "mmsgA", 5U);
    memcpy(&g_window[W_BUF + 8U], "mmsgB", 5U);
    for (uint32_t i = 0U; i < 2U; i++) {
        uint32_t base = W_MVEC + i * 32U;
        st32(base + 8U, W_IOV + i * 8U); /* msg_iov */
        st32(base + 12U, 1U);            /* msg_iovlen */
        st32(base + 28U, 0xFFFFU);       /* msg_len marker */
        st32(W_IOV + i * 8U, W_BUF + i * 8U);
        st32(W_IOV + i * 8U + 4U, 5U);
    }
    CHECK(direct(345, sv[0], W_MVEC, 2U, 0U, 0U, 0U) == 2);
    CHECK(ld32(W_MVEC + 28U) == 5U && ld32(W_MVEC + 60U) == 5U);

    /* recvmmsg via subcall 19 with a zero timeout (drain-only) */
    for (uint32_t i = 0U; i < 2U; i++) {
        uint32_t base = W_MVEC + i * 32U;
        st32(base + 8U, W_IOV + 16U + i * 8U);
        st32(base + 12U, 1U);
        st32(base + 28U, 0xFFFFU);
        st32(W_IOV + 16U + i * 8U, W_BUF2 + i * 8U);
        st32(W_IOV + 16U + i * 8U + 4U, 16U);
    }
    st32(W_TO, 0U);
    st32(W_TO + 4U, 0U);
    CHECK(sc(19U, (const uint32_t[6]){sv[1], W_MVEC, 2U, 0U, W_TO, 0U}) == 2);
    CHECK(ld32(W_MVEC + 28U) == 5U && ld32(W_MVEC + 60U) == 5U);
    CHECK(memcmp(&g_window[W_BUF2], "mmsgA", 5U) == 0);
    CHECK(memcmp(&g_window[W_BUF2 + 8U], "mmsgB", 5U) == 0);
    CHECK(ld32(W_MVEC + 28U) == 5U);

    /* mmsg vec pointer that wraps the window (2 * 32 B at 0xFFFFFFE0) */
    CHECK(direct(345, sv[0], 0xFFFFFFE0U, 2U, 0U, 0U, 0U) == -EFAULT);

    (void)close((int)sv[0]);
    (void)close((int)sv[1]);
}

int main(void)
{
    reset();
    i686_syscalls_sock_init();

    t_dispatch();
    t_socket_datapath();
    t_direct_nrs();
    t_bind_getsockname();
    t_sockopt_timeval();
    t_sendmsg_iov();
    t_cmsg_pure();
    t_cmsg_rights();
    t_iov_pure();
    t_mmsg();

    if (g_fail != 0) {
        printf("L2B FAILED: %d check(s) failed (%d passed)\n", g_fail, g_pass);
        return 1;
    }
    printf("L2B OK\n");
    return 0;
}
