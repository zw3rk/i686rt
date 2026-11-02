/*
 * Internal definitions and marshalling declarations for socket syscalls
 * (src/os/sys_sock.c and src/os/sys_sock_msg.c).
 */

#ifndef I686RT_OS_SYS_SOCK_INTERNAL_H
#define I686RT_OS_SYS_SOCK_INTERNAL_H

#include "os/marshal.h"
#include "os/structs_i386.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

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

/* ---- ABI constants ---------------------------------------------------- */

#define I686_UIO_MAXIOV 1024U
#define I686_ENOSYS 38

#define I686_SOL_SOCKET       1U   /* asm-generic/socket.h SOL_SOCKET */
#define I686_SO_RCVTIMEO_OLD  20U
#define I686_SO_SNDTIMEO_OLD  21U
#define I686_MSG_WAITFORONE   0x10000U /* asm-generic/socket.h */

#define I686_CMSG32_HDR         12U
#define I686_CMSG32_ALIGN(len)  (((uint32_t)(len) + 3U) & ~3U)

#ifndef CMSG_ALIGN
#define CMSG_ALIGN(len) (((len) + sizeof(size_t) - 1U) & ~(sizeof(size_t) - 1U))
#endif

#define I686_SOCKADDR_MAX  ((uint32_t)sizeof(struct sockaddr_storage))

#define I686_CMSG_STACK    256U
#define I686_IOV_STACK     16U
#define I686_CMSG_HOST_MAX 4096U

typedef struct {
    i686_msghdr_t msg_hdr;
    uint32_t      msg_len;
} i686_mmsghdr_t;

_Static_assert(sizeof(i686_mmsghdr_t) == 32U, "i686_mmsghdr_t 32 bytes");
_Static_assert(offsetof(i686_mmsghdr_t, msg_len) == 28U, "mmsg msg_len at 28");

static inline uint32_t guest_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void guest_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static inline int64_t sret(int64_t r)
{
    return (r < 0) ? -(int64_t)errno : r;
}

static inline int va_ok(uint32_t va, uint64_t len)
{
    if (len == 0U) {
        return 1;
    }
    if (va < 0x1000U) {
        return 0;
    }
    return (va + len <= 0x100000000ULL);
}

int i686_sock_cmsg32_to_64(const uint8_t *gctl, uint32_t glen, uint8_t *hbuf,
                           size_t hcap, size_t *out_hlen);
void i686_sock_cmsg64_to_32(const uint8_t *hctl, size_t hlen, uint8_t *gbuf,
                            uint32_t gcap, uint32_t *out_glen,
                            uint32_t *out_add_flags, int close_dropped);
int i686_sock_translate_iov(i686_ctx_t *ctx, uint32_t iov_va, uint32_t iovcnt,
                            struct iovec *stack_iov, uint32_t stack_cap,
                            struct iovec **out_iov);

int64_t i686_sock_sendmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t msg_va,
                          uint32_t flags);
int64_t i686_sock_recvmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t msg_va,
                          uint32_t flags);
int64_t i686_sock_sendmmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t vec_va,
                           uint32_t vlen, uint32_t flags);
int64_t i686_sock_recvmmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t vec_va,
                           uint32_t vlen, uint32_t flags, uint32_t timeout_va,
                           int time64);

#endif /* I686RT_OS_SYS_SOCK_INTERNAL_H */
