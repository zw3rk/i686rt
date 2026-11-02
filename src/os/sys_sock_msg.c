/*
 * cmsghdr/iovec/msghdr conversion and sendmsg/recvmsg/sendmmsg/recvmmsg
 * handlers for i386 socket syscalls (split from src/os/sys_sock.c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "os/sys_sock_internal.h"

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/* ---- cmsghdr conversion (i386 <-> host) ------------------------------- */

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

int64_t i686_sock_sendmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t msg_va,
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
            free(hctl);
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

int64_t i686_sock_recvmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t msg_va,
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
            free(hctl);
        }
        return rc;
    }
    r = recvmsg((int)fd, &hm, (int)flags);
    if (r < 0) {
        rc = -(int)errno;
        goto out_free;
    }
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

int64_t i686_sock_sendmmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t vec_va,
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
        int64_t  r  = i686_sock_sendmsg(ctx, fd, va, flags);
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

int64_t i686_sock_recvmmsg(i686_ctx_t *ctx, uint32_t fd, uint32_t vec_va,
                           uint32_t vlen, uint32_t flags, uint32_t timeout_va,
                           int time64)
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
            return -EINVAL;
        }
        if (sec < 0) {
            sec = 0;
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
                fl |= (uint32_t)MSG_DONTWAIT;
            } else if (saved_valid) {
                struct timeval rt;
                rt.tv_sec  = (time_t)rem_s;
                rt.tv_usec = (suseconds_t)(rem_ns / 1000LL);
                (void)setsockopt((int)fd, SOL_SOCKET, SO_RCVTIMEO, &rt,
                                 (socklen_t)sizeof(rt));
                set_to = 1;
            }
        }
        int64_t r = i686_sock_recvmsg(ctx, fd, va, fl);
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
        return last;
    }
    return (int64_t)n;
}
