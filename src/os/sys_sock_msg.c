/*
 * cmsghdr/iovec/msghdr conversion and sendmsg/recvmsg/sendmmsg/recvmmsg
 * handlers for i386 socket syscalls (split from src/os/sys_sock.c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "os/sys_sock_internal.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
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
            /* I686-R5-5: partial SCM_RIGHTS delivery. Emit the prefix of
             * complete int32 fds that fit (if at least one fits), set
             * MSG_CTRUNC, and close only the undelivered trailing fds. */
            if (cm->cmsg_level == SOL_SOCKET &&
                cm->cmsg_type == SCM_RIGHTS) {
                size_t     nfds = payload / sizeof(int);
                const int *fds  = (const int *)(const void *)CMSG_DATA(cm);
                uint32_t   rem  = (off32 <= gcap) ? (gcap - off32) : 0U;
                size_t     fit  = 0U;
                if (rem >=
                    (uint32_t)I686_CMSG32_HDR + (uint32_t)sizeof(int32_t)) {
                    fit = ((size_t)rem - (size_t)I686_CMSG32_HDR) /
                          sizeof(int32_t);
                    if (fit > nfds) {
                        fit = nfds;
                    }
                }
                if (fit > 0U) {
                    uint32_t len32   = I686_CMSG32_HDR +
                                       (uint32_t)(fit * sizeof(int32_t));
                    uint32_t space32 = I686_CMSG32_ALIGN(len32);
                    guest_store_le32(gbuf + off32, len32);
                    guest_store_le32(gbuf + off32 + 4U,
                                     (uint32_t)cm->cmsg_level);
                    guest_store_le32(gbuf + off32 + 8U,
                                     (uint32_t)cm->cmsg_type);
                    for (size_t i = 0U; i < fit; i++) {
                        guest_store_le32(
                            gbuf + off32 + I686_CMSG32_HDR + i * 4U,
                            (uint32_t)fds[i]);
                    }
                    off32 += (((uint64_t)off32 + space32 <= (uint64_t)gcap)
                                  ? space32
                                  : len32);
                    if (close_dropped) {
                        for (size_t i = fit; i < nfds; i++) {
                            (void)close(fds[i]);
                        }
                    }
                } else if (close_dropped) {
                    for (size_t i = 0U; i < nfds; i++) {
                        (void)close(fds[i]);
                    }
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
    /* I686-R5-4: fetch iovec descriptors with checked guest copies. */
    for (uint32_t i = 0U; i < iovcnt; i++) {
        i686_iovec_t g;
        if (i686_copy_from_guest(
                ctx, &g, iov_va + i * (uint32_t)sizeof(i686_iovec_t),
                sizeof(g)) != 0) {
            if (hiov != stack_iov) {
                free(hiov);
            }
            return -EFAULT;
        }
        if (g.iov_len != 0U) {
            if (g.iov_base < 0x1000U ||
                (uint64_t)g.iov_base + (uint64_t)g.iov_len >
                    0x100000000ULL) {
                if (hiov != stack_iov) {
                    free(hiov);
                }
                return -EFAULT;
            }
            /* Payload staging to host heap happens in msghdr_build so
             * the host kernel never touches A2 covering pages. */
            hiov[i].iov_base = i686_guest_ptr(ctx, g.iov_base);
        } else {
            hiov[i].iov_base = NULL;
        }
        hiov[i].iov_len = (size_t)g.iov_len;
    }
    *out_iov = hiov;
    return 0;
}

/* I686-R5-4: free heap payload buffers staged in hiov[0..cnt). */
static void msg_free_payloads(struct iovec *hiov, uint32_t cnt)
{
    if (hiov == NULL) {
        return;
    }
    for (uint32_t i = 0U; i < cnt; i++) {
        free(hiov[i].iov_base);
        hiov[i].iov_base = NULL;
        hiov[i].iov_len  = 0U;
    }
}

static int msghdr_build(i686_ctx_t *ctx, uint32_t msg_va, int dir_recv,
                        struct msghdr *hm, i686_msghdr_t *gm,
                        struct iovec **iovp, uint8_t **ctlp,
                        uint8_t *stack_ctl, uint32_t stack_ctl_len,
                        struct iovec *stack_iov, uint32_t stack_iov_len)
{
    size_t   ctl_len   = 0U;
    uint8_t *name_buf  = NULL;
    uint8_t *ctl_copy  = NULL;
    int      rc;

    memset(hm, 0, sizeof(*hm));
    *iovp = NULL;
    *ctlp = NULL;
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
    /* I686-R5-4: stage sockaddr through host heap, never guest_ptr. */
    if (gm->msg_name != 0U) {
        uint32_t nlen = (gm->msg_namelen > I686_SOCKADDR_MAX)
                            ? I686_SOCKADDR_MAX
                            : gm->msg_namelen;
        if (nlen != 0U && !va_ok(gm->msg_name, nlen)) {
            return -EFAULT;
        }
        if (nlen != 0U) {
            name_buf = (uint8_t *)malloc((nlen != 0U) ? nlen : 1U);
            if (name_buf == NULL) {
                return -ENOMEM;
            }
            if (!dir_recv) {
                if (i686_copy_from_guest(ctx, name_buf, gm->msg_name,
                                         nlen) != 0) {
                    free(name_buf);
                    return -EFAULT;
                }
            }
        }
        hm->msg_name    = (nlen != 0U) ? name_buf : NULL;
        hm->msg_namelen = nlen;
    } else if (dir_recv) {
        hm->msg_namelen = 0U;
    }
    if (gm->msg_control != 0U && gm->msg_controllen != 0U) {
        if (!va_ok(gm->msg_control, gm->msg_controllen)) {
            free(name_buf);
            return -EFAULT;
        }
        if (!dir_recv) {
            /* I686-R5-4: copy guest control to host heap before walk. */
            ctl_copy = (uint8_t *)malloc(gm->msg_controllen);
            if (ctl_copy == NULL) {
                free(name_buf);
                return -ENOMEM;
            }
            if (i686_copy_from_guest(ctx, ctl_copy, gm->msg_control,
                                     gm->msg_controllen) != 0) {
                free(name_buf);
                free(ctl_copy);
                return -EFAULT;
            }
            rc = i686_sock_cmsg32_to_64(ctl_copy, gm->msg_controllen, NULL,
                                        0U, &ctl_len);
            if (rc != 0) {
                free(name_buf);
                free(ctl_copy);
                return rc;
            }
            if (ctl_len != 0U) {
                *ctlp = (ctl_len <= stack_ctl_len) ? stack_ctl
                                                   : (uint8_t *)malloc(ctl_len);
                if (*ctlp == NULL) {
                    free(name_buf);
                    free(ctl_copy);
                    return -ENOMEM;
                }
                rc = i686_sock_cmsg32_to_64(ctl_copy, gm->msg_controllen,
                                            *ctlp, ctl_len, &ctl_len);
                free(ctl_copy);
                ctl_copy = NULL;
                if (rc != 0) {
                    free(name_buf);
                    if (*ctlp != stack_ctl) {
                        free(*ctlp);
                        *ctlp = NULL;
                    }
                    return rc;
                }
                hm->msg_control    = *ctlp;
                hm->msg_controllen = ctl_len;
            } else {
                free(ctl_copy);
                ctl_copy = NULL;
            }
        } else {
            uint64_t cap = (uint64_t)gm->msg_controllen * 2U;
            if (cap > I686_CMSG_HOST_MAX) {
                cap = I686_CMSG_HOST_MAX;
            }
            if (cap == 0U) {
                hm->msg_control    = NULL;
                hm->msg_controllen = 0U;
            } else {
                *ctlp = (cap <= stack_ctl_len) ? stack_ctl
                                               : (uint8_t *)malloc((size_t)cap);
                if (*ctlp == NULL) {
                    free(name_buf);
                    return -ENOMEM;
                }
                hm->msg_control    = *ctlp;
                hm->msg_controllen = (size_t)cap;
            }
        }
    }
    rc = i686_sock_translate_iov(ctx, gm->msg_iov, gm->msg_iovlen, stack_iov,
                                 stack_iov_len, iovp);
    if (rc != 0) {
        free(name_buf);
        if (*ctlp != NULL && *ctlp != stack_ctl) {
            free(*ctlp);
            *ctlp = NULL;
        }
        hm->msg_name = NULL;
        return rc;
    }
    /* I686-R5-4: stage iovec payloads through host heap buffers. */
    for (uint32_t i = 0U; i < gm->msg_iovlen; i++) {
        i686_iovec_t g;
        uint8_t     *hb = NULL;
        if (i686_copy_from_guest(
                ctx, &g, gm->msg_iov + i * (uint32_t)sizeof(g),
                sizeof(g)) != 0) {
            for (uint32_t j = 0U; j < i; j++) {
                free((*iovp)[j].iov_base);
                (*iovp)[j].iov_base = NULL;
            }
            free(name_buf);
            hm->msg_name = NULL;
            if (*ctlp != NULL && *ctlp != stack_ctl) {
                free(*ctlp);
                *ctlp = NULL;
            }
            if (*iovp != NULL && *iovp != stack_iov) {
                free(*iovp);
                *iovp = NULL;
            }
            return -EFAULT;
        }
        if (g.iov_len == 0U) {
            (*iovp)[i].iov_base = NULL;
            (*iovp)[i].iov_len  = 0U;
            continue;
        }
        hb = (uint8_t *)malloc(g.iov_len);
        if (hb == NULL) {
            for (uint32_t j = 0U; j < i; j++) {
                free((*iovp)[j].iov_base);
            }
            free(name_buf);
            hm->msg_name = NULL;
            if (*ctlp != NULL && *ctlp != stack_ctl) {
                free(*ctlp);
                *ctlp = NULL;
            }
            if (*iovp != NULL && *iovp != stack_iov) {
                free(*iovp);
                *iovp = NULL;
            }
            return -ENOMEM;
        }
        if (!dir_recv) {
            if (i686_copy_from_guest(ctx, hb, g.iov_base, g.iov_len) != 0) {
                free(hb);
                for (uint32_t j = 0U; j < i; j++) {
                    free((*iovp)[j].iov_base);
                }
                free(name_buf);
                hm->msg_name = NULL;
                if (*ctlp != NULL && *ctlp != stack_ctl) {
                    free(*ctlp);
                    *ctlp = NULL;
                }
                if (*iovp != NULL && *iovp != stack_iov) {
                    free(*iovp);
                    *iovp = NULL;
                }
                return -EFAULT;
            }
        }
        (*iovp)[i].iov_base = hb;
        (*iovp)[i].iov_len  = (size_t)g.iov_len;
    }
    hm->msg_iov    = (gm->msg_iovlen != 0U) ? *iovp : NULL;
    hm->msg_iovlen = (size_t)gm->msg_iovlen;
    /* name_buf ownership moves to hm->msg_name; caller frees it. */
    return 0;
}

/* I686-R5-4: release everything msghdr_build staged on success. */
static void msghdr_free(struct msghdr *hm, struct iovec *hiov,
                        struct iovec *stack_iov, uint32_t iovcnt,
                        uint8_t *hctl, uint8_t *stack_ctl)
{
    if (hiov != NULL) {
        msg_free_payloads(hiov, iovcnt);
        if (hiov != stack_iov) {
            free(hiov);
        }
    }
    free(hm->msg_name);
    hm->msg_name = NULL;
    if (hctl != NULL && hctl != stack_ctl) {
        free(hctl);
    }
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
        return (int64_t)rc;
    }
    r = sendmsg((int)fd, &hm, (int)flags);
    if (r < 0) {
        r = -(int64_t)errno;
    }
    msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl, stack_ctl);
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
        return rc;
    }
    r = recvmsg((int)fd, &hm, (int)flags);
    if (r < 0) {
        rc = -(int)errno;
        msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl, stack_ctl);
        return (int64_t)rc;
    }
    /* I686-R5-4: copy payloads back to guest with checked copies. */
    {
        size_t rem = (size_t)r;
        for (uint32_t i = 0U; i < gm.msg_iovlen && rem > 0U; i++) {
            i686_iovec_t g;
            size_t       cp;
            if (i686_copy_from_guest(
                    ctx, &g, gm.msg_iov + i * (uint32_t)sizeof(g),
                    sizeof(g)) != 0) {
                rc = -EFAULT;
                msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl,
                            stack_ctl);
                return (int64_t)rc;
            }
            if (g.iov_len == 0U || hiov[i].iov_base == NULL) {
                continue;
            }
            cp = ((size_t)g.iov_len < rem) ? (size_t)g.iov_len : rem;
            if (cp != 0U &&
                i686_copy_to_guest(ctx, g.iov_base, hiov[i].iov_base, cp) !=
                    0) {
                rc = -EFAULT;
                msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl,
                            stack_ctl);
                return (int64_t)rc;
            }
            rem -= cp;
        }
    }
    {
        uint32_t gcap = gm.msg_controllen;
        uint32_t nlen_in =
            (gm.msg_name != 0U)
                ? ((gm.msg_namelen > I686_SOCKADDR_MAX)
                       ? I686_SOCKADDR_MAX
                       : gm.msg_namelen)
                : 0U;
        gm.msg_namelen    = (uint32_t)hm.msg_namelen;
        gm.msg_flags      = (uint32_t)hm.msg_flags;
        gm.msg_controllen = 0U;
        /* I686-R5-4: copy sockaddr back with a checked copy. */
        if (gm.msg_name != 0U && hm.msg_name != NULL && nlen_in != 0U) {
            uint32_t actual = (uint32_t)hm.msg_namelen;
            uint32_t cp     = (actual < nlen_in) ? actual : nlen_in;
            if (cp != 0U &&
                i686_copy_to_guest(ctx, gm.msg_name, hm.msg_name, cp) != 0) {
                rc = -EFAULT;
                msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl,
                            stack_ctl);
                return (int64_t)rc;
            }
        }
        if (hctl != NULL && gm.msg_control != 0U && gcap != 0U) {
            uint32_t glen = 0U;
            uint32_t addf = 0U;
            uint8_t *gout = (uint8_t *)malloc((gcap != 0U) ? gcap : 1U);
            if (gout == NULL) {
                rc = -ENOMEM;
                msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl,
                            stack_ctl);
                return (int64_t)rc;
            }
            i686_sock_cmsg64_to_32(hctl, hm.msg_controllen, gout, gcap,
                                   &glen, &addf, 1);
            if (glen != 0U &&
                i686_copy_to_guest(ctx, gm.msg_control, gout, glen) != 0) {
                free(gout);
                rc = -EFAULT;
                msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl,
                            stack_ctl);
                return (int64_t)rc;
            }
            free(gout);
            gm.msg_controllen = glen;
            gm.msg_flags |= addf;
        }
    }
    if (i686_copy_to_guest(ctx, msg_va, &gm, sizeof(gm)) != 0) {
        rc = -EFAULT;
        msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl, stack_ctl);
        return (int64_t)rc;
    }
    msghdr_free(&hm, hiov, stack_iov, gm.msg_iovlen, hctl, stack_ctl);
    return r;
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
        /* I686-R5-6: stop on msg_len write-back failure. */
        {
            uint32_t len32 = (uint32_t)r;
            if (i686_copy_to_guest(
                    ctx, va + (uint32_t)offsetof(i686_mmsghdr_t, msg_len),
                    &len32, sizeof(len32)) != 0) {
                return (n == 0U) ? (int64_t)-EFAULT : (int64_t)n;
            }
        }
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
    uint32_t        n    = 0U;
    int64_t         last = 0;

    if (timeout_va != 0U) {
        int64_t sec;
        int64_t nsec;
        if (time64) {
            uint8_t raw[16];
            uint32_t lo, hi, nlo, nhi;
            if (!va_ok(timeout_va, sizeof(raw)) ||
                i686_copy_from_guest(ctx, raw, timeout_va, sizeof(raw)) != 0) {
                return -EFAULT;
            }
            /* I686-R5-9: unsigned shifts, no signed left-shift UB. */
            lo  = guest_le32(raw);
            hi  = guest_le32(raw + 4U);
            nlo = guest_le32(raw + 8U);
            nhi = guest_le32(raw + 12U);
            sec  = (int64_t)(((uint64_t)hi << 32) | (uint64_t)lo);
            nsec = (int64_t)(((uint64_t)nhi << 32) | (uint64_t)nlo);
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
        /* I686-R5-9: reject negative tv_sec. */
        if (sec < 0) {
            return -EINVAL;
        }
        {
            struct timespec now;
            int64_t         add_sec;
            int64_t         sum_sec;
            long            sum_nsec;
            (void)clock_gettime(CLOCK_MONOTONIC, &now);
            /* I686-R5-9: overflow-checked deadline addition. */
            add_sec  = sec;
            sum_nsec = now.tv_nsec + (long)nsec;
            if (sum_nsec >= 1000000000L) {
                sum_nsec -= 1000000000L;
                if (add_sec == INT64_MAX) {
                    return -EINVAL;
                }
                add_sec++;
            }
            if (add_sec > INT64_MAX - (int64_t)now.tv_sec) {
                deadline.tv_sec  = INT64_MAX;
                deadline.tv_nsec = 999999999L;
            } else {
                sum_sec          = (int64_t)now.tv_sec + add_sec;
                deadline.tv_sec  = (time_t)sum_sec;
                deadline.tv_nsec = sum_nsec;
            }
        }
        have_deadline = 1;
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
    /* I686-R5-7: poll with the remaining timeout; never mutate shared
     * socket state via SO_RCVTIMEO. */
    for (uint32_t i = 0U; i < vlen; i++) {
        uint32_t va = vec_va + i * (uint32_t)sizeof(i686_mmsghdr_t);
        uint32_t fl = flags & ~I686_MSG_WAITFORONE;
        int64_t  r;

        if (i > 0U && (flags & I686_MSG_WAITFORONE) != 0U) {
            fl |= (uint32_t)MSG_DONTWAIT;
        } else if (have_deadline) {
            struct timespec now;
            int64_t         rem_s;
            int64_t         rem_ns;
            int64_t         rem_ms;
            struct pollfd   pfd;
            int             prc;
            (void)clock_gettime(CLOCK_MONOTONIC, &now);
            rem_s  = (int64_t)(deadline.tv_sec - now.tv_sec);
            rem_ns = (int64_t)(deadline.tv_nsec - now.tv_nsec);
            if (rem_ns < 0) {
                rem_ns += 1000000000LL;
                rem_s--;
            }
            if (rem_s < 0) {
                fl |= (uint32_t)MSG_DONTWAIT;
            } else {
                rem_ms = rem_s * 1000LL + rem_ns / 1000000LL;
                if (rem_ms > (int64_t)INT_MAX) {
                    rem_ms = (int64_t)INT_MAX;
                }
                pfd.fd      = (int)fd;
                pfd.events  = POLLIN;
                pfd.revents = 0;
                prc         = poll(&pfd, 1, (int)rem_ms);
                if (prc < 0) {
                    int e = errno;
                    if (e == EINTR) {
                        last = -(int64_t)EINTR;
                        break;
                    }
                    last = -(int64_t)e;
                    break;
                }
                if (prc == 0) {
                    fl |= (uint32_t)MSG_DONTWAIT;
                } else {
                    fl |= (uint32_t)MSG_DONTWAIT;
                }
            }
        }
        r = i686_sock_recvmsg(ctx, fd, va, fl);
        if (r < 0) {
            last = r;
            break;
        }
        /* I686-R5-6: stop on msg_len write-back failure. */
        {
            uint32_t len32 = (uint32_t)r;
            if (i686_copy_to_guest(
                    ctx, va + (uint32_t)offsetof(i686_mmsghdr_t, msg_len),
                    &len32, sizeof(len32)) != 0) {
                if (n == 0U) {
                    last = -(int64_t)EFAULT;
                }
                break;
            }
        }
        n++;
    }
    if (n == 0U) {
        return last;
    }
    return (int64_t)n;
}
