/*
 * src/os/marshal.c — guest copy helpers + syscall registry core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include "marshal.h"

#define I686_SYS_MAX 480U

static i686_sys_fn s_sys[I686_SYS_MAX];

/* EFAULT sentinel copied from the i386 table build. */
#define I686_EFAULT 14

int i686_copy_from_guest(i686_ctx_t *ctx, void *dst, uint32_t va, size_t len)
{
    if (len == 0U) {
        return 0;
    }
    if ((uint64_t)va + (uint64_t)len > 0x100000000ULL) {
        return -I686_EFAULT;
    }
    memcpy(dst, i686_guest_ptr(ctx, va), len);
    return 0;
}

int i686_copy_to_guest(i686_ctx_t *ctx, uint32_t va, const void *src, size_t len)
{
    if (len == 0U) {
        return 0;
    }
    if ((uint64_t)va + (uint64_t)len > 0x100000000ULL) {
        return -I686_EFAULT;
    }
    memcpy(i686_guest_ptr(ctx, va), src, len);
    return 0;
}

int i686_fetch_cstr(i686_ctx_t *ctx, uint32_t va, char *buf, size_t buflen)
{
    size_t i;

    if (buflen == 0U) {
        return -I686_EFAULT;
    }
    for (i = 0U; i < buflen; i++) {
        const char *p = (const char *)i686_guest_ptr(ctx, va + (uint32_t)i);
        buf[i] = *p;
        if (*p == '\0') {
            return 0;
        }
    }
    buf[buflen - 1U] = '\0';
    return -I686_EFAULT; /* unterminated within buflen */
}

void i686_sys_register(long nr, i686_sys_fn fn)
{
    if (nr >= 0 && (unsigned long)nr < I686_SYS_MAX) {
        s_sys[nr] = fn;
    }
}

int64_t i686_sys_dispatch(i686_ctx_t *ctx, long nr)
{
    if (nr < 0 || (unsigned long)nr >= I686_SYS_MAX || s_sys[nr] == NULL) {
        return -38; /* -ENOSYS */
    }
    return s_sys[nr](ctx);
}
