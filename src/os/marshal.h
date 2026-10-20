/*
 * src/os/marshal.h — frozen guest copy/marshal helper API (SPEC §3.4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * All copies are bounds-safe: va+len must stay inside the 4 GiB window
 * (natural u32 wrap rejected) — EFAULT otherwise.  Implemented in
 * src/os/marshal.c (coordinator-owned core; lanes add converters in
 * their own sys_*.c files).
 */

#ifndef I686RT_OS_MARSHAL_H
#define I686RT_OS_MARSHAL_H

#include <stddef.h>
#include <stdint.h>

#include "i686rt.h"

/* Returns 0 on success, -EFAULT (as negative errno int) on failure. */
int i686_copy_from_guest(i686_ctx_t *ctx, void *dst, uint32_t va, size_t len);
int i686_copy_to_guest(i686_ctx_t *ctx, uint32_t va, const void *src, size_t len);

/* NUL-terminated string fetch; -EFAULT when unmapped or not terminated
 * within buflen-1.  Always NUL-terminates buf on success. */
int i686_fetch_cstr(i686_ctx_t *ctx, uint32_t va, char *buf, size_t buflen);

/* Syscall handler registry: lanes register in i686_syscalls_<mod>_init. */
typedef int64_t (*i686_sys_fn)(i686_ctx_t *ctx);
void    i686_sys_register(long nr, i686_sys_fn fn);
int64_t i686_sys_dispatch(i686_ctx_t *ctx, long nr);

/* One-shot init of every module (defined in syscalls.c). */
void i686_syscalls_init_once(void);

/* Per-module registration (defined by the marshal lanes). */
void i686_syscalls_stat_init(void);
void i686_syscalls_sock_init(void);
void i686_syscalls_ipc_init(void);
void i686_syscalls_time_init(void);
void i686_syscalls_misc_init(void);
void i686_syscalls_pass_init(void);

#endif /* I686RT_OS_MARSHAL_H */
