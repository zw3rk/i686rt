/*
 * src/os/threads.h — frozen clone/TLS + TSO contract (SPEC §3.6, D5, D8)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * clone(120) i386 ABI: clone(flags, newsp, parent_tidptr, tls, child_tidptr)
 * from EBX,ECX,EDX,ESI,EDI where `tls` is a struct user_desc* when
 * CLONE_SETTLS is set (E09: entry_number=-1 auto-alloc also required).
 *
 * TSO policy (D5 rev 3): STATIC GPR-TSO from process start — no
 * thread-triggered re-translation. The interpreter is inherently
 * ordered (C single-threaded per guest thread); the DBT v1 runs
 * single-threaded guest code in a single host thread per process (host
 * fork for processes; guest pthreads = host threads is Phase H).
 *
 * Lanes must not edit this file.
 */

#ifndef I686RT_OS_THREADS_H
#define I686RT_OS_THREADS_H

#include <stdint.h>

#include "i686rt.h"
#include "os/structs_i386.h" /* i686_user_desc_t */

/* Clone flags we honor (kernel values, i386 == generic). */
#define I686_CLONE_VM 0x00000100U
#define I686_CLONE_FS 0x00000200U
#define I686_CLONE_FILES 0x00000400U
#define I686_CLONE_SIGHAND 0x00000800U
#define I686_CLONE_THREAD 0x00010000U
#define I686_CLONE_SYSVSEM 0x00040000U
#define I686_CLONE_SETTLS 0x00080000U
#define I686_CLONE_PARENT_SETTID 0x00100000U
#define I686_CLONE_CHILD_CLEARTID 0x00200000U
#define I686_CLONE_DETACHED 0x00400000U
#define I686_CLONE_CHILD_SETTID 0x01000000U
#define I686_CLONE_PARENT 0x00008000U
#define I686_CLONE_VFORK 0x00004000U

typedef struct i686_thread_start {
    i686_ctx_t *ctx;         /* private copy for the child               */
    uint32_t   child_eip;    /* resume point (insn after clone)          */
    uint32_t   child_esp;    /* newsp                                    */
    int        (*entry)(struct i686_thread_start *);
} i686_thread_start_t;

/* Install a user_desc as the child's GS base (CLONE_SETTLS). Handles
 * entry_number == -1 auto-alloc. Returns selector or -errno. */
int i686_tls_install(i686_ctx_t *ctx, uint32_t ud_va);

/* Registered by the coordinator (src/os/clone.c). */
void i686_threads_init(void);
void i686_threads_main_init(i686_ctx_t *ctx);
i686_ctx_t *i686_current_ctx(void);

#endif /* I686RT_OS_THREADS_H */
