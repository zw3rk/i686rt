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
 * sys_pass.c (DEFECTS.md C1a/C1b lane split).  Empty until C1b lands.
 */

#include "os/marshal.h"

void i686_syscalls_thread_init(void)
{
    /* C1b registers its handlers here. */
}
