/*
 * src/os/vdso.h — frozen synthetic i386 vDSO interface (SPEC D12, E07)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The vDSO is a tiny ELF32 shared object (L2g builds it) with real
 * DT_VERDEF/DT_VERSYM: LINUX_2.5 = __kernel_vsyscall (= e_entry),
 * __kernel_sigreturn, __kernel_rt_sigreturn; LINUX_2.6 =
 * __vdso_clock_gettime, __vdso_clock_gettime64, __vdso_gettimeofday,
 * __vdso_time, __vdso_clock_getres.  Bodies v1: int $0x80 sequences
 * (correct, not fast).  L2h points AT_SYSINFO/AT_SYSINFO_EHDR at it.
 */

#ifndef I686RT_OS_VDSO_H
#define I686RT_OS_VDSO_H

#include <stdint.h>

#include "i686rt.h"

/* Map the embedded vDSO image into the guest window (page-aligned,
 * recorded as a region named "[vdso]").  Returns the guest base or 0 on
 * failure.  Idempotent: second call returns the same base. */
uint32_t i686_vdso_map(i686_ctx_t *ctx);

/* Guest address of __kernel_vsyscall inside the mapped image (AT_SYSINFO),
 * or 0 when unmapped. */
uint32_t i686_vdso_vsyscall_addr(const i686_ctx_t *ctx);

#endif /* I686RT_OS_VDSO_H */
