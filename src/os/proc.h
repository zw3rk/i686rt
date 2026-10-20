/*
 * src/os/proc.h — /proc virtualization + shared i386 auxv builder (L2h)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Two consumers share this header:
 *   - src/rt32/rt32_stack32.c builds the initial auxv via
 *     i686_auxv_build_i386() (SPEC D12, E07), and
 *   - src/os/proc.c serves /proc/self/{exe,cmdline,maps,auxv},
 *     /proc/version and /proc/cpuinfo via i686_proc_open_at(); the open
 *     path in sys_pass.c wires that in at S2 (documented hook).
 * Hosting the builder here keeps one definition of the D12 auxv contract
 * and makes it unit-testable without linking the rt32 stack (L2h check).
 */

#ifndef I686RT_OS_PROC_H
#define I686RT_OS_PROC_H

#include <stddef.h>
#include <stdint.h>

#include "i686rt.h"

/* ---- ELF auxiliary vector keys (values mirror <elf.h>; namespaced) ---- */
#define I686_AT_NULL         0U
#define I686_AT_PHDR         3U
#define I686_AT_PHENT        4U
#define I686_AT_PHNUM        5U
#define I686_AT_PAGESZ       6U
#define I686_AT_BASE         7U
#define I686_AT_FLAGS        8U
#define I686_AT_ENTRY        9U
#define I686_AT_UID          11U
#define I686_AT_EUID         12U
#define I686_AT_GID          13U
#define I686_AT_EGID         14U
#define I686_AT_PLATFORM     15U
#define I686_AT_HWCAP        16U
#define I686_AT_CLKTCK       17U
#define I686_AT_SECURE       23U
#define I686_AT_RANDOM       25U
#define I686_AT_EXECFN       31U
#define I686_AT_SYSINFO      32U /* i386: __kernel_vsyscall addr (E07)   */
#define I686_AT_SYSINFO_EHDR 33U /* i386: vDSO base (E07)                */

/* ---- CPUID.1.EDX feature mask advertised to the guest (SPEC D10) ------
 * D10 pins the deterministic v1 feature set: FPU, TSC, CX8, CMOV, MMX,
 * FXSR, SSE, SSE2 — no SSE3+.  Bit positions are the CPUID.1.EDX bit
 * numbers, which is also what an i386 kernel would report in AT_HWCAP. */
#define I686_CPUID1_EDX_FPU  (1U << 0)
#define I686_CPUID1_EDX_TSC  (1U << 4)
#define I686_CPUID1_EDX_CX8  (1U << 8)
#define I686_CPUID1_EDX_CMOV (1U << 15)
#define I686_CPUID1_EDX_MMX  (1U << 23)
#define I686_CPUID1_EDX_FXSR (1U << 24)
#define I686_CPUID1_EDX_SSE  (1U << 25)
#define I686_CPUID1_EDX_SSE2 (1U << 26)

/* AT_HWCAP value = 0x07808111 (D10 mask, computed). */
#define I686_HWCAP_I386                                                       \
    (I686_CPUID1_EDX_FPU | I686_CPUID1_EDX_TSC | I686_CPUID1_EDX_CX8 |        \
     I686_CPUID1_EDX_CMOV | I686_CPUID1_EDX_MMX | I686_CPUID1_EDX_FXSR |      \
     I686_CPUID1_EDX_SSE | I686_CPUID1_EDX_SSE2)

/* /proc/cpuinfo flags line — keep in CPUID.1.EDX bit order (D10). */
#define I686_CPUID_FLAGS_STR "fpu tsc cx8 cmov mmx fxsr sse sse2"

/* ---- i386 initial auxv builder (SPEC D12, E07) -------------------------
 * Emits, as u32 key/value pairs in exactly this order: AT_PHDR, AT_PHENT
 * (56 for ELF32), AT_PHNUM, AT_PAGESZ (4096), AT_BASE, AT_FLAGS (0),
 * AT_ENTRY, AT_UID, AT_EUID, AT_GID, AT_EGID, AT_SECURE (0), AT_RANDOM,
 * AT_HWCAP (I686_HWCAP_I386), AT_CLKTCK (100), AT_PLATFORM, AT_SYSINFO
 * (only when vsyscall_addr != 0), AT_SYSINFO_EHDR (only when vdso_base !=
 * 0), AT_EXECFN, AT_NULL.  When the vDSO could not be mapped both vdso
 * entries are omitted and glibc falls back to int $0x80 (E07). */
#define I686_AUXV_I386_MAX_WORDS 48U /* 24 entries; current maximum is 40 */

typedef struct i686_auxv_i386_args {
    uint32_t phdr_vaddr;     /* AT_PHDR                                  */
    uint32_t phent;          /* AT_PHENT (sizeof(Elf32_Phdr) == 56)      */
    uint32_t phnum;          /* AT_PHNUM                                 */
    uint32_t interp_base;    /* AT_BASE (PT_INTERP load base, 0 if none) */
    uint32_t entry;          /* AT_ENTRY                                 */
    uint32_t at_random_va;   /* AT_RANDOM (16 bytes on the guest stack)  */
    uint32_t at_platform_va; /* AT_PLATFORM ("i686\0" on the guest stack)*/
    uint32_t at_execfn_va;   /* AT_EXECFN (exec path string)             */
    uint32_t vdso_base;      /* AT_SYSINFO_EHDR when nonzero             */
    uint32_t vsyscall_addr;  /* AT_SYSINFO when nonzero                  */
} i686_auxv_i386_args_t;

/* Writes at most cap words into auxv; returns the number of u32 words
 * (including the terminating AT_NULL pair), or 0 when cap is too small
 * (needs at most I686_AUXV_I386_MAX_WORDS) or an argument is NULL. */
size_t i686_auxv_build_i386(const i686_auxv_i386_args_t *args, uint32_t *auxv,
                            size_t cap);

/* ---- /proc virtualization (a32rt try_open_virtual_proc pattern) --------
 * Hook for the open path in sys_pass.c (wired by the coordinator at S2):
 * call with the guest path BEFORE attempting the host open.  Returns an
 * fd (>= 0) backed by a memfd/temp file holding the synthesized content,
 * a negative -errno when a virtualized path exists but failed, or
 * I686_PROC_NOT_MATCHED when the path is not virtualized here and the
 * caller should fall through to the host filesystem. */
#define I686_PROC_NOT_MATCHED (-9999)

int i686_proc_open_at(i686_ctx_t *ctx, const char *guest_path);

/* Render helpers (also used by the unit check).  Both write at most cap
 * bytes, keep the result NUL-terminated when cap > 0, and return the
 * number of content bytes (excluding the terminator). */
size_t i686_proc_render_maps(const i686_ctx_t *ctx, char *buf, size_t cap);
size_t i686_proc_render_cmdline(const i686_ctx_t *ctx, char *buf, size_t cap);

/* Static content (release "6.1.0" matches sys_uname in syscalls.c). */
const char *i686_proc_version_str(void);
const char *i686_proc_cpuinfo_str(void);

#endif /* I686RT_OS_PROC_H */
