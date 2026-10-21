/*
 * src/rt32/rt32.h — Interfaces of the vendored a32rt ISA-agnostic core
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first vendoring from the read-only a32rt reference at commit
 * d84feb3 (SPEC D13): mechanical renames a32_→rt32_, A32_→RT32_,
 * `#include "a32rt.h"` → this header / `i686rt.h`, all code retyped on the
 * frozen `i686_ctx_t` from src/i686rt.h.  a32h_* / A32H_* handshake symbols
 * are untouched (include/a32host.h is byte-identical, D14).
 *
 * Per-file a32rt origins (commit d84feb3):
 *   rt32_vm.c         ← a32rt/src/vm.c      (window init, regions, brk,
 *                      mmap2/mremap/munmap/mprotect, gap finder — kept
 *                      functionally intact)
 *   rt32_elf32.c      ← a32rt/src/elf32.c   (ELF32 loader, PT_INTERP via
 *                      sysroot; EM_386; kuser setup dropped — Phase 2 vDSO)
 *   rt32_stack32.c    ← a32rt/src/stack32.c (initial stack; auxv rewritten
 *                      for i386 in Phase 2)
 *   rt32_host.c       ← a32rt/src/host.c    (/dev/a32host probe)
 *   rt32_a64_emit.c/.h ← a32rt/src/a64_emit.c/.h (host-side AArch64
 *                      encoder reused by the Phase 3 DBT; prototypes live
 *                      in rt32_a64_emit.h)
 *
 * Environment variables read by this code (a32rt names mapped to I686RT_*):
 *   I686RT_WINDOW — requested guest window base G for rt32_vm_init
 *                   (rt32_vm.c; was A32RT_WINDOW)
 *   I686RT_HOST   — set to "none" to skip the /dev/a32host probe
 *                   (rt32_host.c; was A32RT_HOST)
 */

#ifndef RT32_H
#define RT32_H

#include "i686rt.h"

/* Host handshake (rt32_host.c) */
void rt32_host_probe(i686_ctx_t *ctx);

/* Guest window & memory management (rt32_vm.c) */
int      rt32_vm_init(i686_ctx_t *ctx, uint64_t requested_window);
int      rt32_vm_record_region(i686_ctx_t *ctx, uint32_t start, uint32_t end,
                              uint32_t prot, uint32_t flags, const char *name);
uint32_t rt32_vm_brk(i686_ctx_t *ctx, uint32_t new_brk);
void rt32_vm_reset_for_exec(i686_ctx_t *ctx);
uint32_t rt32_vm_mmap2(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                       uint32_t flags, int fd, uint32_t pgoffset);
int      rt32_vm_mprotect(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot);
int      rt32_vm_munmap(i686_ctx_t *ctx, uint32_t addr, uint32_t len);
uint32_t rt32_vm_mremap(i686_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                        uint32_t new_len, uint32_t flags, uint32_t new_addr);
void     rt32_vm_sync_ctx(i686_ctx_t *ctx);

/* ELF32 loader & initial stack (rt32_elf32.c, rt32_stack32.c) */
typedef struct rt32_elf_info {
    uint32_t entry;
    uint32_t phdr_vaddr;
    uint32_t phent;
    uint32_t phnum;
    uint32_t load_bias;
    uint32_t max_vaddr;
    uint32_t interp_base;
    uint32_t text_start;
    uint32_t text_end;
    char     interp_path[256];
} rt32_elf_info_t;

int rt32_open_guest_ro(const i686_ctx_t *ctx, const char *guest_path);
int rt32_elf_load(i686_ctx_t *ctx, int exec_fd, const char *path,
                  rt32_elf_info_t *out_info);
/* a32rt's a32_kuser_setup() was dropped: the ARM kuser helper page is
 * replaced by the synthetic i386 vDSO in Phase 2 (SPEC D12). */
int rt32_stack_setup(i686_ctx_t *ctx, const rt32_elf_info_t *elf_info,
                     int guest_argc, char **guest_argv, char **host_envp,
                     uint32_t *out_sp);

#endif /* RT32_H */
