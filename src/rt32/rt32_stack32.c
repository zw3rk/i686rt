/*
 * src/rt32/rt32_stack32.c — 32-bit initial stack, argv, envp, and auxv builder
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from a32rt/src/stack32.c @ d84feb3 (D13): renamed a32_→rt32_,
 * retyped on i686_ctx_t.  The auxv section was rewritten for i386 in
 * Phase 2 (SPEC D12, E07): the table itself is built by
 * i686_auxv_build_i386() in src/os/proc.c (shared definition, L2h).
 */

#define _GNU_SOURCE
#include "rt32.h"

#include "os/proc.h"
#include "os/vdso.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

#define RT32_STACK_TOP  0xE0000000U
#define RT32_STACK_SIZE (8U * 1024U * 1024U)

static uint32_t push_bytes(i686_ctx_t *ctx, uint32_t *sp, const void *data, size_t len)
{
    if (*sp < ctx->stack_base || len > (size_t)(*sp - ctx->stack_base)) {
        return 0U;
    }
    *sp -= (uint32_t)len;
    memcpy(i686_guest_ptr(ctx, *sp), data, len);
    return *sp;
}

static uint32_t push_cstring(i686_ctx_t *ctx, uint32_t *sp, const char *s)
{
    size_t len = strlen(s) + 1U;
    return push_bytes(ctx, sp, s, len);
}

static int push_string_table(i686_ctx_t *ctx, uint32_t *sp, char **strs,
                             int max_count, uint32_t *out_ptrs, int *out_count)
{
    int count = 0;
    if (strs) {
        while (count < max_count && count < 511 && strs[count] != NULL) {
            count++;
        }
        for (int i = count - 1; i >= 0; i--) {
            out_ptrs[i] = push_cstring(ctx, sp, strs[i]);
            if (out_ptrs[i] == 0U) {
                return -1;
            }
        }
    }
    *out_count = count;
    return 0;
}

int rt32_stack_setup(i686_ctx_t *ctx, const rt32_elf_info_t *elf_info,
                    int guest_argc, char **guest_argv, char **host_envp,
                    uint32_t *out_sp)
{
    if (!ctx || !elf_info || !out_sp || guest_argc < 1 || !guest_argv || !guest_argv[0]) {
        return -1;
    }

    /* Map the synthetic i386 vDSO FIRST (SPEC D12, E07): the AT_SYSINFO /
     * AT_SYSINFO_EHDR entries below need live addresses.  i686_vdso_map
     * is idempotent and records the "[vdso]" window region; when mapping
     * fails it returns 0, we emit no vDSO entries, and glibc falls back
     * to its own int $0x80 trampoline (E07) — never fatal. */
    uint32_t vdso_mapped = i686_vdso_map(ctx);

    uint32_t stack_base = RT32_STACK_TOP - RT32_STACK_SIZE;
    void *host_stack = i686_guest_ptr(ctx, stack_base);
    void *res = mmap(host_stack, RT32_STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        fprintf(stderr, "i686rt: failed to map guest stack: %s\n", strerror(errno));
        return -1;
    }
    ctx->stack_top  = RT32_STACK_TOP;
    ctx->stack_base = stack_base;
    rt32_vm_record_region(ctx, stack_base, RT32_STACK_TOP,
                         (uint32_t)(PROT_READ | PROT_WRITE), 0x12U, "[stack]");

    uint32_t sp = RT32_STACK_TOP - 64U;

    uint8_t rand_bytes[16];
    if (getrandom(rand_bytes, sizeof(rand_bytes), 0) != (ssize_t)sizeof(rand_bytes)) {
        for (size_t i = 0; i < sizeof(rand_bytes); i++) {
            rand_bytes[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 17U));
        }
    }
    uint32_t at_random_va   = push_bytes(ctx, &sp, rand_bytes, sizeof(rand_bytes));
    uint32_t at_platform_va = push_cstring(ctx, &sp, "i686");
    const char *execfn_str  = (ctx->exec_path && ctx->exec_path[0]) ? ctx->exec_path : guest_argv[0];
    uint32_t at_execfn_va   = push_cstring(ctx, &sp, execfn_str);
    if (at_random_va == 0U || at_platform_va == 0U || at_execfn_va == 0U) {
        return -1;
    }

    uint32_t env_ptrs[512];
    uint32_t arg_ptrs[512];
    int envc = 0;
    int argc = 0;
    if (push_string_table(ctx, &sp, host_envp, 511, env_ptrs, &envc) != 0 ||
        push_string_table(ctx, &sp, guest_argv, guest_argc, arg_ptrs, &argc) != 0) {
        return -1;
    }

    sp &= ~0xFU;

    /* i386 auxv (SPEC D12, E07): i686_auxv_build_i386 emits the pinned
     * entry order with AT_HWCAP = the D10 CPUID.1.EDX mask and the
     * vDSO pair only when the mapping above succeeded. */
    uint32_t at_sysinfo      = 0U;
    uint32_t at_sysinfo_ehdr = 0U;
    if (vdso_mapped != 0U) {
        at_sysinfo_ehdr = ctx->vdso_base;             /* set by i686_vdso_map */
        at_sysinfo      = i686_vdso_vsyscall_addr(ctx);
    }
    {
        /* RC7b T4b forensics: what the auxv carries for the vDSO pair. */
        extern int i686_sigtrace_on(void);
        if (i686_sigtrace_on()) {
            (void)fprintf(stderr,
                          "AUXV vdso_mapped=%08x ehdr=%08x sysinfo=%08x\n",
                          vdso_mapped, at_sysinfo_ehdr, at_sysinfo);

        }
    }

    i686_auxv_i386_args_t aux_args;
    memset(&aux_args, 0, sizeof(aux_args));
    aux_args.phdr_vaddr     = elf_info->phdr_vaddr;
    aux_args.phent          = elf_info->phent; /* elf32_phdr_t is 32 bytes */
    aux_args.phnum          = elf_info->phnum;
    aux_args.interp_base    = elf_info->interp_base;
    aux_args.entry          = elf_info->entry;
    aux_args.at_random_va   = at_random_va;
    aux_args.at_platform_va = at_platform_va;
    aux_args.at_execfn_va   = at_execfn_va;
    aux_args.vdso_base      = at_sysinfo_ehdr;
    aux_args.vsyscall_addr  = at_sysinfo;

    uint32_t auxv[I686_AUXV_I386_MAX_WORDS];
    size_t   aux_idx = i686_auxv_build_i386(&aux_args, auxv,
                                            I686_AUXV_I386_MAX_WORDS);
    if (aux_idx == 0U) {
        return -1;
    }
    {
        /* RC7b T4b forensics: the full auxv as the guest will see it. */
        extern int i686_sigtrace_on(void);
        if (i686_sigtrace_on()) {
            size_t ai;

            for (ai = 0U; ai + 1U < aux_idx; ai += 2U) {
                (void)fprintf(stderr, "AX %08x %08x\n",
                              auxv[ai], auxv[ai + 1U]);
            }
        }
    }

    /* Frame layout: argc, argv[0..argc-1], NULL, envp[0..envc-1], NULL, auxv[] (16B-aligned) */
    size_t total_words   = 1U + ((size_t)argc + 1U) + ((size_t)envc + 1U) + aux_idx;
    uint32_t frame_bytes = (uint32_t)(total_words * sizeof(uint32_t));
    if (sp < ctx->stack_base || (sp - ctx->stack_base) < frame_bytes + 16U) {
        return -1;
    }
    uint32_t final_sp = (sp - frame_bytes) & ~0xFU;

    uint32_t *w = (uint32_t *)i686_guest_ptr(ctx, final_sp);
    size_t pos = 0;
    w[pos++] = (uint32_t)argc;
    memcpy(&w[pos], arg_ptrs, (size_t)argc * sizeof(uint32_t));
    pos += (size_t)argc;
    w[pos++] = 0U;
    memcpy(&w[pos], env_ptrs, (size_t)envc * sizeof(uint32_t));
    pos += (size_t)envc;
    w[pos++] = 0U;
    memcpy(&w[pos], auxv, aux_idx * sizeof(uint32_t));

    ctx->guest_argc = argc;
    ctx->guest_argv = guest_argv;
    ctx->host_envp  = host_envp;

    size_t copy_words = aux_idx;
    if (copy_words > (sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]))) {
        copy_words = sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]);
    }
    memcpy(ctx->auxv_data, auxv, copy_words * sizeof(uint32_t));
    ctx->auxv_bytes = copy_words * sizeof(uint32_t);

    *out_sp = final_sp;
    return 0;
}
