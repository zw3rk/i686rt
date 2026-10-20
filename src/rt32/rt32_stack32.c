/*
 * src/rt32/rt32_stack32.c — 32-bit initial stack, argv, envp, and auxv builder
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from a32rt/src/stack32.c @ d84feb3 (D13): renamed a32_→rt32_,
 * retyped on i686_ctx_t.  auxv contents are still ARM-flavored and are
 * rewritten for i386 in Phase 2 (SPEC D12).
 */

#define _GNU_SOURCE
#include "rt32.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <unistd.h>

#define RT32_STACK_TOP  0xE0000000U
#define RT32_STACK_SIZE (8U * 1024U * 1024U)

/* Standard Linux ELF auxiliary vector types */
#define AT_NULL         0U
#define AT_PHDR         3U
#define AT_PHENT        4U
#define AT_PHNUM        5U
#define AT_PAGESZ       6U
#define AT_BASE         7U
#define AT_FLAGS        8U
#define AT_ENTRY        9U
#define AT_UID          11U
#define AT_EUID         12U
#define AT_GID          13U
#define AT_EGID         14U
#define AT_PLATFORM     15U
#define AT_HWCAP        16U
#define AT_CLKTCK       17U
#define AT_SECURE       23U
#define AT_RANDOM       25U
#define AT_HWCAP2       26U
#define AT_EXECFN       31U

/* ARMv7 / ARMv8 AArch32 HWCAP bits */
#define ARM_HWCAP_HALF      (1U << 1)
#define ARM_HWCAP_THUMB     (1U << 2)
#define ARM_HWCAP_FAST_MULT (1U << 4)
#define ARM_HWCAP_VFP       (1U << 6)
#define ARM_HWCAP_EDSP      (1U << 7)
#define ARM_HWCAP_NEON      (1U << 12)
#define ARM_HWCAP_VFPv3     (1U << 13)
#define ARM_HWCAP_TLS       (1U << 15)
#define ARM_HWCAP_VFPv4     (1U << 16)
#define ARM_HWCAP_IDIVA     (1U << 17)
#define ARM_HWCAP_IDIVT     (1U << 18)
#define ARM_HWCAP_VFPD32    (1U << 19)
#define ARM_HWCAP_LPAE      (1U << 20)

/* ARMv8 AArch32 HWCAP2 bits */
#define ARM_HWCAP2_AES      (1U << 0)
#define ARM_HWCAP2_PMULL    (1U << 1)
#define ARM_HWCAP2_SHA1     (1U << 2)
#define ARM_HWCAP2_SHA2     (1U << 3)
#define ARM_HWCAP2_CRC32    (1U << 4)

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
    uint32_t at_platform_va = push_cstring(ctx, &sp, "v8l");
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

    uint32_t hwcap = ARM_HWCAP_HALF | ARM_HWCAP_THUMB | ARM_HWCAP_FAST_MULT |
                     ARM_HWCAP_VFP | ARM_HWCAP_EDSP | ARM_HWCAP_NEON |
                     ARM_HWCAP_VFPv3 | ARM_HWCAP_TLS | ARM_HWCAP_VFPv4 |
                     ARM_HWCAP_IDIVA | ARM_HWCAP_IDIVT | ARM_HWCAP_VFPD32 |
                     ARM_HWCAP_LPAE;
    uint32_t hwcap2 = ARM_HWCAP2_AES | ARM_HWCAP2_PMULL | ARM_HWCAP2_SHA1 |
                      ARM_HWCAP2_SHA2 | ARM_HWCAP2_CRC32;
    uint32_t auxv[40];
    size_t   aux_idx = 0;
#define PUSH_AUX(k, v) do { auxv[aux_idx++] = (k); auxv[aux_idx++] = (v); } while (0)
    PUSH_AUX(AT_PHDR,     elf_info->phdr_vaddr);
    PUSH_AUX(AT_PHENT,    elf_info->phent);
    PUSH_AUX(AT_PHNUM,    elf_info->phnum);
    PUSH_AUX(AT_PAGESZ,   I686_PAGE_SIZE);
    PUSH_AUX(AT_BASE,     elf_info->interp_base);
    PUSH_AUX(AT_FLAGS,    0U);
    PUSH_AUX(AT_ENTRY,    elf_info->entry);
    PUSH_AUX(AT_UID,      (uint32_t)getuid());
    PUSH_AUX(AT_EUID,     (uint32_t)geteuid());
    PUSH_AUX(AT_GID,      (uint32_t)getgid());
    PUSH_AUX(AT_EGID,     (uint32_t)getegid());
    PUSH_AUX(AT_PLATFORM, at_platform_va);
    PUSH_AUX(AT_HWCAP,    hwcap);
    PUSH_AUX(AT_CLKTCK,   100U);
    PUSH_AUX(AT_SECURE,   0U);
    PUSH_AUX(AT_RANDOM,   at_random_va);
    PUSH_AUX(AT_HWCAP2,   hwcap2);
    PUSH_AUX(AT_EXECFN,   at_execfn_va);
    PUSH_AUX(AT_NULL,     0U);
#undef PUSH_AUX

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
