/*
 * src/rt32/rt32_vm_internal.h — Internal guest VMA manager declarations
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_RT32_VM_INTERNAL_H
#define I686RT_RT32_VM_INTERNAL_H

#include "rt32.h"
#include "vm/vm32.h"
#include "vm/vm_file.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define RT32_WINDOW_SIZE         0x100000000ULL
#define RT32_MMAP_BASE_32        0x40000000U
#define RT32_MMAP_TOP_32         0xDF000000U
#define RT32_MAP_FIXED           0x10U
#define RT32_MAP_ANONYMOUS       0x20U
#define RT32_MAP_FIXED_NOREPLACE 0x100000U
#define RT32_MREMAP_MAYMOVE      1U
#define RT32_MREMAP_FIXED        2U

extern uint32_t g_vm_mmap_cursor;

static inline uint64_t rt32_page_align_up(uint64_t v)
{
    return (v + 0xFFFULL) & ~0xFFFULL;
}

#ifdef I686RT_NO_DBT
static inline void rt32_vm_invalidate_jit(i686_ctx_t *ctx, uint32_t start,
                                          uint32_t end)
{
    (void)ctx;
    (void)start;
    (void)end;
}
#else
extern void i686_dbt_invalidate_range(i686_ctx_t *ctx, uint32_t start,
                                      uint32_t end);
static inline void rt32_vm_invalidate_jit(i686_ctx_t *ctx, uint32_t start,
                                          uint32_t end)
{
    i686_dbt_invalidate_range(ctx, start, end);
}
#endif

void rt32_vm_lock_acquire(void);
void rt32_vm_lock_release(void);
void rt32_vm_sync_from_ctx(i686_ctx_t *ctx);
void rt32_vm_sync_to_ctx(i686_ctx_t *ctx);
int rt32_vm_reserve_prot_none(i686_ctx_t *ctx, uint32_t start, uint32_t len);
void rt32_vm_union_protect_a2(i686_ctx_t *ctx, uint32_t start, uint32_t end);
bool rt32_vm_a2_staged_needed(const i686_ctx_t *ctx, uint32_t va, uint64_t len,
                              uint32_t flags, uint64_t file_off);
int rt32_vm_mmap2_staged_a2_locked(i686_ctx_t *ctx, uint32_t target_va,
                                   uint32_t len, int fd, uint64_t file_off,
                                   bool is_anon, bool is_shared);
void rt32_vm_file_sync_prot_locked(uint32_t start, uint32_t end);
void rt32_vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end);
int rt32_vm_record_region_locked(uint32_t start, uint32_t end, uint32_t prot,
                                 uint32_t flags, const char *name);
void rt32_vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end,
                                     uint32_t prot);
bool rt32_vm_range_overlaps_locked(uint32_t start, uint32_t end);
bool rt32_vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                       uint32_t *out_prot, uint32_t *out_flags,
                                       char *out_name, size_t name_sz);
int rt32_vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va);

#endif /* I686RT_RT32_VM_INTERNAL_H */
