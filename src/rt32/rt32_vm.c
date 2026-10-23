/*
 * src/rt32/rt32_vm.c — Guest 4 GiB window [G, G+4GiB) reservation and guest VMA manager
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from a32rt/src/vm.c @ d84feb3 (D13): renamed a32_→rt32_,
 * A32_→RT32_, retyped on i686_ctx_t; guest VA ceiling A32_KUSER_BASE_32 →
 * I686_TASK_SIZE_TOP (the ARM kuser page does not exist on i386, D12).
 */

#define _GNU_SOURCE
#include "rt32.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define RT32_WINDOW_SIZE         0x100000000ULL
#define RT32_MMAP_BASE_32        0x40000000U    /* Guest non-fixed mmap region base (1 GiB) */
#define RT32_MMAP_TOP_32         0xDF000000U    /* Below guest stack (0xE0000000) and the i386 ceiling (0xFFFFE000) */
#define RT32_MAP_FIXED           0x10U
#define RT32_MAP_ANONYMOUS       0x20U
#define RT32_MAP_FIXED_NOREPLACE 0x100000U
#define RT32_MREMAP_MAYMOVE      1U
#define RT32_MREMAP_FIXED        2U

static _Atomic uint32_t g_vm_lock = 0U;
static i686_ctx_t       *g_vm_root_ctx = NULL;
static uint32_t         g_vm_brk_base = 0U;
static uint32_t         g_vm_brk_curr = 0U;
static uint32_t         g_vm_mmap_cursor = RT32_MMAP_BASE_32;
static i686_region_t     g_vm_regions[I686_MAX_REGIONS];
static size_t           g_vm_region_count = 0U;

static inline void vm_lock_acquire(void)
{
    i686_spin_lock(&g_vm_lock);
}

static inline void vm_lock_release(void)
{
    i686_spin_unlock(&g_vm_lock);
}

static uint64_t page_align_up(uint64_t v)
{
    return (v + 0xFFFULL) & ~0xFFFULL;
}

static int vm_reserve_prot_none(i686_ctx_t *ctx, uint32_t start, uint32_t len)
{
    void *res = mmap(i686_guest_ptr(ctx, start), (size_t)len, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    return 0;
}

/* Translation-cache invalidation on guest mm ops (D11 SMC): real since
 * Phase H H1; the interpreter has no code cache (the call is cheap). */
extern void i686_dbt_invalidate_range(i686_ctx_t *ctx, uint32_t start,
                                      uint32_t end);
static inline void vm_invalidate_jit(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    i686_dbt_invalidate_range(ctx, start, end);
}

static void vm_sync_from_ctx(i686_ctx_t *ctx)
{
    if (ctx->brk_base != 0U && g_vm_brk_base != ctx->brk_base) {
        g_vm_brk_base = ctx->brk_base;
        g_vm_brk_curr = ctx->brk_curr;
    }
}

static void vm_sync_brk_to_ctx(i686_ctx_t *ctx)
{
    if (g_vm_brk_base != 0U) {
        ctx->brk_base = g_vm_brk_base;
        ctx->brk_curr = g_vm_brk_curr;
        if (g_vm_root_ctx != NULL && g_vm_root_ctx != ctx) {
            g_vm_root_ctx->brk_base = g_vm_brk_base;
            g_vm_root_ctx->brk_curr = g_vm_brk_curr;
        }
    }
}

static void vm_copy_state_to_ctx(i686_ctx_t *dst)
{
    if (g_vm_brk_base != 0U) {
        dst->brk_base = g_vm_brk_base;
        dst->brk_curr = g_vm_brk_curr;
    }
    size_t count = (g_vm_region_count <= I686_MAX_REGIONS) ? g_vm_region_count : I686_MAX_REGIONS;
    dst->mmap_cursor  = g_vm_mmap_cursor;
    dst->region_count = count;
    if (count > 0U) {
        memcpy(dst->regions, g_vm_regions, count * sizeof(i686_region_t));
    }
}

static void vm_sync_to_ctx(i686_ctx_t *ctx)
{
    vm_copy_state_to_ctx(ctx);
    if (g_vm_root_ctx != NULL && g_vm_root_ctx != ctx) {
        vm_copy_state_to_ctx(g_vm_root_ctx);
    }
}

static void vm_remove_region_at(size_t idx)
{
    if (idx >= g_vm_region_count) {
        return;
    }
    if (idx + 1U < g_vm_region_count) {
        memmove(&g_vm_regions[idx], &g_vm_regions[idx + 1U],
                (g_vm_region_count - idx - 1U) * sizeof(i686_region_t));
    }
    g_vm_region_count--;
}

static int vm_insert_region_raw(uint32_t start, uint32_t end,
                                uint32_t prot, uint32_t flags, const char *name)
{
    if (start >= end || g_vm_region_count >= I686_MAX_REGIONS) {
        return -1;
    }
    size_t pos = 0U;
    while (pos < g_vm_region_count && g_vm_regions[pos].start < start) {
        pos++;
    }
    if (pos < g_vm_region_count) {
        memmove(&g_vm_regions[pos + 1U], &g_vm_regions[pos],
                (g_vm_region_count - pos) * sizeof(i686_region_t));
    }
    g_vm_region_count++;
    i686_region_t *r = &g_vm_regions[pos];
    r->start = start;
    r->end   = end;
    r->prot  = prot;
    r->flags = flags;
    if (name) {
        snprintf(r->name, sizeof(r->name), "%s", name);
    } else {
        r->name[0] = '\0';
    }
    return 0;
}

static void vm_coalesce_regions_locked(void)
{
    if (g_vm_region_count < 2U) {
        return;
    }
    size_t dst = 0U;
    for (size_t src = 1U; src < g_vm_region_count; src++) {
        i686_region_t *prev = &g_vm_regions[dst];
        const i686_region_t *curr = &g_vm_regions[src];
        if (prev->end == curr->start && prev->prot == curr->prot &&
            prev->flags == curr->flags && strcmp(prev->name, curr->name) == 0) {
            prev->end = curr->end;
        } else {
            dst++;
            if (dst != src) {
                g_vm_regions[dst] = *curr;
            }
        }
    }
    g_vm_region_count = dst + 1U;
}

static void vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end)
{
    size_t i = 0U;
    while (i < g_vm_region_count) {
        i686_region_t *r = &g_vm_regions[i];
        if (r->end <= unmap_start || r->start >= unmap_end) {
            i++;
            continue;
        }
        if (r->start >= unmap_start && r->end <= unmap_end) {
            vm_remove_region_at(i);
            continue;
        }
        if (r->start < unmap_start && r->end > unmap_end) {
            if (g_vm_region_count + 1U >= I686_MAX_REGIONS) {
                size_t before = g_vm_region_count;
                vm_coalesce_regions_locked();
                if (g_vm_region_count != before) {
                    i = 0U;
                    continue;
                }
            }
            i686_region_t orig = *r;
            if (vm_insert_region_raw(unmap_end, orig.end,
                                     orig.prot, orig.flags, orig.name) == 0) {
                g_vm_regions[i].end = unmap_start;
                i += 2U;
            } else {
                i++;
            }
            continue;
        }
        if (r->start < unmap_start) {
            r->end = unmap_start;
        } else {
            r->start = unmap_end;
        }
        i++;
    }
}

static int vm_record_region_locked(uint32_t start, uint32_t end,
                                   uint32_t prot, uint32_t flags, const char *name)
{
    if (start >= end) {
        return -1;
    }
    char name_copy[64];
    if (name) {
        snprintf(name_copy, sizeof(name_copy), "%s", name);
    } else {
        name_copy[0] = '\0';
    }
    uint32_t clean_flags = flags & ~(RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE);
    vm_unmap_regions_locked(start, end);
    int rc = vm_insert_region_raw(start, end, prot, clean_flags, name_copy);
    if (rc < 0) {
        vm_coalesce_regions_locked();
        rc = vm_insert_region_raw(start, end, prot, clean_flags, name_copy);
    }
    vm_coalesce_regions_locked();
    return rc;
}

static void vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot)
{
    size_t i = 0U;
    while (i < g_vm_region_count) {
        i686_region_t *r = &g_vm_regions[i];
        if (r->end <= mp_start || r->start >= mp_end) {
            i++;
            continue;
        }
        if (r->start >= mp_start && r->end <= mp_end) {
            r->prot = prot;
            i++;
            continue;
        }
        i686_region_t orig = *r;
        if (orig.start < mp_start && orig.end > mp_end) {
            if (g_vm_region_count + 2U <= I686_MAX_REGIONS) {
                r->end = mp_start;
                (void)vm_insert_region_raw(mp_start, mp_end, prot, orig.flags, orig.name);
                (void)vm_insert_region_raw(mp_end, orig.end, orig.prot, orig.flags, orig.name);
                i += 3U;
            } else {
                r->prot = prot;
                i++;
            }
        } else if (orig.start < mp_start) {
            if (vm_insert_region_raw(mp_start, orig.end, prot, orig.flags, orig.name) == 0) {
                g_vm_regions[i].end = mp_start;
                i += 2U;
            } else {
                r->prot = prot;
                i++;
            }
        } else {
            r->start = mp_end;
            if (vm_insert_region_raw(orig.start, mp_end, prot, orig.flags, orig.name) == 0) {
                i += 2U;
            } else {
                r->start = orig.start;
                r->prot  = prot;
                i++;
            }
        }
    }
    vm_coalesce_regions_locked();
}

static bool vm_range_overlaps_locked(uint32_t start, uint32_t end)
{
    for (size_t i = 0U; i < g_vm_region_count && g_vm_regions[i].start < end; i++) {
        if (g_vm_regions[i].end > start) {
            return true;
        }
    }
    return false;
}

static bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                         uint32_t *out_prot, uint32_t *out_flags,
                                         char *out_name, size_t name_sz)
{
    if (start >= end) {
        return false;
    }
    uint32_t cur = start;
    bool     first = true;
    uint32_t first_prot  = 0U;
    uint32_t first_flags = 0U;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const i686_region_t *r = &g_vm_regions[i];
        if (r->end <= cur) {
            continue;
        }
        if (r->start > cur) {
            return false;
        }
        if (first) {
            first_prot  = r->prot;
            first_flags = r->flags & 0x23U;
            if (out_prot) {
                *out_prot = r->prot;
            }
            if (out_flags) {
                *out_flags = r->flags;
            }
            if (out_name && name_sz > 0U) {
                snprintf(out_name, name_sz, "%s", r->name);
            }
            first = false;
        } else if ((out_prot != NULL && r->prot != first_prot) ||
                   (out_flags != NULL && (r->flags & 0x23U) != first_flags)) {
            return false;
        }
        if (r->end >= end) {
            return true;
        }
        cur = r->end;
    }
    return false;
}

static int vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va)
{
    if (aligned_len == 0ULL ||
        aligned_len > (uint64_t)(RT32_MMAP_TOP_32 - RT32_MMAP_BASE_32)) {
        return -1;
    }

    uint64_t cursor_cand = page_align_up((uint64_t)g_vm_mmap_cursor);
    if (cursor_cand < (uint64_t)RT32_MMAP_BASE_32) {
        cursor_cand = (uint64_t)RT32_MMAP_BASE_32;
    }
    if (cursor_cand + aligned_len <= (uint64_t)RT32_MMAP_TOP_32 &&
        !vm_range_overlaps_locked((uint32_t)cursor_cand, (uint32_t)(cursor_cand + aligned_len))) {
        *out_va = (uint32_t)cursor_cand;
        return 0;
    }

    uint64_t cand = (uint64_t)RT32_MMAP_BASE_32;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        uint64_t r_start = (uint64_t)g_vm_regions[i].start;
        uint64_t r_end   = page_align_up((uint64_t)g_vm_regions[i].end);
        if (r_end <= cand) {
            continue;
        }
        if (cand + aligned_len <= r_start) {
            break;
        }
        cand = r_end;
    }

    if (cand + aligned_len > (uint64_t)RT32_MMAP_TOP_32) {
        return -1;
    }

    *out_va = (uint32_t)cand;
    return 0;
}

static int try_reserve_window(uint64_t base)
{
    if ((base & (I686_PAGE_SIZE - 1ULL)) != 0ULL || base > UINT64_MAX - RT32_WINDOW_SIZE) {
        return -1;
    }

    uint64_t map_start = (base == 0ULL) ? (uint64_t)I686_LOW_GUARD_SIZE : base;
    uint64_t map_len   = (base == 0ULL) ? (RT32_WINDOW_SIZE - (uint64_t)I686_LOW_GUARD_SIZE)
                                        : RT32_WINDOW_SIZE;

    void *res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (res == MAP_FAILED && (errno == EINVAL || errno == EOPNOTSUPP)) {
        res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (res == MAP_FAILED) {
        return -1;
    }
    if ((uint64_t)(uintptr_t)res != map_start) {
        munmap(res, (size_t)map_len);
        return -1;
    }
    return 0;
}

int rt32_vm_init(i686_ctx_t *ctx, uint64_t requested_window)
{
    if (!ctx) {
        return -1;
    }

    uint64_t base = requested_window;
    bool     has_explicit = (requested_window != UINT64_MAX);

    if (!has_explicit) {
        const char *env_win = getenv("I686RT_WINDOW");
        if (env_win && env_win[0] != '\0') {
            char *endp = NULL;
            errno = 0;
            unsigned long long val = strtoull(env_win, &endp, 0);
            if (strchr(env_win, '-') != NULL || errno == ERANGE || !endp ||
                endp == env_win || *endp != '\0' || (uint64_t)val == UINT64_MAX) {
                fprintf(stderr, "i686rt: invalid I686RT_WINDOW '%s'\n", env_win);
                return -1;
            }
            base = (uint64_t)val;
            has_explicit = true;
        }
    }

    if (has_explicit) {
        if (try_reserve_window(base) != 0) {
            fprintf(stderr, "i686rt: failed to reserve guest window at 0x%llx\n",
                    (unsigned long long)base);
            return -1;
        }
        ctx->guest_base = base;
    } else if (ctx->has_host_info && ctx->host_info.window_hint != 0ULL &&
               try_reserve_window(ctx->host_info.window_hint) == 0) {
        ctx->guest_base = ctx->host_info.window_hint;
    } else {
        /* Try G = 0 first; if occupied, scan 4 GiB-aligned windows [4G, 64G). */
        if (try_reserve_window(0ULL) == 0) {
            ctx->guest_base = 0ULL;
        } else {
            bool found = false;
            for (uint64_t cand = 0x100000000ULL; cand < 0x1000000000ULL; cand += 0x100000000ULL) {
                if (try_reserve_window(cand) == 0) {
                    ctx->guest_base = cand;
                    found = true;
                    break;
                }
            }
            if (!found) {
                fprintf(stderr, "i686rt: unable to find free 4 GiB guest window\n");
                return -1;
            }
        }
    }

    vm_lock_acquire();
    g_vm_root_ctx     = ctx;
    g_vm_brk_base     = 0U;
    g_vm_brk_curr     = 0U;
    g_vm_mmap_cursor  = RT32_MMAP_BASE_32;
    g_vm_region_count = 0U;
    ctx->mmap_cursor  = RT32_MMAP_BASE_32;
    ctx->region_count = 0U;
    vm_lock_release();
    return 0;
}

int rt32_vm_record_region(i686_ctx_t *ctx, uint32_t start, uint32_t end,
                         uint32_t prot, uint32_t flags, const char *name)
{
    if (!ctx || start >= end) {
        return -1;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_record_region_locked(start, end, prot, flags, name);
    vm_sync_to_ctx(ctx);
    vm_lock_release();
    return rc;
}


/* Exec teardown: drop every region except the vdso from the AUTHORITATIVE
 * global list (ctx->regions is a mirror; vm_sync_from_ctx never copies it
 * back, so a ctx-only clear is undone by the next vm_sync_to_ctx). */
void rt32_vm_reset_for_exec(i686_ctx_t *ctx)
{
    vm_lock_acquire();
    size_t w = 0U;
    for (size_t r = 0U; r < g_vm_region_count; r++) {
        if (strcmp(g_vm_regions[r].name, "[vdso]") == 0) {
            g_vm_regions[w] = g_vm_regions[r];
            w++;
        }
    }
    g_vm_region_count = w;
    g_vm_brk_base  = 0U;
    g_vm_brk_curr  = 0U;
    g_vm_mmap_cursor = RT32_MMAP_BASE_32;
    vm_lock_release();

    /* Kernel exec semantics (RC7b T4b): execve destroys ALL old address
     * space.  Only the region bookkeeping was cleared above, so the
     * stale host mappings of the previous image (in a posix_spawn fork
     * child: the wineserver's whole COW-inherited address space) stayed
     * resident in the window — later ld.so/NTDLL allocations then
     * collided with foreign leftover data (foreign TCBs, foreign code),
     * which killed the boot with NULL-call threads and "could not load
     * kernel32.dll".  Tear the window down; the next stack setup re-maps
     * the vDSO and the stack, and the new image loads fresh pages. */
    (void)munmap((void *)(uintptr_t)I686_LOW_GUARD_SIZE,
                 (size_t)(RT32_WINDOW_SIZE - (uint64_t)I686_LOW_GUARD_SIZE));

    /* Mirror the cleared state into the caller's ctx.  vdso_base must
     * clear too: i686_vdso_map is idempotent on it, and a fork child
     * would otherwise skip the re-map and run without the vDSO page. */
    ctx->brk_base    = 0U;
    ctx->brk_curr    = 0U;
    ctx->mmap_cursor = RT32_MMAP_BASE_32;
    ctx->vdso_base   = 0U;
    ctx->region_count = (w <= I686_MAX_REGIONS) ? w : I686_MAX_REGIONS;
    if (ctx->region_count > 0U) {
        memcpy(ctx->regions, g_vm_regions, ctx->region_count * sizeof(i686_region_t));
    }
}

uint32_t rt32_vm_brk(i686_ctx_t *ctx, uint32_t new_brk)
{
    if (!ctx) {
        return 0U;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);

    uint32_t brk_limit = (g_vm_brk_base < RT32_MMAP_BASE_32) ? RT32_MMAP_BASE_32 : RT32_MMAP_TOP_32;
    if (new_brk == 0U || new_brk < g_vm_brk_base || new_brk > brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        vm_lock_release();
        return curr;
    }

    uint64_t old_page64 = page_align_up((uint64_t)g_vm_brk_curr);
    uint64_t new_page64 = page_align_up((uint64_t)new_brk);
    if (new_page64 > (uint64_t)brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        vm_lock_release();
        return curr;
    }

    uint32_t old_page = (uint32_t)old_page64;
    uint32_t new_page = (uint32_t)new_page64;

    if (new_page > old_page) {
        if (vm_range_overlaps_locked(old_page, new_page)) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        uint32_t len = new_page - old_page;
        void *host_addr = i686_guest_ptr(ctx, old_page);
        void *res = mmap(host_addr, len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (res == MAP_FAILED) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        (void)vm_record_region_locked(old_page, new_page,
                                      (uint32_t)(PROT_READ | PROT_WRITE), 0x22U, "[heap]");
    } else if (new_page < old_page) {
        uint32_t len = old_page - new_page;
        /* Re-reserve shrunk brk pages with PROT_NONE inside the guest window */
        (void)vm_reserve_prot_none(ctx, new_page, len);
        vm_unmap_regions_locked(new_page, old_page);
    }

    g_vm_brk_curr = new_brk;
    if (new_page != old_page) {
        vm_sync_to_ctx(ctx);
    } else {
        vm_sync_brk_to_ctx(ctx);
    }
    vm_lock_release();

    if (new_page < old_page) {
        vm_invalidate_jit(ctx, new_page, old_page);
    }
    return new_brk;
}

static uint32_t vm_mmap2_locked(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                                uint32_t flags, int fd, uint32_t pgoffset)
{
    if (!ctx || len == 0U || (flags & 0x03U) == 0U || (flags & 0x03U) == 0x03U) {
        return (uint32_t)(-EINVAL);
    }

    uint64_t aligned_len = page_align_up((uint64_t)len);
    if (aligned_len == 0ULL || aligned_len > (uint64_t)I686_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    int host_flags = 0;
    if (flags & 0x01U) {
        host_flags |= MAP_SHARED;
    }
    if (flags & 0x02U) {
        host_flags |= MAP_PRIVATE;
    }
    if (flags & RT32_MAP_ANONYMOUS) {
        host_flags |= MAP_ANONYMOUS;
    }

    uint32_t target_va     = 0U;
    bool     update_cursor = false;
    if ((flags & (RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE)) != 0U) {
        if ((addr & (I686_PAGE_SIZE - 1U)) != 0U || addr < I686_LOW_GUARD_SIZE) {
            return (uint32_t)(-EINVAL);
        }
        if ((uint64_t)addr + aligned_len > (uint64_t)I686_TASK_SIZE_TOP) {
            return (uint32_t)(-ENOMEM);
        }
        if ((flags & RT32_MAP_FIXED_NOREPLACE) != 0U &&
            vm_range_overlaps_locked(addr, (uint32_t)((uint64_t)addr + aligned_len))) {
            return (uint32_t)(-EEXIST);
        }
        target_va = addr;
    } else {
        uint32_t hint_va = i686_page_down(addr);
        if (addr != 0U &&
            hint_va >= RT32_MMAP_BASE_32 &&
            (uint64_t)hint_va + aligned_len <= (uint64_t)RT32_MMAP_TOP_32 &&
            !vm_range_overlaps_locked(hint_va, (uint32_t)((uint64_t)hint_va + aligned_len))) {
            target_va = hint_va;
        } else if (vm_find_free_gap_locked(aligned_len, &target_va) != 0) {
            return (uint32_t)(-ENOMEM);
        } else {
            update_cursor = true;
        }
    }

    int   host_prot   = i686_host_prot(ctx, prot);
    void *host_target = i686_guest_ptr(ctx, target_va);
    off_t host_off    = (off_t)pgoffset * (off_t)I686_PAGE_SIZE;
    void *res = mmap(host_target, (size_t)aligned_len, host_prot,
                     host_flags | MAP_FIXED, (host_flags & MAP_ANONYMOUS) ? -1 : fd,
                     (host_flags & MAP_ANONYMOUS) ? 0 : host_off);
    if (res == MAP_FAILED) {
        return (uint32_t)(-errno);
    }

    if (update_cursor) {
        g_vm_mmap_cursor = (uint32_t)((uint64_t)target_va + aligned_len);
    }
    (void)vm_record_region_locked(target_va, (uint32_t)((uint64_t)target_va + aligned_len),
                                  prot & 0x7U, flags, "[mmap]");
    return target_va;
}

uint32_t rt32_vm_mmap2(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                      uint32_t flags, int fd, uint32_t pgoffset)
{
    if (!ctx) {
        return (uint32_t)(-EINVAL);
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    uint32_t res = vm_mmap2_locked(ctx, addr, len, prot, flags, fd, pgoffset);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (res <= 0xFFFFF000U &&
        ((flags & (RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE)) != 0U ||
         (prot & (uint32_t)PROT_EXEC) != 0U)) {
        vm_invalidate_jit(ctx, res, (uint32_t)((uint64_t)res + page_align_up((uint64_t)len)));
    }

    /* a32rt's AOT cache preload (a32_aot_load_fd) was dropped: i686rt has no
     * AOT pre-translator (the DBT compiles lazily, Phase 3). */

    return res;
}

static int vm_mprotect_locked(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    if (!ctx || (addr & (I686_PAGE_SIZE - 1U)) != 0U || addr < 0x1000U || (prot & ~0x7U) != 0U) {
        return -EINVAL;
    }
    if (len == 0U) {
        return 0;
    }
    uint64_t aligned_len = page_align_up((uint64_t)len);
    uint64_t end64       = (uint64_t)addr + aligned_len;
    if (addr < I686_LOW_GUARD_SIZE ||
        aligned_len == 0ULL ||
        end64 > (uint64_t)I686_TASK_SIZE_TOP ||
        !vm_check_mapped_range_locked(addr, (uint32_t)end64, NULL, NULL, NULL, 0U)) {
        return -ENOMEM;
    }

    if (mprotect(i686_guest_ptr(ctx, addr), (size_t)aligned_len, i686_host_prot(ctx, prot)) != 0) {
        return -errno;
    }

    vm_mprotect_regions_locked(addr, (uint32_t)end64, prot & 0x7U);
    return 0;
}

int rt32_vm_mprotect(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    if (!ctx) {
        return -EINVAL;
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_mprotect_locked(ctx, addr, len, prot);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (rc == 0 && len > 0U) {
        vm_invalidate_jit(ctx, addr, (uint32_t)((uint64_t)addr + page_align_up((uint64_t)len)));
    }
    return rc;
}

static int vm_munmap_locked(i686_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    if (!ctx || (addr & (I686_PAGE_SIZE - 1U)) != 0U || len == 0U) {
        return -EINVAL;
    }
    uint64_t aligned_len = page_align_up((uint64_t)len);
    if (addr < I686_LOW_GUARD_SIZE ||
        (uint64_t)addr + aligned_len > (uint64_t)I686_TASK_SIZE_TOP) {
        return -EINVAL;
    }

    uint32_t start = i686_page_down(addr);
    /* Keep the [G, G+4GiB) reservation intact by replacing unmapped pages with PROT_NONE */
    int rc = vm_reserve_prot_none(ctx, start, (uint32_t)aligned_len);
    if (rc != 0) {
        return rc;
    }

    uint32_t end = (uint32_t)((uint64_t)start + aligned_len);
    vm_unmap_regions_locked(start, end);
    if (g_vm_mmap_cursor == end && start >= RT32_MMAP_BASE_32) {
        g_vm_mmap_cursor = start;
    }
    return 0;
}

int rt32_vm_munmap(i686_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    if (!ctx) {
        return -EINVAL;
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_munmap_locked(ctx, addr, len);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (rc == 0) {
        vm_invalidate_jit(ctx, addr, (uint32_t)((uint64_t)addr + page_align_up((uint64_t)len)));
    }
    return rc;
}

uint32_t rt32_vm_mremap(i686_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                       uint32_t new_len, uint32_t flags, uint32_t new_addr)
{
    if (!ctx || (old_addr & (I686_PAGE_SIZE - 1U)) != 0U ||
        old_len == 0U || new_len == 0U) {
        return (uint32_t)(-EINVAL);
    }
    if ((flags & ~(RT32_MREMAP_MAYMOVE | RT32_MREMAP_FIXED)) != 0U ||
        ((flags & RT32_MREMAP_FIXED) != 0U && (flags & RT32_MREMAP_MAYMOVE) == 0U)) {
        return (uint32_t)(-EINVAL);
    }

    uint64_t old_aligned = page_align_up((uint64_t)old_len);
    uint64_t new_aligned = page_align_up((uint64_t)new_len);
    if (old_addr < I686_LOW_GUARD_SIZE ||
        (uint64_t)old_addr + old_aligned > (uint64_t)I686_TASK_SIZE_TOP) {
        return (uint32_t)(-EINVAL);
    }
    if (new_aligned == 0ULL || new_aligned > (uint64_t)I686_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);

    uint32_t prot       = 0x3U;
    uint32_t orig_flags = 0x22U;
    char     orig_name[64];
    orig_name[0] = '\0';
    if (!vm_check_mapped_range_locked(old_addr, (uint32_t)((uint64_t)old_addr + old_aligned),
                                      &prot, &orig_flags, orig_name, sizeof(orig_name))) {
        vm_sync_to_ctx(ctx);
        vm_lock_release();
        return (uint32_t)(-EFAULT);
    }
    uint32_t    keep_flags  = orig_flags & 0x23U;
    uint32_t    map_flags   = (((keep_flags & 0x01U) != 0U) ? 0x01U : 0x02U) | RT32_MAP_ANONYMOUS;
    const char *region_name = (orig_name[0] != '\0') ? orig_name : "[mmap]";

    if ((flags & RT32_MREMAP_FIXED) == 0U) {
        if (new_aligned == old_aligned) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return old_addr;
        }
        if (new_aligned < old_aligned) {
            uint32_t unmap_addr = old_addr + (uint32_t)new_aligned;
            uint32_t unmap_len  = (uint32_t)(old_aligned - new_aligned);
            int rc = vm_munmap_locked(ctx, unmap_addr, unmap_len);
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            if (rc != 0) {
                return (uint32_t)rc;
            }
            vm_invalidate_jit(ctx, unmap_addr, unmap_addr + unmap_len);
            return old_addr;
        }

        uint32_t old_end = (uint32_t)((uint64_t)old_addr + old_aligned);
        uint64_t new_end = (uint64_t)old_addr + new_aligned;
        if (new_end <= (uint64_t)I686_TASK_SIZE_TOP &&
            !vm_range_overlaps_locked(old_end, (uint32_t)new_end)) {
            uint32_t ext = vm_mmap2_locked(ctx, old_end, (uint32_t)(new_aligned - old_aligned),
                                           prot, map_flags | RT32_MAP_FIXED, -1, 0U);
            if (ext <= 0xFFFFF000U) {
                (void)vm_record_region_locked(old_end, (uint32_t)new_end,
                                              prot, keep_flags, region_name);
                uint32_t ext_end = (uint32_t)new_end;
                if (g_vm_mmap_cursor >= old_addr && g_vm_mmap_cursor < ext_end &&
                    ext_end <= RT32_MMAP_TOP_32) {
                    g_vm_mmap_cursor = ext_end;
                }
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                if ((prot & (uint32_t)PROT_EXEC) != 0U) {
                    vm_invalidate_jit(ctx, old_end, ext_end);
                }
                return old_addr;
            }
        }

        if ((flags & RT32_MREMAP_MAYMOVE) == 0U) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return (uint32_t)(-ENOMEM);
        }
    } else {
        if ((new_addr & (I686_PAGE_SIZE - 1U)) != 0U || new_addr < I686_LOW_GUARD_SIZE ||
            (uint64_t)new_addr + new_aligned > (uint64_t)I686_TASK_SIZE_TOP ||
            ((uint64_t)new_addr < (uint64_t)old_addr + old_aligned &&
             (uint64_t)old_addr < (uint64_t)new_addr + new_aligned)) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return (uint32_t)(-EINVAL);
        }
    }

    bool     is_fixed = (flags & RT32_MREMAP_FIXED) != 0U;
    uint32_t rw_prot  = (prot & ~((uint32_t)PROT_EXEC)) | (uint32_t)(PROT_READ | PROT_WRITE);
    uint32_t new_va   = vm_mmap2_locked(ctx, is_fixed ? new_addr : 0U, (uint32_t)new_aligned,
                                        rw_prot, map_flags | (is_fixed ? RT32_MAP_FIXED : 0U),
                                        -1, 0U);
    if (new_va > 0xFFFFF000U) {
        vm_sync_to_ctx(ctx);
        vm_lock_release();
        return new_va;
    }

    if ((prot & 0x1U) == 0U) {
        (void)mprotect(i686_guest_ptr(ctx, old_addr), (size_t)old_aligned, PROT_READ);
    }
    size_t copy_bytes = (size_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
    memcpy(i686_guest_ptr(ctx, new_va), i686_guest_ptr(ctx, old_addr), copy_bytes);
    if (prot != 0x3U) {
        (void)vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned, prot);
    }
    (void)vm_record_region_locked(new_va, (uint32_t)((uint64_t)new_va + new_aligned),
                                  prot, keep_flags, region_name);
    (void)vm_munmap_locked(ctx, old_addr, (uint32_t)old_aligned);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    vm_invalidate_jit(ctx, old_addr, (uint32_t)((uint64_t)old_addr + old_aligned));
    if (is_fixed || (prot & (uint32_t)PROT_EXEC) != 0U) {
        vm_invalidate_jit(ctx, new_va, (uint32_t)((uint64_t)new_va + new_aligned));
    }
    return new_va;
}

void rt32_vm_sync_ctx(i686_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    vm_sync_to_ctx(ctx);
    vm_lock_release();
}
