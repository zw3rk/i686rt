/*
 * src/rt32/rt32_vm.c — Guest 4 GiB window [G, G+4GiB) reservation and guest VMA manager
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from a32rt/src/vm.c @ d84feb3 (D13).
 */
#define _GNU_SOURCE
#include "rt32_vm_internal.h"
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
static _Atomic uint32_t g_vm_lock = 0U;
static _Atomic uint32_t g_vm_epoch = 1U;
static i686_ctx_t       *g_vm_root_ctx = NULL;
static uint32_t         g_vm_brk_base = 0U;
static uint32_t         g_vm_brk_curr = 0U;
uint32_t                g_vm_mmap_cursor = RT32_MMAP_BASE_32;
static i686_region_t    g_vm_regions[I686_MAX_REGIONS];
static size_t           g_vm_region_count = 0U;
static void vm_bump_epoch(void)
{
    uint32_t next = atomic_fetch_add_explicit(&g_vm_epoch, 1U,
                                              memory_order_acq_rel) + 1U;
    if (next == 0U) {
        atomic_fetch_add_explicit(&g_vm_epoch, 1U, memory_order_acq_rel);
    }
}

void rt32_vm_lock_acquire(void)
{
    i686_spin_lock(&g_vm_lock);
}

void rt32_vm_lock_release(void)
{
    i686_spin_unlock(&g_vm_lock);
}

void rt32_vm_fork_prepare(void) { i686_spin_lock(&g_vm_lock); }
void rt32_vm_fork_parent(void) { i686_spin_unlock(&g_vm_lock); }
void rt32_vm_fork_child(void)
{
    atomic_store_explicit(&g_vm_lock, 0U, memory_order_release);
}

int rt32_vm_reserve_prot_none(i686_ctx_t *ctx, uint32_t start, uint32_t len)
{
    /* A2: skip 4 KiB PROT_NONE host op to protect sub-page neighbours. */
    void *res;
    if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u) {
        return 0;
    }
    res = mmap(i686_guest_ptr(ctx, start), (size_t)len, PROT_NONE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    return 0;
}

bool rt32_vm_a2_staged_needed(const i686_ctx_t *ctx, uint32_t va,
                              uint64_t len, uint32_t flags,
                              uint64_t file_off)
{
    uint64_t h;
    if (ctx->vm_regime != I686_VM_REGIME_A2 || ctx->vm_host_page <= 4096u) {
        return false;
    }
    h = (uint64_t)ctx->vm_host_page;
    if ((((uint64_t)va & (h - 1u)) != 0u) || ((len & (h - 1u)) != 0u)) {
        return true;
    }
    return (flags & RT32_MAP_ANONYMOUS) == 0U &&
           ((file_off & (h - 1u)) != 0u);
}
static int vm_stage_shared_copy(i686_ctx_t *ctx, uint32_t va, size_t len,
                                int fd, uint64_t file_off)
{
    uint8_t *dst = (uint8_t *)i686_guest_ptr(ctx, va);
    size_t got = 0u;
    while (got < len) {
        ssize_t n = pread(fd, dst + got, len - got,
                          (off_t)(file_off + (uint64_t)got));
        if (n < 0) {
            int e = errno;
            if (e == EINTR) {
                continue;
            }
            memset(dst, 0, len);
            return -e;
        }
        if (n == 0) {
            break;
        }
        got += (size_t)n;
    }
    if (got < len) {
        memset(dst + got, 0, len - got);
    }
    return 0;
}

int rt32_vm_mmap2_staged_a2_locked(i686_ctx_t *ctx, uint32_t target_va,
                                   uint32_t len, int fd, uint64_t file_off,
                                   bool is_anon, bool is_shared)
{
    uint64_t h = (uint64_t)ctx->vm_host_page;
    uint64_t end = (uint64_t)target_va + (uint64_t)len;
    uint64_t cover_lo = (uint64_t)target_va & ~(h - 1u);
    uint64_t cover_hi = (end + h - 1u) & ~(h - 1u);
    void *cover = (void *)(uintptr_t)(ctx->guest_base + cover_lo);
    size_t cover_len = (size_t)(cover_hi - cover_lo);
    int rc;
    /* Caller holds VM lock + subpage lock (R3-2, VM outer). */
    if (mprotect(cover, cover_len, PROT_READ | PROT_WRITE) != 0) {
        return -errno;
    }
    if (is_anon) {
        memset(i686_guest_ptr(ctx, target_va), 0, len);
        i686_vm_file_set_state(target_va, len, 0u);
        return 0;
    }
    if (!is_shared) {
        rc = i686_vm_file_map_private(ctx->guest_base, target_va, len,
                                      fd, file_off);
    } else {
        rc = vm_stage_shared_copy(ctx, target_va, len, fd, file_off);
        if (rc == 0) {
            i686_vm_file_set_state(target_va, len, 0u);
        }
    }
    if (rc != 0) {
        (void)i686_vm32_widen_prot(ctx, target_va, (uint32_t)end);
    }
    return rc;
}

void rt32_vm_sync_from_ctx(i686_ctx_t *ctx)
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
    size_t count = (g_vm_region_count <= I686_MAX_REGIONS)
                       ? g_vm_region_count
                       : I686_MAX_REGIONS;
    dst->mmap_cursor  = g_vm_mmap_cursor;
    dst->region_count = count;
    dst->vm_reserved[0] = (uint64_t)atomic_load_explicit(&g_vm_epoch, memory_order_acquire);
    if (count > 0U) {
        memcpy(dst->regions, g_vm_regions, count * sizeof(i686_region_t));
    }
}

void rt32_vm_sync_to_ctx(i686_ctx_t *ctx)
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

void rt32_vm_file_sync_prot_locked(uint32_t start, uint32_t end)
{
    uint32_t cur = start;
    (void)i686_vm_file_init((g_vm_root_ctx != NULL) ? g_vm_root_ctx->guest_base
                                                    : 0ULL);
    while (cur < end) {
        bool hit = false;
        size_t i;
        for (i = 0U; i < g_vm_region_count; i++) {
            const i686_region_t *r = &g_vm_regions[i];
            if (r->start <= cur && r->end > cur) {
                uint32_t seg_end = (r->end < end) ? r->end : end;
                i686_vm_file_set_prot(cur, seg_end - cur,
                                      (uint8_t)(r->prot & 0x7U));
                i686_vm_file_flags_add(cur, seg_end - cur, 0x80u);
                cur = seg_end;
                hit = true;
                break;
            }
        }
        if (!hit) {
            uint32_t next = end;
            for (i = 0U; i < g_vm_region_count; i++) {
                if (g_vm_regions[i].start > cur &&
                    g_vm_regions[i].start < next) {
                    next = g_vm_regions[i].start;
                }
            }
            i686_vm_file_set_prot(cur, next - cur, 0U);
            i686_vm_file_flags_clear(cur, next - cur, 0x80u);
            cur = next;
        }
    }
    vm_bump_epoch();
}

void rt32_vm_union_protect_a2(i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    if (ctx == NULL || end <= start ||
        ctx->vm_regime != I686_VM_REGIME_A2) {
        return;
    }
    (void)i686_vm32_union_prot(ctx, start, end);
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

static bool vm_file_contiguous(uint32_t end_a, uint32_t start_b)
{
    int fd_a = -1;
    int fd_b = -1;
    uint64_t off_a = 0ULL;
    uint64_t off_b = 0ULL;
    uint8_t kind_a = 0U;
    uint8_t kind_b = 0U;
    if (end_a < I686_PAGE_SIZE || end_a != start_b) {
        return false;
    }
    if (i686_vm_file_lookup_map(end_a - I686_PAGE_SIZE, &fd_a, &off_a,
                                &kind_a) != 0 ||
        i686_vm_file_lookup_map(start_b, &fd_b, &off_b, &kind_b) != 0) {
        return false;
    }
    return (fd_a == fd_b) && (kind_a == kind_b) &&
           (off_a + (uint64_t)I686_PAGE_SIZE == off_b);
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
            prev->flags == curr->flags && strcmp(prev->name, curr->name) == 0 &&
            ((prev->flags & RT32_MAP_ANONYMOUS) != 0U ||
             vm_file_contiguous(prev->end, curr->start))) {
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
static int vm_unmap_final_count(uint32_t s, uint32_t e, size_t *out_final)
{
    size_t fully = 0U;
    size_t interior = 0U;
    size_t i;
    if (s >= e) {
        return -1;
    }
    for (i = 0U; i < g_vm_region_count; i++) {
        const i686_region_t *r = &g_vm_regions[i];
        if (r->end <= s || r->start >= e) {
            continue;
        }
        fully += (r->start >= s && r->end <= e) ? 1U : 0U;
        interior += (r->start < s && r->end > e) ? 1U : 0U;
    }
    if (g_vm_region_count < fully) {
        return -1;
    }
    *out_final = g_vm_region_count - fully + interior;
    return 0;
}
int rt32_vm_can_unmap_locked(uint32_t s, uint32_t e)
{
    size_t fin = 0U;
    return (vm_unmap_final_count(s, e, &fin) != 0 || fin > I686_MAX_REGIONS)
               ? -1
               : 0;
}
int rt32_vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end)
{
    size_t i = 0U;
    size_t fin = 0U;
    if (unmap_start >= unmap_end) {
        return -1;
    }
    if (vm_unmap_final_count(unmap_start, unmap_end, &fin) != 0 ||
        fin > I686_MAX_REGIONS) {
        return -1;
    }
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
            i686_region_t orig = *r;
            if (vm_insert_region_raw(unmap_end, orig.end,
                                     orig.prot, orig.flags, orig.name) == 0) {
                g_vm_regions[i].end = unmap_start;
                i += 2U;
            } else {
                return -1;
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
    return 0;
}
int rt32_vm_can_record_locked(uint32_t start, uint32_t end)
{
    size_t fin = 0U;
    if (start >= end || vm_unmap_final_count(start, end, &fin) != 0 ||
        fin + 1U > I686_MAX_REGIONS) {
        return -1;
    }
    return 0;
}
int rt32_vm_record_region_locked(uint32_t start, uint32_t end,
                                 uint32_t prot, uint32_t flags, const char *name)
{
    char name_copy[64];
    uint32_t clean_flags;
    int rc;
    if (start >= end) {
        return -1;
    }
    if (rt32_vm_can_record_locked(start, end) != 0) {
        return -1;
    }
    if (name) {
        snprintf(name_copy, sizeof(name_copy), "%s", name);
    } else {
        name_copy[0] = '\0';
    }
    clean_flags = flags & ~(RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE);
    if (rt32_vm_unmap_regions_locked(start, end) != 0) {
        return -1;
    }
    rc = vm_insert_region_raw(start, end, prot, clean_flags, name_copy);
    if (rc < 0) {
        return -1;
    }
    vm_coalesce_regions_locked();
    rt32_vm_file_sync_prot_locked(start, end);
    return rc;
}
static int vm_mprotect_final_count(uint32_t s, uint32_t e, size_t *out_final)
{
    size_t need = 0U;
    size_t i;
    if (s >= e) {
        return -1;
    }
    for (i = 0U; i < g_vm_region_count; i++) {
        const i686_region_t *r = &g_vm_regions[i];
        if (r->end <= s || r->start >= e || (r->start >= s && r->end <= e)) {
            continue;
        }
        need += (r->start < s && r->end > e) ? 2U : 1U;
    }
    *out_final = g_vm_region_count + need;
    return 0;
}
int rt32_vm_can_mprotect_locked(uint32_t s, uint32_t e)
{
    size_t fin = 0U;
    return (vm_mprotect_final_count(s, e, &fin) != 0 || fin > I686_MAX_REGIONS)
               ? -1
               : 0;
}
int rt32_vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end,
                                    uint32_t prot)
{
    size_t i = 0U;
    size_t fin = 0U;
    if (mp_start >= mp_end) {
        return -1;
    }
    if (vm_mprotect_final_count(mp_start, mp_end, &fin) != 0 ||
        fin > I686_MAX_REGIONS) {
        return -1;
    }
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
        {
            i686_region_t orig = *r;
            if (orig.start < mp_start && orig.end > mp_end) {
                r->end = mp_start;
                if (vm_insert_region_raw(mp_start, mp_end, prot, orig.flags,
                                         orig.name) != 0 ||
                    vm_insert_region_raw(mp_end, orig.end, orig.prot,
                                         orig.flags, orig.name) != 0) {
                    return -1;
                }
                i += 3U;
            } else if (orig.start < mp_start) {
                if (vm_insert_region_raw(mp_start, orig.end, prot, orig.flags,
                                         orig.name) != 0) {
                    return -1;
                }
                g_vm_regions[i].end = mp_start;
                i += 2U;
            } else {
                r->start = mp_end;
                if (vm_insert_region_raw(orig.start, mp_end, prot, orig.flags,
                                         orig.name) != 0) {
                    return -1;
                }
                i += 2U;
            }
        }
    }
    vm_coalesce_regions_locked();
    rt32_vm_file_sync_prot_locked(mp_start, mp_end);
    return 0;
}

bool rt32_vm_range_overlaps_locked(uint32_t start, uint32_t end)
{
    for (size_t i = 0U; i < g_vm_region_count && g_vm_regions[i].start < end; i++) {
        if (g_vm_regions[i].end > start) {
            return true;
        }
    }
    return false;
}

bool rt32_vm_check_mapped_range_locked(uint32_t start, uint32_t end,
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
                   (out_flags != NULL &&
                    ((r->flags & 0x23U) != first_flags ||
                     ((first_flags & RT32_MAP_ANONYMOUS) == 0U &&
                      !vm_file_contiguous(cur, r->start))))) {
            return false;
        }
        if (r->end >= end) {
            return true;
        }
        cur = r->end;
    }
    return false;
}

int rt32_vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va)
{
    if (aligned_len == 0ULL ||
        aligned_len > (uint64_t)(RT32_MMAP_TOP_32 - RT32_MMAP_BASE_32)) {
        return -1;
    }

    uint64_t cursor_cand = rt32_page_align_up((uint64_t)g_vm_mmap_cursor);
    if (cursor_cand < (uint64_t)RT32_MMAP_BASE_32) {
        cursor_cand = (uint64_t)RT32_MMAP_BASE_32;
    }
    if (cursor_cand + aligned_len <= (uint64_t)RT32_MMAP_TOP_32 &&
        !rt32_vm_range_overlaps_locked((uint32_t)cursor_cand,
                                       (uint32_t)(cursor_cand + aligned_len))) {
        *out_va = (uint32_t)cursor_cand;
        return 0;
    }

    uint64_t cand = (uint64_t)RT32_MMAP_BASE_32;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        uint64_t r_start = (uint64_t)g_vm_regions[i].start;
        uint64_t r_end   = rt32_page_align_up((uint64_t)g_vm_regions[i].end);
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
                void *res = mmap(NULL, (size_t)RT32_WINDOW_SIZE, PROT_NONE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (res != MAP_FAILED) {
                    ctx->guest_base = (uint64_t)(uintptr_t)res;
                    found = true;
                }
            }
            if (!found) {
                fprintf(stderr, "i686rt: unable to find free 4 GiB guest window\n");
                return -1;
            }
        }
    }

    rt32_vm_lock_acquire();
    g_vm_root_ctx     = ctx;
    g_vm_brk_base     = 0U;
    g_vm_brk_curr     = 0U;
    g_vm_mmap_cursor  = RT32_MMAP_BASE_32;
    g_vm_region_count = 0U;
    ctx->mmap_cursor  = RT32_MMAP_BASE_32;
    ctx->region_count = 0U;
    (void)i686_vm_file_init(ctx->guest_base);
    rt32_vm_file_sync_prot_locked(0U, 0x80000000U);
    rt32_vm_file_sync_prot_locked(0x80000000U, 0xFFFFF000U);
    i686_vm_file_set_prot(0xFFFFF000U, 0x1000U, 0U);
    i686_vm_file_flags_clear(0xFFFFF000U, 0x1000U, 0x80u);
    ctx->vm_reserved[0] = (uint64_t)atomic_load_explicit(&g_vm_epoch, memory_order_acquire);
    rt32_vm_lock_release();
    return 0;
}

int rt32_vm_record_region(i686_ctx_t *ctx, uint32_t start, uint32_t end,
                          uint32_t prot, uint32_t flags, const char *name)
{
    if (!ctx || start >= end) {
        return -1;
    }
    rt32_vm_lock_acquire();
    rt32_vm_sync_from_ctx(ctx);
    int rc = rt32_vm_record_region_locked(start, end, prot, flags, name);
    rt32_vm_sync_to_ctx(ctx);
    rt32_vm_lock_release();
    return rc;
}

void rt32_vm_reset_for_exec(i686_ctx_t *ctx)
{
    rt32_vm_lock_acquire();
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
    i686_vm_file_untrack_map(0U, 0xFFFFF000U);
    rt32_vm_file_sync_prot_locked(0U, 0x80000000U);
    rt32_vm_file_sync_prot_locked(0x80000000U, 0xFFFFF000U);
    i686_vm_file_set_prot(0xFFFFF000U, 0x1000U, 0U);
    i686_vm_file_flags_clear(0xFFFFF000U, 0x1000U, 0x80u);
    rt32_vm_lock_release();

    (void)munmap((void *)(uintptr_t)I686_LOW_GUARD_SIZE,
                 (size_t)(RT32_WINDOW_SIZE - (uint64_t)I686_LOW_GUARD_SIZE));

    ctx->brk_base    = 0U;
    ctx->brk_curr    = 0U;
    ctx->mmap_cursor = RT32_MMAP_BASE_32;
    ctx->vdso_base   = 0U;
    ctx->region_count = (w <= I686_MAX_REGIONS) ? w : I686_MAX_REGIONS;
    ctx->vm_reserved[0] = (uint64_t)atomic_load_explicit(&g_vm_epoch, memory_order_acquire);
    if (ctx->region_count > 0U) {
        memcpy(ctx->regions, g_vm_regions, ctx->region_count * sizeof(i686_region_t));
    }
}

uint32_t rt32_vm_brk(i686_ctx_t *ctx, uint32_t new_brk)
{
    if (!ctx) {
        return 0U;
    }
    rt32_vm_lock_acquire();
    rt32_vm_sync_from_ctx(ctx);

    uint32_t brk_limit = (g_vm_brk_base < RT32_MMAP_BASE_32)
                             ? RT32_MMAP_BASE_32
                             : RT32_MMAP_TOP_32;
    uint64_t old_page64;
    uint64_t new_page64;
    if (new_brk == 0U || new_brk < g_vm_brk_base || new_brk > brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        rt32_vm_lock_release();
        return curr;
    }
    old_page64 = rt32_page_align_up((uint64_t)g_vm_brk_curr);
    new_page64 = rt32_page_align_up((uint64_t)new_brk);
    if (new_page64 > (uint64_t)brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        rt32_vm_lock_release();
        return curr;
    }

    uint32_t old_page = (uint32_t)old_page64;
    uint32_t new_page = (uint32_t)new_page64;

    if (new_page > old_page) {
        uint32_t len;
        int staged;
        uint32_t curr;
        if (rt32_vm_range_overlaps_locked(old_page, new_page) ||
            rt32_vm_can_record_locked(old_page, new_page) != 0) {
            curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            rt32_vm_lock_release();
            return curr;
        }
        len = new_page - old_page;
        staged = rt32_vm_a2_staged_needed(ctx, old_page, len,
                                          RT32_MAP_ANONYMOUS, 0u) ? 1 : 0;
        if (staged) {
            i686_vm32_subpage_lock();
        }
        if (staged) {
            if (rt32_vm_mmap2_staged_a2_locked(ctx, old_page, len, -1, 0u,
                                               true, false) != 0) {
                i686_vm32_subpage_unlock();
                curr = g_vm_brk_curr;
                vm_sync_brk_to_ctx(ctx);
                rt32_vm_lock_release();
                return curr;
            }
        } else {
            void *host_addr = i686_guest_ptr(ctx, old_page);
            void *res = mmap(host_addr, len, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (res == MAP_FAILED) {
                curr = g_vm_brk_curr;
                vm_sync_brk_to_ctx(ctx);
                rt32_vm_lock_release();
                return curr;
            }
        }
        if (rt32_vm_record_region_locked(old_page, new_page,
                                         (uint32_t)(PROT_READ | PROT_WRITE),
                                         0x22U, "[heap]") != 0) {
            if (!staged) {
                (void)rt32_vm_reserve_prot_none(ctx, old_page, len);
            } else {
                (void)i686_vm32_widen_prot(ctx, old_page, new_page);
                i686_vm32_subpage_unlock();
            }
            curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            rt32_vm_lock_release();
            return curr;
        }
        rt32_vm_union_protect_a2(ctx, old_page, new_page);
        if (staged) {
            i686_vm32_subpage_unlock();
        }
    } else if (new_page < old_page) {
        uint32_t len = old_page - new_page;
        uint32_t curr;
        if (rt32_vm_can_unmap_locked(new_page, old_page) != 0) {
            curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            rt32_vm_lock_release();
            return curr;
        }
        (void)rt32_vm_reserve_prot_none(ctx, new_page, len);
        (void)rt32_vm_unmap_regions_locked(new_page, old_page);
        rt32_vm_file_sync_prot_locked(new_page, old_page);
        (void)i686_vm32_widen_prot(ctx, new_page, old_page);
    }

    g_vm_brk_curr = new_brk;
    if (new_page != old_page) {
        rt32_vm_sync_to_ctx(ctx);
    } else {
        vm_sync_brk_to_ctx(ctx);
    }
    rt32_vm_lock_release();

    if (new_page < old_page) {
        rt32_vm_invalidate_jit(ctx, new_page, old_page);
    }
    return new_brk;
}

void rt32_vm_sync_ctx(i686_ctx_t *ctx)
{
    if (!ctx) {
        return;
    }
    rt32_vm_lock_acquire();
    rt32_vm_sync_from_ctx(ctx);
    rt32_vm_sync_to_ctx(ctx);
    rt32_vm_lock_release();
}

void rt32_vm_sync_ctx_if_stale(i686_ctx_t *ctx)
{
    uint32_t ep;
    if (!ctx || ctx->vm_reserved[0] == 0U) {
        return;
    }
    ep = atomic_load_explicit(&g_vm_epoch, memory_order_acquire);
    if (ctx->vm_reserved[0] != (uint64_t)ep) {
        rt32_vm_sync_ctx(ctx);
    }
}
