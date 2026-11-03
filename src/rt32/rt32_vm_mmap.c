/*
 * src/rt32/rt32_vm_mmap.c — Guest mmap2, mprotect, munmap, and mremap handlers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include "rt32_vm_internal.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static uint32_t vm_mmap2_locked(i686_ctx_t *ctx, uint32_t addr, uint32_t len,
                                uint32_t prot, uint32_t flags, int fd,
                                uint32_t pgoffset)
{
    if (!ctx || len == 0U || (flags & 0x03U) == 0U || (flags & 0x03U) == 0x03U) {
        return (uint32_t)(-EINVAL);
    }

    uint64_t aligned_len = rt32_page_align_up((uint64_t)len);
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
            rt32_vm_range_overlaps_locked(addr,
                                          (uint32_t)((uint64_t)addr + aligned_len))) {
            return (uint32_t)(-EEXIST);
        }
        target_va = addr;
    } else {
        uint32_t hint_va = i686_page_down(addr);
        if (addr != 0U &&
            hint_va >= RT32_MMAP_BASE_32 &&
            (uint64_t)hint_va + aligned_len <= (uint64_t)RT32_MMAP_TOP_32 &&
            !rt32_vm_range_overlaps_locked(hint_va,
                                           (uint32_t)((uint64_t)hint_va + aligned_len))) {
            target_va = hint_va;
        } else if (rt32_vm_find_free_gap_locked(aligned_len, &target_va) != 0) {
            return (uint32_t)(-ENOMEM);
        } else {
            update_cursor = true;
        }
    }

    int      host_prot = i686_host_prot(ctx, prot);
    bool     is_anon   = (flags & RT32_MAP_ANONYMOUS) != 0U;
    bool     is_shared = (flags & 0x01U) != 0U;
    uint64_t file_off  = (uint64_t)pgoffset * (uint64_t)I686_PAGE_SIZE;
    uint32_t target_end = (uint32_t)((uint64_t)target_va + aligned_len);
    int want_track = (!is_anon && fd >= 0) ? 1 : 0;
    int staged = rt32_vm_a2_staged_needed(ctx, target_va, aligned_len, flags,
                                          file_off) ? 1 : 0;

    if (!is_anon && fd < 0 && staged) {
        return (uint32_t)(-EBADF);
    }
    if (rt32_vm_can_record_locked(target_va, target_end) != 0) {
        return (uint32_t)(-ENOMEM);
    }
    if (i686_vm_file_can_replace(target_va, (size_t)aligned_len,
                                  want_track) != 0) {
        return (uint32_t)(-ENOMEM);
    }
    if (staged) {
        int rc;
        i686_vm32_subpage_lock();
        rc = rt32_vm_mmap2_staged_a2_locked(ctx, target_va,
                                            (uint32_t)aligned_len, fd, file_off,
                                            is_anon, is_shared);
        if (rc != 0) {
            i686_vm32_subpage_unlock();
            return (uint32_t)rc;
        }
    } else {
        void *host_target = i686_guest_ptr(ctx, target_va);
        off_t host_off    = (off_t)file_off;
        void *res = mmap(host_target, (size_t)aligned_len, host_prot,
                         host_flags | MAP_FIXED, is_anon ? -1 : fd,
                         is_anon ? 0 : host_off);
        if (res == MAP_FAILED) {
            return (uint32_t)(-errno);
        }
    }

    if (rt32_vm_record_region_locked(target_va, target_end,
                                     prot & 0x7U, flags, "[mmap]") != 0) {
        if (!staged) {
            (void)rt32_vm_reserve_prot_none(ctx, target_va,
                                            (uint32_t)aligned_len);
        } else {
            (void)i686_vm32_widen_prot(ctx, target_va, target_end);
            i686_vm32_subpage_unlock();
        }
        return (uint32_t)(-ENOMEM);
    }
    if (i686_vm_file_untrack_map(target_va, (size_t)aligned_len) != 0) {
        (void)rt32_vm_unmap_regions_locked(target_va, target_end);
        rt32_vm_file_sync_prot_locked(target_va, target_end);
        if (!staged) {
            (void)rt32_vm_reserve_prot_none(ctx, target_va,
                                            (uint32_t)aligned_len);
        } else {
            (void)i686_vm32_widen_prot(ctx, target_va, target_end);
            i686_vm32_subpage_unlock();
        }
        return (uint32_t)(-ENOMEM);
    }
    if (want_track) {
        uint8_t kind = is_shared ? I686_BACKING_SHARED_FILE
                                 : I686_BACKING_PRIVATE_FILE;
        if (i686_vm_file_track_map(fd, target_va, (size_t)aligned_len,
                                   (uint64_t)pgoffset * 4096u, kind,
                                   (uint8_t)(staged ? 1 : 0)) != 0) {
            (void)rt32_vm_unmap_regions_locked(target_va, target_end);
            rt32_vm_file_sync_prot_locked(target_va, target_end);
            if (!staged) {
                (void)rt32_vm_reserve_prot_none(ctx, target_va,
                                                (uint32_t)aligned_len);
            } else {
                (void)i686_vm32_widen_prot(ctx, target_va, target_end);
                i686_vm32_subpage_unlock();
            }
            return (uint32_t)(-ENOMEM);
        }
    }
    rt32_vm_union_protect_a2(ctx, target_va, target_end);
    if (staged) {
        i686_vm32_subpage_unlock();
    }
    if (update_cursor) {
        g_vm_mmap_cursor = target_end;
    }
    return target_va;
}

uint32_t rt32_vm_mmap2(i686_ctx_t *ctx, uint32_t addr, uint32_t len,
                       uint32_t prot, uint32_t flags, int fd, uint32_t pgoffset)
{
    if (!ctx) {
        return (uint32_t)(-EINVAL);
    }

    rt32_vm_lock_acquire();
    rt32_vm_sync_from_ctx(ctx);
    uint32_t res = vm_mmap2_locked(ctx, addr, len, prot, flags, fd, pgoffset);
    rt32_vm_sync_to_ctx(ctx);
    rt32_vm_lock_release();

    if (res <= 0xFFFFF000U &&
        ((flags & (RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE)) != 0U ||
         (prot & (uint32_t)PROT_EXEC) != 0U)) {
        rt32_vm_invalidate_jit(ctx, res,
                               (uint32_t)((uint64_t)res + rt32_page_align_up((uint64_t)len)));
    }
    return res;
}

static int vm_mprotect_locked(i686_ctx_t *ctx, uint32_t addr, uint32_t len,
                              uint32_t prot)
{
    if (!ctx || (addr & (I686_PAGE_SIZE - 1U)) != 0U || addr < 0x1000U ||
        (prot & ~0x7U) != 0U) {
        return -EINVAL;
    }
    if (len == 0U) {
        return 0;
    }
    uint64_t aligned_len = rt32_page_align_up((uint64_t)len);
    uint64_t end64       = (uint64_t)addr + aligned_len;
    if (addr < I686_LOW_GUARD_SIZE ||
        aligned_len == 0ULL ||
        end64 > (uint64_t)I686_TASK_SIZE_TOP ||
        !rt32_vm_check_mapped_range_locked(addr, (uint32_t)end64, NULL, NULL,
                                           NULL, 0U)) {
        return -ENOMEM;
    }

    if (rt32_vm_can_mprotect_locked(addr, (uint32_t)end64) != 0) {
        return -ENOMEM;
    }
    if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u) {
        if (rt32_vm_mprotect_regions_locked(addr, (uint32_t)end64,
                                            prot & 0x7U) != 0) {
            return -ENOMEM;
        }
        if (i686_vm32_widen_prot(ctx, addr, (uint32_t)end64) != 0) {
            return -EIO;
        }
        return 0;
    }

    if (mprotect(i686_guest_ptr(ctx, addr), (size_t)aligned_len,
                 i686_host_prot(ctx, prot)) != 0) {
        return -errno;
    }

    if (rt32_vm_mprotect_regions_locked(addr, (uint32_t)end64,
                                        prot & 0x7U) != 0) {
        return -ENOMEM;
    }
    return 0;
}

int rt32_vm_mprotect(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    if (!ctx) {
        return -EINVAL;
    }

    rt32_vm_lock_acquire();
    rt32_vm_sync_from_ctx(ctx);
    int rc = vm_mprotect_locked(ctx, addr, len, prot);
    rt32_vm_sync_to_ctx(ctx);
    rt32_vm_lock_release();

    if (rc == 0 && len > 0U) {
        rt32_vm_invalidate_jit(ctx, addr,
                               (uint32_t)((uint64_t)addr + rt32_page_align_up((uint64_t)len)));
    }
    return rc;
}

static int vm_munmap_locked(i686_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    if (!ctx || (addr & (I686_PAGE_SIZE - 1U)) != 0U || len == 0U) {
        return -EINVAL;
    }
    uint64_t aligned_len = rt32_page_align_up((uint64_t)len);
    if (addr < I686_LOW_GUARD_SIZE ||
        (uint64_t)addr + aligned_len > (uint64_t)I686_TASK_SIZE_TOP) {
        return -EINVAL;
    }

    uint32_t start = i686_page_down(addr);
    uint32_t end = (uint32_t)((uint64_t)start + aligned_len);
    if (rt32_vm_can_unmap_locked(start, end) != 0) {
        return -ENOMEM;
    }
    if (i686_vm_file_can_replace(start, (size_t)aligned_len, 0) != 0) {
        return -ENOMEM;
    }
    if (i686_vm_file_untrack_map(start, (size_t)aligned_len) != 0) {
        return -ENOMEM;
    }
    {
        int rc = rt32_vm_reserve_prot_none(ctx, start, (uint32_t)aligned_len);
        if (rc != 0) {
            return rc;
        }
    }

    if (rt32_vm_unmap_regions_locked(start, end) != 0) {
        return -ENOMEM;
    }
    rt32_vm_file_sync_prot_locked(start, end);
    (void)i686_vm32_widen_prot(ctx, start, end);
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

    rt32_vm_lock_acquire();
    rt32_vm_sync_from_ctx(ctx);
    int rc = vm_munmap_locked(ctx, addr, len);
    rt32_vm_sync_to_ctx(ctx);
    rt32_vm_lock_release();

    if (rc == 0) {
        rt32_vm_invalidate_jit(ctx, addr,
                               (uint32_t)((uint64_t)addr + rt32_page_align_up((uint64_t)len)));
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
        ((flags & RT32_MREMAP_FIXED) != 0U &&
         (flags & RT32_MREMAP_MAYMOVE) == 0U)) {
        return (uint32_t)(-EINVAL);
    }

    uint64_t old_aligned = rt32_page_align_up((uint64_t)old_len);
    uint64_t new_aligned = rt32_page_align_up((uint64_t)new_len);
    if (old_addr < I686_LOW_GUARD_SIZE ||
        (uint64_t)old_addr + old_aligned > (uint64_t)I686_TASK_SIZE_TOP) {
        return (uint32_t)(-EINVAL);
    }
    if (new_aligned == 0ULL || new_aligned > (uint64_t)I686_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    rt32_vm_lock_acquire();
    rt32_vm_sync_from_ctx(ctx);

    uint32_t prot       = 0x3U;
    uint32_t orig_flags = 0x22U;
    char     orig_name[64];
    orig_name[0] = '\0';
    if (!rt32_vm_check_mapped_range_locked(old_addr,
                                           (uint32_t)((uint64_t)old_addr + old_aligned),
                                           &prot, &orig_flags, orig_name,
                                           sizeof(orig_name))) {
        rt32_vm_sync_to_ctx(ctx);
        rt32_vm_lock_release();
        return (uint32_t)(-EFAULT);
    }
    uint32_t    keep_flags  = orig_flags & 0x23U;
    uint32_t    anon_flags  = (((keep_flags & 0x01U) != 0U) ? 0x01U : 0x02U) | RT32_MAP_ANONYMOUS;
    const char *region_name = (orig_name[0] != '\0') ? orig_name : "[mmap]";
    int         map_fd      = -1;
    int         hold_fd     = -1;
    uint64_t    map_foff    = 0ULL;
    uint8_t     map_kind    = 0U;
    bool        has_file    = ((keep_flags & RT32_MAP_ANONYMOUS) == 0U) &&
                              (i686_vm_file_lookup_map(old_addr, &map_fd,
                                                       &map_foff, &map_kind,
                                                       NULL) == 0) &&
                              (map_fd >= 0);
    if (has_file) {
        hold_fd = dup(map_fd);
        if (hold_fd >= 0) {
            map_fd = hold_fd;
        }
    }

    if ((flags & RT32_MREMAP_FIXED) == 0U) {
        if (new_aligned == old_aligned) {
            if (hold_fd >= 0) {
                (void)close(hold_fd);
            }
            rt32_vm_sync_to_ctx(ctx);
            rt32_vm_lock_release();
            return old_addr;
        }
        if (new_aligned < old_aligned) {
            uint32_t unmap_addr = old_addr + (uint32_t)new_aligned;
            uint32_t unmap_len  = (uint32_t)(old_aligned - new_aligned);
            int rc = vm_munmap_locked(ctx, unmap_addr, unmap_len);
            if (hold_fd >= 0) {
                (void)close(hold_fd);
            }
            rt32_vm_sync_to_ctx(ctx);
            rt32_vm_lock_release();
            if (rc != 0) {
                return (uint32_t)rc;
            }
            rt32_vm_invalidate_jit(ctx, unmap_addr, unmap_addr + unmap_len);
            return old_addr;
        }

        uint32_t old_end = (uint32_t)((uint64_t)old_addr + old_aligned);
        uint64_t new_end = (uint64_t)old_addr + new_aligned;
        if (new_end <= (uint64_t)I686_TASK_SIZE_TOP &&
            !rt32_vm_range_overlaps_locked(old_end, (uint32_t)new_end)) {
            uint32_t ext_flags = (has_file ? keep_flags : anon_flags) | RT32_MAP_FIXED;
            int      ext_fd    = has_file ? map_fd : -1;
            uint32_t ext_pgoff = has_file ? (uint32_t)((map_foff + old_aligned) >> 12) : 0U;
            uint32_t ext = vm_mmap2_locked(ctx, old_end,
                                           (uint32_t)(new_aligned - old_aligned),
                                           prot, ext_flags, ext_fd, ext_pgoff);
            if (ext <= 0xFFFFF000U) {
                int rec_rc = rt32_vm_record_region_locked(old_end,
                                                          (uint32_t)new_end,
                                                          prot, keep_flags,
                                                          region_name);
                int ok = 0;
                if (rec_rc == 0 && has_file == false) {
                    ok = 1;
                } else if (rec_rc == 0 && has_file) {
                    /* Transactional replacement (I686-R4-5): the record
                     * and its owned descriptor are prepared before any
                     * existing record is deleted, so a failure keeps the
                     * original tracking (and the extension record added
                     * above is removed with the extension below). */
                    uint8_t orig_staged = 0u;
                    uint8_t ext_staged = 0u;
                    (void)i686_vm_file_lookup_map(old_addr, NULL, NULL, NULL,
                                                  &orig_staged);
                    (void)i686_vm_file_lookup_map(old_end, NULL, NULL, NULL,
                                                  &ext_staged);
                    if (i686_vm_file_replace_map(map_fd, old_addr,
                                                 (size_t)new_aligned,
                                                 map_foff, map_kind,
                                                 (uint8_t)(orig_staged |
                                                           ext_staged)) == 0) {
                        ok = 1;
                    }
                }
                if (!ok) {
                    (void)vm_munmap_locked(ctx, old_end,
                                           (uint32_t)(new_aligned - old_aligned));
                    if (hold_fd >= 0) {
                        (void)close(hold_fd);
                    }
                    rt32_vm_sync_to_ctx(ctx);
                    rt32_vm_lock_release();
                    return (uint32_t)(-ENOMEM);
                }
                if (hold_fd >= 0) {
                    (void)close(hold_fd);
                }
                uint32_t ext_end = (uint32_t)new_end;
                if (g_vm_mmap_cursor >= old_addr && g_vm_mmap_cursor < ext_end &&
                    ext_end <= RT32_MMAP_TOP_32) {
                    g_vm_mmap_cursor = ext_end;
                }
                rt32_vm_sync_to_ctx(ctx);
                rt32_vm_lock_release();
                if ((prot & (uint32_t)PROT_EXEC) != 0U) {
                    rt32_vm_invalidate_jit(ctx, old_end, ext_end);
                }
                return old_addr;
            }
        }

        if ((flags & RT32_MREMAP_MAYMOVE) == 0U) {
            if (hold_fd >= 0) {
                (void)close(hold_fd);
            }
            rt32_vm_sync_to_ctx(ctx);
            rt32_vm_lock_release();
            return (uint32_t)(-ENOMEM);
        }
    } else {
        if ((new_addr & (I686_PAGE_SIZE - 1U)) != 0U || new_addr < I686_LOW_GUARD_SIZE ||
            (uint64_t)new_addr + new_aligned > (uint64_t)I686_TASK_SIZE_TOP ||
            ((uint64_t)new_addr < (uint64_t)old_addr + old_aligned &&
             (uint64_t)old_addr < (uint64_t)new_addr + new_aligned)) {
            if (hold_fd >= 0) {
                (void)close(hold_fd);
            }
            rt32_vm_sync_to_ctx(ctx);
            rt32_vm_lock_release();
            return (uint32_t)(-EINVAL);
        }
    }

    bool     is_fixed  = (flags & RT32_MREMAP_FIXED) != 0U;
    uint32_t rw_prot   = (prot & ~((uint32_t)PROT_EXEC)) | (uint32_t)(PROT_READ | PROT_WRITE);
    uint32_t rel_flags = (has_file ? keep_flags : anon_flags) |
                         (is_fixed ? RT32_MAP_FIXED : 0U);
    int      rel_fd    = has_file ? map_fd : -1;
    uint32_t rel_pgoff = has_file ? (uint32_t)(map_foff >> 12) : 0U;
    uint32_t new_va    = vm_mmap2_locked(ctx, is_fixed ? new_addr : 0U,
                                         (uint32_t)new_aligned, rw_prot,
                                         rel_flags, rel_fd, rel_pgoff);
    if (new_va > 0xFFFFF000U) {
        if (hold_fd >= 0) {
            (void)close(hold_fd);
        }
        rt32_vm_sync_to_ctx(ctx);
        rt32_vm_lock_release();
        return new_va;
    }

    /* Copy existing bytes for anonymous/private mappings, or for Regime A2
     * staged shared mappings where host MAP_SHARED could not be used.
     * On Linux, moving a MAP_SHARED | MAP_ANONYMOUS region uses host mremap
     * so shared identity across fork() is preserved (X-R2-2). I686-R3-9:
     * when that host mremap fails, fail the guest mremap and remove the
     * provisional destination instead of copying into a fresh object
     * that no longer shares identity with a fork peer. */
    bool moved_via_host_mremap = false;
#ifdef __linux__
    if (!has_file && (keep_flags & 0x01U) != 0U &&
        !rt32_vm_a2_staged_needed(ctx, new_va, new_aligned, rel_flags, 0ULL)) {
        void *mr = mremap(i686_guest_ptr(ctx, old_addr), (size_t)old_aligned,
                          (size_t)new_aligned, MREMAP_MAYMOVE | MREMAP_FIXED,
                          i686_guest_ptr(ctx, new_va));
        if (mr != MAP_FAILED) {
            moved_via_host_mremap = true;
        } else {
            int merrno = errno;
            (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
            if (hold_fd >= 0) {
                (void)close(hold_fd);
            }
            rt32_vm_sync_to_ctx(ctx);
            rt32_vm_lock_release();
            return (uint32_t)(-merrno);
        }
    }
#endif
    if (!has_file && (keep_flags & 0x01U) != 0U && !moved_via_host_mremap) {
        /* I686-R3-9 (other backends): a shared anonymous mapping has
         * fork-shared identity, so copying into the fresh provisional
         * destination would silently drop sharing. No
         * backing-preserving move exists here (Linux returns above via
         * host mremap); fail and remove the provisional destination. */
        (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
        if (hold_fd >= 0) {
            (void)close(hold_fd);
        }
        rt32_vm_sync_to_ctx(ctx);
        rt32_vm_lock_release();
        return (uint32_t)(-ENOMEM);
    }
    if (!moved_via_host_mremap &&
        (!has_file || (keep_flags & 0x01U) == 0U ||
         rt32_vm_a2_staged_needed(ctx, new_va, new_aligned, rel_flags, map_foff))) {
        size_t copy_bytes = (size_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
        if (ctx->vm_regime == I686_VM_REGIME_A2 && ctx->vm_host_page > 4096u) {
            /* Staged/A2 copy under the subpage exclusion protocol
             * (I686-R4-4, VM lock outer, subpage lock inner): open the
             * host-page-aligned source and destination covers writable,
             * check both changes, copy, and widen every opened cover
             * back on success and on failure. */
            uint64_t h = (uint64_t)ctx->vm_host_page;
            uint64_t s_lo = (uint64_t)old_addr & ~(h - 1u);
            uint64_t s_hi = ((uint64_t)old_addr + (uint64_t)copy_bytes +
                             h - 1u) & ~(h - 1u);
            uint64_t d_lo = (uint64_t)new_va & ~(h - 1u);
            uint64_t d_hi = ((uint64_t)new_va + (uint64_t)copy_bytes +
                             h - 1u) & ~(h - 1u);
            void *s_cov = (void *)(uintptr_t)(ctx->guest_base + s_lo);
            void *d_cov = (void *)(uintptr_t)(ctx->guest_base + d_lo);
            size_t s_len = (size_t)(s_hi - s_lo);
            size_t d_len = (size_t)(d_hi - d_lo);
            int src_open = 0;
            int dst_open = 0;
            i686_vm32_subpage_lock();
            if (mprotect(s_cov, s_len, PROT_READ | PROT_WRITE) == 0) {
                src_open = 1;
            }
            if (mprotect(d_cov, d_len, PROT_READ | PROT_WRITE) == 0) {
                dst_open = 1;
            }
            if (src_open == 0 || dst_open == 0) {
                if (src_open != 0) {
                    (void)i686_vm32_widen_prot(ctx, old_addr,
                                               (uint32_t)((uint64_t)old_addr +
                                                          copy_bytes));
                }
                if (dst_open != 0) {
                    (void)i686_vm32_widen_prot(ctx, new_va,
                                               (uint32_t)((uint64_t)new_va +
                                                          copy_bytes));
                }
                i686_vm32_subpage_unlock();
                (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
                if (hold_fd >= 0) {
                    (void)close(hold_fd);
                }
                rt32_vm_sync_to_ctx(ctx);
                rt32_vm_lock_release();
                return (uint32_t)(-ENOMEM);
            }
            memcpy(i686_guest_ptr(ctx, new_va), i686_guest_ptr(ctx, old_addr),
                   copy_bytes);
            (void)i686_vm32_widen_prot(ctx, old_addr,
                                       (uint32_t)((uint64_t)old_addr +
                                                  copy_bytes));
            (void)i686_vm32_widen_prot(ctx, new_va,
                                       (uint32_t)((uint64_t)new_va +
                                                  copy_bytes));
            i686_vm32_subpage_unlock();
        } else {
            if ((prot & 0x1U) == 0U) {
                if (mprotect(i686_guest_ptr(ctx, old_addr),
                             (size_t)old_aligned, PROT_READ) != 0) {
                    (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
                    if (hold_fd >= 0) {
                        (void)close(hold_fd);
                    }
                    rt32_vm_sync_to_ctx(ctx);
                    rt32_vm_lock_release();
                    return (uint32_t)(-errno);
                }
            }
            memcpy(i686_guest_ptr(ctx, new_va), i686_guest_ptr(ctx, old_addr),
                   copy_bytes);
        }
    }
    if (prot != rw_prot) {
        if (vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned, prot) != 0) {
            (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
            if (hold_fd >= 0) {
                (void)close(hold_fd);
            }
            rt32_vm_sync_to_ctx(ctx);
            rt32_vm_lock_release();
            return (uint32_t)(-ENOMEM);
        }
    }
    if (rt32_vm_record_region_locked(new_va,
                                     (uint32_t)((uint64_t)new_va + new_aligned),
                                     prot, keep_flags, region_name) != 0) {
        (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
        if (hold_fd >= 0) {
            (void)close(hold_fd);
        }
        rt32_vm_sync_to_ctx(ctx);
        rt32_vm_lock_release();
        return (uint32_t)(-ENOMEM);
    }
    if (vm_munmap_locked(ctx, old_addr, (uint32_t)old_aligned) != 0) {
        if (hold_fd >= 0) {
            (void)close(hold_fd);
        }
        rt32_vm_sync_to_ctx(ctx);
        rt32_vm_lock_release();
        return (uint32_t)(-ENOMEM);
    }
    if (hold_fd >= 0) {
        (void)close(hold_fd);
    }
    rt32_vm_sync_to_ctx(ctx);
    rt32_vm_lock_release();

    rt32_vm_invalidate_jit(ctx, old_addr, (uint32_t)((uint64_t)old_addr + old_aligned));
    if (is_fixed || (prot & (uint32_t)PROT_EXEC) != 0U) {
        rt32_vm_invalidate_jit(ctx, new_va, (uint32_t)((uint64_t)new_va + new_aligned));
    }
    return new_va;
}
