/*
 * src/vm/vm_file.c — Provider A in-place arena file backing (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4, section 5.1. Guest pages live at fixed
 * canonical addresses HVA = arena_base + gva for their whole lifetime:
 * MAP_PRIVATE file bytes are populated with pread64 at mmap time,
 * first-write promotion flips PAGE_COW_CLEAN -> PAGE_COW_DIRTY without
 * moving a single byte, and MAP_SHARED pages use a family-shared backing
 * object. No mremap, no memcpy relocation, no addend slide (fable C2, M2).
 *
 * The per-sub-page tables are MAP_SHARED | MAP_ANONYMOUS so parent and
 * child share size/inode/code-generation state across fork() (5.1.3).
 * Curated C11, no VLAs, no x18 (this file is pure C11 anyway).
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE 1
#endif
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "vm/vm_file.h"
#include "i686rt.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

extern void rt32_vm_lock_acquire(void);
extern void rt32_vm_lock_release(void);
extern void i686_vm32_subpage_lock(void);
extern void i686_vm32_subpage_unlock(void);
extern int i686_vm32_widen_prot(i686_ctx_t *ctx, uint32_t start, uint32_t end);
#ifndef I686RT_NO_DBT
extern void i686_dbt_invalidate_range(i686_ctx_t *ctx, uint32_t start,
                                      uint32_t end);
#endif

/* 4 GiB arena at 4 KiB granule: 2^20 sub-pages. */
#define I686_FILE_NPAGES (1u << 20)

static uint8_t *s_prot;   /* guest PROT_READ/WRITE/EXEC per sub-page */
static uint8_t *s_state;  /* i686_page_state_t per sub-page */
static uint8_t *s_flags;  /* I686_PAGE_HAS_* per sub-page */
static int s_ready;
static uint64_t s_arena_base; /* canonical HVA base (arena_base + gva) */

/* Tracked file-backed mappings for the pwrite/ftruncate/mremap hooks. */
#define I686_FILE_MAX_MAPS 256u

typedef struct {
    int used;
    int fd;
    int owned_fd;
    dev_t dev;
    ino_t ino;
    uint8_t has_ino;
    uint32_t gva;
    size_t len;
    uint64_t file_offset;
    uint8_t kind;
} file_map_t;

static file_map_t s_maps[I686_FILE_MAX_MAPS];

static int dup_map_fd(int fd)
{
    int dfd;
    if (fd < 0) {
        return -1;
    }
#ifdef F_DUPFD_CLOEXEC
    dfd = fcntl(fd, F_DUPFD_CLOEXEC, 512);
    if (dfd >= 0) {
        return dfd;
    }
#endif
    return dup(fd);
}

static void close_map_slot(file_map_t *m)
{
    if (m->owned_fd >= 0) {
        (void)close(m->owned_fd);
        m->owned_fd = -1;
    }
    m->used = 0;
}

static uint32_t page_index(uint32_t gva)
{
    return gva >> I686_FILE_SUBPAGE_BITS;
}

static void touch_span(uint32_t gva, size_t len, uint32_t *first, uint32_t *count)
{
    uint64_t end = (uint64_t)gva + (uint64_t)len;
    uint32_t lo = page_index(gva);
    uint32_t hi = page_index((uint32_t)(end - 1u));
    if (len == 0u || end > UINT64_C(0x100000000)) {
        *first = 0u;
        *count = 0u;
        return;
    }
    *first = lo;
    *count = hi - lo + 1u;
}

int i686_vm_file_init(uint64_t arena_base)
{
    if (s_ready != 0) {
        s_arena_base = arena_base;
        return 0;
    }
    s_arena_base = arena_base;
    s_prot = mmap(NULL, I686_FILE_NPAGES, PROT_READ | PROT_WRITE,
                  MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (s_prot == MAP_FAILED) {
        s_prot = NULL;
        return -1;
    }
    s_state = mmap(NULL, I686_FILE_NPAGES, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (s_state == MAP_FAILED) {
        munmap(s_prot, I686_FILE_NPAGES);
        s_prot = NULL;
        s_state = NULL;
        return -1;
    }
    s_flags = mmap(NULL, I686_FILE_NPAGES, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (s_flags == MAP_FAILED) {
        munmap(s_prot, I686_FILE_NPAGES);
        munmap(s_state, I686_FILE_NPAGES);
        s_prot = NULL;
        s_state = NULL;
        s_flags = NULL;
        return -1;
    }
    s_ready = 1;
    return 0;
}

void i686_vm_file_fini(void)
{
    uint32_t i;
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        if (s_maps[i].used != 0) {
            close_map_slot(&s_maps[i]);
        }
    }
    if (s_ready == 0) {
        return;
    }
    munmap(s_prot, I686_FILE_NPAGES);
    munmap(s_state, I686_FILE_NPAGES);
    munmap(s_flags, I686_FILE_NPAGES);
    s_prot = NULL;
    s_state = NULL;
    s_flags = NULL;
    s_ready = 0;
}

void i686_vm_file_set_prot(uint32_t gva, size_t len, uint8_t prot)
{
    uint32_t first, count;
    uint8_t masked = (uint8_t)(prot & 0x07u);
    if (s_ready == 0) {
        return;
    }
    touch_span(gva, len, &first, &count);
    for (uint32_t i = 0u; i < count; i++) {
        __atomic_store_n(&s_prot[first + i], masked, __ATOMIC_RELEASE);
    }
}

uint8_t i686_vm_file_prot(uint32_t gva)
{
    if (s_ready == 0) {
        return 0u;
    }
    return __atomic_load_n(&s_prot[page_index(gva)], __ATOMIC_ACQUIRE);
}

void i686_vm_file_set_state(uint32_t gva, size_t len, uint8_t state)
{
    uint32_t first, count;
    if (s_ready == 0) {
        return;
    }
    touch_span(gva, len, &first, &count);
    for (uint32_t i = 0u; i < count; i++) {
        __atomic_store_n(&s_state[first + i], state, __ATOMIC_RELEASE);
    }
}

uint8_t i686_vm_file_state(uint32_t gva)
{
    if (s_ready == 0) {
        return 0u;
    }
    return __atomic_load_n(&s_state[page_index(gva)], __ATOMIC_ACQUIRE);
}

void i686_vm_file_flags_add(uint32_t gva, size_t len, uint8_t flags)
{
    uint32_t first, count;
    if (s_ready == 0) {
        return;
    }
    touch_span(gva, len, &first, &count);
    for (uint32_t i = 0u; i < count; i++) {
        (void)__atomic_fetch_or(&s_flags[first + i], flags, __ATOMIC_RELEASE);
    }
}

void i686_vm_file_flags_clear(uint32_t gva, size_t len, uint8_t flags)
{
    uint32_t first, count;
    uint8_t mask = (uint8_t)~flags;
    if (s_ready == 0) {
        return;
    }
    touch_span(gva, len, &first, &count);
    for (uint32_t i = 0u; i < count; i++) {
        (void)__atomic_fetch_and(&s_flags[first + i], mask, __ATOMIC_RELEASE);
    }
}

uint8_t i686_vm_file_flags(uint32_t gva)
{
    if (s_ready == 0) {
        return 0u;
    }
    return __atomic_load_n(&s_flags[page_index(gva)], __ATOMIC_ACQUIRE);
}

size_t i686_vm_file_promote_cow(uint32_t gva, size_t len)
{
    uint32_t first, count;
    size_t promoted = 0u;
    if (s_ready == 0) {
        return 0u;
    }
    touch_span(gva, len, &first, &count);
    /* In-place promotion: only the state byte flips. HVA, addend, and all
     * mapping addresses are untouched by construction. */
    for (uint32_t i = 0u; i < count; i++) {
        if (s_state[first + i] == 1u) { /* I686_PAGE_COW_CLEAN */
            s_state[first + i] = 2u;    /* I686_PAGE_COW_DIRTY */
            promoted++;
        }
    }
    return promoted;
}

int i686_vm_file_map_private(uint64_t arena_base, uint32_t gva, size_t len,
                             int fd, uint64_t file_offset)
{
    uint8_t *dst;
    uint64_t got = 0u;
    if (s_ready == 0 || len == 0u) {
        return -EINVAL;
    }
    dst = (uint8_t *)(uintptr_t)(arena_base + (uint64_t)gva);
    while (got < (uint64_t)len) {
        ssize_t n = pread(fd, dst + got, (size_t)((uint64_t)len - got),
                          (off_t)(file_offset + got));
        if (n < 0) {
            int e = errno;
            memset(dst, 0, len);
            i686_vm_file_set_state(gva, len, 0u);
            return -e;
        }
        if (n == 0) {
            break;
        }
        got += (uint64_t)n;
    }
    if (got < (uint64_t)len) {
        memset(dst + got, 0, (size_t)((uint64_t)len - got));
    }
    i686_vm_file_set_state(gva, len, 1u); /* PAGE_COW_CLEAN, write_tag off */
    return 0;
}

uint32_t i686_vm_file_shrink_cut(uint32_t map_start, size_t map_len,
                                 uint64_t map_file_offset,
                                 uint64_t shrink_size)
{
    uint64_t map_end = (uint64_t)map_start + (uint64_t)map_len;
    uint64_t cut;
    if (map_len == 0u) {
        return map_start;
    }
    if (shrink_size >= map_file_offset + (uint64_t)map_len) {
        return (uint32_t)map_end; /* shrink at/past EOF of the map */
    }
    if (shrink_size <= map_file_offset) {
        return map_start; /* whole map beyond EOF */
    }
    cut = (uint64_t)map_start + (((shrink_size - map_file_offset) +
                                  0xFFFULL) & ~0xFFFULL);
    if (cut > map_end) {
        cut = map_end;
    }
    return (uint32_t)cut;
}

void i686_vm_file_note_shrink(uint64_t arena_base, uint32_t map_start,
                              size_t map_len, uint64_t map_file_offset,
                              uint64_t shrink_size)
{
    uint64_t map_end = (uint64_t)map_start + (uint64_t)map_len;
    uint32_t cut = i686_vm_file_shrink_cut(map_start, map_len,
                                           map_file_offset, shrink_size);
    uint64_t a;
    if (s_ready == 0 || (uint64_t)cut >= map_end || map_len == 0u) {
        return;
    }
    /* Pages wholly past EOF revert to zero-backed CLEAN so a later
     * regrow observes fresh file bytes.  The partial page straddling
     * shrink_size sits before the aligned cut and is preserved. */
    for (a = (uint64_t)cut; a < map_end; a += 0x1000ULL) {
        uint32_t idx = page_index((uint32_t)a);
        memset((void *)(uintptr_t)(arena_base + a), 0, 0x1000u);
        s_state[idx] = 1u; /* I686_PAGE_COW_CLEAN, write_tag off */
    }
}

int i686_vm_file_track_map(int fd, uint32_t gva, size_t len,
                           uint64_t file_offset, uint8_t kind)
{
    uint32_t i;
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        if (s_maps[i].used == 0) {
            struct stat st;
            int owned = (fd >= 0) ? dup_map_fd(fd) : -1;
            if (fd >= 0 && owned < 0) {
                return -1;
            }
            s_maps[i].used = 1;
            s_maps[i].fd = fd;
            s_maps[i].owned_fd = owned;
            if (fd >= 0 && fstat(fd, &st) == 0) {
                s_maps[i].dev = st.st_dev;
                s_maps[i].ino = st.st_ino;
                s_maps[i].has_ino = 1u;
            } else {
                s_maps[i].dev = 0;
                s_maps[i].ino = 0;
                s_maps[i].has_ino = 0u;
            }
            s_maps[i].gva = gva;
            s_maps[i].len = len;
            s_maps[i].file_offset = file_offset;
            s_maps[i].kind = kind;
            return 0;
        }
    }
    return -1;
}

int i686_vm_file_can_replace(uint32_t gva, size_t len, int want_track)
{
    uint64_t end = (uint64_t)gva + (uint64_t)len;
    uint32_t splits_needed = 0u;
    uint32_t free_slots = 0u;
    uint32_t i;
    if (len == 0u || end > UINT64_C(0x100000000)) {
        return -1;
    }
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        if (s_maps[i].used == 0) {
            free_slots++;
        } else {
            uint64_t m_start = (uint64_t)s_maps[i].gva;
            uint64_t m_end = m_start + (uint64_t)s_maps[i].len;
            if (m_start < (uint64_t)gva && m_end > end) {
                splits_needed++;
            } else if (m_start >= (uint64_t)gva && m_end <= end) {
                free_slots++;
            }
        }
    }
    if (splits_needed > free_slots) {
        return -1;
    }
    if (want_track != 0 && free_slots <= splits_needed) {
        return -1;
    }
    return 0;
}

int i686_vm_file_untrack_map(uint32_t gva, size_t len)
{
    uint64_t end = (uint64_t)gva + (uint64_t)len;
    uint32_t splits_needed = 0u;
    uint32_t free_slots = 0u;
    uint32_t i;
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        if (s_maps[i].used == 0) {
            free_slots++;
        } else {
            uint64_t m_start = (uint64_t)s_maps[i].gva;
            uint64_t m_end = m_start + (uint64_t)s_maps[i].len;
            if (m_start < (uint64_t)gva && m_end > end) {
                splits_needed++;
            } else if (m_start >= (uint64_t)gva && m_end <= end) {
                free_slots++;
            }
        }
    }
    if (splits_needed > free_slots) {
        return -1;
    }
    /* Pass 1: free fully covered entries first so an interior split in
     * pass 2 can always reuse a slot the pre-check counted as free,
     * even when the only such slot sits at a higher index than the
     * straddling entry (I686-R2-7 follow-up). */
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        uint64_t m_start;
        uint64_t m_end;
        if (s_maps[i].used == 0) {
            continue;
        }
        m_start = (uint64_t)s_maps[i].gva;
        m_end = m_start + (uint64_t)s_maps[i].len;
        if (m_start >= end || m_end <= (uint64_t)gva) {
            continue;
        }
        if (m_start >= (uint64_t)gva && m_end <= end) {
            close_map_slot(&s_maps[i]);
        }
    }
    /* Pass 2: truncate or split the remaining straddling entries. */
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        uint64_t m_start;
        uint64_t m_end;
        if (s_maps[i].used == 0) {
            continue;
        }
        m_start = (uint64_t)s_maps[i].gva;
        m_end = m_start + (uint64_t)s_maps[i].len;
        if (m_start >= end || m_end <= (uint64_t)gva) {
            continue;
        }
        if (m_start >= (uint64_t)gva && m_end <= end) {
            close_map_slot(&s_maps[i]);
        } else if (m_start < (uint64_t)gva && m_end <= end) {
            s_maps[i].len = (size_t)((uint64_t)gva - m_start);
        } else if (m_start >= (uint64_t)gva && m_end > end) {
            uint64_t delta = end - m_start;
            s_maps[i].gva = (uint32_t)end;
            s_maps[i].len = (size_t)(m_end - end);
            s_maps[i].file_offset += delta;
        } else {
            /* Interior hole unmap (I686-R2-7): split into [m_start, gva)
             * and [end, m_end) with adjusted file_offset and duplicated FD. */
            uint64_t tail_delta = end - m_start;
            size_t tail_len = (size_t)(m_end - end);
            uint32_t j;
            uint32_t free_slot = I686_FILE_MAX_MAPS;
            int src_fd = (s_maps[i].owned_fd >= 0) ? s_maps[i].owned_fd
                                                   : s_maps[i].fd;
            int new_fd = (src_fd >= 0) ? dup_map_fd(src_fd) : -1;
            if (src_fd >= 0 && new_fd < 0) {
                return -1;
            }
            for (j = 0u; j < I686_FILE_MAX_MAPS; j++) {
                if (s_maps[j].used == 0) {
                    free_slot = j;
                    break;
                }
            }
            if (free_slot >= I686_FILE_MAX_MAPS) {
                if (new_fd >= 0) {
                    (void)close(new_fd);
                }
                return -1;
            }
            s_maps[i].len = (size_t)((uint64_t)gva - m_start);
            s_maps[free_slot].used = 1;
            s_maps[free_slot].fd = s_maps[i].fd;
            s_maps[free_slot].owned_fd = new_fd;
            s_maps[free_slot].dev = s_maps[i].dev;
            s_maps[free_slot].ino = s_maps[i].ino;
            s_maps[free_slot].has_ino = s_maps[i].has_ino;
            s_maps[free_slot].gva = (uint32_t)end;
            s_maps[free_slot].len = tail_len;
            s_maps[free_slot].file_offset = s_maps[i].file_offset +
                                            tail_delta;
            s_maps[free_slot].kind = s_maps[i].kind;
        }
    }
    return 0;
}

int i686_vm_file_lookup_map(uint32_t gva, int *out_fd,
                            uint64_t *out_file_offset, uint8_t *out_kind)
{
    uint32_t i;
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        uint64_t m_start;
        uint64_t m_end;
        if (s_maps[i].used == 0) {
            continue;
        }
        m_start = (uint64_t)s_maps[i].gva;
        m_end = m_start + (uint64_t)s_maps[i].len;
        if ((uint64_t)gva >= m_start && (uint64_t)gva < m_end) {
            uint64_t delta = (uint64_t)gva - m_start;
            if (out_fd != NULL) {
                *out_fd = (s_maps[i].owned_fd >= 0) ? s_maps[i].owned_fd
                                                    : s_maps[i].fd;
            }
            if (out_file_offset != NULL) {
                *out_file_offset = s_maps[i].file_offset + delta;
            }
            if (out_kind != NULL) {
                *out_kind = s_maps[i].kind;
            }
            return 0;
        }
    }
    return -1;
}

static int map_matches_fd(const file_map_t *m, int fd, int have_st,
                          const struct stat *st)
{
    if (have_st && m->has_ino != 0u) {
        return (m->dev == st->st_dev && m->ino == st->st_ino) ? 1 : 0;
    }
    return (m->fd == fd || m->owned_fd == fd) ? 1 : 0;
}

size_t i686_vm_file_note_pwrite(i686_ctx_t *ctx, int fd,
                                uint64_t file_offset, size_t len)
{
    uint64_t w_end = file_offset + (uint64_t)len;
    size_t refreshed = 0u;
    struct stat st;
    int have_st;
    uint32_t i;
    if (s_ready == 0 || len == 0u || ctx == NULL) {
        return 0u;
    }
    have_st = (fd >= 0 && fstat(fd, &st) == 0) ? 1 : 0;
    rt32_vm_lock_acquire();
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        uint64_t m_start;
        uint64_t m_end;
        uint64_t o_start;
        uint64_t o_end;
        uint64_t f;
        int rfd;
        if (s_maps[i].used == 0 ||
            !map_matches_fd(&s_maps[i], fd, have_st, &st) ||
            (s_maps[i].kind != 1u &&
                s_maps[i].kind != 2u)) { /* file image (private or A2
            staged shared); anonymous mappings carry no file bytes */
            continue;
        }
        rfd = (s_maps[i].owned_fd >= 0) ? s_maps[i].owned_fd : fd;
        m_start = s_maps[i].file_offset;
        m_end = m_start + (uint64_t)s_maps[i].len;
        o_start = (file_offset > m_start) ? file_offset : m_start;
        o_end = (w_end < m_end) ? w_end : m_end;
        if (o_end <= o_start) {
            continue;
        }
        /* Re-read the overlapped CLEAN pages so they observe the new
         * file bytes; DIRTY pages already diverged from the file. */
        for (f = o_start & ~0xFFFULL; f < o_end; f += 0x1000ULL) {
            uint32_t gva = s_maps[i].gva + (uint32_t)(f - m_start);
            uint32_t idx = page_index(gva);
            uint64_t r_start = (f > o_start) ? f : o_start;
            uint64_t r_end = (f + 0x1000ULL < o_end) ? f + 0x1000ULL : o_end;
            uint8_t tmp[4096];
            size_t want;
            size_t got = 0u;
            int a2;
            /* CLEAN (1) pages refresh from the file; A2 staged shared
             * mappings (kind 2) publish state 0 yet still mirror file
             * bytes, so they refresh too. Other states have diverged. */
            if (s_state[idx] != 1u &&
                (s_maps[i].kind != 2u || s_state[idx] != 0u)) {
                continue;
            }
            want = (size_t)(r_end - r_start);
            if (want == 0u || want > sizeof(tmp)) {
                continue;
            }
            while (got < want) {
                ssize_t n = pread(rfd, tmp + got, want - got,
                                  (off_t)(r_start + (uint64_t)got));
                if (n < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    break;
                }
                if (n == 0) {
                    break;
                }
                got += (size_t)n;
            }
            if (got != want) {
                continue;
            }
            a2 = (ctx->vm_regime == I686_VM_REGIME_A2 &&
                  ctx->vm_host_page > 4096u) ? 1 : 0;
            if (a2) {
                uint32_t hps = ctx->vm_host_page;
                uint32_t gbase = gva & ~(hps - 1u);
                uint64_t cover = ctx->guest_base + (uint64_t)gbase;
                i686_vm32_subpage_lock();
                (void)mprotect((void *)(uintptr_t)cover, (size_t)hps,
                               PROT_READ | PROT_WRITE);
                memcpy((void *)(uintptr_t)(ctx->guest_base + (uint64_t)gva +
                                           (r_start - (f & ~0xFFFULL))),
                       tmp, want);
                (void)i686_vm32_widen_prot(ctx, gbase, gbase + hps);
                i686_vm32_subpage_unlock();
            } else {
                memcpy((void *)(uintptr_t)(ctx->guest_base + (uint64_t)gva +
                                           (r_start - (f & ~0xFFFULL))),
                       tmp, want);
            }
            refreshed++;
#ifndef I686RT_NO_DBT
            if ((i686_vm_file_prot(gva) & 0x04u) != 0u) {
                uint32_t pg = gva & ~0xFFFu;
                i686_dbt_invalidate_range(ctx, pg, pg + 0x1000u);
            }
#else
            (void)gva;
#endif
        }
    }
    rt32_vm_lock_release();
    return refreshed;
}

size_t i686_vm_file_note_ftruncate(int fd, uint64_t new_size)
{
    size_t shrunk = 0u;
    struct stat st;
    int have_st;
    uint32_t i;
    if (s_ready == 0) {
        return 0u;
    }
    have_st = (fd >= 0 && fstat(fd, &st) == 0) ? 1 : 0;
    for (i = 0u; i < I686_FILE_MAX_MAPS; i++) {
        if (s_maps[i].used != 0 &&
            map_matches_fd(&s_maps[i], fd, have_st, &st) &&
            s_maps[i].kind == 1u && /* MAP_PRIVATE file image only */
            new_size < s_maps[i].file_offset + (uint64_t)s_maps[i].len) {
            i686_vm_file_note_shrink(s_arena_base, s_maps[i].gva,
                                     s_maps[i].len, s_maps[i].file_offset,
                                     new_size);
            shrunk++;
        }
    }
    return shrunk;
}
