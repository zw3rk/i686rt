/*
 * src/vm/vm_file.h — Provider A in-place file backing interface (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4, section 5.1: every guest page stays in place
 * at its fixed canonical arena address HVA = arena_base + gva. COW
 * promotion (PAGE_COW_CLEAN -> PAGE_COW_DIRTY) never changes HVA or the
 * Soft-TLB addend, so sibling CLONE_VM threads with warm read_tag entries
 * observe written bytes immediately (fable C2), FUTEX_WAIT/WAKE always
 * address the same HVA, and host fork() COW-clones the MAP_PRIVATE arena
 * between parent and child (fable C1).
 */

#ifndef I686RT_VM_FILE_H
#define I686RT_VM_FILE_H

#include <stddef.h>
#include <stdint.h>

/* Sub-page size tracked here: the guest ABI granule (4 KiB on i686). */
#define I686_FILE_SUBPAGE_BITS 12u
#define I686_FILE_SUBPAGE_SIZE (1u << I686_FILE_SUBPAGE_BITS)

/* Backing kind of one MAP_SHARED family entry (5.1.2). */
typedef enum {
    I686_BACKING_PRIVATE_ANON = 0, /* MAP_PRIVATE arena page, no file identity */
    I686_BACKING_PRIVATE_FILE = 1, /* MAP_PRIVATE file image, COW-clean until first write */
    I686_BACKING_SHARED_FILE = 2   /* MAP_SHARED: family-shared backing object */
} i686_backing_kind_t;

/* Allocate per-sub-page tables for the 4 GiB arena at arena_base.
 * The tables are MAP_SHARED | MAP_ANONYMOUS so the fork family shares
 * inode/size/code-generation state (5.1.3 lightweight family segment).
 * Returns 0 on success, -1 on failure. */
int i686_vm_file_init(uint64_t arena_base);

/* Release the tables (no-op when uninitialized). */
void i686_vm_file_fini(void);

/* Record guest protection bits (PROT_READ/WRITE, never EXEC) for sub-pages
 * fully covered by [gva, gva + len). */
void i686_vm_file_set_prot(uint32_t gva, size_t len, uint8_t prot);

/* Query one sub-page's guest protection (0 when unmapped/unknown). */
uint8_t i686_vm_file_prot(uint32_t gva);

/* Set / query the i686_page_state_t of covered sub-pages. */
void i686_vm_file_set_state(uint32_t gva, size_t len, uint8_t state);
uint8_t i686_vm_file_state(uint32_t gva);

/* Add / clear / query I686_PAGE_HAS_* flags on covered sub-pages. */
void i686_vm_file_flags_add(uint32_t gva, size_t len, uint8_t flags);
void i686_vm_file_flags_clear(uint32_t gva, size_t len, uint8_t flags);
uint8_t i686_vm_file_flags(uint32_t gva);

/* Promote covered PAGE_COW_CLEAN sub-pages to PAGE_COW_DIRTY in place at
 * the exact same HVA (5.1.1). Returns the number of pages promoted. HVA
 * stability is the invariant the unit test pins: callers re-derive
 * i686_vm32_hva() before and after and require equality. */
size_t i686_vm_file_promote_cow(uint32_t gva, size_t len);

/* Populate HVA bytes for a MAP_PRIVATE file mapping at mmap time via
 * pread64(fd, HVA, ...) and mark the span PAGE_COW_CLEAN with write_tag
 * off (5.1.1, H > 4096 path). Returns 0 on success, -errno on failure. */
int i686_vm_file_map_private(uint64_t arena_base, uint32_t gva, size_t len,
                             int fd, uint64_t file_offset);

/* Ordered shrink-then-regrow hook (5.1.3): on ftruncate(fd, S_shrink),
 * discard (zero + mark CLEAN) MAP_PRIVATE pages wholly at or past
 * align_up(S_shrink); partial final dirty pages are preserved.
 * RC-U3: shrink_size is a FILE OFFSET (not a guest VA); map_file_offset
 * translates it into the mapping (cut = map_start + align_up(shrink -
 * file_offset), clamped to the map). */
void i686_vm_file_note_shrink(uint64_t arena_base, uint32_t map_start,
                              size_t map_len, uint64_t map_file_offset,
                              uint64_t shrink_size);

/* Pure cut computation for the shrink hook: the first guest VA at or
 * past the shrink point, or map_end when nothing is cut. */
uint32_t i686_vm_file_shrink_cut(uint32_t map_start, size_t map_len,
                                 uint64_t map_file_offset,
                                 uint64_t shrink_size);

/* Track / untrack a file-backed mapping for the pwrite/ftruncate hooks.
 * kind is an i686_backing_kind_t.  Returns 0 on success, -1 when the
 * fixed registry is full (best effort: the hooks then skip the map). */
int i686_vm_file_track_map(int fd, uint32_t gva, size_t len,
                           uint64_t file_offset, uint8_t kind);
int i686_vm_file_untrack_map(uint32_t gva, size_t len);
/* Capacity check for a replacing mapping [gva, gva+len): 0 when untrack
 * would succeed and, if want_track is nonzero, a slot would remain for
 * the new track. No state is changed. */
int i686_vm_file_can_replace(uint32_t gva, size_t len, int want_track);
int i686_vm_file_lookup_map(uint32_t gva, int *out_fd,
                            uint64_t *out_file_offset, uint8_t *out_kind);

/* pwrite hook: re-read overlapped MAP_PRIVATE CLEAN pages from fd so
 * they observe the new file bytes.  Returns pages refreshed. Caller
 * passes the faulting ctx for quiesced copies and JIT invalidation. */
struct i686_ctx;
size_t i686_vm_file_note_pwrite(struct i686_ctx *ctx, int fd,
                                uint64_t file_offset, size_t len);

/* ftruncate hook: shrink every tracked MAP_PRIVATE map on fd to
 * new_size via the shrink hook above.  Returns maps shrunk. */
size_t i686_vm_file_note_ftruncate(int fd, uint64_t new_size);

#endif /* I686RT_VM_FILE_H */
