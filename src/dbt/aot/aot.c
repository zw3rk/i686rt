/*
 * src/dbt/aot/aot.c — AOT block serializer with relative site tables (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Pure C11, position-independent by construction: only block-relative
 * offsets and guest deltas are stored, so payloads survive process
 * restart and PIE rebasing (warm-cache fault/miss recovery). Corrupt or
 * truncated entries are rejected whole (zero partial application).
 *
 * Curated C11, no VLAs, no x18 (pure C11 file).
 */

#include "dbt/aot/aot.h"
#include "vm/vm_file.h"

#include <stdatomic.h>
#include <string.h>

/* IEEE CRC-32 (bitwise; payloads are small). */
static uint32_t aot_crc32(const uint8_t *p, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;
    size_t i;
    unsigned k;
    for (i = 0u; i < len; i++) {
        crc ^= p[i];
        for (k = 0u; k < 8u; k++) {
            crc = (crc & 1u) ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

/* Thread-local (clone/Phase 4): stack-site notes are recorded during
 * translation and replayed on that same thread's faults, so each thread
 * owns its ring exactly like its direct-mapped cache (engine.c).  A
 * shared ring would interleave two threads' sites into each other's
 * slices and corrupt fault recovery. */
static __thread dbt_mem_site_t s_ring[I686_AOT_SITE_RING];
static __thread uint64_t s_ring_gen[I686_AOT_SITE_RING];
static __thread uint64_t s_ring_next;

size_t i686_aot_note_stack_site(const dbt_mem_site_t *site)
{
    size_t slot;
    if (site == NULL) {
        return 0u;
    }
    slot = (size_t)(s_ring_next % I686_AOT_SITE_RING);
    s_ring[slot] = *site;
    s_ring_gen[slot] = s_ring_next;
    s_ring_next++;
    return slot;
}

size_t i686_aot_ring_count(void)
{
    return (size_t)s_ring_next;
}

int i686_aot_ring_at(size_t seq, dbt_mem_site_t *out)
{
    size_t slot;
    if (seq >= (size_t)s_ring_next) {
        return 0;
    }
    slot = seq % I686_AOT_SITE_RING;
    if (s_ring_gen[slot] != (uint64_t)seq) {
        return 0; /* wrapped: never misapply a recycled slot */
    }
    if (out != NULL) {
        *out = s_ring[slot];
    }
    return 1;
}

/* Lane split lock: the same serialization the unaligned CMPXCHG8B path
 * always used, now shared with unaligned LOCK RMWs.  Held-state is
 * per-thread so the fault checkpoint only releases a lock this thread
 * stranded (never a live peer's). */
static _Atomic uint32_t s_split_lock;
static __thread int t_split_held;

void i686_split_lock_acquire(void)
{
    i686_spin_lock(&s_split_lock);
    t_split_held = 1;
}

void i686_split_lock_release(void)
{
    t_split_held = 0;
    i686_spin_unlock(&s_split_lock);
}

void i686_split_lock_release_if_held(void)
{
    if (t_split_held != 0) {
        t_split_held = 0;
        i686_spin_unlock(&s_split_lock);
    }
}

void i686_aot_fork_child(void)
{
    atomic_store_explicit(&s_split_lock, 0U, memory_order_release);
    t_split_held = 0;
}

bool i686_mem_is_unaligned(const void *p, unsigned width)
{
    uintptr_t a;
    unsigned bytes;
    if (width <= 8U) {
        return false;
    }
    bytes = width / 8U;
    a = (uintptr_t)p;
    return (a & (uintptr_t)(bytes - 1U)) != 0U;
}

bool i686_span_mapped_writable(const i686_ctx_t *ctx, uint32_t ea,
                               unsigned bytes)
{
    uint64_t end;
    uint32_t cur;
    size_t i;
    if (ctx == NULL || bytes == 0U) {
        return false;
    }
    end = (uint64_t)ea + (uint64_t)bytes;
    if (end > UINT64_C(0x100000000)) {
        return false;
    }
    if (ctx->vm_reserved[0] != 0U) {
        uint64_t p;
        for (p = (uint64_t)(ea & ~0xFFFU); p < end; p += 0x1000ULL) {
            uint32_t gva = (uint32_t)p;
            if ((i686_vm_file_flags(gva) & 0x80u) == 0u ||
                (i686_vm_file_prot(gva) & 0x03u) != 0x03u) {
                return false;
            }
        }
        return true;
    }
    cur = ea;
    while (cur < (uint32_t)end) {
        bool ok = false;
        for (i = 0U; i < ctx->region_count; i++) {
            const i686_region_t *r = &ctx->regions[i];
            if (r->start <= cur && r->end > cur &&
                (r->prot & 0x3U) == 0x3U) {
                cur = r->end;
                ok = true;
                break;
            }
        }
        if (!ok) {
            return false;
        }
    }
    return true;
}

uint64_t i686_aot_site_generation(size_t slot)
{
    if (slot >= I686_AOT_SITE_RING) {
        return UINT64_C(0xFFFFFFFFFFFFFFFF);
    }
    return s_ring_gen[slot];
}

void i686_aot_patch_pc_delta(size_t slot, uint64_t generation,
                             uint16_t guest_pc_delta)
{
    if (slot < I686_AOT_SITE_RING && s_ring_gen[slot] == generation) {
        s_ring[slot].guest_pc_delta = guest_pc_delta;
    }
}

int i686_aot_find_site(uint32_t insn_word, dbt_mem_site_t *out)
{
    size_t n = (s_ring_next < I686_AOT_SITE_RING) ? s_ring_next
                                                 : I686_AOT_SITE_RING;
    size_t i;
    for (i = 0u; i < n; i++) {
        const dbt_mem_site_t *s =
            &s_ring[(s_ring_next - 1u - i) % I686_AOT_SITE_RING];
        if (s->insn_word == insn_word) {
            if (out != NULL) {
                *out = *s;
            }
            return 1;
        }
    }
    return 0;
}

size_t i686_aot_write_block(uint8_t *buf, size_t cap, uint32_t guest_base,
                            const uint8_t *code, size_t code_len,
                            const dbt_mem_site_t *sites, size_t site_count,
                            uint32_t insn_len)
{
    i686_aot_block_hdr_t hdr;
    size_t need;
    size_t off = sizeof(hdr);
    if (buf == NULL || code == NULL || (site_count != 0u && sites == NULL)) {
        return 0u;
    }
    need = sizeof(hdr) + code_len + site_count * sizeof(*sites);
    if (cap < need) {
        return 0u;
    }
    hdr.magic = I686_AOT_MAGIC;
    hdr.version = I686_AOT_VERSION;
    hdr.guest_base = guest_base;
    hdr.code_len = (uint32_t)code_len;
    hdr.site_count = (uint32_t)site_count;
    hdr.insn_len = insn_len;
    hdr.crc32 = 0u;
    memcpy(buf, &hdr, sizeof(hdr));
    memcpy(buf + off, code, code_len);
    off += code_len;
    if (site_count != 0u) {
        memcpy(buf + off, sites, site_count * sizeof(*sites));
        off += site_count * sizeof(*sites);
    }
    hdr.crc32 = aot_crc32(buf + sizeof(hdr), off - sizeof(hdr));
    memcpy(buf, &hdr, sizeof(hdr));
    return off;
}

size_t i686_aot_read_block(const uint8_t *buf, size_t len,
                           i686_aot_block_hdr_t *out_hdr,
                           const uint8_t **out_code,
                           const dbt_mem_site_t **out_sites)
{
    i686_aot_block_hdr_t hdr;
    size_t need;
    uint32_t crc;
    if (buf == NULL || len < sizeof(hdr)) {
        return 0u;
    }
    memcpy(&hdr, buf, sizeof(hdr));
    if (hdr.magic != I686_AOT_MAGIC || hdr.version != I686_AOT_VERSION) {
        return 0u;
    }
    need = sizeof(hdr) + (size_t)hdr.code_len +
           (size_t)hdr.site_count * sizeof(dbt_mem_site_t);
    if (len < need) {
        return 0u;
    }
    crc = aot_crc32(buf + sizeof(hdr), need - sizeof(hdr));
    if (crc != hdr.crc32) {
        return 0u;
    }
    if (out_hdr != NULL) {
        *out_hdr = hdr;
    }
    if (out_code != NULL) {
        *out_code = buf + sizeof(hdr);
    }
    if (out_sites != NULL) {
        *out_sites = (const dbt_mem_site_t *)(const void *)(buf + sizeof(hdr) +
                                                            hdr.code_len);
    }
    return need;
}
