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

static dbt_mem_site_t s_ring[I686_AOT_SITE_RING];
static uint64_t s_ring_gen[I686_AOT_SITE_RING];
static uint64_t s_ring_next;

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
