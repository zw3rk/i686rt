/*
 * src/dbt/aot/aot.h — Series AOT cache with relative dbt_mem_site_t (Wave U3, lane u3-i686)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4, sections 4.3.3 and 7 (Wave U6 cache,
 * seeded here for i686 as the first Class-A serializer): every
 * translated block carries its purely-relative 24-byte dbt_mem_site_t[]
 * recovery table, so a warm cache survives process restart and PIE
 * rebasing: no absolute host addresses are stored, only block-relative
 * code offsets plus the guest PC delta.
 *
 * No-Double-Side-Effect rule (4.3.3): stack/base-register adjustments
 * performed before the faulting access are undone via sp_rollback_delta;
 * multi-transfer spans are pre-validated instead (a32 LDM/STM rule,
 * referenced here for the shared landing pad).
 */

#ifndef I686RT_DBT_AOT_H
#define I686RT_DBT_AOT_H

#include <stddef.h>
#include <stdint.h>

/* Guest PC resolution mode for a faulting site. */
typedef enum {
    I686_NPC_SEQUENTIAL = 0,  /* guest_npc = guest_pc + insn_len */
    I686_NPC_STATIC_TARGET = 1, /* guest_npc = block_base + npc_delta */
    I686_NPC_DYNAMIC_CTX = 2  /* guest_npc from ctx delay-target slot */
} i686_npc_mode_t;

/* Site flags. */
#define I686_SITE_STORE 0x01u          /* store (else load) */
#define I686_SITE_SIGNED 0x02u        /* sign-extending load */
#define I686_SITE_BE 0x04u            /* big-endian guest (unused on i686) */
#define I686_SITE_IN_DELAY_SLOT 0x08u /* fault inside a delay slot */
#define I686_SITE_PRE_COMMITTED_SP 0x10u /* SP/base written before access */

/* Purely relative 24-byte site record, serialized into AOT payloads. */
typedef struct {
    uint16_t seq_start_offset;  /* .L_tlb_seq_start (ubfx) rel block base */
    uint16_t host_insn_offset;  /* .L_tlb_mem_insn (ldr/str) rel block base */
    uint16_t cont_insn_offset;  /* .L_tlb_cont rel block base */
    uint16_t guest_pc_delta;    /* faulting guest PC rel block->guest_pc_base */
    int32_t npc_delta;          /* static target delta for NPC_STATIC_TARGET */
    uint32_t insn_word;         /* raw guest word (prefix+op key on i686) */
    int16_t sp_rollback_delta;  /* pre-access SP/base adjust to undo on fault */
    uint8_t npc_mode;           /* i686_npc_mode_t */
    uint8_t width;              /* 1, 2, 4, 8, or 16 */
    uint8_t flags;              /* I686_SITE_* */
    uint8_t val_or_dst_reg;     /* arch reg index: load dst / store value */
    uint8_t addr_base_reg;      /* arch base reg index when rollback != 0 */
    uint8_t reserved;
} dbt_mem_site_t;

_Static_assert(sizeof(dbt_mem_site_t) == 24, "dbt_mem_site_t must be 24 bytes");

/* AOT cache format version (v1 for the Class-A rollout). */
#define I686_AOT_VERSION 1u
#define I686_AOT_MAGIC 0x49363836414f5401ULL /* "I686AOT\x01" */

/* Serialized block header (all offsets relative, position-independent). */
typedef struct {
    uint64_t magic;        /* I686_AOT_MAGIC */
    uint32_t version;      /* I686_AOT_VERSION */
    uint32_t guest_base;   /* block->guest_pc_base */
    uint32_t code_len;     /* emitted code bytes that follow */
    uint32_t site_count;   /* dbt_mem_site_t records after the code */
    uint32_t insn_len;     /* faulting guest insn length for NPC_SEQUENTIAL */
    uint32_t crc32;        /* integrity over code + sites (IEEE) */
} i686_aot_block_hdr_t;

/* In-memory site ring for the running translator (v1: fixed ring; the
 * per-block indexed table arrives with the Soft-TLB emitter lane). */
#define I686_AOT_SITE_RING 256u

/* Unknown guest_pc_delta at emit time: the translator patches it once
 * the faulting PC is assigned (see i686_aot_patch_pc_delta). */
#define I686_SITE_PC_UNKNOWN 0xFFFFu

/* Record one stack-access site (PUSH/POP/CALL/RET class). The record is
 * copied; later faults resolve ESP via sp_rollback_delta. Returns the
 * ring slot index for a later pc-delta patch. */
size_t i686_aot_note_stack_site(const dbt_mem_site_t *site);

/* Fill in guest_pc_delta for a previously recorded slot. The patch
 * applies only when the slot still holds the same generation (else the
 * ring has wrapped and the patch is dropped, never misapplied). */
void i686_aot_patch_pc_delta(size_t slot, uint64_t generation,
                             uint16_t guest_pc_delta);

/* Generation counter of a ring slot (pairs with the note return). */
uint64_t i686_aot_site_generation(size_t slot);

/* Shared fault landing-pad emitter (implemented in src/dbt/emit_mov.c to
 * stay beside the stack emitters; declared here to keep the frozen
 * src/dbt/emit.h untouched). Spills w0..w7, w21, and NZCV into ctx. */
struct i686_emit_ctx;
void i686_emit_fault_landing(struct i686_emit_ctx *e);

/* Look up the most recent site with the given insn_word key. Returns 1
 * and copies the record on hit, 0 on miss. */
int i686_aot_find_site(uint32_t insn_word, dbt_mem_site_t *out);

/* Serialize one block (header + code + sites) into buf (cap bytes).
 * Returns bytes written, 0 when cap is insufficient. */
size_t i686_aot_write_block(uint8_t *buf, size_t cap, uint32_t guest_base,
                            const uint8_t *code, size_t code_len,
                            const dbt_mem_site_t *sites, size_t site_count,
                            uint32_t insn_len);

/* Parse + verify one block. Returns bytes consumed, 0 on any error
 * (bad magic/version/crc/truncation: the entry is rejected, never
 * partially applied — mutation rejection per Wave U6). */
size_t i686_aot_read_block(const uint8_t *buf, size_t len,
                           i686_aot_block_hdr_t *out_hdr,
                           const uint8_t **out_code,
                           const dbt_mem_site_t **out_sites);

/* Apply sp_rollback_delta recovery: *sp_reg = *sp_reg - delta undo.
 * Returns the restored SP value (pure helper for the landing pad). */
static inline uint32_t i686_aot_apply_rollback(uint32_t sp, int16_t delta)
{
    return (uint32_t)((int64_t)(int32_t)sp - (int64_t)delta);
}

#endif /* I686RT_DBT_AOT_H */
