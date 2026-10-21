/*
 * src/dbt/translate.c — block translator core (SPEC §3.3, D2, D6, D7)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Block = straight line until branch/int/hlt/unknown/page end, max 64
 * insns. Unknown opcode -> I686_EXIT_UNDEF with insn length stored so
 * the engine interprets one insn then resumes (D2, never an abort).
 */

#include <stdint.h>
#include <string.h>

#include "dbt/emit.h"
#include "interp/interp.h"
#include "rt32/rt32_a64_emit.h"

#define I686_DBT_MAX_INSNS 64U

/* Fallback table: the interpreter registry is authoritative; for ops the
 * emitter modules decline (return -1), we end the block with UNDEF and
 * the engine loop single-steps via the interpreter. */
int i686_dbt_enabled(void)
{
    return 1;
}

/* Translate one block starting at guest EIP into `code` (cap bytes).
 * Returns bytes emitted, or 0 when nothing could be emitted (engine
 * falls back to the interpreter for this block permanently). */
size_t i686_dbt_translate(i686_ctx_t *ctx, uint32_t eip, uint8_t *code,
                          size_t cap)
{
    i686_emit_ctx_t e;
    uint32_t pc = eip;
    unsigned n;

    i686_emit_begin(&e, ctx, code, cap, eip);

    for (n = 0U; n < I686_DBT_MAX_INSNS; n++) {
        x86_insn_t insn;
        int rc = -1;

        if (x86_decode(ctx, pc, &insn) != 0) {
            i686_emit_exit(&e, I686_EXIT_UNDEF, 0U, pc);
            break;
        }

        /* Category dispatch (lane modules). Order matters only for
         * testing; ids are disjoint. */
        if (insn.pfx_lock != 0U) {
            extern int i686_emit_atomic(i686_emit_ctx_t *,
                                        const x86_insn_t *);
            rc = i686_emit_atomic(&e, &insn);
        } else {
            rc = i686_emit_alu(&e, &insn);
        }
        if (rc < 0) {
            rc = i686_emit_mov(&e, &insn);
        }
        if (rc < 0) {
            rc = i686_emit_branch(&e, &insn);
        }
        if (rc < 0) {
            rc = i686_emit_string(&e, &insn);
        }
        if (rc < 0) {
            /* Not emittable: end block; the engine interprets ONE insn
             * (the D2 fallback) and re-enters translation at pc+len. */
            i686_emit_exit(&e, I686_EXIT_UNDEF, insn.len, pc);
            break;
        }

        pc += insn.len;

        /* Block terminators: branch/trap/syscall exits are emitted by
         * the branch module (it returns 0 after emitting an exit). */
        if (e.block_open == false) {
            break;
        }
        if (i686_page_down(pc) != i686_page_down(eip)) {
            i686_emit_exit(&e, I686_EXIT_BRANCH, 0U, pc);
            break;
        }
    }
    if (n == I686_DBT_MAX_INSNS && e.block_open) {
        i686_emit_exit(&e, I686_EXIT_BRANCH, 0U, pc);
    }

    {
        size_t len;
        (void)i686_emit_finish(&e, &len);
        return len;
    }
}
