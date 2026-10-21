/*
 * src/dbt/emit.h — frozen DBT emitter helper API (Phase 3 freeze, D6/D7)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Register map under the trampoline (D7), fixed:
 *   w0..w7  = EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI (ctx->gpr[0..7] @ 0)
 *   x19     = xCtx (i686_ctx_t *)
 *   x20     = xG   (ctx->guest_base)
 *   x21+    = scratch (caller-saved within the block)
 * EIP lives in ctx; blocks end by storing exit state to ctx and returning.
 * All helpers append to an in-memory code buffer and return the new cursor,
 * or NULL when the literal pool / buffer is exhausted (caller ends block).
 */

#ifndef I686RT_DBT_EMIT_H
#define I686RT_DBT_EMIT_H

#include <stdint.h>

#include "i686rt.h"
#include "rt32_a64_emit.h"
#include "x86/decode.h"

/* Emitted-block exit protocol (mirrors the interpreter's): the epilogue
 * sets ctx->exit_reason (+ exit_arg/exit_dest as applicable), stores the
 * dirty GPRs back to ctx->gpr[0..7], and returns to the trampoline.
 * Reasons: BRANCH (target in ctx->exit_dest, or store EIP for chaining),
 * SYSCALL, UNDEF, FAULT, TRAP, HLT (same constants as interp). */

/* Emission context: rt32_a64_emit's buffer state plus per-block info. */
typedef struct i686_emit_ctx {
    a64_buf_t buf;               /* words/count/cap (a64_emit buffer) */
    i686_ctx_t    *ctx;         /* guest ctx (for constant folding only;
                                   NEVER side-effect guest state at emit) */
    uint32_t       guest_eip;   /* block start EIP (key) */
    size_t         insn_count;  /* emitted so far */
    bool           tso;         /* D5: static per-process; GPR loads/stores
                                   must use LDAPR/STLR class (or LDAR/STLR
                                   base) when true */
    bool           block_open;  /* epilogue emitted yet? */
} i686_emit_ctx_t;

/* Lifecycle (translate.c owns; frozen for lanes). */
void    i686_emit_begin(i686_emit_ctx_t *e, i686_ctx_t *ctx, uint8_t *code,
                        size_t cap, uint32_t guest_eip);
uint8_t *i686_emit_finish(i686_emit_ctx_t *e, size_t *out_len); /* seal */

/* Shared epilogue: store w0..w7 to ctx->gpr, store exit reason/args from
 * w-reg arguments, ret. Every block ends through exactly one of these. */
void i686_emit_exit(i686_emit_ctx_t *e, uint32_t reason, uint32_t arg,
                    uint32_t dest /* only for BRANCH */);

/* Guest EA materialization: emits loads of base/index from w-regs and
 * computes xG + ea into x21 (returns nothing; caller may re-run). Seg
 * base added when the insn needs it (non-flat). Clobbers x21..x23. */
void i686_emit_ea(i686_emit_ctx_t *e, const x86_insn_t *insn, int add_seg);

/* x86 GPR access on the fixed map: wreg(insn->modrm_reg) etc. */
static inline unsigned i686_w(unsigned x86_reg) { return x86_reg & 7U; }
/* 8-bit high half (AH..BH) lives in wN bits 15:8 — same wN register. */

/* Per-category emitter entry points (lane-owned files; translate.c
 * dispatches on insn.op groups — the exact id lists are in
 * docs/lanes/phase-3.md). Each returns 0 on success, -1 when the insn
 * must fall back to interpret-one (D2): translate.c then emits an
 * UNDEF exit with the insn length recorded. */
/* Block translator (src/dbt/translate.c): emits one block starting at
 * eip into code (cap bytes); returns emitted length or 0. */
size_t i686_dbt_translate(i686_ctx_t *ctx, uint32_t eip, uint8_t *code,
                          size_t cap);

/* DBT engine loop (src/dbt/engine.c). */
int i686_dbt_run(i686_ctx_t *ctx);

int i686_emit_alu(i686_emit_ctx_t *e, const x86_insn_t *insn);
int i686_emit_mov(i686_emit_ctx_t *e, const x86_insn_t *insn);
int i686_emit_branch(i686_emit_ctx_t *e, const x86_insn_t *insn);
int i686_emit_string(i686_emit_ctx_t *e, const x86_insn_t *insn);

/* Lazy flags ABI under DBT (D6): cmp/test/sub/add set an in-block NZCV
 * directly (CMN/SUBS) and mark ctx->lazy_op = I686_FOP_A64NZCV (a new
 * constant local to dbt: materialize = copy NZCV to eflags mask);
 * jcc/setcc/cmovcc fuse on NZCV when lazy_op == that constant, else
 * call the flags.c materializer via helper. Frozen in src/dbt/flags_dbt.h
 * (coordinator-owned). */

#endif /* I686RT_DBT_EMIT_H */
