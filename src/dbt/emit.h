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
    /* C6a dead-flag-elimination seam (frozen, fix campaign): what a
     * flag consumer emitted LATER IN THIS BLOCK may rely on.  ZERO is
     * the memset default and the conservative value.
     *   I686_FLAGS_DEAD   nothing: consumer emits the full sequence
     *                     (park GPRs, blr i686_dbt_flags_sync so any
     *                     pending interpreter descriptor materializes,
     *                     reload, rebuild NZCV from ctx->eflags).
     *   I686_FLAGS_EFLAGS ctx->eflags is architecturally current
     *                     (eager producer ran: shifts/IMUL class, or a
     *                     consumer already materialized): consumer
     *                     rebuilds NZCV WITHOUT the helper call.
     *   I686_FLAGS_NZCV   the last fused ALU op left the architectural
     *                     flags live in A64 NZCV: consumer emits only
     *                     the cond-map consume (the fusion), bumps
     *                     ctx->flags_elided.
     * Producers (fused ALU ops, eager-eflags ops, the sync path itself)
     * maintain this field; when unsure, downgrade — DEAD is always
     * correct.  Block exits require nothing (the ctx descriptor is the
     * architectural state, exactly like the interpreter). */
    enum {
        I686_FLAGS_DEAD = 0,
        I686_FLAGS_EFLAGS = 1,
        I686_FLAGS_NZCV = 2
    } flags_src;
    /* Lane P3 (Wave P) per-insn carrier, set by translate.c before each
     * emitter runs.  insn_pc is the insn's guest PC (mid-block fault
     * exits such as DIV/IDIV need it for the UNDEF exit dest).
     * skip_lazy lets the fault-barrier-safe pre-scan suppress dead
     * emit_lazy() stores in register-only ALU sequences: only fused
     * lazy-descriptor producers consult it (ADD/SUB/CMP/AND/OR/XOR/
     * TEST/NEG); eager producers (shifts, IMUL, ADC/SBB, INC/DEC,
     * rotates, MUL/DIV, SHLD/SHRD, COMIS) always store. */
    uint32_t insn_pc;
    uint8_t  skip_lazy;
} i686_emit_ctx_t;

/* Lifecycle (translate.c owns; frozen for lanes). */
void    i686_emit_begin(i686_emit_ctx_t *e, i686_ctx_t *ctx, uint8_t *code,
                        size_t cap, uint32_t guest_eip);
uint8_t *i686_emit_finish(i686_emit_ctx_t *e, size_t *out_len); /* seal */

/* Shared epilogue: store w0..w7 to ctx->gpr, store exit reason/args from
 * w-reg arguments, ret. Every block ends through exactly one of these. */
void i686_emit_exit(i686_emit_ctx_t *e, uint32_t reason, uint32_t arg,
                    uint32_t dest /* only for BRANCH */);

/* Guest EA materialization: writes the 32-bit guest offset
 * disp + base + (index << scale) into w21, wrapped with UXTW.
 * Does not add xG. Callers address with [x20, w21, uxtw].
 * Segment base is added in w21 when add_seg is set. Clobbers w21 and w22. */
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

/* LOCK-prefixed RMW via LSE atomics (src/dbt/emit_atomic.c, L4c). */
int i686_emit_atomic(i686_emit_ctx_t *e, const x86_insn_t *insn);

/* Lazy flags ABI under DBT (D6): cmp/test/sub/add set an in-block NZCV
 * directly (CMN/SUBS) and mark ctx->lazy_op = I686_FOP_A64NZCV (a new
 * constant local to dbt: materialize = copy NZCV to eflags mask);
 * jcc/setcc/cmovcc fuse on NZCV when lazy_op == that constant, else
 * call the flags.c materializer via helper. Frozen in src/dbt/flags_dbt.h
 * (coordinator-owned). */

#endif /* I686RT_DBT_EMIT_H */
