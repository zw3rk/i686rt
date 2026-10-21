/*
 * src/interp/interp.h — frozen interpreter API (Phase 1 freeze, SPEC D2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The interpreter is the correctness oracle.  Handlers are per-opcode-id
 * functions registered into a table keyed by i686_op_t; the loop decodes,
 * dispatches, and applies exit reasons.  Unregistered opcodes are NOT
 * errors to assert on (D2): the loop returns I686_EXIT_UNDEF for them.
 */

#ifndef I686RT_INTERP_INTERP_H
#define I686RT_INTERP_INTERP_H

#include <stdint.h>

#include "i686rt.h"
#include "x86/decode.h"

/* Handler return values. */
#define I686_INTERP_CONTINUE 0
/* >0: an I686_EXIT_* reason; the loop performs reason-specific handling
 * (SYSCALL: call i686_handle_syscall then resume; BRANCH/TRAP/FAULT/
 * UNDEF handling per phase) and may stop. */

typedef int (*i686_interp_fn)(i686_ctx_t *ctx, const x86_insn_t *insn);

/* Register a handler for an opcode id (idempotent: last wins).  Called
 * only from per-module init functions at engine startup. */
void i686_interp_register(uint16_t op, i686_interp_fn fn);

/* Run the guest from ctx->eip until a terminal exit (exit_group, fatal
 * fault, fatal undecodable).  Returns the last exit_reason. */
int i686_interp_run(i686_ctx_t *ctx);

/* Execute exactly ONE guest insn (DBT fallback, D2). Returns 0, or the
 * terminal exit reason. */
int i686_interp_step(i686_ctx_t *ctx);

/* DBT engine loop (src/dbt/engine.c). */
int i686_dbt_run(i686_ctx_t *ctx);

/* Per-module handler registration (defined by the handler files). */
void i686_interp_alu_init(void);        /* src/interp/h_alu.c       */
void i686_interp_mov_init(void);        /* src/interp/h_mov.c       */
void i686_interp_branch_init(void);     /* src/interp/h_branch.c    */
void i686_interp_muldiv_init(void);     /* src/interp/h_muldiv.c    */

/* Engine glue implemented in interp.c (frozen names). */
void i686_interp_init_all(void);        /* calls every *_init once  */
const char *i686_op_name(uint16_t op);  /* from generated tables    */

#endif /* I686RT_INTERP_INTERP_H */
