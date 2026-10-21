/*
 * src/dbt/flags_dbt.c — DBT flags seam (SPEC D6, S3 coordinator fix)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * L3a's fused ALU ops record the lazy descriptor and set in-block NZCV;
 * L3c's condition consumers rebuild NZCV from ctx->eflags. This helper
 * materializes any pending lazy descriptor into ctx->eflags so the
 * rebuild sees architecturally current flags. Emitted code parks the
 * guest GPRs into ctx->gpr[0..7] before the call (AAPCS clobbers
 * x0-x18) and reloads them after.
 */
#include "interp/flags.h"

void i686_dbt_flags_sync(i686_ctx_t *ctx)
{
    if (ctx->lazy_op != I686_FOP_NONE) {
        i686_flags_materialize(ctx);
    }
}
