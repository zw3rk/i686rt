/*
 * src/interp/sse.h — frozen SSE/SSE2 state + MXCSR mapping (Phase 5, D10)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * xmm0..7 live in ctx->xmm[8][16] (frozen offsets).  MXCSR is the
 * authoritative control/status in ctx->mxcsr; the FPCR translation:
 *   MXCSR RC(13-14) -> FPCR(22-23) (same encoding: 0=nearest,1=down,
 *     2=up,3=zero)
 *   MXCSR FTZ(15) -> FPCR.FZ(24); MXCSR DAZ(6) -> FPCR.EPF... v1 keeps
 *     MXCSR emulation pure-C: FTZ/DAZ honoured in the helpers, FPCR is
 *     NOT loaded (the interp uses C double/float math; the DBT maps
 *     MXCSR->FPCR when emitting NEON in H).
 * Exception bits (IE=0..PE=5) accumulate OR'd, never cleared except by
 * ldmxcsr/fxrstor writing zeros.  Lanes must not edit this file.
 */
#ifndef I686RT_SSE_H
#define I686RT_SSE_H

#include <stdint.h>

#include "i686rt.h"

/* helpers shared by interp + dbt emitters */
void     sse_set_xmm(i686_ctx_t *ctx, unsigned reg, const uint8_t v[16]);
void     sse_get_xmm(const i686_ctx_t *ctx, unsigned reg, uint8_t out[16]);
uint32_t sse_get_mxcsr(const i686_ctx_t *ctx);
void     sse_set_mxcsr(i686_ctx_t *ctx, uint32_t v); /* masks reserved */
unsigned sse_round_mode(const i686_ctx_t *ctx);
bool     sse_ftz(const i686_ctx_t *ctx);
bool     sse_daz(const i686_ctx_t *ctx);
#endif
