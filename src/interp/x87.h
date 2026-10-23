/*
 * src/interp/x87.h — frozen x87 state-access API (Phase 5, SPEC D9/D10)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Two modes, fixed per process (ctx->x87_80, chosen at startup):
 *  - default: ST(i) holds a double in the low 8 bytes of x87_st[i];
 *    CW honoured for rounding (not precision — always double).
 *  - --x87-80: ST(i) holds an exact 80-bit extended value in the low
 *    10 bytes (little-endian: 8-byte mantissa then 16-bit
 *    sign+exponent); CW precision + rounding fully honoured.
 * MMX aliases the low 8 bytes of each ST slot (raw bits, no
 * interpretation).  All accessors handle both modes; emitters/handlers
 * never touch x87_st[] directly.  Lanes must not edit this file.
 */

#ifndef I686RT_X87_H
#define I686RT_X87_H

#include <stdbool.h>
#include <stdint.h>

#include "i686rt.h"

/* --- register-stack state ------------------------------------------------ */
uint8_t  x87_top(const i686_ctx_t *ctx);            /* 0..7 */
void     x87_set_top(i686_ctx_t *ctx, uint8_t top);
void     x87_push(i686_ctx_t *ctx);                 /* TOP-- (wrap 8) */
void     x87_pop(i686_ctx_t *ctx);                  /* TOP++ (wrap 8) */

/* Logical ST(i) -> physical slot = (TOP + i) & 7. */

/* Read/write the value in ST(i) as double (mode-converting: in 80-bit
 * mode converts the extended value to double, WITHOUT changing state). */
double x87_get_f64(const i686_ctx_t *ctx, unsigned i);
void   x87_set_f64(i686_ctx_t *ctx, unsigned i, double v);

/* 80-bit extended raw access (little-endian 10 bytes).  In default mode
 * x87_get_ext80 converts the stored double UP to extended; x87_set_ext80
 * stores the rounded-to-double value (matching the mode's semantics). */
void    x87_get_ext80(const i686_ctx_t *ctx, unsigned i, uint8_t out[10]);
void    x87_set_ext80(i686_ctx_t *ctx, unsigned i, const uint8_t in[10]);

/* MMX view: 64-bit raw bits of the physical slot (low 8 bytes). */
uint64_t mmx_get(const i686_ctx_t *ctx, unsigned reg);
void     mmx_set(i686_ctx_t *ctx, unsigned reg, uint64_t v);

/* Integer push/pop for fild/fistp families. */
void    x87_set_int(i686_ctx_t *ctx, int64_t v);
int64_t x87_get_int(const i686_ctx_t *ctx, unsigned i); /* rounded per CW */
int64_t x87_get_int_trunc(const i686_ctx_t *ctx, unsigned i); /* FISTTP */

/* --- environment ---------------------------------------------------------- */
/* CW field encodings (x86): RC = bits 10-11 (0=nearest-even,1=down,
 * 2=up,3=trunc); PC = bits 8-9 (0=24-bit,2=53-bit,3=64-bit). */
unsigned x87_round_mode(const i686_ctx_t *ctx); /* 0..3 */
unsigned x87_prec_mode(const i686_ctx_t *ctx);  /* 24/53/64 bits */
void     x87_update_fstat(i686_ctx_t *ctx);     /* TOP bits 11-13 */

/* Status-word exception bits (PE/UE/OE/ZE/DE/IE) set by arithmetic —
 * v1: set on the exact-mode paths; default mode sets ES/bit7 summary
 * only when unmasked (glibc never masks-traps in v1 targets). */
void x87_set_exc(i686_ctx_t *ctx, unsigned bits); /* bits already in
                                                      x86 SW positions */

/* --- m80 <-> m64 conversion helpers (used by fld/fstp + signal frames) */
void   x87_f64_to_ext80(double v, uint8_t out[10]);
double x87_ext80_to_f64(const uint8_t in[10]);

/* --- tag word -------------------------------------------------------------
 * v1 convention: ftag is authoritative only at fxsave/iahf boundaries;
 * x87_sync_tag(ctx) recomputes packed tags (0=valid,1=zero,2=special,
 * 3=empty) from the slots; x87_mark_empty(ctx, i) marks one. */
void x87_sync_tag(i686_ctx_t *ctx);
void x87_mark_empty(i686_ctx_t *ctx, unsigned i);

#endif /* I686RT_X87_H */
