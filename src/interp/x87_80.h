/*
 * src/interp/x87_80.h — frozen softfloat-extended core API (Phase 5, D9)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3erk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exact 80-bit extended-precision arithmetic, zero dependencies beyond
 * Curated C11 integer math (no host FP for the mantissa/exponent math;
 * host double is allowed ONLY for the m64 conversion edges).  The value
 * type is the 10-byte little-endian encoding of the x87 format:
 *   bytes 0..7  = 64-bit mantissa (explicit integer bit at bit 63)
 *   bytes 8..9  = 16-bit sign(15) + biased exponent(14..0), bias 16383
 * Subnormals, infinities, NaNs (quiet/signaling) and signed zeros are
 * represented exactly as the x87 defines them.  Lanes must not edit.
 */

#ifndef I686RT_X87_80_H
#define I686RT_X87_80_H

#include <stdbool.h>
#include <stdint.h>

typedef uint8_t x87_ext80_t[10]; /* by-value arrays decay; pass pointers */

/* Rounding modes (x87 CW RC encoding): 0 nearest-even, 1 down, 2 up,
 * 3 toward zero.  Precision (24/53/64) applies to computational ops. */
unsigned x87_80_set_round(unsigned rc);   /* returns previous */
unsigned x87_80_set_prec(unsigned bits);  /* returns previous (24/53/64) */

/* Arithmetic.  Each computes a OP b exactly per the current
 * rounding/precision, sets the six exception flags (returned packed in
 * x86 SW bit positions: IE=1, DE=2, ZE=4, OE=8, UE=16, PE=32) and
 * writes the result to *out.  a/b may alias out. */
unsigned x87_80_add(uint8_t out[10], const uint8_t a[10], const uint8_t b[10]);
unsigned x87_80_sub(uint8_t out[10], const uint8_t a[10], const uint8_t b[10]);
unsigned x87_80_mul(uint8_t out[10], const uint8_t a[10], const uint8_t b[10]);
unsigned x87_80_div(uint8_t out[10], const uint8_t a[10], const uint8_t b[10]);
unsigned x87_80_sqrt(uint8_t out[10], const uint8_t a[10]);

/* Comparisons (fld/fucom): return the x87 SW condition-code encoding
 * needed by the caller: sets C3,C2,C0 as FCOM does.  */
void x87_80_fcom(const uint8_t a[10], const uint8_t b[10],
                 bool unordered, unsigned *c3, unsigned *c2, unsigned *c0);

/* Partial remainder (fprem/fprem1): out = a rem b for quotient bits
 * 0..62 (x87 computes up to 63 bits per instruction; *qq holds the
 * low 3 quotient bits for C0-C3; sets DE on unsupported cases). */
unsigned x87_80_fprem(uint8_t out[10], const uint8_t a[10], const uint8_t b[10],
                      uint32_t *qq, bool *reduction_complete);
unsigned x87_80_fprem1(uint8_t out[10], const uint8_t a[10], const uint8_t b[10],
                       uint32_t *qq, bool *reduction_complete);

/* fscale (out = a * 2^trunc(b.exponent-as-int)); fxtract (out1 =
 * exponent-as-extended, out0 = mantissa-as-extended). */
unsigned x87_80_fscale(uint8_t out[10], const uint8_t a[10], const uint8_t b[10]);
unsigned x87_80_fxtract(uint8_t out_sig[10], uint8_t out_exp[10],
                        const uint8_t a[10]);

/* Constants. */
void x87_80_pi(uint8_t out[10]);
void x87_80_log2e(uint8_t out[10]);
void x87_80_ln2(uint8_t out[10]);
void x87_80_ln10(uint8_t out[10]);
void x87_80_zero(uint8_t out[10]);   /* +0 */
void x87_80_one(uint8_t out[10]);
void x87_80_inf(uint8_t out[10], bool sign);
void x87_80_nan(uint8_t out[10], bool signaling, bool sign);

/* Transcendentals: minimum correct-exponent implementations (argument
 * reduction + 64-bit-mantissa polynomial/series) accurate to < 1 ulp on
 * the 64-bit mantissa; exceptions: PE set when inexact. */
unsigned x87_80_f2xm1(uint8_t out[10], const uint8_t a[10]);
unsigned x87_80_fyl2x(uint8_t out[10], const uint8_t a[10], const uint8_t b[10]);
unsigned x87_80_fyl2xp1(uint8_t out[10], const uint8_t a[10], const uint8_t b[10]);
unsigned x87_80_fsin(uint8_t out[10], const uint8_t a[10], bool *stack_fault);
unsigned x87_80_fcos(uint8_t out[10], const uint8_t a[10], bool *stack_fault);
unsigned x87_80_fptan(uint8_t out_tan[10], uint8_t out_one[10],
                      const uint8_t a[10], bool *stack_fault);
unsigned x87_80_fpatan(uint8_t out[10], const uint8_t a[10], const uint8_t b[10]);

/* Load/store conversions (CW precision/rounding honoured on integer
 * stores; IE/PE on inexact). */
unsigned x87_80_from_i32(uint8_t out[10], int32_t v);
unsigned x87_80_from_i64(uint8_t out[10], int64_t v);
unsigned x87_80_from_f32(uint8_t out[10], float v);
unsigned x87_80_from_f64(uint8_t out[10], double v);
unsigned x87_80_to_i32(const uint8_t in[10], int32_t *out, unsigned rc_override);
unsigned x87_80_to_i64(const uint8_t in[10], int64_t *out);
unsigned x87_80_to_f64(const uint8_t in[10], double *out);
unsigned x87_80_to_f32(const uint8_t in[10], float *out);

/* Predicates. */
bool x87_80_is_zero(const uint8_t v[10]);
bool x87_80_is_inf(const uint8_t v[10]);
bool x87_80_is_nan(const uint8_t v[10]);
bool x87_80_is_snan(const uint8_t v[10]);
bool x87_80_sign(const uint8_t v[10]);

#endif /* I686RT_X87_80_H */
