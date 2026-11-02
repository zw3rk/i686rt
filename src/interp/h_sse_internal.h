/*
 * src/interp/h_sse_internal.h — Shared internal helpers for SSE/SSE2/MMX interpreter
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_H_SSE_INTERNAL_H
#define I686RT_H_SSE_INTERNAL_H

#include <stdint.h>
#include <string.h>

#include "interp/flags.h"
#include "interp/interp.h"
#include "interp/sse.h"

#define MXCSR_IE  0x0001u /* invalid operation                         */
#define MXCSR_DE  0x0002u /* denormal operand                          */
#define MXCSR_ZE  0x0004u /* divide by zero                            */
#define MXCSR_OE  0x0008u /* overflow                                  */
#define MXCSR_UE  0x0010u /* underflow                                 */
#define MXCSR_PE  0x0020u /* precision (inexact)                       */
#define MXCSR_DAZ 0x0040u /* denormals-are-zero input mode            */
#define MXCSR_FTZ 0x8000u /* flush-to-zero output mode                */

#define MXCSR_DEFINED 0xFFFFu

#define F32_QNAN_INDEF 0xFFC00000u
#define F64_QNAN_INDEF 0xFFF8000000000000ull
#define F32_POS_INF    0x7F800000u
#define F32_NEG_INF    0xFF800000u
#define F32_MAX_BITS   0x7F7FFFFFu
#define F64_POS_INF    0x7FF0000000000000ull
#define F64_NEG_INF    0xFFF0000000000000ull
#define F64_MAX_BITS   0x7FEFFFFFFFFFFFFFull

#define I686_NONE 0xFFU

static inline uint32_t f32_bits(float f)
{
    uint32_t u;
    memcpy(&u, &f, 4);
    return u;
}

static inline float f32_from(uint32_t b)
{
    float f;
    memcpy(&f, &b, 4);
    return f;
}

static inline uint64_t f64_bits(double d)
{
    uint64_t u;
    memcpy(&u, &d, 8);
    return u;
}

static inline double f64_from(uint64_t b)
{
    double d;
    memcpy(&d, &b, 8);
    return d;
}

static inline int f32_nan(uint32_t b)
{
    return (b & 0x7F800000u) == 0x7F800000u && (b & 0x007FFFFFu) != 0U;
}

static inline int f32_snan(uint32_t b)
{
    return f32_nan(b) && (b & 0x00400000u) == 0U;
}

static inline int f32_den(uint32_t b)
{
    return (b & 0x7F800000u) == 0U && (b & 0x007FFFFFu) != 0U;
}

static inline int f32_inf(uint32_t b)
{
    return (b & 0x7FFFFFFFu) == 0x7F800000u;
}

static inline int f64_nan(uint64_t b)
{
    return (b & 0x7FF0000000000000ull) == 0x7FF0000000000000ull &&
           (b & 0x000FFFFFFFFFFFFFull) != 0U;
}

static inline int f64_snan(uint64_t b)
{
    return f64_nan(b) && (b & 0x0008000000000000ull) == 0U;
}

static inline int f64_den(uint64_t b)
{
    return (b & 0x7FF0000000000000ull) == 0U && (b & 0xFFFFFFFFFFFFFull) != 0U;
}

static inline uint32_t f32_quiet(uint32_t b)
{
    return b | 0x00400000u;
}

static inline uint64_t f64_quiet(uint64_t b)
{
    return b | 0x0008000000000000ull;
}

static inline int sse_done(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->eip += insn->len;
    return I686_INTERP_CONTINUE;
}

static inline uint32_t sse_ea(const i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t ea = insn->ea_disp;
    uint8_t seg;

    if (insn->ea_base != I686_NONE) {
        ea += ctx->gpr[insn->ea_base & 7U];
    }
    if (insn->ea_index != I686_NONE) {
        ea += ctx->gpr[insn->ea_index & 7U] << insn->ea_scale;
    }
    if (insn->pfx_seg != I686_NONE) {
        seg = insn->pfx_seg;
    } else if (insn->modrm_mod != 0U &&
               (insn->ea_base == I686_REG_EBP || insn->ea_base == I686_REG_ESP ||
                (insn->pfx_addrsize != 0U && insn->ea_base == I686_REG_EBP))) {
        seg = I686_SEG_SS;
    } else {
        seg = I686_SEG_DS;
    }
    if (seg < I686_SEG_COUNT) {
        ea += ctx->seg_base[seg];
    }
    return ea;
}

static inline void sse_ld(const i686_ctx_t *ctx, const x86_insn_t *insn,
                          void *out, unsigned n)
{
    memcpy(out, i686_guest_ptr(ctx, sse_ea(ctx, insn)), n);
}

static inline void sse_st(i686_ctx_t *ctx, const x86_insn_t *insn,
                          const void *in, unsigned n)
{
    memcpy(i686_guest_ptr(ctx, sse_ea(ctx, insn)), in, n);
}

static inline void src128(const i686_ctx_t *ctx, const x86_insn_t *insn,
                          uint8_t out[16])
{
    if (insn->modrm_mod == 3U) {
        sse_get_xmm(ctx, insn->modrm_rm, out);
    } else {
        sse_ld(ctx, insn, out, 16);
    }
}

static inline uint32_t lane32(const uint8_t *v, unsigned i)
{
    uint32_t r;
    memcpy(&r, v + 4U * i, 4);
    return r;
}

static inline void set_lane32(uint8_t *v, unsigned i, uint32_t b)
{
    memcpy(v + 4U * i, &b, 4);
}

static inline uint64_t lane64(const uint8_t *v, unsigned i)
{
    uint64_t r;
    memcpy(&r, v + 8U * i, 8);
    return r;
}

static inline void set_lane64(uint8_t *v, unsigned i, uint64_t b)
{
    memcpy(v + 8U * i, &b, 8);
}

static inline uint64_t mm_rd(const i686_ctx_t *ctx, unsigned r)
{
    uint64_t v;
    memcpy(&v, ctx->x87_st[r & 7U], 8);
    return v;
}

static inline void mm_wr(i686_ctx_t *ctx, unsigned r, uint64_t v)
{
    memcpy(ctx->x87_st[r & 7U], &v, 8);
}

static inline void int_vec_dst_fetch(i686_ctx_t *ctx, const x86_insn_t *insn,
                                     uint8_t d[16], int xmm)
{
    if (xmm) {
        sse_get_xmm(ctx, insn->modrm_reg, d);
    } else {
        uint64_t m = mm_rd(ctx, insn->modrm_reg);
        memset(d, 0, 16);
        memcpy(d, &m, 8);
    }
}

static inline int int_vec_src(i686_ctx_t *ctx, const x86_insn_t *insn,
                              uint8_t v[16], int xmm)
{
    memset(v, 0, 16);
    if (xmm) {
        src128(ctx, insn, v);
    } else if (insn->modrm_mod == 3U) {
        uint64_t m = mm_rd(ctx, insn->modrm_rm);
        memcpy(v, &m, 8);
    } else {
        sse_ld(ctx, insn, v, 8);
    }
    return xmm;
}

static inline void int_vec_dst(i686_ctx_t *ctx, const x86_insn_t *insn,
                               const uint8_t v[16], int xmm)
{
    if (xmm) {
        sse_set_xmm(ctx, insn->modrm_reg, v);
    } else {
        uint64_t m;
        memcpy(&m, v, 8);
        mm_wr(ctx, insn->modrm_reg, m);
    }
}

void i686_interp_sse_int_init(void);

static inline uint32_t sse_f32_src(i686_ctx_t *ctx, uint32_t b)
{
    if (f32_den(b)) {
        if (sse_daz(ctx)) {
            return b & 0x80000000u;
        }
        ctx->mxcsr |= MXCSR_DE;
    }
    return b;
}

static inline uint64_t sse_f64_src(i686_ctx_t *ctx, uint64_t b)
{
    if (f64_den(b)) {
        if (sse_daz(ctx)) {
            return b & 0x8000000000000000ull;
        }
        ctx->mxcsr |= MXCSR_DE;
    }
    return b;
}

#endif /* I686RT_H_SSE_INTERNAL_H */
