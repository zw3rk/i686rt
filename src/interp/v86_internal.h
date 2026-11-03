/*
 * Internal definitions and register/memory/flag helpers for the v86
 * real-mode interpreter (src/interp/v86.c).
 */

#ifndef I686RT_INTERP_V86_INTERNAL_H
#define I686RT_INTERP_V86_INTERNAL_H

#include "interp/flags.h"
#include "interp/v86.h"

/* Internal: keep interpreting (packed VM86_* codes are >= 0). */
#define V86_CONT (-1L)

/* Runaway safety bound (kernel has none; E10 proto used 10^6).  A real
 * DOS/BIOS workload can run long, so the cap is generous; hitting it is
 * a documented emulator-bound exit, not guest semantics. */
#define V86_STEP_GUARD (1ULL << 27)

/* v86.c-owned per-process state (ctx->v86state; see file header). */
typedef struct i686_v86state {
    uint8_t *low_shim;    /* private [0, 0x10000) map when guest_base == 0 */
    uint32_t low_bits[8]; /* page p of [0, 1 MiB) mapped iff bit p set */
} i686_v86state_t;

/* v86 linear -> host byte pointer (lin < 1 MiB by construction: the A20
 * mask is applied by every producer below). */
static inline uint8_t *v86_lin_ptr(const i686_ctx_t *ctx,
                                   const i686_v86state_t *vs, uint32_t lin)
{
    lin &= 0xFFFFFU;
    if (vs->low_shim != NULL && lin < I686_VM86_LOW_HOLE) {
        return vs->low_shim + lin;
    }
    return (uint8_t *)i686_guest_ptr(ctx, lin);
}

/* ------------------------------------------------------------------ */
/* 16-bit real-mode register file                                      */
/* ------------------------------------------------------------------ */

/* 16-bit order: ax cx dx bx sp bp si di (x86 reg encoding). */

static inline uint16_t r16_get(const i686_ctx_t *ctx, unsigned r)
{
    return (uint16_t)(ctx->gpr[r & 7U] & 0xFFFFU);
}

static inline void r16_set(i686_ctx_t *ctx, unsigned r, uint16_t v)
{
    ctx->gpr[r & 7U] = v; /* 16-bit writes zero-extend (386 semantics) */
}

static inline uint32_t r32_get(const i686_ctx_t *ctx, unsigned r)
{
    return ctx->gpr[r & 7U];
}

static inline void r32_set(i686_ctx_t *ctx, unsigned r, uint32_t v)
{
    ctx->gpr[r & 7U] = v;
}

/* Segment register values live in ctx->seg_sel[] (real-mode segment
 * values, not GPR indices). */
static inline uint16_t seg_get(const i686_ctx_t *ctx, unsigned s)
{
    return ctx->seg_sel[s];
}

static inline void seg_set(i686_ctx_t *ctx, unsigned s, uint16_t v)
{
    ctx->seg_sel[s] = v;
}

static inline uint8_t r8_get(const i686_ctx_t *ctx, unsigned r)
{
    uint32_t v = ctx->gpr[r & 3U];
    return (uint8_t)((r < 4U) ? (v & 0xFFU) : ((v >> 8) & 0xFFU));
}

static inline void r8_set(i686_ctx_t *ctx, unsigned r, uint8_t v)
{
    uint32_t m = (r < 4U) ? 0x000000FFU : 0x0000FF00U;
    uint32_t s = (r < 4U) ? (uint32_t)v : ((uint32_t)v << 8);
    ctx->gpr[r & 3U] = (ctx->gpr[r & 3U] & ~m) | s;
}

/* 16-bit IP view (kernel IP(regs) = low 16 bits of pt.ip). */
static inline uint16_t v86_ip(const i686_ctx_t *ctx)
{
    return (uint16_t)(ctx->eip & 0xFFFFU);
}

static inline uint16_t v86_sp(const i686_ctx_t *ctx)
{
    return (uint16_t)(ctx->gpr[I686_REG_ESP] & 0xFFFFU);
}

/* ------------------------------------------------------------------ */
/* Memory (little-endian, 20-bit linear, never faults: the megabyte is  */
/* mapped by the time the loop runs)                                    */
/* ------------------------------------------------------------------ */

static inline uint8_t rd8(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin)
{
    return *v86_lin_ptr(ctx, vs, lin);
}

static inline void wr8(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin,
                       uint8_t v)
{
    *v86_lin_ptr(ctx, vs, lin) = v;
}

static inline uint16_t rd16(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin)
{
    uint16_t lo = rd8(ctx, vs, lin);
    uint16_t hi = rd8(ctx, vs, lin + 1U);
    return (uint16_t)(lo | (uint16_t)((uint16_t)hi << 8));
}

static inline void wr16(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin,
                        uint16_t v)
{
    wr8(ctx, vs, lin, (uint8_t)(v & 0xFFU));
    wr8(ctx, vs, lin + 1U, (uint8_t)(v >> 8));
}

static inline uint32_t rd32(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin)
{
    uint32_t b0 = rd8(ctx, vs, lin);
    uint32_t b1 = rd8(ctx, vs, lin + 1U);
    uint32_t b2 = rd8(ctx, vs, lin + 2U);
    uint32_t b3 = rd8(ctx, vs, lin + 3U);
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

static inline void wr32(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin,
                        uint32_t v)
{
    wr8(ctx, vs, lin, (uint8_t)(v & 0xFFU));
    wr8(ctx, vs, lin + 1U, (uint8_t)((v >> 8) & 0xFFU));
    wr8(ctx, vs, lin + 2U, (uint8_t)((v >> 16) & 0xFFU));
    wr8(ctx, vs, lin + 3U, (uint8_t)((v >> 24) & 0xFFU));
}

/* Real-mode linear: (seg << 4) + off, A20 off (mask to 20 bits). */
static inline uint32_t v86_lin(uint16_t seg, uint32_t off)
{
    return (((uint32_t)seg << 4) + off) & 0xFFFFFU;
}

/* 16-bit instruction fetch; IP wraps at 16 bits. */
static inline uint8_t fetch8(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint8_t b = rd8(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_CS), v86_ip(ctx)));
    ctx->eip = (ctx->eip + 1U) & 0xFFFFU;
    return b;
}

static inline uint16_t fetch16(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint16_t lo = fetch8(ctx, vs);
    uint16_t hi = fetch8(ctx, vs);
    return (uint16_t)(lo | (uint16_t)((uint16_t)hi << 8));
}

static inline uint32_t fetch32(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint32_t lo = fetch16(ctx, vs);
    uint32_t hi = fetch16(ctx, vs);
    return lo | (hi << 16);
}

/* Stack push/pop at ss:sp (width by operand size). */
static inline void pushw(i686_ctx_t *ctx, i686_v86state_t *vs, uint16_t v)
{
    uint16_t sp = (uint16_t)(v86_sp(ctx) - 1U);
    wr8(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp), (uint8_t)(v >> 8));
    sp = (uint16_t)(sp - 1U);
    wr8(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp), (uint8_t)(v & 0xFFU));
    r16_set(ctx, I686_REG_ESP, sp);
}

static inline void pushl(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t v)
{
    uint16_t sp = (uint16_t)(v86_sp(ctx) - 4U);
    wr32(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp), v);
    r16_set(ctx, I686_REG_ESP, sp);
}

static inline uint16_t popw(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint16_t sp = v86_sp(ctx);
    uint16_t v = rd16(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp));
    r16_set(ctx, I686_REG_ESP, (uint16_t)(sp + 2U));
    return v;
}

static inline uint32_t popl(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint16_t sp = v86_sp(ctx);
    uint32_t v = rd32(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp));
    r16_set(ctx, I686_REG_ESP, (uint16_t)(sp + 4U));
    return v;
}

/* ------------------------------------------------------------------ */
/* Virtual interrupt flags (kernel set_IF/clear_IF/get_vflags/set_vflags_*)
 * ------------------------------------------------------------------ */

static inline void set_IF(i686_vm86_enter_t *ks)
{
    ks->veflags |= I686_EF_VIF;
}

static inline void clear_IF(i686_vm86_enter_t *ks)
{
    ks->veflags &= ~I686_EF_VIF;
}

/* Guest-visible flags: RETURN_MASK image, IF from VIF, IOPL forced on,
 * cpu_type-masked VEFLAGS bits layered on top (kernel get_vflags). */
static inline uint32_t get_vflags(i686_ctx_t *ctx, i686_vm86_enter_t *ks)
{
    uint32_t f = i686_flags_read(ctx) & I686_VM86_RETURN_MASK;
    if ((ks->veflags & I686_EF_VIF) != 0U) {
        f |= I686_EF_IF;
    }
    f |= I686_EF_IOPL;
    return f | (ks->veflags & ks->veflags_mask);
}

/* kernel set_flags: copy `new`'s bits into `flags` within `mask`. */
static inline uint32_t set_flags(uint32_t flags, uint32_t new, uint32_t mask)
{
    return (flags & ~mask) | (new & mask);
}

/* kernel set_vflags_long (popf/iret with 32-bit operand). */
static inline void set_vflags_long(i686_ctx_t *ctx, i686_vm86_enter_t *ks,
                                   uint32_t new)
{
    ks->veflags = set_flags(ks->veflags, new, ks->veflags_mask);
    ctx->eflags = set_flags(i686_flags_read(ctx), new, I686_VM86_SAFE_MASK);
    if ((new & I686_EF_IF) != 0U) {
        set_IF(ks);
    } else {
        clear_IF(ks);
    }
}

/* kernel set_vflags_short: the VEFLAGS update touches the low 16 bits
 * (VFLAGS view) only. */
static inline void set_vflags_short(i686_ctx_t *ctx, i686_vm86_enter_t *ks,
                                    uint16_t new)
{
    uint32_t mask16 = ks->veflags_mask & 0xFFFFU;
    ks->veflags = (ks->veflags & ~mask16) | (((uint32_t)new) & mask16);
    ctx->eflags = set_flags(i686_flags_read(ctx), new, I686_VM86_SAFE_MASK);
    if ((new & I686_EF_IF) != 0U) {
        set_IF(ks);
    } else {
        clear_IF(ks);
    }
}

static inline int is_revectored(unsigned n, const uint32_t map[8])
{
    if (n >= 256U) {
        return 0;
    }
    return (int)((map[n >> 5] >> (n & 31U)) & 1U);
}

/* ------------------------------------------------------------------ */
/* Exit shapers                                                        */
/* ------------------------------------------------------------------ */

/* Freeze: v86 opcode faults exit VM86_SIGNAL with the 32-bit signal
 * pending (SIGILL for unknown/undecodable opcodes, D2). */
static inline long v86_fault_sigill(i686_ctx_t *ctx)
{
    (void)__atomic_fetch_or(&ctx->pending_signals,
                            (uint64_t)1U << (4U - 1U), /* SIGILL */
                            __ATOMIC_SEQ_CST);
    return I686_VM86_SIGNAL;
}

/* kernel handle_vm86_trap(trapno 1/3) without is_vm86pus delivers the
 * signal to the process (freeze: pending + VM86_SIGNAL). */
static inline long v86_fault_sig(i686_ctx_t *ctx, int sig)
{
    (void)__atomic_fetch_or(&ctx->pending_signals,
                            (uint64_t)1U << (uint32_t)(sig - 1),
                            __ATOMIC_SEQ_CST);
    return I686_VM86_SIGNAL;
}

#endif /* I686RT_INTERP_V86_INTERNAL_H */
