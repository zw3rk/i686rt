/*
 * src/interp/seg.h — frozen segment/descriptor model interface (Phase 7/8)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Coordinator-frozen contract for lanes L7a (seg.c/ldt.c/h_seg.c) and
 * L8a (v86.c/vm86.c).  Implementation notes live in the .c files; this
 * header is the single source of truth for shapes and semantics.
 *
 * Design pins (SPEC §2 D8, §4 7.1/8.1; E09/E10 verdicts):
 *  - Flat 32-bit operation is unchanged: seg_load of a flat code/data
 *    descriptor keeps cs_d=1 and the DBT eligible.  Non-flat or 16-bit
 *    CS (D=0) or any LDT selector in CS routes execution to the
 *    interpreter (D8): the engine checks i686_seg_dbt_eligible() per
 *    block dispatch; no new DBT cache key is introduced this phase.
 *  - LDT: 8192 entries, per-process shadow + free bitmap with entries
 *    0..31 pre-reserved (E09 Wine policy).  Only user_desc (func 0x11)
 *    writes matter to Wine; funcs 0/1/2 are still implemented (SPEC
 *    7.2).  set_thread_area(243)/get_thread_area(244) install/inspect
 *    GDT slots with entry_number=-1 auto-alloc from three slots
 *    (6,7,8) — one clear_thread_area(244 entry) frees.
 *  - vm86 (Phase 8) shares NO descriptor state: real mode linear =
 *    ((seg << 4) + off) & 0xFFFFF, A20 off, IVT at 0:0, defaults
 *    16-bit via ctx->v86 (bit0 = active).  v86 runs interpreter-only.
 *  - Far transfers through code descriptors: lcall/ljmp (0x9a/0xea),
 *    lret/retf (0xcb; 0x66 cross-size per SDM), iret (0xcf; 16-bit
 *    frames when returning to D=0).  Limit/type/dpl checks raise the
 *    guest faults below; sigcontext segment registers (spec 7.1) ride
 *    the existing sigframe builder via i686_seg_sc_encode/sc_decode.
 *
 * Fault encoding shared by the interface (handlers map to guest
 * SIGSEGV with correct trapno/error code, §3.5):
 *   I686_SEG_F_OK     0  no fault
 *   I686_SEG_F_GP     1  #GP(sel)  trapno 13, error = selector bits
 *   I686_SEG_F_NP     2  #NP(sel)  trapno 11 (not-present descriptor)
 *   I686_SEG_F_SS     3  #SS(sel)  trapno 12 (stack limit)
 * (F_-prefixed since I686_SEG_SS is the SS register index in
 * i686rt.h; seg.c additionally keeps local register-index uses.)
 */

#ifndef I686_SEG_H
#define I686_SEG_H

#include <stdbool.h>
#include <stdint.h>

#include "i686rt.h"

#define I686_LDT_ENTRIES 8192u
#define I686_LDT_BM_WORDS (I686_LDT_ENTRIES / 32u)
#define I686_GDT_TLS_SLOTS 3u /* set_thread_area GDT entries 6,7,8 */
#define I686_GDT_TLS_FIRST 6u

/* Decoded descriptor (post-G-granularity byte limit). */
typedef struct i686_desc {
    uint32_t base;   /* linear base */
    uint32_t limit;  /* byte limit (already <<12|0xfff when g=1) */
    uint8_t  type;   /* 4-bit SDM type field */
    uint8_t  dpl;    /* descriptor privilege level */
    uint8_t  d_bit;  /* default size: 1 = 32-bit, 0 = 16-bit */
    uint8_t  flags;  /* bit0 present, bit1 g, bit2 system, bit3 useable */
} i686_desc_t;

#define I686_DESC_PRESENT 0x1u
#define I686_DESC_G       0x2u
#define I686_DESC_SYSTEM  0x4u
#define I686_DESC_USEABLE 0x8u

/* Fault codes (header comment; F_-prefixed, see above). */
#define I686_SEG_F_OK 0
#define I686_SEG_F_GP 1
#define I686_SEG_F_NP 2
#define I686_SEG_F_SS 3

/* Per-process segment state (ctx->ldt points here once i686_seg_init
 * ran; the Phase-0 placeholder comment in i686rt.h is superseded by
 * this header). */
typedef struct i686_segstate {
    /* LDT shadow; entry i valid iff bitmap bit set. */
    uint32_t ldt_bm[I686_LDT_BM_WORDS]; /* word 0 pre-set (0..31) */
    i686_desc_t ldt[I686_LDT_ENTRIES];
    /* GDT TLS slots (set_thread_area); slot j -> entry 6+j. */
    bool  gdt_used[I686_GDT_TLS_SLOTS];
    i686_desc_t gdt_tls[I686_GDT_TLS_SLOTS];
    /* Bump generation: changed whenever any descriptor that affects
     * decoding (CS class) changes; engines re-check eligibility. */
    uint32_t gen;
} i686_segstate_t;

/* --- seg.c (L7a) ------------------------------------------------------- */

void i686_seg_init(i686_ctx_t *ctx); /* allocates + flat defaults */

/* Decode a selector: TI/dpl/RPL; table=0 GDT (TLS slots + flat 4/5),
 * table=1 LDT.  Returns I686_SEG_*; fills *out on OK.  sel==0 is the
 * null selector: OK with a zero descriptor (loads allowed, use faults
 * later per SDM). */
int i686_seg_lookup(const i686_ctx_t *ctx, uint16_t sel, i686_desc_t *out);

/* Segment-register load (mov sreg / pop sreg / les..lss / far transfer):
 * updates ctx->seg_sel[i]/seg_base[i]; validates per SDM (null, TI,
 * type must match data/code class, dpl vs CPL); returns I686_SEG_*. */
int i686_seg_load(i686_ctx_t *ctx, unsigned reg, uint16_t sel);

/* Flat-cs predicate for engines (D8): true iff CS selector is a flat
 * 32-bit code descriptor (the ELF process initial state). */
bool i686_seg_flat_cs(const i686_ctx_t *ctx);

/* --- h_seg.c far transfers (L7a) ---------------------------------------

   All return I686_SEG_* or I686_SEG_OK; on OK the handlers advance
   EIP/ESP themselves per instruction width.  offset/next_eip semantics
   follow the SDM; iret in v86 mode is NOT routed here (v86 owns it). */

int i686_far_call(i686_ctx_t *ctx, uint16_t sel, uint32_t off,
                  uint32_t next_eip);
int i686_far_jmp(i686_ctx_t *ctx, uint16_t sel, uint32_t off);
int i686_far_ret(i686_ctx_t *ctx, unsigned insn_bytes, bool operand32);
/* int N in non-flat/16-bit code: resolvable fault delivery (guest
 * SIGSEGV trapno 13, IP at the int) unless v86 (v86 owns int). */
int i686_far_int_fault(i686_ctx_t *ctx, uint8_t vec);

/* --- ldt.c (L7a) -------------------------------------------------------- */

/* modify_ldt(123): func 0 read byte-count capped, 1 old write, 0x11
 * user_desc write, 2 read_default (returns 0/LDT_SIZE).  Guest VA in,
 * guest VA out.  Returns syscall result or -errno. */
long i686_sys_modify_ldt(i686_ctx_t *ctx, int func, uint32_t ua, uint32_t bc);

/* set_thread_area(243) / get_thread_area(244): user_desc at guest VA;
 * entry_number -1 allocates the first free TLS slot (returned in the
 * struct); -ESI semantics per kernel i386. */
long i686_sys_set_thread_area(i686_ctx_t *ctx, uint32_t ua);
long i686_sys_get_thread_area(i686_ctx_t *ctx, uint32_t ua);

/* --- sigframe segment round-trip (wired into signals_i386.c at S7) ---- */

/* Encode current seg_sel[6] into an i386 sigcontext slot image
 * (guest-order u16 x6: gs fs es ds cs ss). */
void i686_seg_sc_encode(const i686_ctx_t *ctx, uint8_t out[12]);
/* Restore seg_sel from a sigcontext image (returning from handler);
 * validates via i686_seg_load semantics but never faults the guest
 * (kernel reloads blindly; invalid regs fault on next use). */
void i686_seg_sc_decode(i686_ctx_t *ctx, const uint8_t in[12]);

#endif /* I686_SEG_H */
