/*
 * src/interp/v86.c — self-contained real-mode (vm86) interpreter (Phase 8, L8a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The v86 fetch/decode/execute loop over the 20-bit real-mode view of the
 * guest window (SPEC §4 8.1, E10).  Kernel references cite torvalds/linux
 * master (2026-10 snapshot): arch/x86/kernel/vm86_32.c (handle_vm86_fault,
 * do_int, save_v86_state, do_sys_vm86) and arch/x86/include/uapi/asm/vm86.h.
 * The mapping to this file follows experiments/E10-vm86/proto.c items 2, 5-9.
 *
 * Semantics pinned by the coordinator freeze (docs/lanes/phase-8.md):
 *  - linear = ((seg << 4) + off) & 0xFFFFF (A20 off), IVT at physical 0x0;
 *    the whole low megabyte is mapped while the loop runs (see low-memory
 *    model below), so the loop itself never takes a host fault.
 *  - int/iret are this file's own IVT semantics (do_int verbatim incl.
 *    BIOSSEG checks, int21_revectored AH match, flags/cs/ip push with IP
 *    already past the `int`), NOT h_seg far transfers.
 *  - The six IOPL-sensitive opcodes (pushf 9c / popf 9d / int cd / iret cf /
 *    cli fa / sti fb) follow handle_vm86_fault verbatim: prefix stream,
 *    vm86dbg TF-pending hook, VIF/VIP via SAFE_MASK 0xDD5, check_vip ->
 *    VM86_STI, force_return_for_pic -> VM86_PICRETURN, TF re-trap ->
 *    VM86_TRAP (is_vm86pus) / pending SIGTRAP.
 *  - Deviation from the raw kernel (freeze): v86 opcode faults exit
 *    VM86_SIGNAL with the equivalent 32-bit signal left pending
 *    (SIGILL for unimplemented/unknown opcodes, SIGSEGV/SIGTRAP where the
 *    kernel's do_trap would raise them), instead of the kernel's
 *    VM86_UNKNOWN default, so the guest's signal machinery handles them
 *    (D2: unknown opcodes never assert).
 *  - ctx->v86 bit0 = 1 and ctx->cs_d = 0 while active; engine-only (D8):
 *    this loop runs on the ctx inside the vm86 syscall handler and never
 *    dispatches DBT blocks.
 *
 * Low-memory model (v86state, this file's ctx->v86state owner):
 *  - A 256-bit page bitmap tracks which 4 KiB pages of [0, 1 MiB) have a
 *    host mapping.  Under a nonzero window base G (offset mode, the
 *    production hl case) every page maps at G + linear and is shared with
 *    the 32-bit view.  Under a zero-base window the host range
 *    [0, 0x10000) is not mappable (mmap_min_addr), so those pages are
 *    served by one private 64 KiB shim mapping; the window part
 *    [0x10000, 0x100000) stays shared.  v86-internal addressing resolves
 *    the shim through v86state, everything else through guest_base.
 *  - Mappings persist for the process lifetime (kernel vm86 users keep
 *    their low memory mapped too).  Region bookkeeping (/proc/self/maps)
 *    deliberately does not track these pages: the vm86 low megabyte is a
 *    real-mode artifact, not a 32-bit mapping.
 *
 * Instruction subset (16-bit defaults; 0x66 switches to 32-bit operands):
 * the six IOPL-sensitive opcodes, traps (cc int3 / ce into), mov r/m,r
 * (88-8b), mov imm (b0-bf, c6/c7), nop (90), ret (c3/cb), call/jmp rel
 * (e8/e9/eb).  0x67 (32-bit addressing) is accepted as a prefix for the
 * IOPL-sensitive ops (kernel handle_vm86_fault scans past it) but makes
 * any executed-subset memory operand fault like an unknown opcode.
 * Everything else: unknown-opcode fault -> pending SIGILL + VM86_SIGNAL.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* Linux value; macOS (strict POSIX) hides it — this file only RUNS on
 * the Linux host, but compiles in macOS unit-test builds too. */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x20
#endif

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

/* ------------------------------------------------------------------ */
/* Per-process state + low-megabyte mapping                            */
/* ------------------------------------------------------------------ */

static i686_v86state_t *v86_state(i686_ctx_t *ctx)
{
    i686_v86state_t *vs = (i686_v86state_t *)ctx->v86state;
    if (vs == NULL) {
        vs = (i686_v86state_t *)calloc(1U, sizeof(*vs));
        if (vs == NULL) {
            return NULL;
        }
        ctx->v86state = vs;
    }
    return vs;
}

/* True when guest linear page base sits in the window (shared view). */
static int v86_page_in_window(const i686_ctx_t *ctx, uint32_t page)
{
    return (ctx->guest_base != 0ULL) || (page >= (I686_VM86_LOW_HOLE >> 12));
}

/* Existing guest region overlapping [start, end)? (region table is a
 * public ctx field; entries are sorted by start.) */
static int v86_region_overlaps(const i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    size_t i;
    for (i = 0U; i < ctx->region_count; i++) {
        if (ctx->regions[i].end <= start) {
            continue;
        }
        if (ctx->regions[i].start >= end) {
            break;
        }
        return 1;
    }
    return 0;
}

static int v86_map_page_window(i686_ctx_t *ctx, uint32_t page, uint32_t prot)
{
    void  *target = i686_guest_ptr(ctx, page << 12);
    void  *res = mmap(target, I686_PAGE_SIZE, i686_host_prot(ctx, prot),
                      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    return (res == target) ? 0 : -EIO;
}

/* Bring up one 4 KiB page of the low megabyte.  Region-owned pages
 * (mapped by the guest through the normal mmap path, e.g. plain
 * mmap(90) -> sys_misc.c -> rt32_vm_mmap2) are left untouched and
 * SHARED: the region's existing host mapping serves the v86 view, so
 * the 32-bit side and v86 see one memory.  Returns 0 (mapped, shared,
 * or already up), -ENOMEM (shim/mmap failure); -EIO on a failed window
 * mmap.  (Internal: entry pre-map driver; see i686_v86_enter.) */
static int v86_low_map_page(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t page,
                            uint32_t prot)
{
    uint32_t idx = page >> 12;

    if ((vs->low_bits[idx >> 5] & (1U << (idx & 31U))) != 0U) {
        return 0; /* already up */
    }
    if (v86_page_in_window(ctx, idx)) {
        /* Never smash an existing guest mapping: the region owner's
         * mapping IS the shared view.  A PROT_NONE owner would fault on
         * v86 access and surface as a guest SIGSEGV — honest. */
        if (v86_region_overlaps(ctx, page, page + I686_PAGE_SIZE)) {
            vs->low_bits[idx >> 5] |= 1U << (idx & 31U);
            return 0;
        }
        if (v86_map_page_window(ctx, idx, prot) != 0) {
            return -EIO;
        }
    } else {
        /* Zero-base window: [0, 0x10000) is not host-mappable, serve
         * it from the private shim.  One 64 KiB anonymous mapping
         * covers the whole hole (anon memory is lazy). */
        if (vs->low_shim == NULL) {
            void *shim = mmap(NULL, I686_VM86_LOW_HOLE, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (shim == MAP_FAILED) {
                return -ENOMEM;
            }
            vs->low_shim = (uint8_t *)shim;
        }
    }
    vs->low_bits[idx >> 5] |= 1U << (idx & 31U);
    return 0;
}

/* Entry pre-map: best effort over the whole megabyte.  Failures leave
 * the page unmapped; a v86 access to it would take a host fault
 * (delivered as a guest SIGSEGV by the interpreter loop) — honest
 * kernel-like behavior for an unmapped real-mode page.  Never fatal
 * (kernel vm86 does not map anything itself; i686rt's bring-up is a
 * convenience for the common dosemu-style map-after-enter flow). */
static void v86_premap(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint32_t page;
    for (page = 0U; page < I686_VM86_LOW_MEG; page += I686_PAGE_SIZE) {
        (void)v86_low_map_page(ctx, vs, page, PROT_READ | PROT_WRITE);
    }
}

/* v86 linear -> host byte pointer (lin < 1 MiB by construction: the A20
 * mask is applied by every producer below). */
static uint8_t *v86_lin_ptr(const i686_ctx_t *ctx, const i686_v86state_t *vs,
                            uint32_t lin)
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

static uint16_t r16_get(const i686_ctx_t *ctx, unsigned r)
{
    return (uint16_t)(ctx->gpr[r & 7U] & 0xFFFFU);
}

static void r16_set(i686_ctx_t *ctx, unsigned r, uint16_t v)
{
    ctx->gpr[r & 7U] = v; /* 16-bit writes zero-extend (386 semantics) */
}

static uint32_t r32_get(const i686_ctx_t *ctx, unsigned r)
{
    return ctx->gpr[r & 7U];
}

static void r32_set(i686_ctx_t *ctx, unsigned r, uint32_t v)
{
    ctx->gpr[r & 7U] = v;
}

/* Segment register values live in ctx->seg_sel[] (real-mode segment
 * values, not GPR indices). */
static uint16_t seg_get(const i686_ctx_t *ctx, unsigned s)
{
    return ctx->seg_sel[s];
}

static void seg_set(i686_ctx_t *ctx, unsigned s, uint16_t v)
{
    ctx->seg_sel[s] = v;
}

static uint8_t r8_get(const i686_ctx_t *ctx, unsigned r)
{
    uint32_t v = ctx->gpr[r & 3U];
    return (uint8_t)((r < 4U) ? (v & 0xFFU) : ((v >> 8) & 0xFFU));
}

static void r8_set(i686_ctx_t *ctx, unsigned r, uint8_t v)
{
    uint32_t m = (r < 4U) ? 0x000000FFU : 0x0000FF00U;
    uint32_t s = (r < 4U) ? (uint32_t)v : ((uint32_t)v << 8);
    ctx->gpr[r & 3U] = (ctx->gpr[r & 3U] & ~m) | s;
}

/* 16-bit IP view (kernel IP(regs) = low 16 bits of pt.ip). */
static uint16_t v86_ip(const i686_ctx_t *ctx)
{
    return (uint16_t)(ctx->eip & 0xFFFFU);
}

static uint16_t v86_sp(const i686_ctx_t *ctx)
{
    return (uint16_t)(ctx->gpr[I686_REG_ESP] & 0xFFFFU);
}

/* v86 stack arithmetic wraps at 16 bits (kernel handle_vm86_fault
 * computes push/pop addresses from the 16-bit SP view). */

/* ------------------------------------------------------------------ */
/* Memory (little-endian, 20-bit linear, never faults: the megabyte is  */
/* mapped by the time the loop runs)                                    */
/* ------------------------------------------------------------------ */

static uint8_t rd8(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin)
{
    return *v86_lin_ptr(ctx, vs, lin);
}

static void wr8(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin, uint8_t v)
{
    *v86_lin_ptr(ctx, vs, lin) = v;
}

static uint16_t rd16(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin)
{
    uint16_t lo = rd8(ctx, vs, lin);
    uint16_t hi = rd8(ctx, vs, lin + 1U);
    return (uint16_t)(lo | (uint16_t)((uint16_t)hi << 8));
}

static void wr16(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin, uint16_t v)
{
    wr8(ctx, vs, lin, (uint8_t)(v & 0xFFU));
    wr8(ctx, vs, lin + 1U, (uint8_t)(v >> 8));
}

static uint32_t rd32(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin)
{
    uint32_t b0 = rd8(ctx, vs, lin);
    uint32_t b1 = rd8(ctx, vs, lin + 1U);
    uint32_t b2 = rd8(ctx, vs, lin + 2U);
    uint32_t b3 = rd8(ctx, vs, lin + 3U);
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
}

static void wr32(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t lin, uint32_t v)
{
    wr8(ctx, vs, lin, (uint8_t)(v & 0xFFU));
    wr8(ctx, vs, lin + 1U, (uint8_t)((v >> 8) & 0xFFU));
    wr8(ctx, vs, lin + 2U, (uint8_t)((v >> 16) & 0xFFU));
    wr8(ctx, vs, lin + 3U, (uint8_t)((v >> 24) & 0xFFU));
}

/* Real-mode linear: (seg << 4) + off, A20 off (mask to 20 bits). */
static uint32_t v86_lin(uint16_t seg, uint32_t off)
{
    return (((uint32_t)seg << 4) + off) & 0xFFFFFU;
}

/* 16-bit instruction fetch; IP wraps at 16 bits. */
static uint8_t fetch8(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint8_t b = rd8(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_CS), v86_ip(ctx)));
    ctx->eip = (ctx->eip + 1U) & 0xFFFFU;
    return b;
}

static uint16_t fetch16(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint16_t lo = fetch8(ctx, vs);
    uint16_t hi = fetch8(ctx, vs);
    return (uint16_t)(lo | (uint16_t)((uint16_t)hi << 8));
}

static uint32_t fetch32(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint32_t lo = fetch16(ctx, vs);
    uint32_t hi = fetch16(ctx, vs);
    return lo | (hi << 16);
}

/* Stack push/pop at ss:sp (width by operand size). */
static void pushw(i686_ctx_t *ctx, i686_v86state_t *vs, uint16_t v)
{
    uint16_t sp = (uint16_t)(v86_sp(ctx) - 1U);
    wr8(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp), (uint8_t)(v >> 8));
    sp = (uint16_t)(sp - 1U);
    wr8(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp), (uint8_t)(v & 0xFFU));
    r16_set(ctx, I686_REG_ESP, sp);
}

static void pushl(i686_ctx_t *ctx, i686_v86state_t *vs, uint32_t v)
{
    uint16_t sp = (uint16_t)(v86_sp(ctx) - 4U);
    wr32(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp), v);
    r16_set(ctx, I686_REG_ESP, sp);
}

static uint16_t popw(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint16_t sp = v86_sp(ctx);
    uint16_t v = rd16(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp));
    r16_set(ctx, I686_REG_ESP, (uint16_t)(sp + 2U));
    return v;
}

static uint32_t popl(i686_ctx_t *ctx, i686_v86state_t *vs)
{
    uint16_t sp = v86_sp(ctx);
    uint32_t v = rd32(ctx, vs, v86_lin(seg_get(ctx, I686_SEG_SS), sp));
    r16_set(ctx, I686_REG_ESP, (uint16_t)(sp + 4U));
    return v;
}

/* ------------------------------------------------------------------ */
/* Virtual interrupt flags (kernel set_IF/clear_IF/get_vflags/set_vflags_*)
 * ------------------------------------------------------------------ */

static void set_IF(i686_vm86_enter_t *ks)
{
    ks->veflags |= I686_EF_VIF;
}

static void clear_IF(i686_vm86_enter_t *ks)
{
    ks->veflags &= ~I686_EF_VIF;
}

/* Guest-visible flags: RETURN_MASK image, IF from VIF, IOPL forced on,
 * cpu_type-masked VEFLAGS bits layered on top (kernel get_vflags). */
static uint32_t get_vflags(i686_ctx_t *ctx, i686_vm86_enter_t *ks)
{
    uint32_t f = i686_flags_read(ctx) & I686_VM86_RETURN_MASK;
    if ((ks->veflags & I686_EF_VIF) != 0U) {
        f |= I686_EF_IF;
    }
    f |= I686_EF_IOPL;
    return f | (ks->veflags & ks->veflags_mask);
}

/* kernel set_flags: copy `new`'s bits into `flags` within `mask`. */
static uint32_t set_flags(uint32_t flags, uint32_t new, uint32_t mask)
{
    return (flags & ~mask) | (new & mask);
}

/* kernel set_vflags_long (popf/iret with 32-bit operand). */
static void set_vflags_long(i686_ctx_t *ctx, i686_vm86_enter_t *ks, uint32_t new)
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
static void set_vflags_short(i686_ctx_t *ctx, i686_vm86_enter_t *ks, uint16_t new)
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

static int is_revectored(unsigned n, const uint32_t map[8])
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
static long v86_fault_sigill(i686_ctx_t *ctx)
{
    ctx->pending_signals |= (uint64_t)1U << (4U - 1U); /* SIGILL */
    return I686_VM86_SIGNAL;
}

/* kernel handle_vm86_trap(trapno 1/3) without is_vm86pus delivers the
 * signal to the process (freeze: pending + VM86_SIGNAL). */
static long v86_fault_sig(i686_ctx_t *ctx, int sig)
{
    ctx->pending_signals |= (uint64_t)1U << (uint32_t)(sig - 1);
    return I686_VM86_SIGNAL;
}

/* ------------------------------------------------------------------ */
/* do_int — kernel verbatim (vm86_32.c:494-525)                        */
/* ------------------------------------------------------------------ */

static long do_int(i686_ctx_t *ctx, i686_v86state_t *vs, i686_vm86_enter_t *ks,
                   unsigned i)
{
    uint32_t segoffs;

    if (seg_get(ctx, I686_SEG_CS) == I686_VM86_BIOSSEG) {
        goto cannot_handle;
    }
    if (is_revectored(i, ks->int_revectored)) {
        goto cannot_handle;
    }
    if (i == 0x21U &&
        is_revectored((r32_get(ctx, I686_REG_EAX) >> 8) & 0xFFU,
                      ks->int21_revectored)) {
        goto cannot_handle;
    }
    segoffs = rd32(ctx, vs, ((uint32_t)i << 2) & 0xFFFFFU); /* IVT at i*4 */
    if ((segoffs >> 16) == I686_VM86_BIOSSEG) {
        goto cannot_handle;
    }
    pushw(ctx, vs, (uint16_t)get_vflags(ctx, ks));
    pushw(ctx, vs, seg_get(ctx, I686_SEG_CS));
    pushw(ctx, vs, v86_ip(ctx));
    seg_set(ctx, I686_SEG_CS, (uint16_t)(segoffs >> 16));
    ctx->eip = segoffs & 0xFFFFU;
    /* clear_TF / clear_IF / clear_AC (clear_IF clears VEFLAGS.VIF). */
    ctx->eflags &= ~(I686_EF_TF | I686_EF_AC);
    clear_IF(ks);
    return V86_CONT;

cannot_handle:
    return I686_VM86_INTX_CODE(i); /* guest regs intact, IP past the int */
}

/* ------------------------------------------------------------------ */
/* One fetch/decode/execute step                                       */
/* ------------------------------------------------------------------ */

/* 16-bit ModRM EA: returns 0 with (seg, off) filled, -1 for mod == 3
 * (register form: caller decodes the reg fields), faults (VM86_SIGNAL)
 * for the unsupported 32-bit-addressing case.  seg_default: SS for the
 * bp-based forms ([bp+si], [bp+di], [bp+disp]), DS otherwise. */
static long modrm_ea(i686_ctx_t *ctx, i686_v86state_t *vs, uint16_t ov_seg,
                     int has_ov, uint8_t modrm, uint16_t *seg, uint16_t *off)
{
    static const uint8_t rm16_base[8] = {
        3, 3, 5, 5, 6, 6, 5, 3 /* bx, bx, bp, bp, si, di, bp, bx */
    };
    static const uint8_t rm16_idx[8] = {
        6, 7, 6, 7, 0xFF, 0xFF, 0xFF, 0xFF /* si, di, si, di, -, -, -, - */
    };
    uint8_t mod = (uint8_t)(modrm >> 6);
    uint8_t rm = (uint8_t)(modrm & 7U);
    uint16_t base = 0, disp = 0;

    if (mod == 3U) {
        return -1;
    }
    if (mod == 0U && rm == 6U) {
        /* [disp16]: direct 16-bit displacement, NO base register. */
        disp = fetch16(ctx, vs);
    } else {
        base = r16_get(ctx, rm16_base[rm]);
        if (rm16_idx[rm] != 0xFFU) {
            base = (uint16_t)(base + r16_get(ctx, rm16_idx[rm]));
        }
        if (mod == 1U) {
            disp = (uint16_t)(int16_t)(int8_t)fetch8(ctx, vs);
        } else if (mod == 2U) {
            disp = fetch16(ctx, vs);
        }
    }
    *off = (uint16_t)(base + disp);
    if (has_ov) {
        *seg = ov_seg;
    } else {
        *seg = ((rm == 2U || rm == 3U || rm == 6U) && mod != 0U)
                   ? seg_get(ctx, I686_SEG_SS)
                   : seg_get(ctx, I686_SEG_DS);
    }
    return 0;
}

/* TF single-step re-trap after a fault-class op (vm86_fault_return). */
static long v86_tf_trap(i686_ctx_t *ctx, i686_vm86_enter_t *ks)
{
    if (ks->is_vm86pus != 0U) {
        return I686_VM86_TRAP_CODE(1);
    }
    return v86_fault_sig(ctx, 5); /* SIGTRAP */
}

static long v86_step(i686_ctx_t *ctx, i686_v86state_t *vs, i686_vm86_enter_t *ks)
{
    uint32_t orig_flags = i686_flags_read(ctx);
    uint32_t data32 = 0;
    uint16_t ov_seg = 0;
    int has_ov = 0;
    uint8_t op;
    int pref_done = 0;

    /* Prefix stream (kernel handle_vm86_fault scan, vm86_32.c:569-583). */
    do {
        op = fetch8(ctx, vs);
        switch (op) {
        case 0x66: /* 32-bit operand size */
            data32 = 1;
            break;
        case 0x67: /* 32-bit address size: skipped for the fault-class
                    * ops below; the executed subset rejects it */
            break;
        case 0x2e: /* CS */
            ov_seg = seg_get(ctx, I686_SEG_CS); has_ov = 1;
            break;
        case 0x3e: /* DS */
            ov_seg = seg_get(ctx, I686_SEG_DS); has_ov = 1;
            break;
        case 0x26: /* ES */
            ov_seg = seg_get(ctx, I686_SEG_ES); has_ov = 1;
            break;
        case 0x36: /* SS */
            ov_seg = seg_get(ctx, I686_SEG_SS); has_ov = 1;
            break;
        case 0x64: /* FS */
            ov_seg = seg_get(ctx, I686_SEG_FS); has_ov = 1;
            break;
        case 0x65: /* GS */
            ov_seg = seg_get(ctx, I686_SEG_GS); has_ov = 1;
            break;
        case 0xf2: /* repnz */
        case 0xf3: /* rep */
            break;
        default:
            pref_done = 1;
            break;
        }
    } while (pref_done == 0);

    switch (op) {
    /* ---------------- IOPL-sensitive fault class ------------------- */
    case 0x9c: /* pushf */
        if (data32 != 0U) {
            pushl(ctx, vs, get_vflags(ctx, ks));
        } else {
            pushw(ctx, vs, (uint16_t)get_vflags(ctx, ks));
        }
        goto vm86_fault_return;

    case 0x9d: { /* popf */
        uint32_t newflags = (data32 != 0U) ? popl(ctx, vs) : popw(ctx, vs);
        if (ks->vm86dbg_active != 0U && ks->vm86dbg_TFpendig != 0U) {
            newflags |= I686_EF_TF; /* CHECK_IF_IN_TRAP */
        }
        if (data32 != 0U) {
            set_vflags_long(ctx, ks, newflags);
        } else {
            set_vflags_short(ctx, ks, (uint16_t)newflags);
        }
        goto check_vip;
    }

    case 0xcd: { /* int imm8 */
        unsigned intno = fetch8(ctx, vs);
        if (ks->vm86dbg_active != 0U &&
            ((1U << (intno & 7U)) & ks->vm86dbg_intxxtab[intno >> 3]) != 0U) {
            return I686_VM86_INTX_CODE(intno);
        }
        return do_int(ctx, vs, ks, intno);
    }

    case 0xcf: { /* iret */
        uint32_t newip, newcs, newflags;
        if (data32 != 0U) {
            newip = popl(ctx, vs);
            newcs = popl(ctx, vs);
            newflags = popl(ctx, vs);
        } else {
            newip = popw(ctx, vs);
            newcs = popw(ctx, vs);
            newflags = popw(ctx, vs);
        }
        ctx->eip = (data32 != 0U) ? newip : (newip & 0xFFFFU);
        seg_set(ctx, I686_SEG_CS, (uint16_t)newcs);
        if (ks->vm86dbg_active != 0U && ks->vm86dbg_TFpendig != 0U) {
            newflags |= I686_EF_TF;
        }
        if (data32 != 0U) {
            set_vflags_long(ctx, ks, newflags);
        } else {
            set_vflags_short(ctx, ks, (uint16_t)newflags);
        }
        goto check_vip;
    }

    case 0xfa: /* cli */
        clear_IF(ks);
        goto vm86_fault_return;

    case 0xfb: /* sti */
        set_IF(ks);
        goto check_vip;

    /* ---------------- traps (kernel handle_vm86_trap) --------------- */
    case 0xcc: /* int3: #BP -> trap 3 */
        if (ks->is_vm86pus != 0U) {
            return I686_VM86_TRAP_CODE(3);
        }
        return v86_fault_sig(ctx, 5); /* SIGTRAP */

    case 0xce: /* into: #OF (trap 4) when OF set */
        if ((orig_flags & I686_EF_OF) != 0U) {
            if (ks->is_vm86pus != 0U) {
                return do_int(ctx, vs, ks, 4);
            }
            return v86_fault_sig(ctx, 8); /* SIGFPE */
        }
        return V86_CONT;

    /* ---------------- executed subset ------------------------------- */
    case 0x88: /* mov r/m8, r8 */
    case 0x8a: { /* mov r8, r/m8 */
        uint8_t modrm = fetch8(ctx, vs);
        uint16_t seg, off;
        if (modrm_ea(ctx, vs, ov_seg, has_ov, modrm, &seg, &off) != 0) {
            /* register form: 0x88 rm<-reg, 0x8a reg<-rm */
            if (op == 0x88U) {
                r8_set(ctx, modrm & 7U, r8_get(ctx, (modrm >> 3) & 7U));
            } else {
                r8_set(ctx, (modrm >> 3) & 7U, r8_get(ctx, modrm & 7U));
            }
            return V86_CONT;
        }
        if (op == 0x88U) {
            wr8(ctx, vs, v86_lin(seg, off), r8_get(ctx, (modrm >> 3) & 7U));
        } else {
            r8_set(ctx, (modrm >> 3) & 7U, rd8(ctx, vs, v86_lin(seg, off)));
        }
        return V86_CONT;
    }

    case 0x89: /* mov r/m16, r16 (0x66: r/m32, r32) */
    case 0x8b: { /* mov r16, r/m16 */
        uint8_t modrm = fetch8(ctx, vs);
        uint16_t seg, off;
        if (modrm_ea(ctx, vs, ov_seg, has_ov, modrm, &seg, &off) != 0) {
            /* register form: 0x89 rm<-reg, 0x8b reg<-rm */
            unsigned dst = (op == 0x89U) ? (modrm & 7U) : ((modrm >> 3) & 7U);
            unsigned src = (op == 0x89U) ? ((modrm >> 3) & 7U) : (modrm & 7U);
            if (data32 != 0U) {
                r32_set(ctx, dst, r32_get(ctx, src));
            } else {
                r16_set(ctx, dst, r16_get(ctx, src));
            }
            return V86_CONT;
        }
        if (op == 0x89U) {
            if (data32 != 0U) {
                wr32(ctx, vs, v86_lin(seg, off), r32_get(ctx, (modrm >> 3) & 7U));
            } else {
                wr16(ctx, vs, v86_lin(seg, off), r16_get(ctx, (modrm >> 3) & 7U));
            }
        } else {
            if (data32 != 0U) {
                r32_set(ctx, (modrm >> 3) & 7U, rd32(ctx, vs, v86_lin(seg, off)));
            } else {
                r16_set(ctx, (modrm >> 3) & 7U, rd16(ctx, vs, v86_lin(seg, off)));
            }
        }
        return V86_CONT;
    }

    case 0xc6: /* mov r/m8, imm8 */
    case 0xc7: { /* mov r/m16, imm16 (0x66: imm32) */
        uint8_t modrm = fetch8(ctx, vs);
        uint16_t seg, off;
        long is_mem = modrm_ea(ctx, vs, ov_seg, has_ov, modrm, &seg, &off);
        if (op == 0xc6U) {
            uint8_t imm = fetch8(ctx, vs);
            if (is_mem != 0) {
                r8_set(ctx, modrm & 7U, imm);
            } else {
                wr8(ctx, vs, v86_lin(seg, off), imm);
            }
        } else {
            uint32_t imm = (data32 != 0U) ? fetch32(ctx, vs) : fetch16(ctx, vs);
            if (is_mem != 0) {
                if (data32 != 0U) {
                    r32_set(ctx, modrm & 7U, imm);
                } else {
                    r16_set(ctx, modrm & 7U, (uint16_t)imm);
                }
            } else if (data32 != 0U) {
                wr32(ctx, vs, v86_lin(seg, off), imm);
            } else {
                wr16(ctx, vs, v86_lin(seg, off), (uint16_t)imm);
            }
        }
        return V86_CONT;
    }

    case 0xb0: case 0xb1: case 0xb2: case 0xb3: /* mov r8, imm8 */
    case 0xb4: case 0xb5: case 0xb6: case 0xb7:
        r8_set(ctx, (unsigned)(op - 0xb0U), fetch8(ctx, vs));
        return V86_CONT;

    case 0xb8: case 0xb9: case 0xba: case 0xbb: /* mov r16, imm16 */
    case 0xbc: case 0xbd: case 0xbe: case 0xbf: /* (0x66: mov r32, imm32) */
        if (data32 != 0U) {
            r32_set(ctx, (unsigned)(op - 0xb8U), fetch32(ctx, vs));
        } else {
            r16_set(ctx, (unsigned)(op - 0xb8U), fetch16(ctx, vs));
        }
        return V86_CONT;

    case 0x90: /* nop */
        return V86_CONT;

    case 0xc3: { /* ret near */
        ctx->eip = (data32 != 0U) ? popl(ctx, vs) : popw(ctx, vs);
        return V86_CONT;
    }

    case 0xcb: { /* ret far */
        uint32_t newip = (data32 != 0U) ? popl(ctx, vs) : popw(ctx, vs);
        uint32_t newcs = (data32 != 0U) ? popl(ctx, vs) : popw(ctx, vs);
        ctx->eip = (data32 != 0U) ? newip : (newip & 0xFFFFU);
        seg_set(ctx, I686_SEG_CS, (uint16_t)newcs);
        return V86_CONT;
    }

    case 0xe8: { /* call rel16/rel32 */
        uint32_t rel = (data32 != 0U) ? fetch32(ctx, vs) : fetch16(ctx, vs);
        uint32_t next = v86_ip(ctx);
        if (data32 != 0U) {
            pushl(ctx, vs, next);
            ctx->eip = next + rel;
        } else {
            pushw(ctx, vs, (uint16_t)next);
            ctx->eip = (next + (uint16_t)rel) & 0xFFFFU;
        }
        return V86_CONT;
    }

    case 0xe9: { /* jmp rel16/rel32 */
        uint32_t rel = (data32 != 0U) ? fetch32(ctx, vs) : fetch16(ctx, vs);
        if (data32 != 0U) {
            ctx->eip = v86_ip(ctx) + rel;
        } else {
            ctx->eip = (v86_ip(ctx) + (uint16_t)rel) & 0xFFFFU;
        }
        return V86_CONT;
    }

    case 0xeb: { /* jmp rel8 */
        uint16_t rel = (uint16_t)(int16_t)(int8_t)fetch8(ctx, vs);
        ctx->eip = (v86_ip(ctx) + rel) & 0xFFFFU;
        return V86_CONT;
    }

    default:
        /* Unknown/unimplemented opcode (incl. hlt, port IO, 0x0F two-byte
         * ops): kernel would #GP/#UD into handle_vm86_fault's default;
         * the freeze routes it to the guest signal path instead. */
        return v86_fault_sigill(ctx);
    }

check_vip:
    if ((ks->veflags & (I686_EF_VIP | I686_EF_VIF)) ==
        (I686_EF_VIP | I686_EF_VIF)) {
        return I686_VM86_STI;
    }
vm86_fault_return:
    if (ks->force_return_for_pic != 0U &&
        (ks->veflags & (I686_EF_IF | I686_EF_VIF)) != 0U) {
        return I686_VM86_PICRETURN;
    }
    if ((orig_flags & I686_EF_TF) != 0U) {
        return v86_tf_trap(ctx, ks);
    }
    return V86_CONT;
}

/* ------------------------------------------------------------------ */
/* Enter / exit around the loop                                        */
/* ------------------------------------------------------------------ */

/* veflags_mask per cpu_type (kernel do_sys_vm86; 286: 0, 386: NT|IOPL,
 * 486: +AC, otherwise +ID). */
static uint32_t v86_veflags_mask(uint32_t cpu_type)
{
    uint32_t m = I686_EF_NT | I686_EF_IOPL;
    if (cpu_type == I686_VM86_CPU_286) {
        return 0U;
    }
    if (cpu_type == I686_VM86_CPU_386) {
        return m;
    }
    m |= I686_EF_AC;
    if (cpu_type != I686_VM86_CPU_486) {
        m |= I686_EF_ID;
    }
    return m;
}

long i686_v86_enter(i686_ctx_t *ctx, i686_vm86_enter_t *ks)
{
    i686_v86state_t *vs;
    uint32_t pm_eflags;
    long rc;
    uint64_t guard = 0;
    unsigned i;

    if (ctx == NULL || ks == NULL) {
        return -EFAULT;
    }
    vs = v86_state(ctx);
    if (vs == NULL) {
        return -ENOMEM;
    }
    v86_premap(ctx, vs);

    /* Save the 32-bit context (kernel memcpy of regs32; flags are
     * materialized first per D6). */
    ks->regs32_eflags = i686_flags_read(ctx);
    pm_eflags = ks->regs32_eflags;
    for (i = 0U; i < 8U; i++) {
        ks->regs32_gpr[i] = ctx->gpr[i];
    }
    ks->regs32_eip = ctx->eip;
    for (i = 0U; i < I686_SEG_COUNT; i++) {
        ks->regs32_seg_base[i] = ctx->seg_base[i];
        ks->regs32_seg_sel[i] = ctx->seg_sel[i];
    }
    ks->regs32_cs_d = ctx->cs_d;

    /* Install the v86 machine state (kernel do_sys_vm86 register reads:
     * bx cx dx si di bp ax ip cs flags sp ss es ds fs gs; __null_* and
     * orig_eax never cross). */
    ctx->gpr[I686_REG_EBX] = ks->regs.ebx;
    ctx->gpr[I686_REG_ECX] = ks->regs.ecx;
    ctx->gpr[I686_REG_EDX] = ks->regs.edx;
    ctx->gpr[I686_REG_ESI] = ks->regs.esi;
    ctx->gpr[I686_REG_EDI] = ks->regs.edi;
    ctx->gpr[I686_REG_EBP] = ks->regs.ebp;
    ctx->gpr[I686_REG_EAX] = ks->regs.eax;
    ctx->eip = ks->regs.eip & 0xFFFFU;
    seg_set(ctx, I686_SEG_CS, ks->regs.cs);
    seg_set(ctx, I686_SEG_SS, ks->regs.ss);
    seg_set(ctx, I686_SEG_ES, ks->regs.es);
    seg_set(ctx, I686_SEG_DS, ks->regs.ds);
    seg_set(ctx, I686_SEG_FS, ks->regs.fs);
    seg_set(ctx, I686_SEG_GS, ks->regs.gs);
    for (i = 0U; i < I686_SEG_COUNT; i++) {
        ctx->seg_base[i] = (uint32_t)ctx->seg_sel[i] << 4;
    }
    /* Flags sanitize (kernel verbatim): VEFLAGS = user flags; the real
     * flags keep only the SAFE_MASK bits from the user, the rest from the
     * 32-bit (protected-mode) state, plus VM. */
    ks->veflags = ks->regs.eflags;
    ks->veflags_mask = v86_veflags_mask(ks->cpu_type);
    ctx->eflags = (ks->regs.eflags & I686_VM86_SAFE_MASK) |
                  (pm_eflags & ~I686_VM86_SAFE_MASK) | I686_EF_VM;
    ctx->lazy_op = I686_FOP_NONE;
    ctx->v86 = 1;
    ctx->cs_d = 0;

    rc = V86_CONT;
    while (rc == V86_CONT) {
        rc = v86_step(ctx, vs, ks);
        if (rc == V86_CONT && ++guard > V86_STEP_GUARD) {
            rc = I686_VM86_UNKNOWN; /* emulator runaway bound (see header) */
            break;
        }
    }

    /* Collect the exit register image (kernel save_v86_state put_user
     * list: ebx ecx edx esi edi ebp eax eip cs flags sp ss es ds fs gs;
     * screen_bitmap deliberately untouched).  The raw (materialized)
     * flags go back, VM bit included — kernel regs->pt.flags. */
    ks->regs.ebx = ctx->gpr[I686_REG_EBX];
    ks->regs.ecx = ctx->gpr[I686_REG_ECX];
    ks->regs.edx = ctx->gpr[I686_REG_EDX];
    ks->regs.esi = ctx->gpr[I686_REG_ESI];
    ks->regs.edi = ctx->gpr[I686_REG_EDI];
    ks->regs.ebp = ctx->gpr[I686_REG_EBP];
    ks->regs.eax = ctx->gpr[I686_REG_EAX];
    ks->regs.eip = v86_ip(ctx);
    ks->regs.cs = seg_get(ctx, I686_SEG_CS);
    ks->regs.eflags = i686_flags_read(ctx);
    ks->regs.esp = ctx->gpr[I686_REG_ESP];
    ks->regs.ss = seg_get(ctx, I686_SEG_SS);
    ks->regs.es = seg_get(ctx, I686_SEG_ES);
    ks->regs.ds = seg_get(ctx, I686_SEG_DS);
    ks->regs.fs = seg_get(ctx, I686_SEG_FS);
    ks->regs.gs = seg_get(ctx, I686_SEG_GS);

    /* Restore the 32-bit context. */
    for (i = 0U; i < 8U; i++) {
        ctx->gpr[i] = ks->regs32_gpr[i];
    }
    ctx->eip = ks->regs32_eip;
    ctx->eflags = ks->regs32_eflags;
    for (i = 0U; i < I686_SEG_COUNT; i++) {
        ctx->seg_base[i] = ks->regs32_seg_base[i];
        ctx->seg_sel[i] = ks->regs32_seg_sel[i];
    }
    ctx->cs_d = ks->regs32_cs_d;
    ctx->v86 = 0;
    ctx->lazy_op = I686_FOP_NONE;

    return rc;
}
