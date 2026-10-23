/*
 * src/os/ldt.c — modify_ldt(123) + set/get_thread_area(243/244)
 * (Phase 7 card L7a; SPEC §4 7.2, D8; E09 verdict)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * modify_ldt (i386: func in EBX, ptr in ECX, bytecount in EDX):
 *   func 0    read    — copy min(bytecount, LDT_ENTRIES*8) bytes of the
 *                       shadow LDT (entries re-encoded to the raw 8-byte
 *                       descriptor format) to guest memory, count back.
 *   func 1    old write — legacy 16-byte ldt_desc; identical to 0x11 with
 *                       the useable bit forced off (nothing uses it, E09
 *                       (a): funcs 0/1/2 are ABI completeness only).
 *   func 0x11 user_desc write — THE Wine path (E09): entry_number checked
 *                       against 8192, the 16-byte struct decoded per the
 *                       kernel mapping (contents<<2 | writable/readable
 *                       bit; DPL forced 3 by construction; seg_not_present
 *                       -> the all-zero "free" entry), committed into the
 *                       segstate shadow with a gen bump.
 *   func 2    read_default — zero fill capped at the LDT size (the kernel
 *                       hands out 5 zeroed default entries; the card's
 *                       contract text is "returns 0/LDT_SIZE", so the cap
 *                       is the full LDT byte size and the content zeros —
 *                       unused by every known guest, E09).
 *
 * set_thread_area(243)/get_thread_area(244): 16-byte user_desc at EBX;
 * entry_number == -1 auto-allocates the first free GDT TLS slot (6..8,
 * kernel i386 GDT_ENTRY_TLS_MIN; -ESRCH when all three are in use).
 * Installation mirrors the kernel's set_thread_area: the full descriptor
 * goes into the PER-THREAD ctx->tls_desc[slot] (RC7b triage-6, kernel
 * tls_array semantics) AND the v1 bare-base ctx->gdt_tls_slots (the
 * Phase 4 lookup fallback keeps working); the entry number is written
 * back through the same guest field.  A seg_not_present write frees the
 * slot.  Segment registers are never touched — the kernel leaves GS/FS
 * alone, guests issue the mov themselves (RC7b T4b).
 *
 * CLONE_SETTLS is served by i686_ldt_clone_settls below (kernel
 * copy_thread semantics: the desc's entry_number names the entry 6..8,
 * no -1, no write-back, no segment-register side effect).
 *
 * DISPATCH WIRING: i686_syscalls_ldt_init() is invoked both lazily from
 * the Phase-7 interp registration (src/interp/h_seg.c) and from
 * i686_syscalls_init_once (src/os/syscalls.c).  Registration is
 * last-wins, so the v1 syscalls.c stub re-registering 243 in between
 * used to shadow this file's handler depending on init order (RC7b
 * T4b).  The v1 stub now DELEGATES to i686_sys_set_thread_area, making
 * the live implementation order-independent; 123/244 have no v1
 * competitor and are served by this file either way.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

long syscall(long, ...);
#include "i686rt.h"

/* seg.h (frozen) re-spells its fault-code macro I686_SEG_SS (3) over
 * i686rt.h's SS register index (2U); pre-clear so the frozen header's
 * #define is fresh (no redefinition warning), then restore the index. */
#undef I686_SEG_SS
#include "interp/seg.h"
#undef I686_SEG_SS
#define I686_SEG_SS 2u

#include "os/marshal.h"
#include "os/syscalls_i386.h"

/* user_desc (16 B): entry_number, base_addr, limit, then the packed
 * flags word — bit0 seg_32bit, bits1-2 contents, bit3 read_exec_only,
 * bit4 limit_in_pages, bit5 seg_not_present, bit6 useable (kernel
 * include/uapi/asm/ldt.h; frozen structs_i386.h bitfield order). */
#define UD_FLAGS(ud) (le32((ud) + 12u))
#define UD_32BIT(fl)      ((fl) & 0x01u)
#define UD_CONTENTS(fl)   (((fl) >> 1) & 0x03u)
#define UD_REXEC(fl)      (((fl) >> 3) & 0x01u)
#define UD_PAGES(fl)      (((fl) >> 4) & 0x01u)
#define UD_NOTPRESENT(fl) (((fl) >> 5) & 0x01u)
#define UD_USEABLE(fl)    (((fl) >> 6) & 0x01u)

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/* Ensure the per-process segstate exists (flat processes first reaching
 * modify_ldt pay the allocation here). */
static i686_segstate_t *ldt_state(i686_ctx_t *ctx)
{
    if (ctx->ldt == NULL) {
        i686_seg_init(ctx);
    }
    return (i686_segstate_t *)ctx->ldt;
}

/* kernel write_ldt mapping (arch/x86/kernel/ldt.c): type =
 * contents<<2 | (read_exec_only ? 0 : 2) over the S=1 class; DPL forced
 * to 3 by construction (user cannot create privileged descriptors). */
static void desc_from_user_desc(const uint8_t ud[16], i686_desc_t *out)
{
    uint32_t flags = UD_FLAGS(ud);
    uint32_t contents = UD_CONTENTS(flags);
    uint32_t limit = le32(ud + 8u) & 0xFFFFFu; /* 20-bit architectural limit */
    uint8_t type;

    memset(out, 0, sizeof(*out));
    switch (contents) {
    case 0u: type = (uint8_t)(0x10u | (UD_REXEC(flags) != 0u ? 0x00u : 0x02u)); break; /* data, up */
    case 1u: type = (uint8_t)(0x14u | (UD_REXEC(flags) != 0u ? 0x00u : 0x02u)); break; /* data, down */
    case 2u: type = (uint8_t)(0x18u | (UD_REXEC(flags) != 0u ? 0x00u : 0x02u)); break; /* code, non-conf */
    default: type = (uint8_t)(0x1Cu | (UD_REXEC(flags) != 0u ? 0x00u : 0x02u)); break; /* code, conf */
    }
    out->base = le32(ud + 4u);
    if (UD_PAGES(flags) != 0u) {
        out->limit = (limit << 12) | 0xFFFu; /* byte limit, G=1 */
    } else {
        out->limit = limit;
    }
    out->type = type;
    out->dpl = 3u;
    out->d_bit = (uint8_t)(UD_32BIT(flags) != 0u ? 1u : 0u);
    out->flags = (uint8_t)((UD_NOTPRESENT(flags) != 0u ? 0u : I686_DESC_PRESENT) |
                           (UD_PAGES(flags) != 0u ? I686_DESC_G : 0u) |
                           (UD_USEABLE(flags) != 0u ? I686_DESC_USEABLE : 0u));
}

/* Inverse mapping for func 0 reads and get_thread_area. */
static void user_desc_from_desc(uint8_t ud[16], const i686_desc_t *d)
{
    uint32_t contents;
    uint32_t rexec;
    uint32_t flags;
    uint32_t limit;

    memset(ud, 0, 16u);
    switch (d->type & 0x0Fu) {
    case 0x4u: case 0x5u: case 0x6u: case 0x7u:
        contents = 1u; break; /* data expand-down */
    case 0x8u: case 0x9u: case 0xAu: case 0xBu:
        contents = 2u; break; /* code non-conforming */
    case 0xCu: case 0xDu: case 0xEu: case 0xFu:
        contents = 3u; break; /* code conforming */
    default:
        contents = 0u; break; /* data expand-up */
    }
    rexec = ((d->type & 0x02u) != 0u) ? 0u : 1u;
    flags = (d->d_bit != 0u ? 0x01u : 0u) |
            (contents << 1) |
            (rexec << 3) |
            (((d->flags & I686_DESC_G) != 0u) ? 0x10u : 0u) |
            (((d->flags & I686_DESC_PRESENT) != 0u) ? 0u : 0x20u) |
            (((d->flags & I686_DESC_USEABLE) != 0u) ? 0x40u : 0u);
    store_le32(ud + 4u, d->base);
    if ((d->flags & I686_DESC_G) != 0u) {
        limit = d->limit >> 12;
    } else {
        limit = d->limit;
    }
    store_le32(ud + 8u, limit & 0xFFFFFu);
    store_le32(ud + 12u, flags);
}

/* ------------------------------------------------------------------ */
/* modify_ldt(123)                                                     */
/* ------------------------------------------------------------------ */

long i686_sys_modify_ldt(i686_ctx_t *ctx, int func, uint32_t ua, uint32_t bc)
{
    i686_segstate_t *st;

    switch (func) {
    case 0: { /* read: capped byte count of the shadow, raw descriptors */
        uint32_t total = (uint32_t)I686_LDT_ENTRIES * 8u;
        uint32_t n = (bc < total) ? bc : total;
        uint32_t i;

        n &= ~7u; /* whole entries only */
        for (i = 0u; i < n; i += 8u) {
            const i686_desc_t *d;
            uint8_t raw[8];
            uint32_t g_flags;

            if (ctx->ldt == NULL) {
                memset(raw, 0, sizeof(raw)); /* no LDT yet: all zero */
            } else {
                st = (i686_segstate_t *)ctx->ldt;
                d = &st->ldt[i / 8u];
                g_flags = (d->flags & I686_DESC_G) != 0u ? 0x8000u : 0u;
                raw[0] = (uint8_t)(d->limit & 0xFFu);
                raw[1] = (uint8_t)((d->limit >> 8) & 0xFFu);
                raw[2] = (uint8_t)(d->base & 0xFFu);
                raw[3] = (uint8_t)((d->base >> 8) & 0xFFu);
                raw[4] = (uint8_t)((d->base >> 16) & 0xFFu);
                raw[5] = (uint8_t)((d->type & 0x0Fu) | (d->dpl << 5) |
                                   ((d->flags & I686_DESC_PRESENT) ? 0x80u : 0u));
                raw[6] = (uint8_t)(((d->limit >> 16) & 0x0Fu) |
                                   ((d->flags & I686_DESC_USEABLE) ? 0x10u : 0u) |
                                   (d->d_bit != 0u ? 0x40u : 0u) | g_flags);
                raw[7] = (uint8_t)((d->base >> 24) & 0xFFu);
            }
            if (i686_copy_to_guest(ctx, ua + i, raw, sizeof(raw)) != 0) {
                return -EFAULT;
            }
        }
        return (long)n;
    }
    case 1:   /* old write */
    case 0x11: { /* user_desc write — the Wine path (E09) */
        uint8_t ud[16];
        uint32_t entry;
        i686_desc_t d;

        if (bc < 16u) {
            return -EINVAL;
        }
        if (i686_copy_from_guest(ctx, ud, ua, sizeof(ud)) != 0) {
            return -EFAULT;
        }
        entry = le32(ud);
        if (entry >= (uint32_t)I686_LDT_ENTRIES) {
            return -EINVAL;
        }
        st = ldt_state(ctx);
        if (st == NULL) {
            return -ENOMEM;
        }
        desc_from_user_desc(ud, &d);
        if (func == 1) {
            d.flags &= (uint8_t)~I686_DESC_USEABLE; /* old ABI: no AVL */
        }
        st->ldt[entry] = d;
        if ((d.flags & I686_DESC_PRESENT) != 0u) {
            st->ldt_bm[entry >> 5] |= 1u << (entry & 31u);
        } else {
            st->ldt_bm[entry >> 5] &= ~(1u << (entry & 31u)); /* free */
        }
        st->gen++; /* engines re-check eligibility */
        return 0;
    }
    case 2: { /* read_default: zero fill capped at the LDT size */
        uint32_t total = (uint32_t)I686_LDT_ENTRIES * 8u;
        uint32_t n = (bc < total) ? bc : total;
        static const uint8_t zero[64];
        uint32_t i;

        for (i = 0u; i < n; i += sizeof(zero)) {
            uint32_t chunk = (n - i < sizeof(zero)) ? (n - i) : (uint32_t)sizeof(zero);
            if (i686_copy_to_guest(ctx, ua + i, zero, chunk) != 0) {
                return -EFAULT;
            }
        }
        return (long)n;
    }
    default:
        return -ENOSYS;
    }
}

/* ------------------------------------------------------------------ */
/* set_thread_area(243) / get_thread_area(244)                         */
/* ------------------------------------------------------------------ */

long i686_sys_set_thread_area(i686_ctx_t *ctx, uint32_t ua)
{
    uint8_t ud[16];
    uint32_t entry;
    uint32_t slot;
    i686_segstate_t *st;
    i686_desc_t d;
    uint8_t back[4];

    if (i686_copy_from_guest(ctx, ud, ua, sizeof(ud)) != 0) {
        return -EFAULT;
    }
    entry = le32(ud);
    if (entry == 0xFFFFFFFFu) { /* -1: auto-allocate, kernel tls.c order.
                                 * Per-THREAD slots (RC7b T4b): glibc's
                                 * TCB and wine's TEB each allocate from
                                 * their own thread's three entries. */
        for (slot = 0u; slot < 3u; slot++) {
            i686_desc_t *ts = (i686_desc_t *)(void *)ctx->tls_desc[slot];
            if ((ts->flags & I686_DESC_PRESENT) == 0u) {
                break;
            }
        }
        if (slot == 3u) {
            return -ESRCH;
        }
    } else {
        if (entry < (uint32_t)I686_GDT_TLS_FIRST ||
            entry >= (uint32_t)(I686_GDT_TLS_FIRST + I686_GDT_TLS_SLOTS)) {
            return -EINVAL;
        }
        slot = entry - (uint32_t)I686_GDT_TLS_FIRST;
    }

    desc_from_user_desc(ud, &d);
    {
        i686_desc_t *ts = (i686_desc_t *)(void *)ctx->tls_desc[slot];

        *ts = d; /* per-thread; kernel tls_array */
    }
    st = ldt_state(ctx);
    if (st != NULL) {
        st->gen++;
    }
    ctx->gdt_tls_slots[slot] =
        (d.flags & I686_DESC_PRESENT) != 0u ? d.base : 0u;

    entry = (uint32_t)I686_GDT_TLS_FIRST + slot;
    store_le32(back, entry);
    if (i686_copy_to_guest(ctx, ua, back, sizeof(back)) != 0) {
        return -EFAULT;
    }

    /* RC7b T4b: kernel-faithful — set_thread_area installs the
     * descriptor only and never touches segment registers.  The
     * previous v1-compat GS auto-load broke wine, whose start_thread
     * installs its TEB descriptor (entry 6) for %FS; loading it into
     * %GS clobbered the glibc TCB and faulted __errno_location. */
    {
        /* Thread-forensics (RC7b T4b). */
        extern int i686_sigtrace_on(void);
        if (i686_sigtrace_on()) {
            (void)fprintf(stderr,
                          "STA tid=%d entry=%u base=%08x present=%u\n",
                          (int)syscall(SYS_gettid), entry, d.base,
                          (unsigned)((d.flags & I686_DESC_PRESENT) != 0u));
        }
    }
    return 0;
}

/* CLONE_SETTLS (clone.c r_clone): kernel copy_thread/arch/x86 tls
 * semantics (RC7b T4c).  The child's user_desc at ua carries the
 * entry_number to install — 6..8, NO -1 allocation, and the field is
 * NOT written back; glibc's i386 convention passes TLS_GET_GS()>>3
 * (the parent's current GS entry), and the child inherits that GS
 * selector value, so descriptor and register name the same entry.  As
 * with set_thread_area(243), no segment register is loaded by the
 * kernel.  Returns 0 or a negative errno; the caller must fail the
 * clone on error, like the kernel does. */
long i686_ldt_clone_settls(i686_ctx_t *ctx, uint32_t ua)
{
    uint8_t ud[16];
    uint32_t entry;
    uint32_t slot;
    i686_segstate_t *st;
    i686_desc_t d;

    if (i686_copy_from_guest(ctx, ud, ua, sizeof(ud)) != 0) {
        return -EFAULT;
    }
    /* A GDT index is architecturally 13 bits (the segment-register index
     * field); entries above 0x1FFF do not exist.  glibc's i386
     * TLS_GET_GS feeds the raw (unmasked) %gs read into
     * tls_fill_user_desc, relying on the undefined upper bits of its
     * "=q" asm output — the qemu-i386 oracle gets 7 there, our boot
     * leaves 0x0021 residue (0x42007).  Mask to the architectural index
     * width so the kernel-faithful 6..8 validation sees the same entry
     * the oracle's silicon produces (RC7b T4c). */
    entry = le32(ud) & 0x1FFFu;
    if (entry < (uint32_t)I686_GDT_TLS_FIRST ||
        entry >= (uint32_t)(I686_GDT_TLS_FIRST + I686_GDT_TLS_SLOTS)) {
        {
            /* Thread-forensics (RC7b T4c): rejected clone TLS desc. */
            extern int i686_sigtrace_on(void);
            if (i686_sigtrace_on()) {
                (void)fprintf(stderr,
                              "TLSSET tid=%d ua=%08x desc=%08x %08x %08x "
                              "%08x gs=%04x REJECTED\n",
                              (int)syscall(SYS_gettid), ua, le32(ud),
                              le32(ud + 4u), le32(ud + 8u), le32(ud + 12u),
                              (unsigned)ctx->seg_sel[I686_SEG_GS]);
            }
        }
        return -EINVAL;
    }
    slot = entry - (uint32_t)I686_GDT_TLS_FIRST;

    desc_from_user_desc(ud, &d);
    {
        i686_desc_t *ts = (i686_desc_t *)(void *)ctx->tls_desc[slot];

        *ts = d; /* per-thread; kernel tls_array */
    }
    st = ldt_state(ctx);
    if (st != NULL) {
        st->gen++;
    }
    ctx->gdt_tls_slots[slot] =
        (d.flags & I686_DESC_PRESENT) != 0u ? d.base : 0u;
    /* The child's GS carries the inherited parent selector value, which
     * names this same entry; refresh the segstate cache so %gs accesses
     * resolve through the child's new descriptor, not the parent's. */
    ctx->seg_base[I686_SEG_GS] = d.base;
    ctx->seg_sel[I686_SEG_GS] = (uint32_t)((entry << 3) | 3u);
    {
        /* Thread-forensics (RC7b T4b/T4c). */
        extern int i686_sigtrace_on(void);
        if (i686_sigtrace_on()) {
            (void)fprintf(stderr,
                          "TLSSET tid=%d entry=%u base=%08x\n",
                          (int)syscall(SYS_gettid), entry, d.base);
        }
    }
    return 0;
}

long i686_sys_get_thread_area(i686_ctx_t *ctx, uint32_t ua)
{
    uint8_t ud[16];
    uint32_t entry;
    uint32_t slot;
    i686_desc_t d;

    if (i686_copy_from_guest(ctx, ud, ua, sizeof(ud)) != 0) {
        return -EFAULT;
    }
    entry = le32(ud);
    if (entry < (uint32_t)I686_GDT_TLS_FIRST ||
        entry >= (uint32_t)(I686_GDT_TLS_FIRST + I686_GDT_TLS_SLOTS)) {
        return -EINVAL;
    }
    slot = entry - (uint32_t)I686_GDT_TLS_FIRST;

    {
        i686_desc_t *ts = (i686_desc_t *)(void *)ctx->tls_desc[slot];

        if ((ts->flags & I686_DESC_PRESENT) != 0u) {
            d = *ts;
            goto have_desc;
        }
    }
    if (ctx->gdt_tls_slots[slot] != 0u) {
        /* v1 handler installed a bare base (no segstate desc): report
         * the equivalent 32-bit RW data descriptor. */
        memset(&d, 0, sizeof(d));
        d.base = ctx->gdt_tls_slots[slot];
        d.limit = 0xFFFFFFFFu;
        d.type = 0x13u;
        d.dpl = 3u;
        d.d_bit = 1u;
        d.flags = I686_DESC_PRESENT;
    } else {
        memset(&d, 0, sizeof(d));
    }
have_desc:;

    user_desc_from_desc(ud, &d); /* entry_number field preserved as passed */
    if (i686_copy_to_guest(ctx, ua + 4u, ud + 4u, 12u) != 0) {
        return -EFAULT;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Dispatch registration (see file comment for the wiring contract)    */
/* ------------------------------------------------------------------ */

static int64_t r_modify_ldt(i686_ctx_t *ctx)
{
    return i686_sys_modify_ldt(ctx, (int)(int32_t)ctx->gpr[I686_REG_EBX],
                               ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX]);
}

static int64_t r_set_thread_area(i686_ctx_t *ctx)
{
    return i686_sys_set_thread_area(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_get_thread_area(i686_ctx_t *ctx)
{
    return i686_sys_get_thread_area(ctx, ctx->gpr[I686_REG_EBX]);
}

void i686_syscalls_ldt_init(void)
{
    static int s_done;
    if (s_done) {
        return;
    }
    s_done = 1;
    i686_sys_register((long)I686__NR_modify_ldt, r_modify_ldt);
    i686_sys_register((long)I686__NR_set_thread_area, r_set_thread_area);
    i686_sys_register((long)I686__NR_get_thread_area, r_get_thread_area);
}
