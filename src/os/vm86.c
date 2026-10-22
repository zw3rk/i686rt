/*
 * src/os/vm86.c — vm86old(113) / vm86(166) syscalls and marshalling (L8a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 8 lane L8a (SPEC §4 8.2, docs/lanes/phase-8.md, E10 FINDINGS §1/§5).
 * The ABI mirrors the kernel exactly (torvalds/linux master, 2026-10:
 * arch/x86/kernel/vm86_32.c, arch/x86/include/uapi/asm/vm86.h); the v86
 * engine lives in src/interp/v86.c.
 *
 * Syscalls registered here (i386 numbers, table src/os/syscalls_i386.h):
 *   [113] {"vm86old"} — do_sys_vm86(plus = false): one EBX pointer to a
 *                       struct vm86_struct.
 *   [166] {"vm86"}    — cmd = EBX, arg = ECX: VM86_ENTER(1) /
 *                       VM86_ENTER_NO_BYPASS(2) -> do_sys_vm86(plus =
 *                       true); VM86_PLUS_INSTALL_CHECK(0) -> 0;
 *                       VM86_REQUEST_IRQ(3) -> -ENOSYS and
 *                       VM86_FREE_IRQ(4) / VM86_GET_IRQ_BITS(5) /
 *                       VM86_GET_AND_RESET_IRQ(6) -> -EINVAL (E10 §1.6:
 *                       the IRQ subfunctions bind real host IRQ lines
 *                       and cannot be emulated; no surveyed user reaches
 *                       them without a native i386 kernel).  Other cmds
 *                       -> -EINVAL.
 *
 * Marshalling pins (E10 §1.1, binding):
 *   - Entry copy splits at offsetof(struct vm86_struct, int_revectored):
 *     first regs + flags + screen_bitmap + cpu_type, then the two
 *     revectored bitmaps, then vm86plus only when `plus`.
 *   - is_vm86pus is set kernel-side (never read from the user struct).
 *   - __null_ds..__null_gs and orig_eax are ignored on entry.
 *   - VM86_SCREEN_BITMAP (flags bit0) -> -EINVAL ("no longer supported").
 *   - Exit (kernel save_v86_state): exactly ebx ecx edx esi edi ebp eax
 *     eip cs eflags esp ss es ds fs gs go back to the user struct, with
 *     the exact field widths (cs/ss/es/ds/fs/gs as u16; the __csh..__gsh
 *     pad halves are not written); screen_bitmap is deliberately
 *     preserved; flags/bitmaps/vm86plus are not written.  The packed
 *     exit code is the syscall return, i.e. the 32-bit caller's EAX.
 *   - The kernel's security_mmap_addr(0) -> -EPERM guard has no
 *     equivalent here: guest linear 0 lives at the window base G (E10
 *     §1.1); a zero-base window serves [0, 0x10000) from the v86 shim
 *     (src/interp/v86.c) instead of unmappable host low VA.
 *
 * Low-memory note: kernel vm86 users (dosemu, vbetool) map the real-mode
 * address space themselves before VM86_ENTER.  The guest does the same
 * here through the EXISTING plain mmap(90) implementation (L2e,
 * src/os/sys_misc.c r_old_mmap -> rt32_vm_mmap2), which covers every
 * page-aligned MAP_FIXED request in [0x10000, 1 MiB) — the shared part
 * of the v86 megabyte.  The sub-64 KiB part ([0, 0x10000); IVT, BDA)
 * is not guest-mappable under the frozen rt32 low guard; v86.c's entry
 * pre-map brings it up (window pages, or the private shim under a
 * zero-base window) without needing its own syscall.  This file
 * therefore registers ONLY 113 and 166.
 *
 * Registration is done by i686_sys_vm86_init() below; the coordinator
 * wires it from i686_syscalls_init_once() (src/os/syscalls.c) at S8.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "i686rt.h"
#include "interp/v86.h"
#include "os/marshal.h"
#include "os/syscalls_i386.h"

/* ------------------------------------------------------------------ */
/* Guest struct mirrors (kernel uapi vm86.h; i386 long = u32).         */
/* Only shapes/offsets — copies go field-wise through marshal helpers.  */
/* ------------------------------------------------------------------ */

struct g_vm86_regs {          /* 84 B */
    uint32_t ebx, ecx, edx, esi, edi, ebp, eax;      /* 0x00 */
    uint32_t null_ds, null_es, null_fs, null_gs;     /* 0x1c */
    uint32_t orig_eax;                               /* 0x2c */
    uint32_t eip;                                    /* 0x30 */
    uint16_t cs, csh;                                /* 0x34 */
    uint32_t eflags;                                 /* 0x38 */
    uint32_t esp;                                    /* 0x3c */
    uint16_t ss, ssh;                                /* 0x40 */
    uint16_t es, esh, ds, dsh, fs, fsh, gs, gsh;     /* 0x44 */
};

struct g_revectored {         /* 32 B: 256 bits, bit n = int n revectored */
    uint32_t map[8];
};

struct g_vm86_struct {        /* 160 B */
    struct g_vm86_regs regs;               /* 0x00 */
    uint32_t flags;                        /* 0x54 */
    uint32_t screen_bitmap;                /* 0x58 (preserved on exit) */
    uint32_t cpu_type;                     /* 0x5c */
    struct g_revectored int_revectored;    /* 0x60 <- entry copy split */
    struct g_revectored int21_revectored;  /* 0x80 */
};

struct g_vm86plus_info {      /* 36 B: 4-byte bitfield + 32-byte tab */
    uint32_t bits;   /* bit0 force_return_for_pic, bit1 vm86dbg_active,
                      * bit2 vm86dbg_TFpendig, bits 3..30 unused,
                      * bit31 is_vm86pus (kernel-side) */
    uint8_t  vm86dbg_intxxtab[32];         /* 0x24 */
};

struct g_vm86plus_struct {    /* 196 B */
    struct g_vm86_struct v;                /* 0x000 */
    struct g_vm86plus_info plus;           /* 0x0a0 */
};

_Static_assert(sizeof(struct g_vm86_regs) == 84U, "vm86_regs must be 84 B");
_Static_assert(offsetof(struct g_vm86_struct, int_revectored) == 96U,
               "entry copy must split at offsetof(vm86_struct, int_revectored)");
_Static_assert(sizeof(struct g_vm86_struct) == 160U, "vm86_struct must be 160 B");
_Static_assert(sizeof(struct g_vm86plus_info) == 36U, "vm86plus_info must be 36 B");
_Static_assert(sizeof(struct g_vm86plus_struct) == 196U,
               "vm86plus_struct must be 196 B");

/* Field-by-field guest access (little-endian decode, marshal-bounds-safe). */

static uint32_t g_rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t g_rd16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static void g_wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

static void g_wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
}

/* ------------------------------------------------------------------ */
/* do_sys_vm86 equivalent                                              */
/* ------------------------------------------------------------------ */

static int copy_reg_in(i686_ctx_t *ctx, i686_vm86_enter_t *ks, uint32_t uva)
{
    uint8_t part1[96]; /* up to offsetof(vm86_struct, int_revectored) */
    uint8_t maps[64];

    if (i686_copy_from_guest(ctx, part1, uva, sizeof(part1)) != 0) {
        return -EFAULT;
    }
    /* Registers are read field-by-field (kernel do_sys_vm86): bx cx dx
     * si di bp ax ip cs flags sp ss es ds fs gs; the __null_* halves and
     * orig_eax are ignored on entry. */
    ks->regs.ebx   = g_rd32(part1 + 0x00);
    ks->regs.ecx   = g_rd32(part1 + 0x04);
    ks->regs.edx   = g_rd32(part1 + 0x08);
    ks->regs.esi   = g_rd32(part1 + 0x0c);
    ks->regs.edi   = g_rd32(part1 + 0x10);
    ks->regs.ebp   = g_rd32(part1 + 0x14);
    ks->regs.eax   = g_rd32(part1 + 0x18);
    ks->regs.eip   = g_rd32(part1 + 0x30);
    ks->regs.cs    = g_rd16(part1 + 0x34);
    ks->regs.eflags = g_rd32(part1 + 0x38);
    ks->regs.esp   = g_rd32(part1 + 0x3c);
    ks->regs.ss    = g_rd16(part1 + 0x40);
    ks->regs.es    = g_rd16(part1 + 0x44);
    ks->regs.ds    = g_rd16(part1 + 0x48);
    ks->regs.fs    = g_rd16(part1 + 0x4c);
    ks->regs.gs    = g_rd16(part1 + 0x50);
    ks->flags      = g_rd32(part1 + 0x54);
    /* screen_bitmap (0x58): preserved on exit, never read. */
    ks->cpu_type   = g_rd32(part1 + 0x5c);

    if ((ks->flags & I686_VM86_SCREEN_BITMAP) != 0U) {
        return -EINVAL; /* VM86_SCREEN_BITMAP: no longer supported */
    }
    if (i686_copy_from_guest(ctx, maps, uva + 96U, sizeof(maps)) != 0) {
        return -EFAULT;
    }
    memcpy(ks->int_revectored, maps, 32U);
    memcpy(ks->int21_revectored, maps + 32U, 32U);
    return 0;
}

static int copy_plus_in(i686_ctx_t *ctx, i686_vm86_enter_t *ks, uint32_t uva)
{
    uint8_t plus[68];

    if (i686_copy_from_guest(ctx, plus, uva + sizeof(struct g_vm86_struct),
                             sizeof(plus)) != 0) {
        return -EFAULT;
    }
    ks->force_return_for_pic = ((plus[0] & 0x01U) != 0U) ? 1U : 0U;
    ks->vm86dbg_active       = ((plus[0] & 0x02U) != 0U) ? 1U : 0U;
    ks->vm86dbg_TFpendig     = ((plus[0] & 0x04U) != 0U) ? 1U : 0U;
    /* is_vm86pus is set kernel-side (the user's bit31 is not consulted). */
    ks->is_vm86pus = 1U;
    memcpy(ks->vm86dbg_intxxtab, plus + 4U, 32U);
    return 0;
}

/* Exit writeback: exactly the kernel save_v86_state field list, exact
 * widths; screen_bitmap, flags, bitmaps and vm86plus are not written. */
static int copy_regs_out(i686_ctx_t *ctx, const i686_vm86_enter_t *ks, uint32_t uva)
{
    static const uint32_t regs7_off[7] = {
        0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18 /* ebx..eax */
    };
    const uint32_t regs7_val[7] = {
        ks->regs.ebx, ks->regs.ecx, ks->regs.edx, ks->regs.esi,
        ks->regs.edi, ks->regs.ebp, ks->regs.eax,
    };
    uint8_t b[4];
    int i;

    for (i = 0; i < 7; i++) {
        g_wr32(b, regs7_val[i]);
        if (i686_copy_to_guest(ctx, uva + regs7_off[i], b, 4U) != 0) {
            return -EFAULT;
        }
    }
    g_wr32(b, ks->regs.eip);
    if (i686_copy_to_guest(ctx, uva + 0x30U, b, 4U) != 0) {
        return -EFAULT;
    }
    g_wr16(b, ks->regs.cs);
    if (i686_copy_to_guest(ctx, uva + 0x34U, b, 2U) != 0) {
        return -EFAULT;
    }
    g_wr32(b, ks->regs.eflags);
    if (i686_copy_to_guest(ctx, uva + 0x38U, b, 4U) != 0) {
        return -EFAULT;
    }
    g_wr32(b, ks->regs.esp);
    if (i686_copy_to_guest(ctx, uva + 0x3cU, b, 4U) != 0) {
        return -EFAULT;
    }
    {
        static const uint32_t s6_off[5] = { 0x40, 0x44, 0x48, 0x4c, 0x50 };
        const uint16_t s6_val[5] = {
            ks->regs.ss, ks->regs.es, ks->regs.ds, ks->regs.fs, ks->regs.gs,
        };
        for (i = 0; i < 5; i++) {
            g_wr16(b, s6_val[i]);
            if (i686_copy_to_guest(ctx, uva + s6_off[i], b, 2U) != 0) {
                return -EFAULT;
            }
        }
    }
    return 0;
}

/* Full helper: marshal in, run the v86 loop, marshal out, return the
 * packed exit code (or a negative errno). */
static long vm86_do_enter(i686_ctx_t *ctx, uint32_t uva, int plus)
{
    i686_vm86_enter_t ks;
    long rc;

    memset(&ks, 0, sizeof(ks));
    if (uva < 0x1000U) {
        return -EFAULT; /* null-page convention (Phase 1) */
    }
    rc = copy_reg_in(ctx, &ks, uva);
    if (rc != 0) {
        return rc;
    }
    if (plus != 0) {
        rc = copy_plus_in(ctx, &ks, uva);
        if (rc != 0) {
            return rc;
        }
    }

    rc = i686_v86_enter(ctx, &ks);
    if (rc < 0) {
        return rc; /* -ENOMEM and friends (kernel would ENOMEM/EPERM) */
    }

    if (copy_regs_out(ctx, &ks, uva) != 0) {
        /* kernel: force_exit_sig(SIGSEGV); v1 reports EFAULT. */
        return -EFAULT;
    }
    return rc; /* packed VM86_* exit code -> EAX */
}

/* ------------------------------------------------------------------ */
/* Syscall handlers                                                    */
/* ------------------------------------------------------------------ */

static int64_t r_vm86old(i686_ctx_t *ctx)
{
    /* SYSCALL_DEFINE1(vm86old, struct vm86_struct *): arg in EBX. */
    return vm86_do_enter(ctx, ctx->gpr[I686_REG_EBX], 0);
}

static int64_t r_vm86(i686_ctx_t *ctx)
{
    /* SYSCALL_DEFINE2(vm86, cmd, arg): cmd = EBX, arg = ECX. */
    uint32_t cmd = ctx->gpr[I686_REG_EBX];

    switch (cmd) {
    case I686_VM86_CMD_INSTALL_CHECK:
        return 0; /* VM86_PLUS_INSTALL_CHECK (kernel returns 0) */
    case I686_VM86_CMD_ENTER:
    case I686_VM86_CMD_ENTER_NO_BYPASS:
        return vm86_do_enter(ctx, ctx->gpr[I686_REG_ECX], 1);
    case I686_VM86_CMD_REQUEST_IRQ:
        return -ENOSYS;
    case I686_VM86_CMD_FREE_IRQ:
    case I686_VM86_CMD_GET_IRQ_BITS:
    case I686_VM86_CMD_GET_AND_RESET_IRQ:
        return -EINVAL;
    default:
        return -EINVAL;
    }
}

/* Registration: called from i686_syscalls_init_once() at S8 (coordinator
 * snippet — see docs/lanes/phase-8.md):
 *
 *     {
 *         extern void i686_sys_vm86_init(void);
 *         i686_sys_vm86_init();
 *     }
 */
void i686_sys_vm86_init(void)
{
    static int s_done;

    if (s_done) {
        return;
    }
    s_done = 1;
    i686_sys_register((long)I686__NR_vm86old, r_vm86old);
    i686_sys_register((long)I686__NR_vm86, r_vm86);
}
