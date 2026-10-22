/*
 * src/interp/v86.h — vm86 (real-mode 8086) execution interface (Phase 8, L8a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane-owned (L8a) counterpart of the frozen seg.h: this header is the
 * single source of truth for the shapes and semantics of the v86 engine.
 * Implementation lives in src/interp/v86.c (self-contained fetch/decode/
 * execute loop over the 20-bit real-mode linear view) and src/os/vm86.c
 * (vm86old(113)/vm86(166) marshalling).  Design pins: SPEC §2 D8, §4
 * 8.1/8.2, docs/lanes/phase-8.md coordinator freeze, E10 FINDINGS.
 *
 * Model (E10 §1, kernel arch/x86/kernel/vm86_32.c):
 *  - Real-mode linear = ((seg << 4) + off) & 0xFFFFF (A20 off); the low
 *    megabyte of the guest window hosts it (guest linear 0 = G).  Under a
 *    zero-base window the [0, 0x10000) host range is not mappable
 *    (mmap_min_addr), so v86.c shims it with a private 64 KiB mapping
 *    (v86state); the [0x10000, 0x100000) part is always shared with the
 *    window.  The whole megabyte is mapped by the time the loop runs, so
 *    the loop itself never takes a host fault: A20-off keeps every
 *    real-mode access below 1 MiB.
 *  - Exit codes are exactly the six kernel codes (no code 5).  The packed
 *    value (VM86_TYPE | VM86_ARG << 8) is the syscall return, i.e. the
 *    32-bit caller's EAX.  Deviation from the raw kernel (freeze): v86
 *    opcode faults (GP/UD class: unimplemented/privileged opcodes) exit
 *    VM86_SIGNAL with the equivalent 32-bit signal left pending instead
 *    of the kernel's VM86_UNKNOWN default, so the guest's own signal
 *    path handles them (D2: never assert on unknown opcodes).
 *  - int/iret inside v86 are v86.c's own (IVT semantics), NOT h_seg far
 *    transfers.  IOPL is forced to 3 in the guest view (get_vflags); the
 *    six IOPL-sensitive opcodes (pushf/popf/int/iret/cli/sti) follow the
 *    kernel's handle_vm86_fault verbatim, including VIF/VIP (SAFE_MASK
 *    0xDD5), the vm86dbg TF-pending hook, force_return_for_pic and the
 *    TF single-step re-trap.
 *  - The engine guard (D8) keeps v86 interpreter-only: v86.c runs on the
 *    ctx directly inside the syscall handler and never dispatches DBT
 *    blocks; ctx->cs_d = 0 and ctx->v86 bit0 = 1 while active.
 */

#ifndef I686RT_INTERP_V86_H
#define I686RT_INTERP_V86_H

#include <stdint.h>

#include "i686rt.h"

/* Packed exit codes (kernel uapi asm/vm86.h; exactly six, no code 5). */
#define I686_VM86_SIGNAL 0 /* return due to a (pending) 32-bit signal */
#define I686_VM86_UNKNOWN 1 /* unhandled GP fault - IO-instruction or similar */
#define I686_VM86_INTX 2   /* int3/int x instruction (ARG = x) */
#define I686_VM86_STI 3    /* sti/popf/iret enabled virtual interrupts */
#define I686_VM86_PICRETURN 4 /* return due to pending PIC request */
#define I686_VM86_TRAP 6   /* return due to DOS-debugger request (trap 1/3) */

#define I686_VM86_TYPE(r) ((r) & 0xffu)
#define I686_VM86_ARG(r) ((r) >> 8)
#define I686_VM86_INTX_CODE(n) (I686_VM86_INTX + ((uint32_t)(n) << 8))
#define I686_VM86_TRAP_CODE(t) (I686_VM86_TRAP + ((uint32_t)(t) << 8))

/* Kernel constants (E10 §1.1/§1.4; vm86.h / vm86_32.c). */
#define I686_VM86_BIOSSEG    0x0f000u
#define I686_VM86_SAFE_MASK  0x00000DD5u /* user-settable flag bits */
#define I686_VM86_RETURN_MASK 0x00000DFFu /* guest-visible flag bits */
#define I686_VM86_SCREEN_BITMAP 0x00000001u /* vm86_struct.flags bit: rejected */
#define I686_VM86_LOW_MEG    0x100000u    /* A20-off real-mode address space */
#define I686_VM86_LOW_HOLE   0x10000u     /* unsharable host low VA bound */

/* vm86(2) commands (kernel uapi values; E10 §1.1). */
#define I686_VM86_CMD_INSTALL_CHECK 0u /* VM86_PLUS_INSTALL_CHECK -> 0 */
#define I686_VM86_CMD_ENTER         1u /* VM86_ENTER (plus) */
#define I686_VM86_CMD_ENTER_NO_BYPASS 2u /* VM86_ENTER_NO_BYPASS (plus) */
#define I686_VM86_CMD_REQUEST_IRQ   3u  /* -> -ENOSYS stub */
#define I686_VM86_CMD_FREE_IRQ      4u  /* -> -EINVAL stub */
#define I686_VM86_CMD_GET_IRQ_BITS  5u  /* -> -EINVAL stub */
#define I686_VM86_CMD_GET_AND_RESET_IRQ 6u /* -> -EINVAL stub */

/* cpu_type values (kernel vm86.h); selects the VEFLAGS mask. */
#define I686_VM86_CPU_286 2u
#define I686_VM86_CPU_386 3u
#define I686_VM86_CPU_486 4u

/*
 * Kernel-side mirror of the vm86 register block plus the per-entry
 * virtual-interrupt state (kernel struct vm86 + thread.vm86 bits).
 * src/os/vm86.c marshals this to/from the guest's vm86(plus)_struct;
 * v86.c consumes/updates it around the run.  Register order follows the
 * kernel's do_sys_vm86 reads: __null_ds..gs and orig_eax never cross.
 */
typedef struct i686_vm86_regs {
    uint32_t ebx, ecx, edx, esi, edi, ebp, eax;
    uint32_t eip, eflags, esp;
    uint16_t cs, ss, es, ds, fs, gs;
} i686_vm86_regs_t;

typedef struct i686_vm86_enter {
    i686_vm86_regs_t regs;      /* in: entry state; out: exit state */
    uint32_t flags;             /* vm86_struct.flags (SCREEN_BITMAP -> -EINVAL) */
    uint32_t cpu_type;          /* selects veflags_mask */
    uint32_t int_revectored[8]; /* 256-bit revectored bitmaps */
    uint32_t int21_revectored[8];
    /* Virtual-interrupt state (kernel thread.vm86). */
    uint32_t veflags;        /* VEFLAGS: VIF/VIP + user flag image */
    uint32_t veflags_mask;   /* per cpu_type (286: 0, 386: NT|IOPL, ...) */
    /* vm86plus_info_struct (plus entry only; zeroed for vm86old). */
    uint32_t force_return_for_pic;
    uint32_t vm86dbg_active;
    uint32_t vm86dbg_TFpendig;
    uint32_t is_vm86pus;     /* set kernel-side, never read from the user */
    uint8_t  vm86dbg_intxxtab[32];
    /* 32-bit context save area (v86.c-private; opaque to os/vm86.c). */
    uint32_t regs32_gpr[8];
    uint32_t regs32_eip;
    uint32_t regs32_eflags;
    uint32_t regs32_seg_base[I686_SEG_COUNT];
    uint16_t regs32_seg_sel[I686_SEG_COUNT];
    uint8_t  regs32_cs_d;
} i686_vm86_enter_t;

/*
 * Run the v86 loop: apply ks->regs as the entry machine state, execute
 * real-mode code until an exit condition, store the exit register image
 * in ks->regs, and return the packed exit code (I686_VM86_*; the caller
 * surfaces it as the 32-bit syscall return).  A VM86_SIGNAL return has
 * the equivalent 32-bit signal (SIGILL/SIGSEGV/SIGTRAP) left pending in
 * ctx->pending_signals for the interpreter loop to deliver after the
 * 32-bit context is restored.  Installs ctx->v86 = 1 / cs_d = 0 for the
 * duration and restores the saved 32-bit state before returning.
 *
 * Low-memory bring-up happens here: the first entry maps the still
 * unmapped pages of [0, 1 MiB) (window pages at G + linear; the sub-64
 * KiB range through the private shim under a zero-base window).  Pages
 * that already have a guest region (e.g. mapped by the guest via plain
 * mmap(90), src/os/sys_misc.c) are left untouched and shared, so the
 * 32-bit side and the v86 loop see one memory view.  Mappings persist
 * for the process lifetime (kernel vm86 users such as dosemu keep their
 * low memory mapped too).
 */
long i686_v86_enter(i686_ctx_t *ctx, i686_vm86_enter_t *ks);

#endif /* I686RT_INTERP_V86_H */
