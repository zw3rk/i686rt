/*
 * src/os/sigframe_i386.h — frozen i386 signal-frame ABI (SPEC §3.5, E05)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Layouts are kernel-exact (E05 offsets, double-verified): sigcontext_32
 * 88 B with fpstate*@0x4c, oldmask@0x50, cr2@0x54; _fpstate_32 624 B =
 * 112-byte fsave header + 64-byte-aligned FXSAVE image at +112;
 * FP_XSTATE_MAGIC1 0x46505853 in sw_reserved@+0x240 on every use_fxsr
 * frame; MAGIC2 0x46505845 only with xsave (we always emit fxsr-style:
 * magic1 set, magic2 absent). Lanes must not edit this file.
 */

#ifndef I686RT_OS_SIGFRAME_I386_H
#define I686RT_OS_SIGFRAME_I386_H

#include <stdint.h>

/* struct sigcontext_32 (kernel arch/x86/include/uapi/asm/sigcontext.h) */
typedef struct __attribute__((packed)) {
    uint16_t gs, __gsh;
    uint16_t fs, __fsh;
    uint16_t es, __esh;
    uint16_t ds, __dsh;
    uint32_t edi;          /* 0x1c */
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;
    uint32_t trapno;
    uint32_t err;
    uint32_t eip;
    uint16_t cs, __csh;
    uint32_t eflags;
    uint32_t esp_at_signal;
    uint16_t ss, __ssh;
    uint32_t fpstate;      /* 0x4c guest pointer to _fpstate_32 */
    uint32_t oldmask;      /* 0x50 */
    uint32_t cr2;          /* 0x54 */
} i686_sigcontext_t;

/* _fpstate_32: 624 B = 112 B fsave header + FXSAVE image at +112. */
typedef struct __attribute__((packed)) {
    uint32_t cwd, swd, twd, fip, fcs, foo, fos;
    uint32_t st_space[20];    /* 8 x 80-bit regs, 10 B each            */
    uint8_t  __pad0[4];       /* to 112                                */
    uint16_t fctrl;           /* FXSAVE image begins (+112)            */
    uint16_t fstat;
    uint16_t ftag_;
    uint16_t fop;
    uint32_t fpu_ip2;
    uint32_t fpu_cs2;
    uint32_t fpu_dp2;
    uint32_t fpu_ds2;
    uint32_t mxcsr;
    uint32_t mxcsr_mask;
    uint32_t xmm_space[32];   /* xmm0..7, 16 B each (to 0x188)          */
    uint8_t  __pad1[304];     /* to 0x240 (E05: sw_reserved at +0x240)  */
    uint32_t sw_reserved[6]; /* FP_XSTATE_MAGIC1 in [0] on fxsr frames */
    uint8_t  __tail[24];     /* xsave tail; 624 B total (E05)          */
} i686_fpstate_32_t;

/* non-RT sigframe (signal nr < 32 without SA_SIGINFO) */
typedef struct __attribute__((packed)) {
    uint32_t pretcode;        /* guest &retcode                        */
    int32_t  sig;
    i686_sigcontext_t sc;
    uint32_t fpstate_ptr;     /* guest ptr (mirrors sc.fpstate)        */
    uint32_t extramask;       /* blocked mask upper 32 bits            */
    uint16_t retcode[4];      /* guest-side `pop eax; mov nr,eax;      */
                              /* int $0x80` (119) trampoline           */
} i686_sigframe_t;

/* rt_sigframe (SA_SIGINFO) */
typedef struct __attribute__((packed)) {
    uint32_t pretcode;
    int32_t  sig;
    uint32_t pinfo;           /* guest &siginfo                        */
    uint32_t puc;             /* guest &ucontext (0x90 from frame)     */
    uint8_t  siginfo[128];    /* kernel siginfo layout, zeroed + fill  */
    uint8_t  ucontext[116];   /* 268 = 16+128+116+8 (kernel rt frame)  */
    uint16_t retcode[4];
} i686_rt_sigframe_t;

_Static_assert(sizeof(i686_sigcontext_t) == 88, "sigcontext_32 88 B");
_Static_assert(sizeof(i686_fpstate_32_t) == 624, "_fpstate_32 624 B");
_Static_assert(sizeof(i686_rt_sigframe_t) == 268, "rt_sigframe 268 B");

/* Frozen frame-builder API (src/os/signals_i386.c, coordinator-owned). */
void i686_signals_i386_init(void);          /* host sigaction registration */
int  i686_sigframe_build(i686_ctx_t *ctx, int sig, uint32_t handler,
                         uint32_t restorer, int sa_siginfo,
                         uint32_t info_va, uint32_t uc_va);
/* Returns new guest ESP with the frame pushed; sigcontext filled from
 * ctx (regs, eip, eflags, cr2/fault, fpstate from ctx x87/xmm fields). */

/* sigreturn entry: called by the engine when the guest's restorer/retcode
 * invokes sigreturn(119)/rt_sigreturn(173). Restores sigcontext into ctx
 * and returns 0, or -1 on bad frame (-> SIGSEGV). */
int i686_sigreturn(i686_ctx_t *ctx, int rt);

#endif /* I686RT_OS_SIGFRAME_I386_H */
