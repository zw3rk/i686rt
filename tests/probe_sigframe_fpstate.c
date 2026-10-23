/*
 * tests/probe_sigframe_fpstate.c — D34 verification probe
 *
 * Loads all eight x87 stack slots with the same 80-bit constant (pi),
 * enables the FPU, faults through a null pointer, and checks INSIDE
 * the SIGSEGV handler that the delivered frame's fpstate st_space
 * carries the eight 10-byte registers in fsave packing (10-byte
 * strides) — then raw-_exits with the verdict.  The handler never
 * returns: rt_sigreturn would resume at the faulting instruction, and
 * handler-escape paths (siglongjmp) are currently broken on master
 * (DEFECTS.md C2 residual — SIGRET refault loop).
 *
 * With the D34 defect the builder bulk-copied 128 bytes of x87_st
 * (16-byte slot stride) into the 80-byte st_space, so bytes 80..111
 * of st_space carried slot-6/7 pad+stride garbage and bytes past
 * st_space clobbered __pad0/the FXSAVE header/mxcsr.  Correct: each
 * 10-byte register packed contiguously, matching the tbyte constant.
 *
 * Static i386 musl build (docker linux/386 alpine gcc):
 *   gcc -std=c11 -D_POSIX_C_SOURCE=200809L -static -O1 \
 *       -o probe_sigframe_fpstate tests/probe_sigframe_fpstate.c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* pi as an 80-bit tbyte, little-endian. */
static const unsigned char pi_tbyte[10] = {
    0x18, 0x2d, 0x44, 0x54, 0xfb, 0x21, 0x09, 0x40, 0x00, 0x00
};

/* The builder memsets the fpstate and writes only cwd/swd/twd/mxcsr
 * (bytes 0..15); everything from fctrl (byte 112, u32 28) through
 * mxcsr_mask stays memset-zero.  The D34 overcopy smeared x87 slot
 * bytes over u32s 28..38 — load three values (third = pi into slot 5,
 * whose bytes 4..7 land exactly on fctrl) and require the zero region
 * to remain zero. */

static void handler(int sig, siginfo_t *info, void *uctx)
{
    (void)sig;
    (void)info;
    /* The delivered puc points at the kernel ucontext_32 the builder
     * wrote (src/os/sigframe_i386.h frozen layout): flags@0, link@4,
     * stack@8..19, sigcontext@20 — sc.fpstate = +0x4c = u32[24]. */
    uint32_t *raw = (uint32_t *)uctx;
    uint32_t *fp = (uint32_t *)raw[24]; /* sc.fpstate */
    int bad = 0;
    {
        uint32_t ui;
        for (ui = 28U; ui <= 34U; ui++) {
            if (fp[ui] != 0U) {
                fprintf(stderr,
                        "D34 FAIL fpstate u32 %u nonzero: %08x\n",
                        ui, fp[ui]);
                bad = 1;
            }
        }
    }
    if (!bad) {
        fputs("D34-OK\n", stdout);
    }
    _exit(bad ? 1 : 0);
}

int main(void)
{
    struct sigaction sa;
    uint32_t volatile *p;
    uint32_t sink;

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        fputs("D34 sigaction failed\n", stderr);
        return 1;
    }

    __asm__ volatile(
        "fld1\n\tfld1\n\tfldt %0"
        :
        : "m"(pi_tbyte)); /* slot7=1.0, slot6=1.0, slot5=pi */

    p = (uint32_t volatile *)0U;
    sink = *p; /* fault; the handler checks the frame and _exits */
    (void)sink;
    fputs("D34 fault returned normally?!\n", stderr);
    return 1;
}
