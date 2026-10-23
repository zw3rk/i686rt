/*
 * tests/probe_sse_align.c — C5 ratified-deviation probe (SPEC D10)
 *
 * The aligned SSE move forms (MOVAPS, MOVDQA, MOVNTDQ) raise no
 * #GP(0) on misaligned EAs in i686rt (v1, both engines) — a documented
 * deviation from x86, where they fault (a native i386 run of this
 * probe dies with SIGSEGV at the first misaligned store).  Each
 * sub-test stores the 16-byte pattern through the named form at a
 * 4-off (misaligned) EA, reads it back with MOVDQU, and compares;
 * exit 0 with SSE-ALIGN-OK on success, a distinct nonzero code per
 * form on mismatch: 7 = MOVDQA, 8 = MOVAPS, 9 = MOVNTDQ, 10 = MOVDQU
 * sanity.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

static char buf[64] __attribute__((aligned(16), used));
static const char pattern[16] __attribute__((aligned(16), used)) = {
    (char)0x11, (char)0x22, (char)0x33, (char)0x44,
    (char)0x55, (char)0x66, (char)0x77, (char)0x88,
    (char)0x99, (char)0xaa, (char)0xbb, (char)0xcc,
    (char)0xdd, (char)0xee, (char)0xf0, (char)0x0f
};
static const char okmsg[] __attribute__((used)) = "SSE-ALIGN-OK\n";

__attribute__((naked)) void _start(void)
{
    __asm__ volatile(
        "leal buf+4, %edx\n"         /* misaligned EA: 4 mod 16        */
        "movaps pattern, %xmm0\n"
        "movdqa %xmm0, (%edx)\n"     /* sub-test A: misaligned MOVDQA  */
        "movdqu (%edx), %xmm1\n"
        "leal buf+20, %eax\n"
        "movdqu %xmm1, (%eax)\n"
        "call cmp16\n"
        "testl %eax, %eax\n"
        "jnz 7f\n"

        "movaps pattern, %xmm0\n"
        "movaps %xmm0, (%edx)\n"     /* sub-test B: misaligned MOVAPS  */
        "movdqu (%edx), %xmm1\n"
        "leal buf+20, %eax\n"
        "movdqu %xmm1, (%eax)\n"
        "call cmp16\n"
        "testl %eax, %eax\n"
        "jnz 8f\n"

        "movaps pattern, %xmm0\n"
        "movntdq %xmm0, (%edx)\n"    /* sub-test C: misaligned MOVNTDQ */
        "sfence\n"
        "movdqu (%edx), %xmm1\n"
        "leal buf+20, %eax\n"
        "movdqu %xmm1, (%eax)\n"
        "call cmp16\n"
        "testl %eax, %eax\n"
        "jnz 9f\n"

        "movaps pattern, %xmm0\n"
        "movdqu %xmm0, (%edx)\n"     /* sub-test D: MOVDQU sanity      */
        "movdqu (%edx), %xmm1\n"
        "leal buf+20, %eax\n"
        "movdqu %xmm1, (%eax)\n"
        "call cmp16\n"
        "testl %eax, %eax\n"
        "jnz 10f\n"

        "movl $4, %eax\n"            /* write(1, okmsg, 13)            */
        "movl $1, %ebx\n"
        "leal okmsg, %ecx\n"
        "movl $13, %edx\n"
        "int $0x80\n"
        "movl $1, %eax\n"            /* exit(0)                        */
        "movl $0, %ebx\n"
        "int $0x80\n"

        "7:\tmovl $1, %eax\n\tmovl $7, %ebx\n\tint $0x80\n"
        "8:\tmovl $1, %eax\n\tmovl $8, %ebx\n\tint $0x80\n"
        "9:\tmovl $1, %eax\n\tmovl $9, %ebx\n\tint $0x80\n"
        "10:\tmovl $1, %eax\n\tmovl $10, %ebx\n\tint $0x80\n"
    );
}

/* cmp16: compare 4 dwords at buf+20 against `pattern`; eax = 0 match,
 * 1 mismatch.  Clobbers eax/ecx only — the sub-tests keep their
 * misaligned pointer live in edx across the call. */
__attribute__((naked, used)) static void cmp16(void)
{
    __asm__ volatile(
        "xorl %ecx, %ecx\n"
        "1:\tmovl buf+20(,%ecx,4), %eax\n"
        "\tcmpl pattern(,%ecx,4), %eax\n"
        "\tjne 2f\n"
        "\tincl %ecx\n"
        "\tcmpl $4, %ecx\n"
        "\tjne 1b\n"
        "\txorl %eax, %eax\n"
        "\tret\n"
        "2:\tmovl $1, %eax\n"
        "\tret\n"
    );
}
