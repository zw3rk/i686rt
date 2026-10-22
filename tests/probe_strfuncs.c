/*
 * tests/probe_strfuncs.c — RC7b T2 glibc string-function opcode-sequence
 * fixture
 *
 * Root-cause fixture for the wine cmd /c blocker: dash's shellexec only
 * PATH-searches when strchr(argv[0], '/') == NULL, but the arm64 oracle
 * observed a PATH search for the absolute "/usr/bin/sh" — glibc 2.44's
 * i386 strchr (resolved to __strchr_sse2: i686rt's CPUID advertises only
 * SSE/SSE2) returned NULL inside a longer instruction SEQUENCE although
 * RC7b T1's single-opcode probes all matched the linux/386 oracle.
 *
 * This fixture embeds the REAL glibc SSE2 implementations, byte-exact,
 * extracted from the sysroot libc.so.6.  Identity of each body came
 * from its IFUNC resolver target arithmetic (anchor 0x23de34) and was
 * confirmed behaviorally on the linux/386 oracle (an earlier draft
 * mislabeled 0xc0c70/0xc0d80/0xc0f70 as chrnul/strchr/strlen; they are
 * strchr/strrchr/memchr — glibc i386 has no SSE2 strchrnul, and the
 * strlen SSE2 body lives at 0xafc80):
 *
 *   __strchr_sse2  0xc0c70   __strrchr_sse2 0xc0d80
 *   __memchr_sse2  0xc0f70   __strlen_sse2  0xafc80
 *
 * plus hand-written raw-.byte probes for the strchr idioms and every
 * RC7b-T1-added opcode with edge vectors (negative/zero/all-ones),
 * edge alignments and the 64-bit MMX forms:
 *
 *   - S cases (blob calls): strchr/strrchr/memchr/strlen over a
 *     64-byte aligned buffer at alignment offsets 0..63, needles at
 *     positions 0/1/5/15/16/31/33/47/63, absent needles, NUL needles,
 *     needle-after-NUL (chr stops, memchr does not), 16/32/64/128
 *     boundary needles, n=0/n<pos/n>len memchr lengths, >64-byte
 *     multi-loop strings, and the literal failing "/usr/bin/sh";
 *   - P1  movdqu head + punpcklbw x2/pshufd broadcast + pcmpeqb +
 *     pmovmskb masked scan (NUL trick: pcmpeqb against the zeroed
 *     xmm), matching the glibc prologue;
 *   - P2  PSRLDQ/PSLLDQ (66 0F 73 /2 /3) after an unaligned movdqu
 *     load, imm 0/1/15/16/255, on 0x0102.. and all-ones vectors;
 *   - P3  MOVDQA load + pcmpeqb vs zero on zero/all-ones/0x80 sign
 *     vectors + pmovmskb;
 *   - P4  PCMPEQB/PCMPGTB edges (0x80 vs 0x7F signed);
 *   - P5  PCMPEQD equal/unequal dwords;
 *   - P6  PMOVMSKB sign-bit patterns (0x00 FF 80 7F AA 55);
 *   - P7  PMINUB/PMAXUB edges across 0x7F/0x80;
 *   - P8  PSUBB wrap edges both directions;
 *   - P9  MOVQ row (66 0F D6 m64 store + reg-reg upper-preserving,
 *     F3 0F 7E m64 load, F3 0F D6 MOVQ2DQ, F2 0F D6 MOVDQ2Q);
 *   - P10 MOVD 66 0F 6E/7E zero-extension both directions;
 *   - P11 MOVNTDQ (66 0F E7) aligned NT store;
 *   - P12 PREFETCHh (0F 18 /0../3) no-architected-effect + SFENCE
 *     (0F AE /7);
 *   - P14 por (66 0F EB) mask merge;
 *   - P15 MMX plain (64-bit) forms: movq mm, psubb/pcmpeqb/pcmpgtb/
 *     pcmpeqd/pminub/pmaxub mm, pmovmskb mm (8-bit mask), psrlq/psllq
 *     (0F 73 /2 /6), closed by EMMS.
 *
 * Every case prints one line
 *
 *     SF <fn> <case> o=<off> c=<char> got=<hex> exp=<hex> ok|FAIL
 *     PR <name> ... ok|FAIL
 *
 * and the fixture finishes with "DONE <total> FAIL <nfails>".
 * Expectations are recomputed in plain scalar C, so the output is
 * self-checking AND must be byte-identical between the linux/386
 * docker oracle and i686rt (RC7b T2 acceptance).
 *
 * All SSE/MMX is written as raw .byte sequences with pinned registers:
 * the build keeps -march=i686 -mno-mmx, so neither gcc nor as may
 * emit or accept SSE/MMX mnemonics (and gcc cannot auto-vectorize).
 * The asm blocks deliberately omit xmm/mm clobbers: with SSE/MMX
 * disabled for the target gcc rejects "xmm0"-style clobbers ("register
 * cannot be clobbered for the current target") and, more importantly,
 * never allocates those registers at all, so the raw writes cannot
 * disturb register allocation.
 *
 * Build (docker --platform linux/386 alpine:3.20):
 *   cc -std=gnu11 -ffreestanding -static -nostdlib -O2 -march=i686 \
 *      -mno-mmx -fno-pie -fno-stack-protector -o probe_strfuncs \
 *      tests/probe_strfuncs.c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* raw int 0x80 syscalls                                              */
/* ------------------------------------------------------------------ */

static long sys_write(int fd, const void *buf, unsigned long len)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(4L), "b"((long)fd), "c"(buf), "d"((long)len)
                      : "memory");
    return r;
}

__attribute__((noreturn))
static void sys_exit(long code)
{
    __asm__ volatile ("int $0x80" : : "a"(1L), "b"(code));
    __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* print helpers                                                      */
/* ------------------------------------------------------------------ */

static void put(const char *s, unsigned n)
{
    sys_write(1, s, (unsigned long)n);
}

static void puts_(const char *s)
{
    unsigned n = 0u;
    while (s[n] != '\0') {
        n++;
    }
    put(s, n);
}

static void put_dec(unsigned v)
{
    char b[10];
    int i = 10;
    if (v == 0u) {
        put("0", 1);
        return;
    }
    while (v != 0u) {
        b[--i] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    put(b + i, (unsigned)(10 - i));
}

static void phex(uint32_t v)
{
    static const char hx[16] = "0123456789abcdef";
    char b[8];
    int i;
    for (i = 7; i >= 0; i--) {
        b[i] = hx[v & 0xfu];
        v >>= 4;
    }
    put(b, 8);
}

static void phex8(uint8_t v)
{
    static const char hx[16] = "0123456789abcdef";
    char b[2];
    b[0] = hx[v >> 4];
    b[1] = hx[v & 0xfu];
    put(b, 2);
}

/* ------------------------------------------------------------------ */
/* result accounting: append "ok|FAIL" to the open line and count      */
/* ------------------------------------------------------------------ */

static unsigned total;
static unsigned fails;

static void finish(int ok)
{
    puts_(ok ? "ok\n" : "FAIL\n");
    total++;
    if (!ok) {
        fails++;
    }
}

/* ------------------------------------------------------------------ */
/* glibc SSE2 string-function bodies (byte-exact, from the sysroot     */
/* libc.so.6; extraction recorded in docs/lanes/phase-7.md T2)         */
/* ------------------------------------------------------------------ */

__asm__(
    ".text\n"
    ".globl t2_strchr_sse2\n"
    ".type t2_strchr_sse2, @function\n"
    "t2_strchr_sse2:\n"
    ".byte 0x57,0x8b,0x4c,0x24,0x08,0x66,0x0f,0x6e,0x4c,0x24,0x0c,0x66\n\t"
    ".byte 0x0f,0xef,0xd2,0x89,0xcf,0x66,0x0f,0x60,0xc9,0x66,0x0f,0x60\n\t"
    ".byte 0xc9,0x83,0xe1,0x0f,0x66,0x0f,0x70,0xc9,0x00,0x74,0x4d,0x83\n\t"
    ".byte 0xe7,0xf0,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xd0,0x66,0x0f\n\t"
    ".byte 0x74,0xc1,0x66,0x0f,0xd7,0xd2,0x66,0x0f,0xd7,0xc0,0xd3,0xfa\n\t"
    ".byte 0xd3,0xf8,0x85,0xc0,0x74,0x1e,0x0f,0xbc,0xc0,0x85,0xd2,0x74\n\t"
    ".byte 0x0b,0x0f,0xbc,0xd2,0x39,0xd0,0x0f,0x87,0xac,0x00,0x00,0x00\n\t"
    ".byte 0x01,0xf8,0x01,0xc8,0x5f,0xc3,0x8d,0xb6,0x00,0x00,0x00,0x00\n\t"
    ".byte 0x85,0xd2,0x0f,0x85,0x98,0x00,0x00,0x00,0x66,0x0f,0xef,0xd2\n\t"
    ".byte 0x83,0xc7,0x10,0x90,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xd0\n\t"
    ".byte 0x83,0xc7,0x10,0x66,0x0f,0x74,0xc1,0x66,0x0f,0xd7,0xd2,0x66\n\t"
    ".byte 0x0f,0xd7,0xc0,0x09,0xc2,0x75,0x53,0x66,0x0f,0x6f,0x07,0x66\n\t"
    ".byte 0x0f,0x74,0xd0,0x83,0xc7,0x10,0x66,0x0f,0x74,0xc1,0x66,0x0f\n\t"
    ".byte 0xd7,0xd2,0x66,0x0f,0xd7,0xc0,0x09,0xc2,0x75,0x38,0x66,0x0f\n\t"
    ".byte 0x6f,0x07,0x66,0x0f,0x74,0xd0,0x83,0xc7,0x10,0x66,0x0f,0x74\n\t"
    ".byte 0xc1,0x66,0x0f,0xd7,0xd2,0x66,0x0f,0xd7,0xc0,0x09,0xc2,0x75\n\t"
    ".byte 0x1d,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xd0,0x83,0xc7,0x10\n\t"
    ".byte 0x66,0x0f,0x74,0xc1,0x66,0x0f,0xd7,0xd2,0x66,0x0f,0xd7,0xc0\n\t"
    ".byte 0x09,0xc2,0x75,0x02,0xeb,0x92,0x66,0x0f,0xd7,0xd2,0x85,0xc0\n\t"
    ".byte 0x74,0x1a,0x0f,0xbc,0xc0,0x85,0xd2,0x74,0x07,0x0f,0xbc,0xca\n\t"
    ".byte 0x39,0xc8,0x77,0x0c,0x83,0xef,0x10,0x01,0xf8,0x5f,0xc3,0x2e\n\t"
    ".byte 0x8d,0x74,0x26,0x00,0x31,0xc0,0x5f,0xc3\n\t"
    ".size t2_strchr_sse2, . - t2_strchr_sse2\n"
);

__asm__(
    ".text\n"
    ".globl t2_strrchr_sse2\n"
    ".type t2_strrchr_sse2, @function\n"
    "t2_strrchr_sse2:\n"
    ".byte 0x8b,0x4c,0x24,0x04,0x66,0x0f,0x6e,0x4c,0x24,0x08,0x57,0x66\n\t"
    ".byte 0x0f,0xef,0xd2,0x89,0xcf,0x66,0x0f,0x60,0xc9,0x66,0x0f,0x60\n\t"
    ".byte 0xc9,0x83,0xe1,0x3f,0x83,0xf9,0x30,0x66,0x0f,0x70,0xc9,0x00\n\t"
    ".byte 0x77,0x7a,0xf3,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xd0,0x66,0x0f\n\t"
    ".byte 0x74,0xc1,0x66,0x0f,0xd7,0xd2,0x66,0x0f,0xd7,0xc0,0x85,0xc0\n\t"
    ".byte 0x75,0x42,0x85,0xd2,0x0f,0x85,0x8a,0x01,0x00,0x00,0x83,0xe7\n\t"
    ".byte 0xf0,0x83,0xc7,0x10,0x56,0x53,0x31,0xdb,0xe9,0xbb,0x00,0x00\n\t"
    ".byte 0x00,0x8d,0x76,0x00,0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n\t"
    ".byte 0x0f,0xbc,0xca,0xba,0x02,0x00,0x00,0x00,0xd3,0xe2,0x83,0xea\n\t"
    ".byte 0x01,0x21,0xd0,0x0f,0x84,0x5b,0x01,0x00,0x00,0x0f,0xbd,0xc0\n\t"
    ".byte 0x01,0xf8,0x5f,0xc3,0x8d,0x74,0x26,0x00,0x85,0xd2,0x75,0xdc\n\t"
    ".byte 0x56,0x53,0x89,0xc3,0x8d,0x77,0x10,0x83,0xe7,0xf0,0x83,0xc7\n\t"
    ".byte 0x10,0xeb,0x7d,0x2e,0x8d,0x74,0x26,0x00,0x2e,0x8d,0xb4,0x26\n\t"
    ".byte 0x00,0x00,0x00,0x00,0x83,0xe1,0x0f,0x83,0xe7,0xf0,0x66,0x0f\n\t"
    ".byte 0xef,0xdb,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xd8,0x66,0x0f\n\t"
    ".byte 0x74,0xc1,0x66,0x0f,0xd7,0xd3,0x66,0x0f,0xd7,0xc0,0xd3,0xea\n\t"
    ".byte 0xd3,0xe8,0x85,0xc0,0x75,0x3a,0x85,0xd2,0x0f,0x85,0x02,0x01\n\t"
    ".byte 0x00,0x00,0x83,0xc7,0x10,0x56,0x53,0x31,0xdb,0xeb,0x39,0x90\n\t"
    ".byte 0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00,0x01,0xcf,0x0f,0xbc\n\t"
    ".byte 0xca,0xba,0x02,0x00,0x00,0x00,0xd3,0xe2,0x83,0xea,0x01,0x21\n\t"
    ".byte 0xd0,0x0f,0x84,0xd9,0x00,0x00,0x00,0x0f,0xbd,0xc0,0x01,0xf8\n\t"
    ".byte 0x5f,0xc3,0x66,0x90,0x85,0xd2,0x75,0xdc,0x56,0x53,0x89,0xc3\n\t"
    ".byte 0x83,0xc7,0x10,0x8d,0x34,0x0f,0x66,0x90,0x66,0x0f,0x6f,0x07\n\t"
    ".byte 0x66,0x0f,0x74,0xd0,0x83,0xc7,0x10,0x66,0x0f,0x74,0xc1,0x66\n\t"
    ".byte 0x0f,0xd7,0xca,0x66,0x0f,0xd7,0xc0,0x09,0xc1,0x75,0x51,0x66\n\t"
    ".byte 0x0f,0x6f,0x07,0x66,0x0f,0x74,0xd0,0x83,0xc7,0x10,0x66,0x0f\n\t"
    ".byte 0x74,0xc1,0x66,0x0f,0xd7,0xca,0x66,0x0f,0xd7,0xc0,0x09,0xc1\n\t"
    ".byte 0x75,0x36,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xd0,0x83,0xc7\n\t"
    ".byte 0x10,0x66,0x0f,0x74,0xc1,0x66,0x0f,0xd7,0xca,0x66,0x0f,0xd7\n\t"
    ".byte 0xc0,0x09,0xc1,0x75,0x1b,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74\n\t"
    ".byte 0xd0,0x83,0xc7,0x10,0x66,0x0f,0x74,0xc1,0x66,0x0f,0xd7,0xca\n\t"
    ".byte 0x66,0x0f,0xd7,0xc0,0x09,0xc1,0x74,0x94,0x85,0xc0,0x75,0x10\n\t"
    ".byte 0x85,0xdb,0x74,0x5c,0x0f,0xbd,0xc3,0x01,0xf0,0x5b,0x5e,0x83\n\t"
    ".byte 0xe8,0x10,0x5f,0xc3,0x66,0x0f,0xd7,0xca,0x85,0xc9,0x75,0x18\n\t"
    ".byte 0x89,0xc3,0x89,0xfe,0xe9,0x6f,0xff,0xff,0xff,0x8d,0xb4,0x26\n\t"
    ".byte 0x00,0x00,0x00,0x00,0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n\t"
    ".byte 0x0f,0xbc,0xc9,0xba,0x02,0x00,0x00,0x00,0xd3,0xe2,0x83,0xea\n\t"
    ".byte 0x01,0x21,0xd0,0x74,0xbf,0x5b,0x5e,0x0f,0xbd,0xc0,0x01,0xf8\n\t"
    ".byte 0x83,0xe8,0x10,0x5f,0xc3,0x8d,0x76,0x00,0x31,0xc0,0x5f,0xc3\n\t"
    ".byte 0x8d,0x74,0x26,0x00,0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n\t"
    ".byte 0x5b,0x5e,0x5f,0x31,0xc0,0xc3\n\t"
    ".size t2_strrchr_sse2, . - t2_strrchr_sse2\n"
);

__asm__(
    ".text\n"
    ".globl t2_memchr_sse2\n"
    ".type t2_memchr_sse2, @function\n"
    "t2_memchr_sse2:\n"
    ".byte 0x8b,0x4c,0x24,0x04,0x66,0x0f,0x6e,0x4c,0x24,0x08,0x8b,0x54\n\t"
    ".byte 0x24,0x0c,0x85,0xd2,0x74,0x5e,0x89,0xc8,0x66,0x0f,0x60,0xc9\n\t"
    ".byte 0x66,0x0f,0x60,0xc9,0x83,0xe1,0x3f,0x66,0x0f,0x70,0xc9,0x00\n\t"
    ".byte 0x83,0xf9,0x30,0x77,0x57,0xf3,0x0f,0x6f,0x00,0x66,0x0f,0x74\n\t"
    ".byte 0xc1,0x66,0x0f,0xd7,0xc8,0x85,0xc9,0x74,0x17,0x0f,0xbc,0xc9\n\t"
    ".byte 0x29,0xca,0x76,0x30,0x01,0xc8,0xc3,0x2e,0x8d,0x74,0x26,0x00\n\t"
    ".byte 0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00,0x83,0xea,0x10,0x76\n\t"
    ".byte 0x1b,0x57,0x8d,0x78,0x10,0x83,0xe0,0x0f,0x83,0xe7,0xf0,0x01\n\t"
    ".byte 0xc2,0xeb,0x6d,0x2e,0x8d,0x74,0x26,0x00,0x2e,0x8d,0xb4,0x26\n\t"
    ".byte 0x00,0x00,0x00,0x00,0x31,0xc0,0xc3,0x2e,0x8d,0x74,0x26,0x00\n\t"
    ".byte 0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00,0x57,0x89,0xc7,0x83\n\t"
    ".byte 0xe1,0x0f,0x83,0xe7,0xf0,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74\n\t"
    ".byte 0xc1,0x66,0x0f,0xd7,0xc0,0xd3,0xf8,0x85,0xc0,0x74,0x15,0x0f\n\t"
    ".byte 0xbc,0xc0,0x29,0xc2,0x0f,0x86,0xaa,0x02,0x00,0x00,0x01,0xf8\n\t"
    ".byte 0x01,0xc8,0x5f,0xc3,0x8d,0x74,0x26,0x00,0x01,0xca,0x19,0xc0\n\t"
    ".byte 0x09,0xc2,0x83,0xea,0x10,0x0f,0x86,0x91,0x02,0x00,0x00,0x83\n\t"
    ".byte 0xc7,0x10,0x8d,0xb6,0x00,0x00,0x00,0x00,0x2e,0x8d,0xb4,0x26\n\t"
    ".byte 0x00,0x00,0x00,0x00,0x83,0xea,0x40,0x0f,0x86,0x57,0x01,0x00\n\t"
    ".byte 0x00,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xc1,0x66,0x0f,0xd7\n\t"
    ".byte 0xc0,0x85,0xc0,0x0f,0x85,0xf3,0x01,0x00,0x00,0x66,0x0f,0x6f\n\t"
    ".byte 0x57,0x10,0x66,0x0f,0x74,0xd1,0x66,0x0f,0xd7,0xc2,0x85,0xc0\n\t"
    ".byte 0x0f,0x85,0xee,0x01,0x00,0x00,0x66,0x0f,0x6f,0x5f,0x20,0x66\n\t"
    ".byte 0x0f,0x74,0xd9,0x66,0x0f,0xd7,0xc3,0x85,0xc0,0x0f,0x85,0xe9\n\t"
    ".byte 0x01,0x00,0x00,0x66,0x0f,0x6f,0x67,0x30,0x66,0x0f,0x74,0xe1\n\t"
    ".byte 0x83,0xc7,0x40,0x66,0x0f,0xd7,0xc4,0x85,0xc0,0x0f,0x85,0xa1\n\t"
    ".byte 0x01,0x00,0x00,0xf7,0xc7,0x3f,0x00,0x00,0x00,0x74,0x69,0x83\n\t"
    ".byte 0xea,0x40,0x0f,0x86,0xf0,0x00,0x00,0x00,0x66,0x0f,0x6f,0x07\n\t"
    ".byte 0x66,0x0f,0x74,0xc1,0x66,0x0f,0xd7,0xc0,0x85,0xc0,0x0f,0x85\n\t"
    ".byte 0x8c,0x01,0x00,0x00,0x66,0x0f,0x6f,0x57,0x10,0x66,0x0f,0x74\n\t"
    ".byte 0xd1,0x66,0x0f,0xd7,0xc2,0x85,0xc0,0x0f,0x85,0x87,0x01,0x00\n\t"
    ".byte 0x00,0x66,0x0f,0x6f,0x5f,0x20,0x66,0x0f,0x74,0xd9,0x66,0x0f\n\t"
    ".byte 0xd7,0xc3,0x85,0xc0,0x0f,0x85,0x82,0x01,0x00,0x00,0x66,0x0f\n\t"
    ".byte 0x6f,0x5f,0x30,0x66,0x0f,0x74,0xd9,0x66,0x0f,0xd7,0xc3,0x83\n\t"
    ".byte 0xc7,0x40,0x85,0xc0,0x0f,0x85,0x3a,0x01,0x00,0x00,0x89,0xf9\n\t"
    ".byte 0x83,0xe7,0xc0,0x83,0xe1,0x3f,0x01,0xca,0x83,0xea,0x40,0x0f\n\t"
    ".byte 0x86,0x87,0x00,0x00,0x00,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x6f\n\t"
    ".byte 0x57,0x10,0x66,0x0f,0x6f,0x5f,0x20,0x66,0x0f,0x6f,0x67,0x30\n\t"
    ".byte 0x66,0x0f,0x74,0xc1,0x66,0x0f,0x74,0xd1,0x66,0x0f,0x74,0xd9\n\t"
    ".byte 0x66,0x0f,0x74,0xe1,0x66,0x0f,0xde,0xd8,0x66,0x0f,0xde,0xe2\n\t"
    ".byte 0x66,0x0f,0xde,0xe3,0x66,0x0f,0xd7,0xc4,0x83,0xc7,0x40,0x85\n\t"
    ".byte 0xc0,0x74,0xbd,0x83,0xef,0x40,0x66,0x0f,0xd7,0xc0,0x85,0xc0\n\t"
    ".byte 0x0f,0x85,0xee,0x00,0x00,0x00,0x66,0x0f,0xd7,0xc2,0x85,0xc0\n\t"
    ".byte 0x0f,0x85,0xf2,0x00,0x00,0x00,0x66,0x0f,0x6f,0x5f,0x20,0x66\n\t"
    ".byte 0x0f,0x74,0xd9,0x66,0x0f,0x74,0x4f,0x30,0x66,0x0f,0xd7,0xc3\n\t"
    ".byte 0x85,0xc0,0x0f,0x85,0xe8,0x00,0x00,0x00,0x66,0x0f,0xd7,0xc1\n\t"
    ".byte 0x0f,0xbc,0xc0,0x8d,0x44,0x07,0x30,0x5f,0xc3,0x8d,0x76,0x00\n\t"
    ".byte 0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00,0x83,0xc2,0x40,0x83\n\t"
    ".byte 0xfa,0x20,0x76,0x68,0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xc1\n\t"
    ".byte 0x66,0x0f,0xd7,0xc0,0x85,0xc0,0x0f,0x85,0x94,0x00,0x00,0x00\n\t"
    ".byte 0x66,0x0f,0x6f,0x57,0x10,0x66,0x0f,0x74,0xd1,0x66,0x0f,0xd7\n\t"
    ".byte 0xc2,0x85,0xc0,0x0f,0x85,0x8f,0x00,0x00,0x00,0x66,0x0f,0x6f\n\t"
    ".byte 0x5f,0x20,0x66,0x0f,0x74,0xd9,0x66,0x0f,0xd7,0xc3,0x85,0xc0\n\t"
    ".byte 0x0f,0x85,0xba,0x00,0x00,0x00,0x83,0xfa,0x30,0x0f,0x86,0xd1\n\t"
    ".byte 0x00,0x00,0x00,0x66,0x0f,0x74,0x4f,0x30,0x66,0x0f,0xd7,0xc1\n\t"
    ".byte 0x85,0xc0,0x0f,0x85,0xb0,0x00,0x00,0x00,0x31,0xc0,0x5f,0xc3\n\t"
    ".byte 0x8d,0x74,0x26,0x00,0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n\t"
    ".byte 0x66,0x0f,0x6f,0x07,0x66,0x0f,0x74,0xc1,0x66,0x0f,0xd7,0xc0\n\t"
    ".byte 0x85,0xc0,0x75,0x60,0x83,0xfa,0x10,0x0f,0x86,0x97,0x00,0x00\n\t"
    ".byte 0x00,0x66,0x0f,0x74,0x4f,0x10,0x66,0x0f,0xd7,0xc1,0x85,0xc0\n\t"
    ".byte 0x75,0x5a,0x31,0xc0,0x5f,0xc3,0x8d,0xb6,0x00,0x00,0x00,0x00\n\t"
    ".byte 0x0f,0xbc,0xc0,0x8d,0x44,0x38,0xf0,0x5f,0xc3,0x8d,0xb4,0x26\n\t"
    ".byte 0x00,0x00,0x00,0x00,0x0f,0xbc,0xc0,0x01,0xf8,0x5f,0xc3,0x90\n\t"
    ".byte 0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00,0x0f,0xbc,0xc0,0x8d\n\t"
    ".byte 0x44,0x38,0x10,0x5f,0xc3,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n\t"
    ".byte 0x0f,0xbc,0xc0,0x8d,0x44,0x38,0x20,0x5f,0xc3,0x8d,0xb4,0x26\n\t"
    ".byte 0x00,0x00,0x00,0x00,0x0f,0xbc,0xc0,0x29,0xc2,0x76,0x39,0x01\n\t"
    ".byte 0xf8,0x5f,0xc3,0x2e,0x8d,0x74,0x26,0x00,0x83,0xea,0x10,0x0f\n\t"
    ".byte 0xbc,0xc0,0x29,0xc2,0x76,0x26,0x8d,0x44,0x07,0x10,0x5f,0xc3\n\t"
    ".byte 0x83,0xea,0x20,0x0f,0xbc,0xc0,0x29,0xc2,0x76,0x16,0x8d,0x44\n\t"
    ".byte 0x07,0x20,0x5f,0xc3,0x83,0xea,0x30,0x0f,0xbc,0xc0,0x29,0xc2\n\t"
    ".byte 0x76,0x06,0x8d,0x44,0x07,0x30,0x5f,0xc3,0x31,0xc0,0x5f,0xc3\n\t"
    ".size t2_memchr_sse2, . - t2_memchr_sse2\n"
);

__asm__(
    ".text\n"
    ".globl t2_strlen_sse2\n"
    ".type t2_strlen_sse2, @function\n"
    "t2_strlen_sse2:\n"
    ".byte 0x56,0x57,0x8b,0x7c,0x24,0x0c,0x31,0xc0,0x89,0xf9,0x83,0xe1\n\t"
    ".byte 0x3f,0x66,0x0f,0xef,0xc0,0x83,0xf9,0x30,0x77,0x17,0xf3,0x0f\n\t"
    ".byte 0x6f,0x0f,0x66,0x0f,0x74,0xc1,0x66,0x0f,0xd7,0xd0,0x85,0xd2\n\t"
    ".byte 0x75,0x73,0x89,0xf8,0x83,0xe0,0xf0,0xeb,0x1a,0x89,0xf8,0x83\n\t"
    ".byte 0xe0,0xf0,0x66,0x0f,0x74,0x00,0xbe,0xff,0xff,0xff,0xff,0x29\n\t"
    ".byte 0xc1,0xd3,0xe6,0x66,0x0f,0xd7,0xd0,0x21,0xf2,0x75,0x50,0x66\n\t"
    ".byte 0x0f,0xef,0xc0,0x66,0x0f,0xef,0xc9,0x66,0x0f,0xef,0xd2,0x66\n\t"
    ".byte 0x0f,0xef,0xdb,0x90,0x2e,0x8d,0xb4,0x26,0x00,0x00,0x00,0x00\n\t"
    ".byte 0x66,0x0f,0x74,0x40,0x10,0x66,0x0f,0xd7,0xd0,0x85,0xd2,0x75\n\t"
    ".byte 0x34,0x66,0x0f,0x74,0x48,0x20,0x66,0x0f,0xd7,0xd1,0x85,0xd2\n\t"
    ".byte 0x75,0x34,0x66,0x0f,0x74,0x50,0x30,0x66,0x0f,0xd7,0xd2,0x85\n\t"
    ".byte 0xd2,0x75,0x34,0x66,0x0f,0x74,0x58,0x40,0x66,0x0f,0xd7,0xd3\n\t"
    ".byte 0x8d,0x40,0x40,0x85,0xd2,0x74,0xc9,0x29,0xf8,0x0f,0xbc,0xd2\n\t"
    ".byte 0x01,0xd0,0x5f,0x5e,0xc3,0x29,0xf8,0x0f,0xbc,0xd2,0x01,0xd0\n\t"
    ".byte 0x83,0xc0,0x10,0x5f,0x5e,0xc3,0x29,0xf8,0x0f,0xbc,0xd2,0x01\n\t"
    ".byte 0xd0,0x83,0xc0,0x20,0x5f,0x5e,0xc3,0x29,0xf8,0x0f,0xbc,0xd2\n\t"
    ".byte 0x01,0xd0,0x83,0xc0,0x30,0x5f,0x5e,0xc3,0x66,0x90,0x66,0x90\n\t"
    ".byte 0x66,0x90,0x66,0x90,0x56,0x53,0x83,0xec,0x1c,0x8b,0x5c,0x24\n\t"
    ".byte 0x30,0x53,0xff,0x74,0x24,0x30,0xe8,0xad,0x1c,0x01,0x00,0x83\n\t"
    ".byte 0xc4,0x10,0x89,0xc2,0x39,0xc3,0x74,0x28,0x89,0x44,0x24,0x0c\n\t"
    ".byte 0x29,0xc3,0x83,0xec,0x04,0x03,0x44,0x24,0x24,0x53,0xe8,0xca\n\t"
    ".byte 0x97,0x0d,0x00,0x81,0xc3,0xb5,0xe0,0x18,0x00,0x6a,0x00,0x50\n\t"
    ".byte 0xe8,0x33,0x25,0x01,0x00,0x8b,0x54,0x24,0x1c,0x83,0xc4,0x10\n\t"
    ".byte 0xe8,0xb0,0x97,0x0d,0x00,0x81,0xc3,0x9b,0xe0,0x18,0x00,0x83\n\t"
    ".byte 0xec,0x04,0x52,0xff,0x74,0x24,0x2c,0xff,0x74,0x24,0x2c,0xe8\n\t"
    ".byte 0xe0,0x23,0x01,0x00,0x83,0xc4,0x24,0x5b,0x5e,0xc3\n\t"
    ".size t2_strlen_sse2, . - t2_strlen_sse2\n"
);

char *t2_strchr_sse2(const char *s, int c);
char *t2_strrchr_sse2(const char *s, int c);
void *t2_memchr_sse2(const char *s, int c, unsigned long n);
unsigned long t2_strlen_sse2(const char *s);

/* ------------------------------------------------------------------ */
/* scalar references and little helpers                                */
/* ------------------------------------------------------------------ */

static uint32_t ld32(const uint8_t *s)
{
    return (uint32_t)s[0] | ((uint32_t)s[1] << 8) |
           ((uint32_t)s[2] << 16) | ((uint32_t)s[3] << 24);
}

static uint64_t ld64(const uint8_t *s)
{
    return (uint64_t)ld32(s) | ((uint64_t)ld32(s + 4) << 32);
}

static int v8_eq(const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 8u; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static char *ref_strchr(const char *s, int c)
{
    char t = (char)c;
    for (; *s != '\0'; s++) {
        if (*s == t) {
            return (char *)s;
        }
    }
    return t == '\0' ? (char *)s : (char *)0;
}

static char *ref_strrchr(const char *s, int c)
{
    char t = (char)c;
    char *last = (char *)0;
    for (; ; s++) {
        if (*s == t) {
            last = (char *)s;
        }
        if (*s == '\0') {
            break;
        }
    }
    return last;
}

static const void *ref_memchr(const char *s, int c, unsigned long n)
{
    char t = (char)c;
    unsigned long i;
    for (i = 0u; i < n; i++) {
        if (s[i] == t) {
            return s + i;
        }
    }
    return 0;
}

static unsigned long ref_strlen(const char *s)
{
    unsigned long n = 0u;
    while (s[n] != '\0') {
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* blob case runner: 64-byte aligned scratch with slack                */
/* ------------------------------------------------------------------ */

static _Alignas(64) uint8_t buf[512];

static void fill_pattern(uint8_t *p, unsigned n, uint8_t seed)
{
    unsigned i;
    uint8_t x = seed;
    for (i = 0u; i < n; i++) {
        /* xorshift-ish byte stream, never 0x00 and never '/' */
        x = (uint8_t)(x * 31u + 7u);
        if (x == 0u || x == (uint8_t)'/') {
            x = (uint8_t)(x + 17u);
        }
        p[i] = x;
    }
}

static void blob_case(const char *fn, const char *cs, unsigned off,
                      const char *s, int c)
{
    char *g, *e;
    unsigned long got, exp;

    if (fn[1] == 'h') { /* "chr" */
        g = t2_strchr_sse2(s, c);
        e = ref_strchr(s, c);
    } else { /* "rrc" */
        g = t2_strrchr_sse2(s, c);
        e = ref_strrchr(s, c);
    }
    got = (g == 0) ? 0xFFFFFFFFul : (unsigned long)(g - (char *)buf);
    exp = (e == 0) ? 0xFFFFFFFFul : (unsigned long)(e - (char *)buf);
    puts_("SF ");
    puts_(fn);
    put(" ", 1);
    puts_(cs);
    put(" o=", 3);
    phex((uint32_t)off);
    put(" c=", 3);
    phex((uint32_t)(uint8_t)c);
    put(" got=", 5);
    phex((uint32_t)got);
    put(" exp=", 5);
    phex((uint32_t)exp);
    put(" ", 1);
    finish(g == e);
}

static void strlen_case(const char *cs, unsigned off, const char *s)
{
    unsigned long got = t2_strlen_sse2(s);
    unsigned long exp = ref_strlen(s);
    puts_("SF strlen ");
    puts_(cs);
    put(" o=", 3);
    phex((uint32_t)off);
    put(" got=", 5);
    phex((uint32_t)got);
    put(" exp=", 5);
    phex((uint32_t)exp);
    put(" ", 1);
    finish(got == exp);
}

static void mem_case(const char *cs, unsigned off, const char *s, int c,
                     unsigned long n)
{
    const void *g = t2_memchr_sse2(s, c, n);
    const void *e = ref_memchr(s, c, n);
    unsigned long got = (g == 0) ? 0xFFFFFFFFul
                                 : (unsigned long)((const char *)g - (const char *)buf);
    unsigned long exp = (e == 0) ? 0xFFFFFFFFul
                                 : (unsigned long)((const char *)e - (const char *)buf);
    puts_("SF mem ");
    puts_(cs);
    put(" o=", 3);
    phex((uint32_t)off);
    put(" c=", 3);
    phex((uint32_t)(uint8_t)c);
    put(" n=", 3);
    phex((uint32_t)n);
    put(" got=", 5);
    phex((uint32_t)got);
    put(" exp=", 5);
    phex((uint32_t)exp);
    put(" ", 1);
    finish(g == e);
}

/* ------------------------------------------------------------------ */
/* P1: glibc prologue idiom: movdqu + broadcast + two pcmpeqb +        */
/* pmovmskb (NUL trick); returns (nulmask << 16) | charmask            */
/* ------------------------------------------------------------------ */

static uint32_t p1_head_scan(const char *p, uint32_t c)
{
    uint32_t r;
    __asm__ volatile (
        ".byte 0x66,0x0f,0x6e,0xc9\n\t"  /* movd xmm1, ecx          */
        ".byte 0x66,0x0f,0xef,0xd2\n\t"  /* pxor xmm2, xmm2         */
        ".byte 0x66,0x0f,0x60,0xc9\n\t"  /* punpcklbw xmm1, xmm1    */
        ".byte 0x66,0x0f,0x60,0xc9\n\t"  /* punpcklbw xmm1, xmm1    */
        ".byte 0x66,0x0f,0x70,0xc9,0x00\n\t" /* pshufd xmm1,xmm1,0  */
        ".byte 0xf3,0x0f,0x6f,0x07\n\t"  /* movdqu xmm0, [edi]      */
        ".byte 0x66,0x0f,0x74,0xd0\n\t"  /* pcmpeqb xmm2, xmm0 NUL  */
        ".byte 0x66,0x0f,0x74,0xc1\n\t"  /* pcmpeqb xmm0, xmm1 char */
        ".byte 0x66,0x0f,0xd7,0xd2\n\t"  /* pmovmskb edx, xmm2      */
        ".byte 0x66,0x0f,0xd7,0xc0\n\t"  /* pmovmskb eax, xmm0      */
        "shll $16, %%edx\n\t"
        "orl %%edx, %%eax\n\t"
        : "=a"(r)
        : "D"(p), "c"(c)
        : "edx");
    return r;
}

/* ------------------------------------------------------------------ */
/* P2: PSRLDQ/PSLLDQ after an unaligned movdqu load (raw bytes,        */
/* immediate baked in per variant)                                     */
/* ------------------------------------------------------------------ */

#define P2_FN(nm, mrm, imm)                                                   \
    static void nm(const uint8_t *src, uint8_t *dst)                          \
    {                                                                         \
        __asm__ volatile (                                                    \
            ".byte 0xf3,0x0f,0x6f,0x06\n\t" /* movdqu xmm0,[esi] */           \
            ".byte 0x66,0x0f,0x73," mrm "," #imm "\n\t" /* ps r/l dq */       \
            ".byte 0xf3,0x0f,0x7f,0x07\n\t" /* movdqu [edi],xmm0 */           \
            :                                                                 \
            : "S"(src), "D"(dst)                                              \
            : "memory");                                              \
    }

/* 66 0F 73 group: /2 PSRLQ, /3 PSRLDQ, /6 PSLLQ, /7 PSLLDQ */
P2_FN(p2_rl0, "0xd8", 0)
P2_FN(p2_rl1, "0xd8", 1)
P2_FN(p2_rl15, "0xd8", 15)
P2_FN(p2_rl16, "0xd8", 16)
P2_FN(p2_rl255, "0xd8", 255)
P2_FN(p2_ll0, "0xf8", 0)
P2_FN(p2_ll1, "0xf8", 1)
P2_FN(p2_ll15, "0xf8", 15)
P2_FN(p2_ll16, "0xf8", 16)
P2_FN(p2_ll255, "0xf8", 255)

/* PSRLQ/PSLLQ (66 0F 73 /2 /6): 64-bit BIT shifts of the low qword,
 * upper half preserved. */
static void p2q(const uint8_t *src, uint8_t *dst, int psll)
{
    if (psll) {
        __asm__ volatile (
            ".byte 0xf3,0x0f,0x6f,0x06\n\t"
            ".byte 0x66,0x0f,0x73,0xf0,0x04\n\t" /* psllq xmm0, 4 */
            ".byte 0xf3,0x0f,0x7f,0x07\n\t"
            :
            : "S"(src), "D"(dst)
            : "memory");
    } else {
        __asm__ volatile (
            ".byte 0xf3,0x0f,0x6f,0x06\n\t"
            ".byte 0x66,0x0f,0x73,0xd0,0x04\n\t" /* psrlq xmm0, 4 */
            ".byte 0xf3,0x0f,0x7f,0x07\n\t"
            :
            : "S"(src), "D"(dst)
            : "memory");
    }
}

typedef void (*p2_fn)(const uint8_t *, uint8_t *);

/* ------------------------------------------------------------------ */
/* P3: MOVDQA load + pcmpeqb vs zero + pmovmskb                        */
/* ------------------------------------------------------------------ */

static uint32_t p3_zero_scan(const uint8_t *src, uint8_t *dst)
{
    uint32_t r;
    __asm__ volatile (
        ".byte 0x66,0x0f,0x6f,0x06\n\t"  /* movdqa xmm0, [esi]      */
        ".byte 0x66,0x0f,0xef,0xc9\n\t"  /* pxor xmm1, xmm1         */
        ".byte 0x66,0x0f,0x74,0xc1\n\t"  /* pcmpeqb xmm0, xmm1      */
        ".byte 0xf3,0x0f,0x7f,0x07\n\t"  /* movdqu [edi], xmm0      */
        ".byte 0x66,0x0f,0xd7,0xc0\n\t"  /* pmovmskb eax, xmm0      */
        : "=a"(r)
        : "S"(src), "D"(dst)
        : "memory");
    return r;
}

/* ------------------------------------------------------------------ */
/* P4/P5/P7/P8: packed integer edges, raw op bytes per variant         */
/* ------------------------------------------------------------------ */

#define VEC_OP(nm, opb, mrm)                                                  \
    static void nm(const uint8_t *a, const uint8_t *b, uint8_t *out)          \
    {                                                                         \
        __asm__ volatile (                                                    \
            ".byte 0xf3,0x0f,0x6f,0x06\n\t" /* movdqu xmm0,[esi] */           \
            ".byte 0xf3,0x0f,0x6f,0x09\n\t" /* movdqu xmm1,[ecx] */           \
            ".byte 0x66,0x0f," opb "," mrm "\n\t" /* op xmm0, xmm1 */         \
            ".byte 0xf3,0x0f,0x7f,0x02\n\t" /* movdqu [edx],xmm0 */           \
            :                                                                 \
            : "S"(a), "c"(b), "d"(out)                                        \
            : "memory");                                      \
    }

VEC_OP(p4_eq8, "0x74", "0xc1")
VEC_OP(p4_gt8, "0x64", "0xc1")
VEC_OP(p5_eq32, "0x76", "0xc1")
VEC_OP(p7_min, "0xda", "0xc1")
VEC_OP(p7_max, "0xde", "0xc1")
VEC_OP(p8_sub, "0xf8", "0xc1")

static uint32_t p_pmovmskb(const uint8_t *a)
{
    uint32_t r;
    __asm__ volatile (
        ".byte 0xf3,0x0f,0x6f,0x07\n\t"  /* movdqu xmm0, [edi]      */
        ".byte 0x66,0x0f,0xd7,0xc0\n\t"  /* pmovmskb eax, xmm0      */
        : "=a"(r)
        : "D"(a)
    );
    return r;
}

/* ------------------------------------------------------------------ */
/* P9: MOVQ row                                                        */
/* ------------------------------------------------------------------ */

/* 66 0F D6 m64 store (8 bytes only) + F3 0F 7E m64 load (upper zero)
 * + F3 0F 7F movdqu store of that xmm */
static void p9_movq_row(const uint8_t *src, uint8_t *dst64, uint8_t *dst16)
{
    __asm__ volatile (
        ".byte 0xf3,0x0f,0x6f,0x0e\n\t"  /* movdqu xmm1, [esi]      */
        ".byte 0x66,0x0f,0xd6,0x0f\n\t"  /* movq [edi], xmm1  (m64) */
        ".byte 0xf3,0x0f,0x7e,0x06\n\t"  /* movq xmm0, [esi]  (m64) */
        ".byte 0x66,0x0f,0xd6,0x07\n\t"  /* movq [edi], xmm0  (m64) */
        ".byte 0xf3,0x0f,0x7f,0x01\n\t"  /* movdqu [ecx], xmm0      */
        :
        : "S"(src), "D"(dst64), "c"(dst16)
        : "memory");
}

/* 66 0F D6 C1: reg-reg MOVQ keeps the dest upper half */
static void p9_movq_rr(uint8_t *m)
{
    __asm__ volatile (
        ".byte 0xf3,0x0f,0x6f,0x07\n\t"  /* movdqu xmm0, [edi]      */
        ".byte 0xf3,0x0f,0x6f,0x4f,0x10\n\t" /* movdqu xmm1, 16[edi] */
        ".byte 0x66,0x0f,0xd6,0xc1\n\t"  /* movq xmm1.low, xmm0.low */
        ".byte 0xf3,0x0f,0x7f,0x0f\n\t"  /* movdqu [edi], xmm1      */
        :
        : "D"(m)
        : "memory");
}

/* F3 0F D6 MOVQ2DQ (xmm <- mm, upper zeroed) + F2 0F D6 MOVDQ2Q
 * (mm <- xmm low64); mm0 loaded/stored via plain MOVD. */
static uint32_t p9_movq_mmx(uint8_t *q)
{
    uint32_t r;
    __asm__ volatile (
        ".byte 0x0f,0x6e,0xc1\n\t"       /* movd mm0, ecx (const)   */
        ".byte 0xf3,0x0f,0xd6,0xc0\n\t"  /* movq2dq xmm0, mm0       */
        ".byte 0xf3,0x0f,0x7f,0x07\n\t"  /* movdqu [edi], xmm0      */
        ".byte 0xf3,0x0f,0x6f,0x0e\n\t"  /* movdqu xmm1, [esi]      */
        ".byte 0xf2,0x0f,0xd6,0xc1\n\t"  /* movdq2q mm0, xmm1       */
        ".byte 0x0f,0x7e,0xc0\n\t"       /* movd eax, mm0           */
        ".byte 0x0f,0x77\n\t"            /* emms                    */
        : "=a"(r)
        : "c"(0x11223344u), "D"(q), "S"(q)
        : "memory");
    return r;
}

/* ------------------------------------------------------------------ */
/* P10: MOVD zero-extension (m32 load into dirty xmm, then to eax)     */
/* ------------------------------------------------------------------ */

static uint32_t p10_movd(const uint8_t *a)
{
    uint32_t r;
    __asm__ volatile (
        ".byte 0xf3,0x0f,0x6f,0x06\n\t"  /* movdqu xmm0, [esi]      */
        ".byte 0x66,0x0f,0x6e,0x0e\n\t"  /* movd xmm1, [esi]  (m32) */
        ".byte 0x66,0x0f,0x7e,0xc8\n\t"  /* movd eax, xmm1          */
        : "=a"(r)
        : "S"(a)
    );
    return r;
}

/* ------------------------------------------------------------------ */
/* P11: MOVNTDQ aligned NT store (66 0F E7 07)                         */
/* ------------------------------------------------------------------ */

static void p11_movntdq(const uint8_t *src, uint8_t *dst)
{
    __asm__ volatile (
        ".byte 0xf3,0x0f,0x6f,0x06\n\t"  /* movdqu xmm0, [esi]      */
        ".byte 0x66,0x0f,0xe7,0x07\n\t"  /* movntdq [edi], xmm0     */
        :
        : "S"(src), "D"(dst)
        : "memory");
}

/* ------------------------------------------------------------------ */
/* P12: PREFETCHh + SFENCE                                             */
/* ------------------------------------------------------------------ */

static void p12_prefetch_sfence(uint8_t *p)
{
    __asm__ volatile (
        ".byte 0x0f,0x18,0x00\n\t"       /* prefetchnta [eax]       */
        ".byte 0x0f,0x18,0x08\n\t"       /* prefetch0   [eax]       */
        ".byte 0x0f,0x18,0x10\n\t"       /* prefetch1   [eax]       */
        ".byte 0x0f,0x18,0x18\n\t"       /* prefetch2   [eax]       */
        ".byte 0x0f,0xae,0xf8\n\t"       /* sfence                  */
        :
        : "a"(p)
        : "memory");
}

/* ------------------------------------------------------------------ */
/* P14: por mask merge                                                 */
/* ------------------------------------------------------------------ */

static uint32_t p14_por(const uint8_t *a, const uint8_t *b)
{
    uint32_t r;
    __asm__ volatile (
        ".byte 0xf3,0x0f,0x6f,0x07\n\t"  /* movdqu xmm0, [edi]      */
        ".byte 0xf3,0x0f,0x6f,0x0e\n\t"  /* movdqu xmm1, [esi]      */
        ".byte 0x66,0x0f,0xeb,0xc1\n\t"  /* por xmm0, xmm1          */
        ".byte 0x66,0x0f,0xd7,0xc0\n\t"  /* pmovmskb eax, xmm0      */
        : "=a"(r)
        : "D"(a), "S"(b)
    );
    return r;
}

/* ------------------------------------------------------------------ */
/* P15: MMX plain forms of the T1 rows (raw bytes; EMMS closed)        */
/* ------------------------------------------------------------------ */

static void p15_mmx(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
    __asm__ volatile (
        ".byte 0x0f,0x6f,0x06\n\t"       /* movq mm0, [esi]         */
        ".byte 0x0f,0x6f,0x0f\n\t"       /* movq mm1, [edi]         */
        ".byte 0x0f,0xf8,0xc1\n\t"       /* psubb mm0, mm1          */
        ".byte 0x0f,0x7f,0x01\n\t"       /* movq [ecx], mm0         */
        ".byte 0x0f,0x6f,0x06\n\t"
        ".byte 0x0f,0x74,0xc1\n\t"       /* pcmpeqb mm0, mm1        */
        ".byte 0x0f,0x7f,0x41,0x08\n\t"  /* movq 8[ecx], mm0        */
        ".byte 0x0f,0x6f,0x06\n\t"
        ".byte 0x0f,0x64,0xc1\n\t"       /* pcmpgtb mm0, mm1        */
        ".byte 0x0f,0x7f,0x41,0x10\n\t"  /* movq 16[ecx], mm0       */
        ".byte 0x0f,0x6f,0x06\n\t"
        ".byte 0x0f,0x76,0xc1\n\t"       /* pcmpeqd mm0, mm1        */
        ".byte 0x0f,0x7f,0x41,0x18\n\t"  /* movq 24[ecx], mm0       */
        ".byte 0x0f,0x6f,0x06\n\t"
        ".byte 0x0f,0xda,0xc1\n\t"       /* pminub mm0, mm1         */
        ".byte 0x0f,0x7f,0x41,0x20\n\t"  /* movq 32[ecx], mm0       */
        ".byte 0x0f,0x6f,0x06\n\t"
        ".byte 0x0f,0xde,0xc1\n\t"       /* pmaxub mm0, mm1         */
        ".byte 0x0f,0x7f,0x41,0x28\n\t"  /* movq 40[ecx], mm0       */
        ".byte 0x0f,0x6f,0x06\n\t"
        ".byte 0x0f,0xd7,0xc0\n\t"       /* pmovmskb eax, mm0       */
        "movl %%eax, 48(%2)\n\t"
        ".byte 0x0f,0x6f,0x06\n\t"
        ".byte 0x0f,0x73,0xd0,0x04\n\t"  /* psrlq mm0, 4            */
        ".byte 0x0f,0x7f,0x41,0x38\n\t"  /* movq 56[ecx], mm0       */
        ".byte 0x0f,0x6f,0x06\n\t"
        ".byte 0x0f,0x73,0xf0,0x04\n\t"  /* psllq mm0, 4            */
        ".byte 0x0f,0x7f,0x41,0x40\n\t"  /* movq 64[ecx], mm0       */
        ".byte 0x0f,0x77\n\t"            /* emms                    */
        :
        : "S"(a), "D"(b), "c"(out)
        : "eax", "memory");
}

/* ------------------------------------------------------------------ */
/* expected-value helpers                                              */
/* ------------------------------------------------------------------ */

static void exp_pcmp_eq8(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = a[i] == b[i] ? 0xFFu : 0x00u;
    }
}

static void exp_pcmp_gt8(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = (int8_t)a[i] > (int8_t)b[i] ? 0xFFu : 0x00u;
    }
}

static void exp_pcmp_eq32(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 4u; i++) {
        uint32_t m = ld32(a + 4u * i) == ld32(b + 4u * i) ? 0xFFFFFFFFu : 0u;
        o[4u * i] = (uint8_t)m;
        o[4u * i + 1u] = (uint8_t)(m >> 8);
        o[4u * i + 2u] = (uint8_t)(m >> 16);
        o[4u * i + 3u] = (uint8_t)(m >> 24);
    }
}

static void exp_minmaxub(uint8_t *o, const uint8_t *a, const uint8_t *b, int mx)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = mx ? (a[i] > b[i] ? a[i] : b[i])
                  : (a[i] < b[i] ? a[i] : b[i]);
    }
}

static void exp_psubb(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = (uint8_t)(a[i] - b[i]);
    }
}

static uint32_t exp_pmovmskb(const uint8_t *a)
{
    uint32_t r = 0u;
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        r |= (uint32_t)(a[i] >> 7) << i;
    }
    return r;
}

static void exp_por(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = (uint8_t)(a[i] | b[i]);
    }
}

static int v16_eq(const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static void print_v16(const uint8_t *v)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        phex8(v[i]);
    }
}

static void p_line(const char *nm)
{
    puts_("PR ");
    puts_(nm);
    put(" ", 1);
}

/* ------------------------------------------------------------------ */
/* driver                                                              */
/* ------------------------------------------------------------------ */

__attribute__((noreturn))
void _start(void)
{
    unsigned off, k, vi, ii;
    static const int needle_ofs[9] = { 0, 1, 5, 15, 16, 31, 33, 47, 63 };
    char name[8];

    /* ---------------- S: blob cases ---------------- */

    /* the exact failing dash input first */
    fill_pattern(buf, sizeof buf, 0x2Au);
    __builtin_memcpy(buf + 64, "/usr/bin/sh", 12);
    blob_case("chr", "dash", 64u, (const char *)buf + 64, '/');
    blob_case("rrc", "dash", 64u, (const char *)buf + 64, '/');
    mem_case("dash", 64u, (const char *)buf + 64, '/', 12u);
    mem_case("dash", 64u, (const char *)buf + 64, 'n', 8u);
    mem_case("dash", 64u, (const char *)buf + 64, '/', 0u);
    strlen_case("dash", 64u, (const char *)buf + 64);

    for (off = 0u; off < 64u; off++) {
        name[0] = 'a';
        name[1] = (char)('0' + off / 10u);
        name[2] = (char)('0' + off % 10u);
        name[3] = '\0';

        /* needle at position 0, short string */
        fill_pattern(buf, sizeof buf, (uint8_t)(off + 1u));
        buf[off + 0] = (uint8_t)'/';
        buf[off + 1] = (uint8_t)'x';
        buf[off + 2] = (uint8_t)'y';
        buf[off + 3] = 0u;
        blob_case("chr", name, off, (const char *)buf + off, '/');
        blob_case("rrc", name, off, (const char *)buf + off, '/');
        mem_case(name, off, (const char *)buf + off, '/', 4u);

        /* needles deep, string longer than 16, NUL at 70:
         * chr wants the FIRST, rrc the LAST, mem the first within n */
        fill_pattern(buf, sizeof buf, (uint8_t)(off + 7u));
        for (k = 0u; k < 9u; k++) {
            buf[off + (unsigned)needle_ofs[k]] = (uint8_t)'/';
        }
        buf[off + 70] = 0u;
        blob_case("chr", name, off, (const char *)buf + off, '/');
        blob_case("rrc", name, off, (const char *)buf + off, '/');
        mem_case(name, off, (const char *)buf + off, '/', 70u);
        mem_case(name, off, (const char *)buf + off, '/', 2u);

        /* needle absent entirely */
        fill_pattern(buf, sizeof buf, (uint8_t)(off + 13u));
        buf[off + 71] = 0u;
        blob_case("chr", name, off, (const char *)buf + off, '/');
        blob_case("rrc", name, off, (const char *)buf + off, '/');
        mem_case(name, off, (const char *)buf + off, '/', 71u);

        /* NUL needle: strchr(s, 0) -> terminator; rrc ditto;
         * memchr(s, 0, n) finds the first NUL within n */
        buf[off + 5] = 0u;
        blob_case("chr", name, off, (const char *)buf + off, 0);
        blob_case("rrc", name, off, (const char *)buf + off, 0);
        mem_case(name, off, (const char *)buf + off, 0, 71u);

        /* needle after NUL: chr must stop at the NUL (NULL),
         * rrc ditto; memchr does NOT stop at NUL (finds it) */
        buf[off + 3] = 0u;
        buf[off + 9] = (uint8_t)'/';
        blob_case("chr", name, off, (const char *)buf + off, '/');
        blob_case("rrc", name, off, (const char *)buf + off, '/');
        mem_case(name, off, (const char *)buf + off, '/', 71u);

        /* strlen at this offset, length 20 */
        fill_pattern(buf, sizeof buf, (uint8_t)(off + 3u));
        buf[off + 20] = 0u;
        strlen_case(name, off, (const char *)buf + off);

        /* strlen crossing several 64-byte blocks (multi-loop) */
        fill_pattern(buf, sizeof buf, (uint8_t)(off + 17u));
        buf[off + 130] = 0u;
        strlen_case(name, off, (const char *)buf + off);
    }

    /* needles exactly at 16/32/64/128 boundaries, long strings */
    {
        static const unsigned bofs[4] = { 16u, 32u, 64u, 128u };
        unsigned bi;
        for (bi = 0u; bi < 4u; bi++) {
            for (k = 0u; k < 4u; k++) {
                fill_pattern(buf, sizeof buf, (uint8_t)(bi * 4u + k + 29u));
                buf[bofs[bi] + k] = (uint8_t)'/';
                buf[bofs[bi] + 140] = 0u;
                name[0] = 'b';
                name[1] = (char)('0' + bi);
                name[2] = (char)('0' + k);
                name[3] = '\0';
                blob_case("chr", name, bofs[bi] - k,
                          (const char *)buf + bofs[bi] - k, '/');
                blob_case("rrc", name, bofs[bi] - k,
                          (const char *)buf + bofs[bi] - k, '/');
                mem_case(name, bofs[bi] - k,
                         (const char *)buf + bofs[bi] - k, '/', 140u);
            }
        }
    }


    /* ---------------- P1: head-scan prologue ---------------- */
    for (off = 0u; off < 20u; off++) {
        uint8_t c = (uint8_t)('/' + off);
        uint32_t got, exp = 0u;
        unsigned i;

        fill_pattern(buf, sizeof buf, (uint8_t)(off + 5u));
        buf[off + 3] = 0u;
        buf[off + 7] = c;
        got = p1_head_scan((const char *)buf + off, c);
        for (i = 0u; i < 16u; i++) {
            uint8_t b = buf[off + i];
            if (b == 0u) {
                exp |= 0x10000u << i;
            }
            if (b == c) {
                exp |= 1u << i;
            }
        }
        p_line("p1");
        put("o=", 2);
        phex((uint32_t)off);
        put(" got=", 5);
        phex(got);
        put(" exp=", 5);
        phex(exp);
        put(" ", 1);
        finish(got == exp);
    }

    /* ---------------- P2: PSRLDQ/PSLLDQ ---------------- */
    {
        static const struct { const char *nm; p2_fn f; int psll, imm; } p2t[10] = {
            { "p2rl0", p2_rl0, 0, 0 }, { "p2rl1", p2_rl1, 0, 1 },
            { "p2rl15", p2_rl15, 0, 15 }, { "p2rl16", p2_rl16, 0, 16 },
            { "p2rl255", p2_rl255, 0, 255 },
            { "p2ll0", p2_ll0, 1, 0 }, { "p2ll1", p2_ll1, 1, 1 },
            { "p2ll15", p2_ll15, 1, 15 }, { "p2ll16", p2_ll16, 1, 16 },
            { "p2ll255", p2_ll255, 1, 255 }
        };
        static _Alignas(16) uint8_t p2src[16];
        static _Alignas(16) uint8_t got[16], exp[16];
        unsigned i;
        int psll;

        for (ii = 0u; ii < 10u; ii++) {
            int imm = p2t[ii].imm;
            unsigned run;

            for (run = 0u; run < 2u; run++) {
                if (run == 0u) {
                    for (i = 0u; i < 16u; i++) {
                        p2src[i] = (uint8_t)(i + 1u); /* 0102..0f10 */
                    }
                } else {
                    for (i = 0u; i < 16u; i++) {
                        p2src[i] = 0xFFu;
                    }
                }
                p2t[ii].f(p2src, got);
                for (i = 0u; i < 16u; i++) {
                    exp[i] = 0u;
                    if (imm < 16) {
                        if (p2t[ii].psll) {
                            /* PSLLDQ /7: out[j] = s[j-imm] */
                            if (i >= (unsigned)imm) {
                                exp[i] = p2src[i - (unsigned)imm];
                            }
                        } else {
                            /* PSRLDQ /3: out[j] = s[j+imm] */
                            if (i + (unsigned)imm < 16u) {
                                exp[i] = p2src[i + (unsigned)imm];
                            }
                        }
                    }
                }
                p_line(p2t[ii].nm);
                if (run != 0u) {
                    puts_("ff");
                }
                print_v16(got);
                put(" e=", 3);
                print_v16(exp);
                put(" ", 1);
                finish(v16_eq(got, exp));
            }
        }

        /* PSRLQ/PSLLQ: packed 64-bit bit shifts on BOTH quadwords */
        for (psll = 0; psll <= 1; psll++) {
            uint64_t lo, hi;
            for (i = 0u; i < 16u; i++) {
                p2src[i] = (uint8_t)(i + 1u);
            }
            p2q(p2src, got, psll);
            lo = ld64(p2src);
            hi = ld64(p2src + 8);
            lo = psll ? lo << 4 : lo >> 4;
            hi = psll ? hi << 4 : hi >> 4;
            p_line(psll ? "p2llq" : "p2rlq");
            print_v16(got);
            put(" ", 1);
            finish(ld64(got) == lo && ld64(got + 8) == hi);
        }
    }

    /* ---------------- P3: zero scan on edge vectors ---------------- */
    {
        static const uint8_t vecs[4][16] = {
            { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
              0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
            { 0x00, 0xFF, 0x00, 0xFF, 0x80, 0x7F, 0x80, 0x7F,
              0x01, 0xFE, 0x55, 0xAA, 0x00, 0x80, 0xFF, 0x7F }
        };
        static _Alignas(16) uint8_t got[16];
        static _Alignas(16) uint8_t src[16]; /* MOVDQA source */
        uint8_t exp[16];
        for (vi = 0u; vi < 4u; vi++) {
            uint32_t m;
            unsigned i;
            for (i = 0u; i < 16u; i++) {
                src[i] = vecs[vi][i];
            }
            m = p3_zero_scan(src, got);
            for (i = 0u; i < 16u; i++) {
                exp[i] = vecs[vi][i] == 0u ? 0xFFu : 0x00u;
            }
            p_line("p3");
            put("v=", 2);
            phex(vi);
            put(" m=", 3);
            phex(m);
            print_v16(got);
            put(" ", 1);
            finish(m == exp_pmovmskb(exp) && v16_eq(got, exp));
        }
    }

    /* ---------------- P4..P8: packed integer edges ---------------- */
    {
        static const uint8_t A[16] = {
            0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x55, 0xAA,
            0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x55, 0xAA
        };
        static const uint8_t B[16] = {
            0xFF, 0x00, 0x7F, 0x80, 0x01, 0x01, 0xAA, 0x55,
            0x00, 0x00, 0x80, 0x80, 0x7F, 0x7F, 0xAA, 0x55
        };
        static _Alignas(16) uint8_t got[16];
        uint8_t exp[16];

        p4_eq8(A, B, got);
        exp_pcmp_eq8(exp, A, B);
        p_line("p4eq8");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p4_gt8(A, B, got);
        exp_pcmp_gt8(exp, A, B);
        p_line("p4gt8");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p5_eq32(A, B, got);
        exp_pcmp_eq32(exp, A, B);
        p_line("p5eq32");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p7_min(A, B, got);
        exp_minmaxub(exp, A, B, 0);
        p_line("p7min");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p7_max(A, B, got);
        exp_minmaxub(exp, A, B, 1);
        p_line("p7max");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p8_sub(A, B, got);
        exp_psubb(exp, A, B);
        p_line("p8sub");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p8_sub(B, A, got);
        exp_psubb(exp, B, A);
        p_line("p8swp");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));
    }

    /* ---------------- P6: pmovmskb edge patterns ---------------- */
    {
        static const uint8_t P[6][16] = {
            { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
              0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
            { 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
              0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F },
            { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
              0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA },
            { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
              0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 }
        };
        for (vi = 0u; vi < 6u; vi++) {
            uint32_t got = p_pmovmskb(P[vi]);
            uint32_t exp = exp_pmovmskb(P[vi]);
            p_line("p6");
            put("v=", 2);
            phex(vi);
            put(" got=", 5);
            phex(got);
            put(" exp=", 5);
            phex(exp);
            put(" ", 1);
            finish(got == exp);
        }
    }

    /* ---------------- P9: MOVQ row ---------------- */
    {
        static _Alignas(16) uint8_t src[32];
        static _Alignas(16) uint8_t d64[16], d16[16], m[32];
        unsigned i;

        for (i = 0u; i < 32u; i++) {
            src[i] = (uint8_t)(0xA0u + i);
        }
        for (i = 0u; i < 16u; i++) {
            d64[i] = 0x1Cu;
            d16[i] = 0x2Du;
        }
        p9_movq_row(src, d64, d16);
        p_line("p9a");
        print_v16(d64);
        put(" ", 1);
        /* 66 0F D6 m64 store wrote only the low 8 bytes, twice */
        finish(d64[0] == 0xA0u && d64[7] == 0xA7u && d64[8] == 0x1Cu);
        p_line("p9b");
        print_v16(d16);
        put(" ", 1);
        /* F3 0F 7E m64 load zero-extends: d16 high half is zero */
        finish(d16[0] == 0xA0u && d16[7] == 0xA7u && d16[8] == 0x00u &&
               d16[15] == 0x00u);

        for (i = 0u; i < 16u; i++) {
            m[i] = (uint8_t)(0xC0u + i);      /* low pattern  */
            m[16u + i] = (uint8_t)(0xD0u + i); /* high pattern */
        }
        p9_movq_rr(m);
        p_line("p9rr");
        print_v16(m);
        put(" ", 1);
        /* 66 0F D6 reg-reg: xmm1.low <- xmm0.low (C0..C7), and the
         * destination's upper half is CLEARED (both qemu oracles) */
        finish(m[0] == 0xC0u && m[7] == 0xC7u && m[8] == 0x00u &&
               m[15] == 0x00u);

        {
            uint8_t q[16];
            uint32_t back;
            for (i = 0u; i < 16u; i++) {
                q[i] = (uint8_t)(0xE0u + i);
            }
            back = p9_movq_mmx(q);
            p_line("p9mm");
            print_v16(q);
            put(" back=", 6);
            phex(back);
            put(" ", 1);
            /* movq2dq: q <- {44,33,22,11,0,...}; the movdq2q+movd
             * round trip returns the const via mm0. */
            finish(q[0] == 0x44u && q[1] == 0x33u && q[2] == 0x22u &&
                   q[3] == 0x11u && q[4] == 0x00u &&
                   back == 0x11223344u);
        }
    }

    /* ---------------- P10: MOVD zero-extension ---------------- */
    {
        static _Alignas(16) uint8_t a[16];
        uint32_t got;
        unsigned i;
        for (i = 0u; i < 16u; i++) {
            a[i] = 0xF0u;
        }
        a[0] = 0x78u;
        a[1] = 0x56u;
        a[2] = 0x34u;
        a[3] = 0x12u;
        got = p10_movd(a);
        p_line("p10");
        put("got=", 4);
        phex(got);
        put(" ", 1);
        finish(got == 0x12345678u);
    }

    /* ---------------- P11: MOVNTDQ aligned ---------------- */
    {
        static _Alignas(16) uint8_t dst[16];
        uint8_t src[16];
        unsigned i;
        for (i = 0u; i < 16u; i++) {
            src[i] = (uint8_t)(0x60u + i);
            dst[i] = 0;
        }
        p11_movntdq(src, dst);
        p_line("p11");
        print_v16(dst);
        put(" ", 1);
        finish(v16_eq(dst, src));
    }

    /* ---------------- P12: prefetch + sfence ---------------- */
    {
        uint8_t m[16];
        unsigned i;
        for (i = 0u; i < 16u; i++) {
            m[i] = (uint8_t)(0x11u * (i + 1u));
        }
        p12_prefetch_sfence(m);
        p_line("p12");
        print_v16(m);
        put(" ", 1);
        finish(m[0] == 0x11u && m[1] == 0x22u && m[2] == 0x33u &&
               m[3] == 0x44u && m[4] == 0x55u && m[5] == 0x66u &&
               m[6] == 0x77u && m[7] == 0x88u && m[8] == 0x99u &&
               m[15] == 0x10u);
    }

    /* ---------------- P14: por ---------------- */
    {
        static const uint8_t X[16] = {
            0xF0, 0x0F, 0xAA, 0x55, 0x00, 0xFF, 0x80, 0x7F,
            0x01, 0xFE, 0x11, 0xEE, 0x22, 0xDD, 0x44, 0xBB
        };
        static const uint8_t Y[16] = {
            0x0F, 0xF0, 0x55, 0xAA, 0xFF, 0x00, 0x7F, 0x80,
            0xFE, 0x01, 0x11, 0x11, 0x00, 0x00, 0xBB, 0xBB
        };
        uint8_t z[16];
        uint32_t got = p14_por(X, Y);
        exp_por(z, X, Y);
        p_line("p14");
        put("got=", 4);
        phex(got);
        put(" exp=", 5);
        phex(exp_pmovmskb(z));
        put(" ", 1);
        finish(got == exp_pmovmskb(z));
    }

    /* ---------------- P15: MMX plain forms ---------------- */
    {
        static const uint8_t MA[8] = { 0x00, 0xFF, 0x80, 0x7F,
                                       0x01, 0xFE, 0x55, 0xAA };
        static const uint8_t MB[8] = { 0xFF, 0x00, 0x7F, 0x80,
                                       0x01, 0x01, 0xAA, 0x55 };
        static _Alignas(16) uint8_t out[80];
        uint8_t a[16], b[16], e[16];
        uint64_t v;
        int ok = 1;
        unsigned i;

        for (i = 0u; i < 8u; i++) {
            a[i] = MA[i];
            a[8u + i] = 0u;
            b[i] = MB[i];
            b[8u + i] = 0u;
        }
        for (i = 0u; i < (unsigned)sizeof out; i++) {
            out[i] = 0xCCu;
        }
        p15_mmx(MA, MB, out);

        exp_psubb(e, a, b);            /* out[0..7]   */
        ok = ok && v8_eq(out, e);
        exp_pcmp_eq8(e, a, b);         /* out[8..15]  */
        ok = ok && v8_eq(out + 8, e);
        exp_pcmp_gt8(e, a, b);         /* out[16..23] */
        ok = ok && v8_eq(out + 16, e);
        exp_pcmp_eq32(e, a, b);        /* out[24..31] */
        ok = ok && v8_eq(out + 24, e);
        exp_minmaxub(e, a, b, 0);      /* out[32..39] */
        ok = ok && v8_eq(out + 32, e);
        exp_minmaxub(e, a, b, 1);      /* out[40..47] */
        ok = ok && v8_eq(out + 40, e);
        ok = ok && ld32(out + 48) == exp_pmovmskb(a); /* pmovmskb mm (8b) */
        v = ld64(a);
        ok = ok && ld64(out + 56) == (v >> 4) &&
                    ld64(out + 64) == (v << 4) && out[72] == 0xCCu;
        p_line("p15");
        put("got=", 4);
        print_v16(out);
        put(" ", 1);
        finish(ok);
    }

    puts_("DONE ");
    put_dec(total);
    put(" FAIL ", 6);
    put_dec(fails);
    put("\n", 1);
    sys_exit(fails == 0u ? 0L : 1L);
}
