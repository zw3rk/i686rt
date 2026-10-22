/*
 * tests/unit/test_l5a.c — DBT lane L5a check: SSE/SSE2/MMX emitters
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Based on tests/unit/test_l3a.c: each case writes hand-assembled x86
 * SSE bytes into a fake guest window, runs them through
 * i686_dbt_translate + i686_jit_run_block (an HLT sentinel ends every
 * stream), and compares the resulting XMM/GPR/EFLAGS/MXCSR/memory/x87
 * state bit-exactly against expectations computed here in C — via the
 * frozen ctx layout plus <arm_neon.h> intrinsics for the FP arithmetic
 * families (the interpreter oracle h_sse is L5b's file and is not
 * merged yet).  The first block's exit {reason, arg, dest} is asserted
 * to prove the SSE insns executed natively: the block must end exactly
 * at the sentinel (an emitter decline would UNDEF at that insn's own
 * PC) as HLT (or the 1-byte-HLT UNDEF shape).
 *
 * Compiles and runs on aarch64 Linux only (the DBT emits and executes
 * A64; run inside the arm64 docker VM per docs/lanes/phase-5.md).
 * Expected final line: L5A OK.
 */

#define _GNU_SOURCE /* MAP_ANONYMOUS/MAP_NORESERVE, as in src/rt32 */

#include <arm_neon.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x1000
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

#include "dbt/emit.h"
#include "i686rt.h"
#include "interp/interp.h"

extern size_t i686_dbt_translate(i686_ctx_t *ctx, uint32_t eip, uint8_t *code,
                                 size_t cap);
extern uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                                   void *cur_entry, const void *epoch_ptr);

#define WIN_FULL  0x100000000ULL
#define WIN_SMALL 0x1000000UL
#define CODE_CAP  4096U
#define CASE_EIP  0x001000U
#define DATA1     0x002000U
#define DATA2     0x002100U

static uint8_t  *g_win;
static uint8_t  *g_code;
static uint32_t  g_epoch;
static int       g_pass;
static int       g_fail;
static i686_ctx_t g_c; /* final ctx of the last run case */

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

/* Initial guest state per case: code + optional 16 B data at DATA1,
 * GPRs, EFLAGS, MXCSR, 8 XMM registers as LE u32 lanes, ftag, and the
 * low qwords of x87_st[6]/[7] (the MMX alias file). */
typedef struct {
    const uint8_t *code;
    size_t         clen;
    const uint32_t *data;     /* 4 dwords placed at DATA1 */
    uint32_t       gpr[8];
    uint32_t       eflags;
    const uint32_t (*xmm)[4]; /* NULL or 8 entries           */
    uint32_t       mxcsr;
    uint16_t       ftag;
    uint64_t       mm[3];     /* st[6], st[7], st[1] low qwords */
} case_t;

static void prime(const case_t *k)
{
    memset(&g_win[CASE_EIP], 0xCC, 0x1000U);
    memcpy(&g_win[CASE_EIP], k->code, k->clen);
    g_win[CASE_EIP + k->clen] = 0xF4U; /* HLT sentinel */
    memset(&g_win[DATA1], 0, 32U);
    memset(&g_win[DATA2], 0, 32U);
    if (k->data != NULL) {
        memcpy(&g_win[DATA1], k->data, 16U);
    }
}

static void ctx_setup(i686_ctx_t *c, const case_t *k)
{
    memset(c, 0, sizeof(*c));
    c->guest_base = (uint64_t)(uintptr_t)g_win;
    c->eip = CASE_EIP;
    memcpy(c->gpr, k->gpr, sizeof(c->gpr));
    c->eflags = k->eflags | 0x2U;
    c->mxcsr = (k->mxcsr != 0U) ? k->mxcsr : 0x1F80U;
    c->ftag = k->ftag;
    if (k->xmm != NULL) {
        memcpy(c->xmm, k->xmm, sizeof(c->xmm));
    }
    memcpy(&c->x87_st[6][0], &k->mm[0], 8U);
    memcpy(&c->x87_st[7][0], &k->mm[1], 8U);
    memcpy(&c->x87_st[1][0], &k->mm[2], 8U);
}

/* Drive translate + run; finish any interpret-one fallback with the
 * interpreter.  first_* capture block #1's exit for the native proof. */
static int dbt_engine(i686_ctx_t *c, uint32_t *first_reason,
                      uint32_t *first_arg, uint32_t *first_dest)
{
    unsigned iter;

    for (iter = 0U; iter < 32U; iter++) {
        size_t len = i686_dbt_translate(c, c->eip, g_code, CODE_CAP);
        if (len == 0U) {
            return -1;
        }
        (void)i686_jit_run_block(c, (const void *)g_code, NULL,
                                 (const void *)&g_epoch);
        if (iter == 0U) {
            *first_reason = c->exit_reason;
            *first_arg = c->exit_arg;
            *first_dest = c->exit_dest;
        }
        if (c->exit_reason == I686_EXIT_BRANCH) {
            c->eip = c->exit_dest;
            continue;
        }
        if (c->exit_reason == I686_EXIT_UNDEF) {
            c->eip = c->exit_dest;
            return i686_interp_run(c);
        }
        return (int)c->exit_reason;
    }
    return -1;
}

/* Run one case into g_c.  Returns 0 when the engine reached HLT with
 * the native proof intact (caller then checks state), -1 otherwise. */
static int run_case(const char *name, const case_t *k)
{
    uint32_t fr = 0U, fa = 0U, fd = 0U;
    int rc;

    prime(k);
    ctx_setup(&g_c, k);
    rc = dbt_engine(&g_c, &fr, &fa, &fd);
    if (rc != I686_EXIT_HLT) {
        printf("FAIL %s: dbt engine rc=%d (first exit %u/%u ->%08x)\n", name,
               rc, fr, fa, fd);
        g_fail++;
        return -1;
    }
    /* Native proof: the block covered every SSE insn and ended at the
     * sentinel — either the emitted HLT exit (dest = post-HLT resume
     * PC) or the declined-HLT UNDEF shape (arg 1, dest = HLT PC).  An
     * emitter decline would UNDEF at that SSE insn's own PC instead. */
    if (!((fr == I686_EXIT_HLT && fd == (uint32_t)(CASE_EIP + k->clen + 1U)) ||
          (fr == I686_EXIT_UNDEF && fa == 1U &&
           fd == (uint32_t)(CASE_EIP + k->clen)))) {
        printf("FAIL %s: not native: first exit %u/%u ->%08x (want HLT"
               " ->%08x or UNDEF/1 ->%08x)\n",
               name, fr, fa, fd, (uint32_t)(CASE_EIP + k->clen + 1U),
               (uint32_t)(CASE_EIP + k->clen));
        g_fail++;
        return -1;
    }
    return 0;
}

static void xmm_eq(unsigned r, const uint32_t w[4])
{
    if (memcmp(g_c.xmm[r], w, 16U) != 0) {
        uint32_t g[4];
        memcpy(g, g_c.xmm[r], 16U);
        printf("FAIL xmm%u: got {%08x %08x %08x %08x} want {%08x %08x"
               " %08x %08x}\n",
               r, g[0], g[1], g[2], g[3], w[0], w[1], w[2], w[3]);
    }
    CHECK(memcmp(g_c.xmm[r], w, 16U) == 0);
}

static void mm_eq(unsigned r, uint64_t v)
{
    uint64_t got;
    memcpy(&got, &g_c.x87_st[r][0], 8U);
    if (got != v) {
        printf("FAIL mm%u: got %016llx want %016llx\n", r,
               (unsigned long long)got, (unsigned long long)v);
    }
    CHECK(got == v);
}

static uint32_t xmm_word(unsigned r, unsigned i)
{
    uint32_t v;
    memcpy(&v, &g_c.xmm[r][4U * i], 4U);
    return v;
}

static uint32_t data_word(unsigned va, unsigned idx)
{
    uint32_t v;
    memcpy(&v, &g_win[va + 4U * idx], 4U);
    return v;
}

int main(void)
{
    g_win = mmap(NULL, WIN_FULL, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (g_win == MAP_FAILED) {
        g_win = mmap(NULL, WIN_SMALL, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    g_code = mmap(NULL, CODE_CAP, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_win == MAP_FAILED || g_code == MAP_FAILED) {
        printf("L5A FAILED: mmap window/code\n");
        return 1;
    }
    i686_interp_init_all();

    /* 1. MOVUPS reg + MOVAPS mem load/store (full 128-bit). */
    {
        static const uint8_t code[] = {
            0x0F, 0x10, 0xC1,             /* movups xmm0, xmm1  */
            0x0F, 0x28, 0x16,             /* movaps xmm2, [esi] */
            0x0F, 0x29, 0x17,             /* movaps [edi], xmm2 */
        };
        static const uint32_t mem[4] = {0x44332211U, 0x88776655U,
                                        0xCCBBAA99U, 0xEEDDFF00U};
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0x11223344U, 0x55667788U, 0x99AABBCCU, 0xDEADBEEFU},
        };
        case_t k = {code, sizeof code, mem,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("movups/movaps", &k) == 0) {
            xmm_eq(0, xmm[1]);
            xmm_eq(2, mem);
            CHECK(data_word(DATA2, 0) == mem[0] &&
                  data_word(DATA2, 3) == mem[3]);
        }
    }

    /* 2. MOVSS/MOVSD loads keep the destination upper; MOVSS stores
     *    the low lane only; reg-reg MOVSD copies one lane. */
    {
        static const uint8_t code[] = {
            0xF3, 0x0F, 0x10, 0x06,       /* movss xmm0, [esi]  */
            0xF2, 0x0F, 0x10, 0x16,       /* movsd xmm2, [esi]  */
            0xF3, 0x0F, 0x11, 0x07,       /* movss [edi], xmm0  */
            0xF2, 0x0F, 0x11, 0xD1,       /* movsd xmm1, xmm2   */
        };
        static const uint32_t mem[4] = {0x40490FDBU, 0x400921FBU,
                                        0x3FC90FDBU, 0x11223344U};
        static const uint32_t xmm[8][4] = {
            {0x11111111U, 0x22222222U, 0x33333333U, 0x44444444U},
            {0U, 0U, 0U, 0U},
            {0xAAAAAAAAU, 0xBBBBBBBBU, 0xCCCCCCCCU, 0xDDDDDDDDU},
        };
        case_t k = {code, sizeof code, mem,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("movss/movsd lanes", &k) == 0) {
            static const uint32_t e0[4] = {0x40490FDBU, 0x22222222U,
                                           0x33333333U, 0x44444444U};
            static const uint32_t e2[4] = {0x40490FDBU, 0x400921FBU,
                                           0xCCCCCCCCU, 0xDDDDDDDDU};
            static const uint32_t e1[4] = {0x40490FDBU, 0x400921FBU,
                                           0U, 0U};
            xmm_eq(0, e0);
            xmm_eq(2, e2);
            xmm_eq(1, e1); /* lane copy preserved xmm1's zero upper */
            CHECK(data_word(DATA2, 0) == 0x40490FDBU);
            CHECK(data_word(DATA2, 1) == 0U); /* only 4 bytes stored */
        }
    }

    /* 3. MOVAPD reg + MOVHPD/MOVLPD load + MOVUPD store. */
    {
        static const uint8_t code[] = {
            0x66, 0x0F, 0x28, 0xC1,       /* movapd xmm0, xmm1    */
            0x66, 0x0F, 0x16, 0x06,       /* movhpd xmm0, [esi]   */
            0x66, 0x0F, 0x12, 0x46, 0x08, /* movlpd xmm0, [esi+8] */
            0x66, 0x0F, 0x11, 0x07,       /* movupd [edi], xmm0   */
        };
        static const uint32_t mem[4] = {0x99999999U, 0x11111111U,
                                        0x77777777U, 0x33333333U};
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0xAAAAAAAAU, 0xAAAAAAAAU, 0x55555555U, 0x55555555U},
        };
        case_t k = {code, sizeof code, mem,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("movapd/movhpd/movlpd/movupd", &k) == 0) {
            static const uint32_t e0[4] = {0x77777777U, 0x33333333U,
                                           0x99999999U, 0x11111111U};
            xmm_eq(0, e0);
            CHECK(data_word(DATA2, 0) == 0x77777777U &&
                  data_word(DATA2, 3) == 0x11111111U);
        }
    }

    /* 3b. Plain MOVLPS/MOVHPS lane moves + MOVHLPS/MOVLHPS reg forms. */
    {
        static const uint8_t code[] = {
            0x0F, 0x12, 0x06,             /* movlps  xmm0, [esi] */
            0x0F, 0x16, 0x0E,             /* movhps  xmm1, [esi] */
            0x0F, 0x12, 0xD3,             /* movhlps xmm2, xmm3  */
            0x0F, 0x16, 0xE3,             /* movlhps xmm4, xmm3  */
            0x0F, 0x13, 0x07,             /* movlps  [edi], xmm0 */
            0x0F, 0x17, 0x67, 0x08,       /* movhps  [edi+8], xmm4 */
        };
        static const uint32_t mem[4] = {0x11111111U, 0x22222222U,
                                        0x33333333U, 0x44444444U};
        static const uint32_t xmm[8][4] = {
            {0xA0A0A0A0U, 0xA1A1A1A1U, 0xA2A2A2A2U, 0xA3A3A3A3U},
            {0xB0B0B0B0U, 0xB1B1B1B1U, 0xB2B2B2B2U, 0xB3B3B3B3U},
            {0xC0C0C0C0U, 0xC1C1C1C1U, 0xC2C2C2C2U, 0xC3C3C3C3U},
            {0xD0D0D0D0U, 0xD1D1D1D1U, 0xD2D2D2D2U, 0xD3D3D3D3U},
            {0xE0E0E0E0U, 0xE1E1E1E1U, 0xE2E2E2E2U, 0xE3E3E3E3U},
        };
        case_t k = {code, sizeof code, mem,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("movlps/movhps/movhlps/movlhps", &k) == 0) {
            static const uint32_t e0[4] = {0x11111111U, 0x22222222U,
                                           0xA2A2A2A2U, 0xA3A3A3A3U};
            static const uint32_t e1[4] = {0xB0B0B0B0U, 0xB1B1B1B1U,
                                           0x11111111U, 0x22222222U};
            static const uint32_t e2[4] = {0xD2D2D2D2U, 0xD3D3D3D3U,
                                           0xC2C2C2C2U, 0xC3C3C3C3U};
            static const uint32_t e4[4] = {0xE0E0E0E0U, 0xE1E1E1E1U,
                                           0xD0D0D0D0U, 0xD1D1D1D1U};
            xmm_eq(0, e0);
            xmm_eq(1, e1);
            xmm_eq(2, e2);
            xmm_eq(4, e4);
            CHECK(data_word(DATA2, 0) == 0x11111111U &&
                  data_word(DATA2, 1) == 0x22222222U);
            CHECK(data_word(DATA2, 2) == 0xD0D0D0D0U &&
                  data_word(DATA2, 3) == 0xD1D1D1D1U);
        }
    }

    /* 4. MOVD gpr<->xmm (zero-extension) + MOVQ reg (upper zeroed) +
     *    MOVQ xmm, m64 load (F3 7E). */
    {
        static const uint8_t code[] = {
            0x66, 0x0F, 0x6E, 0xC0,       /* movd xmm0, eax  */
            0x66, 0x0F, 0x7E, 0xC8,       /* movd eax, xmm1  */
            0xF3, 0x0F, 0x7E, 0xD1,       /* movq xmm2, xmm1 */
            0x66, 0x0F, 0x6E, 0x1E,       /* movd xmm3, [esi] */
            0xF3, 0x0F, 0x7E, 0x26,       /* movq xmm4, [esi] */
        };
        static const uint32_t mem[4] = {0xCAFEBABEU, 0xFEEDFACEU, 0U, 0U};
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0x01020304U, 0x05060708U, 0U, 0U},
            {0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU},
            {0U, 0U, 0U, 0U},
            {0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU},
        };
        case_t k = {code, sizeof code, mem,
                    {0x89ABCDEFU, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("movd/movq", &k) == 0) {
            static const uint32_t e0[4] = {0x89ABCDEFU, 0U, 0U, 0U};
            static const uint32_t e2[4] = {0x01020304U, 0x05060708U, 0U, 0U};
            static const uint32_t e3[4] = {0xCAFEBABEU, 0U, 0U, 0U};
            static const uint32_t e4[4] = {0xCAFEBABEU, 0xFEEDFACEU, 0U, 0U};
            xmm_eq(0, e0);
            CHECK(g_c.gpr[I686_REG_EAX] == 0x01020304U);
            xmm_eq(2, e2);
            xmm_eq(3, e3);
            xmm_eq(4, e4);
        }
    }

    /* 5. PUNPCKLDQ/HDQ/LQDQ/HQDQ + PUNPCKLBW/HWD (byte/word lanes). */
    {
        static const uint8_t code[] = {
            0x66, 0x0F, 0x62, 0xC1,       /* punpckldq  xmm0, xmm1 */
            0x66, 0x0F, 0x6A, 0xD1,       /* punpckhdq  xmm2, xmm1 */
            0x66, 0x0F, 0x6C, 0xD9,       /* punpcklqdq xmm3, xmm1 */
            0x66, 0x0F, 0x6D, 0xE1,       /* punpckhqdq xmm4, xmm1 */
            0x66, 0x0F, 0x60, 0xEE,       /* punpcklbw  xmm5, xmm6 */
            0x66, 0x0F, 0x69, 0xF5,       /* punpckhwd  xmm6, xmm5 */
        };
        static const uint32_t xmm[8][4] = {
            {0xA0U, 0xA1U, 0xA2U, 0xA3U},
            {0xB0U, 0xB1U, 0xB2U, 0xB3U},
            {0xC0U, 0xC1U, 0xC2U, 0xC3U},
            {0xD0U, 0xD1U, 0xD2U, 0xD3U},
            {0xE0U, 0xE1U, 0xE2U, 0xE3U},
            {0x03020100U, 0x07060504U, 0x0B0A0908U, 0x0F0E0D0CU},
            {0x13121110U, 0x17161514U, 0x1B1A1918U, 0x1F1E1D1CU},
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("punpck b/w/d/q", &k) == 0) {
            static const uint32_t e0[4] = {0xA0U, 0xB0U, 0xA1U, 0xB1U};
            static const uint32_t e2[4] = {0xC1U, 0xB1U, 0xC3U, 0xB3U};
            static const uint32_t e3[4] = {0xD0U, 0xD1U, 0xB0U, 0xB1U};
            static const uint32_t e4[4] = {0xE2U, 0xE3U, 0xB2U, 0xB3U};
            /* punpcklbw interleaves dest-low bytes with src-low bytes
             * (dest byte first); punpckhwd then reads xmm5's UPDATED
             * high words {1404,1505,1606,1707} (chained in-stream). */
            static const uint32_t e5[4] = {0x11011000U, 0x13031202U,
                                           0x15051404U, 0x17071606U};
            static const uint32_t e6[4] = {0x14041918U, 0x15051B1AU,
                                           0x16061D1CU, 0x17071F1EU};
            xmm_eq(0, e0);
            xmm_eq(2, e2);
            xmm_eq(3, e3);
            xmm_eq(4, e4);
            xmm_eq(5, e5);
            xmm_eq(6, e6);
        }
    }

    /* 6. PSHUFD/PSHUFLW/PSHUFHW (sel 0x1B = reverse) + PSHUFW (MMX). */
    {
        static const uint8_t code[] = {
            0x66, 0x0F, 0x70, 0xC1, 0x1B, /* pshufd  xmm0, xmm1 */
            0xF2, 0x0F, 0x70, 0xD1, 0x1B, /* pshuflw xmm2, xmm1 */
            0xF3, 0x0F, 0x70, 0xD9, 0x1B, /* pshufhw xmm3, xmm1 */
            0x0F, 0x70, 0xC1, 0x1B,       /* pshufw  mm0, mm1   */
        };
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0x03020100U, 0x07060504U, 0x0B0A0908U, 0x0F0E0D0CU},
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0xAAAAU, {0U, 0U, 0x7777555533331111ULL}};
        if (run_case("pshufd/pshuflw/pshufhw/pshufw", &k) == 0) {
            static const uint32_t e0[4] = {0x0F0E0D0CU, 0x0B0A0908U,
                                           0x07060504U, 0x03020100U};
            static const uint32_t e2[4] = {0x05040706U, 0x01000302U,
                                           0x0B0A0908U, 0x0F0E0D0CU};
            static const uint32_t e3[4] = {0x03020100U, 0x07060504U,
                                           0x0D0C0F0EU, 0x09080B0AU};
            xmm_eq(0, e0);
            xmm_eq(2, e2);
            xmm_eq(3, e3);
            /* pshufw reversed mm1's words into mm0; tags -> valid */
            mm_eq(0, 0x1111333355557777ULL);
            CHECK(g_c.ftag == 0U);
        }
    }

    /* 7. PADDD/PADDQ/PSUBD/PSUBQ/PMULLW/PMULUDQ (C-computed wraps). */
    {
        static const uint8_t code[] = {
            0x66, 0x0F, 0xFE, 0xC1,       /* paddd   xmm0, xmm1 */
            0x66, 0x0F, 0xD4, 0xD1,       /* paddq   xmm2, xmm1 */
            0x66, 0x0F, 0xFB, 0xD9,       /* psubq   xmm3, xmm1 */
            0x66, 0x0F, 0xFA, 0xE1,       /* psubd   xmm4, xmm1 */
            0x66, 0x0F, 0xD5, 0xE9,       /* pmullw  xmm5, xmm1 */
            0x66, 0x0F, 0xF4, 0xF1,       /* pmuludq xmm6, xmm1 */
        };
        static const uint32_t xmm[8][4] = {
            {0x7FFFFFFFU, 1U, 10U, 20U},
            {1U, 0xFFFFFFFFU, 300U, 400U},
            {0xFFFFFFFFU, 0xFFFFFFFFU, 2U, 3U},
            {5U, 0U, 0U, 0U},
            {0x80000000U, 0U, 0U, 0U},
            {0x8000U, 0x7FFFU, 0x00FFU, 0x0101U},
            {0x00010001U, 0x00FF00FFU, 0U, 0U},
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("pint arith", &k) == 0) {
            uint32_t e[4];
            /* paddd */
            e[0] = 0x7FFFFFFFU + 1U; e[1] = 1U + 0xFFFFFFFFU;
            e[2] = 10U + 300U; e[3] = 20U + 400U;
            xmm_eq(0, e);
            /* paddq / psubq as 64-bit lanes */
            {
                uint64_t q0 = 0xFFFFFFFFFFFFFFFFULL + 0xFFFFFFFF00000001ULL;
                uint64_t q1 = ((uint64_t)2U | ((uint64_t)3U << 32)) +
                              ((uint64_t)300U | ((uint64_t)400U << 32));
                memcpy(e, &q0, 8U); memcpy(e + 2, &q1, 8U);
                xmm_eq(2, e);
                q0 = 5ULL - 0xFFFFFFFF00000001ULL;
                q1 = 0ULL - ((uint64_t)300U | ((uint64_t)400U << 32));
                memcpy(e, &q0, 8U); memcpy(e + 2, &q1, 8U);
                xmm_eq(3, e);
            }
            /* psubd */
            e[0] = 0x80000000U - 1U; e[1] = 0U - 0xFFFFFFFFU;
            e[2] = 0U - 300U; e[3] = 0U - 400U;
            xmm_eq(4, e);
            /* pmullw: 16-bit lanes of both operands */
            {
                uint16_t w[8];
                unsigned i;
                for (i = 0U; i < 8U; i++) {
                    uint16_t a = (uint16_t)(xmm[5][i / 2U] >> (16U * (i % 2U)));
                    uint16_t b = (uint16_t)(xmm[1][i / 2U] >> (16U * (i % 2U)));
                    w[i] = (uint16_t)(a * b);
                }
                memcpy(e, w, 8U);
                e[2] = (uint32_t)w[4] | ((uint32_t)w[5] << 16);
                e[3] = (uint32_t)w[6] | ((uint32_t)w[7] << 16);
                xmm_eq(5, e);
            }
            /* pmuludq: even dwords, zero-extended 32x32 -> 64 */
            {
                uint64_t q0 = (uint64_t)xmm[6][0] * (uint64_t)xmm[1][0];
                uint64_t q1 = (uint64_t)xmm[6][2] * (uint64_t)xmm[1][2];
                memcpy(e, &q0, 8U); memcpy(e + 2, &q1, 8U);
                xmm_eq(6, e);
            }
        }
    }

    /* 8. PXOR/PAND/PANDN/POR + ANDPS/XORPS/XORPD. */
    {
        static const uint8_t code[] = {
            0x66, 0x0F, 0xEF, 0xC1,       /* pxor  xmm0, xmm1 */
            0x66, 0x0F, 0xDB, 0xD1,       /* pand  xmm2, xmm1 */
            0x66, 0x0F, 0xEB, 0xD9,       /* por   xmm3, xmm1 */
            0x66, 0x0F, 0xDF, 0xE1,       /* pandn xmm4, xmm1 */
            0x0F, 0x54, 0xE9,             /* andps xmm5, xmm1 */
            0x0F, 0x57, 0xF1,             /* xorps xmm6, xmm1 */
            0x66, 0x0F, 0x57, 0xFF,       /* xorpd xmm7, xmm7 */
        };
        static const uint32_t xmm[8][4] = {
            {0xF0F0F0F0U, 0U, 0U, 0U},
            {0xFF00FF00U, 0x0F0F0F0FU, 0U, 0U},
            {0xAAAAAAAAU, 0U, 0U, 0U},
            {0x12345678U, 0U, 0U, 0U},
            {0xF0F0F0F0U, 0U, 0U, 0U},
            {0xFFFFFFFFU, 0U, 0U, 0U},
            {0x11111111U, 0U, 0U, 0U},
            {0x22222222U, 0x33333333U, 0U, 0U},
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("plogic", &k) == 0) {
            uint32_t e[4];
            e[0] = 0xF0F0F0F0U ^ 0xFF00FF00U;
            e[1] = 0U ^ 0x0F0F0F0FU; e[2] = 0U; e[3] = 0U;
            xmm_eq(0, e);
            e[0] = 0xAAAAAAAAU & 0xFF00FF00U; e[1] = 0U; e[2] = 0U; e[3] = 0U;
            xmm_eq(2, e);
            e[0] = 0x12345678U | 0xFF00FF00U;
            e[1] = 0x0F0F0F0FU; e[2] = 0U; e[3] = 0U;
            xmm_eq(3, e);
            e[0] = ~0xF0F0F0F0U & 0xFF00FF00U;
            e[1] = ~0U & 0x0F0F0F0FU; e[2] = 0U; e[3] = 0U;
            xmm_eq(4, e);
            e[0] = 0xFFFFFFFFU & 0xFF00FF00U; e[1] = 0U; e[2] = 0U; e[3] = 0U;
            xmm_eq(5, e);
            e[0] = 0x11111111U ^ 0xFF00FF00U;
            e[1] = 0U ^ 0x0F0F0F0FU; e[2] = 0U; e[3] = 0U;
            xmm_eq(6, e);
            e[0] = 0U; e[1] = 0U; e[2] = 0U; e[3] = 0U;
            xmm_eq(7, e);
        }
    }

    /* 9. ADD/SUB/MUL/DIV ps/pd/ss/sd (NEON-intrinsic expectations;
     *    scalar forms check the preserved upper lanes). */
    {
        static const uint8_t code[] = {
            0x0F, 0x58, 0xC1,             /* addps xmm0, xmm1 */
            0x66, 0x0F, 0x58, 0xD1,       /* addpd xmm2, xmm1 */
            0xF3, 0x0F, 0x58, 0xD9,       /* addss xmm3, xmm1 */
            0xF2, 0x0F, 0x58, 0xE1,       /* addsd xmm4, xmm1 */
            0x0F, 0x5C, 0xE9,             /* subps xmm5, xmm1 */
            0x0F, 0x59, 0xF1,             /* mulps xmm6, xmm1 */
            0x0F, 0x5E, 0xF9,             /* divps xmm7, xmm1 */
        };
        static uint32_t xmm[8][4] = {
            {0x3FC00000U, 0xC0200000U, 0U, 0x41200000U}, /* 1.5,-2.5,0,10 */
            {0x3F000000U, 0x3F000000U, 0x40400000U, 0x40800000U}, /*.5,.5,3,4*/
            {0x3FF80000U, 0xC0040000U, 0U, 0U},        /* 1.5, -2.5 d */
            {0x40E00000U, 0x42820000U, 0xDEAD0000U, 0xBEEF0000U},
            {0U, 0U, 0x13579BDFU, 0x2468ACE0U},        /* d0 = 7.0 below */
            {0x3FC00000U, 0xC0200000U, 0U, 0x41200000U},
            {0x3FC00000U, 0xC0200000U, 0U, 0x41200000U},
            {0x3FC00000U, 0xC0200000U, 0U, 0x41200000U},
        };
        double seven = 7.0;
        case_t k;
        memcpy(&xmm[4][0], &seven, 8U);
        k.code = code; k.clen = sizeof code; k.data = NULL;
        memset((void *)k.gpr, 0, sizeof(k.gpr));
        k.gpr[I686_REG_ESI] = DATA1; k.gpr[I686_REG_EDI] = DATA2;
        k.eflags = 0U; k.xmm = (const uint32_t (*)[4])xmm;
        k.mxcsr = 0U; k.ftag = 0U; k.mm[0] = 0U; k.mm[1] = 0U; k.mm[2] = 0U;
        if (run_case("fp arith families", &k) == 0) {
            float32x4_t a = vld1q_f32((const float32_t *)xmm[0]);
            float32x4_t b = vld1q_f32((const float32_t *)xmm[1]);
            float64x2_t ad = vld1q_f64((const float64_t *)xmm[2]);
            float64x2_t bd = vld1q_f64((const float64_t *)xmm[1]);
            uint32_t e[4];
            vst1q_u32(e, vreinterpretq_u32_f32(vaddq_f32(a, b)));
            xmm_eq(0, e);
            vst1q_u32(e, vreinterpretq_u32_f64(vaddq_f64(ad, bd)));
            xmm_eq(2, e);
            { /* addss: lane 0 only, upper 3 lanes preserved */
                float r = vgetq_lane_f32(vld1q_f32((const float32_t *)xmm[3]),
                                         0) +
                          0.5f;
                uint32_t lanes[4];
                memcpy(lanes, xmm[3], sizeof(lanes));
                memcpy(&lanes[0], &r, 4U);
                xmm_eq(3, lanes);
            }
            { /* addsd: d0 only, upper preserved; the source is the
               * full 64 bits of xmm1's d0 (the {0.5f,0.5f} lanes). */
                double src;
                double r;
                uint64_t bits;
                memcpy(&src, &xmm[1][0], 8U);
                r = 7.0 + src;
                memcpy(&bits, &r, 8U);
                CHECK(memcmp(&g_c.xmm[4][0], &bits, 8U) == 0 &&
                      xmm_word(4, 2) == 0x13579BDFU &&
                      xmm_word(4, 3) == 0x2468ACE0U);
            }
            vst1q_u32(e, vreinterpretq_u32_f32(vsubq_f32(a, b)));
            xmm_eq(5, e);
            vst1q_u32(e, vreinterpretq_u32_f32(vmulq_f32(a, b)));
            xmm_eq(6, e);
            vst1q_u32(e, vreinterpretq_u32_f32(vdivq_f32(a, b)));
            xmm_eq(7, e);
        }
    }

    /* 10. CMPPS eq/lt/unord + CMPSD neq + CMPSS le. */
    {
        static const uint8_t code[] = {
            0x0F, 0xC2, 0xC1, 0x00,       /* cmpps xmm0, xmm1, eq    */
            0x0F, 0xC2, 0xD1, 0x01,       /* cmpps xmm2, xmm1, lt    */
            0x0F, 0xC2, 0xD9, 0x03,       /* cmpps xmm3, xmm1, unord */
            0xF2, 0x0F, 0xC2, 0xE1, 0x04, /* cmpsd xmm4, xmm1, neq   */
            0xF3, 0x0F, 0xC2, 0xE9, 0x02, /* cmpss xmm5, xmm1, le    */
        };
        static const uint32_t nan = 0x7FC00000U;
        static const uint32_t xmm[8][4] = {
            {0x3F800000U, 0x40000000U, nan, 0x80000000U}, /* 1,2,NaN,-0 */
            {0x3F800000U, 0x40400000U, 0x3F800000U, 0U},  /* 1,3,1,0    */
            {0x40A00000U, 0x40A00000U, 0x40A00000U, 0x40A00000U},
            {0x3F800000U, 0x3F800000U, nan, 0x3F800000U},
            {0x40000000U, 0U, 0x42484000U, 0U},           /* 2.0d       */
            {0x3F800000U, 0xDEADBEEFU, 0xCAFEBABEU, 0U},  /* 1.0f       */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("cmpp predicates", &k) == 0) {
            static const uint32_t m = 0xFFFFFFFFU;
            static const uint32_t e0[4] = {m, 0U, 0U, m}; /* eq; -0.0==0.0 */
            static const uint32_t e2[4] = {0U, 0U, 0U, 0U}; /* lt: 5<1.. all F */
            static const uint32_t e3[4] = {0U, 0U, m, 0U};  /* unord */
            static const uint32_t e4[4] = {m, m, 0x42484000U, 0U};
            static const uint32_t e5[4] = {m, 0xDEADBEEFU, 0xCAFEBABEU, 0U};
            xmm_eq(0, e0);
            xmm_eq(2, e2);
            xmm_eq(3, e3);
            xmm_eq(4, e4); /* 2.0 != 0.5, upper lanes preserved */
            xmm_eq(5, e5); /* 1.0 <= 1.0, upper lanes preserved */
        }
    }

    /* 11. MOVMSKPS/MOVMSKPD. */
    {
        static const uint8_t code[] = {
            0x0F, 0x50, 0xC1,             /* movmskps eax, xmm1 */
            0x66, 0x0F, 0x50, 0xCA,       /* movmskpd ecx, xmm2 */
        };
        static uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0xBF800000U, 0x3F800000U, 0xC0000000U, 0xBF000000U},
            {0U, 0U, 0U, 0U},
        };
        uint64_t pos = 0x3FF0000000000000ULL; /*  1.0 */
        uint64_t neg = 0xC008000000000000ULL; /* -3.0 */
        case_t k;
        memcpy(&xmm[2][0], &pos, 8U);
        memcpy(&xmm[2][2], &neg, 8U);
        k.code = code; k.clen = sizeof code; k.data = NULL;
        k.gpr[0] = 0x55U; k.gpr[1] = 0xAAU;
        k.gpr[2] = 0U; k.gpr[3] = 0U; k.gpr[4] = 0U; k.gpr[5] = 0U;
        k.gpr[6] = DATA1; k.gpr[7] = DATA2;
        k.eflags = 0U; k.xmm = (const uint32_t (*)[4])xmm;
        k.mxcsr = 0U; k.ftag = 0U; k.mm[0] = 0U; k.mm[1] = 0U; k.mm[2] = 0U;
        if (run_case("movmskps/pd", &k) == 0) {
            CHECK(g_c.gpr[I686_REG_EAX] == 0xDU);
            CHECK(g_c.gpr[I686_REG_ECX] == 0x2U);
        }
    }

    /* 12a. COMISS greater: ZF/CF/PF clear, OF/SF/AF cleared, DF/IF
     *      kept, lazy_op = NONE. */
    {
        static const uint8_t code[] = {0x0F, 0x2F, 0xC1};
        static const uint32_t xmm[8][4] = {
            {0x40000000U, 0U, 0U, 0U}, /* 2.0f */
            {0x3F800000U, 0U, 0U, 0U}, /* 1.0f */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0xED7U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("comiss greater", &k) == 0) {
            uint32_t fl = g_c.eflags;
            CHECK((fl & (I686_EF_ZF | I686_EF_CF | I686_EF_PF)) == 0U);
            CHECK((fl & (I686_EF_OF | I686_EF_SF | I686_EF_AF)) == 0U);
            CHECK((fl & (I686_EF_DF | I686_EF_IF)) ==
                  (I686_EF_DF | I686_EF_IF));
            CHECK(g_c.lazy_op == I686_FOP_NONE);
        }
    }
    /* 12b. COMISS less: CF only. */
    {
        static const uint8_t code[] = {0x0F, 0x2F, 0xD9}; /* xmm3 vs xmm1 */
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0x3F800000U, 0U, 0U, 0U}, /* 1.0f */
            {0U, 0U, 0U, 0U},
            {0x3F000000U, 0U, 0U, 0U}, /* 0.5f */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0xED7U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("comiss less", &k) == 0) {
            uint32_t fl = g_c.eflags;
            CHECK((fl & I686_EF_CF) != 0U);
            CHECK((fl & (I686_EF_ZF | I686_EF_PF)) == 0U);
            CHECK((fl & (I686_EF_OF | I686_EF_SF | I686_EF_AF)) == 0U);
            CHECK(g_c.lazy_op == I686_FOP_NONE);
        }
    }
    /* 12c. COMISD unordered: ZF/CF/PF all set. */
    {
        static const uint8_t code[] = {0x66, 0x0F, 0x2F, 0xE1};
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {0U, 0x7FF80000U, 0U, 0U}, /* qNaN double */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0xED7U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("comisd unordered", &k) == 0) {
            uint32_t fl = g_c.eflags;
            CHECK((fl & (I686_EF_ZF | I686_EF_CF | I686_EF_PF)) ==
                  (I686_EF_ZF | I686_EF_CF | I686_EF_PF));
            CHECK((fl & (I686_EF_OF | I686_EF_SF | I686_EF_AF)) == 0U);
            CHECK(g_c.lazy_op == I686_FOP_NONE);
        }
    }

    /* 13. CVTSI2SS/SD + CVTTSS2SI/CVTTSD2SI. */
    {
        static const uint8_t code[] = {
            0xF3, 0x0F, 0x2A, 0xC0,       /* cvtsi2ss xmm0, eax  */
            0xF2, 0x0F, 0x2A, 0xC8,       /* cvtsi2sd xmm1, eax  */
            0xF3, 0x0F, 0x2C, 0xD2,       /* cvttss2si edx, xmm2 */
            0xF2, 0x0F, 0x2C, 0xDB,       /* cvttsd2si ebx, xmm3 */
        };
        static uint32_t xmm[8][4] = {
            {0U, 0x11111111U, 0x22222222U, 0x33333333U},
            {0U, 0U, 0x44444444U, 0x55555555U},
            {0x406CCCCDU, 0U, 0U, 0U}, /* 3.7f */
            {0U, 0U, 0U, 0U},           /* -2.9d below */
        };
        double m29 = -2.9;
        case_t k;
        memcpy(&xmm[3][0], &m29, 8U);
        k.code = code; k.clen = sizeof code; k.data = NULL;
        k.gpr[0] = 7U; k.gpr[1] = 0U; k.gpr[2] = 0U; k.gpr[3] = 0U;
        k.gpr[4] = 0U; k.gpr[5] = 0U; k.gpr[6] = DATA1; k.gpr[7] = DATA2;
        k.eflags = 0U; k.xmm = (const uint32_t (*)[4])xmm;
        k.mxcsr = 0U; k.ftag = 0U; k.mm[0] = 0U; k.mm[1] = 0U; k.mm[2] = 0U;
        if (run_case("cvt si<->fp", &k) == 0) {
            float f7 = 7.0f;
            double d7 = 7.0;
            uint32_t fb;
            uint64_t db;
            memcpy(&fb, &f7, 4U);
            memcpy(&db, &d7, 8U);
            CHECK(xmm_word(0, 0) == fb && xmm_word(0, 1) == 0x11111111U &&
                  xmm_word(0, 2) == 0x22222222U &&
                  xmm_word(0, 3) == 0x33333333U);
            CHECK(memcmp(&g_c.xmm[1][0], &db, 8U) == 0 &&
                  xmm_word(1, 2) == 0x44444444U &&
                  xmm_word(1, 3) == 0x55555555U);
            CHECK(g_c.gpr[I686_REG_EDX] == 3U);
            CHECK(g_c.gpr[I686_REG_EBX] == (uint32_t)-2);
        }
    }

    /* 14. CVTPS2PD/CVTPD2PS/CVTSS2SD/CVTSD2SS. */
    {
        static const uint8_t code[] = {
            0x0F, 0x5A, 0xC1,             /* cvtps2pd xmm0, xmm1 */
            0x66, 0x0F, 0x5A, 0xD3,       /* cvtpd2ps xmm2, xmm3 */
            0xF3, 0x0F, 0x5A, 0xE1,       /* cvtss2sd xmm4, xmm1 */
            0xF2, 0x0F, 0x5A, 0xEB,       /* cvtsd2ss xmm5, xmm3 */
        };
        static uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0x3FC00000U, 0xBE800000U, 0U, 0U}, /* 1.5f, -0.25f */
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},                   /* 2.75d, -8.5d below */
            {0U, 0U, 0xDEADBEEFU, 0x1BADB002U},
            {0U, 0x13579BDFU, 0x2468ACE0U, 0U},
        };
        double d2[2] = {2.75, -8.5};
        case_t k;
        memcpy(&xmm[3][0], d2, 16U);
        k.code = code; k.clen = sizeof code; k.data = NULL;
        memset((void *)k.gpr, 0, sizeof(k.gpr));
        k.gpr[I686_REG_ESI] = DATA1; k.gpr[I686_REG_EDI] = DATA2;
        k.eflags = 0U; k.xmm = (const uint32_t (*)[4])xmm;
        k.mxcsr = 0U; k.ftag = 0U; k.mm[0] = 0U; k.mm[1] = 0U; k.mm[2] = 0U;
        if (run_case("cvt widths", &k) == 0) {
            double e0[2] = {1.5, -0.25};
            float e2[4] = {2.75f, -8.5f, 0.0f, 0.0f};
            double e4 = 1.5;
            uint32_t e5;
            float f275 = 2.75f;
            memcpy(&e5, &f275, 4U);
            CHECK(memcmp(g_c.xmm[0], e0, 16U) == 0);
            CHECK(memcmp(g_c.xmm[2], e2, 16U) == 0);
            CHECK(memcmp(&g_c.xmm[4][0], &e4, 8U) == 0 &&
                  xmm_word(4, 2) == 0xDEADBEEFU &&
                  xmm_word(4, 3) == 0x1BADB002U);
            CHECK(xmm_word(5, 0) == e5 &&
                  xmm_word(5, 1) == 0x13579BDFU &&
                  xmm_word(5, 2) == 0x2468ACE0U &&
                  xmm_word(5, 3) == 0U);
        }
    }

    /* 15. CVTDQ2PS/CVTPS2DQ (round-even)/CVTTPS2DQ + MMX CVTPI2PS +
     *     CVTTPS2PI + CVTTPD2PI + CVTPI2PD (tags -> valid). */
    {
        static const uint8_t code[] = {
            0x0F, 0x2A, 0xC6,             /* cvtpi2ps  xmm0, mm6  */
            0x0F, 0x2C, 0xC7,             /* cvttps2pi mm0, xmm7  */
            0x0F, 0x5B, 0xD5,             /* cvtdq2ps  xmm2, xmm5 */
            0x66, 0x0F, 0x5B, 0xD9,       /* cvtps2dq  xmm3, xmm1 */
            0xF3, 0x0F, 0x5B, 0xE1,       /* cvttps2dq xmm4, xmm1 */
            0x66, 0x0F, 0x2A, 0xF6,       /* cvtpi2pd  xmm6, mm6  */
            0x66, 0x0F, 0x2C, 0xCE,       /* cvttpd2pi mm1, xmm6  */
        };
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0x0BADF00DU, 0x600DCAFEU},
            {0x3FC00000U, 0x40200000U, 0xBFC00000U, 0x3F000000U}, /*1.5,2.5,-1.5,.5*/
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {1U, 0xFFFFFFFEU, 3U, 0xFFFFFFFCU}, /* 1,-2,3,-4 */
            {0U, 0U, 0U, 0U},
            {0x3FF33333U, 0xC0273333U, 0U, 0U}, /* 1.9f, -2.9f */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0xAAAAU, {0x0000000400000003ULL, 0U, 0U}};
        if (run_case("cvt packed + mmx", &k) == 0) {
            float f[2] = {3.0f, 4.0f};
            double d34[2] = {3.0, 4.0};
            static const uint32_t e2[4] = {0x3F800000U, 0xC0000000U,
                                           0x40400000U, 0xC0800000U};
            static const uint32_t e3[4] = {2U, 2U, (uint32_t)-2U, 0U};
            static const uint32_t e4[4] = {1U, 2U, (uint32_t)-1U, 0U};
            CHECK(memcmp(&g_c.xmm[0][0], f, 8U) == 0 &&
                  xmm_word(0, 2) == 0x0BADF00DU &&
                  xmm_word(0, 3) == 0x600DCAFEU);
            mm_eq(0, 0xFFFFFFFE00000001ULL); /* f32 path: {1, -2} */
            mm_eq(1, 0x0000000400000003ULL); /* f64 path: {3, 4}   */
            xmm_eq(2, e2);
            xmm_eq(3, e3); /* nearest-even: 2.5->2, -1.5->-2 */
            xmm_eq(4, e4); /* truncate */
            CHECK(memcmp(&g_c.xmm[6][0], d34, 16U) == 0);
            CHECK(g_c.ftag == 0U);
        }
    }

    /* 16. LDMXCSR (reserved bits masked) + STMXCSR + EMMS (ftag empty)
     *     + PAUSE = NOP (no state change). */
    {
        static const uint8_t code[] = {
            0x0F, 0xAE, 0x16,             /* ldmxcsr [esi]  */
            0x0F, 0xAE, 0x1F,             /* stmxcsr [edi]  */
            0x0F, 0x77,                   /* emms           */
            0xF3, 0x0F, 0x90, 0xC0,       /* pause          */
            0xB8, 0x33, 0x00, 0x00, 0x00, /* mov eax, 0x33  */
        };
        static const uint32_t mem[4] = {0x12349F80U, 0U, 0U, 0U};
        case_t k = {code, sizeof code, mem,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, NULL, 0x1F80U, 0x5555U, {0U, 0U}};
        if (run_case("mxcsr/emms/pause", &k) == 0) {
            CHECK(g_c.mxcsr == 0x00009F80U);
            CHECK(data_word(DATA2, 0) == 0x00009F80U);
            CHECK(g_c.ftag == 0xFFFFU);
            CHECK(g_c.gpr[I686_REG_EAX] == 0x33U);
        }
    }

    if (g_fail != 0) {
        printf("L5A FAILED: %d check(s) failed (%d passed)\n", g_fail,
               g_pass);
        return 1;
    }
    printf("L5A OK\n");
    return 0;
}
