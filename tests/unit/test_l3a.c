/*
 * tests/unit/test_l3a.c — DBT lane L3a check: shared exits, EA, ALU
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Based on tests/unit/dbt_driver.c: each case writes hand-assembled x86
 * bytes into a fake guest window, runs them through i686_dbt_translate +
 * i686_jit_run_block (an HLT sentinel ends every stream), then finishes
 * any interpret-one fallback with the interpreter, and compares the
 * final GPR/EFLAGS/EIP state bit-exactly against the reference computed
 * by running the interpreter on a fresh clone.  The first block's exit
 * {reason, arg, dest} is asserted against the exit protocol (UNDEF with
 * the sentinel's length, or BRANCH at a page boundary with dest = next
 * pc), which also proves the case's instructions were actually emitted,
 * not silently declined.
 *
 * Compiles and runs on aarch64 Linux only (the DBT emits and executes
 * A64; run inside the arm64 docker VM per docs/lanes/phase-3.md).
 * Expected final line: L3A OK.
 */

#define _GNU_SOURCE /* MAP_ANONYMOUS/MAP_NORESERVE, as in src/rt32 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

/* Local syntax-check hosts (darwin) hide these; the arm64 musl target
 * defines the real values. */
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x1000
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

#include "dbt/emit.h"
#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"

/* src/dbt/translate.c and src/trampoline.S (linked into this test). */
extern size_t i686_dbt_translate(i686_ctx_t *ctx, uint32_t eip, uint8_t *code,
                                 size_t cap);
extern uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                                   void *cur_entry, const void *epoch_ptr);

#define WIN_FULL  0x100000000ULL /* [G, G+4GiB) window like the runtime  */
#define WIN_SMALL 0x1000000UL    /* fallback when overcommit refuses     */
#define CODE_CAP  4096U
#define CASE_EIP  0x001000U
#define PAGE_EIP  0x001FF6U      /* 5 x 2-byte insns end exactly at 0x2000 */
#define DATA1     0x002000U
#define DATA2     0x002100U

static uint8_t  *g_win;
static uint64_t  g_win_size;
static int       g_win_full; /* 4 GiB window mapped (wrap case possible) */
static uint8_t  *g_code;     /* RWX code buffer for translated blocks    */
static uint32_t  g_epoch;
static int       g_pass;
static int       g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

typedef struct {
    const uint8_t *code;
    size_t         clen;
    uint32_t       eip;
    uint32_t       gpr[8];
    uint32_t       eflags;
    uint32_t       fs_base;
    const uint32_t *data;   /* dwords to place at data_va   */
    size_t         dwords;
    uint32_t       data_va;
} case_t;

/* Reset code + data areas identically for each engine run. */
static void prime(const case_t *c)
{
    memset(&g_win[CASE_EIP], 0xCC, 0x1000U);
    memset(&g_win[PAGE_EIP], 0xCC, 0x20U);
    memcpy(&g_win[c->eip], c->code, c->clen);
    g_win[c->eip + c->clen] = 0xF4U; /* HLT sentinel */
    if (c->data != NULL && c->dwords != 0U) {
        memcpy(&g_win[c->data_va], c->data, c->dwords * 4U);
    }
}

static void ctx_setup(i686_ctx_t *c, const case_t *k)
{
    memset(c, 0, sizeof(*c));
    c->guest_base = (uint64_t)(uintptr_t)g_win;
    c->eip = k->eip;
    memcpy(c->gpr, k->gpr, sizeof(c->gpr));
    c->eflags = k->eflags | 0x2U; /* bit 1 reserved-reads-as-1 */
    c->seg_base[I686_SEG_FS] = k->fs_base;
}

/* Drive translate + run; on UNDEF finish with the interpreter (the same
 * continuation the engine's interpret-one step produces for streams
 * that end at the HLT sentinel).  first_* capture block #1's exit. */
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

static void run_case(const char *name, const case_t *k)
{
    i686_ctx_t c;
    i686_ctx_t ref;
    uint32_t fr = 0U, fa = 0U, fd = 0U;
    int rc;
    int ok;
    unsigned i;

    prime(k);
    ctx_setup(&c, k);
    rc = dbt_engine(&c, &fr, &fa, &fd);
    if (rc != I686_EXIT_HLT) {
        printf("FAIL %s: dbt engine rc=%d (first exit %u/%u ->%08x)\n", name,
               rc, fr, fa, fd);
        g_fail++;
        return;
    }
    /* Every instruction before the sentinel must have been emitted: the
     * first block ends declining exactly the 1-byte HLT... */
    if (k->eip == PAGE_EIP) {
        /* ...or, at the page boundary, with a BRANCH to the next page. */
        CHECK(fr == I686_EXIT_BRANCH && fd == 0x2000U && fa == 0U);
    } else {
        CHECK(fr == I686_EXIT_UNDEF && fa == 1U &&
              fd == (uint32_t)(k->eip + k->clen));
    }

    prime(k);
    ctx_setup(&ref, k);
    rc = i686_interp_run(&ref);
    if (rc != I686_EXIT_HLT) {
        printf("FAIL %s: reference rc=%d\n", name, rc);
        g_fail++;
        return;
    }

    ok = i686_flags_read(&c) == i686_flags_read(&ref) && c.eip == ref.eip;
    for (i = 0U; i < 8U; i++) {
        ok = ok && (c.gpr[i] == ref.gpr[i]);
    }
    if (!ok) {
        printf("FAIL %s: state mismatch dbt {eip=%08x fl=%08x r0=%08x r1=%08x"
               " r2=%08x r3=%08x} ref {eip=%08x fl=%08x r0=%08x r1=%08x"
               " r2=%08x r3=%08x}\n",
               name, c.eip, i686_flags_read(&c), c.gpr[0], c.gpr[1], c.gpr[2],
               c.gpr[3], ref.eip, i686_flags_read(&ref), ref.gpr[0],
               ref.gpr[1], ref.gpr[2], ref.gpr[3]);
    }
    CHECK(ok);
}

int main(void)
{
    g_win = mmap(NULL, WIN_FULL, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (g_win == MAP_FAILED) {
        g_win_size = WIN_SMALL;
        g_win = mmap(NULL, g_win_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        g_win_full = 0;
    } else {
        g_win_size = WIN_FULL;
        g_win_full = 1;
    }
    g_code = mmap(NULL, CODE_CAP, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_win == MAP_FAILED || g_code == MAP_FAILED) {
        printf("L3A FAILED: mmap window/code\n");
        return 1;
    }
    i686_interp_init_all();
    CHECK(g_epoch == 0U);

    /* 1. add ebx,ecx — signed overflow at 32 bits (OF/SF fused). */
    {
        static const uint8_t code[] = {0x01, 0xCB};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0U, 0U, 0U, 0x7FFFFFFFU, 0U, 0U, 0U, 0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("add ebx,ecx (ovf)", &k);
    }
    /* 2. add eax,imm32 — unsigned carry out of bit 31 (CF fused). */
    {
        static const uint8_t code[] = {0x05, 0x78, 0x56, 0x34, 0x12};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0xEDCBA988U, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("add eax,0x12345678 (carry)", &k);
    }
    /* 3. add dword [ebx+8],0x100 — mem dst, wrap to zero (CF|ZF). */
    {
        static const uint8_t code[] = {0x81, 0x43, 0x08, 0x00, 0x01, 0x00, 0x00};
        static const uint32_t data[] = {0xFFFFFF00U};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0U, 0U, 0U, DATA1 - 8U, 0U, 0U, 0U, 0U},
                    0U, 0U, data, 1U, DATA1};
        run_case("add [ebx+8],0x100 (mem)", &k);
    }
    /* 4. add byte [esi],0x7F — byte add carry out of bit 7 (shift
     *    trick); initial DF must survive both engines. */
    {
        static const uint8_t code[] = {0x80, 0x06, 0x7F};
        static const uint32_t data[] = {0x00000090U};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, 0U},
                    I686_EF_DF, 0U, data, 1U, DATA1};
        run_case("add [esi],0x7F (byte carry)", &k);
    }
    /* 5. sub eax,edx; cmp eax,100 — borrow (inverted A64 C) + CMP no
     *    writeback. */
    {
        static const uint8_t code[] = {0x29, 0xD0, 0x83, 0xF8, 0x64};
        case_t k = {code, sizeof code, CASE_EIP,
                    {5U, 0U, 7U, 0U, 0U, 0U, 0U, 0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("sub eax,edx; cmp eax,100", &k);
    }
    /* 6. and/or/xor/test — logic flags (CF=OF=0) across reg+imm. */
    {
        static const uint8_t code[] = {0x25, 0x00, 0xFF, 0x00, 0xFF,
                                       0x09, 0xCB, 0x31, 0xFE, 0x85, 0xC3};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0xDEADBEEFU, 0U, 0U, 0x00FF00FFU, 0U, 0U, 0x12345678U,
                     0x9ABCDEF0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("and/or/xor/test", &k);
    }
    /* 7. byte registers incl. AH/BH merge and preservation of bits
     *    15:8 / 31:16. */
    {
        static const uint8_t code[] = {0x00, 0xD8, 0x08, 0xFC, 0xA8, 0x80};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0x123400C0U, 0x56780050U, 0U, 0U, 0U, 0U, 0U, 0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("add al,bl; or ah,bh; test al,0x80", &k);
    }
    /* 8. 16-bit ops via 66: carry out of bit 15, imm8 sign-extended. */
    {
        static const uint8_t code[] = {0x66, 0x01, 0xCB, 0x66, 0x83, 0xEB, 0x02,
                                       0x66, 0x3D, 0x34, 0x12};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0U, 0x2000U, 0U, 0xAAFFF000U, 0U, 0U, 0U, 0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("66 add/sub/cmp 16-bit", &k);
    }
    /* 9. not ebx (flags untouched); neg eax; neg cl — initial arith+DF
     *    bits pin the preserve/clear behavior. */
    {
        static const uint8_t code[] = {0xF7, 0xD3, 0xF7, 0xD8, 0xF6, 0xD9};
        case_t k = {code, sizeof code, CASE_EIP,
                    {5U, 0x89U, 0U, 0x12345678U, 0U, 0U, 0U, 0U},
                    0xCD5U, 0U, NULL, 0U, 0U};
        run_case("not; neg eax; neg cl", &k);
    }
    /* 10. imul ebx,ecx; imul eax,ebx,100; imul esi,[ebx],0x1234 (mem rm,
     *     ebx==21 after insn 1 -> dword pre-placed at va 21). */
    {
        static const uint8_t code[] = {0x0F, 0xAF, 0xD9, 0x6B, 0xC3, 0x64,
                                       0x69, 0x33, 0x34, 0x12, 0x00, 0x00};
        static const uint32_t data[] = {3U};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0U, 0U, 7U, 3U, 0U, 0U, 0U, 0U},
                    0U, 0U, data, 1U, 21U};
        run_case("imul 2/3-op + mem", &k);
    }
    /* 11. imul eax,ebx overflow (CF=OF=1, result truncated) and a
     *     16-bit imul with the same rule. */
    {
        static const uint8_t code[] = {0x0F, 0xAF, 0xC3, 0x66, 0x0F, 0xAF, 0xD9};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0x40000000U, 0U, 0x300U, 4U, 0U, 0U, 0U, 0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("imul ovf 32/16", &k);
    }
    /* 12. shl eax,4; shr ebx,1 (OF=MSB src); sar ecx,31; shl al,9
     *     (cnt > width: CF=0, res=0); 66 shr ax,1. */
    {
        static const uint8_t code[] = {0xC1, 0xE0, 0x04, 0xD1, 0xEB,
                                       0xC1, 0xF9, 0x1F, 0xC0, 0xE0, 0x09,
                                       0x66, 0xD1, 0xE8};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0x12345678U, 0x80000001U, 0xF0000001U, 0U, 0U, 0U, 0U, 0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("shl/shr/sar imm", &k);
    }
    /* 13. add eax,[ebx+esi*4+0x40] — SIB scale+index+disp8 EA. */
    {
        static const uint8_t code[] = {0x03, 0x44, 0xB3, 0x40};
        static const uint32_t data[] = {0x11112222U};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0x01000000U, 0U, 0U, DATA1, 0U, 0U, 2U, 0U},
                    0U, 0U, data, 1U, DATA1 + 8U + 0x40U};
        run_case("add [ebx+esi*4+0x40]", &k);
    }
    /* 14. fs-override: add eax,fs:[0x2000] with a non-flat FS base. */
    {
        static const uint8_t code[] = {0x64, 0x03, 0x05, 0x00, 0x20, 0x00, 0x00};
        static const uint32_t data[] = {0x55667788U};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0x111U, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
                    0U, 0x100U, data, 1U, 0x2100U};
        run_case("fs: add eax,[0x2000]", &k);
    }
    /* 15. 16-bit addressing (67): add eax,[si]. */
    {
        static const uint8_t code[] = {0x67, 0x03, 0x04};
        static const uint32_t data[] = {0x55667788U};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0x1000U, 0U, 0U, 0U, 0U, 0U, DATA1, 0U},
                    0U, 0U, data, 1U, DATA1};
        run_case("67 add eax,[si]", &k);
    }
    /* 16. EA wrap at 4 GiB: add eax,[ebx+0x20] with ebx=0xFFFFFFE8. */
    if (g_win_full) {
        static const uint8_t code[] = {0x03, 0x43, 0x20};
        static const uint32_t data[] = {0xCAFEBABEU};
        case_t k = {code, sizeof code, CASE_EIP,
                    {0x77U, 0U, 0U, 0xFFFFFFE8U, 0U, 0U, 0U, 0U},
                    0U, 0U, data, 1U, 8U};
        run_case("add [ebx+0x20] wrap", &k);
    } else {
        printf("note: 4 GiB window unavailable, wrap case skipped\n");
    }
    /* 17. page-boundary block: five 2-byte adds end exactly at 0x2000,
     *     first exit must be BRANCH -> 0x2000. */
    {
        static const uint8_t code[] = {0x01, 0xC0, 0x01, 0xC8, 0x01, 0xD0,
                                       0x01, 0xD8, 0x01, 0xDE};
        case_t k = {code, sizeof code, PAGE_EIP,
                    {1U, 0U, 0x10U, 0x100U, 0x1000U, 0U, 0x10000U, 0U},
                    0U, 0U, NULL, 0U, 0U};
        run_case("page-boundary BRANCH exit", &k);
    }

    if (g_fail != 0) {
        printf("L3A FAILED: %d check(s) failed (%d passed)\n", g_fail, g_pass);
        return 1;
    }
    printf("L3A OK\n");
    return 0;
}
