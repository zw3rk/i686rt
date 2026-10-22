/*
 * tests/unit/test_l4c.c — DBT lane L4c check: LOCK -> LSE atomics
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * tests/unit/dbt_driver.c pattern (as test_l3a.c): each case writes
 * hand-assembled F0-prefixed x86 bytes into a fake guest window at
 * CASE_EIP, runs them through i686_dbt_translate + i686_jit_run_block
 * (an HLT sentinel ends the stream), and checks:
 *
 *  1. the LOCK instruction was EMITTED natively: the block exit is
 *     HLT with arg == 0 and dest one byte past the HLT. A declined
 *     LOCK would end the block as UNDEF with the LOCK's own length;
 *  2. the memory effect, the register effect, and EFLAGS match a host
 *     __atomic/__sync oracle executed over a shadow copy of the data
 *     (fetch_add / fetch_sub / fetch_and / fetch_or / fetch_xor /
 *     exchange / val_compare_and_swap at seq_cst), with the expected
 *     EFLAGS computed by the frozen src/interp/flags.c helpers;
 *  3. the full final state (GPRs, EFLAGS, EIP, data window) is
 *     bit-identical to the interpreter oracle run on a fresh prime.
 *
 * Compiles and runs on aarch64 Linux only (the DBT emits and executes
 * A64; run inside the arm64 docker VM).  Expected final line: L4C OK.
 */

#define _GNU_SOURCE /* MAP_ANONYMOUS/MAP_NORESERVE, as in src/rt32 */

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
#include "interp/flags.h"
#include "interp/interp.h"

/* src/dbt/translate.c and src/trampoline.S (linked into this test). */
extern size_t i686_dbt_translate(i686_ctx_t *ctx, uint32_t eip, uint8_t *code,
                                 size_t cap);
extern uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                                   void *cur_entry, const void *epoch_ptr);

/* src/dbt/engine.c is not linked into this unit test (it pulls the whole
 * runtime loop); src/os/clone.c's thread_entry references the engine
 * entry point.  No guest thread is cloned here — never reached. */
int i686_dbt_run(i686_ctx_t *ctx)
{
    (void)ctx;
    return -1;
}

#define WIN_SIZE  0x1000000UL /* 16 MiB fake guest window (RW)       */
#define CODE_CAP  4096U
#define CASE_EIP  0x001000U
#define DATA_VA   0x002000U

/* Oracle kinds (mirror of the emitter's AT_* dispatch). */
enum {
    OR_ADD,    /* r/m += src                       */
    OR_SUB,    /* r/m -= src                       */
    OR_AND,    /* r/m &= src                       */
    OR_OR,     /* r/m |= src                       */
    OR_XOR,    /* r/m ^= src                       */
    OR_XADD,   /* r/m += src, reg <- old           */
    OR_XCHG,   /* r/m <-> reg                      */
    OR_CAS     /* cmpxchg with reg new value       */
};

typedef struct {
    const uint8_t *code;
    size_t         clen;
    uint32_t       gpr[8];
    uint32_t       eflags;
    unsigned       width;   /* 8 / 16 / 32                             */
    unsigned       kind;    /* OR_*                                    */
    uint32_t       src;     /* immediate source (imm forms)            */
    uint8_t        src_reg; /* modrm reg field (reg forms; 0xFF imm)   */
    uint32_t       data;    /* initial dword at DATA_VA                */
} case_t;

static uint8_t  *g_win;
static uint8_t  *g_code;
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

static uint32_t width_mask(unsigned width)
{
    return width == 8U ? 0xFFU : (width == 16U ? 0xFFFFU : 0xFFFFFFFFU);
}

/* x86 byte-register view of the initial GPRs (AH..BH in bits 15:8). */
static uint32_t oracle_src(const case_t *k)
{
    if (k->src_reg != 0xFFU) {
        if (k->width == 32U) {
            return k->gpr[k->src_reg & 7U];
        }
        if (k->width == 16U) {
            return k->gpr[k->src_reg & 7U] & 0xFFFFU;
        }
        if (k->src_reg >= 4U) {
            return (k->gpr[k->src_reg - 4U] >> 8U) & 0xFFU;
        }
        return k->gpr[k->src_reg & 7U] & 0xFFU;
    }
    return k->src & width_mask(k->width);
}

/* Run the host atomic oracle over a shadow copy of the case data.
 * Outputs: *old = pre-op memory value, *mem = post-op dword, and the
 * expected EFLAGS via the frozen flags.c lazy setters. */
static void run_oracle(const case_t *k, uint32_t *old, uint32_t *mem,
                       uint32_t *eflags, uint32_t *reg_after)
{
    uint8_t shadow[4];
    uint32_t src = oracle_src(k);
    uint32_t acc = k->gpr[I686_REG_EAX] & width_mask(k->width);
    uint32_t o = 0U;
    i686_ctx_t f;

    memcpy(shadow, &k->data, 4U);
    if (k->width == 8U) {
        uint8_t *p = shadow;
        switch (k->kind) {
        case OR_ADD:  o = __atomic_fetch_add(p, (uint8_t)src, 5); break;
        case OR_SUB:  o = __atomic_fetch_sub(p, (uint8_t)src, 5); break;
        case OR_AND:  o = __atomic_fetch_and(p, (uint8_t)src, 5); break;
        case OR_OR:   o = __atomic_fetch_or(p, (uint8_t)src, 5); break;
        case OR_XOR:  o = __atomic_fetch_xor(p, (uint8_t)src, 5); break;
        case OR_XADD: o = __atomic_fetch_add(p, (uint8_t)src, 5); break;
        case OR_XCHG: o = __atomic_exchange_n(p, (uint8_t)src, 5); break;
        default:      o = __sync_val_compare_and_swap(p, (uint8_t)acc,
                                                      (uint8_t)src);
                      break;
        }
    } else if (k->width == 16U) {
        uint16_t *p = (uint16_t *)(void *)shadow;
        switch (k->kind) {
        case OR_ADD:  o = __atomic_fetch_add(p, (uint16_t)src, 5); break;
        case OR_SUB:  o = __atomic_fetch_sub(p, (uint16_t)src, 5); break;
        case OR_AND:  o = __atomic_fetch_and(p, (uint16_t)src, 5); break;
        case OR_OR:   o = __atomic_fetch_or(p, (uint16_t)src, 5); break;
        case OR_XOR:  o = __atomic_fetch_xor(p, (uint16_t)src, 5); break;
        case OR_XADD: o = __atomic_fetch_add(p, (uint16_t)src, 5); break;
        case OR_XCHG: o = __atomic_exchange_n(p, (uint16_t)src, 5); break;
        default:      o = __sync_val_compare_and_swap(p, (uint16_t)acc,
                                                      (uint16_t)src);
                      break;
        }
    } else {
        uint32_t *p = (uint32_t *)(void *)shadow;
        switch (k->kind) {
        case OR_ADD:  o = __atomic_fetch_add(p, src, 5); break;
        case OR_SUB:  o = __atomic_fetch_sub(p, src, 5); break;
        case OR_AND:  o = __atomic_fetch_and(p, src, 5); break;
        case OR_OR:   o = __atomic_fetch_or(p, src, 5); break;
        case OR_XOR:  o = __atomic_fetch_xor(p, src, 5); break;
        case OR_XADD: o = __atomic_fetch_add(p, src, 5); break;
        case OR_XCHG: o = __atomic_exchange_n(p, src, 5); break;
        default:      o = __sync_val_compare_and_swap(p, acc, src); break;
        }
    }
    memcpy(mem, shadow, 4U);

    /* Expected EFLAGS from the same lazy semantics the DBT must store
     * (h_alu.c rules: ADD/AND/OR/XOR/XADD add/logic, SUB/CMPXCHG sub,
     * XCHG untouched). */
    memset(&f, 0, sizeof(f));
    f.eflags = k->eflags | 0x2U;
    if (k->kind == OR_ADD || k->kind == OR_XADD) {
        i686_flags_add(&f, o & width_mask(k->width), src, k->width);
    } else if (k->kind == OR_SUB) {
        i686_flags_sub(&f, o & width_mask(k->width), src, k->width);
    } else if (k->kind == OR_AND || k->kind == OR_OR || k->kind == OR_XOR) {
        i686_flags_logic(&f, *mem & width_mask(k->width), k->width);
    } else if (k->kind == OR_CAS) {
        i686_flags_sub(&f, acc, o & width_mask(k->width), k->width);
    }
    *eflags = i686_flags_read(&f);

    *old = o;
    *reg_after = 0U;
    if (k->kind == OR_XADD || k->kind == OR_XCHG) {
        uint32_t m = width_mask(k->width);
        uint8_t r = k->src_reg & 7U;
        uint32_t oldreg = (k->width == 8U && k->src_reg >= 4U)
                              ? k->gpr[(r - 4U) & 7U]
                              : k->gpr[r];
        unsigned pos = (k->width == 8U && k->src_reg >= 4U) ? 8U : 0U;
        *reg_after = (oldreg & ~(m << pos)) | ((o & m) << pos);
    } else if (k->kind == OR_CAS) {
        uint32_t m = width_mask(k->width);
        uint32_t oldreg = k->gpr[I686_REG_EAX];
        if (acc != (o & m)) { /* failure: EAX <- old memory value */
            *reg_after = (oldreg & ~m) | (o & m);
        } else {
            *reg_after = oldreg;
        }
    }
}

/* Reset code + data areas identically for each engine run. */
static void prime(const case_t *k)
{
    memset(&g_win[CASE_EIP], 0xCC, 0x100U);
    memset(&g_win[DATA_VA], 0, 16U);
    memcpy(&g_win[CASE_EIP], k->code, k->clen);
    g_win[CASE_EIP + k->clen] = 0xF4U; /* HLT sentinel */
    memcpy(&g_win[DATA_VA], &k->data, 4U);
}

static void ctx_setup(i686_ctx_t *c, const case_t *k)
{
    memset(c, 0, sizeof(*c));
    c->guest_base = (uint64_t)(uintptr_t)g_win;
    c->eip = CASE_EIP;
    memcpy(c->gpr, k->gpr, sizeof(c->gpr));
    c->gpr[I686_REG_EBX] = DATA_VA; /* [ebx] is the atomic operand */
    c->eflags = k->eflags | 0x2U;
}

/* Drive translate + run; on UNDEF finish with the interpreter (the
 * same continuation the engine's interpret-one step produces). */
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
    uint32_t old, mem, ef, reg_after;
    uint32_t got_data;
    int rc;

    run_oracle(k, &old, &mem, &ef, &reg_after);

    prime(k);
    ctx_setup(&c, k);
    rc = dbt_engine(&c, &fr, &fa, &fd);
    if (rc != I686_EXIT_HLT) {
        printf("FAIL %s: dbt engine rc=%d (first exit %u/%u ->%08x)\n", name,
               rc, fr, fa, fd);
        g_fail++;
        return;
    }
    /* Emitted-natively proof: the whole stream (LOCK insn + the 1-byte
     * HLT) was one block; L3c's branch emitter exits HLT with the
     * post-HLT resume EIP.  A declined LOCK would have ended block 1
     * with UNDEF and the LOCK's own length instead. */
    CHECK(fr == I686_EXIT_HLT && fa == 0U && fd == CASE_EIP + k->clen + 1U);
    CHECK(c.eip == CASE_EIP + k->clen + 1U);

    memcpy(&got_data, &g_win[DATA_VA], 4U);
    CHECK(got_data == mem);
    CHECK(g_win[DATA_VA + 4U] == 0U && g_win[DATA_VA + 8U] == 0U);

    if (k->kind == OR_XADD || k->kind == OR_XCHG) {
        uint8_t r = k->src_reg & 7U;
        if (k->width == 8U && k->src_reg >= 4U) {
            CHECK(c.gpr[(r - 4U) & 7U] == reg_after);
        } else {
            CHECK(c.gpr[r] == reg_after);
        }
    } else if (k->kind == OR_CAS) {
        CHECK(c.gpr[I686_REG_EAX] == reg_after);
    }
    CHECK(i686_flags_read(&c) == ef);

    /* Interpreter oracle over a fresh prime: full-state equality. */
    prime(k);
    ctx_setup(&ref, k);
    rc = i686_interp_run(&ref);
    if (rc != I686_EXIT_HLT) {
        printf("FAIL %s: reference rc=%d\n", name, rc);
        g_fail++;
        return;
    }
    {
        uint32_t ref_data;
        unsigned i;
        int ok = i686_flags_read(&c) == i686_flags_read(&ref) &&
                 c.eip == ref.eip;
        for (i = 0U; i < 8U; i++) {
            ok = ok && (c.gpr[i] == ref.gpr[i]);
        }
        memcpy(&ref_data, &g_win[DATA_VA], 4U);
        ok = ok && ref_data == mem;
        if (!ok) {
            printf("FAIL %s: state mismatch dbt {eip=%08x fl=%08x eax=%08x"
                   " ebx=%08x mem=%08x} ref {eip=%08x fl=%08x eax=%08x"
                   " ebx=%08x mem=%08x}\n",
                   name, c.eip, i686_flags_read(&c), c.gpr[0], c.gpr[3],
                   got_data, ref.eip, i686_flags_read(&ref), ref.gpr[0],
                   ref.gpr[3], ref_data);
        }
        CHECK(ok);
    }
}

int main(void)
{
    g_win = mmap(NULL, WIN_SIZE, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    g_code = mmap(NULL, CODE_CAP, PROT_READ | PROT_WRITE | PROT_EXEC,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_win == MAP_FAILED || g_code == MAP_FAILED) {
        printf("L4C FAILED: mmap window/code\n");
        return 1;
    }
    i686_interp_init_all();

    /* 1. lock add dword [ebx], imm32 — unsigned carry out of bit 31. */
    {
        static const uint8_t code[] = {0xF0, 0x81, 0x03,
                                       0x78, 0x56, 0x34, 0x12};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    32U, OR_ADD, 0x12345678U, 0xFFU, 0xFFFFFF00U};
        run_case("lock add [ebx],imm32 (carry)", &k);
    }
    /* 2. lock add byte [ebx], 0x7F — byte carry out of bit 7. */
    {
        static const uint8_t code[] = {0xF0, 0x80, 0x03, 0x7F};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    8U, OR_ADD, 0x7FU, 0xFFU, 0x00000090U};
        run_case("lock add byte [ebx],0x7F (carry)", &k);
    }
    /* 3. lock add word [ebx], imm16 — carry out of bit 15 (66). */
    {
        static const uint8_t code[] = {0x66, 0xF0, 0x81, 0x03, 0x00, 0x80};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    16U, OR_ADD, 0x8000U, 0xFFU, 0x0000F000U};
        run_case("lock add word [ebx],0x8000 (carry)", &k);
    }
    /* 4. lock add dword [ebx], imm8sx(-1) — EvIbSX path. */
    {
        static const uint8_t code[] = {0xF0, 0x83, 0x03, 0xFF};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    32U, OR_ADD, 0xFFFFFFFFU, 0xFFU, 0x00000000U};
        run_case("lock add [ebx],-1 (imm8sx)", &k);
    }
    /* 5. lock sub dword [ebx], eax — borrow, reg source (LDADD -src). */
    {
        static const uint8_t code[] = {0xF0, 0x29, 0x03};
        case_t k = {code, sizeof code,
                    {5U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    32U, OR_SUB, 0U, 0U, 3U};
        run_case("lock sub [ebx],eax (borrow)", &k);
    }
    /* 6. lock sub byte [ebx], imm8 — LDADDALB with negated imm. */
    {
        static const uint8_t code[] = {0xF0, 0x80, 0x2B, 0x02};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    8U, OR_SUB, 0x02U, 0xFFU, 0x00000001U};
        run_case("lock sub byte [ebx],2", &k);
    }
    /* 7. lock and dword [ebx], imm32 — LDCLRAL with folded complement. */
    {
        static const uint8_t code[] = {0xF0, 0x81, 0x23,
                                       0xFF, 0x00, 0xFF, 0x00};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    32U, OR_AND, 0x00FF00FFU, 0xFFU, 0xDEADBEEFU};
        run_case("lock and [ebx],imm32 (ldclr)", &k);
    }
    /* 8. lock and byte [ebx], AH — high-byte register source + LDCLRALB
     *    (MVN runtime complement), AH position merge checked. */
    {
        static const uint8_t code[] = {0xF0, 0x20, 0x23};
        case_t k = {code, sizeof code,
                    {0x1234F0F0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    8U, OR_AND, 0U, 4U, 0x0000003CU};
        run_case("lock and byte [ebx],ah", &k);
    }
    /* 9. lock xor word [ebx], imm16 — LDEORALH. */
    {
        static const uint8_t code[] = {0x66, 0xF0, 0x81, 0x33, 0x34, 0x12};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    16U, OR_XOR, 0x1234U, 0xFFU, 0xABCD5678U};
        run_case("lock xor word [ebx],0x1234", &k);
    }
    /* 10. lock xor dword [ebx], ecx — reg source LDEORAL. */
    {
        static const uint8_t code[] = {0xF0, 0x31, 0x0B};
        case_t k = {code, sizeof code,
                    {0U, 0x55AA55AAU, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    32U, OR_XOR, 0U, 1U, 0x0F0F0F0FU};
        run_case("lock xor [ebx],ecx", &k);
    }
    /* 11. lock xadd dword [ebx], eax — reg <- old, mem <- old+src,
     *     flags of the ADD. */
    {
        static const uint8_t code[] = {0xF0, 0x0F, 0xC1, 0x03};
        case_t k = {code, sizeof code,
                    {0x11111111U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    32U, OR_XADD, 0U, 0U, 0x22222222U};
        run_case("lock xadd [ebx],eax", &k);
    }
    /* 12. lock xadd byte [ebx], al — byte width, AH-neighborhood
     *     preserved in EAX. */
    {
        static const uint8_t code[] = {0xF0, 0x0F, 0xC0, 0x03};
        case_t k = {code, sizeof code,
                    {0xABCD0099U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    8U, OR_XADD, 0U, 0U, 0x00000037U};
        run_case("lock xadd byte [ebx],al", &k);
    }
    /* 13. lock xchg dword [ebx], esi — SWPAL; flags untouched (pin
     *     DF|ZF|SF to prove the descriptor/eflags are not written). */
    {
        static const uint8_t code[] = {0xF0, 0x87, 0x33};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0xCAFEBABEU, 0U},
                    I686_EF_DF | I686_EF_ZF | I686_EF_SF,
                    32U, OR_XCHG, 0U, 6U, 0x01020304U};
        run_case("lock xchg [ebx],esi", &k);
    }
    /* 14. lock xchg word [ebx], di — SWPALH, upper half of the dword
     *     and of EDI preserved. */
    {
        static const uint8_t code[] = {0xF0, 0x66, 0x87, 0x3B};
        case_t k = {code, sizeof code,
                    {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0x5A5A1234U}, 0U,
                    16U, OR_XCHG, 0U, 7U, 0x99887766U};
        run_case("lock xchg word [ebx],di", &k);
    }
    /* 15. lock cmpxchg dword [ebx], edx — success (EAX == mem): mem <-
     *     EDX (different value, so the store is observable), ZF=1. */
    {
        static const uint8_t code[] = {0xF0, 0x0F, 0xB1, 0x13};
        case_t k = {code, sizeof code,
                    {0x55667788U, 0U, 0xCAFEBABEU, 0U, 0U, 0U, 0U, 0U}, 0U,
                    32U, OR_CAS, 0U, 2U, 0x55667788U};
        run_case("lock cmpxchg [ebx],edx (hit)", &k);
    }
    /* 16. lock cmpxchg dword [ebx], edx — failure: EAX <- old, ZF=0,
     *     memory unchanged. */
    {
        static const uint8_t code[] = {0xF0, 0x0F, 0xB1, 0x13};
        case_t k = {code, sizeof code,
                    {0x11111111U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    32U, OR_CAS, 0U, 2U, 0x7F000001U};
        run_case("lock cmpxchg [ebx],edx (miss)", &k);
    }
    /* 17. lock cmpxchg byte [ebx], bl — failure at byte width: AL <-
     *     old byte, bits 31:8 of EAX preserved. */
    {
        static const uint8_t code[] = {0xF0, 0x0F, 0xB0, 0x1B};
        case_t k = {code, sizeof code,
                    {0xDEAD0042U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, 0U,
                    8U, OR_CAS, 0U, 3U, 0x00000099U};
        run_case("lock cmpxchg byte [ebx],bl (miss)", &k);
    }

    if (g_fail != 0) {
        printf("L4C FAILED: %d check(s) failed (%d passed)\n", g_fail,
               g_pass);
        return 1;
    }
    printf("L4C OK\n");
    return 0;
}
