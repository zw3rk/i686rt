/*
 * tests/unit/test_l3b.c — lane L3b DBT MOV/LEA/stack emitter check
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Executes real translated A64 blocks (aarch64-only) and compares the
 * DBT result against the interpreter oracle on a cloned context, per
 * tests/unit/dbt_driver.c and docs/lanes/phase-3.md card L3b.  Each
 * case is placed at the TAIL of the code page so translate.c ends the
 * block right after it (page-end BRANCH exit); the following poison
 * page (0xD8, undecodable) stops the interpreter oracle at the same
 * EIP.  Covers MOV reg/mem all widths (incl. AH..BH and 16-bit
 * preservation), MOV immediates, MOVZX/MOVSX, XCHG, PUSH/POP (incl.
 * ESP corner cases and the imm8 sign-extension), BSWAP, LEA, plus the
 * v1 declines (PUSHA/POPA/ENTER/LEAVE, XCHG mem) via the D2 UNDEF exit.
 *
 * Build (cross, inside nix shell
 *   nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc,
 *   CC=aarch64-unknown-linux-musl-gcc):
 *   $CC -std=c11 -D_POSIX_C_SOURCE=200809L -Wall -Wextra -Werror=vla \
 *       -pedantic -O2 -Iinclude -Isrc -Isrc/rt32 -o _build/test_l3b \
 *       tests/unit/test_l3b.c tests/unit/ea_for_test.c \
 *       src/dbt/emit_mov.c src/dbt/emit_stubs.c src/dbt/translate.c \
 *       src/x86/decode.c src/interp src/rt32 src/os (all .c files) \
 *       src/trampoline.S -Wl,--allow-multiple-definition -static
 * (ea_for_test.c comes BEFORE emit_stubs.c so its frozen-contract
 * i686_emit_ea/i686_emit_exit override the do-nothing stubs.)
 *
 * Run in the arm64 docker VM:
 *   docker run --rm --platform linux/arm64 -v "$PWD":/w alpine:3.20 \
 *       /w/_build/test_l3b        # final line: L3B OK
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1 /* MAP_ANONYMOUS on musl/glibc */

#ifndef MAP_ANONYMOUS
/* strict-POSIX Darwin hides MAP_ANON too; the value is only needed for
 * host-side syntax checks (the lane check runs on Linux/arm64). */
#define MAP_ANONYMOUS 0x1000
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "dbt/emit.h"
#include "i686rt.h"
#include "interp/interp.h"
#include "x86/decode.h"

/* Frozen engine entry points (src/dbt/translate.c, src/trampoline.S). */
extern size_t i686_dbt_translate(i686_ctx_t *ctx, uint32_t eip,
                                 uint8_t *code, size_t cap);
extern uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                                   void *cur_entry, const void *epoch_ptr);

static int g_fail;
static int g_checks;

#ifdef TEST_DEBUG
#define DBG(...)                                                              \
    do {                                                                      \
        fprintf(stderr, "DBG %s:%d: ", __FILE__, __LINE__);                   \
        fprintf(stderr, __VA_ARGS__);                                         \
        fprintf(stderr, "\n");                                                \
    } while (0)
#else
#define DBG(...) do { } while (0)
#endif

#define CHECK(cond)                                                         \
    do {                                                                    \
        g_checks++;                                                         \
        if (!(cond)) {                                                      \
            g_fail++;                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                   \
    } while (0)

/* ---- guest memory layout inside each slab (two independent slabs:
 * one for the DBT run, one for the interpreter oracle) ---------------- */
#define SLAB_SIZE  0x14000U
#define DATA_PAGE  0x1000U   /* MOV r/m data area                          */
#define STACK_PAGE 0x2000U   /* PUSH/POP area (ESP 0x2800)                 */
#define CODE_PAGE  0x11000U  /* cases placed at the page tail              */
#define END_VA     0x12000U  /* first byte past the code page (poison)     */
#define POISON_END 0x13000U
#define CODE_CAP   4096U     /* JIT scratch buffer bytes                   */

#define POISON_BYTE 0xD8U    /* x87: INVALID -> decode fails (D2)          */

typedef struct {
    const char *name;
    uint8_t     code[9];
    uint8_t     len;
    uint8_t     declined;    /* expect the D2 UNDEF exit, not emission    */
    uint8_t     ovr_reg[2];  /* per-case GPR overrides (0xFF = none)      */
    uint32_t    ovr_val[2];
} case_t;

/* x86 GPR indices for the override slots. */
#define R_ESI 6U
#define R_NONE 0xFFU

static const case_t k_cases[] = {
    /* MOV reg, reg — 32/16/8-bit incl. the AH..BH high bytes */
    {"mov eax,ebx",           {0x89, 0xD8}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov ebx,eax",           {0x8B, 0xD8}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov16 ax,cx",           {0x66, 0x89, 0xC8}, 3, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov al,bl",             {0x8A, 0xC3}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov ah,dl",             {0x88, 0xD4}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov bh,al",             {0x88, 0xC7}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov ch,ah",             {0x8A, 0xEC}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    /* MOV reg, imm */
    {"mov al,0x5a",           {0xB0, 0x5A}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov ah,0x3c",           {0xB4, 0x3C}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov eax,0xdeadbeef",    {0xB8, 0xEF, 0xBE, 0xAD, 0xDE}, 5, 0,
     {R_NONE, R_NONE}, {0, 0}},
    {"mov16 bx,0x1234",       {0x66, 0xBB, 0x34, 0x12}, 4, 0,
     {R_NONE, R_NONE}, {0, 0}},
    /* MOV reg <-> mem (disp/base/index/scale, byte/word/dword, imm) */
    {"mov [ebx],eax",         {0x89, 0x03}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov eax,[ebx]",         {0x8B, 0x03}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov16 [esi],di",        {0x66, 0x89, 0x3E}, 3, 0, {R_ESI, R_NONE},
     {0x1010U, 0}},
    {"mov al,[ebx+esi*2+4]",  {0x8A, 0x44, 0x73, 0x04}, 4, 0,
     {R_NONE, R_NONE}, {0, 0}},
    {"mov [ecx+edx*4-8],dl",  {0x88, 0x54, 0x11, 0xF8}, 4, 0,
     {R_NONE, R_NONE}, {0, 0}},
    {"mov16 ax,[ebx+2]",      {0x66, 0x8B, 0x43, 0x02}, 4, 0,
     {R_NONE, R_NONE}, {0, 0}},
    {"mov w [0x1234],0xbeef", {0x66, 0xC7, 0x05, 0x34, 0x12, 0x00, 0x00,
                               0xEF, 0xBE}, 9, 0, {R_NONE, R_NONE}, {0, 0}},
    {"mov b [ebx],0x77",      {0xC6, 0x03, 0x77}, 3, 0, {R_NONE, R_NONE},
     {0, 0}},
    {"mov [ebx],esi",         {0x89, 0x33}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    /* MOVZX / MOVSX (all four, reg and mem sources) */
    {"movzx ebx,al",          {0x0F, 0xB6, 0xD8}, 3, 0, {R_NONE, R_NONE},
     {0, 0}},
    {"movzx eax,b [ebx]",     {0x0F, 0xB6, 0x03}, 3, 0, {R_NONE, R_NONE},
     {0, 0}},
    {"movsx ecx,ah",          {0x0F, 0xBE, 0xCC}, 3, 0, {R_NONE, R_NONE},
     {0, 0}},
    {"movsx edx,w [esi]",     {0x0F, 0xBF, 0x16}, 3, 0, {R_ESI, R_NONE},
     {0x1020U, 0}},
    {"mov16 zx cx,bl",        {0x66, 0x0F, 0xB6, 0xCB}, 4, 0,
     {R_NONE, R_NONE}, {0, 0}},
    {"movsx eax,w [ebx+esi*4]", {0x0F, 0xBF, 0x04, 0x33}, 4, 0,
     {R_NONE, R_NONE}, {0, 0}},
    /* XCHG register forms */
    {"xchg eax,ebx",          {0x93}, 1, 0, {R_NONE, R_NONE}, {0, 0}},
    {"xchg eax,ecx",          {0x91}, 1, 0, {R_NONE, R_NONE}, {0, 0}},
    {"xchg16 ax,di",          {0x66, 0x97}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"xchg al,ah",            {0x86, 0xE0}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"xchg ebx,esi",          {0x87, 0xF3}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    /* stack: PUSH/POP reg, ESP corner cases, immediates, 16-bit */
    {"push eax",              {0x50}, 1, 0, {R_NONE, R_NONE}, {0, 0}},
    {"pop ebx",               {0x5B}, 1, 0, {R_NONE, R_NONE}, {0, 0}},
    {"push esp",              {0x54}, 1, 0, {R_NONE, R_NONE}, {0, 0}},
    {"pop esp",               {0x5C}, 1, 0, {R_NONE, R_NONE}, {0, 0}},
    {"push 0xcafebabe",       {0x68, 0xBE, 0xBA, 0xFE, 0xCA}, 5, 0,
     {R_NONE, R_NONE}, {0, 0}},
    {"push -23",              {0x6A, 0xE9}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"push16 cx",             {0x66, 0x51}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"pop16 dx",              {0x66, 0x5A}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    /* BSWAP and LEA */
    {"bswap eax",             {0x0F, 0xC8}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"bswap ebx",             {0x0F, 0xCB}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"lea eax,[ebx+esi*4+0x40]", {0x8D, 0x44, 0x33, 0x40}, 4, 0,
     {R_NONE, R_NONE}, {0, 0}},
    {"lea ecx,[edx]",         {0x8D, 0x0A}, 2, 0, {R_NONE, R_NONE}, {0, 0}},
    {"lea16 ax,[ebx+2]",      {0x66, 0x8D, 0x43, 0x02}, 4, 0,
     {R_NONE, R_NONE}, {0, 0}},
    /* v1 declines: D2 UNDEF exit with the insn length recorded */
    {"pusha (declined)",      {0x60}, 1, 1, {R_NONE, R_NONE}, {0, 0}},
    {"popa (declined)",       {0x61}, 1, 1, {R_NONE, R_NONE}, {0, 0}},
    {"enter 16,0 (declined)", {0xC8, 0x10, 0x00, 0x00}, 4, 1,
     {R_NONE, R_NONE}, {0, 0}},
    {"leave (declined)",      {0xC9}, 1, 1, {R_NONE, R_NONE}, {0, 0}},
    {"xchg [ebx],eax (declined)", {0x87, 0x03}, 2, 1, {R_NONE, R_NONE},
     {0, 0}},
};

static uint8_t *g_slab_a; /* DBT run      */
static uint8_t *g_slab_b; /* interp oracle */
static uint8_t *g_code;   /* RWX JIT scratch */

static uint8_t *slab_map(void)
{
    void *p = mmap(NULL, SLAB_SIZE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        perror("mmap slab");
        exit(1);
    }
    return (uint8_t *)p;
}

/* Identical deterministic fill for both slabs. */
static void slab_fill(uint8_t *base)
{
    for (uint32_t va = 0U; va < SLAB_SIZE; va++) {
        base[va] = (uint8_t)(va * 31U + 7U);
    }
    memset(base + END_VA, POISON_BYTE, POISON_END - END_VA);
}

static void ctx_init(i686_ctx_t *ctx, uint8_t *slab)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->guest_base = (uint64_t)(uintptr_t)slab;
    ctx->eip = 0U;
    ctx->eflags = 0x00000246U;
    ctx->gpr[I686_REG_EAX] = 0x13579BDFU; /* AH != 0 for the byte cases */
    ctx->gpr[I686_REG_ECX] = 0x00001080U; /* EA base                     */
    ctx->gpr[I686_REG_EDX] = 0x00000010U; /* EA index / low byte DL      */
    ctx->gpr[I686_REG_EBX] = 0x00001000U; /* EA base (data page)         */
    ctx->gpr[I686_REG_ESP] = 0x00002800U; /* inside the stack page       */
    ctx->gpr[I686_REG_EBP] = 0x00002900U;
    ctx->gpr[I686_REG_ESI] = 0x00000010U; /* EA index default            */
    ctx->gpr[I686_REG_EDI] = 0x00C0FFEEU;
    ctx->seg_sel[I686_SEG_DS] = 0x0023U;
    ctx->seg_sel[I686_SEG_SS] = 0x002BU;
}

static void apply_ovr(i686_ctx_t *ctx, const case_t *c)
{
    for (unsigned i = 0U; i < 2U; i++) {
        if (c->ovr_reg[i] != R_NONE && c->ovr_reg[i] < 8U) {
            ctx->gpr[c->ovr_reg[i]] = c->ovr_val[i];
        }
    }
}

static void cmp_pages(const case_t *c)
{
    if (memcmp(g_slab_a + DATA_PAGE, g_slab_b + DATA_PAGE,
               STACK_PAGE - DATA_PAGE) != 0) {
        g_fail++;
        fprintf(stderr, "FAIL %s: data page differs\n", c->name);
    }
    if (memcmp(g_slab_a + STACK_PAGE, g_slab_b + STACK_PAGE,
               CODE_PAGE - STACK_PAGE) != 0) {
        g_fail++;
        fprintf(stderr, "FAIL %s: stack page differs\n", c->name);
    }
    if (memcmp(g_slab_a + CODE_PAGE, g_slab_b + CODE_PAGE,
               END_VA - CODE_PAGE) != 0) {
        g_fail++;
        fprintf(stderr, "FAIL %s: code page differs\n", c->name);
    }
    g_checks += 3;
}

int main(void)
{
    size_t n_cases;

    DBG("start");
    g_slab_a = slab_map();
    g_slab_b = slab_map();
    g_code = (uint8_t *)mmap(NULL, CODE_CAP,
                             PROT_READ | PROT_WRITE | PROT_EXEC,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_code == MAP_FAILED) {
        perror("mmap code");
        return 1;
    }
    slab_fill(g_slab_a);
    slab_fill(g_slab_b);

    DBG("slabs+code mapped");
    i686_interp_init_all(); /* oracle handlers */
    DBG("interp init done");

    n_cases = sizeof(k_cases) / sizeof(k_cases[0]);
    for (size_t i = 0U; i < n_cases; i++) {
        const case_t *c = &k_cases[i];
        uint32_t eip = END_VA - c->len;
        i686_ctx_t ctx_a, ctx_b, ctx_ref;
        size_t emitted;

        memcpy(g_slab_a + eip, c->code, c->len);
        memcpy(g_slab_b + eip, c->code, c->len);

        ctx_init(&ctx_ref, g_slab_a); /* template incl. overrides */
        apply_ovr(&ctx_ref, c);

        ctx_init(&ctx_a, g_slab_a);
        apply_ovr(&ctx_a, c);
        ctx_a.eip = eip;

        DBG("case %zu (%s) eip=%08x", i, c->name, eip);
        emitted = i686_dbt_translate(&ctx_a, eip, g_code, CODE_CAP);
        DBG("translate -> %zu bytes", emitted);
#ifdef TEST_DEBUG
        for (size_t w = 0U; w < emitted / 4U; w++) {
            fprintf(stderr, "DBG word[%2zu] = %08x\n", w,
                    ((const uint32_t *)(const void *)g_code)[w]);
        }
#endif
        CHECK(emitted > 0U);
        if (emitted == 0U) {
            continue;
        }
        __builtin___clear_cache((char *)g_code,
                                (char *)g_code + emitted);
        DBG("icache flushed; entering block");
        (void)i686_jit_run_block(&ctx_a, g_code, NULL, NULL);
        DBG("block returned reason=%u eip=%08x", ctx_a.exit_reason,
            ctx_a.eip);

        if (c->declined != 0) {
            /* D2: block ends UNDEF with the insn length recorded; the
             * engine would interpret exactly one insn at eip. */
            CHECK(ctx_a.exit_reason == I686_EXIT_UNDEF);
            CHECK(ctx_a.exit_arg == (uint32_t)c->len);
            CHECK(ctx_a.exit_dest == eip);
            CHECK(memcmp(ctx_a.gpr, ctx_ref.gpr, sizeof(ctx_a.gpr)) == 0);
            printf("ok %2zu declined %s\n", i, c->name);
            continue;
        }

        CHECK(ctx_a.exit_reason == I686_EXIT_BRANCH);
        CHECK(ctx_a.eip == END_VA);
        if (ctx_a.exit_reason != I686_EXIT_BRANCH) {
            fprintf(stderr, "FAIL %s: not emitted (reason=%u)\n", c->name,
                    ctx_a.exit_reason);
            g_fail++;
            continue;
        }

        /* Interpreter oracle on the clone: executes the insn, then stops
         * undecodable at the poison page with EIP == END_VA. */
        ctx_init(&ctx_b, g_slab_b);
        apply_ovr(&ctx_b, c);
        ctx_b.eip = eip;
        (void)i686_interp_run(&ctx_b);
        DBG("oracle done eip=%08x", ctx_b.eip);
        CHECK(ctx_b.eip == END_VA);

        for (unsigned r = 0U; r < 8U; r++) {
            if (ctx_a.gpr[r] != ctx_b.gpr[r]) {
                g_fail++;
                fprintf(stderr, "FAIL %s: gpr[%u] dbt=%08x interp=%08x\n",
                        c->name, r, ctx_a.gpr[r], ctx_b.gpr[r]);
            }
        }
        g_checks += 8 + 2;
        CHECK(ctx_a.eip == ctx_b.eip);
        CHECK(ctx_a.eflags == ctx_b.eflags);
        cmp_pages(c);

        printf("ok %2zu %s\n", i, c->name);
    }

    printf("%zu cases, %d checks, %d failures\n", n_cases, g_checks, g_fail);
    if (g_fail == 0) {
        printf("L3B OK\n");
        return 0;
    }
    printf("L3B FAIL\n");
    return 1;
}
