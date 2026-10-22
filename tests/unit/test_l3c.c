/*
 * tests/unit/test_l3c.c — Phase 3 L3c lane check (DBT branch + string)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Arm64-only driver per tests/unit/dbt_driver.c: every case writes
 * hand-crafted x86 bytes into a fake guest window, runs them through
 * i686_dbt_translate + i686_jit_run_block (a miniature engine loop
 * implementing the frozen exit protocol: BRANCH resumes at
 * ctx->exit_dest, SYSCALL dispatches through i686_handle_syscall and
 * resumes, everything else is terminal), and compares the final
 * {reason, eip, gpr[8], eflags} against the interpreter oracle run on
 * an identical clone of the context.  Blocks enter with materialized
 * EFLAGS (the engine materializes the lazy descriptor before every
 * block, matching the v1 driver contract documented in
 * src/dbt/emit_branch.c until flags_dbt.h lands).
 *
 * PF/AF are masked out for the CMPS/SCAS cases: the DBT string module
 * materializes only SF/ZF/CF/OF in v1 (see src/dbt/emit_string.c).
 * exit_arg is compared only where the interpreter defines it the same
 * way (HLT / continued-syscall finals), never for TRAP/UNDEF terminals
 * whose arg encodings intentionally differ (insn length vs opcode id).
 *
 * ESCALATION NOTE (frozen-file defect, coordinator): src/trampoline.S
 * loads guest ECX into w1 (zero-extending x1) BEFORE `blr x1`, so the
 * block pointer argument is destroyed — a32rt's original spills it
 * first (`mov x17, x1` before the ldp).  Until trampoline.S is fixed,
 * this driver relays the code pointer through guest ECX: the JIT
 * buffer is mmapped at a fixed address below 4 GiB, ECX is set to that
 * address around the call, and restored afterwards (blocks in these
 * tests never read or write ECX; the CMOVcc cases therefore target
 * EBX).  Delete the relay (search "x1 relay") once the trampoline is
 * patched.
 *
 * Compile (cross, inside nix shell pkgsCross.aarch64-multiplatform-musl;
 * -Isrc/rt32 because the frozen dbt/emit.h includes rt32_a64_emit.h by
 * bare name; link every interp/os/rt32 module like the main build):
 *   aarch64-unknown-linux-musl-gcc -std=c11 -D_POSIX_C_SOURCE=200809L \
 *     -Wall -Wextra -Werror=vla -pedantic -O2 -Isrc -Isrc/rt32 -Iinclude \
 *     -static -o _build/test_l3c tests/unit/test_l3c.c \
 *     src/dbt/translate.c src/dbt/emit_stubs.c src/dbt/emit_branch.c \
 *     src/dbt/emit_string.c src/trampoline.S src/x86/decode.c \
 *     src/interp modules, src/os modules, src/rt32 modules
 * Run: docker run --rm --platform linux/arm64 -v "$PWD/_build":/w \
 *     alpine:3.20 /w/test_l3c   -> last line "L3C OK"
 */

#define _POSIX_C_SOURCE 200809L

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "dbt/emit.h"
#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"

extern size_t i686_dbt_translate(i686_ctx_t *ctx, uint32_t eip,
                                 uint8_t *code, size_t cap);
extern uint32_t i686_jit_run_block(i686_ctx_t *ctx, const void *code_ptr,
                                   void *cur_entry, const void *epoch_ptr);
extern long i686_handle_syscall(i686_ctx_t *ctx);
extern int i686_syscall_is_exit(long nr);

static int g_fail;
static int g_checks;

#define CHECK(cond)                                                         \
    do {                                                                    \
        g_checks++;                                                         \
        if (!(cond)) {                                                      \
            g_fail++;                                                       \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                   \
    } while (0)

/* ---- fake machine: guest window + JIT code buffer ----------------- */

static uint8_t *g_win;    /* guest window base (guest va 0 .. 0x20000) */
static uint8_t *g_jit;    /* RWX buffer for translated blocks          */
static size_t g_jit_cap = 65536U;
static volatile uint64_t g_epoch = 1U;

/* Fixed low mapping so the code pointer fits in a W register (x1 relay
 * workaround for the frozen trampoline; see header note). */
#define T_JIT_ADDR 0x40000000U

#define T_STACK_TOP 0x18000U
#define T_EF_PF_AF (~(I686_EF_PF | I686_EF_AF))

static void t_put(uint32_t va, const void *p, size_t n)
{
    memcpy(g_win + va, p, n);
}

static void t_w32(uint32_t va, uint32_t v)
{
    t_put(va, &v, sizeof(v));
}

static void t_ctx_init(i686_ctx_t *ctx, uint32_t eip, uint32_t eflags)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->eip = eip;
    ctx->eflags = eflags;
    ctx->gpr[I686_REG_ESP] = T_STACK_TOP;
    ctx->guest_base = (uint64_t)(uintptr_t)g_win;
    ctx->lazy_op = I686_FOP_NONE;
}

/* Miniature DBT engine loop (frozen exit protocol). */
static void t_dbt_run(i686_ctx_t *ctx)
{
    unsigned iter;

    for (iter = 0U; iter < 1000U; iter++) {
        size_t len;

        i686_flags_materialize(ctx);
        len = i686_dbt_translate(ctx, ctx->eip, g_jit, g_jit_cap);
        if (len == 0U) {
            /* Whole first insn declined/undecodable and the stub exit
             * emitted nothing: mirror the terminal UNDEF. */
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = 0U;
            return;
        }
        __builtin___clear_cache((char *)g_jit, (char *)g_jit + len);
        {
            /* x1 relay (see header note): pass the block pointer via
             * guest ECX because the trampoline clobbers x1 with w1
             * before blr.  Restore ECX unless the block wrote it. */
            uint32_t ecx = ctx->gpr[I686_REG_ECX];
            ctx->gpr[I686_REG_ECX] = (uint32_t)(uintptr_t)g_jit;
            (void)i686_jit_run_block(ctx, (const void *)g_jit, NULL,
                                     (const void *)&g_epoch);
            if (ctx->gpr[I686_REG_ECX] ==
                (uint32_t)(uintptr_t)g_jit) {
                ctx->gpr[I686_REG_ECX] = ecx;
            }
        }
        if (ctx->exit_reason == I686_EXIT_BRANCH) {
            ctx->eip = ctx->exit_dest; /* resume at the branch target */
            continue;
        }
        if (ctx->exit_reason == I686_EXIT_SYSCALL) {
            long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
            long rv = i686_handle_syscall(ctx);
            if (i686_syscall_is_exit(nr)) {
                ctx->exit_reason = I686_EXIT_SYSCALL;
                ctx->exit_arg = (uint32_t)rv;
                return;
            }
            continue; /* EIP already advanced past the gate */
        }
        return; /* TRAP/HLT/UNDEF/FAULT: terminal for the check */
    }
    ctx->exit_reason = 0xFFU; /* iteration cap: surfaced as a mismatch */
}

/* ---- case runner --------------------------------------------------- */

typedef void (*t_setup_fn)(i686_ctx_t *ctx, uint32_t slot);

typedef struct {
    const char *name;
    uint32_t slot;         /* guest va the code bytes are placed at */
    const uint8_t *bytes;
    size_t blen;
    uint32_t eflags;
    uint32_t gpr[8];       /* initial EAX..EDI (ESP overridden below) */
    t_setup_fn setup;      /* extra window writes before each run */
    uint32_t ef_mask;      /* eflags compare mask */
    int cmp_arg;           /* compare exit_arg too */
} t_case_t;

static void t_run_case(const t_case_t *c)
{
    i686_ctx_t a, b;
    uint8_t snap[0x100];
    unsigned i;

    /* DBT run. */
    t_ctx_init(&a, c->slot, c->eflags);
    memcpy(a.gpr, c->gpr, sizeof(a.gpr));
    a.gpr[I686_REG_ESP] = T_STACK_TOP;
    t_put(c->slot, c->bytes, c->blen);
    if (c->setup != NULL) {
        c->setup(&a, c->slot);
    }
    t_dbt_run(&a);
    /* Guest-memory parity probe: the case's 256-byte slot after the
     * DBT run must equal its state after the oracle run (covers the
     * MOVS/STOS stores and the CALL return-address push data). */
    memcpy(snap, g_win + c->slot, sizeof(snap));

    /* Interpreter oracle on an identical clone. */
    t_ctx_init(&b, c->slot, c->eflags);
    memcpy(b.gpr, c->gpr, sizeof(b.gpr));
    b.gpr[I686_REG_ESP] = T_STACK_TOP;
    t_put(c->slot, c->bytes, c->blen);
    if (c->setup != NULL) {
        c->setup(&b, c->slot);
    }
    (void)i686_interp_run(&b);
    i686_flags_materialize(&b);

    CHECK(a.exit_reason == b.exit_reason);
    if (a.exit_reason != b.exit_reason) {
        fprintf(stderr, "      %s: reason dbt=%u interp=%u\n", c->name,
                a.exit_reason, b.exit_reason);
    }
    CHECK(a.eip == b.eip);
    if (a.eip != b.eip) {
        fprintf(stderr, "      %s: eip dbt=%08x interp=%08x (arg dbt=%08x "
                        "interp=%08x dest dbt=%08x interp=%08x)\n",
                c->name, a.eip, b.eip, a.exit_arg, b.exit_arg, a.exit_dest,
                b.exit_dest);
    }
    for (i = 0U; i < 8U; i++) {
        if (a.gpr[i] != b.gpr[i]) {
            fprintf(stderr, "      %s: gpr[%u] dbt=%08x interp=%08x\n",
                    c->name, i, a.gpr[i], b.gpr[i]);
        }
        CHECK(a.gpr[i] == b.gpr[i]);
    }
    CHECK((a.eflags & c->ef_mask) == (b.eflags & c->ef_mask));
    CHECK(memcmp(snap, g_win + c->slot, sizeof(snap)) == 0);
    if (c->cmp_arg) {
        CHECK(a.exit_arg == b.exit_arg);
    }
    if (g_fail == 0U) {
        printf("ok %s (reason=%u eip=%08x esp=%08x)\n", c->name,
               a.exit_reason, a.eip, a.gpr[I686_REG_ESP]);
    }
}

/* ---- data-slot setups ---------------------------------------------- */

static void t_setup_jmp_mem(i686_ctx_t *ctx, uint32_t slot)
{
    ctx->gpr[I686_REG_EAX] = slot + 0x40U;
    t_w32(slot + 0x40U, slot + 8U); /* [eax] = hlt address */
}

static void t_setup_ret_imm(i686_ctx_t *ctx, uint32_t slot)
{
    (void)ctx;
    t_w32(T_STACK_TOP, slot + 4U); /* popped return address -> hlt */
}

static void t_setup_movsb(i686_ctx_t *ctx, uint32_t slot)
{
    (void)ctx;
    t_w32(slot + 0x40U, 0xAB00CD11U); /* source data */
}

static void t_setup_stosb(i686_ctx_t *ctx, uint32_t slot)
{
    (void)ctx;
    t_w32(slot + 0x60U, 0x12345678U); /* poison destination */
}

static void t_setup_cmps_eq(i686_ctx_t *ctx, uint32_t slot)
{
    (void)ctx;
    t_w32(slot + 0x40U, 0x41C0FFEEU);
    t_w32(slot + 0x60U, 0x41C0FFEEU);
}

static void t_setup_cmps_ne(i686_ctx_t *ctx, uint32_t slot)
{
    (void)ctx;
    t_w32(slot + 0x40U, 0x41C0FFEEU);
    t_w32(slot + 0x60U, 0x42C0FFEEU);
}

static void t_setup_scas(i686_ctx_t *ctx, uint32_t slot)
{
    ctx->gpr[I686_REG_EAX] = 0x00000041U;
    t_w32(slot + 0x60U, 0x00000042U); /* [edi] != AL */
}

static void t_setup_scas_eq(i686_ctx_t *ctx, uint32_t slot)
{
    ctx->gpr[I686_REG_EAX] = 0x00000042U;
    t_w32(slot + 0x60U, 0x00000042U); /* [edi] == AL */
}

/* ---- main case table ----------------------------------------------- */

#define T_SLOT(i) (0x10000U + (uint32_t)(i) * 0x100U)

int main(void)
{
    static const uint8_t b_jmp_fwd[] = {0xEB, 0x03, 0x00, 0x00, 0x00, 0xF4};
    static const uint8_t b_jmp_back[] = {0xF4, 0x90, 0x90, 0xEB, 0xFB};
    static const uint8_t b_jmp32_fwd[] = {0xE9, 0x03, 0x00, 0x00, 0x00,
                                          0x90, 0x90, 0x90, 0xF4};
    static const uint8_t b_jmp32_back[] = {0xF4, 0x90, 0x90, 0x90, 0x90,
                                           0xE9, 0xF6, 0xFF, 0xFF, 0xFF};
    static const uint8_t b_jmp_reg[] = {0xFF, 0xE0, 0x90, 0x90, 0x90,
                                        0x90, 0xF4};
    static const uint8_t b_jmp_mem[] = {0xFF, 0x20, 0x90, 0x90, 0x90,
                                        0x90, 0x90, 0x90, 0xF4};
    static const uint8_t b_jmp_ax16[] = {0x66, 0xFF, 0xE0, 0x90, 0x90,
                                         0x90, 0xF4};
    static const uint8_t b_call_ret[] = {0xE8, 0x03, 0x00, 0x00, 0x00,
                                         0xF4, 0x90, 0x90, 0xC3};
    static const uint8_t b_call16_ret16[] = {0x66, 0xE8, 0x01, 0x00,
                                             0xF4, 0x66, 0xC3};
    static const uint8_t b_ret_imm[] = {0xC2, 0x08, 0x00, 0x90, 0xF4};
    static const uint8_t b_int80[] = {0xCD, 0x80, 0xF4};
    static const uint8_t b_sysenter[] = {0x0F, 0x34, 0xF4};
    static const uint8_t b_int3[] = {0xCC, 0xF4};
    static const uint8_t b_int_other[] = {0xCD, 0x21, 0xF4};
    static const uint8_t b_ud2[] = {0x0F, 0x0B, 0xF4};
    static const uint8_t b_hlt[] = {0xF4};
    static const uint8_t b_nop_wait[] = {0x90, 0x9B, 0xF4};
    static const uint8_t b_bad[] = {0x0F, 0x0E, 0xF4};
    static const uint8_t b_movsb[] = {0xA4, 0xF4};
    static const uint8_t b_movsw[] = {0xA5, 0xF4};
    static const uint8_t b_stosb[] = {0xAA, 0xF4};
    static const uint8_t b_stosw[] = {0xAB, 0xF4};
    static const uint8_t b_lodsb[] = {0xAC, 0xF4};
    static const uint8_t b_cmps_jz[] = {0xA6, 0x74, 0x01, 0xF4, 0xCC};
    static const uint8_t b_scas_jnz[] = {0xAE, 0x75, 0x01, 0xF4, 0xCC};

    /* Jcc matrix: one byte stream, 14 fusible conditions, taken and
     * fall-through directions via two EFLAGS settings each. */
    static const struct {
        uint8_t cond;
        uint32_t ef_true;
        uint32_t ef_false;
    } jcc_tab[] = {
        {0U, I686_EF_OF, 0U},                       /* O  */
        {1U, 0U, I686_EF_OF},                       /* NO */
        {2U, I686_EF_CF, 0U},                       /* B  */
        {3U, 0U, I686_EF_CF},                       /* AE */
        {4U, I686_EF_ZF, 0U},                       /* E  */
        {5U, 0U, I686_EF_ZF},                       /* NE */
        {6U, I686_EF_CF | I686_EF_ZF, 0U},          /* BE */
        {7U, 0U, I686_EF_CF | I686_EF_ZF},          /* A  */
        {8U, I686_EF_SF, 0U},                       /* S  */
        {9U, 0U, I686_EF_SF},                       /* NS */
        {12U, I686_EF_SF, 0U},                      /* L: SF != OF */
        {13U, 0U, I686_EF_SF},                      /* GE: SF == OF */
        {14U, I686_EF_ZF | I686_EF_SF | I686_EF_OF, 0U}, /* LE */
        {15U, 0U, I686_EF_ZF | I686_EF_SF | I686_EF_OF}, /* G  */
    };
    static const uint8_t b_jcc[] = {0x00, 0x01, 0xF4, 0xCC};

    /* 32-bit slot counter + 16-bit-zone bookkeeping. */
    unsigned slot = 0U;
    unsigned j;
    unsigned i;
    uint8_t bytes[8];

    g_win = mmap(NULL, 0x20000U, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    g_jit = mmap((void *)(uintptr_t)T_JIT_ADDR, g_jit_cap,
                 PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g_win == MAP_FAILED || g_jit == MAP_FAILED ||
        (uintptr_t)g_jit != T_JIT_ADDR) {
        fprintf(stderr, "L3C FAIL: mmap\n");
        return 1;
    }

    i686_interp_init_all();

    {
        const t_case_t cases[] = {
            {"jmp_fwd", 0U, b_jmp_fwd, sizeof(b_jmp_fwd), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"jmp_back", 0U, b_jmp_back, sizeof(b_jmp_back), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"jmp32_fwd", 0U, b_jmp32_fwd, sizeof(b_jmp32_fwd), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"jmp32_back", 0U, b_jmp32_back, sizeof(b_jmp32_back), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"jmp_reg", 0U, b_jmp_reg, sizeof(b_jmp_reg), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"jmp_mem", 0U, b_jmp_mem, sizeof(b_jmp_mem), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_jmp_mem,
             0xFFFFFFFFU, 1},
            {"jmp_ax16", 0x8000U, b_jmp_ax16, sizeof(b_jmp_ax16), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"call_ret", 0U, b_call_ret, sizeof(b_call_ret), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"call16_ret16", 0x8020U, b_call16_ret16,
             sizeof(b_call16_ret16), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"ret_imm", 0U, b_ret_imm, sizeof(b_ret_imm), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_ret_imm,
             0xFFFFFFFFU, 1},
            {"int80_getpid", 0U, b_int80, sizeof(b_int80), 2U,
             {20U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 0},
            {"sysenter_getpid", 0U, b_sysenter, sizeof(b_sysenter), 2U,
             {20U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 0},
            {"int3", 0U, b_int3, sizeof(b_int3), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 0},
            {"int_non80", 0U, b_int_other, sizeof(b_int_other), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 0},
            {"ud2", 0U, b_ud2, sizeof(b_ud2), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 0},
            {"hlt", 0U, b_hlt, sizeof(b_hlt), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"nop_wait", 0U, b_nop_wait, sizeof(b_nop_wait), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 1},
            {"d2_undecodable", 0U, b_bad, sizeof(b_bad), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, NULL, 0xFFFFFFFFU, 0},
            {"movsb_df0", 0U, b_movsb, sizeof(b_movsb), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_movsb,
             0xFFFFFFFFU, 1},
            {"movsb_df1", 0U, b_movsb, sizeof(b_movsb),
             2U | I686_EF_DF, {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
             t_setup_movsb, 0xFFFFFFFFU, 1},
            {"movsw_df0", 0U, b_movsw, sizeof(b_movsw), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_movsb,
             0xFFFFFFFFU, 1},
            {"movsw_df1", 0U, b_movsw, sizeof(b_movsw),
             2U | I686_EF_DF, {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
             t_setup_movsb, 0xFFFFFFFFU, 1},
            {"stosb_df0", 0U, b_stosb, sizeof(b_stosb), 2U,
             {0x5AU, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_stosb,
             0xFFFFFFFFU, 1},
            {"stosb_df1", 0U, b_stosb, sizeof(b_stosb),
             2U | I686_EF_DF, {0x5AU, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
             t_setup_stosb, 0xFFFFFFFFU, 1},
            {"stosd_df0", 0U, b_stosw, sizeof(b_stosw), 2U,
             {0xCAFEBABEU, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_stosb,
             0xFFFFFFFFU, 1},
            {"lodsb_df1", 0U, b_lodsb, sizeof(b_lodsb),
             2U | I686_EF_DF, {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
             t_setup_movsb, 0xFFFFFFFFU, 1},
            {"cmps_eq_jz", 0U, b_cmps_jz, sizeof(b_cmps_jz), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_cmps_eq,
             T_EF_PF_AF, 0},
            {"cmps_ne_jz", 0U, b_cmps_jz, sizeof(b_cmps_jz), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_cmps_ne,
             T_EF_PF_AF, 0},
            {"scas_ne_jnz", 0U, b_scas_jnz, sizeof(b_scas_jnz), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_scas,
             T_EF_PF_AF, 0},
            {"scas_eq_jnz", 0U, b_scas_jnz, sizeof(b_scas_jnz), 2U,
             {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U}, t_setup_scas_eq,
             T_EF_PF_AF, 0},
        };

        for (i = 0U; i < sizeof(cases) / sizeof(cases[0]); i++) {
            t_case_t c = cases[i];
            /* Fixed 16-bit-zone slots stay; everything else spreads. */
            if (c.slot == 0U) {
                c.slot = T_SLOT(slot++);
            }
            /* String cases need ESI/EDI pointed at the data slots. */
            if (c.setup == t_setup_movsb || c.setup == t_setup_stosb ||
                c.setup == t_setup_cmps_eq || c.setup == t_setup_cmps_ne ||
                c.setup == t_setup_scas || c.setup == t_setup_scas_eq) {
                c.gpr[I686_REG_ESI] = c.slot + 0x40U;
                c.gpr[I686_REG_EDI] = c.slot + 0x60U;
            }
            if (c.name[0] == 'j' && c.name[1] == 'm' &&
                c.name[2] == 'p' && c.name[3] == '_') {
                if (strcmp(c.name, "jmp_reg") == 0) {
                    c.gpr[I686_REG_EAX] = c.slot + 6U;
                } else if (strcmp(c.name, "jmp_ax16") == 0) {
                    c.gpr[I686_REG_EAX] = 0xBEEF0000U | (c.slot + 6U);
                }
            }
            t_run_case(&c);
        }
    }

    /* Jcc matrix: 14 conditions x {taken, fall-through}. */
    for (j = 0U; j < sizeof(jcc_tab) / sizeof(jcc_tab[0]); j++) {
        t_case_t c;
        i686_ctx_t probe;
        char nb[32];
        int want_t, want_f;

        memset(&c, 0, sizeof(c));
        memcpy(bytes, b_jcc, sizeof(b_jcc));
        bytes[0] = (uint8_t)(0x70U | jcc_tab[j].cond);
        c.slot = T_SLOT(slot++);
        c.bytes = bytes;
        c.blen = sizeof(b_jcc);
        c.ef_mask = 0xFFFFFFFFU;
        c.cmp_arg = 0;

        /* Sanity: the flag pairs must actually evaluate taken/clear. */
        t_ctx_init(&probe, 0U, 2U | jcc_tab[j].ef_true);
        want_t = i686_flags_cc(&probe, jcc_tab[j].cond);
        t_ctx_init(&probe, 0U, 2U | jcc_tab[j].ef_false);
        want_f = i686_flags_cc(&probe, jcc_tab[j].cond);
        CHECK(want_t == 1 && want_f == 0);

        c.eflags = 2U | jcc_tab[j].ef_true;
        (void)snprintf(nb, sizeof(nb), "jcc_cc%u_taken",
                       (unsigned)jcc_tab[j].cond);
        c.name = nb;
        t_run_case(&c);
        c.eflags = 2U | jcc_tab[j].ef_false;
        (void)snprintf(nb, sizeof(nb), "jcc_cc%u_fall",
                       (unsigned)jcc_tab[j].cond);
        c.name = nb;
        t_run_case(&c);
    }

    /* SETcc sample (E/GE/A). E and A use a taken mask and a not-taken
     * mask. GE's not-taken mask is SF only. GE is SF==OF, so SF without
     * OF is the not-taken polarity. The Jcc matrix above checks that
     * same SF-only not-taken case. */
    {
        static const uint8_t setcc_conds[] = {4U, 13U, 7U};
        static const uint32_t setcc_t[] = {I686_EF_ZF,
                                           0U,
                                           0U};
        static const uint32_t setcc_f[] = {0U,
                                           I686_EF_SF,
                                           I686_EF_CF | I686_EF_ZF};
        for (j = 0U; j < sizeof(setcc_conds); j++) {
            t_case_t c;
            char nb[32];
            memset(&c, 0, sizeof(c));
            bytes[0] = 0x0FU;
            bytes[1] = (uint8_t)(0x90U | setcc_conds[j]);
            bytes[2] = 0xC0U; /* setcc al */
            bytes[3] = 0xF4U;
            c.slot = T_SLOT(slot++);
            c.bytes = bytes;
            c.blen = 4U;
            c.eflags = 2U | setcc_t[j];
            c.ef_mask = 0xFFFFFFFFU;
            c.cmp_arg = 1;
            (void)snprintf(nb, sizeof(nb), "setcc_cc%u_t",
                           (unsigned)setcc_conds[j]);
            c.name = nb;
            t_run_case(&c);
            (void)snprintf(nb, sizeof(nb), "setcc_cc%u_f",
                           (unsigned)setcc_conds[j]);
            c.name = nb;
            c.eflags = 2U | setcc_f[j];
            t_run_case(&c);
        }
    }

    /* CMOVcc 32-bit and 16-bit, both directions.  Destination is EBX
     * (not ECX) because of the trampoline x1 relay — see header. */
    {
        static const uint8_t b_cmov32[] = {0x0F, 0x44, 0xD8, 0xF4};
        static const uint8_t b_cmov16[] = {0x66, 0x0F, 0x44, 0xD8, 0xF4};
        t_case_t c;
        memset(&c, 0, sizeof(c));
        c.gpr[I686_REG_EAX] = 0x11223344U;
        c.gpr[I686_REG_EBX] = 0x55667788U;
        c.ef_mask = 0xFFFFFFFFU;
        c.cmp_arg = 1;
        c.bytes = b_cmov32;
        c.blen = sizeof(b_cmov32);
        c.name = "cmov32_t";
        c.slot = T_SLOT(slot++);
        c.eflags = 2U | I686_EF_ZF;
        t_run_case(&c);
        c.name = "cmov32_f";
        c.eflags = 2U;
        t_run_case(&c);
        c.bytes = b_cmov16;
        c.blen = sizeof(b_cmov16);
        c.name = "cmov16_t";
        c.slot = T_SLOT(slot++);
        c.eflags = 2U | I686_EF_ZF;
        t_run_case(&c);
        c.name = "cmov16_f";
        c.eflags = 2U;
        t_run_case(&c);
    }

    /* Targeted invariant: the ret_imm DBT run must leave ESP exactly
     * top+4+8 (functional proof the imm16 pop-adjust ran in-block). */
    {
        i686_ctx_t a;
        t_ctx_init(&a, T_SLOT(30U), 2U);
        t_put(T_SLOT(30U), b_ret_imm, sizeof(b_ret_imm));
        t_setup_ret_imm(&a, T_SLOT(30U));
        t_dbt_run(&a);
        CHECK(a.exit_reason == I686_EXIT_HLT);
        CHECK(a.gpr[I686_REG_ESP] == T_STACK_TOP + 4U + 8U);
        CHECK(a.eip == T_SLOT(30U) + 5U);
    }

    if (g_fail != 0U) {
        printf("L3C FAIL (%d checks failed of %d)\n", g_fail, g_checks);
        return 1;
    }
    printf("L3C OK (%d checks)\n", g_checks);
    return 0;
}
