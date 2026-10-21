/*
 * src/interp/interp.c — interpreter loop and handler registry (SPEC D2)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * The interpreter is the correctness oracle: decode → dispatch → repeat.
 * Handlers advance EIP themselves (branches set it directly); exit codes
 > 0 return to this loop for reason-specific handling.  Unknown opcodes
 * stop with a diagnostic — never an abort (D2).
 */

#include <stdio.h>
#include <stdlib.h>

#include "interp/interp.h"
#include "os/marshal.h"

/* Long i686_handle_syscall / int i686_syscall_is_exit (src/os/syscalls.c) */
long i686_handle_syscall(i686_ctx_t *ctx);
int  i686_syscall_is_exit(long nr);

#define I686_REGISTRY_MAX 512U

static i686_interp_fn s_registry[I686_REGISTRY_MAX];

void i686_interp_register(uint16_t op, i686_interp_fn fn)
{
    if ((unsigned)op < I686_REGISTRY_MAX) {
        s_registry[op] = fn;
    }
}

static int s_trace;

void i686_interp_init_all(void)
{
    static int s_done;
    if (s_done) {
        return;
    }
    s_done = 1;
    s_trace = getenv("I686RT_TRACE") != NULL;
    i686_interp_alu_init();
    i686_interp_mov_init();
    i686_interp_branch_init();
    i686_interp_muldiv_init();
}

const char *i686_op_name(uint16_t op)
{
    static char buf[24];
    (void)snprintf(buf, sizeof(buf), "op:%u", (unsigned)op);
    return buf;
}

static void diag(const char *what, const i686_ctx_t *ctx, uint16_t op)
{
    (void)fprintf(stderr,
                  "i686rt: interp: %s at eip=0x%08x (%s), esp=0x%08x\n",
                  what, ctx->eip, i686_op_name(op), ctx->gpr[I686_REG_ESP]);
}

/* DBT fallback hook: execute exactly ONE guest insn via the interpreter
 * handlers (D2). Returns 0 on success, or the terminal exit reason. */
int i686_interp_step(i686_ctx_t *ctx)
{
    x86_insn_t insn;
    i686_interp_fn fn;
    int r;

    if (x86_decode(ctx, ctx->eip, &insn) != 0) {
        ctx->exit_reason = I686_EXIT_UNDEF;
        ctx->exit_arg = 0;
        diag("undecodable instruction", ctx, 0);
        return I686_EXIT_UNDEF;
    }
    fn = (unsigned)insn.op < I686_REGISTRY_MAX ? s_registry[insn.op] : NULL;
    if (fn == NULL) {
        ctx->exit_reason = I686_EXIT_UNDEF;
        ctx->exit_arg = insn.op;
        diag("unimplemented opcode", ctx, insn.op);
        return I686_EXIT_UNDEF;
    }
    r = fn(ctx, &insn);
    ctx->blocks_executed++;
    if (r == I686_INTERP_CONTINUE) {
        return 0;
    }
    switch (r) {
    case I686_EXIT_SYSCALL: {
        long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
        long rv = i686_handle_syscall(ctx);
        if (i686_syscall_is_exit(nr)) {
            ctx->exit_reason = I686_EXIT_SYSCALL;
            ctx->exit_arg = (uint32_t)rv;
            return I686_EXIT_SYSCALL;
        }
        return 0;
    }
    default:
        ctx->exit_reason = (uint32_t)r;
        return r;
    }
}

int i686_interp_run(i686_ctx_t *ctx)
{
    for (;;) {
        x86_insn_t insn;
        i686_interp_fn fn;
        int r;

        if (x86_decode(ctx, ctx->eip, &insn) != 0) {
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = 0;
            diag("undecodable instruction", ctx, 0);
            return I686_EXIT_UNDEF;
        }
        fn = (unsigned)insn.op < I686_REGISTRY_MAX ? s_registry[insn.op] : NULL;
        if (fn == NULL) {
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = insn.op;
            diag("unimplemented opcode", ctx, insn.op);
            return I686_EXIT_UNDEF;
        }
        if (s_trace) {
            uint32_t b;
            fprintf(stderr, "T %08x op=%u len=%u b=", ctx->eip,
                    (unsigned)insn.op, insn.len);
            for (b = 0U; b < insn.len && b < 8U; b++) {
                const volatile uint8_t *p =
                    (const volatile uint8_t *)i686_guest_ptr(ctx, ctx->eip + b);
                fprintf(stderr, "%02x", *p);
            }
            fprintf(stderr, " esp=%08x\n", ctx->gpr[I686_REG_ESP]);
        }
        r = fn(ctx, &insn);
        ctx->blocks_executed++;

        if (r == I686_INTERP_CONTINUE) {
            if (ctx->pending_signals != 0U) {
                /* Signal delivery lands in Phase 4; safe-point check kept
                 * so the contract is visible from day one. */
            }
            continue;
        }
        switch (r) {
        case I686_EXIT_SYSCALL: {
            long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
            long rv = i686_handle_syscall(ctx);
            if (s_trace) {
                if (nr == 4 || nr == 3) {
                    (void)fprintf(stderr, "S %ld(%u,%08x,%u) -> %ld\n", nr,
                                  ctx->gpr[I686_REG_EBX],
                                  ctx->gpr[I686_REG_ECX],
                                  ctx->gpr[I686_REG_EDX], rv);
                } else if (nr == 5 || nr == 195 || nr == 196 || nr == 383 ||
                           nr == 11) {
                    /* Raw arg only: fetching the string can fault on
                     * garbage pointers until Phase 4 installs the
                     * fault-to-EFAULT machinery. */
                    (void)fprintf(stderr, "S %ld(%08x) -> %ld\n", nr,
                                  ctx->gpr[I686_REG_EBX], rv);
                } else {
                    (void)fprintf(stderr, "S %ld -> %ld\n", nr, rv);
                }
            }
            if (i686_syscall_is_exit(nr)) {
                ctx->exit_reason = I686_EXIT_SYSCALL;
                ctx->exit_arg = (uint32_t)rv; /* process exit status */
                return I686_EXIT_SYSCALL;
            }
            break;
        }
        case I686_EXIT_HLT:
            diag("guest hlt", ctx, insn.op);
            ctx->exit_reason = I686_EXIT_HLT;
            return I686_EXIT_HLT;
        case I686_EXIT_TRAP:
            diag("debug trap", ctx, insn.op);
            ctx->exit_reason = I686_EXIT_TRAP;
            ctx->exit_arg = insn.op;
            return I686_EXIT_TRAP;
        case I686_EXIT_FAULT:
            diag("guest fault", ctx, insn.op);
            ctx->exit_reason = I686_EXIT_FAULT;
            return I686_EXIT_FAULT;
        case I686_EXIT_UNDEF:
            diag("opcode refused", ctx, insn.op);
            ctx->exit_reason = I686_EXIT_UNDEF;
            ctx->exit_arg = insn.op;
            return I686_EXIT_UNDEF;
        default:
            ctx->exit_reason = (uint32_t)r;
            return r;
        }
    }
}
