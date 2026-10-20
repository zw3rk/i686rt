/*
 * src/main.c — entry point and option handling for i686rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0: option/env plumbing and the invocation forms only.  No engine is
 * wired yet (Phases 1 and 3); running a guest exits 1 with a clear message.
 */

/* POSIX 2008: setenv/environ under strict -std=c11 with musl. */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "i686rt.h"
#include "interp/interp.h"
#include "rt32/rt32.h"

extern char **environ;

#define I686RT_VERSION "0.0-phase0"

static void usage(FILE *out)
{
    static const char *msg =
        "i686rt — 32-bit x86 (i686) Linux user-mode translator\n"
        "\n"
        "Usage:\n"
        "  i686rt [--window HEX] [--sysroot DIR] [--cache DIR]\n"
        "         [--engine interp|dbt] [--x87-64|--x87-80] -- PATH [ARGV0...]\n"
        "  i686rt --help\n"
        "  i686rt --version\n"
        "\n"
        "Environment: I686RT_WINDOW, I686RT_SYSROOT, I686RT_CACHE,\n"
        "             I686RT_ENGINE, I686RT_X87, I686RT_HOST\n";
    fputs(msg, out);
}

static int parse_engine(const char *s, int *out)
{
    if (strcmp(s, "interp") == 0) {
        *out = I686_ENGINE_INTERP;
        return 0;
    }
    if (strcmp(s, "dbt") == 0) {
        *out = I686_ENGINE_DBT;
        return 0;
    }
    return -1;
}

static int parse_x87(const char *s, bool *x87_80)
{
    if (strcmp(s, "64") == 0) {
        *x87_80 = false;
        return 0;
    }
    if (strcmp(s, "80") == 0) {
        *x87_80 = true;
        return 0;
    }
    return -1;
}

/* Returns the index of the guest PATH in argv[], or -1 on error. */
static int parse_args(i686_ctx_t *ctx, int argc, char **argv)
{
    int i = 1;

    while (i < argc && strcmp(argv[i], "--") != 0) {
        if (strcmp(argv[i], "--help") == 0) {
            usage(stdout);
            exit(0);
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("i686rt %s\n", I686RT_VERSION);
            exit(0);
        }
        if (i + 1 >= argc) {
            return -1;
        }
        if (strcmp(argv[i], "--window") == 0) {
            char *end = NULL;
            unsigned long long v = strtoull(argv[i + 1], &end, 0);
            if (end == argv[i + 1] || *end != '\0' || v > 0xffffffffffffffffULL) {
                return -1;
            }
            /* Stored via I686RT_WINDOW-equivalent; consumed by vm init later. */
            setenv("I686RT_WINDOW", argv[i + 1], 1);
        } else if (strcmp(argv[i], "--sysroot") == 0) {
            ctx->sysroot = argv[i + 1];
        } else if (strcmp(argv[i], "--cache") == 0) {
            ctx->cache_dir = argv[i + 1];
        } else if (strcmp(argv[i], "--engine") == 0) {
            if (parse_engine(argv[i + 1], &ctx->engine) != 0) {
                return -1;
            }
        } else if (strcmp(argv[i], "--x87-80") == 0) {
            ctx->x87_80 = true;
            i--; /* flag without argument: undo the i+1 advance below */
        } else if (strcmp(argv[i], "--x87-64") == 0) {
            ctx->x87_80 = false;
            i--;
        } else {
            return -1;
        }
        i += 2;
    }

    if (i >= argc) {
        return -1; /* missing "-- PATH" */
    }
    return i + 1; /* first token after "--" */
}

static void apply_env(i686_ctx_t *ctx)
{
    const char *s;

    if (ctx->engine == I686_ENGINE_DBT || ctx->engine == I686_ENGINE_INTERP) {
        /* Already set explicitly by --engine; env must not override. */
    } else if ((s = getenv("I686RT_ENGINE")) != NULL) {
        if (parse_engine(s, &ctx->engine) != 0) {
            fprintf(stderr, "i686rt: bad I686RT_ENGINE=%s\n", s);
            exit(2);
        }
    }
    if (!ctx->x87_80 && (s = getenv("I686RT_X87")) != NULL) {
        if (parse_x87(s, &ctx->x87_80) != 0) {
            fprintf(stderr, "i686rt: bad I686RT_X87=%s\n", s);
            exit(2);
        }
    }
    if (ctx->sysroot == NULL && (s = getenv("I686RT_SYSROOT")) != NULL) {
        ctx->sysroot = s;
    }
    if (ctx->cache_dir == NULL && (s = getenv("I686RT_CACHE")) != NULL) {
        ctx->cache_dir = s;
    }
    /* I686RT_HOST=none opts out of the /dev/a32host handshake (D14). */
    if ((s = getenv("I686RT_HOST")) != NULL && strcmp(s, "none") == 0) {
        ctx->has_host_info = false;
    }
}

static uint64_t env_window(void)
{
    const char *s = getenv("I686RT_WINDOW");
    char *end = NULL;
    unsigned long long v;

    if (s == NULL) {
        return 0;
    }
    v = strtoull(s, &end, 0);
    if (end == s || *end != '\0') {
        return 0;
    }
    return (uint64_t)v;
}

/* Load the guest and run it on the configured engine.  Returns the guest
 * exit status (0..255) or -1 on a host-side failure. */
static int run_guest(i686_ctx_t *ctx)
{
    rt32_elf_info_t info;
    uint32_t sp = 0;
    int fd;
    int r;

    rt32_host_probe(ctx);
    if (rt32_vm_init(ctx, env_window()) != 0) {
        (void)fprintf(stderr, "i686rt: guest window init failed\n");
        return -1;
    }

    fd = open(ctx->exec_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        (void)fprintf(stderr, "i686rt: open %s: %s\n", ctx->exec_path,
                      strerror(errno));
        return -1;
    }
    if (rt32_elf_load(ctx, fd, ctx->exec_path, &info) != 0) {
        (void)fprintf(stderr, "i686rt: ELF load failed: %s\n", ctx->exec_path);
        (void)close(fd);
        return -1;
    }
    (void)close(fd);

    if (rt32_stack_setup(ctx, &info, ctx->guest_argc, ctx->guest_argv,
                         ctx->host_envp, &sp) != 0) {
        (void)fprintf(stderr, "i686rt: guest stack setup failed\n");
        return -1;
    }

    /* Flat i386 Linux initial state. */
    ctx->gpr[I686_REG_ESP] = sp;
    ctx->eip = info.entry;
    ctx->eflags = 0x202U; /* IF set; bit 1 reserved, always 1 */
    ctx->seg_sel[I686_SEG_CS] = 0x23U;
    ctx->seg_sel[I686_SEG_DS] = 0x2bU;
    ctx->seg_sel[I686_SEG_ES] = 0x2bU;
    ctx->seg_sel[I686_SEG_SS] = 0x2bU;
    ctx->seg_sel[I686_SEG_FS] = 0U;
    ctx->seg_sel[I686_SEG_GS] = 0U;
    ctx->seg_base[I686_SEG_CS] = 0;
    ctx->seg_base[I686_SEG_DS] = 0;
    ctx->seg_base[I686_SEG_ES] = 0;
    ctx->seg_base[I686_SEG_SS] = 0;
    ctx->seg_base[I686_SEG_FS] = 0;
    ctx->seg_base[I686_SEG_GS] = 0;

    if (ctx->engine == I686_ENGINE_DBT) {
        (void)fprintf(stderr, "i686rt: dbt engine lands in phase 3; "
                              "using interpreter\n");
        ctx->engine = I686_ENGINE_INTERP;
    }

    i686_interp_init_all();
    r = i686_interp_run(ctx);
    if (r == I686_EXIT_SYSCALL) {
        return (int)(ctx->exit_arg & 0xffU);
    }
    return 1;
}

int main(int argc, char **argv)
{
    i686_ctx_t ctx;
    int path_idx;
    int st;

    memset(&ctx, 0, sizeof(ctx));
    ctx.engine = I686_ENGINE_INTERP; /* interpreter is the default oracle (D2) */

    path_idx = parse_args(&ctx, argc, argv);
    if (path_idx < 0) {
        usage(stderr);
        return 2;
    }
    apply_env(&ctx);
    ctx.exec_path = argv[path_idx];
    ctx.guest_argc = argc - path_idx;
    ctx.guest_argv = &argv[path_idx];
    ctx.host_envp = environ;

    st = run_guest(&ctx);
    if (st < 0) {
        return 1;
    }
    if (ctx.stats_enabled) {
        (void)fprintf(stderr, "i686rt: blocks=%llu syscalls=%llu\n",
                      (unsigned long long)ctx.blocks_executed,
                      (unsigned long long)ctx.syscalls_executed);
    }
    return st;
}
