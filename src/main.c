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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "i686rt.h"

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

int main(int argc, char **argv)
{
    i686_ctx_t ctx;
    int path_idx;

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

    (void)ctx.guest_base;
    fprintf(stderr,
            "i686rt: no engine implemented yet (phase 0 scaffold); "
            "cannot run %s\n",
            ctx.exec_path);
    return 1;
}
