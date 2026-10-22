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
        /* Unset means "no explicit choice": rt32_vm_init then applies
         * its own resolution order (env re-read, a32host hint, scan).
         * A literal I686RT_WINDOW=0 still selects no-offset mode. */
        return UINT64_MAX;
    }
    v = strtoull(s, &end, 0);
    if (end == s || *end != '\0') {
        return UINT64_MAX; /* rt32_vm_init re-parses and reports it */
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

    /* Launch-side binfmt_script (RC7b): the kernel would interpret a
     * `#!` executable the same way guest execve does (r_execve), so
     * reinterpret before the ELF gate — wine's usr/bin/wine wrapper is
     * a shell script.  The interpreter resolves under --sysroot. */
    {
        char lpath[4096];
        unsigned depth;

        if (snprintf(lpath, sizeof lpath, "%s", ctx->exec_path) >=
            (int)sizeof lpath) {
            (void)fprintf(stderr, "i686rt: exec path too long\n");
            return -1;
        }
        int argv_owned = 0; /* guest_argv starts as main's argv slice */

        for (depth = 0U; depth < 5U; depth++) {
            char magic[2];
            char **na;
            char *script_copy;

            {
                extern int i686_exec_open(const i686_ctx_t *ctx,
                                          const char *path);
                fd = i686_exec_open(ctx, lpath);
            }
            if (fd < 0) {
                (void)fprintf(stderr, "i686rt: open %s: %s\n", lpath,
                              strerror(errno));
                return -1;
            }
            if (read(fd, magic, 2) == 2 && magic[0] == '#' && magic[1] == '!') {
                (void)close(fd);
                script_copy = malloc(strlen(lpath) + 1U);
                if (script_copy == NULL) {
                    return -1;
                }
                memcpy(script_copy, lpath, strlen(lpath) + 1U);
                {
                    extern char **i686_exec_script_reinterp(
                        const i686_ctx_t *ctx, char *path_buf, size_t path_sz,
                        char *script_path, char **argv);
                    na = i686_exec_script_reinterp(ctx, lpath, sizeof lpath,
                                                   script_copy,
                                                   ctx->guest_argv);
                }
                if (na == NULL) {
                    (void)fprintf(stderr, "i686rt: %s: not an ELF file\n",
                                  ctx->exec_path);
                    free(script_copy);
                    return -1;
                }
                if (argv_owned) {
                    free(ctx->guest_argv[0]);
                    free(ctx->guest_argv);
                }
                argv_owned = 1;
                ctx->guest_argv = na;
                ctx->guest_argc += (na[1] == script_copy) ? 1 : 2;
                ctx->exec_path = strdup(lpath); /* interpreter image */
                continue;
            }
            (void)lseek(fd, 0, SEEK_SET);
            break;
        }
        if (depth == 5U) {
            (void)fprintf(stderr, "i686rt: script interpreter nesting too deep\n");
            return -1;
        }
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
    ctx->eip = ctx->elf_entry; /* interp entry when PT_INTERP, else exe */
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

#ifdef I686RT_STRTRACE
    {
        uint32_t *fr = (uint32_t *)i686_guest_ptr(ctx, ctx->gpr[I686_REG_ESP]);
        uint32_t argc2 = fr[0];
        uint32_t k;
        for (k = 0U; k < argc2 && k < 16U; k++) {
            const char *g = (const char *)i686_guest_ptr(ctx, fr[1 + k]);
            (void)fprintf(stderr, "ARGV %u @%08x = \"%s\"\n", k, fr[1 + k], g);
        }
        {
            uint32_t q;
            for (q = 0U; q < 0x60U; q += 16U) {
                const uint8_t *b = (const uint8_t *)i686_guest_ptr(ctx, 0xdfffff00U + q);
                uint32_t j;
                (void)fprintf(stderr, "D %08x:", 0xdfffff00U + q);
                for (j = 0U; j < 16U; j++) {
                    (void)fprintf(stderr, " %02x", b[j]);
                }
                (void)fprintf(stderr, "\n");
            }
        }
    }
#endif

    if (ctx->engine < 0) {
        ctx->engine = I686_ENGINE_INTERP; /* default oracle (D2) */
    }
    {
        extern void i686_threads_main_init(i686_ctx_t *);
        extern void i686_signals_i386_init(void);
        i686_threads_main_init(ctx);
        i686_signals_i386_init();
    }
    i686_interp_init_all();
    if (ctx->engine == I686_ENGINE_DBT) {
        extern void i686_dbt_trace_enable(int);
        i686_dbt_trace_enable(getenv("I686RT_TRACE") != NULL);
        r = i686_dbt_run(ctx);
    } else {
        r = i686_interp_run(ctx);
    }
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
    ctx.engine = -1; /* unset: --engine or I686RT_ENGINE; INTERP default */

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
#ifdef I686RT_STRTRACE
    {
        /* dump printable strings in the guest heap for tokenizer forensics */
        uint32_t q;
        unsigned run = 0;
        char buf[80];
        for (q = 0x40002000U; q < 0x40004000U; q++) {
            uint8_t ch = *(const uint8_t *)i686_guest_ptr(&ctx, q);
            int printable = ch >= 0x20U && ch < 0x7fU;
            if (printable && run < sizeof(buf) - 1U) {
                buf[run++] = (char)ch;
            } else {
                if (run >= 4U) {
                    buf[run] = 0;
                    (void)fprintf(stderr, "HS %08x \"%s\"\n", q - run, buf);
                }
                run = 0;
            }
        }
    }
#endif

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
