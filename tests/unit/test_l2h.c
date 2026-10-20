/*
 * tests/unit/test_l2h.c — host-native unit driver for the L2h pieces
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Links only test_l2h.c + src/os/proc.c (the shared i386 auxv builder
 * lives there, see src/os/proc.h): asserts the pinned D12/E07 auxv entry
 * order and values for the vDSO-unmapped and vDSO-mapped cases, the
 * /proc/self/maps line format, the /proc/cpuinfo flags line, and the
 * fd-returning contract of i686_proc_open_at (memfd on Linux, unlinked
 * temp file elsewhere).
 *
 * Compile:
 *   clang -std=c11 -Wall -Wextra -Werror=vla -pedantic \
 *       -Isrc -Iinclude -o /tmp/test_l2h tests/unit/test_l2h.c src/os/proc.c
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "os/proc.h"

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

/* ---- auxv builder (SPEC D12, E07) -------------------------------------- */

static size_t aux_find(const uint32_t *av, size_t words, uint32_t key)
{
    for (size_t i = 0U; i + 1U < words; i += 2U) {
        if (av[i] == key) {
            return i;
        }
    }
    return (size_t)-1;
}

static void t_auxv_novdso(void)
{
    i686_auxv_i386_args_t a;
    memset(&a, 0, sizeof(a));
    a.phdr_vaddr     = 0x08048074U;
    a.phent          = 56U; /* sizeof(Elf32_Phdr) */
    a.phnum          = 8U;
    a.interp_base    = 0x20000000U;
    a.entry          = 0x08048100U;
    a.at_random_va   = 0xDFFFFF00U;
    a.at_platform_va = 0xDFFFFF10U;
    a.at_execfn_va   = 0xDFFFFF20U;
    a.vdso_base      = 0U; /* vDSO mapping failed -> no vdso entries */
    a.vsyscall_addr  = 0U;

    uint32_t av[I686_AUXV_I386_MAX_WORDS];
    size_t n = i686_auxv_build_i386(&a, av, I686_AUXV_I386_MAX_WORDS);
    CHECK(n == 36U); /* 18 entries + AT_NULL = 36 u32 words */

    static const uint32_t want_keys[18] = {
        I686_AT_PHDR,     I686_AT_PHENT,       I686_AT_PHNUM,
        I686_AT_PAGESZ,   I686_AT_BASE,        I686_AT_FLAGS,
        I686_AT_ENTRY,    I686_AT_UID,         I686_AT_EUID,
        I686_AT_GID,      I686_AT_EGID,        I686_AT_SECURE,
        I686_AT_RANDOM,   I686_AT_HWCAP,       I686_AT_CLKTCK,
        I686_AT_PLATFORM, I686_AT_EXECFN,      I686_AT_NULL,
    };
    for (size_t i = 0U; i < 18U; i++) {
        CHECK(av[2U * i] == want_keys[i]);
    }
    CHECK(av[2U * 17U] == I686_AT_NULL && av[2U * 17U + 1U] == 0U);

    CHECK(av[aux_find(av, n, I686_AT_PHDR) + 1U] == 0x08048074U);
    CHECK(av[aux_find(av, n, I686_AT_PHENT) + 1U] == 56U);
    CHECK(av[aux_find(av, n, I686_AT_PHNUM) + 1U] == 8U);
    CHECK(av[aux_find(av, n, I686_AT_PAGESZ) + 1U] == 4096U);
    CHECK(av[aux_find(av, n, I686_AT_BASE) + 1U] == 0x20000000U);
    CHECK(av[aux_find(av, n, I686_AT_FLAGS) + 1U] == 0U);
    CHECK(av[aux_find(av, n, I686_AT_ENTRY) + 1U] == 0x08048100U);
    CHECK(av[aux_find(av, n, I686_AT_UID) + 1U] == (uint32_t)getuid());
    CHECK(av[aux_find(av, n, I686_AT_EUID) + 1U] == (uint32_t)geteuid());
    CHECK(av[aux_find(av, n, I686_AT_GID) + 1U] == (uint32_t)getgid());
    CHECK(av[aux_find(av, n, I686_AT_EGID) + 1U] == (uint32_t)getegid());
    CHECK(av[aux_find(av, n, I686_AT_SECURE) + 1U] == 0U);
    CHECK(av[aux_find(av, n, I686_AT_RANDOM) + 1U] == 0xDFFFFF00U);
    CHECK(av[aux_find(av, n, I686_AT_HWCAP) + 1U] == 0x07808111U);
    CHECK(av[aux_find(av, n, I686_AT_CLKTCK) + 1U] == 100U);
    CHECK(av[aux_find(av, n, I686_AT_PLATFORM) + 1U] == 0xDFFFFF10U);
    CHECK(av[aux_find(av, n, I686_AT_EXECFN) + 1U] == 0xDFFFFF20U);

    /* D10 mask computed from the CPUID.1.EDX bit positions */
    CHECK(I686_HWCAP_I386 == 0x07808111U);
    CHECK((I686_HWCAP_I386 & (1U << 0)) != 0U);  /* FPU  */
    CHECK((I686_HWCAP_I386 & (1U << 4)) != 0U);  /* TSC  */
    CHECK((I686_HWCAP_I386 & (1U << 8)) != 0U);  /* CX8  */
    CHECK((I686_HWCAP_I386 & (1U << 15)) != 0U); /* CMOV */
    CHECK((I686_HWCAP_I386 & (1U << 23)) != 0U); /* MMX  */
    CHECK((I686_HWCAP_I386 & (1U << 24)) != 0U); /* FXSR */
    CHECK((I686_HWCAP_I386 & (1U << 25)) != 0U); /* SSE  */
    CHECK((I686_HWCAP_I386 & (1U << 26)) != 0U); /* SSE2 */
    CHECK((I686_HWCAP_I386 & ~(0x07808111U)) == 0U); /* nothing else */

    /* no vdso entries when the mapping failed */
    CHECK(aux_find(av, n, I686_AT_SYSINFO) == (size_t)-1);
    CHECK(aux_find(av, n, I686_AT_SYSINFO_EHDR) == (size_t)-1);

    /* undersized buffer refuses rather than truncating */
    CHECK(i686_auxv_build_i386(&a, av, 4U) == 0U);
    CHECK(i686_auxv_build_i386(NULL, av, 48U) == 0U);
    CHECK(i686_auxv_build_i386(&a, NULL, 48U) == 0U);
}

static void t_auxv_vdso(void)
{
    i686_auxv_i386_args_t a;
    memset(&a, 0, sizeof(a));
    a.phdr_vaddr     = 0x08048074U;
    a.phent          = 56U;
    a.phnum          = 8U;
    a.interp_base    = 0U; /* static executable: AT_BASE 0 */
    a.entry          = 0x08048100U;
    a.at_random_va   = 0xDFFFFF00U;
    a.at_platform_va = 0xDFFFFF10U;
    a.at_execfn_va   = 0xDFFFFF20U;
    a.vdso_base      = 0x408A9000U; /* E07 empirical dump values */
    a.vsyscall_addr  = 0x408A9554U;

    uint32_t av[I686_AUXV_I386_MAX_WORDS];
    size_t n = i686_auxv_build_i386(&a, av, I686_AUXV_I386_MAX_WORDS);
    CHECK(n == 40U); /* 20 entries incl. both vdso pairs */

    /* order: ..., AT_PLATFORM, AT_SYSINFO, AT_SYSINFO_EHDR, AT_EXECFN, AT_NULL */
    CHECK(av[30U] == I686_AT_PLATFORM);
    CHECK(av[31U] == 0xDFFFFF10U);
    CHECK(av[32U] == I686_AT_SYSINFO);
    CHECK(av[33U] == 0x408A9554U);
    CHECK(av[34U] == I686_AT_SYSINFO_EHDR);
    CHECK(av[35U] == 0x408A9000U);
    CHECK(av[36U] == I686_AT_EXECFN);
    CHECK(av[37U] == 0xDFFFFF20U);
    CHECK(av[38U] == I686_AT_NULL);
    CHECK(av[39U] == 0U);
    /* static executable: AT_BASE emitted as 0 */
    CHECK(av[aux_find(av, n, I686_AT_BASE) + 1U] == 0U);
}

/* ---- /proc/self/maps line format --------------------------------------- */

static void t_maps_format(void)
{
    i686_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.regions[0].start = 0x08048000U;
    ctx.regions[0].end   = 0x0804A000U;
    ctx.regions[0].prot  = PROT_READ | PROT_EXEC;
    ctx.regions[0].flags = 0U;
    strcpy(ctx.regions[0].name, "/bin/busybox");
    ctx.regions[1].start = 0xD8000000U;
    ctx.regions[1].end   = 0xE0000000U;
    ctx.regions[1].prot  = PROT_READ | PROT_WRITE;
    ctx.regions[1].flags = 0x12U;
    strcpy(ctx.regions[1].name, "[stack]");
    ctx.region_count = 2U;

    char buf[1024];
    size_t n = i686_proc_render_maps(&ctx, buf, sizeof(buf));
    static const char want[] =
        "08048000-0804a000 r-xp 00000000 00:00 0          /bin/busybox\n"
        "d8000000-e0000000 rw-p 00000000 00:00 0  [stack]\n";
    CHECK(n == sizeof(want) - 1U);
    CHECK(strcmp(buf, want) == 0);

    /* zero-sized regions are skipped */
    ctx.regions[0].end = ctx.regions[0].start;
    static const char want_stack[] =
        "d8000000-e0000000 rw-p 00000000 00:00 0  [stack]\n";
    n = i686_proc_render_maps(&ctx, buf, sizeof(buf));
    CHECK(n == sizeof(want_stack) - 1U);
    CHECK(strcmp(buf, want_stack) == 0);
    char tiny[8];
    CHECK(i686_proc_render_maps(&ctx, tiny, sizeof(tiny)) == 0U);
    CHECK(tiny[0] == '\0');
    CHECK(i686_proc_render_maps(&ctx, NULL, 16U) == 0U);
    CHECK(i686_proc_render_maps(NULL, buf, sizeof(buf)) == 0U);
}

/* ---- /proc/cpuinfo + /proc/version ------------------------------------- */

static int count_substrings(const char *hay, const char *needle)
{
    int count = 0;
    const char *p = strstr(hay, needle);
    while (p != NULL) {
        count++;
        p = strstr(p + 1, needle);
    }
    return count;
}

static void t_cpuinfo_version(void)
{
    const char *ci = i686_proc_cpuinfo_str();
    CHECK(strstr(ci, "vendor_id\t: GenuineIntel\n") != NULL);
    CHECK(strstr(ci, "cpu family\t: 6\n") != NULL);
    CHECK(strstr(ci, "flags\t\t: " I686_CPUID_FLAGS_STR "\n") != NULL);
    CHECK(strcmp(I686_CPUID_FLAGS_STR, "fpu tsc cx8 cmov mmx fxsr sse sse2") == 0);
    CHECK(count_substrings(ci, "processor\t: 0\n") == 1); /* cpu count 1 */
    CHECK(strstr(ci, "processor\t: 1\n") == NULL);

    const char *v = i686_proc_version_str();
    static const char v_prefix[] = "Linux version 6.1.0 (i686rt) ";
    CHECK(strncmp(v, v_prefix, sizeof(v_prefix) - 1U) == 0);
    CHECK(strchr(v, '\n') != NULL);
}

/* ---- i686_proc_open_at -------------------------------------------------- */

static size_t read_all(int fd, char *buf, size_t cap)
{
    size_t off = 0U;
    while (off < cap) {
        ssize_t r = read(fd, buf + off, cap - off);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (r == 0) {
            break;
        }
        off += (size_t)r;
    }
    return off;
}

static void t_open_at(void)
{
    i686_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    static char arg0[] = "./_build/busybox-i686";
    static char arg1[] = "sh";
    static char arg2[] = "-c";
    static char arg3[] = "echo hi";
    static char *argv4[5] = { arg0, arg1, arg2, arg3, NULL };
    ctx.guest_argc = 4;
    ctx.guest_argv = argv4;

    ctx.regions[0].start = 0x08048000U;
    ctx.regions[0].end   = 0x0804A000U;
    ctx.regions[0].prot  = PROT_READ | PROT_EXEC;
    strcpy(ctx.regions[0].name, "/bin/busybox");
    ctx.regions[1].start = 0xD8000000U;
    ctx.regions[1].end   = 0xE0000000U;
    ctx.regions[1].prot  = PROT_READ | PROT_WRITE;
    strcpy(ctx.regions[1].name, "[stack]");
    ctx.region_count = 2U;

    /* not virtualized -> caller falls through to the host path */
    CHECK(i686_proc_open_at(&ctx, "/etc/passwd") == I686_PROC_NOT_MATCHED);
    CHECK(i686_proc_open_at(&ctx, "/proc/meminfo") == I686_PROC_NOT_MATCHED);
    CHECK(i686_proc_open_at(&ctx, "/proc/self/environ") == I686_PROC_NOT_MATCHED);
    CHECK(i686_proc_open_at(&ctx, "proc/cpuinfo") == I686_PROC_NOT_MATCHED);
    CHECK(i686_proc_open_at(&ctx, NULL) == I686_PROC_NOT_MATCHED);

    char buf[8192];
    size_t n;

    int fd = i686_proc_open_at(&ctx, "/proc/version");
    CHECK(fd >= 0);
    if (fd >= 0) {
        n = read_all(fd, buf, sizeof(buf));
        CHECK(n == strlen(i686_proc_version_str()));
        CHECK(strcmp(buf, i686_proc_version_str()) == 0);
        close(fd);
    }

    fd = i686_proc_open_at(&ctx, "/proc/cpuinfo");
    CHECK(fd >= 0);
    if (fd >= 0) {
        n = read_all(fd, buf, sizeof(buf));
        CHECK(n == strlen(i686_proc_cpuinfo_str()));
        CHECK(strcmp(buf, i686_proc_cpuinfo_str()) == 0);
        close(fd);
    }

    /* extra slashes resolve like a32rt's skip_proc_prefix */
    fd = i686_proc_open_at(&ctx, "//proc///self//maps");
    CHECK(fd >= 0);
    if (fd >= 0) {
        char want[1024];
        size_t wlen = i686_proc_render_maps(&ctx, want, sizeof(want));
        n = read_all(fd, buf, sizeof(buf));
        CHECK(n == wlen);
        CHECK(memcmp(buf, want, wlen) == 0);
        close(fd);
    }

    fd = i686_proc_open_at(&ctx, "/proc/self/cmdline");
    CHECK(fd >= 0);
    if (fd >= 0) {
        static const char want[] =
            "./_build/busybox-i686\0sh\0-c\0echo hi\0";
        n = read_all(fd, buf, sizeof(buf));
        CHECK(n == sizeof(want) - 1U);
        CHECK(memcmp(buf, want, sizeof(want) - 1U) == 0);
        close(fd);
    }

    /* /proc/self/auxv serves the recorded initial auxv verbatim */
    ctx.auxv_data[0] = I686_AT_PHDR;
    ctx.auxv_data[1] = 0x08048074U;
    ctx.auxv_data[2] = I686_AT_NULL;
    ctx.auxv_data[3] = 0U;
    ctx.auxv_bytes    = 4U * sizeof(uint32_t);
    fd = i686_proc_open_at(&ctx, "/proc/self/auxv");
    CHECK(fd >= 0);
    if (fd >= 0) {
        n = read_all(fd, buf, sizeof(buf));
        CHECK(n == ctx.auxv_bytes);
        CHECK(memcmp(buf, ctx.auxv_data, ctx.auxv_bytes) == 0);
        close(fd);
    }

    /* /proc/self/exe opens the translated executable */
    char tmpl[] = "/tmp/test_l2h_exe_XXXXXX";
    int tfd = mkstemp(tmpl);
    CHECK(tfd >= 0);
    if (tfd >= 0) {
        static const char exe_body[] = "fake guest exe\n";
        CHECK(write(tfd, exe_body, sizeof(exe_body) - 1U) ==
              (ssize_t)(sizeof(exe_body) - 1U));
        close(tfd);
        ctx.exec_path = tmpl;
        fd = i686_proc_open_at(&ctx, "/proc/self/exe");
        CHECK(fd >= 0);
        if (fd >= 0) {
            n = read_all(fd, buf, sizeof(buf));
            CHECK(n == sizeof(exe_body) - 1U);
            CHECK(memcmp(buf, exe_body, n) == 0);
            close(fd);
        }
        unlink(tmpl);
    }

    /* /proc/self/exe with nothing to fall back to -> -ENOENT */
    ctx.exec_path = NULL;
    ctx.guest_argv = NULL;
    fd = i686_proc_open_at(&ctx, "/proc/self/exe");
    CHECK(fd == -ENOENT);
}

int main(void)
{
    t_auxv_novdso();
    t_auxv_vdso();
    t_maps_format();
    t_cpuinfo_version();
    t_open_at();

    if (g_fail != 0) {
        fprintf(stderr, "L2H FAILED: %d of %d checks failed\n", g_fail,
                g_checks);
        return 1;
    }
    puts("L2H OK");
    return 0;
}
