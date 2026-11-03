/*
 * src/os/proc.c — /proc virtualization + shared i386 auxv builder (L2h)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Copy-first from a32rt's try_open_virtual_proc pattern (a32rt
 * src/syscalls.c @ d84feb3, read-only reference): /proc paths that guests
 * actually read are synthesized into an anonymous file (memfd on Linux,
 * unlinked mkstemp temp elsewhere) and served as a plain fd.  This file
 * also hosts i686_auxv_build_i386(), the single definition of the D12
 * i386 auxv contract used by rt32_stack32.c (see proc.h).
 *
 * Integration hook (S2, coordinator): before resolving a guest path
 * against the host, the open path in sys_pass.c calls
 *   int fd = i686_proc_open_at(ctx, guest_path);
 *   if (fd != I686_PROC_NOT_MATCHED) return fd;
 * (>= 0 is the synthesized fd, negative is already -errno).  Not wired
 * in this lane.
 */

#define _POSIX_C_SOURCE 200809L

#include "os/proc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
/* libc hides the generic syscall(2) wrapper unless _GNU_SOURCE; declare
 * the libc prototype locally so the prescribed strict C11 flags keep it
 * visible (identical declaration, so a visible libc prototype is fine). */
long syscall(long, ...);
#ifndef SYS_memfd_create
#define SYS_memfd_create 279 /* aarch64 (and x86_64) __NR_memfd_create */
#endif
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

/* ---- i386 initial auxv (SPEC D12, E07) -------------------------------- */

size_t i686_auxv_build_i386(const i686_auxv_i386_args_t *args, uint32_t *auxv,
                            size_t cap)
{
    if (args == NULL || auxv == NULL) {
        return 0U;
    }
    size_t n = 0U;
#define I686_PUSH_AUX(k, v)                                                   \
    do {                                                                      \
        if (n + 2U > cap) {                                                   \
            return 0U;                                                        \
        }                                                                     \
        auxv[n++] = (k);                                                      \
        auxv[n++] = (v);                                                      \
    } while (0)
    I686_PUSH_AUX(I686_AT_PHDR, args->phdr_vaddr);
    I686_PUSH_AUX(I686_AT_PHENT, args->phent); /* 56 for ELF32 */
    I686_PUSH_AUX(I686_AT_PHNUM, args->phnum);
    I686_PUSH_AUX(I686_AT_PAGESZ, I686_PAGE_SIZE);
    I686_PUSH_AUX(I686_AT_BASE, args->interp_base);
    I686_PUSH_AUX(I686_AT_FLAGS, 0U);
    I686_PUSH_AUX(I686_AT_ENTRY, args->entry);
    I686_PUSH_AUX(I686_AT_UID, (uint32_t)getuid());
    I686_PUSH_AUX(I686_AT_EUID, (uint32_t)geteuid());
    I686_PUSH_AUX(I686_AT_GID, (uint32_t)getgid());
    I686_PUSH_AUX(I686_AT_EGID, (uint32_t)getegid());
    I686_PUSH_AUX(I686_AT_SECURE, 0U);
    I686_PUSH_AUX(I686_AT_RANDOM, args->at_random_va);
    I686_PUSH_AUX(I686_AT_HWCAP, I686_HWCAP_I386);
    I686_PUSH_AUX(I686_AT_CLKTCK, 100U);
    I686_PUSH_AUX(I686_AT_PLATFORM, args->at_platform_va);
    if (args->vsyscall_addr != 0U) {
        I686_PUSH_AUX(I686_AT_SYSINFO, args->vsyscall_addr);
    }
    if (args->vdso_base != 0U) {
        I686_PUSH_AUX(I686_AT_SYSINFO_EHDR, args->vdso_base);
    }
    I686_PUSH_AUX(I686_AT_EXECFN, args->at_execfn_va);
    I686_PUSH_AUX(I686_AT_NULL, 0U);
#undef I686_PUSH_AUX
    return n;
}

/* ---- synthesized /proc content ----------------------------------------- */

/* a32rt-style anonymous file: memfd on Linux, unlinked temp file as the
 * portable fallback (the unit check runs on a non-Linux host).  Returns
 * an fd positioned at 0 or a negative -errno. */
static int create_anon_file(const char *name, const void *data, size_t len)
{
    int fd = -1;
#if defined(__linux__)
    fd = (int)syscall(SYS_memfd_create, name, MFD_CLOEXEC);
#else
    (void)name;
#endif
    if (fd < 0) {
        char tmpl[] = "/tmp/i686rt_proc_XXXXXX";
        fd = mkstemp(tmpl);
        if (fd < 0) {
            return -errno;
        }
        (void)unlink(tmpl);
    }
    if (data != NULL && len > 0U) {
        const uint8_t *p = (const uint8_t *)data;
        size_t off = 0U;
        while (off < len) {
            ssize_t w = write(fd, p + off, len - off);
            if (w < 0) {
                if (errno == EINTR) {
                    continue;
                }
                close(fd);
                return -errno;
            }
            off += (size_t)w;
        }
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            close(fd);
            return -errno;
        }
    }
    return fd;
}

size_t i686_proc_render_maps(const i686_ctx_t *ctx, char *buf, size_t cap)
{
    extern void rt32_vm_sync_ctx_if_stale(i686_ctx_t *);
    if (buf == NULL || cap == 0U) {
        return 0U;
    }
    buf[0] = '\0';
    if (ctx == NULL) {
        return 0U;
    }
    rt32_vm_sync_ctx_if_stale((i686_ctx_t *)(uintptr_t)ctx);
    size_t off = 0U;
    for (size_t i = 0U; i < ctx->region_count; i++) {
        const i686_region_t *r = &ctx->regions[i];
        if (r->end <= r->start) {
            continue;
        }
        char line[160];
        char prot_r = (r->prot & PROT_READ) ? 'r' : '-';
        char prot_w = (r->prot & PROT_WRITE) ? 'w' : '-';
        char prot_x = (r->prot & PROT_EXEC) ? 'x' : '-';
        char prot_s = (r->flags & 0x01U) ? 's' : 'p';
        const char *pad =
            (r->name[0] != '\0' && r->name[0] != '[') ? "         " : " ";
        int n = snprintf(line, sizeof(line),
                         "%08x-%08x %c%c%c%c 00000000 00:00 0 %s%s\n",
                         (unsigned)r->start, (unsigned)r->end, prot_r, prot_w,
                         prot_x, prot_s, pad, r->name);
        if (n < 0 || (size_t)n >= sizeof(line)) {
            continue; /* cannot happen for a <= 73-byte expansion */
        }
        if (off + (size_t)n + 1U > cap) {
            break; /* keep the buffer NUL-terminated, drop the rest */
        }
        memcpy(buf + off, line, (size_t)n);
        off += (size_t)n;
        buf[off] = '\0';
    }
    return off;
}

size_t i686_proc_render_cmdline(const i686_ctx_t *ctx, char *buf, size_t cap)
{
    if (buf == NULL || cap == 0U) {
        return 0U;
    }
    buf[0] = '\0';
    if (ctx == NULL || ctx->guest_argv == NULL) {
        return 0U;
    }
    size_t off = 0U;
    for (int i = 0; i < ctx->guest_argc; i++) {
        const char *arg = ctx->guest_argv[i];
        if (arg == NULL) {
            continue;
        }
        size_t len = strlen(arg) + 1U; /* kernel layout: NUL after each arg */
        if (off + len + 1U > cap) {
            break; /* room for the content plus one terminator */
        }
        memcpy(buf + off, arg, len);
        off += len;
        buf[off] = '\0';
    }
    return off;
}

const char *i686_proc_version_str(void)
{
    /* Release "6.1.0" matches sys_uname's utsname.release (syscalls.c). */
    return "Linux version 6.1.0 (i686rt) (i686rt synthetic kernel) #1 SMP\n";
}

const char *i686_proc_cpuinfo_str(void)
{
    return "processor\t: 0\n"
           "vendor_id\t: GenuineIntel\n"
           "cpu family\t: 6\n"
           "model\t\t: 1\n"
           "model name\t: i686rt virtual CPU\n"
           "stepping\t: 1\n"
           "cpu MHz\t\t: 1000.000\n"
           "cache size\t: 0 KB\n"
           "flags\t\t: " I686_CPUID_FLAGS_STR "\n"
           "clflush size\t: 64\n"
           "cache_alignment\t: 64\n"
           "address sizes\t: 32 bits physical, 32 bits virtual\n"
           "\n";
}

/* ---- open-time redirect (a32rt try_open_virtual_proc pattern) --------- */

/* Path must be absolute and name /proc; returns the leaf after "/proc/"
 * with extra slashes skipped, or NULL when the path is not under /proc. */
static const char *skip_proc_prefix(const char *path)
{
    if (path == NULL || path[0] != '/') {
        return NULL;
    }
    const char *p = path;
    while (*p == '/') {
        p++;
    }
    if (strncmp(p, "proc/", 5) != 0) {
        return NULL;
    }
    p += 5;
    while (*p == '/') {
        p++;
    }
    return p;
}

/* I686-R12-5: canonicalize the leaf after "/proc/" before matching:
 * collapse duplicate '/' runs, drop "/./" segments, strip trailing '/'.
 * Non-canonical spellings such as "/proc/self//maps" or
 * "/proc/./self/maps" must hit the synthetic handler instead of leaking
 * the host file.  Returns 0 with the NUL-terminated form in out, or -1
 * when the leaf does not fit (then it cannot be a virtual path). */
static int canon_proc_leaf(const char *leaf, char *out, size_t cap)
{
    size_t o = 0U;
    int first = 1;
    const char *p = leaf;

    if (cap == 0U) {
        return -1;
    }
    while (*p != '\0') {
        const char *q;
        size_t len;

        while (*p == '/') {
            p++;
        }
        if (*p == '\0') {
            break;
        }
        q = p;
        while (*q != '\0' && *q != '/') {
            q++;
        }
        len = (size_t)(q - p);
        if (len == 1U && p[0] == '.') {
            p = q;
            continue;
        }
        if ((!first && o + 1U >= cap) || o + len >= cap) {
            return -1;
        }
        if (!first) {
            out[o++] = '/';
        }
        memcpy(out + o, p, len);
        o += len;
        first = 0;
        p = q;
    }
    out[o] = '\0';
    return 0;
}

int i686_proc_open_at(i686_ctx_t *ctx, const char *guest_path)
{
    const char *leaf = skip_proc_prefix(guest_path);
    char canon[64];
    if (leaf == NULL) {
        return I686_PROC_NOT_MATCHED;
    }
    if (canon_proc_leaf(leaf, canon, sizeof(canon)) != 0) {
        return I686_PROC_NOT_MATCHED;
    }
    if (strcmp(canon, "cpuinfo") == 0) {
        const char *s = i686_proc_cpuinfo_str();
        return create_anon_file("proc_cpuinfo", s, strlen(s));
    }
    if (strcmp(canon, "version") == 0) {
        const char *s = i686_proc_version_str();
        return create_anon_file("proc_version", s, strlen(s));
    }
    if (strcmp(canon, "self/maps") == 0) {
        char buf[16384];
        size_t n = i686_proc_render_maps(ctx, buf, sizeof(buf));
        return create_anon_file("proc_maps", buf, n);
    }
    if (strcmp(canon, "self/cmdline") == 0) {
        char buf[4096];
        size_t n = i686_proc_render_cmdline(ctx, buf, sizeof(buf));
        return create_anon_file("proc_cmdline", buf, n);
    }
    if (strcmp(canon, "self/auxv") == 0) {
        return create_anon_file("proc_auxv", ctx->auxv_data,
                                ctx->auxv_bytes);
    }
    if (strcmp(canon, "self/exe") == 0) {
        const char *ep = (ctx->exec_path != NULL && ctx->exec_path[0] != '\0')
                             ? ctx->exec_path
                             : ((ctx->guest_argv != NULL)
                                    ? ctx->guest_argv[0]
                                    : NULL);
        if (ep == NULL || ep[0] == '\0') {
            return -ENOENT;
        }
        {
            int fd = open(ep, O_RDONLY | O_CLOEXEC);
            return (fd >= 0) ? fd : -errno;
        }
    }
    return I686_PROC_NOT_MATCHED;
}
