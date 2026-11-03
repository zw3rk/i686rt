/*
 * src/os/syscalls.c — minimal i386 (int 0x80) syscall layer (Phase 1, L1f)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * i386 syscall ABI (SPEC §3.4): the syscall number travels in EAX and the
 * six arguments in EBX, ECX, EDX, ESI, EDI, EBP (in that order).  The
 * result goes back to EAX: success values and guest addresses as unsigned
 * 32-bit patterns, errors as negative errno (-38 = -ENOSYS), i.e. the
 * kernel's -4095..-1 window that guest libcs probe with IS_ERR_VALUE().
 *
 * Implemented in Phase 1 (smoke set): read(3), write(4), exit(1),
 * exit_group(252), brk(45), mmap2(192), uname(122), getpid(20);
 * set_thread_area(243) delegates to src/os/ldt.c (RC7b T4c).  Phase 2
 * L2f adds fork(2)/vfork(190)/wait4(114)/waitpid(7)
 * (rusage converted to the kernel i386 layout); the layout-neutral set
 * lives in src/os/sys_pass.c.  Every other number returns -ENOSYS in EAX.
 *
 * Exit contract (for the engine loop in src/interp/interp.c): exit(1) and
 * exit_group(252) never return to the guest.  The loop checks
 * i686_syscall_is_exit(nr) — nr taken from EAX before dispatch (or from
 * ctx->exit_arg where the dispatcher parks the syscall number) — and
 * treats the dispatch as terminal instead of resuming at EIP.  The guest
 * exit status (first argument, EBX) is returned from i686_handle_syscall
 * and mirrored into EAX, so the loop can propagate it to the host exit
 * status.  i686_syscall_name(nr) is provided for tracing/diagnostics.
 */

#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "i686rt.h"
#include "os/syscalls_i386.h"
#include "os/marshal.h"
#include "os/threads.h"
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>

#include "rt32/rt32.h"

/* i386 GDT TLS entries GDT_ENTRY_TLS_MIN..+2 (6..8); selectors with RPL 3,
 * so entry 6 -> selector 0x33, entry 7 -> 0x3b, entry 8 -> 0x43. */
#define I686_GDT_ENTRY_TLS_MIN 6U
#define I686_TLS_SLOTS         3U
#define I686_TLS_SELECTOR(entry) ((uint16_t)((((uint32_t)(entry)) << 3) | 3U))

/* struct utsname (i386): six NUL-padded fields of 65 bytes each. */
#define I686_UTS_FIELD  65U
#define I686_UTS_FIELDS 6U
#define I686_UTS_TOTAL  (I686_UTS_FIELD * I686_UTS_FIELDS)

/* Guest memory is little-endian x86; encode exactly rather than casting. */
static void guest_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

/* Host syscall result -> guest convention: negative errno, else the value.
 * Short (partial) read/write counts are genuine syscall results. */
static long host_ret(ssize_t n)
{
    return (n < 0) ? -(long)errno : (long)n;
}

/* Guest u32 result as the kernel would leave it in EAX: vm_mmap2 returns
 * addresses and (uint32_t)-errno in one u32; sign-extend so errors read as
 * negative errno here, and the EAX truncation at the bottom of
 * i686_handle_syscall restores the exact 32-bit pattern either way. */
static long ret_guest_u32(uint32_t v)
{
    return (long)(int32_t)v;
}

static long sys_read(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    extern int i686_subpage_range_ok(const i686_ctx_t *, uint32_t, uint64_t, uint8_t);
    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    if (count > 0U && ctx != NULL && ctx->vm_regime == I686_VM_REGIME_A2 &&
        ctx->vm_host_page > 4096U) {
        uint8_t sbuf[4096];
        uint8_t *tmp;
        ssize_t n;
        int rc;
        if (!i686_subpage_range_ok(ctx, buf_va, count, 0x02u)) {
            return -EFAULT;
        }
        tmp = (count <= sizeof(sbuf)) ? sbuf : (uint8_t *)malloc(count);
        if (tmp == NULL) {
            return -ENOMEM;
        }
        n = read((int)fd, tmp, (size_t)count);
        if (n < 0) {
            long err = -(long)errno;
            if (tmp != sbuf) {
                free(tmp);
            }
            return err;
        }
        rc = (n > 0) ? i686_copy_to_guest(ctx, buf_va, tmp, (size_t)n) : 0;
        if (tmp != sbuf) {
            free(tmp);
        }
        return (rc != 0) ? (long)rc : (long)n;
    }
    return host_ret(read((int)fd, i686_guest_ptr(ctx, buf_va), (size_t)count));
}

static long sys_write(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    extern int i686_subpage_range_ok(const i686_ctx_t *, uint32_t, uint64_t, uint8_t);
    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    if (count > 0U && ctx != NULL && ctx->vm_regime == I686_VM_REGIME_A2 &&
        ctx->vm_host_page > 4096U) {
        uint8_t sbuf[4096];
        uint8_t *tmp;
        ssize_t n;
        int rc;
        if (!i686_subpage_range_ok(ctx, buf_va, count, 0x01u)) {
            return -EFAULT;
        }
        tmp = (count <= sizeof(sbuf)) ? sbuf : (uint8_t *)malloc(count);
        if (tmp == NULL) {
            return -ENOMEM;
        }
        rc = i686_copy_from_guest(ctx, tmp, buf_va, (size_t)count);
        if (rc != 0) {
            if (tmp != sbuf) {
                free(tmp);
            }
            return (long)rc;
        }
        n = write((int)fd, tmp, (size_t)count);
        if (n < 0) {
            long err = -(long)errno;
            if (tmp != sbuf) {
                free(tmp);
            }
            return err;
        }
        if (tmp != sbuf) {
            free(tmp);
        }
        return (long)n;
    }
    return host_ret(write((int)fd, i686_guest_ptr(ctx, buf_va), (size_t)count));
}

static long sys_brk(i686_ctx_t *ctx, uint32_t new_brk)
{
    /* rt32_vm_brk: new_brk == 0 reads out the current break; otherwise it
     * grows/shrinks the guest heap and returns the new break (the old one
     * when the request is invalid), matching Linux brk semantics. */
    return ret_guest_u32(rt32_vm_brk(ctx, new_brk));
}

static long sys_mmap2(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                      uint32_t flags, uint32_t fd, uint32_t pgoff)
{
    /* i386 mmap2(addr, len, prot, flags, fd, pgoff): fd in EDI, the page
     * offset (not bytes) in EBP; (int)fd keeps -1 anonymous maps. */
    uint32_t r = rt32_vm_mmap2(ctx, addr, len, prot, flags, (int)fd, pgoff);
    return ret_guest_u32(r);
}

static long sys_getpid(const i686_ctx_t *ctx)
{
    return (ctx->host_tid > 0) ? (long)ctx->host_tid : 1000L;
}

static long sys_uname(i686_ctx_t *ctx, uint32_t buf_va)
{
    static const char *const uts_fields[I686_UTS_FIELDS] = {
        "Linux", "i686rt", "6.1.0", "#1 SMP i686rt", "i686", "(none)",
    };

    /* Checked guest write (I686-R9-2): build locally, then copy so
     * unmapped/PROT_NONE/read-only destinations return -EFAULT instead
     * of host-faulting. Wrap is rejected by i686_copy_to_guest. */
    uint8_t ubuf[I686_UTS_TOTAL];
    for (size_t i = 0U; i < I686_UTS_FIELDS; i++) {
        uint8_t *field = ubuf + i * I686_UTS_FIELD;
        memset(field, 0, I686_UTS_FIELD);
        for (size_t j = 0U; uts_fields[i][j] != '\0' && j < I686_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)uts_fields[i][j];
        }
    }
    return i686_copy_to_guest(ctx, buf_va, ubuf, sizeof(ubuf));
}

/*
 * set_thread_area(243): DELEGATES to the kernel-faithful per-thread
 * implementation in src/os/ldt.c (i686_sys_set_thread_area: full desc
 * into ctx->tls_desc[slot], kernel tls_array semantics, RC7b triage-6).
 * The registration of 243 by either init path (the v1 list here, or the
 * lazy i686_syscalls_ldt_init from h_seg.c) therefore cannot choose the
 * implementation — both resolve to the same handler (RC7b T4c).
 */
static long sys_set_thread_area(i686_ctx_t *ctx, uint32_t ud_va)
{
    if (ud_va > UINT32_MAX - 15U) {
        return -EFAULT; /* user_desc would wrap the 32-bit guest space */
    }
    {
        extern long i686_sys_set_thread_area(i686_ctx_t *ctx, uint32_t ua);

        return i686_sys_set_thread_area(ctx, ud_va);
    }
}

/* Cross-module by-nr re-entry (clone.c uses fork). */
int64_t i686_sys_call_nr(long nr, i686_ctx_t *ctx)
{
    i686_syscalls_init_once();
    return i686_sys_dispatch(ctx, nr);
}

int i686_syscall_is_exit(long nr)
{
    return (nr == (long)I686__NR_exit || nr == (long)I686__NR_exit_group) ? 1 : 0;
}

const char *i686_syscall_name(long nr)
{
    if (nr < 0L || nr >= (long)I686_NR_MAX) {
        return NULL;
    }
    return i686_sysent[(size_t)nr].name;
}

/* Registry adapters: i686_sys_fn handlers take only ctx; args come from
 * the i386 register block (EBX..EBP) exactly as the old switch did. */
static int64_t r_read(i686_ctx_t *ctx)
{
    return sys_read(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                    ctx->gpr[I686_REG_EDX]);
}

static int64_t r_write(i686_ctx_t *ctx)
{
    return sys_write(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

static int64_t r_exit(i686_ctx_t *ctx)
{
    /* Terminal: the engine loop stops via i686_syscall_is_exit(); the
     * guest exit status rides back in EAX and our return value.
     * C2/C10: for a CLONED thread this syscall IS the thread's do_exit
     * — the kernel-shaped teardown (robust walk, cleartid clear + wake)
     * completes HERE, inside the dying thread's last syscall.  musl's
     * exit path wakes the joiner in guest code before SYS_enter, so any
     * teardown the thread performs after this syscall returns can write
     * into the stack range the woken joiner already munmapped and
     * re-mapped (the C2 rt32 stack-overlap defect).  The main thread's
     * SYS_exit stays a plain process exit. */
    if (!i686_thread_is_main(ctx)) {
        i686_thread_exit_teardown(ctx);
    }
    return (int64_t)(int32_t)ctx->gpr[I686_REG_EBX];
}

static int64_t r_brk(i686_ctx_t *ctx)
{
    return sys_brk(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_mmap2(i686_ctx_t *ctx)
{
    return sys_mmap2(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                     ctx->gpr[I686_REG_EDI], ctx->gpr[I686_REG_EBP]);
}

static int64_t r_set_thread_area(i686_ctx_t *ctx)
{
    return sys_set_thread_area(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_uname(i686_ctx_t *ctx)
{
    return sys_uname(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_getpid(i686_ctx_t *ctx)
{
    return sys_getpid(ctx);
}

/* Phase 2 L2f additions — process creation and reaping.  Numbers from
 * the generated table in os/syscalls_i386.h. */
#define NR_waitpid 7U /* [7]   {"waitpid"} */
#define NR_fork     2U /* [2]   {"fork"}    */
#define NR_wait4  114U /* [114] {"wait4"}   */
#define NR_vfork  190U /* [190] {"vfork"}   */

/* wait4(2) is a BSD extension hidden from strict _POSIX_C_SOURCE
 * builds; declare the (musl) prototype verbatim. */
pid_t wait4(pid_t, int *, int, struct rusage *);

/*
 * i686_rusage_to_guest (src/os/sys_pass.c): converts the host 64-bit
 * struct rusage into the 72-byte kernel i386 layout (2 x {u32 sec, u32
 * usec} + 14 x u32, arch/x86/include/uapi/asm/resource.h).  Declared
 * here rather than in frozen marshal.h; unit-tested via test_l2f.c.
 */
int i686_rusage_to_guest(i686_ctx_t *ctx, uint32_t ru_va, const struct rusage *ru);

/*
 * fork(2) and vfork(190) both map onto host fork().
 *
 * The whole guest state lives in the [G, G+4 GiB) window, which rt32
 * maps MAP_PRIVATE anonymous: the host fork's copy-on-write duplication
 * of that mapping IS fork semantics for the guest — parent and child
 * see identical guest memory, stack, and fd table, and diverge page by
 * page on write, exactly like a native i386 fork.  In the child the
 * syscall returns 0 (EAX), in the parent the child pid, and both simply
 * CONTINUE in the interpreter loop from the instruction after int 0x80:
 * no guest re-init, no re-exec, nothing is duplicated except memory.
 *
 * Double-cleanup is not an issue in v1: the runtime registers no host
 * atexit handlers and keeps no stdio buffers that the child could
 * flush again (trace output uses write(2)); the child eventually calls
 * exit/exit_group, which is terminal in the engine loop, so parent and
 * child never both run the host cleanup path — each exits exactly once.
 * Region teardown (/proc/self/maps bookkeeping) is likewise per-process
 * host memory, and the COW window means neither side corrupts the other.
 *
 * vfork(190) is served by the same host fork(): the kernel contract
 * (parent suspended until the child execs or exits) is relaxed in v1 —
 * the parent races ahead instead.  Guests that vfork precisely to
 * execve immediately still behave acceptably, and execve itself is the
 * coordinator's S2 work.  clone(120) stays -ENOSYS until Phase 4.
 */
static int64_t r_fork(i686_ctx_t *ctx)
{
    pid_t pid = fork();

    if (pid < 0) {
        return -errno;
    }
    if (pid == 0) {
        /* Child: a fresh host pid, reported by getpid(20) from now on. */
        ctx->host_tid = (int)getpid();
        return 0;
    }
    return (int64_t)pid;
}

static long sys_wait4(i686_ctx_t *ctx, int32_t pid, uint32_t status_va,
                      uint32_t options, uint32_t ru_va)
{
    int status = 0;
    struct rusage ru;
    struct rusage *rup = (ru_va != 0U) ? &ru : NULL;
    pid_t r = wait4((pid_t)pid, &status, (int)options, rup);

    if (r < 0) {
        return -errno;
    }
    if (status_va != 0U) {
        if (status_va < 0x1000U) {
            return -EFAULT; /* null-page guard, Phase 1 convention */
        }
        uint8_t le[4];
        guest_store_le32(le, (uint32_t)status);
        int rc = i686_copy_to_guest(ctx, status_va, le, sizeof le);
        if (rc != 0) {
            return rc;
        }
    }
    if (rup != NULL) {
        int rc = i686_rusage_to_guest(ctx, ru_va, rup);
        if (rc != 0) {
            return rc;
        }
    }
    return (long)r;
}

static int64_t r_wait4(i686_ctx_t *ctx)
{
    return sys_wait4(ctx, (int32_t)ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_waitpid(i686_ctx_t *ctx)
{
    /* waitpid(7): wait4 with no rusage pointer. */
    return sys_wait4(ctx, (int32_t)ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX], 0U);
}


/* ---- in-process execve (S2 coordinator design) ------------------------ */
/* Reload a new i386 image into the same process: marshal argv/envp, tear
 * down all guest regions except the vDSO, load the new ELF, build a fresh
 * i386 stack (auxv per E07), and restart guest execution at the new entry.
 * The interpreter loop simply continues; its next decode is at the new EIP.
 * This is what busybox's applet dispatch (execve("/proc/self/exe", ...))
 * rides on, with /proc/self/exe virtualized to ctx->exec_path. */
#define I686_EXEC_MAX_ARGS 4096U

static char **marshal_strv(i686_ctx_t *ctx, uint32_t va, size_t *out_n)
{
    char **v;
    size_t n = 0U;
    size_t i;
    uint32_t elem;

    *out_n = 0U;
    if (va == 0U) {
        v = malloc(sizeof(char *));
        if (v != NULL) {
            v[0] = NULL;
        }
        return v;
    }
    for (i = 0U; i < I686_EXEC_MAX_ARGS; i++) {
        if (i686_copy_from_guest(ctx, &elem, va + (uint32_t)(4U * i), 4U) != 0) {
            return NULL;
        }
        if (elem == 0U) {
            break;
        }
        n++;
    }
    if (n == I686_EXEC_MAX_ARGS) {
        return NULL; /* -E2BIG */
    }
    v = malloc(sizeof(char *) * (n + 1U));
    if (v == NULL) {
        return NULL;
    }
    for (i = 0U; i < n; i++) {
        char buf[4096];
        (void)i686_copy_from_guest(ctx, &elem, va + (uint32_t)(4U * i), 4U);
        if (i686_fetch_cstr(ctx, elem, buf, sizeof(buf)) != 0) {
            size_t j;
            for (j = 0U; j < i; j++) {
                free(v[j]);
            }
            free(v);
            return NULL;
        }
        v[i] = malloc(strlen(buf) + 1U);
        if (v[i] == NULL) {
            size_t j;
            for (j = 0U; j < i; j++) {
                free(v[j]);
            }
            free(v);
            return NULL;
        }
        memcpy(v[i], buf, strlen(buf) + 1U);
    }
    v[n] = NULL;
    *out_n = n;
    return v;
}

static void free_strv(char **v)
{
    size_t i;
    if (v == NULL) {
        return;
    }
    for (i = 0U; v[i] != NULL; i++) {
        free(v[i]);
    }
    free(v);
}

static void guest_regions_teardown(i686_ctx_t *ctx)
{
    rt32_vm_reset_for_exec(ctx);
    {
        /* Exec invalidates the translation cache too (RC7b T4b): fork
         * children inherit the parent's COW JIT blocks, and a new image
         * at the same EIPs must not run the previous image's code. */
#ifndef I686RT_NO_DBT
        extern void i686_dbt_flush_all(void);
        i686_dbt_flush_all();
#endif
    }
}

/* Kernel exec semantics (RC7b T4b): execve closes every fd >= 3 that
 * carries FD_CLOEXEC.  There is no host exec in the translator, so the
 * guest's execve must do it here — wineserver fork/spawn children
 * otherwise inherit the server's whole fd table (pipes, sockets, the
 * epoll), and request/reply routing deadlocks with both ends of a
 * request pipe resident in the wrong process. */
static void exec_close_cloexec_fds(void)
{
    DIR *d;
    struct dirent *de;

    d = opendir("/proc/self/fd");
    if (d == NULL) {
        return;
    }
    while ((de = readdir(d)) != NULL) {
        const char *n = de->d_name;
        int fd = 0;
        int fl;

        for (const char *p = n; *p != '\0'; p++) {
            if (*p < '0' || *p > '9') {
                fd = -1;
                break;
            }
            fd = fd * 10 + (*p - '0');
        }
        if (fd <= 2) {
            continue;
        }
        fl = fcntl(fd, F_GETFD);
        if (fl >= 0 && (fl & FD_CLOEXEC) != 0) {
            (void)close(fd);
        }
    }
    (void)closedir(d);
}

/* sysroot-aware execve open (RC7b): guest absolute paths resolve under
 * --sysroot first, then the plain path — same model as open_guest in
 * sys_pass.c.  The SCRIPT/ELF fd is read here; argv keeps the guest's
 * original path strings (the interpreter re-opens the script through
 * the normal sysroot-aware sys_open path). */
int i686_exec_open(const i686_ctx_t *ctx, const char *path)
{
    char buf[4096];

    if (path[0] == '/' && ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        size_t n = strlen(ctx->sysroot);
        size_t pl = strlen(path);
        if (n + pl < sizeof buf) {
            int fd;

            memcpy(buf, ctx->sysroot, n);
            memcpy(buf + n, path, pl + 1U);
            fd = open(buf, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                return fd;
            }
        }
    }
    return open(path, O_RDONLY | O_CLOEXEC);
}

/* binfmt_script reinterpretation (kernel semantics): `#! interp [arg]`
 * re-execs the interpreter with argv = {interp, [arg], script_path,
 * orig argv[1:]}, orig argv[0] dropped.  The optional argument is the
 * rest of the line after the interpreter token (trimmed).  Rewrites
 * *path_buf (interp) and returns the rebuilt argv (caller frees the
 * old array + argv[0]); NULL on malformed lines (-ENOEXEC territory).
 * script_path must be a heap copy: it is stored into the new argv. */
char **i686_exec_script_reinterp(const i686_ctx_t *ctx, char *path_buf,
                              size_t path_sz, char *script_path,
                              char **argv)
{
    char line[128];
    char interp[96];
    char sarg[24];
    char **na;
    size_t i, j = 0U, k, argc;
    int in = -1;
    ssize_t got;

    for (argc = 0U; argv[argc] != NULL; argc++) {
    }

    in = i686_exec_open(ctx, path_buf); /* peek at the first line only */
    if (in < 0) {
        return NULL;
    }
    got = read(in, line, sizeof line - 1U);
    close(in);
    if (got < 3 || line[0] != '#' || line[1] != '!') {
        errno = ENOEXEC;
        return NULL;
    }
    line[got] = '\0';
    { /* token 1: interpreter path */
        char *p = line + 2;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '\n') { errno = ENOEXEC; return NULL; }
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n' && j < sizeof interp - 1U)
            interp[j++] = *p++;
        interp[j] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        /* token 2 (optional): rest of line, trimmed */
        k = 0U;
        while (*p != '\0' && *p != '\n' && k < sizeof sarg - 1U)
            sarg[k++] = *p++;
        while (k > 0U && (sarg[k-1U] == ' ' || sarg[k-1U] == '\t')) k--;
        sarg[k] = '\0';
    }
    if (snprintf(path_buf, path_sz, "%s", interp) >= (int)path_sz) {
        errno = ENOEXEC;
        return NULL;
    }
    na = malloc(sizeof(char *) * (argc + 3U));
    if (na == NULL) {
        errno = ENOMEM;
        return NULL;
    }
    j = 0U;
    na[j] = malloc(strlen(interp) + 1U);
    if (na[j] == NULL) goto oom;
    memcpy(na[j++], interp, strlen(interp) + 1U);
    if (sarg[0] != '\0') {
        na[j] = malloc(strlen(sarg) + 1U);
        if (na[j] == NULL) goto oom1;
        memcpy(na[j++], sarg, strlen(sarg) + 1U);
    }
    na[j++] = script_path; /* takes ownership */
    for (i = 1U; i < argc; i++) {
        na[j++] = argv[i];
    }
    na[j] = NULL;
    return na;
oom1:
    free(na[0]);
oom:
    free(na);
    errno = ENOMEM;
    return NULL;
}

static int64_t r_execve(i686_ctx_t *ctx)
{
    char path[4096];
    char *path_copy;
    char **argv;
    char **envp;
    size_t argc = 0U;
    size_t envc = 0U;
    rt32_elf_info_t info;
    uint32_t sp = 0U;
    int fd;
    unsigned depth;

    /* I686-R10-2: reject while sibling threads are registered; with only
     * the caller present the registry is pruned to the caller. */
    {
        extern int i686_thread_exec_begin(i686_ctx_t *);
        int erc = i686_thread_exec_begin(ctx);
        if (erc != 0) {
            return (int64_t)erc;
        }
    }

    if (i686_fetch_cstr(ctx, ctx->gpr[I686_REG_EBX], path, sizeof(path)) != 0) {
        return -EFAULT;
    }
    argv = marshal_strv(ctx, ctx->gpr[I686_REG_ECX], &argc);
    if (argv == NULL) {
        return -E2BIG;
    }
    envp = marshal_strv(ctx, ctx->gpr[I686_REG_EDX], &envc);
    if (envp == NULL) {
        free_strv(argv);
        return -E2BIG;
    }

    /* binfmt_script: reinterpret `#!` lines before the ELF gate; the
     * kernel re-enters execve with the interpreter, so loop (bounded
     * like the kernel's recursion cap of 5). */
    for (depth = 0U; depth < 5U; depth++) {
        char *script_copy;
        char **na;

        fd = i686_exec_open(ctx, path);
        if (fd < 0) {
            int e = errno;

            free_strv(argv);
            free_strv(envp);
            return -e;
        }
        {
            char magic[2];

            if (read(fd, magic, 2) == 2 && magic[0] == '#' && magic[1] == '!') {
                (void)close(fd);
                script_copy = malloc(strlen(path) + 1U);
                if (script_copy == NULL) {
                    free_strv(argv);
                    free_strv(envp);
                    return -ENOMEM;
                }
                memcpy(script_copy, path, strlen(path) + 1U);
                na = i686_exec_script_reinterp(ctx, path, sizeof path, script_copy,
                                     argv);
                if (na == NULL) {
                    int e = errno;

                    free(script_copy);
                    free_strv(argv);
                    free_strv(envp);
                    return (e == ENOMEM || e == ENOEXEC) ? -e : -ENOEXEC;
                }
                free(argv[0]); /* script's own argv[0] is dropped */
                free(argv);    /* array only; argv[1:] moved to na */
                argv = na;
                argc += (na[1] == script_copy) ? 1U : 2U;
                continue;
            }
            (void)lseek(fd, 0, SEEK_SET);
        }
        break; /* ELF (or ENOEXEC below) */
    }
    if (depth == 5U) {
        free_strv(argv);
        free_strv(envp);
        return -ELOOP;
    }
    /* I686-R10-1: heap-duplicate the exec path — path[] is stack-local
     * and post-exec readers outlive this frame. */
    path_copy = strdup(path);
    if (path_copy == NULL) {
        free_strv(argv);
        free_strv(envp);
        return -ENOMEM;
    }
    guest_regions_teardown(ctx);
    if (rt32_elf_load(ctx, fd, path, &info) != 0) {
        (void)close(fd);
        free(path_copy);
        free_strv(argv);
        free_strv(envp);
        return -ENOEXEC;
    }
    (void)close(fd);
    /* Kernel exec semantics (RC7b T4b): the image is loaded and its fd
     * consumed — now close every CLOEXEC fd before the new program
     * starts (no host exec happens here, so nothing else does it). */
    exec_close_cloexec_fds();
    /* I686-R10-2: the new image starts with an empty futex table. */
    {
        extern void i686_vm32_futex_reset(void);
        i686_vm32_futex_reset();
    }

    ctx->exec_path = path_copy; /* heap copy: path[] dies here (R10-1) */
    if (rt32_stack_setup(ctx, &info, (int)argc, argv, envp, &sp) != 0) {
        free_strv(argv);
        free_strv(envp);
        return -ENOMEM;
    }
    /* Update the startup metadata AFTER stack setup consumed them. */
    ctx->guest_argc = (int)argc;
    ctx->guest_argv = argv;      /* ownership moves to ctx */
    ctx->host_envp = envp;
    /* argv[0] preserved verbatim (busybox applet dispatch). */

    memset(ctx->gpr, 0, sizeof(ctx->gpr));
    ctx->gpr[I686_REG_ESP] = sp;
    ctx->eip = ctx->elf_entry; /* rt32_elf_load sets the interpreter
                                * entry when PT_INTERP (launch parity) */
    ctx->eflags = 0x202U;
    ctx->lazy_op = I686_FOP_NONE;
    ctx->seg_sel[I686_SEG_CS] = 0x23U;
    ctx->seg_sel[I686_SEG_DS] = 0x2bU;
    ctx->seg_sel[I686_SEG_ES] = 0x2bU;
    ctx->seg_sel[I686_SEG_SS] = 0x2bU;
    ctx->seg_sel[I686_SEG_FS] = 0U;
    ctx->seg_sel[I686_SEG_GS] = 0U;
    memset(ctx->seg_base, 0, sizeof(ctx->seg_base));
    ctx->cs_d = 1U; /* exec reloads flat segment regs; the LDT itself
                     * persists (per-mm on i386), segment state resets */
    ctx->ss_b = 1U; /* R7-11: flat stack is 32-bit */
    {
        extern void i686_seg_exec_reset_tls(i686_ctx_t *ctx);
        i686_seg_exec_reset_tls(ctx);
    }
    {
        extern void i686_gsig_exec_reset(void);
        i686_gsig_exec_reset();
    }
    ctx->altstack_sp = 0U;
    ctx->altstack_size = 0U;
    ctx->altstack_flags = 0x2U;
    ctx->altstack_onstack = 0U;
    ctx->sig_last_frame_va = 0U;
    ctx->sig_last_frame_rt = 0U;
    return 0;
}

long i686_handle_syscall(i686_ctx_t *ctx)
{
    long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
    long ret;
    static int s_systrace = -1;

    if (s_systrace < 0) {
        s_systrace = getenv("I686RT_SYSTRACE") != NULL;
    }

    ctx->syscalls_executed++;

    i686_syscalls_init_once();
    ret = (long)i686_sys_dispatch(ctx, nr);
    if (s_systrace) {
        (void)fprintf(stderr,
                      "SYS %ld %ld -> %ld (bx=%08x cx=%08x dx=%08x si=%08x)\n",
                      (long)getpid(), nr, ret, ctx->gpr[I686_REG_EBX],
                      ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                      ctx->gpr[I686_REG_ESI]);
    }
    /* R7-20: a successful sigreturn (119/173) restores EAX from the
     * sigcontext (like the kernel) — storing the handler's return code
     * would clobber it.  Only failed restores (-EFAULT) set EAX. */
    if (!(((long)I686__NR_sigreturn == nr || (long)I686__NR_rt_sigreturn == nr) &&
          ret == 0L)) {
        ctx->gpr[I686_REG_EAX] = (uint32_t)ret;
    }
    return ret;
}

int i686_systrace_on(void)
{
    return getenv("I686RT_SYSTRACE") != NULL;
}

void i686_syscalls_init_once(void)
{
    static int s_done;
    if (s_done) {
        return;
    }
    s_done = 1;
    i686_sys_register(I686__NR_read, r_read);
    i686_sys_register(I686__NR_write, r_write);
    i686_sys_register(I686__NR_exit, r_exit);
    i686_sys_register(I686__NR_exit_group, r_exit);
    i686_sys_register(I686__NR_brk, r_brk);
    i686_sys_register(I686__NR_mmap2, r_mmap2);
    i686_sys_register(I686__NR_set_thread_area, r_set_thread_area);
    i686_sys_register(I686__NR_uname, r_uname);
    i686_sys_register(I686__NR_getpid, r_getpid);
    i686_sys_register(I686__NR_execve, r_execve);
    {
        extern int64_t i686_sys_sigreturn(i686_ctx_t *);
        extern int64_t i686_sys_rt_sigreturn(i686_ctx_t *);
        i686_sys_register(I686__NR_sigreturn, i686_sys_sigreturn);
        i686_sys_register(I686__NR_rt_sigreturn, i686_sys_rt_sigreturn);
    }
    i686_sys_register(NR_fork, r_fork);
    i686_sys_register(NR_vfork, r_fork);
    i686_sys_register(NR_wait4, r_wait4);
    i686_sys_register(NR_waitpid, r_waitpid);
    i686_syscalls_stat_init();
    i686_syscalls_sock_init();
    i686_syscalls_ipc_init();
    i686_syscalls_time_init();
    i686_syscalls_misc_init();
    i686_syscalls_pass_init();
    i686_syscalls_thread_init(); /* tkill/tgkill/sched/robust-list class
                                  * (src/os/sys_thread.c, C1b seam) */
    /* Phase 7/8 module registrations run LAST: registration is
     * last-wins, and ldt.c's full set_thread_area(243) supersedes the
     * flat-model v1 stub registered above (S7 wiring). */
    {
        extern void i686_syscalls_ldt_init(void);   /* 123, 243, 244 */
        extern void i686_sys_vm86_init(void);       /* 113, 166 */
        i686_syscalls_ldt_init();
        i686_sys_vm86_init();
    }
}
