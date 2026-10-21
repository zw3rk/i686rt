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
 * exit_group(252), brk(45), mmap2(192), set_thread_area(243), uname(122),
 * getpid(20).  Phase 2 L2f adds fork(2)/vfork(190)/wait4(114)/waitpid(7)
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

/* Guest memory is little-endian x86; decode exactly rather than casting. */
static uint32_t guest_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

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
    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    return host_ret(read((int)fd, i686_guest_ptr(ctx, buf_va), (size_t)count));
}

static long sys_write(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
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

    if (buf_va > UINT32_MAX - (I686_UTS_TOTAL - 1U)) {
        return -EFAULT; /* struct would wrap the 32-bit guest space */
    }
    uint8_t *buf = (uint8_t *)i686_guest_ptr(ctx, buf_va);
    for (size_t i = 0U; i < I686_UTS_FIELDS; i++) {
        uint8_t *field = buf + i * I686_UTS_FIELD;
        memset(field, 0, I686_UTS_FIELD);
        for (size_t j = 0U; uts_fields[i][j] != '\0' && j < I686_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)uts_fields[i][j];
        }
    }
    return 0;
}

/*
 * set_thread_area(243): install a GDT TLS descriptor for the flat-model
 * v1 runtime.  The guest hands us a 16-byte struct user_desc (u32
 * entry_number, u32 base_addr, u32 limit, u32 flags); entry_number == -1
 * asks for the lowest free TLS entry, which is handed back through the
 * same guest field.  Bookkeeping is single-thread-minimal:
 * ctx->gdt_tls_slots[i] holds the installed base of GDT entry 6+i and 0
 * means free (a legitimate base of exactly 0 would be re-allocatable —
 * fine for one thread; revisit together with clone()).
 */
static long sys_set_thread_area(i686_ctx_t *ctx, uint32_t ud_va)
{
    if (ud_va > UINT32_MAX - 15U) {
        return -EFAULT; /* user_desc would wrap the 32-bit guest space */
    }
    uint8_t *ud    = (uint8_t *)i686_guest_ptr(ctx, ud_va);
    uint32_t entry = guest_le32(ud);
    uint32_t base  = guest_le32(ud + 4U);

    uint32_t slot;
    if (entry == 0xFFFFFFFFU) {
        slot = I686_TLS_SLOTS;
        for (uint32_t i = 0U; i < I686_TLS_SLOTS; i++) {
            if (ctx->gdt_tls_slots[i] == 0U) {
                slot = i;
                break;
            }
        }
        if (slot == I686_TLS_SLOTS) {
            return -ESRCH; /* all three TLS entries are in use */
        }
    } else {
        if (entry < I686_GDT_ENTRY_TLS_MIN ||
            entry >= I686_GDT_ENTRY_TLS_MIN + I686_TLS_SLOTS) {
            return -EINVAL;
        }
        slot = entry - I686_GDT_ENTRY_TLS_MIN;
    }

    ctx->gdt_tls_slots[slot]   = base;
    ctx->seg_base[I686_SEG_GS] = base;
    ctx->seg_sel[I686_SEG_GS]  = I686_TLS_SELECTOR(I686_GDT_ENTRY_TLS_MIN + slot);
    guest_store_le32(ud, I686_GDT_ENTRY_TLS_MIN + slot);
    return 0;
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
     * guest exit status rides back in EAX and our return value. */
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
}

static int64_t r_execve(i686_ctx_t *ctx)
{
    char path[4096];
    char **argv;
    char **envp;
    size_t argc = 0U;
    size_t envc = 0U;
    rt32_elf_info_t info;
    uint32_t sp = 0U;
    int fd;

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

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        free_strv(argv);
        free_strv(envp);
        return -errno;
    }
    guest_regions_teardown(ctx);
    if (rt32_elf_load(ctx, fd, path, &info) != 0) {
        (void)close(fd);
        free_strv(argv);
        free_strv(envp);
        return -ENOEXEC;
    }
    (void)close(fd);

    ctx->exec_path = path; /* fresh auxv AT_EXECFN source */
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
    ctx->eip = info.entry;
    ctx->eflags = 0x202U;
    ctx->lazy_op = I686_FOP_NONE;
    ctx->seg_sel[I686_SEG_CS] = 0x23U;
    ctx->seg_sel[I686_SEG_DS] = 0x2bU;
    ctx->seg_sel[I686_SEG_ES] = 0x2bU;
    ctx->seg_sel[I686_SEG_SS] = 0x2bU;
    ctx->seg_sel[I686_SEG_FS] = 0U;
    ctx->seg_sel[I686_SEG_GS] = 0U;
    memset(ctx->seg_base, 0, sizeof(ctx->seg_base));
    return 0;
}

long i686_handle_syscall(i686_ctx_t *ctx)
{
    long nr = (long)(int32_t)ctx->gpr[I686_REG_EAX];
    long ret;

    ctx->syscalls_executed++;

    i686_syscalls_init_once();
    ret = (long)i686_sys_dispatch(ctx, nr);
    ctx->gpr[I686_REG_EAX] = (uint32_t)ret;
    return ret;
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
}
