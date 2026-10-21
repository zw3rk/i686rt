/*
 * src/os/sys_pass.c — process syscalls + layout-neutral passthroughs (L2f)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 lane L2f, part 1: the layout-neutral i386 syscall set (SPEC §3.4
 * marshalling rules, lane card docs/lanes/phase-2.md "L2f process +
 * passthrough + registry").  Everything that reaches the host carries a
 * byte-layout argument in a comment; where i386 and the aarch64 host agree,
 * the values were verified against the kernel uapi headers and (empirically)
 * against musl userspace headers on both sides:
 *
 * O_ flags for open(5) — the i386 and aarch64 values DIFFER for four bits
 * (kernel citations):
 *   i386 (arch/x86 has no own fcntl.h; include/uapi/asm-generic/fcntl.h):
 *     O_CREAT=0100(0x40)   O_EXCL=0200(0x80)      O_NOCTTY=0400(0x100)
 *     O_TRUNC=01000(0x200) O_APPEND=02000(0x400)  O_NONBLOCK=04000(0x800)
 *     O_DSYNC=010000(0x1000) FASYNC=020000(0x2000) O_DIRECT=040000(0x4000)
 *     O_LARGEFILE=0100000(0x8000) O_DIRECTORY=0200000(0x10000)
 *     O_NOFOLLOW=0400000(0x20000)  O_NOATIME=01000000(0x40000)
 *     O_CLOEXEC=02000000(0x80000)  __O_SYNC=04000000(0x100000)
 *     O_SYNC=04010000(0x101000)    O_PATH=010000000(0x200000)
 *     __O_TMPFILE=020000000(0x400000)
 *     (verified empirically: linux/386 alpine musl O_DIRECTORY=0200000,
 *      O_DIRECT=040000, O_LARGEFILE=0100000, O_NOFOLLOW=0400000)
 *   aarch64 host (arch/arm64/include/uapi/asm/fcntl.h — ARM32-derived,
 *     overriding asm-generic for exactly these four):
 *     O_DIRECTORY=(1<<14)=0x4000  O_NOFOLLOW=(1<<15)=0x8000
 *     O_DIRECT=(1<<16)=0x10000    O_LARGEFILE=(1<<17)=0x20000
 *     (verified empirically: linux/arm64 alpine musl O_DIRECTORY=040000
 *      and open("/", O_DIRECTORY) succeeds with that value)
 *   Every other bit (incl. accmode 0..3 and O_SYNC=0x101000) is numerically
 *   identical on both.  The translation table below hard-codes BOTH sides
 *   as literals: the host <fcntl.h> macros are deliberately unused because
 *   the unit test compiles this file on macOS where they differ again.
 *
 * L2e owns the fcntl/fcntl64 flag translation; this file translates flags
 * for open(5)/dup3(330) only (dup3 flags: O_CLOEXEC=0x80000 identical).
 *
 * termios ioctls (verified: request numbers and kernel struct layouts are
 * identical on i386 and aarch64 — x86 ioctls.h/termbits.h match
 * asm-generic/ioctls.h/termbits.h, which arm64 uses):
 *   TCGETS/TCSETS/TCSETSW/TCSETSF (0x5401..0x5404): kernel struct termios
 *   = 4 x u32 (c_iflag..c_lflag) + u8 c_line + u8 c_cc[19] = 36 bytes
 *   (NCCS=19; speeds live in termios2/TCGETS2, not here).
 *   TCGETA/TCSETA/TCSETAW/TCSETAF (0x5405..0x5408): struct termio =
 *   4 x u16 + u8 c_line + u8 c_cc[8] = 17 bytes.
 *   TIOCGWINSZ/TIOCSWINSZ (0x5413/0x5414): struct winsize = 4 x u16 = 8 B.
 *   FIONREAD (0x541B): int out, 4 B.
 *   No-pointer requests are passed through with the integer argument.
 *   Everything else returns -ENOTTY (Phase 2 whitelist; Phase H may widen).
 *
 * rusage: kernel i386 struct rusage = 2 x __kernel_old_timeval (8 B each:
 * u32 tv_sec + u32 tv_usec) + 14 x 32-bit long = 72 bytes total
 * (arch/x86/include/uapi/asm/resource.h; the host's 64-bit struct rusage
 * is converted field-by-field in i686_rusage_to_guest).
 *
 * Signal syscalls (rt_sigaction/rt_sigprocmask/rt_sigpending/sigaltstack)
 * are STORE-ONLY v1: busybox sh calls them at startup and must not see
 * -ENOSYS, but no signal is ever delivered until Phase 4.  The blocked
 * mask lives in ctx->sig_mask (the ABI-locked field); the 64-entry
 * handler table and the prctl comm name are file-static and move into
 * per-thread state in Phase 4.  kill(37)/tkill/tgkill and capget/capset
 * are deliberately NOT registered: dispatch returns -ENOSYS for them
 * (Phase 4), and execve(11)/execveat(358) stay -ENOSYS for the
 * coordinator's in-process exec at S2.
 *
 * futex(240) v1 single-threaded stopgap (Phase 4 brings real futexes):
 *   FUTEX_WAKE -> 0, FUTEX_WAIT -> -EAGAIN when *uaddr != val else 0
 *   (never blocks), other ops -> -ENOSYS.
 */

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h> /* rename(3) lives in ISO stdio */
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "os/marshal.h"
#include "os/proc.h"
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "i686rt.h"
#include "marshal.h"
#include "rt32/rt32.h"

/* Syscall numbers, values from the authoritative generated table in
 * src/os/syscalls_i386.h (quoted as [nr] {"name"}). */
#define NR_unlink        10U /* [10]  {"unlink"}       */
#define NR_open           5U /* [5]   {"open"}         */
#define NR_writev         146U /* [146] {"writev"}       */
#define NR_close          6U /* [6]   {"close"}        */
#define NR_lseek         19U /* [19]  {"lseek"}        */
#define NR_link           9U /* [9]   {"link"}         */
#define NR_mkdir         39U /* [39]  {"mkdir"}        */
#define NR_rmdir         40U /* [40]  {"rmdir"}        */
#define NR_rename       38U /* [38]  {"rename"}       */
#define NR_symlink      83U /* [83]  {"symlink"}      */
#define NR_chmod        15U /* [15]  {"chmod"}        */
#define NR_fchmod       94U /* [94]  {"fchmod"}       */
#define NR_lchown       16U /* [16]  {"lchown"}       */
#define NR_chown       182U /* [182] {"chown"}        */
#define NR_fchown       95U /* [95]  {"fchown"}       */
#define NR_lchown32    198U /* [198] {"lchown32"}     */
#define NR_chown32     212U /* [212] {"chown32"}      */
#define NR_fchown32    207U /* [207] {"fchown32"}     */
#define NR_fchmodat    306U /* [306] {"fchmodat"}     */
#define NR_fchownat    298U /* [298] {"fchownat"}     */
#define NR_access       33U /* [33]  {"access"}       */
#define NR_faccessat   307U /* [307] {"faccessat"}    */
#define NR_chdir        12U /* [12]  {"chdir"}        */
#define NR_fchdir      133U /* [133] {"fchdir"}       */
#define NR_getcwd      183U /* [183] {"getcwd"}       */
#define NR_getppid      64U /* [64]  {"getppid"}      */
#define NR_getuid       24U /* [24]  {"getuid"}       */
#define NR_getuid32    199U /* [199] {"getuid32"}     */
#define NR_getgid       47U /* [47]  {"getgid"}       */
#define NR_getgid32    200U /* [200] {"getgid32"}     */
#define NR_geteuid      49U /* [49]  {"geteuid"}      */
#define NR_geteuid32   201U /* [201] {"geteuid32"}    */
#define NR_getegid      50U /* [50]  {"getegid"}      */
#define NR_getegid32   202U /* [202] {"getegid32"}    */
#define NR_setuid       23U /* [23]  {"setuid"}       */
#define NR_setuid32    213U /* [213] {"setuid32"}     */
#define NR_setgid       46U /* [46]  {"setgid"}       */
#define NR_setgid32    214U /* [214] {"setgid32"}     */
#define NR_getgroups    80U /* [80]  {"getgroups"}    */
#define NR_setgroups    81U /* [81]  {"setgroups"}    */
#define NR_getgroups32 205U /* [205] {"getgroups32"}  */
#define NR_setgroups32 206U /* [206] {"setgroups32"}  */
#define NR_umask        60U /* [60]  {"umask"}        */
#define NR_dup          41U /* [41]  {"dup"}          */
#define NR_dup2         63U /* [63]  {"dup2"}         */
#define NR_dup3        330U /* [330] {"dup3"}         */
#define NR_ioctl        54U /* [54]  {"ioctl"}        */
#define NR_munmap       91U /* [91]  {"munmap"}       */
#define NR_mprotect    125U /* [125] {"mprotect"}     */
#define NR_mremap      163U /* [163] {"mremap"}       */
#define NR_personality 136U /* [136] {"personality"}  */
#define NR_prctl       172U /* [172] {"prctl"}        */
#define NR_rt_sigaction  174U /* [174] {"rt_sigaction"}  */
#define NR_rt_sigprocmask 175U /* [175] {"rt_sigprocmask"} */
#define NR_rt_sigpending  176U /* [176] {"rt_sigpending"}  */
#define NR_sigaltstack 186U /* [186] {"sigaltstack"}  */
#define NR_set_tid_address 258U /* [258] {"set_tid_address"} */
#define NR_futex       240U /* [240] {"futex"}        */

/* Guest i386 O_ bits (kernel asm-generic values; see file header). */
#define I686_O_ACCMODE   0x0000003u
#define I686_O_CREAT     0100
#define I686_O_EXCL      0200
#define I686_O_NOCTTY    0400
#define I686_O_TRUNC     01000
#define I686_O_APPEND    02000
#define I686_O_NONBLOCK  04000
#define I686_O_DSYNC     010000
#define I686_O_FASYNC    020000
#define I686_O_DIRECT    040000
#define I686_O_LARGEFILE 0100000
#define I686_O_DIRECTORY 0200000
#define I686_O_NOFOLLOW  0400000
#define I686_O_NOATIME   01000000
#define I686_O_CLOEXEC   02000000
#define I686_O__SYNC     04000000 /* __O_SYNC, the non-O_DSYNC half */
#define I686_O_PATH      010000000
#define I686_O__TMPFILE  020000000

/* Host (aarch64 Linux kernel) equivalents, ARM32-derived where they
 * differ; literals so the macOS-built unit test sees the same numbers. */
#define HOST_O_CREAT     0x40u
#define HOST_O_EXCL      0x80u
#define HOST_O_NOCTTY    0x100u
#define HOST_O_TRUNC     0x200u
#define HOST_O_APPEND    0x400u
#define HOST_O_NONBLOCK  0x800u
#define HOST_O_DSYNC     0x1000u
#define HOST_O_FASYNC    0x2000u
#define HOST_O_DIRECT    0x10000u  /* (1<<16) arm64 uapi fcntl.h  */
#define HOST_O_DIRECTORY 0x4000u   /* (1<<14) arm64 uapi fcntl.h  */
#define HOST_O_NOFOLLOW  0x8000u   /* (1<<15) arm64 uapi fcntl.h  */
#define HOST_O_NOATIME   0x40000u
#define HOST_O_CLOEXEC   0x80000u
#define HOST_O__SYNC     0x100000u /* arm64 O_SYNC 04010000 = 0x101000 */
#define HOST_O_PATH      0x200000u
#define HOST_O__TMPFILE  0x400000u /* arm64 O_TMPFILE 020040000 sans
                                    * its O_DIRECTORY part */

/* ioctl request numbers (identical i386/aarch64; see file header). */
#define REQ_TCGETS     0x5401u
#define REQ_TCSETS     0x5402u
#define REQ_TCSETSW    0x5403u
#define REQ_TCSETSF    0x5404u
#define REQ_TCGETA     0x5405u
#define REQ_TCSETA     0x5406u
#define REQ_TCSETAW    0x5407u
#define REQ_TCSETAF    0x5408u
#define REQ_TCSBRK     0x5409u
#define REQ_TCXONC     0x540Au
#define REQ_TCFLSH     0x540Bu
#define REQ_TIOCEXCL   0x540Cu
#define REQ_TIOCNXCL   0x540Du
#define REQ_TIOCNOTTY  0x5422u
#define REQ_TCSBRKP    0x5425u
#define REQ_TIOCSBRK   0x5427u
#define REQ_TIOCCBRK   0x5428u
#define REQ_TIOCGWINSZ 0x5413u
#define REQ_TIOCSWINSZ 0x5414u
#define REQ_FIONREAD   0x541Bu
#define REQ_FIONCLEX   0x5450u
#define REQ_FIOCLEX    0x5451u

/* Kernel ABI struct sizes for the whitelisted ioctls. */
#define K_TERMIOS_SZ 36u
#define K_TERMIO_SZ  17u
#define K_WINSIZE_SZ 8u
#define K_INT_SZ     4u

/* prctl options (include/uapi/linux/prctl.h, arch-independent). */
#define PR_SET_NAME_ 15
#define PR_GET_NAME_ 16

/* futex op encoding (include/uapi/linux/futex.h). */
#define FUTEX_WAIT_         0u
#define FUTEX_WAKE_         1u
#define FUTEX_PRIVATE_FLAG_ 128u
#define FUTEX_CMD_MASK_     0x7Fu

/* Linux resource limits / stack constants. */
#define NGROUPS_MAX_ 65536u
#define SS_ 12u /* i386 stack_t: u32 ss_sp, u32 ss_flags, u32 ss_size */

/* Guest paths can be at most PATH_MAX-1 + NUL before the kernel cuts
 * them off; same budget on the host side. */
#define PATH_BUF 4096

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

/* Phase 1 convention (src/os/syscalls.c): the low 4 KiB of the window is
 * the unmapped null page — a guest pointer there is EFAULT, not data. */
static int guest_ptr_bad(uint32_t va)
{
    return (va < 0x1000U) ? 1 : 0;
}

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void wr_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static long host_ret_(ssize_t n)
{
    return (n < 0) ? -(long)errno : (long)n;
}

/* Path fetch with the null-page guard: returns 0 on success, -1 when
 * the guest pointer is in the low guard or the string is unterminated. */
static int fetch_path(i686_ctx_t *ctx, uint32_t va, char *buf)
{
    if (guest_ptr_bad(va)) {
        return -1;
    }
    return (i686_fetch_cstr(ctx, va, buf, PATH_BUF) != 0) ? -1 : 0;
}

static long host_ret_int(long n)
{
    return (n < 0) ? -(long)errno : n;
}

/* setgroups(3) is a BSD extension that strict _POSIX_C_SOURCE builds
 * hide from <grp.h>; declare the (musl) prototype verbatim. */
int setgroups(int, const gid_t *);

/* ------------------------------------------------------------------ */
/* O_ flag translation (open-only; fcntl paths belong to L2e)           */
/* ------------------------------------------------------------------ */

/*
 * Translate i386 open(2) flags to aarch64 host flags.  Returns the host
 * flag word, or -EINVAL when the guest set bits unknown to the i386
 * kernel (Linux build_open_flags rejects those too).  Guest O_LARGEFILE
 * is dropped: it is a no-op for 64-bit hosts.  Guest O_SYNC arrives (as
 * on i386) as __O_SYNC|O_DSYNC = 0x101000 and reassembles into the host
 * O_SYNC 04010000; guest O_TMPFILE = __O_TMPFILE|O_DIRECTORY similarly
 * reassembles because both halves are translated individually.
 */
long i686_open_flags_to_host(uint32_t guest_flags)
{
    static const struct { uint32_t guest, host; } map[] = {
        { I686_O_CREAT,     HOST_O_CREAT },     /* 0x40    -> 0x40    */
        { I686_O_EXCL,      HOST_O_EXCL },      /* 0x80    -> 0x80    */
        { I686_O_NOCTTY,    HOST_O_NOCTTY },    /* 0x100   -> 0x100   */
        { I686_O_TRUNC,     HOST_O_TRUNC },     /* 0x200   -> 0x200   */
        { I686_O_APPEND,    HOST_O_APPEND },    /* 0x400   -> 0x400   */
        { I686_O_NONBLOCK,  HOST_O_NONBLOCK },  /* 0x800   -> 0x800   */
        { I686_O_DSYNC,     HOST_O_DSYNC },     /* 0x1000  -> 0x1000  */
        { I686_O_FASYNC,    HOST_O_FASYNC },    /* 0x2000  -> 0x2000  */
        { I686_O_DIRECT,    HOST_O_DIRECT },    /* 0x4000  -> 0x10000 */
        { I686_O_DIRECTORY, HOST_O_DIRECTORY }, /* 0x10000 -> 0x4000  */
        { I686_O_NOFOLLOW,  HOST_O_NOFOLLOW },  /* 0x20000 -> 0x8000  */
        { I686_O_NOATIME,   HOST_O_NOATIME },   /* 0x40000 -> 0x40000 */
        { I686_O_CLOEXEC,   HOST_O_CLOEXEC },   /* 0x80000 -> 0x80000 */
        { I686_O__SYNC,     HOST_O__SYNC },     /* 0x100000-> 0x100000*/
        { I686_O_PATH,      HOST_O_PATH },      /* 0x200000-> 0x200000*/
        { I686_O__TMPFILE,  HOST_O__TMPFILE },  /* 0x400000-> 0x400000*/
    };

    uint32_t host = guest_flags & I686_O_ACCMODE; /* accmode identical */

    guest_flags &= ~I686_O_ACCMODE; /* already accounted for above */
    if ((guest_flags & I686_O_LARGEFILE) != 0U) {
        guest_flags &= ~I686_O_LARGEFILE; /* no-op on 64-bit hosts */
    }
    for (size_t i = 0U; i < sizeof map / sizeof map[0]; i++) {
        if ((guest_flags & map[i].guest) != 0U) {
            host |= map[i].host;
            guest_flags &= ~map[i].guest;
        }
    }
    if (guest_flags != 0U) {
        return -EINVAL; /* unknown bits: kernel-parity rejection */
    }
    return (long)host;
}

/* ------------------------------------------------------------------ */
/* Pure marshalling helpers (unit-tested in tests/unit/test_l2f.c)      */
/* ------------------------------------------------------------------ */

/*
 * getcwd(2) store phase: kernel semantics for the guest buffer — size 0
 * is EINVAL, a buffer shorter than cwd_len (which includes the NUL) is
 * ERANGE, a bad pointer is EFAULT; on success the length including the
 * NUL is returned and cwd_len bytes are stored at buf_va.
 */
long i686_getcwd_store(i686_ctx_t *ctx, uint32_t buf_va, uint32_t size,
                       const char *cwd, size_t cwd_len)
{
    if (size == 0U) {
        return -EINVAL;
    }
    if (guest_ptr_bad(buf_va) ||
        (uint64_t)buf_va + (uint64_t)cwd_len > 0x100000000ULL) {
        return -EFAULT;
    }
    if ((size_t)size < cwd_len) {
        return -ERANGE;
    }
    int rc = i686_copy_to_guest(ctx, buf_va, cwd, cwd_len);
    return (rc != 0) ? rc : (long)cwd_len;
}

/*
 * Host (64-bit) struct rusage -> kernel i386 layout: ru_utime, ru_stime
 * (u32 sec + u32 usec each), then 14 x u32 longs = 72 bytes total (file
 * header citation).  64-bit fields truncate to 32 bits, matching what a
 * native i386 kernel would report after equally long uptimes.
 */
int i686_rusage_to_guest(i686_ctx_t *ctx, uint32_t ru_va, const struct rusage *ru)
{
    uint8_t out[72];
    const long fields[14] = {
        ru->ru_maxrss, ru->ru_ixrss, ru->ru_idrss, ru->ru_isrss,
        ru->ru_minflt, ru->ru_majflt, ru->ru_nswap, ru->ru_inblock,
        ru->ru_oublock, ru->ru_msgsnd, ru->ru_msgrcv, ru->ru_nsignals,
        ru->ru_nvcsw, ru->ru_nivcsw,
    };

    wr_le32(out + 0U, (uint32_t)ru->ru_utime.tv_sec);
    wr_le32(out + 4U, (uint32_t)ru->ru_utime.tv_usec);
    wr_le32(out + 8U, (uint32_t)ru->ru_stime.tv_sec);
    wr_le32(out + 12U, (uint32_t)ru->ru_stime.tv_usec);
    for (size_t i = 0U; i < 14U; i++) {
        wr_le32(out + 16U + 4U * i, (uint32_t)fields[i]);
    }

    if (guest_ptr_bad(ru_va)) {
        return -EFAULT;
    }
    return i686_copy_to_guest(ctx, ru_va, out, sizeof out);
}

/*
 * setgroups32 marshalling: guest u32 gid array -> host gid_t array.
 * Returns 0 with *out malloc'd (caller frees; NULL when n == 0),
 * -EINVAL above NGROUPS_MAX, -EFAULT on a bad guest range, -ENOMEM.
 */
int i686_groups_from_guest(i686_ctx_t *ctx, uint32_t list_va, uint32_t n, gid_t **out)
{
    *out = NULL;
    if (n == 0U) {
        return 0;
    }
    if (n > NGROUPS_MAX_) {
        return -EINVAL;
    }
    gid_t *g = malloc((size_t)n * sizeof *g);
    if (g == NULL) {
        return -ENOMEM;
    }
    if (guest_ptr_bad(list_va) ||
        i686_copy_from_guest(ctx, g, list_va, (size_t)n * sizeof *g) != 0) {
        free(g);
        return -EFAULT;
    }
    for (uint32_t i = 0U; i < n; i++) {
        uint32_t v = rd_le32((const uint8_t *)&g[i]);
        g[i] = (gid_t)v;
    }
    *out = g;
    return 0;
}

/*
 * setgroups (old, nr 81) marshalling: entries are kernel old_gid_t
 * (u16), zero-extended to host gid_t.
 */
int i686_groups16_from_guest(i686_ctx_t *ctx, uint32_t list_va, uint32_t n, gid_t **out)
{
    *out = NULL;
    if (n == 0U) {
        return 0;
    }
    if (n > NGROUPS_MAX_) {
        return -EINVAL;
    }
    gid_t *g = malloc((size_t)n * sizeof *g);
    uint8_t *raw = (g != NULL) ? malloc((size_t)n * 2U) : NULL;
    if (g == NULL || raw == NULL) {
        free(g);
        free(raw);
        return -ENOMEM;
    }
    if (guest_ptr_bad(list_va) ||
        i686_copy_from_guest(ctx, raw, list_va, (size_t)n * 2U) != 0) {
        free(g);
        free(raw);
        return -EFAULT;
    }
    for (uint32_t i = 0U; i < n; i++) {
        /* old_gid_t entries are packed 2-byte records, not 4-byte slots. */
        g[i] = (gid_t)((uint16_t)raw[2U * i] | ((uint16_t)raw[2U * i + 1U] << 8));
    }
    free(raw);
    *out = g;
    return 0;
}

/* ------------------------------------------------------------------ */
/* File-static Phase 4 state                                           */
/* ------------------------------------------------------------------ */

/* rt_sigaction store: guest kernel sigaction (20 B, structs_i386.h
 * i686_sigaction_t) per signum 1..64.  Phase 4 moves this next to the
 * per-thread state and actually delivers signals. */
static struct {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer;
    uint64_t mask;
} s_sigact[65];

/* prctl PR_{GET,SET}_NAME: TASK_COMM_LEN = 16 NUL-padded bytes. */
static char s_comm[16];

/* ------------------------------------------------------------------ */
/* Handlers                                                             */
/* ------------------------------------------------------------------ */

static long sys_open(i686_ctx_t *ctx, uint32_t path_va, uint32_t flags, uint32_t mode)
{
    char path[PATH_BUF];
    long hf = i686_open_flags_to_host(flags);
    long pfd;
    if (hf < 0) {
        return hf;
    }
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    pfd = i686_proc_open_at(ctx, path); /* S2 wiring (src/os/proc.{h,c}) */
    if (pfd != I686_PROC_NOT_MATCHED) {
        return pfd;
    }
    return host_ret_(open(path, (int)hf, (mode_t)mode));
}

static long sys_unlink(i686_ctx_t *ctx, uint32_t path_va)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(unlink(path));
}

static long sys_rmdir(i686_ctx_t *ctx, uint32_t path_va)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(rmdir(path));
}

static long sys_mkdir(i686_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(mkdir(path, (mode_t)mode));
}

static long sys_rename(i686_ctx_t *ctx, uint32_t old_va, uint32_t new_va)
{
    char oldp[PATH_BUF], newp[PATH_BUF];
    if (fetch_path(ctx, old_va, oldp) != 0 || fetch_path(ctx, new_va, newp) != 0) {
        return -EFAULT;
    }
    return host_ret_(rename(oldp, newp));
}

static long sys_link(i686_ctx_t *ctx, uint32_t old_va, uint32_t new_va)
{
    char oldp[PATH_BUF], newp[PATH_BUF];
    if (fetch_path(ctx, old_va, oldp) != 0 || fetch_path(ctx, new_va, newp) != 0) {
        return -EFAULT;
    }
    return host_ret_(link(oldp, newp));
}

static long sys_symlink(i686_ctx_t *ctx, uint32_t target_va, uint32_t link_va)
{
    char target[PATH_BUF], linkp[PATH_BUF];
    if (fetch_path(ctx, target_va, target) != 0 ||
        fetch_path(ctx, link_va, linkp) != 0) {
        return -EFAULT;
    }
    return host_ret_(symlink(target, linkp));
}

static long sys_chmod(i686_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(chmod(path, (mode_t)mode));
}

static long sys_fchmod(uint32_t fd, uint32_t mode)
{
    return host_ret_(fchmod((int)fd, (mode_t)mode));
}

/* uid/gid args: the "16" variants (nr 16/23/46/95) take kernel old
 * ids — the syscall argument is truncated to 16 bits exactly like the
 * i386 kernel's sys_*16 entry points do. */
static long sys_chown(i686_ctx_t *ctx, uint32_t path_va, uint32_t uid, uint32_t gid)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(chown(path, (uid_t)uid, (gid_t)gid));
}

static long sys_lchown(i686_ctx_t *ctx, uint32_t path_va, uint32_t uid, uint32_t gid)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(lchown(path, (uid_t)uid, (gid_t)gid));
}

static long sys_fchown(uint32_t fd, uint32_t uid, uint32_t gid)
{
    return host_ret_(fchown((int)fd, (uid_t)uid, (gid_t)gid));
}

static long sys_fchmodat(i686_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
                         uint32_t mode, uint32_t flags)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    /* flags: only AT_SYMLINK_NOFOLLOW (0x100), identical on both. */
    return host_ret_int(fchmodat((int)(int32_t)dirfd, path, (mode_t)mode, (int)flags));
}

static long sys_fchownat(i686_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
                         uint32_t uid, uint32_t gid, uint32_t flags)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    /* AT_SYMLINK_NOFOLLOW/AT_EMPTY_PATH identical on both arches. */
    return host_ret_int(fchownat((int)(int32_t)dirfd, path, (uid_t)uid,
                                 (gid_t)gid, (int)flags));
}

static long sys_access(i686_ctx_t *ctx, uint32_t path_va, uint32_t mode)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(access(path, (int)mode));
}

static long sys_faccessat(i686_ctx_t *ctx, uint32_t dirfd, uint32_t path_va,
                          uint32_t mode, uint32_t flags)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    /* AT_EACCESS (0x200) / AT_SYMLINK_NOFOLLOW (0x100) identical. */
    return host_ret_int(faccessat((int)(int32_t)dirfd, path, (int)mode, (int)flags));
}

static long sys_chdir(i686_ctx_t *ctx, uint32_t path_va)
{
    char path[PATH_BUF];
    if (fetch_path(ctx, path_va, path) != 0) {
        return -EFAULT;
    }
    return host_ret_(chdir(path));
}

static long sys_getcwd(i686_ctx_t *ctx, uint32_t buf_va, uint32_t size)
{
    char cwd[PATH_BUF];
    if (getcwd(cwd, sizeof cwd) == NULL) {
        return -errno; /* ERANGE here means >4 KiB cwd: v1 cap, documented */
    }
    return i686_getcwd_store(ctx, buf_va, size, cwd, strlen(cwd) + 1U);
}

static long sys_setgroups32(i686_ctx_t *ctx, uint32_t n, uint32_t list_va)
{
    gid_t *g = NULL;
    int rc = i686_groups_from_guest(ctx, list_va, n, &g);
    if (rc != 0) {
        return rc;
    }
    long r = host_ret_int(setgroups((int)n, g));
    free(g);
    return r;
}

static long sys_setgroups16(i686_ctx_t *ctx, uint32_t n, uint32_t list_va)
{
    gid_t *g = NULL;
    int rc = i686_groups16_from_guest(ctx, list_va, n, &g);
    if (rc != 0) {
        return rc;
    }
    long r = host_ret_int(setgroups((int)n, g));
    free(g);
    return r;
}

static long sys_getgroups32(i686_ctx_t *ctx, uint32_t size, uint32_t list_va)
{
    if (size == 0U) {
        return host_ret_int(getgroups(0, NULL)); /* kernel: return count */
    }
    if (size > NGROUPS_MAX_) {
        return -EINVAL;
    }
    gid_t *g = malloc((size_t)size * sizeof *g);
    if (g == NULL) {
        return -ENOMEM;
    }
    int r = getgroups((int)size, g);
    if (r < 0) {
        free(g);
        return -errno;
    }
    if (guest_ptr_bad(list_va) ||
        i686_copy_to_guest(ctx, list_va, g, (size_t)r * sizeof *g) != 0) {
        free(g);
        return -EFAULT;
    }
    free(g);
    return r;
}

static long sys_getgroups16(i686_ctx_t *ctx, uint32_t size, uint32_t list_va)
{
    if (size == 0U) {
        return host_ret_int(getgroups(0, NULL));
    }
    if (size > NGROUPS_MAX_) {
        return -EINVAL;
    }
    gid_t *g = malloc((size_t)size * sizeof *g);
    if (g == NULL) {
        return -ENOMEM;
    }
    int r = getgroups((int)size, g);
    if (r < 0) {
        free(g);
        return -errno;
    }
    uint8_t *out = malloc((size_t)r * 2U);
    if (out == NULL) {
        free(g);
        return -ENOMEM;
    }
    for (int i = 0; i < r; i++) {
        wr_le16(out + 2U * (size_t)i, (uint16_t)g[i]); /* old_gid_t: low 16 */
    }
    free(g);
    if (guest_ptr_bad(list_va) ||
        i686_copy_to_guest(ctx, list_va, out, (size_t)r * 2U) != 0) {
        free(out);
        return -EFAULT;
    }
    free(out);
    return r;
}

static long sys_dup3(uint32_t oldfd, uint32_t newfd, uint32_t flags)
{
    /* Only O_CLOEXEC is legal here, 0x80000 on both i386 and aarch64
     * (macOS's own O_CLOEXEC differs, hence the literal). */
    if ((flags & ~(uint32_t)0x80000u) != 0U) {
        return -EINVAL;
    }
#ifdef __APPLE__
    /* Unit-test build hosts (macOS) have no dup3; dup2 + F_SETFD gives
     * the same semantics for the flag set allowed above.  The deploy
     * host (aarch64 Linux) takes the real dup3 below. */
    {
        int fd = dup2((int)oldfd, (int)newfd);
        if (fd < 0) {
            return -errno;
        }
        if ((flags & 0x80000u) != 0U) {
            (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        return fd;
    }
#else
    return host_ret_(dup3((int)oldfd, (int)newfd,
                          (int)((flags & 0x80000u) ? 0x80000 : 0)));
#endif
}

/* Struct-carrying whitelisted ioctl: len bytes are copied guest->host
 * before the call (set direction) or host->guest after it (get
 * direction); the request number itself is identical on both arches. */
static long ioctl_buf(i686_ctx_t *ctx, uint32_t fd, uint32_t req, uint32_t arg,
                      size_t len, int set_direction)
{
    uint8_t buf[K_TERMIOS_SZ];

    if (guest_ptr_bad(arg)) {
        return -EFAULT;
    }
    if (set_direction) {
        if (i686_copy_from_guest(ctx, buf, arg, len) != 0) {
            return -EFAULT;
        }
    }
    long r = ioctl((int)fd, (unsigned long)req, buf);
    if (r < 0) {
        return -errno;
    }
    if (!set_direction) {
        if (i686_copy_to_guest(ctx, arg, buf, len) != 0) {
            return -EFAULT;
        }
    }
    return r;
}

static long sys_ioctl(i686_ctx_t *ctx, uint32_t fd, uint32_t req, uint32_t arg)
{
    switch (req) {
    case REQ_TCGETS:
        return ioctl_buf(ctx, fd, req, arg, K_TERMIOS_SZ, 0);
    case REQ_TCSETS:
    case REQ_TCSETSW:
    case REQ_TCSETSF:
        return ioctl_buf(ctx, fd, req, arg, K_TERMIOS_SZ, 1);
    case REQ_TCGETA:
        return ioctl_buf(ctx, fd, req, arg, K_TERMIO_SZ, 0);
    case REQ_TCSETA:
    case REQ_TCSETAW:
    case REQ_TCSETAF:
        return ioctl_buf(ctx, fd, req, arg, K_TERMIO_SZ, 1);
    case REQ_TIOCGWINSZ:
        return ioctl_buf(ctx, fd, req, arg, K_WINSIZE_SZ, 0);
    case REQ_TIOCSWINSZ:
        return ioctl_buf(ctx, fd, req, arg, K_WINSIZE_SZ, 1);
    case REQ_FIONREAD:
        return ioctl_buf(ctx, fd, req, arg, K_INT_SZ, 0);
    /* Integer/no-pointer requests: the u32 argument rides along
     * uninterpreted (it is not a guest address). */
    case REQ_TCSBRK:
    case REQ_TCSBRKP:
    case REQ_TCXONC:
    case REQ_TCFLSH:
    case REQ_TIOCEXCL:
    case REQ_TIOCNXCL:
    case REQ_TIOCNOTTY:
    case REQ_TIOCSBRK:
    case REQ_TIOCCBRK:
    case REQ_FIONCLEX:
    case REQ_FIOCLEX:
        return host_ret_int(ioctl((int)fd, (unsigned long)req, (unsigned long)arg));
    default:
        return -ENOTTY; /* not whitelisted in Phase 2 */
    }
}

static long sys_rt_sigaction(i686_ctx_t *ctx, uint32_t sig, uint32_t act_va,
                             uint32_t oldact_va, uint32_t sigsetsize)
{
    if (sigsetsize != 8U || sig == 0U || sig > 64U) {
        return -EINVAL;
    }
    if (oldact_va != 0U) {
        uint8_t old[20];
        wr_le32(old + 0U, s_sigact[sig].handler);
        wr_le32(old + 4U, s_sigact[sig].flags);
        wr_le32(old + 8U, s_sigact[sig].restorer);
        memcpy(old + 12U, &s_sigact[sig].mask, 8U); /* host LE = guest LE */
        if (guest_ptr_bad(oldact_va) ||
            i686_copy_to_guest(ctx, oldact_va, old, sizeof old) != 0) {
            return -EFAULT;
        }
    }
    if (act_va != 0U) {
        uint8_t act[20];
        if (guest_ptr_bad(act_va) ||
            i686_copy_from_guest(ctx, act, act_va, sizeof act) != 0) {
            return -EFAULT;
        }
        s_sigact[sig].handler  = rd_le32(act + 0U);
        s_sigact[sig].flags    = rd_le32(act + 4U);
        s_sigact[sig].restorer = rd_le32(act + 8U);
        memcpy(&s_sigact[sig].mask, act + 12U, 8U);
    }
    return 0; /* store-only: no delivery until Phase 4 */
}

static long sys_rt_sigprocmask(i686_ctx_t *ctx, uint32_t how, uint32_t set_va,
                               uint32_t oldset_va, uint32_t sigsetsize)
{
    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (oldset_va != 0U) {
        uint8_t old[8];
        memcpy(old, &ctx->sig_mask, 8U);
        if (guest_ptr_bad(oldset_va) ||
            i686_copy_to_guest(ctx, oldset_va, old, sizeof old) != 0) {
            return -EFAULT;
        }
    }
    if (set_va != 0U) {
        uint8_t set[8];
        uint64_t m;
        if (guest_ptr_bad(set_va) ||
            i686_copy_from_guest(ctx, set, set_va, sizeof set) != 0) {
            return -EFAULT;
        }
        memcpy(&m, set, 8U);
        switch (how) {
        case 0U: /* SIG_BLOCK */
            ctx->sig_mask |= m;
            break;
        case 1U: /* SIG_UNBLOCK */
            ctx->sig_mask &= ~m;
            break;
        case 2U: /* SIG_SETMASK */
            ctx->sig_mask = m;
            break;
        default:
            return -EINVAL;
        }
    }
    return 0; /* mask is bookkeeping only until Phase 4 */
}

static long sys_rt_sigpending(i686_ctx_t *ctx, uint32_t set_va, uint32_t sigsetsize)
{
    uint8_t zeros[8] = { 0 };

    if (sigsetsize != 8U) {
        return -EINVAL;
    }
    if (guest_ptr_bad(set_va) ||
        i686_copy_to_guest(ctx, set_va, zeros, sizeof zeros) != 0) {
        return -EFAULT;
    }
    return 0; /* nothing is ever pending in v1 */
}

static long sys_sigaltstack(i686_ctx_t *ctx, uint32_t ss_va, uint32_t old_ss_va)
{
    /* i386 stack_t { u32 ss_sp; u32 ss_flags; u32 ss_size } = 12 B; the
     * aarch64 host layout is 24 B, so this is store-only into the ctx
     * altstack fields (never handed to the host). */
    if (old_ss_va != 0U) {
        uint8_t old[SS_];
        wr_le32(old + 0U, ctx->altstack_sp);
        wr_le32(old + 4U, ctx->altstack_flags);
        wr_le32(old + 8U, ctx->altstack_size);
        if (guest_ptr_bad(old_ss_va) ||
            i686_copy_to_guest(ctx, old_ss_va, old, sizeof old) != 0) {
            return -EFAULT;
        }
    }
    if (ss_va != 0U) {
        uint8_t ss[SS_];
        if (guest_ptr_bad(ss_va) ||
            i686_copy_from_guest(ctx, ss, ss_va, sizeof ss) != 0) {
            return -EFAULT;
        }
        ctx->altstack_sp    = rd_le32(ss + 0U);
        ctx->altstack_flags = rd_le32(ss + 4U);
        ctx->altstack_size  = rd_le32(ss + 8U);
    }
    return 0;
}

static long sys_prctl(i686_ctx_t *ctx, uint32_t option, uint32_t arg2)
{
    if (option == (uint32_t)PR_SET_NAME_) {
        if (guest_ptr_bad(arg2) ||
            i686_copy_from_guest(ctx, s_comm, arg2, sizeof s_comm) != 0) {
            return -EFAULT;
        }
        return 0;
    }
    if (option == (uint32_t)PR_GET_NAME_) {
        char name[16];
        memcpy(name, s_comm, sizeof name);
        if (guest_ptr_bad(arg2) ||
            i686_copy_to_guest(ctx, arg2, name, sizeof name) != 0) {
            return -EFAULT;
        }
        return 0;
    }
    return -EINVAL; /* PR_SET_NAME/PR_GET_NAME only in Phase 2 */
}

static long sys_set_tid_address(i686_ctx_t *ctx, uint32_t tidptr_va)
{
    /* Kernel returns the previous clear_child_tid; the first call — the
     * only one in a single-threaded v1 — returns 0. */
    uint32_t prev = ctx->clear_child_tid;
    ctx->clear_child_tid = tidptr_va;
    return (long)prev;
}

static long sys_personality(i686_ctx_t *ctx, uint32_t persona)
{
    (void)ctx;
    /* v1 knows only persona 0 (PER_LINUX).  ADDR_LIMIT_3GB (0x00800000)
     * needs window/top switching and arrives with the vm work later. */
    return (persona == 0U) ? 0 : -EINVAL;
}

static long sys_futex(i686_ctx_t *ctx, uint32_t uaddr, uint32_t op, uint32_t val)
{
    /*
     * Phase 4 stopgap, single-threaded semantics (documented deviation):
     * FUTEX_WAKE reports "no waiters" (0); FUTEX_WAIT verifies *uaddr ==
     * val (returning -EAGAIN like the kernel on mismatch) and then
     * reports "woken" (0) without ever blocking.  Real futexes arrive
     * with clone() in Phase 4.
     */
    switch (op & FUTEX_CMD_MASK_) {
    case FUTEX_WAIT_: {
        uint8_t cur[4];
        if (guest_ptr_bad(uaddr) ||
            i686_copy_from_guest(ctx, cur, uaddr, sizeof cur) != 0) {
            return -EFAULT;
        }
        return (rd_le32(cur) == val) ? 0 : -EAGAIN;
    }
    case FUTEX_WAKE_:
        return 0;
    default:
        return -ENOSYS;
    }
}

/* ------------------------------------------------------------------ */
/* Registry adapters (args from EBX..EBP per the i386 syscall ABI)      */
/* ------------------------------------------------------------------ */


/* writev(146) — iovec array in guest memory (L2f passthrough family,
 * S2 coordinator addition: busybox sh error paths print via writev). */
struct i686_iov_local {
    uint32_t base;
    uint32_t len;
};

static int64_t r_writev(i686_ctx_t *ctx)
{
    int fd = (int)ctx->gpr[I686_REG_EBX];
    uint32_t iov_va = ctx->gpr[I686_REG_ECX];
    uint32_t cnt = ctx->gpr[I686_REG_EDX];
    int64_t total = 0;
    uint32_t i;

    if (cnt > 1024U) {
        return -EINVAL; /* UIO_MAXIOV */
    }
    for (i = 0U; i < cnt; i++) {
        struct i686_iov_local iov;
        char stk[512];
        uint32_t off;
        if (i686_copy_from_guest(ctx, &iov, iov_va + 8U * i, sizeof(iov)) != 0) {
            return -EFAULT;
        }
        for (off = 0U; off < iov.len; off += sizeof(stk)) {
            uint32_t chunk = iov.len - off;
            ssize_t n;
            if (chunk > sizeof(stk)) {
                chunk = (uint32_t)sizeof(stk);
            }
            if (i686_copy_from_guest(ctx, stk, iov.base + off, chunk) != 0) {
                return -EFAULT;
            }
            n = write(fd, stk, chunk);
            if (n < 0) {
                return (total > 0) ? total : -(int64_t)errno;
            }
            total += n;
            if ((size_t)n < chunk) {
                return total;
            }
        }
    }
    return total;
}

static int64_t r_open(i686_ctx_t *ctx)
{
    return sys_open(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                    ctx->gpr[I686_REG_EDX]);
}

static int64_t r_close(i686_ctx_t *ctx)
{
    return host_ret_(close((int)ctx->gpr[I686_REG_EBX]));
}

static int64_t r_lseek(i686_ctx_t *ctx)
{
    /* i386 off_t is signed 32-bit; large files go through _llseek (L2e). */
    return host_ret_(lseek((int)ctx->gpr[I686_REG_EBX],
                           (off_t)(int32_t)ctx->gpr[I686_REG_ECX],
                           (int)ctx->gpr[I686_REG_EDX]));
}

static int64_t r_unlink(i686_ctx_t *ctx)
{
    return sys_unlink(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_rmdir(i686_ctx_t *ctx)
{
    return sys_rmdir(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_mkdir(i686_ctx_t *ctx)
{
    return sys_mkdir(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_rename(i686_ctx_t *ctx)
{
    return sys_rename(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_link(i686_ctx_t *ctx)
{
    return sys_link(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_symlink(i686_ctx_t *ctx)
{
    return sys_symlink(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_chmod(i686_ctx_t *ctx)
{
    return sys_chmod(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_fchmod(i686_ctx_t *ctx)
{
    return sys_fchmod(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_chown(i686_ctx_t *ctx)
{
    return sys_chown(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

static int64_t r_lchown(i686_ctx_t *ctx)
{
    /* old lchown(16): old_uid_t/old_gid_t are u16 in the kernel. */
    return sys_lchown(ctx, ctx->gpr[I686_REG_EBX],
                      ctx->gpr[I686_REG_ECX] & 0xFFFFu,
                      ctx->gpr[I686_REG_EDX] & 0xFFFFu);
}

static int64_t r_fchown(i686_ctx_t *ctx)
{
    return sys_fchown(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX] & 0xFFFFu,
                      ctx->gpr[I686_REG_EDX] & 0xFFFFu);
}

static int64_t r_chown32(i686_ctx_t *ctx)
{
    return sys_chown(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

static int64_t r_lchown32(i686_ctx_t *ctx)
{
    return sys_lchown(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                      ctx->gpr[I686_REG_EDX]);
}

static int64_t r_fchown32(i686_ctx_t *ctx)
{
    return sys_fchown(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                      ctx->gpr[I686_REG_EDX]);
}

static int64_t r_fchmodat(i686_ctx_t *ctx)
{
    return sys_fchmodat(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_fchownat(i686_ctx_t *ctx)
{
    return sys_fchownat(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                        ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                        ctx->gpr[I686_REG_EDI]);
}

static int64_t r_access(i686_ctx_t *ctx)
{
    return sys_access(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_faccessat(i686_ctx_t *ctx)
{
    return sys_faccessat(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_chdir(i686_ctx_t *ctx)
{
    return sys_chdir(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_fchdir(i686_ctx_t *ctx)
{
    return host_ret_(fchdir((int)ctx->gpr[I686_REG_EBX]));
}

static int64_t r_getcwd(i686_ctx_t *ctx)
{
    return sys_getcwd(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_getppid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)getppid();
}

static int64_t r_getuid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)((uint32_t)getuid() & 0xFFFFu); /* old uid16 */
}

static int64_t r_getuid32(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)getuid();
}

static int64_t r_getgid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)((uint32_t)getgid() & 0xFFFFu);
}

static int64_t r_getgid32(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)getgid();
}

static int64_t r_geteuid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)((uint32_t)geteuid() & 0xFFFFu);
}

static int64_t r_geteuid32(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)geteuid();
}

static int64_t r_getegid(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)((uint32_t)getegid() & 0xFFFFu);
}

static int64_t r_getegid32(i686_ctx_t *ctx)
{
    (void)ctx;
    return (int64_t)getegid();
}

static int64_t r_setuid(i686_ctx_t *ctx)
{
    return host_ret_(setuid((uid_t)(ctx->gpr[I686_REG_EBX] & 0xFFFFu)));
}

static int64_t r_setuid32(i686_ctx_t *ctx)
{
    return host_ret_(setuid((uid_t)ctx->gpr[I686_REG_EBX]));
}

static int64_t r_setgid(i686_ctx_t *ctx)
{
    return host_ret_(setgid((gid_t)(ctx->gpr[I686_REG_EBX] & 0xFFFFu)));
}

static int64_t r_setgid32(i686_ctx_t *ctx)
{
    return host_ret_(setgid((gid_t)ctx->gpr[I686_REG_EBX]));
}

static int64_t r_setgroups32(i686_ctx_t *ctx)
{
    return sys_setgroups32(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_setgroups16(i686_ctx_t *ctx)
{
    return sys_setgroups16(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_getgroups32(i686_ctx_t *ctx)
{
    return sys_getgroups32(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_getgroups16(i686_ctx_t *ctx)
{
    return sys_getgroups16(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_umask(i686_ctx_t *ctx)
{
    return (int64_t)umask((mode_t)ctx->gpr[I686_REG_EBX]);
}

static int64_t r_dup(i686_ctx_t *ctx)
{
    return host_ret_(dup((int)ctx->gpr[I686_REG_EBX]));
}

static int64_t r_dup2(i686_ctx_t *ctx)
{
    return host_ret_(dup2((int)ctx->gpr[I686_REG_EBX], (int)ctx->gpr[I686_REG_ECX]));
}

static int64_t r_dup3(i686_ctx_t *ctx)
{
    return sys_dup3(ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                    ctx->gpr[I686_REG_EDX]);
}

static int64_t r_ioctl(i686_ctx_t *ctx)
{
    return sys_ioctl(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

static int64_t r_munmap(i686_ctx_t *ctx)
{
    return rt32_vm_munmap(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_mprotect(i686_ctx_t *ctx)
{
    /* PROT_* values (0x1/0x2/0x4) are identical on both arches. */
    return rt32_vm_mprotect(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                            ctx->gpr[I686_REG_EDX]);
}

static int64_t r_mremap(i686_ctx_t *ctx)
{
    /* MREMAP_MAYMOVE (1) / MREMAP_FIXED (2) are identical on both; the
     * i386 5-arg form maps straight onto rt32's. */
    uint32_t r = rt32_vm_mremap(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                                ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                                ctx->gpr[I686_REG_EDI]);
    return (long)(int32_t)r;
}

static int64_t r_rt_sigaction(i686_ctx_t *ctx)
{
    return sys_rt_sigaction(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                            ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_rt_sigprocmask(i686_ctx_t *ctx)
{
    return sys_rt_sigprocmask(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                              ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI]);
}

static int64_t r_rt_sigpending(i686_ctx_t *ctx)
{
    return sys_rt_sigpending(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_sigaltstack(i686_ctx_t *ctx)
{
    return sys_sigaltstack(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_prctl(i686_ctx_t *ctx)
{
    return sys_prctl(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX]);
}

static int64_t r_set_tid_address(i686_ctx_t *ctx)
{
    return sys_set_tid_address(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_personality(i686_ctx_t *ctx)
{
    return sys_personality(ctx, ctx->gpr[I686_REG_EBX]);
}

static int64_t r_futex(i686_ctx_t *ctx)
{
    return sys_futex(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX]);
}

void i686_syscalls_pass_init(void)
{
    /* Deliberately NOT registered (registry default = -ENOSYS):
     *   kill(37), tkill(238), tgkill(270) and every other signal
     *     sender/delivery syscall — Phase 4; they must not "succeed".
     *   capget(184)/capset(185) — Phase 4.
     *   clone(120) — Phase 4 (see src/os/syscalls.c for fork/vfork).
     *   execve(11)/execveat(358) — coordinator in-process exec at S2.
     * getpid(20) stays in src/os/syscalls.c (Phase 1 adapter). */
    i686_sys_register(NR_open, r_open);
    i686_sys_register(NR_writev, r_writev);
    i686_sys_register(NR_close, r_close);
    i686_sys_register(NR_lseek, r_lseek);
    i686_sys_register(NR_unlink, r_unlink);
    i686_sys_register(NR_rmdir, r_rmdir);
    i686_sys_register(NR_mkdir, r_mkdir);
    i686_sys_register(NR_rename, r_rename);
    i686_sys_register(NR_link, r_link);
    i686_sys_register(NR_symlink, r_symlink);
    i686_sys_register(NR_chmod, r_chmod);
    i686_sys_register(NR_fchmod, r_fchmod);
    i686_sys_register(NR_lchown, r_lchown);
    i686_sys_register(NR_chown, r_chown);
    i686_sys_register(NR_fchown, r_fchown);
    i686_sys_register(NR_lchown32, r_lchown32);
    i686_sys_register(NR_chown32, r_chown32);
    i686_sys_register(NR_fchown32, r_fchown32);
    i686_sys_register(NR_fchmodat, r_fchmodat);
    i686_sys_register(NR_fchownat, r_fchownat);
    i686_sys_register(NR_access, r_access);
    i686_sys_register(NR_faccessat, r_faccessat);
    i686_sys_register(NR_chdir, r_chdir);
    i686_sys_register(NR_fchdir, r_fchdir);
    i686_sys_register(NR_getcwd, r_getcwd);
    i686_sys_register(NR_getppid, r_getppid);
    i686_sys_register(NR_getuid, r_getuid);
    i686_sys_register(NR_getuid32, r_getuid32);
    i686_sys_register(NR_getgid, r_getgid);
    i686_sys_register(NR_getgid32, r_getgid32);
    i686_sys_register(NR_geteuid, r_geteuid);
    i686_sys_register(NR_geteuid32, r_geteuid32);
    i686_sys_register(NR_getegid, r_getegid);
    i686_sys_register(NR_getegid32, r_getegid32);
    i686_sys_register(NR_setuid, r_setuid);
    i686_sys_register(NR_setuid32, r_setuid32);
    i686_sys_register(NR_setgid, r_setgid);
    i686_sys_register(NR_setgid32, r_setgid32);
    i686_sys_register(NR_setgroups, r_setgroups16);
    i686_sys_register(NR_setgroups32, r_setgroups32);
    i686_sys_register(NR_getgroups, r_getgroups16);
    i686_sys_register(NR_getgroups32, r_getgroups32);
    i686_sys_register(NR_umask, r_umask);
    i686_sys_register(NR_dup, r_dup);
    i686_sys_register(NR_dup2, r_dup2);
    i686_sys_register(NR_dup3, r_dup3);
    i686_sys_register(NR_ioctl, r_ioctl);
    i686_sys_register(NR_munmap, r_munmap);
    i686_sys_register(NR_mprotect, r_mprotect);
    i686_sys_register(NR_mremap, r_mremap);
    i686_sys_register(NR_rt_sigaction, r_rt_sigaction);
    i686_sys_register(NR_rt_sigprocmask, r_rt_sigprocmask);
    i686_sys_register(NR_rt_sigpending, r_rt_sigpending);
    i686_sys_register(NR_sigaltstack, r_sigaltstack);
    i686_sys_register(NR_prctl, r_prctl);
    i686_sys_register(NR_set_tid_address, r_set_tid_address);
    i686_sys_register(NR_personality, r_personality);
    i686_sys_register(NR_futex, r_futex);
}
