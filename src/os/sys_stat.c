/*
 * src/os/sys_stat.c — Phase 2 lane L2a: stat/statfs/dirent marshalling
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * i386 syscall set (numbers transcribed from the authoritative generated
 * table in os/syscalls_i386.h; that header only pre-defines I686__NR_*
 * macros for the Phase-1 smoke set, so the rows are cited per define):
 *
 *   statfs(99) fstatfs(100) getdents(141) stat64(195) lstat64(196)
 *   fstat64(197) getdents64(220) statfs64(268) fstatfs64(269)
 *   fstatat64(300) statx(383)
 *
 * Host syscalls run against PLAIN HOST PATHS in Phase 2 — the rt32 sysroot
 * resolver arrives in a later phase and will be threaded through
 * l2a_path_at() below.
 *
 * LAYOUT VERIFICATION (card-mandated; references fetched 2026-10-20):
 *
 * 1. i686_stat64_t (frozen src/os/structs_i386.h:27-47) vs
 *    kernel arch/x86/include/uapi/asm/stat.h, struct stat64 at lines
 *    29-60 (torvalds/linux master):
 *      :30 st_dev unsigned long long      -> offset  0 (8 B)
 *      :31 __pad0[4]                      -> offset  8
 *      :33 __st_ino unsigned long (u32)   -> offset 12
 *      :35 st_mode, :36 st_nlink          -> 16, 20
 *      :38 st_uid, :39 st_gid             -> 24, 28
 *      :41 st_rdev unsigned long long     -> 32, :42 __pad3[4] -> 40
 *      :44 st_size long long              -> 44
 *      :45 st_blksize unsigned long (u32) -> 52
 *      :48 st_blocks unsigned long long   -> 56
 *      :50/51 st_atime/_nsec              -> 64/68
 *      :53/54 st_mtime/_nsec              -> 72/76 (:54 is the odd
 *                                          "unsigned int" spelling; same
 *                                          4 bytes on i386)
 *      :56/57 st_ctime/_nsec              -> 80/84
 *      :59 st_ino unsigned long long      -> 88
 *    Total 96 B, field-for-field identical to the frozen header. MATCH.
 *    musl arch/i386/bits/stat.h ("copied from kernel definition, but with
 *    padding replaced by the corresponding correctly-sized userspace
 *    types") mirrors the same fields for the USERSPACE struct; the
 *    syscall wire this module must produce is the kernel struct above.
 *
 * 2. i686_statfs_t (frozen :65-78) vs kernel
 *    include/uapi/asm-generic/statfs.h: __statfs_word == __u32 on
 *    32-bit (:24), struct statfs at :28-41 — f_type, f_bsize, f_blocks,
 *    f_bfree, f_bavail, f_files, f_ffree (all u32), f_fsid
 *    (__kernel_fsid_t = int[2]), f_namelen, f_frsize, f_flags,
 *    f_spare[4] -> 64 B. MATCH.
 *
 * 3. i686_statfs64_t (frozen :50-63) vs kernel
 *    include/uapi/asm-generic/statfs.h, struct statfs64 at :49-62:
 *    u32 f_type/f_bsize, u64 blocks/bfree/bavail/files/ffree, fsid@48,
 *    u32 namelen@56/frsize@60/flags@64/spare[4]@68 -> 84 B. x86 does not
 *    ARCH_PACK_STATFS64 and i386 aligns u64 to 4, so 84 B unpadded too —
 *    exactly what an i386 statfs64(268) caller expects, and the sz
 *    argument glibc/musl pass is 84. MATCH.
 *    (musl note: git.musl-libc.org was unreachable during this lane;
 *    musl's userspace struct statfs uses 64-bit fsblkcnt_t even on
 *    32-bit archs — see a local musl 1.2.6 install, include/bits/
 *    statfs.h:1-7 — and converts internally. The SYSCALL wire stays the
 *    kernel layout above, which is what this module produces.)
 *
 * 4. getdents64(220) record vs kernel include/linux/dirent.h struct
 *    linux_dirent64: u64 d_ino@0, s64 d_off@8, u16 d_reclen@16,
 *    u8 d_type@18, char d_name[]@19; fs/readdir.c filldir64 computes
 *    reclen = ALIGN(19 + namlen + 1, sizeof(u64) = 8) — the aarch64 host
 *    kernel emits exactly this wire, so records pass through with only
 *    d_off (and nothing else) rewritten. Verified below as
 *    i686_linux_dirent64_t with static asserts.
 *
 * 5. getdents(141) old record vs kernel fs/readdir.c compat_filldir:
 *    struct compat_linux_dirent { compat_ulong_t d_ino; compat_ulong_t
 *    d_off; unsigned short d_reclen; char d_name[] } — header 10 B
 *    (d_ino@0, d_off@4, d_reclen@8, name@10), reclen = ALIGN(10 +
 *    namlen + 2, sizeof(compat_long_t) = 4), d_type stored at
 *    reclen-1, and the syscall epilogue overwrites the last record's
 *    d_off with ctx->pos. NOTE: the frozen i686_linux_dirent_t
 *    (structs_i386.h:81-87) is the glibc/musl USERSPACE struct dirent
 *    (musl include/bits/dirent.h: ino_t d_ino; off_t d_off; unsigned
 *    short d_reclen; unsigned char d_type; char d_name[256] — on i386
 *    that is d_type inline @10, name @11), which is NOT the wire shape:
 *    the kernel hides d_type at the record tail. The wire marshal below
 *    follows the kernel; the frozen struct pins the first three field
 *    types/offsets (asserted here). No header change needed.
 *
 * Follow-ups outside this file's ownership (a32rt reference
 * ../a32rt/src/syscalls.c:1908-1921): lseek must translate guest dir
 * cookies back to host offsets via an unmap, and close() drops the fd's
 * cookie entries. Both live in sys_pass.c (L2f)/coordinator territory;
 * the cookie table here is file-local per the lane card.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <sys/mount.h> /* macOS keeps struct statfs here (no statfs.h) */
#else
#include <sys/statfs.h>
#include <sys/syscall.h>
#endif

/* macOS (and glibc with _POSIX_C_SOURCE >= 200809) define st_atime/
 * st_mtime/st_ctime as accessor macros, and macOS <sys/signal.h> defines
 * sa_handler the same way; the frozen i386 layouts use these names as
 * plain fields, so the macros must go before structs_i386.h. POSIX
 * explicitly permits undefining them. */
#undef st_atime
#undef st_mtime
#undef st_ctime
#undef sa_handler

#include "marshal.h"
#include "structs_i386.h"

/* ---- syscall numbers (rows of os/syscalls_i386.h, authoritative) ------ */

#define L2A_NR_statfs     99U   /* syscalls_i386.h [99]  statfs     */
#define L2A_NR_fstatfs    100U  /* syscalls_i386.h [100] fstatfs    */
#define L2A_NR_getdents   141U  /* syscalls_i386.h [141] getdents   */
#define L2A_NR_stat64     195U  /* syscalls_i386.h [195] stat64     */
#define L2A_NR_lstat64    196U  /* syscalls_i386.h [196] lstat64    */
#define L2A_NR_fstat64    197U  /* syscalls_i386.h [197] fstat64    */
#define L2A_NR_getdents64 220U  /* syscalls_i386.h [220] getdents64 */
#define L2A_NR_statfs64   268U  /* syscalls_i386.h [268] statfs64   */
#define L2A_NR_fstatfs64  269U  /* syscalls_i386.h [269] fstatfs64  */
#define L2A_NR_fstatat64  300U  /* syscalls_i386.h [300] fstatat64  */
#define L2A_NR_statx      383U  /* syscalls_i386.h [383] statx      */

/* ---- host struct spelling shims (aarch64 Linux vs macOS test host) ----
 *
 * The cross target is aarch64-linux (st_atim, f_fsid.__val, f_namelen,
 * f_frsize); the host-native unit test builds on macOS, where the times
 * are st_atimespec.., fsid_t is struct { int32_t val[2]; } and statfs
 * has no f_namelen/f_frsize (they only exist in statvfs). The macOS
 * values below exist solely so the unit test can drive the converters;
 * production paths run on Linux. */

static void host_stat_times(const struct stat *s, int64_t sec[3],
                            int32_t nsec[3])
{
#if defined(__APPLE__) && defined(__MACH__)
    const struct timespec *t[3] = { &s->st_atimespec, &s->st_mtimespec,
                                    &s->st_ctimespec };
#else
    const struct timespec *t[3] = { &s->st_atim, &s->st_mtim, &s->st_ctim };
#endif
    for (int i = 0; i < 3; i++) {
        sec[i]  = (int64_t)t[i]->tv_sec;
        nsec[i] = (int32_t)t[i]->tv_nsec;
    }
}

#if defined(__APPLE__) && defined(__MACH__)
#define HOST_FS_FSID_VAL(s, i) ((uint32_t)(s)->f_fsid.val[(i)])
#define HOST_FS_NAMELEN(s)     (255U)              /* no f_namelen on macOS */
#define HOST_FS_FRSIZE(s)      ((uint32_t)(s)->f_bsize) /* no f_frsize */
#else
#define HOST_FS_FSID_VAL(s, i) ((uint32_t)(s)->f_fsid.__val[(i)])
#define HOST_FS_NAMELEN(s)     ((uint32_t)(s)->f_namelen)
#define HOST_FS_FRSIZE(s)      ((uint32_t)(s)->f_frsize)
#endif

static int64_t err_neg(void)
{
    return -(int64_t)errno;
}

/* ---- host stat/statfs -> guest wire converters -------------------------
 *
 * Non-static for tests/unit/test_l2a.c (per the lane card); not part of
 * any frozen interface. Guest and hosts are little-endian, so a packed
 * struct filled field-by-field and copied with i686_copy_to_guest is
 * byte-exact. */

void i686_stat64_from_host(i686_stat64_t *dst, const struct stat *src)
{
    int64_t sec[3];
    int32_t nsec[3];

    host_stat_times(src, sec, nsec);
    memset(dst, 0, sizeof(*dst));
    dst->st_dev        = (uint64_t)src->st_dev;
    dst->st_ino_lo     = (uint32_t)src->st_ino; /* kernel __st_ino */
    dst->st_mode       = (uint32_t)src->st_mode;
    dst->st_nlink      = (uint32_t)src->st_nlink;
    dst->st_uid        = (uint32_t)src->st_uid;
    dst->st_gid        = (uint32_t)src->st_gid;
    dst->st_rdev       = (uint64_t)src->st_rdev;
    dst->st_size       = (int64_t)src->st_size;
    dst->st_blksize    = (uint32_t)src->st_blksize;
    dst->st_blocks     = (uint64_t)src->st_blocks;
    dst->st_atime      = (uint32_t)sec[0];
    dst->st_atime_nsec = (uint32_t)nsec[0];
    dst->st_mtime      = (uint32_t)sec[1];
    dst->st_mtime_nsec = (uint32_t)nsec[1];
    dst->st_ctime      = (uint32_t)sec[2];
    dst->st_ctime_nsec = (uint32_t)nsec[2];
    dst->st_ino        = (uint64_t)src->st_ino;
}

void i686_statfs_from_host(i686_statfs_t *dst, const struct statfs *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->f_type    = (uint32_t)src->f_type;
    dst->f_bsize   = (uint32_t)src->f_bsize;
    dst->f_blocks  = (uint32_t)src->f_blocks; /* 32-bit compat truncation */
    dst->f_bfree   = (uint32_t)src->f_bfree;
    dst->f_bavail  = (uint32_t)src->f_bavail;
    dst->f_files   = (uint32_t)src->f_files;
    dst->f_ffree   = (uint32_t)src->f_ffree;
    dst->f_fsid[0] = HOST_FS_FSID_VAL(src, 0);
    dst->f_fsid[1] = HOST_FS_FSID_VAL(src, 1);
    dst->f_namelen = HOST_FS_NAMELEN(src);
    dst->f_frsize  = HOST_FS_FRSIZE(src);
    dst->f_flags   = (uint32_t)src->f_flags;
}

void i686_statfs64_from_host(i686_statfs64_t *dst, const struct statfs *src)
{
    memset(dst, 0, sizeof(*dst));
    dst->f_type    = (uint32_t)src->f_type;
    dst->f_bsize   = (uint32_t)src->f_bsize;
    dst->f_blocks  = (uint64_t)src->f_blocks;
    dst->f_bfree   = (uint64_t)src->f_bfree;
    dst->f_bavail  = (uint64_t)src->f_bavail;
    dst->f_files   = (uint64_t)src->f_files;
    dst->f_ffree   = (uint64_t)src->f_ffree;
    dst->f_fsid[0] = HOST_FS_FSID_VAL(src, 0);
    dst->f_fsid[1] = HOST_FS_FSID_VAL(src, 1);
    dst->f_namelen = HOST_FS_NAMELEN(src);
    dst->f_frsize  = HOST_FS_FRSIZE(src);
    dst->f_flags   = (uint32_t)src->f_flags;
}

/* ---- guest dirent64 wire record (see layout notes 4 above) ------------- */

typedef struct __attribute__((packed)) {
    uint64_t d_ino;    /*  0 */
    int64_t  d_off;    /*  8 */
    uint16_t d_reclen; /* 16 */
    uint8_t  d_type;   /* 18 */
    char     d_name[]; /* 19 — C11 FAM; kernel name starts at 19 */
} i686_linux_dirent64_t;

_Static_assert(offsetof(i686_linux_dirent64_t, d_ino) == 0,
               "dirent64 d_ino @0");
_Static_assert(offsetof(i686_linux_dirent64_t, d_off) == 8,
               "dirent64 d_off @8");
_Static_assert(offsetof(i686_linux_dirent64_t, d_reclen) == 16,
               "dirent64 d_reclen @16");
_Static_assert(offsetof(i686_linux_dirent64_t, d_type) == 18,
               "dirent64 d_type @18");
_Static_assert(offsetof(i686_linux_dirent64_t, d_name) == 19,
               "dirent64 d_name @19");
_Static_assert(sizeof(i686_linux_dirent64_t) == 19,
               "dirent64 header is 19 B + name");

/* Old getdents(141) wire offsets (layout note 5): the frozen
 * i686_linux_dirent_t pins the first three fields; the wire keeps d_type
 * at reclen-1 and the name at 10. */
_Static_assert(offsetof(i686_linux_dirent_t, d_ino) == 0, "old d_ino @0");
_Static_assert(offsetof(i686_linux_dirent_t, d_off) == 4, "old d_off @4");
_Static_assert(offsetof(i686_linux_dirent_t, d_reclen) == 8, "old d_reclen @8");

#define OLD_OFF_INO    0U
#define OLD_OFF_OFF    4U
#define OLD_OFF_RECLEN 8U
#define OLD_OFF_NAME   10U

/* ---- guest LE record primitives (all targets are little-endian) -------- */

static uint16_t rec_load_u16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static uint64_t rec_load_u64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, sizeof(v));
    return v;
}

static void rec_store_u16(uint8_t *p, uint16_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void rec_store_u32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void rec_store_u64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, sizeof(v));
}

/* ---- d_off cookie remap (a32rt map_dir_cookie pattern) -----------------
 *
 * Host getdents64 d_off values are 64-bit. i386 getdents64 d_off is
 * also 64-bit. This remap still folds offsets at or above the cookie
 * base into a 32-bit cookie and writes it into that 64-bit field. Raw
 * truncation of the unmapped values could collide and would not be stable
 * across batches. Host offsets at or above L2A_DIR_COOKIE_BASE are mapped
 * injectively (per fd) into stable small cookies; smaller offsets pass
 * through untouched (tmpfs-style filesystems use tiny offsets). Guest
 * telldir/seekdir round-trips need lseek to translate back — L2f
 * follow-up, see the file header. */

#define L2A_MAX_DIR_COOKIES 4096U
#define L2A_DIR_COOKIE_BASE 0x70000000ULL

typedef struct {
    int      fd;
    uint64_t off64;
} l2a_dir_cookie_ent_t;

static l2a_dir_cookie_ent_t s_dir_cookies[L2A_MAX_DIR_COOKIES];
static size_t               s_dir_cookie_count;

static uint64_t map_dir_cookie(int fd, uint64_t host_off)
{
    if (host_off < L2A_DIR_COOKIE_BASE) {
        return host_off;
    }
    for (size_t i = 0U; i < s_dir_cookie_count; i++) {
        if (s_dir_cookies[i].fd == fd &&
            s_dir_cookies[i].off64 == host_off) {
            return L2A_DIR_COOKIE_BASE + (uint64_t)i;
        }
    }
    size_t idx;
    if (s_dir_cookie_count < L2A_MAX_DIR_COOKIES) {
        idx = s_dir_cookie_count++;
    } else {
        idx = (size_t)(host_off % L2A_MAX_DIR_COOKIES);
    }
    s_dir_cookies[idx].fd    = fd;
    s_dir_cookies[idx].off64 = host_off;
    return L2A_DIR_COOKIE_BASE + (uint64_t)idx;
}

/* ---- dirent batch converters (non-static for the unit test) ------------- */

/* Rewrites d_off of every getdents64 record in buf through the cookie
 * map. Records are walked strictly by reclen; a malformed tail is left
 * as-is. Returns len. */
size_t i686_dirent64_remap_offs(int fd, uint8_t *buf, size_t len)
{
    size_t pos = 0U;

    while (pos + offsetof(i686_linux_dirent64_t, d_name) <= len) {
        uint16_t reclen = rec_load_u16(buf + pos +
                                       offsetof(i686_linux_dirent64_t,
                                                d_reclen));
        if (reclen == 0U || pos + (size_t)reclen > len) {
            break;
        }
        uint64_t host_off =
            rec_load_u64(buf + pos + offsetof(i686_linux_dirent64_t, d_off));
        rec_store_u64(buf + pos + offsetof(i686_linux_dirent64_t, d_off),
                      map_dir_cookie(fd, host_off));
        pos += (size_t)reclen;
    }
    return len;
}

/* Converts one host getdents64 batch (in/in_len) into old-getdents(141)
 * wire records (out/out_cap), applying the cookie map. On return
 * *host_resume holds the host directory offset where the next
 * unconverted record starts (the d_off of the last converted record;
 * the caller initializes it to the pre-read fd position), and
 * *truncated is set when a record did not fit out_cap. Returns the
 * number of bytes written. d_ino is truncated to 32 bits (a32rt
 * behaviour; the native kernel would fail with EOVERFLOW instead). */
size_t i686_dirent_old_from64(int fd, const uint8_t *in, size_t in_len,
                              uint8_t *out, size_t out_cap,
                              uint64_t *host_resume, int *truncated)
{
    size_t in_pos  = 0U;
    size_t out_pos = 0U;

    *truncated = 0;
    while (in_pos + offsetof(i686_linux_dirent64_t, d_name) <= in_len) {
        uint16_t reclen = rec_load_u16(in + in_pos +
                                       offsetof(i686_linux_dirent64_t,
                                                d_reclen));
        if (reclen < 20U || in_pos + (size_t)reclen > in_len) {
            break; /* malformed record: no name byte inside */
        }
        const char *name =
            (const char *)(in + in_pos +
                           offsetof(i686_linux_dirent64_t, d_name));
        size_t namlen = strnlen(name,
                                (size_t)reclen -
                                    offsetof(i686_linux_dirent64_t, d_name));
        size_t rec32 = (OLD_OFF_NAME + namlen + 2U + 3U) & ~(size_t)3U;

        if (out_pos + rec32 > out_cap) {
            *truncated = 1;
            break;
        }

        uint64_t host_ino =
            rec_load_u64(in + in_pos +
                         offsetof(i686_linux_dirent64_t, d_ino));
        uint64_t host_off =
            rec_load_u64(in + in_pos +
                         offsetof(i686_linux_dirent64_t, d_off));

        memset(out + out_pos, 0, rec32);
        rec_store_u32(out + out_pos + OLD_OFF_INO, (uint32_t)host_ino);
        rec_store_u32(out + out_pos + OLD_OFF_OFF,
                      (uint32_t)(map_dir_cookie(fd, host_off) &
                                 0x7FFFFFFFU));
        rec_store_u16(out + out_pos + OLD_OFF_RECLEN, (uint16_t)rec32);
        memcpy(out + out_pos + OLD_OFF_NAME, name, namlen);
        out[out_pos + rec32 - 1U] =
            in[in_pos + offsetof(i686_linux_dirent64_t, d_type)];

        *host_resume = host_off;
        out_pos += rec32;
        in_pos += (size_t)reclen;
    }
    return out_pos;
}

/* ---- host getdents64 ---------------------------------------------------- */

#if defined(__APPLE__) && defined(__MACH__)
/* macOS host-native unit builds have no getdents64; the handler bodies
 * stay compiled and reachable but report -ENOSYS. Production targets
 * are Linux only; the unit test drives the converters above directly. */
static ssize_t host_getdents64(int fd, void *buf, size_t len)
{
    (void)fd;
    (void)buf;
    (void)len;
    errno = ENOSYS;
    return -1;
}
#else
/* musl (and glibc) only declare syscall() under _GNU_SOURCE; the check
 * build uses -D_POSIX_C_SOURCE=200809L, so declare the stable prototype
 * (identical in glibc and musl) instead of widening the feature set. */
long syscall(long number, ...);

static ssize_t host_getdents64(int fd, void *buf, size_t len)
{
    return (ssize_t)syscall(SYS_getdents64, fd, buf, len);
}
#endif

/* ---- shared handler pieces ---------------------------------------------- */

/* AT_FDCWD and the AT_* flag bits are ABI-identical on i386 and
 * aarch64 (asm-generic values), so dirfd/flags pass through 1:1. */
static int xlate_dirfd(uint32_t guest_dfd)
{
    if (guest_dfd == (uint32_t)AT_FDCWD) {
        return AT_FDCWD;
    }
    return (int)(int32_t)guest_dfd;
}

#define L2A_PATH_MAX 4096U

/* Guest NULL-page guard, a32rt style: pointer arguments below the first
 * page are faults, not window addresses. */
static int bad_ptr(uint32_t va)
{
    return va < 0x1000U;
}

/* stat64 family core: fetch path, host fstatat, convert, copy out. */
static int64_t stat_path(i686_ctx_t *ctx, int dirfd, uint32_t path_va,
                         uint32_t buf_va, int flags)
{
    char path[L2A_PATH_MAX];
    struct stat st;
    i686_stat64_t gs;

    if (bad_ptr(path_va) || bad_ptr(buf_va)) {
        return -EFAULT;
    }
    int r = i686_fetch_cstr(ctx, path_va, path, sizeof(path));
    if (r != 0) {
        return r;
    }
    {
        extern int i686_systrace_on(void);
        if (i686_systrace_on()) {
            (void)fprintf(stderr, "STAT %s\n", path);
        }
    }
    /* Absolute guest paths resolve under --sysroot first (open_guest
     * model; dash `test -x` stats sysroot paths, RC7b). */
    if (path[0] == '/' && dirfd == AT_FDCWD && ctx->sysroot != NULL &&
        ctx->sysroot[0] != '\0') {
        char sp[L2A_PATH_MAX];
        size_t sl = strlen(ctx->sysroot);

        if (sl + strlen(path) < sizeof sp) {
            memcpy(sp, ctx->sysroot, sl);
            strcpy(sp + sl, path);
            if (fstatat(AT_FDCWD, sp, &st, flags) == 0) {
                goto have_stat;
            }
        }
    }
    if (fstatat(dirfd, path, &st, flags) != 0) {
        return err_neg();
    }
have_stat:;
    i686_stat64_from_host(&gs, &st);
    return i686_copy_to_guest(ctx, buf_va, &gs, sizeof(gs));
}

/* ---- statx(383): guest wire struct ---------------------------------------
 *
 * include/uapi/linux/stat.h struct statx (statx_timestamp is
 * {s64 tv_sec; u32 tv_nsec; s32 __pad} = 16 B).  Every field is
 * fixed-width and each u64 lands on an 8-byte offset on i386 as well
 * (its 4-byte u64 alignment never binds here), so the layout is
 * byte-identical on the aarch64 host and the host syscall's buffer
 * transfers to the guest verbatim.  Total 0x100 = 256 bytes — the size
 * every 4.11+ kernel copies to the user buffer (later kernels carved
 * stx_mnt_id and the dio_align fields out of the spare tail without
 * growing it). */

typedef struct __attribute__((packed)) {
    uint32_t stx_mask;             /* 0x000 what results were written  */
    uint32_t stx_blksize;          /* 0x004 preferred I/O size         */
    uint64_t stx_attributes;       /* 0x008 file attribute flags       */
    uint32_t stx_nlink;            /* 0x010 hard links                 */
    uint32_t stx_uid;              /* 0x014 owner uid                  */
    uint32_t stx_gid;              /* 0x018 owner gid                  */
    uint16_t stx_mode;             /* 0x01c file mode (type + perms)   */
    uint16_t stx_spare0;           /* 0x01e                            */
    uint64_t stx_ino;              /* 0x020 inode number               */
    uint64_t stx_size;             /* 0x028 file size                  */
    uint64_t stx_blocks;           /* 0x030 512-byte blocks allocated      */
    uint64_t stx_attributes_mask;  /* 0x038 supported attribute bits   */
    uint64_t stx_atime_sec;        /* 0x040 last access                */
    uint32_t stx_atime_nsec;       /* 0x048                            */
    uint32_t stx_atime_pad;        /* 0x04c                            */
    uint64_t stx_btime_sec;        /* 0x050 creation                   */
    uint32_t stx_btime_nsec;       /* 0x058                            */
    uint32_t stx_btime_pad;        /* 0x05c                            */
    uint64_t stx_ctime_sec;        /* 0x060 last status change         */
    uint32_t stx_ctime_nsec;       /* 0x068                            */
    uint32_t stx_ctime_pad;        /* 0x06c                            */
    uint64_t stx_mtime_sec;        /* 0x070 last data modification     */
    uint32_t stx_mtime_nsec;       /* 0x078                            */
    uint32_t stx_mtime_pad;        /* 0x07c                            */
    uint32_t stx_rdev_major;       /* 0x080 device id of special file  */
    uint32_t stx_rdev_minor;       /* 0x084                            */
    uint32_t stx_dev_major;        /* 0x088 device containing the file */
    uint32_t stx_dev_minor;        /* 0x08c                            */
    uint64_t stx_mnt_id;           /* 0x090 mount id (5.8+)            */
    uint32_t stx_dio_mem_align;    /* 0x098 dio buffer alignment (6.9+) */
    uint32_t stx_dio_offset_align; /* 0x09c dio offset alignment       */
    uint64_t stx_spare1[12];       /* 0x0a0 kernel spare tail          */
} i686_statx_t;

_Static_assert(offsetof(i686_statx_t, stx_mask) == 0x000, "statx mask @0x000");
_Static_assert(offsetof(i686_statx_t, stx_blksize) == 0x004, "statx blksize @0x004");
_Static_assert(offsetof(i686_statx_t, stx_attributes) == 0x008, "statx attributes @0x008");
_Static_assert(offsetof(i686_statx_t, stx_nlink) == 0x010, "statx nlink @0x010");
_Static_assert(offsetof(i686_statx_t, stx_uid) == 0x014, "statx uid @0x014");
_Static_assert(offsetof(i686_statx_t, stx_gid) == 0x018, "statx gid @0x018");
_Static_assert(offsetof(i686_statx_t, stx_mode) == 0x01c, "statx mode @0x01c");
_Static_assert(offsetof(i686_statx_t, stx_spare0) == 0x01e, "statx spare0 @0x01e");
_Static_assert(offsetof(i686_statx_t, stx_ino) == 0x020, "statx ino @0x020");
_Static_assert(offsetof(i686_statx_t, stx_size) == 0x028, "statx size @0x028");
_Static_assert(offsetof(i686_statx_t, stx_blocks) == 0x030, "statx blocks @0x030");
_Static_assert(offsetof(i686_statx_t, stx_attributes_mask) == 0x038, "statx attributes_mask @0x038");
_Static_assert(offsetof(i686_statx_t, stx_atime_sec) == 0x040, "statx atime @0x040");
_Static_assert(offsetof(i686_statx_t, stx_atime_nsec) == 0x048, "statx atime_nsec @0x048");
_Static_assert(offsetof(i686_statx_t, stx_atime_pad) == 0x04c, "statx atime pad @0x04c");
_Static_assert(offsetof(i686_statx_t, stx_btime_sec) == 0x050, "statx btime @0x050");
_Static_assert(offsetof(i686_statx_t, stx_btime_nsec) == 0x058, "statx btime_nsec @0x058");
_Static_assert(offsetof(i686_statx_t, stx_ctime_sec) == 0x060, "statx ctime @0x060");
_Static_assert(offsetof(i686_statx_t, stx_ctime_nsec) == 0x068, "statx ctime_nsec @0x068");
_Static_assert(offsetof(i686_statx_t, stx_mtime_sec) == 0x070, "statx mtime @0x070");
_Static_assert(offsetof(i686_statx_t, stx_mtime_nsec) == 0x078, "statx mtime_nsec @0x078");
_Static_assert(offsetof(i686_statx_t, stx_rdev_major) == 0x080, "statx rdev_major @0x080");
_Static_assert(offsetof(i686_statx_t, stx_rdev_minor) == 0x084, "statx rdev_minor @0x084");
_Static_assert(offsetof(i686_statx_t, stx_dev_major) == 0x088, "statx dev_major @0x088");
_Static_assert(offsetof(i686_statx_t, stx_dev_minor) == 0x08c, "statx dev_minor @0x08c");
_Static_assert(offsetof(i686_statx_t, stx_mnt_id) == 0x090, "statx mnt_id @0x090");
_Static_assert(offsetof(i686_statx_t, stx_dio_mem_align) == 0x098, "statx dio_mem_align @0x098");
_Static_assert(offsetof(i686_statx_t, stx_dio_offset_align) == 0x09c, "statx dio_offset_align @0x09c");
_Static_assert(sizeof(i686_statx_t) == 0x100, "statx wire struct is 256 B");

/* ---- handlers (args in EBX, ECX, EDX, ESI, EDI, EBP) -------------------- */

static int64_t h_stat64(i686_ctx_t *ctx)
{
    return stat_path(ctx, AT_FDCWD, ctx->gpr[I686_REG_EBX],
                     ctx->gpr[I686_REG_ECX], 0);
}

static int64_t h_lstat64(i686_ctx_t *ctx)
{
    return stat_path(ctx, AT_FDCWD, ctx->gpr[I686_REG_EBX],
                     ctx->gpr[I686_REG_ECX], AT_SYMLINK_NOFOLLOW);
}

static int64_t h_fstat64(i686_ctx_t *ctx)
{
    struct stat st;
    i686_stat64_t gs;
    uint32_t buf_va = ctx->gpr[I686_REG_ECX];

    if (bad_ptr(buf_va)) {
        return -EFAULT;
    }
    if (fstat((int)(int32_t)ctx->gpr[I686_REG_EBX], &st) != 0) {
        return err_neg();
    }
    i686_stat64_from_host(&gs, &st);
    return i686_copy_to_guest(ctx, buf_va, &gs, sizeof(gs));
}

static int64_t h_fstatat64(i686_ctx_t *ctx)
{
    return stat_path(ctx, xlate_dirfd(ctx->gpr[I686_REG_EBX]),
                     ctx->gpr[I686_REG_ECX], ctx->gpr[I686_REG_EDX],
                     (int)(int32_t)ctx->gpr[I686_REG_ESI]);
}

static int64_t h_statfs(i686_ctx_t *ctx)
{
    char path[L2A_PATH_MAX];
    struct statfs sfs;
    i686_statfs_t g;
    uint32_t buf_va = ctx->gpr[I686_REG_ECX];

    if (bad_ptr(ctx->gpr[I686_REG_EBX]) || bad_ptr(buf_va)) {
        return -EFAULT;
    }
    int r = i686_fetch_cstr(ctx, ctx->gpr[I686_REG_EBX], path, sizeof(path));
    if (r != 0) {
        return r;
    }
    if (statfs(path, &sfs) != 0) {
        return err_neg();
    }
    i686_statfs_from_host(&g, &sfs);
    return i686_copy_to_guest(ctx, buf_va, &g, sizeof(g));
}

static int64_t h_fstatfs(i686_ctx_t *ctx)
{
    struct statfs sfs;
    i686_statfs_t g;
    uint32_t buf_va = ctx->gpr[I686_REG_ECX];

    if (bad_ptr(buf_va)) {
        return -EFAULT;
    }
    if (fstatfs((int)(int32_t)ctx->gpr[I686_REG_EBX], &sfs) != 0) {
        return err_neg();
    }
    i686_statfs_from_host(&g, &sfs);
    return i686_copy_to_guest(ctx, buf_va, &g, sizeof(g));
}

/* statfs64/fstatfs64: the i386 ABI is (path|fd, sz, buf) with sz == 84
 * (sizeof(struct statfs64) on i386); anything else is -EINVAL before
 * any guest dereference, mirroring the kernel's compat check. */
static int64_t h_statfs64(i686_ctx_t *ctx)
{
    char path[L2A_PATH_MAX];
    struct statfs sfs;
    i686_statfs64_t g;
    uint32_t sz     = ctx->gpr[I686_REG_ECX];
    uint32_t buf_va = ctx->gpr[I686_REG_EDX];

    if (sz != (uint32_t)sizeof(i686_statfs64_t)) {
        return -EINVAL;
    }
    if (bad_ptr(ctx->gpr[I686_REG_EBX]) || bad_ptr(buf_va)) {
        return -EFAULT;
    }
    int r = i686_fetch_cstr(ctx, ctx->gpr[I686_REG_EBX], path, sizeof(path));
    if (r != 0) {
        return r;
    }
    if (statfs(path, &sfs) != 0) {
        return err_neg();
    }
    i686_statfs64_from_host(&g, &sfs);
    return i686_copy_to_guest(ctx, buf_va, &g, sizeof(g));
}

static int64_t h_fstatfs64(i686_ctx_t *ctx)
{
    struct statfs sfs;
    i686_statfs64_t g;
    uint32_t sz     = ctx->gpr[I686_REG_ECX];
    uint32_t buf_va = ctx->gpr[I686_REG_EDX];

    if (sz != (uint32_t)sizeof(i686_statfs64_t)) {
        return -EINVAL;
    }
    if (bad_ptr(buf_va)) {
        return -EFAULT;
    }
    if (fstatfs((int)(int32_t)ctx->gpr[I686_REG_EBX], &sfs) != 0) {
        return err_neg();
    }
    i686_statfs64_from_host(&g, &sfs);
    return i686_copy_to_guest(ctx, buf_va, &g, sizeof(g));
}

static int64_t h_getdents64(i686_ctx_t *ctx)
{
    int      fd    = (int)(int32_t)ctx->gpr[I686_REG_EBX];
    uint32_t va    = ctx->gpr[I686_REG_ECX];
    uint32_t count = ctx->gpr[I686_REG_EDX];

    if (count > 0U && bad_ptr(va)) {
        return -EFAULT;
    }
    uint8_t *host = malloc(count > 0U ? (size_t)count : 1U);
    if (host == NULL) {
        return -ENOMEM;
    }
    ssize_t n = host_getdents64(fd, host, count);
    if (n < 0) {
        free(host);
        return err_neg();
    }
    (void)i686_dirent64_remap_offs(fd, host, (size_t)n);
    int r = i686_copy_to_guest(ctx, va, host, (size_t)n);
    free(host);
    return (r != 0) ? r : (int64_t)n;
}

static int64_t h_getdents(i686_ctx_t *ctx)
{
    int      fd    = (int)(int32_t)ctx->gpr[I686_REG_EBX];
    uint32_t va    = ctx->gpr[I686_REG_ECX];
    uint32_t count = ctx->gpr[I686_REG_EDX];

    if (count > 0U && bad_ptr(va)) {
        return -EFAULT;
    }

    /* Old records are strictly smaller than their 64-bit sources, so a
     * host buffer of the read size also bounds the output. */
    size_t host_size = (count > 32768U) ? 65536U : (size_t)count * 2U;
    if (host_size < 1024U) {
        host_size = 1024U;
    }
    uint8_t *host = malloc(host_size);
    uint8_t *out  = malloc(host_size);
    if (host == NULL || out == NULL) {
        free(host);
        free(out);
        return -ENOMEM;
    }

    uint64_t resume = 0U;
    off_t    cur    = lseek(fd, 0, SEEK_CUR);
    if (cur >= 0) {
        resume = (uint64_t)cur;
    }
    ssize_t n = host_getdents64(fd, host, host_size);
    if (n < 0) {
        free(host);
        free(out);
        return err_neg();
    }

    int    truncated = 0;
    size_t written =
        i686_dirent_old_from64(fd, host, (size_t)n, out, count, &resume,
                               &truncated);
    if (truncated != 0) {
        /* Rewind to just after the last converted record so the next
         * call re-reads the record that did not fit. */
        off_t back = (resume <= (uint64_t)INT64_MAX) ? (off_t)resume
                                                     : (off_t)INT64_MAX;
        (void)lseek(fd, back, SEEK_SET);
    }
    int64_t ret;
    if (written == 0U && n > 0) {
        ret = -EINVAL; /* not even the first record fits */
    } else {
        ret = i686_copy_to_guest(ctx, va, out, written);
        if (ret == 0) {
            ret = (int64_t)written;
        }
    }
    free(host);
    free(out);
    return ret;
}

/* statx(383): (dirfd, path, flags, mask, buf) in EBX..EDI.  The AT_*
 * flag bits (AT_SYMLINK_NOFOLLOW 0x100, AT_NO_AUTOMOUNT 0x800,
 * AT_EMPTY_PATH 0x1000, AT_STATX_SYNC_* 0x6000) and the STATX_* mask
 * are arch-independent asm-generic values, so both pass through 1:1 and
 * the host kernel decides what to fill — its stx_mask reports that,
 * which is exactly the "honor the mask like the kernel" contract.  The
 * host buffer is the kernel's 256-byte copy plus headroom in case a
 * future kernel outgrows it; only the guest wire size is copied out.
 * macOS (the host-native unit build) has no SYS_statx: the shim keeps
 * the handler compiled and reports -ENOSYS there. */
static int64_t h_statx(i686_ctx_t *ctx)
{
    char path[L2A_PATH_MAX];
    _Alignas(8) uint8_t stx[512];
    int dirfd = xlate_dirfd(ctx->gpr[I686_REG_EBX]);
    uint32_t flags = ctx->gpr[I686_REG_EDX];
    uint32_t mask = ctx->gpr[I686_REG_ESI];
    uint32_t buf_va = ctx->gpr[I686_REG_EDI];

    if (bad_ptr(ctx->gpr[I686_REG_ECX]) || bad_ptr(buf_va)) {
        return -EFAULT;
    }
    int r = i686_fetch_cstr(ctx, ctx->gpr[I686_REG_ECX], path, sizeof(path));
    if (r != 0) {
        return r;
    }
    {
        extern int i686_systrace_on(void);
        if (i686_systrace_on()) {
            (void)fprintf(stderr, "STATX %s\n", path);
        }
    }
#if defined(__APPLE__) && defined(__MACH__)
    (void)dirfd;
    (void)flags;
    (void)mask;
    return -ENOSYS;
#else
    memset(stx, 0, sizeof(stx));
    /* Absolute guest paths resolve under --sysroot first (stat_path
     * model), AT_FDCWD only. */
    if (path[0] == '/' && dirfd == AT_FDCWD && ctx->sysroot != NULL &&
        ctx->sysroot[0] != '\0') {
        char sp[L2A_PATH_MAX];
        size_t sl = strlen(ctx->sysroot);

        if (sl + strlen(path) < sizeof sp) {
            memcpy(sp, ctx->sysroot, sl);
            strcpy(sp + sl, path);
            if (syscall(SYS_statx, dirfd, sp, (unsigned int)flags,
                        (unsigned int)mask, stx) == 0) {
                goto have_statx;
            }
        }
    }
    if (syscall(SYS_statx, dirfd, path, (unsigned int)flags,
                (unsigned int)mask, stx) < 0) {
        return err_neg();
    }
have_statx:;
    return i686_copy_to_guest(ctx, buf_va, stx, sizeof(i686_statx_t));
#endif
}


/* ---- registration -------------------------------------------------------- */

void i686_syscalls_stat_init(void)
{
    i686_sys_register((long)L2A_NR_statfs, h_statfs);
    i686_sys_register((long)L2A_NR_fstatfs, h_fstatfs);
    i686_sys_register((long)L2A_NR_statfs64, h_statfs64);
    i686_sys_register((long)L2A_NR_fstatfs64, h_fstatfs64);
    i686_sys_register((long)L2A_NR_stat64, h_stat64);
    i686_sys_register((long)L2A_NR_lstat64, h_lstat64);
    i686_sys_register((long)L2A_NR_fstat64, h_fstat64);
    i686_sys_register((long)L2A_NR_fstatat64, h_fstatat64);
    i686_sys_register((long)L2A_NR_getdents, h_getdents);
    i686_sys_register((long)L2A_NR_getdents64, h_getdents64);
    i686_sys_register((long)L2A_NR_statx, h_statx);
}
