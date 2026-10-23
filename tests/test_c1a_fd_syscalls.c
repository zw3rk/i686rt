/*
 * tests/test_c1a_fd_syscalls.c — C1a fd-syscall fixture (static i386 musl)
 *
 * Exercises the five C1a syscalls from guest userspace the way real
 * consumers do, plus raw-syscall ABI pins:
 *
 *   _llseek(140)    fseeko/ftello past 2 GiB on a sparse file
 *                   (musl i386 lseek routes through _llseek) + raw
 *                   calls pinning (fd, hi, lo, result*, whence) — the
 *                   64-bit result is written through the result
 *                   POINTER, and a bad result pointer is -EFAULT.
 *   readv(145)      scatter read of a known pattern (incl. a zero-len
 *                   iov and short-EOF partial return).
 *   msync(144)      MAP_SHARED modify + MS_SYNC/MS_ASYNC, and -EINVAL
 *                   for a flag bit outside MS_ASYNC/MS_INVALIDATE/
 *                   MS_SYNC.
 *   ftruncate64(194) grow/shrink past 2 GiB and past 4 GiB (hi word).
 *   statx(383)      raw syscall, STATX_BASIC_STATS fields, ENOENT.
 *
 * Build (linux/386 alpine oracle):
 *   cc -std=c11 -D_POSIX_C_SOURCE=200809L -static -O2 -Wall -Wextra \
 *       -o fix_c1a tests/test_c1a_fd_syscalls.c
 * Run:  fix_c1a <scratch-dir>   (all files are created there)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

/* musl hides syscall(3) under _GNU_SOURCE; declare verbatim. */
long syscall(long, ...);

#ifndef SYS_statx
#define SYS_statx 383 /* include/uapi/asm-generic/unistd.h (i386 + arm64) */
#endif
#ifndef SYS__llseek
#define SYS__llseek 140
#endif

#ifndef STATX_TYPE
#define STATX_TYPE 0x0001U
#define STATX_MODE 0x0002U
#define STATX_NLINK 0x0004U
#define STATX_SIZE 0x0200U
#define STATX_BLOCKS 0x0400U
#define STATX_BASIC_STATS 0x07ffU
#endif

/* ---- guest wire struct statx (include/uapi/linux/stat.h) ----------------
 * Fixed-width fields, every u64 on an 8-byte offset on i386 too, so the
 * i386 layout is what the fixture sees natively. */

struct statx_ts {
    int64_t sec;
    uint32_t nsec;
    int32_t pad;
};

struct statxg {
    uint32_t mask;      /* 0x00 */
    uint32_t blksize;   /* 0x04 */
    uint64_t attrs;     /* 0x08 */
    uint32_t nlink;     /* 0x10 */
    uint32_t uid;       /* 0x14 */
    uint32_t gid;       /* 0x18 */
    uint16_t mode;      /* 0x1c */
    uint16_t spare0;    /* 0x1e */
    uint64_t ino;       /* 0x20 */
    uint64_t size;      /* 0x28 */
    uint64_t blocks;    /* 0x30 */
    uint64_t attrsmask; /* 0x38 */
    struct statx_ts atime, btime, ctime, mtime; /* 0x40..0x7f */
    uint32_t rdev_major, rdev_minor, dev_major, dev_minor; /* 0x80 */
    uint64_t mnt_id;    /* 0x90 */
    uint32_t dio_mem_align, dio_offset_align; /* 0x98 */
    uint64_t spare[12]; /* 0xa0..0xff */
};

static int fails;

#define CHECK(cond)                                                     \
    do {                                                                \
        if (!(cond)) {                                                  \
            printf("FAIL %s:%d: %s (errno=%d)\n", __func__, __LINE__,   \
                   #cond, errno);                                       \
            fails++;                                                    \
        }                                                               \
    } while (0)

#define BIG  (((off_t)3) << 30) /* 3 GiB: past the signed i386 off_t range */
#define BIG2 (((off_t)5) << 30) /* 5 GiB: _llseek offset_hi = 1 */

static char dirbuf[4096];

static void makepath(const char *name, char *out, size_t outsz)
{
    snprintf(out, outsz, "%s/%s", dirbuf, name);
}

/* ---- _llseek(140) -------------------------------------------------------- */

static int my_llseek(int fd, uint32_t hi, uint32_t lo, int64_t *res,
                     uint32_t whence)
{
    return (int)syscall(SYS__llseek, fd, hi, lo, res, whence);
}

static void test_llseek(void)
{
    char p[4352]; /* dirbuf(<=4096) + / + name + NUL */
    FILE *f;
    int fd;
    int64_t res = -1;

    makepath("c1a_big.bin", p, sizeof(p));
    f = fopen(p, "wb+");
    CHECK(f != NULL);
    if (f == NULL) {
        return;
    }
    CHECK(fseeko(f, BIG, SEEK_SET) == 0);
    CHECK(ftello(f) == BIG);
    CHECK(fputc('A', f) == 'A');
    CHECK(fseeko(f, BIG2, SEEK_SET) == 0);
    CHECK(ftello(f) == BIG2);
    CHECK(fputc('B', f) == 'B');
    CHECK(fclose(f) == 0);

    /* libc readback: the whole point of the glibc stdio consumer case. */
    f = fopen(p, "rb");
    CHECK(f != NULL);
    CHECK(fseeko(f, BIG, SEEK_SET) == 0);
    CHECK(fgetc(f) == 'A');
    CHECK(fseeko(f, BIG2, SEEK_SET) == 0);
    CHECK(fgetc(f) == 'B');
    CHECK(fseeko(f, 0, SEEK_END) == 0);
    CHECK(ftello(f) == BIG2 + 1);
    fclose(f);

    /* Raw ABI pin: result comes back through the pointer, not eax. */
    fd = open(p, O_RDONLY);
    CHECK(fd >= 0);
    CHECK(my_llseek(fd, 0, (uint32_t)0xC0000000U, &res, 0 /* SET */) == 0);
    CHECK(res == BIG);
    CHECK(my_llseek(fd, 1, 0, &res, 0) == 0);
    CHECK(res == (((off_t)1) << 32)); /* 4 GiB: hi word is used */
    CHECK(my_llseek(fd, 0, 0, &res, 2 /* END */) == 0);
    CHECK(res == BIG2 + 1); /* stored result itself is past 4 GiB */
    errno = 0;
    CHECK(my_llseek(fd, 0, 0, &res, 3 /* bad whence */) == -1 &&
          errno == EINVAL);
    errno = 0;
    CHECK(my_llseek(fd, 0, 0, (int64_t *)0x4 /* guard page */, 0) == -1 &&
          errno == EFAULT);
    close(fd);
}

/* ---- readv(145) ----------------------------------------------------------- */

static void test_readv(void)
{
    char p[4352]; /* dirbuf(<=4096) + / + name + NUL */
    const char *seg1 = "alpha-beta-";
    const char *seg2 = "gamma-delta-epsilon-";
    const char *seg3 = "zeta.\n";
    char b1[5], b3[6];
    char big[64 * 1024];
    struct iovec iov[4];
    ssize_t n;
    int fd;

    makepath("c1a_scatter.bin", p, sizeof(p));
    fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    CHECK(write(fd, seg1, strlen(seg1)) == (ssize_t)strlen(seg1));
    CHECK(write(fd, seg2, strlen(seg2)) == (ssize_t)strlen(seg2));
    CHECK(write(fd, seg3, strlen(seg3)) == (ssize_t)strlen(seg3));
    CHECK(lseek(fd, 0, SEEK_SET) == 0);

    memset(b1, 0, sizeof(b1));
    memset(big, 0, sizeof(big));
    memset(b3, 0, sizeof(b3));
    /* 5 + 20 + 0 + 6 = 31 of the 37 file bytes: the read must fill the
     * iovs in order and stop there (partial-transfer semantics). */
    iov[0].iov_base = b1;
    iov[0].iov_len = 5;                       /* "alpha" */
    iov[1].iov_base = big;                    /* middle slab */
    iov[1].iov_len = 20;                      /* "-beta-gamma-delta-ep" */
    iov[2].iov_base = NULL;                   /* zero-len iov is skipped */
    iov[2].iov_len = 0;
    iov[3].iov_base = b3;
    iov[3].iov_len = 6;                       /* "silon-" */
    n = readv(fd, iov, 4);
    CHECK(n == 31);
    CHECK(memcmp(b1, "alpha", 5) == 0);
    CHECK(memcmp(big, "-beta-gamma-delta-ep", 20) == 0);
    CHECK(memcmp(b3, "silon-", 6) == 0);

    /* Whole file through one 64 KiB iov (crosses several 512-byte
     * staging chunks in the translator). */
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    iov[0].iov_base = big;
    iov[0].iov_len = sizeof(big);
    n = readv(fd, iov, 1);
    CHECK(n == 37);
    CHECK(memcmp(big, "alpha-beta-gamma-delta-epsilon-zeta.\n", 37) == 0);

    /* 5000-byte pattern through a 64 KiB iov: 5000 crosses ten 512-byte
     * staging chunks inside one iov. */
    {
        char pat[4096 + 904];
        char back[sizeof(pat)];
        char q[4352];
        size_t i;

        for (i = 0; i < sizeof(pat); i++) {
            pat[i] = (char)('0' + (i % 10));
        }
        makepath("c1a_pattern.bin", q, sizeof(q));
        int fd2 = open(q, O_RDWR | O_CREAT | O_TRUNC, 0600);
        CHECK(fd2 >= 0);
        CHECK(write(fd2, pat, sizeof(pat)) == (ssize_t)sizeof(pat));
        CHECK(lseek(fd2, 0, SEEK_SET) == 0);
        iov[0].iov_base = back;
        iov[0].iov_len = sizeof(back);
        n = readv(fd2, iov, 1);
        CHECK(n == (ssize_t)sizeof(pat));
        CHECK(memcmp(back, pat, sizeof(pat)) == 0);
        close(fd2);
    }

    /* At EOF readv returns 0. */
    CHECK(lseek(fd, 0, SEEK_END) == 37); /* returns the new offset */
    iov[0].iov_base = big;
    iov[0].iov_len = sizeof(big);
    n = readv(fd, iov, 1);
    CHECK(n == 0);

    close(fd);
}

/* ---- msync(144) ------------------------------------------------------------ */

static void test_msync(void)
{
    char p[4352]; /* dirbuf(<=4096) + / + name + NUL */
    uint8_t *map;
    int fd;

    makepath("c1a_mapped.bin", p, sizeof(p));
    fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    CHECK(ftruncate(fd, 8192) == 0);
    map = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(map != MAP_FAILED);
    if (map == MAP_FAILED) {
        close(fd);
        return;
    }
    map[0] = 0x5A;
    map[4095] = 0xA5;
    CHECK(msync(map, 8192, MS_SYNC) == 0);
    CHECK(msync(map, 8192, MS_ASYNC) == 0);
    errno = 0;
    CHECK(msync(map, 8192, 0x8 /* unknown bit */) == -1 && errno == EINVAL);
    CHECK(munmap(map, 8192) == 0);

    /* The MS_SYNC'd stores are visible through the file. */
    uint8_t rbuf[2];
    CHECK(pread(fd, rbuf, 1, 0) == 1 && rbuf[0] == 0x5A);
    CHECK(pread(fd, rbuf, 1, 4095) == 1 && rbuf[0] == 0xA5);
    close(fd);
}

/* ---- ftruncate64(194) ------------------------------------------------------- */

static void test_ftruncate64(void)
{
    char p[4352]; /* dirbuf(<=4096) + / + name + NUL */
    struct stat st;
    off_t len4g = (((off_t)1) << 32) + 8; /* crosses the hi word */
    int fd;

    makepath("c1a_trunc.bin", p, sizeof(p));
    fd = open(p, O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    CHECK(ftruncate(fd, BIG) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == BIG);
    CHECK(ftruncate(fd, len4g) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == len4g);
    CHECK(ftruncate(fd, 7) == 0);
    CHECK(fstat(fd, &st) == 0 && st.st_size == 7);
    errno = 0;
    CHECK(ftruncate(fd, -1) == -1 && errno == EINVAL);
    close(fd);
}

/* ---- statx(383) -------------------------------------------------------------- */

static void test_statx(void)
{
    char p[4352]; /* dirbuf(<=4096) + / + name + NUL */
    struct statxg sx;
    long r;

    makepath("c1a_scatter.bin", p, sizeof(p));
    memset(&sx, 0, sizeof(sx));
    r = syscall(SYS_statx, -100 /* AT_FDCWD */, p, 0,
                STATX_BASIC_STATS, &sx);
    CHECK(r == 0);
    if (r != 0) {
        return;
    }
    CHECK((sx.mask & STATX_BASIC_STATS) == STATX_BASIC_STATS);
    CHECK(S_ISREG(sx.mode));
    CHECK(sx.size == (uint64_t)(strlen("alpha-beta-") +
                                strlen("gamma-delta-epsilon-") +
                                strlen("zeta.\n")));
    CHECK(sx.nlink == 1);
    CHECK(sx.ino != 0);
    CHECK(sx.blksize > 0);
    CHECK(sx.atime.sec > 0);
    CHECK(sx.mtime.sec > 0);

    /* Follow-symlink-off flag is asm-generic 0x100 on both arches. */
    memset(&sx, 0, sizeof(sx));
    r = syscall(SYS_statx, -100, p, 0x100 /* AT_SYMLINK_NOFOLLOW */,
                STATX_BASIC_STATS, &sx);
    CHECK(r == 0 && S_ISREG(sx.mode));

    errno = 0;
    memset(&sx, 0, sizeof(sx));
    makepath("c1a_missing.bin", p, sizeof(p));
    r = syscall(SYS_statx, -100, p, 0, STATX_BASIC_STATS, &sx);
    CHECK(r == -1 && errno == ENOENT);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <scratch-dir>\n", argv[0]);
        return 2;
    }
    snprintf(dirbuf, sizeof(dirbuf), "%s", argv[1]);

    test_llseek();
    test_readv();
    test_msync();
    test_ftruncate64();
    test_statx();

    if (fails != 0) {
        printf("C1a fd syscalls: %d FAILURES\n", fails);
        return 1;
    }
    printf("C1a fd syscalls: ALL PASS (_llseek readv msync ftruncate64 statx)\n");
    return 0;
}
