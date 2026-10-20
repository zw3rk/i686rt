/*
 * tests/unit/test_l2a.c — host-native unit driver for the L2a module
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Links tests/unit/test_l2a.c + src/os/sys_stat.c + src/os/marshal.c
 * (clang, macOS host): a fake 64 KiB guest window, hand-crafted host
 * stat/statfs buffers driven through the module converters, registry
 * routing through i686_sys_dispatch for the sz validation and a live
 * fstat64/statfs64 round trip, and synthetic getdents64 batches for the
 * old-wire conversion plus the d_off cookie-remap stability. Byte-exact
 * guest buffers are asserted via memcmp at ABI offsets.
 *
 * Compile:
 *   clang -std=c11 -Wall -Wextra -Werror=vla -pedantic \
 *       -Isrc -Iinclude -o /tmp/test_l2a \
 *       tests/unit/test_l2a.c src/os/sys_stat.c src/os/marshal.c
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <sys/mount.h>
#define T_HOST_FS_FSID_SET(s, a, b) \
    do {                            \
        (s)->f_fsid.val[0] = (a);   \
        (s)->f_fsid.val[1] = (b);   \
    } while (0)
#define T_HOST_NAMEMAX 255U /* macOS statfs has no f_namelen/f_frsize */
#define T_HOST_FRSIZE_FROM(s) ((uint32_t)(s)->f_bsize)
#define T_HOST_ATIM(s, i) (&(s)->st_atimespec)
#define T_HOST_MTIM(s, i) (&(s)->st_mtimespec)
#define T_HOST_CTIM(s, i) (&(s)->st_ctimespec)
#else
#include <sys/statfs.h>
#define T_HOST_FS_FSID_SET(s, a, b)  \
    do {                             \
        (s)->f_fsid.__val[0] = (a);  \
        (s)->f_fsid.__val[1] = (b);  \
    } while (0)
#define T_HOST_NAMEMAX 255U /* crafted; set via the same shim below */
#define T_HOST_FRSIZE_FROM(s) ((uint32_t)(s)->f_frsize)
#define T_HOST_ATIM(s, i) (&(s)->st_atim)
#define T_HOST_MTIM(s, i) (&(s)->st_mtim)
#define T_HOST_CTIM(s, i) (&(s)->st_ctim)
#endif

#include "i686rt.h"
#include "os/marshal.h"

/* macOS system headers define st_atime/st_mtime/st_ctime/sa_handler as
 * macros; the frozen i386 layouts use them as plain field names. */
#undef st_atime
#undef st_mtime
#undef st_ctime
#undef sa_handler

#include "os/structs_i386.h"

/* Internal converters exercised directly (per the lane card). */
extern void   i686_stat64_from_host(i686_stat64_t *dst,
                                    const struct stat *src);
extern void   i686_statfs_from_host(i686_statfs_t *dst,
                                    const struct statfs *src);
extern void   i686_statfs64_from_host(i686_statfs64_t *dst,
                                      const struct statfs *src);
extern size_t i686_dirent64_remap_offs(int fd, uint8_t *buf, size_t len);
extern size_t i686_dirent_old_from64(int fd, const uint8_t *in,
                                     size_t in_len, uint8_t *out,
                                     size_t out_cap, uint64_t *host_resume,
                                     int *truncated);

/* Rows of the authoritative table in src/os/syscalls_i386.h. */
#define T_NR_fstat64   197L
#define T_NR_statfs64  268L

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

/* ---- fixture: fake guest window ---------------------------------------- */

#define WIN_SIZE 0x10000U

static uint8_t *g_win;

static uint8_t *mem(uint32_t va)
{
    return (uint8_t *)(g_win + va);
}

static uint32_t ld32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t ld64(const uint8_t *p)
{
    return (uint64_t)ld32(p) | ((uint64_t)ld32(p + 4) << 32);
}

static i686_ctx_t *new_ctx(void)
{
    i686_ctx_t *ctx = calloc(1U, sizeof(*ctx));
    if (ctx == NULL) {
        fprintf(stderr, "L2A FAILED: out of memory\n");
        exit(1);
    }
    ctx->guest_base = (uint64_t)(uintptr_t)g_win;
    return ctx;
}

/* ---- synthetic host getdents64 records ----------------------------------
 * Packed little-endian, exactly as an aarch64 host kernel emits them
 * (reclen = ALIGN(19 + namlen + 1, 8), d_name at offset 19). */

static size_t put_d64(uint8_t *buf, size_t off, uint64_t ino, uint64_t doff,
                      uint8_t type, const char *name)
{
    size_t namlen = strlen(name);
    size_t reclen = (19U + namlen + 1U + 7U) & ~(size_t)7U;
    uint16_t rl   = (uint16_t)reclen;

    memset(buf + off, 0, reclen);
    memcpy(buf + off + 0U, &ino, sizeof(ino));
    memcpy(buf + off + 8U, &doff, sizeof(doff));
    memcpy(buf + off + 16U, &rl, sizeof(rl));
    buf[off + 18U] = type;
    memcpy(buf + off + 19U, name, namlen + 1U);
    return reclen;
}

/* Independent oracle for old-getdents(141) wire records: d_ino u32 @0,
 * d_off u32 @4, d_reclen u16 @8, name @10, d_type at reclen-1,
 * reclen = ALIGN(10 + namlen + 2, 4). */
static size_t put_old(uint8_t *buf, size_t off, uint32_t ino, uint32_t doff,
                      uint8_t type, const char *name)
{
    size_t namlen = strlen(name);
    size_t reclen = (10U + namlen + 2U + 3U) & ~(size_t)3U;
    uint16_t rl   = (uint16_t)reclen;

    memset(buf + off, 0, reclen);
    memcpy(buf + off + 0U, &ino, sizeof(ino));
    memcpy(buf + off + 4U, &doff, sizeof(doff));
    memcpy(buf + off + 8U, &rl, sizeof(rl));
    memcpy(buf + off + 10U, name, namlen + 1U);
    buf[off + reclen - 1U] = type;
    return reclen;
}

/* ---- scenarios ----------------------------------------------------------- */

static void t_stat64_layout(void)
{
    /* Frozen-header ABI offsets (kernel stat64; see src/os/sys_stat.c). */
    CHECK(offsetof(i686_stat64_t, st_dev) == 0U);
    CHECK(offsetof(i686_stat64_t, st_ino_lo) == 12U);
    CHECK(offsetof(i686_stat64_t, st_mode) == 16U);
    CHECK(offsetof(i686_stat64_t, st_nlink) == 20U);
    CHECK(offsetof(i686_stat64_t, st_uid) == 24U);
    CHECK(offsetof(i686_stat64_t, st_gid) == 28U);
    CHECK(offsetof(i686_stat64_t, st_rdev) == 32U);
    CHECK(offsetof(i686_stat64_t, st_size) == 44U);
    CHECK(offsetof(i686_stat64_t, st_blksize) == 52U);
    CHECK(offsetof(i686_stat64_t, st_blocks) == 56U);
    CHECK(offsetof(i686_stat64_t, st_atime) == 64U);
    CHECK(offsetof(i686_stat64_t, st_atime_nsec) == 68U);
    CHECK(offsetof(i686_stat64_t, st_mtime) == 72U);
    CHECK(offsetof(i686_stat64_t, st_mtime_nsec) == 76U);
    CHECK(offsetof(i686_stat64_t, st_ctime) == 80U);
    CHECK(offsetof(i686_stat64_t, st_ctime_nsec) == 84U);
    CHECK(offsetof(i686_stat64_t, st_ino) == 88U);
    CHECK(sizeof(i686_stat64_t) == 96U);

    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_dev     = 0x1234;
    st.st_ino     = 0x1122334455667788ULL;
    st.st_mode    = 0x81EDU;
    st.st_nlink   = 7U;
    st.st_uid     = 1000U;
    st.st_gid     = 20U;
    st.st_rdev    = 0x901U;
    st.st_size    = (off_t)0x7FFFFFFFFFFFLL;
    st.st_blksize = 4096;
    st.st_blocks  = 40;
    T_HOST_ATIM(&st, 0)->tv_sec  = 1700000100;
    T_HOST_ATIM(&st, 0)->tv_nsec = 111111111;
    T_HOST_MTIM(&st, 0)->tv_sec  = 1700000200;
    T_HOST_MTIM(&st, 0)->tv_nsec = 222222222;
    T_HOST_CTIM(&st, 0)->tv_sec  = 1700000300;
    T_HOST_CTIM(&st, 0)->tv_nsec = 333333333;

    const i686_stat64_t exp = {
        .st_dev        = 0x1234U,
        .st_ino_lo     = 0x55667788U,
        .st_mode       = 0x81EDU,
        .st_nlink      = 7U,
        .st_uid        = 1000U,
        .st_gid        = 20U,
        .st_rdev       = 0x901U,
        .st_size       = (int64_t)0x7FFFFFFFFFFFLL,
        .st_blksize    = 4096U,
        .st_blocks     = 40U,
        .st_atime      = 1700000100U,
        .st_atime_nsec = 111111111U,
        .st_mtime      = 1700000200U,
        .st_mtime_nsec = 222222222U,
        .st_ctime      = 1700000300U,
        .st_ctime_nsec = 333333333U,
        .st_ino        = 0x1122334455667788ULL,
    };

    i686_stat64_t got;
    memset(&got, 0xAA, sizeof(got));
    i686_stat64_from_host(&got, &st);
    CHECK(memcmp(&got, &exp, sizeof(exp)) == 0);
    /* Spot-check the byte level at two offsets (pads must be zero). */
    CHECK(ld64((uint8_t *)&got + 88) == 0x1122334455667788ULL);
    CHECK(ld32((uint8_t *)&got + 12) == 0x55667788U);
    CHECK(ld32((uint8_t *)&got + 52) == 4096U);
}

static void t_statfs_layout(void)
{
    CHECK(sizeof(i686_statfs_t) == 64U);
    CHECK(sizeof(i686_statfs64_t) == 84U);
    CHECK(offsetof(i686_statfs_t, f_fsid) == 28U);
    CHECK(offsetof(i686_statfs_t, f_namelen) == 36U);
    CHECK(offsetof(i686_statfs64_t, f_blocks) == 8U);
    CHECK(offsetof(i686_statfs64_t, f_fsid) == 48U);
    CHECK(offsetof(i686_statfs64_t, f_namelen) == 56U);
    CHECK(offsetof(i686_statfs64_t, f_flags) == 64U);

    struct statfs sfs;
    memset(&sfs, 0, sizeof(sfs));
    sfs.f_type   = 0x01021994U;
    sfs.f_bsize  = 4096U;
    sfs.f_blocks = 100000U;
    sfs.f_bfree  = 60000U;
    sfs.f_bavail = 50000U;
    sfs.f_files  = 20000U;
    sfs.f_ffree  = 15000U;
    T_HOST_FS_FSID_SET(&sfs, (int32_t)0x11111111, (int32_t)0x22222222);
    sfs.f_flags = 0U;

    const uint32_t namelen = T_HOST_NAMEMAX;
    const uint32_t frsize  = T_HOST_FRSIZE_FROM(&sfs);

    i686_statfs_t got;
    memset(&got, 0xAA, sizeof(got));
    i686_statfs_from_host(&got, &sfs);
    CHECK(ld32((uint8_t *)&got + 0) == 0x01021994U);
    CHECK(ld32((uint8_t *)&got + 4) == 4096U);
    CHECK(ld32((uint8_t *)&got + 8) == 100000U);
    CHECK(ld32((uint8_t *)&got + 24) == 15000U);
    CHECK(ld32((uint8_t *)&got + 28) == 0x11111111U);
    CHECK(ld32((uint8_t *)&got + 32) == 0x22222222U);
    CHECK(ld32((uint8_t *)&got + 36) == namelen);
    CHECK(ld32((uint8_t *)&got + 40) == frsize);
    CHECK(ld32((uint8_t *)&got + 44) == 0U);
    /* bytes 48..63 (f_spare) zeroed by the converter */
    for (unsigned i = 48U; i < 64U; i++) {
        CHECK(((uint8_t *)&got)[i] == 0U);
    }

    i686_statfs64_t got64;
    memset(&got64, 0xAA, sizeof(got64));
    i686_statfs64_from_host(&got64, &sfs);
    CHECK(ld32((uint8_t *)&got64 + 0) == 0x01021994U);
    CHECK(ld32((uint8_t *)&got64 + 4) == 4096U);
    CHECK(ld64((uint8_t *)&got64 + 8) == 100000U);
    CHECK(ld64((uint8_t *)&got64 + 32) == 20000U);
    CHECK(ld64((uint8_t *)&got64 + 40) == 15000U);
    CHECK(ld32((uint8_t *)&got64 + 48) == 0x11111111U);
    CHECK(ld32((uint8_t *)&got64 + 52) == 0x22222222U);
    CHECK(ld32((uint8_t *)&got64 + 56) == namelen);
    CHECK(ld32((uint8_t *)&got64 + 60) == frsize);
    CHECK(ld32((uint8_t *)&got64 + 64) == 0U);
    for (unsigned i = 68U; i < 84U; i++) {
        CHECK(((uint8_t *)&got64)[i] == 0U);
    }
}

static void t_statfs64_sz_validation(void)
{
    i686_ctx_t *ctx = new_ctx();
    strcpy((char *)mem(0x2000U), "/");

    ctx->gpr[I686_REG_EBX] = 0x2000U;
    ctx->gpr[I686_REG_EDX] = 0x3000U;

    ctx->gpr[I686_REG_ECX] = 83U; /* != 84 */
    CHECK(i686_sys_dispatch(ctx, T_NR_statfs64) == -(int64_t)EINVAL);
    ctx->gpr[I686_REG_ECX] = 88U; /* the ARM value is not i386's */
    CHECK(i686_sys_dispatch(ctx, T_NR_statfs64) == -(int64_t)EINVAL);
    ctx->gpr[I686_REG_ECX] = 0U;
    CHECK(i686_sys_dispatch(ctx, T_NR_statfs64) == -(int64_t)EINVAL);

    /* Positive control through the registry: live host statfs("/"). */
    ctx->gpr[I686_REG_ECX] = 84U;
    int64_t r = i686_sys_dispatch(ctx, T_NR_statfs64);
    CHECK(r == 0);
    if (r == 0) {
        struct statfs host;
        CHECK(statfs("/", &host) == 0);
        CHECK(ld32(mem(0x3000U) + 4) == (uint32_t)host.f_bsize);
        CHECK(ld64(mem(0x3000U) + 8) == (uint64_t)host.f_blocks);
        CHECK(ld32(mem(0x3000U) + 56) == T_HOST_NAMEMAX);
    }
    free(ctx);
}

static void t_fstat64_route(void)
{
    int fd = open("/dev/null", O_RDONLY);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }

    i686_ctx_t *ctx = new_ctx();
    ctx->gpr[I686_REG_EBX] = (uint32_t)fd;
    ctx->gpr[I686_REG_ECX] = 0x4000U;
    CHECK(i686_sys_dispatch(ctx, T_NR_fstat64) == 0);

    struct stat host;
    CHECK(fstat(fd, &host) == 0);
    i686_stat64_t exp;
    i686_stat64_from_host(&exp, &host);
    CHECK(memcmp(mem(0x4000U), &exp, sizeof(exp)) == 0);
    CHECK(ld32(mem(0x4000U) + 16) == (uint32_t)host.st_mode);
    CHECK((ld32(mem(0x4000U) + 16) & S_IFMT) == S_IFCHR);
    CHECK(ld64(mem(0x4000U) + 32) == (uint64_t)host.st_rdev);

    close(fd);
    free(ctx);
}

static void t_dirent64_remap_stability(void)
{
    uint8_t batch1[256];
    uint8_t batch2[256];
    memset(batch1, 0xEE, sizeof(batch1));
    memset(batch2, 0xEE, sizeof(batch2));

    const uint64_t off_a = 0x0000000100000001ULL; /* >= cookie base */
    const uint64_t off_b = 0x0000000200000002ULL;
    const uint64_t off_c = 0x0000000300000003ULL;
    const uint64_t small = 0x100U; /* tmpfs-style: passes through */

    size_t len1 = put_d64(batch1, 0U, 0xABC00000042ULL, off_a, 4U, "foo");
    len1 += put_d64(batch1, len1, 0xABC00000043ULL, off_b, 4U, "bar.dir");
    len1 += put_d64(batch1, len1, 0xABC00000044ULL, small, 8U, "tiny");

    CHECK(i686_dirent64_remap_offs(7, batch1, len1) == len1);

    /* Record layout untouched except d_off; offsets per kernel dirent64. */
    CHECK(ld64(batch1 + 0U) == 0xABC00000042ULL);
    CHECK(ld64(batch1 + 8U) >= 0x70000000ULL &&
          ld64(batch1 + 8U) < 0x70000000ULL + 4096U);
    CHECK(batch1[16U] == (uint8_t)(24U & 0xFFU)); /* "foo" reclen 24 */
    CHECK(batch1[17U] == 0U);
    CHECK(batch1[18U] == 4U);
    CHECK(memcmp(batch1 + 19U, "foo", 4U) == 0);

    const uint64_t cookie_a = ld64(batch1 + 8U);       /* table idx 0 */
    const uint64_t cookie_b = ld64(batch1 + 8U + 24U); /* table idx 1 */
    CHECK(cookie_a == 0x70000000ULL);
    CHECK(cookie_b == 0x70000001ULL);
    CHECK(cookie_a != cookie_b);
    CHECK(ld64(batch1 + 8U + 24U + 32U) == small); /* passthrough */

    /* Batch 2 on the SAME fd: a repeated host offset must map to the
     * SAME guest cookie; a fresh one gets a fresh cookie. */
    size_t len2 = put_d64(batch2, 0U, 0xABC00000045ULL, off_b, 4U, "baz");
    len2 += put_d64(batch2, len2, 0xABC00000046ULL, off_c, 4U, "qux");
    (void)i686_dirent64_remap_offs(7, batch2, len2);
    CHECK(ld64(batch2 + 8U) == cookie_b);
    CHECK(ld64(batch2 + 8U + 24U) == 0x70000002ULL); /* fresh idx 2 */
}

static void t_dirent_old_wire(void)
{
    uint8_t host[512];
    uint8_t out[512];
    uint8_t exp[512];
    memset(host, 0, sizeof(host));

    const uint64_t off_a = 0x0000000100000001ULL;
    const uint64_t off_b = 0x0000000200000002ULL;
    const uint64_t off_c = 0x0000000300000003ULL;

    size_t hlen = put_d64(host, 0U, 0xAB000000CDULL, off_a, 4U, ".");
    hlen += put_d64(host, hlen, 0xAB000000CEULL, off_b, 4U, "..");
    hlen += put_d64(host, hlen, 0xAB000000CFULL, off_c, 8U, "a.txt");

    uint64_t resume    = 0U;
    int      truncated = 1;
    size_t   n = i686_dirent_old_from64(9, host, hlen, out, sizeof(out),
                                        &resume, &truncated);
    CHECK(truncated == 0);
    CHECK(n == 16U + 16U + 20U); /* ALIGN(10+1+2,4) + ALIGN(10+2+2,4) +
                                    ALIGN(10+5+2,4) */

    /* Rebuild the expected wire independently: d_off values are the
     * cookies established by the remap scenario above (fd 9 is a fresh
     * fd, so its cookies continue after that scenario's three entries),
     * and d_ino is the 64-bit host ino truncated to 32 bits. */
    size_t elen = put_old(exp, 0U, (uint32_t)0xAB000000CDULL,
                          0x70000000U + 3U, 4U, ".");
    elen += put_old(exp, elen, (uint32_t)0xAB000000CEULL,
                    0x70000000U + 4U, 4U, "..");
    elen += put_old(exp, elen, (uint32_t)0xAB000000CFULL,
                    0x70000000U + 5U, 8U, "a.txt");
    CHECK(n == elen);
    CHECK(memcmp(out, exp, n) == 0);
    CHECK(resume == off_c);
    CHECK(ld32(out + 16U + 16U) == 0xCFU); /* d_ino truncated */
    CHECK(out[16U + 16U + 10U] == 'a');
    CHECK(out[16U + 16U + 20U - 1U] == 8U); /* d_type at reclen-1 */

    /* Truncation: cap that fits only the first two records. */
    uint64_t r2    = 0U;
    int      tr    = 0;
    size_t   cap   = 16U + 16U;
    size_t   npart = i686_dirent_old_from64(9, host, hlen, out, cap, &r2,
                                            &tr);
    CHECK(tr == 1);
    CHECK(npart == cap);
    CHECK(memcmp(out, exp, cap) == 0);
    CHECK(r2 == off_b); /* resume at the last converted record's d_off */

    /* Not even the first record fits: zero bytes written, truncated. */
    size_t n0 = i686_dirent_old_from64(9, host, hlen, out, 8U, &r2, &tr);
    CHECK(tr == 1);
    CHECK(n0 == 0U);

    /* Cookie stability on the old path: a repeated host offset on the
     * same fd yields the same 32-bit guest d_off. */
    uint8_t host2[256];
    size_t  h2 = put_d64(host2, 0U, 0xAB000000D0ULL, off_c, 8U, "next");
    uint64_t r3    = 0U;
    int      tr3   = 0;
    size_t   n2 = i686_dirent_old_from64(9, host2, h2, out, sizeof(out),
                                         &r3, &tr3);
    CHECK(tr3 == 0);
    CHECK(n2 == 16U); /* ALIGN(10+4+2,4) */
    CHECK(ld32(out + 4U) == 0x70000000U + 5U);
}

int main(void)
{
    g_win = calloc(1U, WIN_SIZE);
    if (g_win == NULL) {
        fprintf(stderr, "L2A FAILED: out of memory\n");
        return 1;
    }
    i686_syscalls_stat_init();

    t_stat64_layout();
    t_statfs_layout();
    t_statfs64_sz_validation();
    t_fstat64_route();
    t_dirent64_remap_stability();
    t_dirent_old_wire();

    if (g_fail != 0) {
        fprintf(stderr, "L2A FAILED: %d of %d checks failed\n", g_fail,
                g_checks);
        return 1;
    }
    puts("L2A OK");
    return 0;
}
