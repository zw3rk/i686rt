/*
 * src/os/sys_pass_internal.h — Internal definitions for sys_pass
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686_SYS_PASS_INTERNAL_H
#define I686_SYS_PASS_INTERNAL_H

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "os/backend.h"
#include "os/marshal.h"
#include "os/proc.h"
#include "os/threads.h"
#include "vm/vm_file.h"
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/syscall.h>
long syscall(long, ...);
#endif
#ifndef __APPLE__
int pipe2(int [2], int);
#endif
#include <sys/types.h>
#include <unistd.h>

#include "i686rt.h"
#include "marshal.h"
#include "rt32/rt32.h"

/* Syscall numbers, values from the authoritative generated table in
 * src/os/syscalls_i386.h (quoted as [nr] {"name"}). */
#define NR_unlink        10U /* [10]  {"unlink"}       */
#define NR_open           5U /* [5]   {"open"}         */
#define NR_openat   295U /* [295] {"openat"} */
#define NR_writev         146U /* [146] {"writev"}       */
#define NR_readv          145U /* [145] {"readv"}        */
#define NR_close          6U /* [6]   {"close"}        */
#define NR_readlink      85U /* [85]  {"readlink"}     */
#define NR_lseek         19U /* [19]  {"lseek"}        */
#define NR__llseek      140U /* [140] {"_llseek"}      */
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
#define NR_pipe         42U /* [42]  {"pipe"}         */
#define NR_pipe2       331U /* [331] {"pipe2"}        */
#define NR_pread64     180U /* [180] {"pread64"}      */
#define NR_pwrite64    181U /* [181] {"pwrite64"}     */
#define NR_ftruncate64 194U /* [194] {"ftruncate64"}  */
#define NR_ioctl        54U /* [54]  {"ioctl"}        */
#define NR_munmap       91U /* [91]  {"munmap"}       */
#define NR_mprotect    125U /* [125] {"mprotect"}     */
#define NR_mremap      163U /* [163] {"mremap"}       */
#define NR_msync       144U /* [144] {"msync"}        */
#define NR_personality 136U /* [136] {"personality"}  */
#define NR_prctl       172U /* [172] {"prctl"}        */
#define NR_rt_sigaction  174U /* [174] {"rt_sigaction"}  */
#define NR_rt_sigprocmask 175U /* [175] {"rt_sigprocmask"} */
#define NR_rt_sigpending  176U /* [176] {"rt_sigpending"}  */
#define NR_sigaltstack 186U /* [186] {"sigaltstack"}  */
#define NR_set_tid_address 258U /* [258] {"set_tid_address"} */
#define NR_futex       240U /* [240] {"futex"}        */

/* Guest i386 O_ bits */
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
#define I686_O__SYNC     04000000
#define I686_O_PATH      010000000
#define I686_O__TMPFILE  020000000

/* Host (aarch64 Linux kernel) equivalents */
#define HOST_O_CREAT     0x40u
#define HOST_O_EXCL      0x80u
#define HOST_O_NOCTTY    0x100u
#define HOST_O_TRUNC     0x200u
#define HOST_O_APPEND    0x400u
#define HOST_O_NONBLOCK  0x800u
#define HOST_O_DSYNC     0x1000u
#define HOST_O_FASYNC    0x2000u
#define HOST_O_DIRECT    0x10000u
#define HOST_O_DIRECTORY 0x4000u
#define HOST_O_NOFOLLOW  0x8000u
#define HOST_O_NOATIME   0x40000u
#define HOST_O_CLOEXEC   0x80000u
#define HOST_O__SYNC     0x100000u
#define HOST_O_PATH      0x200000u
#define HOST_O__TMPFILE  0x400000u

/* ioctl request numbers */
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

#define K_TERMIOS_SZ 36u
#define K_TERMIO_SZ  17u
#define K_WINSIZE_SZ 8u
#define K_INT_SZ     4u

#define PR_SET_NAME_ 15
#define PR_GET_NAME_ 16

#define FUTEX_WAIT_            0u
#define FUTEX_WAKE_            1u
#define FUTEX_REQUEUE_         3u
#define FUTEX_CMP_REQUEUE_     4u
#define FUTEX_WAKE_OP_         5u
#define FUTEX_LOCK_PI_         6u
#define FUTEX_UNLOCK_PI_       7u
#define FUTEX_TRYLOCK_PI_      8u
#define FUTEX_WAIT_BITSET_     9u
#define FUTEX_WAKE_BITSET_    10u
#define FUTEX_WAIT_REQUEUE_PI_ 11u
#define FUTEX_CMP_REQUEUE_PI_  12u
#define FUTEX_PRIVATE_FLAG_    128u
#define FUTEX_CLOCK_REALTIME_  256u
#define FUTEX_CMD_MASK_        0x7Fu

#define I686_MS_ASYNC      1u
#define I686_MS_INVALIDATE 2u
#define I686_MS_SYNC       4u

#define NGROUPS_MAX_ 65536u
#define SS_ 12u
#define PATH_BUF 4096

static inline int guest_ptr_bad(uint32_t va)
{
    return (va < 0x1000U) ? 1 : 0;
}

static inline uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void wr_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static inline void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static inline long host_ret_(ssize_t n)
{
    return (n < 0) ? -(long)errno : (long)n;
}

static inline int fetch_path(i686_ctx_t *ctx, uint32_t va, char *buf)
{
    if (guest_ptr_bad(va)) {
        return -1;
    }
    return (i686_fetch_cstr(ctx, va, buf, PATH_BUF) != 0) ? -1 : 0;
}

static inline long host_ret_int(long n)
{
    return (n < 0) ? -(long)errno : n;
}

int setgroups(int, const gid_t *);

/* Pure marshalling helpers */
long i686_open_flags_to_host(uint32_t guest_flags);
long i686_getcwd_store(i686_ctx_t *ctx, uint32_t buf_va, uint32_t size,
                       const char *cwd, size_t cwd_len);
int i686_rusage_to_guest(i686_ctx_t *ctx, uint32_t ru_va, const struct rusage *ru);
int i686_groups_from_guest(i686_ctx_t *ctx, uint32_t list_va, uint32_t n, gid_t **out);
int i686_groups16_from_guest(i686_ctx_t *ctx, uint32_t list_va, uint32_t n, gid_t **out);

/* Handlers across sys_pass_fs.c and sys_pass_io.c */
int64_t i686_pass_r_open(i686_ctx_t *ctx);
int64_t i686_pass_r_openat(i686_ctx_t *ctx);
int64_t i686_pass_r_writev(i686_ctx_t *ctx);
int64_t i686_pass_r_readv(i686_ctx_t *ctx);
int64_t i686_pass_r_close(i686_ctx_t *ctx);
int64_t i686_pass_r_readlink(i686_ctx_t *ctx);
int64_t i686_pass_r_lseek(i686_ctx_t *ctx);
int64_t i686_pass_r_llseek(i686_ctx_t *ctx);
int64_t i686_pass_r_unlink(i686_ctx_t *ctx);
int64_t i686_pass_r_rmdir(i686_ctx_t *ctx);
int64_t i686_pass_r_mkdir(i686_ctx_t *ctx);
int64_t i686_pass_r_rename(i686_ctx_t *ctx);
int64_t i686_pass_r_link(i686_ctx_t *ctx);
int64_t i686_pass_r_symlink(i686_ctx_t *ctx);
int64_t i686_pass_r_chmod(i686_ctx_t *ctx);
int64_t i686_pass_r_fchmod(i686_ctx_t *ctx);
int64_t i686_pass_r_lchown(i686_ctx_t *ctx);
int64_t i686_pass_r_chown(i686_ctx_t *ctx);
int64_t i686_pass_r_fchown(i686_ctx_t *ctx);
int64_t i686_pass_r_lchown32(i686_ctx_t *ctx);
int64_t i686_pass_r_chown32(i686_ctx_t *ctx);
int64_t i686_pass_r_fchown32(i686_ctx_t *ctx);
int64_t i686_pass_r_fchmodat(i686_ctx_t *ctx);
int64_t i686_pass_r_fchownat(i686_ctx_t *ctx);
int64_t i686_pass_r_access(i686_ctx_t *ctx);
int64_t i686_pass_r_faccessat(i686_ctx_t *ctx);
int64_t i686_pass_r_chdir(i686_ctx_t *ctx);
int64_t i686_pass_r_fchdir(i686_ctx_t *ctx);
int64_t i686_pass_r_getcwd(i686_ctx_t *ctx);
int64_t i686_pass_r_getppid(i686_ctx_t *ctx);
int64_t i686_pass_r_getuid(i686_ctx_t *ctx);
int64_t i686_pass_r_getuid32(i686_ctx_t *ctx);
int64_t i686_pass_r_getgid(i686_ctx_t *ctx);
int64_t i686_pass_r_getgid32(i686_ctx_t *ctx);
int64_t i686_pass_r_geteuid(i686_ctx_t *ctx);
int64_t i686_pass_r_geteuid32(i686_ctx_t *ctx);
int64_t i686_pass_r_getegid(i686_ctx_t *ctx);
int64_t i686_pass_r_getegid32(i686_ctx_t *ctx);
int64_t i686_pass_r_setuid(i686_ctx_t *ctx);
int64_t i686_pass_r_setuid32(i686_ctx_t *ctx);
int64_t i686_pass_r_setgid(i686_ctx_t *ctx);
int64_t i686_pass_r_setgid32(i686_ctx_t *ctx);
int64_t i686_pass_r_setgroups16(i686_ctx_t *ctx);
int64_t i686_pass_r_setgroups32(i686_ctx_t *ctx);
int64_t i686_pass_r_getgroups16(i686_ctx_t *ctx);
int64_t i686_pass_r_getgroups32(i686_ctx_t *ctx);
int64_t i686_pass_r_umask(i686_ctx_t *ctx);
int64_t i686_pass_r_dup(i686_ctx_t *ctx);
int64_t i686_pass_r_dup2(i686_ctx_t *ctx);
int64_t i686_pass_r_dup3(i686_ctx_t *ctx);
int64_t i686_pass_r_pipe(i686_ctx_t *ctx);
int64_t i686_pass_r_pipe2(i686_ctx_t *ctx);
int64_t i686_pass_r_pread64(i686_ctx_t *ctx);
int64_t i686_pass_r_pwrite64(i686_ctx_t *ctx);
int64_t i686_pass_r_ftruncate64(i686_ctx_t *ctx);
int64_t i686_pass_r_ioctl(i686_ctx_t *ctx);
int64_t i686_pass_r_munmap(i686_ctx_t *ctx);
int64_t i686_pass_r_mprotect(i686_ctx_t *ctx);
int64_t i686_pass_r_mremap(i686_ctx_t *ctx);
int64_t i686_pass_r_msync(i686_ctx_t *ctx);

#endif /* I686_SYS_PASS_INTERNAL_H */
