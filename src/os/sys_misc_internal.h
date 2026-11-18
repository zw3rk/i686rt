/*
 * src/os/sys_misc_internal.h — Internal definitions for sys_misc
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686_SYS_MISC_INTERNAL_H
#define I686_SYS_MISC_INTERNAL_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* structs_i386.h must be parsed before <stdlib.h>: the macOS unit-test
 * build's stdlib pulls in sys/signal.h, whose sa_handler macro clashes
 * with i686_sigaction_t.sa_handler in the frozen header. */
#include "marshal.h"
#include "structs_i386.h"
#include "syscalls_i386.h"

/* Canonical guest<->host O_ flag map (I686_O_* / HOST_O_*).  Included
 * for the sys_misc converters so both sys_pass_fs.c and sys_misc_conv.c
 * share the single table; the GO_/HO_ names below alias onto it. */
#include "sys_pass_internal.h"

#include "rt32/rt32.h"

#include <stdlib.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <time.h>
#include <poll.h>

#ifdef __linux__
#include <sys/epoll.h>
#include <sys/sysinfo.h>
#endif

/* Syscall nrs (names authoritative per src/os/syscalls_i386.h). */
#define L2E_NR_fcntl          55U
#define L2E_NR_setrlimit      75U
#define L2E_NR_getrlimit      76U
#define L2E_NR_select         82U
#define L2E_NR_poll          168U
#define L2E_NR_mmap           90U
#define L2E_NR_sysinfo       116U
#define L2E_NR_newselect     142U
#define L2E_NR_flock         143U
#define L2E_NR_madvise       219U
#define L2E_NR_fcntl64       221U
#define L2E_NR_epoll_create  254U
#define L2E_NR_epoll_ctl     255U
#define L2E_NR_epoll_wait    256U
#define L2E_NR_ugetrlimit    191U
#define L2E_NR_epoll_pwait   319U
#define L2E_NR_prlimit64     340U
#define L2E_NR_pselect6     308U
#define L2E_NR_pselect6_time64 413U

/* O_ flag aliases onto the single canonical map in
 * src/os/sys_pass_internal.h (guest i386 I686_O_*, host aarch64 Linux
 * HOST_O_*).  O_DIRECT (guest 0x4000, host 0x10000), O_DIRECTORY
 * (guest 0x10000, host 0x4000) and O_NOFOLLOW (guest 0x20000, host
 * 0x8000) differ between guest and host (on Darwin hosts the <fcntl.h>
 * constants apply); the rest are bit-identical.  The host has no
 * O_LARGEFILE (64-bit: always large); the guest bit maps to nothing. */
#define I686_GO_ACCMODE   I686_O_ACCMODE
#define I686_GO_CREAT     I686_O_CREAT
#define I686_GO_EXCL      I686_O_EXCL
#define I686_GO_NOCTTY    I686_O_NOCTTY
#define I686_GO_TRUNC     I686_O_TRUNC
#define I686_GO_APPEND    I686_O_APPEND
#define I686_GO_NONBLOCK  I686_O_NONBLOCK
#define I686_GO_DSYNC     I686_O_DSYNC
#define I686_GO_FASYNC    I686_O_FASYNC
#define I686_GO_DIRECT    I686_O_DIRECT
#define I686_GO_LARGEFILE I686_O_LARGEFILE
#define I686_GO_DIRECTORY I686_O_DIRECTORY
#define I686_GO_NOFOLLOW  I686_O_NOFOLLOW
#define I686_GO_NOATIME   I686_O_NOATIME
#define I686_GO_CLOEXEC   I686_O_CLOEXEC
#define I686_GO_OSYNC     I686_O__SYNC
#define I686_GO_PATH      I686_O_PATH
#define I686_GO_TMPFILE   I686_O__TMPFILE

#define I686_HO_ACCMODE   I686_O_ACCMODE
#define I686_HO_CREAT     HOST_O_CREAT
#define I686_HO_EXCL      HOST_O_EXCL
#define I686_HO_NOCTTY    HOST_O_NOCTTY
#define I686_HO_TRUNC     HOST_O_TRUNC
#define I686_HO_APPEND    HOST_O_APPEND
#define I686_HO_NONBLOCK  HOST_O_NONBLOCK
#define I686_HO_DSYNC     HOST_O_DSYNC
#define I686_HO_FASYNC    HOST_O_FASYNC
#define I686_HO_DIRECT    HOST_O_DIRECT
#define I686_HO_DIRECTORY HOST_O_DIRECTORY
#define I686_HO_NOFOLLOW  HOST_O_NOFOLLOW
#define I686_HO_NOATIME   HOST_O_NOATIME
#define I686_HO_CLOEXEC   HOST_O_CLOEXEC
#define I686_HO_OSYNC     HOST_O__SYNC
#define I686_HO_PATH      HOST_O_PATH
#define I686_HO_TMPFILE   HOST_O__TMPFILE

#define I686_O_KNOWN                                                         \
    (I686_O_ACCMODE | I686_O_CREAT | I686_O_EXCL | I686_O_NOCTTY |           \
     I686_O_TRUNC | I686_O_APPEND | I686_O_NONBLOCK | I686_O_DSYNC |         \
     I686_O_FASYNC | I686_O_DIRECT | I686_O_LARGEFILE |                     \
     I686_O_DIRECTORY | I686_O_NOFOLLOW | I686_O_NOATIME |                  \
     I686_O_CLOEXEC | I686_O__SYNC | I686_O_PATH | I686_O__TMPFILE)

/* fcntl F_SETFL-allowed set: kernel fs/fcntl.c SETFL_MASK + FASYNC. */
#define I686_SETFL_ALLOWED                                                   \
    (I686_O_APPEND | I686_O_NONBLOCK | I686_O_DIRECT | I686_O_NOATIME |      \
     I686_O_FASYNC)

/* Identical encodings stay pinned; the three that differ are pinned to
 * their distinct values on each side. */
_Static_assert(I686_GO_CREAT == I686_HO_CREAT, "i386/aarch64 O_CREAT differ");
_Static_assert(I686_GO_APPEND == I686_HO_APPEND, "i386/aarch64 O_APPEND differ");
_Static_assert(I686_GO_NONBLOCK == I686_HO_NONBLOCK, "O_NONBLOCK differs");
_Static_assert(I686_GO_CLOEXEC == I686_HO_CLOEXEC, "O_CLOEXEC differs");
_Static_assert(I686_GO_NOATIME == I686_HO_NOATIME, "O_NOATIME differs");
_Static_assert(I686_GO_DIRECT != I686_HO_DIRECT, "O_DIRECT must differ");
_Static_assert(I686_GO_DIRECTORY != I686_HO_DIRECTORY, "O_DIRECTORY must differ");
_Static_assert(I686_GO_NOFOLLOW != I686_HO_NOFOLLOW, "O_NOFOLLOW must differ");
_Static_assert(I686_GO_DIRECT == I686_HO_DIRECTORY, "DIRECT/DIRECTORY swap");
_Static_assert(I686_GO_DIRECTORY == I686_HO_DIRECT, "DIRECTORY/DIRECT swap");

/* fcntl commands (identical numbering; the *64 cmds map down on the
 * 64-bit host — see i686_fcntl_cmd_to_host). */
#define I686_FC_DUPFD           0u
#define I686_FC_GETFD           1u
#define I686_FC_SETFD           2u
#define I686_FC_GETFL           3u
#define I686_FC_SETFL           4u
#define I686_FC_GETLK           5u
#define I686_FC_SETLK           6u
#define I686_FC_SETLKW          7u
#define I686_FC_SETOWN          8u
#define I686_FC_GETOWN          9u
#define I686_FC_SETSIG          10u
#define I686_FC_GETSIG          11u
#define I686_FC_GETLK64         12u
#define I686_FC_SETLK64         13u
#define I686_FC_SETLKW64        14u
#define I686_FC_SETOWN_EX       15u
#define I686_FC_GETOWN_EX       16u
#define I686_FC_GETOWNER_UIDS   17u
#define I686_FC_OFD_GETLK       36u
#define I686_FC_OFD_SETLK       37u
#define I686_FC_OFD_SETLKW      38u
#define I686_FC_DUPFD_CLOEXEC   1030u /* F_LINUX_SPECIFIC_BASE + 6 */
#define I686_FC_SETPIPE_SZ      1031u
#define I686_FC_GETPIPE_SZ      1032u

/* flock(2) LOCK_* and flock l_type: identical on both sides. */
#define I686_LOCK_SH 1
#define I686_LOCK_EX 2
#define I686_LOCK_NB 4
#define I686_LOCK_UN 8

/* MAP_ flags: identical bit values; x86-only hints stripped on the way
 * to the host (arch/x86 uapi/asm/mman.h adds only MAP_32BIT 0x40 and
 * MAP_ABOVE4G 0x80 on top of asm-generic). */
#define I686_GM_SHARED          0x00001u
#define I686_GM_PRIVATE         0x00002u
#define I686_GM_TYPE            0x0000fu
#define I686_GM_FIXED           0x00010u
#define I686_GM_ANONYMOUS       0x00020u
#define I686_GM_32BIT_X86       0x00040u /* x86-only: MAP_32BIT */
#define I686_GM_ABOVE4G_X86     0x00080u /* x86-only: MAP_ABOVE4G */
#define I686_GM_GROWSDOWN       0x00100u
#define I686_GM_DENYWRITE       0x00800u
#define I686_GM_EXECUTABLE      0x01000u
#define I686_GM_LOCKED          0x02000u
#define I686_GM_NORESERVE       0x04000u
#define I686_GM_POPULATE        0x08000u
#define I686_GM_NONBLOCK        0x10000u
#define I686_GM_STACK           0x20000u
#define I686_GM_HUGETLB         0x40000u
#define I686_GM_SYNC            0x80000u
#define I686_GM_FIXED_NOREPLACE 0x100000u

/* Guest RLIMIT: rlim_t is u32; infinity is 0xFFFFFFFF. */
#define I686_GRLIM_INFINITY 0xFFFFFFFFu
/* Host RLIM_INFINITY (u64 ~0). */
#define I686_HRLIM_INFINITY 0xFFFFFFFFFFFFFFFFull
/* RLIM_NLIMITS: 16 on both (asm-generic/resource.h, same on i386). */
#define I686_RLIM_NLIMITS 16u

/* EPOLL_CTL_*: 1/2/3 on both sides (linux/eventpoll.h). */
#define I686_EPOLL_CTL_ADD 1
#define I686_EPOLL_CTL_DEL 2
#define I686_EPOLL_CTL_MOD 3

/* fd_set geometry: i386 uses 32-bit words (FD_SETSIZE 1024 -> 128 bytes);
 * the aarch64 host fd_set also spans 1024 fds but in 64-bit words. */
#define I686_FD_SETSIZE 1024u
#define I686_FD_BYTES   128u

#define I686_HOST_EPOLL_SZ  16u
#define I686_HOST_FLOCK_SZ  32u
#define I686_HOST_SYSINFO_SZ 112u

#ifdef __linux__
#if defined(__aarch64__)
_Static_assert(sizeof(struct epoll_event) == I686_HOST_EPOLL_SZ,
               "host epoll_event layout");
_Static_assert(offsetof(struct epoll_event, data) == 8, "host epoll data @8");
#else
_Static_assert(sizeof(struct epoll_event) == 12u,
               "host epoll_event layout (x86 packed)");
_Static_assert(offsetof(struct epoll_event, data) == 4,
               "host epoll data @4 (x86 packed)");
#undef I686_HOST_EPOLL_SZ
#define I686_HOST_EPOLL_SZ 12u
#endif
_Static_assert(sizeof(struct flock) == I686_HOST_FLOCK_SZ, "host flock layout");
_Static_assert(offsetof(struct flock, l_start) == 8, "host flock l_start @8");
_Static_assert(offsetof(struct flock, l_len) == 16, "host flock l_len @16");
_Static_assert(offsetof(struct flock, l_pid) == 24, "host flock l_pid @24");
_Static_assert(sizeof(struct sysinfo) >= I686_HOST_SYSINFO_SZ,
               "host sysinfo too small");
_Static_assert(offsetof(struct sysinfo, totalram) == 32, "sysinfo totalram @32");
_Static_assert(offsetof(struct sysinfo, mem_unit) == 104, "mem_unit @104");
_Static_assert(sizeof(struct rlimit) == 16, "host rlimit layout");
#endif

int prlimit(pid_t, int, const struct rlimit *, struct rlimit *);
int madvise(void *, size_t, int);

_Static_assert(sizeof(fd_set) == I686_FD_BYTES, "host fd_set must be 128 bytes");

typedef struct {
    uint32_t n;
    uint32_t inp;
    uint32_t outp;
    uint32_t exp;
    uint32_t tvp;
} __attribute__((packed)) i686_sel_args_t;

static inline uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

/* rd_le32/wr_le32/wr_le16 come from sys_pass_internal.h (single copy). */

static inline uint64_t rd_le64(const uint8_t *p)
{
    return (uint64_t)rd_le32(p) | ((uint64_t)rd_le32(p + 4) << 32);
}

static inline void wr_le64(uint8_t *p, uint64_t v)
{
    wr_le32(p, (uint32_t)v);
    wr_le32(p + 4, (uint32_t)(v >> 32));
}

static inline int64_t fixup(int64_t r)
{
    return (r < 0) ? -(int64_t)errno : r;
}

void i686_fdset_g2h(uint8_t *host128, const uint8_t *guest, uint32_t n);
void i686_fdset_h2g(uint8_t *guest, const uint8_t *host128, uint32_t n);
void i686_epoll_pack_guest(uint8_t *dst, const uint8_t *src, int n);
void i686_epoll_unpack_guest(uint8_t *dst, const uint8_t *src, int n);
void i686_flock32_to_host(uint8_t *host32, const uint8_t *guest16);
void i686_flock32_from_host(uint8_t *guest16, const uint8_t *host32);
void i686_flock64_to_host(uint8_t *host32, const i686_flock64_t *g);
void i686_flock64_from_host(i686_flock64_t *g, const uint8_t *host32);
void i686_rlimit_g2h(const i686_rlimit_t *g, uint64_t *cur, uint64_t *max);
void i686_rlimit_h2g(i686_rlimit_t *g, uint64_t cur, uint64_t max);
uint32_t i686_oflags_g2h(uint32_t g);
uint32_t i686_oflags_h2g(uint32_t h);
uint32_t i686_setfl_to_host(uint32_t g);
int i686_fcntl_cmd_to_host(uint32_t cmd, int fcntl64_entry, int *flock_bytes);
void i686_sysinfo_to_guest(i686_sysinfo_t *g, const uint8_t *host112);

#endif /* I686_SYS_MISC_INTERNAL_H */
