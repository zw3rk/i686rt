/*
 * src/os/sys_misc.c — Phase 2 lane L2e syscall marshalling module
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Owns the misc set: select(82)/_newselect(142), epoll_create(254)/
 * epoll_ctl(255)/epoll_wait(256)/epoll_pwait(319), flock(143),
 * fcntl(55)/fcntl64(221), getrlimit(76)/setrlimit(75)/ugetrlimit(191)/
 * prlimit64(340), sysinfo(116), old mmap(90) and madvise(219).
 *
 * Kernel citations (torvalds/linux master, checked 2026-10):
 *  - arch/x86/include/uapi/asm/mman.h: defines only MAP_32BIT 0x40 (and the
 *    new MAP_ABOVE4G 0x80) and includes <asm-generic/mman.h>; MAP_SHARED
 *    0x01/MAP_PRIVATE 0x02 live in asm-generic/mman-common.h, MAP_FIXED
 *    0x10/MAP_ANONYMOUS 0x20/MAP_FIXED_NOREPLACE 0x100000 likewise — i386
 *    and aarch64 MAP_* values are bit-identical except the two x86-only
 *    hints.  MADV_* (mman-common.h) are shared values too.
 *  - include/uapi/asm-generic/fcntl.h (aarch64; x86 has no own fcntl.h in
 *    current kernels and the historical x86 values were identical):
 *    O_CREAT (1<<6) .. __O_TMPFILE (1<<22), O_LARGEFILE (1<<15),
 *    F_DUPFD 0 .. F_GETOWNER_UIDS 17, F_OFD_GETLK 36/F_OFD_SETLK 37/
 *    F_OFD_SETLKW 38, FD_CLOEXEC 1, LOCK_SH 1/LOCK_EX 2/LOCK_NB 4/
 *    LOCK_UN 8, F_LINUX_SPECIFIC_BASE 1024.  fs/fcntl.c SETFL_MASK is
 *    (O_APPEND|O_NONBLOCK|O_NDELAY|O_DIRECT|O_NOATIME) with FASYNC handled
 *    beside it; unknown cmds return -EINVAL; compat fcntl(55) rejects the
 *    F_*64 cmds with -EINVAL while fcntl64(221) takes them, and
 *    convert_fcntl_cmd() maps F_GETLK64/13/14 -> F_GETLK/6/7.
 *  - fs/select.c: SYSCALL_DEFINE5(select, n, inp, outp, exp, tvp) — five
 *    register args, no stack arg; compat_sel_arg_struct for old select(82)
 *    is five compat_ulongs {n, inp, outp, exp, tvp} (20 bytes); the
 *    timeout writeback in poll_select_finish() stores the remaining time
 *    and is skipped for a zero timeout.  The i386 fd_set uses 32-bit words
 *    (__NFDBITS 32) vs the host's 64-bit words, so fd_sets are re-packed
 *    bit by bit, never memcpy'd.
 *  - arch/x86/kernel/sys_ia32.c ia32_mmap: struct {addr,len,prot,flags,fd,
 *    offset} (6 x u32), "if (a.offset & ~PAGE_MASK) return -EINVAL;", call
 *    with a.offset>>PAGE_SHIFT.
 *  - kernel/sys.c: SYSCALL_DEFINE4(prlimit64, pid, resource, new_rlim,
 *    old_rlim) — four args, NO 64-bit register split on i386 (the guest
 *    struct rlimit64 {u64 rlim_cur; u64 rlim_max} has identical offsets
 *    0/8 under i386's 4-byte u64 alignment); compat getrlimit clamps
 *    values above COMPAT_RLIM_INFINITY (0xFFFFFFFF) to it, compat
 *    setrlimit maps 0xFFFFFFFF to RLIM_INFINITY; compat sysinfo scales
 *    with "while (s.mem_unit < PAGE_SIZE) { s.mem_unit <<= 1; bitcount++;
 *    }" plus right-shifts of the eight memory counters when
 *    upper_32_bits(totalram || totalswap).
 *  - include/uapi/asm-generic/unistd.h (aarch64 numbers): epoll_create1
 *    20, epoll_ctl 21, epoll_pwait 22, fcntl 25, flock 32, getrlimit 163,
 *    setrlimit 164, pselect6 72, madvise 233, sysinfo 179, prlimit64 261
 *    (used through the libc wrappers).
 *  - include/uapi/linux/eventpoll.h: EPOLL_CTL_ADD/DEL/MOD 1/2/3; the
 *    aarch64 host struct epoll_event is {u32 events; u64 data} with data
 *    at offset 8 and sizeof 16 (no EPOLL_PACKED outside x86_64), vs the
 *    12-byte i386 layout pinned by i686_epoll_event_t.
 *
 * Frozen-header deviation (ESCALATED, not editable in this lane): the
 * frozen i686_select_args_t in structs_i386.h is missing the leading 'n'
 * field of the kernel's five-word struct; the correct 20-byte layout is
 * defined locally below as i686_sel_args_t.
 */

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

/* ------------------------------------------------------------------ */
/* Guest (i386) and host (asm-generic/aarch64) ABI constants.  The two  */
/* sets are written out separately so any future divergence shows as a  */
/* single-line change plus the _Static_asserts below.                   */
/* ------------------------------------------------------------------ */

/* O_ flags: historical x86 values (musl arch/i386/bits/fcntl.h) vs
 * include/uapi/asm-generic/fcntl.h — bit-identical. */
#define I686_GO_CREAT     0x000040u
#define I686_GO_EXCL      0x000080u
#define I686_GO_NOCTTY    0x000100u
#define I686_GO_TRUNC     0x000200u
#define I686_GO_APPEND    0x000400u
#define I686_GO_NONBLOCK  0x000800u
#define I686_GO_DSYNC     0x001000u
#define I686_GO_FASYNC    0x002000u
#define I686_GO_DIRECT    0x004000u
#define I686_GO_LARGEFILE 0x008000u
#define I686_GO_DIRECTORY 0x010000u
#define I686_GO_NOFOLLOW  0x020000u
#define I686_GO_NOATIME   0x040000u
#define I686_GO_CLOEXEC   0x080000u
#define I686_GO_OSYNC     0x101000u
#define I686_GO_PATH      0x200000u
#define I686_GO_TMPFILE   0x400000u
#define I686_GO_ACCMODE   0x000003u

#define I686_HO_CREAT     0x000040u
#define I686_HO_EXCL      0x000080u
#define I686_HO_NOCTTY    0x000100u
#define I686_HO_TRUNC     0x000200u
#define I686_HO_APPEND    0x000400u
#define I686_HO_NONBLOCK  0x000800u
#define I686_HO_DSYNC     0x001000u
#define I686_HO_FASYNC    0x002000u
#define I686_HO_DIRECT    0x004000u
#define I686_HO_LARGEFILE 0x008000u
#define I686_HO_DIRECTORY 0x010000u
#define I686_HO_NOFOLLOW  0x020000u
#define I686_HO_NOATIME   0x040000u
#define I686_HO_CLOEXEC   0x080000u
#define I686_HO_OSYNC     0x101000u
#define I686_HO_PATH      0x200000u
#define I686_HO_TMPFILE   0x400000u
#define I686_HO_ACCMODE   0x000003u

#define I686_O_KNOWN                                                         \
    (I686_GO_ACCMODE | I686_GO_CREAT | I686_GO_EXCL | I686_GO_NOCTTY |       \
     I686_GO_TRUNC | I686_GO_APPEND | I686_GO_NONBLOCK | I686_GO_DSYNC |     \
     I686_GO_FASYNC | I686_GO_DIRECT | I686_GO_LARGEFILE |                   \
     I686_GO_DIRECTORY | I686_GO_NOFOLLOW | I686_GO_NOATIME |                \
     I686_GO_CLOEXEC | I686_GO_OSYNC | I686_GO_PATH | I686_GO_TMPFILE)

/* fcntl F_SETFL-allowed set: kernel fs/fcntl.c SETFL_MASK + FASYNC. */
#define I686_SETFL_ALLOWED                                                   \
    (I686_GO_APPEND | I686_GO_NONBLOCK | I686_GO_DIRECT | I686_GO_NOATIME |  \
     I686_GO_FASYNC)

_Static_assert(I686_GO_CREAT == I686_HO_CREAT, "i386/aarch64 O_CREAT differ");
_Static_assert(I686_GO_APPEND == I686_HO_APPEND, "i386/aarch64 O_APPEND differ");
_Static_assert(I686_GO_NONBLOCK == I686_HO_NONBLOCK, "O_NONBLOCK differs");
_Static_assert(I686_GO_LARGEFILE == I686_HO_LARGEFILE, "O_LARGEFILE differs");
_Static_assert(I686_GO_CLOEXEC == I686_HO_CLOEXEC, "O_CLOEXEC differs");
_Static_assert(I686_GO_NOATIME == I686_HO_NOATIME, "O_NOATIME differs");

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

/* aarch64 host struct layouts (pinned, byte-exact):
 *   epoll_event : u32 events @0, u64 data @8, sizeof 16 (not packed)
 *   flock (LP64): i16 l_type @0, i16 l_whence @2, i64 l_start @8,
 *                 i64 l_len @16, i32 l_pid @24, sizeof 32
 *   sysinfo     : u64 uptime @0, u64 loads[3] @8, totalram @32, freeram
 *                 @40, sharedram @48, bufferram @56, totalswap @64,
 *                 freeswap @72, u16 procs @80, u16 pad @82, u64
 *                 totalhigh @88, freehigh @96, u32 mem_unit @104,
 *                 sizeof 112
 */
#define I686_HOST_EPOLL_SZ  16u
#define I686_HOST_FLOCK_SZ  32u
#define I686_HOST_SYSINFO_SZ 112u

#ifdef __linux__
_Static_assert(sizeof(struct epoll_event) == I686_HOST_EPOLL_SZ,
               "host epoll_event layout");
_Static_assert(offsetof(struct epoll_event, data) == 8, "host epoll data @8");
_Static_assert(sizeof(struct flock) == I686_HOST_FLOCK_SZ, "host flock layout");
_Static_assert(offsetof(struct flock, l_start) == 8, "host flock l_start @8");
_Static_assert(offsetof(struct flock, l_len) == 16, "host flock l_len @16");
_Static_assert(offsetof(struct flock, l_pid) == 24, "host flock l_pid @24");
/* musl pads struct sysinfo with a 256-byte __reserved tail the kernel
 * never writes; the kernel layout prefix is the pinned 112 bytes and
 * the field offsets below hold for both libc layouts. */
_Static_assert(sizeof(struct sysinfo) >= I686_HOST_SYSINFO_SZ,
               "host sysinfo too small");
_Static_assert(offsetof(struct sysinfo, totalram) == 32, "sysinfo totalram @32");
_Static_assert(offsetof(struct sysinfo, mem_unit) == 104, "mem_unit @104");
_Static_assert(sizeof(struct rlimit) == 16, "host rlimit layout");
#endif

/* musl hides these behind _GNU_SOURCE, which the curated build does not
 * define; declare the libc prototypes with identical signatures (a
 * compatible redeclaration when the header already provides them). */
int prlimit(pid_t, int, const struct rlimit *, struct rlimit *);
int madvise(void *, size_t, int);

_Static_assert(sizeof(fd_set) == I686_FD_BYTES, "host fd_set must be 128 bytes");

/* old select(82): five-word arg block (kernel compat_sel_arg_struct).
 * The frozen structs_i386.h i686_select_args_t lacks the leading n —
 * escalated; the kernel layout is used here. */
typedef struct {
    uint32_t n;
    uint32_t inp;
    uint32_t outp;
    uint32_t exp;
    uint32_t tvp;
} __attribute__((packed)) i686_sel_args_t;

/* ------------------------------------------------------------------ */
/* Little-endian byte helpers (guest memory is x86 LE; explicit decode  */
/* like src/os/syscalls.c, no struct punning).                         */
/* ------------------------------------------------------------------ */

static uint16_t rd_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd_le64(const uint8_t *p)
{
    return (uint64_t)rd_le32(p) | ((uint64_t)rd_le32(p + 4) << 32);
}

static void wr_le16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
}

static void wr_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static void wr_le64(uint8_t *p, uint64_t v)
{
    wr_le32(p, (uint32_t)v);
    wr_le32(p + 4, (uint32_t)(v >> 32));
}

/* Host libc result convention (-1 + errno) -> handler convention. */
static int64_t fixup(int64_t r)
{
    return (r < 0) ? -(int64_t)errno : r;
}

/* ------------------------------------------------------------------ */
/* Pure converters (exported for tests/unit/test_l2e.c; not in any      */
/* public header — test declares matching externs).                    */
/* ------------------------------------------------------------------ */

/* fd_set re-pack: guest 32-bit words -> host 64-bit words, bits >= n
 * dropped (kernel get_fd_set reads only the words covering n). */
void i686_fdset_g2h(uint8_t *host128, const uint8_t *guest, uint32_t n)
{
    memset(host128, 0, I686_FD_BYTES);
    for (uint32_t fd = 0U; fd < n && fd < I686_FD_SETSIZE; fd++) {
        uint32_t word = rd_le32(guest + (fd / 32u) * 4u);
        if ((word & (1u << (fd % 32u))) != 0u) {
            uint64_t hw = rd_le64(host128 + (fd / 64u) * 8u);
            wr_le64(host128 + (fd / 64u) * 8u, hw | (UINT64_C(1) << (fd % 64u)));
        }
    }
}

/* Host -> guest fd_set: writes exactly ceil(n/32) 32-bit guest words;
 * bits >= n are cleared (kernel set_fd_set writes whole guest words
 * covering n with host bits that were zeroed above n). */
void i686_fdset_h2g(uint8_t *guest, const uint8_t *host128, uint32_t n)
{
    uint32_t words = (n + 31u) / 32u;
    memset(guest, 0, words * 4u);
    for (uint32_t fd = 0U; fd < n && fd < I686_FD_SETSIZE; fd++) {
        uint64_t hw = rd_le64(host128 + (fd / 64u) * 8u);
        if ((hw & (UINT64_C(1) << (fd % 64u))) != 0u) {
            uint32_t word = rd_le32(guest + (fd / 32u) * 4u);
            wr_le32(guest + (fd / 32u) * 4u, word | (1u << (fd % 32u)));
        }
    }
}

/* epoll events: 16-byte host stride -> 12-byte guest stride. */
void i686_epoll_pack_guest(uint8_t *dst, const uint8_t *src, int n)
{
    for (int i = 0; i < n; i++) {
        const uint8_t *h = src + (size_t)i * I686_HOST_EPOLL_SZ;
        uint8_t *g = dst + (size_t)i * 12u;
        wr_le32(g, rd_le32(h));
        wr_le64(g + 4, rd_le64(h + 8));
    }
}

/* epoll events: 12-byte guest stride -> 16-byte host stride (tail and
 * inter-member padding zeroed). */
void i686_epoll_unpack_guest(uint8_t *dst, const uint8_t *src, int n)
{
    for (int i = 0; i < n; i++) {
        const uint8_t *g = src + (size_t)i * 12u;
        uint8_t *h = dst + (size_t)i * I686_HOST_EPOLL_SZ;
        memset(h, 0, I686_HOST_EPOLL_SZ);
        wr_le32(h, rd_le32(g));
        wr_le64(h + 8, rd_le64(g + 4));
    }
}

/* struct flock conversions.  Guest 16-byte compat flock (i32 off_t,
 * sign-extended like get_compat_flock) and the frozen 24-byte
 * i686_flock64_t -> 32-byte LP64 host flock. */
void i686_flock32_to_host(uint8_t *host32, const uint8_t *guest16)
{
    memset(host32, 0, I686_HOST_FLOCK_SZ);
    wr_le16(host32, rd_le16(guest16));
    wr_le16(host32 + 2, rd_le16(guest16 + 2));
    wr_le64(host32 + 8, (uint64_t)(int64_t)(int32_t)rd_le32(guest16 + 4));
    wr_le64(host32 + 16, (uint64_t)(int64_t)(int32_t)rd_le32(guest16 + 8));
    wr_le32(host32 + 24, rd_le32(guest16 + 12));
}

void i686_flock32_from_host(uint8_t *guest16, const uint8_t *host32)
{
    wr_le16(guest16, rd_le16(host32));
    wr_le16(guest16 + 2, rd_le16(host32 + 2));
    wr_le32(guest16 + 4, (uint32_t)rd_le64(host32 + 8));
    wr_le32(guest16 + 8, (uint32_t)rd_le64(host32 + 16));
    wr_le32(guest16 + 12, rd_le32(host32 + 24));
}

void i686_flock64_to_host(uint8_t *host32, const i686_flock64_t *g)
{
    const uint8_t *gb = (const uint8_t *)g;
    memset(host32, 0, I686_HOST_FLOCK_SZ);
    wr_le16(host32, rd_le16(gb));
    wr_le16(host32 + 2, rd_le16(gb + 2));
    wr_le64(host32 + 8, rd_le64(gb + 4));
    wr_le64(host32 + 16, rd_le64(gb + 12));
    wr_le32(host32 + 24, rd_le32(gb + 20));
}

void i686_flock64_from_host(i686_flock64_t *g, const uint8_t *host32)
{
    uint8_t *gb = (uint8_t *)g;
    wr_le16(gb, rd_le16(host32));
    wr_le16(gb + 2, rd_le16(host32 + 2));
    wr_le64(gb + 4, rd_le64(host32 + 8));
    wr_le64(gb + 12, rd_le64(host32 + 16));
    wr_le32(gb + 20, rd_le32(host32 + 24));
}

/* rlimit u32 pair <-> u64 pair with the kernel compat infinity mapping:
 * guest 0xFFFFFFFF -> host RLIM_INFINITY; host > 0xFFFFFFFF -> guest
 * 0xFFFFFFFF (COMPAT_RLIM_INFINITY clamp). */
void i686_rlimit_g2h(const i686_rlimit_t *g, uint64_t *cur, uint64_t *max)
{
    *cur = (g->rlim_cur == I686_GRLIM_INFINITY) ? I686_HRLIM_INFINITY
                                                : (uint64_t)g->rlim_cur;
    *max = (g->rlim_max == I686_GRLIM_INFINITY) ? I686_HRLIM_INFINITY
                                                : (uint64_t)g->rlim_max;
}

void i686_rlimit_h2g(i686_rlimit_t *g, uint64_t cur, uint64_t max)
{
    g->rlim_cur = (cur > I686_GRLIM_INFINITY) ? I686_GRLIM_INFINITY
                                              : (uint32_t)cur;
    g->rlim_max = (max > I686_GRLIM_INFINITY) ? I686_GRLIM_INFINITY
                                              : (uint32_t)max;
}

/* g2h keeps I686_O_KNOWN and drops O_LARGEFILE. It does not swap
 * DIRECTORY, DIRECT, or NOFOLLOW. i686_open_flags_to_host does that
 * for open. h2g below rewrites host DIRECT and NOFOLLOW only. */
uint32_t i686_oflags_g2h(uint32_t g)
{
    return g & I686_O_KNOWN & ~(uint32_t)I686_GO_LARGEFILE;
}

/* S2 arbitration: the four O_ bits whose i386 and aarch64 encodings
 * differ (empirically verified by the L2f lane; both sides hard-coded):
 * O_DIRECT 0x4000 <-> 0x10000, O_DIRECTORY 0x10000 <-> 0x4000,
 * O_NOFOLLOW 0x20000 <-> 0x8000, O_LARGEFILE guest 0x8000 (host no-op). */
#define I686_HO_DIRECT_ 0x10000u
#define I686_HO_NOFOLLOW_ 0x8000u

/* L2f owns the full table (src/os/sys_pass.c). */
long i686_open_flags_to_host(uint32_t guest_flags);

uint32_t i686_oflags_h2g(uint32_t h)
{
    uint32_t g = h & I686_O_KNOWN;
    if ((g & I686_HO_DIRECT_) != 0U) {
        g = (g & ~I686_HO_DIRECT_) | I686_GO_DIRECT;
    }
    if ((g & I686_HO_NOFOLLOW_) != 0U) {
        g = (g & ~I686_HO_NOFOLLOW_) | I686_GO_NOFOLLOW;
    }
    if ((g & I686_HO_LARGEFILE) != 0U) { /* host O_LARGEFILE slot holds
        O_NOFOLLOW on arm64; that bit is handled above, nothing to do */
    }
    return g & I686_O_KNOWN;
}

/* F_SETFL argument subset (kernel SETFL_MASK + FASYNC), guest bits
 * translated to host (O_DIRECT moves; O_LARGEFILE is a 64-bit no-op). */
uint32_t i686_setfl_to_host(uint32_t g)
{
    uint32_t allowed = g & I686_SETFL_ALLOWED;
    if ((allowed & I686_GO_DIRECT) != 0U) {
        allowed = (allowed & ~I686_GO_DIRECT) | I686_HO_DIRECT_;
    }
    allowed &= ~I686_GO_LARGEFILE;
    return allowed;
}

/* Guest fcntl cmd -> host cmd.  fcntl64_entry selects the fcntl64(221)
 * entry point (accepts the F_*64 and F_OFD_* cmds with 24-byte
 * flock64); the plain fcntl(55) entry rejects them with -EINVAL exactly
 * like the kernel's compat do_fcntl/do_compat_fcntl64 split.
 * *flock_bytes receives 0, 16 or 24 (guest struct flock width).
 * Returns the host cmd or -1 when the kernel would return -EINVAL. */
int i686_fcntl_cmd_to_host(uint32_t cmd, int fcntl64_entry, int *flock_bytes)
{
    *flock_bytes = 0;
    switch (cmd) {
    case I686_FC_DUPFD:
    case I686_FC_GETFD:
    case I686_FC_SETFD:
    case I686_FC_GETFL:
    case I686_FC_SETFL:
    case I686_FC_SETOWN:
    case I686_FC_GETOWN:
    case I686_FC_SETSIG:
    case I686_FC_GETSIG:
    case I686_FC_SETOWN_EX:
    case I686_FC_GETOWN_EX:
    case I686_FC_GETOWNER_UIDS:
    case I686_FC_DUPFD_CLOEXEC:
    case I686_FC_SETPIPE_SZ:
    case I686_FC_GETPIPE_SZ:
        return (int)cmd;
    case I686_FC_GETLK:
    case I686_FC_SETLK:
    case I686_FC_SETLKW:
        *flock_bytes = 16;
        return (int)cmd;
    case I686_FC_GETLK64:
    case I686_FC_SETLK64:
    case I686_FC_SETLKW64:
        if (!fcntl64_entry) {
            return -1;
        }
        *flock_bytes = 24; /* convert_fcntl_cmd(): F_GETLK64 -> F_GETLK */
        return (int)(cmd - (I686_FC_GETLK64 - I686_FC_GETLK));
    case I686_FC_OFD_GETLK:
    case I686_FC_OFD_SETLK:
    case I686_FC_OFD_SETLKW:
        if (!fcntl64_entry) {
            return -1;
        }
        *flock_bytes = 24;
        return (int)cmd;
    default:
        return -1;
    }
}

/* sysinfo: 112-byte LP64 host struct -> 64-byte i686_sysinfo_t with the
 * kernel compat scaling (kernel/sys.c COMPAT_SYSCALL_DEFINE1(sysinfo)):
 * when totalram or totalswap exceeds 32 bits, mem_unit is shifted up to
 * PAGE_SIZE and the eight counters follow. */
void i686_sysinfo_to_guest(i686_sysinfo_t *g, const uint8_t *host112)
{
    uint64_t totalram = rd_le64(host112 + 32);
    uint64_t freeram = rd_le64(host112 + 40);
    uint64_t sharedram = rd_le64(host112 + 48);
    uint64_t bufferram = rd_le64(host112 + 56);
    uint64_t totalswap = rd_le64(host112 + 64);
    uint64_t freeswap = rd_le64(host112 + 72);
    uint64_t totalhigh = rd_le64(host112 + 88);
    uint64_t freehigh = rd_le64(host112 + 96);
    uint32_t mem_unit = rd_le32(host112 + 104);

    if ((totalram >> 32) != 0u || (totalswap >> 32) != 0u) {
        unsigned bitcount = 0u;
        while ((uint64_t)mem_unit < (uint64_t)I686_PAGE_SIZE) {
            mem_unit <<= 1;
            bitcount++;
        }
        totalram >>= bitcount;
        freeram >>= bitcount;
        sharedram >>= bitcount;
        bufferram >>= bitcount;
        totalswap >>= bitcount;
        freeswap >>= bitcount;
        totalhigh >>= bitcount;
        freehigh >>= bitcount;
    }

    memset(g, 0, sizeof(*g));
    g->uptime = (int32_t)rd_le64(host112);
    g->loads[0] = (uint32_t)rd_le64(host112 + 8);
    g->loads[1] = (uint32_t)rd_le64(host112 + 16);
    g->loads[2] = (uint32_t)rd_le64(host112 + 24);
    g->totalram = (uint32_t)totalram;
    g->freeram = (uint32_t)freeram;
    g->sharedram = (uint32_t)sharedram;
    g->bufferram = (uint32_t)bufferram;
    g->totalswap = (uint32_t)totalswap;
    g->freeswap = (uint32_t)freeswap;
    g->procs = rd_le16(host112 + 80);
    g->totalhigh = (uint32_t)totalhigh;
    g->freehigh = (uint32_t)freehigh;
    g->mem_unit = mem_unit;
}

/* Guest MAP_* -> host MAP_*: identical bits; x86-only hints stripped.
 * File-local for now (shared export deferred per the lane card). */
static uint32_t mmap_flags_to_host(uint32_t flags)
{
    return flags & ~(uint32_t)(I686_GM_32BIT_X86 | I686_GM_ABOVE4G_X86);
}

/* ------------------------------------------------------------------ */
/* Host call shims.  The Linux-only set (epoll, sysinfo, prlimit64) has */
/* macOS stand-ins so the module links into the host-native unit test;  */
/* those paths are never exercised by the test driver.                 */
/* ------------------------------------------------------------------ */

#ifdef __linux__

static int64_t host_epoll_create(int size)
{
    return fixup((int64_t)epoll_create(size));
}

static int64_t host_epoll_ctl(int epfd, int op, int fd, uint8_t *host_ev16)
{
    return fixup((int64_t)epoll_ctl(epfd, op, fd, (struct epoll_event *)(void *)host_ev16));
}

static int64_t host_epoll_wait(int epfd, uint8_t *host_ev16, int maxevents,
                               int timeout_ms)
{
    return fixup((int64_t)epoll_wait(epfd, (struct epoll_event *)(void *)host_ev16,
                                     maxevents, timeout_ms));
}

static int64_t host_epoll_pwait(int epfd, uint8_t *host_ev16, int maxevents,
                                int timeout_ms, const uint8_t *mask8)
{
    return fixup((int64_t)epoll_pwait(epfd, (struct epoll_event *)(void *)host_ev16,
                                      maxevents, timeout_ms,
                                      (const sigset_t *)(const void *)mask8));
}

static int64_t host_sysinfo(uint8_t *out112)
{
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        return -(int64_t)errno;
    }
    memcpy(out112, &si, I686_HOST_SYSINFO_SZ);
    return 0;
}

static int64_t host_prlimit64(int64_t pid, int resource, const uint8_t *new16,
                              uint8_t *old16)
{
    return fixup((int64_t)prlimit((pid_t)pid, resource,
                                  (const struct rlimit *)(const void *)new16,
                                  (struct rlimit *)(void *)old16));
}

#else /* !__linux__ (unit-test build host) */

static int64_t host_epoll_create(int size)
{
    (void)size;
    errno = ENOSYS;
    return -1;
}

static int64_t host_epoll_ctl(int epfd, int op, int fd, uint8_t *host_ev16)
{
    (void)epfd;
    (void)op;
    (void)fd;
    (void)host_ev16;
    errno = ENOSYS;
    return -1;
}

static int64_t host_epoll_wait(int epfd, uint8_t *host_ev16, int maxevents,
                               int timeout_ms)
{
    (void)epfd;
    (void)host_ev16;
    (void)maxevents;
    (void)timeout_ms;
    errno = ENOSYS;
    return -1;
}

static int64_t host_epoll_pwait(int epfd, uint8_t *host_ev16, int maxevents,
                                int timeout_ms, const uint8_t *mask8)
{
    (void)epfd;
    (void)host_ev16;
    (void)maxevents;
    (void)timeout_ms;
    (void)mask8;
    errno = ENOSYS;
    return -1;
}

static int64_t host_sysinfo(uint8_t *out112)
{
    (void)out112;
    errno = ENOSYS;
    return -1;
}

static int64_t host_prlimit64(int64_t pid, int resource, const uint8_t *new16,
                              uint8_t *old16)
{
    (void)pid;
    (void)resource;
    (void)new16;
    (void)old16;
    errno = ENOSYS;
    return -1;
}

#endif /* __linux__ */

/* ------------------------------------------------------------------ */
/* select / _newselect                                                  */
/* ------------------------------------------------------------------ */

/* Shared worker for old select(82) and _newselect(142): copy the (up to
 * three) 128-byte guest fd_sets in 32-bit words, re-pack to the host's
 * 64-bit words, call pselect6 through the libc pselect() wrapper (the
 * aarch64 host has no old select syscall; libc maps pselect to it), and
 * write back the remaining-time timeval like poll_select_finish(). */
static int64_t do_select(i686_ctx_t *ctx, uint32_t n, uint32_t in_va,
                         uint32_t out_va, uint32_t exc_va, uint32_t tv_va)
{
    uint8_t gin[I686_FD_BYTES], gout[I686_FD_BYTES], gexc[I686_FD_BYTES];
    uint64_t hin[16], hout[16], hexc[16];
    struct timespec ts = {0, 0}, start = {0, 0};
    uint32_t orig_sec = 0u, orig_usec = 0u;
    int have_tv = (tv_va != 0u);
    int rc;
    int64_t ret;

    if ((int32_t)n < 0) {
        return -EINVAL;
    }
    if (n > I686_FD_SETSIZE) {
        n = I686_FD_SETSIZE; /* kernel clamps n to files->max_fds */
    }
    uint32_t nbytes = ((n + 31u) / 32u) * 4u; /* guest words covering n */

    if (in_va != 0u) {
        int e = i686_copy_from_guest(ctx, gin, in_va, nbytes);
        if (e != 0) return e;
    }
    if (out_va != 0u) {
        int e = i686_copy_from_guest(ctx, gout, out_va, nbytes);
        if (e != 0) return e;
    }
    if (exc_va != 0u) {
        int e = i686_copy_from_guest(ctx, gexc, exc_va, nbytes);
        if (e != 0) return e;
    }

    if (have_tv) {
        i686_timeval_t gtv;
        int e = i686_copy_from_guest(ctx, &gtv, tv_va, sizeof(gtv));
        if (e != 0) return e;
        if (gtv.tv_sec < 0 || gtv.tv_usec < 0 || gtv.tv_usec > 999999) {
            return -EINVAL;
        }
        orig_sec = (uint32_t)gtv.tv_sec;
        orig_usec = (uint32_t)gtv.tv_usec;
        ts.tv_sec = (time_t)gtv.tv_sec;
        ts.tv_nsec = (long)gtv.tv_usec * 1000L;
    }

    if (in_va != 0u) i686_fdset_g2h((uint8_t *)hin, gin, n);
    if (out_va != 0u) i686_fdset_g2h((uint8_t *)hout, gout, n);
    if (exc_va != 0u) i686_fdset_g2h((uint8_t *)hexc, gexc, n);

    if (have_tv && (orig_sec != 0u || orig_usec != 0u)) {
        (void)clock_gettime(CLOCK_MONOTONIC, &start);
    }
    rc = pselect((int)n,
                 (in_va != 0u) ? (fd_set *)(void *)hin : NULL,
                 (out_va != 0u) ? (fd_set *)(void *)hout : NULL,
                 (exc_va != 0u) ? (fd_set *)(void *)hexc : NULL,
                 have_tv ? &ts : NULL, NULL);
    ret = (rc < 0) ? -(int64_t)errno : (int64_t)rc;

    /* fd_set writeback: only on success (kernel skips it on error). */
    if (ret >= 0) {
        if (in_va != 0u) {
            i686_fdset_h2g(gin, (const uint8_t *)hin, n);
            (void)i686_copy_to_guest(ctx, in_va, gin, nbytes);
        }
        if (out_va != 0u) {
            i686_fdset_h2g(gout, (const uint8_t *)hout, n);
            (void)i686_copy_to_guest(ctx, out_va, gout, nbytes);
        }
        if (exc_va != 0u) {
            i686_fdset_h2g(gexc, (const uint8_t *)hexc, n);
            (void)i686_copy_to_guest(ctx, exc_va, gexc, nbytes);
        }
    }

    /* Timeout writeback: remaining time, skipped for a zero timeout,
     * EFAULT-tolerant (kernel poll_select_finish). */
    if (have_tv && (orig_sec != 0u || orig_usec != 0u) &&
        (ret >= 0 || ret == -(int64_t)EINTR)) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
            int64_t elapsed_us = (int64_t)(now.tv_sec - start.tv_sec) * 1000000 +
                                 (int64_t)(now.tv_nsec - start.tv_nsec) / 1000;
            int64_t orig_us = (int64_t)orig_sec * 1000000 + (int64_t)orig_usec;
            int64_t rem = orig_us - elapsed_us;
            i686_timeval_t gtv;
            if (rem < 0) {
                rem = 0;
            }
            gtv.tv_sec = (int32_t)(rem / 1000000);
            gtv.tv_usec = (int32_t)(rem % 1000000);
            (void)i686_copy_to_guest(ctx, tv_va, &gtv, sizeof(gtv));
        }
    }
    return ret;
}

static int64_t r_old_select(i686_ctx_t *ctx)
{
    i686_sel_args_t a;
    int e = i686_copy_from_guest(ctx, &a, ctx->gpr[I686_REG_EBX], sizeof(a));
    if (e != 0) return e;
    return do_select(ctx, a.n, a.inp, a.outp, a.exp, a.tvp);
}

static int64_t r_newselect(i686_ctx_t *ctx)
{
    return do_select(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                     ctx->gpr[I686_REG_EDX], ctx->gpr[I686_REG_ESI],
                     ctx->gpr[I686_REG_EDI]);
}

/* ------------------------------------------------------------------ */
/* poll                                                                 */
/* ------------------------------------------------------------------ */

/* poll(168): struct pollfd { int fd; short events; short revents; } is
 * 8 bytes with identical layout and identical POLL* bit values on i386
 * and the aarch64 host (include/uapi/asm-generic/poll.h; x86 has no
 * arch override), so the guest array is handed to the host poll() in
 * place — the guest window is host-addressable memory (same convention
 * as sys_read/sys_write in src/os/syscalls.c) and the host kernel
 * writes revents straight back through the mapping.  wineserver's
 * sock_check_pollhup() startup self-test and its client loop run on
 * this (RC7b T4). */
static int64_t r_poll(i686_ctx_t *ctx)
{
    uint32_t fds_va = ctx->gpr[I686_REG_EBX];
    uint32_t nfds = ctx->gpr[I686_REG_ECX];
    int32_t timeout = (int32_t)ctx->gpr[I686_REG_EDX];
    int r;

    if (nfds > 0U && fds_va < 0x1000U) {
        return -EFAULT;
    }
    if ((uint64_t)fds_va + (uint64_t)nfds * 8U > 0x100000000ULL) {
        return -EFAULT;
    }
    r = poll((struct pollfd *)(void *)i686_guest_ptr(ctx, fds_va),
             (nfds_t)nfds, (int)timeout);
    return (r < 0) ? -(long)errno : (int64_t)r;
}

/* ------------------------------------------------------------------ */
/* epoll                                                                */
/* ------------------------------------------------------------------ */

static int64_t r_epoll_create(i686_ctx_t *ctx)
{
    int32_t size = (int32_t)ctx->gpr[I686_REG_EBX];
    if (size <= 0) {
        return -EINVAL; /* kernel SYSCALL_DEFINE1(epoll_create, size) */
    }
    return host_epoll_create((int)size);
}

static int64_t r_epoll_ctl(i686_ctx_t *ctx)
{
    uint32_t op = ctx->gpr[I686_REG_ECX];
    uint32_t ev_va = ctx->gpr[I686_REG_ESI];
    uint8_t host_ev[I686_HOST_EPOLL_SZ] = {0};
    uint8_t guest_ev[12];
    int opv;

    switch (op) {
    case (uint32_t)I686_EPOLL_CTL_ADD:
        opv = I686_EPOLL_CTL_ADD;
        break;
    case (uint32_t)I686_EPOLL_CTL_DEL:
        opv = I686_EPOLL_CTL_DEL;
        break;
    case (uint32_t)I686_EPOLL_CTL_MOD:
        opv = I686_EPOLL_CTL_MOD;
        break;
    default:
        return -EINVAL;
    }

    /* The kernel copies the event only for ADD/MOD (ep_op_has_event). */
    if (opv != I686_EPOLL_CTL_DEL) {
        int e = i686_copy_from_guest(ctx, guest_ev, ev_va, sizeof(guest_ev));
        if (e != 0) return e;
        i686_epoll_unpack_guest(host_ev, guest_ev, 1);
    }
    return host_epoll_ctl((int)ctx->gpr[I686_REG_EBX], opv,
                          (int)ctx->gpr[I686_REG_EDX], host_ev);
}

static int64_t do_epoll_wait(i686_ctx_t *ctx, uint32_t epfd, uint32_t ev_va,
                             uint32_t maxevents, int32_t timeout_ms,
                             uint32_t mask_va, uint32_t sigsetsize)
{
    uint8_t *host_arr = NULL;
    uint8_t *guest_arr = NULL;
    uint8_t mask8[8];
    int64_t r;

    if ((int32_t)maxevents <= 0 || maxevents > (0x7FFFFFFFu / 16u)) {
        return -EINVAL;
    }
    if (mask_va != 0u) {
        /* compat_sys_epoll_pwait: sigsetsize must equal the 64-bit
         * compat sigset size (8). */
        if (sigsetsize != 8u) {
            return -EINVAL;
        }
        {
            int e = i686_copy_from_guest(ctx, mask8, mask_va, sizeof(mask8));
            if (e != 0) return e;
        }
    }

    host_arr = (uint8_t *)malloc((size_t)maxevents * I686_HOST_EPOLL_SZ);
    if (host_arr == NULL) {
        return -ENOMEM;
    }
    if (mask_va != 0u) {
        r = host_epoll_pwait((int)epfd, host_arr, (int)maxevents,
                             (int)timeout_ms, mask8);
    } else {
        r = host_epoll_wait((int)epfd, host_arr, (int)maxevents, (int)timeout_ms);
    }
    if (r > 0) {
        guest_arr = (uint8_t *)malloc((size_t)r * 12u);
        if (guest_arr == NULL) {
            free(host_arr);
            return -ENOMEM;
        }
        i686_epoll_pack_guest(guest_arr, host_arr, (int)r);
        {
            int e = i686_copy_to_guest(ctx, ev_va, guest_arr, (size_t)r * 12u);
            if (e != 0) {
                r = e;
            }
        }
    }
    free(guest_arr);
    free(host_arr);
    return r;
}

static int64_t r_epoll_wait(i686_ctx_t *ctx)
{
    return do_epoll_wait(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX],
                         (int32_t)ctx->gpr[I686_REG_ESI], 0u, 0u);
}

static int64_t r_epoll_pwait(i686_ctx_t *ctx)
{
    return do_epoll_wait(ctx, ctx->gpr[I686_REG_EBX], ctx->gpr[I686_REG_ECX],
                         ctx->gpr[I686_REG_EDX],
                         (int32_t)ctx->gpr[I686_REG_ESI],
                         ctx->gpr[I686_REG_EDI], ctx->gpr[I686_REG_EBP]);
}

/* ------------------------------------------------------------------ */
/* flock / fcntl / fcntl64                                              */
/* ------------------------------------------------------------------ */

static int64_t r_flock(i686_ctx_t *ctx)
{
    /* LOCK_SH/EX/NB/UN (and the old LOCK_MAND group) are identical on
     * i386 and the generic host (asm-generic/fcntl.h). */
    return fixup((int64_t)flock((int)ctx->gpr[I686_REG_EBX],
                                (int)ctx->gpr[I686_REG_ECX]));
}

static int64_t do_fcntl(i686_ctx_t *ctx, int fcntl64_entry)
{
    uint32_t fd = ctx->gpr[I686_REG_EBX];
    uint32_t cmd = ctx->gpr[I686_REG_ECX];
    uint32_t arg = ctx->gpr[I686_REG_EDX];
    int flock_bytes;
    int hcmd = i686_fcntl_cmd_to_host(cmd, fcntl64_entry, &flock_bytes);
    int64_t r;

    if (hcmd < 0) {
        return -EINVAL;
    }

    if (flock_bytes != 0) {
        uint8_t host_fl[I686_HOST_FLOCK_SZ];
        uint8_t guest_fl[24];
        int e = i686_copy_from_guest(ctx, guest_fl, arg, (size_t)flock_bytes);
        if (e != 0) return e;
        if (flock_bytes == 16) {
            i686_flock32_to_host(host_fl, guest_fl);
        } else {
            i686_flock64_to_host(host_fl, (const i686_flock64_t *)(const void *)guest_fl);
        }
        r = fixup((int64_t)fcntl((int)fd, hcmd, host_fl));
        if (r >= 0) {
            /* F_GETLK/F_OFD_GETLK fill the struct on success. */
            if (flock_bytes == 16) {
                i686_flock32_from_host(guest_fl, host_fl);
            } else {
                i686_flock64_from_host((i686_flock64_t *)(void *)guest_fl, host_fl);
            }
            (void)i686_copy_to_guest(ctx, arg, guest_fl, (size_t)flock_bytes);
        }
        return r;
    }

    switch (cmd) {
    case I686_FC_GETFL:
        r = fixup((int64_t)fcntl((int)fd, hcmd, 0));
        return (r >= 0) ? (int64_t)i686_oflags_h2g((uint32_t)r) : r;
    case I686_FC_SETFL:
        return fixup((int64_t)fcntl((int)fd, hcmd, i686_setfl_to_host(arg)));
    case I686_FC_SETOWN:
        /* arg is an int pid (may be a negative pgrp). */
        return fixup((int64_t)fcntl((int)fd, hcmd, (int)(int32_t)arg));
    case I686_FC_GETOWN_EX:
    case I686_FC_GETOWNER_UIDS: {
        uint8_t out8[8];
        r = fixup((int64_t)fcntl((int)fd, hcmd, out8));
        if (r >= 0) {
            (void)i686_copy_to_guest(ctx, arg, out8, sizeof(out8));
        }
        return r;
    }
    case I686_FC_SETOWN_EX: {
        uint8_t in8[8];
        int e = i686_copy_from_guest(ctx, in8, arg, sizeof(in8));
        if (e != 0) return e;
        return fixup((int64_t)fcntl((int)fd, hcmd, in8));
    }
    default:
        /* F_DUPFD/FD cmds/F_SETSIG/F_GETSIG/DUPFD_CLOEXEC/PIPE_SZ take
         * the integer arg straight through. */
        return fixup((int64_t)fcntl((int)fd, hcmd, arg));
    }
}

static int64_t r_fcntl(i686_ctx_t *ctx)
{
    return do_fcntl(ctx, 0);
}

static int64_t r_fcntl64(i686_ctx_t *ctx)
{
    return do_fcntl(ctx, 1);
}

/* ------------------------------------------------------------------ */
/* rlimits                                                              */
/* ------------------------------------------------------------------ */

static int64_t do_getrlimit(i686_ctx_t *ctx)
{
    uint32_t resource = ctx->gpr[I686_REG_EBX];
    uint32_t rlim_va = ctx->gpr[I686_REG_ECX];
    struct rlimit hr;
    i686_rlimit_t gr;

    if (resource >= I686_RLIM_NLIMITS) {
        return -EINVAL;
    }
    if (getrlimit((int)resource, &hr) != 0) {
        return -(int64_t)errno;
    }
    i686_rlimit_h2g(&gr, (uint64_t)hr.rlim_cur, (uint64_t)hr.rlim_max);
    return i686_copy_to_guest(ctx, rlim_va, &gr, sizeof(gr));
}

static int64_t r_getrlimit(i686_ctx_t *ctx)
{
    return do_getrlimit(ctx);
}

static int64_t r_ugetrlimit(i686_ctx_t *ctx)
{
    return do_getrlimit(ctx);
}

static int64_t r_setrlimit(i686_ctx_t *ctx)
{
    uint32_t resource = ctx->gpr[I686_REG_EBX];
    uint32_t rlim_va = ctx->gpr[I686_REG_ECX];
    i686_rlimit_t gr;
    struct rlimit hr;
    uint64_t cur, max;

    if (resource >= I686_RLIM_NLIMITS) {
        return -EINVAL;
    }
    {
        int e = i686_copy_from_guest(ctx, &gr, rlim_va, sizeof(gr));
        if (e != 0) return e;
    }
    i686_rlimit_g2h(&gr, &cur, &max);
    hr.rlim_cur = (rlim_t)cur;
    hr.rlim_max = (rlim_t)max;
    if (setrlimit((int)resource, &hr) != 0) {
        return -(int64_t)errno;
    }
    return 0;
}

/* prlimit64(340): (pid, resource, new_rlim, old_rlim) — four args, the
 * 64-bit fields live inside the 16-byte struct rlimit64 whose offsets
 * (0/8) are identical on i386 and LP64, so it is a raw copy-through. */
static int64_t r_prlimit64(i686_ctx_t *ctx)
{
    uint32_t resource = ctx->gpr[I686_REG_ECX];
    uint32_t new_va = ctx->gpr[I686_REG_EDX];
    uint32_t old_va = ctx->gpr[I686_REG_ESI];
    uint8_t new16[16], old16[16];

    if (resource >= I686_RLIM_NLIMITS) {
        return -EINVAL;
    }
    if (new_va != 0u) {
        int e = i686_copy_from_guest(ctx, new16, new_va, sizeof(new16));
        if (e != 0) return e;
    }
    {
        int64_t r = host_prlimit64((int64_t)(int32_t)ctx->gpr[I686_REG_EBX],
                                   (int)resource, new_va != 0u ? new16 : NULL,
                                   old_va != 0u ? old16 : NULL);
        if (r < 0) {
            return r;
        }
    }
    if (old_va != 0u) {
        return i686_copy_to_guest(ctx, old_va, old16, sizeof(old16));
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* sysinfo / old mmap / madvise                                         */
/* ------------------------------------------------------------------ */

static int64_t r_sysinfo(i686_ctx_t *ctx)
{
    uint8_t host112[I686_HOST_SYSINFO_SZ];
    i686_sysinfo_t g;
    int64_t r = host_sysinfo(host112);
    if (r < 0) {
        return r;
    }
    i686_sysinfo_to_guest(&g, host112);
    return i686_copy_to_guest(ctx, ctx->gpr[I686_REG_EBX], &g, sizeof(g));
}

static int64_t r_old_mmap(i686_ctx_t *ctx)
{
    i686_mmap_arg_struct_t a;
    int e = i686_copy_from_guest(ctx, &a, ctx->gpr[I686_REG_EBX], sizeof(a));
    if (e != 0) return e;

    /* arch/x86/kernel/sys_ia32.c ia32_mmap: unaligned byte offset is
     * -EINVAL; the vm layer gets the offset in pages. */
    if ((a.offset & (uint32_t)(I686_PAGE_SIZE - 1u)) != 0u) {
        return -EINVAL;
    }
    {
        uint32_t r = rt32_vm_mmap2(ctx, a.addr, a.len, a.prot,
                                   mmap_flags_to_host(a.flags), (int)a.fd,
                                   a.offset >> 12);
        return (int64_t)(int32_t)r;
    }
}

/* madvise(219): MADV_* values are shared (asm-generic/mman-common.h);
 * advice passes straight to the host window mapping. */
static int64_t r_madvise(i686_ctx_t *ctx)
{
    return fixup((int64_t)madvise(i686_guest_ptr(ctx, ctx->gpr[I686_REG_EBX]),
                                  (size_t)ctx->gpr[I686_REG_ECX],
                                  (int)ctx->gpr[I686_REG_EDX]));
}

/* ------------------------------------------------------------------ */
/* registration                                                         */
/* ------------------------------------------------------------------ */

void i686_syscalls_misc_init(void)
{
    i686_sys_register((long)L2E_NR_fcntl, r_fcntl);
    i686_sys_register((long)L2E_NR_setrlimit, r_setrlimit);
    i686_sys_register((long)L2E_NR_getrlimit, r_getrlimit);
    i686_sys_register((long)L2E_NR_ugetrlimit, r_ugetrlimit);
    i686_sys_register((long)L2E_NR_select, r_old_select);
    i686_sys_register((long)L2E_NR_poll, r_poll);
    i686_sys_register((long)L2E_NR_mmap, r_old_mmap);
    i686_sys_register((long)L2E_NR_sysinfo, r_sysinfo);
    i686_sys_register((long)L2E_NR_newselect, r_newselect);
    i686_sys_register((long)L2E_NR_flock, r_flock);
    i686_sys_register((long)L2E_NR_madvise, r_madvise);
    i686_sys_register((long)L2E_NR_fcntl64, r_fcntl64);
    i686_sys_register((long)L2E_NR_epoll_create, r_epoll_create);
    i686_sys_register((long)L2E_NR_epoll_ctl, r_epoll_ctl);
    i686_sys_register((long)L2E_NR_epoll_wait, r_epoll_wait);
    i686_sys_register((long)L2E_NR_epoll_pwait, r_epoll_pwait);
    i686_sys_register((long)L2E_NR_prlimit64, r_prlimit64);
}
