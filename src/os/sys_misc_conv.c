/*
 * src/os/sys_misc_conv.c — Pure ABI converters for sys_misc (L2e)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sys_misc_internal.h"

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

/* L2f owns the full table (src/os/sys_pass_fs.c). */
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
