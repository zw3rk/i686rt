/*
 * src/os/structs_i386.h — i386 guest-visible struct layouts (SPEC §3.4)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2 freeze: sizes/offsets are ABI against kernel uapi values
 * (i386 aligns u64 to 4).  Marshalling lanes convert host (aarch64)
 * layouts to these guest layouts.  Every struct carries a _Static_assert;
 * lanes must not edit this file — escalate instead.
 */

#ifndef I686RT_OS_STRUCTS_I386_H
#define I686RT_OS_STRUCTS_I386_H

#include <stdint.h>

/* ---- time (32-bit) ---------------------------------------------------- */
typedef struct { int32_t tv_sec; int32_t tv_nsec; } i686_timespec_t;
typedef struct { int32_t tv_sec; int32_t tv_usec; } i686_timeval_t;
typedef struct {
    i686_timeval_t it_interval;
    i686_timeval_t it_value;
} i686_itimerval_t;

/* ---- stat64 (96 B, syscall 195/196/197/267) --------------------------- */
typedef struct __attribute__((packed)) {
    uint64_t st_dev;        /*  0 */
    uint8_t  __pad0[4];     /*  8 */
    uint32_t st_ino_lo;     /* 12 __st_ino */
    uint32_t st_mode;       /* 16 */
    uint32_t st_nlink;      /* 20 */
    uint32_t st_uid;        /* 24 */
    uint32_t st_gid;        /* 28 */
    uint64_t st_rdev;       /* 32 */
    uint8_t  __pad1[4];     /* 40 */
    uint64_t st_size;       /* 44 */
    uint32_t st_blksize;    /* 52 */
    uint64_t st_blocks;     /* 56 */
    uint32_t st_atime;      /* 64 */
    uint32_t st_atime_nsec; /* 68 */
    uint32_t st_mtime;      /* 72 */
    uint32_t st_mtime_nsec; /* 76 */
    uint32_t st_ctime;      /* 80 */
    uint32_t st_ctime_nsec; /* 84 */
    uint64_t st_ino;        /* 88 */
} i686_stat64_t;

/* ---- statfs64 (84 B, syscall 268; statfs(99) uses i686_statfs_t) ------ */
typedef struct __attribute__((packed)) {
    uint32_t f_type;      /*  0 */
    uint32_t f_bsize;     /*  4 */
    uint64_t f_blocks;    /*  8 */
    uint64_t f_bfree;     /* 16 */
    uint64_t f_bavail;    /* 24 */
    uint64_t f_files;     /* 32 */
    uint64_t f_ffree;     /* 40 */
    uint32_t f_fsid[2];   /* 48 fsid_t */
    uint32_t f_namelen;   /* 56 */
    uint32_t f_frsize;    /* 60 */
    uint32_t f_flags;     /* 64 */
    uint32_t f_spare[4];  /* 68 */
} i686_statfs64_t;

typedef struct __attribute__((packed)) {
    uint32_t f_type;
    uint32_t f_bsize;
    uint32_t f_blocks;   /* 32-bit counts: old compat_statfs */
    uint32_t f_bfree;
    uint32_t f_bavail;
    uint32_t f_files;
    uint32_t f_ffree;
    uint32_t f_fsid[2];
    uint32_t f_namelen;
    uint32_t f_frsize;
    uint32_t f_flags;
    uint32_t f_spare[4];
} i686_statfs_t;

/* ---- old getdents(141) dirent ----------------------------------------- */
typedef struct {
    uint32_t d_ino;
    int32_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[256];
} i686_linux_dirent_t;

/* ---- epoll (12 B vs aarch64's 16) ------------------------------------- */
typedef struct {
    uint32_t events;
    uint64_t data;
} __attribute__((packed)) i686_epoll_event_t;

/* ---- flock64 (24 B) ---------------------------------------------------- */
typedef struct {
    int16_t  l_type;
    int16_t  l_whence;
    uint64_t l_start;
    uint64_t l_len;
    int32_t  l_pid;
} __attribute__((packed)) i686_flock64_t;

/* ---- rlimit (8 B, u32 pair) ------------------------------------------- */
typedef struct { uint32_t rlim_cur; uint32_t rlim_max; } i686_rlimit_t;

/* ---- sysinfo (64 B on i386) ------------------------------------------- */
typedef struct {
    int32_t  uptime;
    uint32_t loads[3];
    uint32_t totalram;
    uint32_t freeram;
    uint32_t sharedram;
    uint32_t bufferram;
    uint32_t totalswap;
    uint32_t freeswap;
    uint16_t procs;
    uint16_t pad;
    uint32_t totalhigh;
    uint32_t freehigh;
    uint32_t mem_unit;
    char     _f[20 - 2 * sizeof(int32_t) - sizeof(int32_t)];
} i686_sysinfo_t;

/* ---- rt_sigaction (i386 order; 20 B + mask) --------------------------- */
typedef struct {
    uint32_t sa_handler;
    uint32_t sa_flags;
    uint32_t sa_restorer;
    uint32_t sa_mask[2];     /* 64-bit sigmask */
} i686_sigaction_t;

/* ---- user_desc (16 B, set_thread_area) --------------------------------- */
typedef struct {
    uint32_t entry_number;
    uint32_t base_addr;
    uint32_t limit;
    uint32_t seg_32bit : 1;
    uint32_t contents  : 2;
    uint32_t read_exec_only : 1;
    uint32_t limit_in_pages : 1;
    uint32_t seg_not_present : 1;
    uint32_t useable : 1;
} i686_user_desc_t;

/* ---- sockets ----------------------------------------------------------- */
typedef struct {
    uint32_t msg_name;
    uint32_t msg_namelen;
    uint32_t msg_iov;
    uint32_t msg_iovlen;
    uint32_t msg_control;
    uint32_t msg_controllen;
    uint32_t msg_flags;
} i686_msghdr_t;

typedef struct { uint32_t iov_base; uint32_t iov_len; } i686_iovec_t;

/* ---- old mmap(90): struct mmap_arg_struct ------------------------------ */
typedef struct {
    uint32_t addr;
    uint32_t len;
    uint32_t prot;
    uint32_t flags;
    uint32_t fd;
    uint32_t offset;
} i686_mmap_arg_struct_t;

/* ---- old select(82): fd_set-ish arg block ------------------------------ */
typedef struct {
    uint32_t in, out, exc;   /* pointers to 128-byte fd_sets */
    uint32_t timeout;        /* pointer to i686_timeval_t */
} i686_select_args_t;

/* ---- ustat / uname already in syscalls.c -------------------------------- */

_Static_assert(sizeof(i686_timespec_t) == 8, "i686_timespec_t");
_Static_assert(sizeof(i686_stat64_t) == 96, "i686_stat64_t must be 96 bytes");
_Static_assert(sizeof(i686_statfs64_t) == 84, "i686_statfs64_t must be 84 bytes");
_Static_assert(sizeof(i686_statfs_t) == 64, "i686_statfs_t must be 64 bytes");
_Static_assert(sizeof(i686_epoll_event_t) == 12, "i686_epoll_event_t 12 bytes");
_Static_assert(sizeof(i686_flock64_t) == 24, "i686_flock64_t 24 bytes");
_Static_assert(sizeof(i686_rlimit_t) == 8, "i686_rlimit_t");
_Static_assert(sizeof(i686_sysinfo_t) == 64, "i686_sysinfo_t 64 bytes");
_Static_assert(sizeof(i686_sigaction_t) == 20, "i686_sigaction_t 20 bytes");
_Static_assert(sizeof(i686_user_desc_t) == 16, "i686_user_desc_t 16 bytes");
_Static_assert(sizeof(i686_msghdr_t) == 28, "i686_msghdr_t 28 bytes");
_Static_assert(sizeof(i686_iovec_t) == 8, "i686_iovec_t");
_Static_assert(sizeof(i686_mmap_arg_struct_t) == 24, "mmap_arg_struct 24 bytes");

#endif /* I686RT_OS_STRUCTS_I386_H */
