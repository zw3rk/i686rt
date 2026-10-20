/*
 * src/os/sys_ipc.c — ipc(117): SysV IPC multiplexer (Phase 2, lane L2c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest ABI (verified against the Linux sources, master @ Oct 2026):
 *   - ipc(117) is SYSCALL_DEFINE6(ipc, unsigned int call, int first,
 *     unsigned long second, unsigned long third, void __user *ptr,
 *     long fifth) in ipc/syscall.c; on i386 the int 0x80 register
 *     order EBX,ECX,EDX,ESI,EDI,EBP maps to call,first,second,third,
 *     ptr,fifth (arch/x86/entry/entry_32.S; same order our Phase 1
 *     src/os/syscalls.c documents).
 *   - version = call >> 16; call &= 0xffff (the "hack for backward
 *     compatibility", ipc/syscall.c ksys_ipc).
 *   - Call numbers (include/uapi/linux/ipc.h; the x86 ipcbits.h the
 *     lane card pointed at does not exist in mainline — the constants
 *     live in linux/ipc.h since the 2025 consolidation):
 *       SEMOP 1, SEMGET 2, SEMCTL 3, SEMTIMEDOP 4,
 *       MSGSND 11, MSGRCV 12, MSGGET 13, MSGCTL 14,
 *       SHMAT 21, SHMDT 22, SHMGET 23, SHMCTL 24,
 *       IPC_64 0x0100, IPCCALL(v,op) ((v)<<16|(op)).
 *   - MSGRCV (ipc/syscall.c, case MSGRCV): version == 0 reads a
 *     guest struct ipc_kludge { struct msgbuf *msgp; long msgtyp; }
 *     (8 bytes on i386: u32 msgp, s32 msgtyp) from `ptr`
 *     (NULL ptr -> -EINVAL, bad ptr -> -EFAULT); any other version
 *     takes `ptr` as the msgbuf and `fifth` as msgtyp.  musl i386 uses
 *     the version-0 kludge form (src/ipc/msgrcv.c passes
 *     ((long[]){(long)m, type})); glibc likewise; the direct form is
 *     kept for IPC_64-style callers.
 *   - SEMCTL (ipc/syscall.c, case SEMCTL): ptr == NULL -> -EINVAL;
 *     the union semun value is fetched as one unsigned long (u32 on
 *     i386) from *ptr (musl src/ipc/semctl.c passes &arg.buf).
 *   - SHMAT (ipc/syscall.c, case SHMAT): version == 1 -> -EINVAL
 *     (iBCS2 relic); otherwise do_shmat semantics with the attach
 *     address written via put_user(raddr, (unsigned long __user *)third).
 *     SHMLBA on i386 is PAGE_SIZE (arch/x86/include/asm/shmparam.h).
 *   - musl/glibc i386 ctl calls carry IPC_64 (0x100) ORed into the cmd
 *     (second), never the call number; the host libc ORs IPC_64 into
 *     its own direct syscall, so this module strips the guest's IPC_64
 *     bit and always marshals the ipc64 layouts below.
 *
 * Guest (i386) ipc64 layouts are defined locally per kernel uapi (the
 * frozen structs_i386.h intentionally omits them, per the L2c card);
 * x86-32 uses the asm-generic ipcbuf/shmbuf/msgbuf headers plus the
 * __i386__ branch of x86 sembuf.h:
 *   - ipc64_perm: 36 B, mode u16 @20 (__kernel_mode_t is u16 on x86-32,
 *     arch/x86/include/uapi/asm/posix_types_32.h), seq u16 @24.
 *   - semid64_ds: 64 B (perm + otime/otime_high/ctime/ctime_high/
 *     nsems/unused3/unused4, all u32; arch/x86/include/uapi/asm/sembuf.h).
 *   - shmid64_ds: 84 B (perm + segsz + atime/dtime/ctime each with
 *     _high halves + cpid/lpid s32 + nattch/unused4/unused5;
 *     include/uapi/asm-generic/shmbuf.h, __BITS_PER_LONG == 32 branch).
 *   - msqid64_ds: 88 B (perm + stime/rtime/ctime with _high halves +
 *     cbytes/qnum/qbytes + lspid/lrpid + unused4/5;
 *     include/uapi/asm-generic/msgbuf.h).
 * Host (aarch64) layouts are the libc structs from <sys/{ipc,sem,shm,msg}.h>
 * accessed through POSIX field names only (key/uid/.../mode/seq,
 * sem_*, shm_*, msg_*), which are layout-compatible with the native
 * kernel ipc64 structs on the aarch64 host for both musl and glibc.
 *
 * shmat v1 LIMITATION (loud, per lane card): the host shmat() cannot
 * attach a segment at an arbitrary guest-window address, so v1 attaches
 * the segment at a kernel-chosen scratch address, copies the contents
 * ONCE into a fresh "[shm]" guest-window region, and copies guest
 * writes back at shmdt.  Writes performed by OTHER processes between
 * our shmat and shmdt are NOT observed, and our writes are not visible
 * to them until shmdt — this is a documented Phase H follow-up (direct
 * window mapping of SysV shm segments).  busybox does not use SysV shm.
 */

#define _GNU_SOURCE /* semtimedop(3) needs __USE_GNU on glibc/musl hosts */
#include "structs_i386.h" /* before sys headers: Darwin sys/signal.h
                           * #defines sa_handler, which would break the
                           * frozen header's sigaction field name. */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <time.h>

#include "marshal.h"
#include "os/syscalls_i386.h"
#include "rt32/rt32.h"

/*
 * struct ipc_perm key/seq field names: Linux libcs expose `key`/`seq`
 * (musl maps its reserved __key/__seq under _GNU_SOURCE, glibc under
 * __USE_MISC); Darwin's SDK reserves them as `_key`/`_seq`.  The three
 * hosts all carry the same values; only the spelling differs.
 */
#ifdef __APPLE__
#define I686_HPERM_KEY(p) ((p)->_key)
#define I686_HPERM_SEQ(p) ((p)->_seq)
#else
#define I686_HPERM_KEY(p) ((p)->key)
#define I686_HPERM_SEQ(p) ((p)->seq)
#endif

/*
 * macOS has no semtimedop(2); the host-native unit driver links a
 * TEST-ONLY stub (the host-syscall path itself is compile-checked
 * only, per the lane card).  On Linux hosts the libc declaration from
 * <sys/sem.h> (_GNU_SOURCE) is used.
 */
#if defined(__APPLE__) && !defined(__linux__)
int semtimedop(int semid, struct sembuf *sops, size_t nsops,
               const struct timespec *timeout);
#endif

/* Frozen table entry [117] = {"ipc"} (syscalls_i386.h); the frozen
 * header only spells out the Phase 1 macros, so pin it here. */
#define I686__NR_ipc 117U

/* ---- pinned guest-side ABI constants (kernel uapi values) -------------- */

/* include/uapi/linux/ipc.h */
#define I686_IPC_64    0x0100U
#define I686_IPC_RMID  0U
#define I686_IPC_SET   1U
#define I686_IPC_STAT  2U
#define I686_IPC_INFO  3U

/* include/uapi/linux/sem.h */
#define I686_SEM_GETPID     11U
#define I686_SEM_GETVAL     12U
#define I686_SEM_GETALL     13U
#define I686_SEM_GETNCNT    14U
#define I686_SEM_GETZCNT    15U
#define I686_SEM_SETVAL     16U
#define I686_SEM_SETALL     17U
#define I686_SEM_STAT       18U
#define I686_SEM_INFO       19U
#define I686_SEM_STAT_ANY   20U
/* include/uapi/linux/sem.h: SEMOPM 500, "should not be increased beyond
 * 1000"; ipc/sem.c do_semtimedop() answers anything above the live
 * sc_semopm with -E2BIG.  Cap staging at the documented ceiling. */
#define I686_SEMOPM_CEIL    1000U

/* include/uapi/linux/msg.h */
#define I686_MSG_STAT       11U
#define I686_MSG_INFO      12U
#define I686_MSG_STAT_ANY  13U

/* include/uapi/linux/shm.h */
#define I686_SHM_RDONLY   010000U
#define I686_SHM_RND     020000U
#define I686_SHM_REMAP   040000U
#define I686_SHM_LOCK       11U
#define I686_SHM_UNLOCK     12U
#define I686_SHM_STAT       13U
#define I686_SHM_INFO       14U
#define I686_SHM_STAT_ANY   15U

/* i386 mmap flag bits (rt32 guest values; MAP_PRIVATE|ANON = 0x22 is
 * the same flag set rt32_vm.c uses for anonymous guest mappings). */
#define I686_MAP_PRIVATE  0x02U
#define I686_MAP_FIXED    0x10U
#define I686_MAP_ANON     0x20U
#define I686_PROT_RW      0x03U
#define I686_PROT_RO      0x01U

/* ipc multiplexer call numbers (include/uapi/linux/ipc.h) */
#define I686_IPCOP_SEMOP      1U
#define I686_IPCOP_SEMGET     2U
#define I686_IPCOP_SEMCTL     3U
#define I686_IPCOP_SEMTIMEDOP 4U
#define I686_IPCOP_MSGSND    11U
#define I686_IPCOP_MSGRCV    12U
#define I686_IPCOP_MSGGET    13U
#define I686_IPCOP_MSGCTL    14U
#define I686_IPCOP_SHMAT     21U
#define I686_IPCOP_SHMDT     22U
#define I686_IPCOP_SHMGET    23U
#define I686_IPCOP_SHMCTL    24U

/* ---- guest (i386) ipc64 layouts, local per kernel uapi ------------------ */

typedef struct __attribute__((packed)) {
    uint32_t key;       /*  0 __kernel_key_t            */
    uint32_t uid;       /*  4 __kernel_uid32_t          */
    uint32_t gid;       /*  8                           */
    uint32_t cuid;      /* 12                           */
    uint32_t cgid;      /* 16                           */
    uint16_t mode;      /* 20 __kernel_mode_t (u16!)    */
    uint16_t __pad1;    /* 22                           */
    uint16_t seq;       /* 24                           */
    uint16_t __pad2;    /* 26                           */
    uint32_t __unused1; /* 28                           */
    uint32_t __unused2; /* 32                           */
} i686_ipc64_perm_t;

typedef struct __attribute__((packed)) {
    i686_ipc64_perm_t sem_perm; /*  0 */
    uint32_t sem_otime;      /* 36 */
    uint32_t sem_otime_high; /* 40 */
    uint32_t sem_ctime;      /* 44 */
    uint32_t sem_ctime_high; /* 48 */
    uint32_t sem_nsems;      /* 52 */
    uint32_t __unused3;      /* 56 */
    uint32_t __unused4;      /* 60 */
} i686_semid64_ds_t;

typedef struct __attribute__((packed)) {
    i686_ipc64_perm_t shm_perm; /*  0 */
    uint32_t shm_segsz;      /* 36 */
    uint32_t shm_atime;      /* 40 */
    uint32_t shm_atime_high; /* 44 */
    uint32_t shm_dtime;      /* 48 */
    uint32_t shm_dtime_high; /* 52 */
    uint32_t shm_ctime;      /* 56 */
    uint32_t shm_ctime_high; /* 60 */
    int32_t  shm_cpid;       /* 64 */
    int32_t  shm_lpid;       /* 68 */
    uint32_t shm_nattch;     /* 72 */
    uint32_t __unused4;      /* 76 */
    uint32_t __unused5;      /* 80 */
} i686_shmid64_ds_t;

typedef struct __attribute__((packed)) {
    i686_ipc64_perm_t msg_perm; /*  0 */
    uint32_t msg_stime;      /* 36 */
    uint32_t msg_stime_high; /* 40 */
    uint32_t msg_rtime;      /* 44 */
    uint32_t msg_rtime_high; /* 48 */
    uint32_t msg_ctime;      /* 52 */
    uint32_t msg_ctime_high; /* 56 */
    uint32_t msg_cbytes;     /* 60 */
    uint32_t msg_qnum;       /* 64 */
    uint32_t msg_qbytes;     /* 68 */
    int32_t  msg_lspid;      /* 72 */
    int32_t  msg_lrpid;      /* 76 */
    uint32_t __unused4;      /* 80 */
    uint32_t __unused5;      /* 84 */
} i686_msqid64_ds_t;

/* struct ipc_kludge, i386 form (include/uapi/linux/ipc.h): the version-0
 * MSGRCV indirection — u32 msgbuf pointer + s32 msgtyp. */
typedef struct __attribute__((packed)) {
    uint32_t msgp;
    int32_t  msgtyp;
} i686_ipc_kludge_t;

/* struct seminfo (include/uapi/linux/sem.h): 10 ints, layout-identical
 * on i386 and aarch64 — one local type serves host and guest sides. */
typedef struct __attribute__((packed)) {
    int32_t semmap;
    int32_t semmni;
    int32_t semmns;
    int32_t semmnu;
    int32_t semmsl;
    int32_t semopm;
    int32_t semume;
    int32_t semusz;
    int32_t semvmx;
    int32_t semaem;
} i686_seminfo_t;

/* struct msginfo (include/uapi/linux/msg.h): 7 ints + 1 u16,
 * layout-identical on i386 and aarch64. */
typedef struct __attribute__((packed)) {
    int32_t  msgpool;
    int32_t  msgmap;
    int32_t  msgmax;
    int32_t  msgmnb;
    int32_t  msgmni;
    int32_t  msgssz;
    int32_t  msgtql;
    uint16_t msgseg;
} i686_msginfo_t;

/* struct shminfo64: GUEST (i386) form — 9 u32 (asm-generic/shmbuf.h). */
typedef struct __attribute__((packed)) {
    uint32_t shmmax;
    uint32_t shmmin;
    uint32_t shmmni;
    uint32_t shmseg;
    uint32_t shmall;
    uint32_t __unused1;
    uint32_t __unused2;
    uint32_t __unused3;
    uint32_t __unused4;
} i686_shminfo64_t;

/* struct shminfo64: HOST form — 9 unsigned long (72 B on LP64 hosts);
 * the host shmctl(IPC_INFO) fills this native layout. */
typedef struct {
    unsigned long shmmax;
    unsigned long shmmin;
    unsigned long shmmni;
    unsigned long shmseg;
    unsigned long shmall;
    unsigned long __unused1;
    unsigned long __unused2;
    unsigned long __unused3;
    unsigned long __unused4;
} i686h_shminfo64_t;

/* struct shm_info (include/uapi/linux/shm.h): GUEST (i386) form. */
typedef struct __attribute__((packed)) {
    int32_t  used_ids;
    uint32_t shm_tot;
    uint32_t shm_rss;
    uint32_t shm_swp;
    uint32_t swap_attempts;
    uint32_t swap_successes;
} i686_shm_info_t;

/* struct shm_info: HOST form (int + 5 unsigned long, 48 B on LP64). */
typedef struct {
    int           used_ids;
    unsigned long shm_tot;
    unsigned long shm_rss;
    unsigned long shm_swp;
    unsigned long swap_attempts;
    unsigned long swap_successes;
} i686h_shm_info_t;

_Static_assert(sizeof(i686_ipc64_perm_t) == 36, "i386 ipc64_perm must be 36 B");
_Static_assert(offsetof(i686_ipc64_perm_t, mode) == 20, "ipc64_perm.mode @20");
_Static_assert(offsetof(i686_ipc64_perm_t, seq) == 24, "ipc64_perm.seq @24");
_Static_assert(sizeof(i686_semid64_ds_t) == 64, "i386 semid64_ds must be 64 B");
_Static_assert(offsetof(i686_semid64_ds_t, sem_otime) == 36, "semid64_ds.otime @36");
_Static_assert(offsetof(i686_semid64_ds_t, sem_nsems) == 52, "semid64_ds.nsems @52");
_Static_assert(sizeof(i686_shmid64_ds_t) == 84, "i386 shmid64_ds must be 84 B");
_Static_assert(offsetof(i686_shmid64_ds_t, shm_segsz) == 36, "shmid64_ds.segsz @36");
_Static_assert(offsetof(i686_shmid64_ds_t, shm_nattch) == 72, "shmid64_ds.nattch @72");
_Static_assert(sizeof(i686_msqid64_ds_t) == 88, "i386 msqid64_ds must be 88 B");
_Static_assert(offsetof(i686_msqid64_ds_t, msg_cbytes) == 60, "msqid64_ds.cbytes @60");
_Static_assert(offsetof(i686_msqid64_ds_t, msg_lspid) == 72, "msqid64_ds.lspid @72");
_Static_assert(sizeof(i686_ipc_kludge_t) == 8, "i386 ipc_kludge must be 8 B");
_Static_assert(sizeof(i686_seminfo_t) == 40, "seminfo must be 40 B");
_Static_assert(sizeof(i686_msginfo_t) == 30, "msginfo must be 30 B");
_Static_assert(sizeof(i686_shminfo64_t) == 36, "guest shminfo64 must be 36 B");
_Static_assert(sizeof(i686_shm_info_t) == 24, "guest shm_info must be 24 B");

/* ---- conversions: host libc struct <-> guest ipc64 (byte-exact) --------- */

static uint32_t i686_time_lo(int64_t t)
{
    return (uint32_t)(uint64_t)t;
}

static uint32_t i686_time_hi(int64_t t)
{
    return (uint32_t)((uint64_t)t >> 32);
}

void i686_ipc_perm_to_guest(const struct ipc_perm *h, i686_ipc64_perm_t *g)
{
    memset(g, 0, sizeof *g);
    g->key  = (uint32_t)I686_HPERM_KEY(h);
    g->uid  = (uint32_t)h->uid;
    g->gid  = (uint32_t)h->gid;
    g->cuid = (uint32_t)h->cuid;
    g->cgid = (uint32_t)h->cgid;
    g->mode = (uint16_t)h->mode;
    g->seq  = (uint16_t)I686_HPERM_SEQ(h);
}

void i686_ipc_perm_to_host(const i686_ipc64_perm_t *g, struct ipc_perm *h)
{
    memset(h, 0, sizeof *h);
    I686_HPERM_KEY(h) = (key_t)g->key;
    h->uid  = (uid_t)g->uid;
    h->gid  = (gid_t)g->gid;
    h->cuid = (uid_t)g->cuid;
    h->cgid = (gid_t)g->cgid;
    h->mode = (mode_t)g->mode;
    I686_HPERM_SEQ(h) = (unsigned short)g->seq;
}

void i686_ipc_semid_to_guest(const struct semid_ds *h, i686_semid64_ds_t *g)
{
    memset(g, 0, sizeof *g);
    i686_ipc_perm_to_guest(&h->sem_perm, &g->sem_perm);
    g->sem_otime      = i686_time_lo((int64_t)h->sem_otime);
    g->sem_otime_high = i686_time_hi((int64_t)h->sem_otime);
    g->sem_ctime      = i686_time_lo((int64_t)h->sem_ctime);
    g->sem_ctime_high = i686_time_hi((int64_t)h->sem_ctime);
    g->sem_nsems      = (uint32_t)h->sem_nsems;
}

void i686_ipc_semid_to_host(const i686_semid64_ds_t *g, struct semid_ds *h)
{
    memset(h, 0, sizeof *h);
    i686_ipc_perm_to_host(&g->sem_perm, &h->sem_perm);
    /* times are not settable through IPC_SET; kernel ignores them. */
    h->sem_nsems = g->sem_nsems; /* implicit narrowing on ushort hosts */
}

void i686_ipc_shmid_to_guest(const struct shmid_ds *h, i686_shmid64_ds_t *g)
{
    memset(g, 0, sizeof *g);
    i686_ipc_perm_to_guest(&h->shm_perm, &g->shm_perm);
    g->shm_segsz      = (uint32_t)h->shm_segsz;
    g->shm_atime      = i686_time_lo((int64_t)h->shm_atime);
    g->shm_atime_high = i686_time_hi((int64_t)h->shm_atime);
    g->shm_dtime      = i686_time_lo((int64_t)h->shm_dtime);
    g->shm_dtime_high = i686_time_hi((int64_t)h->shm_dtime);
    g->shm_ctime      = i686_time_lo((int64_t)h->shm_ctime);
    g->shm_ctime_high = i686_time_hi((int64_t)h->shm_ctime);
    g->shm_cpid       = (int32_t)h->shm_cpid;
    g->shm_lpid       = (int32_t)h->shm_lpid;
    g->shm_nattch     = (uint32_t)h->shm_nattch;
}

void i686_ipc_shmid_to_host(const i686_shmid64_ds_t *g, struct shmid_ds *h)
{
    memset(h, 0, sizeof *h);
    i686_ipc_perm_to_host(&g->shm_perm, &h->shm_perm);
    h->shm_segsz = (size_t)g->shm_segsz;
}

void i686_ipc_msqid_to_guest(const struct msqid_ds *h, i686_msqid64_ds_t *g)
{
    memset(g, 0, sizeof *g);
    i686_ipc_perm_to_guest(&h->msg_perm, &g->msg_perm);
    g->msg_stime      = i686_time_lo((int64_t)h->msg_stime);
    g->msg_stime_high = i686_time_hi((int64_t)h->msg_stime);
    g->msg_rtime      = i686_time_lo((int64_t)h->msg_rtime);
    g->msg_rtime_high = i686_time_hi((int64_t)h->msg_rtime);
    g->msg_ctime      = i686_time_lo((int64_t)h->msg_ctime);
    g->msg_ctime_high = i686_time_hi((int64_t)h->msg_ctime);
    g->msg_cbytes     = (uint32_t)h->msg_cbytes;
    g->msg_qnum       = (uint32_t)h->msg_qnum;
    g->msg_qbytes     = (uint32_t)h->msg_qbytes;
    g->msg_lspid      = (int32_t)h->msg_lspid;
    g->msg_lrpid      = (int32_t)h->msg_lrpid;
}

void i686_ipc_msqid_to_host(const i686_msqid64_ds_t *g, struct msqid_ds *h)
{
    memset(h, 0, sizeof *h);
    i686_ipc_perm_to_host(&g->msg_perm, &h->msg_perm);
    h->msg_qbytes = g->msg_qbytes;
}

/* ---- msgbuf pack/unpack (mtype: guest s32 <-> host long) ---------------- */

/*
 * Guest struct msgbuf is { s32 mtype; char mtext[] }, the host's is
 * { long mtype; char mtext[] } — repack between the raw byte images.
 * Both ends are little-endian (i386 guest, aarch64 host), so the host
 * mtype's low 4 bytes are the guest value.  Returns 0 or -EOVERFLOW.
 */
int i686_ipc_msgbuf_pack(uint8_t *host_buf, size_t host_len,
                         const uint8_t *guest_buf, uint32_t msgsz)
{
    if (host_len < sizeof(long) + (size_t)msgsz) {
        return -EOVERFLOW;
    }
    int64_t mtype = (int64_t)(int32_t)((uint32_t)guest_buf[0] |
                                       ((uint32_t)guest_buf[1] << 8) |
                                       ((uint32_t)guest_buf[2] << 16) |
                                       ((uint32_t)guest_buf[3] << 24));
    long hm = (long)mtype;
    memcpy(host_buf, &hm, sizeof hm);
    memcpy(host_buf + sizeof hm, guest_buf + 4U, (size_t)msgsz);
    return 0;
}

int i686_ipc_msgbuf_unpack(uint8_t *guest_buf, size_t guest_len,
                           const uint8_t *host_buf, uint32_t rlen)
{
    if (guest_len < 4U + (size_t)rlen) {
        return -EOVERFLOW;
    }
    long hm = 0;
    memcpy(&hm, host_buf, sizeof hm);
    uint32_t mtype = (uint32_t)(uint64_t)hm; /* truncate like i386 musl */
    guest_buf[0] = (uint8_t)(mtype & 0xFFU);
    guest_buf[1] = (uint8_t)((mtype >> 8) & 0xFFU);
    guest_buf[2] = (uint8_t)((mtype >> 16) & 0xFFU);
    guest_buf[3] = (uint8_t)((mtype >> 24) & 0xFFU);
    memcpy(guest_buf + 4U, host_buf + sizeof hm, (size_t)rlen);
    return 0;
}

/* ---- version-0 MSGRCV kludge ------------------------------------------- */

int i686_ipc_kludge_parse(i686_ctx_t *ctx, uint32_t ptr,
                          uint32_t *msgp, int32_t *msgtyp)
{
    if (ptr < 0x1000U) {
        return -EFAULT; /* low guard page inside the guest window */
    }
    i686_ipc_kludge_t kl;
    int rc = i686_copy_from_guest(ctx, &kl, ptr, sizeof kl);
    if (rc != 0) {
        return rc; /* -EFAULT */
    }
    *msgp   = kl.msgp;
    *msgtyp = kl.msgtyp;
    return 0;
}

/* ---- shmat/shmdt bookkeeping ------------------------------------------- */

typedef struct {
    uint32_t va;   /* guest attach address (region start)      */
    uint32_t size; /* page-rounded mapping size                */
    uint32_t len;  /* logical segment size (bytes copied)      */
    void    *host; /* host scratch attachment from shmat(2)    */
} i686_shm_attach_t;

#define I686_SHM_MAX_ATTACH 64U
static i686_shm_attach_t s_shm_attach[I686_SHM_MAX_ATTACH];

const i686_shm_attach_t *i686_ipc_shm_attach_find(uint32_t va)
{
    for (size_t i = 0U; i < I686_SHM_MAX_ATTACH; i++) {
        if (s_shm_attach[i].host != NULL && s_shm_attach[i].va == va) {
            return &s_shm_attach[i];
        }
    }
    return NULL;
}

int i686_ipc_shm_attach_add(uint32_t va, uint32_t size, uint32_t len, void *host)
{
    for (size_t i = 0U; i < I686_SHM_MAX_ATTACH; i++) {
        if (s_shm_attach[i].host == NULL) {
            s_shm_attach[i].va   = va;
            s_shm_attach[i].size = size;
            s_shm_attach[i].len  = len;
            s_shm_attach[i].host = host;
            return 0;
        }
    }
    return -ENOSPC; /* kernel limit is SHMSEG == SHMMNI (4096); v1 caps at 64 */
}

void i686_ipc_shm_attach_remove(uint32_t va)
{
    const i686_shm_attach_t *e = i686_ipc_shm_attach_find(va);
    if (e != NULL) {
        ((i686_shm_attach_t *)e)->host = NULL;
    }
}

/* do_shmat address rules (ipc/shm.c): NULL -> kernel picks (we hand the
 * choice to rt32_vm_mmap2); SHM_RND rounds down to SHMLBA (PAGE_SIZE on
 * i386); otherwise shmaddr must be SHMLBA-aligned; else -EINVAL. */
int64_t i686_ipc_shmaddr_resolve(uint32_t shmaddr, uint32_t shmflg,
                                 uint32_t *out_addr)
{
    if (shmaddr == 0U) {
        *out_addr = 0U;
        return 0;
    }
    if ((shmflg & I686_SHM_RND) != 0U) {
        *out_addr = shmaddr & ~(uint32_t)(I686_PAGE_SIZE - 1U);
        return 0;
    }
    if ((shmaddr & (uint32_t)(I686_PAGE_SIZE - 1U)) != 0U) {
        return -EINVAL;
    }
    *out_addr = shmaddr;
    return 0;
}

static int shm_range_mapped(const i686_ctx_t *ctx, uint32_t start, uint32_t end)
{
    for (size_t i = 0U; i < ctx->region_count; i++) {
        const i686_region_t *r = &ctx->regions[i];
        if (r->start < end && r->end > start) {
            return 1;
        }
    }
    return 0;
}

/* ---- host helpers ------------------------------------------------------- */

static int64_t host_ret(long r)
{
    return (r < 0) ? -(long)errno : r;
}

/* ---- SEMOP / SEMTIMEDOP -------------------------------------------------- */

static int64_t ipc_semop(i686_ctx_t *ctx, uint32_t semid, uint32_t sops_va,
                         uint32_t nsops, uint32_t timeout_va)
{
    /* struct sembuf is 6 B with identical layout on i386 and aarch64
     * (kernel ipc/syscall.c: "struct sembuf is the same on 32 and 64bit"). */
    if (nsops > I686_SEMOPM_CEIL) {
        return -E2BIG; /* ipc/sem.c: nsops > sc_semopm -> -E2BIG */
    }

    struct sembuf *sops = NULL;
    if (nsops > 0U) {
        if (sops_va < 0x1000U) {
            return -EFAULT;
        }
        sops = malloc((size_t)nsops * sizeof *sops);
        if (sops == NULL) {
            return -ENOMEM;
        }
        int rc = i686_copy_from_guest(ctx, sops, sops_va,
                                      (size_t)nsops * sizeof *sops);
        if (rc != 0) {
            free(sops);
            return rc;
        }
    }

    struct timespec ts;
    struct timespec *tsp = NULL;
    if (timeout_va != 0U) { /* SEMTIMEDOP only */
        i686_timespec_t g;
        int rc = i686_copy_from_guest(ctx, &g, timeout_va, sizeof g);
        if (rc != 0) {
            free(sops);
            return rc;
        }
        ts.tv_sec  = (time_t)(int32_t)g.tv_sec;
        ts.tv_nsec = (long)(int32_t)g.tv_nsec;
        tsp = &ts;
    }

    long r = (tsp != NULL)
                 ? semtimedop((int)semid, sops, (size_t)nsops, tsp)
                 : semop((int)semid, sops, (size_t)nsops);
    free(sops);
    return host_ret(r);
}

/* ---- SEMCTL --------------------------------------------------------------- */

static int64_t ipc_semctl(i686_ctx_t *ctx, uint32_t semid, uint32_t semnum,
                          uint32_t cmd_raw, uint32_t ptr)
{
    if (ptr == 0U) {
        return -EINVAL; /* ipc/syscall.c SEMCTL: !ptr -> -EINVAL */
    }
    if (ptr < 0x1000U) {
        return -EFAULT; /* low guard page inside the guest window */
    }
    uint32_t arg = 0;
    int rc = i686_copy_from_guest(ctx, &arg, ptr, sizeof arg);
    if (rc != 0) {
        return rc;
    }
    uint32_t cmd = cmd_raw & ~I686_IPC_64;

    switch (cmd) {
    case I686_IPC_RMID:
    case I686_SEM_GETPID:
    case I686_SEM_GETVAL:
    case I686_SEM_GETNCNT:
    case I686_SEM_GETZCNT:
        return host_ret(semctl((int)semid, (int)semnum, (int)cmd, 0));

    case I686_SEM_SETVAL:
        return host_ret(semctl((int)semid, (int)semnum, (int)cmd, (int)arg));

    case I686_IPC_SET:
    case I686_IPC_STAT:
    case I686_SEM_STAT:
    case I686_SEM_STAT_ANY: {
        struct semid_ds h;
        i686_semid64_ds_t g;
        if (arg < 0x1000U) {
            return -EFAULT; /* union semun buf is NULL/guard page */
        }
        memset(&h, 0, sizeof h);
        if (cmd == I686_IPC_SET) {
            rc = i686_copy_from_guest(ctx, &g, arg, sizeof g);
            if (rc != 0) {
                return rc;
            }
            i686_ipc_semid_to_host(&g, &h);
        }
        long r = semctl((int)semid, (int)semnum, (int)cmd, &h);
        if (r < 0) {
            return -errno;
        }
        if (cmd != I686_IPC_SET) {
            i686_ipc_semid_to_guest(&h, &g);
            rc = i686_copy_to_guest(ctx, arg, &g, sizeof g);
            if (rc != 0) {
                return rc;
            }
        }
        return r;
    }

    case I686_IPC_INFO:
    case I686_SEM_INFO: {
        if (arg < 0x1000U) {
            return -EFAULT;
        }
        i686_seminfo_t si; /* layout-identical on i386 and aarch64 */
        memset(&si, 0, sizeof si);
        long r = semctl((int)semid, (int)semnum, (int)cmd, &si);
        if (r < 0) {
            return -errno;
        }
        rc = i686_copy_to_guest(ctx, arg, &si, sizeof si);
        if (rc != 0) {
            return rc;
        }
        return r;
    }

    case I686_SEM_GETALL:
    case I686_SEM_SETALL: {
        /* The kernel moves sem_nsems unsigned shorts; nsems is immutable
         * per semid, so fetch it via a host IPC_STAT first (same EACCES
         * check the real GETALL/SETALL would hit; a write-only segment
         * would wrongly see EACCES for SETALL — v1 documented).
         * NB: musl hosts type sem_nsems as ushort (kernel layout keeps
         * it inside a long-sized slot), so segments beyond 65535 sems
         * (SEMMSL default 32000) cannot be staged. */
        struct semid_ds h;
        if (semctl((int)semid, 0, (int)I686_IPC_STAT, &h) < 0) {
            return -errno;
        }
        uint32_t nsems = (uint32_t)h.sem_nsems;
        unsigned short dummy = 0;
        unsigned short *vals = (nsems != 0U)
                                   ? malloc((size_t)nsems * sizeof *vals)
                                   : &dummy;
        if (vals == NULL) {
            return -ENOMEM;
        }
        if (cmd == I686_SEM_SETALL && nsems != 0U) {
            rc = i686_copy_from_guest(ctx, vals, arg,
                                      (size_t)nsems * sizeof *vals);
            if (rc != 0) {
                if (vals != &dummy) {
                    free(vals);
                }
                return rc;
            }
        } else if (cmd == I686_SEM_GETALL && arg < 0x1000U && nsems != 0U) {
            if (vals != &dummy) {
                free(vals);
            }
            return -EFAULT;
        }
        long r = semctl((int)semid, (int)semnum, (int)cmd, vals);
        if (r >= 0 && cmd == I686_SEM_GETALL && nsems != 0U) {
            rc = i686_copy_to_guest(ctx, arg, vals,
                                    (size_t)nsems * sizeof *vals);
            if (rc != 0) {
                if (vals != &dummy) {
                    free(vals);
                }
                return rc;
            }
        }
        if (vals != &dummy) {
            free(vals);
        }
        return (r < 0) ? -(long)errno : r;
    }

    default:
        return -EINVAL;
    }
}

/* ---- MSGSND / MSGRCV ------------------------------------------------------ */

static int64_t ipc_msgsnd(i686_ctx_t *ctx, uint32_t qid, uint32_t msgp_va,
                          uint32_t msgsz, uint32_t msgflg)
{
    if (msgp_va < 0x1000U) {
        return -EFAULT;
    }
    /* msgsz is a u32, so staging (sizeof(long) + msgsz) cannot overflow
     * size_t on the LP64 hosts; an absurd size just fails malloc below. */
    uint8_t *hbuf = malloc(sizeof(long) + (size_t)msgsz);
    uint8_t *gbuf = malloc(4U + (size_t)msgsz);
    if (hbuf == NULL || gbuf == NULL) {
        free(hbuf);
        free(gbuf);
        return -ENOMEM;
    }
    int rc = i686_copy_from_guest(ctx, gbuf, msgp_va, 4U + (size_t)msgsz);
    if (rc == 0) {
        rc = i686_ipc_msgbuf_pack(hbuf, sizeof(long) + (size_t)msgsz,
                                  gbuf, msgsz);
    }
    long r = -1;
    if (rc == 0) {
        r = msgsnd((int)qid, hbuf, (size_t)msgsz, (int)msgflg);
    }
    free(hbuf);
    free(gbuf);
    return (rc != 0) ? (int64_t)rc : host_ret(r);
}

static int64_t ipc_msgrcv(i686_ctx_t *ctx, uint32_t qid, uint32_t ptr,
                          uint32_t msgsz, uint32_t msgflg, uint32_t fifth,
                          uint32_t version)
{
    uint32_t msgp_va;
    int32_t msgtyp;

    if (version == 0U) {
        /* kludge form (musl/glibc i386): ptr -> struct ipc_kludge */
        if (ptr == 0U) {
            return -EINVAL;
        }
        int rc = i686_ipc_kludge_parse(ctx, ptr, &msgp_va, &msgtyp);
        if (rc != 0) {
            return rc;
        }
    } else {
        msgp_va = ptr;
        msgtyp  = (int32_t)fifth;
    }
    if (msgp_va < 0x1000U) {
        return -EFAULT;
    }

    uint8_t *hbuf = malloc(sizeof(long) + (size_t)msgsz);
    if (hbuf == NULL) {
        return -ENOMEM;
    }
    long r = msgrcv((int)qid, hbuf, (size_t)msgsz,
                    (long)(int32_t)msgtyp, (int)msgflg);
    if (r < 0) {
        free(hbuf);
        return -errno;
    }
    uint8_t gbuf[4U + 64U];
    uint8_t *out = (msgsz <= 64U) ? gbuf
                                  : malloc(4U + (size_t)msgsz);
    if (out == NULL) {
        free(hbuf);
        return -ENOMEM;
    }
    int rc = i686_ipc_msgbuf_unpack(out, 4U + (size_t)msgsz, hbuf, (uint32_t)r);
    if (rc == 0) {
        rc = i686_copy_to_guest(ctx, msgp_va, out, 4U + (size_t)r);
    }
    if (out != gbuf) {
        free(out);
    }
    free(hbuf);
    return (rc != 0) ? rc : r;
}

/* ---- MSGCTL / SHMCTL ------------------------------------------------------ */

static int64_t ipc_msgctl(i686_ctx_t *ctx, uint32_t qid, uint32_t cmd_raw,
                          uint32_t buf_va)
{
    uint32_t cmd = cmd_raw & ~I686_IPC_64;

    switch (cmd) {
    case I686_IPC_RMID:
        return host_ret(msgctl((int)qid, (int)cmd, NULL));

    case I686_IPC_SET:
    case I686_IPC_STAT:
    case I686_MSG_STAT:
    case I686_MSG_STAT_ANY: {
        struct msqid_ds h;
        i686_msqid64_ds_t g;
        if (buf_va < 0x1000U) {
            return -EFAULT; /* NULL/guard-page buffer (kernel: EFAULT) */
        }
        memset(&h, 0, sizeof h);
        if (cmd == I686_IPC_SET) {
            int rc = i686_copy_from_guest(ctx, &g, buf_va, sizeof g);
            if (rc != 0) {
                return rc;
            }
            i686_ipc_msqid_to_host(&g, &h);
        }
        long r = msgctl((int)qid, (int)cmd, &h);
        if (r < 0) {
            return -errno;
        }
        if (cmd != I686_IPC_SET) {
            i686_ipc_msqid_to_guest(&h, &g);
            int rc = i686_copy_to_guest(ctx, buf_va, &g, sizeof g);
            if (rc != 0) {
                return rc;
            }
        }
        return r;
    }

    case I686_IPC_INFO:
    case I686_MSG_INFO: {
        if (buf_va < 0x1000U) {
            return -EFAULT;
        }
        i686_msginfo_t mi; /* layout-identical on i386 and aarch64 */
        memset(&mi, 0, sizeof mi);
        long r = msgctl((int)qid, (int)cmd, (struct msqid_ds *)(void *)&mi);
        if (r < 0) {
            return -errno;
        }
        int rc = i686_copy_to_guest(ctx, buf_va, &mi, sizeof mi);
        if (rc != 0) {
            return rc;
        }
        return r;
    }

    default:
        return -EINVAL;
    }
}

static int64_t ipc_shmctl(i686_ctx_t *ctx, uint32_t shmid, uint32_t cmd_raw,
                          uint32_t buf_va)
{
    uint32_t cmd = cmd_raw & ~I686_IPC_64;

    switch (cmd) {
    case I686_IPC_RMID:
    case I686_SHM_LOCK:
    case I686_SHM_UNLOCK:
        return host_ret(shmctl((int)shmid, (int)cmd, NULL));

    case I686_IPC_SET:
    case I686_IPC_STAT:
    case I686_SHM_STAT:
    case I686_SHM_STAT_ANY: {
        struct shmid_ds h;
        i686_shmid64_ds_t g;
        if (buf_va < 0x1000U) {
            return -EFAULT; /* NULL/guard-page buffer (kernel: EFAULT) */
        }
        memset(&h, 0, sizeof h);
        if (cmd == I686_IPC_SET) {
            int rc = i686_copy_from_guest(ctx, &g, buf_va, sizeof g);
            if (rc != 0) {
                return rc;
            }
            i686_ipc_shmid_to_host(&g, &h);
        }
        long r = shmctl((int)shmid, (int)cmd, &h);
        if (r < 0) {
            return -errno;
        }
        if (cmd != I686_IPC_SET) {
            i686_ipc_shmid_to_guest(&h, &g);
            int rc = i686_copy_to_guest(ctx, buf_va, &g, sizeof g);
            if (rc != 0) {
                return rc;
            }
        }
        return r;
    }

    case I686_IPC_INFO: {
        if (buf_va < 0x1000U) {
            return -EFAULT;
        }
        i686h_shminfo64_t hi; /* host (LP64) layout */
        memset(&hi, 0, sizeof hi);
        long r = shmctl((int)shmid, (int)cmd, (struct shmid_ds *)(void *)&hi);
        if (r < 0) {
            return -errno;
        }
        i686_shminfo64_t g;
        g.shmmax  = (uint32_t)hi.shmmax;
        g.shmmin  = (uint32_t)hi.shmmin;
        g.shmmni  = (uint32_t)hi.shmmni;
        g.shmseg  = (uint32_t)hi.shmseg;
        g.shmall  = (uint32_t)hi.shmall;
        g.__unused1 = 0;
        g.__unused2 = 0;
        g.__unused3 = 0;
        g.__unused4 = 0;
        int rc = i686_copy_to_guest(ctx, buf_va, &g, sizeof g);
        if (rc != 0) {
            return rc;
        }
        return r;
    }

    case I686_SHM_INFO: {
        if (buf_va < 0x1000U) {
            return -EFAULT;
        }
        i686h_shm_info_t hi; /* host (LP64) layout */
        memset(&hi, 0, sizeof hi);
        long r = shmctl((int)shmid, (int)cmd, (struct shmid_ds *)(void *)&hi);
        if (r < 0) {
            return -errno;
        }
        i686_shm_info_t g;
        g.used_ids       = hi.used_ids;
        g.shm_tot        = (uint32_t)hi.shm_tot;
        g.shm_rss        = (uint32_t)hi.shm_rss;
        g.shm_swp        = (uint32_t)hi.shm_swp;
        g.swap_attempts  = (uint32_t)hi.swap_attempts;
        g.swap_successes = (uint32_t)hi.swap_successes;
        int rc = i686_copy_to_guest(ctx, buf_va, &g, sizeof g);
        if (rc != 0) {
            return rc;
        }
        return r;
    }

    default:
        return -EINVAL;
    }
}

/* ---- SHMAT / SHMDT (v1 scratch-copy; see the header comment) ------------- */

static int64_t ipc_shmat(i686_ctx_t *ctx, uint32_t shmid, uint32_t shmaddr,
                         uint32_t shmflg, uint32_t raddr_va, uint32_t version)
{
    if (version == 1U) {
        return -EINVAL; /* iBCS2 kernel-origin entry point (ipc/syscall.c) */
    }

    uint32_t addr = 0;
    int64_t ar = i686_ipc_shmaddr_resolve(shmaddr, shmflg, &addr);
    if (ar != 0) {
        return ar;
    }

    /* Segment size + shmid validation via host IPC_STAT — exactly where
     * do_shmat() would fail for a bad id or missing permissions. */
    struct shmid_ds h;
    if (shmctl((int)shmid, (int)I686_IPC_STAT, &h) != 0) {
        return -errno;
    }
    uint32_t len  = (uint32_t)h.shm_segsz;
    uint32_t size = i686_page_up(len == 0U ? 1U : len);

    uint32_t prot = ((shmflg & I686_SHM_RDONLY) != 0U) ? I686_PROT_RO : I686_PROT_RW;
    uint32_t map_flags = I686_MAP_PRIVATE | I686_MAP_ANON;
    if (addr != 0U) {
        /* do_shmat: without SHM_REMAP an overlapping mapping fails with
         * -EINVAL; with it the range is taken over. */
        if ((shmflg & I686_SHM_REMAP) == 0U &&
            shm_range_mapped(ctx, addr, addr + size)) {
            return -EINVAL;
        }
        map_flags |= I686_MAP_FIXED;
    }

    uint32_t va = rt32_vm_mmap2(ctx, addr, size, prot, map_flags, -1, 0U);
    if (va > 0xFFFFF000U) {
        return (int64_t)(int32_t)va; /* (uint32_t)-errno from the vm layer */
    }

    /* v1: attach at a kernel-chosen scratch address and copy once. */
    void *scratch = shmat((int)shmid, NULL,
                          ((shmflg & I686_SHM_RDONLY) != 0U) ? SHM_RDONLY : 0);
    if (scratch == (void *)-1) {
        (void)rt32_vm_munmap(ctx, va, size);
        return -errno;
    }
    int rc = i686_copy_to_guest(ctx, va, scratch, len);
    if (rc != 0) {
        (void)shmdt(scratch);
        (void)rt32_vm_munmap(ctx, va, size);
        return rc;
    }
    rc = i686_ipc_shm_attach_add(va, size, len, scratch);
    if (rc != 0) {
        (void)shmdt(scratch);
        (void)rt32_vm_munmap(ctx, va, size);
        return rc;
    }
    (void)rt32_vm_record_region(ctx, va, va + size, prot,
                                I686_MAP_PRIVATE | I686_MAP_ANON, "[shm]");

    if (raddr_va < 0x1000U) {
        rc = -EFAULT;
    } else {
        rc = i686_copy_to_guest(ctx, raddr_va, &va, sizeof va);
    }
    if (rc != 0) {
        (void)shmdt(scratch);
        (void)rt32_vm_munmap(ctx, va, size);
        i686_ipc_shm_attach_remove(va);
        return rc;
    }
    return 0;
}

static int64_t ipc_shmdt(i686_ctx_t *ctx, uint32_t shmaddr)
{
    const i686_shm_attach_t *e = i686_ipc_shm_attach_find(shmaddr);
    if (e == NULL) {
        return -EINVAL; /* ksys_shmdt: only exact attach addresses detach */
    }

    /* v1: publish the guest's writes back into the real segment, then
     * detach the scratch attachment and release the window region. */
    int rc = i686_copy_from_guest(ctx, e->host, e->va, e->len);
    if (rc != 0) {
        return rc;
    }
    if (shmdt(e->host) != 0) {
        return -errno;
    }
    uint32_t va = e->va;
    uint32_t size = e->size;
    i686_ipc_shm_attach_remove(va);
    (void)rt32_vm_munmap(ctx, va, size);
    return 0;
}

/* ---- multiplexer ---------------------------------------------------------- */

static int64_t r_ipc(i686_ctx_t *ctx)
{
    uint32_t call    = ctx->gpr[I686_REG_EBX];
    int32_t  first   = (int32_t)ctx->gpr[I686_REG_ECX];
    uint32_t second  = ctx->gpr[I686_REG_EDX];
    uint32_t third   = ctx->gpr[I686_REG_ESI];
    uint32_t ptr     = ctx->gpr[I686_REG_EDI];
    uint32_t fifth   = ctx->gpr[I686_REG_EBP];
    uint32_t version = call >> 16; /* ipc/syscall.c backward-compat hack */
    uint32_t op      = call & 0xFFFFU;

    switch (op) {
    case I686_IPCOP_SEMOP:
        return ipc_semop(ctx, (uint32_t)first, ptr, second, 0U);
    case I686_IPCOP_SEMTIMEDOP:
        return ipc_semop(ctx, (uint32_t)first, ptr, second, fifth);
    case I686_IPCOP_SEMGET:
        return host_ret(semget((key_t)first, (int)second, (int)third));
    case I686_IPCOP_SEMCTL:
        return ipc_semctl(ctx, (uint32_t)first, second, third, ptr);
    case I686_IPCOP_MSGSND:
        return ipc_msgsnd(ctx, (uint32_t)first, ptr, second, third);
    case I686_IPCOP_MSGRCV:
        return ipc_msgrcv(ctx, (uint32_t)first, ptr, second, third, fifth,
                          version);
    case I686_IPCOP_MSGGET:
        return host_ret(msgget((key_t)first, (int)second));
    case I686_IPCOP_MSGCTL:
        return ipc_msgctl(ctx, (uint32_t)first, second, ptr);
    case I686_IPCOP_SHMAT:
        return ipc_shmat(ctx, (uint32_t)first, ptr, second, third, version);
    case I686_IPCOP_SHMDT:
        return ipc_shmdt(ctx, ptr);
    case I686_IPCOP_SHMGET:
        return host_ret(shmget((key_t)first, (size_t)second, (int)third));
    case I686_IPCOP_SHMCTL:
        return ipc_shmctl(ctx, (uint32_t)first, second, ptr);
    default:
        return -ENOSYS;
    }
}

void i686_syscalls_ipc_init(void)
{
    i686_sys_register(I686__NR_ipc, r_ipc);
}
