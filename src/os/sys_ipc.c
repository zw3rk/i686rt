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
#include "os/sys_ipc_internal.h"
#include "os/syscalls_i386.h"
#include "rt32/rt32.h"

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

#ifdef __APPLE__
    (void)tsp;
    long r = semop((int)semid, sops, (size_t)nsops);
#else
    long r = (tsp != NULL)
                 ? semtimedop((int)semid, sops, (size_t)nsops, tsp)
                 : semop((int)semid, sops, (size_t)nsops);
#endif
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
        i686_msginfo_t mi; /* packed; uapi struct msginfo is not */
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
