/*
 * tests/unit/test_l2c.c — host-native unit driver for lane L2c (ipc(117))
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Drives the pure marshalling surface of src/os/sys_ipc.c against a fake
 * guest window: byte-exact ipc64 struct conversions (semid64_ds 64 B,
 * shmid64_ds 84 B, msqid64_ds 88 B, ipc64_perm 36 B), the version-0
 * MSGRCV ipc_kludge parse, msgbuf mtype pack/unpack (s32 <-> long),
 * shmat address resolution, the "[shm]" attach table, and the registry
 * dispatch guards that reject before any host SysV call is made.
 *
 * Host-syscall-touching paths (real semop/shmat/msgsnd/... on the host)
 * are compile-checked only, per the lane card: they are part of the
 * linked module object but never driven here (macOS SysV availability
 * is not deterministic, and staging real SysV objects is RC2's job).
 *
 * The struct types below mirror the module-private guest layouts in
 * src/os/sys_ipc.c; the byte-exact assertions use hard offsets, so any
 * drift in either direction fails loudly.
 *
 * Prints "L2C OK" and exits 0 when every check passes.
 */

#include "os/structs_i386.h" /* before sys headers (Darwin sa_handler macro) */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <time.h>

#include "i686rt.h"
#include "os/marshal.h"

/* ------------------------------------------------------------------ */
/* Harness                                                             */
/* ------------------------------------------------------------------ */

static int g_pass;
static int g_fail;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)

/* Fake guest window: guest_base + va lands inside this buffer
 * (little-endian host assumed — macOS arm64/x86_64). */
static uint8_t g_window[0x20000];
static i686_ctx_t ctx;

static void reset(void)
{
    memset(&ctx, 0, sizeof ctx);
    ctx.guest_base = (uint64_t)(uintptr_t)&g_window[0];
    memset(g_window, 0, sizeof g_window);
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint16_t le16(const uint8_t *p)
{
    return (uint16_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8));
}

/* ------------------------------------------------------------------ */
/* TEST-ONLY shims (module link requirements)                          */
/* ------------------------------------------------------------------ */

/* rt32 vm entry points used by the (never driven here) shmat/shmdt
 * paths; the stubs just record the call. */
static int    g_vm_mmap_calls;
static int    g_vm_munmap_calls;
static uint32_t g_vm_last_mmap_addr, g_vm_last_mmap_len;

uint32_t rt32_vm_mmap2(i686_ctx_t *c, uint32_t addr, uint32_t len, uint32_t prot,
                       uint32_t flags, int fd, uint32_t pgoff)
{
    (void)c;
    (void)prot;
    (void)flags;
    (void)fd;
    (void)pgoff;
    g_vm_mmap_calls++;
    g_vm_last_mmap_addr = addr;
    g_vm_last_mmap_len  = len;
    return 0x40000000U; /* pretend the allocator chose 1 GiB */
}

int rt32_vm_munmap(i686_ctx_t *c, uint32_t addr, uint32_t len)
{
    (void)c;
    g_vm_munmap_calls++;
    (void)addr;
    (void)len;
    return 0;
}

int rt32_vm_record_region(i686_ctx_t *c, uint32_t start, uint32_t end,
                          uint32_t prot, uint32_t flags, const char *name)
{
    (void)c;
    (void)end;
    (void)prot;
    (void)flags;
    if (c->region_count < I686_MAX_REGIONS) {
        i686_region_t *r = &c->regions[c->region_count++];
        r->start = start;
        r->end   = end;
        r->prot  = prot;
        snprintf(r->name, sizeof r->name, "%s", name);
    }
    return 0;
}

/* macOS has no semtimedop(2); host-syscall paths are compile-checked
 * only, so a recording stub is enough for the link. */
#if defined(__APPLE__) && !defined(__linux__)
int semtimedop(int semid, struct sembuf *sops, size_t nsops,
               const struct timespec *timeout)
{
    (void)semid;
    (void)sops;
    (void)nsops;
    (void)timeout;
    errno = ENOSYS;
    return -1;
}
#endif

/* ------------------------------------------------------------------ */
/* Mirrors of the module-private guest ipc64 layouts + extern decls    */
/* ------------------------------------------------------------------ */

typedef struct __attribute__((packed)) {
    uint32_t key, uid, gid, cuid, cgid;
    uint16_t mode, __pad1, seq, __pad2;
    uint32_t __unused1, __unused2;
} m_perm_t;

typedef struct __attribute__((packed)) {
    m_perm_t sem_perm;
    uint32_t sem_otime, sem_otime_high;
    uint32_t sem_ctime, sem_ctime_high;
    uint32_t sem_nsems, __unused3, __unused4;
} m_semid64_ds_t;

typedef struct __attribute__((packed)) {
    m_perm_t shm_perm;
    uint32_t shm_segsz;
    uint32_t shm_atime, shm_atime_high;
    uint32_t shm_dtime, shm_dtime_high;
    uint32_t shm_ctime, shm_ctime_high;
    int32_t  shm_cpid, shm_lpid;
    uint32_t shm_nattch, __unused4, __unused5;
} m_shmid64_ds_t;

typedef struct __attribute__((packed)) {
    m_perm_t msg_perm;
    uint32_t msg_stime, msg_stime_high;
    uint32_t msg_rtime, msg_rtime_high;
    uint32_t msg_ctime, msg_ctime_high;
    uint32_t msg_cbytes, msg_qnum, msg_qbytes;
    int32_t  msg_lspid, msg_lrpid;
    uint32_t __unused4, __unused5;
} m_msqid64_ds_t;

typedef struct { uint32_t va; uint32_t size; uint32_t len; void *host; } m_attach_t;

void i686_ipc_perm_to_guest(const struct ipc_perm *h, m_perm_t *g);
void i686_ipc_perm_to_host(const m_perm_t *g, struct ipc_perm *h);
void i686_ipc_semid_to_guest(const struct semid_ds *h, m_semid64_ds_t *g);
void i686_ipc_semid_to_host(const m_semid64_ds_t *g, struct semid_ds *h);
void i686_ipc_shmid_to_guest(const struct shmid_ds *h, m_shmid64_ds_t *g);
void i686_ipc_shmid_to_host(const m_shmid64_ds_t *g, struct shmid_ds *h);
void i686_ipc_msqid_to_guest(const struct msqid_ds *h, m_msqid64_ds_t *g);
void i686_ipc_msqid_to_host(const m_msqid64_ds_t *g, struct msqid_ds *h);
int  i686_ipc_kludge_parse(i686_ctx_t *ctx, uint32_t ptr,
                           uint32_t *msgp, int32_t *msgtyp);
int  i686_ipc_msgbuf_pack(uint8_t *host_buf, size_t host_len,
                          const uint8_t *guest_buf, uint32_t msgsz);
int  i686_ipc_msgbuf_unpack(uint8_t *guest_buf, size_t guest_len,
                            const uint8_t *host_buf, uint32_t rlen);
int64_t i686_ipc_shmaddr_resolve(uint32_t shmaddr, uint32_t shmflg,
                                 uint32_t *out_addr);
const m_attach_t *i686_ipc_shm_attach_find(uint32_t va);
int  i686_ipc_shm_attach_add(uint32_t va, uint32_t size, uint32_t len,
                             void *host);
void i686_ipc_shm_attach_remove(uint32_t va);

/* module init (also declared in marshal.h) */
/* void i686_syscalls_ipc_init(void); */

/* ------------------------------------------------------------------ */
/* Layout self-checks (module carries the _Static_asserts; runtime     */
/* belt-and-braces on the mirrors with hard offsets)                   */
/* ------------------------------------------------------------------ */

static void t_layout(void)
{
    CHECK(sizeof(m_perm_t) == 36);
    CHECK(offsetof(m_perm_t, mode) == 20);
    CHECK(offsetof(m_perm_t, seq) == 24);
    CHECK(sizeof(m_semid64_ds_t) == 64);
    CHECK(offsetof(m_semid64_ds_t, sem_otime) == 36);
    CHECK(offsetof(m_semid64_ds_t, sem_nsems) == 52);
    CHECK(sizeof(m_shmid64_ds_t) == 84);
    CHECK(offsetof(m_shmid64_ds_t, shm_segsz) == 36);
    CHECK(offsetof(m_shmid64_ds_t, shm_nattch) == 72);
    CHECK(sizeof(m_msqid64_ds_t) == 88);
    CHECK(offsetof(m_msqid64_ds_t, msg_cbytes) == 60);
    CHECK(offsetof(m_msqid64_ds_t, msg_lspid) == 72);
}

/* ------------------------------------------------------------------ */
/* ipc64_perm conversion                                               */
/* ------------------------------------------------------------------ */

static void t_perm(void)
{
    struct ipc_perm h;
    memset(&h, 0, sizeof h);
#ifdef __APPLE__
    h._key = 0x51AB2C3D;
    h._seq = 0xBEEF;
#else
    h.key = 0x51AB2C3D;
    h.seq = 0xBEEF;
#endif
    h.uid = 1000;
    h.gid = 2000;
    h.cuid = 3000;
    h.cgid = 4000;
    h.mode = 0100644 & 07777; /* 0644 */

    m_perm_t g;
    i686_ipc_perm_to_guest(&h, &g);

    const uint8_t *b = (const uint8_t *)&g;
    CHECK(le32(b + 0) == 0x51AB2C3D);  /* key     @0  */
    CHECK(le32(b + 4) == 1000);        /* uid     @4  */
    CHECK(le32(b + 8) == 2000);        /* gid     @8  */
    CHECK(le32(b + 12) == 3000);       /* cuid    @12 */
    CHECK(le32(b + 16) == 4000);       /* cgid    @16 */
    CHECK(le16(b + 20) == 0644);       /* mode    @20 */
    CHECK(le16(b + 22) == 0);          /* __pad1  @22 */
    CHECK(le16(b + 24) == 0xBEEF);     /* seq     @24 */
    CHECK(le16(b + 26) == 0);          /* __pad2  @26 */
    CHECK(le32(b + 28) == 0);          /* unused1 @28 */
    CHECK(le32(b + 32) == 0);          /* unused2 @32 */

    struct ipc_perm h2;
    memset(&h2, 0xAA, sizeof h2);
    i686_ipc_perm_to_host(&g, &h2);
#ifdef __APPLE__
    CHECK(h2._key == 0x51AB2C3D && h2._seq == 0xBEEF);
#else
    CHECK(h2.key == 0x51AB2C3D && h2.seq == 0xBEEF);
#endif
    CHECK(h2.uid == 1000 && h2.gid == 2000 && h2.cuid == 3000 && h2.cgid == 4000);
    CHECK((h2.mode & 0777) == 0644);
}

/* ------------------------------------------------------------------ */
/* semid64_ds conversion (byte-exact, incl. y2038 _high halves)        */
/* ------------------------------------------------------------------ */

static void t_semid(void)
{
    struct semid_ds h;
    memset(&h, 0, sizeof h);
#ifdef __APPLE__
    h.sem_perm._key = 7;
    h.sem_perm._seq = 3;
#else
    h.sem_perm.key = 7;
    h.sem_perm.seq = 3;
#endif
    h.sem_perm.uid = 12;
    h.sem_perm.mode = 0600;
    h.sem_otime = (time_t)0x0000000200000001LL; /* > 32 bits */
    h.sem_ctime = (time_t)0x0000000100000002LL;
    h.sem_nsems = 4; /* ushort on musl/Darwin hosts */

    m_semid64_ds_t g;
    memset(&g, 0xEE, sizeof g);
    i686_ipc_semid_to_guest(&h, &g);

    const uint8_t *b = (const uint8_t *)&g;
    CHECK(le32(b + 36) == 0x00000001); /* sem_otime      @36 */
    CHECK(le32(b + 40) == 0x00000002); /* sem_otime_high @40 */
    CHECK(le32(b + 44) == 0x00000002); /* sem_ctime      @44 */
    CHECK(le32(b + 48) == 0x00000001); /* sem_ctime_high @48 */
    CHECK(le32(b + 52) == 4);          /* sem_nsems      @52 */
    CHECK(le32(b + 56) == 0);          /* __unused3      @56 (zeroed) */
    CHECK(le32(b + 60) == 0);          /* __unused4      @60 (zeroed) */

    struct semid_ds h2;
    memset(&h2, 0, sizeof h2);
    i686_ipc_semid_to_host(&g, &h2);
    CHECK(h2.sem_nsems == 4);
#ifdef __APPLE__
    CHECK(h2.sem_perm._key == 7);
#else
    CHECK(h2.sem_perm.key == 7);
#endif
}

/* ------------------------------------------------------------------ */
/* shmid64_ds conversion                                               */
/* ------------------------------------------------------------------ */

static void t_shmid(void)
{
    struct shmid_ds h;
    memset(&h, 0, sizeof h);
#ifdef __APPLE__
    h.shm_perm._key = 99;
    h.shm_perm._seq = 55;
#else
    h.shm_perm.key = 99;
    h.shm_perm.seq = 55;
#endif
    h.shm_perm.mode = 0666;
    h.shm_segsz = 0x10000;
    h.shm_atime = (time_t)0x0000000300000007LL;
    h.shm_dtime = (time_t)0xFFFFFFFF00000008LL; /* negative-ish hi */
    h.shm_ctime = 1700000000;
    h.shm_cpid = 4242;
    h.shm_lpid = 4243;
    h.shm_nattch = 2;

    m_shmid64_ds_t g;
    memset(&g, 0xEE, sizeof g);
    i686_ipc_shmid_to_guest(&h, &g);

    const uint8_t *b = (const uint8_t *)&g;
    CHECK(le32(b + 36) == 0x10000);    /* shm_segsz      @36 */
    CHECK(le32(b + 40) == 0x00000007); /* shm_atime      @40 */
    CHECK(le32(b + 44) == 0x00000003); /* shm_atime_high @44 */
    CHECK(le32(b + 48) == 0x00000008); /* shm_dtime      @48 */
    CHECK(le32(b + 52) == 0xFFFFFFFF); /* shm_dtime_high @52 */
    CHECK(le32(b + 56) == 1700000000); /* shm_ctime      @56 */
    CHECK(le32(b + 60) == 0);          /* shm_ctime_high @60 */
    CHECK(le32(b + 64) == 4242);       /* shm_cpid       @64 */
    CHECK(le32(b + 68) == 4243);       /* shm_lpid       @68 */
    CHECK(le32(b + 72) == 2);          /* shm_nattch     @72 */
    CHECK(le32(b + 76) == 0);          /* __unused4      @76 */
    CHECK(le32(b + 80) == 0);          /* __unused5      @80 */

    struct shmid_ds h2;
    memset(&h2, 0, sizeof h2);
    i686_ipc_shmid_to_host(&g, &h2);
    CHECK(h2.shm_segsz == 0x10000); /* IPC_SET only carries perm+segsz */
#ifdef __APPLE__
    CHECK(h2.shm_perm._key == 99 && h2.shm_perm._seq == 55);
#else
    CHECK(h2.shm_perm.key == 99 && h2.shm_perm.seq == 55);
#endif
}

/* ------------------------------------------------------------------ */
/* msqid64_ds conversion                                               */
/* ------------------------------------------------------------------ */

static void t_msqid(void)
{
    struct msqid_ds h;
    memset(&h, 0, sizeof h);
#ifdef __APPLE__
    h.msg_perm._key = 0xC0FFEE;
    h.msg_perm._seq = 9;
#else
    h.msg_perm.key = 0xC0FFEE;
    h.msg_perm.seq = 9;
#endif
    h.msg_perm.mode = 0660;
    h.msg_stime = (time_t)0x0000000400000009LL;
    h.msg_rtime = 0;
    h.msg_ctime = 1600000000;
    h.msg_cbytes = 1234;
    h.msg_qnum = 17;
    h.msg_qbytes = 16384;
    h.msg_lspid = 31337;
    h.msg_lrpid = 31338;

    m_msqid64_ds_t g;
    memset(&g, 0xEE, sizeof g);
    i686_ipc_msqid_to_guest(&h, &g);

    const uint8_t *b = (const uint8_t *)&g;
    CHECK(le32(b + 36) == 0x00000009); /* msg_stime      @36 */
    CHECK(le32(b + 40) == 0x00000004); /* msg_stime_high @40 */
    CHECK(le32(b + 44) == 0);          /* msg_rtime      @44 */
    CHECK(le32(b + 48) == 0);          /* msg_rtime_high @48 */
    CHECK(le32(b + 52) == 1600000000); /* msg_ctime      @52 */
    CHECK(le32(b + 56) == 0);          /* msg_ctime_high @56 */
    CHECK(le32(b + 60) == 1234);       /* msg_cbytes     @60 */
    CHECK(le32(b + 64) == 17);         /* msg_qnum       @64 */
    CHECK(le32(b + 68) == 16384);      /* msg_qbytes     @68 */
    CHECK(le32(b + 72) == 31337);      /* msg_lspid      @72 */
    CHECK(le32(b + 76) == 31338);      /* msg_lrpid      @76 */
    CHECK(le32(b + 80) == 0);          /* __unused4      @80 */

    struct msqid_ds h2;
    memset(&h2, 0, sizeof h2);
    i686_ipc_msqid_to_host(&g, &h2);
    CHECK(h2.msg_qbytes == 16384); /* IPC_SET only carries perm+qbytes */
#ifdef __APPLE__
    CHECK(h2.msg_perm._key == 0xC0FFEE);
#else
    CHECK(h2.msg_perm.key == 0xC0FFEE);
#endif
}

/* ------------------------------------------------------------------ */
/* MSGRCV ipc_kludge parse (version-0 form)                            */
/* ------------------------------------------------------------------ */

static void t_kludge(void)
{
    reset();
    /* guest struct ipc_kludge { u32 msgp; s32 msgtyp; } at 0x1000 */
    g_window[0x1000] = 0xEF;
    g_window[0x1001] = 0xBE;
    g_window[0x1002] = 0xAD;
    g_window[0x1003] = 0xDE;
    g_window[0x1004] = 0xFB;
    g_window[0x1005] = 0xFF;
    g_window[0x1006] = 0xFF;
    g_window[0x1007] = 0xFF;

    uint32_t msgp = 0;
    int32_t msgtyp = 0;
    CHECK(i686_ipc_kludge_parse(&ctx, 0x1000, &msgp, &msgtyp) == 0);
    CHECK(msgp == 0xDEADBEEF);
    CHECK(msgtyp == -5); /* s32 sign-extended semantics preserved */

    /* kernel: !ptr -> -EINVAL is the handler's job; the parser only
     * guards the low window and bounds. */
    CHECK(i686_ipc_kludge_parse(&ctx, 0x800, &msgp, &msgtyp) == -EFAULT);
    /* 8-byte read crossing the 4 GiB wrap: va 0xFFFFFFFD + 8 */
    CHECK(i686_ipc_kludge_parse(&ctx, 0xFFFFFFFDU, &msgp, &msgtyp) == -EFAULT);
}

/* ------------------------------------------------------------------ */
/* msgbuf pack/unpack (msgsnd/msgrcv mtype marshalling)                */
/* ------------------------------------------------------------------ */

static void t_msgbuf(void)
{
    /* guest: mtype -3 (s32), text "AB" */
    uint8_t gbuf[4 + 2] = {0xFD, 0xFF, 0xFF, 0xFF, 'A', 'B'};
    uint8_t hbuf[8 + 2];
    memset(hbuf, 0, sizeof hbuf);
    CHECK(i686_ipc_msgbuf_pack(hbuf, sizeof hbuf, gbuf, 2) == 0);
    CHECK(sizeof(long) == 8); /* LP64 test host */
    CHECK(le32(hbuf) == 0xFFFFFFFD);        /* mtype low half */
    CHECK(hbuf[4] == 0xFF && hbuf[5] == 0xFF && hbuf[6] == 0xFF &&
          hbuf[7] == 0xFF);                 /* sign extension to long */
    CHECK(hbuf[8] == 'A' && hbuf[9] == 'B');

    /* too small host buffer -> -EOVERFLOW */
    CHECK(i686_ipc_msgbuf_pack(hbuf, 9, gbuf, 2) == -EOVERFLOW);

    /* reverse: host long 0x1_00000005 truncates to guest u32 5 */
    uint8_t hsrc[8 + 3] = {5, 0, 0, 0, 1, 0, 0, 0, 'X', 'Y', 'Z'};
    uint8_t gout[4 + 3];
    memset(gout, 0xEE, sizeof gout);
    CHECK(i686_ipc_msgbuf_unpack(gout, sizeof gout, hsrc, 3) == 0);
    CHECK(le32(gout) == 5); /* truncation like i386 musl */
    CHECK(gout[4] == 'X' && gout[5] == 'Y' && gout[6] == 'Z');
    CHECK(i686_ipc_msgbuf_unpack(gout, 6, hsrc, 3) == -EOVERFLOW);
}

/* ------------------------------------------------------------------ */
/* shmat address resolution + attach table                             */
/* ------------------------------------------------------------------ */

static void t_shm_resolve(void)
{
    uint32_t addr = 0xFFFFFFFFU;

    CHECK(i686_ipc_shmaddr_resolve(0, 0, &addr) == 0 && addr == 0);
    CHECK(i686_ipc_shmaddr_resolve(0x2000, 0, &addr) == 0 && addr == 0x2000);
    /* unaligned without SHM_RND -> -EINVAL (do_shmat) */
    CHECK(i686_ipc_shmaddr_resolve(0x2001, 0, &addr) == -EINVAL);
    /* SHM_RND rounds down to SHMLBA == PAGE_SIZE on i386 */
    CHECK(i686_ipc_shmaddr_resolve(0x2F9B, 020000U, &addr) == 0);
    CHECK(addr == 0x2000);
    CHECK(i686_ipc_shmaddr_resolve(0x3111, 020000U, &addr) == 0);
    CHECK(addr == 0x3000);
}

static void t_shm_table(void)
{
    /* start from a clean table (module static state) */
    i686_ipc_shm_attach_remove(0x40000000U);
    CHECK(i686_ipc_shm_attach_find(0x40000000U) == NULL);
    CHECK(i686_ipc_shm_attach_add(0x40000000U, 0x2000U, 0x1234U,
                                  (void *)0x1) == 0);
    const m_attach_t *e = i686_ipc_shm_attach_find(0x40000000U);
    CHECK(e != NULL);
    CHECK(e->va == 0x40000000U && e->size == 0x2000U && e->len == 0x1234U);
    CHECK(e->host == (void *)0x1);
    /* kernel shmdt only accepts exact attach addresses */
    CHECK(i686_ipc_shm_attach_find(0x40000123U) == NULL);
    CHECK(i686_ipc_shm_attach_find(0x3FFF0000U) == NULL);
    i686_ipc_shm_attach_remove(0x40000000U);
    CHECK(i686_ipc_shm_attach_find(0x40000000U) == NULL);
}

/* ------------------------------------------------------------------ */
/* guest window copies (the shm scratch-copy primitive)                */
/* ------------------------------------------------------------------ */

static void t_window_copy(void)
{
    reset();
    static const uint8_t src[16] = {
        'i', '6', '8', '6', 'r', 't', '-', 's',
        'h', 'm', '-', 'c', 'o', 'p', 'y', '!',
    };
    CHECK(i686_copy_to_guest(&ctx, 0x1000, src, sizeof src) == 0);
    CHECK(memcmp(&g_window[0x1000], src, sizeof src) == 0);

    uint8_t dst[16];
    CHECK(i686_copy_from_guest(&ctx, dst, 0x1000, sizeof dst) == 0);
    CHECK(memcmp(dst, src, sizeof dst) == 0);

    /* 4 GiB wrap rejection (marshal.c contract) */
    CHECK(i686_copy_to_guest(&ctx, 0xFFFFFFF8U, src, 16) == -EFAULT);
    CHECK(i686_copy_from_guest(&ctx, dst, 0xFFFFFFF8U, 16) == -EFAULT);
    /* length 0 is fine even at the top of the window */
    CHECK(i686_copy_to_guest(&ctx, 0xFFFFFFF8U, src, 0) == 0);
}

/* ------------------------------------------------------------------ */
/* registry + dispatch guards (no host SysV touched)                   */
/* ------------------------------------------------------------------ */

#define T_NR_IPC 117U /* frozen syscalls_i386.h table [117] = {"ipc"} */

static void t_dispatch(void)
{
    int64_t r;

    /* unknown subcall -> -ENOSYS (ksys_ipc default) */
    reset();
    ctx.gpr[I686_REG_EBX] = 0x0099U; /* call 0x99, version 0 */
    r = i686_sys_dispatch(&ctx, (long)T_NR_IPC);
    CHECK(r == -ENOSYS);

    /* SEMOP with nsops above the SEMOPM ceiling -> -E2BIG pre-host */
    reset();
    ctx.gpr[I686_REG_EBX] = 1U;              /* SEMOP */
    ctx.gpr[I686_REG_ECX] = 42U;             /* semid */
    ctx.gpr[I686_REG_EDX] = 2000U;           /* nsops */
    ctx.gpr[I686_REG_ESI] = 0x2000U;         /* sops (unused: cap first) */
    r = i686_sys_dispatch(&ctx, (long)T_NR_IPC);
    CHECK(r == -E2BIG);

    /* SEMOP with a guard-page sops pointer -> -EFAULT */
    reset();
    ctx.gpr[I686_REG_EBX] = 1U;
    ctx.gpr[I686_REG_ECX] = 42U;
    ctx.gpr[I686_REG_EDX] = 2U;
    ctx.gpr[I686_REG_ESI] = 0x800U;
    r = i686_sys_dispatch(&ctx, (long)T_NR_IPC);
    CHECK(r == -EFAULT);

    /* SEMCTL with ptr == NULL -> -EINVAL (ipc/syscall.c) */
    reset();
    ctx.gpr[I686_REG_EBX] = 3U;              /* SEMCTL */
    ctx.gpr[I686_REG_ECX] = 42U;
    ctx.gpr[I686_REG_EDX] = 0U;
    ctx.gpr[I686_REG_ESI] = 2U;              /* IPC_STAT */
    ctx.gpr[I686_REG_EDI] = 0U;              /* ptr */
    r = i686_sys_dispatch(&ctx, (long)T_NR_IPC);
    CHECK(r == -EINVAL);

    /* SEMCTL IPC_STAT with union buf in the guard page -> -EFAULT */
    reset();
    ctx.gpr[I686_REG_EBX] = 3U;
    ctx.gpr[I686_REG_ECX] = 42U;
    ctx.gpr[I686_REG_EDX] = 0U;
    ctx.gpr[I686_REG_ESI] = 2U;
    ctx.gpr[I686_REG_EDI] = 0x1000U;         /* ptr to union value... */
    g_window[0x1000] = 0x00;
    g_window[0x1001] = 0x08;                 /* ...arg = 0x800 (guard) */
    g_window[0x1002] = 0x00;
    g_window[0x1003] = 0x00;
    r = i686_sys_dispatch(&ctx, (long)T_NR_IPC);
    CHECK(r == -EFAULT);

    /* MSGRCV version-0 with ptr == NULL -> -EINVAL (kludge form) */
    reset();
    ctx.gpr[I686_REG_EBX] = 12U;             /* MSGRCV, version 0 */
    ctx.gpr[I686_REG_ECX] = 7U;
    ctx.gpr[I686_REG_EDX] = 16U;
    ctx.gpr[I686_REG_ESI] = 0U;              /* msgflg */
    ctx.gpr[I686_REG_EDI] = 0U;              /* ptr */
    r = i686_sys_dispatch(&ctx, (long)T_NR_IPC);
    CHECK(r == -EINVAL);

    /* SHMAT with version == 1 -> -EINVAL (iBCS2 relic, ipc/syscall.c) */
    reset();
    ctx.gpr[I686_REG_EBX] = (1U << 16) | 21U; /* SHMAT, version 1 */
    ctx.gpr[I686_REG_ECX] = 42U;
    ctx.gpr[I686_REG_EDX] = 0U;
    ctx.gpr[I686_REG_ESI] = 0U;
    ctx.gpr[I686_REG_EDI] = 0U;
    r = i686_sys_dispatch(&ctx, (long)T_NR_IPC);
    CHECK(r == -EINVAL);

    /* SHMAT unaligned fixed address without SHM_RND -> -EINVAL */
    reset();
    ctx.gpr[I686_REG_EBX] = 21U;             /* SHMAT, version 0 */
    ctx.gpr[I686_REG_ECX] = 42U;
    ctx.gpr[I686_REG_EDX] = 0x2001U;         /* shmaddr */
    ctx.gpr[I686_REG_ESI] = 0U;              /* shmflg */
    ctx.gpr[I686_REG_EDI] = 0x3000U;         /* raddr out (unused) */
    r = i686_sys_dispatch(&ctx, (long)T_NR_IPC);
    CHECK(r == -EINVAL);
}

/* ------------------------------------------------------------------ */

int main(void)
{
    reset();
    i686_syscalls_ipc_init();

    t_layout();
    t_perm();
    t_semid();
    t_shmid();
    t_msqid();
    t_kludge();
    t_msgbuf();
    t_shm_resolve();
    t_shm_table();
    t_window_copy();
    t_dispatch();

    if (g_fail != 0) {
        printf("L2C FAILED: %d check(s) failed (%d passed)\n", g_fail, g_pass);
        return 1;
    }
    printf("L2C OK\n");
    return 0;
}
