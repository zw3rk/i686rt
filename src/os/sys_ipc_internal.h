/*
 * Internal definitions and marshalling declarations for SysV IPC syscalls
 * (src/os/sys_ipc.c and src/os/sys_ipc_conv.c).
 */

#ifndef I686RT_OS_SYS_IPC_INTERNAL_H
#define I686RT_OS_SYS_IPC_INTERNAL_H

#include "os/structs_i386.h" /* before sys headers: Darwin sys/signal.h */

#include <stddef.h>
#include <stdint.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <time.h>

#include "os/marshal.h"
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
#define I686_SEMOPM_CEIL    1000U

/* include/uapi/linux/msg.h */
#define I686_MSG_STAT       11U
#define I686_MSG_INFO       12U
#define I686_MSG_STAT_ANY   13U

/* include/uapi/linux/shm.h */
#define I686_SHM_RDONLY   010000U
#define I686_SHM_RND      020000U
#define I686_SHM_REMAP    040000U
#define I686_SHM_LOCK       11U
#define I686_SHM_UNLOCK     12U
#define I686_SHM_STAT       13U
#define I686_SHM_INFO       14U
#define I686_SHM_STAT_ANY   15U

/* i386 mmap flag bits */
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

typedef struct __attribute__((packed)) {
    uint32_t msgp;
    int32_t  msgtyp;
} i686_ipc_kludge_t;

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

typedef struct __attribute__((packed)) {
    int32_t  used_ids;
    uint32_t shm_tot;
    uint32_t shm_rss;
    uint32_t shm_swp;
    uint32_t swap_attempts;
    uint32_t swap_successes;
} i686_shm_info_t;

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

typedef struct {
    uint32_t va;   /* guest attach address (region start)      */
    uint32_t size; /* page-rounded mapping size                */
    uint32_t len;  /* logical segment size (bytes copied)      */
    void    *host; /* host scratch attachment from shmat(2)    */
} i686_shm_attach_t;

void i686_ipc_perm_to_guest(const struct ipc_perm *h, i686_ipc64_perm_t *g);
void i686_ipc_perm_to_host(const i686_ipc64_perm_t *g, struct ipc_perm *h);
void i686_ipc_semid_to_guest(const struct semid_ds *h, i686_semid64_ds_t *g);
void i686_ipc_semid_to_host(const i686_semid64_ds_t *g, struct semid_ds *h);
void i686_ipc_shmid_to_guest(const struct shmid_ds *h, i686_shmid64_ds_t *g);
void i686_ipc_shmid_to_host(const i686_shmid64_ds_t *g, struct shmid_ds *h);
void i686_ipc_msqid_to_guest(const struct msqid_ds *h, i686_msqid64_ds_t *g);
void i686_ipc_msqid_to_host(const i686_msqid64_ds_t *g, struct msqid_ds *h);

int i686_ipc_msgbuf_pack(uint8_t *host_buf, size_t host_len,
                         const uint8_t *guest_buf, uint32_t msgsz);
int i686_ipc_msgbuf_unpack(uint8_t *guest_buf, size_t guest_len,
                           const uint8_t *host_buf, uint32_t rlen);
int i686_ipc_kludge_parse(i686_ctx_t *ctx, uint32_t ptr,
                          uint32_t *msgp, int32_t *msgtyp);

const i686_shm_attach_t *i686_ipc_shm_attach_find(uint32_t va);
int i686_ipc_shm_attach_add(uint32_t va, uint32_t size, uint32_t len,
                            void *host);
void i686_ipc_shm_attach_remove(uint32_t va);
int64_t i686_ipc_shmaddr_resolve(uint32_t shmaddr, uint32_t shmflg,
                                 uint32_t *out_addr);

#endif /* I686RT_OS_SYS_IPC_INTERNAL_H */
