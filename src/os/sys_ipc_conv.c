/*
 * Pure marshalling and shmat bookkeeping helpers for SysV IPC syscalls
 * (Phase 2, lane L2c; split from src/os/sys_ipc.c).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include "os/sys_ipc_internal.h"

#include <errno.h>
#include <string.h>

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
