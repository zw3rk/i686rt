/*
 * tests/unit/test_u3_sites.c — Wave U3 lane u3-i686 host-side check
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Portable host test (macOS arm64 and aarch64 Linux): pins the 24-byte
 * dbt_mem_site_t layout, the PUSH sp_rollback_delta convention, the AOT
 * round-trip + corruption rejection, Provider A in-place COW promotion
 * (HVA stability), regime selection, and the dual-backend smoke set
 * (map/protect/unmap, JIT alloc/seal, worker sync, futex wait/wake with
 * a real cross-thread wake, epoll readiness). Expected final line:
 * U3-I686 OK.
 */

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dbt/aot/aot.h"
#include "os/backend.h"
#include "vm/vm32.h"
#include "vm/vm_file.h"

static int s_fail;
static int s_gap;

#define CHECK(cond, name)                                                  \
    do {                                                                   \
        if (!(cond)) {                                                     \
            printf("FAIL: %s (line %d)\n", name, __LINE__);                \
            s_fail++;                                                      \
        }                                                                  \
    } while (0)

/* ---- site layout -------------------------------------------------- */

static void t_site_layout(void)
{
    CHECK(sizeof(dbt_mem_site_t) == 24u, "site is 24 bytes");
    CHECK(offsetof(dbt_mem_site_t, seq_start_offset) == 0u, "site seq off");
    CHECK(offsetof(dbt_mem_site_t, host_insn_offset) == 2u, "site mem off");
    CHECK(offsetof(dbt_mem_site_t, cont_insn_offset) == 4u, "site cont off");
    CHECK(offsetof(dbt_mem_site_t, guest_pc_delta) == 6u, "site pc off");
    CHECK(offsetof(dbt_mem_site_t, npc_delta) == 8u, "site npc off");
    CHECK(offsetof(dbt_mem_site_t, insn_word) == 12u, "site insn off");
    CHECK(offsetof(dbt_mem_site_t, sp_rollback_delta) == 16u, "site sp off");
    CHECK(offsetof(dbt_mem_site_t, width) == 19u, "site width off");
    CHECK(offsetof(dbt_mem_site_t, flags) == 20u, "site flags off");
    CHECK(sizeof(i686_tlb_entry_t) == 32u, "tlb entry is 32 bytes");

    /* PUSH32 rollback: ESP pre-decremented by 4 faults -> restore +4. */
    CHECK(i686_aot_apply_rollback(0xBFFFF000u, -4) == 0xBFFFF004u,
          "push32 rollback");
    CHECK(i686_aot_apply_rollback(0xBFFFF000u, -2) == 0xBFFFF002u,
          "push16 rollback");
    CHECK(i686_aot_apply_rollback(0xBFFFF000u, 0) == 0xBFFFF000u,
          "pop rollback is identity");
}

/* ---- site ring ---------------------------------------------------- */

static void t_site_ring(void)
{
    dbt_mem_site_t site;
    dbt_mem_site_t got;
    size_t slot;
    uint64_t gen;
    memset(&site, 0, sizeof(site));
    site.insn_word = 0x00ABCD68u; /* PUSH Iz class key */
    site.width = 4u;
    site.sp_rollback_delta = -4;
    site.flags = (uint8_t)(I686_SITE_STORE | I686_SITE_PRE_COMMITTED_SP);
    site.addr_base_reg = 4u;
    site.guest_pc_delta = I686_SITE_PC_UNKNOWN;
    slot = i686_aot_note_stack_site(&site);
    gen = i686_aot_site_generation(slot);
    CHECK(i686_aot_find_site(0x00ABCD68u, &got) == 1, "ring find hits");
    CHECK(got.sp_rollback_delta == -4, "ring preserves rollback");
    CHECK(got.width == 4u, "ring preserves width");
    i686_aot_patch_pc_delta(slot, gen, 3u);
    CHECK(i686_aot_find_site(0x00ABCD68u, &got) == 1, "ring find after patch");
    CHECK(got.guest_pc_delta == 3u, "patch applies with live generation");
    i686_aot_patch_pc_delta(slot, gen + 1000000u, 9u);
    CHECK(i686_aot_find_site(0x00ABCD68u, &got) == 1, "ring find after stale");
    CHECK(got.guest_pc_delta == 3u, "stale patch is dropped");
    CHECK(i686_aot_find_site(0x00DCBA98u, &got) == 0, "ring miss returns 0");
}

/* ---- AOT round-trip ------------------------------------------------ */

static void t_aot_roundtrip(void)
{
    uint8_t code[64];
    uint8_t buf[512];
    dbt_mem_site_t sites[2];
    i686_aot_block_hdr_t hdr;
    const uint8_t *rcode;
    const dbt_mem_site_t *rsites;
    size_t n;
    size_t i;
    for (i = 0u; i < sizeof(code); i++) {
        code[i] = (uint8_t)(i * 7u + 1u);
    }
    memset(sites, 0, sizeof(sites));
    sites[0].width = 4u;
    sites[0].sp_rollback_delta = -4;
    sites[1].width = 2u;
    sites[1].sp_rollback_delta = -2;
    n = i686_aot_write_block(buf, sizeof(buf), 0x08048000u, code, sizeof(code),
                             sites, 2u, 5u);
    CHECK(n > 0u, "aot write fits");
    CHECK(i686_aot_read_block(buf, n, &hdr, &rcode, &rsites) == n,
          "aot read consumes exactly");
    CHECK(hdr.magic == I686_AOT_MAGIC, "aot magic");
    CHECK(hdr.version == I686_AOT_VERSION, "aot version");
    CHECK(hdr.guest_base == 0x08048000u, "aot guest base");
    CHECK(hdr.code_len == sizeof(code), "aot code len");
    CHECK(hdr.site_count == 2u, "aot site count");
    CHECK(memcmp(rcode, code, sizeof(code)) == 0, "aot code intact");
    CHECK(rsites[0].sp_rollback_delta == -4, "aot site0 rollback");
    CHECK(rsites[1].width == 2u, "aot site1 width");

    /* Corruption anywhere rejects the whole entry. */
    buf[n / 2] ^= 0xFFu;
    CHECK(i686_aot_read_block(buf, n, NULL, NULL, NULL) == 0u,
          "aot corrupt rejects");
    buf[n / 2] ^= 0xFFu;
    CHECK(i686_aot_read_block(buf, n, NULL, NULL, NULL) == n,
          "aot healed accepts");
    CHECK(i686_aot_read_block(buf, n - 1u, NULL, NULL, NULL) == 0u,
          "aot truncation rejects");
    CHECK(i686_aot_write_block(buf, 10u, 0u, code, sizeof(code), sites, 2u,
                               1u) == 0u,
          "aot short cap writes nothing");
}

/* ---- regime + Provider A ------------------------------------------- */

static void t_regime_file(void)
{
    void *before;
    void *after;
    size_t promoted;
    CHECK(i686_vm_regime_for_host_page(4096u) == I686_VM_REGIME_A1,
          "4K selects A1");
    CHECK(i686_vm_regime_for_host_page(16384u) == I686_VM_REGIME_A2,
          "16K selects A2");
    CHECK(i686_vm_regime_for_host_page(65536u) == I686_VM_REGIME_A2,
          "64K selects A2");
    CHECK(i686_vm_file_init(0x100000000ULL) == 0, "vm_file init");
    i686_vm_file_set_prot(0x08048000u, 8192u, 0x03u);
    CHECK(i686_vm_file_prot(0x08048000u) == 0x03u, "prot sticks");
    i686_vm_file_set_state(0x08048000u, 8192u, 1u); /* COW_CLEAN */
    before = (void *)(uintptr_t)(0x100000000ULL + 0x08048000ULL);
    promoted = i686_vm_file_promote_cow(0x08048000u, 8192u);
    after = (void *)(uintptr_t)(0x100000000ULL + 0x08048000ULL);
    CHECK(promoted == 2u, "two pages promoted");
    CHECK(before == after, "HVA stable across COW promotion");
    CHECK(i686_vm_file_state(0x08048000u) == 2u, "state is DIRTY");
    CHECK(i686_vm_file_promote_cow(0x08048000u, 8192u) == 0u,
          "second promotion is empty");
    i686_vm_file_flags_add(0x08048000u, 4096u, 0x01u);
    CHECK((i686_vm_file_flags(0x08048000u) & 0x01u) != 0u, "flag sticks");
    i686_vm_file_flags_clear(0x08048000u, 4096u, 0x01u);
    CHECK((i686_vm_file_flags(0x08048000u) & 0x01u) == 0u, "flag clears");
    {
        int pfd[2] = { -1, -1 };
        int out_fd = -1;
        uint64_t out_off = 0u;
        uint8_t out_kind = 0u;
        CHECK(pipe(pfd) == 0, "pipe for file map test");
        CHECK(i686_vm_file_track_map(pfd[0], 0x40000000u, 3u * 4096u, 4096u,
                                     I686_BACKING_SHARED_FILE) == 0,
              "track file map succeeds");
        (void)close(pfd[0]);
        (void)close(pfd[1]);
        /* Interior hole split (I686-R2-7) + owned_fd retention (I686-R2-6). */
        CHECK(i686_vm_file_untrack_map(0x40001000u, 4096u) == 0,
              "interior hole split succeeds");
        CHECK(i686_vm_file_lookup_map(0x40000000u, &out_fd, &out_off,
                                      &out_kind) == 0 &&
              out_fd >= 0 && out_fd != pfd[0] && out_off == 4096u &&
              out_kind == I686_BACKING_SHARED_FILE,
              "prefix retained after interior hole split");
        CHECK(i686_vm_file_lookup_map(0x40002000u, &out_fd, &out_off,
                                      &out_kind) == 0 &&
              out_fd >= 0 && out_fd != pfd[0] && out_off == 12288u &&
              out_kind == I686_BACKING_SHARED_FILE,
              "suffix retained with adjusted file_off after hole split");
    }
    i686_vm_file_fini();
}

/* I686-R2-7 follow-up: pass 1 must free fully covered entries before
 * pass 2 splits a straddling entry, so the split reuses the freed slot
 * even when the only free slot sits at a higher index than the
 * straddling entry. The old single-pass order silently dropped the
 * suffix in that layout. */
static void t_file_untrack_high_slot(void)
{
    uint32_t k;
    int fill_ok = 1;
    int out_fd = -2;
    uint64_t out_off = 0u;
    uint8_t out_kind = 0u;
    CHECK(i686_vm_file_init(0x100000000ULL) == 0, "vm_file re-init");
    /* Slot 0: straddling entry needing an interior split. */
    CHECK(i686_vm_file_track_map(-1, 0x50000000u, 5u * 4096u, 0u,
                                 I686_BACKING_SHARED_FILE) == 0,
          "track straddler");
    /* Slots 1..254: dummies outside the untrack range. */
    for (k = 0u; k < 254u; k++) {
        if (i686_vm_file_track_map(-1, 0x60000000u + k * 4096u, 4096u, 0u,
                                   I686_BACKING_SHARED_FILE) != 0) {
            fill_ok = 0;
        }
    }
    CHECK(fill_ok, "fill registry 1..254");
    /* Slot 255: fully covered entry inside the untrack range. */
    CHECK(i686_vm_file_track_map(-1, 0x50002000u, 4096u, 0x2000u,
                                 I686_BACKING_SHARED_FILE) == 0,
          "track covered high slot");
    CHECK(i686_vm_file_untrack_map(0x50002000u, 2u * 4096u) == 0,
          "high-slot interior untrack succeeds");
    CHECK(i686_vm_file_lookup_map(0x50000000u, &out_fd, &out_off,
                                  &out_kind) == 0 && out_off == 0u &&
          out_kind == I686_BACKING_SHARED_FILE,
          "prefix retained after high-slot split");
    CHECK(i686_vm_file_lookup_map(0x50004000u, &out_fd, &out_off,
                                  &out_kind) == 0 && out_off == 0x4000u &&
          out_kind == I686_BACKING_SHARED_FILE,
          "suffix split into freed high slot");
    CHECK(i686_vm_file_lookup_map(0x50002000u, NULL, NULL, NULL) != 0,
          "covered high entry freed");
    i686_vm_file_fini();
}

/* ---- backend smoke -------------------------------------------------- */

static void t_backend_mem(void)
{
    void *p = NULL;
    CHECK(rt_host_page_size() >= 4096u, "page size sane");
    CHECK(rt_host_map_anon(NULL, 16384u, RT_PROT_READ | RT_PROT_WRITE, 0, 0,
                           &p) == 0 && p != NULL,
          "map anon");
    if (p != NULL) {
        memset(p, 0xA5, 16384u);
        CHECK(((volatile uint8_t *)p)[1000] == 0xA5u, "anon writable");
        CHECK(rt_host_protect(p, 16384u, RT_PROT_READ) == 0, "protect RO");
        CHECK(rt_host_unmap(p, 16384u) == 0, "unmap");
    }
}

static void t_backend_jit(void)
{
    uint8_t *code = rt_host_jit_alloc(16384u);
    CHECK(code != NULL, "jit alloc");
    if (code != NULL) {
        rt_host_jit_thread_init();
        rt_host_jit_begin_write(code, 16384u);
        memset(code, 0xC0, 64u);
        CHECK(rt_host_jit_seal_rx(code, 16384u) == 0, "jit seal RX");
        rt_host_jit_free(code, 16384u);
    }
}

static void t_backend_sync(void)
{
    rt_worker_sync_t ws;
    uint32_t seq;
    CHECK(rt_host_worker_sync_init(&ws) == 0, "sync init");
    seq = atomic_load(&ws.sig_seq);
    rt_host_worker_notify_signal(&ws);
    CHECK(atomic_load(&ws.sig_seq) == seq + 1u, "notify bumps seq");
    rt_host_worker_sync_destroy(&ws);
}

static void t_backend_futex(void)
{
    _Atomic uint32_t cell = 0u;
    rt_futex_key_t key;
    struct timespec short_ts = { 0, 50000000L }; /* 50 ms */
    int64_t rc;
    memset(&key, 0, sizeof(key));
    key.kind = RT_FUTEX_KEY_PRIVATE;
    atomic_store(&cell, 7u);
    rc = rt_host_futex_wait_bitset(&cell, &key, 8u, NULL, 0, 0, 0xFFFFFFFFu,
                                   NULL, 0u);
    CHECK(rc == (int64_t)-EAGAIN, "futex mismatch is EAGAIN");
    rc = rt_host_futex_wait_bitset(&cell, &key, 7u, &short_ts, 0, 0,
                                   0xFFFFFFFFu, NULL, 0u);
    CHECK(rc == (int64_t)-ETIMEDOUT, "futex expiry is ETIMEDOUT");
    rc = rt_host_futex_wake_bitset(&cell, &key, 1, 0xFFFFFFFFu);
    CHECK(rc == 0, "futex wake ok");
}

#ifdef __APPLE__
static _Atomic uint32_t s_wcell;
static volatile int s_wwoke;

static void *futex_waiter(void *arg)
{
    rt_futex_key_t *key = arg;
    struct timespec long_ts = { 5, 0 };
    int64_t rc = rt_host_futex_wait_bitset(&s_wcell, key, 100u, &long_ts, 0, 0,
                                           0xFFFFFFFFu, NULL, 0u);
    s_wwoke = (rc == 0 && atomic_load(&s_wcell) == 200u) ? 1 : -1;
    return NULL;
}

static void t_backend_futex_threaded(void)
{
    rt_futex_key_t key;
    pthread_t th;
    struct timespec nap = { 0, 50000000L };
    memset(&key, 0, sizeof(key));
    key.kind = RT_FUTEX_KEY_PRIVATE;
    atomic_store(&s_wcell, 100u);
    s_wwoke = 0;
    CHECK(pthread_create(&th, NULL, futex_waiter, &key) == 0,
          "waiter spawns");
    (void)nanosleep(&nap, NULL); /* let the waiter sleep */
    atomic_store(&s_wcell, 200u);
    CHECK(rt_host_futex_wake_bitset(&s_wcell, &key, 1, 0xFFFFFFFFu) == 0,
          "threaded wake ok");
    (void)pthread_join(th, NULL);
    CHECK(s_wwoke == 1, "waiter woke with new value");
}
#endif

static void t_backend_epoll(void)
{
    int64_t epfd = rt_host_epoll_create1(0);
    int fds[2] = { -1, -1 };
    uint8_t evbuf[16];
    uint8_t outbuf[16];
    int64_t n;
    if (epfd < 0) {
        s_gap++;
        printf("GAP: epoll backend unavailable (%lld)\n", (long long)epfd);
        return;
    }
    CHECK(rt_host_pipe2(fds, 0) == 0, "pipe for epoll");
    memset(evbuf, 0, sizeof(evbuf));
    evbuf[0] = 0x01u; /* EPOLLIN on both backends */
    memcpy(evbuf + 8, "DATA1234", 8u);
    CHECK(rt_host_epoll_ctl(epfd, 1, fds[0], evbuf) == 0, "epoll add");
    CHECK(write(fds[1], "x", 1) == 1, "epoll stimulus");
    n = rt_host_epoll_pwait(epfd, outbuf, 4, 2000, NULL, NULL, 0u);
    CHECK(n >= 1, "epoll fires");
    if (n >= 1) {
        CHECK(memcmp(outbuf + 8, "DATA1234", 8u) == 0, "epoll data round-trips");
    }
    CHECK(rt_host_epoll_ctl(epfd, 2, fds[0], NULL) == 0, "epoll del");
    (void)close(fds[0]);
    (void)close(fds[1]);
}

int main(void)
{
    t_site_layout();
    t_site_ring();
    t_aot_roundtrip();
    t_regime_file();
    t_file_untrack_high_slot();
    t_backend_mem();
    t_backend_jit();
    t_backend_sync();
    t_backend_futex();
#ifdef __APPLE__
    t_backend_futex_threaded();
#endif
    t_backend_epoll();
    if (s_fail == 0 && s_gap == 0) {
        printf("U3-I686 OK (0 FAIL, 0 GAP)\n");
        return 0;
    }
    printf("U3-I686 done: %d FAIL, %d GAP\n", s_fail, s_gap);
    return 1;
}
