/*
 * tests/c2_futex_pi.c — static i386 musl fixture for fix-campaign card
 * L-C2: the futex PI family and the val2-carrying commands, driven by
 * raw syscalls and compared against the host kernel (the SAME binary
 * runs natively in the linux/386 oracle container).
 *
 * Covered (linux/futex.h op numbers):
 *   LOCK_PI(6)/UNLOCK_PI(7)/TRYLOCK_PI(8): acquire, owner word = tid,
 *     relock -> -EDEADLK, trylock on held -> -EAGAIN, unlock by
 *     non-owner -> -EPERM, unlock of unowned -> -EPERM, blocked LOCK_PI
 *     timeout -> -ETIMEDOUT, LOCK_PI waiter acquires on UNLOCK_PI.
 *   CMP_REQUEUE(4): waiters requeued onto a second futex with
 *     val2 = nr_requeue taken from the i386 arg4 register (the timespec
 *     slot) — the translator must pass that register raw, not as a
 *     timeout pointer and not as 0.
 *   WAKE_OP(5): val2 (nr_wake2) rides the same slot.
 *   WAIT_REQUEUE_PI(11) + CMP_REQUEUE_PI(12): the glibc condvar+PI
 *     mutex shape — wait on a plain futex, requeue onto a PI-held
 *     futex, acquisition through the holder's UNLOCK_PI.
 *
 * Build (linux/386 oracle, alpine gcc, static musl):
 *   cc -std=c11 -O1 -static -o /w/_build/c2_futex_pi /w/tests/c2_futex_pi.c
 * Run natively in the 386 container (oracle) and under the i686rt build
 * in the arm64 container: both must print "C2PI PASS" and exit 0.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define FUTEX_WAIT           0u
#define FUTEX_WAKE           1u
#define FUTEX_CMP_REQUEUE    4u
#define FUTEX_WAKE_OP        5u
#define FUTEX_LOCK_PI        6u
#define FUTEX_UNLOCK_PI      7u
#define FUTEX_TRYLOCK_PI     8u
#define FUTEX_WAIT_REQUEUE_PI 11u
#define FUTEX_CMP_REQUEUE_PI  12u
#define FUTEX_PRIVATE       128u
#define FUTEX_TID_MASK      0x3fffffffu
#define FUTEX_WAITERS_BIT   0x80000000u

/* i386 timespec the kernel reads for futex timeouts: s32 sec + u32 nsec. */
struct fx_ts {
    int32_t  sec;
    uint32_t nsec;
};

static volatile uint32_t w_cond;  /* plain cond futex word  */
static volatile uint32_t w_cond2; /* requeue target (plain) */
static volatile uint32_t w_pi;    /* PI futex word          */

static long fx(volatile uint32_t *u, uint32_t op, uint32_t val, void *ts,
               volatile uint32_t *u2, uint32_t val3)
{
    /* musl syscall() returns -1 and sets errno on failure; normalize to
     * the raw kernel convention (negative errno) for the checks. */
    long r = syscall(SYS_futex, (uint32_t *)u, op, val, ts,
                     (uint32_t *)u2, val3);
    return (r < 0) ? -errno : r;
}

static int nfail;

static int fail(const char *what, long rc, long want)
{
    printf("C2PI FAIL %s rc=%ld want=%ld (errno=%d %s)\n", what, rc, want,
           errno, strerror(errno));
    nfail++;
    return 1;
}

static long tid(void)
{
    return syscall(SYS_gettid);
}

static void rel_ts(struct fx_ts *t, long ms)
{
    t->sec = (int32_t)(ms / 1000);
    t->nsec = (uint32_t)((ms % 1000) * 1000000u);
}

/* ---- 1. LOCK_PI/UNLOCK_PI basic + EDEADLK relock ---- */

static void t1_basic(void)
{
    struct fx_ts ts;
    long r;

    w_pi = 0u;
    if (fx(&w_pi, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0) != 0) {
        fail("lock_pi", -1, 0);
        return;
    }
    if ((w_pi & FUTEX_TID_MASK) != (uint32_t)tid()) {
        fail("lock_pi word", (long)(w_pi & FUTEX_TID_MASK), tid());
    }
    /* Owner relock: -EDEADLK. */
    errno = 0;
    r = fx(&w_pi, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0);
    if (r != -EDEADLK) {
        fail("relock_pi EDEADLK", r, -EDEADLK);
    }
    /* Unlock by the owner. */
    if (fx(&w_pi, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0) != 0) {
        fail("unlock_pi", -1, 0);
    }
    if (w_pi != 0u) {
        fail("unlock_pi word", (long)w_pi, 0);
    }
    /* Unlock of an unowned PI futex: -EPERM. */
    errno = 0;
    r = fx(&w_pi, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0);
    if (r != -EPERM) {
        fail("unlock_pi unowned EPERM", r, -EPERM);
    }
    /* Lock timeout on an unowned futex must not block. */
    rel_ts(&ts, 100);
    if (fx(&w_pi, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, &ts, NULL, 0) != 0) {
        fail("lock_pi free+timeout", -1, 0);
    }
    if (fx(&w_pi, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0) != 0) {
        fail("unlock_pi 2", -1, 0);
    }
}

/* ---- 2. TRYLOCK_PI / EAGAIN / EPERM cross-thread ---- */

static volatile uint32_t t2_held;
static volatile long     t2_tid_rc;
static volatile long     t2_try_rc;
static volatile long     t2_unlock_rc;
static pthread_barrier_t bar2;

static void *t2_body(void *arg)
{
    (void)arg;
    t2_tid_rc = tid();
    if (fx(&t2_held, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0) != 0) {
        t2_held = 0u;
        t2_tid_rc = -1;
        pthread_barrier_wait(&bar2);
        return NULL;
    }
    pthread_barrier_wait(&bar2);
    /* main: TRYLOCK_PI on t2's word, then UNLOCK_PI on t2's word */
    pthread_barrier_wait(&bar2);
    t2_held = 0u;
    return NULL;
}

static void t2_cross(void)
{
    struct fx_ts ts;
    long r;

    pthread_barrier_init(&bar2, NULL, 2);
    pthread_t th;
    pthread_create(&th, NULL, t2_body, NULL);
    pthread_barrier_wait(&bar2);
    if (t2_held == 0u || t2_tid_rc < 0) {
        fail("t2 lock_pi setup", t2_tid_rc, 0);
        pthread_join(th, NULL);
        return;
    }
    /* Waiter lock with timeout on a held PI futex: -ETIMEDOUT. */
    rel_ts(&ts, 150);
    errno = 0;
    r = fx(&t2_held, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, &ts, NULL, 0);
    if (r != -ETIMEDOUT) {
        fail("lock_pi held timeout ETIMEDOUT", r, -ETIMEDOUT);
    }
    /* TRYLOCK_PI on a held PI futex: -EAGAIN. */
    errno = 0;
    r = fx(&t2_held, FUTEX_TRYLOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0);
    if (r != -EAGAIN) {
        fail("trylock_pi held EAGAIN", r, -EAGAIN);
    }
    /* Unlock by a non-owner tid: -EPERM. */
    errno = 0;
    r = fx(&t2_held, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0);
    if (r != -EPERM) {
        fail("unlock_pi foreign EPERM", r, -EPERM);
    }
    pthread_barrier_wait(&bar2); /* t2 releases + exits */
    pthread_join(th, NULL);
    pthread_barrier_destroy(&bar2);
}

/* ---- 3. LOCK_PI waiter acquires on UNLOCK_PI ---- */

static volatile uint32_t w_wait;
static volatile long     t3_rc;
static volatile long     t3_tid;

static void *t3_body(void *arg)
{
    (void)arg;
    t3_rc = fx(&w_wait, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0);
    if (t3_rc == 0) {
        t3_tid = tid();
    }
    return NULL;
}

static void t3_waiter_wake(void)
{
    w_wait = 0u;
    if (fx(&w_wait, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0) != 0) {
        fail("t3 holder lock", -1, 0);
        return;
    }
    pthread_t th;
    pthread_create(&th, NULL, t3_body, NULL);
    struct timespec ms20 = { 0, 20 * 1000 * 1000 };
    nanosleep(&ms20, NULL); /* let t3 block */
    if (fx(&w_wait, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0) != 0) {
        fail("t3 holder unlock", -1, 0);
    }
    pthread_join(th, NULL);
    if (t3_rc != 0) {
        fail("t3 waiter acquire", t3_rc, 0);
    } else if (t3_tid != (long)(w_wait & FUTEX_TID_MASK)) {
        fail("t3 waiter word tid", (long)(w_wait & FUTEX_TID_MASK), t3_tid);
    }
    if (t3_tid > 0) {
        /* the waiter's own unlock in its (already finished) context is
         * done here by tid equality having been checked; nothing more */
    }
}

/* ---- 4. CMP_REQUEUE: val2 (nr_requeue) rides i386 arg4 ---- */

static volatile long t4_rc;
static void *t4_body(void *arg)
{
    (void)arg;
    t4_rc = fx(&w_cond, FUTEX_WAIT | FUTEX_PRIVATE, 0, NULL, NULL, 0);
    return NULL;
}

static void t4_cmp_requeue(void)
{
    struct fx_ts wake_ts;
    long r;

    w_cond = 0u;
    w_cond2 = 0u;
    rel_ts(&wake_ts, 5000); /* each waiter's own escape bound */
    pthread_t th[2];
    for (int i = 0; i < 2; i++) {
        pthread_create(&th[i], NULL, t4_body, NULL);
    }
    struct timespec ms50 = { 0, 50 * 1000 * 1000 };
    nanosleep(&ms50, NULL);

    /* wake 1 at w_cond, requeue 1 onto w_cond2 (cmp val 0).  val2 is
     * i386 arg4 — the slot the translator previously passed as a NULL
     * timeout pointer, stranding the second waiter. */
    r = fx(&w_cond, FUTEX_CMP_REQUEUE | FUTEX_PRIVATE, 1,
           (void *)1 /* val2 = nr_requeue */, &w_cond2, 0u);
    if (r != 2) {
        fail("cmp_requeue rc", r, 2);
    }
    /* The requeued waiter must still be asleep on w_cond2. */
    r = fx(&w_cond2, FUTEX_WAKE | FUTEX_PRIVATE, 1, NULL, NULL, 0);
    if (r != 1) {
        fail("cmp_requeue wake on target", r, 1);
    }
    for (int i = 0; i < 2; i++) {
        pthread_join(th[i], NULL);
    }
    if (t4_rc != 0) {
        fail("cmp_requeue waiter rc", t4_rc, 0);
    }
}

/* ---- 5. WAKE_OP: val2 (nr_wake2) rides i386 arg4 ---- */

#define FUTEX_OP_SET     0u
#define FUTEX_CMP_EQ     0u

static volatile long t5_rc[2];
static void *t5_body(void *arg)
{
    long i = (long)(intptr_t)arg;
    t5_rc[i] = fx(&w_cond2, FUTEX_WAIT | FUTEX_PRIVATE, 0, NULL, NULL, 0);
    return NULL;
}

static void t5_wake_op(void)
{
    long r;

    w_cond = 0u;
    w_cond2 = 0u;
    pthread_t th[2];
    for (int i = 0; i < 2; i++) {
        pthread_create(&th[i], NULL, t5_body, (void *)(intptr_t)i);
    }
    struct timespec ms50 = { 0, 50 * 1000 * 1000 };
    nanosleep(&ms50, NULL);

    /* wake 0 at w_cond; on w_cond2: SET old->1, cmp old == 0 -> wake 2.
     * op cmd encoding: op | (oparg << 12) | (cmp << 24) | cmparg. */
    uint32_t opcmd = FUTEX_OP_SET | (1u << 12) | (FUTEX_CMP_EQ << 24) | 0u;
    r = fx(&w_cond, FUTEX_WAKE_OP | FUTEX_PRIVATE, 0, (void *)2,
           &w_cond2, opcmd);
    if (r != 2) {
        fail("wake_op rc", r, 2);
    }
    for (int i = 0; i < 2; i++) {
        pthread_join(th[i], NULL);
    }
    if (t5_rc[0] != 0 || t5_rc[1] != 0) {
        fail("wake_op waiter rc", t5_rc[0] | t5_rc[1], 0);
    }
    if (w_cond2 != 1u) {
        fail("wake_op word", (long)w_cond2, 1);
    }
}

/* ---- 6. WAIT_REQUEUE_PI + CMP_REQUEUE_PI (glibc cond+PI shape) ---- */

static volatile uint32_t w_rq_cond; /* plain futex the waiter sleeps on */
static volatile uint32_t w_rq_pi;   /* PI futex requeued onto          */
static volatile long     t6_rc;

static void *t6_body(void *arg)
{
    (void)arg;
    /* (uaddr, val, timeout, uaddr2, val3=bitset) */
    t6_rc = fx(&w_rq_cond, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE, 0,
               NULL, &w_rq_pi, 0u);
    if (t6_rc == 0) {
        /* requeued AND acquired the PI futex through the unlock */
        if ((w_rq_pi & FUTEX_TID_MASK) != (uint32_t)tid()) {
            t6_rc = -1000 - (long)(w_rq_pi & FUTEX_TID_MASK);
        } else if (fx(&w_rq_pi, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0,
                      NULL, NULL, 0) != 0) {
            t6_rc = -2000;
        }
    }
    return NULL;
}

static void t6_wait_requeue_pi(void)
{
    long r;

    w_rq_cond = 0u;
    w_rq_pi = 0u;
    if (fx(&w_rq_pi, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0) != 0) {
        fail("t6 pi lock", -1, 0);
        return;
    }
    pthread_t th;
    pthread_create(&th, NULL, t6_body, NULL);
    struct timespec ms50 = { 0, 50 * 1000 * 1000 };
    nanosleep(&ms50, NULL);

    /* requeue the waiter onto the HELD PI futex.  kernel/futex/requeue.c:
     * nr_wake MUST be 1 for the requeue_pi commands (-EINVAL otherwise);
     * the glibc pthread_cond_broadcast shape is (1, INT_MAX). */
    r = fx(&w_rq_cond, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE, 1,
           (void *)1 /* val2 = nr_requeue */, &w_rq_pi, 0u);
    if (r != 1) {
        fail("cmp_requeue_pi rc", r, 1);
    }
    /* releasing the PI futex hands it to the requeued waiter */
    if (fx(&w_rq_pi, FUTEX_UNLOCK_PI | FUTEX_PRIVATE, 0, NULL, NULL, 0) != 0) {
        fail("t6 pi unlock", -1, 0);
    }
    pthread_join(th, NULL);
    if (t6_rc != 0) {
        fail("wait_requeue_pi waiter rc", t6_rc, 0);
    }
    if (w_rq_pi != 0u) {
        fail("wait_requeue_pi final word", (long)w_rq_pi, 0);
    }
    /* WAIT_REQUEUE_PI timeout path: nobody requeues -> -ETIMEDOUT */
    struct fx_ts ts;
    rel_ts(&ts, 200);
    w_rq_cond = 0u;
    w_rq_pi = 0u;
    errno = 0;
    r = fx(&w_rq_cond, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE, 0, &ts,
           &w_rq_pi, 0u);
    if (r != -ETIMEDOUT) {
        fail("wait_requeue_pi timeout", r, -ETIMEDOUT);
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    t1_basic();
    t2_cross();
    t3_waiter_wake();
    t4_cmp_requeue();
    t5_wake_op();
    t6_wait_requeue_pi();

    if (nfail == 0) {
        printf("C2PI PASS\n");
        return 0;
    }
    printf("C2PI FAIL n=%d\n", nfail);
    return 1;
}
