/*
 * tests/c2_robust_exit.c — static i386 musl fixture for fix-campaign
 * card L-C2: robust-list processing at thread exit.  musl registers a
 * per-thread robust list (set_robust_list); the KERNEL walks it when a
 * thread dies holding a robust mutex: the futex word gains
 * FUTEX_OWNER_DIED and, if a waiter is queued (FUTEX_WAITERS), the
 * waiter is futex-woken and observes EOWNERDEAD.
 *
 * Phase 1: a thread locks a robust mutex and exits without unlocking;
 * the joiner's lock must return EOWNERDEAD, then consistent/unlock
 * round-trips the mutex back to healthy.
 *
 * Phase 2: a second thread blocks on the held robust mutex (the
 * FUTEX_WAITERS bit is set in the word) while the owner exits without
 * unlocking; the exit walk must both mark OWNER_DIED and WAKE the
 * waiter.
 *
 * Oracle note: under qemu-user i386 the oracle's set_robust_list is
 * unavailable (musl pthread_mutex_init(ROBUST) fails with ENOSYS), so
 * the fixture records "SKIP robust unsupported" with exit 42 there;
 * the translator run MUST run all phases.  Each phase is also under a
 * 10 s watchdog (exit 42 + SKIP) so a missing walk shows as a bounded
 * SKIP-or-fail, not an unbounded hang.
 *
 * Build (linux/386 oracle, alpine gcc, static musl):
 *   cc -std=gnu11 -O1 -static -o /w/_build/c2-fixtures/c2_robust_exit /w/tests/c2_robust_exit.c
 * Run natively (386 oracle) and under i686rt (arm64): translator must
 * print "C2ROBUST PASS" and exit 0.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int nfail;

static void fail(const char *what, int got, int want)
{
    printf("C2ROBUST FAIL %s got=%d (%s) want=%d (%s)\n", what, got,
           strerror(got), want, strerror(want));
    nfail++;
}

static void msleep(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000 * 1000 };
    nanosleep(&ts, NULL);
}

/* ---- watchdog (10 s per phase -> exit 42 + SKIP line) ---- */

static volatile int phase_done;

static void *watchdog(void *arg)
{
    const char *phase = arg;
    for (int i = 0; i < 100; i++) {
        if (phase_done != 0) {
            return NULL;
        }
        msleep(100);
    }
    printf("C2ROBUST SKIP %s (deadline)\n", phase);
    fflush(stdout);
    _exit(42);
}

static int wd_start(pthread_t *th, const char *phase)
{
    phase_done = 0;
    return pthread_create(th, NULL, watchdog, (void *)phase);
}

static void wd_stop(pthread_t th)
{
    phase_done = 1;
    pthread_join(th, NULL);
}

/* ---- robust mutex init; returns 0, or -ENOSYS where the kernel/oracle
 * lacks robust-list support (qemu-user) ---- */

static int robust_init(pthread_mutex_t *m)
{
    pthread_mutexattr_t a;
    int rc = pthread_mutexattr_init(&a);
    if (rc != 0) {
        return rc;
    }
    rc = pthread_mutexattr_setrobust(&a, PTHREAD_MUTEX_ROBUST);
    if (rc != 0) {
        pthread_mutexattr_destroy(&a);
        return rc;
    }
    rc = pthread_mutex_init(m, &a);
    pthread_mutexattr_destroy(&a);
    return rc;
}

/* musl's mutex futex word is the first int of pthread_mutex_t; the
 * fixture polls the FUTEX_WAITERS bit to synchronize before the exit
 * that must wake the waiter (documented musl layout). */
#define MUSL_FUTEX_WORD(m)   ((volatile uint32_t *)(const void *)(m))
#define FUTEX_WAITERS_BIT    0x80000000u

/* ---- phase 1: die holding the mutex ---- */

static pthread_mutex_t m1;
static volatile int    t1_locked;

static void *t1_body(void *arg)
{
    (void)arg;
    int rc = pthread_mutex_lock(&m1);
    if (rc != 0) {
        fail("t1 lock", rc, 0);
        return NULL;
    }
    t1_locked = 1;
    /* exit WITHOUT unlock — the robust list must recover the word */
    pthread_exit(NULL);
}

static int phase1(void)
{
    int rc = robust_init(&m1);
    if (rc != 0) {
        return rc;
    }

    pthread_t th, wd;
    if (wd_start(&wd, "phase1") != 0) {
        fail("p1 watchdog", -1, 0);
        return 0;
    }
    rc = pthread_create(&th, NULL, t1_body, NULL);
    if (rc != 0) {
        fail("p1 create", rc, 0);
        wd_stop(wd);
        return 0;
    }
    while (t1_locked == 0) {
        msleep(5);
    }
    pthread_join(th, NULL);

    /* the died-owner mutex must report EOWNERDEAD */
    rc = pthread_mutex_lock(&m1);
    if (rc != EOWNERDEAD) {
        fail("lock after owner death", rc, EOWNERDEAD);
        wd_stop(wd);
        return 0;
    }
    rc = pthread_mutex_consistent(&m1);
    if (rc != 0) {
        fail("consistent", rc, 0);
    }
    rc = pthread_mutex_unlock(&m1);
    if (rc != 0) {
        fail("unlock", rc, 0);
    }
    rc = pthread_mutex_lock(&m1);
    if (rc != 0) {
        fail("relock healthy", rc, 0);
        wd_stop(wd);
        return 0;
    }
    rc = pthread_mutex_unlock(&m1);
    if (rc != 0) {
        fail("unlock healthy", rc, 0);
    }
    wd_stop(wd);
    return 0;
}

/* ---- phase 2: waiter blocked on the mutex while the owner dies ---- */

static pthread_mutex_t m2;
static volatile int    t2_holding;
static volatile long   t3_rc;
static volatile int    t3_done;

static void *t2_body(void *arg)
{
    (void)arg;
    if (pthread_mutex_lock(&m2) != 0) {
        return NULL;
    }
    t2_holding = 1;
    /* stay runnable until cancelled; NO cleanup handlers are pushed,
     * so the cancel exits the thread while still holding m2 */
    for (;;) {
        msleep(20);
    }
    return NULL;
}

static void *t3_body(void *arg)
{
    int rc;
    (void)arg;
    /* blocks with FUTEX_WAITERS set until t2's exit walk wakes it */
    rc = pthread_mutex_lock(&m2);
    t3_rc = rc; /* expect EOWNERDEAD */
    t3_done = 1;
    if (rc == 0) {
        pthread_mutex_unlock(&m2);
    }
    return NULL;
}

static void phase2(void)
{
    int rc = robust_init(&m2);
    if (rc != 0) {
        fail("p2 robust_init", rc, 0);
        return;
    }

    pthread_t t2, t3, wd;
    if (wd_start(&wd, "phase2") != 0) {
        fail("p2 watchdog", -1, 0);
        return;
    }
    rc = pthread_create(&t2, NULL, t2_body, NULL);
    if (rc != 0) {
        fail("p2 create t2", rc, 0);
        wd_stop(wd);
        return;
    }
    while (t2_holding == 0) {
        msleep(5);
    }
    rc = pthread_create(&t3, NULL, t3_body, NULL);
    if (rc != 0) {
        fail("p2 create t3", rc, 0);
        wd_stop(wd);
        return;
    }
    /* give t3 time to block on the mutex (WAITERS bit visible in the
     * musl futex word) before the owner exits */
    for (int i = 0; i < 400 && (MUSL_FUTEX_WORD(&m2)[0] &
                                FUTEX_WAITERS_BIT) == 0u; i++) {
        msleep(5);
    }
    rc = pthread_cancel(t2);
    if (rc != 0) {
        fail("p2 cancel", rc, 0);
    }
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    if (t3_rc != EOWNERDEAD) {
        fail("waiter lock after owner death", (int)t3_rc, EOWNERDEAD);
    }
    wd_stop(wd);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    {
        int rc = phase1();
        if (rc == ENOSYS) {
            printf("C2ROBUST SKIP robust unsupported (setrobust rc=%d)\n",
                   rc);
            return 42;
        }
    }
    phase2();

    if (nfail == 0) {
        printf("C2ROBUST PASS\n");
        return 0;
    }
    printf("C2ROBUST FAIL n=%d\n", nfail);
    return 1;
}
