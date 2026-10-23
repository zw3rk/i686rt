/*
 * tests/c2_cancel.c — static i386 musl fixture for fix-campaign card
 * L-C2: pthread_cancel delivery.  musl cancels via tgkill(SIGCANCEL =
 * SIGRTMIN) to the target tid; the translator must (a) deliver the
 * pending bit at a safe point of a RUNNING target and (b) interrupt a
 * host-futex-blocked target (a thread in pthread_cond_wait never
 * reaches a safe point while it sleeps in the host kernel).
 *
 * Phase 1: cancel a RUNNING target (poll loop of cancellation points);
 * the cleanup handler must run and pthread_join must return
 * PTHREAD_CANCELED.
 *
 * Phase 2: cancel a target blocked in pthread_cond_wait (futex);
 * without the blocked-target wake this never completes (the exact
 * functional/pthread_cancel timeout signature).
 *
 * Phase 3: pending cancel against a mutex-holder target: sched_yield
 * is a musl cancellation point, so the pending cancel fires in the
 * spin loop (deferred cancellation is observed as NOT reaching the
 * post-loop code).
 *
 * Oracle note: the linux/386 qemu-user oracle cannot deliver SIGCANCEL
 * into a tight guest loop (the phase-1 join never completes there), so
 * every phase runs under a 10 s watchdog that records "SKIP <phase>"
 * with exit 42 — the translator run MUST complete instead.
 *
 * Build (linux/386 oracle, alpine gcc, static musl):
 *   cc -std=gnu11 -O1 -static -o /w/_build/c2-fixtures/c2_cancel /w/tests/c2_cancel.c
 * Run natively (386 oracle) and under i686rt (arm64): translator must
 * print "C2CANCEL PASS" and exit 0.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int nfail;

static void fail(const char *what, long got, long want)
{
    printf("C2CANCEL FAIL %s got=%ld want=%ld\n", what, got, want);
    nfail++;
}

static void msleep(long ms)
{
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000 * 1000 };
    nanosleep(&ts, NULL);
}

/* ---- per-phase watchdog: bound each phase at 10 s, exit 42 with a
 * SKIP line (the qemu-user oracle cannot run the spin-cancel phase;
 * the translator run must not need it) ---- */

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
    printf("C2CANCEL SKIP %s (deadline)\n", phase);
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

/* musl's sched_yield is NOT a cancellation point; nanosleep is. */
static void point(void)
{
    pthread_testcancel();
    msleep(1);
}

/* ---- phase 1: cancel a running target ---- */

static volatile int p1_cleanup_ran;

static void p1_cleanup(void *arg)
{
    (void)arg;
    p1_cleanup_ran = 1;
}

static void *p1_body(void *arg)
{
    (void)arg;
    pthread_cleanup_push(p1_cleanup, NULL);
    for (;;) {
        point(); /* cancellation point, target stays runnable */
    }
    pthread_cleanup_pop(1); /* unreachable */
    return NULL;
}

static void phase1(void)
{
    pthread_t th, wd;
    void *ret;
    if (wd_start(&wd, "phase1") != 0) {
        fail("p1 watchdog", -1, 0);
        return;
    }
    int rc = pthread_create(&th, NULL, p1_body, NULL);
    if (rc != 0) {
        fail("p1 create", rc, 0);
        wd_stop(wd);
        return;
    }
    msleep(50); /* let it spin */
    rc = pthread_cancel(th);
    if (rc != 0) {
        fail("p1 cancel", rc, 0);
    }
    rc = pthread_join(th, &ret);
    if (rc != 0) {
        fail("p1 join", rc, 0);
    }
    if (ret != PTHREAD_CANCELED) {
        fail("p1 ret", (long)(intptr_t)ret, (long)PTHREAD_CANCELED);
    }
    if (p1_cleanup_ran != 1) {
        fail("p1 cleanup", p1_cleanup_ran, 1);
    }
    wd_stop(wd);
}

/* ---- phase 2: cancel a cond-wait (host-futex-blocked) target ---- */

static pthread_mutex_t p2_m;
static pthread_cond_t  p2_c;
static volatile int    p2_cleanup_ran;
static volatile int    p2_waiting;
static volatile int    p2_inwait;

static void p2_cleanup(void *arg)
{
    (void)arg;
    p2_cleanup_ran = 1;
    pthread_mutex_unlock(&p2_m);
}

static void *p2_body(void *arg)
{
    (void)arg;
    if (pthread_mutex_lock(&p2_m) != 0) {
        return NULL;
    }
    p2_waiting = 1;
    pthread_cleanup_push(p2_cleanup, NULL);
    for (;;) {
        p2_inwait = 1;
        /* the whole loop body sleeps in the host futex */
        pthread_cond_wait(&p2_c, &p2_m);
    }
    pthread_cleanup_pop(1); /* unreachable */
    return NULL;
}

static void phase2(void)
{
    pthread_t th, wd;
    void *ret;
    int rc;

    if (wd_start(&wd, "phase2") != 0) {
        fail("p2 watchdog", -1, 0);
        return;
    }
    rc = pthread_mutex_init(&p2_m, NULL);
    rc |= pthread_cond_init(&p2_c, NULL);
    if (rc != 0) {
        fail("p2 init", rc, 0);
        wd_stop(wd);
        return;
    }
    rc = pthread_create(&th, NULL, p2_body, NULL);
    if (rc != 0) {
        fail("p2 create", rc, 0);
        wd_stop(wd);
        return;
    }
    while (p2_inwait == 0) {
        msleep(5);
    }
    msleep(100); /* let it sink into the futex wait */
    rc = pthread_cancel(th);
    if (rc != 0) {
        fail("p2 cancel", rc, 0);
    }
    rc = pthread_join(th, &ret);
    if (rc != 0) {
        fail("p2 join", rc, 0);
    }
    if (p2_cleanup_ran != 1) {
        fail("p2 cleanup", p2_cleanup_ran, 1);
    }
    /* the cleanup re-locked the mutex in musl's cancel path; leave it
     * consistent for the destroy below */
    pthread_mutex_unlock(&p2_m);
    pthread_cond_destroy(&p2_c);
    pthread_mutex_destroy(&p2_m);
    wd_stop(wd);
}

/* ---- phase 3: pending cancel on a mutex-holder target ---- */

static pthread_mutex_t p3_m;
static volatile int    p3_holding;
static volatile int    p3_ran;
static volatile int    p3_stop;

static void *p3_body(void *arg)
{
    (void)arg;
    if (pthread_mutex_lock(&p3_m) != 0) {
        return NULL;
    }
    p3_holding = 1;
    while (p3_stop == 0) {
        point(); /* cancellation point: the pending cancel fires here */
    }
    p3_ran = 1; /* only reached if the pending cancel did NOT fire */
    pthread_mutex_unlock(&p3_m);
    return NULL;
}

static void phase3(void)
{
    pthread_t th, wd;
    void *ret;
    int rc;

    if (wd_start(&wd, "phase3") != 0) {
        fail("p3 watchdog", -1, 0);
        return;
    }
    rc = pthread_mutex_init(&p3_m, NULL);
    if (rc != 0) {
        fail("p3 init", rc, 0);
        wd_stop(wd);
        return;
    }
    rc = pthread_create(&th, NULL, p3_body, NULL);
    if (rc != 0) {
        fail("p3 create", rc, 0);
        wd_stop(wd);
        return;
    }
    while (p3_holding == 0) {
        msleep(5);
    }
    rc = pthread_cancel(th);
    if (rc != 0) {
        fail("p3 cancel", rc, 0);
    }
    msleep(50);
    p3_stop = 1;
    pthread_join(th, &ret);
    if (p3_ran != 0) {
        fail("p3 deferred cancel", p3_ran, 0);
    }
    if (ret != PTHREAD_CANCELED) {
        fail("p3 ret", (long)(intptr_t)ret, (long)PTHREAD_CANCELED);
    }
    wd_stop(wd);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    phase1();
    phase2();
    phase3();

    if (nfail == 0) {
        printf("C2CANCEL PASS\n");
        return 0;
    }
    printf("C2CANCEL FAIL n=%d\n", nfail);
    return 1;
}
