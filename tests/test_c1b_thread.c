/*
 * tests/test_c1b_thread.c — static i386 musl fixture for fix-campaign
 * card L-C1b (thread/sched syscalls 238, 270, 242, 311, 312)
 *
 * Exercises the C1b surface from real guest code:
 *   (1) sigaction(SIGUSR1) handler; tkill(gettid, SIGUSR1) — the call
 *       musl raise() makes — handler sets a flag and the main flow
 *       verifies it ran via the interp safe-point delivery path.
 *   (2) tgkill(getpid(), gettid(), SIGUSR2) directly (glibc-raise
 *       shape), handler bumps a second flag.
 *   (3) sched_getaffinity(0, sizeof(mask), &mask): CPU 0 present,
 *       syscall returns > 0; a too-short len fails with -1/EINVAL and
 *       an unknown pid fails with -1/ESRCH.
 *   (4) set_robust_list round-trip: set(head, 12) == 0, wrong len
 *       (16) == -1/EINVAL, then get_robust_list(0, ...) returns the
 *       stored head/len; get_robust_list on an unknown tid is
 *       -1/ESRCH.
 *   (5) tkill existence probe: tkill(gettid(), 0) == 0; tkill(bogus
 *       tid) == -1/ESRCH.
 *
 * Build (linux/386 oracle, alpine gcc, static musl):
 *   cc -static -O1 -o /w/_build/test_c1b_thread /w/tests/test_c1b_thread.c
 * Run (aarch64 container, under the i686rt build): must print
 *   C1B PASS ...
 * and exit 0.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile int g_usr1_ran;
static volatile int g_usr2_ran;

static void usr1_handler(int sig)
{
    (void)sig;
    g_usr1_ran = 1;
}

static void usr2_handler(int sig)
{
    (void)sig;
    g_usr2_ran = 1;
}

static int fail(const char *what, long rc)
{
    printf("C1B FAIL %s rc=%ld errno=%d (%s)\n", what, rc, errno,
           strerror(errno));
    return 1;
}

int main(void)
{
    struct sigaction sa;
    unsigned long mask[32];
    unsigned long head[3];
    unsigned long got_head = 0;
    unsigned long got_len = 0;
    long rc;
    pid_t self_tid;

    /* (1) SIGUSR1 raised exactly the way musl raise() does —
     * tkill(gettid, sig) (SYS_tkill 238) — but without the blocked
     * mask window raise() wraps it in: i686rt's v1 delivery drops
     * pending bits while the signal is blocked (that is the C2 wave's
     * delivery machinery), so the fixture raises with an empty guest
     * mask and lets the interp safe-point poll deliver. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr1_handler;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        return fail("sigaction USR1", 0);
    }
    self_tid = (pid_t)syscall(SYS_gettid);
    if (self_tid <= 0) {
        return fail("gettid", (long)self_tid);
    }
    rc = syscall(SYS_tkill, self_tid, SIGUSR1);
    if (rc != 0) {
        return fail("tkill SIGUSR1", rc);
    }
    if (!g_usr1_ran) {
        printf("C1B FAIL USR1 handler did not run\n");
        return 1;
    }

    /* (2) SIGUSR2 via tgkill(270) directly (glibc-raise shape). */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = usr2_handler;
    if (sigaction(SIGUSR2, &sa, NULL) != 0) {
        return fail("sigaction USR2", 0);
    }
    self_tid = (pid_t)syscall(SYS_gettid);
    rc = syscall(SYS_tgkill, getpid(), self_tid, SIGUSR2);
    if (rc != 0) {
        return fail("tgkill SIGUSR2", rc);
    }
    if (!g_usr2_ran) {
        printf("C1B FAIL USR2 handler did not run\n");
        return 1;
    }

    /* (3) sched_getaffinity(242): CPU 0, plus error shapes. */
    memset(mask, 0, sizeof(mask));
    rc = syscall(SYS_sched_getaffinity, 0, sizeof(mask), mask);
    if (rc < 0) {
        return fail("sched_getaffinity", rc);
    }
    if (!(mask[0] & 1UL)) {
        printf("C1B FAIL affinity CPU0 bit clear (mask0=%lx)\n", mask[0]);
        return 1;
    }
    errno = 0;
    rc = syscall(SYS_sched_getaffinity, 0, 2UL, mask);
    if (rc != -1 || errno != EINVAL) {
        printf("C1B FAIL affinity len=2 rc=%ld errno=%d (want EINVAL)\n",
               rc, errno);
        return 1;
    }
    errno = 0;
    rc = syscall(SYS_sched_getaffinity, 424242, sizeof(mask), mask);
    if (rc != -1 || errno != ESRCH) {
        printf("C1B FAIL affinity pid=424242 rc=%ld errno=%d (want ESRCH)\n",
               rc, errno);
        return 1;
    }

    /* (4) set/get_robust_list (311/312) round-trip. */
    head[0] = (unsigned long)head; /* kernel stores the pointer verbatim */
    rc = syscall(SYS_set_robust_list, head, 12UL);
    if (rc != 0) {
        return fail("set_robust_list", rc);
    }
    errno = 0;
    rc = syscall(SYS_set_robust_list, head, 16UL);
    if (rc != -1 || errno != EINVAL) {
        printf("C1B FAIL set_robust_list len=16 rc=%ld errno=%d "
               "(want EINVAL)\n", rc, errno);
        return 1;
    }
    rc = syscall(SYS_get_robust_list, 0, &got_head, &got_len);
    if (rc != 0) {
        return fail("get_robust_list self", rc);
    }
    if (got_head != (unsigned long)head || got_len != 12UL) {
        printf("C1B FAIL robust round-trip head=%lx len=%lu "
               "(want %lx, 12)\n", got_head, got_len,
               (unsigned long)head);
        return 1;
    }
    errno = 0;
    rc = syscall(SYS_get_robust_list, 424242, &got_head, &got_len);
    if (rc != -1 || errno != ESRCH) {
        printf("C1B FAIL get_robust_list tid=424242 rc=%ld errno=%d "
               "(want ESRCH)\n", rc, errno);
        return 1;
    }

    /* (5) tkill(238) shapes: existence probe and unknown tid. */
    rc = syscall(SYS_tkill, self_tid, 0);
    if (rc != 0) {
        return fail("tkill sig=0 probe", rc);
    }
    errno = 0;
    rc = syscall(SYS_tkill, 424242, SIGUSR1);
    if (rc != -1 || errno != ESRCH) {
        printf("C1B FAIL tkill tid=424242 rc=%ld errno=%d (want ESRCH)\n",
               rc, errno);
        return 1;
    }

    printf("C1B PASS tkill/tgkill handlers ran (tid=%ld), affinity=cpu0, "
           "robust_list ok\n", (long)self_tid);
    return 0;
}
