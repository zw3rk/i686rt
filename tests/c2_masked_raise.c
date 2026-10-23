/*
 * tests/c2_masked_raise.c — static i386 musl fixture for fix-campaign
 * card L-C2: the C1b handoff finding.  musl 1.2.5 raise() blocks all
 * signals, tkills the caller's own tid, and restores the mask — the
 * delivery poll runs inside the blocked window, so the pending bit
 * MUST survive being masked (kernel semantics: bits stay pending while
 * masked and deliver at unmask).  The v1 delivery core wiped ALL
 * pending bits after every poll, so the signal was dropped before the
 * restore and the handler never ran.
 *
 * Phase 1: the exact C1b raise() register shape with raw syscalls:
 * rt_sigprocmask(SIG_BLOCK, all) -> tkill(self, SIGUSR1) -> restore;
 * the handler must have run after the restore.
 *
 * Phase 2: two signals (SIGUSR1+SIGUSR2) raised inside the blocked
 * window — both must deliver at unmask (a poll that drops undelivered
 * bits loses the second one).
 *
 * Phase 3: the real musl raise() on a handler-installed signal runs
 * the handler and returns.
 *
 * Build (linux/386 oracle, alpine gcc, static musl):
 *   cc -std=c11 -O1 -static -o /w/_build/c2_masked_raise /w/tests/c2_masked_raise.c
 * Run natively (386 oracle) and under i686rt (arm64): both print
 * "C2MASK PASS" and exit 0.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

static int nfail;

static void fail(const char *what, long got, long want)
{
    printf("C2MASK FAIL %s got=%ld want=%ld\n", what, got, want);
    nfail++;
}

static volatile int g_usr1;
static volatile int g_usr2;

static void h_usr1(int sig)
{
    (void)sig;
    g_usr1 = 1;
}

static void h_usr2(int sig)
{
    (void)sig;
    g_usr2 = 1;
}

static long raw_sigmask(int how, const void *set, void *old)
{
    return syscall(SYS_rt_sigprocmask, how, set, old, 8u);
}

static void phase1(void)
{
    uint64_t all = ~0ULL;
    uint64_t old = 0ULL;
    struct sigaction sa;

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_usr1;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) {
        fail("sigaction usr1", -1, 0);
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = h_usr2;
    if (sigaction(SIGUSR2, &sa, NULL) != 0) {
        fail("sigaction usr2", -1, 0);
        return;
    }

    g_usr1 = 0;
    /* SIG_BLOCK = 0 */
    if (raw_sigmask(0, &all, &old) != 0) {
        fail("block all", -1, 0);
        return;
    }
    if (syscall(SYS_tkill, syscall(SYS_gettid), SIGUSR1) != 0) {
        fail("tkill", -1, 0);
    }
    /* still inside the blocked window: nothing delivered yet */
    if (g_usr1 != 0) {
        fail("delivered while blocked", g_usr1, 0);
    }
    /* SIG_SETMASK = 2 */
    if (raw_sigmask(2, &old, NULL) != 0) {
        fail("restore mask", -1, 0);
        return;
    }
    if (g_usr1 != 1) {
        fail("handler at unmask", g_usr1, 1);
    }
}

static void phase2(void)
{
    uint64_t all = ~0ULL;
    uint64_t old = 0ULL;

    g_usr1 = 0;
    g_usr2 = 0;
    if (raw_sigmask(0, &all, &old) != 0) {
        fail("p2 block all", -1, 0);
        return;
    }
    if (syscall(SYS_tkill, syscall(SYS_gettid), SIGUSR1) != 0) {
        fail("p2 tkill usr1", -1, 0);
    }
    if (syscall(SYS_tkill, syscall(SYS_gettid), SIGUSR2) != 0) {
        fail("p2 tkill usr2", -1, 0);
    }
    if (raw_sigmask(2, &old, NULL) != 0) {
        fail("p2 restore mask", -1, 0);
        return;
    }
    if (g_usr1 != 1 || g_usr2 != 1) {
        fail("p2 both at unmask", (long)(g_usr1 * 10 + g_usr2), 11);
    }
}

static void phase3(void)
{
    g_usr2 = 0;
    if (raise(SIGUSR2) != 0) {
        fail("raise", -1, 0);
        return;
    }
    if (g_usr2 != 1) {
        fail("raise handler", g_usr2, 1);
    }
}

int main(void)
{
    phase1();
    phase2();
    phase3();

    if (nfail == 0) {
        printf("C2MASK PASS\n");
        return 0;
    }
    printf("C2MASK FAIL n=%d\n", nfail);
    return 1;
}
