/* RC4: dynamic glibc-i686 threads/signals smoke (plain POSIX, no
 * freestanding tricks — glibc's pthread/signal paths must work). */
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static sigjmp_buf g_jmp;
static volatile sig_atomic_t g_fpe_ok;
static void on_fpe(int sig)
{
    (void)sig;
    g_fpe_ok = 1;
    siglongjmp(g_jmp, 1); /* returning would re-execute the div */
}

static void *worker(void *arg)
{
    int *shared = arg;
    *shared = 0x5a5a;
    return NULL;
}

int main(void)
{
    pthread_t th;
    int shared = 0, rc = 0;

    if (signal(SIGFPE, on_fpe) == SIG_ERR) { rc = 2; goto out; }

    /* SIGFPE recovery via siglongjmp (a returning handler would
     * re-execute the faulting division on real Linux as well) */
    if (sigsetjmp(g_jmp, 1) == 0) {
        volatile int z = 0;
        int r = 1 / z; /* i686 idiv faults */
        if (r == 42) { rc = 3; goto out; }
        rc = 4; goto out; /* should have longjmp'd */
    }
    if (!g_fpe_ok) { rc = 4; goto out; }

    /* pthread round-trip */
    if (pthread_create(&th, NULL, worker, &shared) != 0) { rc = 5; goto out; }
    if (pthread_join(th, NULL) != 0) { rc = 6; goto out; }
    if (shared != 0x5a5a) { rc = 7; goto out; }

    /* fork + wait4 */
    {
        pid_t p = fork();
        if (p == 0) { _exit(42); }
        if (p < 0) { rc = 8; goto out; }
        {
            int st = 0;
            if (waitpid(p, &st, 0) < 0 || !WIFEXITED(st) ||
                WEXITSTATUS(st) != 42) { rc = 9; goto out; }
        }
    }

    if (printf("PASS\n") < 0) { rc = 10; }
out:
    if (rc != 0) {
        fprintf(stderr, "FAIL rc=%d fpe=%d\n", rc, g_fpe_ok);
    }
    return rc;
}
