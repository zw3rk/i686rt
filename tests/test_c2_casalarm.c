/* Diag C2-2d: alarm dumps counter if join hangs. */
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static volatile int counter = 0;

static void on_alarm(int sig)
{
    (void)sig;
    printf("ALARM counter=%d\n", counter);
    fflush(stdout);
    _exit(42);
}

static void *worker(void *arg)
{
    long n = *(long *)arg;
    long i;
    for (i = 0; i < n; i++) {
        int exp, nv;
        do {
            exp = counter;
            nv = exp + 1;
        } while (!__sync_bool_compare_and_swap(&counter, exp, nv));
    }
    return 0;
}

int main(void)
{
    long n = 5000L;
    pthread_t a, b;
    signal(SIGALRM, on_alarm);
    alarm(8);
    if (pthread_create(&a, NULL, worker, &n) != 0) {
        return 1;
    }
    printf("created A\n");
    fflush(stdout);
    if (pthread_create(&b, NULL, worker, &n) != 0) {
        return 1;
    }
    printf("created B joining A\n");
    fflush(stdout);
    pthread_join(a, NULL);
    printf("joined A counter=%d joining B\n", counter);
    fflush(stdout);
    pthread_join(b, NULL);
    printf("joined B counter=%d want=%ld %s\n", counter, 2 * n,
           counter == 2 * (int)n ? "OK" : "BROKEN");
    return 0;
}
