/* Diag C2-2c: one CAS worker + blocking join. */
#include <pthread.h>
#include <stdio.h>

static volatile int counter = 0;

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
    pthread_t a;
    if (pthread_create(&a, NULL, worker, &n) != 0) {
        return 1;
    }
    pthread_join(a, NULL);
    printf("counter=%d want=%ld %s\n", counter, n,
           counter == (int)n ? "OK" : "BROKEN");
    return counter == (int)n ? 0 : 1;
}
