/* Probe C2-2i: create B while A spins (no exit/malloc overlap). */
#include <pthread.h>
#include <stdio.h>

static volatile int go = 0;
static volatile long acc_a = 0;

static void *spinner(void *arg)
{
    (void)arg;
    while (!go) {
    }
    {
        volatile long acc = 0;
        long i;
        for (i = 0; i < 20000L; i++) {
            acc += i;
        }
        acc_a = acc;
    }
    return (void *)1;
}

static void *worker(void *arg)
{
    long n = *(long *)arg;
    volatile long acc = 0;
    long i;
    for (i = 0; i < n; i++) {
        acc += i;
    }
    return (void *)(long)(acc == (n * (n - 1L) / 2L));
}

int main(void)
{
    long n = 20000L;
    pthread_t a, b;
    void *ra = 0, *rb = 0;
    if (pthread_create(&a, NULL, spinner, NULL) != 0) {
        return 1;
    }
    printf("created A\n");
    fflush(stdout);
    if (pthread_create(&b, NULL, worker, &n) != 0) {
        return 1;
    }
    printf("created B\n");
    fflush(stdout);
    go = 1;
    pthread_join(a, &ra);
    pthread_join(b, &rb);
    printf("ra=%ld rb=%ld %s\n", (long)ra, (long)rb,
           (ra && rb) ? "OK" : "BROKEN");
    return (ra && rb) ? 0 : 1;
}
