/* Probe C2-2h: two threads, pure compute, no libc calls in worker. */
#include <pthread.h>
#include <stdio.h>

static volatile long acc_a = 0;
static volatile long acc_b = 0;

static void *worker_a(void *arg)
{
    long n = *(long *)arg;
    volatile long acc = 0;
    long i;
    for (i = 0; i < n; i++) {
        acc += i;
    }
    acc_a = acc;
    return (void *)(long)(acc == (n * (n - 1L) / 2L));
}

static void *worker_b(void *arg)
{
    long n = *(long *)arg;
    volatile long acc = 0;
    long i;
    for (i = 0; i < n; i++) {
        acc += i;
    }
    acc_b = acc;
    return (void *)(long)(acc == (n * (n - 1L) / 2L));
}

int main(void)
{
    long n = 20000L;
    pthread_t a, b;
    void *ra = 0, *rb = 0;
    if (pthread_create(&a, NULL, worker_a, &n) != 0) {
        return 1;
    }
    if (pthread_create(&b, NULL, worker_b, &n) != 0) {
        return 1;
    }
    pthread_join(a, &ra);
    pthread_join(b, &rb);
    printf("ra=%ld rb=%ld %s\n", (long)ra, (long)rb,
           (ra && rb) ? "OK" : "BROKEN");
    return (ra && rb) ? 0 : 1;
}
