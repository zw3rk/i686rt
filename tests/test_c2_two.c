/* Probe C2-2f: two threads, private work, join. No shared writes. */
#include <pthread.h>
#include <stdio.h>

static void *worker(void *arg)
{
    long n = *(long *)arg;
    volatile long acc = 0;
    long i;
    printf("worker start self=%lu\n", (unsigned long)pthread_self());
    fflush(stdout);
    for (i = 0; i < n; i++) {
        acc += i;
    }
    printf("worker end self=%lu acc=%ld\n", (unsigned long)pthread_self(),
           acc);
    fflush(stdout);
    return (void *)(long)(acc == (n * (n - 1L) / 2L));
}

int main(void)
{
    long n = 20000L;
    pthread_t a, b;
    void *ra = 0, *rb = 0;
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
    pthread_join(a, &ra);
    printf("joined A ra=%ld joining B\n", (long)ra);
    fflush(stdout);
    pthread_join(b, &rb);
    printf("ra=%ld rb=%ld %s\n", (long)ra, (long)rb,
           (ra && rb) ? "OK" : "BROKEN");
    return (ra && rb) ? 0 : 1;
}
