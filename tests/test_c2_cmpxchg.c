/* Probe C2-2: lock cmpxchg increments from two threads, interp vs dbt. */
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
    pthread_t a, b;
    if (pthread_create(&a, NULL, worker, &n) != 0) {
        printf("CREATE A FAIL\n");
        return 1;
    }
    if (pthread_create(&b, NULL, worker, &n) != 0) {
        printf("CREATE B FAIL\n");
        return 1;
    }
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("counter=%d want=%ld %s\n", counter, 2 * n,
           counter == 2 * (int)n ? "OK" : "BROKEN");
    return counter == 2 * (int)n ? 0 : 1;
}
