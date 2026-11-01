/* Probe C2-2e: mutex-protected counter, 2 threads + join. */
#include <pthread.h>
#include <stdio.h>

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static volatile int counter = 0;

static void *worker(void *arg)
{
    long n = *(long *)arg;
    long i;
    for (i = 0; i < n; i++) {
        pthread_mutex_lock(&mtx);
        counter++;
        pthread_mutex_unlock(&mtx);
    }
    return 0;
}

int main(void)
{
    long n = 2000L;
    pthread_t a, b;
    if (pthread_create(&a, NULL, worker, &n) != 0) {
        return 1;
    }
    if (pthread_create(&b, NULL, worker, &n) != 0) {
        return 1;
    }
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    printf("counter=%d want=%ld %s\n", counter, 2 * n,
           counter == 2 * (int)n ? "OK" : "BROKEN");
    return counter == 2 * (int)n ? 0 : 1;
}
