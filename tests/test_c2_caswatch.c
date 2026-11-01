/* Diag C2-2: is the hang in CAS retry or in join? */
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

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
    int i, ra, rb;
    if (pthread_create(&a, NULL, worker, &n) != 0) {
        return 1;
    }
    if (pthread_create(&b, NULL, worker, &n) != 0) {
        return 1;
    }
    ra = rb = 0;
    for (i = 0; i < 20; i++) {
        sleep(1);
        if (!ra) {
            ra = (pthread_tryjoin_np(a, NULL) == 0);
        }
        if (!rb) {
            rb = (pthread_tryjoin_np(b, NULL) == 0);
        }
        printf("t=%d counter=%d ja=%d jb=%d\n", i, counter, ra, rb);
        if (ra && rb) {
            break;
        }
    }
    printf("final counter=%d want=%ld %s\n", counter, 2 * n,
           counter == 2 * (int)n ? "OK" : "BROKEN");
    return 0;
}
