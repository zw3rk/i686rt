/* Minimal C2-2 testthread isolation: worker computes a sum, returns it
 * via malloc; join checks the exact value. No munmap involved. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

static void *worker(void *arg)
{
    long n = *(long *)arg;
    volatile long acc = 0;
    long i;
    long *out;
    for (i = 0; i < n; i++) {
        acc += i;
    }
    out = (long *)malloc(sizeof(long));
    if (out != NULL) {
        *out = acc;
    }
    return out;
}

int main(void)
{
    long n = 20000L; /* fits 32-bit: sum and product both exact */
    long want = n * (n - 1L) / 2L;
    pthread_t th;
    void *res = NULL;
    if (pthread_create(&th, NULL, worker, &n) != 0) {
        printf("CREATE FAIL\n");
        return 1;
    }
    if (pthread_join(th, &res) != 0) {
        printf("JOIN FAIL\n");
        return 1;
    }
    if (res == NULL) {
        printf("RESULT NULL\n");
        return 1;
    }
    {
        int ok = (*(long *)res == want);
        printf("got=%ld want=%ld %s\n", *(long *)res, want,
               ok ? "MATCH" : "MISMATCH");
        free(res);
        return ok ? 0 : 1;
    }
}
