/* Minimal C2-2 testthread isolation with the racing munmap. */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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
    long n = 200000L;
    long want = n * (n - 1L) / 2L;
    long ps = sysconf(_SC_PAGESIZE);
    size_t len;
    unsigned char *p;
    pthread_t th;
    void *res = NULL;
    if (ps < 4096L) {
        ps = 4096L;
    }
    len = (size_t)ps * 2u;
    p = (unsigned char *)mmap(NULL, len, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        printf("MMAP FAIL\n");
        return 1;
    }
    memset(p, 0x77, len);
    if (pthread_create(&th, NULL, worker, &n) != 0) {
        printf("CREATE FAIL\n");
        return 1;
    }
    if (munmap(p + (size_t)ps, (size_t)ps) != 0) {
        printf("MUNMAP FAIL\n");
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
    printf("got=%ld want=%ld %s\n", *(long *)res, want,
           (*(long *)res == want) ? "MATCH" : "MISMATCH");
    free(res);
    return (*(long *)res == want) ? 0 : 1;
}
