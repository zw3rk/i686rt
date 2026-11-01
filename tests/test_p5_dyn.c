/* Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Parity guest (P5-class, dynamic): exercises PT_INTERP loading via
 * the committed tests/sysroot/ (ld-musl-i386), libc startup, TLS,
 * qsort, malloc/free and pthreads through real musl libc. Output is
 * fully deterministic (no pointers, pids, or timestamps).
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static __thread unsigned tls_counter;

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;
    return (x > y) - (x < y);
}

static void *worker(void *arg)
{
    unsigned n = (unsigned)(unsigned long)arg;
    unsigned i;
    for (i = 0u; i < n; i++)
        tls_counter += i;
    return (void *)(unsigned long)tls_counter;
}

int main(void)
{
    int vals[8] = { 7, 3, 5, 1, 8, 2, 6, 4 };
    char buf[64];
    char *heap;
    pthread_t th[2];
    void *r0 = NULL;
    void *r1 = NULL;
    unsigned i;
    qsort(vals, 8u, sizeof(int), cmp_int);
    for (i = 0u; i < 8u; i++)
        printf("sort[%u]=%d\n", i, vals[i]);
    memcpy(buf, "Hello, i686 dynamic!", 21u);
    printf("msg=%s\n", buf);
    heap = (char *)malloc(32u);
    if (heap == NULL) {
        printf("malloc failed\n");
        return 1;
    }
    memset(heap, 0x41, 32u);
    heap[31] = '\0';
    printf("heaplen=%lu head=%c\n", (unsigned long)strlen(heap), heap[0]);
    free(heap);
    if (pthread_create(&th[0], NULL, worker, (void *)100ul) != 0 ||
        pthread_create(&th[1], NULL, worker, (void *)200ul) != 0) {
        printf("threads failed\n");
        return 1;
    }
    pthread_join(th[0], &r0);
    pthread_join(th[1], &r1);
    printf("join0=%lu join1=%lu\n", (unsigned long)r0, (unsigned long)r1);
    printf("P5DYN OK\n");
    return 0;
}
