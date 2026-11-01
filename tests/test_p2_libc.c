/* Combined static libc guest: printf, qsort, malloc, file I/O. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;
    return (x > y) - (x < y);
}

int main(void)
{
    int vals[8] = { 7, 3, 9, 1, 5, 8, 2, 6 };
    int i;
    int *dyn;
    FILE *f;
    char buf[64];
    size_t n;

    printf("p2_libc printf %d %s\n", 42, "ok");
    qsort(vals, 8, sizeof(int), cmp_int);
    printf("p2_libc qsort");
    for (i = 0; i < 8; i++) {
        printf(" %d", vals[i]);
    }
    printf("\n");
    dyn = (int *)malloc(8 * sizeof(int));
    if (dyn == NULL) {
        printf("p2_libc malloc FAIL\n");
        return 1;
    }
    memcpy(dyn, vals, 8 * sizeof(int));
    dyn = (int *)realloc(dyn, 16 * sizeof(int));
    if (dyn == NULL) {
        printf("p2_libc realloc FAIL\n");
        return 1;
    }
    printf("p2_libc malloc %d %d\n", dyn[0], dyn[7]);
    free(dyn);
    f = fopen("/tmp/p2_libc_probe.txt", "w");
    if (f == NULL) {
        printf("p2_libc fopen FAIL\n");
        return 1;
    }
    fprintf(f, "fileio %d\n", 1234);
    fclose(f);
    f = fopen("/tmp/p2_libc_probe.txt", "r");
    if (f == NULL) {
        printf("p2_libc reopen FAIL\n");
        return 1;
    }
    buf[0] = '\0';
    n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);
    remove("/tmp/p2_libc_probe.txt");
    printf("p2_libc fileio %s", buf);
    printf("p2_libc ALL OK\n");
    return 0;
}
