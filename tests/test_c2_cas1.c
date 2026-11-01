/* Probe C2-2b: single-thread lock cmpxchg increments. */
#include <stdio.h>

static volatile int counter = 0;

int main(void)
{
    long i;
    for (i = 0; i < 5000; i++) {
        int exp, nv;
        do {
            exp = counter;
            nv = exp + 1;
        } while (!__sync_bool_compare_and_swap(&counter, exp, nv));
    }
    printf("counter=%d want=5000 %s\n", counter,
           counter == 5000 ? "OK" : "BROKEN");
    return counter == 5000 ? 0 : 1;
}
