/* E06: compute-bound probe for QEMU TCG emulation cost. */
#include <stdio.h>

int main(void)
{
	unsigned long i, s = 0;
	for (i = 0; i < 200000000UL; i++)
		s += i;
	printf("s=%lu\n", s);
	return 0;
}
