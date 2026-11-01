/* C2-2 DBT bisector: exact suspect span from test_c2_threadonly
 * (0x804e637 lea; neg; and; mov ebp; test; jne) with an EBX canary.
 * Absolute addressing throughout (no ESP-relative operands). */
#include <stdio.h>
#include <stdint.h>

uint32_t ebx_after, eax_out, edx_out;
uint32_t ecx_in = 0x00021000u, eax_in = 0x08051f00u;
uint32_t edx_in = 0x12345678u, esi_in = 0u;

int main(void)
{
    __asm__ volatile (
        "movl $0x08051fe8, %%ebx\n"
        "movl ecx_in, %%ecx\n"
        "movl eax_in, %%eax\n"
        "movl edx_in, %%edx\n"
        "movl esi_in, %%esi\n"
        "lea -0x70(%%ecx,%%eax), %%eax\n"
        "neg %%edx\n"
        "and %%eax, %%edx\n"
        "pushl %%ebp\n"
        "movl %%edx, %%ebp\n"
        "testl %%esi, %%esi\n"
        "jne 1f\n"
        "movl %%ebx, ebx_after\n"
        "movl %%eax, eax_out\n"
        "movl %%edx, edx_out\n"
        "jmp 2f\n"
        "1: movl $0xdeadbeef, ebx_after\n"
        "2:\n"
        "popl %%ebp\n"
        :
        :
        : "eax", "ebx", "ecx", "edx", "esi", "memory", "cc");
    printf("ebx=0x%08x want=0x08051fe8 eax=0x%08x edx=0x%08x\n",
           ebx_after, eax_out, edx_out);
    if (ebx_after != 0x08051fe8u) {
        printf("EBX CLOBBERED\n");
        return 1;
    }
    printf("EBX OK\n");
    return 0;
}
