/* C2-2 DBT bisector: large-displacement loads (mod=10 disp32). */
#include <stdio.h>
#include <stdint.h>

uint32_t backing[512];
uint32_t out1, out2, out3, out4;
uint32_t disp_base;
uint32_t disp_v1, disp_v2, disp_v3, disp_v4;

static void __attribute__((noinline)) run_disp32(void)
{
    disp_base = (uint32_t)(uintptr_t)&backing[0];
    disp_v1 = disp_v2 = disp_v3 = disp_v4 = 0u;
    __asm__ volatile (
        "pushl %%ebp\n"
        "movl disp_base, %%ebx\n"
        "movl 0x1e0(%%ebx), %%eax\n"   /* disp32, base ebx */
        "movl %%eax, disp_v1\n"
        "movl disp_base, %%ebp\n"
        "movl 0x1e0(%%ebp), %%eax\n"   /* disp32, base ebp */
        "movl %%eax, disp_v2\n"
        "movl disp_base, %%esi\n"
        "movl 0x1e0(%%esi), %%eax\n"   /* disp32, base esi */
        "movl %%eax, disp_v3\n"
        "movl disp_base, %%ecx\n"
        "movl 0x1e0(%%ecx), %%eax\n"   /* disp32, base ecx */
        "movl %%eax, disp_v4\n"
        "popl %%ebp\n"
        :
        :
        : "eax", "ebx", "ebp", "esi", "ecx", "memory");
}

int main(void)
{
    uint32_t i;
    for (i = 0u; i < 512u; i++) {
        backing[i] = 0xA5000000u | i;
    }
    /* backing[0x78] = 0xA5000078 at offset 0x1e0; use disp32 0x1e0. */
    {
        run_disp32();
        printf("ebx+1e0: 0x%08x want 0x%08x %s\n", disp_v1, backing[0x78],
               disp_v1 == backing[0x78] ? "OK" : "BROKEN");
        printf("ebp+1e0: 0x%08x want 0x%08x %s\n", disp_v2, backing[0x78],
               disp_v2 == backing[0x78] ? "OK" : "BROKEN");
        printf("esi+1e0: 0x%08x want 0x%08x %s\n", disp_v3, backing[0x78],
               disp_v3 == backing[0x78] ? "OK" : "BROKEN");
        printf("ecx+1e0: 0x%08x want 0x%08x %s\n", disp_v4, backing[0x78],
               disp_v4 == backing[0x78] ? "OK" : "BROKEN");
        if (disp_v1 != backing[0x78] || disp_v2 != backing[0x78] ||
            disp_v3 != backing[0x78] || disp_v4 != backing[0x78]) {
            return 1;
        }
    }
    printf("DISP32 OK\n");
    return 0;
}
