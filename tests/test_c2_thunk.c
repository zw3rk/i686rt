/* Minimal get-pc thunk probe (C2-2 DBT isolation): replicates the musl
 * static-PIC pattern `call thunk; add ebx, imm` and reports EBX. */
#include <stdio.h>
#include <stdint.h>

__asm__(
    ".globl getpc_thunk\n"
    "getpc_thunk:\n"
    "movl (%esp), %ebx\n"
    "ret\n");

extern uint32_t getpc_thunk(void);

static uint32_t call_thunk(void)
{
    uint32_t out;
    __asm__ volatile ("call getpc_thunk" : "=b" (out) : : "memory");
    return out;
}

int main(void)
{
    uint32_t v = call_thunk();
    uint32_t self = (uint32_t)(uintptr_t)&v;
    printf("thunk ebx=0x%08x stack=0x%08x\n", v, self);
    /* ebx must be a text address (high bits 0x0804); a small value like
     * 0x2000 means the thunk read the wrong stack slot. */
    if ((v & 0xFFFF0000u) != 0x08040000u) {
        printf("THUNK BROKEN\n");
        return 1;
    }
    printf("THUNK OK\n");
    return 0;
}
