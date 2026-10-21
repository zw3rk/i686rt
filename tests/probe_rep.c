__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "sub $0x100, %esp\n"
        "cld\n"
        "mov %esp, %edi\n"
        "mov $65, %al\n"          /* 'A' */
        "mov $16, %ecx\n"
        "rep stosb\n"             /* fill 16 bytes */
        "mov %esp, %esi\n"
        "lodsb\n"                 /* first byte */
        "cmp $65, %al\n"
        "jne 1f\n"
        "mov $0, %ebx\n"
        "jmp 2f\n"
        "1: mov $1, %ebx\n"
        "2: mov %ebx, %ebx\n"
        "mov $1, %eax\n"
        "int $0x80\n"             /* expect 0 */
    );
}
