__attribute__((naked)) void _start(void) {
    __asm__ volatile(
        "sub $0x10, %esp\n"
        "movl $41, (%esp)\n"     /* slot = 41 */
        "addl $1, (%esp)\n"      /* slot = 42 */
        "mov (%esp), %ebx\n"     /* read back */
        "mov $1, %eax\n"
        "int $0x80\n"            /* expect 42 */
    );
}
