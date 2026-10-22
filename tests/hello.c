/*
 * tests/hello.c — minimal freestanding i386 smoke fixture for i686rt
 *
 * msg is "hello\n" (6 bytes). write uses edx=5, so the newline is not
 * sent. Exits 0 using only raw int 0x80 syscalls:
 * write(eax=4, ebx=1, ecx=msg, edx=5) then exit(eax=1,
 * ebx=0).  No libc, no crt; _start is the ELF entry point.  Build via
 * tools/build_fixture.sh (docker linux/386 alpine gcc, E06).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

static const char msg[6] = "hello\n";

__attribute__((noreturn))
void _start(void)
{
    __asm__ volatile (
        "movl $4, %%eax\n\t"   /* __NR_write */
        "movl $1, %%ebx\n\t"   /* fd = stdout */
        "movl %0, %%ecx\n\t"   /* buf = msg */
        "movl $5, %%edx\n\t"   /* len = 5 */
        "int $0x80\n\t"
        "movl $1, %%eax\n\t"   /* __NR_exit */
        "movl $0, %%ebx\n\t"   /* status = 0 */
        "int $0x80\n\t"
        :
        : "r"(msg)
        : "eax", "ebx", "ecx", "edx", "memory");
    __builtin_unreachable();
}
