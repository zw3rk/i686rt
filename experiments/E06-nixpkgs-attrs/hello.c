/* E06 fixture: minimal freestanding i386 static ELF, raw int 0x80 syscalls.
 * Build: cc -static -nostdlib -ffreestanding -o hello hello.c
 * Expect: prints "hello from i386 static" and exits 42 (exit_group).
 */
static long sys3(long n, long a, long b, long c)
{
	long ret;
	__asm__ volatile("int $0x80"
			 : "=a"(ret)
			 : "a"(n), "b"(a), "c"(b), "d"(c)
			 : "memory");
	return ret;
}

static const char msg[] = "hello from i386 static\n";

void _start(void)
{
	sys3(4, 1, (long)msg, (long)(sizeof(msg) - 1)); /* write(1, msg, len) */
	sys3(252, 42, 0, 0);			    /* exit_group(42) */
	for (;;)
		;
}
