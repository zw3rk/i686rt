/*
 * run-exe.c — E02 helper.
 *
 * execve() wrapper for the guest init: on failure it prints the raw
 * errno (e.g. 8 = ENOEXEC when i386 ELF exec is refused) and exits 127,
 * instead of a shell silently retrying the file as a script (ash's
 * ENOEXEC fallback would turn a refused i386 binary into shell noise).
 *
 * Freestanding static non-PIE x86-64: no libc, own _start, raw syscalls.
 */

#define SYS_write  1L
#define SYS_execve 59L
#define SYS_exit   60L

static long sys_write(int fd, const void *buf, unsigned long n)
{
    long ret;
    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(SYS_write), "D"((long)fd), "S"(buf), "d"(n)
                         : "rcx", "r11", "memory");
    return ret;
}

static long sys_execve(const char *path, char *const argv[],
                       char *const envp[])
{
    long ret;
    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(SYS_execve), "D"(path), "S"(argv), "d"(envp)
                         : "rcx", "r11", "memory");
    return ret;
}

static void __attribute__((noreturn)) sys_exit(int code)
{
    __asm__ __volatile__("syscall" ::"a"(SYS_exit), "D"((long)code));
    __builtin_unreachable();
}

static void wr(const char *s, unsigned long n)
{
    (void)sys_write(1, s, n);
}

#define WRLIT(x) wr(x, (unsigned long)(sizeof(x) - 1))

static unsigned long str_len(const char *s, unsigned long max)
{
    unsigned long i = 0UL;

    while (i < max && s[i] != '\0') {
        i++;
    }
    return i;
}

static unsigned long dec_unsigned(unsigned long u, char buf[24])
{
    unsigned long i = 24;

    do {
        buf[--i] = (char)('0' + (int)(u % 10UL));
        u /= 10UL;
    } while (u != 0UL && i > 0UL);
    return 24UL - i;
}

void _start(void)
{
    unsigned long argc;
    char **argv;
    char *prog;
    char *nargv[2];
    char *envp[1];
    long ret;
    char buf[24];
    unsigned long n;

    /* Initial process stack: [rsp]=argc, [rsp+8]=argv[0], ..., NULL. */
    __asm__ __volatile__("movq (%%rsp), %0\n\t"
                         "leaq 8(%%rsp), %1"
                         : "=r"(argc), "=r"(argv)
                         :
                         : "memory");

    if (argc < 2UL) {
        WRLIT("run-exe: usage: run-exe PROG\n");
        sys_exit(126);
    }
    prog = argv[1];

    nargv[0] = prog;
    nargv[1] = (char *)0;
    envp[0] = (char *)0;

    ret = sys_execve(prog, nargv, envp);

    WRLIT("EXEC:");
    wr(prog, str_len(prog, 4096UL));
    WRLIT(": errno=");
    n = dec_unsigned((unsigned long)-ret, buf);
    (void)sys_write(1, &buf[24UL - n], n);
    wr("\n", 1UL);
    sys_exit(127);
}
