/*
 * probe-int80.c — E02 ia32-cs probe.
 *
 * Question: with ia32_emulation=0 (kernel 6.7+), is int $0x80 entry
 * blocked (SIGSEGV) or does the compat entry stub still run and return
 * -ENOSYS for an invalid syscall number?
 *
 * Method: from 64-bit code, execute `mov $9999,%eax; int $0x80`.
 *   - entry works  -> eax = -38 (-ENOSYS), we print it and exit 0;
 *   - entry blocked -> the task takes SIGSEGV and dies with status 139
 *     (the guest init script reports it; the "attempting" line is
 *     printed first so the faulting instruction is unambiguous).
 *
 * Freestanding static non-PIE x86-64: no libc, own _start, raw syscalls.
 */

#define SYS_write 1L
#define SYS_exit  60L

static long sys_write(int fd, const void *buf, unsigned long n)
{
    long ret;
    __asm__ __volatile__("syscall"
                         : "=a"(ret)
                         : "a"(SYS_write), "D"((long)fd), "S"(buf), "d"(n)
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

/* Decoding of a signed long into decimal, bounded by the buffer. */
static unsigned long dec_signed(long v, char buf[24])
{
    unsigned long i = 24;
    unsigned long u;
    int neg = 0;

    if (v < 0) {
        neg = 1;
        u = (unsigned long)(-(v + 1)) + 1UL; /* avoid LONG_MIN overflow */
    } else {
        u = (unsigned long)v;
    }
    do {
        buf[--i] = (char)('0' + (int)(u % 10UL));
        u /= 10UL;
    } while (u != 0UL && i > 1UL);
    if (neg != 0) {
        buf[--i] = '-';
    }
    return 24UL - i; /* length; digits start at &buf[i] */
}

void _start(void)
{
    long eax_out;
    char buf[24];
    unsigned long n;

    WRLIT("INT80: start (64-bit code)\n");
    WRLIT("INT80: attempting int $0x80 with eax=9999 (invalid nr)\n");

    __asm__ __volatile__(
        "movl $9999, %%eax\n\t"
        "int $0x80\n\t"
        : "=a"(eax_out)
        :
        : "memory");

    if (eax_out == -38L) {
        WRLIT("INT80:WORKS eax=-38 (-ENOSYS): compat entry ran\n");
    } else {
        WRLIT("INT80:UNEXPECTED eax=");
        n = dec_signed(eax_out, buf);
        (void)sys_write(1, &buf[24UL - n], n);
        wr("\n", 1UL);
    }
    sys_exit(0);
}
