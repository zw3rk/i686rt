/*
 * tests/test_p1_isa.c — freestanding i386 Phase 1 integer-ISA self-test
 *
 * A no-libc i386 static ELF that exercises the Phase 1 interpreter
 * surface (docs/lanes/phase-1.md): ALU with full flag checks (EFLAGS
 * masked to CF|PF|AF|ZF|SF|OF), shifts/rotates, mul/div/imul/idiv,
 * mov/movzx/movsx/xchg/lea, stack ops, string ops with both DF
 * directions, all 16 jcc in both polarities + loop/jcxz/setcc/cmovcc,
 * bit ops, cmpxchg/xadd, bswap, cpuid, and the pushf/popf roundtrip.
 * hlt is deliberately NOT executed.
 *
 * Every expectation below was hand-derived from the Intel SDM and is
 * validated against a real ia32 environment before commit:
 *   tools/build_fixture.sh tests/test_p1_isa.c _build/test_p1_isa
 *   docker run --rm -v "$PWD/_build":/w --platform linux/386 alpine \
 *       /w/test_p1_isa        # must print PASS
 *
 * Shift helpers return flags masked by F_CC, which still includes AF.
 * An exact comparison can therefore fail when a shift sets AF. OF for
 * a shift count other than 1 is simply absent from the expected masks.
 * cpuid leaf 0: i686rt reports
 * "GenuineIntel"; the docker/QEMU oracle reports its default CPU
 * vendor "AuthenticAMD" — both are accepted, garbage is not.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* raw int 0x80 syscalls                                              */
/* ------------------------------------------------------------------ */

static long sys_write(int fd, const void *buf, unsigned long len)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(4L), "b"((long)fd), "c"(buf), "d"((long)len)
                      : "memory");
    return r;
}

__attribute__((noreturn))
static void sys_exit(long code)
{
    __asm__ volatile ("int $0x80" : : "a"(1L), "b"(code));
    __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* print helpers                                                      */
/* ------------------------------------------------------------------ */

static void put(const char *s, unsigned n)
{
    sys_write(1, s, (unsigned long)n);
}

static void puts_(const char *s)
{
    unsigned n = 0u;
    while (s[n] != '\0') {
        n++;
    }
    put(s, n);
}

static void phex(uint32_t v)
{
    static const char hx[16] = "0123456789abcdef";
    char b[8];
    int i;
    for (i = 7; i >= 0; i--) {
        b[i] = hx[v & 0xfu];
        v >>= 4;
    }
    put(b, 8);
}

/* TEST(name, got, want): on mismatch print
 * "FAIL <name> got=0x.. want=0x.." and exit(1). */
#define TEST(name, got, want)                            \
    do {                                                 \
        uint32_t g_ = (uint32_t)(got);                   \
        uint32_t w_ = (uint32_t)(want);                  \
        if (g_ != w_) {                                  \
            puts_("FAIL ");                              \
            puts_(name);                                 \
            puts_(" got=0x");                            \
            phex(g_);                                    \
            puts_(" want=0x");                           \
            phex(w_);                                    \
            put("\n", 1);                                \
            sys_exit(1);                                 \
        }                                                \
    } while (0)

/* ------------------------------------------------------------------ */
/* flag helpers: run one insn, return EFLAGS masked to the six         */
/* arithmetic flags; masks below drop architecturally undefined bits.  */
/* ------------------------------------------------------------------ */

#define F_CF   0x0001u
#define F_PF   0x0004u
#define F_AF   0x0010u
#define F_ZF   0x0040u
#define F_SF   0x0080u
#define F_OF   0x0800u
#define F_CC    (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF) /* 0x8d5 */
#define F_NOCF  (F_CC & ~F_CF)                            /* inc/dec keep CF   */
#define F_NOAF  (F_CC & ~F_AF)                            /* logic ops         */
#define F_CCOF  (F_CF | F_OF)                             /* mul/imul define   */
#define F_CPSZ  (F_CF | F_PF | F_ZF | F_SF)               /* shifts, count!=1  */

static uint32_t f_add(uint32_t a, uint32_t b, uint32_t *r)
{
    uint32_t f;
    __asm__ ("add %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             : [b] "r"(b)
             : "cc");
    *r = a;
    return f & F_CC;
}

static uint32_t f_sub(uint32_t a, uint32_t b, uint32_t *r)
{
    uint32_t f;
    __asm__ ("sub %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             : [b] "r"(b)
             : "cc");
    *r = a;
    return f & F_CC;
}

static uint32_t f_cmp(uint32_t a, uint32_t b)
{
    uint32_t f;
    __asm__ ("cmp %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [f] "=r"(f)
             : [a] "r"(a), [b] "r"(b)
             : "cc");
    return f & F_CC;
}

static uint32_t f_adc(uint32_t a, uint32_t b, int cf, uint32_t *r)
{
    uint32_t f;
    if (cf != 0) {
        __asm__ ("stc\n\tadc %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
                 : [a] "+r"(a), [f] "=r"(f)
                 : [b] "r"(b)
                 : "cc");
    } else {
        __asm__ ("clc\n\tadc %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
                 : [a] "+r"(a), [f] "=r"(f)
                 : [b] "r"(b)
                 : "cc");
    }
    *r = a;
    return f & F_CC;
}

static uint32_t f_sbb(uint32_t a, uint32_t b, int cf, uint32_t *r)
{
    uint32_t f;
    if (cf != 0) {
        __asm__ ("stc\n\tsbb %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
                 : [a] "+r"(a), [f] "=r"(f)
                 : [b] "r"(b)
                 : "cc");
    } else {
        __asm__ ("clc\n\tsbb %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
                 : [a] "+r"(a), [f] "=r"(f)
                 : [b] "r"(b)
                 : "cc");
    }
    *r = a;
    return f & F_CC;
}

static uint32_t f_inc(uint32_t a, uint32_t *r)
{
    uint32_t f;
    __asm__ ("inc %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             :
             : "cc");
    *r = a;
    return f & F_CC;
}

static uint32_t f_inc_stc(uint32_t a, uint32_t *r)
{
    uint32_t f;
    __asm__ ("stc\n\tinc %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             :
             : "cc");
    *r = a;
    return f & F_CC;
}

static uint32_t f_dec_clc(uint32_t a, uint32_t *r)
{
    uint32_t f;
    __asm__ ("clc\n\tdec %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             :
             : "cc");
    *r = a;
    return f & F_CC;
}

static uint32_t f_neg(uint32_t a, uint32_t *r)
{
    uint32_t f;
    __asm__ ("neg %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             :
             : "cc");
    *r = a;
    return f & F_CC;
}

#define LOGIC_OP(op)                                                     \
    static uint32_t f_##op(uint32_t a, uint32_t b, uint32_t *r)          \
    {                                                                    \
        uint32_t f;                                                      \
        __asm__ (#op " %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"              \
                 : [a] "+r"(a), [f] "=r"(f)                              \
                 : [b] "r"(b)                                            \
                 : "cc");                                                \
        *r = a;                                                          \
        return f & F_CC;                                                 \
    }

LOGIC_OP(and)
LOGIC_OP(or)
LOGIC_OP(xor)

static uint32_t f_test(uint32_t a, uint32_t b)
{
    uint32_t f;
    __asm__ ("test %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [f] "=r"(f)
             : [a] "r"(a), [b] "r"(b)
             : "cc");
    return f & F_CC;
}

/* ------------------------------------------------------------------ */
/* shifts/rotates (count in CL; immediate forms tested inline)         */
/* ------------------------------------------------------------------ */

#define SHIFT_OP(op)                                                     \
    static uint32_t f_##op(uint32_t v, uint32_t cnt, uint32_t *r)        \
    {                                                                    \
        uint32_t f;                                                      \
        __asm__ (#op " %b[c], %k[v]\n\tpushfl\n\tpop %k[f]"              \
                 : [v] "+r"(v), [f] "=r"(f)                              \
                 : [c] "c"(cnt)                                          \
                 : "cc");                                                \
        *r = v;                                                          \
        return f & F_CC;                                                 \
    }

SHIFT_OP(shl)
SHIFT_OP(shr)
SHIFT_OP(sar)
SHIFT_OP(rol)
SHIFT_OP(ror)

#define RC_OP(op)                                                        \
    static uint32_t f_##op(uint32_t v, uint32_t cnt, int cf, uint32_t *r) \
    {                                                                    \
        uint32_t f;                                                      \
        if (cf != 0) {                                                   \
            __asm__ ("stc\n\t" #op " %b[c], %k[v]\n\tpushfl\n\tpop %k[f]" \
                     : [v] "+r"(v), [f] "=r"(f)                          \
                     : [c] "c"(cnt)                                      \
                     : "cc");                                            \
        } else {                                                         \
            __asm__ ("clc\n\t" #op " %b[c], %k[v]\n\tpushfl\n\tpop %k[f]" \
                     : [v] "+r"(v), [f] "=r"(f)                          \
                     : [c] "c"(cnt)                                      \
                     : "cc");                                            \
        }                                                                \
        *r = v;                                                          \
        return f & F_CC;                                                 \
    }

RC_OP(rcl)
RC_OP(rcr)

/* ------------------------------------------------------------------ */
/* mul/div                                                             */
/* ------------------------------------------------------------------ */

static uint32_t f_mul32(uint32_t a, uint32_t b, uint32_t *lo, uint32_t *hi)
{
    uint32_t f, h;
    __asm__ ("mul %k[b]\n\tpushfl\n\tpop %k[f]"
             : [a] "+a"(a), [h] "=d"(h), [f] "=r"(f)
             : [b] "r"(b)
             : "cc");
    *lo = a;
    *hi = h;
    return f & F_CC;
}

static uint32_t f_mul16(uint16_t a, uint16_t b, uint16_t *lo, uint16_t *hi)
{
    uint32_t f;
    uint16_t h;
    __asm__ ("mul %w[b]\n\tpushfl\n\tpop %k[f]"
             : [a] "+a"(a), [h] "=d"(h), [f] "=r"(f)
             : [b] "r"(b)
             : "cc");
    *lo = a;
    *hi = h;
    return f & F_CC;
}

static uint32_t f_imul1(uint32_t a, uint32_t b, uint32_t *lo, uint32_t *hi)
{
    uint32_t f, h;
    __asm__ ("imul %k[b]\n\tpushfl\n\tpop %k[f]"
             : [a] "+a"(a), [h] "=d"(h), [f] "=r"(f)
             : [b] "r"(b)
             : "cc");
    *lo = a;
    *hi = h;
    return f & F_CC;
}

static uint32_t f_imul2(uint32_t a, uint32_t b, uint32_t *r)
{
    uint32_t f;
    __asm__ ("imul %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             : [b] "r"(b)
             : "cc");
    *r = a;
    return f & F_CC;
}

static void do_div(uint32_t b, uint32_t *eax, uint32_t *edx)
{
    __asm__ ("div %k[b]"
             : [a] "+a"(*eax), [h] "+d"(*edx)
             : [b] "r"(b)
             : "cc");
}

static void do_idiv(uint32_t b, uint32_t *eax, uint32_t *edx)
{
    __asm__ ("idiv %k[b]"
             : [a] "+a"(*eax), [h] "+d"(*edx)
             : [b] "r"(b)
             : "cc");
}

static uint32_t do_cdq(uint32_t a)
{
    uint32_t d;
    __asm__ ("cdq" : [d] "=d"(d) : [a] "a"(a));
    return d;
}

static uint32_t do_cwde(uint32_t a /* ax holds the 16-bit input */)
{
    __asm__ ("cwde" : [a] "+a"(a));
    return a;
}

/* ------------------------------------------------------------------ */
/* scratch memory for memory-form operands (static => .data, no libc)  */
/* ------------------------------------------------------------------ */

static uint8_t  g_src[16];
static uint8_t  g_dst[16];
static uint8_t  g_dst2[16];
static uint8_t  g_fill[16];
static uint8_t  g_b2[2]  = { 0x80, 0x7f };
static uint16_t g_w2[2]  = { 0x8001, 0x7fff };
static uint16_t g_w[2]   = { 0x1234, 0x5678 };
static uint32_t g_mw[2];
static uint32_t g_sp[3];
static uint32_t g_en[6];
static const uint8_t g_scan[5] = { 'h', 'e', 'l', 'l', 'o' };

/* ------------------------------------------------------------------ */
/* branch condition setups (flags fully determined by the setup):      */
/*   ST_LT:  cmp 1,2  -> CF=1 SF=1 ZF=0 OF=0 PF=1                      */
/*   ST_GT:  cmp 2,1  -> CF=0 SF=0 ZF=0 OF=0 PF=0                      */
/*   ST_EQ:  cmp 3,3  -> CF=0 SF=0 ZF=1 OF=0 PF=1                      */
/*   ST_OV:  add 0x7fffffff,1 -> OF=1 SF=1 CF=0 ZF=0 PF=1              */
/* ------------------------------------------------------------------ */

#define ST_LT "movl $1, %%eax\n\tmovl $2, %%edx\n\tcmp %%edx, %%eax\n\t"
#define ST_GT "movl $2, %%eax\n\tmovl $1, %%edx\n\tcmp %%edx, %%eax\n\t"
#define ST_EQ "movl $3, %%eax\n\tmovl $3, %%edx\n\tcmp %%edx, %%eax\n\t"
#define ST_OV "movl $0x7fffffff, %%eax\n\taddl $1, %%eax\n\t"

/* All 16 jcc encodings: the 8 primary conditions and (inverted pass)
 * their 8 complements.  Local numeric labels are reused; forward
 * references bind to the next definition (GNU as semantics). */
/* The accumulator is zeroed BEFORE the flag setup so the setup's
 * flags survive into the jcc chain, and the increment uses lea (no
 * flags) so taken branches do not disturb the conditions under test. */
#define JCC_PRIM                                                           \
    "jo 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                        \
    "jb 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                        \
    "je 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                        \
    "jbe 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                       \
    "js 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                        \
    "jp 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                        \
    "jl 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                        \
    "jle 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"

#define JCC_INV                                                            \
    "jno 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                       \
    "jae 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                       \
    "jne 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                       \
    "ja 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                        \
    "jns 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                       \
    "jnp 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                       \
    "jge 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"                       \
    "jg 1f\n\tjmp 2f\n1:\n\tleal 1(%0), %0\n2:\n\t"

#define CHECK_JCC(lbl, st, want_t, want_i)                                 \
    do {                                                                   \
        uint32_t acc_ = 0u;                                                \
        __asm__ volatile ("xorl %0, %0\n\t" st JCC_PRIM                    \
                          : "+r"(acc_) : : "eax", "edx", "cc");            \
        TEST(lbl "_t", acc_, (want_t));                                    \
        __asm__ volatile ("xorl %0, %0\n\t" st JCC_INV                     \
                          : "+r"(acc_) : : "eax", "edx", "cc");            \
        TEST(lbl "_i", acc_, (want_i));                                    \
    } while (0)

/* All 16 setcc encodings accumulated into a bitmask.  The setup flags
 * are saved to EAX once; each setcc is preceded by push %eax / popf
 * (popf consumes stack, so every restore needs its own push).  The
 * shl/or between setccs clobber flags, which is why the saved copy is
 * re-pushed each time. */
#define SETCC16(st)                                                        \
    "xorl %0, %0\n\txorl %%ecx, %%ecx\n\t"                                 \
    st                                                                     \
    "pushfl\n\tpopl %%eax\n\t"                                             \
    "pushl %%eax\n\tpopfl\n\tseto %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $0, %%ecx\n\torl %%ecx, %0\n\t"   \
    "pushl %%eax\n\tpopfl\n\tsetno %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $1, %%ecx\n\torl %%ecx, %0\n\t"  \
    "pushl %%eax\n\tpopfl\n\tsetb %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $2, %%ecx\n\torl %%ecx, %0\n\t"   \
    "pushl %%eax\n\tpopfl\n\tsetae %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $3, %%ecx\n\torl %%ecx, %0\n\t"  \
    "pushl %%eax\n\tpopfl\n\tsete %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $4, %%ecx\n\torl %%ecx, %0\n\t"   \
    "pushl %%eax\n\tpopfl\n\tsetne %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $5, %%ecx\n\torl %%ecx, %0\n\t"  \
    "pushl %%eax\n\tpopfl\n\tsetbe %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $6, %%ecx\n\torl %%ecx, %0\n\t"  \
    "pushl %%eax\n\tpopfl\n\tseta %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $7, %%ecx\n\torl %%ecx, %0\n\t"   \
    "pushl %%eax\n\tpopfl\n\tsets %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $8, %%ecx\n\torl %%ecx, %0\n\t"   \
    "pushl %%eax\n\tpopfl\n\tsetns %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $9, %%ecx\n\torl %%ecx, %0\n\t"  \
    "pushl %%eax\n\tpopfl\n\tsetp %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $10, %%ecx\n\torl %%ecx, %0\n\t"  \
    "pushl %%eax\n\tpopfl\n\tsetnp %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $11, %%ecx\n\torl %%ecx, %0\n\t" \
    "pushl %%eax\n\tpopfl\n\tsetl %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $12, %%ecx\n\torl %%ecx, %0\n\t"  \
    "pushl %%eax\n\tpopfl\n\tsetge %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $13, %%ecx\n\torl %%ecx, %0\n\t" \
    "pushl %%eax\n\tpopfl\n\tsetle %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $14, %%ecx\n\torl %%ecx, %0\n\t" \
    "pushl %%eax\n\tpopfl\n\tsetg %%cl\n\tmovzbl %%cl, %%ecx\n\tshll $15, %%ecx\n\torl %%ecx, %0\n\t"

static void run_tests(void)
{
    uint32_t r, f, hi, lo, v;
    int i;

    /* ---------------- ALU (full CF|PF|AF|ZF|SF|OF checks) --------- */

    f = f_add(1u, 2u, &r);        TEST("add1_r", r, 0x00000003u); TEST("add1_f", f, F_PF);
    f = f_add(0xFFFFFFFFu, 1u, &r); TEST("add2_r", r, 0x00000000u);
    TEST("add2_f", f, F_CF | F_PF | F_AF | F_ZF);              /* 0x55 */
    f = f_add(0x7FFFFFFFu, 1u, &r); TEST("add3_r", r, 0x80000000u);
    TEST("add3_f", f, F_PF | F_AF | F_SF | F_OF);              /* 0x894 */
    f = f_add(0x80000000u, 0x80000000u, &r); TEST("add4_r", r, 0x00000000u);
    TEST("add4_f", f, F_CF | F_PF | F_ZF | F_OF);              /* 0x845 */
    f = f_add(0x12345678u, 0x11111111u, &r); TEST("add5_r", r, 0x23456789u);
    TEST("add5_f", f, 0u);

    f = f_sub(5u, 3u, &r);        TEST("sub1_r", r, 2u); TEST("sub1_f", f, 0u);
    f = f_sub(3u, 5u, &r);        TEST("sub2_r", r, 0xFFFFFFFEu);
    TEST("sub2_f", f, F_CF | F_AF | F_SF);                     /* 0x91 */
    f = f_sub(0x80000000u, 1u, &r); TEST("sub3_r", r, 0x7FFFFFFFu);
    TEST("sub3_f", f, F_PF | F_AF | F_OF);                     /* 0x814 */
    f = f_sub(7u, 7u, &r);        TEST("sub4_r", r, 0u); TEST("sub4_f", f, F_PF | F_ZF);

    f = f_adc(0u, 0u, 0, &r);     TEST("adc0_r", r, 0u); TEST("adc0_f", f, F_PF | F_ZF);
    f = f_adc(0u, 0u, 1, &r);     TEST("adc1_r", r, 1u); TEST("adc1_f", f, 0u);
    f = f_adc(0xFFFFFFFFu, 0u, 1, &r); TEST("adc2_r", r, 0u);
    TEST("adc2_f", f, F_CF | F_PF | F_AF | F_ZF);              /* 0x55 */
    f = f_sbb(0u, 1u, 0, &r);     TEST("sbb0_r", r, 0xFFFFFFFFu);
    TEST("sbb0_f", f, F_CF | F_PF | F_AF | F_SF);              /* 0x95 */
    f = f_sbb(5u, 3u, 1, &r);     TEST("sbb1_r", r, 1u); TEST("sbb1_f", f, 0u);

    f = f_inc(0xFFFFFFFFu, &r);   TEST("inc1_r", r, 0u);
    TEST("inc1_f", f & F_NOCF, F_PF | F_AF | F_ZF);            /* 0x54 */
    f = f_inc(0x7FFFFFFFu, &r);   TEST("inc2_r", r, 0x80000000u);
    TEST("inc2_f", f & F_NOCF, F_PF | F_AF | F_SF | F_OF);     /* 0x894 */
    f = f_inc_stc(0xFFFFFFFFu, &r); TEST("inc3_r", r, 0u);
    TEST("inc3_f", f, F_CF | F_PF | F_AF | F_ZF);              /* CF preserved */
    f = f_dec_clc(0u, &r);        TEST("dec1_r", r, 0xFFFFFFFFu);
    TEST("dec1_f", f & F_NOCF, F_PF | F_AF | F_SF);            /* 0x94 */
    f = f_dec_clc(0x80000000u, &r); TEST("dec2_r", r, 0x7FFFFFFFu);
    TEST("dec2_f", f & F_NOCF, F_PF | F_AF | F_OF);            /* 0x814 */

    f = f_neg(0u, &r);            TEST("neg1_r", r, 0u); TEST("neg1_f", f, F_PF | F_ZF);
    f = f_neg(5u, &r);            TEST("neg2_r", r, 0xFFFFFFFBu);
    TEST("neg2_f", f, F_CF | F_AF | F_SF);                     /* 0x91 */
    f = f_neg(0x80000000u, &r);   TEST("neg3_r", r, 0x80000000u);
    TEST("neg3_f", f, F_CF | F_PF | F_SF | F_OF);              /* 0x885 */

    f = f_and(0xF0F0F0F0u, 0x0F0F0F0Fu, &r); TEST("and1_r", r, 0u);
    TEST("and1_f", f & F_NOAF, F_PF | F_ZF);                   /* AF undefined */
    f = f_and(0xFF00FF00u, 0xFFFF0000u, &r); TEST("and2_r", r, 0xFF000000u);
    TEST("and2_f", f & F_NOAF, F_PF | F_SF);
    f = f_or(0u, 0u, &r);         TEST("or1_r", r, 0u); TEST("or1_f", f & F_NOAF, F_PF | F_ZF);
    f = f_or(0x80000000u, 1u, &r); TEST("or2_r", r, 0x80000001u);
    TEST("or2_f", f & F_NOAF, F_SF);
    f = f_xor(0xAAAAAAAAu, 0xAAAAAAAAu, &r); TEST("xor1_r", r, 0u);
    TEST("xor1_f", f & F_NOAF, F_PF | F_ZF);
    f = f_xor(0xFFFFFFFFu, 0x0F0F0F0Fu, &r); TEST("xor2_r", r, 0xF0F0F0F0u);
    TEST("xor2_f", f & F_NOAF, F_PF | F_SF);
    TEST("test1_f", f_test(0x12345678u, 0xF0F0F0F0u) & F_NOAF, 0u);  /* 0x10305070 */
    TEST("test2_f", f_test(0u, 0u) & F_NOAF, F_PF | F_ZF);
    TEST("cmp1_f", f_cmp(1u, 2u), F_CF | F_PF | F_AF | F_SF);  /* 0x95 */
    TEST("cmp2_f", f_cmp(3u, 3u), F_PF | F_ZF);                /* 0x44 */

    /* ---------------- shifts/rotates (CL + imm forms) -------------- */
    /* OF defined only for count==1; AF undefined for shifts. */

    f = f_shl(1u, 1u, &r);        TEST("shl1_r", r, 2u); TEST("shl1_f", f, 0u);
    f = f_shl(0x80000001u, 1u, &r); TEST("shl2_r", r, 2u);
    TEST("shl2_f", f, F_CF | F_OF);                            /* 0x801 */
    f = f_shl(1u, 31u, &r);       TEST("shl31_r", r, 0x80000000u);
    TEST("shl31_f", f & F_CPSZ, F_PF | F_SF);                  /* CF=bit1=0 */
    f = f_shl(0xFFFFFF00u, 8u, &r); TEST("shl8_r", r, 0xFFFF0000u);
    TEST("shl8_f", f & F_CPSZ, F_CF | F_PF | F_SF);            /* 0x85 */
    f = f_shl(1u, 33u, &r);       TEST("shl33_r", r, 2u);      /* count &= 31 */
    {   /* count 0 leaves flags and value alone */
        uint32_t v0 = 0x42u;
        __asm__ volatile (ST_EQ "shl %b[c], %k[vv]\n\tpushfl\n\tpop %k[ff]"
                         : [vv] "+r"(v0), [ff] "=r"(f)
                         : [c] "c"(0u)
                         : "eax", "edx", "cc");
        TEST("shl0_r", v0, 0x42u); TEST("shl0_f", f & F_CC, F_PF | F_ZF);
    }
    {   /* immediate-count encodings (C1 /4, C1 /5, C1 /7) */
        v = 1u;
        __asm__ ("shll $1, %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(v), [f] "=r"(f) : : "cc");
        TEST("shli1_r", v, 2u); TEST("shli1_f", f & F_CC, 0u);
        v = 0xFFFFFF00u;
        __asm__ ("shll $8, %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(v), [f] "=r"(f) : : "cc");
        TEST("shli8_r", v, 0xFFFF0000u); TEST("shli8_f", f & F_CPSZ, F_CF | F_PF | F_SF);
        v = 0x80000000u;
        __asm__ ("shrl $1, %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(v), [f] "=r"(f) : : "cc");
        TEST("shri1_r", v, 0x40000000u); TEST("shri1_f", f & F_CC, F_PF | F_OF);
        v = 0x80000000u;
        __asm__ ("sarl $1, %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(v), [f] "=r"(f) : : "cc");
        TEST("sari1_r", v, 0xC0000000u); TEST("sari1_f", f & F_CC, F_PF | F_SF);
    }

    f = f_shr(0x80000000u, 1u, &r); TEST("shr1_r", r, 0x40000000u);
    TEST("shr1_f", f, F_PF | F_OF);                            /* OF=old MSB */
    f = f_shr(1u, 1u, &r);       TEST("shr2_r", r, 0u); TEST("shr2_f", f, F_CF | F_PF | F_ZF);
    f = f_shr(0x12345678u, 8u, &r); TEST("shr8_r", r, 0x00123456u); TEST("shr8_f", f & F_CPSZ, F_PF);
    f = f_shr(0xFFu, 8u, &r);    TEST("shr8b_r", r, 0u);
    TEST("shr8b_f", f & F_CPSZ, F_CF | F_PF | F_ZF);

    f = f_sar(0x80000000u, 1u, &r); TEST("sar1_r", r, 0xC0000000u);
    TEST("sar1_f", f, F_PF | F_SF);
    f = f_sar(0xFFFFFF00u, 8u, &r); TEST("sar8_r", r, 0xFFFFFFFFu);
    TEST("sar8_f", f & F_CPSZ, F_PF | F_SF);                   /* CF=bit7(0x00)=0 */
    f = f_sar(0x7FFFFFFFu, 31u, &r); TEST("sar31_r", r, 0u);
    TEST("sar31_f", f & F_CPSZ, F_CF | F_PF | F_ZF);           /* CF=bit30=1 */

    /* rotates: only CF (and OF for count==1) are defined */
    f = f_rol(0x80000001u, 1u, &r); TEST("rol1_r", r, 3u);
    TEST("rol1_f", f & F_CCOF, F_CF | F_OF);
    f = f_rol(1u, 8u, &r);       TEST("rol8_r", r, 0x100u); TEST("rol8_f", f & F_CF, 0u);
    f = f_rol(0x12345678u, 0u, &r); TEST("rol0_r", r, 0x12345678u); TEST("rol0_f", f & F_CCOF, 0u);
    f = f_ror(3u, 1u, &r);       TEST("ror1_r", r, 0x80000001u);
    TEST("ror1_f", f & F_CCOF, F_CF | F_OF);
    f = f_ror(0x81020304u, 8u, &r); TEST("ror8_r", r, 0x04810203u); TEST("ror8_f", f & F_CF, 0u);

    f = f_rcl(0x80000000u, 1u, 1, &r); TEST("rcl1_r", r, 1u);
    TEST("rcl1_f", f & F_CCOF, F_CF | F_OF);
    f = f_rcl(0x40000000u, 1u, 1, &r); TEST("rcl2_r", r, 0x80000001u);
    TEST("rcl2_f", f & F_CCOF, F_OF);
    f = f_rcl(0x12345678u, 0u, 1, &r); TEST("rcl0_r", r, 0x12345678u);
    TEST("rcl0_f", f & F_CCOF, F_CF);                          /* flags unchanged */
    f = f_rcr(1u, 1u, 1, &r);    TEST("rcr1_r", r, 0x80000000u);
    TEST("rcr1_f", f & F_CCOF, F_CF | F_OF);
    {   /* rcr imm1 encoding with carry set */
        uint32_t v1 = 1u;
        __asm__ ("stc\n\trcr $1, %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(v1), [f] "=r"(f) : : "cc");
        TEST("rcri1_r", v1, 0x80000000u); TEST("rcri1_f", f & F_CCOF, F_CF | F_OF);
    }

    /* ---------------- mul/div/imul/idiv + cdq/cwde ---------------- */

    f = f_mul32(0x10000u, 0x10000u, &lo, &hi);
    TEST("mul1_lo", lo, 0u); TEST("mul1_hi", hi, 1u);
    TEST("mul1_f", f & F_CCOF, F_CCOF);
    f = f_mul32(2u, 3u, &lo, &hi);
    TEST("mul2_lo", lo, 6u); TEST("mul2_hi", hi, 0u); TEST("mul2_f", f & F_CCOF, 0u);
    {
        uint16_t l16 = 0u, h16 = 0u;
        f = f_mul16(0x100u, 0x100u, &l16, &h16);
        TEST("mul16_lo", l16, 0u); TEST("mul16_hi", h16, 1u);
        TEST("mul16_f", f & F_CCOF, F_CCOF);
    }
    f = f_imul2(0xFFFFFFFBu, 7u, &r); TEST("imul2_r", r, 0xFFFFFFDDu); TEST("imul2_f", f & F_CCOF, 0u);
    f = f_imul2(0x40000000u, 4u, &r); TEST("imul2b_r", r, 0u);
    TEST("imul2b_f", f & F_CCOF, F_CCOF);
    f = f_imul1(0xFFFFFFFFu, 2u, &lo, &hi);
    TEST("imul1_lo", lo, 0xFFFFFFFEu); TEST("imul1_hi", hi, 0xFFFFFFFFu);
    TEST("imul1_f", f & F_CCOF, 0u);

    lo = 0u; hi = 1u; do_div(0x10u, &lo, &hi);
    TEST("div1_q", lo, 0x10000000u); TEST("div1_r", hi, 0u);
    lo = 100u; hi = 0u; do_div(7u, &lo, &hi);
    TEST("div2_q", lo, 14u); TEST("div2_r", hi, 2u);
    lo = 0xFFFFFF9Cu; hi = 0xFFFFFFFFu; do_idiv(7u, &lo, &hi);  /* -100 cdq 7 */
    TEST("idiv1_q", lo, 0xFFFFFFF2u); TEST("idiv1_r", hi, 0xFFFFFFFEu);

    TEST("cdq1", do_cdq(0x80000000u), 0xFFFFFFFFu);
    TEST("cdq2", do_cdq(0x12345678u), 0u);
    TEST("cwde1", do_cwde(0x8000u), 0xFFFF8000u);
    TEST("cwde2", do_cwde(0x7FFFu), 0x00007FFFu);

    /* ---------------- mov/movzx/movsx/xchg/lea --------------------- */

    __asm__ ("movzbl %[s], %k[d]" : [d] "=r"(r) : [s] "m"(g_b2[0]));
    TEST("movzbl", r, 0x00000080u);
    __asm__ ("movzbl %[s], %k[d]" : [d] "=r"(r) : [s] "m"(g_b2[1]));
    TEST("movzbl2", r, 0x0000007Fu);
    __asm__ ("movzwl %[s], %k[d]" : [d] "=r"(r) : [s] "m"(g_w2[0]));
    TEST("movzwl", r, 0x00008001u);
    __asm__ ("movsbl %[s], %k[d]" : [d] "=r"(r) : [s] "m"(g_b2[0]));
    TEST("movsbl", r, 0xFFFFFF80u);
    __asm__ ("movswl %[s], %k[d]" : [d] "=r"(r) : [s] "m"(g_w2[0]));
    TEST("movswl", r, 0xFFFF8001u);
    __asm__ ("movswl %[s], %k[d]" : [d] "=r"(r) : [s] "m"(g_w2[1]));
    TEST("movswl2", r, 0x00007FFFu);

    __asm__ ("movl $0xDEADBEEF, %k[d]" : [d] "=r"(r));
    TEST("mov_i", r, 0xDEADBEEFu);
    __asm__ ("movl %k[s], %k[d]" : [d] "=r"(r) : [s] "r"(0xCAFEBABEu));
    TEST("mov_rr", r, 0xCAFEBABEu);
    __asm__ ("movl %k[s], %[m]" : [m] "=m"(g_mw[0]) : [s] "r"(0xCAFEBABEu));
    __asm__ ("movl %[s], %k[d]" : [d] "=r"(r) : [s] "m"(g_mw[0]));
    TEST("mov_mm", r, 0xCAFEBABEu);

    {
        uint32_t x = 0x11111111u, y = 0x22222222u;
        __asm__ ("xchg %k[y], %k[x]" : [x] "+r"(x), [y] "+r"(y));
        TEST("xchg_rr1", x, 0x22222222u); TEST("xchg_rr2", y, 0x11111111u);
        g_mw[1] = 0xAABBCCDDu;
        __asm__ ("xchg %k[x], %[m]" : [x] "+r"(x), [m] "+m"(g_mw[1]) : : "memory");
        TEST("xchg_rm1", x, 0xAABBCCDDu); TEST("xchg_rm2", g_mw[1], 0x22222222u);
    }
    {
        uint32_t b_ = 0x1000u, s_ = 0x10u, d_;
        __asm__ ("lea 0x10(%k[b],%k[s],4), %k[d]"
                 : [d] "=r"(d_)
                 : [b] "r"(b_), [s] "r"(s_));
        TEST("lea_sib", d_, 0x1050u);
    }

    /* ---------------- stack: push/pop/pusha/popa/enter/leave -------- */

    {
        uint32_t pv = 0xDEADBEEFu, pr;
        __asm__ ("movl %%esp, %[a]\n\tpush %k[v]\n\tmovl %%esp, %[b]\n\t"
                 "pop %k[o]\n\tmovl %%esp, %[c]\n\t"
                 : [o] "=r"(pr), [a] "=m"(g_sp[0]), [b] "=m"(g_sp[1]), [c] "=m"(g_sp[2])
                 : [v] "r"(pv)
                 : "cc");
        TEST("push_v", pr, 0xDEADBEEFu);
        TEST("push_sp", g_sp[1], g_sp[0] - 4u);
        TEST("pop_sp", g_sp[2], g_sp[0]);
    }
    {   /* PUSH_Ib: imm8 sign-extended (-103 == 0xFFFFFF99) and positive */
        uint32_t iv;
        __asm__ ("push $-103\n\tpop %k0" : "=r"(iv));
        TEST("push_ib_sx", iv, 0xFFFFFF99u);
        __asm__ ("push $0x42\n\tpop %k0" : "=r"(iv));
        TEST("push_ib", iv, 0x42u);
    }
    {
        uint32_t va = 0x11111111u, vb = 0x22222222u, vc = 0x33333333u;
        uint32_t vd = 0x44444444u, vs = 0x55555555u, vi = 0x66666666u;
        __asm__ volatile (
            "pusha\n\t"
            "xorl %%eax, %%eax\n\txorl %%ebx, %%ebx\n\txorl %%ecx, %%ecx\n\t"
            "xorl %%edx, %%edx\n\txorl %%esi, %%esi\n\txorl %%edi, %%edi\n\t"
            "popa\n\t"
            : "+a"(va), "+b"(vb), "+c"(vc), "+d"(vd), "+S"(vs), "+D"(vi)
            :
            : "ebp", "cc");
        TEST("pusha_eax", va, 0x11111111u); TEST("pusha_ebx", vb, 0x22222222u);
        TEST("pusha_ecx", vc, 0x33333333u); TEST("pusha_edx", vd, 0x44444444u);
        TEST("pusha_esi", vs, 0x55555555u); TEST("pusha_edi", vi, 0x66666666u);
        __asm__ volatile (
            "movl %%esp, %[a]\n\t"
            "pusha\n\tpopa\n\t"
            "movl %%esp, %[b]\n\t"
            : [a] "=m"(g_sp[0]), [b] "=m"(g_sp[1])
            :
            : "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "cc", "memory");
        TEST("pusha_sp", g_sp[1], g_sp[0]);
    }
    {
        __asm__ volatile (
            "movl %%esp, %[a]\n\t"
            "movl %%ebp, %[b]\n\t"
            "enter $48, $0\n\t"
            "movl %%esp, %[c]\n\t"
            "movl %%ebp, %[d]\n\t"
            "leave\n\t"
            "movl %%esp, %[e]\n\t"
            "movl %%ebp, %[f2]\n\t"
            : [a] "=m"(g_en[0]), [b] "=m"(g_en[1]), [c] "=m"(g_en[2]),
              [d] "=m"(g_en[3]), [e] "=m"(g_en[4]), [f2] "=m"(g_en[5])
            :
            : "memory", "cc");
        TEST("enter_sp", g_en[2], g_en[0] - 52u);   /* pushed rbp + 48 */
        TEST("enter_bp", g_en[3], g_en[0] - 4u);
        TEST("leave_sp", g_en[4], g_en[0]);
        TEST("leave_bp", g_en[5], g_en[1]);
    }
    {   /* pushf/popf roundtrip through DF + arithmetic bits; DF is
         * restored to 0 so later compiler code stays in the ABI. */
        uint32_t fin, fout;
        __asm__ volatile (
            "pushfl\n\tpop %k0\n\t"
            "andl $0x8d5, %k0\n\t"
            "orl $0x400, %k0\n\t"        /* set DF */
            "push %k0\n\tpopfl\n\t"
            "pushfl\n\tpop %k1\n\t"
            "cld\n\t"
            : "=r"(fin), "=r"(fout));
        TEST("popf_rt", fout & 0xcd5u, fin);
    }

    /* ---------------- strings: movsb/stosb/scasb/lodsw, DF both ------ */

    for (i = 0; i < 16; i++) {
        g_src[i] = (uint8_t)(0x10u + (uint32_t)i);
        g_dst[i] = 0xFFu;
        g_dst2[i] = 0xFFu;
        g_fill[i] = 0u;
    }
    {
        const uint8_t *sp_ = g_src;
        uint8_t *dp_ = g_dst;
        uint32_t n_ = 16u;
        __asm__ volatile ("cld\n\trep movsb"
                          : "+S"(sp_), "+D"(dp_), "+c"(n_)
                          :
                          : "memory");
    }
    {
        uint32_t acc_ = 0u;
        for (i = 0; i < 16; i++) {
            acc_ |= (uint32_t)(g_dst[i] ^ g_src[i]);
        }
        TEST("rep_movsb_f", acc_, 0u);
    }
    {
        const uint8_t *sp_ = g_src + 15;
        uint8_t *dp_ = g_dst2 + 15;
        uint32_t n_ = 16u;
        __asm__ volatile ("std\n\trep movsb\n\tcld"
                          : "+S"(sp_), "+D"(dp_), "+c"(n_)
                          :
                          : "memory");
    }
    {
        uint32_t acc_ = 0u;
        for (i = 0; i < 16; i++) {
            acc_ |= (uint32_t)(g_dst2[i] ^ g_src[i]);
        }
        TEST("rep_movsb_b", acc_, 0u);
    }
    {
        uint8_t *dp_ = g_fill;
        uint32_t n_ = 16u;
        __asm__ volatile ("cld\n\trep stosb"
                          : "+D"(dp_), "+c"(n_)
                          : "a"(0xABu)
                          : "memory");
    }
    {
        uint32_t acc_ = 0u;
        for (i = 0; i < 16; i++) {
            acc_ |= (uint32_t)g_fill[i] ^ 0xABu;
        }
        TEST("rep_stosb", acc_, 0u);
    }
    {
        const uint8_t *p = g_scan;
        uint32_t n = 5u;
        __asm__ volatile ("cld\n\trepne scasb\n\tpushfl\n\tpop %k[f]"
                          : "+D"(p), [c] "+c"(n), [f] "=r"(f)
                          : [a] "a"((uint32_t)'l')
                          : "cc");
        TEST("repne_scasb_n", n, 2u);
        TEST("repne_scasb_p", (uint32_t)(p - g_scan), 3u);
        TEST("repne_scasb_zf", f & F_ZF, F_ZF);
    }
    {
        const uint16_t *p = g_w;
        __asm__ ("cld\n\tlodsw\n\tmovzwl %%ax, %%eax"
                 : "=a"(r), "+S"(p));
        TEST("lodsw_f_v", r, 0x1234u); TEST("lodsw_f_p", (uint32_t)(p - g_w), 1u);
        p = g_w + 1;
        __asm__ ("std\n\tlodsw\n\tmovzwl %%ax, %%eax\n\tcld"
                 : "=a"(r), "+S"(p));
        TEST("lodsw_b_v", r, 0x5678u); TEST("lodsw_b_p", (uint32_t)(p - g_w), 0u);
    }

    /* ---------------- branches: 16 jcc x2, loop/jcxz, setcc, cmovcc -- */

    /* primaries: {jo,jb,je,jbe,js,jp,jl,jle}; complements complete all
     * 16 encodings.  want_t counts true primaries, want_i = 8 - want_t. */
    CHECK_JCC("jcc_lt", ST_LT, 6u, 2u);
    CHECK_JCC("jcc_gt", ST_GT, 0u, 8u);
    CHECK_JCC("jcc_eq", ST_EQ, 4u, 4u);
    CHECK_JCC("jcc_ov", ST_OV, 3u, 5u);

    {
        uint32_t bits = 0u;
        __asm__ volatile (SETCC16(ST_EQ) : "+r"(bits) : : "eax", "edx", "ecx", "cc");
        /* true: AE E BE NS P GE LE NO -> bits 1,3,4,6,9,10,13,14 */
        TEST("setcc_eq", bits, 0x665Au);
        bits = 0u;
        __asm__ volatile (SETCC16(ST_LT) : "+r"(bits) : : "eax", "edx", "ecx", "cc");
        /* true: NO B NE BE S P L LE -> bits 1,2,5,6,8,10,12,14 */
        TEST("setcc_lt", bits, 0x5566u);
    }
    {
        uint32_t d = 0u;
        __asm__ (ST_EQ "cmovz %k[s], %k[d]" : [d] "+r"(d) : [s] "r"(0x1111u)
                 : "eax", "edx", "cc");
        TEST("cmovz", d, 0x1111u);
        d = 0u;
        __asm__ (ST_EQ "cmovnz %k[s], %k[d]" : [d] "+r"(d) : [s] "r"(0x2222u)
                 : "eax", "edx", "cc");
        TEST("cmovnz", d, 0u);
        d = 0u;
        __asm__ (ST_LT "cmovb %k[s], %k[d]" : [d] "+r"(d) : [s] "r"(0x3333u)
                 : "eax", "edx", "cc");
        TEST("cmovb", d, 0x3333u);
        d = 0u;
        __asm__ (ST_LT "cmovge %k[s], %k[d]" : [d] "+r"(d) : [s] "r"(0x4444u)
                 : "eax", "edx", "cc");
        TEST("cmovge", d, 0u);
        d = 0u;
        __asm__ (ST_OV "cmovo %k[s], %k[d]" : [d] "+r"(d) : [s] "r"(0x5555u)
                 : "eax", "edx", "cc");
        TEST("cmovo", d, 0x5555u);
        d = 0u;
        __asm__ (ST_LT "cmovs %k[s], %k[d]" : [d] "+r"(d) : [s] "r"(0x6666u)
                 : "eax", "edx", "cc");
        TEST("cmovs", d, 0x6666u);
    }
    {
        uint32_t it = 0u;
        __asm__ volatile (
            "xorl %0, %0\n\tmovl $3, %%ecx\n\t"
            "1:\n\tleal 1(%0), %0\n\tloop 1b\n\t"
            : "+r"(it) : : "ecx", "cc");
        TEST("loop", it, 3u);
        it = 0u;
        __asm__ volatile (
            "xorl %0, %0\n\tmovl $4, %%ecx\n\tcmpl %%eax, %%eax\n\t"
            "1:\n\tleal 1(%0), %0\n\tloopz 1b\n\t"
            : "+r"(it) : : "eax", "ecx", "cc");
        TEST("loopz", it, 4u);
        it = 0u;
        __asm__ volatile (
            "xorl %0, %0\n\tmovl $3, %%ecx\n\txorl %%eax, %%eax\n\tcmpl $1, %%eax\n\t"
            "1:\n\tleal 1(%0), %0\n\tloopnz 1b\n\t"
            : "+r"(it) : : "eax", "ecx", "cc");
        TEST("loopnz", it, 3u);
        it = 0u;
        __asm__ volatile (
            "xorl %%ecx, %%ecx\n\tjcxz 1f\n\tjmp 2f\n"
            "1:\n\tmovl $1, %0\n"
            "2:"
            : "+r"(it) : : "ecx", "cc");
        TEST("jcxz_t", it, 1u);
        it = 0u;
        __asm__ volatile (
            "movl $1, %%ecx\n\tjcxz 1f\n\tjmp 2f\n"
            "1:\n\tmovl $1, %0\n"
            "2:"
            : "+r"(it) : : "ecx", "cc");
        TEST("jcxz_n", it, 0u);
    }

    /* ---------------- bit ops: bt/bts/btr/btc/bsf/bsr/shld/shrd ----- */

    __asm__ ("bt $8, %k[v]\n\tpushfl\n\tpop %k[f]" : [f] "=r"(f) : [v] "r"(0x100u) : "cc");
    TEST("bt_i1", f & F_CF, F_CF);
    __asm__ ("bt $9, %k[v]\n\tpushfl\n\tpop %k[f]" : [f] "=r"(f) : [v] "r"(0x100u) : "cc");
    TEST("bt_i0", f & F_CF, 0u);
    __asm__ ("bt %k[i], %k[v]\n\tpushfl\n\tpop %k[f]"
             : [f] "=r"(f) : [v] "r"(0x00080000u), [i] "r"(19u) : "cc");
    TEST("bt_r1", f & F_CF, F_CF);
    {
        uint32_t val;
        val = 0u;
        __asm__ ("bts $5, %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(val), [f] "=r"(f) : : "cc");
        TEST("bts_i_v", val, 0x20u); TEST("bts_i_f", f & F_CF, 0u);
        val = 0x20u;
        __asm__ ("btr $5, %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(val), [f] "=r"(f) : : "cc");
        TEST("btr_i_v", val, 0u); TEST("btr_i_f", f & F_CF, F_CF);
        val = 0x20u;
        __asm__ ("btc $5, %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(val), [f] "=r"(f) : : "cc");
        TEST("btc_i_v", val, 0u); TEST("btc_i_f", f & F_CF, F_CF);
        val = 0u;
        __asm__ ("btc %k[i], %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(val), [f] "=r"(f) : [i] "r"(31u) : "cc");
        TEST("btc_r_v", val, 0x80000000u); TEST("btc_r_f", f & F_CF, 0u);
        val = 0u;
        __asm__ ("bts %k[i], %k[v]\n\tpushfl\n\tpop %k[f]"
                 : [v] "+r"(val), [f] "=r"(f) : [i] "r"(0u) : "cc");
        TEST("bts_r_v", val, 1u); TEST("bts_r_f", f & F_CF, 0u);
    }
    {
        uint32_t d_;
        __asm__ ("bsf %k[s], %k[d]\n\tpushfl\n\tpop %k[f]"
                 : [d] "=r"(d_), [f] "=r"(f) : [s] "r"(0x00080000u) : "cc");
        TEST("bsf1", d_, 19u); TEST("bsf1_f", f & F_ZF, 0u);
        __asm__ ("bsf %k[s], %k[d]\n\tpushfl\n\tpop %k[f]"
                 : [d] "=r"(d_), [f] "=r"(f) : [s] "r"(0x00FF00F0u) : "cc");
        TEST("bsf2", d_, 4u);
        __asm__ ("bsr %k[s], %k[d]\n\tpushfl\n\tpop %k[f]"
                 : [d] "=r"(d_), [f] "=r"(f) : [s] "r"(0x00FF00F0u) : "cc");
        TEST("bsr2", d_, 23u);
        __asm__ ("bsf %k[s], %k[d]\n\tpushfl\n\tpop %k[f]"
                 : [d] "=r"(d_), [f] "=r"(f) : [s] "r"(0u) : "cc");
        TEST("bsf0_f", f & F_ZF, F_ZF);   /* dst undefined, ZF defined */
        (void)d_;
    }
    {
        uint32_t d_ = 0x12345678u, s_ = 0x9ABCDEF0u;
        __asm__ ("shld %b[c], %k[s], %k[d]\n\tpushfl\n\tpop %k[f]"
                 : [d] "+r"(d_), [f] "=r"(f) : [s] "r"(s_), [c] "c"(8u) : "cc");
        TEST("shld_v", d_, 0x3456789Au);
        TEST("shld_f", f & F_CPSZ, F_PF);                    /* CF=bit24=0 */
        d_ = 0x12345678u;
        __asm__ ("shrd %b[c], %k[s], %k[d]\n\tpushfl\n\tpop %k[f]"
                 : [d] "+r"(d_), [f] "=r"(f) : [s] "r"(s_), [c] "c"(8u) : "cc");
        TEST("shrd_v", d_, 0xF0123456u);
        TEST("shrd_f", f & F_CPSZ, F_PF | F_SF);             /* CF=bit7=0 */
    }

    /* ---------------- cmpxchg / xadd / bswap ------------------------ */

    {
        uint32_t m = 0x11u, n_ = 0x22u, e_ = 0x11u, fl_;
        __asm__ volatile ("cmpxchg %k[n], %[m]\n\tpushfl\n\tpop %k[f]"
                          : [m] "+m"(m), [n] "+r"(n_), [e] "+a"(e_), [f] "=r"(fl_)
                          :
                          : "memory", "cc");
        TEST("cmpxchg_eq_m", m, 0x22u); TEST("cmpxchg_eq_zf", fl_ & F_ZF, F_ZF);
        TEST("cmpxchg_eq_eax", e_, 0x11u); TEST("cmpxchg_eq_src", n_, 0x22u);
        m = 0x11u; n_ = 0x22u; e_ = 0x33u;
        __asm__ volatile ("cmpxchg %k[n], %[m]\n\tpushfl\n\tpop %k[f]"
                          : [m] "+m"(m), [n] "+r"(n_), [e] "+a"(e_), [f] "=r"(fl_)
                          :
                          : "memory", "cc");
        TEST("cmpxchg_ne_m", m, 0x11u); TEST("cmpxchg_ne_zf", fl_ & F_ZF, 0u);
        TEST("cmpxchg_ne_eax", e_, 0x11u);
    }
    {
        uint32_t m = 5u, a_ = 3u, old_, fl_;
        __asm__ volatile ("xadd %k[a], %[m]\n\tpushfl\n\tpop %k[f]"
                          : [m] "+m"(m), [a] "+r"(a_), [f] "=r"(fl_)
                          :
                          : "memory", "cc");
        old_ = a_;
        TEST("xadd_m", m, 8u); TEST("xadd_old", old_, 5u);
        TEST("xadd_f", fl_ & F_CC, 0u);                      /* 5+3: no nibble carry */
        m = 0u; a_ = 0u;
        __asm__ volatile ("xadd %k[a], %[m]\n\tpushfl\n\tpop %k[f]"
                          : [m] "+m"(m), [a] "+r"(a_), [f] "=r"(fl_)
                          :
                          : "memory", "cc");
        TEST("xadd2_m", m, 0u); TEST("xadd2_f", fl_ & F_CC, F_PF | F_ZF);
    }
    {
        uint32_t b_ = 0x12345678u;
        __asm__ ("bswap %k0" : "+r"(b_));
        TEST("bswap", b_, 0x78563412u);
    }

    /* ---------------- cpuid + final --------------------------------- */

    {
        uint32_t a_, b_, c_, d_;
        __asm__ ("cpuid" : "=a"(a_), "=b"(b_), "=c"(c_), "=d"(d_) : "a"(0u));
        TEST("cpuid_max", a_ >= 1u, 1u);
        /* i686rt reports "GenuineIntel"; QEMU TCG reports its default
         * vendor "AuthenticAMD" (verified on the docker oracle). */
        TEST("cpuid_genu",
             (b_ == 0x756e6547u && d_ == 0x49656e69u && c_ == 0x6c65746eu) ||
             (b_ == 0x68747541u && d_ == 0x69746e65u && c_ == 0x444d4163u),
             1u);
    }
}

__attribute__((noreturn))
void _start(void)
{
    run_tests();
    put("PASS\n", 5);
    sys_exit(0);
}
