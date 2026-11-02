/*
 * tests/test_p1_isa_cases.c — Helpers and macros for test_p1_isa.c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_p1_isa_internal.h"

/* ------------------------------------------------------------------ */
/* raw int 0x80 syscalls                                              */
/* ------------------------------------------------------------------ */

long sys_write(int fd, const void *buf, unsigned long len)
{
    long r;
    __asm__ volatile ("int $0x80"
                      : "=a"(r)
                      : "a"(4L), "b"((long)fd), "c"(buf), "d"((long)len)
                      : "memory");
    return r;
}

__attribute__((noreturn))
void sys_exit(long code)
{
    __asm__ volatile ("int $0x80" : : "a"(1L), "b"(code));
    __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* print helpers                                                      */
/* ------------------------------------------------------------------ */

void put(const char *s, unsigned n)
{
    sys_write(1, s, (unsigned long)n);
}

void puts_(const char *s)
{
    unsigned n = 0u;
    while (s[n] != '\0') {
        n++;
    }
    put(s, n);
}

void phex(uint32_t v)
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


/* ------------------------------------------------------------------ */
/* flag helpers                                                       */
/* ------------------------------------------------------------------ */

#define F_CF   0x0001u
#define F_PF   0x0004u
#define F_AF   0x0010u
#define F_ZF   0x0040u
#define F_SF   0x0080u
#define F_OF   0x0800u
#define F_CC    (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF)
#define F_NOCF  (F_CC & ~F_CF)
#define F_NOAF  (F_CC & ~F_AF)
#define F_CCOF  (F_CF | F_OF)
#define F_CPSZ  (F_CF | F_PF | F_ZF | F_SF)

uint32_t f_add(uint32_t a, uint32_t b, uint32_t *r)
{
    uint32_t f;
    __asm__ ("add %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             : [b] "r"(b)
             : "cc");
    *r = a;
    return f & F_CC;
}

uint32_t f_sub(uint32_t a, uint32_t b, uint32_t *r)
{
    uint32_t f;
    __asm__ ("sub %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             : [b] "r"(b)
             : "cc");
    *r = a;
    return f & F_CC;
}

uint32_t f_cmp(uint32_t a, uint32_t b)
{
    uint32_t f;
    __asm__ ("cmp %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [f] "=r"(f)
             : [a] "r"(a), [b] "r"(b)
             : "cc");
    return f & F_CC;
}

uint32_t f_adc(uint32_t a, uint32_t b, int cf, uint32_t *r)
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

uint32_t f_sbb(uint32_t a, uint32_t b, int cf, uint32_t *r)
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

uint32_t f_inc(uint32_t a, uint32_t *r)
{
    uint32_t f;
    __asm__ ("inc %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             :
             : "cc");
    *r = a;
    return f & F_CC;
}

uint32_t f_inc_stc(uint32_t a, uint32_t *r)
{
    uint32_t f;
    __asm__ ("stc\n\tinc %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             :
             : "cc");
    *r = a;
    return f & F_CC;
}

uint32_t f_dec_clc(uint32_t a, uint32_t *r)
{
    uint32_t f;
    __asm__ ("clc\n\tdec %k[a]\n\tpushfl\n\tpop %k[f]"
             : [a] "+r"(a), [f] "=r"(f)
             :
             : "cc");
    *r = a;
    return f & F_CC;
}

uint32_t f_neg(uint32_t a, uint32_t *r)
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
    uint32_t f_##op(uint32_t a, uint32_t b, uint32_t *r)          \
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

uint32_t f_test(uint32_t a, uint32_t b)
{
    uint32_t f;
    __asm__ ("test %k[b], %k[a]\n\tpushfl\n\tpop %k[f]"
             : [f] "=r"(f)
             : [a] "r"(a), [b] "r"(b)
             : "cc");
    return f & F_CC;
}

/* ------------------------------------------------------------------ */
/* shifts/rotates                                                     */
/* ------------------------------------------------------------------ */

#define SHIFT_OP(op)                                                     \
    uint32_t f_##op(uint32_t v, uint32_t cnt, uint32_t *r)        \
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
    uint32_t f_##op(uint32_t v, uint32_t cnt, int cf, uint32_t *r) \
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

uint32_t f_mul32(uint32_t a, uint32_t b, uint32_t *lo, uint32_t *hi)
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

uint32_t f_mul16(uint16_t a, uint16_t b, uint16_t *lo, uint16_t *hi)
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

uint32_t f_imul1(uint32_t a, uint32_t b, uint32_t *lo, uint32_t *hi)
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

uint32_t f_imul2(uint32_t a, uint32_t b, uint32_t *r)
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

static uint32_t do_cwde(uint32_t a)
{
    __asm__ ("cwde" : [a] "+a"(a));
    return a;
}

/* ------------------------------------------------------------------ */
/* scratch memory                                                     */
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

#define ST_LT "movl $1, %%eax\n\tmovl $2, %%edx\n\tcmp %%edx, %%eax\n\t"
#define ST_GT "movl $2, %%eax\n\tmovl $1, %%edx\n\tcmp %%edx, %%eax\n\t"
#define ST_EQ "movl $3, %%eax\n\tmovl $3, %%edx\n\tcmp %%edx, %%eax\n\t"
#define ST_OV "movl $0x7fffffff, %%eax\n\taddl $1, %%eax\n\t"

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

