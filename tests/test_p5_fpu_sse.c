/*
 * tests/test_p5_fpu_sse.c — freestanding i386 Phase 5 x87/SSE fixture
 *
 * A no-libc i386 static ELF that exercises the Phase 5 FPU surface
 * (docs/lanes/phase-5.md, SPEC D9/D10): x87 add/sub/mul/div (m64 and
 * m32, including subnormals), fld/fstp m80 round-trip, fprem/fprem1,
 * fscale, frndint in all four CW rounding modes, fsqrt, the
 * transcendental spot values (f2xm1/fyl2x/fsin/fcos/fpatan), fxam and
 * fcomi flag results, fnstsw AX encodings, and the SSE/SSE2 set
 * (addps/subps/mulps/divps + scalar, denormals with FTZ/DAZ on and
 * off, all eight cmpps predicates, movmskps/pd, cvtps2pd/cvtpdps/
 * cvtsi2ss/cvttss2si incl. overflow, pxor/pand/por, paddd/paddq,
 * comisd flags, movd).
 *
 * The fixture never self-checks: every case prints
 *
 *     CASE <name> <hexbits>          (double-mode-safe case)
 *     CASE X87ONLY <name> <hexbits>  (case whose bits are only defined
 *                                     by exact 80-bit x87 semantics)
 *
 * followed by "DONE <count>", exit 0.  The expectations live in
 * tests/golden/p5.txt and p5_x87_80.txt, captured from the docker
 * linux/386 QEMU oracle by tools/mkgolden.sh.  The default-mode RC5
 * check skips X87ONLY lines (i686rt default mode models 64-bit doubles
 * per ST, D9); the --x87-80 check compares every line.
 *
 * Every case is wrapped in fninit + fldcw (x87) or ldmxcsr (SSE) so
 * both i686rt modes see a fully defined FPU environment.  Cases NOT
 * marked X87ONLY run with CW = 0x027F (PC=53-bit, round-to-nearest):
 * the x87 then rounds every register result once to IEEE double
 * precision, which makes hardware, QEMU and i686rt's default
 * (double-per-ST) mode bit-identical, and a subsequent m32 store
 * (53->24 bits, >= 2*24+2, innocuous per Figueroa) matches a
 * compute-in-double implementation exactly.  X87ONLY cases use
 * CW = 0x037F (extended precision) and rely on 64-bit-mantissa
 * semantics: m80 round-trips, extended-denormal fxam, fprem/fprem1
 * quotient/flag encodings and the transcendentals, whose extended
 * results do not agree with double-based evaluation in the last bits.
 *
 * No compiler-generated FP exists in this binary: every FP operation
 * is explicit inline asm; all constants are raw integer bit patterns
 * and the build uses -march=i686 -msse -msse2 -mno-mmx (SSE enabled
 * only so the assembler accepts the deliberate SSE instructions).
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
/* print helpers (printf-free hex/dec printers, as in test_p1_isa.c)   */
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

static void phex64(uint64_t v)
{
    phex((uint32_t)(v >> 32));
    phex((uint32_t)v);
}

static void phex80(const uint8_t *b)
{
    static const char hx[16] = "0123456789abcdef";
    char o[2];
    int i;
    for (i = 0; i < 10; i++) {
        o[0] = hx[b[i] >> 4];
        o[1] = hx[b[i] & 0xfu];
        put(o, 2);
    }
}

static void put_dec(unsigned v)
{
    char b[10];
    int i = 0;
    int j;
    if (v == 0u) {
        put("0", 1);
        return;
    }
    while (v != 0u && i < 10) {
        b[i++] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    }
    for (j = i; j > 0; j--) {
        put(&b[j - 1], 1);
    }
}

static unsigned g_count;

static void emit_case(const char *tag, const char *name)
{
    puts_("CASE ");
    puts_(tag);
    puts_(name);
    put(" ", 1);
    g_count++;
}

static void case_u32(const char *name, uint32_t v)
{
    emit_case("", name);
    phex(v);
    put("\n", 1);
}

static void case_u64(const char *name, uint64_t v)
{
    emit_case("", name);
    phex64(v);
    put("\n", 1);
}

static void case_q(const char *name, const uint32_t *w)
{
    emit_case("", name);
    phex(w[0]);
    phex(w[1]);
    phex(w[2]);
    phex(w[3]);
    put("\n", 1);
}

static void case_d(const char *name, const uint64_t *q)
{
    emit_case("", name);
    phex64(q[0]);
    phex64(q[1]);
    put("\n", 1);
}

static void xcase_u32(const char *name, uint32_t v)
{
    emit_case("X87ONLY ", name);
    phex(v);
    put("\n", 1);
}

static void xcase_u64(const char *name, uint64_t v)
{
    emit_case("X87ONLY ", name);
    phex64(v);
    put("\n", 1);
}

static void xcase_m80(const char *name, const uint8_t *b)
{
    emit_case("X87ONLY ", name);
    phex80(b);
    put("\n", 1);
}

/* ------------------------------------------------------------------ */
/* FPU control words / MXCSR values and operand bit patterns          */
/* ------------------------------------------------------------------ */

/* x87 CW: all exceptions masked; PC/RC per case. */
static const uint16_t g_cw_d  = 0x027Fu; /* PC=53-bit, RC=nearest     */
static const uint16_t g_cw_e  = 0x037Fu; /* PC=64-bit ext, RC=nearest */
static const uint16_t g_cw_dn = 0x067Fu; /* PC=53-bit, RC=down        */
static const uint16_t g_cw_up = 0x0A7Fu; /* PC=53-bit, RC=up          */
static const uint16_t g_cw_ch = 0x0C7Fu; /* PC=53-bit, RC=chop        */

/* MXCSR: all exceptions masked, round-to-nearest. */
static const uint32_t g_mx_def = 0x1F80u; /* FTZ off, DAZ off */
static const uint32_t g_mx_ftz = 0x9F80u; /* FTZ on,  DAZ off */
static const uint32_t g_mx_daz = 0x1FC0u; /* FTZ off, DAZ on  */

/* double bit patterns (no FP constants in C — raw bits only) */
static const uint64_t g_d_1_0     = 0x3FF0000000000000ULL; /*  1.0   */
static const uint64_t g_d_2_0     = 0x4000000000000000ULL; /*  2.0   */
static const uint64_t g_d_2_25    = 0x4002000000000000ULL; /*  2.25  */
static const uint64_t g_d_2_5     = 0x4004000000000000ULL; /*  2.5   */
static const uint64_t g_d_3_0     = 0x4008000000000000ULL; /*  3.0   */
static const uint64_t g_d_4_0     = 0x4010000000000000ULL; /*  4.0   */
static const uint64_t g_d_n4_0    = 0xC010000000000000ULL; /* -4.0   */
static const uint64_t g_d_5_75    = 0x4017000000000000ULL; /*  5.75  */
static const uint64_t g_d_10_75   = 0x4025800000000000ULL; /* 10.75  */
static const uint64_t g_d_1_5     = 0x3FF8000000000000ULL; /*  1.5   */
static const uint64_t g_d_0_5     = 0x3FE0000000000000ULL; /*  0.5   */
static const uint64_t g_d_0_25    = 0x3FD0000000000000ULL; /*  0.25  */
static const uint64_t g_d_0_1     = 0x3FB999999999999AULL; /*  0.1   */
static const uint64_t g_d_0_2     = 0x3FC999999999999AULL; /*  0.2   */
static const uint64_t g_d_n2_5    = 0xC004000000000000ULL; /* -2.5   */
static const uint64_t g_d_2pN600  = 0x01A70000000000000ULL; /*  2^-600*/
static const uint64_t g_d_submin  = 0x0000000000000001ULL; /* min double subnormal */
static const uint64_t g_d_submax  = 0x000FFFFFFFFFFFFFULL; /* max double subnormal */
static const uint64_t g_d_inf     = 0x7FF0000000000000ULL; /* +inf   */
static const uint64_t g_d_qnan    = 0x7FF8000000000000ULL; /* qnan   */
static const uint64_t g_d_zero    = 0x0000000000000000ULL; /* +0.0   */

/* float bit patterns */
static const uint32_t g_f_1_0     = 0x3F800000u; /*  1.0f  */
static const uint32_t g_f_1_5     = 0x3FC00000u; /*  1.5f  */
static const uint32_t g_f_2_5     = 0x40200000u; /*  2.5f  */
static const uint32_t g_f_0_25    = 0x3E800000u; /*  0.25f */
static const uint32_t g_f_0_1     = 0x3DCCCCCDu; /*  0.1f  */
static const uint32_t g_f_0_3     = 0x3E99999Au; /*  0.3f  */
static const uint32_t g_f_submin  = 0x00000001u; /* min float subnormal */
static const uint32_t g_f_2p31    = 0x4F000000u; /*  2^31f (cvtt overflow) */
static const uint32_t g_f_1234_75 = 0x449A5800u; /* 1234.75f */
static const uint32_t g_f_2_0     = 0x40000000u; /*  2.0f  */

/* packed lanes (16-byte aligned for movaps) */
static _Alignas(16) const uint32_t g_ps_a[4] = {
    0x3FC00000u, 0x40200000u, 0x7FC00000u, 0x3E800000u
};                                              /* 1.5, 2.5, qnan, 0.25  */
static _Alignas(16) const uint32_t g_ps_b[4] = {
    0x3FC00000u, 0x40600000u, 0x3F800000u, 0x3E000000u
};                                              /* 1.5, 3.5, 1.0,  0.125 */
static _Alignas(16) const uint32_t g_ps_dn_a[4] = {
    0x00000001u, 0x00000002u, 0x80000001u, 0x00000000u
};                                              /* denormal lanes        */
static _Alignas(16) const uint32_t g_ps_dn_b[4] = {
    0x00000001u, 0x00000002u, 0x80000002u, 0x00000000u
};
static _Alignas(16) const uint32_t g_ps_mov[4] = {
    0x3FC00000u, 0xC0200000u, 0xFFC00000u, 0x80000000u
};                                              /* +, -, -qnan, -0       */
static _Alignas(16) const uint32_t g_ps_ss_a[4] = {
    0x3FC00000u, 0x4F000000u, 0x40400000u, 0x40800000u
};                                              /* addss src (upper kept) */
static _Alignas(16) const uint32_t g_ps_div_a[4] = {
    0x3DCCCCCDu, 0x3F800000u, 0x3F800000u, 0x3F800000u
};                                              /* divss src              */
static _Alignas(16) const uint32_t g_pi_a[4] = {
    0xF0F0F0F0u, 0xFF00FF00u, 0xAAAAAAAAu, 0x12345678u
};
static _Alignas(16) const uint32_t g_pi_b[4] = {
    0x0F0F0F0Fu, 0x00FF00FFu, 0x55555555u, 0x87654321u
};
static _Alignas(16) const uint32_t g_pi_ad_a[4] = { 1u, 2u, 3u, 4u };
static _Alignas(16) const uint32_t g_pi_ad_b[4] = { 0x10u, 0x20u, 0x30u, 0x40u };
static _Alignas(16) const uint64_t g_pq_a[2] = { 0x100000000ULL, 5ULL };
static _Alignas(16) const uint64_t g_pq_b[2] = { 0x100000000ULL, 6ULL };
static _Alignas(16) const uint64_t g_pd_add_a[2] = {
    0x3FF8000000000000ULL, 0x4004000000000000ULL
};                                              /* 1.5, 2.5              */
static _Alignas(16) const uint64_t g_pd_mov[2] = {
    0xBFF0000000000000ULL, 0x4000000000000000ULL
};                                              /* -1.0, 2.0             */
static _Alignas(16) const uint64_t g_pd_lt[2] = { 0xBFF0000000000000ULL, 0 };
static _Alignas(16) const uint64_t g_pd_eq[2] = { 0x3FF0000000000000ULL, 0 };
static _Alignas(16) const uint64_t g_pd_gt[2] = { 0x4000000000000000ULL, 0 };
static _Alignas(16) const uint64_t g_pd_un[2] = { 0x7FF8000000000000ULL, 0 };
static const uint32_t g_cvtps_in[2] = { 0x3FC00000u, 0x3DCCCCCDu }; /* 1.5f, 0.1f */
static _Alignas(16) const uint64_t g_cvtpd_in[2] = {
    0x3FF8000000000000ULL, 0x3FB999999999999AULL
};                                              /* 1.5, 0.1              */

/* m80 bit images, little-endian: 8 mantissa bytes then sign+exponent */
static const uint8_t g_m80_pi[10]  = { 0x35, 0xC2, 0x68, 0x21, 0xA2,
                                       0xDA, 0x0F, 0xC9, 0xFF, 0x3F };
static const uint8_t g_m80_den[10] = { 0x01, 0x00, 0x00, 0x00, 0x00,
                                       0x00, 0x00, 0x00, 0x00, 0x00 };

/* scratch results (memory destinations of the FP asm) */
static uint64_t g_o64;
static uint32_t g_o32;
static _Alignas(16) uint32_t g_oq[4];
static _Alignas(16) uint64_t g_od[2];
static uint8_t  g_o80[10];

/* ------------------------------------------------------------------ */
/* case drivers: one explicit asm block per case, fp state fully set   */
/* ------------------------------------------------------------------ */

/* x87: fninit + CW, push a, push b, INSN (popping form), store m64.
 * NOTE: gas AT&T syntax historically interchanges fsubp/fsubrp and
 * fdivp/fdivrp (binutils i386 "Bugs" appendix), so the *r mnemonics
 * are what compute a-b / a/b with this assembler; the encoded bytes
 * are the plain Intel FSUBP/FDIVP pop forms. */
#define X87_BIN64(label, cwv, av, bv, insn)                                \
    do {                                                                   \
        __asm__ volatile ("fninit\n\tfldcw %[cw]\n\t"                      \
                          "fldl %[a]\n\tfldl %[b]\n\t" insn                \
                          "\n\tfstpl %[o]"                                 \
                          : [o] "=m"(g_o64)                                \
                          : [cw] "m"(cwv), [a] "m"(av), [b] "m"(bv)        \
                          : "memory");                                     \
        case_u64(label, g_o64);                                            \
    } while (0)

/* x87: same over m32 float operands, store m32 */
#define X87_BIN32(label, cwv, av, bv, insn)                                \
    do {                                                                   \
        __asm__ volatile ("fninit\n\tfldcw %[cw]\n\t"                      \
                          "flds %[a]\n\tflds %[b]\n\t" insn                \
                          "\n\tfstps %[o]"                                 \
                          : [o] "=m"(g_o32)                                \
                          : [cw] "m"(cwv), [a] "m"(av), [b] "m"(bv)        \
                          : "memory");                                     \
        case_u32(label, g_o32);                                            \
    } while (0)

/* x87: fninit + CW, push a, INSN (in-place), store m64 */
#define X87_UN64(label, cwv, av, insn)                                     \
    do {                                                                   \
        __asm__ volatile ("fninit\n\tfldcw %[cw]\n\t"                      \
                          "fldl %[a]\n\t" insn "\n\tfstpl %[o]"            \
                          : [o] "=m"(g_o64)                                \
                          : [cw] "m"(cwv), [a] "m"(av)                     \
          : "memory");                                                     \
        case_u64(label, g_o64);                                            \
    } while (0)

/* x87: same with an m32 operand and m32 store */
#define X87_UN32(label, cwv, av, insn)                                     \
    do {                                                                   \
        __asm__ volatile ("fninit\n\tfldcw %[cw]\n\t"                      \
                          "flds %[a]\n\t" insn "\n\tfstps %[o]"            \
                          : [o] "=m"(g_o32)                                \
                          : [cw] "m"(cwv), [a] "m"(av)                     \
          : "memory");                                                     \
        case_u32(label, g_o32);                                            \
    } while (0)

/* x87: fxam of a double constant, SW printed via fnstsw AX */
#define X87_FXAM(label, cwv, av)                                           \
    do {                                                                   \
        uint32_t sw_;                                                      \
        __asm__ volatile ("fninit\n\tfldcw %[cw]\n\tfldl %[a]\n\t"         \
                          "fxam\n\tfnstsw %%ax\n\tmovzwl %%ax, %[s]"       \
                          : [s] "=r"(sw_)                                  \
                          : [cw] "m"(cwv), [a] "m"(av)                     \
                          : "eax", "memory");                              \
        case_u32(label, sw_);                                              \
    } while (0)

/* x87: fcomi/fcomip of two doubles, EFLAGS masked to ZF|PF|CF */
#define X87_COMI(label, cwv, av, bv, op)                                   \
    do {                                                                   \
        uint32_t f_;                                                       \
        __asm__ volatile ("fninit\n\tfldcw %[cw]\n\t"                      \
                          "fldl %[a]\n\tfldl %[b]\n\t" op                  \
                          "\n\tpushfl\n\tpopl %[f]"                        \
                          : [f] "=r"(f_)                                   \
                          : [cw] "m"(cwv), [a] "m"(av), [b] "m"(bv)        \
                          : "cc", "memory");                               \
        case_u32(label, f_ & 0x45u);                                       \
    } while (0)

/* SSE: MXCSR + packed register binop over two aligned 16-byte sources */
#define SSE_PS2(label, mxv, av, bv, insn)                                  \
    do {                                                                   \
        __asm__ volatile ("ldmxcsr %[mx]\n\t"                              \
                          "movaps %[a], %%xmm0\n\tmovaps %[b], %%xmm1\n\t" \
                          insn " %%xmm1, %%xmm0\n\tmovaps %%xmm0, %[o]"    \
                          : [o] "=m"(g_oq[0])                              \
                          : [mx] "m"(mxv), [a] "m"(av), [b] "m"(bv)        \
          : "xmm0", "xmm1", "memory");                                     \
        case_q(label, g_oq);                                               \
    } while (0)

/* SSE: cmpps with an immediate predicate (0..7) */
#define SSE_CMPPS(label, pred)                                             \
    do {                                                                   \
        __asm__ volatile ("ldmxcsr %[mx]\n\t"                              \
                          "movaps %[a], %%xmm0\n\tmovaps %[b], %%xmm1\n\t" \
                          "cmpps $%c[p], %%xmm1, %%xmm0\n\t"               \
                          "movaps %%xmm0, %[o]"                            \
                          : [o] "=m"(g_oq[0])                              \
                          : [mx] "m"(g_mx_def), [a] "m"(g_ps_a[0]),        \
                            [b] "m"(g_ps_b[0]), [p] "i"(pred)              \
                          : "xmm0", "xmm1", "memory");                     \
        case_q(label, g_oq);                                               \
    } while (0)

/* SSE: comisd of a double lane vs a double, EFLAGS masked ZF|PF|CF */
#define SSE_COMISD(label, ap, bv)                                          \
    do {                                                                   \
        uint32_t f_;                                                       \
        __asm__ volatile ("ldmxcsr %[mx]\n\t"                              \
                          "movapd %[a], %%xmm0\n\tcomisd %[b], %%xmm0\n\t" \
                          "pushfl\n\tpopl %[f]"                            \
                          : [f] "=r"(f_)                                   \
                          : [mx] "m"(g_mx_def), [a] "m"(ap[0]),            \
                            [b] "m"(bv)                                    \
                          : "xmm0", "cc");                                 \
        case_u32(label, f_ & 0x45u);                                       \
    } while (0)

/* ------------------------------------------------------------------ */
/* the cases                                                           */
/* ------------------------------------------------------------------ */

static void run_tests(void)
{
    uint32_t r_;
    uint32_t sw_;

    /* ------------- x87 add/sub/mul/div, m64 (CW PC=53) ------------- */

    X87_BIN64("x87_add_m64", g_cw_d, g_d_1_0, g_d_2_25, "faddp"); /* 3.75 */
    X87_BIN64("x87_add_m64_r", g_cw_d, g_d_0_1, g_d_0_2, "faddp");
    X87_BIN64("x87_sub_m64", g_cw_d, g_d_5_75, g_d_2_25, "fsubrp"); /* a-b; see note */
    X87_BIN64("x87_mul_m64", g_cw_d, g_d_1_5, g_d_1_5, "fmulp");   /* 2.25 */
    X87_BIN64("x87_mul_m64_r", g_cw_d, g_d_0_1, g_d_0_2, "fmulp");
    X87_BIN64("x87_div_m64", g_cw_d, g_d_1_0, g_d_3_0, "fdivrp"); /* a/b; see note */

    /* ------------- x87 add/sub/mul/div, m32 (CW PC=53) ------------- */

    X87_BIN32("x87_add_m32", g_cw_d, g_f_1_5, g_f_2_5, "faddp");   /* 4.0f */
    X87_BIN32("x87_sub_m32", g_cw_d, g_f_1_5, g_f_0_25, "fsubrp"); /* a-b; see note */
    X87_BIN32("x87_mul_m32", g_cw_d, g_f_0_1, g_f_0_3, "fmulp");
    X87_BIN32("x87_div_m32", g_cw_d, g_f_1_0, g_f_0_3, "fdivrp"); /* a/b; see note */

    /* ------------- x87 subnormals (exact in both modes) ------------ */

    X87_BIN64("x87_subn_add_m64", g_cw_d, g_d_submin, g_d_submin, "faddp");
    X87_BIN64("x87_subn_addmax_m64", g_cw_d, g_d_submax, g_d_submin, "faddp");
    X87_BIN64("x87_subn_mul_m64", g_cw_d, g_d_2pN600, g_d_2pN600, "fmulp");
    X87_BIN32("x87_subn_add_m32", g_cw_d, g_f_submin, g_f_submin, "faddp");

    /* ------------- x87 fscale / frndint / fsqrt -------------------- */

    /* fscale scales ST(0) by 2^trunc(ST(1)); the scale stays on the
     * stack, so each block pops it with fincstp (cosmetic: every case
     * starts with fninit anyway). */

    /* x87_fscale_pos: 1.5 * 2^4 */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\t"
        "fldl %[s]\n\tfldl %[v]\n\tfscale\n\tfstpl %[o]\n\tfincstp"
        : [o] "=m"(g_o64)
        : [cw] "m"(g_cw_d), [s] "m"(g_d_4_0), [v] "m"(g_d_1_5)
        : "memory");
    case_u64("x87_fscale_pos", g_o64);

    /* x87_fscale_neg: 1.5 * 2^-4 */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\t"
        "fldl %[s]\n\tfldl %[v]\n\tfscale\n\tfstpl %[o]\n\tfincstp"
        : [o] "=m"(g_o64)
        : [cw] "m"(g_cw_d), [s] "m"(g_d_n4_0), [v] "m"(g_d_1_5)
        : "memory");
    case_u64("x87_fscale_neg", g_o64);

    /* frndint in all four CW rounding modes, +2.5 and -2.5 */
    X87_UN64("x87_frndint_ne", g_cw_d, g_d_2_5, "frndint");
    X87_UN64("x87_frndint_dn", g_cw_dn, g_d_2_5, "frndint");
    X87_UN64("x87_frndint_up", g_cw_up, g_d_2_5, "frndint");
    X87_UN64("x87_frndint_ch", g_cw_ch, g_d_2_5, "frndint");
    X87_UN64("x87_frndint_n_ne", g_cw_d, g_d_n2_5, "frndint");
    X87_UN64("x87_frndint_n_dn", g_cw_dn, g_d_n2_5, "frndint");
    X87_UN64("x87_frndint_n_up", g_cw_up, g_d_n2_5, "frndint");
    X87_UN64("x87_frndint_n_ch", g_cw_ch, g_d_n2_5, "frndint");

    X87_UN64("x87_fsqrt_m64", g_cw_d, g_d_2_0, "fsqrt");
    X87_UN32("x87_fsqrt_m32", g_cw_d, g_f_2_0, "fsqrt");

    /* ------------- x87 fxam classes (double-representable) --------- */

    X87_FXAM("x87_fxam_pos", g_cw_d, g_d_1_5);
    X87_FXAM("x87_fxam_zero", g_cw_d, g_d_zero);
    X87_FXAM("x87_fxam_neg", g_cw_d, g_d_n2_5);
    X87_FXAM("x87_fxam_inf", g_cw_d, g_d_inf);
    X87_FXAM("x87_fxam_nan", g_cw_d, g_d_qnan);

    /* ------------- x87 fcomi flag results -------------------------- */

    /* st0 = second push; comi compares ST(0) with ST(1). */
    X87_COMI("x87_fcomi_lt", g_cw_d, g_d_2_0, g_d_1_0, "fcomip %%st(1), %%st");
    X87_COMI("x87_fcomi_eq", g_cw_d, g_d_1_0, g_d_1_0, "fcomip %%st(1), %%st");
    X87_COMI("x87_fcomi_gt", g_cw_d, g_d_1_0, g_d_2_0, "fcomip %%st(1), %%st");
    X87_COMI("x87_fcomi_unord", g_cw_d, g_d_1_0, g_d_qnan, "fcomi %%st(1), %%st");

    /* ------------- x87 fnstsw AX encodings ------------------------- */

    /* fucompp of 1.0 vs 2.0: condition codes + TOP after the pops */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\t"
        "fldl %[a]\n\tfldl %[b]\n\tfucompp\n\t"
        "fnstsw %%ax\n\tmovzwl %%ax, %[s]"
        : [s] "=r"(sw_)
        : [cw] "m"(g_cw_d), [a] "m"(g_d_2_0), [b] "m"(g_d_1_0)
        : "eax", "memory");
    case_u32("x87_fnstsw_fcom", sw_);

    /* TOP field after three pushes from a fresh stack */
    __asm__ volatile (
        "fninit\n\tfld1\n\tfld1\n\tfld1\n\t"
        "fnstsw %%ax\n\tmovzwl %%ax, %[s]"
        : [s] "=r"(sw_)
        :
        : "eax");
    case_u32("x87_fnstsw_top", sw_);

    /* ------------- x87 X87ONLY: m80 / fprem / transcendentals ------ */

    /* fldt/fstpt round-trip of a full 64-bit-mantissa pattern (pi80) */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\tfldt %[i]\n\tfstpt %[o]"
        : [o] "=m"(g_o80[0])
        : [cw] "m"(g_cw_e), [i] "m"(g_m80_pi[0])
        : "memory");
    xcase_m80("x87_fldt_fstpt_m80", g_o80);

    /* fxam of a true extended-precision denormal (exp=0 in m80) */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\tfldt %[i]\n\tfxam\n\t"
        "fnstsw %%ax\n\tmovzwl %%ax, %[s]"
        : [s] "=r"(sw_)
        : [cw] "m"(g_cw_e), [i] "m"(g_m80_den[0])
        : "eax", "memory");
    xcase_u32("x87_fxam_denorm_m80", sw_);

    /* fprem 10.75 mod 3.0: value and the qq-dependent SW encoding */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\t"
        "fldl %[d]\n\tfldl %[n]\n\tfprem\n\t"
        "fnstsw %%ax\n\tmovzwl %%ax, %[s]\n\tfstpl %[o]"
        : [s] "=r"(sw_), [o] "=m"(g_o64)
        : [cw] "m"(g_cw_e), [d] "m"(g_d_3_0), [n] "m"(g_d_10_75)
        : "eax", "memory");
    xcase_u32("x87_fprem_sw", sw_);
    xcase_u64("x87_fprem_val", g_o64);

    /* fprem1 (IEEE remainder): 10.75 - round(10.75/3)*3 = -1.25 */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\t"
        "fldl %[d]\n\tfldl %[n]\n\tfprem1\n\tfstpl %[o]\n\tfincstp"
        : [o] "=m"(g_o64)
        : [cw] "m"(g_cw_e), [d] "m"(g_d_3_0), [n] "m"(g_d_10_75)
        : "memory");
    xcase_u64("x87_fprem1_val", g_o64);

    /* f2xm1(0.5) = 2^0.5 - 1 */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\tfldl %[a]\n\tf2xm1\n\tfstpl %[o]"
        : [o] "=m"(g_o64)
        : [cw] "m"(g_cw_e), [a] "m"(g_d_0_5)
        : "memory");
    xcase_u64("x87_f2xm1", g_o64);

    /* fyl2x: 2.5 * log2(3.0) */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\t"
        "fldl %[m]\n\tfldl %[a]\n\tfyl2x\n\tfstpl %[o]"
        : [o] "=m"(g_o64)
        : [cw] "m"(g_cw_e), [m] "m"(g_d_2_5), [a] "m"(g_d_3_0)
        : "memory");
    xcase_u64("x87_fyl2x", g_o64);

    /* fsin(1.0), fcos(1.0) */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\tfldl %[a]\n\tfsin\n\tfstpl %[o]"
        : [o] "=m"(g_o64)
        : [cw] "m"(g_cw_e), [a] "m"(g_d_1_0)
        : "memory");
    xcase_u64("x87_fsin", g_o64);
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\tfldl %[a]\n\tfcos\n\tfstpl %[o]"
        : [o] "=m"(g_o64)
        : [cw] "m"(g_cw_e), [a] "m"(g_d_1_0)
        : "memory");
    xcase_u64("x87_fcos", g_o64);

    /* fpatan: atan2(2.0, 3.0) */
    __asm__ volatile (
        "fninit\n\tfldcw %[cw]\n\t"
        "fldl %[y]\n\tfldl %[x]\n\tfpatan\n\tfstpl %[o]"
        : [o] "=m"(g_o64)
        : [cw] "m"(g_cw_e), [y] "m"(g_d_2_0), [x] "m"(g_d_3_0)
        : "memory");
    xcase_u64("x87_fpatan", g_o64);

    /* ------------- SSE packed/scalar arithmetic --------------------- */

    SSE_PS2("sse_addps", g_mx_def, g_ps_a, g_ps_b, "addps");
    SSE_PS2("sse_subps", g_mx_def, g_ps_a, g_ps_b, "subps");
    SSE_PS2("sse_mulps", g_mx_def, g_ps_a, g_ps_b, "mulps");
    SSE_PS2("sse_divps", g_mx_def, g_ps_a, g_ps_b, "divps");

    /* addss: only the low lane computes, upper lanes keep the source
     * (the register-destination mem form merges; a movss LOAD from
     * memory would zero the upper lanes instead) */
    __asm__ volatile (
        "ldmxcsr %[mx]\n\tmovaps %[a], %%xmm0\n\t"
        "addss %[b], %%xmm0\n\tmovaps %%xmm0, %[o]"
        : [o] "=m"(g_oq[0])
        : [mx] "m"(g_mx_def), [a] "m"(g_ps_ss_a[0]), [b] "m"(g_f_0_25)
        : "xmm0", "memory");
    case_q("sse_addss", g_oq);

    /* divss: 0.1f / 0.3f in the low lane */
    __asm__ volatile (
        "ldmxcsr %[mx]\n\tmovaps %[a], %%xmm0\n\t"
        "divss %[b], %%xmm0\n\tmovaps %%xmm0, %[o]"
        : [o] "=m"(g_oq[0])
        : [mx] "m"(g_mx_def), [a] "m"(g_ps_div_a[0]), [b] "m"(g_f_0_3)
        : "xmm0", "memory");
    case_q("sse_divss", g_oq);

    /* addsd: low double lane, upper preserved (mem src merges) */
    __asm__ volatile (
        "ldmxcsr %[mx]\n\tmovapd %[a], %%xmm0\n\t"
        "addsd %[b], %%xmm0\n\tmovapd %%xmm0, %[o]"
        : [o] "=m"(g_od[0])
        : [mx] "m"(g_mx_def), [a] "m"(g_pd_add_a[0]), [b] "m"(g_d_0_25)
        : "xmm0", "memory");
    case_d("sse_addsd", g_od);

    /* ------------- SSE denormals: FTZ/DAZ off and on --------------- */

    SSE_PS2("sse_denorm_addps", g_mx_def, g_ps_dn_a, g_ps_dn_b, "addps");
    SSE_PS2("sse_ftz_addps", g_mx_ftz, g_ps_dn_a, g_ps_dn_b, "addps");
    SSE_PS2("sse_daz_addps", g_mx_daz, g_ps_dn_a, g_ps_dn_b, "addps");

    /* stmxcsr after the FTZ flush: exception-flag accumulation */
    __asm__ volatile (
        "ldmxcsr %[mx]\n\tmovaps %[a], %%xmm0\n\tmovaps %[b], %%xmm1\n\t"
        "addps %%xmm1, %%xmm0\n\tstmxcsr %[o]"
        : [o] "=m"(g_o32)
        : [mx] "m"(g_mx_ftz), [a] "m"(g_ps_dn_a[0]), [b] "m"(g_ps_dn_b[0])
        : "xmm0", "xmm1", "memory");
    case_u32("sse_ftz_mxcsr", g_o32);

    /* ------------- SSE cmpps: all 8 predicates --------------------- */

    SSE_CMPPS("sse_cmpps_eq", 0);
    SSE_CMPPS("sse_cmpps_lt", 1);
    SSE_CMPPS("sse_cmpps_le", 2);
    SSE_CMPPS("sse_cmpps_unord", 3);
    SSE_CMPPS("sse_cmpps_neq", 4);
    SSE_CMPPS("sse_cmpps_nlt", 5);
    SSE_CMPPS("sse_cmpps_nle", 6);
    SSE_CMPPS("sse_cmpps_ord", 7);

    /* ------------- SSE movmsk / conversions ------------------------ */

    __asm__ volatile (
        "ldmxcsr %[mx]\n\tmovaps %[a], %%xmm0\n\tmovmskps %%xmm0, %[r]"
        : [r] "=r"(r_)
        : [mx] "m"(g_mx_def), [a] "m"(g_ps_mov[0])
        : "xmm0");
    case_u32("sse_movmskps", r_);

    __asm__ volatile (
        "ldmxcsr %[mx]\n\tmovapd %[a], %%xmm0\n\tmovmskpd %%xmm0, %[r]"
        : [r] "=r"(r_)
        : [mx] "m"(g_mx_def), [a] "m"(g_pd_mov[0])
        : "xmm0");
    case_u32("sse_movmskpd", r_);

    __asm__ volatile (
        "ldmxcsr %[mx]\n\tcvtps2pd %[a], %%xmm0\n\tmovapd %%xmm0, %[o]"
        : [o] "=m"(g_od[0])
        : [mx] "m"(g_mx_def), [a] "m"(g_cvtps_in[0])
        : "xmm0", "memory");
    case_d("sse_cvtps2pd", g_od);

    __asm__ volatile (
        "ldmxcsr %[mx]\n\tcvtpd2ps %[a], %%xmm0\n\tmovaps %%xmm0, %[o]"
        : [o] "=m"(g_oq[0])
        : [mx] "m"(g_mx_def), [a] "m"(g_cvtpd_in[0])
        : "xmm0", "memory");
    case_q("sse_cvtpd2ps", g_oq);

    __asm__ volatile (
        "ldmxcsr %[mx]\n\tcvtsi2ss %[v], %%xmm0\n\tmovd %%xmm0, %[r]"
        : [r] "=r"(r_)
        : [mx] "m"(g_mx_def), [v] "r"(1234567u)
        : "xmm0");
    case_u32("sse_cvtsi2ss", r_);

    __asm__ volatile (
        "ldmxcsr %[mx]\n\tcvttss2si %[a], %[r]"
        : [r] "=r"(r_)
        : [mx] "m"(g_mx_def), [a] "m"(g_f_1234_75));
    case_u32("sse_cvttss2si_ok", r_);

    __asm__ volatile (
        "ldmxcsr %[mx]\n\tcvttss2si %[a], %[r]"
        : [r] "=r"(r_)
        : [mx] "m"(g_mx_def), [a] "m"(g_f_2p31));
    case_u32("sse_cvttss2si_ovf", r_);

    /* ------------- SSE integer / logic / compare ------------------- */

    SSE_PS2("sse_pxor", g_mx_def, g_pi_a, g_pi_b, "pxor");
    SSE_PS2("sse_pand", g_mx_def, g_pi_a, g_pi_b, "pand");
    SSE_PS2("sse_por", g_mx_def, g_pi_a, g_pi_b, "por");
    SSE_PS2("sse_paddd", g_mx_def, g_pi_ad_a, g_pi_ad_b, "paddd");
    SSE_PS2("sse_paddq", g_mx_def, g_pq_a, g_pq_b, "paddq");

    SSE_COMISD("sse_comisd_lt", g_pd_lt, g_d_2_0);
    SSE_COMISD("sse_comisd_eq", g_pd_eq, g_d_1_0);
    SSE_COMISD("sse_comisd_gt", g_pd_gt, g_d_n2_5);
    SSE_COMISD("sse_comisd_unord", g_pd_un, g_d_1_0);

    /* movd gpr<->xmm round-trip */
    __asm__ volatile (
        "movd %[v], %%xmm0\n\tmovd %%xmm0, %[r]"
        : [r] "=r"(r_)
        : [v] "r"(0xDEADBEEFu)
        : "xmm0");
    case_u32("sse_movd", r_);
}

__attribute__((noreturn))
void _start(void)
{
    run_tests();
    puts_("DONE ");
    put_dec(g_count);
    put("\n", 1);
    sys_exit(0);
}
