/*
 * tests/probe_strfuncs.c — RC7b T2 glibc string-function opcode-sequence
 * fixture
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "probe_strfuncs_internal.h"

/* ------------------------------------------------------------------ */
/* expected-value helpers                                              */
/* ------------------------------------------------------------------ */

static void exp_pcmp_eq8(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = a[i] == b[i] ? 0xFFu : 0x00u;
    }
}

static void exp_pcmp_gt8(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = (int8_t)a[i] > (int8_t)b[i] ? 0xFFu : 0x00u;
    }
}

static void exp_pcmp_eq32(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 4u; i++) {
        uint32_t m = ld32(a + 4u * i) == ld32(b + 4u * i) ? 0xFFFFFFFFu : 0u;
        o[4u * i] = (uint8_t)m;
        o[4u * i + 1u] = (uint8_t)(m >> 8);
        o[4u * i + 2u] = (uint8_t)(m >> 16);
        o[4u * i + 3u] = (uint8_t)(m >> 24);
    }
}

static void exp_minmaxub(uint8_t *o, const uint8_t *a, const uint8_t *b, int mx)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = mx ? (a[i] > b[i] ? a[i] : b[i])
                  : (a[i] < b[i] ? a[i] : b[i]);
    }
}

static void exp_psubb(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = (uint8_t)(a[i] - b[i]);
    }
}

static uint32_t exp_pmovmskb(const uint8_t *a)
{
    uint32_t r = 0u;
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        r |= (uint32_t)(a[i] >> 7) << i;
    }
    return r;
}

static void exp_por(uint8_t *o, const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        o[i] = (uint8_t)(a[i] | b[i]);
    }
}

static int v16_eq(const uint8_t *a, const uint8_t *b)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        if (a[i] != b[i]) {
            return 0;
        }
    }
    return 1;
}

static void print_v16(const uint8_t *v)
{
    unsigned i;
    for (i = 0u; i < 16u; i++) {
        phex8(v[i]);
    }
}

static void p_line(const char *nm)
{
    puts_("PR ");
    puts_(nm);
    put(" ", 1);
}

/* ------------------------------------------------------------------ */
/* driver                                                              */
/* ------------------------------------------------------------------ */

__attribute__((noreturn))
void _start(void)
{
    unsigned off, k, vi, ii;
    static const int needle_ofs[9] = { 0, 1, 5, 15, 16, 31, 33, 47, 63 };
    char name[8];

    /* ---------------- S: blob cases ---------------- */

    fill_pattern(buf, sizeof buf, 0x2Au);
    __builtin_memcpy(buf + 64, "/usr/bin/sh", 12);
    blob_case("chr", "dash", 64u, (const char *)buf + 64, '/');
    blob_case("rrc", "dash", 64u, (const char *)buf + 64, '/');
    mem_case("dash", 64u, (const char *)buf + 64, '/', 12u);
    mem_case("dash", 64u, (const char *)buf + 64, 'n', 8u);
    mem_case("dash", 64u, (const char *)buf + 64, '/', 0u);
    strlen_case("dash", 64u, (const char *)buf + 64);

    for (off = 0u; off < 64u; off++) {
        name[0] = 'a';
        name[1] = (char)('0' + off / 10u);
        name[2] = (char)('0' + off % 10u);
        name[3] = '\0';

        fill_pattern(buf, sizeof buf, (uint8_t)(off + 1u));
        buf[off + 0] = (uint8_t)'/';
        buf[off + 1] = (uint8_t)'x';
        buf[off + 2] = (uint8_t)'y';
        buf[off + 3] = 0u;
        blob_case("chr", name, off, (const char *)buf + off, '/');
        blob_case("rrc", name, off, (const char *)buf + off, '/');
        mem_case(name, off, (const char *)buf + off, '/', 4u);

        fill_pattern(buf, sizeof buf, (uint8_t)(off + 7u));
        for (k = 0u; k < 9u; k++) {
            buf[off + (unsigned)needle_ofs[k]] = (uint8_t)'/';
        }
        buf[off + 70] = 0u;
        blob_case("chr", name, off, (const char *)buf + off, '/');
        blob_case("rrc", name, off, (const char *)buf + off, '/');
        mem_case(name, off, (const char *)buf + off, '/', 70u);
        mem_case(name, off, (const char *)buf + off, '/', 2u);

        fill_pattern(buf, sizeof buf, (uint8_t)(off + 13u));
        buf[off + 71] = 0u;
        blob_case("chr", name, off, (const char *)buf + off, '/');
        blob_case("rrc", name, off, (const char *)buf + off, '/');
        mem_case(name, off, (const char *)buf + off, '/', 71u);

        buf[off + 5] = 0u;
        blob_case("chr", name, off, (const char *)buf + off, 0);
        blob_case("rrc", name, off, (const char *)buf + off, 0);
        mem_case(name, off, (const char *)buf + off, 0, 71u);

        buf[off + 3] = 0u;
        buf[off + 9] = (uint8_t)'/';
        blob_case("chr", name, off, (const char *)buf + off, '/');
        blob_case("rrc", name, off, (const char *)buf + off, '/');
        mem_case(name, off, (const char *)buf + off, '/', 71u);

        fill_pattern(buf, sizeof buf, (uint8_t)(off + 3u));
        buf[off + 20] = 0u;
        strlen_case(name, off, (const char *)buf + off);

        fill_pattern(buf, sizeof buf, (uint8_t)(off + 17u));
        buf[off + 130] = 0u;
        strlen_case(name, off, (const char *)buf + off);
    }

    {
        static const unsigned bofs[4] = { 16u, 32u, 64u, 128u };
        unsigned bi;
        for (bi = 0u; bi < 4u; bi++) {
            for (k = 0u; k < 4u; k++) {
                fill_pattern(buf, sizeof buf, (uint8_t)(bi * 4u + k + 29u));
                buf[bofs[bi] + k] = (uint8_t)'/';
                buf[bofs[bi] + 140] = 0u;
                name[0] = 'b';
                name[1] = (char)('0' + bi);
                name[2] = (char)('0' + k);
                name[3] = '\0';
                blob_case("chr", name, bofs[bi] - k,
                          (const char *)buf + bofs[bi] - k, '/');
                blob_case("rrc", name, bofs[bi] - k,
                          (const char *)buf + bofs[bi] - k, '/');
                mem_case(name, bofs[bi] - k,
                         (const char *)buf + bofs[bi] - k, '/', 140u);
            }
        }
    }

    /* ---------------- P1: head-scan prologue ---------------- */
    for (off = 0u; off < 20u; off++) {
        uint8_t c = (uint8_t)('/' + off);
        uint32_t got, exp = 0u;
        unsigned i;

        fill_pattern(buf, sizeof buf, (uint8_t)(off + 5u));
        buf[off + 3] = 0u;
        buf[off + 7] = c;
        got = p1_head_scan((const char *)buf + off, c);
        for (i = 0u; i < 16u; i++) {
            uint8_t b = buf[off + i];
            if (b == 0u) {
                exp |= 0x10000u << i;
            }
            if (b == c) {
                exp |= 1u << i;
            }
        }
        p_line("p1");
        put("o=", 2);
        phex((uint32_t)off);
        put(" got=", 5);
        phex(got);
        put(" exp=", 5);
        phex(exp);
        put(" ", 1);
        finish(got == exp);
    }

    /* ---------------- P2: PSRLDQ/PSLLDQ ---------------- */
    {
        static const struct { const char *nm; p2_fn f; int psll, imm; } p2t[10] = {
            { "p2rl0", p2_rl0, 0, 0 }, { "p2rl1", p2_rl1, 0, 1 },
            { "p2rl15", p2_rl15, 0, 15 }, { "p2rl16", p2_rl16, 0, 16 },
            { "p2rl255", p2_rl255, 0, 255 },
            { "p2ll0", p2_ll0, 1, 0 }, { "p2ll1", p2_ll1, 1, 1 },
            { "p2ll15", p2_ll15, 1, 15 }, { "p2ll16", p2_ll16, 1, 16 },
            { "p2ll255", p2_ll255, 1, 255 }
        };
        static _Alignas(16) uint8_t p2src[16];
        static _Alignas(16) uint8_t got[16], exp[16];
        unsigned i;
        int psll;

        for (ii = 0u; ii < 10u; ii++) {
            int imm = p2t[ii].imm;
            unsigned run;

            for (run = 0u; run < 2u; run++) {
                if (run == 0u) {
                    for (i = 0u; i < 16u; i++) {
                        p2src[i] = (uint8_t)(i + 1u);
                    }
                } else {
                    for (i = 0u; i < 16u; i++) {
                        p2src[i] = 0xFFu;
                    }
                }
                p2t[ii].f(p2src, got);
                for (i = 0u; i < 16u; i++) {
                    exp[i] = 0u;
                    if (imm < 16) {
                        if (p2t[ii].psll) {
                            if (i >= (unsigned)imm) {
                                exp[i] = p2src[i - (unsigned)imm];
                            }
                        } else {
                            if (i + (unsigned)imm < 16u) {
                                exp[i] = p2src[i + (unsigned)imm];
                            }
                        }
                    }
                }
                p_line(p2t[ii].nm);
                if (run != 0u) {
                    puts_("ff");
                }
                print_v16(got);
                put(" e=", 3);
                print_v16(exp);
                put(" ", 1);
                finish(v16_eq(got, exp));
            }
        }

        for (psll = 0; psll <= 1; psll++) {
            uint64_t lo, hi;
            for (i = 0u; i < 16u; i++) {
                p2src[i] = (uint8_t)(i + 1u);
            }
            p2q(p2src, got, psll);
            lo = ld64(p2src);
            hi = ld64(p2src + 8);
            lo = psll ? lo << 4 : lo >> 4;
            hi = psll ? hi << 4 : hi >> 4;
            p_line(psll ? "p2llq" : "p2rlq");
            print_v16(got);
            put(" ", 1);
            finish(ld64(got) == lo && ld64(got + 8) == hi);
        }
    }

    /* ---------------- P3: zero scan on edge vectors ---------------- */
    {
        static const uint8_t vecs[4][16] = {
            { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
              0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
            { 0x00, 0xFF, 0x00, 0xFF, 0x80, 0x7F, 0x80, 0x7F,
              0x01, 0xFE, 0x55, 0xAA, 0x00, 0x80, 0xFF, 0x7F }
        };
        static _Alignas(16) uint8_t got[16];
        static _Alignas(16) uint8_t src[16];
        uint8_t exp[16];
        for (vi = 0u; vi < 4u; vi++) {
            uint32_t m;
            unsigned i;
            for (i = 0u; i < 16u; i++) {
                src[i] = vecs[vi][i];
            }
            m = p3_zero_scan(src, got);
            for (i = 0u; i < 16u; i++) {
                exp[i] = vecs[vi][i] == 0u ? 0xFFu : 0x00u;
            }
            p_line("p3");
            put("v=", 2);
            phex(vi);
            put(" m=", 3);
            phex(m);
            print_v16(got);
            put(" ", 1);
            finish(m == exp_pmovmskb(exp) && v16_eq(got, exp));
        }
    }

    /* ---------------- P4..P8: packed integer edges ---------------- */
    {
        static const uint8_t A[16] = {
            0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x55, 0xAA,
            0x00, 0xFF, 0x80, 0x7F, 0x01, 0xFE, 0x55, 0xAA
        };
        static const uint8_t B[16] = {
            0xFF, 0x00, 0x7F, 0x80, 0x01, 0x01, 0xAA, 0x55,
            0x00, 0x00, 0x80, 0x80, 0x7F, 0x7F, 0xAA, 0x55
        };
        static _Alignas(16) uint8_t got[16];
        uint8_t exp[16];

        p4_eq8(A, B, got);
        exp_pcmp_eq8(exp, A, B);
        p_line("p4eq8");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p4_gt8(A, B, got);
        exp_pcmp_gt8(exp, A, B);
        p_line("p4gt8");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p5_eq32(A, B, got);
        exp_pcmp_eq32(exp, A, B);
        p_line("p5eq32");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p7_min(A, B, got);
        exp_minmaxub(exp, A, B, 0);
        p_line("p7min");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p7_max(A, B, got);
        exp_minmaxub(exp, A, B, 1);
        p_line("p7max");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p8_sub(A, B, got);
        exp_psubb(exp, A, B);
        p_line("p8sub");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));

        p8_sub(B, A, got);
        exp_psubb(exp, B, A);
        p_line("p8swp");
        print_v16(got);
        put(" e=", 3);
        print_v16(exp);
        put(" ", 1);
        finish(v16_eq(got, exp));
    }

    /* ---------------- P6: pmovmskb edge patterns ---------------- */
    {
        static const uint8_t P[6][16] = {
            { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
              0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
              0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 },
            { 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F,
              0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F, 0x7F },
            { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
              0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA },
            { 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
              0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55 }
        };
        for (vi = 0u; vi < 6u; vi++) {
            uint32_t got = p_pmovmskb(P[vi]);
            uint32_t exp = exp_pmovmskb(P[vi]);
            p_line("p6");
            put("v=", 2);
            phex(vi);
            put(" got=", 5);
            phex(got);
            put(" exp=", 5);
            phex(exp);
            put(" ", 1);
            finish(got == exp);
        }
    }

    /* ---------------- P9: MOVQ row ---------------- */
    {
        static _Alignas(16) uint8_t src[32];
        static _Alignas(16) uint8_t d64[16], d16[16], m[32];
        unsigned i;

        for (i = 0u; i < 32u; i++) {
            src[i] = (uint8_t)(0xA0u + i);
        }
        for (i = 0u; i < 16u; i++) {
            d64[i] = 0x1Cu;
            d16[i] = 0x2Du;
        }
        p9_movq_row(src, d64, d16);
        p_line("p9a");
        print_v16(d64);
        put(" ", 1);
        finish(d64[0] == 0xA0u && d64[7] == 0xA7u && d64[8] == 0x1Cu);
        p_line("p9b");
        print_v16(d16);
        put(" ", 1);
        finish(d16[0] == 0xA0u && d16[7] == 0xA7u && d16[8] == 0x00u &&
               d16[15] == 0x00u);

        for (i = 0u; i < 16u; i++) {
            m[i] = (uint8_t)(0xC0u + i);
            m[16u + i] = (uint8_t)(0xD0u + i);
        }
        p9_movq_rr(m);
        p_line("p9rr");
        print_v16(m);
        put(" ", 1);
        finish(m[0] == 0xC0u && m[7] == 0xC7u && m[8] == 0x00u &&
               m[15] == 0x00u);

        {
            uint8_t q[16];
            uint32_t back;
            for (i = 0u; i < 16u; i++) {
                q[i] = (uint8_t)(0xE0u + i);
            }
            back = p9_movq_mmx(q);
            p_line("p9mm");
            print_v16(q);
            put(" back=", 6);
            phex(back);
            put(" ", 1);
            finish(q[0] == 0x44u && q[1] == 0x33u && q[2] == 0x22u &&
                   q[3] == 0x11u && q[4] == 0x00u &&
                   back == 0x11223344u);
        }
    }

    /* ---------------- P10: MOVD zero-extension ---------------- */
    {
        static _Alignas(16) uint8_t a[16];
        uint32_t got;
        unsigned i;
        for (i = 0u; i < 16u; i++) {
            a[i] = 0xF0u;
        }
        a[0] = 0x78u;
        a[1] = 0x56u;
        a[2] = 0x34u;
        a[3] = 0x12u;
        got = p10_movd(a);
        p_line("p10");
        put("got=", 4);
        phex(got);
        put(" ", 1);
        finish(got == 0x12345678u);
    }

    /* ---------------- P11: MOVNTDQ aligned ---------------- */
    {
        static _Alignas(16) uint8_t dst[16];
        uint8_t src[16];
        unsigned i;
        for (i = 0u; i < 16u; i++) {
            src[i] = (uint8_t)(0x60u + i);
            dst[i] = 0;
        }
        p11_movntdq(src, dst);
        p_line("p11");
        print_v16(dst);
        put(" ", 1);
        finish(v16_eq(dst, src));
    }

    /* ---------------- P12: prefetch + sfence ---------------- */
    {
        uint8_t m[16];
        unsigned i;
        for (i = 0u; i < 16u; i++) {
            m[i] = (uint8_t)(0x11u * (i + 1u));
        }
        p12_prefetch_sfence(m);
        p_line("p12");
        print_v16(m);
        put(" ", 1);
        finish(m[0] == 0x11u && m[1] == 0x22u && m[2] == 0x33u &&
               m[3] == 0x44u && m[4] == 0x55u && m[5] == 0x66u &&
               m[6] == 0x77u && m[7] == 0x88u && m[8] == 0x99u &&
               m[15] == 0x10u);
    }

    /* ---------------- P14: por ---------------- */
    {
        static const uint8_t X[16] = {
            0xF0, 0x0F, 0xAA, 0x55, 0x00, 0xFF, 0x80, 0x7F,
            0x01, 0xFE, 0x11, 0xEE, 0x22, 0xDD, 0x44, 0xBB
        };
        static const uint8_t Y[16] = {
            0x0F, 0xF0, 0x55, 0xAA, 0xFF, 0x00, 0x7F, 0x80,
            0xFE, 0x01, 0x11, 0x11, 0x00, 0x00, 0xBB, 0xBB
        };
        uint8_t z[16];
        uint32_t got = p14_por(X, Y);
        exp_por(z, X, Y);
        p_line("p14");
        put("got=", 4);
        phex(got);
        put(" exp=", 5);
        phex(exp_pmovmskb(z));
        put(" ", 1);
        finish(got == exp_pmovmskb(z));
    }

    /* ---------------- P15: MMX plain forms ---------------- */
    {
        static const uint8_t MA[8] = { 0x00, 0xFF, 0x80, 0x7F,
                                       0x01, 0xFE, 0x55, 0xAA };
        static const uint8_t MB[8] = { 0xFF, 0x00, 0x7F, 0x80,
                                       0x01, 0x01, 0xAA, 0x55 };
        static _Alignas(16) uint8_t out[80];
        uint8_t a[16], b[16], e[16];
        uint64_t v;
        int ok = 1;
        unsigned i;

        for (i = 0u; i < 8u; i++) {
            a[i] = MA[i];
            a[8u + i] = 0u;
            b[i] = MB[i];
            b[8u + i] = 0u;
        }
        for (i = 0u; i < (unsigned)sizeof out; i++) {
            out[i] = 0xCCu;
        }
        p15_mmx(MA, MB, out);

        exp_psubb(e, a, b);
        ok = ok && v8_eq(out, e);
        exp_pcmp_eq8(e, a, b);
        ok = ok && v8_eq(out + 8, e);
        exp_pcmp_gt8(e, a, b);
        ok = ok && v8_eq(out + 16, e);
        exp_pcmp_eq32(e, a, b);
        ok = ok && v8_eq(out + 24, e);
        exp_minmaxub(e, a, b, 0);
        ok = ok && v8_eq(out + 32, e);
        exp_minmaxub(e, a, b, 1);
        ok = ok && v8_eq(out + 40, e);
        ok = ok && ld32(out + 48) == exp_pmovmskb(a);
        v = ld64(a);
        ok = ok && ld64(out + 56) == (v >> 4) &&
                    ld64(out + 64) == (v << 4) && out[72] == 0xCCu;
        p_line("p15");
        put("got=", 4);
        print_v16(out);
        put(" ", 1);
        finish(ok);
    }

    puts_("DONE ");
    put_dec(total);
    put(" FAIL ", 6);
    put_dec(fails);
    put("\n", 1);
    sys_exit(fails == 0u ? 0L : 1L);
}
