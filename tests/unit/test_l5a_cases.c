/*
 * tests/unit/test_l5a_cases.c — Unit test cases for test_l5a
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "test_l5a_internal.h"

void run_l5a_part2(void)
{
    /* 9. ADD/SUB/MUL/DIV ps/pd/ss/sd (NEON-intrinsic expectations;
     *    scalar forms check the preserved upper lanes). */
    {
        static const uint8_t code[] = {
            0x0F, 0x58, 0xC1,             /* addps xmm0, xmm1 */
            0x66, 0x0F, 0x58, 0xD1,       /* addpd xmm2, xmm1 */
            0xF3, 0x0F, 0x58, 0xD9,       /* addss xmm3, xmm1 */
            0xF2, 0x0F, 0x58, 0xE1,       /* addsd xmm4, xmm1 */
            0x0F, 0x5C, 0xE9,             /* subps xmm5, xmm1 */
            0x0F, 0x59, 0xF1,             /* mulps xmm6, xmm1 */
            0x0F, 0x5E, 0xF9,             /* divps xmm7, xmm1 */
        };
        static uint32_t xmm[8][4] = {
            {0x3FC00000U, 0xC0200000U, 0U, 0x41200000U}, /* 1.5,-2.5,0,10 */
            {0x3F000000U, 0x3F000000U, 0x40400000U, 0x40800000U}, /*.5,.5,3,4*/
            {0x3FF80000U, 0xC0040000U, 0U, 0U},        /* 1.5, -2.5 d */
            {0x40E00000U, 0x42820000U, 0xDEAD0000U, 0xBEEF0000U},
            {0U, 0U, 0x13579BDFU, 0x2468ACE0U},        /* d0 = 7.0 below */
            {0x3FC00000U, 0xC0200000U, 0U, 0x41200000U},
            {0x3FC00000U, 0xC0200000U, 0U, 0x41200000U},
            {0x3FC00000U, 0xC0200000U, 0U, 0x41200000U},
        };
        double seven = 7.0;
        case_t k;
        memcpy(&xmm[4][0], &seven, 8U);
        k.code = code; k.clen = sizeof code; k.data = NULL;
        memset((void *)k.gpr, 0, sizeof(k.gpr));
        k.gpr[I686_REG_ESI] = DATA1; k.gpr[I686_REG_EDI] = DATA2;
        k.eflags = 0U; k.xmm = (const uint32_t (*)[4])xmm;
        k.mxcsr = 0U; k.ftag = 0U; k.mm[0] = 0U; k.mm[1] = 0U; k.mm[2] = 0U;
        if (run_case("fp arith families", &k) == 0) {
            float32x4_t a = vld1q_f32((const float32_t *)xmm[0]);
            float32x4_t b = vld1q_f32((const float32_t *)xmm[1]);
            float64x2_t ad = vld1q_f64((const float64_t *)xmm[2]);
            float64x2_t bd = vld1q_f64((const float64_t *)xmm[1]);
            uint32_t e[4];
            vst1q_u32(e, vreinterpretq_u32_f32(vaddq_f32(a, b)));
            xmm_eq(0, e);
            vst1q_u32(e, vreinterpretq_u32_f64(vaddq_f64(ad, bd)));
            xmm_eq(2, e);
            { /* addss: lane 0 only, upper 3 lanes preserved */
                float r = vgetq_lane_f32(vld1q_f32((const float32_t *)xmm[3]),
                                         0) +
                          0.5f;
                uint32_t lanes[4];
                memcpy(lanes, xmm[3], sizeof(lanes));
                memcpy(&lanes[0], &r, 4U);
                xmm_eq(3, lanes);
            }
            { /* addsd: d0 only, upper preserved; the source is the
               * full 64 bits of xmm1's d0 (the {0.5f,0.5f} lanes). */
                double src;
                double r;
                uint64_t bits;
                memcpy(&src, &xmm[1][0], 8U);
                r = 7.0 + src;
                memcpy(&bits, &r, 8U);
                CHECK(memcmp(&g_c.xmm[4][0], &bits, 8U) == 0 &&
                      xmm_word(4, 2) == 0x13579BDFU &&
                      xmm_word(4, 3) == 0x2468ACE0U);
            }
            vst1q_u32(e, vreinterpretq_u32_f32(vsubq_f32(a, b)));
            xmm_eq(5, e);
            vst1q_u32(e, vreinterpretq_u32_f32(vmulq_f32(a, b)));
            xmm_eq(6, e);
            vst1q_u32(e, vreinterpretq_u32_f32(vdivq_f32(a, b)));
            xmm_eq(7, e);
        }
    }

    /* 10. CMPPS eq/lt/unord + CMPSD neq + CMPSS le. */
    {
        static const uint8_t code[] = {
            0x0F, 0xC2, 0xC1, 0x00,       /* cmpps xmm0, xmm1, eq    */
            0x0F, 0xC2, 0xD1, 0x01,       /* cmpps xmm2, xmm1, lt    */
            0x0F, 0xC2, 0xD9, 0x03,       /* cmpps xmm3, xmm1, unord */
            0xF2, 0x0F, 0xC2, 0xE1, 0x04, /* cmpsd xmm4, xmm1, neq   */
            0xF3, 0x0F, 0xC2, 0xE9, 0x02, /* cmpss xmm5, xmm1, le    */
        };
        static const uint32_t nan = 0x7FC00000U;
        static const uint32_t xmm[8][4] = {
            {0x3F800000U, 0x40000000U, nan, 0x80000000U}, /* 1,2,NaN,-0 */
            {0x3F800000U, 0x40400000U, 0x3F800000U, 0U},  /* 1,3,1,0    */
            {0x40A00000U, 0x40A00000U, 0x40A00000U, 0x40A00000U},
            {0x3F800000U, 0x3F800000U, nan, 0x3F800000U},
            {0x40000000U, 0U, 0x42484000U, 0U},           /* 2.0d       */
            {0x3F800000U, 0xDEADBEEFU, 0xCAFEBABEU, 0U},  /* 1.0f       */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("cmpp predicates", &k) == 0) {
            static const uint32_t m = 0xFFFFFFFFU;
            static const uint32_t e0[4] = {m, 0U, 0U, m}; /* eq; -0.0==0.0 */
            static const uint32_t e2[4] = {0U, 0U, 0U, 0U}; /* lt: 5<1.. all F */
            static const uint32_t e3[4] = {0U, 0U, m, 0U};  /* unord */
            static const uint32_t e4[4] = {m, m, 0x42484000U, 0U};
            static const uint32_t e5[4] = {m, 0xDEADBEEFU, 0xCAFEBABEU, 0U};
            xmm_eq(0, e0);
            xmm_eq(2, e2);
            xmm_eq(3, e3);
            xmm_eq(4, e4); /* 2.0 != 0.5, upper lanes preserved */
            xmm_eq(5, e5); /* 1.0 <= 1.0, upper lanes preserved */
        }
    }

    /* 11. MOVMSKPS/MOVMSKPD. */
    {
        static const uint8_t code[] = {
            0x0F, 0x50, 0xC1,             /* movmskps eax, xmm1 */
            0x66, 0x0F, 0x50, 0xCA,       /* movmskpd ecx, xmm2 */
        };
        static uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0xBF800000U, 0x3F800000U, 0xC0000000U, 0xBF000000U},
            {0U, 0U, 0U, 0U},
        };
        uint64_t pos = 0x3FF0000000000000ULL; /*  1.0 */
        uint64_t neg = 0xC008000000000000ULL; /* -3.0 */
        case_t k;
        memcpy(&xmm[2][0], &pos, 8U);
        memcpy(&xmm[2][2], &neg, 8U);
        k.code = code; k.clen = sizeof code; k.data = NULL;
        k.gpr[0] = 0x55U; k.gpr[1] = 0xAAU;
        k.gpr[2] = 0U; k.gpr[3] = 0U; k.gpr[4] = 0U; k.gpr[5] = 0U;
        k.gpr[6] = DATA1; k.gpr[7] = DATA2;
        k.eflags = 0U; k.xmm = (const uint32_t (*)[4])xmm;
        k.mxcsr = 0U; k.ftag = 0U; k.mm[0] = 0U; k.mm[1] = 0U; k.mm[2] = 0U;
        if (run_case("movmskps/pd", &k) == 0) {
            CHECK(g_c.gpr[I686_REG_EAX] == 0xDU);
            CHECK(g_c.gpr[I686_REG_ECX] == 0x2U);
        }
    }

    /* 12a. COMISS greater: ZF/CF/PF clear, OF/SF/AF cleared, DF/IF
     *      kept, lazy_op = NONE. */
    {
        static const uint8_t code[] = {0x0F, 0x2F, 0xC1};
        static const uint32_t xmm[8][4] = {
            {0x40000000U, 0U, 0U, 0U}, /* 2.0f */
            {0x3F800000U, 0U, 0U, 0U}, /* 1.0f */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0xED7U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("comiss greater", &k) == 0) {
            uint32_t fl = g_c.eflags;
            CHECK((fl & (I686_EF_ZF | I686_EF_CF | I686_EF_PF)) == 0U);
            CHECK((fl & (I686_EF_OF | I686_EF_SF | I686_EF_AF)) == 0U);
            CHECK((fl & (I686_EF_DF | I686_EF_IF)) ==
                  (I686_EF_DF | I686_EF_IF));
            CHECK(g_c.lazy_op == I686_FOP_NONE);
        }
    }
    /* 12b. COMISS less: CF only. */
    {
        static const uint8_t code[] = {0x0F, 0x2F, 0xD9}; /* xmm3 vs xmm1 */
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0x3F800000U, 0U, 0U, 0U}, /* 1.0f */
            {0U, 0U, 0U, 0U},
            {0x3F000000U, 0U, 0U, 0U}, /* 0.5f */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0xED7U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("comiss less", &k) == 0) {
            uint32_t fl = g_c.eflags;
            CHECK((fl & I686_EF_CF) != 0U);
            CHECK((fl & (I686_EF_ZF | I686_EF_PF)) == 0U);
            CHECK((fl & (I686_EF_OF | I686_EF_SF | I686_EF_AF)) == 0U);
            CHECK(g_c.lazy_op == I686_FOP_NONE);
        }
    }
    /* 12c. COMISD unordered: ZF/CF/PF all set. */
    {
        static const uint8_t code[] = {0x66, 0x0F, 0x2F, 0xE1};
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {0U, 0x7FF80000U, 0U, 0U}, /* qNaN double */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0xED7U, xmm, 0U, 0U, {0U, 0U, 0U}};
        if (run_case("comisd unordered", &k) == 0) {
            uint32_t fl = g_c.eflags;
            CHECK((fl & (I686_EF_ZF | I686_EF_CF | I686_EF_PF)) ==
                  (I686_EF_ZF | I686_EF_CF | I686_EF_PF));
            CHECK((fl & (I686_EF_OF | I686_EF_SF | I686_EF_AF)) == 0U);
            CHECK(g_c.lazy_op == I686_FOP_NONE);
        }
    }

    /* 13. CVTSI2SS/SD + CVTTSS2SI/CVTTSD2SI. */
    {
        static const uint8_t code[] = {
            0xF3, 0x0F, 0x2A, 0xC0,       /* cvtsi2ss xmm0, eax  */
            0xF2, 0x0F, 0x2A, 0xC8,       /* cvtsi2sd xmm1, eax  */
            0xF3, 0x0F, 0x2C, 0xD2,       /* cvttss2si edx, xmm2 */
            0xF2, 0x0F, 0x2C, 0xDB,       /* cvttsd2si ebx, xmm3 */
        };
        static uint32_t xmm[8][4] = {
            {0U, 0x11111111U, 0x22222222U, 0x33333333U},
            {0U, 0U, 0x44444444U, 0x55555555U},
            {0x406CCCCDU, 0U, 0U, 0U}, /* 3.7f */
            {0U, 0U, 0U, 0U},           /* -2.9d below */
        };
        double m29 = -2.9;
        case_t k;
        memcpy(&xmm[3][0], &m29, 8U);
        k.code = code; k.clen = sizeof code; k.data = NULL;
        k.gpr[0] = 7U; k.gpr[1] = 0U; k.gpr[2] = 0U; k.gpr[3] = 0U;
        k.gpr[4] = 0U; k.gpr[5] = 0U; k.gpr[6] = DATA1; k.gpr[7] = DATA2;
        k.eflags = 0U; k.xmm = (const uint32_t (*)[4])xmm;
        k.mxcsr = 0U; k.ftag = 0U; k.mm[0] = 0U; k.mm[1] = 0U; k.mm[2] = 0U;
        if (run_case("cvt si<->fp", &k) == 0) {
            float f7 = 7.0f;
            double d7 = 7.0;
            uint32_t fb;
            uint64_t db;
            memcpy(&fb, &f7, 4U);
            memcpy(&db, &d7, 8U);
            CHECK(xmm_word(0, 0) == fb && xmm_word(0, 1) == 0x11111111U &&
                  xmm_word(0, 2) == 0x22222222U &&
                  xmm_word(0, 3) == 0x33333333U);
            CHECK(memcmp(&g_c.xmm[1][0], &db, 8U) == 0 &&
                  xmm_word(1, 2) == 0x44444444U &&
                  xmm_word(1, 3) == 0x55555555U);
            CHECK(g_c.gpr[I686_REG_EDX] == 3U);
            CHECK(g_c.gpr[I686_REG_EBX] == (uint32_t)-2);
        }
    }

    /* 14. CVTPS2PD/CVTPD2PS/CVTSS2SD/CVTSD2SS. */
    {
        static const uint8_t code[] = {
            0x0F, 0x5A, 0xC1,             /* cvtps2pd xmm0, xmm1 */
            0x66, 0x0F, 0x5A, 0xD3,       /* cvtpd2ps xmm2, xmm3 */
            0xF3, 0x0F, 0x5A, 0xE1,       /* cvtss2sd xmm4, xmm1 */
            0xF2, 0x0F, 0x5A, 0xEB,       /* cvtsd2ss xmm5, xmm3 */
        };
        static uint32_t xmm[8][4] = {
            {0U, 0U, 0U, 0U},
            {0x3FC00000U, 0xBE800000U, 0U, 0U}, /* 1.5f, -0.25f */
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},                   /* 2.75d, -8.5d below */
            {0U, 0U, 0xDEADBEEFU, 0x1BADB002U},
            {0U, 0x13579BDFU, 0x2468ACE0U, 0U},
        };
        double d2[2] = {2.75, -8.5};
        case_t k;
        memcpy(&xmm[3][0], d2, 16U);
        k.code = code; k.clen = sizeof code; k.data = NULL;
        memset((void *)k.gpr, 0, sizeof(k.gpr));
        k.gpr[I686_REG_ESI] = DATA1; k.gpr[I686_REG_EDI] = DATA2;
        k.eflags = 0U; k.xmm = (const uint32_t (*)[4])xmm;
        k.mxcsr = 0U; k.ftag = 0U; k.mm[0] = 0U; k.mm[1] = 0U; k.mm[2] = 0U;
        if (run_case("cvt widths", &k) == 0) {
            double e0[2] = {1.5, -0.25};
            float e2[4] = {2.75f, -8.5f, 0.0f, 0.0f};
            double e4 = 1.5;
            uint32_t e5;
            float f275 = 2.75f;
            memcpy(&e5, &f275, 4U);
            CHECK(memcmp(g_c.xmm[0], e0, 16U) == 0);
            CHECK(memcmp(g_c.xmm[2], e2, 16U) == 0);
            CHECK(memcmp(&g_c.xmm[4][0], &e4, 8U) == 0 &&
                  xmm_word(4, 2) == 0xDEADBEEFU &&
                  xmm_word(4, 3) == 0x1BADB002U);
            CHECK(xmm_word(5, 0) == e5 &&
                  xmm_word(5, 1) == 0x13579BDFU &&
                  xmm_word(5, 2) == 0x2468ACE0U &&
                  xmm_word(5, 3) == 0U);
        }
    }

    /* 15. CVTDQ2PS/CVTPS2DQ (round-even)/CVTTPS2DQ + MMX CVTPI2PS +
     *     CVTTPS2PI + CVTTPD2PI + CVTPI2PD (tags -> valid). */
    {
        static const uint8_t code[] = {
            0x0F, 0x2A, 0xC6,             /* cvtpi2ps  xmm0, mm6  */
            0x0F, 0x2C, 0xC7,             /* cvttps2pi mm0, xmm7  */
            0x0F, 0x5B, 0xD5,             /* cvtdq2ps  xmm2, xmm5 */
            0x66, 0x0F, 0x5B, 0xD9,       /* cvtps2dq  xmm3, xmm1 */
            0xF3, 0x0F, 0x5B, 0xE1,       /* cvttps2dq xmm4, xmm1 */
            0x66, 0x0F, 0x2A, 0xF6,       /* cvtpi2pd  xmm6, mm6  */
            0x66, 0x0F, 0x2C, 0xCE,       /* cvttpd2pi mm1, xmm6  */
        };
        static const uint32_t xmm[8][4] = {
            {0U, 0U, 0x0BADF00DU, 0x600DCAFEU},
            {0x3FC00000U, 0x40200000U, 0xBFC00000U, 0x3F000000U}, /*1.5,2.5,-1.5,.5*/
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {0U, 0U, 0U, 0U},
            {1U, 0xFFFFFFFEU, 3U, 0xFFFFFFFCU}, /* 1,-2,3,-4 */
            {0U, 0U, 0U, 0U},
            {0x3FF33333U, 0xC0273333U, 0U, 0U}, /* 1.9f, -2.9f */
        };
        case_t k = {code, sizeof code, NULL,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, xmm, 0U, 0xAAAAU, {0x0000000400000003ULL, 0U, 0U}};
        if (run_case("cvt packed + mmx", &k) == 0) {
            float f[2] = {3.0f, 4.0f};
            double d34[2] = {3.0, 4.0};
            static const uint32_t e2[4] = {0x3F800000U, 0xC0000000U,
                                           0x40400000U, 0xC0800000U};
            static const uint32_t e3[4] = {2U, 2U, (uint32_t)-2U, 0U};
            static const uint32_t e4[4] = {1U, 2U, (uint32_t)-1U, 0U};
            CHECK(memcmp(&g_c.xmm[0][0], f, 8U) == 0 &&
                  xmm_word(0, 2) == 0x0BADF00DU &&
                  xmm_word(0, 3) == 0x600DCAFEU);
            mm_eq(0, 0xFFFFFFFE00000001ULL); /* f32 path: {1, -2} */
            mm_eq(1, 0x0000000400000003ULL); /* f64 path: {3, 4}   */
            xmm_eq(2, e2);
            xmm_eq(3, e3); /* nearest-even: 2.5->2, -1.5->-2 */
            xmm_eq(4, e4); /* truncate */
            CHECK(memcmp(&g_c.xmm[6][0], d34, 16U) == 0);
            CHECK(g_c.ftag == 0U);
        }
    }

    /* 16. LDMXCSR (reserved bits masked) + STMXCSR + EMMS (ftag empty)
     *     + PAUSE = NOP (no state change). */
    {
        static const uint8_t code[] = {
            0x0F, 0xAE, 0x16,             /* ldmxcsr [esi]  */
            0x0F, 0xAE, 0x1F,             /* stmxcsr [edi]  */
            0x0F, 0x77,                   /* emms           */
            0xF3, 0x0F, 0x90, 0xC0,       /* pause          */
            0xB8, 0x33, 0x00, 0x00, 0x00, /* mov eax, 0x33  */
        };
        static const uint32_t mem[4] = {0x12349F80U, 0U, 0U, 0U};
        case_t k = {code, sizeof code, mem,
                    {0U, 0U, 0U, 0U, 0U, 0U, DATA1, DATA2},
                    0U, NULL, 0x1F80U, 0x5555U, {0U, 0U}};
        if (run_case("mxcsr/emms/pause", &k) == 0) {
            CHECK(g_c.mxcsr == 0x00009F80U);
            CHECK(data_word(DATA2, 0) == 0x00009F80U);
            CHECK(g_c.ftag == 0xFFFFU);
            CHECK(g_c.gpr[I686_REG_EAX] == 0x33U);
        }
    }
}

