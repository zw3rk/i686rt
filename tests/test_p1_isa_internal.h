/*
 * tests/test_p1_isa_internal.h — Declarations and macros for test_p1_isa
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_TEST_P1_ISA_INTERNAL_H
#define I686RT_TESTS_TEST_P1_ISA_INTERNAL_H

#include <stdint.h>

long sys_write(int fd, const void *buf, unsigned long len);
__attribute__((noreturn)) void sys_exit(long code);
void put(const char *s, unsigned n);
void puts_(const char *s);
void phex(uint32_t v);

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

uint32_t f_add(uint32_t a, uint32_t b, uint32_t *r);
uint32_t f_sub(uint32_t a, uint32_t b, uint32_t *r);
uint32_t f_cmp(uint32_t a, uint32_t b);
uint32_t f_adc(uint32_t a, uint32_t b, int cf, uint32_t *r);
uint32_t f_sbb(uint32_t a, uint32_t b, int cf, uint32_t *r);
uint32_t f_inc(uint32_t a, uint32_t *r);
uint32_t f_inc_stc(uint32_t a, uint32_t *r);
uint32_t f_dec_clc(uint32_t a, uint32_t *r);
uint32_t f_neg(uint32_t a, uint32_t *r);
uint32_t f_and(uint32_t a, uint32_t b, uint32_t *r);
uint32_t f_or(uint32_t a, uint32_t b, uint32_t *r);
uint32_t f_xor(uint32_t a, uint32_t b, uint32_t *r);
uint32_t f_test(uint32_t a, uint32_t b);
uint32_t f_shl(uint32_t v, uint32_t cnt, uint32_t *r);
uint32_t f_shr(uint32_t v, uint32_t cnt, uint32_t *r);
uint32_t f_sar(uint32_t v, uint32_t cnt, uint32_t *r);
uint32_t f_rol(uint32_t v, uint32_t cnt, uint32_t *r);
uint32_t f_ror(uint32_t v, uint32_t cnt, uint32_t *r);
uint32_t f_shld_i(uint32_t dst, uint32_t src, uint32_t *r);
uint32_t f_shrd_i(uint32_t dst, uint32_t src, uint32_t *r);
uint32_t f_shld_cl(uint32_t dst, uint32_t src, uint32_t cnt, uint32_t *r);
uint32_t f_shrd_cl(uint32_t dst, uint32_t src, uint32_t cnt, uint32_t *r);
uint32_t f_bt(uint32_t v, uint32_t bit);
uint32_t f_bts(uint32_t v, uint32_t bit, uint32_t *r);
uint32_t f_btr(uint32_t v, uint32_t bit, uint32_t *r);
uint32_t f_btc(uint32_t v, uint32_t bit, uint32_t *r);
uint32_t f_bsf(uint32_t v, uint32_t init_dst, uint32_t *r);
uint32_t f_bsr(uint32_t v, uint32_t init_dst, uint32_t *r);
uint32_t f_mul(uint32_t a, uint32_t b, uint32_t *hi, uint32_t *lo);
uint32_t f_imul1(int32_t a, int32_t b, uint32_t *hi, uint32_t *lo);
uint32_t f_imul2(int32_t a, int32_t b, uint32_t *r);
uint32_t f_div(uint32_t hi, uint32_t lo, uint32_t d, uint32_t *q, uint32_t *rem);
uint32_t f_idiv(int32_t hi, uint32_t lo, int32_t d, int32_t *q, int32_t *rem);

#endif /* I686RT_TESTS_TEST_P1_ISA_INTERNAL_H */
