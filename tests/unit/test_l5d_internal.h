/*
 * tests/unit/test_l5d_internal.h — Shared declarations for test_l5d
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_UNIT_TEST_L5D_INTERNAL_H
#define I686RT_TESTS_UNIT_TEST_L5D_INTERNAL_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "interp/x87_80.h"
#define X_IE 1u
#define X_DE 2u
#define X_ZE 4u
#define X_OE 8u
#define X_UE 16u
#define X_PE 32u
#define CHECK(cond, ...)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            g_fail++;                                                       \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);                     \
            printf(__VA_ARGS__);                                            \
            printf("\n");                                                   \
        }                                                                   \
    } while (0)
typedef struct {
    uint64_t mant; /* normalized, bit63 set (finite nonzero numerics) */
    int32_t exp;   /* value = mant * 2^(exp-63) */
    bool sign;
    int cls; /* 0 zero, 1 num, 2 inf, 3 qnan, 4 snan, 5 unsupported */
    bool den_enc;
} dec_t;
#define NL 12
#define TOPBIT (NL * 32 - 1)
typedef struct { uint32_t l[NL]; } big_t;

extern int g_fail;

void mk80(uint8_t v[10], unsigned se, uint64_t mant);
void hx80(const uint8_t v[10], char *buf, size_t cap);
int eq80(const uint8_t a[10], const uint8_t b[10]);
void from_hex(uint8_t v[10], const char *hex);
void dec(const uint8_t v[10], dec_t *d);
int ulp1(const uint8_t a[10], const uint8_t b[10]);
void big_zero(big_t *b);
void big_u64(big_t *b, uint64_t v);
int big_is_zero(const big_t *b);
unsigned big_bit(const big_t *b, unsigned pos);
int big_bits_below(const big_t *b, unsigned pos);
void big_norm(big_t *b, int32_t *e);
int big_cmp(const big_t *a, const big_t *b);
void big_add(big_t *a, const big_t *b);
void big_add_u64(big_t *a, uint64_t v);
void big_shl(big_t *a, unsigned bits);
void big_shr(big_t *a, unsigned bits, int *sticky);
void big_mul_small(big_t *a, uint32_t m);
void big_mul_u64(big_t *a, uint64_t m);
void big_divmod_u64(const big_t *a, uint64_t d, big_t *q, uint64_t *rem);
uint64_t big_isqrt(uint64_t nhi, uint64_t nlo);
unsigned orc(uint8_t out[10], bool sign, big_t m, int32_t e, int sticky,
                    unsigned rc, unsigned pc);
unsigned orc_addsub(uint8_t out[10], const dec_t *a, const dec_t *b,
                           bool sub, unsigned rc, unsigned pc);
unsigned orc_mul(uint8_t out[10], const dec_t *a, const dec_t *b,
                        unsigned rc, unsigned pc);
unsigned orc_div(uint8_t out[10], const dec_t *a, const dec_t *b,
                        unsigned rc, unsigned pc);
unsigned orc_sqrt(uint8_t out[10], const dec_t *a, unsigned rc, unsigned pc);
int op_id(const char *s);
int eq_hex(const uint8_t o[10], const char *want);
uint32_t strtoul_hex32(const char *h);
uint64_t strtoul_hex64(const char *h);
int ulp1_hex(const uint8_t o[10], const char *want);
void run_goldens(void);
void run_specials(void);
uint64_t nextr(void);
void gen_operand(uint8_t v[10], dec_t *d);
void run_random(void);

#endif /* I686RT_TESTS_UNIT_TEST_L5D_INTERNAL_H */
