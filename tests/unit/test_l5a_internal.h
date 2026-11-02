/*
 * tests/unit/test_l5a_internal.h — Shared declarations for test_l5a
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_UNIT_TEST_L5A_INTERNAL_H
#define I686RT_TESTS_UNIT_TEST_L5A_INTERNAL_H

#define _GNU_SOURCE /* MAP_ANONYMOUS/MAP_NORESERVE, as in src/rt32 */
#include <arm_neon.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS 0x1000
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif
#include "dbt/emit.h"
#include "i686rt.h"
#include "interp/interp.h"
#define WIN_FULL  0x100000000ULL
#define WIN_SMALL 0x1000000UL
#define CODE_CAP  4096U
#define CASE_EIP  0x001000U
#define DATA1     0x002000U
#define DATA2     0x002100U
#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)
typedef struct {
    const uint8_t *code;
    size_t         clen;
    const uint32_t *data;     /* 4 dwords placed at DATA1 */
    uint32_t       gpr[8];
    uint32_t       eflags;
    const uint32_t (*xmm)[4]; /* NULL or 8 entries           */
    uint32_t       mxcsr;
    uint16_t       ftag;
    uint64_t       mm[3];     /* st[6], st[7], st[1] low qwords */
} case_t;

extern uint8_t  *g_win;
extern uint8_t  *g_code;
extern uint32_t  g_epoch;
extern int       g_pass;
extern int       g_fail;
extern i686_ctx_t g_c;

void prime(const case_t *k);
void ctx_setup(i686_ctx_t *c, const case_t *k);
int dbt_engine(i686_ctx_t *c, uint32_t *first_reason,
                      uint32_t *first_arg, uint32_t *first_dest);
int run_case(const char *name, const case_t *k);
void xmm_eq(unsigned r, const uint32_t w[4]);
void mm_eq(unsigned r, uint64_t v);
uint32_t xmm_word(unsigned r, unsigned i);
uint32_t data_word(unsigned va, unsigned idx);
void run_l5a_part2(void);

#endif /* I686RT_TESTS_UNIT_TEST_L5A_INTERNAL_H */
