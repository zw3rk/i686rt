/*
 * tests/unit/test_l5c_internal.h — Shared declarations for test_l5c
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_UNIT_TEST_L5C_INTERNAL_H
#define I686RT_TESTS_UNIT_TEST_L5C_INTERNAL_H

#include <float.h>
#include <math.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "i686rt.h"
#include "interp/interp.h"
#include "interp/x87.h"
#include "x86/decode.h"
#define WIN_SIZE 0x100000U /* 1 MiB fake guest window */
#define CODE_VA  0x001000U
#define DATA_VA  0x002000U
#define ENV_VA   0x003000U
#define FX_VA    0x003800U
#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            t_pass++;                                                        \
        } else {                                                             \
            t_fail++;                                                        \
            printf("FAIL %d: %s\n", __LINE__, #cond);                        \
        }                                                                    \
    } while (0)

extern i686_interp_fn t_tab[I686_OP_COUNT];
extern uint8_t *t_win;
extern int t_pass;
extern int t_fail;

uint32_t gm_rd32(const i686_ctx_t *ctx, uint32_t va);
uint64_t gm_rd64(const i686_ctx_t *ctx, uint32_t va);
void gm_wr32(i686_ctx_t *ctx, uint32_t va, uint32_t v);
void gm_wr64m(i686_ctx_t *ctx, uint32_t va, uint64_t v);
void reset_fpu(i686_ctx_t *ctx);
i686_ctx_t *mkctx(int mode80);
int run(i686_ctx_t *ctx, const uint8_t *b, unsigned n);
int runb(i686_ctx_t *ctx, ...);
void wr32m(i686_ctx_t *ctx, uint32_t v);
void wr64m(i686_ctx_t *ctx, double d);
void push_d(i686_ctx_t *ctx, double v);
uint64_t e80_lo(const uint8_t b[10]);
uint16_t e80_hi(const uint8_t b[10]);
void test_compare(int mode80);
void test_transcendentals(int mode80);
void test_env(int mode80);
void test_declined(int mode80);

#endif /* I686RT_TESTS_UNIT_TEST_L5C_INTERNAL_H */
