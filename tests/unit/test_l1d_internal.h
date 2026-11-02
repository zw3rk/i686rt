/*
 * tests/unit/test_l1d_internal.h — Shared declarations for test_l1d
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_UNIT_TEST_L1D_INTERNAL_H
#define I686RT_TESTS_UNIT_TEST_L1D_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "i686rt.h"
#include "interp/flags.h"
#include "interp/interp.h"
#include "x86/decode.h"
#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            failures++;                                                      \
            (void)printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);     \
        }                                                                    \
    } while (0)
#define TEST_MAX_OPS 512U

extern uint8_t window[0x10000U];
extern i686_ctx_t ctx;
extern int failures;
extern i686_interp_fn test_handlers[TEST_MAX_OPS];

void reset_ctx(void);
uint32_t tload32(uint32_t va);
void tstore32(uint32_t va, uint32_t v);
int run(uint16_t op, i686_ctx_t *c, const x86_insn_t *in);
unsigned test_parity(uint8_t v);
void test_set_arith(i686_ctx_t *c, unsigned cf, unsigned pf, unsigned af,
                           unsigned zf, unsigned sf, unsigned of);
uint32_t test_rm_load(const i686_ctx_t *c, uint32_t va, unsigned width);
x86_insn_t mk_insn(uint16_t op);
void set_rr(x86_insn_t *in, uint8_t reg, uint8_t rm);
void set_mem(x86_insn_t *in, uint8_t reg, uint32_t disp);
void test_bt_regs(void);
void test_bt_mem(void);
void test_bsf_bsr(void);
void test_shld_shrd(void);
void test_int_trap(void);
void test_registration(void);

#endif /* I686RT_TESTS_UNIT_TEST_L1D_INTERNAL_H */
