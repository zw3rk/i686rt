/*
 * tests/unit/test_l5b_internal.h — Shared declarations for test_l5b
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_UNIT_TEST_L5B_INTERNAL_H
#define I686RT_TESTS_UNIT_TEST_L5B_INTERNAL_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "i686rt.h"
#include "interp/interp.h"
#include "interp/sse.h"
#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)
#define T_IE 0x01u
#define T_DE 0x02u
#define T_ZE 0x04u
#define T_OE 0x08u
#define T_UE 0x10u
#define T_PE 0x20u
#define T_DAZ 0x40u
#define T_FTZ 0x8000u
#define DATA_VA 0x2000u

extern int g_pass;
extern int g_fail;
extern i686_interp_fn t_reg[I686_OP_COUNT];
extern uint8_t g_window[0x10000];
extern i686_ctx_t ctx;

void reset(void);
void w32va(uint32_t va, uint32_t v);
void w64va(uint32_t va, uint64_t v);
uint32_t r32va(uint32_t va);
uint64_t r64va(uint32_t va);
x86_insn_t mkrr(uint16_t op, unsigned reg, unsigned rm);
x86_insn_t mkmem(uint16_t op, unsigned reg);
int run(const x86_insn_t *insn);
uint32_t bitsf(float f);
uint32_t xl32(unsigned reg, unsigned lane);
void xs32(unsigned reg, unsigned lane, uint32_t b);
uint64_t xl64(unsigned reg, unsigned lane);
void xs64(unsigned reg, unsigned lane, uint64_t b);
uint64_t mm(unsigned reg);
void mmset(unsigned reg, uint64_t v);
void t_cvt(void);
void t_intops(void);
void t_mem_mxcsr(void);

#endif /* I686RT_TESTS_UNIT_TEST_L5B_INTERNAL_H */
