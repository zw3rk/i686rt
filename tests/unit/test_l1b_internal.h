/*
 * tests/unit/test_l1b_internal.h — Shared declarations for test_l1b
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_UNIT_TEST_L1B_INTERNAL_H
#define I686RT_TESTS_UNIT_TEST_L1B_INTERNAL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "interp/flags.h"
#include "interp/interp.h"
#define CHECK(cond)                                                        \
    do {                                                                   \
        g_checks++;                                                        \
        if (!(cond)) {                                                     \
            g_fail++;                                                      \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);\
        }                                                                  \
    } while (0)
#define REGISTRY_MAX 128
#define WIN_SIZE 0x10000U /* 64 KiB guest window at guest addresses 0.. */

extern int g_fail;
extern int g_checks;
extern i686_interp_fn g_fns[REGISTRY_MAX];
extern uint16_t g_ops[REGISTRY_MAX];
extern int g_nreg;
extern unsigned g_lazy_width;
extern uint8_t *g_win;

void run(i686_ctx_t *ctx, uint16_t op, const x86_insn_t *insn);
uint32_t mem_read(const i686_ctx_t *ctx, uint32_t va, unsigned width);
void mem_write(i686_ctx_t *ctx, uint32_t va, unsigned width, uint32_t val);
uint32_t wmask(unsigned width);
uint32_t wmsb(unsigned width);
void lazy_set(i686_ctx_t *ctx, uint32_t op, uint32_t res, uint32_t s1,
                     uint32_t s2, uint32_t cf, unsigned width);
uint32_t parity_bit(uint8_t v);
i686_ctx_t *new_ctx(void);
x86_insn_t mk(uint16_t op);
x86_insn_t mk_rr(uint16_t op, uint8_t reg, uint8_t rm);
x86_insn_t mk_mem(uint16_t op, uint8_t reg, uint32_t va);
void t_sub_cmp(void);
void t_incdec_neg_not(void);
void t_xchg(void);
void t_cmpxchg_xadd(void);
void t_pushf_popf(void);
void t_flag_bits_sahf_lahf(void);

#endif /* I686RT_TESTS_UNIT_TEST_L1B_INTERNAL_H */
