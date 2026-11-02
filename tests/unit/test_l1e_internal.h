/*
 * tests/unit/test_l1e_internal.h — Shared declarations for test_l1e
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_UNIT_TEST_L1E_INTERNAL_H
#define I686RT_TESTS_UNIT_TEST_L1E_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "i686rt.h"
#include "x86/decode.h"
#include "interp/interp.h"
#define CHECK(cond)                                                          \
    do {                                                                     \
        if (cond) {                                                          \
            g_pass++;                                                        \
        } else {                                                             \
            g_fail++;                                                        \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);           \
        }                                                                    \
    } while (0)
#define F_CF(ctx) (((ctx).eflags & I686_EF_CF) != 0U)
#define F_OF(ctx) (((ctx).eflags & I686_EF_OF) != 0U)
#define F_SF(ctx) (((ctx).eflags & I686_EF_SF) != 0U)
#define F_ZF(ctx) (((ctx).eflags & I686_EF_ZF) != 0U)
#define F_PF(ctx) (((ctx).eflags & I686_EF_PF) != 0U)
#define F_AF(ctx) (((ctx).eflags & I686_EF_AF) != 0U)
#define F_IF(ctx) (((ctx).eflags & I686_EF_IF) != 0U)

extern int g_pass;
extern int g_fail;
extern i686_interp_fn g_tab[256];
extern uint8_t g_window[0x8000];
extern i686_ctx_t ctx;
extern unsigned g_twidth;

void reset(void);
int run(const x86_insn_t *i);
x86_insn_t mkinsn(uint16_t op, uint8_t o0, uint8_t o1);
void mkmem(x86_insn_t *i, uint32_t va);
void mem_set(uint32_t va, uint32_t v, unsigned w);
uint32_t mem_get(uint32_t va, unsigned w);
uint32_t t_mask(unsigned w);
int64_t t_sext(uint32_t v, unsigned w);
void arm_add(uint32_t s1, uint32_t s2, unsigned w);
void t_idiv(void);
void t_cwde_cdq(void);
void t_shifts(void);
void t_rotates(void);
void t_rcl_rcr(void);
void t_mem_forms(void);

#endif /* I686RT_TESTS_UNIT_TEST_L1E_INTERNAL_H */
