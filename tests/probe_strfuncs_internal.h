/*
 * tests/probe_strfuncs_internal.h — Declarations for probe_strfuncs
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef I686RT_TESTS_PROBE_STRFUNCS_INTERNAL_H
#define I686RT_TESTS_PROBE_STRFUNCS_INTERNAL_H

#include <stdint.h>

extern unsigned total;
extern unsigned fails;

long sys_write(int fd, const void *buf, unsigned long len);
__attribute__((noreturn))
void sys_exit(long code);
void put(const char *s, unsigned n);
void puts_(const char *s);
void put_dec(unsigned v);
void phex(uint32_t v);
void phex8(uint8_t v);
void finish(int ok);
uint32_t ld32(const uint8_t *s);
uint64_t ld64(const uint8_t *s);
int v8_eq(const uint8_t *a, const uint8_t *b);
char *ref_strchr(const char *s, int c);
char *ref_strrchr(const char *s, int c);
const void *ref_memchr(const char *s, int c, unsigned long n);
unsigned long ref_strlen(const char *s);
void fill_pattern(uint8_t *p, unsigned n, uint8_t seed);
void blob_case(const char *fn, const char *cs, unsigned off,
                      const char *s, int c);
void strlen_case(const char *cs, unsigned off, const char *s);
void mem_case(const char *cs, unsigned off, const char *s, int c,
                     unsigned long n);
uint32_t p1_head_scan(const char *p, uint32_t c);
void p2q(const uint8_t *src, uint8_t *dst, int psll);
uint32_t p3_zero_scan(const uint8_t *src, uint8_t *dst);
uint32_t p_pmovmskb(const uint8_t *a);
void p9_movq_row(const uint8_t *src, uint8_t *dst64, uint8_t *dst16);
void p9_movq_rr(uint8_t *m);
uint32_t p9_movq_mmx(uint8_t *q);
uint32_t p10_movd(const uint8_t *a);
void p11_movntdq(const uint8_t *src, uint8_t *dst);
void p12_prefetch_sfence(uint8_t *p);
uint32_t p14_por(const uint8_t *a, const uint8_t *b);
void p15_mmx(const uint8_t *a, const uint8_t *b, uint8_t *out);

#endif /* I686RT_TESTS_PROBE_STRFUNCS_INTERNAL_H */
