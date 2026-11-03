/*
 * src/interp/h_x87_trans.c -- x87 two-operand transcendentals
 * (FYL2X/FYL2XP1, FPTAN, FPATAN)
 *
 * Split from h_x87_math.c for the 900-line gate; declarations live in
 * interp/h_x87_internal.h ("Cross-TU helpers in h_x87_math.c").
 * Registration lives in h_x87.c.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interp/h_x87_internal.h"

/* ------------------------------------------------------------------ */
/* FYL2X / FPTAN / FPATAN (both modes)                                  */
/* ------------------------------------------------------------------ */

void i686_x87_op_fyl2x(i686_ctx_t *ctx, int p1)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0) || x87_src(ctx, 1)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        x87_get_ext80(ctx, 1, b);
        exc = p1 ? x87_80_fyl2xp1(r, a, b) : x87_80_fyl2x(r, a, b);
        /* R7-30: an unmasked raise inhibits the store/pop below. */
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 1, r);
        x87_pop(ctx);
        return;
    }
    {
        /* I686-R4-7: FYL2X (p1 == 0) computes b * log2(a) valid for
         * a >= 0; FYL2XP1 (p1 != 0) computes b * log2(a + 1) valid for
         * a >= -1, so -1 < a < 0 is legal input there. A zero logarithm
         * argument yields a signed infinity (b * -Inf, opposite sign to
         * b) with #Z, except 0 * -Inf which is #I; an infinite argument
         * yields b * +Inf (b's sign) with no flag, except 0 * +Inf which
         * is #I. A zero logarithm with an infinite multiplier is #I. */
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, 1);
        double r;

        if (isnan(a) || isnan(b)) {
            /* R7-30: an unmasked raise inhibits the
             * store/pop below (dispatch returns #MF). */
            if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                return;
            }
            x87_set_f64(ctx, 1, (double)NAN);
            x87_pop(ctx);
            return;
        }
        if (p1) {
            if (a < -1.0) {
                /* R7-30: an unmasked raise inhibits the
                 * store/pop below (dispatch returns #MF). */
                if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                    return;
                }
                x87_set_f64(ctx, 1, (double)NAN);
                x87_pop(ctx);
                return;
            }
            if (a == -1.0) {
                if (b == 0.0) {
                    /* R7-30: an unmasked raise inhibits the
                     * store/pop below (dispatch returns #MF). */
                    if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                        return;
                    }
                    x87_set_f64(ctx, 1, (double)NAN);
                } else {
                    /* R7-30: an unmasked raise inhibits the
                     * store/pop below (dispatch returns #MF). */
                    if (x87_exc_raise(ctx, SW_ZE) != I686_INTERP_CONTINUE) {
                        return;
                    }
                    x87_set_f64(ctx, 1,
                                signbit(b) ? HUGE_VAL : -HUGE_VAL);
                }
                x87_pop(ctx);
                return;
            }
            if (isinf(a)) {
                if (b == 0.0) {
                    /* R7-30: an unmasked raise inhibits the
                     * store/pop below (dispatch returns #MF). */
                    if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                        return;
                    }
                    x87_set_f64(ctx, 1, (double)NAN);
                } else {
                    x87_set_f64(ctx, 1,
                                signbit(b) ? -HUGE_VAL : HUGE_VAL);
                }
                x87_pop(ctx);
                return;
            }
            {
                double l = log1p(a) * M_LOG2E;
                if (l == 0.0 && isinf(b)) {
                    /* R7-30: an unmasked raise inhibits the
                     * store/pop below (dispatch returns #MF). */
                    if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                        return;
                    }
                    x87_set_f64(ctx, 1, (double)NAN);
                    x87_pop(ctx);
                    return;
                }
                r = d_mul(ctx, b, l);
            }
        } else {
            if (a < 0.0) {
                /* R7-30: an unmasked raise inhibits the
                 * store/pop below (dispatch returns #MF). */
                if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                    return;
                }
                x87_set_f64(ctx, 1, (double)NAN);
                x87_pop(ctx);
                return;
            }
            if (a == 0.0) {
                if (b == 0.0) {
                    /* R7-30: an unmasked raise inhibits the
                     * store/pop below (dispatch returns #MF). */
                    if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                        return;
                    }
                    x87_set_f64(ctx, 1, (double)NAN);
                } else {
                    /* R7-30: an unmasked raise inhibits the
                     * store/pop below (dispatch returns #MF). */
                    if (x87_exc_raise(ctx, SW_ZE) != I686_INTERP_CONTINUE) {
                        return;
                    }
                    x87_set_f64(ctx, 1,
                                signbit(b) ? HUGE_VAL : -HUGE_VAL);
                }
                x87_pop(ctx);
                return;
            }
            if (isinf(a)) {
                if (b == 0.0) {
                    /* R7-30: an unmasked raise inhibits the
                     * store/pop below (dispatch returns #MF). */
                    if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                        return;
                    }
                    x87_set_f64(ctx, 1, (double)NAN);
                } else {
                    x87_set_f64(ctx, 1,
                                signbit(b) ? -HUGE_VAL : HUGE_VAL);
                }
                x87_pop(ctx);
                return;
            }
            {
                double l = log2(a);
                if (l == 0.0 && isinf(b)) {
                    /* R7-30: an unmasked raise inhibits the
                     * store/pop below (dispatch returns #MF). */
                    if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                        return;
                    }
                    x87_set_f64(ctx, 1, (double)NAN);
                    x87_pop(ctx);
                    return;
                }
                r = d_mul(ctx, b, l);
            }
        }
        /* R7-30: d_mul records status internally; an unmasked
         * raise inhibits the store/pop below. */
        if (x87_exc_raise(ctx, 0U) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_f64(ctx, 1, r);
        x87_pop(ctx);
    }
}

void i686_x87_op_fptan(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t t[10];
        uint8_t one[10];
        bool fault;
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a);
        exc = x87_80_fptan(t, one, a, &fault);
        if (fault) {
            set_c2(ctx, 1);
            return;
        }
        /* R7-30: an unmasked raise inhibits the stores/push. */
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return;
        }
        set_c2(ctx, 0); /* R7-38: success clears a stale C2 */
        x87_set_ext80(ctx, 0, t);
        /* R7-31: overflow validated before TOP moves. */
        if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 0, one);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0);

        if (fabs(a) >= 9223372036854775808.0) {
            set_c2(ctx, 1);
            return;
        }
        set_c2(ctx, 0); /* R7-38: success clears a stale C2 */
        x87_set_f64(ctx, 0, tan(a));
        /* R7-31: overflow validated before TOP moves. */
        if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_f64(ctx, 0, 1.0);
    }
}

void i686_x87_op_fpatan(i686_ctx_t *ctx)
{
    /* R7-31: stack sources validated before any read (the
     * fixed-form dispatch returns #MF on an unmasked fault). */
    if (x87_src(ctx, 0) || x87_src(ctx, 1)) {
        return;
    }

    if (ctx->x87_80) {
        uint8_t a[10];
        uint8_t b[10];
        uint8_t r[10];
        unsigned exc;

        x80_set_mode(ctx, 1);
        x87_get_ext80(ctx, 0, a); /* x */
        x87_get_ext80(ctx, 1, b); /* y */
        exc = x87_80_fpatan(r, a, b);
        /* R7-30: an unmasked raise inhibits the store/pop below. */
        if (x87_exc_raise(ctx, exc) != I686_INTERP_CONTINUE) {
            return;
        }
        x87_set_ext80(ctx, 1, r);
        x87_pop(ctx);
        return;
    }
    {
        double a = x87_get_f64(ctx, 0); /* x */
        double b = x87_get_f64(ctx, 1); /* y */

        x87_set_f64(ctx, 1, atan2(b, a));
        x87_pop(ctx);
    }
}
