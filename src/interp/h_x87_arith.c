/*
 * src/interp/h_x87_arith.c — x87 D8/DC/DE/DA/DB/DF handlers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interp/h_x87_internal.h"

static int do_fcomi(i686_ctx_t *ctx, const x86_insn_t *insn, int pop);

/* ------------------------------------------------------------------ */
/* D8 / DC / DE arithmetic + compare                                   */
/* ------------------------------------------------------------------ */

static int arith_d8dc(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned kind,
                      unsigned mbytes)
{
    unsigned reg = insn->modrm_mod == 3U;
    unsigned k = kind;
    unsigned dst = 0;

    if (reg && mbytes == 8) {
        dst = insn->modrm_rm;
        if (kind == K_SUB) {
            k = K_SUBR;
        } else if (kind == K_SUBR) {
            k = K_SUB;
        } else if (kind == K_DIV) {
            k = K_DIVR;
        } else if (kind == K_DIVR) {
            k = K_DIV;
        }
    }
    if (!ctx->x87_80) {
        double a;
        double b;
        double r;

        if (reg) {
            if (mbytes == 4) {
                a = x87_get_f64(ctx, 0);
                b = x87_get_f64(ctx, insn->modrm_rm);
            } else {
                a = x87_get_f64(ctx, insn->modrm_rm);
                b = x87_get_f64(ctx, 0);
            }
        } else {
            uint32_t va = x86_ea_compute(ctx, insn);
            a = x87_get_f64(ctx, 0);
            b = (mbytes == 4) ? (double)ld_f32(ctx, va) : ld_f64(ctx, va);
        }
        r = dcalc(ctx, k, a, b);
        x87_set_f64(ctx, dst, r);
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        uint8_t r[10];
        unsigned exc;

        if (reg) {
            if (mbytes == 4) {
                x87_get_ext80(ctx, 0, sa);
                x87_get_ext80(ctx, insn->modrm_rm, sb);
            } else {
                x87_get_ext80(ctx, insn->modrm_rm, sa);
                x87_get_ext80(ctx, 0, sb);
            }
        } else {
            uint32_t va = x86_ea_compute(ctx, insn);
            x87_get_ext80(ctx, 0, sa);
            if (mbytes == 4) {
                x87_80_from_f32(sb, ld_f32(ctx, va));
            } else {
                x87_80_from_f64(sb, ld_f64(ctx, va));
            }
        }
        exc = x80calc(ctx, k, r, sa, sb);
        x87_set_ext80(ctx, dst, r);
        x87_set_exc(ctx, exc);
    }
    return done(ctx, insn);
}

static int arith_de(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned kind)
{
    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn); /* FIADD/FIMUL/FISUB/FIDIV declined */
    }
    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, insn->modrm_rm);
        double b = x87_get_f64(ctx, 0);
        double r = dcalc(ctx, kind, a, b);

        x87_set_f64(ctx, insn->modrm_rm, r);
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        uint8_t r[10];
        unsigned exc;

        x87_get_ext80(ctx, insn->modrm_rm, sa);
        x87_get_ext80(ctx, 0, sb);
        exc = x80calc(ctx, kind, r, sa, sb);
        x87_set_ext80(ctx, insn->modrm_rm, r);
        x87_set_exc(ctx, exc);
    }
    x87_pop(ctx);
    return done(ctx, insn);
}

static int do_fcom(i686_ctx_t *ctx, const x86_insn_t *insn, unsigned mbytes,
                   int pop)
{
    int un;

    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b;

        if (insn->modrm_mod == 3U) {
            b = x87_get_f64(ctx, insn->modrm_rm);
        } else {
            uint32_t va = x86_ea_compute(ctx, insn);
            b = (mbytes == 4) ? (double)ld_f32(ctx, va) : ld_f64(ctx, va);
        }
        un = cc_of_cmp(a, b, ctx);
        exc_ie_cmp(ctx, a, b, un, false);
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        if (insn->modrm_mod == 3U) {
            x87_get_ext80(ctx, insn->modrm_rm, sb);
        } else {
            uint32_t va = x86_ea_compute(ctx, insn);
            if (mbytes == 4) {
                x87_80_from_f32(sb, ld_f32(ctx, va));
            } else {
                x87_80_from_f64(sb, ld_f64(ctx, va));
            }
        }
        x87_80_fcom(sa, sb, false, &c3, &c2, &c0);
        set_cc(ctx, c0, 0, c2, c3);
        if (c0 && c2 && c3) {
            x87_set_exc(ctx, SW_IE);
        }
    }
    if (pop) {
        x87_pop(ctx);
    }
    return done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* D8 / DC / DE slot handlers                                          */
/* ------------------------------------------------------------------ */

static int h_fadd_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_ADD, 4);
}

static int h_fmul_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_MUL, 4);
}

static int h_fcom_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_fcom(ctx, insn, 4, 0);
}

static int h_fcomp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_fcom(ctx, insn, 4, 1);
}

static int h_fsub_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_SUB, 4);
}

static int h_fsubr_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_SUBR, 4);
}

static int h_fdiv_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_DIV, 4);
}

static int h_fdivr_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_DIVR, 4);
}

static int h_fadd_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_ADD, 8);
}

static int h_fmul_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_MUL, 8);
}

static int h_fcom_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_fcom(ctx, insn, 8, 0);
}

static int h_fcomp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_fcom(ctx, insn, 8, 1);
}

static int h_fsub_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_SUB, 8);
}

static int h_fsubr_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_SUBR, 8);
}

static int h_fdiv_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_DIV, 8);
}

static int h_fdivr_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_d8dc(ctx, insn, K_DIVR, 8);
}

static int h_faddp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_ADD);
}

static int h_fmulp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_MUL);
}

static int h_fsubrp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_SUBR);
}

static int h_fsubp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_SUB);
}

static int h_fdivrp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_DIVR);
}

static int h_fdivp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return arith_de(ctx, insn, K_DIV);
}

/* ------------------------------------------------------------------ */
/* DA / DB / DF slot handlers                                          */
/* ------------------------------------------------------------------ */

static int do_da_fcom(i686_ctx_t *ctx, const x86_insn_t *insn, int pop)
{
    int un;

    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, insn->modrm_rm);

        un = cc_of_cmp(a, b, ctx);
        exc_ie_cmp(ctx, a, b, un, true);
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        x87_get_ext80(ctx, insn->modrm_rm, sb);
        x87_80_fcom(sa, sb, true, &c3, &c2, &c0);
        set_cc(ctx, c0, 0, c2, c3);
        if ((c0 && c2 && c3) &&
            (x87_80_is_snan(sa) || x87_80_is_snan(sb))) {
            x87_set_exc(ctx, SW_IE);
        }
    }
    if (pop != 0) {
        x87_pop(ctx);
    }
    return done(ctx, insn);
}

static int h_fcom_sti(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_da_fcom(ctx, insn, 0);
}

static int h_fucom_sti(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_da_fcom(ctx, insn, 0);
}

static int h_fcomp_sti(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    return do_da_fcom(ctx, insn, 1);
}

static int h_fucompp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int r;

    if (insn->modrm_mod != 3U || insn->modrm_rm != 1U) {
        return undef_form(ctx, insn);
    }
    r = do_da_fcom(ctx, insn, 0);
    if (r == I686_INTERP_CONTINUE) {
        x87_pop(ctx);
        x87_pop(ctx);
    }
    return r;
}

static int h_fild_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v;

    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    v = (uint32_t)mem_rd(ctx, x86_ea_compute(ctx, insn), 4);
    push_int(ctx, (int64_t)(int32_t)v);
    return done(ctx, insn);
}

static int h_fist_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int(ctx, x86_ea_compute(ctx, insn), 4);
    return done(ctx, insn);
}

static int h_fistp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int r = h_fist_m32(ctx, insn);

    if (r == I686_INTERP_CONTINUE) {
        x87_pop(ctx);
    }
    return r;
}

static int h_fisttp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int_trunc(ctx, x86_ea_compute(ctx, insn), 4);
    x87_pop(ctx);
    return done(ctx, insn);
}

static int h_fisttp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int_trunc(ctx, x86_ea_compute(ctx, insn), 8);
    x87_pop(ctx);
    return done(ctx, insn);
}

static int h_fisttp_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int_trunc(ctx, x86_ea_compute(ctx, insn), 2);
    x87_pop(ctx);
    return done(ctx, insn);
}

static int h_fninit(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    if (insn->modrm_rm == 3U) {
        ctx->fctrl = 0x037fU;
        ctx->fstat = 0;
        ctx->ftag = 0xffffU;
        ctx->x87_top = 0;
        ctx->fop = 0;
        ctx->fpu_ip = 0;
        ctx->fpu_dp = 0;
        return done(ctx, insn);
    }
    if (insn->modrm_rm == 2U) {
        ctx->fstat = (uint16_t)(ctx->fstat & ~(0xffU | 0x8000U));
        return done(ctx, insn);
    }
    return undef_form(ctx, insn);
}

static int h_fld_m80(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return do_fcomi(ctx, insn, 0);
    }
    {
        uint32_t va = x86_ea_compute(ctx, insn);
        uint8_t b[10];

        for (unsigned i = 0; i < 10; i++) {
            b[i] = (uint8_t)mem_rd(ctx, va + i, 1);
        }
        x87_push(ctx);
        x87_set_ext80(ctx, 0, b);
    }
    return done(ctx, insn);
}

static int h_fcomi(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    return do_fcomi(ctx, insn, 0);
}

static int h_fstp_m80(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_m80(ctx, x86_ea_compute(ctx, insn));
    x87_pop(ctx);
    return done(ctx, insn);
}

static int h_fild_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t v;

    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    v = (uint32_t)mem_rd(ctx, x86_ea_compute(ctx, insn), 2);
    push_int(ctx, (int64_t)(int16_t)v);
    return done(ctx, insn);
}

static int h_fist_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int(ctx, x86_ea_compute(ctx, insn), 2);
    return done(ctx, insn);
}

static int h_fistp_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int r = h_fist_m16(ctx, insn);

    if (r == I686_INTERP_CONTINUE) {
        x87_pop(ctx);
    }
    return r;
}

static int h_fnstsw_ax(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U || insn->modrm_rm != 0U) {
        return undef_form(ctx, insn);
    }
    x86_reg_write(ctx, I686_REG_EAX, 16, ctx->fstat);
    return done(ctx, insn);
}

static int h_fild_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return do_fcomi(ctx, insn, 1);
    }
    {
        uint64_t v = mem_rd(ctx, x86_ea_compute(ctx, insn), 8);
        int64_t s;

        memcpy(&s, &v, 8);
        push_int(ctx, s);
    }
    return done(ctx, insn);
}

static int h_fcomip(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    return do_fcomi(ctx, insn, 1);
}

static int h_fistp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_int(ctx, x86_ea_compute(ctx, insn), 8);
    x87_pop(ctx);
    return done(ctx, insn);
}

static int do_fcomi(i686_ctx_t *ctx, const x86_insn_t *insn, int pop)
{
    unsigned un;
    unsigned lt;
    unsigned eq;

    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, insn->modrm_rm);

        un = (isnan(a) || isnan(b)) ? 1U : 0U;
        lt = !un && a < b ? 1U : 0U;
        eq = !un && a == b ? 1U : 0U;
    } else {
        uint8_t sa[10];
        uint8_t sb[10];
        unsigned c0 = 0;
        unsigned c2 = 0;
        unsigned c3 = 0;

        x87_get_ext80(ctx, 0, sa);
        x87_get_ext80(ctx, insn->modrm_rm, sb);
        x87_80_fcom(sa, sb, true, &c3, &c2, &c0);
        un = (c0 && c2 && c3) ? 1U : 0U;
        lt = !un && c0 ? 1U : 0U;
        eq = !un && c3 ? 1U : 0U;
    }
    if (un) {
        x87_set_exc(ctx, SW_IE);
    }
    i686_flags_materialize(ctx);
    ctx->eflags &= ~(uint32_t)(I686_EF_ZF | I686_EF_PF | I686_EF_CF |
                               I686_EF_OF | I686_EF_SF | I686_EF_AF);
    if (un) {
        ctx->eflags |= I686_EF_ZF | I686_EF_PF | I686_EF_CF;
    } else if (lt) {
        ctx->eflags |= I686_EF_CF;
    } else if (eq) {
        ctx->eflags |= I686_EF_ZF;
    }
    if (pop) {
        x87_pop(ctx);
    }
    return done(ctx, insn);
}

void i686_interp_x87_init_arith(void)
{
    /* D8 (m32 / ST(i)) */
    i686_interp_register(I686_OP_FADD_m32, h_fadd_m32);
    i686_interp_register(I686_OP_FMUL_m32, h_fmul_m32);
    i686_interp_register(I686_OP_FCOM_m32, h_fcom_m32);
    i686_interp_register(I686_OP_FCOMP_m32, h_fcomp_m32);
    i686_interp_register(I686_OP_FSUB_m32, h_fsub_m32);
    i686_interp_register(I686_OP_FSUBR_m32, h_fsubr_m32);
    i686_interp_register(I686_OP_FDIV_m32, h_fdiv_m32);
    i686_interp_register(I686_OP_FDIVR_m32, h_fdivr_m32);
    /* DC (m64 / ST(i),ST(0)) */
    i686_interp_register(I686_OP_FADD_m64, h_fadd_m64);
    i686_interp_register(I686_OP_FMUL_m64, h_fmul_m64);
    i686_interp_register(I686_OP_FCOM_m64, h_fcom_m64);
    i686_interp_register(I686_OP_FCOMP_m64, h_fcomp_m64);
    i686_interp_register(I686_OP_FSUB_m64, h_fsub_m64);
    i686_interp_register(I686_OP_FSUBR_m64, h_fsubr_m64);
    i686_interp_register(I686_OP_FDIV_m64, h_fdiv_m64);
    i686_interp_register(I686_OP_FDIVR_m64, h_fdivr_m64);
    /* DE (pop) */
    i686_interp_register(I686_OP_FADDP, h_faddp);
    i686_interp_register(I686_OP_FMULP, h_fmulp);
    i686_interp_register(I686_OP_FSUBRP, h_fsubrp);
    i686_interp_register(I686_OP_FSUBP, h_fsubp);
    i686_interp_register(I686_OP_FDIVRP, h_fdivrp);
    i686_interp_register(I686_OP_FDIVP, h_fdivp);
    /* DB */
    i686_interp_register(I686_OP_FILD_m32, h_fild_m32);
    i686_interp_register(I686_OP_FIST_m32, h_fist_m32);
    i686_interp_register(I686_OP_FISTP_m32, h_fistp_m32);
    i686_interp_register(I686_OP_FNINIT, h_fninit);
    i686_interp_register(I686_OP_FLD_m80, h_fld_m80);
    i686_interp_register(I686_OP_FCOMI, h_fcomi);
    i686_interp_register(I686_OP_FSTP_m80, h_fstp_m80);
    /* DA */
    i686_interp_register(I686_OP_FUCOMPP, h_fucompp);
    i686_interp_register(I686_OP_FCOM_STi, h_fcom_sti);
    i686_interp_register(I686_OP_FUCOM_STi, h_fucom_sti);
    i686_interp_register(I686_OP_FCOMP_STi, h_fcomp_sti);
    /* DF */
    i686_interp_register(I686_OP_FILD_m16, h_fild_m16);
    i686_interp_register(I686_OP_FIST_m16, h_fist_m16);
    i686_interp_register(I686_OP_FISTP_m16, h_fistp_m16);
    i686_interp_register(I686_OP_FNSTSW_AX, h_fnstsw_ax);
    i686_interp_register(I686_OP_FILD_m64, h_fild_m64);
    i686_interp_register(I686_OP_FCOMIP, h_fcomip);
    i686_interp_register(I686_OP_FISTP_m64, h_fistp_m64);
    /* FISTTP (SSE3, RC7b T4b) */
    i686_interp_register(I686_OP_FISTTP_m32, h_fisttp_m32);
    i686_interp_register(I686_OP_FISTTP_m64, h_fisttp_m64);
    i686_interp_register(I686_OP_FISTTP_m16, h_fisttp_m16);
}
