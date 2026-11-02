/*
 * src/interp/h_x87.c — x87/MMX-state interpreter handlers (Phase 5 L5c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interp/h_x87_internal.h"

/* --- D9 ---------------------------------------------------------------- */

/* D9 /0: FLD m32 | mod=3 C0+i FLD ST(i). */
static int h_fld_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (!ctx->x87_80) {
            double v = x87_get_f64(ctx, insn->modrm_rm);

            x87_push(ctx);
            x87_set_f64(ctx, 0, v);
        } else {
            uint8_t b[10];

            x87_get_ext80(ctx, insn->modrm_rm, b);
            x87_push(ctx);
            x87_set_ext80(ctx, 0, b);
        }
        return done(ctx, insn);
    }
    push_f32(ctx, ld_f32(ctx, x86_ea_compute(ctx, insn)));
    return done(ctx, insn);
}

/* D9 /1 memory is invalid; mod=3 C8+i FXCH ST(i) (contents AND tags
 * move with the values). */
static int h_fxch(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    unsigned p0 = (unsigned)x87_top(ctx);
    unsigned p1 = (p0 + insn->modrm_rm) & 7U;
    unsigned t0;
    unsigned t1;
    uint8_t tmp[16];

    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    memcpy(tmp, &ctx->x87_st[p0][0], 16);
    memcpy(&ctx->x87_st[p0][0], &ctx->x87_st[p1][0], 16);
    memcpy(&ctx->x87_st[p1][0], tmp, 16);
    t0 = (ctx->ftag >> (p0 * 2U)) & 3U;
    t1 = (ctx->ftag >> (p1 * 2U)) & 3U;
    ctx->ftag = (uint16_t)((ctx->ftag & ~(3U << (p0 * 2U))) | (t1 << (p0 * 2U)));
    ctx->ftag = (uint16_t)((ctx->ftag & ~(3U << (p1 * 2U))) | (t0 << (p1 * 2U)));
    return done(ctx, insn);
}

/* D9 /2: FST m32 | mod=3 D0 FNOP (D1-D7 invalid). */
static int h_fst_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (insn->modrm_rm != 0U) {
            return undef_form(ctx, insn);
        }
        return done(ctx, insn); /* FNOP */
    }
    st_f32(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* D9 /3: FSTP m32 (mod=3 invalid). */
static int h_fstp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    st_f32(ctx, x86_ea_compute(ctx, insn));
    x87_pop(ctx);
    return done(ctx, insn);
}

/* D9 /4: FLDENV m14/28 | mod=3 E0 FCHS, E1 FABS, E4 FTST, E5 FXAM. */
static int h_fldenv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        switch (insn->modrm_rm) {
        case 0:
            i686_x87_op_fchs(ctx);
            break;
        case 1:
            i686_x87_op_fabs(ctx);
            break;
        case 4:
            i686_x87_op_ftst(ctx);
            break;
        case 5:
            i686_x87_op_fxam(ctx);
            break;
        default:
            return undef_form(ctx, insn);
        }
        return done(ctx, insn);
    }
    i686_x87_op_fldenv(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* D9 /5: FLDCW m16 | mod=3 E8+i constants (rm 7, D9 EF, is invalid). */
static int h_fldcw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (insn->modrm_rm > 6U) {
            return undef_form(ctx, insn);
        }
        i686_x87_op_fld_const(ctx, insn->modrm_rm);
        return done(ctx, insn);
    }
    ctx->fctrl = (uint16_t)mem_rd(ctx, x86_ea_compute(ctx, insn), 2);
    return done(ctx, insn);
}

/* D9 /6: FNSTENV m14/28 | mod=3 F0 F2XM1, F1 FYL2X, F2 FPTAN, F3 FPATAN,
 * F4 FXTRACT, F5 FPREM1, F6 FDECSTP, F7 FINCSTP. */
static int h_fnstenv(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        switch (insn->modrm_rm) {
        case 0:
            i686_x87_op_f2xm1(ctx);
            break;
        case 1:
            i686_x87_op_fyl2x(ctx, 0);
            break;
        case 2:
            i686_x87_op_fptan(ctx);
            break;
        case 3:
            i686_x87_op_fpatan(ctx);
            break;
        case 4:
            i686_x87_op_fxtract(ctx);
            break;
        case 5:
            i686_x87_op_fprem(ctx, 1);
            break;
        case 6:
            ctx->x87_top = (ctx->x87_top + 7U) & 7U;
            x87_update_fstat(ctx);
            break;
        default:
            ctx->x87_top = (ctx->x87_top + 1U) & 7U;
            x87_update_fstat(ctx);
            break;
        }
        return done(ctx, insn);
    }
    i686_x87_op_fnstenv(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* D9 /7: FNSTCW m16 | mod=3 F8 FPREM, F9 FYL2XP1, FA FSQRT, FB FSINCOS,
 * FC FRNDINT, FD FSCALE, FE FSIN, FF FCOS. */
static int h_fnstcw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        switch (insn->modrm_rm) {
        case 0:
            i686_x87_op_fprem(ctx, 0);
            break;
        case 1:
            i686_x87_op_fyl2x(ctx, 1);
            break;
        case 2:
            i686_x87_op_fsqrt(ctx);
            break;
        case 3:
            i686_x87_op_fsincos(ctx);
            break;
        case 4:
            i686_x87_op_frndint(ctx);
            break;
        case 5:
            i686_x87_op_fscale(ctx);
            break;
        case 6:
            i686_x87_op_fsin(ctx, 0);
            break;
        default:
            i686_x87_op_fsin(ctx, 1);
            break;
        }
        return done(ctx, insn);
    }
    mem_wr(ctx, x86_ea_compute(ctx, insn), 2, ctx->fctrl);
    return done(ctx, insn);
}

/* --- DD ---------------------------------------------------------------- */

/* DD /0: FLD m64 | mod=3 C0+i FFREE ST(i). */
static int h_fld_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        x87_mark_empty(ctx, insn->modrm_rm);
        return done(ctx, insn);
    }
    push_f64(ctx, ld_f64(ctx, x86_ea_compute(ctx, insn)));
    return done(ctx, insn);
}

/* DD /2: FST m64 | mod=3 D0+i FST ST(i) (store ST(0) into ST(i)). */
static int h_fst_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (!ctx->x87_80) {
            x87_set_f64(ctx, insn->modrm_rm, x87_get_f64(ctx, 0));
        } else {
            uint8_t b[10];

            x87_get_ext80(ctx, 0, b);
            x87_set_ext80(ctx, insn->modrm_rm, b);
        }
        return done(ctx, insn);
    }
    st_f64(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* DD /3: FSTP m64 | mod=3 D8+i FSTP ST(i). */
static int h_fstp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (!ctx->x87_80) {
            x87_set_f64(ctx, insn->modrm_rm, x87_get_f64(ctx, 0));
        } else {
            uint8_t b[10];

            x87_get_ext80(ctx, 0, b);
            x87_set_ext80(ctx, insn->modrm_rm, b);
        }
        x87_pop(ctx);
        return done(ctx, insn);
    }
    st_f64(ctx, x86_ea_compute(ctx, insn));
    x87_pop(ctx);
    return done(ctx, insn);
}

/* DD /4 mod=3 E0+i FUCOM ST(i) (memory form = FRSTOR m108). */
static int h_fucom(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int un;

    if (insn->modrm_mod != 3U) {
        i686_x87_op_frstor(ctx, x86_ea_compute(ctx, insn));
        return done(ctx, insn);
    }
    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, insn->modrm_rm);

        un = cc_of_cmp(a, b, ctx);
        exc_ie_cmp(ctx, a, b, un, true);
        return done(ctx, insn);
    }
    {
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
    return done(ctx, insn);
}

/* DD /5 mod=3 E8+i FUCOMP ST(i) (compare then pop). */
static int h_fucomp(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int r;

    if (insn->modrm_mod != 3U) {
        return undef_form(ctx, insn);
    }
    r = h_fucom(ctx, insn);
    if (r == I686_INTERP_CONTINUE) {
        x87_pop(ctx);
    }
    return r;
}

/* DD /6: FNSAVE m108 (no register form). */
static int h_fnsave(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    i686_x87_op_fnsave(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* DD /7: FNSTSW m16 (mod=3 invalid). */
static int h_fnstsw_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    mem_wr(ctx, x86_ea_compute(ctx, insn), 2, ctx->fstat);
    return done(ctx, insn);
}

/* --- 0F map ------------------------------------------------------------ */

static int h_emms(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    ctx->ftag = 0xffffU;
    return done(ctx, insn);
}

static int h_fxsave(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    i686_x87_op_fxsave(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

static int h_fxrstor(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    i686_x87_op_fxrstor(ctx, x86_ea_compute(ctx, insn));
    return done(ctx, insn);
}

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

void i686_interp_x87_init(void)
{
    i686_interp_x87_init_arith();

    /* D9 */
    i686_interp_register(I686_OP_FLD_m32, h_fld_m32);
    i686_interp_register(I686_OP_FXCH, h_fxch);
    i686_interp_register(I686_OP_FST_m32, h_fst_m32);
    i686_interp_register(I686_OP_FSTP_m32, h_fstp_m32);
    i686_interp_register(I686_OP_FLDENV, h_fldenv);
    i686_interp_register(I686_OP_FLDCW, h_fldcw);
    i686_interp_register(I686_OP_FNSTENV, h_fnstenv);
    i686_interp_register(I686_OP_FNSTCW, h_fnstcw);
    /* DD */
    i686_interp_register(I686_OP_FLD_m64, h_fld_m64);
    i686_interp_register(I686_OP_FST_m64, h_fst_m64);
    i686_interp_register(I686_OP_FSTP_m64, h_fstp_m64);
    i686_interp_register(I686_OP_FUCOM, h_fucom);
    i686_interp_register(I686_OP_FUCOMP, h_fucomp);
    i686_interp_register(I686_OP_FNSTSW_m16, h_fnstsw_m16);
    i686_interp_register(I686_OP_FNSAVE, h_fnsave); /* DD /6; /4 mem = FRSTOR */
    /* 0F map */
    i686_interp_register(I686_OP_EMMS, h_emms);
    i686_interp_register(I686_OP_FXSAVE, h_fxsave);
    i686_interp_register(I686_OP_FXRSTOR, h_fxrstor);
}
