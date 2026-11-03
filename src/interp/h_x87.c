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
        /* R7-31: an empty source reads indefinite (masked) or
         * faults (unmasked); the push is validated before TOP
         * moves in either mode. */
        int vs = x87_val_src(ctx, insn->modrm_rm);

        if (vs == I686_EXIT_FAULT) {
            return I686_EXIT_FAULT;
        }
        if (x87_push_checked(ctx) != I686_INTERP_CONTINUE) {
            return I686_EXIT_FAULT;
        }
        if (!ctx->x87_80) {
            double v = (vs == X87_SRC_EMPTY)
                           ? (double)NAN
                           : x87_get_f64(ctx, insn->modrm_rm);

            x87_set_f64(ctx, 0, v);
        } else {
            uint8_t b[10];

            if (vs == X87_SRC_EMPTY) {
                x87_80_nan(b, false, false);
            } else {
                x87_get_ext80(ctx, insn->modrm_rm, b);
            }
            x87_set_ext80(ctx, 0, b);
        }
        return done(ctx, insn);
    }
    /* R7-31: overflow faults with TOP unchanged. */
    if (push_f32(ctx, ld_f32(ctx, x87_ea_checked(ctx, insn, 4u, 0u))) !=
        I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT;
    }
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
    /* R7-31: empty sides read indefinite (masked) or fault. */
    if (x87_src(ctx, 0) || x87_src(ctx, insn->modrm_rm)) {
        return I686_EXIT_FAULT;
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
    /* R7-31: an empty source reads indefinite (masked) or
     * faults (unmasked). */
    if (x87_src(ctx, 0)) {
        return I686_EXIT_FAULT;
    }
    if (st_f32(ctx, x87_ea_checked(ctx, insn, 4u, 1u)) !=
        I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT; /* R7-30: store inhibited */
    }
    return done(ctx, insn);
}

/* D9 /3: FSTP m32 (mod=3 invalid). */
static int h_fstp_m32(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    /* R7-31: an empty source reads indefinite (masked) or
     * faults (unmasked). */
    if (x87_src(ctx, 0)) {
        return I686_EXIT_FAULT;
    }
    if (st_f32(ctx, x87_ea_checked(ctx, insn, 4u, 1u)) !=
        I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT; /* R7-30: store inhibited */
    }
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
        case 4: {
            int fr = i686_x87_op_ftst(ctx);

            if (fr != I686_INTERP_CONTINUE) {
                return fr; /* R7-30: unmasked #MF, EIP stays */
            }
            break;
        }
        case 5:
            i686_x87_op_fxam(ctx);
            break;
        default:
            return undef_form(ctx, insn);
        }
        return done(ctx, insn);
    }
    i686_x87_op_fldenv(ctx, x87_ea_checked(ctx, insn,
                       (insn->pfx_opsize != 0U) ? 14u : 28u, 0u),
                       insn->pfx_opsize != 0U);
    return done(ctx, insn);
}

/* D9 /5: FLDCW m16 | mod=3 E8+i constants (rm 7, D9 EF, is invalid). */
static int h_fldcw(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        if (insn->modrm_rm > 6U) {
            return undef_form(ctx, insn);
        }
        /* R7-31: overflow faults with TOP unchanged. */
        if (i686_x87_op_fld_const(ctx, insn->modrm_rm) !=
            I686_INTERP_CONTINUE) {
            return I686_EXIT_FAULT;
        }
        return done(ctx, insn);
    }
    ctx->fctrl = (uint16_t)mem_rd(ctx, x87_ea_checked(ctx, insn, 2u, 0u), 2);
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
        /* R7-30: a fixed-form op that raised unmasked returns #MF
         * here (its store/push was inhibited inside the op). */
        if ((ctx->fstat & 0x80U) != 0U) {
            extern void i686_fault_sig_record(int sig);

            ctx->exit_arg = 16U; /* #MF trapno */
            i686_fault_sig_record(8); /* SIGFPE */
            return I686_EXIT_FAULT;
        }
        return done(ctx, insn);
    }
    i686_x87_op_fnstenv(ctx, x87_ea_checked(ctx, insn,
                        (insn->pfx_opsize != 0U) ? 14u : 28u, 1u),
                        insn->pfx_opsize != 0U);
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
        /* R7-30: a fixed-form op that raised unmasked returns #MF
         * here (its store/push was inhibited inside the op). */
        if ((ctx->fstat & 0x80U) != 0U) {
            extern void i686_fault_sig_record(int sig);

            ctx->exit_arg = 16U; /* #MF trapno */
            i686_fault_sig_record(8); /* SIGFPE */
            return I686_EXIT_FAULT;
        }
        return done(ctx, insn);
    }
    mem_wr(ctx, x87_ea_checked(ctx, insn, 2u, 1u), 2, ctx->fctrl);
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
    /* R7-31: overflow faults with TOP unchanged. */
    if (push_f64(ctx, ld_f64(ctx, x87_ea_checked(ctx, insn, 8u, 0u))) !=
        I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT;
    }
    return done(ctx, insn);
}

/* DD /2: FST m64 | mod=3 D0+i FST ST(i) (store ST(0) into ST(i)). */
static int h_fst_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        /* R7-31: an empty source reads indefinite (masked) or
         * faults (unmasked). */
        if (x87_src(ctx, 0)) {
                return I686_EXIT_FAULT;
        }
        if (!ctx->x87_80) {
            x87_set_f64(ctx, insn->modrm_rm, x87_get_f64(ctx, 0));
        } else {
            uint8_t b[10];

            x87_get_ext80(ctx, 0, b);
            x87_set_ext80(ctx, insn->modrm_rm, b);
        }
        return done(ctx, insn);
    }
    /* R7-31: an empty source reads indefinite (masked) or
     * faults (unmasked). */
    if (x87_src(ctx, 0)) {
        return I686_EXIT_FAULT;
    }
    if (st_f64(ctx, x87_ea_checked(ctx, insn, 8u, 1u)) !=
        I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT; /* R7-30: store inhibited */
    }
    return done(ctx, insn);
}

/* DD /3: FSTP m64 | mod=3 D8+i FSTP ST(i). */
static int h_fstp_m64(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        /* R7-31: an empty source reads indefinite (masked) or
         * faults (unmasked). */
        if (x87_src(ctx, 0)) {
                return I686_EXIT_FAULT;
        }
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
    /* R7-31: an empty source reads indefinite (masked) or
     * faults (unmasked). */
    if (x87_src(ctx, 0)) {
        return I686_EXIT_FAULT;
    }
    if (st_f64(ctx, x87_ea_checked(ctx, insn, 8u, 1u)) !=
        I686_INTERP_CONTINUE) {
        return I686_EXIT_FAULT; /* R7-30: store inhibited */
    }
    x87_pop(ctx);
    return done(ctx, insn);
}

/* DD /4 mod=3 E0+i FUCOM ST(i) (memory form = FRSTOR m108). */
static int h_fucom(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    int un;

    if (insn->modrm_mod != 3U) {
        i686_x87_op_frstor(ctx, x87_ea_checked(ctx, insn, 108u, 0u),
                           insn->pfx_opsize != 0U);
        return done(ctx, insn);
    }
    /* R7-31: empty sources read indefinite or fault. */
    if (x87_src(ctx, 0) || x87_src(ctx, insn->modrm_rm)) {
        return I686_EXIT_FAULT;
    }
    if (!ctx->x87_80) {
        double a = x87_get_f64(ctx, 0);
        double b = x87_get_f64(ctx, insn->modrm_rm);

        un = cc_of_cmp(a, b, ctx);
        /* R7-30: an unmasked raise faults (no pop in this form). */
        if (exc_ie_cmp(ctx, a, b, un, true) != I686_INTERP_CONTINUE) {
            return I686_EXIT_FAULT;
        }
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
            /* R7-30: an unmasked raise faults (no pop here;
             * h_fucomp pops only on CONTINUE). */
            if (x87_exc_raise(ctx, SW_IE) != I686_INTERP_CONTINUE) {
                return I686_EXIT_FAULT;
            }
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
    i686_x87_op_fnsave(ctx, x87_ea_checked(ctx, insn, 108u, 1u),
                       insn->pfx_opsize != 0U);
    return done(ctx, insn);
}

/* DD /7: FNSTSW m16 (mod=3 invalid). */
static int h_fnstsw_m16(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    mem_wr(ctx, x87_ea_checked(ctx, insn, 2u, 1u), 2, ctx->fstat);
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
    uint32_t va;
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    va = x87_ea_checked(ctx, insn, 512u, 1u);
    /* R7-43: FXSAVE faults #GP(0) on misaligned operands before
     * any state side effect. */
    i686_seg_check_align(ctx, va, 16u);
    i686_x87_op_fxsave(ctx, va);
    return done(ctx, insn);
}

static int h_fxrstor(i686_ctx_t *ctx, const x86_insn_t *insn)
{
    uint32_t va;
    if (insn->modrm_mod == 3U) {
        return undef_form(ctx, insn);
    }
    va = x87_ea_checked(ctx, insn, 512u, 0u);
    /* R7-43: FXRSTOR faults #GP(0) on misaligned operands before
     * any state side effect. */
    i686_seg_check_align(ctx, va, 16u);
    /* R7-37: reserved MXCSR image bits fault #GP(0) before any
     * state commit (DAZ itself loads via the op below). */
    if (((uint32_t)mem_rd(ctx, va + 24U, 4) & ~0xFFFFu) != 0U) {
        extern void i686_fault_sig_record(int sig);

        ctx->exit_arg = 13U; /* #GP */
        i686_fault_sig_record(11); /* SIGSEGV */
        ctx->exit_dest = 0U; /* error code */
        ctx->fault_addr = 0u;
        return I686_EXIT_FAULT;
    }
    i686_x87_op_fxrstor(ctx, va);
    return done(ctx, insn);
}

/* N3: no-wait control/save forms (FNINIT/FNSTSW/FNSTCW/FNSTENV/
 * FNSAVE/FXSAVE/FXRSTOR) never observe a pending unmasked x87
 * exception (SDM: those stores/saves execute despite ES).  Without
 * this a SIGFPE handler running FNCLEX re-faults forever.
 * D9 /6 and /7 share their op id with waiting register forms
 * (F2XM1..FINCSTP, FPREM..FCOS), so only the memory form is no-wait;
 * FRSTOR keeps the waiting check. */
int i686_x87_is_nowait(const x86_insn_t *insn)
{
    switch (insn->op) {
    case I686_OP_FNINIT:      /* FNCLEX + FNINIT (DB E2/E3) */
    case I686_OP_FNSTSW_AX:   /* DF E0 */
    case I686_OP_FNSTSW_m16:  /* DD /7 mem */
    case I686_OP_FNSAVE:      /* DD /6 mem */
    case I686_OP_FXSAVE:      /* 0F AE /0 mem */
    case I686_OP_FXRSTOR:     /* 0F AE /1 mem */
        return 1;
    case I686_OP_FNSTENV:     /* D9 /6 mem only; reg = F2XM1..FINCSTP */
    case I686_OP_FNSTCW:      /* D9 /7 mem only; reg = FPREM..FCOS */
        return insn->modrm_mod != 3U;
    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Registration                                                         */
/* ------------------------------------------------------------------ */

void i686_interp_x87_init(void)
{
    i686_interp_x87_init_arith();

    /* D9 */
    fp_reg(I686_OP_FLD_m32, h_fld_m32);
    fp_reg(I686_OP_FXCH, h_fxch);
    fp_reg(I686_OP_FST_m32, h_fst_m32);
    fp_reg(I686_OP_FSTP_m32, h_fstp_m32);
    fp_reg(I686_OP_FLDENV, h_fldenv);
    fp_reg(I686_OP_FLDCW, h_fldcw);
    fp_reg(I686_OP_FNSTENV, h_fnstenv);
    fp_reg(I686_OP_FNSTCW, h_fnstcw);
    /* DD */
    fp_reg(I686_OP_FLD_m64, h_fld_m64);
    fp_reg(I686_OP_FST_m64, h_fst_m64);
    fp_reg(I686_OP_FSTP_m64, h_fstp_m64);
    fp_reg(I686_OP_FUCOM, h_fucom);
    fp_reg(I686_OP_FUCOMP, h_fucomp);
    fp_reg(I686_OP_FNSTSW_m16, h_fnstsw_m16);
    fp_reg(I686_OP_FNSAVE, h_fnsave); /* DD /6; /4 mem = FRSTOR */
    /* 0F map */
    i686_interp_register(I686_OP_EMMS, h_emms);
    fp_reg(I686_OP_FXSAVE, h_fxsave);
    fp_reg(I686_OP_FXRSTOR, h_fxrstor);
}
