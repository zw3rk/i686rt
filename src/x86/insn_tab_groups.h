/*
 * Group resolution tables for i686 instruction decoder.
 * Included by src/x86/insn_tab.h.
 */

#ifndef I686RT_X86_INSN_TAB_GROUPS_H
#define I686RT_X86_INSN_TAB_GROUPS_H

/* Group resolution: the decoder looks up (map0f, opcode) here after
 * fetching the modrm byte; reg[reg_field] is the concrete id,
 * opnd[reg_field] the authoritative operand kinds, and bit r of
 * lockable set if that form may take LOCK with a memory destination
 * (group byte descriptors above carry group_op=1 and zero opnd). */
typedef struct {
    uint8_t   map0f;       /* 0 = one-byte map, 1 = 0F two-byte map */
    uint8_t   opcode;      /* group opcode byte                        */
    i686_op_t reg[8];      /* modrm reg field -> concrete opcode id    */
    uint8_t   opnd[8][3];  /* per-reg operand kinds, Intel order       */
    uint8_t   lockable;    /* bit r: reg r form is lockable (mem dest) */
} i686_group_t;

static const i686_group_t i686_group_tab[] = {
    /* G1: 80 Eb,Ib */
    { 0u, 0x80u,
      { I686_OP_ADD_EbIb, I686_OP_OR_EbIb, I686_OP_ADC_EbIb, I686_OP_SBB_EbIb,
        I686_OP_AND_EbIb, I686_OP_SUB_EbIb, I686_OP_XOR_EbIb, I686_OP_CMP_EbIb },
      { { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u },
        { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u } },
      0x7Fu },
    /* G1: 81 Ev,Iz */
    { 0u, 0x81u,
      { I686_OP_ADD_EvIz, I686_OP_OR_EvIz, I686_OP_ADC_EvIz, I686_OP_SBB_EvIz,
        I686_OP_AND_EvIz, I686_OP_SUB_EvIz, I686_OP_XOR_EvIz, I686_OP_CMP_EvIz },
      { { 6u, 10u, 0u }, { 6u, 10u, 0u }, { 6u, 10u, 0u }, { 6u, 10u, 0u },
        { 6u, 10u, 0u }, { 6u, 10u, 0u }, { 6u, 10u, 0u }, { 6u, 10u, 0u } },
      0x7Fu },
    /* G1: 82 alias of 80 (Eb,Ib) */
    { 0u, 0x82u,
      { I686_OP_ADD_EbIb, I686_OP_OR_EbIb, I686_OP_ADC_EbIb, I686_OP_SBB_EbIb,
        I686_OP_AND_EbIb, I686_OP_SUB_EbIb, I686_OP_XOR_EbIb, I686_OP_CMP_EbIb },
      { { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u },
        { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u } },
      0x7Fu },
    /* G1: 83 Ev,Ib sx */
    { 0u, 0x83u,
      { I686_OP_ADD_EvIbSX, I686_OP_OR_EvIbSX, I686_OP_ADC_EvIbSX, I686_OP_SBB_EvIbSX,
        I686_OP_AND_EvIbSX, I686_OP_SUB_EvIbSX, I686_OP_XOR_EvIbSX, I686_OP_CMP_EvIbSX },
      { { 6u, 8u, 0u }, { 6u, 8u, 0u }, { 6u, 8u, 0u }, { 6u, 8u, 0u },
        { 6u, 8u, 0u }, { 6u, 8u, 0u }, { 6u, 8u, 0u }, { 6u, 8u, 0u } },
      0x7Fu },
    /* G2: C0 Eb,Ib */
    { 0u, 0xC0u,
      { I686_OP_ROL_EbIb, I686_OP_ROR_EbIb, I686_OP_RCL_EbIb, I686_OP_RCR_EbIb,
        I686_OP_SHL_EbIb, I686_OP_SHR_EbIb, I686_OP_SHL_EbIb, I686_OP_SAR_EbIb },
      { { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u },
        { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 7u, 0u } },
      0x00u },
    /* G2: C1 Ev,Ib */
    { 0u, 0xC1u,
      { I686_OP_ROL_EvIb, I686_OP_ROR_EvIb, I686_OP_RCL_EvIb, I686_OP_RCR_EvIb,
        I686_OP_SHL_EvIb, I686_OP_SHR_EvIb, I686_OP_SHL_EvIb, I686_OP_SAR_EvIb },
      { { 6u, 7u, 0u }, { 6u, 7u, 0u }, { 6u, 7u, 0u }, { 6u, 7u, 0u },
        { 6u, 7u, 0u }, { 6u, 7u, 0u }, { 6u, 7u, 0u }, { 6u, 7u, 0u } },
      0x00u },
    /* G2: D0 Eb,1 */
    { 0u, 0xD0u,
      { I686_OP_ROL_Eb1, I686_OP_ROR_Eb1, I686_OP_RCL_Eb1, I686_OP_RCR_Eb1,
        I686_OP_SHL_Eb1, I686_OP_SHR_Eb1, I686_OP_SHL_Eb1, I686_OP_SAR_Eb1 },
      { { 4u, 14u, 0u }, { 4u, 14u, 0u }, { 4u, 14u, 0u }, { 4u, 14u, 0u },
        { 4u, 14u, 0u }, { 4u, 14u, 0u }, { 4u, 14u, 0u }, { 4u, 14u, 0u } },
      0x00u },
    /* G2: D1 Ev,1 */
    { 0u, 0xD1u,
      { I686_OP_ROL_Ev1, I686_OP_ROR_Ev1, I686_OP_RCL_Ev1, I686_OP_RCR_Ev1,
        I686_OP_SHL_Ev1, I686_OP_SHR_Ev1, I686_OP_SHL_Ev1, I686_OP_SAR_Ev1 },
      { { 6u, 14u, 0u }, { 6u, 14u, 0u }, { 6u, 14u, 0u }, { 6u, 14u, 0u },
        { 6u, 14u, 0u }, { 6u, 14u, 0u }, { 6u, 14u, 0u }, { 6u, 14u, 0u } },
      0x00u },
    /* G2: D2 Eb,CL */
    { 0u, 0xD2u,
      { I686_OP_ROL_EbCL, I686_OP_ROR_EbCL, I686_OP_RCL_EbCL, I686_OP_RCR_EbCL,
        I686_OP_SHL_EbCL, I686_OP_SHR_EbCL, I686_OP_SHL_EbCL, I686_OP_SAR_EbCL },
      { { 4u, 15u, 0u }, { 4u, 15u, 0u }, { 4u, 15u, 0u }, { 4u, 15u, 0u },
        { 4u, 15u, 0u }, { 4u, 15u, 0u }, { 4u, 15u, 0u }, { 4u, 15u, 0u } },
      0x00u },
    /* G2: D3 Ev,CL */
    { 0u, 0xD3u,
      { I686_OP_ROL_EvCL, I686_OP_ROR_EvCL, I686_OP_RCL_EvCL, I686_OP_RCR_EvCL,
        I686_OP_SHL_EvCL, I686_OP_SHR_EvCL, I686_OP_SHL_EvCL, I686_OP_SAR_EvCL },
      { { 6u, 15u, 0u }, { 6u, 15u, 0u }, { 6u, 15u, 0u }, { 6u, 15u, 0u },
        { 6u, 15u, 0u }, { 6u, 15u, 0u }, { 6u, 15u, 0u }, { 6u, 15u, 0u } },
      0x00u },
    /* G3: F6 (/1 aliases /0; NOT,NEG lockable) */
    { 0u, 0xF6u,
      { I686_OP_TEST_EbIb, I686_OP_TEST_EbIb, I686_OP_NOT_Eb, I686_OP_NEG_Eb,
        I686_OP_MUL_Eb, I686_OP_IMUL_Eb, I686_OP_DIV_Eb, I686_OP_IDIV_Eb },
      { { 4u, 7u, 0u }, { 4u, 7u, 0u }, { 4u, 0u, 0u }, { 4u, 0u, 0u },
        { 4u, 0u, 0u }, { 4u, 0u, 0u }, { 4u, 0u, 0u }, { 4u, 0u, 0u } },
      0x0Cu },
    /* G3: F7 (/1 aliases /0; NOT,NEG lockable) */
    { 0u, 0xF7u,
      { I686_OP_TEST_EvIz, I686_OP_TEST_EvIz, I686_OP_NOT_Ev, I686_OP_NEG_Ev,
        I686_OP_MUL_Ev, I686_OP_IMUL_Ev, I686_OP_DIV_Ev, I686_OP_IDIV_Ev },
      { { 6u, 10u, 0u }, { 6u, 10u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u },
        { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u } },
      0x0Cu },
    /* G4: FE */
    { 0u, 0xFEu,
      { I686_OP_INC_Eb, I686_OP_DEC_Eb, I686_OP_INVALID, I686_OP_INVALID,
        I686_OP_INVALID, I686_OP_INVALID, I686_OP_INVALID, I686_OP_INVALID },
      { { 4u, 0u, 0u }, { 4u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u },
        { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u } },
      0x03u },
    /* G5: FF (far /3,/5 omitted in v1) */
    { 0u, 0xFFu,
      { I686_OP_INC_Ev, I686_OP_DEC_Ev, I686_OP_CALL_Ev, I686_OP_INVALID,
        I686_OP_JMP_Ev, I686_OP_INVALID, I686_OP_PUSH_Ev, I686_OP_INVALID },
      { { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 0u, 0u, 0u },
        { 6u, 0u, 0u }, { 0u, 0u, 0u }, { 6u, 0u, 0u }, { 0u, 0u, 0u } },
      0x03u },
    /* 0F BA: /0-/3 reserved; BT (/4) never locks */
    { 1u, 0xBAu,
      { I686_OP_INVALID, I686_OP_INVALID, I686_OP_INVALID, I686_OP_INVALID,
        I686_OP_BT_EvIb, I686_OP_BTS_EvIb, I686_OP_BTR_EvIb, I686_OP_BTC_EvIb },
      { { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u },
        { 6u, 8u, 0u }, { 6u, 8u, 0u }, { 6u, 8u, 0u }, { 6u, 8u, 0u } },
      0xE0u },
    /* x87 D8: ST(0) op= m32fp32 or ST(i) */
    { 0u, 0xD8u,
      { I686_OP_FADD_m32, I686_OP_FMUL_m32, I686_OP_FCOM_m32, I686_OP_FCOMP_m32,
        I686_OP_FSUB_m32, I686_OP_FSUBR_m32, I686_OP_FDIV_m32, I686_OP_FDIVR_m32 },
      { { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u },
        { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u } },
      0x00u },
    /* x87 D9: loads/stores, env, fixed forms via mod=3 rm */
    { 0u, 0xD9u,
      { I686_OP_FLD_m32, I686_OP_FXCH, I686_OP_FST_m32, I686_OP_FSTP_m32,
        I686_OP_FLDENV, I686_OP_FLDCW, I686_OP_FNSTENV, I686_OP_FNSTCW },
      { { 6u, 0u, 0u }, { 0u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u },
        { 6u, 0u, 0u }, { 5u, 0u, 0u }, { 6u, 0u, 0u }, { 5u, 0u, 0u } },
      0x00u },
    /* x87 DA: mod=3 FCMOVcc ST(i) (R7-27; /0=B,/1=E,/2=BE,/3=U); DA E9
     * FUCOMPP; FIADD-class m32 declined in the handler */
    { 0u, 0xDAu,
      { I686_OP_FCMOV_STi, I686_OP_FCMOV_STi, I686_OP_FCMOV_STi, I686_OP_FCMOV_STi,
        I686_OP_INVALID, I686_OP_FUCOMPP, I686_OP_INVALID, I686_OP_INVALID },
      { { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u },
        { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u } },
      0x00u },
    /* x87 DB: FISTTP /1 (RC7b T4b, SSE3 truncate-store); FNCLEX/FNINIT via /4 mod=3; FUCOMI rides FLD_m80 mod=3 */
    { 0u, 0xDBu,
      { I686_OP_FILD_m32, I686_OP_FISTTP_m32, I686_OP_FIST_m32, I686_OP_FISTP_m32,
        I686_OP_FNINIT, I686_OP_FLD_m80, I686_OP_FCOMI, I686_OP_FSTP_m80 },
      { { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u },
        { 0u, 0u, 0u }, { 6u, 0u, 0u }, { 0u, 0u, 0u }, { 6u, 0u, 0u } },
      0x00u },
    /* x87 DC: ST(0) op= m64fp64 or ST(i),ST(0) reversed */
    { 0u, 0xDCu,
      { I686_OP_FADD_m64, I686_OP_FMUL_m64, I686_OP_FCOM_m64, I686_OP_FCOMP_m64,
        I686_OP_FSUB_m64, I686_OP_FSUBR_m64, I686_OP_FDIV_m64, I686_OP_FDIVR_m64 },
      { { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u },
        { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u } },
      0x00u },
    /* x87 DD: FISTTP /1 and FNSAVE /6 m108 (RC7b T4b); FRSTOR rides FUCOM /4 memory form; FFREE rides FLD_m64 mod=3; FUCOM* mod=3 only */
    { 0u, 0xDDu,
      { I686_OP_FLD_m64, I686_OP_FISTTP_m64, I686_OP_FST_m64, I686_OP_FSTP_m64,
        I686_OP_FUCOM, I686_OP_FUCOMP, I686_OP_FNSAVE, I686_OP_FNSTSW_m16 },
      { { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u },
        { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 6u, 0u, 0u }, { 5u, 0u, 0u } },
      0x00u },
    /* x87 DE: ST(i),ST(0) then pop; memory FIADD-class declined */
    { 0u, 0xDEu,
      { I686_OP_FADDP, I686_OP_FMULP, I686_OP_INVALID, I686_OP_INVALID,
        I686_OP_FSUBRP, I686_OP_FSUBP, I686_OP_FDIVRP, I686_OP_FDIVP },
      { { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u },
        { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u } },
      0x00u },
    /* x87 DF: FISTTP /1 (RC7b T4b), FBLD/FBSTP declined; FUCOMIP rides FILD_m64 mod=3 */
    { 0u, 0xDFu,
      { I686_OP_FILD_m16, I686_OP_FISTTP_m16, I686_OP_FIST_m16, I686_OP_FISTP_m16,
        I686_OP_FNSTSW_AX, I686_OP_FILD_m64, I686_OP_FCOMIP, I686_OP_FISTP_m64 },
      { { 5u, 0u, 0u }, { 5u, 0u, 0u }, { 5u, 0u, 0u }, { 5u, 0u, 0u },
        { 0u, 0u, 0u }, { 6u, 0u, 0u }, { 0u, 0u, 0u }, { 6u, 0u, 0u } },
      0x00u },
    /* 0F AE: FXSAVE /0 and FXRSTOR /1 m512; LDMXCSR /2 and STMXCSR /3 m32 (Phase 5 shared spec); /4-/6 (XSAVE family, LFENCE/MFENCE) declined; SFENCE /7 (RC7b T1) */
    { 1u, 0xAEu,
      { I686_OP_FXSAVE, I686_OP_FXRSTOR, I686_OP_LDMXCSR, I686_OP_STMXCSR,
        I686_OP_INVALID, I686_OP_INVALID, I686_OP_INVALID, I686_OP_SFENCE },
      { { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u }, { 6u, 0u, 0u },
        { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u }, { 0u, 0u, 0u } },
      0x00u },
};

#define I686_GROUP_TAB_LEN \
    ((unsigned)(sizeof(i686_group_tab) / sizeof(i686_group_tab[0])))

_Static_assert(sizeof(i686_group_tab) / sizeof(i686_group_tab[0]) == 24u,
               "i686_group_tab row count changed");

#endif /* I686RT_X86_INSN_TAB_GROUPS_H */
