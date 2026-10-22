#!/usr/bin/env python3
"""
test_insn_tab.py -- verify the generated src/x86/insn_tab.h (Phase 1, lane L1a).

Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
SPDX-License-Identifier: Apache-2.0

Checks (stdlib only, no imports of the generator):
  1. every frozen-contract identifier exists EXACTLY once in the i686_op_t
     enum, with no unexpected extra ids and I686_OP_INVALID = 0;
  2. ~60 spot-asserted descriptor rows in both 256-entry tables, including
     every entry named on the lane card (0x01, 0x8F, 0xC2, F6 reg2, 0F B6,
     0F A2, 0F 34, 0F 0B, ...);
  3. no duplicate opcode ids anywhere in the enum, and the group table
     resolves reg fields per the contract (G1/G2/G3/G4/G5 + 0F BA);
  4. the header's numeric operand-kind legend matches src/x86/decode.h.

Prints "L1A OK" on success; exits 1 with a failure list otherwise.
"""

import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
HEADER = REPO / "src" / "x86" / "insn_tab.h"
DECODE_H = REPO / "src" / "x86" / "decode.h"
GUARD = "I686RT_X86_INSN_TAB_H"

# ---------------------------------------------------------------------------
# Expected identifier list, hand-expanded from docs/lanes/phase-1.md (the
# frozen contract).  LEA_GvM is the single documented L1a addition (8D).
# ---------------------------------------------------------------------------

_ALU = ("ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP")
_SHF = ("ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "SAR")

EXPECTED_IDS = []
for _f in _ALU:
    EXPECTED_IDS += [
        _f + "_EbGb", _f + "_EvGv", _f + "_GbEb", _f + "_GvEv",
        _f + "_ALIb", _f + "_eAXIz", _f + "_EbIb", _f + "_EvIz",
        _f + "_EvIbSX",
    ]
EXPECTED_IDS += [
    "TEST_EbGb", "TEST_EvGv", "TEST_ALIb", "TEST_eAXIz",
    "TEST_EbIb", "TEST_EvIz",
]
for _f in _SHF:
    EXPECTED_IDS += [
        _f + "_Eb1", _f + "_Ev1", _f + "_EbCL", _f + "_EvCL",
        _f + "_EbIb", _f + "_EvIb",
    ]
for _g in ("NOT", "NEG", "MUL", "IMUL", "DIV", "IDIV"):
    EXPECTED_IDS += [_g + "_Eb", _g + "_Ev"]
EXPECTED_IDS += [
    "INC_Eb", "DEC_Eb", "INC_Ev", "DEC_Ev", "CALL_Ev", "JMP_Ev", "PUSH_Ev",
]
EXPECTED_IDS += [
    "MOV_EbGb", "MOV_EvGv", "MOV_GbEb", "MOV_GvEv", "MOV_ALOb", "MOV_eAXOv",
    "MOV_ObAL", "MOV_OveAX", "MOV_GbIb", "MOV_GvIv", "MOV_EbIb", "MOV_EvIz",
    "MOV_EwSw", "MOV_SwEw",
]
EXPECTED_IDS += [
    "PUSH_Gv", "POP_Gv", "PUSH_Iz", "PUSH_Ib", "PUSHA", "POPA", "PUSHF",
    "POPF", "ENTER", "LEAVE", "PUSH_ES", "POP_ES", "PUSH_DS", "POP_DS",
    "PUSH_FS", "POP_FS", "PUSH_GS", "POP_GS", "PUSH_Ev", "POP_Ev",
]
EXPECTED_IDS += ["XCHG_EbGb", "XCHG_EvGv", "XCHG_eAXGv"]
EXPECTED_IDS += [
    "NOP", "CMC", "CLC", "STC", "CLI", "STI", "CLD", "STD", "SAHF", "LAHF",
    "CBW", "CWDE", "CDQ", "XLAT", "HLT", "WAIT", "UD2", "CPUID", "SYSENTER",
    "CMPXCHG_EbGb", "CMPXCHG_EvGv", "XADD_EbGb", "XADD_EvGv", "BSWAP_Gv",
    "MOVZX_GvEb", "MOVZX_GvEw", "MOVSX_GvEb", "MOVSX_GvEw",
    "LEA_GvM",
]
EXPECTED_IDS += [
    "JMP_Jb", "JMP_Jz", "JMP_Ev", "CALL_Jz", "CALL_Ev", "RET", "RET_Iw",
    "JCC_Jb", "JCC_Jz", "SETcc_Eb", "CMOVcc_Gv",
    "LOOPNZ_Jb", "LOOPZ_Jb", "LOOP_Jb", "JCXZ_Jb",
]
EXPECTED_IDS += [
    "BT_EvGv", "BTS_EvGv", "BTR_EvGv", "BTC_EvGv", "BSF_GvEv", "BSR_GvEv",
    "BT_EvIb", "BTS_EvIb", "BTR_EvIb", "BTC_EvIb", "SHLD_EvIb", "SHLD_EvCL",
    "SHRD_EvIb", "SHRD_EvCL", "IMUL_GvEv", "RDTSC",
    # S1 ratified amendment: three-operand IMUL
    "IMUL_GvEvIz", "IMUL_GvEvIb",
]
EXPECTED_IDS += [
    "MOVSb", "MOVSw", "CMPSb", "CMPSw", "STOSb", "STOSw",
    "LODSb", "LODSw", "SCASb", "SCASw",
]
EXPECTED_IDS += ["INT_Ib", "INT3", "INTO", "IRET"]

# Phase 5 shared spec (docs/lanes/phase-5.md): one id per 0F opcode byte;
# 66/F2/F3 select the family member inside the handler.
EXPECTED_IDS += [
    "MOVUPS", "MOVLPS", "MOVHPS", "MOVAPS", "MOVQ_xmm",
    "CVTPI2PS", "CVTTPS2PI", "CVTPS2PD", "CVTDQ2PS",
    "UCOMISS", "COMISS", "MOVMSKPS",
    "ANDPS", "ANDNPS", "ORPS", "XORPS",
    "ADDPS", "MULPS", "SUBPS", "DIVPS",
    "PUNPCKLBW", "PUNPCKLWD", "PUNPCKLDQ",
    "PUNPCKHBW", "PUNPCKHWD", "PUNPCKHDQ",
    "PUNPCKLQDQ", "PUNPCKHQDQ",
    "PSHUFW", "CMPPS",
    "PADDQ", "PMULLW", "PAND", "PANDN", "POR", "PXOR",
    "PMULUDQ", "PSUBD", "PSUBQ", "PADDD",
    "LDMXCSR", "STMXCSR", "EMMS",
]

# Phase 5 L5c x87/MMX set (docs/lanes/phase-5.md + hardware-verified
# second bytes): D8-DF group ids plus 0F 77 EMMS and 0F AE /0-/1.
EXPECTED_IDS += [
    # D8 / DC: m32 + m64 arithmetic/compare forms
    "FADD_m32", "FMUL_m32", "FCOM_m32", "FCOMP_m32",
    "FSUB_m32", "FSUBR_m32", "FDIV_m32", "FDIVR_m32",
    "FADD_m64", "FMUL_m64", "FCOM_m64", "FCOMP_m64",
    "FSUB_m64", "FSUBR_m64", "FDIV_m64", "FDIVR_m64",
    # DE pop forms
    "FADDP", "FMULP", "FSUBRP", "FSUBP", "FDIVRP", "FDIVP",
    # D9
    "FLD_m32", "FXCH", "FST_m32", "FSTP_m32",
    "FLDENV", "FLDCW", "FNSTENV", "FNSTCW",
    # DD
    "FLD_m64", "FST_m64", "FSTP_m64", "FUCOM", "FUCOMP", "FNSTSW_m16",
    # DB
    "FILD_m32", "FIST_m32", "FISTP_m32", "FNINIT", "FLD_m80", "FCOMI",
    "FSTP_m80",
    # DA
    "FUCOMPP",
    # DF
    "FILD_m16", "FIST_m16", "FISTP_m16", "FNSTSW_AX", "FILD_m64",
    "FCOMIP", "FISTP_m64",
    # 0F map
    "EMMS", "FXSAVE", "FXRSTOR",
]

# CALL_Ev/JMP_Ev/PUSH_Ev are named in two contract lists (G5 and
# branches/stack) but are single ids; EMMS likewise rides both the SSE
# and x87 lists.  Count uniques for the size check.
EXPECTED_UNIQUE = sorted(set(EXPECTED_IDS))
assert len(EXPECTED_IDS) - len(EXPECTED_UNIQUE) == 4

# ---------------------------------------------------------------------------
# Descriptor spot checks: (byte, op, opnd-kinds, modrm, group_op, lockable)
# ---------------------------------------------------------------------------

S_1B = [
    (0x00, "ADD_EbGb", ("RM8", "R8"), 1, 0, 1),
    (0x01, "ADD_EvGv", ("RM32", "R32"), 1, 0, 1),   # card spot
    (0x02, "ADD_GbEb", ("R8", "RM8"), 1, 0, 0),
    (0x05, "ADD_eAXIz", ("R32", "I32"), 0, 0, 0),
    (0x06, "PUSH_ES", ("NONE",), 0, 0, 0),
    (0x1F, "POP_DS", ("NONE",), 0, 0, 0),
    (0x38, "CMP_EbGb", ("RM8", "R8"), 1, 0, 0),
    (0x39, "CMP_EvGv", ("RM32", "R32"), 1, 0, 0),
    (0x40, "INC_Ev", ("RM32",), 0, 0, 0),
    (0x4F, "DEC_Ev", ("RM32",), 0, 0, 0),
    (0x50, "PUSH_Gv", ("R32",), 0, 0, 0),
    (0x5F, "POP_Gv", ("R32",), 0, 0, 0),
    (0x69, "IMUL_GvEvIz", ("R32", "RM32", "I32"), 1, 0, 0),
    (0x6A, "PUSH_Ib", ("I8SX",), 0, 0, 0),
    (0x70, "JCC_Jb", ("REL8",), 0, 0, 0),
    (0x7F, "JCC_Jb", ("REL8",), 0, 0, 0),
    (0x80, "INVALID", None, 1, 1, 0),
    (0x84, "TEST_EbGb", ("RM8", "R8"), 1, 0, 0),
    (0x86, "XCHG_EbGb", ("RM8", "R8"), 1, 0, 1),
    (0x87, "XCHG_EvGv", ("RM32", "R32"), 1, 0, 1),
    (0x88, "MOV_EbGb", ("RM8", "R8"), 1, 0, 0),
    (0x8B, "MOV_GvEv", ("R32", "RM32"), 1, 0, 0),
    (0x8C, "MOV_EwSw", ("RM16", "SREG"), 1, 0, 0),
    (0x8D, "LEA_GvM", ("R32", "RM32"), 1, 0, 0),
    (0x8E, "MOV_SwEw", ("SREG", "RM16"), 1, 0, 0),
    (0x8F, "POP_Ev", ("RM32",), 1, 0, 0),           # card spot
    (0x90, "XCHG_eAXGv", ("R32", "R32"), 0, 0, 0),  # card: NOP special case
    (0x98, "CWDE", ("NONE",), 0, 0, 0),
    (0x99, "CDQ", ("NONE",), 0, 0, 0),
    (0x9C, "PUSHF", ("NONE",), 0, 0, 0),
    (0xA0, "MOV_ALOb", ("R8", "RM8"), 0, 0, 0),
    (0xA4, "MOVSb", ("NONE",), 0, 0, 0),
    (0xA8, "TEST_ALIb", ("R8", "I8"), 0, 0, 0),
    (0xB0, "MOV_GbIb", ("R8", "I8"), 1, 0, 0),
    (0xB8, "MOV_GvIv", ("R32", "I32"), 1, 0, 0),
    (0xC2, "RET_Iw", ("I16",), 0, 0, 0),            # card spot
    (0xC3, "RET", ("NONE",), 0, 0, 0),
    (0xC6, "MOV_EbIb", ("RM8", "I8"), 1, 0, 0),
    (0xC7, "MOV_EvIz", ("RM32", "I32"), 1, 0, 0),
    (0xC8, "ENTER", ("I16", "I8"), 0, 0, 0),
    (0xCD, "INT_Ib", ("I8",), 0, 0, 0),
    (0xD1, "INVALID", None, 1, 1, 0),
    (0xD7, "XLAT", ("NONE",), 0, 0, 0),
    (0xD8, "INVALID", None, 1, 1, 0),   # x87 group (L5c)
    (0xD9, "INVALID", None, 1, 1, 0),
    (0xDA, "INVALID", None, 1, 1, 0),
    (0xDB, "INVALID", None, 1, 1, 0),
    (0xDC, "INVALID", None, 1, 1, 0),
    (0xDD, "INVALID", None, 1, 1, 0),
    (0xDE, "INVALID", None, 1, 1, 0),
    (0xDF, "INVALID", None, 1, 1, 0),
    (0xE0, "LOOPNZ_Jb", ("REL8",), 0, 0, 0),
    (0xE9, "JMP_Jz", ("REL32",), 0, 0, 0),
    (0xEB, "JMP_Jb", ("REL8",), 0, 0, 0),
    (0xF4, "HLT", ("NONE",), 0, 0, 0),
    (0xF6, "INVALID", None, 1, 1, 0),
    (0xFD, "STD", ("NONE",), 0, 0, 0),
    (0xFF, "INVALID", None, 1, 1, 0),
]

S_0F = [
    (0x0B, "UD2", ("NONE",), 0, 0, 0),              # card spot
    (0x10, "MOVUPS", ("R32", "RM32"), 1, 0, 0),     # Phase 5 SSE
    (0x31, "RDTSC", ("NONE", "NONE", "NONE", "NONE", "NONE", "NONE"), 0, 0, 0),
    (0x34, "SYSENTER", ("NONE",), 0, 0, 0),         # card spot
    (0x40, "CMOVcc_Gv", ("R32", "RM32"), 1, 0, 0),
    (0x4F, "CMOVcc_Gv", ("R32", "RM32"), 1, 0, 0),
    (0x80, "JCC_Jz", ("REL32",), 0, 0, 0),
    (0x8F, "JCC_Jz", ("REL32",), 0, 0, 0),
    (0x90, "SETcc_Eb", ("RM8",), 1, 0, 0),
    (0x9F, "SETcc_Eb", ("RM8",), 1, 0, 0),
    (0xA0, "PUSH_FS", ("NONE",), 0, 0, 0),
    (0xA2, "CPUID", ("NONE",), 0, 0, 0),            # card spot
    (0xA3, "BT_EvGv", ("RM32", "R32"), 1, 0, 0),
    (0xA4, "SHLD_EvIb", ("RM32", "R32", "I8"), 1, 0, 0),
    (0xA5, "SHLD_EvCL", ("RM32", "R32", "CL"), 1, 0, 0),
    (0xAB, "BTS_EvGv", ("RM32", "R32"), 1, 0, 1),
    (0xAF, "IMUL_GvEv", ("R32", "RM32"), 1, 0, 0),
    (0xB0, "CMPXCHG_EbGb", ("RM8", "R8"), 1, 0, 1),
    (0xB3, "BTR_EvGv", ("RM32", "R32"), 1, 0, 1),
    (0xB6, "MOVZX_GvEb", ("R32", "RM8"), 1, 0, 0),  # card spot
    (0xB7, "MOVZX_GvEw", ("R32", "RM16"), 1, 0, 0),
    (0xBA, "INVALID", None, 1, 1, 0),
    (0xBB, "BTC_EvGv", ("RM32", "R32"), 1, 0, 1),
    (0xBC, "BSF_GvEv", ("R32", "RM32"), 1, 0, 0),
    (0xBE, "MOVSX_GvEb", ("R32", "RM8"), 1, 0, 0),
    (0xBF, "MOVSX_GvEw", ("R32", "RM16"), 1, 0, 0),
    (0xC0, "XADD_EbGb", ("RM8", "R8"), 1, 0, 1),
    (0xC8, "BSWAP_Gv", ("R32",), 0, 0, 0),
    (0x77, "EMMS", ("NONE",), 0, 0, 0),            # L5c x87/MMX
    (0xAE, "INVALID", None, 1, 1, 0),              # L5c 0F AE group
    (0xD0, "INVALID", None, 0, 0, 0),
    # Phase 5 SSE/MMX rows (full byte map lock; every assigned byte).
    (0x11, "MOVUPS", ("RM32", "R32"), 1, 0, 0),
    (0x12, "MOVLPS", ("R32", "RM32"), 1, 0, 0),
    (0x13, "MOVLPS", ("RM32", "R32"), 1, 0, 0),
    (0x14, "INVALID", None, 0, 0, 0),               # UNPCKLPS not in v1
    (0x16, "MOVHPS", ("R32", "RM32"), 1, 0, 0),
    (0x17, "MOVHPS", ("RM32", "R32"), 1, 0, 0),
    (0x28, "MOVAPS", ("R32", "RM32"), 1, 0, 0),
    (0x29, "MOVAPS", ("RM32", "R32"), 1, 0, 0),
    (0x2A, "CVTPI2PS", ("R32", "RM32"), 1, 0, 0),
    (0x2C, "CVTTPS2PI", ("R32", "RM32"), 1, 0, 0),
    (0x2D, "INVALID", None, 0, 0, 0),               # CVTPS2PI fam not in v1
    (0x2E, "UCOMISS", ("R32", "RM32"), 1, 0, 0),
    (0x2F, "COMISS", ("R32", "RM32"), 1, 0, 0),
    (0x50, "MOVMSKPS", ("R32", "RM32"), 1, 0, 0),
    (0x54, "ANDPS", ("R32", "RM32"), 1, 0, 0),
    (0x55, "ANDNPS", ("R32", "RM32"), 1, 0, 0),
    (0x56, "ORPS", ("R32", "RM32"), 1, 0, 0),
    (0x57, "XORPS", ("R32", "RM32"), 1, 0, 0),
    (0x58, "ADDPS", ("R32", "RM32"), 1, 0, 0),
    (0x59, "MULPS", ("R32", "RM32"), 1, 0, 0),      # hw map: MUL=59
    (0x5A, "CVTPS2PD", ("R32", "RM32"), 1, 0, 0),
    (0x5B, "CVTDQ2PS", ("R32", "RM32"), 1, 0, 0),
    (0x5C, "SUBPS", ("R32", "RM32"), 1, 0, 0),
    (0x5D, "INVALID", None, 0, 0, 0),               # MIN family not in v1
    (0x5E, "DIVPS", ("R32", "RM32"), 1, 0, 0),
    (0x5F, "INVALID", None, 0, 0, 0),               # MAX family not in v1
    (0x60, "PUNPCKLBW", ("R32", "RM32"), 1, 0, 0),
    (0x61, "PUNPCKLWD", ("R32", "RM32"), 1, 0, 0),
    (0x62, "PUNPCKLDQ", ("R32", "RM32"), 1, 0, 0),
    (0x63, "INVALID", None, 0, 0, 0),               # PACKSSWB not in v1
    (0x68, "PUNPCKHBW", ("R32", "RM32"), 1, 0, 0),
    (0x69, "PUNPCKHWD", ("R32", "RM32"), 1, 0, 0),
    (0x6A, "PUNPCKHDQ", ("R32", "RM32"), 1, 0, 0),
    (0x6C, "PUNPCKLQDQ", ("R32", "RM32"), 1, 0, 0),
    (0x6D, "PUNPCKHQDQ", ("R32", "RM32"), 1, 0, 0),
    (0x6E, "MOVQ_xmm", ("R32", "RM32"), 1, 0, 0),
    (0x6F, "INVALID", None, 0, 0, 0),               # MOVDQA/MOVDQU not in v1
    (0x70, "PSHUFW", ("R32", "RM32", "I8"), 1, 0, 0),
    (0x7E, "MOVQ_xmm", ("RM32", "R32"), 1, 0, 0),
    (0x7F, "INVALID", None, 0, 0, 0),
    (0xC2, "CMPPS", ("R32", "RM32", "I8"), 1, 0, 0),
    (0xD4, "PADDQ", ("R32", "RM32"), 1, 0, 0),
    (0xD5, "PMULLW", ("R32", "RM32"), 1, 0, 0),
    (0xDB, "PAND", ("R32", "RM32"), 1, 0, 0),
    (0xDF, "PANDN", ("R32", "RM32"), 1, 0, 0),
    (0xEB, "POR", ("R32", "RM32"), 1, 0, 0),
    (0xEF, "PXOR", ("R32", "RM32"), 1, 0, 0),
    (0xF4, "PMULUDQ", ("R32", "RM32"), 1, 0, 0),
    (0xFA, "PSUBD", ("R32", "RM32"), 1, 0, 0),
    (0xFB, "PSUBQ", ("R32", "RM32"), 1, 0, 0),
    (0xFE, "PADDD", ("R32", "RM32"), 1, 0, 0),
]

# Group rows: ((map0f, opcode), [8 ids], lock mask)
_g2 = lambda suf: [f + suf for f in
                   ("ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "SHL", "SAR")]
S_GROUPS = [
    ((0, 0x80), [f + "_EbIb" for f in _ALU], 0x7F),
    ((0, 0x81), [f + "_EvIz" for f in _ALU], 0x7F),
    ((0, 0x82), [f + "_EbIb" for f in _ALU], 0x7F),  # alias of 80
    ((0, 0x83), [f + "_EvIbSX" for f in _ALU], 0x7F),
    ((0, 0xC1), _g2("_EvIb"), 0x00),
    ((0, 0xD3), _g2("_EvCL"), 0x00),
    ((0, 0xF6), ["TEST_EbIb", "TEST_EbIb", "NOT_Eb", "NEG_Eb",
                 "MUL_Eb", "IMUL_Eb", "DIV_Eb", "IDIV_Eb"], 0x0C),
    ((0, 0xF7), ["TEST_EvIz", "TEST_EvIz", "NOT_Ev", "NEG_Ev",
                 "MUL_Ev", "IMUL_Ev", "DIV_Ev", "IDIV_Ev"], 0x0C),
    ((0, 0xFE), ["INC_Eb", "DEC_Eb"] + ["INVALID"] * 6, 0x03),
    ((0, 0xFF), ["INC_Ev", "DEC_Ev", "CALL_Ev", "INVALID",
                 "JMP_Ev", "INVALID", "PUSH_Ev", "INVALID"], 0x03),
    ((1, 0xBA), ["INVALID"] * 4 + ["BT_EvIb", "BTS_EvIb", "BTR_EvIb",
                                   "BTC_EvIb"], 0xE0),
    # Phase 5 L5c x87 groups (D8-DF by modrm reg field; mod picks mem vs
    # ST(i) in the handler; 0F AE /0-/1 FXSAVE/FXRSTOR).
    ((0, 0xD8), ["FADD_m32", "FMUL_m32", "FCOM_m32", "FCOMP_m32",
                 "FSUB_m32", "FSUBR_m32", "FDIV_m32", "FDIVR_m32"], 0x00),
    ((0, 0xD9), ["FLD_m32", "FXCH", "FST_m32", "FSTP_m32",
                 "FLDENV", "FLDCW", "FNSTENV", "FNSTCW"], 0x00),
    ((0, 0xDA), ["INVALID"] * 5 + ["FUCOMPP"] + ["INVALID"] * 2, 0x00),
    ((0, 0xDB), ["FILD_m32", "INVALID", "FIST_m32", "FISTP_m32",
                 "FNINIT", "FLD_m80", "FCOMI", "FSTP_m80"], 0x00),
    ((0, 0xDC), ["FADD_m64", "FMUL_m64", "FCOM_m64", "FCOMP_m64",
                 "FSUB_m64", "FSUBR_m64", "FDIV_m64", "FDIVR_m64"], 0x00),
    ((0, 0xDD), ["FLD_m64", "INVALID", "FST_m64", "FSTP_m64",
                 "FUCOM", "FUCOMP", "INVALID", "FNSTSW_m16"], 0x00),
    ((0, 0xDE), ["FADDP", "FMULP", "INVALID", "INVALID",
                 "FSUBRP", "FSUBP", "FDIVRP", "FDIVP"], 0x00),
    ((0, 0xDF), ["FILD_m16", "INVALID", "FIST_m16", "FISTP_m16",
                 "FNSTSW_AX", "FILD_m64", "FCOMIP", "FISTP_m64"], 0x00),
    # Phase 5 shared spec: 0F AE /2 LDMXCSR, /3 STMXCSR join the L5c
    # FXSAVE/FXRSTOR group slots (/4-/7 stay INVALID).
    ((1, 0xAE), ["FXSAVE", "FXRSTOR", "LDMXCSR", "STMXCSR"]
     + ["INVALID"] * 4, 0x00),
]


def load_kinds_decode():
    text = DECODE_H.read_text(encoding="utf-8")
    start = text.index("I686_OPND_NONE")
    block = text[start:text.index("};", start)]
    names = re.findall(r"I686_OPND_(\w+)", block)
    return {n: i for i, n in enumerate(names)}


ROW_RE = re.compile(
    r"/\* 0x([0-9A-F]{2}) \*/ \{ (I686_OP_\w+), "
    r"\{ (\d+)u, (\d+)u, (\d+)u \}, (\d+)u, (\d+)u, (\d+)u \}")
GROUP_RE = re.compile(
    r"\{ (\d+)u, (0x[0-9A-F]{2})u,(.*?)0x([0-9A-F]{2})u \},", re.S)


def parse_table(text, name):
    start = text.index("i686_insn_tab_%s[256] = {" % name)
    end = text.index("};", start)
    rows = {}
    for m in ROW_RE.finditer(text[start:end]):
        rows[int(m.group(1), 16)] = (
            m.group(2)[len("I686_OP_"):],
            tuple(int(m.group(i)) for i in range(3, 9)),
        )
    return rows


def main():
    failures = []

    def check(cond, msg):
        if not cond:
            failures.append(msg)

    text = HEADER.read_text(encoding="utf-8")

    # --- header scaffolding ------------------------------------------------
    check(text.count("#ifndef %s" % GUARD) == 1, "missing/dup #ifndef guard")
    check(text.count("#define %s" % GUARD) == 1, "missing/dup #define guard")
    check(text.count("#endif /* %s */" % GUARD) == 1, "missing #endif guard")
    check("static const i686_insn_desc_t i686_insn_tab_1b[256]" in text,
          "i686_insn_tab_1b must be a static const inline array")
    check("static const i686_insn_desc_t i686_insn_tab_0f[256]" in text,
          "i686_insn_tab_0f must be a static const inline array")

    # --- enum completeness / uniqueness ------------------------------------
    estart = text.index("typedef enum {")
    eend = text.index("} i686_op_t;", estart)
    eblock = text[estart:eend]
    enum_ids = re.findall(r"I686_OP_(\w+)", eblock)
    counts = Counter(enum_ids)
    for ident in EXPECTED_IDS:
        n = counts.get(ident, 0)
        check(n == 1, "I686_OP_%s occurs %d times in the enum (want 1)" % (ident, n))
    dupes = sorted(i for i, n in counts.items() if n > 1)
    check(not dupes, "duplicate opcode ids in enum: %r" % dupes)
    expected_set = set(EXPECTED_IDS) | {"INVALID"}
    extras = sorted(set(enum_ids) - expected_set)
    check(not extras, "unexpected extra enum ids: %r" % extras)
    missing = sorted(expected_set - set(enum_ids))
    check(not missing, "missing enum ids: %r" % missing)
    check("I686_OP_INVALID = 0" in eblock, "I686_OP_INVALID must be 0")
    check(len(enum_ids) == len(EXPECTED_UNIQUE) + 1,
          "enum has %d ids (want %d)" % (len(enum_ids), len(EXPECTED_UNIQUE) + 1))

    # --- operand-kind legend matches decode.h ------------------------------
    kinds = load_kinds_decode()
    legend_map = {}
    for line in text.splitlines():
        stripped = line.lstrip().lstrip("*").strip()
        if re.fullmatch(r"(\d+\s+\w+)(\s+\d+\s+\w+)*", stripped):
            toks = stripped.split()
            for i in range(0, len(toks), 2):
                legend_map[toks[i + 1]] = int(toks[i])
    check(legend_map == kinds,
          "legend %r != decode.h I686_OPND_* %r" % (legend_map, kinds))

    # --- descriptor spot checks ---------------------------------------------
    def kind_nums(opnds):
        if not opnds:
            return (0, 0, 0)
        return tuple(kinds[k] for k in (tuple(opnds) + ("NONE",) * 3)[:3])

    for tname, spots in (("1b", S_1B), ("0f", S_0F)):
        rows = parse_table(text, tname)
        check(len(rows) == 256,
              "i686_insn_tab_%s parsed %d rows (want 256)" % (tname, len(rows)))
        for byte, op, opnds, modrm, group, lock in spots:
            got = rows.get(byte)
            if got is None:
                failures.append("%s[0x%02X]: no row parsed" % (tname, byte))
                continue
            g_op, (g0, g1, g2, gm, gg, gl) = got
            if op == "INVALID":
                ok = (g_op == "INVALID" and (g0, g1, g2) == (0, 0, 0)
                      and gg == group and gm == modrm and gl == lock)
            else:
                ok = (g_op == op and (g0, g1, g2) == kind_nums(opnds)
                      and gm == modrm and gg == group and gl == lock)
            check(ok, "%s[0x%02X] = %r (want %s %r m=%d g=%d l=%d)"
                  % (tname, byte, got, op, kind_nums(opnds), modrm, group, lock))

    # --- group table ---------------------------------------------------------
    gstart = text.index("static const i686_group_t i686_group_tab[] = {")
    gend = text.index("};", gstart)
    groups = {}
    for m in GROUP_RE.finditer(text[gstart:gend]):
        key = (int(m.group(1)), int(m.group(2), 16))
        ids = re.findall(r"I686_OP_(\w+)", m.group(3))
        groups[key] = (ids, int(m.group(4), 16))
    check(len(groups) == 24, "group tab has %d rows (want 24)" % len(groups))
    for key, want_ids, want_lock in S_GROUPS:
        got = groups.get(key)
        if got is None:
            failures.append("group tab missing (map0f=%d, opcode=0x%02X)" % key)
            continue
        ids, lock = got
        check(ids == want_ids,
              "group (map0f=%d, 0x%02X) ids %r != %r" % (key[0], key[1], ids, want_ids))
        check(lock == want_lock,
              "group (map0f=%d, 0x%02X) lock 0x%02X != 0x%02X" % (key[0], key[1], lock, want_lock))

    # --- static size checks present (also keep -Wall clean) ------------------
    check("_Static_assert(sizeof(i686_insn_tab_1b)" in text,
          "missing 1b size _Static_assert")
    check("_Static_assert(sizeof(i686_insn_tab_0f)" in text,
          "missing 0f size _Static_assert")

    if failures:
        for f in failures:
            print("FAIL: %s" % f)
        print("%d failure(s)" % len(failures))
        return 1
    print("L1A OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
