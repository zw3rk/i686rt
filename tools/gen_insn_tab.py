#!/usr/bin/env python3
"""
gen_insn_tab.py -- generate src/x86/insn_tab.h for i686rt (Phase 1, lane L1a).

Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
SPDX-License-Identifier: Apache-2.0

Emits the frozen opcode-id contract of docs/lanes/phase-1.md:
  - i686_op_t enum (I686_OP_INVALID = 0, then every contract identifier),
  - i686_insn_desc_t { op, opnd[3], modrm, group_op, lockable },
  - static const i686_insn_tab_1b[256] / i686_insn_tab_0f[256],
  - static const i686_group_tab[] resolving group bytes (modrm reg field)
    to concrete ids, per-reg operand kinds, and per-reg lockability.

Operand kinds are emitted as NUMERIC values because decode.h includes this
header before defining the I686_OPND_* enum; the numbering is parsed from
decode.h at generation time so the two files can never drift silently.

Usage: python3 tools/gen_insn_tab.py [output-path]
       (default output: src/x86/insn_tab.h under the repo root)
"""

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DECODE_H = REPO / "src" / "x86" / "decode.h"
DEFAULT_OUT = REPO / "src" / "x86" / "insn_tab.h"
GUARD = "I686RT_X86_INSN_TAB_H"

# ---------------------------------------------------------------------------
# Operand kinds (numbering parsed from the frozen decode.h)
# ---------------------------------------------------------------------------

KIND_ORDER = (
    "NONE", "R8", "R16", "R32", "RM8", "RM16", "RM32", "I8", "I8SX",
    "I16", "I32", "REL8", "REL32", "M1616", "ONE", "CL", "SREG",
)


def load_opnd_kinds():
    """Return {name: value} for I686_OPND_* exactly as ordered in decode.h."""
    text = DECODE_H.read_text(encoding="utf-8")
    start = text.index("I686_OPND_NONE")
    block = text[start : text.index("};", start)]
    names = re.findall(r"I686_OPND_(\w+)", block)
    if tuple(names) != KIND_ORDER:
        raise SystemExit(
            "decode.h I686_OPND_* order changed: %r (expected %r)"
            % (names, KIND_ORDER)
        )
    return {n: i for i, n in enumerate(names)}


# ---------------------------------------------------------------------------
# Opcode-id enumeration (frozen contract expansion rules)
# ---------------------------------------------------------------------------

ALU = ("ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR", "CMP")
ALU_WRITES = ("ADD", "OR", "ADC", "SBB", "AND", "SUB", "XOR")  # CMP writes no mem
SHIFTS = ("ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "SAR")
G3_UNARY = ("NOT", "NEG", "MUL", "IMUL", "DIV", "IDIV")


def contract_ids():
    """Ordered (section, [ids]) exactly per docs/lanes/phase-1.md."""
    sections = []
    alu = []
    for f in ALU:
        alu += [
            f + "_EbGb", f + "_EvGv", f + "_GbEb", f + "_GvEv",
            f + "_ALIb", f + "_eAXIz",
            f + "_EbIb", f + "_EvIz", f + "_EvIbSX",
        ]
    sections.append(("ALU ADD OR ADC SBB AND SUB XOR CMP: 6 base forms + G1-resolved immediates (9 each)", alu))
    sections.append(("TEST (84/85/A8/A9; F6/F7 /0)", [
        "TEST_EbGb", "TEST_EvGv", "TEST_ALIb", "TEST_eAXIz",
        "TEST_EbIb", "TEST_EvIz",
    ]))
    shifts = []
    for f in SHIFTS:
        shifts += [f + "_Eb1", f + "_Ev1", f + "_EbCL", f + "_EvCL",
                   f + "_EbIb", f + "_EvIb"]
    sections.append(("shifts/rotates ROL ROR RCL RCR SHL SHR SAR: 6 forms each (G2 resolved)", shifts))
    g3 = []
    for g in G3_UNARY:
        g3 += [g + "_Eb", g + "_Ev"]
    sections.append(("G3 unary (F6/F7 /2../7)", g3))
    sections.append(("G4 (FE) and G5 (FF)", [
        "INC_Eb", "DEC_Eb", "INC_Ev", "DEC_Ev", "CALL_Ev", "JMP_Ev", "PUSH_Ev",
    ]))
    sections.append(("MOV", [
        "MOV_EbGb", "MOV_EvGv", "MOV_GbEb", "MOV_GvEv", "MOV_ALOb", "MOV_eAXOv",
        "MOV_ObAL", "MOV_OveAX", "MOV_GbIb", "MOV_GvIv", "MOV_EbIb", "MOV_EvIz",
        "MOV_EwSw", "MOV_SwEw",
    ]))
    sections.append(("stack", [
        "PUSH_Gv", "POP_Gv", "PUSH_Iz", "PUSH_Ib", "PUSHA", "POPA", "PUSHF",
        "POPF", "ENTER", "LEAVE", "PUSH_ES", "POP_ES", "PUSH_DS", "POP_DS",
        "PUSH_FS", "POP_FS", "PUSH_GS", "POP_GS", "POP_Ev",
        # PUSH_Ev is listed here and in G5; it is one id (see G5 section)
    ]))
    sections.append(("XCHG", ["XCHG_EbGb", "XCHG_EvGv", "XCHG_eAXGv"]))
    sections.append(("flags/misc", [
        "NOP", "CMC", "CLC", "STC", "CLI", "STI", "CLD", "STD", "SAHF", "LAHF",
        "CBW", "CWDE", "CDQ", "XLAT", "HLT", "WAIT", "UD2", "CPUID", "SYSENTER",
        "CMPXCHG_EbGb", "CMPXCHG_EvGv", "XADD_EbGb", "XADD_EvGv", "BSWAP_Gv",
        "MOVZX_GvEb", "MOVZX_GvEw", "MOVSX_GvEb", "MOVSX_GvEw",
        "LEA_GvM",  # not named in the phase-1 list; 8D required (see header notes)
    ]))
    sections.append(("branches (JCC/SETcc/CMOVcc carry the condition in modrm_reg)", [
        "JMP_Jb", "JMP_Jz", "CALL_Jz", "RET", "RET_Iw",
        # JMP_Ev and CALL_Ev are listed here and in G5; one id each (see G5)
        "JCC_Jb", "JCC_Jz", "SETcc_Eb", "CMOVcc_Gv",
        "LOOPNZ_Jb", "LOOPZ_Jb", "LOOP_Jb", "JCXZ_Jb",
    ]))
    sections.append(("bit ops (0F)", [
        "BT_EvGv", "BTS_EvGv", "BTR_EvGv", "BTC_EvGv", "BSF_GvEv", "BSR_GvEv",
        "BT_EvIb", "BTS_EvIb", "BTR_EvIb", "BTC_EvIb", "SHLD_EvIb", "SHLD_EvCL",
        "SHRD_EvIb", "SHRD_EvCL", "IMUL_GvEv", "RDTSC",
        # Contract amendment (S1, ratified): three-operand IMUL (gcc-required)
        "IMUL_GvEvIz", "IMUL_GvEvIb",
    ]))
    sections.append(("strings (REP via pfx_rep)", [
        "MOVSb", "MOVSw", "CMPSb", "CMPSw", "STOSb", "STOSw",
        "LODSb", "LODSw", "SCASb", "SCASw",
    ]))
    sections.append(("int/trap", ["INT_Ib", "INT3", "INTO", "IRET"]))

    # Phase 5 shared spec (docs/lanes/phase-5.md "Generator rows", lanes
    # L5a+L5b emit byte-identically): SSE2 integer + SSE scalar FP over
    # the used 0F map -- ONE id per opcode byte; the mandatory prefixes
    # (66 -> pfx_opsize, F2/F3 -> pfx_rep) select the family member
    # inside the handler.  LDMXCSR/STMXCSR bind via the 0F AE group
    # (/2,/3); EMMS also rides the L5c x87 set below (one id).
    sections.append(("SSE/MMX families (Phase 5 shared spec, docs/lanes/phase-5.md: ONE id per 0F opcode byte; the mandatory prefixes 66/F2/F3 ride pfx_opsize/pfx_rep and select the family member inside the handler)", [
        "MOVUPS", "MOVLPS", "MOVHPS", "MOVAPS", "MOVQ_xmm",
        "CVTPI2PS", "CVTTPS2PI", "CVTPS2PD", "CVTDQ2PS",
        "UCOMISS", "COMISS", "MOVMSKPS",
        "ANDPS", "ANDNPS", "ORPS", "XORPS",
        "ADDPS", "MULPS", "SUBPS", "DIVPS",
        "PUNPCKLBW", "PUNPCKLWD", "PUNPCKLDQ",
        "PUNPCKHBW", "PUNPCKHWD", "PUNPCKHDQ",
        "PUNPCKLQDQ", "PUNPCKHQDQ",
        "PSHUFW", "CMPPS",
        # RC7b triage T1 (sanctioned union extension, docs/lanes/
        # phase-7.md): SSE2 data-movement + integer rows the wine32
        # sysroot binaries actually execute.  One id per 0F byte;
        # MOVDQA covers the 6F load / 7F store rows (MOVDQU + MMX MOVQ).
        "MOVDQA", "MOVQ2DQ", "MOVNTDQ",
        "PCMPGTB", "PSRLDQ", "PCMPEQB", "PCMPEQD",
        "PADDQ", "PMULLW", "PAND", "PANDN", "POR", "PXOR",
        "PMULUDQ", "PSUBD", "PSUBQ", "PADDD",
        "PMINUB", "PMAXUB", "PSUBB", "PMOVMSKB",
        "PREFETCH", "LDMXCSR", "STMXCSR", "EMMS",
    ]))

    # RC7b triage T4 (docs/lanes/phase-7.md): 0F C7 /1 CMPXCHG8B m64 --
    # ntdll.so's NtAllocateUuids interlocked loop runs `lock cmpxchg8b`
    # during wine startup.
    sections.append(("CMPXCHG8B (0F C7 /1, RC7b T4)", ["CMPXCHG8B"]))

    # Phase 5 (L5c) x87/MMX set.  D8-DF are group bytes: the modrm reg
    # field picks one of 8 ids per byte and the mod bit selects the memory
    # vs ST(i) form inside the handler (x87 second-byte fixed forms ride
    # the owning slot's handler via a modrm_mod/modrm_rm sub-dispatch --
    # see src/interp/h_x87.c).  0F 77 EMMS and the 0F AE /0-/1 group
    # (FXSAVE/FXRSTOR) complete the set; byte-identical rows are also
    # emitted by the SSE lanes per docs/lanes/phase-5.md (S5 dedupes).
    sections.append(("x87/MMX x87 state (D8-DF groups + 0F 77/0F AE, Phase 5 L5c)", [
        # D8: m32 arithmetic/compare (+ ST(i) register forms via mod=3)
        "FADD_m32", "FMUL_m32", "FCOM_m32", "FCOMP_m32",
        "FSUB_m32", "FSUBR_m32", "FDIV_m32", "FDIVR_m32",
        # DC: m64 arithmetic/compare (+ ST(i),ST(0) reversed forms)
        "FADD_m64", "FMUL_m64", "FCOM_m64", "FCOMP_m64",
        "FSUB_m64", "FSUBR_m64", "FDIV_m64", "FDIVR_m64",
        # DE: pop forms ST(i),ST(0) (memory FIADD-class declined)
        "FADDP", "FMULP", "FSUBRP", "FSUBP", "FDIVRP", "FDIVP",
        # D9 env/slots (fixed forms via sub-dispatch)
        "FLD_m32", "FXCH", "FST_m32", "FSTP_m32",
        "FLDENV", "FLDCW", "FNSTENV", "FNSTCW",
        # DD
        "FLD_m64", "FST_m64", "FSTP_m64", "FUCOM", "FUCOMP", "FNSTSW_m16",
        # DB (FUCOMI rides FLD_m80 mod=3; FNCLEX rides FNINIT mod=3)
        "FILD_m32", "FIST_m32", "FISTP_m32", "FNINIT", "FLD_m80", "FCOMI",
        "FSTP_m80",
        # DA
        "FUCOMPP",
        # DF (FUCOMIP rides FILD_m64 mod=3; FNSTSW AX is DF E0)
        "FILD_m16", "FIST_m16", "FISTP_m16", "FNSTSW_AX", "FILD_m64",
        "FCOMIP", "FISTP_m64",
        # 0F map
        "EMMS", "FXSAVE", "FXRSTOR",
        # RC7b T1: 0F AE /7 joins the group (store fence; no-op in the
        # single-threaded TSO guest model).
        "SFENCE",
        # RC7b triage T4b (docs/lanes/phase-7.md): FISTTP — SSE3
        # truncate-store integer; ntdll.dll uses it for C99 (int)
        # conversions.  Appended (ids are append-stable).
        "FISTTP_m32", "FISTTP_m64", "FISTTP_m16",
        # RC7b triage T4b: FNSAVE (DD /6 m108, save+reinit); FRSTOR
        # (DD /4 memory form) rides the FUCOM slot handler like the
        # other L5c fixed-form sub-dispatches.
        "FNSAVE",
        # RC7b triage T4b: DA mod=3 register compare forms (glibc/i386
        # float code): DA C0+i FCOM, D0+i FUCOM, D8+i FCOMP.
        "FCOM_STi", "FUCOM_STi", "FCOMP_STi",
    ]))
    return sections


# ---------------------------------------------------------------------------
# Descriptor tables
# ---------------------------------------------------------------------------

class Desc:
    __slots__ = ("op", "opnd", "modrm", "group", "lock", "note")

    def __init__(self, op, opnd=("NONE", "NONE", "NONE"), modrm=1,
                 group=0, lock=0, note=""):
        self.op = op
        self.opnd = opnd
        self.modrm = modrm
        self.group = group
        self.lock = lock
        self.note = note


def invalid(note="unassigned"):
    return Desc("INVALID", ("NONE", "NONE", "NONE"), 0, 0, 0, note)


def group_desc(note):
    return Desc("INVALID", ("NONE", "NONE", "NONE"), 1, 1, 0, note)


# Reasons for notable INVALID bytes (default rows say just "unassigned").
ONEB_INVALID = {
    0x0F: "0F escape: see i686_insn_tab_0f",
    0x0E: "PUSH CS: not in v1 contract",
    0x16: "PUSH SS: not in v1 contract",
    0x17: "POP SS: not in v1 contract",
    0x27: "DAA: BCD excluded",
    0x2F: "DAS: BCD excluded",
    0x37: "AAA: BCD excluded",
    0x3F: "AAS: BCD excluded",
    0x62: "BOUND: excluded",
    0x63: "ARPL: excluded",
    0x6C: "INS: I/O excluded", 0x6D: "INS: I/O excluded",
    0x6E: "OUTS: I/O excluded", 0x6F: "OUTS: I/O excluded",
    0x9A: "CALLF: far transfer excluded",
    0xC4: "LES: excluded", 0xC5: "LDS: excluded",
    0xCA: "RETF: far transfer excluded", 0xCB: "RETF: far transfer excluded",
    0xD4: "DAA: BCD excluded", 0xD5: "AAA: BCD excluded",
    0xD6: "SALC: excluded",
    0xEA: "JMPF: far transfer excluded",
    0xE4: "IN: I/O excluded", 0xE5: "IN: I/O excluded",
    0xE6: "OUT: I/O excluded", 0xE7: "OUT: I/O excluded",
    0xEC: "IN: I/O excluded", 0xED: "IN: I/O excluded",
    0xEE: "OUT: I/O excluded", 0xEF: "OUT: I/O excluded",
    0xF0: "LOCK prefix (decoder)", 0xF2: "REPNE prefix (decoder)",
    0xF3: "REP/REPE prefix (decoder)",
}
PREFIX_BYTES = (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67)

TWOB_INVALID = {
    0x00: "0F 00 group: excluded", 0x01: "0F 01 group: excluded",
    0x02: "LAR: excluded", 0x03: "LSL: excluded", 0x04: "",
    0x05: "",
    0x06: "CLTS: excluded", 0x07: "",
    0x08: "", 0x09: "", 0x0A: "", 0x0C: "", 0x0D: "", 0x0E: "", 0x0F: "",
    0x14: "SSE excluded", 0x15: "SSE excluded",
    0x19: "SSE excluded", 0x1A: "SSE excluded", 0x1B: "SSE excluded",
    0x1C: "SSE excluded", 0x1D: "SSE excluded", 0x1E: "SSE excluded",
    0x1F: "SSE excluded (NOP variant)",
    # (0x10-0x13, 0x16, 0x17 now MOVUPS/MOVLPS/MOVHPS rows, Phase 5;
    #  0x18 PREFETCH, RC7b T1)
    0x20: "MOV Cd/Td: excluded", 0x21: "", 0x22: "", 0x23: "",
    0x24: "MOV Rd/Td test: excluded", 0x25: "", 0x26: "", 0x27: "",
    # 0x28/0x29 MOVAPS, 0x2A CVTPI2PS, 0x2C CVTTPS2PI, 0x2E/0x2F
    # UCOMISS/COMISS: Phase 5 rows.
    0x2D: "CVTPS2PI/CVTSS2SI family (0F 2D): not in v1",
    0x30: "WRMSR: excluded", 0x31: "RDTSC: excluded", 0x32: "RDMSR: excluded",
    0x33: "",
    0x35: "SYSEXIT: not in v1",
    0x51: "SSE excluded", 0x52: "SSE excluded", 0x53: "SSE excluded",
    0x5D: "MIN family (MINPS/MINSS/MINPD/MINSD): not in v1",
    0x5F: "MAX family (MAXPS/MAXSS/MAXPD/MAXSD): not in v1",
    0x63: "PACKSSWB: not in v1",
    0x65: "PCMPGTW: not in v1", 0x66: "PCMPGTD: not in v1",
    0x67: "PACKUSWB: not in v1", 0x6B: "PACKSSDW: not in v1",
    # (0x64 PCMPGTB, 0x6F/0x7F MOVDQA family, 0x73 PSRLDQ, 0x74 PCMPEQB,
    #  0x76 PCMPEQD: RC7b T1 rows)
    0x71: "SSE excluded", 0x72: "SSE excluded",
    0x75: "PCMPEQW: unused by the RC7b targets",
    0x78: "SSE excluded", 0x79: "SSE excluded", 0x7A: "SSE excluded",
    0x7B: "SSE excluded", 0x7C: "SSE excluded", 0x7D: "SSE excluded",
    0xA6: "reserved", 0xA7: "reserved",
    0xAA: "RSM: excluded",
    0xB2: "reserved", 0xB4: "reserved", 0xB5: "reserved",
    0xB8: "reserved (POP gs variant)", 0xB9: "reserved group",
    0xC3: "SSE excluded", 0xC4: "SSE excluded",
    0xC5: "SSE excluded", 0xC6: "SSE excluded",
    # (0xC7 CMPXCHG8B: RC7b T4 row)
}
TWOB_INVALID_RANGES = ((0xD0, 0xFF, "MMX/SSE excluded"),)


def build_oneb():
    t = {}
    for i, f in enumerate(ALU):
        b = i * 8
        w = 1 if f in ALU_WRITES else 0
        t[b + 0] = Desc(f + "_EbGb", ("RM8", "R8"), lock=w)
        t[b + 1] = Desc(f + "_EvGv", ("RM32", "R32"), lock=w)
        t[b + 2] = Desc(f + "_GbEb", ("R8", "RM8"))
        t[b + 3] = Desc(f + "_GvEv", ("R32", "RM32"))
        t[b + 4] = Desc(f + "_ALIb", ("R8", "I8"), modrm=0,
                        note="AL is opnd[0]; decoder sets modrm_reg=0")
        t[b + 5] = Desc(f + "_eAXIz", ("R32", "I32"), modrm=0,
                        note="eAX is opnd[0]; decoder sets modrm_reg=0")
    t[0x06] = Desc("PUSH_ES", modrm=0)
    t[0x07] = Desc("POP_ES", modrm=0)
    t[0x1E] = Desc("PUSH_DS", modrm=0)
    t[0x1F] = Desc("POP_DS", modrm=0)
    for r in range(8):
        t[0x40 + r] = Desc("INC_Ev", ("RM32",), modrm=0,
                           note="decoder synthesizes mod=3, rm=opcode&7")
        t[0x48 + r] = Desc("DEC_Ev", ("RM32",), modrm=0,
                           note="decoder synthesizes mod=3, rm=opcode&7")
        t[0x50 + r] = Desc("PUSH_Gv", ("R32",), modrm=0, note="rm=opcode&7")
        t[0x58 + r] = Desc("POP_Gv", ("R32",), modrm=0, note="rm=opcode&7")
        t[0xB0 + r] = Desc("MOV_GbIb", ("R8", "I8"), modrm=1,
                           note="reg=opcode&7 into modrm_reg (no modrm byte)")
        t[0xB8 + r] = Desc("MOV_GvIv", ("R32", "I32"), modrm=1,
                           note="reg=opcode&7 into modrm_reg (no modrm byte)")
        t[0x90 + r] = Desc("XCHG_eAXGv", ("R32", "R32"), modrm=0,
                           note=("rm=opcode&7; opnd[0] is eAX"
                                 + ("; rm==0 means decoder reports NOP"
                                    if r == 0 else "")))
    for r in range(16):
        t[0x70 + r] = Desc("JCC_Jb", ("REL8",), modrm=0,
                           note="cond=opcode&0xF carried in modrm_reg")
    t[0x60] = Desc("PUSHA", modrm=0)
    t[0x61] = Desc("POPA", modrm=0)
    t[0x68] = Desc("PUSH_Iz", ("I32",), modrm=0)
    t[0x6A] = Desc("PUSH_Ib", ("I8SX",), modrm=0, note="imm8 sign-extended")
    for b, note in ((0x80, "G1 Eb,Ib (see i686_group_tab)"),
                    (0x81, "G1 Ev,Iz (see i686_group_tab)"),
                    (0x82, "G1 alias of 80 (see i686_group_tab)"),
                    (0x83, "G1 Ev,Ib sx (see i686_group_tab)"),
                    (0xC0, "G2 shift Eb,Ib (see i686_group_tab)"),
                    (0xC1, "G2 shift Ev,Ib (see i686_group_tab)"),
                    (0xD0, "G2 shift Eb,1 (see i686_group_tab)"),
                    (0xD1, "G2 shift Ev,1 (see i686_group_tab)"),
                    (0xD2, "G2 shift Eb,CL (see i686_group_tab)"),
                    (0xD3, "G2 shift Ev,CL (see i686_group_tab)"),
                    (0xF6, "G3 byte (see i686_group_tab)"),
                    (0xF7, "G3 word/dword (see i686_group_tab)"),
                    (0xFE, "G4 (see i686_group_tab)"),
                    (0xFF, "G5 (see i686_group_tab)"),
                    # Phase 5 L5c: x87 escape bytes resolve by modrm reg
                    # field; the mod bit picks mem vs ST(i) in handlers.
                    (0xD8, "x87 D8: m32/ST(i) arith+com (see i686_group_tab)"),
                    (0xD9, "x87 D9: env/fixed forms (see i686_group_tab)"),
                    (0xDA, "x87 DA: FUCOMPP only (see i686_group_tab)"),
                    (0xDB, "x87 DB: FILD/FIST/FLD m80/COMI (see i686_group_tab)"),
                    (0xDC, "x87 DC: m64/ST(i),ST(0) arith (see i686_group_tab)"),
                    (0xDD, "x87 DD: FLD/FST m64, FUCOM*, FNSTSW (see i686_group_tab)"),
                    (0xDE, "x87 DE: arithmetic pop forms (see i686_group_tab)"),
                    (0xDF, "x87 DF: FILD/FIST m16/m64, FNSTSW AX (see i686_group_tab)")):
        t[b] = group_desc(note)
    t[0x84] = Desc("TEST_EbGb", ("RM8", "R8"))
    t[0x85] = Desc("TEST_EvGv", ("RM32", "R32"))
    t[0x86] = Desc("XCHG_EbGb", ("RM8", "R8"), lock=1)
    t[0x87] = Desc("XCHG_EvGv", ("RM32", "R32"), lock=1)
    t[0x88] = Desc("MOV_EbGb", ("RM8", "R8"))
    t[0x89] = Desc("MOV_EvGv", ("RM32", "R32"))
    t[0x8A] = Desc("MOV_GbEb", ("R8", "RM8"))
    t[0x8B] = Desc("MOV_GvEv", ("R32", "RM32"))
    # Contract amendment (S1, ratified): three-operand IMUL.
    t[0x69] = Desc("IMUL_GvEvIz", ("R32", "RM32", "I32"))
    t[0x6B] = Desc("IMUL_GvEvIb", ("R32", "RM32", "I8SX"))
    t[0x8C] = Desc("MOV_EwSw", ("RM16", "SREG"))
    t[0x8D] = Desc("LEA_GvM", ("R32", "RM32"),
                   note="not named in the phase-1 list; 8D is required for flat code")
    t[0x8E] = Desc("MOV_SwEw", ("SREG", "RM16"))
    t[0x8F] = Desc("POP_Ev", ("RM32",), note="8F /0")
    t[0x98] = Desc("CWDE", modrm=0, note="66 98 = CBW (decoder swaps the id)")
    t[0x99] = Desc("CDQ", modrm=0)
    t[0x9B] = Desc("WAIT", modrm=0)
    t[0x9C] = Desc("PUSHF", modrm=0)
    t[0x9D] = Desc("POPF", modrm=0)
    t[0x9E] = Desc("SAHF", modrm=0)
    t[0x9F] = Desc("LAHF", modrm=0)
    t[0xA0] = Desc("MOV_ALOb", ("R8", "RM8"), modrm=0, note="moffs, no modrm")
    t[0xA1] = Desc("MOV_eAXOv", ("R32", "RM32"), modrm=0, note="moffs, no modrm")
    t[0xA2] = Desc("MOV_ObAL", ("RM8", "R8"), modrm=0, note="moffs, no modrm")
    t[0xA3] = Desc("MOV_OveAX", ("RM32", "R32"), modrm=0, note="moffs, no modrm")
    for b, op in ((0xA4, "MOVSb"), (0xA5, "MOVSw"), (0xA6, "CMPSb"),
                  (0xA7, "CMPSw"), (0xAA, "STOSb"), (0xAB, "STOSw"),
                  (0xAC, "LODSb"), (0xAD, "LODSw"), (0xAE, "SCASb"),
                  (0xAF, "SCASw")):
        t[b] = Desc(op, modrm=0, note="implicit ESI/EDI/AL/eAX; REP via pfx_rep")
    t[0xA8] = Desc("TEST_ALIb", ("R8", "I8"), modrm=0,
                   note="AL is opnd[0]; decoder sets modrm_reg=0")
    t[0xA9] = Desc("TEST_eAXIz", ("R32", "I32"), modrm=0,
                   note="eAX is opnd[0]; decoder sets modrm_reg=0")
    t[0xC2] = Desc("RET_Iw", ("I16",), modrm=0)
    t[0xC3] = Desc("RET", modrm=0)
    t[0xC6] = Desc("MOV_EbIb", ("RM8", "I8"))
    t[0xC7] = Desc("MOV_EvIz", ("RM32", "I32"))
    t[0xC8] = Desc("ENTER", ("I16", "I8"), modrm=0)
    t[0xC9] = Desc("LEAVE", modrm=0)
    t[0xCC] = Desc("INT3", modrm=0)
    t[0xCD] = Desc("INT_Ib", ("I8",), modrm=0)
    t[0xCE] = Desc("INTO", modrm=0, note="decode-only in v1 (UNDEF handler)")
    t[0xCF] = Desc("IRET", modrm=0, note="decode-only in v1 (Phase 4)")
    t[0xD7] = Desc("XLAT", modrm=0)
    t[0xE0] = Desc("LOOPNZ_Jb", ("REL8",), modrm=0)
    t[0xE1] = Desc("LOOPZ_Jb", ("REL8",), modrm=0)
    t[0xE2] = Desc("LOOP_Jb", ("REL8",), modrm=0)
    t[0xE3] = Desc("JCXZ_Jb", ("REL8",), modrm=0)
    t[0xE8] = Desc("CALL_Jz", ("REL32",), modrm=0)
    t[0xE9] = Desc("JMP_Jz", ("REL32",), modrm=0)
    t[0xEB] = Desc("JMP_Jb", ("REL8",), modrm=0)
    t[0xF4] = Desc("HLT", modrm=0)
    t[0xF5] = Desc("CMC", modrm=0)
    t[0xF8] = Desc("CLC", modrm=0)
    t[0xF9] = Desc("STC", modrm=0)
    t[0xFA] = Desc("CLI", modrm=0)
    t[0xFB] = Desc("STI", modrm=0)
    t[0xFC] = Desc("CLD", modrm=0)
    t[0xFD] = Desc("STD", modrm=0)
    return t


def build_twob():
    t = {}
    t[0x0B] = Desc("UD2", modrm=0)
    t[0x34] = Desc("SYSENTER", modrm=0, note="syscall exit per D12")
    t[0x31] = Desc("RDTSC", modrm=0)
    for r in range(16):
        t[0x40 + r] = Desc("CMOVcc_Gv", ("R32", "RM32"),
                           note="cond=opcode&0xF carried in modrm_reg")
        t[0x80 + r] = Desc("JCC_Jz", ("REL32",), modrm=0,
                           note="cond=opcode&0xF carried in modrm_reg")
        t[0x90 + r] = Desc("SETcc_Eb", ("RM8",),
                           note="cond=opcode&0xF carried in modrm_reg")
    t[0xA0] = Desc("PUSH_FS", modrm=0)
    t[0xA1] = Desc("POP_FS", modrm=0)
    t[0xA2] = Desc("CPUID", modrm=0)
    t[0xA3] = Desc("BT_EvGv", ("RM32", "R32"))
    t[0xA4] = Desc("SHLD_EvIb", ("RM32", "R32", "I8"))
    t[0xA5] = Desc("SHLD_EvCL", ("RM32", "R32", "CL"))
    t[0xA8] = Desc("PUSH_GS", modrm=0)
    t[0xA9] = Desc("POP_GS", modrm=0)
    t[0xAB] = Desc("BTS_EvGv", ("RM32", "R32"), lock=1)
    t[0xAC] = Desc("SHRD_EvIb", ("RM32", "R32", "I8"))
    t[0xAD] = Desc("SHRD_EvCL", ("RM32", "R32", "CL"))
    t[0xAF] = Desc("IMUL_GvEv", ("R32", "RM32"))
    t[0xB0] = Desc("CMPXCHG_EbGb", ("RM8", "R8"), lock=1,
                   note="AL/EAX compare is implicit")
    t[0xB1] = Desc("CMPXCHG_EvGv", ("RM32", "R32"), lock=1,
                   note="AL/EAX compare is implicit")
    t[0xB3] = Desc("BTR_EvGv", ("RM32", "R32"), lock=1)
    t[0xB6] = Desc("MOVZX_GvEb", ("R32", "RM8"))
    t[0xB7] = Desc("MOVZX_GvEw", ("R32", "RM16"))
    t[0xBA] = group_desc("BT group: /0-/3 reserved (see i686_group_tab)")
    t[0xBB] = Desc("BTC_EvGv", ("RM32", "R32"), lock=1)
    t[0xBC] = Desc("BSF_GvEv", ("R32", "RM32"))
    t[0xBD] = Desc("BSR_GvEv", ("R32", "RM32"))
    t[0xBE] = Desc("MOVSX_GvEb", ("R32", "RM8"))
    t[0xBF] = Desc("MOVSX_GvEw", ("R32", "RM16"))
    t[0xC0] = Desc("XADD_EbGb", ("RM8", "R8"), lock=1)
    t[0xC1] = Desc("XADD_EvGv", ("RM32", "R32"), lock=1)
    # RC7b triage T4: 0F C7 /1 CMPXCHG8B m64 (ntdll.so's NtAllocateUuids
    # runs `lock cmpxchg8b`); f0 legal, /1 only.  The m64 EA rides the
    # RM32 modrm plumbing; the handler does the 8-byte access at EA.
    t[0xC7] = Desc("CMPXCHG8B", ("RM32",), lock=1,
                   note="m64 at EA; reg /1, mod!=3 (handler #UDs others)")
    for r in range(8):
        t[0xC8 + r] = Desc("BSWAP_Gv", ("R32",), modrm=0, note="rm=opcode&7")
    # Phase 5 shared spec (docs/lanes/phase-5.md "Generator rows"): SSE2
    # integer + SSE scalar FP over the used 0F map.  One id per opcode
    # byte; the mandatory prefixes (66 -> pfx_opsize, F2/F3 -> pfx_rep)
    # select the family member inside the handler.  Load rows carry
    # (R32, RM32) [reg = xmm dest], store rows (RM32, R32) [rm = dest];
    # plain-map 0F 6C/6D (PUNPCKLQDQ/HQDQ) have no MMX form.  Hardware
    # note: the lane card's "SUB/MUL/DIV (5C/5D/5E)" is corrected to the
    # real map (MUL=59, SUB=5C, DIV=5E; 5D/5F are MIN/MAX, not in v1).
    t[0x10] = Desc("MOVUPS", ("R32", "RM32"),
                   note="load; 66=MOVUPD, F3=MOVSS, F2=MOVSD")
    t[0x11] = Desc("MOVUPS", ("RM32", "R32"),
                   note="store; 66=MOVUPD, F3=MOVSS, F2=MOVSD")
    t[0x12] = Desc("MOVLPS", ("R32", "RM32"),
                   note="low64 <- m64 (mod=3 plain: MOVHLPS); 66=MOVLPD")
    t[0x13] = Desc("MOVLPS", ("RM32", "R32"), note="m64 <- low64; 66=MOVLPD")
    t[0x16] = Desc("MOVHPS", ("R32", "RM32"),
                   note="high64 <- m64 (mod=3 plain: MOVLHPS); 66=MOVHPD")
    t[0x17] = Desc("MOVHPS", ("RM32", "R32"), note="m64 <- high64; 66=MOVHPD")
    t[0x28] = Desc("MOVAPS", ("R32", "RM32"),
                   note="128-bit load (v1: no #GP on unaligned); 66=MOVAPD")
    t[0x29] = Desc("MOVAPS", ("RM32", "R32"),
                   note="128-bit store; 66=MOVAPD")
    t[0x2A] = Desc("CVTPI2PS", ("R32", "RM32"),
                   note="66=CVTPI2PD, F3=CVTSI2SS, F2=CVTSI2SD")
    t[0x2C] = Desc("CVTTPS2PI", ("R32", "RM32"),
                   note="66=CVTTPD2PI, F3=CVTTSS2SI, F2=CVTTSD2SI")
    t[0x2E] = Desc("UCOMISS", ("R32", "RM32"), note="66=UCOMISD")
    t[0x2F] = Desc("COMISS", ("R32", "RM32"), note="66=COMISD")
    t[0x50] = Desc("MOVMSKPS", ("R32", "RM32"),
                   note="66=MOVMSKPD; rm must be a register (mod=3)")
    t[0x54] = Desc("ANDPS", ("R32", "RM32"), note="66=ANDPD")
    t[0x55] = Desc("ANDNPS", ("R32", "RM32"), note="66=ANDNPD")
    t[0x56] = Desc("ORPS", ("R32", "RM32"), note="66=ORPD")
    t[0x57] = Desc("XORPS", ("R32", "RM32"), note="66=XORPD")
    t[0x58] = Desc("ADDPS", ("R32", "RM32"),
                   note="F3=ADDSS, 66=ADDPD, F2=ADDSD")
    t[0x59] = Desc("MULPS", ("R32", "RM32"),
                   note="F3=MULSS, 66=MULPD, F2=MULSD")
    t[0x5A] = Desc("CVTPS2PD", ("R32", "RM32"),
                   note="66=CVTPD2PS, F3=CVTSS2SD, F2=CVTSD2SS")
    t[0x5B] = Desc("CVTDQ2PS", ("R32", "RM32"),
                   note="66=CVTPS2DQ, F3=CVTTPS2DQ")
    t[0x5C] = Desc("SUBPS", ("R32", "RM32"),
                   note="F3=SUBSS, 66=SUBPD, F2=SUBSD")
    t[0x5E] = Desc("DIVPS", ("R32", "RM32"),
                   note="F3=DIVSS, 66=DIVPD, F2=DIVSD")
    t[0x60] = Desc("PUNPCKLBW", ("R32", "RM32"),
                   note="66 = xmm form, plain = MMX")
    t[0x61] = Desc("PUNPCKLWD", ("R32", "RM32"),
                   note="66 = xmm form, plain = MMX")
    t[0x62] = Desc("PUNPCKLDQ", ("R32", "RM32"),
                   note="66 = xmm form, plain = MMX")
    t[0x68] = Desc("PUNPCKHBW", ("R32", "RM32"),
                   note="66 = xmm form, plain = MMX")
    t[0x69] = Desc("PUNPCKHWD", ("R32", "RM32"),
                   note="66 = xmm form, plain = MMX")
    t[0x6A] = Desc("PUNPCKHDQ", ("R32", "RM32"),
                   note="66 = xmm form, plain = MMX")
    t[0x6C] = Desc("PUNPCKLQDQ", ("R32", "RM32"), note="66 only (SSE2)")
    t[0x6D] = Desc("PUNPCKHQDQ", ("R32", "RM32"), note="66 only (SSE2)")
    t[0x6E] = Desc("MOVQ_xmm", ("R32", "RM32"),
                   note="MOVD/MOVQ mm|xmm <- r/m32; 66 = xmm dest, plain = MMX")
    t[0x70] = Desc("PSHUFW", ("R32", "RM32", "I8"),
                   note="66=PSHUFD, F2=PSHUFLW, F3=PSHUFHW; plain = MMX")
    t[0x7E] = Desc("MOVQ_xmm", ("RM32", "R32"),
                   note="r/m32 <- MOVD/MOVQ mm|xmm (66); F3 = MOVQ xmm,xmm/m64")
    t[0xC2] = Desc("CMPPS", ("R32", "RM32", "I8"),
                   note="F3=CMPSS, 66=CMPPD, F2=CMPSD; imm8 predicate")
    t[0xD4] = Desc("PADDQ", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xD5] = Desc("PMULLW", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xDB] = Desc("PAND", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xDF] = Desc("PANDN", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xEB] = Desc("POR", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xEF] = Desc("PXOR", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xF4] = Desc("PMULUDQ", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xFA] = Desc("PSUBD", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xFB] = Desc("PSUBQ", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xFE] = Desc("PADDD", ("R32", "RM32"), note="66 = xmm, plain = MMX")

    # RC7b triage T1 (sanctioned union extension, docs/lanes/phase-7.md):
    # the SSE2 data-movement + integer rows present in the wine32 sysroot
    # binaries (glibc SSE2 memcpy/strcmp/strlen paths).  One id per byte;
    # the plain (unprefixed) forms are the MMX variants of the same row.
    t[0x18] = Desc("PREFETCH", ("RM32",),
                   note="PREFETCHh hint: no memory access, no faults; "
                        "66/F2/F3 forms undefined x86")
    t[0x64] = Desc("PCMPGTB", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0x6F] = Desc("MOVDQA", ("R32", "RM32"),
                   note="load; 66=MOVDQA (#GP on misaligned 16B EA), "
                        "F3=MOVDQU, plain = MMX MOVQ load")
    t[0x7F] = Desc("MOVDQA", ("RM32", "R32"),
                   note="store forms of the 6F row (same rules)")
    t[0x73] = Desc("PSRLDQ", ("R32", "RM32", "I8"),
                   note="66 /2=PSRLDQ /3=PSLLDQ (128-bit byte shifts); "
                        "plain /2=PSRLQ /6=PSLLQ (MMX)")
    t[0x74] = Desc("PCMPEQB", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0x76] = Desc("PCMPEQD", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xD6] = Desc("MOVQ2DQ", ("RM32", "R32"),
                   note="66=MOVQ m64/xmm-low <- xmm.d0; F2=MOVDQ2Q; "
                        "F3=MOVQ2DQ xmm <- mm")
    t[0xD7] = Desc("PMOVMSKB", ("R32", "RM32"),
                   note="r32 <- byte sign mask; mod=3 required; "
                        "66 = 16 bytes, plain = MMX 8")
    t[0xDA] = Desc("PMINUB", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xDE] = Desc("PMAXUB", ("R32", "RM32"), note="66 = xmm, plain = MMX")
    t[0xE7] = Desc("MOVNTDQ", ("RM32", "R32"),
                   note="66=MOVNTDQ m128 (#GP on misaligned 16B EA), "
                        "plain=MOVNTQ m64 (8B); NT = plain store here")
    t[0xF8] = Desc("PSUBB", ("R32", "RM32"), note="66 = xmm, plain = MMX")

    # Phase 5 L5c + SSE lanes: EMMS (x87 tag reset, rides the x87
    # handler set) and the 0F AE group /0-/3 (FXSAVE/FXRSTOR m512 from
    # L5c; LDMXCSR/STMXCSR m32 at /2,/3 from the SSE shared spec).
    # /4-/6 (XSAVE family, LFENCE/MFENCE) stay INVALID; RC7b T1 binds
    # /7 SFENCE (present after NT-store blocks in the sysroot libc).
    t[0x77] = Desc("EMMS", modrm=0, note="x87 tag word reset (MMX done)")
    t[0xAE] = group_desc("0F AE group: FXSAVE /0, FXRSTOR /1, "
                         "LDMXCSR /2, STMXCSR /3, SFENCE /7 "
                         "(see i686_group_tab)")
    return t


class Group:
    __slots__ = ("map0f", "opcode", "ids", "opnds", "lock", "note")

    def __init__(self, map0f, opcode, ids, opnds, lock, note):
        assert len(ids) == 8 and len(opnds) == 8
        self.map0f = map0f
        self.opcode = opcode
        self.ids = ids
        self.opnds = opnds
        self.lock = lock
        self.note = note


def build_groups():
    g = []
    imm = {}
    for f in ALU:
        imm[f] = (f + "_EbIb", f + "_EvIz", f + "_EvIbSX")
    alu8 = [imm[f][0] for f in ALU]
    aluz = [imm[f][1] for f in ALU]
    alusx = [imm[f][2] for f in ALU]
    ebib = ("RM8", "I8")
    eviz = ("RM32", "I32")
    evsx = ("RM32", "I8SX")
    lock_g1 = 0x7F  # ADD..XOR write memory; CMP (/7) never locks
    g.append(Group(0, 0x80, alu8, [ebib] * 8, lock_g1, "G1: 80 Eb,Ib"))
    g.append(Group(0, 0x81, aluz, [eviz] * 8, lock_g1, "G1: 81 Ev,Iz"))
    g.append(Group(0, 0x82, alu8, [ebib] * 8, lock_g1,
                   "G1: 82 alias of 80 (Eb,Ib)"))
    g.append(Group(0, 0x83, alusx, [evsx] * 8, lock_g1, "G1: 83 Ev,Ib sx"))

    # G2 reg slots: /0 ROL /1 ROR /2 RCL /3 RCR /4 SHL /5 SHR /6 SAL (alias
    # of /4 SHL, as on real hardware) /7 SAR.
    g2 = ("ROL", "ROR", "RCL", "RCR", "SHL", "SHR", "SHL", "SAR")
    sh_ib = [f + "_EbIb" for f in g2]
    sh_iv = [f + "_EvIb" for f in g2]
    sh_1b = [f + "_Eb1" for f in g2]
    sh_1v = [f + "_Ev1" for f in g2]
    sh_cb = [f + "_EbCL" for f in g2]
    sh_cv = [f + "_EvCL" for f in g2]
    rm8 = ("RM8",)
    rm32 = ("RM32",)
    g.append(Group(0, 0xC0, sh_ib, [("RM8", "I8")] * 8, 0, "G2: C0 Eb,Ib"))
    g.append(Group(0, 0xC1, sh_iv, [("RM32", "I8")] * 8, 0, "G2: C1 Ev,Ib"))
    g.append(Group(0, 0xD0, sh_1b, [("RM8", "ONE")] * 8, 0, "G2: D0 Eb,1"))
    g.append(Group(0, 0xD1, sh_1v, [("RM32", "ONE")] * 8, 0, "G2: D1 Ev,1"))
    g.append(Group(0, 0xD2, sh_cb, [("RM8", "CL")] * 8, 0, "G2: D2 Eb,CL"))
    g.append(Group(0, 0xD3, sh_cv, [("RM32", "CL")] * 8, 0, "G2: D3 Ev,CL"))

    test8 = ("RM8", "I8")
    testz = ("RM32", "I32")
    g3_8 = ["TEST_EbIb", "TEST_EbIb", "NOT_Eb", "NEG_Eb",
            "MUL_Eb", "IMUL_Eb", "DIV_Eb", "IDIV_Eb"]
    g3_z = ["TEST_EvIz", "TEST_EvIz", "NOT_Ev", "NEG_Ev",
            "MUL_Ev", "IMUL_Ev", "DIV_Ev", "IDIV_Ev"]
    g3_8_opnds = [test8, test8] + [rm8] * 6
    g3_z_opnds = [testz, testz] + [rm32] * 6
    g.append(Group(0, 0xF6, g3_8, g3_8_opnds, 0x0C,
                   "G3: F6 (/1 aliases /0; NOT,NEG lockable)"))
    g.append(Group(0, 0xF7, g3_z, g3_z_opnds, 0x0C,
                   "G3: F7 (/1 aliases /0; NOT,NEG lockable)"))

    g.append(Group(0, 0xFE, ["INC_Eb", "DEC_Eb"] + ["INVALID"] * 6,
                   [rm8, rm8] + [("NONE",)] * 6, 0x03, "G4: FE"))
    g.append(Group(0, 0xFF, ["INC_Ev", "DEC_Ev", "CALL_Ev", "INVALID",
                             "JMP_Ev", "INVALID", "PUSH_Ev", "INVALID"],
                   [rm32] * 3 + [("NONE",)] + [rm32] + [("NONE",)] + [rm32]
                   + [("NONE",)],
                   0x03, "G5: FF (far /3,/5 omitted in v1)"))

    bt = ("RM32", "I8SX")  # bit offset imm8 is sign-extended for Ev
    g.append(Group(1, 0xBA, ["INVALID"] * 4
                   + ["BT_EvIb", "BTS_EvIb", "BTR_EvIb", "BTC_EvIb"],
                   [("NONE",)] * 4 + [bt] * 4, 0xE0,
                   "0F BA: /0-/3 reserved; BT (/4) never locks"))

    # ------------------------------------------------------------------
    # Phase 5 L5c: x87 escape-byte groups.  reg field picks the id; the
    # mod bit selects memory vs ST(i) forms inside the handler (true FP
    # widths live in the id suffix; RM32/RM16 are the closest frozen
    # operand kinds).  Operand kinds are documentation only for x87 rows:
    # the decoder always decodes the modrm byte for group rows and the
    # handlers access guest memory at explicit widths.
    # ------------------------------------------------------------------
    rm32 = ("RM32",)
    rm16 = ("RM16",)
    non = ("NONE",)
    n8 = [non] * 8
    g.append(Group(0, 0xD8,
                   ["FADD_m32", "FMUL_m32", "FCOM_m32", "FCOMP_m32",
                    "FSUB_m32", "FSUBR_m32", "FDIV_m32", "FDIVR_m32"],
                   [rm32] * 8, 0, "x87 D8: ST(0) op= m32fp32 or ST(i)"))
    g.append(Group(0, 0xD9,
                   ["FLD_m32", "FXCH", "FST_m32", "FSTP_m32",
                    "FLDENV", "FLDCW", "FNSTENV", "FNSTCW"],
                   [rm32, non, rm32, rm32, rm32, rm16, rm32, rm16], 0,
                   "x87 D9: loads/stores, env, fixed forms via mod=3 rm"))
    g.append(Group(0, 0xDA,
                   ["FCOM_STi", "FUCOM_STi", "FCOMP_STi", "INVALID",
                    "INVALID", "FUCOMPP", "INVALID", "INVALID"],
                   [non, non, non, non, non, non, non, non], 0,
                   "x87 DA: mod=3 FCOM/FUCOM/FCOMP ST(i) (RC7b T4b); "
                   "DA E9 FUCOMPP; FIADD-class m32 declined"))
    g.append(Group(0, 0xDB,
                   ["FILD_m32", "FISTTP_m32", "FIST_m32", "FISTP_m32",
                    "FNINIT", "FLD_m80", "FCOMI", "FSTP_m80"],
                   [rm32, rm32, rm32, rm32, non, rm32, non, rm32], 0,
                   "x87 DB: FISTTP /1 (RC7b T4b, SSE3 truncate-store); "
                   "FNCLEX/FNINIT via /4 mod=3; FUCOMI rides FLD_m80 mod=3"))
    g.append(Group(0, 0xDC,
                   ["FADD_m64", "FMUL_m64", "FCOM_m64", "FCOMP_m64",
                    "FSUB_m64", "FSUBR_m64", "FDIV_m64", "FDIVR_m64"],
                   [rm32] * 8, 0,
                   "x87 DC: ST(0) op= m64fp64 or ST(i),ST(0) reversed"))
    g.append(Group(0, 0xDD,
                   ["FLD_m64", "FISTTP_m64", "FST_m64", "FSTP_m64",
                    "FUCOM", "FUCOMP", "FNSAVE", "FNSTSW_m16"],
                   [rm32, rm32, rm32, rm32, non, non, rm32, rm16], 0,
                   "x87 DD: FISTTP /1 and FNSAVE /6 m108 (RC7b T4b); "
                   "FRSTOR rides FUCOM /4 memory form; FFREE rides "
                   "FLD_m64 mod=3; FUCOM* mod=3 only"))
    g.append(Group(0, 0xDE,
                   ["FADDP", "FMULP", "INVALID", "INVALID",
                    "FSUBRP", "FSUBP", "FDIVRP", "FDIVP"],
                   [non, non, non, non, non, non, non, non], 0,
                   "x87 DE: ST(i),ST(0) then pop; memory FIADD-class declined"))
    g.append(Group(0, 0xDF,
                   ["FILD_m16", "FISTTP_m16", "FIST_m16", "FISTP_m16",
                    "FNSTSW_AX", "FILD_m64", "FCOMIP", "FISTP_m64"],
                   [rm16, rm16, rm16, rm16, non, rm32, non, rm32], 0,
                   "x87 DF: FISTTP /1 (RC7b T4b), FBLD/FBSTP declined; "
                   "FUCOMIP rides FILD_m64 mod=3"))
    g.append(Group(1, 0xAE,
                   ["FXSAVE", "FXRSTOR", "LDMXCSR", "STMXCSR"]
                   + ["INVALID", "INVALID", "INVALID", "SFENCE"],
                   [rm32, rm32, rm32, rm32, non, non, non, non], 0,
                   "0F AE: FXSAVE /0 and FXRSTOR /1 m512; LDMXCSR /2 and "
                   "STMXCSR /3 m32 (Phase 5 shared spec); /4-/6 (XSAVE "
                   "family, LFENCE/MFENCE) declined; SFENCE /7 (RC7b T1)"))
    return g


# ---------------------------------------------------------------------------
# Emission
# ---------------------------------------------------------------------------

def fmt_row(d, kinds):
    op = "I686_OP_" + d.op
    o = ", ".join("%uu" % kinds[k] for k in (tuple(d.opnd) + ("NONE", "NONE", "NONE"))[:3])
    head = "{ %s, { %s }, %uu, %uu, %uu }," % (
        op, o, d.modrm, d.group, d.lock)
    note = d.note
    if d.group and not note:
        note = "group; see i686_group_tab"
    return head, note


def emit_table(name, table, kinds, invalid_note):
    lines = ["static const i686_insn_desc_t %s[256] = {" % name]
    for b in range(256):
        d = table.get(b)
        if d is None:
            note = (invalid_note(b) if invalid_note else None) or "unassigned"
            row = "{ I686_OP_INVALID, { 0u, 0u, 0u }, 0u, 0u, 0u },"
        else:
            row, note = fmt_row(d, kinds)
            if not note:
                note = None
        if note:
            lines.append("    /* 0x%02X */ %s /* %s */" % (b, row, note))
        else:
            lines.append("    /* 0x%02X */ %s" % (b, row))
    lines.append("};")
    return lines


def emit_groups(groups, kinds):
    lines = [
        "/* Group resolution: the decoder looks up (map0f, opcode) here after",
        " * fetching the modrm byte; reg[reg_field] is the concrete id,",
        " * opnd[reg_field] the authoritative operand kinds, and bit r of",
        " * lockable set if that form may take LOCK with a memory destination",
        " * (group byte descriptors above carry group_op=1 and zero opnd). */",
        "typedef struct {",
        "    uint8_t   map0f;       /* 0 = one-byte map, 1 = 0F two-byte map */",
        "    uint8_t   opcode;      /* group opcode byte                        */",
        "    i686_op_t reg[8];      /* modrm reg field -> concrete opcode id    */",
        "    uint8_t   opnd[8][3];  /* per-reg operand kinds, Intel order       */",
        "    uint8_t   lockable;    /* bit r: reg r form is lockable (mem dest) */",
        "} i686_group_t;",
        "",
        "static const i686_group_t i686_group_tab[] = {",
    ]
    for grp in groups:
        lines.append("    /* %s */" % grp.note)
        lines.append("    { %uu, 0x%02Xu," % (grp.map0f, grp.opcode))
        ids = ["I686_OP_" + i for i in grp.ids]
        lines.append("      { %s, %s, %s, %s," % tuple(ids[0:4]))
        lines.append("        %s, %s, %s, %s }," % tuple(ids[4:8]))
        rows = []
        for opnd in grp.opnds:
            ks = (tuple(opnd) + ("NONE", "NONE", "NONE"))[:3]
            rows.append("{ %s }" % ", ".join("%uu" % kinds[k] for k in ks))
        lines.append("      { %s, %s, %s, %s," % tuple(rows[0:4]))
        lines.append("        %s, %s, %s, %s }," % tuple(rows[4:8]))
        lines.append("      0x%02Xu }," % grp.lock)
    lines.append("};")
    lines.append("")
    lines.append("#define I686_GROUP_TAB_LEN \\")
    lines.append("    ((unsigned)(sizeof(i686_group_tab) / sizeof(i686_group_tab[0])))")
    return lines


HEADER_NOTES = """\
 * Implementation choices (L1a; resolved within the frozen contract):
 *  - The arrays are `static const` in this header so the freeze stays a
 *    single file; every including TU gets its own copy (~4.7 KiB total).
 *    Switch to `extern` plus one insn_tab.c TU if that ever matters.  The
 *    _Static_assert size checks below also mark the tables used in every
 *    TU, keeping -Wall quiet for TUs that only need the types.
 *  - 66/67 prefixes select operand/address width at RUNTIME; the table
 *    always carries the 32-bit kind: RM32 == RMv, I32 == Iz, REL32 == Jz.
 *  - I686_OP_NOP and I686_OP_CBW have no direct opcode byte: 0x90 maps to
 *    XCHG_eAXGv (rm==0, i.e. eAX<->eAX, is reported as NOP by the decoder)
 *    and CBW is `66 98` (the decoder swaps CWDE->CBW when pfx_opsize is
 *    set; `66 99` keeps CDQ, no CWD id exists in v1).
 *  - 0x40-0x4F (INC/DEC r32) reuse INC_Ev/DEC_Ev -- the contract defines
 *    no dedicated ids; the decoder synthesizes mod=3, rm=opcode&7.
 *  - Hardware aliases kept: 82 == 80 (Eb,Ib), G2 /6 == SHL (/4, SAL),
 *    G3 /1 == TEST (/0).  0F BA /0-/3 stay INVALID (reserved on hardware).
 *  - SETcc is 0F 90-9F on real hardware (the lane card's "0F 98-9F" range
 *    is a typo); this table follows the hardware.
 *  - I686_OP_LEA_GvM is not named in the phase-1 identifier list, but 8D
 *    is required for flat-mode code; added for coordinator ratification.
 *  - Left INVALID per the contract (decode -> I686_EXIT_UNDEF, D2):
 *    x87's declined forms (FBLD/FBSTP BCD, the FIADD-class m16/
 *    m32 integer arithmetic and FICOM, and the DA/DE C8-FF undefined
 *    second bytes -- decoded-but-declined modrm forms return UNDEF from
 *    their handlers instead; FISTTP joined via RC7b T4b, FNSAVE/FRSTOR
 *    via RC7b T4b), SSE3+ and the SSE/SSE2 leftovers not in
 *    the Phase 5 or RC7b T1 rows (MIN/MAX 5D/5F, SQRT family 51-53,
 *    0F 2D, SHUFPS 0F C6, ...), BCD (27 2F 37 3F D4-D6),
 *    I/O (E4-E7 EC-EF 6C-6F), far transfers (9A EA CA CB),
 *    LES/LDS (C4 C5), BOUND/ARPL (62 63), PUSH/POP CS/SS (0E 16 17), and
 *    69/6B (IMUL Gv,Ev,Iz/Ib has no v1 contract id).
 *  - Phase 5 (docs/lanes/phase-5.md shared spec): SSE2 integer + SSE
 *    scalar FP families ride ONE id per 0F opcode byte -- the mandatory
 *    prefixes (66 in pfx_opsize, F2/F3 in pfx_rep) select the family
 *    member inside the handler, e.g. I686_OP_ADDPS also covers
 *    ADDSS/ADDPD/ADDSD, I686_OP_MOVQ_xmm covers MOVD/MOVQ loads and
 *    stores, and 0F AE /2,/3 resolve through the group table to
 *    LDMXCSR/STMXCSR.  Hardware map correction: MULPS is 0F 59 (the
 *    lane card's "SUB/MUL/DIV (5C/5D/5E)" miscounted; 5D/5F are the
 *    MIN/MAX families, not in v1).
 *  - Phase 5 L5c x87 resolution: D8-DF are GROUP rows resolved by the
 *    modrm reg field (one id per /digit); the mod bit selects memory vs
 *    ST(i) register forms inside src/interp/h_x87.c, and the mod=3
 *    fixed second-byte forms (D9 C0-FF families, DB E2/E3/E8+i/F0+i,
 *    DF E0/E8+i/F0+i, DD C0+i) sub-dispatch on modrm_rm in the owning
 *    slot's handler.  Operand kinds on x87 rows are documentation only:
 *    RM32/RM16 stand for m32fp/m64fp/m80/m16/m512 (no 64/80-bit frozen
 *    kinds exist) and NONE marks implicit-stack forms.
 *  - RC7b triage T1 (sanctioned union extension, docs/lanes/phase-7.md):
 *    the SSE2 data-movement + integer rows the wine32 sysroot binaries
 *    (dash, ld-linux.so.2, glibc 2.44 libc.so.6) actually execute
 *    joined the union, one id per 0F byte as above: MOVDQA/MOVDQU +
 *    MMX MOVQ (6F load / 7F store rows, one id), MOVQ2DQ (D6: 66/F2/F3
 *    forms), MOVNTDQ/MOVNTQ (E7), PSRLDQ/PSLLDQ + MMX PSRLQ/PSLLQ (73),
 *    PCMPGTB (64), PCMPEQB (74), PCMPEQD (76), PMOVMSKB (D7), PMINUB
 *    (DA), PMAXUB (DE), PSUBB (F8), PREFETCHh (18; hint-NOP, no memory
 *    access, no faults), and SFENCE via the 0F AE group /7 slot (fence
 *    = no-op in the single-threaded TSO guest model).  66 0F 6F/7F and
 *    the NT stores raise #GP(0) (trapno 13 via the seg-fault path,
 *    eip unadvanced) on misaligned EAs in the interpreter; MOVAPS keeps
 *    its documented v1 no-fault behavior, and the DBT emits plain Q
 *    moves/stores without the alignment check (documented deviation).
 *    Still left INVALID: the three-byte maps 0F 38/0F 3A (SSSE3/SSE4,
 *    CPUID-gated off under the v1 feature set), 0F 01 (RDPKRU/XGETBV,
 *    system class, OSXSAVE-gated), 0F C7 (XSAVEC), 0F AE /4-/6 (XSAVE
 *    family; LFENCE/MFENCE not present in the targets), PCMPEQW 75
 *    (present nowhere in the targets), and every row not appearing in
 *    the sweep (MIN/MAX 5D/5F, SQRT 51-53, PACK/PCMPGTW-D, ...).
"""


def generate():
    kinds = load_opnd_kinds()
    sections = contract_ids()
    ids = [i for _, sec in sections for i in sec]
    # EMMS is listed in both the SSE/MMX and x87 sections (one id, two
    # contract lists -- same convention as CALL_Ev/JMP_Ev/PUSH_Ev).
    dups = sorted({i for i in ids if ids.count(i) > 1} - {"EMMS"})
    if dups:
        raise SystemExit("duplicate contract ids: %r" % dups)
    ids = sorted(set(ids))
    if len(ids) != 366:
        raise SystemExit("expected 366 contract ids (+S1 IMUL +S4 RDTSC "
                         "+S5 x87 54 +S5 SSE 42 +RC7b T1 SSE2 movement 13 "
                         "+RC7b T4 CMPXCHG8B +RC7b T4b FISTTP 3 +FNSAVE "
                         "+DA mod3 FCOM/FUCOM/FCOMP 3), "
                         "got %d" % len(ids))

    oneb = build_oneb()
    twob = build_twob()
    groups = build_groups()

    # Structural validation before emitting anything.
    idset = set(ids)
    used = set()
    for name, tab in (("1b", oneb), ("0f", twob)):
        for b, d in tab.items():
            if not d.group:
                if d.op not in idset:
                    raise SystemExit("%s[0x%02X]: unknown id %s" % (name, b, d.op))
                used.add(d.op)
            for k in d.opnd:
                if k not in kinds:
                    raise SystemExit("unknown operand kind %r" % k)
    for grp in groups:
        for i in grp.ids:
            if i == "INVALID":
                continue
            if i not in idset:
                raise SystemExit("group 0x%02X: unknown id %s" % (grp.opcode, i))
            used.add(i)
    # Ids intentionally not bound to any opcode byte or group slot.
    unused = idset - used
    if unused != {"NOP", "CBW"}:
        raise SystemExit("unexpected enum-only ids: %r" % sorted(unused))
    for byte in PREFIX_BYTES:
        oneb.setdefault(byte, invalid("prefix (handled by the decoder)"))
    # 0xD8-0xDF are explicit x87 group rows now (Phase 5 L5c); the old
    # "x87: excluded in v1" defaults are gone.

    out = []
    out.append("/*")
    out.append(" * src/x86/insn_tab.h -- GENERATED by tools/gen_insn_tab.py; DO NOT EDIT.")
    out.append(" *")
    out.append(" * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.")
    out.append(" * SPDX-License-Identifier: Apache-2.0")
    out.append(" *")
    out.append(" * Frozen opcode-id contract (docs/lanes/phase-1.md, lane L1a):")
    out.append(" * i686_op_t, i686_insn_desc_t, i686_insn_tab_1b[256],")
    out.append(" * i686_insn_tab_0f[256], and i686_group_tab[].  Operand kinds in")
    out.append(" * opnd[] are I686_OPND_* VALUES in Intel order (dest first); they are")
    out.append(" * emitted numerically because decode.h includes this header before its")
    out.append(" * I686_OPND_* enum.  Legend (must match src/x86/decode.h):")
    for i in range(0, len(KIND_ORDER), 6):
        chunk = KIND_ORDER[i:i + 6]
        out.append(" *   " + "  ".join("%2d %s" % (kinds[k], k) for k in chunk))
    out.append(" *")
    out.append(" * Descriptor fields: op = i686_op_t; opnd[3] = operand kinds;")
    out.append(" * modrm = 1 if the encoding carries modrm-encoded operands (real or")
    out.append(" * synthesized per the row note); group_op = 1 for group bytes whose")
    out.append(" * concrete id lives in i686_group_tab; lockable = 1 if the form may")
    out.append(" * take LOCK with a memory destination.")
    out.append(" *")
    out.append(HEADER_NOTES.rstrip("\n"))
    out.append(" */")
    out.append("")
    out.append("#ifndef %s" % GUARD)
    out.append("#define %s" % GUARD)
    out.append("")
    out.append("#include <stdint.h>")
    out.append("")
    out.append("/* Opcode ids (i686_op_t); value 0 is reserved for unassigned bytes. */")
    out.append("typedef enum {")
    out.append("    I686_OP_INVALID = 0,")
    seen = {"INVALID"}
    for title, sec in sections:
        out.append("")
        out.append("    /* %s */" % title)
        fresh = [x for x in sec if x not in seen]
        seen.update(fresh)
        for i in range(0, len(fresh), 4):
            out.append("    " + ", ".join("I686_OP_" + x for x in fresh[i:i + 4]) + ",")
    out.append("} i686_op_t;")
    out.append("")
    out.append("#define I686_OP_COUNT %du /* including I686_OP_INVALID */" % (len(ids) + 1))
    out.append("")
    out.append("/* Per-opcode descriptor (frozen in docs/lanes/phase-1.md). */")
    out.append("typedef struct {")
    out.append("    uint16_t op;        /* i686_op_t                                */")
    out.append("    uint8_t  opnd[3];   /* I686_OPND_* kinds, Intel order (dest 1st) */")
    out.append("    uint8_t  modrm;     /* 1 if modrm-encoded operands apply        */")
    out.append("    uint8_t  group_op;  /* 1 if a group byte: resolve via group tab */")
    out.append("    uint8_t  lockable;  /* 1 if LOCK legal with a memory dest       */")
    out.append("} i686_insn_desc_t;")
    out.append("")

    def inote_1b(b):
        return ONEB_INVALID.get(b)

    out += emit_table("i686_insn_tab_1b", oneb, kinds, inote_1b)
    out.append("")

    def inote_0f(b):
        if b in TWOB_INVALID and TWOB_INVALID[b]:
            return TWOB_INVALID[b]
        for lo, hi, why in TWOB_INVALID_RANGES:
            if lo <= b <= hi:
                return why
        return None

    out += emit_table("i686_insn_tab_0f", twob, kinds, inote_0f)
    out.append("")
    out.append("/* Sanity: complete 256-entry maps (also marks the tables used in")
    out.append(" * every including TU, so -Wunused-const-variable stays quiet). */")
    out.append("_Static_assert(sizeof(i686_insn_tab_1b) / sizeof(i686_insn_tab_1b[0]) == 256u,")
    out.append("               \"i686_insn_tab_1b must have 256 rows\");")
    out.append("_Static_assert(sizeof(i686_insn_tab_0f) / sizeof(i686_insn_tab_0f[0]) == 256u,")
    out.append("               \"i686_insn_tab_0f must have 256 rows\");")
    out.append("")
    out += emit_groups(groups, kinds)
    out.append("")
    out.append("_Static_assert(sizeof(i686_group_tab) / sizeof(i686_group_tab[0]) == %du," % len(groups))
    out.append("               \"i686_group_tab row count changed\");")
    out.append("")
    out.append("#endif /* %s */" % GUARD)
    return "\n".join(out) + "\n"


def main(argv):
    out_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_OUT
    text = generate()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(text, encoding="utf-8")
    print("wrote %s (%d bytes)" % (out_path, len(text.encode("utf-8"))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
