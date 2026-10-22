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
    0x10: "SSE excluded", 0x11: "SSE excluded", 0x12: "SSE excluded",
    0x13: "SSE excluded", 0x14: "SSE excluded", 0x15: "SSE excluded",
    0x16: "SSE excluded", 0x17: "SSE excluded", 0x18: "SSE excluded",
    0x19: "SSE excluded", 0x1A: "SSE excluded", 0x1B: "SSE excluded",
    0x1C: "SSE excluded", 0x1D: "SSE excluded", 0x1E: "SSE excluded",
    0x1F: "SSE excluded (NOP variant)",
    0x20: "MOV Cd/Td: excluded", 0x21: "", 0x22: "", 0x23: "",
    0x24: "MOV Rd/Td test: excluded", 0x25: "", 0x26: "", 0x27: "",
    0x28: "MOV Rd/Dd: excluded", 0x29: "", 0x2A: "", 0x2B: "",
    0x2C: "", 0x2D: "", 0x2E: "", 0x2F: "",
    0x30: "WRMSR: excluded", 0x31: "RDTSC: excluded", 0x32: "RDMSR: excluded",
    0x33: "",
    0x35: "SYSEXIT: not in v1",
    0x50: "SSE excluded", 0x51: "SSE excluded", 0x52: "SSE excluded",
    0x53: "SSE excluded", 0x54: "SSE excluded", 0x55: "SSE excluded",
    0x56: "SSE excluded", 0x57: "SSE excluded", 0x58: "SSE excluded",
    0x59: "SSE excluded", 0x5A: "SSE excluded", 0x5B: "SSE excluded",
    0x5C: "SSE excluded", 0x5D: "SSE excluded", 0x5E: "SSE excluded",
    0x5F: "SSE excluded",
    0x60: "SSE excluded", 0x61: "SSE excluded", 0x62: "SSE excluded",
    0x63: "SSE excluded", 0x64: "SSE excluded", 0x65: "SSE excluded",
    0x66: "SSE excluded", 0x67: "SSE excluded", 0x68: "SSE excluded",
    0x69: "SSE excluded", 0x6A: "SSE excluded", 0x6B: "SSE excluded",
    0x6C: "SSE excluded", 0x6D: "SSE excluded", 0x6E: "SSE excluded",
    0x6F: "SSE excluded",
    0x70: "SSE excluded", 0x71: "SSE excluded", 0x72: "SSE excluded",
    0x73: "SSE excluded", 0x74: "SSE excluded", 0x75: "SSE excluded",
    0x76: "SSE excluded", 0x77: "SSE excluded", 0x78: "SSE excluded",
    0x79: "SSE excluded", 0x7A: "SSE excluded", 0x7B: "SSE excluded",
    0x7C: "SSE excluded", 0x7D: "SSE excluded", 0x7E: "SSE excluded",
    0x7F: "SSE excluded",
    0xA6: "reserved", 0xA7: "reserved",
    0xAA: "RSM: excluded", 0xAE: "excluded",
    0xB2: "reserved", 0xB4: "reserved", 0xB5: "reserved",
    0xB8: "reserved (POP gs variant)", 0xB9: "reserved group",
    0xC2: "SSE excluded", 0xC3: "SSE excluded", 0xC4: "SSE excluded",
    0xC5: "SSE excluded", 0xC6: "SSE excluded", 0xC7: "SSE excluded",
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
                    (0xFF, "G5 (see i686_group_tab)")):
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
    for r in range(8):
        t[0xC8 + r] = Desc("BSWAP_Gv", ("R32",), modrm=0, note="rm=opcode&7")
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
 *    x87 (D8-DF, 0F 0x/1x/2x/5x-7x/Ex), SSE, BCD (27 2F 37 3F D4-D6),
 *    I/O (E4-E7 EC-EF 6C-6F), far transfers (9A EA CA CB), LES/LDS
 *    (C4 C5), BOUND/ARPL (62 63), PUSH/POP CS/SS (0E 16 17), and
 *    69/6B (IMUL Gv,Ev,Iz/Ib has no v1 contract id).
"""


def generate():
    kinds = load_opnd_kinds()
    sections = contract_ids()
    ids = [i for _, sec in sections for i in sec]
    if len(ids) != len(set(ids)):
        dup = sorted({i for i in ids if ids.count(i) > 1})
        raise SystemExit("duplicate contract ids: %r" % dup)
    if len(ids) != 249:
        raise SystemExit("expected 249 contract ids (+S1 IMUL +S4 RDTSC), got %d" % len(ids))

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
    for byte in range(0xD8, 0xE0):
        oneb.setdefault(byte, invalid("x87: excluded in v1"))

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
    for title, sec in sections:
        out.append("")
        out.append("    /* %s */" % title)
        for i in range(0, len(sec), 4):
            out.append("    " + ", ".join("I686_OP_" + x for x in sec[i:i + 4]) + ",")
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
