# Phase 1 — interpreter hello lane cards (frozen by the coordinator)

Frozen on master (read-only to lanes): `src/i686rt.h` (ctx + I686_EXIT_*),
`src/x86/decode.h` (x86_insn_t, I686_OPND_*, decoder API),
`src/interp/interp.h` (handler signature, registry, module inits),
`src/interp/flags.h` (lazy-flags API), `src/rt32/**` (Phase 0 output),
`src/main.c`, `Makefile`, `flake.nix`, SPEC.md, AGENTS.md, this file.
Reference: `../a32rt` @ d84feb3 (read-only).

Common lane rules: as Phase 0 (worktree/branch only, never push, Curated
C11, one commit after the check passes, escalate after 2 failed check
attempts / needed file outside ownership / ambiguity). Cross-compile checks
use `nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc`
with `CC=aarch64-unknown-linux-musl-gcc` (gcc-flavored; see the Phase 0
amendment note). Host-native unit checks use macOS `clang`.

## Frozen opcode-id contract (L1a generates; L1b–L1e implement)

`src/x86/insn_tab.h` (generated; format below) defines `i686_op_t` enum
identifiers `I686_OP_<NAME>` and tables `i686_insn_tab_1b[256]` /
`i686_insn_tab_0f[256]` of `i686_insn_desc_t { uint16_t op; uint8_t
opnd[3]; uint8_t modrm; uint8_t group_op; uint8_t lockable; }`.
`opnd[i]` are `I686_OPND_*` kinds in Intel order (dest first).

### Naming + expansion rules (deterministic)

- ALU families `ADD OR ADC SBB AND SUB XOR CMP`: forms `_EbGb _EvGv _GbEb
  _GvEv _ALIb _eAXIz` (TEST: only `_EbGb _EvGv _ALIb _eAXIz`). Immediate
  forms via group G1 (opcodes 80–83), RESOLVED AT DECODE TABLE LEVEL into
  `I686_OP_<F>_EbIb`, `I686_OP_<F>_EvIz`, `I686_OP_<F>_EvIbSX` (82 alias
  → same as 80). So each ALU mnem has 9 ids (TEST/CMP have no EbIb group
  form difference: TEST gets `_EbIb`? no — TEST G3: `TEST_EbIb`,
  `TEST_EvIz` from F6/F7).
- Shift/rotate `ROL ROR RCL RCR SHL SHR SAR`: forms `_Eb1 _Ev1 _EbCL
  _EvCL _EbIb _EvIb` (C0–D3 group G2 resolved) — 6 ids each, 42 total.
- G3 (F6/F7) resolved: `TEST_EbIb TEST_EvIz NOT_Eb NOT_Ev NEG_Eb NEG_Ev
  MUL_Eb MUL_Ev IMUL_Eb IMUL_Ev DIV_Eb DIV_Ev IDIV_Eb IDIV_Ev`.
- G4 (FE): `INC_Eb DEC_Eb`; G5 (FF): `INC_Ev DEC_Ev CALL_Ev JMP_Ev
  PUSH_Ev` (far forms reg 3/5 omitted in v1).
- MOV: `MOV_EbGb MOV_EvGv MOV_GbEb MOV_GvEv MOV_ALOb MOV_eAXOv MOV_ObAL
  MOV_OveAX MOV_GbIb MOV_GvIv MOV_EbIb MOV_EvIz MOV_EwSw MOV_SwEw` (B0–
  BF use rm as reg; moffs forms have no modrm).
- Stack: `PUSH_Gv POP_Gv PUSH_Iz PUSH_Ib PUSHA POPA PUSHF POPF ENTER LEAVE
  PUSH_ES POP_ES PUSH_DS POP_DS PUSH_FS POP_FS PUSH_GS POP_GS PUSH_Ev POP_Ev`.
- XCHG: `XCHG_EbGb XCHG_EvGv XCHG_eAXGv` (90 = XCHG_eAXGv with rm=0 ==
  NOP; decoder emits `NOP` when rm==0).
- Flags/misc: `NOP CMC CLC STC CLI STI CLD STD SAHF LAHF CBW CWDE CDQ
  XLAT HLT WAIT UD2 CPUID SYSENTER CMPXCHG_EbGb CMPXCHG_EvGv XADD_EbGb
  XADD_EvGv BSWAP_Gv LEA_GvM MOVZX_GvEb MOVZX_GvEw MOVSX_GvEb MOVSX_GvEw`.
- Branches: `JMP_Jb JMP_Jz JMP_Ev CALL_Jz CALL_Ev RET RET_Iw` plus family
  ids with the condition in `modrm_reg`: `JCC_Jb JCC_Jz SETcc_Eb CMOVcc_Gv`
  and `LOOPNZ_Jb LOOPZ_Jb LOOP_Jb JCXZ_Jb` (family ids cover their opcode
  ranges 70–7F / 0F 80–8F / 0F 98–9F / 0F 40–4F; cond = 0..15).
- Bit ops: `BT_EvGv BTS_EvGv BTR_EvGv BTC_EvGv BSF_GvEv BSR_GvEv BT_EvIb
  BTS_EvIb BTR_EvIb BTC_EvIb SHLD_EvIb SHLD_EvCL SHRD_EvIb SHRD_EvCL
  IMUL_GvEv`.
- Strings (with REP handled via pfx_rep): `MOVSb MOVSw CMPSb CMPSw STOSb
  STOSw LODSb LODSw SCASb SCASw`.
- Int/trap: `INT_Ib INT3 INTO IRET` (INTO/IRET decode-only in v1: IRET
  lands Phase 4, INTO → UNDEF handler).
- NOT in v1 tables (decode → I686_EXIT_UNDEF per D2): x87 (D8–DF, 0F
  1x/2x/5x–7x/Ex), SSE (0F 10–1F, 5x, 6x except listed), DAA/AAA/BCD
  (27 2F 37 3F D4 D5 D6), I/O (E4–E7 EC–EF, 6C–6F), far transfers (9A EA
  CA CB, LES/LDS C4 C5), ARPL/BOUND/etc, 0F 0B UD2 **is** included.
- 0F 34 = SYSENTER (syscall exit per D12), 0F 35 not in v1.

### Descriptor `opnd[]` conventions

Register-only forms use `I686_OPND_R8/R16/R32` (reg field, rm==0 when
single-reg opcode like B8+r: decoder puts the register in modrm_reg).
Immediate forms: `RM* + I8/I8SX/I16/I32` as Intel order dictates.
`modrm`=1 for every encoding with modrm; `lockable`=1 for lockable RMW
destinations (mem forms of ALU + cmpxchg/xadd + btc forms).

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L1a | `lane/1-l1a` `../i686rt-l1a` | `tools/gen_insn_tab.py`, `src/x86/insn_tab.h` (generated, committed), `tools/gen_insn_tab.py` unit test `tools/test_insn_tab.py` | `python3 tools/gen_insn_tab.py src/x86/insn_tab.h && python3 tools/test_insn_tab.py` → `L1A OK` |
| L1b | `lane/1-l1b` `../i686rt-l1b` | `src/interp/h_alu.c`, `src/interp/h_flagsops.c` | cross-compile both + host unit `tests/unit/test_l1b` → `L1B OK` |
| L1c | `lane/1-l1c` `../i686rt-l1c` | `src/interp/h_mov.c`, `src/interp/h_string.c` | cross-compile + host unit `tests/unit/test_l1c` → `L1C OK` |
| L1d | `lane/1-l1d` `../i686rt-l1d` | `src/interp/h_branch.c`, `src/interp/h_bit.c` | cross-compile + host unit `tests/unit/test_l1d` → `L1D OK` |
| L1e | `lane/1-l1e` `../i686rt-l1e` | `src/interp/h_muldiv.c`, `src/interp/h_shift.c` | cross-compile + host unit `tests/unit/test_l1e` → `L1E OK` |
| L1f | `lane/1-l1f` `../i686rt-l1f` | `tools/gen_syscall_tab.py`, `src/os/syscalls_i386.h` (generated), `src/os/syscalls.c` | cross-compile syscalls.c + `python3 tools/gen_syscall_tab.py src/os/syscalls_i386.h && grep -c` → `L1F OK` |
| L1g | `lane/1-l1g` `../i686rt-l1g` | `tests/hello.c`, `tests/test_p1_isa.c`, `tools/build_fixture.sh`, `Makefile` (append test-p1 targets) | `tools/build_fixture.sh tests/test_p1_isa.c _build/test_p1_isa && docker run --rm -v "$PWD/_build:/w" --platform linux/386 alpine /w/test_p1_isa` → prints `PASS` (native-oracle self-check) |

Notes:
- Handler lanes code against the frozen headers; `insn_tab.h` is generated
  by L1a — until it exists on master, handler lanes create a PRIVATE
  minimal stub `src/x86/insn_tab.h` inside their worktree ONLY for their
  unit tests if needed, and MUST delete it before committing (their commit
  contains only their owned files; the real header comes from L1a at S1).
  Unit drivers under `tests/unit/` construct `x86_insn_t` values by hand.
- `syscalls.c` uses `rt32_vm_*` for brk/mmap2 and implements: write(4),
  exit(1), exit_group(252), brk(45), mmap2(192), set_thread_area(243
  flat: base into `ctx->seg_base[I686_SEG_GS]` + gdt_tls_slots), uname(122,
  i386 6×65 layout, machine "i686"). Unimplemented → `-ENOSYS` in EAX.
- The coordinator implements in parallel: `src/x86/decode.c`,
  `src/interp/interp.c`, `src/interp/flags.c`, `src/x86/cpuid.c`, and the
  main.c engine wiring (`rt32_elf_load` + `rt32_stack_setup` + interp run +
  syscall dispatch). S1 merges everything and runs RC1
  (`make test-p1-lima` → `PASS` under lima).
