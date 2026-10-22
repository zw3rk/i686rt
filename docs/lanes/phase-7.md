# Phase 7 — Wine-style LDT (L7a → S7/RC7; L7b wine smoke → RC7b)

SPEC §4 7.1–7.3, §2 D8, E09 verdict ( Wine uses modify_ldt func 0x11 +
set_thread_area only; LDT 8192, entries 0..31 reserved; free = all-zero
not-present entry; far transfers and fault surfaces as listed ).

## Coordinator freeze (7.1 — binding for the fan-out)

- src/interp/seg.h is FROZEN (committed with the ctx tail extension:
  cs_d, v86, v86state appended; `ctx->ldt` now holds `i686_segstate_t*`).
  Lanes implement against it and never edit it.
- Effective addressing with segments: linear32 = (uint32_t)
  (seg_base[seg] + offset) — segment base added AFTER the 16/32-bit
  offset computation, wrapping in 32 bits (D4/D7); the window base xG
  is added after that as today. Default segment per opcode class per
  SDM (SS for ESP-based, DS otherwise); override prefixes select
  es/cs/ss/ds/fs/gs.
- Decode defaults: operand/address defaults come from ctx->cs_d
  (1 = 32-bit, set at process start for flat CS). Prefixes 66/67
  invert per instruction as today. vm86 (Phase 8) reuses this by
  setting cs_d=0 while active.
- Engines (D8): non-flat CS, LDT selector in CS, or v86 active →
  interpreter only. Guard: engine dispatch checks
  i686_seg_flat_cs(ctx) && !ctx->v86 before running/caching blocks;
  flat processes are unaffected.
- Fault surface: #GP trapno 13 / #NP trapno 11 / #SS trapno 12 with
  error code = selector bits, delivered through the existing sync
  fault path (signals_i386.c), guest IP at the faulting instruction.
  Privileged instructions in 16-bit code (cli/sti/in/out/hlt/mov
  cr/dr) fault the same way (E09 gap list). int NN (NN != 0x80) in
  non-flat code = resolvable fault (E09), IP at the int.
- Sigcontext round-trip via i686_seg_sc_encode/sc_decode; wiring into
  signals_i386.c happens at S7 merge (coordinator) to keep file
  ownership exclusive.
- Syscall registration (123 modify_ldt, 243/244 set/get_thread_area):
  handler functions land in src/os/ldt.c; the 3-line dispatch wiring
  into the syscall table is done by the coordinator at S7 merge — the
  lane documents the exact snippet in its record.

## Card L7a — descriptor model implementation (grunt lane)

- Scope: implement seg.h completely: src/interp/seg.c (lookup/load/
  flat defaults/generation), src/interp/h_seg.c (segment-register
  moves 8C/8E, pops 07/17/1F, les/lds/lss/lfs/lgs C4/C5/0F B2/B4/B5,
  far call/jmp 9A/EA, lret CB incl. 0x66 cross-size, non-v86 iret CF,
  int NN fault path, privileged-instruction faults), src/os/ldt.c
  (modify_ldt funcs 0/1/0x11/2, set/get_thread_area with -1
  auto-alloc), tests/test_p7_ldt.c + fixture. Bounded edits: decode.c
  (far-op operands m16:16/m16:32, cs_d defaults, segment-override EA
  plumbing), engine.c (flat/v86 guard), flags on far transfers.
  16-bit operand/address execution uses existing handlers — widths
  already parameterised; defaults come from cs_d.
- Worktree ../i686rt-l7a, branch lane/7-l7a. Files owned (exclusive):
  src/interp/seg.c, src/interp/h_seg.c, src/os/ldt.c,
  tests/test_p7_ldt.c. Bounded: src/x86/decode.c, src/dbt/engine.c,
  Makefile (objects), tests/golden untouched.
- Fixture (SPEC 7.2): install LDT data + 16-bit code descriptors via
  modify_ldt 0x11; load %fs/%es from LDT; far call into 16-bit code
  and back (m16:16); access memory via %fs base; fault on limit
  overrun (expect SIGSEGV trapno 13); set_thread_area -1 alloc +
  %gs load. Print PASS at the end (pattern: test_p4 fixtures).
- Acceptance check (single command, arm64 docker):
  build fixture with tools/build_fixture.sh, then
  `/w/i686rt -- /w/test_p7_ldt` → last line `PASS`
  (engine=interp default is fine; DBT must stay eligible-flat only).
- Escalate after 2 failed attempts / any frozen-interface change
  (seg.h, i686rt.h) / ambiguity. No scope widening; never push; no AI
  mentions in commits.

## Card L7b — Wine32 sysroot smoke (dispatched after S7)

tools/setup-wine32.sh fetching Debian i386 wine (non-wow64) per the
setup_sysroot.py pattern; triage list for RC7b. Owned: the script +
docs/lanes/phase-7.md L7b record only.

## S7/RC7 (coordinator)

Merge L7a (--no-ff), wire syscall registration + sigframe sc_encode/
sc_decode + far-int fault delivery, run RC7: `test_p7_ldt` prints PASS
(lima stand-in: arm64 docker container — recorded deviation as in
RC1–RC5). RC7b after L7b: `wine cmd /c echo ok`.
