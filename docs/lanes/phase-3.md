# Phase 3 — DBT core lane cards (frozen by the coordinator)

Frozen on master (read-only to lanes): `src/dbt/emit.h` (emitter API,
register map D7, exit protocol), `src/dbt/translate.c` (block driver:
max 64 insns, page-end termination, category dispatch order
alu→mov→branch→string, D2 fallback via UNDEF exit with insn len),
`src/dbt/emit_stubs.c` (coordinator v1 stubs — the engine compiles and
runs with pure interpret-one fallback), `src/trampoline.S`
(i686_jit_run_block; w0..w7=EAX..EDI, x19=xCtx, x20=xG),
`src/rt32/rt32_a64_emit.h/.c` (A64 encoder), all Phase 0–2 sources,
SPEC.md, this file.

Common rules: as before (worktree/branch only; never push; Curated C11
zero-warning under the cross gcc; one commit after the check; escalate
after 2 failed attempts / needed file outside ownership / ambiguity).
Cross-compile: `nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc`
with `CC=aarch64-unknown-linux-musl-gcc`.

## DBT conventions binding all emitter lanes

- Register map (D7): w0..w7 = ctx->gpr[0..7] (EAX..EDI); x19 = ctx
  (callee-saved from trampoline), x20 = xG; x21+ scratch. 8-bit high
  registers (AH..BH) = bits 15:8 of the SAME wN. 16-bit ops mask to
  0xFFFF and preserve the upper half.
- Memory: EA computed in a scratch reg then `ldrb/ldrh/ldr wX, [x20, xa]`
  (or str*), with `uextw` semantics: guest EA wraps in 32 bits BEFORE the
  add; uxtw addressing on [x20, wX] gives exactly that. TSO mode (D5,
  e->tso, static): GPR loads LDAPR/STLR class (a64_emit helpers where
  present; else ldar/stlr); vector/plain otherwise. LOCK prefix: LDAPR-
  class + LSE atomics for the RMW op is Phase 4 (L4c); in Phase 3 emit
  the non-locked semantics and return 0 (single-threaded correctness).
- Lazy flags (D6): ALU cmp/test/sub/add emit SUBS/ADDS/ANDS setting
  NZCV in-block; jcc/setcc/cmovcc fuse directly on NZCV. ADC/SBB and
  byte/word flags that NZCV cannot express: end the block with a helper
  call to the C materializer (declare extern, call via x-auth reg; the
  exact helper ABI is src/dbt/flags_dbt.h — coordinator-owned, see
  below) — v1 lanes MAY simply decline those insns (return -1) and let
  the D2 interpreter fallback handle them; declining is safe.
- Declining (return -1) is always safe: translate.c emits UNDEF+length
  and the engine interprets one insn. Correctness beats coverage in v1.
- Epilogue: `i686_emit_exit(e, reason, arg, dest)` — the lane-owned
  implementation lives in src/dbt/emit_exit.c (L3a owns the file; all
  lanes code against the frozen signature). Branch module: taken
  branches emit the exit with the computed target; fallthrough exits
  with dest=next_pc.

| Lane | Branch/worktree | Owns | Check (once) |
|---|---|---|---|
| L3a | `lane/3-l3a` `../i686rt-l3a` | `src/dbt/emit_exit.c`, `src/dbt/emit_alu.c`, `src/dbt/emit_ea.c` | cross-compile + `tests/unit/test_l3a` prints `L3A OK` |
| L3b | `lane/3-l3b` `../i686rt-l3b` | `src/dbt/emit_mov.c` | → `L3B OK` |
| L3c | `lane/3-l3c` `../i686rt-l3c` | `src/dbt/emit_branch.c`, `src/dbt/emit_string.c` | → `L3C OK` |
| L3d | `lane/3-l3d` `../i686rt-l3d` | `tools/difftest.sh`, `tools/difftrace.py`, Makefile append | → `L3D OK` |

## Card L3a — shared exits, EA, ALU emitters

- `emit_exit.c`: i686_emit_begin/finish/exit/ea. exit: store w0..w7 to
  [x19, #0..28] (stp pairs), movz w8,#reason; str w8,[x19,#120]; str
  w9(arg),[x19,#124]; str w10(dest),[x19,#132]; also store EIP when
  reason==BRANCH into [x19,#32]; ret. i686_emit_ea per emit.h (compute
  base+index<<scale+disp into w21 with uxtw, optionally add seg base
  via ldr w22,[x19, #40 + 4*seg]).
- `emit_alu.c`: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP/TEST reg+mem forms,
  INC/DEC/NEG/NOT reg forms, IMUL two/three-op reg forms, shifts by
  imm reg forms. NZCV fusion for cmp/test/sub/add per the conventions;
  decline adc/sbb/byte-flag consumers you cannot fuse (v1).
- Unit test: run the DBT on curated micro-blocks under the host?? — NO:
  DBT code is A64; the check must EXECUTE on the arm64 docker VM. The
  lane check builds a small driver (tests/unit/test_l3a.c) that the
  CARD RUNNER (the lane) executes inside docker arm64 via the same
  `make build` binary: it embeds translate+run for hand-written x86
  byte sequences and compares against interpreter-computed results.
  Template provided at tests/unit/dbt_driver.c (coordinator, committed
  with this freeze). Expected final line: `L3A OK`.

## Card L3b — MOV/LEA/stack emitters

- MOV reg↔reg/mem all widths (high-byte forms via bfi/ubfx on the same
  wN), MOV imm forms, LEA (compute EA without seg), MOVZX/MOVSX all
  four, XCHG reg forms, PUSH/POP reg/imm (sp arithmetic on w4 with
  uxtw store/load [x20, w4]), PUSHA/POPA optional (decline ok), BSWAP.
- Same driver-based check → `L3B OK`.

## Card L3c — branch/string emitters

- JMP rel8/32 + reg/mem, Jcc (NZCV fusion; declined insns fall back),
  CALL rel32 (push ret-addr via w4 store, exit to target), RET/RET imm
  (pop target, exit), LOOP/JCXZ (decline ok), INT_Ib (exit SYSCALL with
  arg), INT3 (exit TRAP), HLT, NOP, SETcc reg forms (NZCV), CMOVcc reg
  forms, BT/BTS/BTR/BTC reg forms optional.
- String ops: MOVS/STOS/LODS/SCAS/CMPS single-step (non-REP) with DF
  from ctx->eflags bit 10; REP forms: emit an in-block loop with
  iteration check every 256 (safe point reading ctx->pending_signals)
  — or decline REP entirely in v1 (safe).
- → `L3C OK`.

## Card L3d — differential harness

- tools/difftest.sh: runs `I686RT_ENGINE=interp` vs `dbt` over the
  fixtures with I686RT_TRACE captured per engine, then
  tools/difftrace.py compares the (eip,opcode,esp) tuples and the
  syscall trace; prints mismatches with line numbers. Exit 0 = equal.
- Makefile: `test-p3-lima` target running the harness over
  test_p1_isa + busybox `echo` smoke, printing a single `PASS` line
  when 0 mismatches and busybox outputs match.
- → `L3D OK` (harness self-check: two runs of the SAME engine compare
  equal; a deliberately corrupted trace compares unequal).

Coordinator (after S3 merge): wire engine=dbt into main.c (translate
caching in a simple per-EIP hash, call i686_jit_run_block), then RC3 =
`make test-p3-lima` PASS + busybox smoke under dbt.
