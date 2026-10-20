# i686rt agent instructions

Follow `~/.config/ai/AGENTS.md`, `~/.config/ai/C_GUIDELINES.md`, and the
sibling boundary rules in `../hyper-linux/AGENTS.md` and
`../hyper-linux/docs/SIBLING-REPOS.md`. Use the root Makefile inside
`nix develop`; keep `CLAUDE.md` pointing to this file. `SPEC.md` is the
single source of truth (§0 reference study, §2 decisions D1–D15, §3
technical spec, §4 phases and §4.C concurrency plan); `GOAL.md` adds the
coordinator/worker-lane workflow. `../a32rt` and `../hyper-linux` are
read-only references.

## Project invariants

- `i686rt` is a standalone, zero-dependency Curated C11 + minimal AArch64
  asm, static-PIE aarch64-linux user-mode translator that runs 32-bit x86
  (`ELFCLASS32`, `EM_386`) Linux binaries using only native 64-bit Linux
  syscalls, under the a32rt host contract (`A32H_ABI 1.0`). The planned
  runtime artifact is static musl for AArch64 Linux; tier 2 is an
  interpreter-only x86_64 build.
- Phase E experiments (`experiments/Enn-*/FINDINGS.md`) gate all
  implementation: no implementation code before RC-E, and a phase starts
  only once its gating experiments are reviewed and SPEC.md is patched.
  Then phases 0–8 (7 LDT, 8 vm86) and H1–H6 per SPEC §4. Exactly one
  acceptance check per task/phase; never re-run a passed check; no tests
  nobody requested.
- Copy-first from a32rt into `src/rt32/` with the `rt32_` prefix. No
  shared rt32 library extraction, no changes to a32rt, and no hl changes
  before Phase 6 (D13, D15).
- Two engines: the portable C interpreter (`src/interp/`) is the
  correctness oracle and fallback; the DBT x86→A64 (`src/dbt/`) reuses
  a32rt's cache/dispatcher/emitter skeleton. Unknown opcodes
  interpret-one-then-resume; never assert on them (D2).
- Keep the guest window `[G, G+4 GiB)` with a32rt's G resolution order
  and offset mode (G = 4 GiB under hl). Effective addresses wrap in
  32-bit W registers before `xG` is added; never sign-extend or truncate
  guest addresses (D4, D7).
- x86 is TSO on weak A64: plain loads/stores while single-threaded,
  re-translate in TSO mode after `clone(CLONE_VM)`, and LOCK-prefixed RMW
  via LSE atomics. Preserve lazy EFLAGS semantics, precise guest state,
  x87/SSE state and rounding, and i386 structure, sigframe and syscall
  layouts (D5, D6, §3.4–§3.6). x87 requires both the 64-bit default and
  exact 80-bit `--x87-80` modes (D9).
- Wine-style LDT (`modify_ldt`, LDT selectors in segment loads, far
  transfers, 16-bit code segments) and vm86 are in scope; non-flat/16-bit
  code runs in the interpreter first (D8, Phases 7–8).
- Reuse `/dev/a32host` and `A32H_ABI 1.0` unchanged; `I686RT_HOST=none`
  opts out. Environment prefix is `I686RT_*` (WINDOW, SYSROOT, CACHE,
  ENGINE, X87). Rosetta handles x86_64 only; never route `EM_386` through
  hl's Rosetta path (D14, E03).
- Do not claim ISA, syscall, ELF, or execution-mode support until
  implemented and covered by the current phase's acceptance check.
- lima (`limactl`, aarch64 Linux) is the ground-truth oracle; `hl` on
  macOS Apple Silicon is the primary target from Phase 6 on. Keep
  `make help` the default goal; products belong in `_build/`; `all`,
  `test`, `check`, `clean` stay the basic targets.
- Use Curated C11 with the prescribed warning flags. Check all file,
  buffer, allocation, and integer-boundary operations. Zero dependencies
  beyond libc (vendored a32rt-derived sources included).
- Lanes use isolated git worktrees (`../i686rt-<lane>` on
  `lane/<phase>-<lane>`) with exclusive file ownership and frozen
  interfaces; preserve sibling/user changes; never push. BUILD is the
  default; measure before optimizing.
- Apache-2.0; attribute project work to Moritz Angermann
  <moritz@zw3rk.com>, zw3rk pte. ltd. No AI attribution trailers, and no
  commit identity, message, or trailer may mention any AI agent or model.
