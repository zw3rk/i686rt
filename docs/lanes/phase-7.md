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

## L7a record

Implemented seg.h completely (files owned): `src/interp/seg.c`
(segstate alloc + flat defaults, selector lookup null/GDT-flat/TLS/LDT,
validated segment loads with SDM DPL/RPL/type checks, cs_d maintenance,
`i686_seg_flat_cs`, LDT data-limit enforcement along the decode EA path,
`i686_seg_sc_encode/sc_decode`), `src/interp/h_seg.c` (MOV sreg 8E,
pops 07/17/1F/0F A1/0F A9 via i686_seg_load, les/lds/lss/lfs/lgs, far
call/jmp 9A/EA, lret CB incl. 0x66 cross-size, non-v86 iret CF, int NN
resolvable fault in non-flat code, privileged cli/sti/hlt + synthetic
IN/OUT/MOV CR,DR faults in 16-bit code), `src/os/ldt.c` (modify_ldt
funcs 0/1/0x11/2, set/get_thread_area 243/244 with entry_number -1
auto-alloc, seg_not_present frees, v1-compat GS auto-load), fixture
`tests/test_p7_ldt.c`. Bounded edits: `src/x86/decode.c` (CS-relative
instruction fetch, cs_d-driven defaults normalized into
pfx_opsize/pfx_addrsize so every frozen handler keeps its
`pfx ? 16 : 32` convention, 16-bit EA wrap mod 64K before the segment
base, LDT limit check in x86_rm_read/x86_rm_write, far-op operand
decode m16:16/m16:32 into synthetic registry ids 350–359 handled by
h_seg.c, lazy idempotent `i686_interp_seg_init()` call), `src/dbt/
engine.c` (per-dispatch guard `i686_seg_flat_cs(ctx) && !ctx->v86`).
Makefile needed no edit (SRCS wildcards pick the new TUs up).

**Syscall registration snippet for the coordinator (S7)** — in
`i686_syscalls_init_once` (src/os/syscalls.c), after the existing
registrations, add:

```c
    {
        extern void i686_syscalls_ldt_init(void);
        i686_syscalls_ldt_init();   /* 123 modify_ldt, 243/244 set/get_thread_area */
    }
```

(already callable: ldt.c defines it idempotently; until wired it is
invoked lazily from the Phase-7 interp registration. Note the v1
syscalls.c init re-registers 243 at the first syscall, so it wins for
set_thread_area until this moves here; 123/244 are served by ldt.c
either way.)

Also at S7 (already implemented, awaiting wiring, coordinator-owned
files):
- `src/os/signals_i386.c`: call `i686_seg_sc_encode(ctx, sc.gs..ss)`
  when building sigcontexts and `i686_seg_sc_decode(ctx, in)` from
  `i686_sigreturn`; and preserve the lane's trapno in `i686_deliver_sync`
  (limit/segment/int-NN faults raise `ctx->exit_arg` = 13/11/12 with the
  error code stashed in `ctx->exit_dest`; the current delivery overwrites
  exit_arg to 14 — until wired, guest trapno reads 14 for all SIGSEGVs).
- `src/interp/interp.c` (optional symmetry): move the
  `i686_interp_seg_init()` call from decode.c into `i686_interp_init_all()`.

Deviations / notes (all within card bounds):
- Fault delivery uses the existing sync channel: handlers return
  I686_EXIT_FAULT with exit_arg = trapno; the guest IP stays at the
  faulting instruction (resumable). Limit faults additionally raise a
  deterministic host SIGSEGV by touching the offending guest address
  first (exact cr2 when the page is PROT_NONE — the fixture's overrun
  at 0xF0001000), falling back to the always-unmapped guest VA 0.
- The fixture cannot exercise the privileged-instruction fault from
  inside 16-bit code end-to-end yet: signal delivery enters the handler
  with the interrupted CS (16-bit) and sigreturn does not restore
  segments until the sc_encode/sc_decode wiring above; the h_seg
  handlers and the decode path are in place and covered by the record.
- Limit enforcement covers the modrm/moffs EA path for LDT (TI=1)
  selectors only; flat/GDT selectors are never limit-checked (v1
  compatibility, D8 DBT-eligibility unchanged). 16-bit addressing now
  wraps the offset mod 64K before the segment base is added (SDM
  correct; flat 67-prefix behaviour change noted).
- No vm86 paths touched (ctx->v86 guard only).
- FROZEN-HEADER HAZARD for the coordinator (no change required this
  phase, worked around lane-side): seg.h re-spells the FAULT codes
  I686_SEG_OK/GP/NP/SS over i686rt.h's segment-register index macros —
  I686_SEG_SS is 3 (fault) vs 2U (SS register index). Files including
  both pre-clear the macro (#undef before including seg.h so the frozen
  #define is fresh) and use collision-free SEG_F_* locals; seg.h should
  rename its fault codes (e.g. I686_SEGF_*) at the next sanctioned
  header touch.
- execve leaves ctx->cs_d stale if the execing context ran with D=0
  (the kernel drops the LDT on exec; the coordinator may reset
  ctx->ldt/cs_d in r_execve at S7).

Acceptance check (single run, 2026-10-22):

    tools/build_fixture.sh tests/test_p7_ldt.c _build/test_p7_ldt
      -> build_fixture.sh: _build/test_p7_ldt: ELF 32-bit LSB executable,
         Intel 80386, version 1 (SYSV), statically linked, not stripped
    nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.buildPackages.gcc \
      -c make build CC=aarch64-unknown-linux-musl-gcc        (zero warnings)
    docker run --name l7a-check --rm --platform linux/arm64 \
      -v "$PWD/_build/p7stage":/w alpine:3.20 sh -c 'timeout 60 /w/i686rt -- /w/test_p7_ldt'

Output, verbatim (last line exactly PASS; exit 0; container gone —
`docker ps -a --filter name=l7a-check` empty after the run):

    PASS

(The fixture also passes under I686RT_ENGINE=dbt in pre-flight: the
engine guard keeps DBT to flat blocks and single-steps the far ops
through the interpreter, D8.)

## S7/RC7 (coordinator)

Merge L7a (--no-ff), wire syscall registration + sigframe sc_encode/
sc_decode + far-int fault delivery, run RC7: `test_p7_ldt` prints PASS
(lima stand-in: arm64 docker container — recorded deviation as in
RC1–RC5). RC7b after L7b: `wine cmd /c echo ok`.

## S7/RC7 record (2026-10-22) — PASSED

L7a merged --no-ff (11321cd); coordinator wiring committed: ldt.c
syscalls registered last-wins (123/243/244; full set_thread_area
supersedes the flat v1 stub), sigframe segment round-trip via
i686_seg_sc_decode + segment-fault trapno preservation (#GP 13/#NP
11/#SS 12 with the error code in sc.err instead of the #PF-14
overwrite), i686_interp_seg_init in init_all, r_execve cs_d reset,
seg.h fault codes renamed I686_SEG_F_*.  RC7 evidence (arm64 docker
alpine:3.20, staging /tmp/rc3): `timeout 60 /w/i686rt -- /w/test_p7_ldt`
→ rc=0, last line PASS.  Deviations: lima stand-in as in RC1–RC5.
Noted behavior change (SDM-correct): 16-bit EA wrap mod 64K for
67-prefixed flat code.
