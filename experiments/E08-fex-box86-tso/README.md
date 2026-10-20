# E08 — fex-box86-tso

How do FEX-Emu and Box86/Box64 handle x86 TSO memory ordering on weak (A64)
hosts? Source/doc study; no build required.

## Hypothesis

- FEX defaults to software TSO: acquire/release LDAPR/STLR where FEAT_LRCPC is
  available, else LDAR/STLR ("half barrier") or full-barrier options; optional
  HW TSO enable on Apple via ACTLR_EL1 when permitted; can be disabled for
  per-game compatibility.
- Box86/Box64 default to NO TSO emulation with an opt-in strong-memory option
  (`BOX86_DYNAREC_STRONGMEM` / `BOX64_DYNAREC_STRONGMEM`, with levels).
- Also: what triggers stronger ordering (multi-threaded process? per
  instruction? LOCK always atomic?).

## Procedure

1. FEX-Emu: partial clone (blobless, no checkout) to `/tmp/fex-e08`; `git
   grep` on `HEAD` (blobs fetched on demand) for `LDAPR`, `TSO`, `ACTLR`,
   `HalfBarrier`, strong MEM flags. Identify config option names + defaults
   (`Source/Common/Config.cpp`), the emitter choice logic (LDAPR vs LDAR vs
   plain LDR), dependence on FEAT_LRCPC CPUID, runtime re-translation when
   threads appear, and the Apple ACTLR_EL1 HW-TSO path.
2. box86 + box64: shallow clones to `/tmp/box86-e08`, `/tmp/box64-e08`; grep
   `STRONGMEM` for option levels and defaults; grep dynarec for
   `LDAXR|CASAL|SWPAL|LDADDAL` to confirm LOCK-prefixed ops always emit
   atomics.
3. Write the comparison table (rows = project; columns = default ordering,
   mechanisms, config knobs + defaults, multi-thread trigger policy,
   vector/unaligned notes) with `file:line` citations and clone commit hashes.

## Deliverable

`FINDINGS.md` with `VERDICT: ANSWER:` line, Evidence (comparison table +
citations), and Consequence for SPEC (D5).

Acceptance check (once):

```
grep -m1 -E '^VERDICT: (PASS|FAIL|ANSWER: )' experiments/E08-fex-box86-tso/FINDINGS.md
```
