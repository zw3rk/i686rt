# Fix campaign close-out summary (2026-10-24)

Coordinator record for GOAL-DEFECTS.md.  Every DEFECTS.md
§"Open campaign defects" entry (C1–C12) reached a terminal state;
this file lists each with its verification evidence.  Records with
full output live in the per-lane documents (docs/lanes/fix-*.md) and
the committed logs (tests/hardening/, tests/golden/).

## C1 — eight unimplemented syscalls: FIXED

Merged: lane/fix-c1a (f24db6e: _llseek 140, readv 145, msync 144,
ftruncate64 194, statx 383), lane/fix-c1b (tkill 238, tgkill 270,
sched_getaffinity 242, set/get_robust_list 311/312; set_tid_address
258 superseded, gettid 224 added).

Verification (verbatim tails):
- C1a fixture: `C1a fd syscalls: ALL PASS (_llseek readv msync
  ftruncate64 statx)` / `guest-exit=0` / `host-rc=0` (green under
  interp AND dbt).
- C1b fixture: `C1B PASS tkill/tgkill handlers ran (tid=1000),
  affinity=cpu0, robust_list ok` / `exit=0`.
- `tools/run-libctest.sh` on merged master:
  `# RESULT libctest pass=135 fail=184 timeout=23 skip=1 total=343`
  (H2 floor 125/343 — no regression).
- `tools/run-ltp.sh` after harness repair b316069 (the inner runner
  passed relative guest paths, so every pre-campaign LTP log was a
  vacuous all-fail artifact):
  `# RESULT ltp pass=25 fail=19 timeout=1 skip=72 total=117`
  — test bodies reached, zero framework setup deaths; residuals are
  body-level (fcntl lease family fails on overlayfs; fcntl31/32
  ENOSYS class; fork stress under interpreter speed).

## C2 — pthread cancel/cond/robust/once timeouts: PARTIALLY FIXED, remainder root-caused

Merged: lane/fix-c2 (futex val2/requeue + PI, kernel pending-signal
semantics, robust exit walk, blocked-target wake, dual cleartid wake,
host-tid namespace) + fix batch ba4e54f (FPREM indefinite C2).

Verification (verbatim):
- PI fixture, host-oracle-identical: oracle `C2PI PASS`, i686rt
  `C2PI PASS`.
- Post-fix rerun (tests/run_c2_libctest.sh): `# RESULT libctest-c2
  pass=8 fail=5 timeout=6 total=19` — pthread_cond, pthread_robust,
  drem, dremf, fmod, fmodf, remainder, remainderf pass; fmodl/
  remainderl/remquo family now completes but miscomputes FPREM
  quotient-bit state (the documented D73 class); clocale_mbfuncs and
  crypt pass unbounded (71s/42s vs the 30s wall bound); tls_get_new-
  dttv is the pre-existing dlopen DSO-not-built class.
- Still open (root-caused): second-generation cancellation restores a
  zeroed sigcontext (evidence: docs/lanes/fix-c2-rt32-evidence.md);
  and the verification probe exposed that handler-initiated
  siglongjmp no longer escapes — SIGRET restores eip onto the
  faulting instruction and refaults in a loop (I686RT_SIGTRACE:
  `SIGRET rt=1 ... eip=0804932d` repeated; the RC4-era
  test_p4_threads_signals fixture rots with the same signature).
  Routed to SPEC §7.

## C3 — wine chain under engine=dbt: VERIFIED, residual documented

- RC7b-era stall: FIXED by H1 (lane/fix-c3 record: full boot, prefix
  install completes under dbt).
- The #DE misdeliveries: FIXED (ba4e54f — deliver_sync classifies by
  the recorded host signal; DBT resets exit_arg per dispatch).
- Residual (SPEC §7): the gate fails inside wine's dash wrapper
  discovery ("error: unable to find wine executable, this
  shouldn't happen.") after an empty-path STATX probe sequence
  (`STATX /etc/ld.so.cache` / `ACCESS /etc/ld.so.preload` /
  `STATX ` / `STATX /` / `STATX .`); the interp chain prints ok
  rc=0.  Evidence: docs/lanes/fix-c3-trace.md, _build/fix-c3-raw/.

## C4 — round_pack80 deep-tiny: FIXED

`make`-level golden floor after the fix (verbatim): `P5 GOLDEN:
0 diff both modes`; unit part 1: `L5D OK` / `unit exit=0`.
Commits 7e5d7a2 + d5a3f45 (the Makefile X87ONLY-strip fix the lane's
escalation exposed).

## C5 — MOVDQA alignment: RATIFIED

tests/probe_sse_align.c under both engines (verbatim): `SSE-ALIGN-OK`
/ `interp rc=0` / `dbt rc=0`.  SPEC D10 amended (f4336d0).

## C6 — DBT performance: RE-SCOPED (coordinator rationale in DEFECTS.md)

C6a dead-flag elimination (difftest `DIFFTEST: EQUAL`,
`flags_elided=5496` on busybox), C6b block linking (64.3% of block
executions chain in asm; `ibtc_hits=2604`), C6c dispatch-cost levers
(host rt_sigprocmask 1110 -> 2; IBTC collision healing).  CoreMark
post-levers: `H3: interp=69 dbt=24 oracle=4285`, CRCs intact
(`Correct operation validated` all three runs).  The remaining ~3x
gap is the block-granular translation model — H5/H6-class work.

## C7 — SMC reclamation: FIXED

`test_h1_smc` PASS both engines; RSS fixture (verbatim):
`VMRSS_BEFORE_KB 2580` / `SMC_EVENTS 10200VMRSS_AFTER_KB 2828` /
`RSS_GROWTH_KB 248` / `rss-stable ok` / `PASS` (the pre-fix control
grows 2964 KiB on the same fixture).

## C8 — hl A32RT_WINDOW: UPSTREAM (recorded in SPEC §7; no repo change)

## C9 — winevdm stderr: FIXED via C1

Root cause (docs/lanes/fix-c9-diagnosis.md): the missing _llseek(140)
made wine's update pass corrupt winedevice.exe (96-byte duplicated
header).  Acceptance rerun post-C1a (verbatim): `GATE-RC=0`,
stdout `ok`, `DOS-lines: 0`, winedevice.exe 142896 bytes with
`PE\0\0` at e_lfanew.

## C10 — formal dynamic-glibc rerun: PARTIALLY FIXED, residual root-caused

The C2 dual cleartid wake fixed the join block (dynamic-glibc join
fixture: `PASS t4 join-returned`).  Post-fix gate rerun: glibc
startup, TLS, robust lists (311 -> 0), clone3->clone fallback,
threads, fork/wait (child exit 42 reaped via wait4) and statx (383
-> 0) all trace working; the run then dies at a guest indirect jump
to `eip=0x00000001` (fault_addr=0x1) — a deeper dynamic-glibc
divergence of the wine-anchor class (docs/lanes/fix-c10-record.md).

## C11 — H2 math under --x87-80: MEASURED

`# RESULT libctest pass=122 fail=215 timeout=7 skip=1 total=345`
(80-bit run); two-mode table in tests/hardening/h2-report.md; math
delta -1.0 pp with 20/22 flips and 12 timeouts resolving — the
80-bit rounding/signed-zero cluster is recorded as the x87_80-mode
evidence (SPEC §7 item 9).

## C12 — quarantine stashes + D-series: RECONCILED

Stashes: 8 hunks superseded, 6 insn_tab.h hunks (D9-D12) silently
reverted by the l5c merge — port applied, both stashes dropped
(`git stash list` = 0).  D-series: 3 fixed-on-master, 1 moot, 15
still-live (docs/lanes/fix-c12-dseries.md).  The standout, D34
(sigframe st_space overcopy), FIXED in 1879927 and verified by
tests/probe_sigframe_fpstate.c (verbatim):
- fixed master: `D34-OK` / `rc=0`
- pre-fix control (C2-branch binary): `D34 FAIL fpstate u32 32
  nonzero: 3ff00000` / `rc=1`
The stale futex header comment (EBP/ESI swap) corrected.

## Regression floor (post-campaign spot list, all verbatim)

- dash interp: `dash-ok` rc=0; dash dbt: `dash-ok` rc=0.
- busybox interp: `busybox-ok` rc=0; busybox dbt: `busybox-ok` rc=0.
- wine --version interp (fresh prefix): `wine-10.0 (debian
  10.0~repack-12+b1)` rc=0.
- p5 goldens after the x87/DBT changes: `P5 GOLDEN: 0 diff both
  modes`; p7 seg-fault fixture: `PASS`.
