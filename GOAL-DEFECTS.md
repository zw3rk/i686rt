/goal Fix every open defect in /Users/angerman/Projects/zw3rk/i686rt/DEFECTS.md (section "Open campaign defects", C1–C12) using a maximally concurrent coordinator + worker-lane workflow.

## Context

The i686rt campaign (SPEC.md, docs/FINAL-REPORT.md) passed every phase gate RC-E, RC0–RC8 (incl. RC6 hl, RC7/RC7b wine) and H1–H4. The remaining known defects are inventoried in DEFECTS.md §"Open campaign defects" (C1–C12) with fix sites, verification commands, and severity. This goal closes them all or moves each to a state the coordinator records as terminal (fixed / ratified-in-SPEC / upstream-owned with evidence / won't-fix with rationale in DEFECTS.md).

## Roles (unchanged from the campaign)

- **GLM-5.3 = single coordinator.** Owns the DAG, freezes interfaces before each fan-out, writes task cards, batch-reviews, merges `--no-ff` locally, resolves escalations, and does the design-heavy work itself: C2 root-cause direction, C6's dead-flag-elimination and block-linking contracts, C5's ratify-or-fix call, C8's upstream note. No grunt work.
- **GLM-5.3-Flash = worker lanes** (`grunt-work` subagent type), one git worktree each (`git worktree add ../i686rt-<lane> -b lane/fix-<id>`), exclusive file ownership, ONE acceptance check per card, escalate after 2 failed attempts or any frozen-interface need.

## Parallelization DAG (waves)

**Wave 1 — independent, launch together:**
- **L-C1a** file-descriptor syscalls: `_llseek`(140), `readv`(145), `msync`(144), `ftruncate64`(194), `statx`(383). Files: src/os/sys_pass.c, sys_stat.c. Check: LTP framework deaths = 0.
- **L-C1b** thread/sched syscalls: `tkill`(238), `sched_getaffinity`(242), `set_robust_list`(311)/`get_robust_list`(312). Files: src/os/sys_pass.c, clone.c. Check: raise()/pthread_cancel signal path unit test.
- **L-C3** verification-only: wine chain under `I686RT_ENGINE=dbt` (RC7b env). Pass → close; stall → capture SYSTRACE, escalate.
- **L-C4** x87_80 directed-mode deep-tiny fix + unit vectors (golden baseline must stay 0-diff). File: src/interp/x87_80.c, tests/unit.
- **L-C7** SMC reclamation (generation counter at block exit or graveyard free-list). Files: src/dbt/engine.c, trampoline.S contract WITH the coordinator (frozen first).
- **L-C10** formal dynamic-glibc RC4 rerun (sysroot glibc 2.44; no src/ changes expected — if one is needed, escalate).
- **L-C11** H2 math `--x87-80` runner variant + two-mode report table. Files: tools/run-libctest.sh, tests/hardening/.
- **L-C9** winevdm stderr diagnosis (read-only forensics first; fix only if translator-side).

**Wave 2 — after Wave 1 merges:**
- **L-C2** pthread timeouts root-cause + fix (needs C1b's tkill/robust-list landed; dual-oracle futex-PI fixtures). Coordinator writes the diagnosis card after L-C1b's evidence.
- **L-C6a** dead-flag elimination (coordinator freezes the flags_dbt contract first; then lane implements). Files: src/dbt/flags_dbt.c, translate.c.
- **L-C6b** block linking via IBTC slots (coordinator freezes the trampoline/engine chaining contract; may share files with C6a — SEQUENTIAL after C6a).
- **L-C12** quarantine-stash reconciliation + D-series re-read (after the tree settles).

**Coordinator-serial:**
- **C5** ratify-or-fix MOVDQA alignment (decision + SPEC patch, or an emit_sse lane).
- **C8** upstream hl note (A32RT_WINDOW): document for Moritz; local verification lane only if a patched hl branch appears. Never modify ../hyper-linux shared checkout; never push.

## Scope rules (non-negotiable, carry over verbatim)

- Never push anything to any remote; all branches/worktrees stay local.
- Commit messages/identity must never mention any AI agent or model; author = Moritz Angermann <moritz@zw3rk.com>.
- Copy-first from ../a32rt into src/rt32/ only; no changes to ../a32rt or ../hyper-linux shared checkouts (the hl fix branch lane/6-l6a pattern — local worktree branches only).
- One acceptance check per card, run once; never re-run a passed check; no tests nobody requested.
- Every test/debugger run wall-clock bounded, containers named/tracked/cleaned per AGENTS.md.
- Regression floor: after each merge the coordinator runs the busybox echo smoke (interp + dbt) ONCE per affected engine; before the final close, the phase-gate spot list in the final summary re-verifies nothing regressed (busybox, dash, wine --version — not the full gate re-runs).
- Build with the cached cross toolchain store path (gcc-wrapper-15.2.0); never `nix shell nixpkgs#...` (registry drift).

## Done when

1. Every C1–C12 entry in DEFECTS.md carries a terminal status (FIXED with commit + verification evidence; RATIFIED with the SPEC patch; UPSTREAM with the recorded note; or WONTFIX with rationale), updated in the same file.
2. LTP reaches test bodies (framework deaths = 0) and the libctest pass count does not regress from `H2: libctest=125/343`.
3. CoreMark records a new H3 line with dbt > interp, CRCs intact (C6), or C6 is explicitly re-scoped with the coordinator's written rationale.
4. The pthread timeout cluster (C2) is either fixed (the 19 named tests leave the timeout class) or each remaining one has a root-caused DEFECTS.md note.
5. A closing summary commit lists every defect, its terminal state, the verification command output (verbatim), and any new open questions appended to SPEC.md §7.
