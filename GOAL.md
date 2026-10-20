/goal Implement i686rt per /workspace/i686rt/SPEC.md using a maximally concurrent coordinator + worker-lane workflow.

## What i686rt is
A standalone, zero-dependency Curated C11 + minimal AArch64 asm, static-PIE aarch64-linux user-mode translator that runs 32-bit x86 (ELFCLASS32, EM_386) Linux binaries using only native 64-bit Linux syscalls, with the host contract of zw3rk/a32rt. SPEC.md is the single source of truth: read §0 (reference study), §2 (decisions D1–D15), §3 (technical spec), §4 (phases, gates, acceptance checks) and §4.C (concurrency plan / lane tables) before starting. Reference repos, read-only: /workspace/a32rt and /workspace/hyper-linux.

## Roles
- **GLM-5.3 = single coordinator and senior escalation engineer.** Owns: the dependency DAG; the interfaces/contracts it freezes before each fan-out (headers, struct layouts, function signatures, file ownership); task cards; review gates; merges; escalations; all [GLM-5.3] design tasks in SPEC.md (ABI-locked `i686_ctx_t` + trampoline, decoder core, lazy flags, TSO, signal frames, clone/TLS, x87 model for both modes, LDT/segment model, vm86 model, hl integration). It does **no grunt work** (no tables, boilerplate, fixtures, repetitive handlers).
- **GLM-5.3-Flash = worker lanes.** Run as many lanes in parallel as the DAG allows (e.g. all ten Phase E experiments at once; syscall table, struct-layout translators, opcode decode tables, x87, SSE, LDT and vm86 fixtures fanned out per file/module). Flash does every [GLM-5.3-Flash] task.

## Task cards (one per lane; GLM-5.3 writes them)
Each card states exactly: **scope**; **files owned** (exclusive — no two concurrent lanes write the same file; shared headers are frozen and read-only to lanes); **frozen interface** (the headers/signatures the lane codes against); **one acceptance check** (a single command + expected output); **output location** (branch name + paths, or `experiments/Enn-*/FINDINGS.md`).
Each lane works in its own git worktree on its own local branch: `git worktree add ../i686rt-<lane> -b lane/<phase>-<lane>`.

## Escalation protocol (Flash lanes)
A lane **stops and escalates to GLM-5.3** — with a short note (what, attempted, error, proposed fix) — when: (1) its acceptance check fails twice; (2) it needs any change to a frozen interface or a file it doesn't own; (3) the spec or card is ambiguous. A lane never widens its scope, never edits frozen headers, never "fixes" another lane's files. GLM-5.3 resolves by amending the card, re-freezing the interface (and notifying affected lanes), or taking the design question itself.

## Reviews, merges, verification
- GLM-5.3 reviews completed lanes **in batches** against SPEC.md and the card; accepted lanes are merged into `main` locally (no fast-forward of unreviewed work).
- Verification is minimal: per merged lane, run only that lane's check once; per phase, run the phase acceptance check once at the sync point. Never re-run a check that already passed; never add or run tests nobody requested. Builds needed for a check are fine.
- Rejected work goes back **to the same lane** with concrete, numbered notes; that lane fixes only those notes.
- Commit in each lane once its check passes; GLM-5.3 commits merges.

## Phase order and gates
- **Phase E (experiments E01–E10) first, all lanes in parallel.** No implementation code before the RC-E review passes. Each experiment: `README.md` (hypothesis, procedure) + `FINDINGS.md` with one verdict line. GLM-5.3 reviews every conclusion and updates SPEC.md; if a finding contradicts a decision, SPEC.md is revised before dependent phases start. A phase may not start until the experiments in its "Gates" column are reviewed.
- Then: 0 → 1 → 2 → 3 → 4 → 5 → 6 → 7 (LDT) → 8 (vm86) → H1–H6, with intra-phase fan-out per SPEC §4.C. Phases may overlap only where §4.C shows no dependency. Phases 0–8 are explore-fast (internal APIs may break between phases; frozen within a fan-out); hardening only in H.

## Scope rules (non-negotiable)
- Focus: only what the current card/phase lists. No side quests, no unrelated refactors, no extra features, no hl changes before Phase 6.
- Copy-first: a32rt code is copied into `src/rt32/`; **no extraction of a shared rt32 library** and no changes to /workspace/a32rt.
- x87: 64-bit default **and** exact 80-bit via `--x87-80` (`I686RT_X87=80`) — both required.
- Wine-style LDT (`modify_ldt`, LDT selectors in segment loads, far calls/jumps/returns, 16-bit code segments) and vm86 (`vm86`/`vm86old`, real-mode/v86 interpreter path) are in scope.
- **Never push** anything to any remote (no `git push`, no PRs, no comments). All branches and worktrees stay local.

## Commit hygiene (hard rule)
Commit messages, trailers, Co-authored-by lines, and the author/committer name and email must never mention Cursor, cursor-agent, Zcode, GLM, or any AI agent or model. Use the repository's configured human author identity only. No "Generated with" or similar lines.

## Done when
RC-E; RC6 (`hl ./busybox-i686 sh -c 'echo ok'` prints `ok` on macOS Apple Silicon); RC7/RC7b (LDT fixture PASS, `wine cmd /c echo ok`); RC8 (vm86 fixture PASS); H1–H4 acceptance checks — each passed once. Final report: experiment verdicts, phases completed with their check results, escalations raised and how they were resolved, open questions added to SPEC.md.
