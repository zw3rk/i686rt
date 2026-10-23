# Fix campaign — C1–C12 worker-lane cards (2026-10-23)

Coordinator-owned DAG for closing DEFECTS.md §"Open campaign defects".
This file is the single source for lane cards; lanes read it from their
own worktree.  Cards for Wave 2 (C2, C6a, C6b, C12) are appended by the
coordinator at their dispatch.

## Campaign rules (non-negotiable)

- Work ONLY inside your own worktree `../i686rt-<lane>` on branch
  `lane/fix-<id>`.  Never touch the main checkout, sibling worktrees,
  `../a32rt`, or `../hyper-linux`.  Never push anything.
- Commits: author Moritz Angermann <moritz@zw3rk.com> (inherited git
  config — verify with `git config user.name` / `user.email`).  No
  commit message, trailer, or code comment may mention any AI agent or
  model.  Commit in small, buildable steps on your branch.
- ONE acceptance check per card, run once, never re-run a passed
  check.  Development/iteration testing before the acceptance run is
  expected; the acceptance check itself is the single named run.
- Every docker/test run: wall-clock `timeout`, unique container name +
  `--cidfile`, CPU/memory limits, verify removal (`docker ps -a` filtered
  on your cid/name) after completion, timeout, cancellation, or error.
  Stop only containers you own.
- Build with the cached toolchain, never `nix shell nixpkgs#...`:
  `make build CC=/nix/store/cs8q52va4acssg38pivn7f9kyvk9lzjd-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc`
  (keep that wrapper's bin dir on PATH for binutils).  Product lands in
  `_build/i686rt` (static-PIE aarch64-linux).
- Docker images: `alpine:3.20` `--platform linux/arm64` = the aarch64
  runtime VM (mount your worktree, run `_build/i686rt`); `--platform
  linux/386` = the i386 build oracle (alpine gcc for static i386
  fixtures; `apk add gcc musl-dev` inside).  Docker Desktop mounts
  /Users paths; container /tmp is NOT shared — mount scratch dirs
  explicitly.
- Reusable caches on the host: `/Users/angerman/Projects/zw3rk/i686rt/_sysroot/`
  (668 MB: `debian-wine32-i386` wine sysroot + `pool` deb cache +
  `debian-i386` when built) — mount it read-only into your container at
  the same path inside your worktree mount instead of refetching:
  `-v /Users/angerman/Projects/zw3rk/i686rt/_sysroot:<your-worktree>/_sysroot:ro`.
  `_build/libc-test` / LTP trees are NOT cached anymore — the H2
  harnesses fetch and build them under their own bounds.
- Escalate to the coordinator (report in your final message) after 2
  failed attempts at the same fix, or if your card would require
  touching a file you do not own or a frozen contract.
- Final message format: branch + commit hashes, files changed, the
  acceptance command and its verbatim output tail (last ~20 lines),
  pass/fail verdict, escalations.

## Frozen ownership map (Wave 1)

| Lane | Branch | Owns (may WRITE) | Must NOT write |
|------|--------|------------------|----------------|
| c1a | lane/fix-c1a | src/os/sys_pass.c, src/os/sys_stat.c, tests/ fixtures it adds | src/os/sys_thread.c, clone.c, everything else |
| c1b | lane/fix-c1b | src/os/sys_thread.c, src/os/clone.c, tests/ fixtures it adds | sys_pass.c, sys_stat.c, everything else |
| c3 | lane/fix-c3 | nothing (verification-only; records only) | everything |
| c4 | lane/fix-c4 | src/interp/x87_80.c, tests/unit/ (new vectors) | everything else |
| c7 | lane/fix-c7 | src/dbt/engine.c, an SMC RSS-loop fixture under tests/ | trampoline.S (frozen), everything else |
| c9 | lane/fix-c9 | nothing until diagnosis says translator-side; then src/ with coordinator sign-off | everything |
| c10 | lane/fix-c10 | nothing (verification-only; a record doc under docs/) | everything |
| c11 | lane/fix-c11 | tools/run-libctest.sh, tests/hardening/ | everything else |

Registration seam (already on master before your branch): C1b's
handlers register from `src/os/sys_thread.c::i686_syscalls_thread_init`
(called from syscalls.c init_once).  C1a registers fd-class handlers in
`sys_pass.c::i686_syscalls_pass_init` / `sys_stat.c::i686_syscalls_stat_init`
as the existing families do.  Statx (383) belongs to the stat family
init (C1a).

---

## Card L-C1a — fd syscalls (140, 145, 144, 194, 383)

Task: implement five i386 syscalls, kernel-ABI exact, in the existing
pass/stat families.  For each: a handler `sys_*` (implementation) +
`r_*` (register fetch) + registration, mirroring the sibling style
(lseek/writev are the models).

Kernel ABI (verify each against man-pages/kernel headers before coding;
the DEFECTS.md parentheticals are summaries, this table is the
contract):

- `_llseek` (140): `ebx`=fd, `ecx`=offset_high, `edx`=offset_low,
  `esi`=guest `loff_t*` result pointer, `edi`=whence.  Merge
  `(u64)high<<32 | low`, host `lseek(fd, off64, whence)`; on success
  write the 64-bit result to the GUEST result pointer and return 0;
  errors negative.  (NOT "returns off in EDX:EAX" — the kernel writes
  *result.)
- `readv` (145): `ebx`=fd, `ecx`=guest iov*, `edx`=iovcnt.  Marshal
  guest iovecs ({void*, u32 len} pairs) to host iovecs; mirror the
  existing writev implementation's approach; partial-transfer and
  EFAULT semantics follow what writev does.
- `msync` (144): `ebx`=addr, `ecx`=len, `edx`=flags.  The guest window
  is host-mapped 1:1 modulo guest_base — pass
  `i686_guest_ptr(ctx, addr)` to host msync.  Linux only accepts
  MS_ASYNC(1)/MS_SYNC(4)/MS_INVALIDATE(2); kernel returns -EINVAL for
  other flag bits — match that (mask nothing silently).
- `ftruncate64` (194): `ebx`=fd, `ecx`=length_low, `edx`=length_high.
  Host ftruncate64.
- `statx` (383): `ebx`=dirfd, `ecx`=path*, `edx`=flags, `esi`=mask,
  `edi`=statx buf*.  Implement via host `statx` (SYS_statx exists on
  aarch64) or host fstatat + translation; fill the i386 `struct statx`
  layout (32-bit fields: blksize/devices as maj/min splits, stx_mask
  result reflecting what was filled; zero the buffer first; honor
  STATX_* mask the way the kernel does at least for BASIC_STATS).  The
  guest struct layout must be asserted with `_Static_assert` offsets
  like the sibling struct headers do.

Development evidence (not the acceptance): a static i386 C fixture
(build in the linux/386 oracle container, alpine gcc) exercising
fseeko/ftello past 2 GiB on a sparse tmpfs file, readv scatter, msync,
ftruncate64 grow/shrink, statx basic fields — run under your built
i686rt in the arm64 container.  Iterate until green.

Acceptance check (run ONCE, by the coordinator on merged master after
C1a+C1b): `tools/run-ltp.sh` reaches test bodies — framework deaths = 0
(no TBROK from SAFE_* setup ENOSYS) — plus `tools/run-libctest.sh` with
no pass-count regression from 125/343.  Do NOT run these two scripts as
part of your lane work.

Escalate if: a fix needs anything outside your two files (e.g. the
window map or marshal helpers are insufficient).

## Card L-C1b — thread/sched syscalls (238, 270, 242, 311, 312)

Task: implement in `src/os/sys_thread.c` (registrations go in
`i686_syscalls_thread_init`), with any thread-registry work in
`src/os/clone.c` (you own it; `i686_current_ctx` and the tid mapping
live there).

- `tkill` (238): `ebx`=tid, `ecx`=sig.  Find the guest thread ctx by
  guest tid (your registry addition to clone.c), set
  `ctx->pending_signals |= 1<<(sig-1)`.  The interp loop polls pending
  signals at safe points (`i686_deliver_pending`) — that is the v1
  delivery mechanism; you do NOT need to interrupt a futex-blocked
  thread for this card (that is C2 scope).  Unknown tid -> -ESRCH; sig
  0 = existence probe (kernel returns 0/-ESRCH without delivering).
- `tgkill` (270): `ebx`=tgid, `ecx`=tid, `edx`=sig.  Same routing;
  verify tgid matches the process or return -ESRCH/-EINVAL per kernel.
  musl's `raise()` calls tgkill — this is what makes raise() work.
  (Optional, same mechanism, only if trivial: `kill` (37) routes to the
  process's threads; skip if it drags in process-group semantics.)
- `sched_getaffinity` (242): `ebx`=pid, `ecx`=len, `edx`=guest
  mask*.  Return a single-CPU affinity: kernel semantics = clear the
  buffer (min(len, kernel mask size)), set CPU 0, return the number of
  bytes copied (e.g. 4).  pid must match 0/self (others -> -ESRCH is
  fine for v1); len < 4 -> -EINVAL.
- `set_robust_list` (311): `ebx`=head, `ecx`=len; store both per-ctx
  (fields on i686_ctx_t or your clone.c registry), return 0; len must
  be `sizeof(struct robust_list_head)` = 12 on i386, else -EINVAL.
- `get_robust_list` (312): `ebx`=tid, `ecx`=head_ptr*, `edx`=len_ptr*;
  return the stored head/len via guest pointers (own tid or 0; other
  tids -> -ESRCH for v1); unknown tid -> -ESRCH.
  NO robust-list walking at thread exit in this card (C2 scope).

Do NOT touch sys_pass.c signal machinery; pending-bit setting only
needs `ctx->pending_signals` (public in i686rt.h) and your registry.

Development evidence: a static i386 musl fixture: install a SIGUSR1
handler (sigaction), `raise(SIGUSR1)`, handler sets a flag, main
verifies + also exercises sched_getaffinity and
set/get_robust_list round-trip; run under your i686rt in arm64 alpine.

Acceptance check (run ONCE, in your worktree): that fixture's
single run exits 0 with the handler-run line printed.  Record the
command + output verbatim.

## Card L-C3 — wine chain under engine=dbt (verification-only)

Task: re-run the RC7b gate with the DBT engine.  H1 fixed the missing
host-fault checkpoint install in the DBT loop — the RC7b-recorded stall
is suspected fixed; never re-run since.  Context: docs/lanes/phase-7.md
(launch chain, sysroot) + docs/FINAL-REPORT.md RC7b row.

Procedure: worktree build (dbt is in by default); mount the shared
`_sysroot` read-only; arm64 alpine container; fresh WINEPREFIX under a
mounted scratch dir; run, with a 30-minute wall clock `timeout`:

    I686RT_ENGINE=dbt <i686rt> --sysroot /w/_sysroot/debian-wine32-i386 -- \
        /w/_sysroot/debian-wine32-i386/usr/bin/wine cmd /c "echo ok"

(match the RC7b invocation exactly as recorded in phase-7.md, including
WINEPREFIX/env setup steps; interp warm boot of the prefix first if
RC7b did so).

Pass (ok, rc=0): record it; your record closes C3.
Stall/timeout: re-run ONCE more with `I686RT_SYSTRACE=1` (bounded 30
min) — capture the first retry loop, save the trace under
docs/lanes/fix-c3-trace.md in your worktree, commit, escalate.
Any crash: capture the fatal-region dump + I686RT_TRACE tail the same
way.

Acceptance check (run ONCE): the single gated command above (plus, only
on stall, the one SYSTRACE capture).  Your final message IS the C3
record — include the verbatim output tail.

## Card L-C4 — round_pack80 directed-rounding deep-tiny

Task: `src/interp/x87_80.c` `round_pack80`'s `eff < 0` branch returns
signed zero under EVERY rounding mode.  IEEE-correct: under RC
toward -inf/+inf a nonzero tiny inexact result of the matching sign
must round to the minimum extended subnormal (1 ulp of 2^-16445), not
zero.  Mirror the fix pattern already applied to `to_ieee_bits` (commit
e31dccc): nearest and toward-zero keep signed zero; toward an infinity
matching the result's sign takes the min subnormal; the opposite-sign
direction keeps signed zero.  Nearest-mode behavior must remain
bit-identical (RC5 golden baseline).

Add directed-mode unit vectors to the existing x87_80 unit test you
find under tests/unit/ (values strictly below 2^-16446/2 around the
min-subnormal boundary, all four RC modes, both signs; expect: 0 for
nearest/toward-zero/opposite-sign, min-subnormal for toward-inf
matching sign).  Follow the existing test file's conventions.

Acceptance check (run ONCE, both parts in one pass):
1. the extended unit test binary passes (arm64 alpine, static-pie
   build), and
2. the RC5 golden check `make test-p5-lima` (or the equivalent fixture
   vs committed goldens run used at RC5) reports 0 diff lines for BOTH
   default and --x87-80 modes.
Escalate if the golden run shows any diff (that means nearest-mode
changed — stop, do not iterate on goldens).

## Card L-C7 — SMC dead-mark reclamation (frozen contract)

Frozen contract (coordinator-designed; deviating requires escalation):

- Add a bounded graveyard free-list to `src/dbt/engine.c`:
  `static struct { uint8_t *code; size_t cap; } s_graveyard[256];
  static size_t s_graveyard_n;` ( Curated C11: designated init, no VLA).
- Both dead-mark sites (`i686_dbt_invalidate_range`,
  `i686_dbt_smc_write_fault`) push the dead entry's {code, cap} into
  the graveyard instead of leaking it; if the graveyard is full,
  munmap the oldest immediately (bounded memory, no unbounded growth).
- `dbt_graveyard_drain(void)` munmaps every graveyard entry and resets
  the count.  Frozen call sites ONLY:
  (a) top of the `for(;;)` dispatch loop in `i686_dbt_run`, before the
  D8 guard / `dbt_get_or_compile` — this is a safe point: no emitted
  block is on the host stack;
  (b) `i686_dbt_flush_all` drains (it already frees everything).
  NOWHERE else.  `i686_dbt_invalidate_range` and
  `i686_dbt_smc_write_fault` must NEVER free (mid-flight use-after-free
  is what H1 fixed).
- `src/trampoline.S` MUST NOT change.  Neither may the emit/exit
  contract.  If you believe you need to, escalate.

Task mechanics: implement the above; keep the dead-mark
(`eip = 0xFFFFFFFFU`, IBTC/RAS clears) exactly as is.

RSS fixture (requested by DEFECTS.md C7): a small freestanding i386
guest fixture (style of tests/test_h1_smc.c) that performs ≥10,000
SMC events in-guest (rewrite its own code page in a loop — each write
takes the fault -> dead-mark -> graveyard path).  Measure the i686rt
process RSS inside the arm64 container (sample /proc/<pid>/status
VmRSS) before and after the loop: with the fix, growth must be < 1 MiB
(the leak it fixes grows ~80 MiB over 10k events at ~8 KiB/block).

Acceptance check (run ONCE): `tests/test_h1_smc` passes under BOTH
engines (interp sanity + dbt — the same single command pattern the H1
record used; see docs/lanes/phase-h.md) AND your RSS fixture run
reports the before/after VmRSS pair with < 1 MiB growth.  One
containerized session, all output recorded verbatim.

## Card L-C9 — winevdm stderr diagnosis (forensics first)

Task: during RC7b's `wine cmd /c "echo ok"` (interp engine), three
stderr lines of the form "winedevice.exe is a DOS application" appear;
the oracle is silent.  stdout/rc are clean.  T4c's hypothesis:
wineboot's launch of winevdm racing the slow first-run copy of
winedevice.exe (launch-vs-copy overlap under our ~10x interpreter).

Procedure (READ-ONLY forensics first): reproduce with a fresh
WINEPREFIX (boot = `wineboot` then the cmd chain, per phase-7.md env),
capture stderr with timestamps; correlate with I686RT_SYSTRACE
(open/openat/exec lines around winevdm/winedevice paths) to establish
the exact ordering: who stats/opens the missing-or-partial file, and
whether the message comes from wine's loader seeing a pre-copy state.
Bound every run (30 min), separate WINEPREFIX per run.

Verdict paths:
- Translator-side (e.g. a wrong error code, a spurious EAGAIN/ENOENT
  our syscalls inject, missing fstat completeness making wine
  misjudge the copy): propose the minimal fix IN YOUR REPORT — do not
  write src/ without coordinator sign-off (your file map says "nothing
  until diagnosis").
- Wine-side timing (wine racing its own copy; the interpreter being
  slow is enough to expose it): record the diagnosis with evidence;
  that is a WONTFIX-with-rationale outcome (fix belongs to wine, not
  the translator).

Acceptance check (run ONCE): the diagnostic run itself — the captured
stderr + SYSTRACE excerpt + your written verdict, committed as
docs/lanes/fix-c9-diagnosis.md in your worktree.  (If and only if the
coordinator later accepts a translator-side fix, a follow-up card
re-runs the gate for the stderr-empty criterion.)

## Card L-C10 — formal dynamic-glibc RC4 rerun (verification-only)

Task: close the recorded RC4 deviation formally.  RC4 ran the dynamic
ELF32 pthread/SIGFPE/fork test against musl-i386; the gate letter says
glibc.  The wine sysroot proves glibc 2.44 i386 works de facto; this
card runs the actual test binary against a glibc sysroot.

Procedure:
1. Build the plain glibc sysroot: `tools/setup_sysroot.py` targets
   `_sysroot/debian-i386/` and shares `_sysroot/pool` (libc6 2.44-3 is
   already in the pool — mount the host `_sysroot` read-only and the
   script should skip downloads; run it on the HOST macOS side, not in
   a container, exactly as RC7b ran setup-wine32.sh).
2. Compile `tests/test_p4_glibc.c` as a DYNAMICALLY linked i386 binary
   against that sysroot: docker `--platform linux/386` alpine +
   `apk add gcc musl-dev` is the WRONG libc here — instead cross-link
   with the sysroot's glibc: use the docker 386 gcc with
   `-Wl,--dynamic-linker=/lib/ld-linux.so.2 -Wl,-rpath-link
   --sysroot=<mounted sysroot>` pointing at the debian-i386 tree (the
   tree layout matches the multiarch paths; phase-7.md documents the
   same resolution for wine).  `-static` is the musl pattern — NOT
   this card.
3. Run it: arm64 alpine, your worktree i686rt build, `--sysroot
   /w/_sysroot/debian-i386`, bounded 30 min.  PASS criterion = same as
   RC4: the binary prints PASS (threads + SIGFPE handler +
   fork/waitpid all exercised).
4. Write the record (command, libc version stamp
   `libc.so.6 --version`-equivalent via the deb filename, verbatim
   output tail) into docs/lanes/fix-c10-record.md; commit.

If the test needs a source change to pass under glibc: STOP — that is
an escalation (the card assumes none).

Acceptance check (run ONCE): step 3's single run.  Verbatim output in
your final message.

## Card L-C11 — H2 math under --x87-80 (measurement)

Task: quantify the exact 80-bit x87 mode for the libc-test math suite
(DEFECTS.md C11 — measures D9's exactness claim; no fix obligation).

1. `tools/run-libctest.sh`: add an env knob `H2_X87_80=1` that makes
   the runner's i686rt invocations pass `--x87-80` (and name the TAP
   output `libctest-x87_80.tap` so the default log is never
   overwritten).  Keep the default path byte-identical when unset.
2. Run the 80-bit variant ONCE (full suite; same bounds; it is fine to
   reuse the fetched/built libc-test tree from your own default run or
   skip building default — only the 80-bit run is required).
3. Append a "two-mode table" section to `tests/hardening/h2-report.md`:
   per-suite rows (functional / regression / math) with default-mode
   numbers (from the committed H2 log, cited) and the new 80-bit
   numbers, plus the math delta highlighted.  Update the report's
   regeneration tooling if h2-report.md is generated by
   `make h2-report` (tools/mkreport.sh or equivalent — keep the
   committed file and the generator consistent).
4. Commit script + report + the raw 80-bit TAP log.

Acceptance check (run ONCE): the step-2 run completing with its final
`# RESULT libctest ...` line; the report table matches the TAP totals.
Expect math to jump (80-bit exactness is what the math vectors demand);
functional/regression must not regress (they don't use x87 transcendentals,
but record whatever you measure — measurement card, no threshold).

Escalate if: making the knob touches other tools' files.

---

# Wave 2 cards (dispatched after Wave 1 merges; branch from merged master)

## Card L-C6a — dead-flag elimination (FROZEN contract)

The seam `i686_emit_ctx_t.flags_src` (src/dbt/emit.h) is frozen on
master BEFORE you branch: I686_FLAGS_DEAD / I686_FLAGS_EFLAGS /
I686_FLAGS_NZCV with the semantics in that comment.  You own
src/dbt/emit_alu.c, src/dbt/emit_branch.c, src/dbt/emit_sse.c,
src/dbt/flags_dbt.c — NOT emit.h, NOT translate.c, NOT engine.c.

Task:
1. Producers: the fused ALU ops (emit_alu.c ADD/SUB/CMP/AND/OR/XOR/TEST
   via SUBS/ANDS + emit_lazy) set `e->flags_src = I686_FLAGS_NZCV`;
   eager-eflags producers (IMUL/shift class that write ctx->eflags
   directly and store lazy_op = NONE) set I686_FLAGS_EFLAGS; anything
   that can invalidate NZCV (a blr through the helper, an exit, an
   UNDEF-declined insn mid-block — the block ends there anyway) leaves
   DEAD or is unreachable.
2. Consumers (jcc/jcc-rel/setcc/cmovcc in emit_branch.c; COMISS/COMISD/
   UCOMISS/UCOMISD class in emit_sse.c): switch on e->flags_src.
   NZCV -> emit ONLY the cond-map consume (l3c_cond_map path) and bump
   ctx->flags_elided by 1 (uint64; add a _Static_assert for its
   offsetof in i686rt.h and use it in the asm increment; a consumer
   that TOOK the NZCV path may leave flags_src = NZCV for the next
   consumer only if NZCV still holds that image — setcc/cmovcc do not
   disturb NZCV, so yes).  EFLAGS -> rebuild NZCV from ctx->eflags
   WITHOUT the park/sync helper (the w9 mask build + msr).  DEAD ->
   today's full l3c sequence unchanged.
3. PF (parity) conditions still decline (return -1) — unchanged.
4. ctx->flags_elided is diagnostics: I686RT_STATS=1 readout already
   prints counters — verify it appears (see H3 record), no new report.

Correctness floor (dev iteration, not the acceptance): tools/difftest.sh
on test_p1_isa (interp-vs-dbt (eip,op,len) trace EQUAL) and the p5
golden check used at RC5 (0 diff, both modes).  Run difftest as often
as you like; goldens once at the end.

Acceptance check (run ONCE): difftest EQUAL on test_p1_isa AND busybox
echo smoke under dbt AND test_p5_fpu_sse vs goldens 0-diff both modes —
one pass, recorded verbatim.  (CoreMark speed measurement is C6b's
acceptance, not yours.)

## Card L-C6b — block linking via IBTC slots (FROZEN contract;
SEQUENTIAL after C6a merges — you share emit/engine files)

Frozen constants (all ABI-locked, static-asserted in i686rt.h):
exit_reason @0x78 (I686_EXIT_BRANCH == 1), exit_dest @0x84, eip @0x20,
ibtc[] @0x9e8, entry stride 32 {key@0, epoch@4, host_code@8, entry@16},
hash = (eip >> 2) & 1023, ibtc_hits @0x1d0 (uint64), gpr[8] @0x0.
You own src/dbt/engine.c and src/trampoline.S.  NOT translate.c,
NOT emit_*.c.  The C7 graveyard drain (already merged) sits at the
loop top — keep its call site and order untouched.

Task:
1. engine.c `dbt_get_or_compile`: after a successful translate+install,
   fill the slot: `ctx->ibtc[i686_ibtc_hash(eip)] = (i686_ibtc_entry_t)
   { .key = eip, .epoch = 1U, .host_code = code, .entry = code }`.
   Dead-marked slots (eip == 0xFFFFFFFFU) are never refilled except by
   a fresh successful compile (the eviction path already handles it).
2. trampoline.S: turn the single-shot body into a dispatch loop.
   After `blr x23` and the GPR store-back:
   - ldr w8, [x19, #120]; cmp w8, #1 (I686_EXIT_BRANCH); b.ne -> exit
     to the C epilogue as today.
   - ldr w9, [x19, #132] (exit_dest); idx = w9 >> 2, and #1023;
     slot = x19 + 0x9e8 + idx*32.
   - ldr w10, [slot]; cmp w10, w9; b.ne -> C epilogue.
   - ldr x11, [slot, #8] (host_code); cbz x11 -> C epilogue.
   - x23 = x11; reload GPRs from ctx (4x ldp); bump ibtc_hits
     (ldr/add/str x12); blr x23; branch back to the GPR store-back.
   Keep the existing prologue/epilogue framing exactly (callee-save
   d8-d15, x19-x28).  cur_entry/epoch_ptr (x21/x22) stay unused.
3. Add C-side _Static_asserts in engine.c pinning what the asm
   assumes: I686_EXIT_BRANCH == 1, offsetof(ibtc) == 2536, sizeof entry
   == 32, offsetof(exit_reason) == 120, offsetof(exit_dest) == 132.

Safety argument (include in your commit message): the chain decision
reads ctx->ibtc only between blocks (no emitted block on the host
stack); every invalidation path (i686_dbt_invalidate_range, SMC fault,
flush_all) clears keys/entries BEFORE the next dispatch, so a cleared
or collided slot falls back to the C engine loop, which recompiles.

Acceptance check (run ONCE): `tools/run-coremark.sh` full chain — new
H3 line with dbt strictly ABOVE interp (71 iter/s) and the standard 2K
CRCs validating; append/refresh the H3 record table.  If dbt lands at
or below interp after profiling: STOP, do not iterate on benchmarks —
write up where the time goes (I686RT_STATS=1 block/ibtc counters) and
escalate for the re-scope decision.

## Card L-C2 — pthread cancel/cond/robust/once timeouts

Prerequisite: L-C1b merged (tkill/tgkill/robust-list acceptance stored
in ctx).  Start from merged master.  You own src/os/sys_pass.c (futex),
src/os/sys_thread.c, src/os/clone.c, tests/ fixtures you add.  h_sse.c/
interp files are off-limits.

Evidence base: the 19 timeout tests are listed per-suite in
tests/hardening/results/libctest.tap (timeout= counts; the H2 record in
tests/hardening/h2-report.md names the cluster).  T4d already fixed the
base WAIT/WAKE/REQUEUE/CMP_REQUEUE + BITSET ABI; the PI family
(LOCK_PI 6, UNLOCK_PI 7, TRYLOCK_PI 8, WAIT_REQUEUE_PI 9? — check the
linux futex_op values, WAIT_REQUEUE_PI 11, REQUEUE_PI 13,
CMP_REQUEUE_PI 14) is unverified, robust-list processing at thread exit
is not implemented (C1b only stores), and cancellation delivery needs a
runnable-target wake (pending bit set by tkill/tgkill from another
guest thread; a futex-blocked target never polls).

Method (coordinator's direction):
1. Dual-oracle fixtures first (tools/probe_strfuncs style): a static
   i386 musl fixture per semantic area — (a) futex PI family vs the
   host kernel's return values/timeouts (docker 386 runs the SAME
   fixture natively as the oracle), (b) robust-list walk on thread
   exit (muslpthread exit with a held robust mutex: oracle = the lock
   word gets FUTEX_OWNER_DIED | TID cleared and a FUTEX_WAKE issued),
   (c) pthread_cancel join (SIGRTMIN-order signal via tgkill to a
   running and to a futex-blocked target).  Bound everything.
2. Fix what the fixtures prove broken, in your files: sys_futex PI
   commands (host futex supports PI natively — map the uaddr 1:1 as
   T4d does and pass through, re-encoding op exactly like the T4d
   re-encode does for the base family), robust-list walk in the thread
   exit path (clone.c), and for cancellation: a waker that marks
   pending AND wakes a host-futex-blocked target (a host tgkill with a
   dedicated SIGUSR-class signal whose handler only interrupts the
   futex, if pending-bit polling proves insufficient — coordinate with
   the host-fault checkpoint install; the interp arms/disarms the
   SIGSEGV handler and a second host signal must not fight it — if it
   does, STOP and escalate the design question instead of hacking the
   fault path).
3. Iterate on the individual timeout tests from the libc-test tree
   (build once, run per-test) — dev evidence.

C1b handoff (2026-10-23, verified evidence — fold into step 1/2):
musl 1.2.5 raise() = rt_sigprocmask(SIG_BLOCK,all) -> tkill -> restore,
and i686_deliver_pending (src/os/signals_i386.c, tail) wipes ALL
pending bits after the single poll, so a signal raised inside the
blocked window is dropped before the mask restores ("handler did not
run"; SYSTRACE: 258->1000, 174->0, block 175->0, tkill(1000,10)->0,
restore 175->0).  Kernel semantics: bits stay pending while masked
and deliver at unmask.  Fix belongs in the delivery core (drop only
the bits actually delivered/popped; keep the rest), plus the
blocked-target wake problem below.  glibc raise()->tgkill works with
C1b as landed (no mask window).  C1b also superseded set_tid_address
(258, returns caller tid) and added gettid(224) via the sys_thread.c
seam — the D31 behavior note is thereby fixed on master.

Acceptance check (run ONCE, on your worktree): the 19 named tests
re-run with the per-test bound; record pass/fail/timeout per test.  A
test that still times out MUST come with your root-cause paragraph
(that is the DEFECTS.md note format).  Also run the futex PI
unit-vs-host fixture once (the card's new pin): same results as the
host oracle.

## Card L-C12 — quarantine-stash reconciliation + D-series re-read

Read-mostly hygiene card, dispatched last (after C2/C6 settle the
tree).  Worktree ../i686rt-c12, branch lane/fix-c12.  You may edit
DEFECTS.md and docs/lanes/fix-c12-*.md ONLY — any code port goes
through the coordinator first.

Tasks:
1. `git stash list` on master shows quarantine and quarantine-2 (the
   Phase-5 lane-leak quarantines).  Diff each against current master:
   every hunk is either (a) already on master (superseded), (b) a
   still-valid comment correction matching a DEFECTS.md D-entry, or
   (c) obsolete.  Produce the disposition table in
   docs/lanes/fix-c12-stashes.md.  Port candidates (b) as a patch file
   in your report — do NOT touch src/ yourself.
2. Re-read every OPEN correctness D-entry (D13, D14, D25, D26, D27,
   D28, D31, D34, D37, D39, D41, D43, D47, D51, D52, D53, D57-D64,
   D65-D73 on the lane branches only — check which are on master) and
   mark in docs/lanes/fix-c12-dseries.md: FIXED-on-master (cite the
   commit), STILL-LIVE (the defect's code unchanged on master), or
   MOOT (the code path is gone/different).  Verify by reading the
   current master file, not the D-entry's cited commit.
3. Hand both documents to the coordinator (final message).  Stash drops
   and any src/ ports happen by the coordinator after review — not you.

Acceptance check (run ONCE): the two disposition documents complete
(every stash hunk and every D-entry classified), committed on your
branch.  No docker needed except none — this is a reading card.

## Coordinator log (fix campaign)

- 2026-10-24 — C3f escalation item 1 REFUTED: the reported statx(383)
  ENOENT on /etc/ld.so.cache is not a C1a regression. Probes on master:
  statx resolves sysroot-only paths correctly (libc.so.6 -> 0);
  /etc/ld.so.cache and /etc/hostname do not exist in the wine sysroot,
  so ENOENT is the correct answer (identical to the pre-C1a fstatat64
  fallback). The #DE misdelivery root cause (fix-c3f-diagnosis.md) is
  the actionable C3 finding; its fix routes to a dedicated lane once
  signals_i386.c (C2) and engine.c (C6c) free up.

## Coordinator log (close-out additions, 2026-10-24)

- Real LTP rerun (after harness fix b316069): 25 pass / 19 fail /
  1 timeout / 72 TCONF skips — test bodies reached, zero framework
  setup deaths; residuals are body-level (fcntl leases on overlayfs,
  fcntl31/32 ENOSYS class, fork stress).
- Wine-under-dbt gate after the #DE fix: still fails, now inside
  wine's dash wrapper discovery ("unable to find wine executable")
  after an empty-path STATX probe sequence — a dash-under-dbt
  divergence, SYSTRACE-documented; C3 residual (SPEC §7 item 3).
- C2 post-fix rerun: 8/19 pass; fmodl/remainderl/remquo complete but
  miscompute FPREM quotient bits (D73 class); second-generation
  cancel still zeroed-sc; clocale/crypt pass unbounded.
- D34 fixed and probe-verified (fixed: D34-OK rc=0; pre-fix control:
  FAIL with smeared slot bytes).  Stashes dropped after the port.
- New still-live finding recorded (SPEC §7 item 5): siglongjmp out
  of a delivered-signal handler refaults in a loop — suspected C2
  sigframe-rework fallout; the RC4 p4 fixture rots with the same
  signature.
- Spot list green: dash interp+dbt, busybox interp+dbt, wine
  --version interp (wine-10.0, rc=0).
