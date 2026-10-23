# Phase H — hardening (H1 SMC · H2 suite runners · H3 perf · H4 x86_64 ·
# H5 AOT · H6 segmented DBT; per-task cards, §4 Phase H)

## H2 card — musl libc-test + LTP subset runners; triage list

Worktree `../i686rt-h2`, branch `lane/h-h2`.  Owned (exclusive):
`tools/run-libctest.sh` (new), `tools/run-ltp.sh` (new),
`tests/hardening/` (runner glue, README, committed pass-rate report
`h2-report.md` + committed `results/*.tap` logs), `docs/lanes/phase-h.md`
(this file).  Bounded: `Makefile` (one `h2-report` target in the existing
style).  Accept (single chain, once): `tools/run-libctest.sh &&
tools/run-ltp.sh && make h2-report` → exit 0, `h2-report.md` ends with
`H2: libctest=<p>/<t> ltp=<p>/<t>`, nonzero totals on both sides.
Coordinator sets thresholds from the numbers; the lane's job is faithful
numbers + honest triage, NOT a passing suite.

## H2 record (2026-10-23)

Delivered, all in the owned file set:

- `tools/run-libctest.sh` (POSIX sh, `set -eu`): fetches musl libc-test
  (cached `_build/libc-test`; canonical `git.musl-libc.org` first, then
  `repo.or.cz/libc-test.git`, then the `nsz.repo.hu` GitHub mirror — the
  canonical host redirects to its cgit UI and both git:// and repo.or.cz
  were unreachable from this environment, so the run used
  `https://github.com/AssemblyScript/libc-test` @ `a0c28c76`, tip
  2021-04-27; URL + commit are stamped into every tap header); builds the
  `-static.exe` targets of `functional`, `regression`, `math` plus
  `src/api/main.exe` with `make -k` inside the docker linux/386
  `alpine:3.20` gcc oracle container (E06-proven `build_fixture.sh`
  pattern; alpine musl-dev ships the `-lpthread/-ldl/-lcrypt/-lresolv/
  -lutil` stub archives so `config.mak.def` works unmodified); then runs
  every built binary under `_build/i686rt` in the arm64 alpine container,
  `timeout -s KILL 30` per test (H2_TEST_TIMEOUT), a global run-loop wall
  bound (H2_GLOBAL_TIMEOUT, 5400 s; expiry recorded as `global-bound`
  skips, never silently dropped), appending TAP-ish rows + `# SUITE` +
  `# RESULT libctest` lines to `tests/hardening/results/libctest.tap`.
  Exit-code convention: 0 = pass; 124/137 = timeout; 129..159 = host
  signal death (`sig<N>`); stderr `not a 32-bit little-endian x86` =
  `exec-format`; "Function not implemented" in stdout = `enosys`; other
  rc = `rc<N>` fail (libc-test rc = failed-subcheck count).  Containers
  named (`h2-libctest-fetch/-build/-run`), `--memory 2g --cpus 2`,
  bounded, and removal verified after every run (repo lifecycle rules).
- `tools/run-ltp.sh` (same skeleton): fetches the LTP 20240930 release
  tarball only (sha256 verified against the release `.sha256`; shallow
  git clone at the tag as fallback), builds ONLY
  `testcases/kernel/syscalls/{write,read,fork,mmap,fcntl,socket}` plus
  `lib/libltp.a`, runs every static ELF32 result under the same
  classification (`rc & 32` without bits 1/2 = `tconf` skip), writing
  `results/ltp.tap` with per-directory `# SUITE` lines and
  `# RESULT ltp`.
- `tests/hardening/README.md`: harness description, LTP subset
  selection rationale (file I/O, fork, mmap, fcntl record locks,
  socketcall(102) multiplexer; signal delivery covered transitively; ~6
  directories per the card), formats, classification rules, knobs.
- `tests/hardening/mkreport.sh` + `Makefile h2-report` target: generate
  `tests/hardening/h2-report.md` (summary + per-suite tables + failure/
  skip classes with one-line triage notes + repro + environment), ending
  with the machine line `H2: libctest=<p>/<t> ltp=<p>/<t>`.
- `tests/hardening/results/{libctest,ltp}.tap`: the committed evidence.

### LTP build-system findings (bound into the runner, no LTP patches)

The bounded LTP build needs three non-obvious invocations, encoded in
`run-ltp.sh` (upstream Makefile machinery, nothing patched):
`make -C lib libltp.a` (NOT `all` — the lib trunk target also builds
lib/newlib_tests + lib/tests, which cannot bootstrap-link against
`-lltp`); `FILTER_OUT_DIRS="android_libpthread android_librt
newlib_tests tests"` on the test-dir makes (rides MAKEFLAGS into the
recursive `make -C lib all` from include/mk/testcases.mk); and `-static`
ONLY through configure (`LDFLAGS=-static ./configure` → baked into
include/mk/config.mk) — a command-line `make LDFLAGS=-static` replaces
the `-L$(top_builddir)/lib` that include/mk/env_post.mk appends and
every `-lltp` link fails with "cannot find -lltp".

### Official acceptance run (single chain, once, 2026-10-23)

    tools/run-libctest.sh && tools/run-ltp.sh && make h2-report

Chain exit 0 (first attempt).  Environment: macOS arm64 Docker Desktop;
build oracle docker `--platform linux/386 alpine:3.20` (gcc 13.2.1,
TCG-emulated), runtime docker `--platform linux/arm64 alpine:3.20`
native; engine interp (default); per-test bound 30 s; global bounds
5400 s / 3600 s (not hit; libctest run-loop wall 618 s, ltp 1 s).

Official numbers (verbatim from the committed taps / report):

    # RESULT libctest pass=125 fail=194 timeout=19 skip=5 total=343
       functional  pass=42 fail=23 timeout=5  skip=5 total=75  (56.0%)
       regression  pass=51 fail=15 timeout=3  skip=0 total=69  (73.9%)
       math        pass=32 fail=156 timeout=11 skip=0 total=199 (16.1%)
       (# API api-compile compiled=78 of=79 main.exe=dynamic-only —
        compile-time suite, outside the runtime totals)
    # RESULT ltp pass=0 fail=117 timeout=0 skip=0 total=117
       write 0/6  read 0/4  fork 0/11  mmap 0/20  fcntl 0/74
       socket 0/2  (every test dies in LTP framework SAFE_* setup —
       see triage item 2)
    H2: libctest=125/343 ltp=0/117

i686rt binary: `_build/i686rt` sha256
`a6db82545cb30b1577f67020821dd9e6b4f269cba9fbff5c6cf0d702bdc05c98`
(37-TU build from this worktree, zero new warnings; the pre-existing
`emit_sse.c` `sse_emit_prefetch` unused-parameter warning documented in
the T4d record is present).  Both taps are committed under
`tests/hardening/results/` as the raw evidence; the summary line above
matches the last line of the committed `tests/hardening/h2-report.md`.

### Triage list (top failure classes; H2 does not fix)

1. math suite (libc-test, ~199 tests): musl math vectors demand exact
   80-bit x87 results AND fenv exception flags; the D9 default mode is
   64-bit doubles + CW rounding with approximate flags → 1-ulp double
   mismatches, large long-double ('l') mismatches, "bad fp exception"
   flag diffs, fenv rounding-mode restore gaps.  `--x87-80` is the
   exactness mode (not exercised by this runner).
2. Unimplemented syscalls hit by both suites (I686RT_SYSTRACE-pinned):
   `_llseek`(140), `readv`(145), `msync`(144), `ftruncate64`(194),
   `tkill`(238), `sched_getaffinity`(242), `get_robust_list`(312),
   `statx`(383) → -ENOSYS.  `_llseek` alone breaks stdio
   fseek/ftello/fseek-dependent stdio tests; `tkill` breaks
   raise()/pthread_cancel() delivery; LTP's framework dies in SAFE_*
   setup on ftruncate64/sched_getaffinity before most test bodies run.
3. pthread/futex edge cluster (timeouts + fails): pthread
   cancel/cond/robust/once-deadlock/raise-race timeouts (futex-edge
   deadlock/livelock signature), PI relock EDEADLK-vs-deadlock,
   FUTEX_WAIT_REQUEUE_PI, robust-mutex detach.
4. SysV IPC: msg_lspid/shm_cpid/sempid carry host pids instead of the
   guest pid.
5. Guest setrlimit not enforced on fork (RLIMIT_NPROC) / brk
   (RLIMIT_DATA).
6. exec-format (by design): popen/spawn/system/vfork tests exec the
   container's arm64 /bin/sh — the translator only loads
   ELFCLASS32/EM_386.
7. dlopen-dependent libc-test tests: static scope has no DSOs
   (build-fail skips + tls_get_new-dtv_dso argv convention).
8. Misc singles: strptime "%F", strtod double-rounding (D9 class),
   lseek-large off_t handling at 0x7fffffff.

Coordinator-facing: classes 2 and 5 are concrete syscall-layer work
(items 140/144/145/194/238/242/312/383 + rlimit enforcement); class 1
needs an `--x87-80` runner variant to quantify; class 3 needs
I686RT_TRACE sampling.

## H2 thresholds (GLM-5.3, 2026-10-23) — ACCEPTED as committed

H2's acceptance is the committed pass-rate report (met: dacc099,
merged; machine line `H2: libctest=125/343 ltp=0/117` verified on
master).  Thresholds for interpretation:

- libctest functional >= 50% and regression >= 70%: MET (56.0% /
  73.9%).  These are the gates for "process/stdio/stdlib machinery
  sound".
- libctest math: NO threshold in the default mode — musl's vectors
  demand exact 80-bit x87 + fenv flags; D9's default mode is 64-bit
  double by design.  A future --x87-80 runner variant may quantify
  exactness (open item, not a gate).
- LTP: the 0/117 is a framework artifact, not test-body evidence —
  every case dies in SAFE_* setup on two unimplemented syscalls
  (ftruncate64(194), sched_getaffinity(242)).  Threshold: framework
  setup must reach test bodies before any rate is interpreted; the
  eight pinned unimplemented syscalls (_llseek 140, readv 145, msync
  144, ftruncate64 194, tkill 238, sched_getaffinity 242,
  get_robust_list 312, statx 383) go to the final report as the H2
  triage output.  pthread cancel/cond/robust timeouts (19) join the
  DBT-stall item as H-grade open work.

## H3 card — CoreMark performance: interp vs dbt vs oracle

Worktree `../i686rt-h3`, branch `lane/h-h3`.  Owned (exclusive):
`tools/run-coremark.sh` (new), `tests/hardening/h3-coremark.md` (the
report: scores table, environment, counters, machine line),
`docs/lanes/phase-h.md` (this file).  Bounded: `Makefile` (one
`h3-coremark` target mirroring the `h2-report` style).  No src/
changes.  Accept (single chain, once): `tools/run-coremark.sh &&
make h3-coremark` -> exit 0 with `h3-coremark.md` ending in
`H3: interp=<score> dbt=<score> oracle=<score>`, all three scores from
real bounded runs.  This is the MEASUREMENT lane: record honest numbers
+ the existing counters' readings; do NOT implement optimizations; a
failing DBT is evidence, not a blocker.

## H3 record (2026-10-23)

Delivered, all in the owned file set:

- `tools/run-coremark.sh` (POSIX sh, `set -eu`, difftest.sh header
  style): fetches CoreMark v1.01 (GitHub mirror of the canonical tag
  first, then eembc.org; bounded curl in a named arm64 container;
  cached `_build/coremark-1.01.tar.gz`, sha256
  `99c5a6d63af85a281b4e4d6ccb522c446653c435dfec9455ad73ef9e71f28bde`);
  builds ONE static i386 binary in the docker linux/386 alpine:3.20 gcc
  oracle container: `make PORT_DIR=linux compile XCFLAGS="-march=i686
  -static -DPERFORMANCE_RUN=1 -DHAS_FLOAT=0"`; then runs the canonical
  performance invocation `coremark.exe 0x0 0x0 0x66 <iters> 7 1 2000`
  three times (sequential, each `timeout -s KILL 600`, `--memory 2g
  --cpus 2`, named containers h3-coremark-{fetch,build,oracle,interp,
  dbt} with removal verified): (a) oracle natively in the linux/386
  container, (b) interp under `_build/i686rt` in the arm64 container,
  (c) dbt under `I686RT_ENGINE=dbt`.  Iterations ride the port's
  SEED_ARG command line, so one binary serves all three runs; per-run
  counts only tune wall time (oracle 300000 / interp 30000 / dbt 9000,
  from calibration rates: oracle in the card's 60-120 s window, each
  engine run well inside the 600 s bound and far above CoreMark's 10 s
  validity minimum).  Raw evidence + an env stamp land in
  `tests/hardening/results/coremark-*.{log,err,txt}`; the `report`
  subcommand (what `make h3-coremark` runs) assembles
  `tests/hardening/h3-coremark.md` from them, idempotently.
- `-DHAS_FLOAT=0` is a port knob that changes ONLY score printing
  ("%f" -> "%d"; secs_ret double -> ee_u32; the "CoreMark 1.0 : ..."
  banner is omitted, "Iterations/Sec" remains the metric).  The
  workload — list, matrix incl. the float matmul, state machine — and
  the CRC validation are unchanged; the standard 2K performance CRCs
  (list 0xe714 / matrix 0x1fd7 / state 0x8e3a, seedcrc 0xe9f5) validate
  on all three runs.  This knob exists because the default-port build
  CANNOT finish under i686rt — see finding 1.
- `tests/hardening/h3-coremark.md`: scores table (CoreMark score +
  wall-derived precise iters/s + wall/rc + validation per engine),
  environment, counters status, findings, repro, machine line.
- `Makefile`: `h3-coremark` target (mirrors `h2-report`).

### Official numbers (single chain, 2026-10-23T11:34Z, chain exit 0)

| engine | iterations | CoreMark Iterations/Sec | precise (wall) | wall s | validation |
|---|---|---|---|---|---|
| interp (i686rt default) | 30000 | 71 | 71.5 | 419 | ok |
| dbt (I686RT_ENGINE=dbt) | 9000 | 23 | 23.8 | 378 | ok |
| oracle (linux/386 container) | 300000 | 5000 | 5000.0 | 60 | ok |

    H3: interp=71 dbt=23 oracle=5000

Environment: macOS arm64 Docker Desktop; i686rt `_build/i686rt` sha256
`8c43655697e4f752944d32e16bde8457411cd6b710cf9b8d52d23a60c11b0dc1`
(37-TU cross-musl build, only the documented pre-existing
`sse_emit_prefetch` warning); gcc (Alpine 13.2.1_git20240309) 13.2.1
20240309.  Counters: NOT OBSERVABLE — `stats_enabled` is never set by
any flag or env var in the current tree (no `--stats`; `parse_args`
rejects it), so main.c's stats line is unreachable, and
`flags_elided`/`chain_hits` have no runtime readout at all (chain_hits
is accumulated only in DBT trampoline registers).  Recorded honestly;
the wiring work belongs to lanes that own src/.

### Findings (measurement lane; not fixed here)

1. INTERPRETER DECODE DEFECT (escalated to the coordinator;
   DEFECTS.md is not lane-owned): the stock-port build
   (-DHAS_FLOAT=1) dies under BOTH engines after completing all
   iterations, in the final score PRINTING — musl's static printf
   float formatter `fmt_fp` executes `DA E9` (FUCOMPP; then FNSTSW AX,
   SAHF) and i686rt reports `interp: undecodable instruction at
   eip=0x0804e76f (op:0)`.  The DA-page group row in
   `src/x86/insn_tab.h` routes mod=3 reg=5 (DA E8+i FUCOMP family,
   which is where FUCOMPP/DA E9 lives) to I686_OP_INVALID even though
   the row comment claims "DA E9 FUCOMPP"; the registered `h_fucompp`
   handler is unreachable.  dbt dies through the D2
   interpret-one-then-resume exit at the same eip (0 DBTFALL lines —
   the fall-back itself hits the interp hole).  Calibration evidence:
   interp died at 28 s, dbt at 87 s, both with 2000/2000 iterations
   done.  Any static-musl i386 binary that printf's a float will hit
   this (alpine musl was built upstream; the caller's XCFLAGS do not
   change libc.a).
2. dbt is ~3x SLOWER than interp on CoreMark (23 vs 71 Iterations/
   Sec).  These are the honest baseline numbers for the H-grade perf
   work named in the card (dead-flag elimination, block linking); no
   DBTFALL interpreter fallbacks occurred in the dbt run.
3. The "oracle" is NOT qemu TCG: Docker Desktop on Apple Silicon runs
   linux/386 containers with user-space x86 translation (Rosetta-class)
   over an arm64 kernel (/proc/cpuinfo exposes the Apple ARM cpu;
   observed 4170-5000 iter/s is 1-2 orders above qemu-TCG class).  The
   card's "(qemu TCG)" assumption is corrected here; the number is
   still a genuine timed oracle run, just a much stronger reference.
   Rosetta timing is noisy on this host (3333 / ~4170 / 5000 across
   three full invocations — treat the oracle as +/-25%; engine numbers
   repeated within ~2%).

### Acceptance chain

    tools/run-coremark.sh && make h3-coremark

Chain exit 0 on the second invocation (first invocation aborted the
interp/dbt runs before any guest execution on a harness argument bug —
the runner got no `--`-separated guest argv and exited rc=2 with its
usage; harness fixed, attempt discarded, no numbers from it are
reported).  Every container named, bounded, removal verified.

## H1 record (2026-10-23) — PASSED (both engines)

D11 implemented: translated pages write-protected (bitmap over the
window); guest stores to them fault, the handler invalidates the
page's blocks (dead-mark — same-block SMC and the post-syscall path
may still reference the code; eviction frees), clears IBTC/RAS
entries, restores RW and re-executes the store.  vm mm-op hooks call
the real invalidation.  The DBT loop now installs+arms the host-fault
checkpoint (window faults under engine=dbt previously killed the
process).  Acceptance (arm64 docker, staging /tmp/rc3):
  interp: timeout 60 /w/i686rt -- /w/test_h1_smc -> smc-patch-imm ok /
  smc-rewrite-stub ok / smc-same-page ok / PASS, rc=0
  dbt (I686RT_ENGINE=dbt): identical, rc=0
Regression: busybox echo ok under both engines.  Known residual
(documented): dead-marked blocks free only on hash eviction (bounded
leak per SMC event); the DBT same-block SMC tail (generation counter
at block exit) is covered by the fault path instead of a pre-emptive
block-end, per the a32rt precedent measured here.

## H4 record (2026-10-23) — PASSED

`nix build .#packages.x86_64-linux.i686rt-x86_64` (musl64 stdenv via
the external x86_64-linux builder) produces the interpreter-only
static-PIE binary (-DI686RT_NO_DBT compiles out the DBT, trampoline.S
and rt32_a64_emit; the x86 musl epoll_event is packed like the i386
guest's, asserts + size retargeted).  Acceptance (docker
--platform linux/amd64, x86_64 kernel — ia32_emulation irrelevant:
i686rt IS the translator):
  i686rt -- experiments/E03-rosetta-elf32/hello-i386 -> rc=42
  i686rt -- busybox-i686 sh -c 'echo hello-from-x86_64-host'
    -> hello-from-x86_64-host, rc=0
