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
