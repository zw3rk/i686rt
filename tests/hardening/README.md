# tests/hardening — Phase H item H2 (musl libc-test + LTP subset runners)

Phase H item H2 (SPEC.md §4): *musl libc-test + LTP subset runners; triage
list.  Accept: pass-rate report committed; GLM-5.3 sets thresholds.*

These runners measure how much of two real-world i386 test corpora the
i686rt translator (interp engine by default) can execute correctly.  H2
**triages and reports — it does not fix anything**: failures are classified
in the committed report, nobody patches the translator or the tests here.

## Layout

| file | role |
|---|---|
| `../../tools/run-libctest.sh` | fetch (cached `_build/libc-test`), build static i386 musl libc-test binaries in the docker `linux/386` alpine gcc oracle container, run every binary under `_build/i686rt` in the arm64 alpine container |
| `../../tools/run-ltp.sh` | same pattern for a bounded Linux Test Project 20240930 subset (`_build/ltp-20240930`) |
| `mkreport.sh` | assemble `h2-report.md` from the committed tap logs (`make h2-report`) |
| `results/*.tap` | committed TAP-ish per-test logs (one row per test + `# SUITE`/`# RESULT` summary lines) |
| `h2-report.md` | the committed pass-rate report (generated; ends with the machine-readable `H2: libctest=<p>/<t> ltp=<p>/<t>` line) |

## Usage

```sh
PATH=/nix/store/cs8q52va4acssg38pivn7f9kyvk9lzjd-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin:$PATH \
  make build CC=/nix/store/cs8q52va4acssg38pivn7f9kyvk9lzjd-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc
tools/run-libctest.sh
tools/run-ltp.sh
make h2-report
```

Both runners are idempotent: fetches and builds are cached under `_build/`
(gitignored); a rerun only re-executes the tests.  `H2_FORCE_FETCH=1` /
`H2_FORCE_BUILD=1` invalidate the caches.  Knobs: `H2_TEST_TIMEOUT`
(default 30 s per test), `H2_GLOBAL_TIMEOUT` (default 5400 s libctest /
3600 s LTP run-loop bound; expired tests are recorded as `global-bound`
skips, never silently dropped), `H2_IMAGE` (default `alpine:3.20`),
`I686RT_ENGINE` (default `interp`).  For `run-libctest.sh` only:
`H2_X87_80=1` runs i686rt with `--x87-80` (SPEC decision D9's exact
80-bit x87 mode) and names the TAP log
`results/libctest-x87_80.tap` so the default-mode `libctest.tap` is
never overwritten; with the knob unset the runner behaves exactly as
before.  Every container is named
(`h2-libctest-*`, `h2-ltp-*`), bounded by `--memory 2g --cpus 2` plus a
busybox `timeout`, and its removal is verified after the run (repo test
lifecycle rules).

## What gets run, and why

### musl libc-test

All three runtime suites are built from the same source tree with alpine's
native i386 musl gcc (`cc -static`, the `src/<suite>/<name>-static.exe`
targets; the E06-proven oracle pattern from `tools/build_fixture.sh`):

- **functional** — broad libc functional coverage (processes, files,
  strings, time, math-adjacent libc paths),
- **regression** — ~90 historical bug repros (mostly musl/glibc regression
  tests; heavy syscall-edge coverage),
- **math** — per-libm-function vector tests (~200 binaries; exercises x87
  rounding/fenv semantics under the default 64-bit x87 mode).

Conventions: a test binary exits 0 on success, non-zero = failure count;
on success it prints nothing.  The api suite is **compile-time-only**
(its check is that each header test compiles with `-pedantic-errors
-Werror` against the *oracle's* own musl headers — translator-independent),
and its runtime binary (`src/api/main.exe`) is built dynamic-only, so api
is recorded as a comment line (`# API api-compile compiled=<n> of=<m>`) in
the log and excluded from the runtime totals.  The dynamic `-static.exe`
twins of every test are deliberately out of scope: running them would need
a staged i386 loader/libc sysroot (Phase 4 style), which this bounded
runner does not set up.

Source: cloned in-order from `https://git.musl-libc.org/libc-test`, with
`https://repo.or.cz/libc-test.git` and the `nsz.repo.hu` GitHub mirror
(`https://github.com/AssemblyScript/libc-test`) as bounded fallbacks (the
canonical host was unreachable from the H2 environment; the exact URL and
commit are recorded in each tap header).  The mirror's tip at the time of
the H2 run is 2021-04-27 (`a0c28c76`).

### LTP 20240930 subset

The full LTP tree is far too large to build; only six syscall test
directories are configured and compiled, chosen to match syscall families
i686rt implements, each mapping to a distinct translator subsystem:

| directory | family / rationale |
|---|---|
| `read`, `write` | basic file I/O (`read`(2)/`write`(2) families) — the hottest guest path (every test framework prints through it) |
| `fork` | process creation — exercises i686rt's fork/clone path, address-space snapshot and child state (incl. RLIMIT interactions) |
| `mmap` | memory management (`mmap`/`munmap`/`mprotect`) — the same substrate the guest window itself is built on |
| `fcntl` | file control incl. record locks (`F_SETLK`/`F_GETLK`) and `dup` — a known syscall-marshalling surface (`handle_fcntl_flock` in the a32rt-derived layer) |
| `socket` | socket basics through the i386 `socketcall`(102) multiplexer — an i386-specific dispatch path no other suite covers |

Signal delivery is covered transitively (fork/abort paths in both suites);
a dedicated `kill` directory was dropped to keep the bounded subset within
the ~4–6 directory budget.  Only `testcases/kernel/syscalls/<dir>` binaries
are built (`make -C lib` + `make -C testcases/kernel/syscalls/<dir>`,
`LDFLAGS=-static`); tests that fail to build are recorded as `build-fail`
skips, and ELF executables that came out dynamic are recorded as
`design-dynamic` skips.

Release source: `https://github.com/linux-test-project/ltp/releases/download/20240930/ltp-full-20240930.tar.xz`
(sha256 verified against the release's `.sha256` sidecar; shallow git clone
at the tag as fallback).

## Result format

`results/*.tap` are TAP-ish (TAP plan + `ok`/`not ok` rows, not a strict
TAP dialect):

    not ok 57 - regression/statx-noatime
    # class=rc1 rc=1
    # out: t_error: statx failed: Function not implemented
    ...
    # SUITE regression pass=83 fail=6 timeout=1 skip=2 total=92
    # RESULT libctest pass=250 fail=12 timeout=3 skip=10 total=275
    # WALL seconds=1234
    1..275

Per-test outcome classification (both runners):

| exit / signal | outcome |
|---|---|
| 0 | pass |
| 124 / 137 (busybox `timeout -s KILL`) | `timeout` |
| LTP only: bit 32 (TCONF) set, bits 1/2 (TFAIL/TBROK) clear | `tconf` skip |
| >= 128 | `sig<N>` fail (translator process killed by host signal N) |
| anything else | `rc<N>` fail |

Static captures: stderr is additionally inspected for
`not a 32-bit little-endian x86` (`exec-format` — a guest tried to exec a
non-EM_386 image) and `Function not implemented` (`enosys`); the first
stdout line of every non-pass is embedded as a `# out:` comment for the
triage table.  Skips are explicit rows (`# SKIP class=build-fail`,
`design-dynamic`, `tconf`, `global-bound`) so totals are stable across
runs.

## Machine-readable summary

`h2-report.md` ends with exactly one line:

    H2: libctest=<p>/<t> ltp=<p>/<t>

(p = pass count, t = total rows recorded; thresholds are set by GLM-5.3
from these numbers — H2's job is faithful numbers and honest triage.)
