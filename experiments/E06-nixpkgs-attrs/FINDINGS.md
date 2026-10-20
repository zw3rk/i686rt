# E06 FINDINGS — nixpkgs i686 cross attrs + local i386 fixture path

VERDICT: ANSWER: attrs=pkgsCross.musl32 (i686-unknown-linux-musl), pkgsCross.gnu32 (i686-unknown-linux-gnu), legacyPackages.i686-linux (native set); NOT pkgsi686Linux (throws off x86), NOT pkgsCross.i686-unknown-linux-musl (no such attr); build-path=fixtures via nix cross (musl32 for musl, gnu32 for glibc) built with `--system x86_64-linux` on the external builder (one-time toolchain compile, then cached); quick local iteration AND running i386 fixtures: `docker run --platform linux/386 alpine:3.20` + `cc -static` (musl gcc 13.2.1) — proven end-to-end, ~18x QEMU-TCG slowdown.

- Environment: nix 2.35.3, `system = aarch64-darwin`, external builders for
  aarch64-linux + x86_64-linux only (no i686-linux builder). nixpkgs =
  `flake:nixpkgs` registry pin, release 26.05.
- The no-i686-builder error, verbatim (from `nix build --impure --expr
  'let f = builtins.getFlake "nixpkgs"; in f.legacyPackages.i686-linux.hello'`;
  note the whole i686-linux stdenv substituted from cache.nixos.org, only the
  final `hello` drv could not run):

  ```
  error: Cannot build '/nix/store/6s52fb2sn9f2frrnj0bamlia6hgg3b41-hello-2.12.3.drv'.
         Reason: platform mismatch
         Required system: 'i686-linux'
         Current system: 'aarch64-darwin'
  ```

## Evidence

All exact commands + outputs in `commands.log`. Key evidence:

1. Attr evaluation (all from aarch64-darwin, nixpkgs 26.05):
   - `nix eval nixpkgs#pkgsCross.musl32.stdenv.hostPlatform.config` →
     `"i686-unknown-linux-musl"`.
   - `nix eval nixpkgs#pkgsCross.gnu32.stdenv.hostPlatform.config` →
     `"i686-unknown-linux-gnu"`.
   - `nix eval nixpkgs#pkgsi686Linux.stdenv.hostPlatform.config` →
     `error: i686 Linux package set can only be used with the x86 family.`
     (`pkgs/top-level/stage.nix:257`).
   - `nix eval nixpkgs#pkgsCross.i686-unknown-linux-musl.…` →
     `flake 'flake:nixpkgs' does not provide attribute …pkgsCross.i686-unknown-linux-musl…`
     — the musl i686 attr is named `musl32`, not after the triple.
   - Toolchain versions: `pkgsCross.{musl32,gnu32}.stdenv.cc.version` →
     `"15.3.0"` (matches the cross-gcc 15.3.0 drvs in build plans);
     `pkgsCross.musl32.musl.version` → `"1.2.5"`.
     (`pkgsCross.musl32.gcc.version` evaluates to 15.2.0 but that is not what
     the cross stdenv builds — trust `stdenv.cc.version`.)
2. Builds:
   - `nix build nixpkgs#pkgsCross.musl32.hello` (from darwin): plan = 12
     derivations, all `system = aarch64-darwin` (cross-binutils 2.46
     `--build=arm64-apple-darwin --target=i686-unknown-linux-musl`, nolibc-gcc
     15.3.0, musl 1.2.5, cross gcc 15.3.0, hello) — nothing cached for a
     darwin build platform, so the entire cross toolchain compiles locally.
     Aborted at ~28 min (card bound 10 min), still inside cross-binutils.
     Darwin→i686 cross is *supported* (no eval error), just source-bootstrapped
     and slow.
   - `nix build nixpkgs#pkgsCross.gnu32.hello` (from darwin): no build plan
     printed within 12 min (cross-glibc evaluation is heavy/contended);
     aborted per bound.
   - `nix build --system x86_64-linux nixpkgs#pkgsCross.gnu32.hello`:
     evaluates fine; 474.8 MiB x86_64-linux bootstrap stdenv substituted from
     cache.nixos.org; 14 cross derivations (i686 cross binutils 2.46,
     nolibc-gcc 15.3.0, glibc 2.42-100, libgcc, cross gcc 15.3.0, hello)
     dispatched to the external x86_64-linux builder VM (2 vCPU/4 GiB).
     Aborted at ~26 min (extended cap; card default 10) while still compiling
     cross-binutils. No eval/builder/dispatch errors — the path works; the
     one-time cross-toolchain compile simply exceeds the bound. Once built it
     is cached and subsequent fixture builds are fast.
   - `legacyPackages.i686-linux.hello`: entire i686-linux stdenv (gcc 15.2.0,
     glibc 2.42) substituted from cache; final drv fails with the
     platform-mismatch error quoted above.
3. Docker workaround (build AND run i386 locally, bounded):
   - `docker run --rm --platform linux/386 alpine:3.20` → `uname -m` =
     `i686`; `cc` not in base image, `apk add build-base` → gcc 13.2.1 (musl).
   - `hello.c` (freestanding, raw `int $0x80` write/exit_group, `_start`):
     `cc -static -nostdlib -ffreestanding` →
     `ELF 32-bit LSB executable, Intel 80386, statically linked`
     (`readelf -h`: Class ELF32, Machine: Intel 80386, Type EXEC, entry
     0x804902a). Runs: prints `hello from i386 static`, `exit=42`.
   - Emulation cost: compute-bound 2e8-iteration loop, full
     container+apk+compile+run cycle: linux/386 (QEMU TCG) 32.0 s vs native
     arm64 1.7 s ≈ **18–19x**; 300k-iteration shell loop: 10.6 s (386) vs
     8.2 s (arm64 container) vs 6.4 s (amd64 via Rosetta) — startup-dominated
     at that size. Fine for smoke fixtures; not for benchmarks.
   - Bonus: the i386 run printed `s=3649838848` where native printed
     `s=19999999900000000` — 32-bit `unsigned long` wrap, i.e. the target
     really is ILP32 i386.

## Table

| attr | triple | eval (aarch64-darwin) | build attempt | where it runs |
|---|---|---|---|---|
| `pkgsCross.musl32` | i686-unknown-linux-musl | OK | `.hello` plan OK; full toolchain from source; aborted ~28 min | locally on aarch64-darwin (drvs `system=aarch64-darwin`) |
| `pkgsCross.gnu32` | i686-unknown-linux-gnu | OK | no plan in 12 min (slow cross-glibc eval); aborted; `--system x86_64-linux` variant: bootstrap cached, cross toolchain compiling on builder, aborted ~26 min | `--system x86_64-linux` → external x86_64-linux builder VM |
| `pkgsi686Linux` | (i686-linux) | throws: "i686 Linux package set can only be used with the x86 family." | n/a | n/a — never reaches a builder |
| `pkgsCross.i686-unknown-linux-musl` | — | attr does not exist | n/a | n/a (use `musl32`) |
| `legacyPackages.i686-linux` | i686-linux | OK (native set) | stdenv 100% from cache; final drv: `Required system: 'i686-linux'` … platform mismatch | nowhere on this machine (no i686-linux builder) |
| docker `--platform linux/386` alpine:3.20 | i686 (real ia32 kernel mode) | n/a | static ELF32 EM_386 built + run, exit 42 | Docker Desktop Linux VM via QEMU TCG (~18x compute cost) |

## Consequence for SPEC

- **Phase 0 flake (`mkI686rt`, `mkI686rtTests`)**: fixtures must use
  `pkgsCross.musl32` (i686-unknown-linux-musl, musl 1.2.5, gcc 15.3.0) —
  exactly mirroring a32rt's cross-musl fixture pattern — and glibc fixtures
  via `pkgsCross.gnu32`. Never reference `pkgsi686Linux` (throws on any
  non-x86 eval host, including our darwin machines and aarch64-linux CI);
  never `pkgsCross.i686-unknown-linux-musl` (does not exist). `mkI686rt`
  itself is an aarch64-linux-musl build (like `mkA32rt`) and is unaffected.
- **Fixture-build strategy**: nix cross builds of i686 fixtures are possible
  from this machine but pay a one-time full cross-toolchain compile —
  either locally from aarch64-darwin (slowest; nothing cached for a darwin
  build platform) or, preferred, `nix build --system x86_64-linux …` on the
  external builder (bootstrap stdenv cached from cache.nixos.org; ~14 cross
  drvs, est. well over the 10-min experiment bound once, then cached in
  /nix/store). Budget that one-time cost at Phase 0 and keep the toolchain
  warm.
- **E-test / day-to-day fixture strategy**: build AND run i386 fixtures
  locally via `docker run --platform linux/386 alpine:3.20` with
  `apk add build-base` + `cc -static` (musl gcc 13.2.1). Proven end-to-end in
  seconds. This is also a free secondary oracle: fixtures execute under a
  real ia32 Linux before i686rt runs them (and could serve later ia32
  probes). QEMU TCG makes compile+run cycles ~18x slower than native —
  acceptable for smoke tests, not for performance claims (SPEC's ≥30%
  CoreMark goal must be measured on lima/aarch64 hardware, not here).
- Cross-check links: macOS cannot run EM_386 natively and Rosetta is x86_64
  only (D14/E03), so docker-QEMU is the only local execution path; lima
  (aarch64-linux + i686rt) remains the ground-truth executor per SPEC.
