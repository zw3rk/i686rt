# E06 — nixpkgs i686 cross attr names + practical local i386 fixture path

Experiment card E06 (Phase E). Question: **Which nixpkgs attr(s) build i686
(32-bit x86) artifacts, and what is the practical local path for building AND
running i386 test fixtures on this machine?**

## Environment

- nix 2.35.3, `system = aarch64-darwin` (macOS, Apple Silicon).
- `external-builders`: a nix-linux-builder VM serving **aarch64-linux** and
  **x86_64-linux** only — no i686-linux builder is registered.
- nixpkgs = `flake:nixpkgs` registry pin, release **26.05**
  (`/nix/store/mcw86k11xl4bnd6mhb7b93l34kxr13lz-source`).
- Docker Desktop (aarch64) can run `--platform linux/386` (QEMU TCG) and
  `linux/amd64` (Rosetta) images.
- Cache: cache.nixos.org + others (see `nix config show substituters`).

## Hypothesis

`pkgsCross.musl32` (i686-unknown-linux-musl) and `pkgsi686Linux` /
`pkgsCross.gnu32` exist; i686-linux derivations have no registered builder, so
the practical fixture path needs a workaround (external x86_64-linux builder
cross-compiling to i686, or docker linux/386).

## Procedure

1. Evaluate candidate attrs and record exact command + output:
   - `nix eval nixpkgs#pkgsCross.musl32.stdenv.hostPlatform.config`
   - `nix eval nixpkgs#pkgsCross.gnu32.stdenv.hostPlatform.config`
   - `nix eval nixpkgs#pkgsi686Linux.stdenv.hostPlatform.config`
   - `nix eval nixpkgs#pkgsCross.i686-unknown-linux-musl.stdenv.hostPlatform.config`
     (expected: may not exist)
   - gcc/musl version strings for the cross stdenvs.
2. Build attempts (record each outcome, including failure/abort text):
   - `nix build nixpkgs#pkgsCross.musl32.hello` (from aarch64-darwin),
   - `nix build nixpkgs#pkgsCross.gnu32.hello` (from aarch64-darwin),
   - `nix build --system x86_64-linux nixpkgs#pkgsCross.gnu32.hello`
     (external x86_64-linux builder becomes the host).
   Builds are bounded: abort anything running > 10 min and record that as the
   finding (one deliberate, recorded exception for the decisive `--system
   x86_64-linux` probe: capped at 25 min total because cache downloads
   dominated the first ~12 min; see FINDINGS).
3. Docker linux/386 workaround: prove a trivial static i386 binary builds and
   runs (`hello.c`, raw `int 0x80` write/exit_group), record exit/output and
   the ELF header; measure the QEMU TCG emulation cost on a compute-bound
   loop (`loop.c`) vs native.

## Files

- `commands.log` — exact commands and outputs (chronological; the musl32
  darwin-local build ran concurrently with the docker probes, so their entries
  interleave).
- `hello.c`, `loop.c` — fixture sources used by the docker probe.
- `FINDINGS.md` — verdict, evidence table, consequence for SPEC.
