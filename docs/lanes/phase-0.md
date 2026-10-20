# Phase 0 — scaffold lane cards (frozen by the coordinator before fan-out)

Frozen on master before fan-out (read-only to lanes): `src/i686rt.h`
(`i686_ctx_t`, ABI-locked offsets 0..35303), `src/main.c` (invocation stub),
`include/a32host.h` (vendored byte-identical to a32rt's), this file, SPEC.md,
AGENTS.md. Reference: `../a32rt` @ d84feb3 (read-only).

Common lane rules (same as Phase E): work only in your worktree on your
branch; never touch master/other lanes/`../a32rt`/`../hyper-linux`; never
push; Curated C11 (`-std=c11 -Wall -Wextra -Werror=vla -pedantic`, no VLA,
no sprintf/strcpy/strcat); commit once when your check passes with a plain
message (no AI mentions); escalate per protocol (2 failed check attempts,
needed file outside ownership, ambiguity).

| Lane | Branch / worktree | Owns | Check (run once) |
|---|---|---|---|
| L0a | `lane/0-l0a` `../i686rt-l0a` | `src/rt32/**` | cross-compile each `src/rt32/*.c` (see card) |
| L0b | `lane/0-l0b` `../i686rt-l0b` | `flake.nix`, `flake.lock` | `nix build .#i686rt` → static-PIE aarch64 ELF (main.c only; rt32 not yet present pre-merge) |
| L0c | `lane/0-l0c` `../i686rt-l0c` | `Makefile`, `LICENSE`, `.gitignore` | `nix develop nixpkgs#pkgsCross.aarch64-multiplatform-musl -c make build` → `_build/i686rt`, `file` shows `static-pie` |

Coordinator amendment (2026-10-21, after L0c escalation): `nix develop
nixpkgs#pkgsCross.aarch64-multiplatform-musl` is broken on this host (the
cross stdenv's env-derivation fails under the nix daemon with an empty log;
suspect stale `__impureHostDeps` referencing a path absent on macOS 26.5.2).
All Phase 0 lane checks that need the aarch64 musl cross toolchain use the
equivalent `nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc`
form instead (compiler is gcc-flavored: `aarch64-unknown-linux-musl-gcc`).
Verified outcomes stand: L0b `nix build .#i686rt` → static-PIE (plain form);
L0c cross build → static-PIE via nix shell with `CC` override.

## Card L0a — vendor a32rt ISA-agnostic core into `src/rt32/` (rt32_ prefix)

Scope: copy-first vendoring (D13). Copy from `../a32rt/src/` and mechanically
rename: `a32_`→`rt32_`, `A32_`→`RT32_`, `a32rt.h`→`i686rt.h` include. Keep
`a32h_*` symbols untouched (vendored `include/a32host.h`, D14). Files:
- `vm.c` → `src/rt32/rt32_vm.c` (window init, regions, brk, mmap2/mremap/
  munmap/mprotect, gap finder — ISA-agnostic)
- `elf32.c` → `src/rt32/rt32_elf32.c` (ELF32 loader, PT_INTERP via sysroot;
  DROP `a32_kuser_setup` → `rt32_kuser_setup` entirely — replaced by the
  i386 vDSO in Phase 2; leave a one-line comment where it was)
- `stack32.c` → `src/rt32/rt32_stack32.c` (initial stack; auxv contents are
  ARM-flavored and will be rewritten in Phase 2 — copy as-is for now)
- `host.c` → `src/rt32/rt32_host.c` (`/dev/a32host` probe, `I686RT_HOST`
  env must be honored in place of `A32RT_HOST`)
- `a64_emit.c`/`a64_emit.h` → `src/rt32/rt32_a64_emit.c`/`.h` (host-side
  emitter, reused as-is later by the DBT)
- new `src/rt32/rt32.h`: renamed prototypes for the above, typed on
  `i686_ctx_t` (from `src/i686rt.h`); document the a32rt origin of each
  file in a header comment (file, commit d84feb3).
Env renames: `A32RT_WINDOW`→`I686RT_WINDOW`, `A32RT_HOST`→`I686RT_HOST`
(and any other `A32RT_*` env the copied code reads — map all to `I686RT_*`).
Do NOT copy jit.c/decode_*/syscalls.c/signals.c/aot.c/gdb.c/main.c/vfp_neon.c
(later phases adapt them; jitcore in Phase 3, marshal in Phase 2).
Check (once): inside `nix develop nixpkgs#pkgsCross.aarch64-multiplatform-musl`
run for each `src/rt32/*.c`:
`clang -std=c11 -Wall -Wextra -Werror=vla -pedantic -I../include -I../src -c <f> -o /tmp/l0a-<n>.o`
(compiler in that shell is the aarch64 musl cross clang). All must succeed.
Expected: every file compiles with zero warnings; `ls /tmp/l0a-*.o` lists them.

## Card L0b — flake.nix (mkI686rt)

Scope: `flake.nix` (+ generated `flake.lock`) modeled on `../a32rt/flake.nix`
(read it first): package `i686rt` for `aarch64-linux` via
`pkgsCross.aarch64-multiplatform-musl` (from `aarch64-darwin` this dispatches
to the external builder — `nix build --system aarch64-linux .#i686rt` also
acceptable if plain `.#i686rt` cannot schedule; record which worked),
static-PIE, building via the repo Makefile if present else direct clang of
`src/main.c` (+`src/rt32/*.c` when they exist — glob so the flake stays
correct after L0a merges; pre-merge it builds main.c alone and must still
link). Also define `mkI686rtTests` as an eval-only placeholder attr set
(fixtures arrive Phase 1 via `pkgsCross.musl32`, E06). Install
`bin/i686rt` and an `i686rt-binfmt-p` symlink (argv0 alias convention, D-0.1).
Check (once): `nix build .#i686rt` (or the --system form) then
`file ./result/bin/i686rt` → contains `static-pie` (and `ARM aarch64`).

## Card L0c — Makefile skeleton + LICENSE

Scope: self-documenting Makefile (## help default goal; grouped targets;
.PHONY; products in `_build/`; basic targets `all`, `build`, `test`,
`check`, `clean` as agreed aliases; `test-p0-lima` stub target that prints
"phase 0: no test yet"); `build` compiles `src/main.c` + glob
`src/rt32/*.c` with `$(CC) $(CFLAGS)` where CC/CFLAGS default to the shell's
cross clang (works inside `nix develop nixpkgs#pkgsCross.aarch64-multiplatform-musl`),
CFLAGS = `-std=c11 -Wall -Wextra -Werror=vla -pedantic -Os -static-pie
-Iinclude -Isrc` (add `-fPIE` and link `-static-pie`); Apache-2.0 `LICENSE`
(copy text from `../a32rt/LICENSE`); `.gitignore` gains `_build/` and
`/result`.
Check (once): `nix develop nixpkgs#pkgsCross.aarch64-multiplatform-musl -c make build`
then `file _build/i686rt` → contains `static-pie`.

Sync S0 (coordinator, after all three merge): RC0 check
`nix build .#i686rt && file ./result/bin/i686rt` → static-PIE aarch64 ELF.
