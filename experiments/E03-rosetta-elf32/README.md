# E03 — rosetta-elf32 experiment

Exact behaviour of RosettaLinux on a 32-bit x86 (`ELFCLASS32`/`EM_386`)
static ELF. Results and SPEC consequences: `FINDINGS.md`.

## Layout

| File | What it is |
|------|------------|
| `gen_hello386.c` | Curated C11 generator for the ELF32 EM_386 test vector (no cross toolchain needed) |
| `hello-i386` | 96-byte test vector: one R+X PT_LOAD, entry 0x08048054, `mov $1,%eax; mov $42,%ebx; int $0x80` |
| `run-e03.sh` | Probe driver; re-runs every measurement below |
| `logs/` | Verbatim as-run transcripts (`00-environment.log` first) |

## What is measured

1. **Baselines** — the guest+Rosetta pipeline is proven working first, on
   both hosts: hl on Apple Silicon macOS with x86_64 `test-hello`/busybox
   through hl's Rosetta path, and the lima `hl-rosetta` VM (vz, aarch64)
   with the Rosetta share at `/mnt/lima-rosetta` (explicit translator call
   and kernel binfmt dispatch, both x86_64).
2. **Core probe** (SPEC §0 E03 method) — `/mnt/lima-rosetta/rosetta
   /tmp/hello-i386`: the RosettaLinux translator itself is handed the ELF32
   image. Exit status, stdout and stderr are captured byte-exactly (`od`).
3. **Kernel-direct exec** in the Rosetta VM, with and without the VM's
   pre-existing `qemu-i386` binfmt handler (reversible `echo 0/1` cycle on
   `/proc/sys/fs/binfmt_misc/qemu-i386`, restored in the same command).
4. **hl routes** — `hl ./hello-i386` (launch), guest-`execve` of the ELF32
   inside an hl x86_64 guest, guest-`execve` of the translator image, and
   native launch of the translator — documenting that every hl path to
   Rosetta is ELF64/EM_X86_64-gated.

## Reproduce

Prerequisites (as run 2026-10-20):

- Apple Silicon macOS with Rosetta installed
  (`/Library/Apple/usr/libexec/oah/RosettaLinux/rosetta` present),
- `../hyper-linux/_build/hl` built (read-only use),
- the x86_64 guest binaries from the hyper-linux devshell
  (`nix develop ../hyper-linux` → `$GUEST_X64_TEST_BINARIES`,
  `$GUEST_X64_BUSYBOX`; the driver pins the store paths it used),
- lima VM `hl-rosetta` running (vz, `vmOpts.vz.rosetta: enabled, binfmt`),
  `limactl` at the nix store path pinned in the driver,
- `clang` on the Mac.

```sh
clang -std=c11 -Wall -Wextra -pedantic -o gen_hello386 gen_hello386.c
./gen_hello386          # writes hello-i386 (96 bytes)
./run-e03.sh            # writes logs/*.log
```

Note: the lima VM carries third-party qemu-user-static binfmt handlers; an
unqualified direct exec of `hello-i386` there is emulated by `qemu-i386`
(exit 42) and is NOT Rosetta behaviour — `run-e03.sh` isolates both cases
and restores the handler state.
