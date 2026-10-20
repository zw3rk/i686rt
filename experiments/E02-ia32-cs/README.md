# E02 — ia32-cs: does `ia32_emulation=0` (kernel 6.7+) remove the 32-bit user code segment?

Card (SPEC §6 E02): with `ia32_emulation=0`, does `__USER32_CS` (selector
0x23) stay in the GDT and still execute 32-bit code via a far jump, while
int 0x80 entry is blocked and i386 ELF exec fails? Answer: yes — see
`FINDINGS.md` for the verdict and evidence.

## Layout

| File | Purpose |
| --- | --- |
| `FINDINGS.md` | Verdict line + evidence + SPEC consequence (D3, H4) |
| `probe-farjmp.S` | Freestanding static non-PIE x86-64: records CS, far-jumps into selector 0x23, runs a `.code32` stub (`mov $0x5A5A,%eax; lret`), reports OK / dies with SIGSEGV (139) |
| `probe-int80.c` | Freestanding x86-64: `int $0x80` with eax=9999; prints returned eax (-38 = ENOSYS) or dies with SIGSEGV (139) |
| `gen_hello386.c` | Host C11 generator that emits the ELF32 i386 hello binary byte-by-byte (no cross toolchain): `mov $1,%eax; mov $42,%ebx; int $0x80` → exit(42) |
| `run-exe.c` | Guest helper: execve() wrapper printing the raw errno on failure (8 = ENOEXEC), so a refused i386 ELF is unambiguous (ash would otherwise retry it as a script) |
| `init` | Guest PID 1 script: runs the three probes, reports exit codes, `poweroff -f` |
| `fetch-downloads.sh` | Fetches the Alpine kernel + busybox-static into `downloads/` |
| `mkinit.sh` | Compiles the probes in docker (`--platform linux/amd64 alpine` + gcc, TCG), runs the host generator, assembles the gzipped newc initramfs (with `/dev/console`) |
| `run-boot.sh` | Boots the VM (qemu TCG, serial → log file) with a watchdog |
| `boot-default.log` | Serial log, boot A: `console=ttyS0 panic=-1` |
| `boot-ia32off.log` | Serial log, boot B: `console=ttyS0 panic=-1 ia32_emulation=0` |
| `downloads/`, `build/` | Untracked artifacts (kernel image, busybox, binaries, cpio) |

## External artifacts (not committed; size > policy)

- Kernel: <https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/x86_64/netboot-3.22.6/vmlinuz-virt>
  - sha256 `6b58e5d779e44e57c9efa20232da18650415eceb9d4f544e5c165c1f392c5d51`
  - 6.12.110-0-virt; published config has `CONFIG_IA32_EMULATION=y`,
    `CONFIG_IA32_EMULATION_DEFAULT_DISABLED` not set; validated empirically
    (default boot runs an i386 static ELF).
- Busybox: <https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/busybox-static-1.37.0-r20.apk>
  - sha256 `488ad6efd04b5a722719e79f8e0dcc2c24afd6758867af3ce41b04839e60c74b`
- qemu: `nix build nixpkgs#qemu` (10.2.4); run-boot.sh honors `$QEMU`.

## Reproduce

```sh
cd experiments/E02-ia32-cs
./fetch-downloads.sh        # kernel + busybox into downloads/
./mkinit.sh                 # probes (docker amd64) + hello-i386 + initramfs
./run-boot.sh boot-default.log                       # boot A (default)
./run-boot.sh boot-ia32off.log "ia32_emulation=0"    # boot B
```

Requirements: docker (amd64 emulation), nix for qemu (or a native
`qemu-system-x86_64` via `QEMU=…`), curl, a C11 compiler for the host
generator.

## Exit-code key (guest init output)

- `probe-farjmp`: rc 0 with `FARJMP:OK eax=0x5a5a` = 32-bit code executed
  in selector 0x23; rc 139 = SIGSEGV at the `ljmp` (selector unusable).
- `probe-int80`: rc 0 with printed eax (-38 = ENOSYS) = compat entry ran;
  rc 139 = SIGSEGV at `int $0x80` (entry blocked, #GP).
- `hello-i386`: rc 42 = ELF32 exec + int 0x80 exit(42) worked; rc 139 =
  ran but int 0x80 blocked; rc 127 with `EXEC:…: errno=8` = execve
  refused (ENOEXEC).
