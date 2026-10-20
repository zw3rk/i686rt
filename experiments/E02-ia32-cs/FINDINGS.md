# E02 — ia32-cs: does `ia32_emulation=0` (kernel 6.7+) remove the 32-bit user code segment?

VERDICT: ANSWER: ia32_emulation=0: CS-32 usable yes; int0x80 SIGSEGV; i386 ELF refused; default: CS-32 usable yes; int0x80 works; i386 ELF execs

## Hypothesis (SPEC §6 E02)

With `ia32_emulation=0`, the `__USER32_CS` descriptor (selector 0x23)
remains in the GDT and a far jump into it still executes 32-bit code,
but int 0x80 / sysenter entry is blocked and exec of i386 ELF fails.

**Result: hypothesis confirmed on kernel 6.12.110 (`ia32_emulation=0` runtime param).**

## Environment

- Kernel: Alpine `vmlinuz-virt` 6.12.110-0-virt (`CONFIG_IA32_EMULATION=y`,
  `CONFIG_IA32_EMULATION_DEFAULT_DISABLED` not set; published config checked,
  then validated empirically via the default boot).
- VM: qemu-system-x86_64 10.2.4 (TCG) on Apple Silicon macOS,
  `-m 512M -kernel … -initrd … -nographic -no-reboot`,
  `console=ttyS0 panic=-1` (+ `ia32_emulation=0` for boot B).
- Guest: busybox-static 1.37.0-r0 (Alpine v3.22) initramfs, /init runs
  `probe-farjmp`, `probe-int80`, `run-exe /hello-i386` and reports exit codes.
- `uname`: `Linux (none) 6.12.110-0-virt #1-Alpine SMP PREEMPT_DYNAMIC 2026-09-14 14:01:22 x86_64 Linux`.

## Evidence

Boot A — default (`boot-default.log`):

```
### BEGIN probe-farjmp
FARJMP: start (static non-PIE, low VA)
FARJMP: current cs=0x0033
FARJMP: attempting ljmp to selector 0x23 (__USER32_CS)
FARJMP:OK eax=0x5a5a after lret to cs=0x33
### END probe-farjmp rc=0
### BEGIN probe-int80
INT80: attempting int $0x80 with eax=9999 (invalid nr)
INT80:WORKS eax=-38 (-ENOSYS): compat entry ran
### END probe-int80 rc=0
### BEGIN hello-i386 (i386 static ELF -> exit(42) via int 0x80)
### END hello-i386 rc=42
```

- far jump into selector 0x23 executes the `.code32` stub (`mov $0x5A5A,%eax`)
  and `lret` returns to 64-bit CS 0x33 — CS-32 usable.
- int 0x80 entry runs; invalid nr 9999 returns -38 (-ENOSYS).
- the ELF32 binary execs and its `int $0x80` `exit(42)` yields rc=42 —
  this boot also empirically proves IA32 emulation is compiled in.

Boot B — `ia32_emulation=0` (`boot-ia32off.log`):

```
--- cmdline:
console=ttyS0 panic=-1 ia32_emulation=0
### BEGIN probe-farjmp
FARJMP: current cs=0x0033
FARJMP: attempting ljmp to selector 0x23 (__USER32_CS)
FARJMP:OK eax=0x5a5a after lret to cs=0x33
### END probe-farjmp rc=0
### BEGIN probe-int80
INT80: attempting int $0x80 with eax=9999 (invalid nr)
[    2.582154] traps: probe-int80[434] general protection fault ip:40102d sp:7ffcca69b558 error:402 in probe-int80[102d,401000+1000]
Segmentation fault
### END probe-int80 rc=139
### BEGIN hello-i386 (i386 static ELF -> exit(42) via int 0x80)
[    2.601843] 32-bit emulation disabled. You can reenable with ia32_emulation=on
EXEC:/hello-i386: errno=8
### END hello-i386 rc=127
```

- `__USER32_CS` (0x23) is still present and usable: same far-jump/lret
  round trip succeeds — the descriptor is NOT removed by `ia32_emulation=0`.
- int 0x80 raises #GP (error code 0x402 = EXT|IDT|vector 0x80: the IDT
  gate for vector 0x80 is gone), delivered to user space as SIGSEGV
  (rc 139). It is a trap on the instruction itself, not an ENOSYS return.
- execve of the ELFCLASS32 program returns ENOEXEC (errno 8); the kernel
  logs `32-bit emulation disabled. You can reenable with ia32_emulation=on`
  at that first compat-exec attempt. (No ia32-related line is printed at
  boot itself; the message appears on demand.)
- dmesg otherwise contains no ia32/compat lines in either boot beyond the
  cmdline echoes above.

Probe notes (trustworthiness): `probe-farjmp` is static non-PIE linked at
VA < 4 GiB with a low `.bss` stack, because 32-bit compat-mode stack
references use SS:ESP; the far-return frame is the 32-bit pair
`[ret64][0x33]` since a compat-mode `lret` pops 4+4 bytes. An earlier
build that pushed two 64-bit words faulted at the `lret` (CS read from
the upper half of the pushed RIP → null selector); that was a probe bug,
fixed before the recorded runs. Exit codes come from busybox ash
(139 = SIGSEGV).

## Consequence for SPEC

- **D3 tier-2 open question #2 is resolved: the native compat-CS fast
  path remains available on `ia32_emulation=0` hosts.** The GDT keeps
  `__USER32_CS` (0x23), user code can far-jump into 32-bit compat mode and
  far-return, so an x86_64-hosted engine could in principle execute
  guest 32-bit code natively in that segment. The blocker is only the
  syscall/vDSO surface: int 0x80 (and by kernel construction sysenter)
  entry is #GP/SIGSEGV, and compat ELF exec is ENOEXEC.
- **H4 (x86_64 tier-2 build, D3):** the interpreter build for
  x86_64-without-ia32 hosts must be an ELFCLASS64 binary that loads and
  interprets the ELFCLASS32 guest itself (execve of the guest binary is
  refused with ENOEXEC), and must route every guest syscall through the
  native 64-bit `syscall` entry — never int 0x80/sysenter, which fault.
  This experiment's VM setup (Alpine 6.12 virt kernel + qemu TCG +
  `ia32_emulation=0`) is a ready-made acceptance environment for
  `nix build .#i686rt-x86_64` (SPEC §4 H4 accept: "runs hello on an
  x86_64 kernel with ia32_emulation=0").
- The runtime knob is also re-enableable per the kernel's own message
  (`ia32_emulation=on`), matching the 6.7+ parameter design.

## Reproduce

See `README.md` in this directory (fetch-downloads.sh → mkinit.sh →
run-boot.sh). Full serial logs: `boot-default.log`, `boot-ia32off.log`.
