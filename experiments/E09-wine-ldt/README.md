# E09 — wine-ldt: what Wine (32-bit, non-wow64) needs from the LDT

Card: E09. Question: "What exactly does Wine (32-bit, non-wow64) need from
the LDT?"

Deliverables: (a) the set of `modify_ldt` operations Wine uses; (b) the
descriptor kinds it installs (incl. `struct user_desc` flag usage); (c) the
instruction surface touching LDT selectors; (d) GDT TLS (`set_thread_area`)
usage side by side. Anything i686rt must support that is not in SPEC D8
today is called out explicitly.

## Method

Source study of wine-mirror/wine, primary commit
`840a939ee526137639665ff5f587224d6a36403f` (dev HEAD, sparse cone
`dlls/ntdll/unix`, `dlls/krnl386.exe16`, `include/wine`), cross-checked
against release tags `wine-10.0` (`b073859675060c9211fcbccfd90e4e87520dc2c2`),
`wine-8.0` (`6677c044abb711f423fadfb61f2c9a37da6ff686`), `wine-5.0`,
`wine-3.0`, `wine-2.0`, `wine-0.9.37` (via `libs/wine/ldt.c`) to confirm the
findings are stable across the deployed Wine era, not a dev-HEAD artifact.

Layout note: the standalone `ldt.c` is gone from modern Wine. The LDT
machinery now lives in `dlls/ntdll/unix/signal_i386.c` (syscall wrappers,
`ldt_set_entry`, `%fs`/`set_thread_area`), `dlls/ntdll/unix/virtual.c`
(shadow `ldt_copy`, `ldt_bitmap`, `NtSetLdtEntries`), and
`dlls/krnl386.exe16/selector.c` + `int31.c` (Win16/DPMI allocator and API).
Wine keeps its own shadow copy of every entry it writes and never reads the
LDT back from the kernel.

Optional live trace: attempted per card. Debian bookworm i386 container +
`wine32` 8.0~repack-4 installed fine, but `strace` fails inside Docker
Desktop's `--platform linux/386` (binfmt qemu-user-static):
`ptrace(PTRACE_TRACEME): Function not implemented`. Skipped per the
~10-minute rule; the source evidence below is complete without it.

## Contents

- `FINDINGS.md` — verdict, evidence with file:line citations, and
  consequence for SPEC (D8 refinement, Phase 7 card contents).
