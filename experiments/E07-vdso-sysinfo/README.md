# E07 — vdso-sysinfo (experiment lane)

Card E07: glibc i686 vDSO symbol/version contract + the %gs offset of the
SYSINFO (vsyscall) pointer. Source study; results in `FINDINGS.md`, the
consolidated symbol/version/offset table in `symbols.txt`.

## What was studied

All sources fetched 2026-10-20 (raw.githubusercontent.com / sourceware cgit /
git.musl-libc.org; local copies under the fetch cache, not committed):

- glibc master (bminor/glibc):
  - `sysdeps/i386/nptl/tls.h` — `tcbhead_t` layout, `INIT_SYSINFO`
  - `sysdeps/i386/nptl/tcb-offsets.sym` — `SYSINFO_OFFSET`
  - `sysdeps/unix/sysv/linux/i386/sysdep.h` — `ENTER_KERNEL`, `VDSO_NAME`,
    the `HAVE_*_VSYSCALL` list
  - `sysdeps/unix/sysv/linux/i386/dl-sysdep.h` — `NEED_DL_SYSINFO`,
    `_dl_sysinfo_int80`
  - `sysdeps/unix/sysv/linux/i386/libc-do-syscall.S` — `ENTER_KERNEL` user
  - `sysdeps/unix/sysv/linux/dl-parse_auxv.h` — AT_SYSINFO/AT_SYSINFO_EHDR
    consumption
  - `elf/setup-vdso.h`, `elf/dl-support.c` — vDSO map, `dl_sysinfo` fallback
  - `sysdeps/unix/sysv/linux/dl-vdso.h`, `dl-vdso-setup.h`, `dl-vdso-setup.c`
    — versioned weak lookup helper and pointer setup
  - `sysdeps/unix/sysv/linux/sysdep-vdso.h` — `INLINE_VSYSCALL`
- Linux master + v6.1 (torvalds/linux):
  - `arch/x86/entry/vdso/vdso32/vdso32.lds.S` (both refs) — exported
    symbols + version script, `ENTRY(__kernel_vsyscall)`
  - `arch/x86/entry/vdso/vdso32/Makefile`, `arch/x86/entry/vdso/Makefile`
  - `arch/x86/entry/vdso/vma.c` — `load_vdso32`, mapping, `mm->context.vdso`
  - `arch/x86/include/asm/elf.h` — `ARCH_DLINFO_IA32`, `AT_SYSINFO 32`,
    `VDSO_ENTRY`, `VDSO_CURRENT_BASE`, `COMPAT_ARCH_DLINFO`
- qemu master: `linux-user/i386/vdso.ld` (synthetic-vDSO precedent)
- musl master: `arch/i386/reloc.h` (no `VDSO_CGT_SYM` — musl i386 ignores
  the vDSO)

Path notes: on current master the 32-bit vDSO tree lives under
`arch/x86/entry/vdso/vdso32/` (same path on v6.1); the pre-consolidation
location `arch/x86/entry/vdso32/` no longer resolves. In glibc master the
i386 TLS header is `sysdeps/i386/nptl/tls.h` and there is no
`sysdeps/unix/sysv/linux/i386/init-first.c` any more (its role is covered by
`dl-parse_auxv.h` + `setup-vdso.h` + `INIT_SYSINFO`).

## Empirical dump (optional leg, done once)

`docker run --rm --platform linux/386 alpine:latest` on Docker Desktop
29.8.2 (aarch64 VM): dumped the `[vdso]` page via `dd` on `/proc/self/mem`
and `/proc/self/auxv`, then parsed the ELF32 image locally (dynsym/verdef
via PT_DYNAMIC).

Provenance caveat: on Apple Silicon a `--platform linux/386` container runs
under qemu-user emulation, so the dumped image is **qemu's synthetic i386
vDSO** (`linux-user/i386/vdso.S`), not a native kernel `vdso32.so`. It is
used only as a cross-check of the symbol/version shape and of the
AT_SYSINFO/AT_SYSINFO_EHDR pair, and as precedent for D12's hand-built
synthetic vDSO. A true kernel vdso32 dump would need a native x86 kernel
(none available on this host; lima is aarch64).

## Reproduction

    docker run --rm --platform linux/386 alpine sh -c \
      'start=$(grep vdso /proc/self/maps | head -1 | cut -d- -f1); \
       dd if=/proc/self/mem bs=4096 skip=$((0x$start/4096)) count=1; \
       dd if=/proc/self/auxv' > vdso-and-auxv.bin

Parse with any ELF32 tooling (`readelf -V` on binutils-equipped guests, or a
PT_DYNAMIC-based parser on the raw page, as was done here).

## Deliverables

- `FINDINGS.md` — verdict, evidence (file:line), consequence for SPEC D12 /
  Phase 2, escalations (none).
- `symbols.txt` — symbol -> version matrix (glibc expected, kernel master,
  kernel v6.1, qemu), auxv contract, TCB offset chain, dump record.
