# E07 — vdso-sysinfo: glibc i686 vDSO symbol/version contract + %gs offset of the SYSINFO (vsyscall) pointer

VERDICT: ANSWER: sysinfo=%gs:0x10; symbols=__vdso_clock_gettime,__vdso_clock_gettime64,__vdso_gettimeofday,__vdso_time,__vdso_clock_getres; versions=LINUX_2.6 (glibc lookup); kernel vdso32 exports LINUX_2.5+LINUX_2.6

## Answers to the three questions

### (1) Symbols glibc i386 looks up in the vDSO

glibc i386 (current master) requests exactly five vDSO functions, all under
version `LINUX_2.6` (`sysdeps/unix/sysv/linux/i386/sysdep.h:252-260`):

| glibc macro (`sysdep.h`) | Symbol looked up | Version |
|---|---|---|
| `HAVE_CLOCK_GETTIME_VSYSCALL` | `__vdso_clock_gettime` | `LINUX_2.6` |
| `HAVE_CLOCK_GETTIME64_VSYSCALL` | `__vdso_clock_gettime64` | `LINUX_2.6` |
| `HAVE_GETTIMEOFDAY_VSYSCALL` | `__vdso_gettimeofday` | `LINUX_2.6` |
| `HAVE_TIME_VSYSCALL` | `__vdso_time` | `LINUX_2.6` |
| `HAVE_CLOCK_GETRES_VSYSCALL` | `__vdso_clock_getres` | `LINUX_2.6` |

- `VDSO_NAME "LINUX_2.6"`, `VDSO_HASH 61765110` (`sysdep.h:252-253`). 61765110
  is the SysV ELF hash of `"LINUX_2.6"` (verified by recomputation).
- **No `getcpu` lookup on i386**: `HAVE_GETCPU_VSYSCALL` is absent from
  `sysdeps/unix/sysv/linux/i386/sysdep.h` (it exists for x86_64), even though
  the kernel's vdso32 exports `__vdso_getcpu`.
- No `__vdso_clock_getres_time64` lookup on i386 either (kernel exports it,
  glibc i386 does not reference it).
- The lookup itself is a WEAK, *version-required* symbol request:
  `sysdeps/unix/sysv/linux/dl-vdso.h` (`dl_vdso_vsym`) builds an
  `ElfW(Sym)` with `STB_WEAK/STT_NOTYPE` and an
  `r_found_version { VDSO_NAME, VDSO_HASH, hidden = 1 }` and calls
  `_dl_lookup_symbol_x` on the vDSO link map. Missing symbols yield NULL and
  glibc falls back to the plain syscall (no error).
- Consumers: `setup_vdso_pointers()` in
  `sysdeps/unix/sysv/linux/dl-vdso-setup.h:23-46` fills
  `GLRO(dl_vdso_clock_gettime)` etc.; used by the clock/time wrappers via
  `INLINE_VSYSCALL` (`sysdeps/unix/sysv/linux/sysdep-vdso.h`).
- Side note (musl guests): musl i386 does not use the vDSO at all —
  `arch/i386/reloc.h` defines no `VDSO_CGT_SYM`, so the vdso path in
  `src/time/clock_gettime.c` compiles out. Only glibc i386 guests exercise
  this contract.

### (2) What the kernel's vdso32 actually exports

`arch/x86/entry/vdso/vdso32/vdso32.lds.S` (torvalds master, 2026-10; on
v6.1 the identical file lives at the same path) — version script lines
22-47:

```
VERSION
{
	LINUX_2.6 {
	global:
#ifdef CONFIG_COMPAT_32BIT_TIME
		__vdso_clock_gettime;
		__vdso_gettimeofday;
		__vdso_time;
		__vdso_clock_getres;
#endif /* CONFIG_COMPAT_32BIT_TIME */
		__vdso_clock_gettime64;
		__vdso_clock_getres_time64;
		__vdso_getcpu;
#ifdef CONFIG_FUTEX_ROBUST_UNLOCK
		__vdso_futex_robust_list32_try_unlock;
#endif
	};

	LINUX_2.5 {
	global:
		__kernel_vsyscall;
		__kernel_sigreturn;
		__kernel_rt_sigreturn;
	local: *;
	};
}
```

- `LINUX_2.5` carries the three kernel-ABI symbols (`__kernel_vsyscall`,
  `__kernel_sigreturn`, `__kernel_rt_sigreturn`) and marks everything else
  `local:`; `LINUX_2.6` carries the `__vdso_*` set. There is **no
  LINUX_2.12** anywhere in `arch/x86/entry/vdso*/` (grepped).
- `ENTRY(__kernel_vsyscall)` (`vdso32.lds.S:16-17`): the ELF `e_entry` is
  `__kernel_vsyscall`, with the comment "The ELF entry point can be used to
  set the AT_SYSINFO value."
- v6.1 vs master deltas (v6.1 `vdso32.lds.S:22-40`): v6.1 exports only
  `__vdso_clock_gettime/gettimeofday/time/clock_getres/clock_gettime64` under
  `LINUX_2.6` (no `getcpu`, no `clock_getres_time64`, no time32 `#ifdef`).
  Master adds `__vdso_getcpu`, `__vdso_clock_getres_time64`, the
  `CONFIG_COMPAT_32BIT_TIME` guard on time32 symbols and the robust-futex
  entry. **Every symbol glibc i386 requests is present in both.**
- `AT_SYSINFO` vs `AT_SYSINFO_EHDR` for 32-bit:
  - `arch/x86/include/asm/elf.h:289-296` (`ARCH_DLINFO_IA32`): a 32-bit
    exec gets **both** `NEW_AUX_ENT(AT_SYSINFO, VDSO_ENTRY)` and
    `NEW_AUX_ENT(AT_SYSINFO_EHDR, VDSO_CURRENT_BASE)` when the vDSO is
    mapped; `AT_SYSINFO == 32` (`elf.h:346`).
  - `elf.h:358-362`: `VDSO_CURRENT_BASE = mm->context.vdso` and
    `VDSO_ENTRY = mm->context.vdso + vdso32_image.sym___kernel_vsyscall` —
    i.e. AT_SYSINFO is the absolute address of `__kernel_vsyscall`
    (equal to `vdso_base + e_entry`).
  - `elf.h:319` makes this `ARCH_DLINFO` for `CONFIG_X86_32`;
    `elf.h:348-352` (`COMPAT_ARCH_DLINFO`) applies the same pair to EM_386
    compat execs under `CONFIG_IA32_EMULATION`.
  - `arch/x86/entry/vdso/vma.c:249-255` (`load_vdso32`, gated on
    `vdso32_enabled == 1`), `vma.c:257-267`
    (`arch_setup_additional_pages` → `load_vdso32` on X86_32) and
    `vma.c:270-283` (`compat_arch_setup_additional_pages` → `load_vdso32`
    for i386 ELF32 on 64-bit kernels). `map_vdso` records
    `mm->context.vdso` (`vma.c:212`).

### (3) Where glibc stores the AT_SYSINFO pointer in the TCB — exact offset

**`tcbhead_t.sysinfo` is at offset `0x10` from the %gs base**, i.e. the
vsyscall pointer is loaded/called via `%gs:0x10`.

Offset chain from the struct definition
(`sysdeps/i386/nptl/tls.h:33-54`, ILP32 — every pointer/uintptr_t is 4 bytes):

| Offset | Field | Size |
|---|---|---|
| `0x00` | `void *tcb` | 4 |
| `0x04` | `dtv_t *dtv` | 4 |
| `0x08` | `void *self` | 4 |
| `0x0c` | `int multiple_threads` | 4 |
| **`0x10`** | **`uintptr_t sysinfo`** | 4 |
| `0x14` | `uintptr_t stack_guard` | 4 |
| `0x18` | `uintptr_t pointer_guard` | 4 |
| `0x1c` | `int gscope_flag` | 4 |
| `0x20` | `unsigned int feature_1` | 4 |
| `0x24` | `void *__private_tm[3]` | 12 |
| `0x30` | `void *__private_ss` | 4 |
| `0x34` | `unsigned long ssp_base` | 4 |

Cross-check: `_Static_assert (offsetof (tcbhead_t, __private_ss) == 0x30)`
(`tls.h:56-58`) validates the arithmetic (0x10 + 4+4+4+4+4 + 12 = 0x30). ∎

The complete store/use chain:

1. auxv → rtld: `sysdeps/unix/sysv/linux/dl-parse_auxv.h:57-61`:
   `GLRO(dl_sysinfo_dso) = auxv_values[AT_SYSINFO_EHDR];` and, under
   `NEED_DL_SYSINFO` (defined in
   `sysdeps/unix/sysv/linux/i386/dl-sysdep.h:28`), **only if
   `dl_sysinfo_dso != NULL`**: `GLRO(dl_sysinfo) = auxv_values[AT_SYSINFO];`.
   If absent, the default is `_dl_sysinfo_int80`, an inline `int $0x80; ret`
   trampoline (`i386/dl-sysdep.h:31-32,35-42`).
2. vDSO fallback: `elf/setup-vdso.h:109-110`: if `dl_sysinfo` is still the
   default, `GLRO(dl_sysinfo) = vDSO->e_entry + l_addr` (= `__kernel_vsyscall`,
   because `e_entry == __kernel_vsyscall`).
3. store into TCB: `sysdeps/i386/nptl/tls.h:141-147`:
   `#define INIT_SYSINFO _head->sysinfo = GLRO(dl_sysinfo)`, invoked from
   `TLS_INIT_TP` (`tls.h:187`) and propagated to new threads by
   `SETUP_THREAD_SYSINFO` (`tls.h:144-145`).
4. use: `sysdeps/unix/sysv/linux/i386/sysdep.h:115-123`:
   `#define ENTER_KERNEL call *%gs:SYSINFO_OFFSET` (PIC libc), where
   `SYSINFO_OFFSET offsetof (tcbhead_t, sysinfo)`
   (`sysdeps/i386/nptl/tcb-offsets.sym:10`). The C-level inline-syscall
   variants emit `call *%%gs:%P2` with operand constraint
   `"i" (offsetof (tcbhead_t, sysinfo))` (`sysdep.h:345-358`), and
   `__libc_do_syscall` (`libc-do-syscall.S`) routes through the same
   `ENTER_KERNEL`. `I386_USE_SYSENTER` (and hence the %gs path) is enabled
   only for `IS_IN (libc) || IS_IN (libpthread)` PIC builds (`sysdep.h:36-43`);
   otherwise the literal `int $0x80` is used (`sysdep.h:122`).

## Empirical dump (provenance: qemu-user synthetic i386 vDSO, NOT a native kernel vdso32)

Docker Desktop 29.8.2 (aarch64 VM), `docker run --platform linux/386 alpine`,
2026-10-20. On Apple Silicon this runs the i386 process under qemu-user
emulation, so the `[vdso]` page at `0x408a9000` is **qemu's synthetic i386
vDSO** (`linux-user/i386/vdso.S` + `vdso.ld`), not a kernel `vdso32.so`.
It is included because it is an existence proof of exactly the D12 approach
(a hand-built 4 KiB i386 vDSO image with kernel-compatible symbols/versions)
working under emulation:

- auxv: `AT_SYSINFO (32) = 0x408a9554` and `AT_SYSINFO_EHDR (33) = 0x408a9000`
  — both entries present, mirroring `ARCH_DLINFO_IA32`.
- dumped image: ELF32 `ET_DYN` `EM_386`, single RWX PT_LOAD (0xae8 bytes),
  `e_entry = 0x554`; dynsym `__kernel_vsyscall @ base+0x554` — equals the
  AT_SYSINFO value (`base + e_entry`).
- dynsym exports: `__kernel_vsyscall`, `__vdso_clock_gettime`,
  `__vdso_clock_getres`, `__vdso_clock_gettime64`, `__vdso_gettimeofday`,
  `__vdso_time`, `__vdso_getcpu`, `__kernel_sigreturn`,
  `__kernel_rt_sigreturn`; verdef chain `linux-gate.so.1` (base) →
  `LINUX_2.6` → `LINUX_2.5`. qemu's `linux-user/i386/vdso.ld` VERSION block
  puts `__vdso_clock_gettime/gettimeofday/time/clock_getres/clock_gettime64/getcpu`
  under `LINUX_2.6` and the three `__kernel_*` under `LINUX_2.5` — same shape
  as the kernel. (qemu omits `DT_VERSYM`; the kernel's image carries it.)

## Consequence for SPEC (D12 synthetic vDSO; Phase 2 auxv/vDSO)

1. **D12 symbol set confirmed** with exact versions — the synthetic i386
   vDSO must be an ELF32 `ET_DYN` `EM_386` image whose verdefs are
   `LINUX_2.5` (base chain plus) and `LINUX_2.6`, exporting:
   - `LINUX_2.5`: `__kernel_vsyscall` (= `e_entry`), `__kernel_sigreturn`,
     `__kernel_rt_sigreturn`;
   - `LINUX_2.6`: `__vdso_clock_gettime`, `__vdso_gettimeofday`,
     `__vdso_time`, `__vdso_clock_getres`, `__vdso_clock_gettime64`
     (adding `__vdso_getcpu` is harmless and matches modern kernels).
   glibc matches *version + name* (`dl_vdso_vsym` passes `hidden=1`
   `r_found_version`), so carry `DT_VERDEF`/`DT_VERSYM` like the kernel
   image rather than qemu's versym-less layout.
2. **AT_SYSINFO contract (Phase 2 auxv L2h)**: emit BOTH
   `AT_SYSINFO (32) = vdso_base + __kernel_vsyscall_offset` (== `e_entry`)
   and `AT_SYSINFO_EHDR (33) = vdso_base`. glibc ignores AT_SYSINFO unless
   AT_SYSINFO_EHDR is also non-NULL (`dl-parse_auxv.h:57-61`) and otherwise
   falls back to `e_entry`; making `e_entry == __kernel_vsyscall` satisfies
   both paths. If no vDSO is mapped, glibc degrades to its own
   `int $0x80` trampoline — the vDSO is a fast path, not a hard requirement,
   for dynamically linked glibc.
3. **`%gs:0x10` is guest-libc-owned**: the translator never writes the TCB
   field; it must (a) place the auxv pair on the initial stack (Phase 2),
   (b) execute `call *%gs:0x10` correctly, i.e. resolve the indirect target
   through the guest %gs base + 0x10 and land in the mapped vDSO window,
   and (c) implement `__kernel_vsyscall` semantics as the int-0x80-style
   syscall ABI (args in %ebx/%ecx/%edx/%esi/%edi/%ebp, nr in %eax, result
   in %eax) — D12's `int $0x80; ret` body is exactly right, since glibc
   treats the entry as an opaque call target (the kernel's sysenter-based
   `__kernel_vsyscall` is interchangeable with the int80 one from the
   caller's perspective).
4. **Translator dispatch opportunity**: since all glibc i386 libc.so
   syscalls funnel through `*%gs:0x10` (or the `_dl_sysinfo_int80` /
   `__libc_do_syscall_int80` `int $0x80` trampolines), a cheap Phase 2
   fast-path is to recognize calls landing at the vDSO `__kernel_vsyscall`
   address as direct syscall entry.

## Escalations

None. glibc's five requested symbols are provided under `LINUX_2.6` by both
kernel master and v6.1; the only asymmetries (`__vdso_getcpu`,
`__vdso_clock_getres_time64` exported by the kernel but not requested by
glibc i386) are benign superset cases, not contradictions.
