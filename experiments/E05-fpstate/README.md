# E05 — fpstate: `struct _fpstate_32` layout and the FXSR/xstate magic values

## Hypothesis (SPEC §3.5, marked [U])

SPEC's current text — "fpstate = `_fpstate_32` (x87 env + 8x10-byte regs +
FXSR area + magic 0x46505853 [U])" — conflates three distinct magics. Card
E05 hypothesis row: `_fpstate_32.magic` = 0x0000 for FXSR,
`FP_XSTATE_MAGIC1` = 0x46505853 in sw_reserved. Resolve exactly:

1. field order/offsets of `struct _fpstate_32` (and `struct sigcontext_32`
   for the frame builder);
2. when `magic1` is 0 vs `FP_XSTATE_MAGIC1`, and what `sw_reserved` /
   `magic2` (`FP_XSTATE_MAGIC2`) are — including the real value of the "old
   FXSR magic" (the card suspects 0xA467 is bogus);
3. non-RT vs RT i386 frame layouts as the kernel defines them;
4. glibc's SA_RESTORER usage on i386 ("always passes restorer" — verify).

## Procedure

- `sources/` holds the primary sources, curl-fetched 2026-10-20 from
  torvalds/linux master (plus v5.15 fpu/signal.c and v5.15..v6.15 constant
  spot-checks), glibc master and glibc 2.28, musl master, and QEMU master:

  | file | origin |
  |---|---|
  | uapi-sigcontext.h | arch/x86/include/uapi/asm/sigcontext.h |
  | asm-sigcontext.h | arch/x86/include/asm/sigcontext.h (legacy shim) |
  | signal_32.c | arch/x86/kernel/signal_32.c |
  | signal.c | arch/x86/kernel/signal.c (get_sigframe) |
  | fpu-signal.c / fpu-signal-v5.15.c | arch/x86/kernel/fpu/signal.c |
  | fpu-regset.c | arch/x86/kernel/fpu/regset.c (convert_from_fxsr) |
  | fpu-types.h | arch/x86/include/asm/fpu/types.h (fregs_state = 112 B) |
  | asm-sigframe.h | arch/x86/include/asm/sigframe.h (frame structs) |
  | asm-sighandling.h | arch/x86/include/asm/sighandling.h |
  | ucontext.h, uapi-signal.h | uapi headers (UC_FP_XSTATE, SA_RESTORER) |
  | glibc-i386-libc_sigaction.c | glibc sysdeps/unix/sysv/linux/i386/libc_sigaction.c (master; sigaction.c was renamed) |
  | glibc-2.28-i386-sigaction.c | same file at glibc-2.28 |
  | glibc-x86-sigcontext.h | glibc sysdeps/unix/sysv/linux/x86/bits/sigcontext.h |
  | musl-sigaction.c, musl-i386-restore.s | musl src/signal |
  | qemu-i386-signal.c | qemu linux-user/i386/signal.c |

- `probe/k-sigcontext.h` is the uapi header with only its two kernel-internal
  `#include` lines stubbed by typedefs; every struct is untouched.
- `probe/layout_probe.c` prints offsetof/sizeof for sigcontext_32,
  _fpstate_32, _fpx_sw_bytes, ucontext_ia32, sigframe_ia32, rt_sigframe_ia32
  plus cross-checks. Built and run with real i386 gcc
  (`docker run --platform linux/386 alpine` + apk gcc, static); output in
  `probe/layout_probe.out`. Independently cross-checked with
  `clang -m32 -Xclang -fdump-record-layouts` (probe/clang-layout-dump.txt).
- `probe/sigframe_probe.c` dumps a live RT-sigframe fpstate from inside a
  handler and checks the magics (probe/sigframe_probe.out). Caveat: the
  container is QEMU user-mode i386 on the arm64 linuxkit kernel
  (probe/docker-env.txt), so the frame is QEMU-constructed — treated as a
  second ABI implementation, not as the kernel oracle; the kernel's own
  constants come from the cited sources.

## Deliverables

- `offsets.txt` — byte-offset tables, constants, magic conditions.
- `FINDINGS.md` — verdict, evidence, consequence for SPEC.
