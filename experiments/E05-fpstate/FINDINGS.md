# E05 — fpstate: i386 FPU signal-frame layout, `struct _fpstate_32` and the FXSR/xstate magics

VERDICT: ANSWER: magic1=FP_XSTATE_MAGIC1=0x46505853 u32 in sw_reserved at fpstate+0x240 (kernel writes it on EVERY use_fxsr() frame, i.e. fxsave and xsave alike); magic2=FP_XSTATE_MAGIC2=0x46505845 u32 at buf_fx+xstate_size (written only when use_xsave()); the separate u16 _fpstate_32.magic at fpstate+0x6e is the OLD FXSR magic X86_FXSR_MAGIC=0x0000 (0xffff = FPU-only convention; "0xA467" is bogus) and is never checked on sigreturn; conditions: use_fxsr()->{magic=0x0000, magic1=MAGIC1, extended_size=user_size+4+112(ia32)}, use_xsave()->+{magic2, FPSSE bits forced}, fsave-only->neither magic written, fpstate=0 when no FP context.

## Evidence

All citations are to the files fetched verbatim under `sources/`
(torvalds/linux master, 2026-10-20) and verified against v5.15, v6.1, v6.6,
v6.12, v6.15 tags — the constants are identical across all of them.

### 1. The three magics, exactly

- `FP_XSTATE_MAGIC1 = 0x46505853U`, `FP_XSTATE_MAGIC2 = 0x46505845U`,
  `FP_XSTATE_MAGIC2_SIZE = 4` — uapi-sigcontext.h:21-23.
  NOT 0x46505854 for magic2 (a common misquote); glibc agrees exactly
  (glibc-x86-sigcontext.h:27-29) and so does QEMU linux-user
  (qemu-i386-signal.c:28-29, comments "FPXS"/"FPXE").
- `X86_FXSR_MAGIC = 0x0000` — uapi-sigcontext.h:102. This is the "old FXSR
  magic": the u16 at `_fpstate_32.magic` (offset 0x6e, uapi-sigcontext.h:118-119
  "0xffff: regular FPU data only, 0x0000: FXSR FPU data"). The card's
  suspected "0xA467" does not exist anywhere in the kernel/glibc sources.
- `sw_reserved` is `struct _fpx_sw_bytes` (uapi-sigcontext.h:40-70), overlaid
  at fpstate+0x240 via the `padding2[12]` union (uapi-sigcontext.h:132-135);
  0x240 = 112 (fsave header) + 464 (FXSAVE bytes 464..511 reserved for SW).

### 2. magic assignment conditions (kernel writer side)

fpu-signal.c (master):
- `save_fsave_header()` :69-96 — for ia32 fxstate frames writes the
  fsave-format header (convert_from_fxsr env, fpu-regset.c:331-366), sets
  `status = xsave->i387.swd` (:84) and `magic = X86_FXSR_MAGIC`
  (:85) — only under `use_fxsr()`; the pure-fsave branch copies swd→status
  and writes no magic.
- `save_sw_bytes()` :105-115 — `magic1 = FP_XSTATE_MAGIC1` UNCONDITIONALLY
  (i.e. also on fxsave-only CPUs), `extended_size = user_size + 4 (+112 for
  ia32)`, `xfeatures = user_xfeatures`, `xstate_size = user_size`.
- `save_xstate_epilog()` :117-148 — writes sw_reserved at `&x->i387.sw_reserved`
  (fx image + 464); `magic2 = FP_XSTATE_MAGIC2` at `buf + fpstate->user_size`
  ONLY `if (use_xsave())` (:128-132); forces FP+SSE bits (:145).
- Frame positioning: fpu-signal.c:494-509 `fpu__alloc_mathframe` —
  `buf_fx = round_down(sp - frame_size, 64)`, and for ia32+fxsr the fsave
  header is 112 bytes below, so `sc.fpstate = buf_fx - 112`; whole-map ASCII
  in signal.c:194-208; ia32 stack alignment `((sp + 4) & -16) - 4`
  (signal.c:137-142).
- v5.15 agreement: fpu-signal-v5.15.c:95-134 (same epilog structure) and
  :524 `fx_sw_reserved.magic1 = FP_XSTATE_MAGIC1` (unconditional there too).

sigreturn acceptance (kernel reader side), fpu-signal.c:27-64
`check_xstate_in_sigframe` + :343 `fx_only = !fx_sw_user.magic1`:
- xstate restore only if `magic1 == FP_XSTATE_MAGIC1` AND
  `xstate_size >= 576` AND `<= user_size` AND `<= extended_size` AND the u32
  at `buf_fx + xstate_size == FP_XSTATE_MAGIC2`; anything else falls back to
  fx-only restore of the 512-byte fxsave area. The u16 at 0x6e is never read.

### 3. Offset tables

See offsets.txt (verified twice: real i386 gcc offsetof run,
probe/layout_probe.out, docker linux/386 alpine; and clang
-fdump-record-layouts, probe/clang-layout-dump.txt — identical).
Headlines: `sizeof(sigcontext_32) = 88` (fpstate ptr @ 0x4c, oldmask 0x50,
cr2 0x54 — the SPEC §3.5 listed order `fpstate*, oldmask, cr2` is correct);
`sizeof(_fpstate_32) = 624`; `_st @ 0x1c`, `status @ 0x6c`, `magic @ 0x6e`,
`_fxsr_env @ 0x70`, `mxcsr @ 0x88`, `_xmm @ 0x110`,
`sw_reserved @ 0x240`; frames: `sigframe_ia32 = 732` B (sc @ 0x8,
fpstate_unused placeholder @ 0x60, extramask @ 0x2d0, retcode @ 0x2d4),
`rt_sigframe_ia32 = 268` B (info @ 0x10, uc @ 0x90, uc_mcontext @ 0xa4,
uc_sigmask @ 0xfc, retcode @ 0x104); `UC_FP_XSTATE = 0x1` in uc_flags when
the CPU has XSAVE (signal_32.c:360-363, ucontext.h:10).

### 4. Live frame dump (secondary implementation view)

probe/sigframe_probe.out (docker linux/386, QEMU user-mode i386 on the arm64
linuxkit kernel — frame constructed by QEMU, see probe/docker-env.txt):
`sw_reserved.magic1 = 0x46505853`, `xstate_size = 2696`,
`extended_size = 2812 = 2696 + 4 + 112`, `xfeatures = 0x21f`,
`(fpstate+112) % 64 == 0`, `magic2 @ +112+xstate_size = 0x46505845` —
every load-bearing constant and the +112 buf_fx relationship confirmed.
QEMU divergences from the kernel on the two ADVISORY bytes:
`fpstate->magic = 0xffff` for fxsr/xsave frames
(qemu-i386-signal.c:396-397) where the kernel writes 0x0000, and
`magic1 = 0` for fxsave-only frames (:325) where the kernel writes
FP_XSTATE_MAGIC1. Harmless in practice (nothing on the restore path reads
them) but relevant if i686rt ever diffs frames against QEMU-generated goldens.

### 5. Restorer / SA_RESTORER on i386

`SA_RESTORER = 0x04000000` (uapi-signal.h:64). Kernel selection
(signal_32.c): SA_RESTORER → `sa_restorer`; else non-RT uses vdso
`__kernel_sigreturn` with an in-frame `retcode` fallback
(`popl %eax; movl $119,%eax; int $0x80`, :267-288, still always written for
gdb); RT uses vdso `__kernel_rt_sigreturn` with no in-frame fallback
(:367-371). glibc does NOT "always" pass a restorer: it sets SA_RESTORER +
`__restore`/`__restore_rt` only when `dl_sysinfo_dso == NULL` (no vDSO);
with a vDSO it passes `sa_restorer = NULL` and no SA_RESTORER
(glibc-i386-libc_sigaction.c:27-37; identical in glibc 2.28,
glibc-2.28-i386-sigaction.c:27-41). musl ALWAYS sets SA_RESTORER
(musl-sigaction.c:48-50; musl-i386-restore.s: 119/173 via `int $0x80`).

## Consequence for SPEC

- §3.5 currently says "FXSR area + magic 0x46505853 [U]" — patch to: fpstate
  is a 624-byte `_fpstate_32` = 112-byte fsave-format header (env + st[8] +
  status@0x6c + magic@0x6e = `X86_FXSR_MAGIC` 0x0000) followed by the
  64-byte-aligned FXSAVE/XSAVE image at fpstate+112 (mxcsr = fx+24, st =
  fx+32, xmm = fx+160, sw_reserved = fx+464); `sw_reserved.magic1 =
  FP_XSTATE_MAGIC1` 0x46505853, `extended_size = xstate_size+4+112`,
  `xstate_size`, `xfeatures`; `magic2 = FP_XSTATE_MAGIC2` 0x46505845 at
  fx+xstate_size when xsave is advertised; `sc.fpstate = 0` when there is no
  FP context. The D15-adjacent sigframe builder must also set
  `uc_flags |= UC_FP_XSTATE (0x1)` on RT frames when xsave is advertised.
- Phase 4 (signals): i686rt always emulates SSE, so it always builds FXSR
  frames and should decide once whether to advertise xsave in the
  synthesized /proc/cpuinfo (D10): advertise fxsr-only → user_size = 512,
  magic1 = MAGIC1, NO magic2, xfeatures = FPSSE (0x3), extended_size = 628;
  or advertise xsave → additionally write the xsave header (FPSSE forced)
  and magic2. Either choice is kernel-valid; the sigreturn side must accept
  the kernel's fallback rules (bad/missing magic1 or magic2 → fx-only
  restore of 512 bytes; fpstate == NULL → clear FP state) and must NOT
  reject on the 0x6e magic byte.
- Restorer handling: musl guests always arrive with SA_RESTORER; glibc
  guests arrive with SA_RESTORER absent whenever AT_SYSINFO_EHDR was
  delivered — i686rt must then use its synthetic vDSO
  `__kernel_(rt_)sigreturn` as pretcode (D12 already plans the symbols);
  the RT path has no retcode fallback, so the vDSO must always be mapped.
  Non-RT frames keep the 8-byte retcode image for gdb compatibility.
