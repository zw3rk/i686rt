# Phase 8 — vm86 (L8a → S8/RC8)

SPEC §4 8.1–8.2, §2 D8, E10 verdict (pure emulation; ABI pins below).
Runs concurrently with Phase 7 (SPEC §4.C) — no file overlap with L7a:
the v86 loop is self-contained and reuses only public handler helpers.

## Coordinator freeze (8.1 — binding)

- ctx->v86 (bit0 active) + ctx->v86state (v86.c-owned) + cs_d=0 while
  active (16-bit defaults through the normal decode path). Real-mode
  linear = ((seg << 4) + off) & 0xFFFFF; A20 off (no A20 gate exists in
  the kernel's vm86 layer — E10); IVT at physical 0x0.
- Exit codes exactly six (E10): VM86_SIGNAL 0, UNKNOWN 1, INTx 2,
  STI 3, PICRETURN 4, TRAP 6 (no code 5). Exit code returned in EAX of
  the 32-bit caller.
- do_int protocol (E10): BIOSSEG checks, int21 AH match against
  int21_revectored, IVT vectoring pushes flags/cs/ip with IP already
  past the `int`; int_revectored/int21_revectored bitmaps 32 bytes
  each (256 bits).
- VIF/VIP: SAFE_MASK 0xDD5; IOPL forced 3 semantics inside v86.
- Marshalling pins (E10): guest-side entry copy splits at
  offsetof(vm86_struct/int_revectored); is_vm86pus set kernel-side;
  screen_bitmap preserved on exit; __null_* / orig_eax ignored on
  entry.
- Syscalls: vm86old(113) and vm86(166) with VM86_ENTER,
  VM86_ENTER_NO_BYPASS, VM86_PLUS_INSTALL_CHECK (returns 0);
  VM86_FREE_IRQ / REQUEST_IRQ / GET_IRQ_BITS / GET_AND_RESET_IRQ →
  -EINVAL / -ENOSYS stubs (E10).
- Engines: v86 runs interpreter-only (D8) — the engine guard from the
  Phase 7 freeze also checks !ctx->v86 (L7a lands it; if S8 merges
  before S7, the coordinator adds the guard atomically).
- iret/int inside v86 are v86.c's own (IVT semantics), NOT h_seg far
  transfers. Faults inside v86 (limit-free real mode: only GP/UD/NP on
  opcode issues) exit as VM86_SIGNAL with the 32-bit signal pending.
- Syscall registration (113/166): handler functions in src/os/vm86.c;
  dispatch wiring by the coordinator at S8 (lane documents the
  snippet).

## Card L8a — vm86 emulation (grunt lane)

- Scope: src/interp/v86.h (self-written, mirrors seg.h style — this
  one is lane-owned) + src/interp/v86.c (self-contained
  fetch/decode/execute loop at the 20-bit linear view reusing public
  handler helpers where signatures fit; int/iret/STI-halt/popf/sti/cli
  exit conditions; do_int protocol; VIF/VIP) + src/os/vm86.c (struct
  marshalling per the pins above, both syscalls) +
  tests/test_p8_vm86.c + fixture. NO edits to decode.c, interp.c,
  seg.c, h_seg.c, engine.c (public includes only).
- Worktree ../i686rt-l8a, branch lane/8-l8a. Files owned (exclusive):
  src/interp/v86.h, src/interp/v86.c, src/os/vm86.c,
  tests/test_p8_vm86.c. Bounded: Makefile (objects).
- Fixture (SPEC 8.2): i386 program that maps real-mode code at
  0x7c00 (via plain mmap into the guest window — physical 0x7c00 is
  inside the window), fills a vm86(plus)_struct, calls vm86(166) with
  int 0x10 revectored → asserts return == VM86_INTx(0x10) with the
  pushed frame pointing past the `int`, regs as set by the real-mode
  stub; a second subtest exercises VM86_SIGNAL on a faulting opcode.
  Print PASS at the end.
- Acceptance check (single command, arm64 docker):
  `/w/i686rt -- /w/test_p8_vm86` → last line `PASS`.
- Escalate after 2 failed attempts / frozen-interface need (seg.h,
  i686rt.h, ctx fields) / ambiguity. Never push; no AI mentions.

## S8/RC8 (coordinator)

Merge L8a (--no-ff), wire syscall registration, RC8: `test_p8_vm86`
prints PASS (arm64 docker stand-in, recorded deviation).

## L8a record (lane, 2026-10-22) — PASSED

Landed on `lane/8-l8a` (worktree ../i686rt-l8a):
`src/interp/v86.h` + `src/interp/v86.c` (self-contained 16-bit
fetch/decode/execute loop: prefix stream, six IOPL-sensitive opcodes
kernel-verbatim incl. check_vip/PICRETURN/TF-re-trap/vm86dbg, do_int
protocol, traps cc/ce, executed subset 88-8b/b0-bf/c6-c7/90/c3/cb/
e8/e9/eb, A20-off linear model, G-agnostic low-megabyte bring-up with a
private 64 KiB shim for zero-base windows), `src/os/vm86.c`
(vm86old(113)/vm86(166) marshalling per the E10 pins: split copy at
offsetof(vm86_struct,int_revectored), kernel-side is_vm86pus,
__null_*/orig_eax ignored, VM86_SCREEN_BITMAP -> -EINVAL, exit
writeback of exactly ebx..eax/eip/cs/eflags/esp/ss/es/ds/fs/gs at
kernel widths, screen_bitmap preserved, packed exit code in EAX), and
`tests/test_p8_vm86.c`. Makefile needed no edit (wildcard sources).
Frozen files untouched (git status: only the four lane files).

**Syscall registration snippet** (the coordinator applies this inside
`i686_syscalls_init_once()` in src/os/syscalls.c at S8, next to the
other `i686_syscalls_*_init()` calls; 113/166 only — plain mmap(90)
already exists via L2e `i686_syscalls_misc_init()`/`r_old_mmap` and was
deliberately not touched):

```c
{
    extern void i686_sys_vm86_init(void);
    i686_sys_vm86_init();
}
```

**Acceptance check** (run once, verbatim; staging held `_build/i686rt`
+ `_build/test_p8_vm86`, fixture per tools/build_fixture.sh, docker
linux/386 gcc build, zero warnings):

```
$ docker run --rm --platform linux/arm64 --memory 1g --cpus 2 \
    --name l8a-check -v "$PWD/_build/staging":/w:ro alpine:3.20 \
    sh -c 'timeout 60 /w/i686rt -- /w/test_p8_vm86'
PASS
# rc=0; container removed; docker ps -a verified gone
```

The check binary carried the snippet above applied locally to
syscalls.c (unregistered 113/166 dispatch to -ENOSYS); the wiring was
reverted before commit — the committed tree contains NO syscalls.c
change and builds warning-clean (the one branch warning,
`dbt/engine.c:50 dbt_lookup unused`, is pre-existing on the frozen
file).

**Coordinator notes / deviations:**

1. **v86 opcode faults exit VM86_SIGNAL + pending 32-bit signal** per
   the freeze (SIGILL for unknown/unimplemented opcodes, incl. hlt;
   SIGTRAP for non-vm86pus int3/TF; SIGFPE for non-vm86pus into).
   The kernel's VM86_UNKNOWN default is therefore not generated
   anywhere; the macro stays defined. A runaway guard (2^27 steps)
   exits VM86_UNKNOWN as an emulator bound (documented in v86.c).
2. **Pre-existing Phase-1 decoder bug found (frozen decode.c, not
   touched): `66`-prefixed moffs moves (`66 a1`/`66 a3`) size the
   moffs displacement by OPERAND size (4-byte insn) instead of ADDRESS
   size (6-byte insn, SDM/GCC/objdump all use 32-bit moffs).** Any
   gcc-generated i386 `movw` to/from a static address breaks. The
   fixture works around it by accessing every u16 segment field as its
   u32 (seg|pad) pair. Recommend a Phase-1 decoder fix lane.
3. The fixture stub sits at **0x1000:0x7c00** (linear 0x17c00), keeping
   SPEC's 0x7c00 IP: the check container resolves **guest_base = 0**
   (no /dev/a32host hint), where host linear [0, mmap_min_addr) is
   unmappable, so 0:0x7c00 is not 32-bit-side addressable there. It
   exercises the identical seg<<4+off rule; in offset mode (hl) 0:0x7c00
   works identically. v86.c still contains the full G=0 shim for
   [0,0x10000) (IVT/BDA/stack) and it was exercised (trace: sub-64K
   v86 traffic via shim, self-consistent).
4. VM86 command stubs: REQUEST_IRQ -> -ENOSYS;
   FREE_IRQ/GET_IRQ_BITS/GET_AND_RESET_IRQ -> -EINVAL (freeze allowed
   "-EINVAL/-ENOSYS"); VM86_PLUS_INSTALL_CHECK -> 0; other cmds ->
   -EINVAL.
5. Signal delivery after a VM86_SIGNAL return happens at the
   interpreter's next safe point (one 32-bit instruction after the
   syscall) — Phase-4 v1 delivery-point behavior, unchanged by this
   lane.
6. v86 stack arithmetic wraps at 16 bits (kernel handle_vm86_fault
   computes push/pop addresses from the 16-bit SP view).
7. Engine guard: v86 is interpreter-only by construction (the loop runs
   on the ctx inside the syscall handler and never dispatches DBT
   blocks); the `!ctx->v86` DBT guard from the Phase 7 freeze remains
   S7/S8 coordination as written.
