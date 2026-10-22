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
