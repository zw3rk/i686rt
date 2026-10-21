# Phase 4 — threads/TSO/signals lane cards (frozen by the coordinator)

Frozen on master (read-only to lanes): `src/os/sigframe_i386.h` (kernel-
exact sigcontext 88 B, _fpstate_32 624 B with FP_XSTATE_MAGIC1 in
sw_reserved@+0x240 per E05, rt_sigframe 268 B), `src/os/signals_i386.c`
(frame builder + sigreturn + i686_deliver_sync), `src/os/threads.h`
(clone flag set, user_desc/CLONE_SETTLS contract incl. -1 auto-alloc,
static-TSO note per D5), `src/os/clone.c` (clone: fork path for
!CLONE_VM, host-thread path for CLONE_VM|CLONE_THREAD with private ctx
copy, per-thread GS base), `src/os/sys_pass.c`'s `i686_gsig_tab` export,
and everything from Phases 0–3.

Common rules: as before (worktree/branch only; never push; Curated C11
zero-warning under the cross gcc; one commit after the check; escalate
after 2 failed attempts / needed file outside ownership / ambiguity).

| Lane | Branch/worktree | Owns | Check (once) |
|---|---|---|---|
| L4a | `lane/4-l4a` `../i686rt-l4a` | `tests/test_p4_threads_signals.c` | fixture PASS on both the i386 oracle (qemu) and i686rt interp → `L4A OK` |
| L4b | `lane/4-l4b` `../i686rt-l4b` | `tools/setup_sysroot.py` | script fetches Debian i386 glibc sysroot into `_sysroot/debian-i386/` with `ld-linux.so.2`, `libc.so.6` present + sha256 stamp → `L4B OK` |
| L4c | `lane/4-l4c` `../i686rt-l4c` | `src/dbt/emit_atomic.c` (+ `emit.h` decl block appended by coordinator — see note) | cross-compile + host-a64 unit in docker arm64 → `L4C OK` |

## Card L4a — threads/signals fixture
- tests/test_p4_threads_signals.c: freestanding i386 (own _start, int
  0x80, no libc), exercising: (1) rt_sigaction + raise a SYNC SIGSEGV
  via a null-pointer write, handler recovers via siglongjmp-style
  manual esp/eip restore + sigreturn (both non-RT frame and SA_SIGINFO
  path with SA_RESTORER to a guest retcode stub); (2) rt_sigaction for
  SIGFPE + division by zero -> handler runs, exits 0; (3) clone
  (CLONE_VM|CLONE_THREAD|CLONE_SETTLS|CLONE_PARENT_SETTID|
  CLONE_CHILD_CLEARTID) with a user_desc tls=-1 auto-alloc: child
  writes a value through its GS base, parent futex-waits on
  child_tidptr (FUTEX_WAKE from child) and verifies; (4) fork+wait4
  child exit status. End prints PASS. Build with tools/build_fixture.sh
  style (docker 386). Oracle check: runs PASS under qemu (docker
  linux/386). i686rt check: PASS under interp in docker arm64.
- NOTE (frozen contract): the sync-fault handler return path uses the
  guest sigreturn(119)/rt_sigreturn(173) syscalls; the engine routes
  those to i686_sigreturn (S4 coordinator wiring; if the lane sees
  -ENOSYS on 119/173 during ITS i686rt run, that wiring hasn't merged
  yet — run the check on the lane branch with a note, and the
  coordinator completes wiring at S4).

## Card L4b — sysroot setup
- tools/setup_sysroot.py (python3 stdlib only): fetch Debian ports
  i386 base packages (debian-ports or archive.debian.org; e.g.
  libc6_*_i386.deb + libc6-i686 + ld-linux.so.2 from libc6) and
  extract into _sysroot/debian-i386/{lib,lib/i386-linux-gnu,usr/...};
  write _sysroot/debian-i386/.stamp with URLs + sha256s; idempotent.
  Validate: ld-linux.so.2 and libc.so.6 are ELF32 EM_386 (parse the
  ELF header in the script; no `file` dependency). Expected final line
  L4B OK. (Network available; pick current Debian stable main repo.)

## Card L4c — LOCK→LSE emitters
- src/dbt/emit_atomic.c: implement i686_emit_atomic(i686_emit_ctx_t*,
  const x86_insn_t*) handling LOCK-prefixed ADD/OR/ADC/SBB/AND/SUB/XOR
  (reg+mem forms) via LSE LDADDAL/CASAL-style sequences (FEAT_LSE
  assumed; runtime HWCAP check is Phase H), XADD (SWPAL), CMPXCHG
  (CASAL loop-free on memory: load, cmp with EAX, CAS), XCHG mem
  (SWPAL). Guest EA via the frozen i686_emit_ea; atomic on [x20, w21].
  Byte/word widths: LDADDA<B/H>. Wire: translate.c dispatch is frozen —
  instead the coordinator has appended an `i686_emit_atomic` call in
  the dispatch chain (see master translate.c); lanes only add the file.
  Unit: docker arm64 micro-driver comparing against a host __sync
  oracle over a shared window page, ~12 cases → L4C OK.

## S4 progress (2026-10-21)

- All three lanes merged. Coordinator wiring landed: sigreturn(119)/
  rt_sigreturn(173) registered; host SIGSEGV/SIGBUS/SIGILL/SIGFPE
  handler + sigsetjmp checkpoint converts window faults into guest
  FAULT exits -> i686_deliver_sync; async pending delivery at interp
  safe points; the two frame bugs L4a flagged fixed (rt pinfo/puc
  fixed frame VAs; sigreturn non-RT base = frame+8 for the popped
  pretcode+sig convention); blocked-mask via i686_current_ctx.
- test_p4_threads_signals: ORACLE PASS (qemu 386). Under i686rt interp:
  rt_sigaction OK, then hangs in a tight loop around guest 0x080492xx
  after sigaction setup — 54k traced insns, no further syscalls.
  Suspects: (a) futex WAIT returns immediately (v1 stopgap) so the
  parent spin-waits on a value the child never writes, or the child
  host-thread never runs/crashes; (b) fault->handler->sigreturn loop.
  Next: trace the child thread / check clone child actually starts;
  fix futex FUTEX_WAIT to actually block on a host futex.
