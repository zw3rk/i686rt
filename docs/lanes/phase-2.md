# Phase 2 — static libc + busybox lane cards (frozen by the coordinator)

Frozen on master (read-only to lanes): `src/os/structs_i386.h` (guest
layouts + _Static_asserts), `src/os/marshal.h` (copy helpers + registry),
`src/os/marshal.c`, `src/os/vdso.h` (vDSO contract), `src/os/syscalls.c`
REGISTRY CORE (L2f owns the file but the init-once skeleton and registry
adapters stay), all Phase 0/1 sources, SPEC.md, AGENTS.md, this file.
Reference: `../a32rt` @ d84feb3 (`src/syscalls.c` is the marshalling
style guide), `experiments/E04,E05,E07` FINDINGS for layout/ABI pins.

Common rules: as Phase 1 (worktree/branch only; never push; Curated C11
zero-warning under the cross gcc; one commit after the check; escalate
after 2 failed attempts / needed file outside ownership / ambiguity).
Cross-compile checks: `nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc`
with `CC=aarch64-unknown-linux-musl-gcc` (see Phase 0 amendment).
Host syscall numbers come ONLY from `src/os/syscalls_i386.h` (generated,
authoritative). Guest memory access ONLY via marshal.h helpers or
i686_guest_ptr with explicit bounds thinking. Handlers return int64_t:
value ≥ 0 or -errno (negative). All registered via
`i686_sys_register(I686__NR_<name>, fn)` in the module init.

| Lane | Branch/worktree | Owns | Check (once) |
|---|---|---|---|
| L2a | `lane/2-l2a` `../i686rt-l2a` | `src/os/sys_stat.c` | cross-compile + `tests/unit/test_l2a` prints `L2A OK` |
| L2b | `lane/2-l2b` `../i686rt-l2b` | `src/os/sys_sock.c` | same pattern → `L2B OK` |
| L2c | `lane/2-l2c` `../i686rt-l2c` | `src/os/sys_ipc.c` | → `L2C OK` |
| L2d | `lane/2-l2d` `../i686rt-l2d` | `src/os/sys_time.c` | → `L2D OK` |
| L2e | `lane/2-l2e` `../i686rt-l2e` | `src/os/sys_misc.c` | → `L2E OK` |
| L2f | `lane/2-l2f` `../i686rt-l2f` | `src/os/sys_pass.c`, `src/os/syscalls.c` | → `L2F OK` |
| L2g | `lane/2-l2g` `../i686rt-l2g` | `src/os/vdso.c`, `src/os/vdso32/` (asm + linker script), `src/os/vdso32_blob.c` (generated), `tools/mkvdso32.sh` | → `L2G OK` |
| L2h | `lane/2-l2h` `../i686rt-l2h` | `src/rt32/rt32_stack32.c` (auxv section only), `src/os/proc.c`, `tools/fetch_busybox.sh`, `Makefile` (append test-p2 targets) | → `L2H OK` |

Unit-check pattern (all lanes): cross-compile the module zero-warning,
then build+run a host-native unit driver `tests/unit/test_l2<X>.c`
(fake window ctx; hand-built guest structs; assert byte-exact guest
layouts and errno mapping; link the module + marshal.c + a test-local
guest-memory shim if needed) printing `L2<X> OK`.

## Scope lists (nrs resolved from syscalls_i386.h; names authoritative)

- **L2a stat/dirent**: stat64, lstat64, fstat64, fstatat64 (translate host
  struct stat → i686_stat64_t; verify each frozen layout against musl's
  i386 bits headers + kernel uapi and ESCALATE any mismatch), statfs,
  fstatfs, statfs64 (the sz argument must equal 84), fstatfs64, getdents
  (old, i686_linux_dirent_t) and getdents64 with the d_off cookie remap
  (a32rt map_dir_cookie pattern), readlink/readlinkat where they touch
  /proc (delegate proc paths to `i686_proc_open_at` if present, else
  normal host path).
- **L2b socketcall**: socketcall(102) multiplexer reading the guest args
  ARRAY (unsigned long*, 32-bit entries): socket bind connect listen
  accept accept4? (i386 socketcall subop set per kernel) getsockname
  getpeername socketpair sendto recvfrom send recv shutdown setsockopt
  getsockopt; plus direct (non-multiplexed) i386 socket syscalls
  (socketcall covers all on i386 — confirm from the table); msghdr/
  cmsghdr/iovec deep-copy with iovec aggregation; SO_/SOL_ constants are
  ABI-identical (verify; escalate diffs).
- **L2c ipc**: ipc(117) with the `version` (call x) layout: first arg
  packs (call << 16) | version; implement semget/semctl/semop/semtimedop,
  shmget/shmat/shmdt/shmctl, msgget/msgctl/msgsnd/msgrcv; shmat returns
  guest address via rt32 window allocation for shm regions (v1: map a
  fresh window region, host shmat into a scratch buffer + copy on
  shmdt is UNACCEPTABLE for correctness of ls-style loads — implement
  host shmat into a temporary host buffer then i686_copy_to_guest ONLY
  for v1 (documented limitation, busybox does not use SysV shm); mark a
  Phase H follow-up); semctl union marshalling; ipc64 struct conversions
  (define locally per kernel uapi; the frozen header intentionally omits
  them — add defines in sys_ipc.c, sizes verified against kernel).
- **L2d time**: time, stime, gettimeofday, settimeofday, adjtimex
  (timex conversion 32↔64), nanosleep, clock_gettime, clock_settime,
  clock_getres, clock_nanosleep, getitimer/setitimer (i686_itimerval_t),
  alarm, plus the time64 set (clock_gettime64 etc., nr ≥ 403 names from
  the table) sharing converters with 64-bit host timespec.
- **L2e misc**: select (old struct form, i686_select_args_t) and
  _newselect, epoll_create/epoll_ctl/epoll_wait/epoll_pwait
  (i686_epoll_event_t packing), flock + fcntl/fcntl64 (flock64
  translation, F_/O_ flag mapping — O_ flags differ i386↔aarch64! build
  the mapping table from kernel fcntl.h values), getrlimit/setrlimit/
  ugetrlimit/prlimit64 (i686_rlimit_t), sysinfo (i686_sysinfo_t + mem_unit
  scaling), old mmap(90) via i686_mmap_arg_struct_t, madvise passthrough.
- **L2f process + passthrough + registry**: fork(2) and vfork(190) = host
  fork() (window is MAP_PRIVATE anon → COW semantics are exactly fork;
  child returns 0 and CONTINUES in the interp loop — no re-init; document
  that parent/child share nothing but must both clean regions on exit —
  v1: acceptable), wait4(114)/waitpid(7) with rusage conversion,
  clone(120) returns -ENOSYS in Phase 2 (Phase 4), execve(11)/execveat:
  leave -ENOSYS (coordinator implements in-process exec at S2 using the
  L2h auxv/vDSO pieces — do NOT stub it yourself). Layout-neutral
  passthroughs: open/close/lseek/dup/dup2/dup3/readlinkat?/unlink/
  rmdir/mkdir/rename/link/symlink/chmod/fchmod/chown/fchmodat/fchownat/
  lchown/fchown/access/faccessat/chdir/fchdir/getcwd/ioctl (whitelist
  TCGETS/TCSETS/TCGETA? + TIOCGWINSZ + neutral no-arg ioctls; else
  -ENOTTY), getuid/geteuid/getgid/getegid/getpid/getppid/setuid/setgid/
  setgroups( marshalled array)/umask/getdents already L2a, mprotect via
  rt32, munmap, mremap, exit/exit_group already present, set_tid_address
  (store, return prev), prctl(PR_GET/SET_NAME only), futex(240) v1:
  single-threaded semantics: FUTEX_WAKE→0, FUTEX_WAIT→verify value then
  -EAGAIN (document; real futex in Phase 4), kill(37)/signal stubs
  -ENOSYS (Phase 4), rt_sigaction/rt_sigprocmask/rt_sigpending minimal
  STORE-ONLY state (no delivery until Phase 4; sigprocmask returns old
  mask zeros; sigaction records handler for Phase 4 use) — busybox sh
  calls these at startup and must not see -ENOSYS for them.
- **L2g vDSO**: tools/mkvdso32.sh builds src/os/vdso32/vdso32.so from
  hand-written asm via `docker run --platform linux/386 alpine` (apk add
  binutils; as + ld with a linker script: ELF32 SO, e_entry =
  __kernel_vsyscall, version script LINUX_2.5/LINUX_2.6 as in vdso.h,
  .dynsym/.gnu.version/.dynvers; small enough to eyeball with readelf -V)
  and emits src/os/vdso32_blob.c (byte array + size). src/os/vdso.c
  implements i686_vdso_map per vdso.h (parse minimal ELF32: phdrs, map
  PT_LOADs into one window region "[vdso]", align; set ctx->vdso_base;
  resolve __kernel_vsyscall via .dynsym — no relocation processing needed
  for a static asm image with absolute symbols; document assumptions).
  vdso32 bodies: __kernel_vsyscall: int $0x80; ret;
  __kernel_sigreturn: popl %eax; movl $119,%eax; jmp 1f... implement the
  kernel-expected sequences: sigreturn: mov $__NR_sigreturn,%eax; int $0x80;
  rt_sigreturn likewise with 173; __vdso_clock_gettime(time64)/
  gettimeofday/time/clock_getres: mov $NR,%eax; int $0x80; ret (args
  already in i386 syscall regs only for clock_gettime(2 args) — for
  gettimeofday/time/clock_getres the vDSO ABI uses the SAME args as the
  syscall ✓ document each).
- **L2h auxv + /proc + busybox**: rt32_stack32.c auxv section → i386 set
  (E07): AT_SYSINFO (= i686_vdso_vsyscall_addr(ctx)) AND AT_SYSINFO_EHDR
  (= ctx->vdso_base) both emitted when vdso mapped; AT_HWCAP = CPUID.1.EDX
  feature mask (D10 constant), AT_PLATFORM "i686" (string on the stack),
  AT_PAGESZ 4096, AT_PHDR/AT_PHENT/AT_PHNUM/AT_ENTRY/AT_BASE (interp),
  AT_UID/EUID/GID/EGID, AT_SECURE 0, AT_RANDOM (16 random-ish bytes on
  the guest stack, pointer emitted), AT_EXECFN (exec_path string), AT_NULL
  last. src/os/proc.c: i686_proc_open_at(ctx, dirfd, path) + friends —
  virtualize /proc/self/exe (opens ctx->exec_path), /proc/self/cmdline,
  /proc/self/maps (from ctx->regions), /proc/version (minimal),
  /proc/cpuinfo (vendor/family/flags per D10); integrate with rt32 guest
  path resolution (open-time redirect; follow a32rt's try_open_virtual_proc
  pattern in ../a32rt/src/syscalls.c). tools/fetch_busybox.sh: curl the
  Alpine x86_64? NO — Alpine i686 busybox-static apk (dl-cdn.alpinelinux.org,
  latest-stable/main/x86? use x86 arch dir) → extract bin/busybox to
  _build/busybox-i686 (verify `file` says ELF 32-bit LSB Intel 80386;
  reference URL + sha256 in a stamp file). Makefile: targets
  `busybox` (fetch), `test-p2-lima` (document + run the RC2 command on
  the aarch64 docker VM like test-p1: run `./_build/i686rt --
  _build/busybox-i686 sh -c 'ls / && echo ok'`), `test-p2-fixture`-style
  oracle self-check (docker 386 run busybox `sh -c 'echo ok'` → ok).

Coordinator note: after S2 merge I implement in-process execve (guest ELF
reload + L2h auxv + vDSO) and run RC2.

Sync S2: batch review, merge all lanes, coordinator integration (execve),
RC2: `make test-p2-lima` (busybox `sh -c 'ls / && echo ok'` → `ok`, interp,
aarch64 docker VM with the recorded lima deviation).

## S2 progress record (2026-10-21)

- All eight lanes merged; coordinator fixes applied: i686_select_args_t
  5-word form, sa_handler darwin guard, full I686__NR_* macro generation
  (462), /proc wiring into sys_open, fcntl O_DIRECT four-bit arbitration
  (L2f's table wins), in-process execve (regions teardown minus [vdso],
  fresh i386 stack/auxv, registry preserved).
- Interpreter fix from the RC2 chase: 0x91-0x97 XCHG eAX,r synthesis
  (was a no-op swap; musl PIC conventions corrupted argv/applet state).
  busybox `echo hi` now prints and exits 0 under interp.
- RC2 remains open: `busybox sh -c 'ls / && echo ok'` crashes in sh init
  (~37k insns in, corrupted return slot on a function epilogue; -O0 vs
  -O2 divergence (127 vs SIGSEGV) points at UB in our C; UBSan is not
  available for cross-musl; next step: targeted watchpoint on the
  caller frame or bisect the trace writes).
- RC2-debug state (precise): O2 vs -O0 builds of the SAME interpreter
  diverge at trace line 8432, at guest 0x08063215 `jne` closing a
  byte-compare loop (0x0806320d: xor ecx,ecx / mov bl,[edx+ecx] / test
  / je / inc ecx / cmp [eax+ecx-1],bl / jne). O2 takes the back-edge,
  O0 falls through — same inputs, different flags => undefined behavior
  in our C (in, or affecting, the CMP_EbGb->lazy-SUB->JNE path or the
  memory values feeding it). 37k-insn crash later is downstream
  corruption. Next: gdb both builds side by side at guest 0x0806320d,
  compare ctx->eflags/lazy state and guest memory at [eax+ecx-1].

## RC2 debug state (turn N)

- Fixed and working after the xchg fix: busybox `echo hi` end-to-end.
- sh `-c`/script modes: ash tokenizes multi-word lines as ONE word
  ("echo ok" exec'd whole). qemu-vs-ours checkpoint diff (tool: parse
  qemu -d in_asm,exec,nochain Trace lines for TB-start eips; walk our
  T-trace; collapse qemu rep-chunking repeats) pins the FIRST semantic
  divergence to musl init env processing at 0x81177b9: our getenv-family
  lookup returns NULL where qemu finds a value. The compare engine is
  the strncmp at 0x8113904 (stack-slot pointer pairs at (%esp)/0x1c(%esp),
  advanced by addl $1,(%esp) / addl $1,0x1c(%esp) at 0x8113922).
  Symptom cluster: repeated same-address reads at the s2 pointer.
  Next: gdb dump BOTH slots (%esp and %esp+0x1c) plus al/cl per
  iteration at 0x8113932 for the LC_ALL-family lookups; the mismatching
  iteration is the bug. q3 trace: /tmp/i686smoke/qs3.txt; ours:
  /tmp/scr1.txt (sh /w/script).
