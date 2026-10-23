# fix-c2 — rt32_vm stack-recycle defect evidence (for the coordinator)

Card L-C2 escalation artifact.  After the C2 fixes (delivery core, futex
val2/PI, robust exit walk, blocked-target wake, tid-namespace unify) got
the pthread cluster past its old livelocks, `functional/pthread_cancel`
deterministically dies with a guest call/ret to `eip=0`.  Root cause
class: **two guest threads of consecutive pthread_create generations
hold signal frames at overlapping guest-stack addresses while the
second generation's frame sc is zeroed between delivery and sigreturn**
— on a stack region the translator recycle-mapped in between.  The
bookkeeping/mapping side is `src/rt32/rt32_vm.c` (coordinator-owned;
this lane only committed the reproduction and the traces).

## Reproduction

- Fixture: `tests/c2_rt32_pthread_cancel_repro.c` (verbatim musl
  libc-test `src/functional/pthread_cancel.c`, MIT; origin and build
  line in the file header).
- Build: `cc -std=gnu11 -O1 -static -o pthread_cancel-static.exe <src>`
  in the linux/386 alpine:3.20 oracle container.
- Run: `_build/i686rt -- <binary>` (arm64 alpine:3.20), engine=interp.
- libc-test @ a0c28c7673121dcb9305d1ea21aa5a42a5d9929d.

## Verbatim SYSTRACE (I686RT_SYSTRACE=1, the create/recycle window)

All lines verbatim; the leading number is the host pid (7), then the
i386 syscall nr.

```
SYS 7 192 -> 1073741824 (bx=00000000 cx=00023000 dx=00000000 si=00000022)   <- mmap2(NULL, 0x23000, MAP_PRIVATE|ANON): thread A stack -> 0x40000000
SYS 7 125 -> 0 (bx=40002000 cx=00021000 dx=00000003 si=00021000)            <- mprotect(0x40002000, 0x21000, RW): stack #1 rw part
SYS 7 120 -> 101 (bx=007d0f00 cx=40022f60 dx=40022fa8 si=dffffbcc)          <- clone A (newsp 0x40022f60, CHILD_CLEARTID 0x40022fa8)
SYS 7 240 -> 1 (bx=40022fb0 cx=00000081 dx=00000001 si=000000f0)            <- main sem/first futex wake on A's pd (op WAKE|PRIVATE -> 1)
SYS 7 1 -> 0 (bx=00000000 cx=00000001 dx=40022fb0 si=000000f0)              <- A: exit(0) (async-cancelled thread gone)
SYS 7 240 -> 0 (bx=40022fb0 cx=00000080 dx=00000002 si=00000000)            <- joiner's FUTEX_WAIT|PRIVATE on A's tid word returns 0 (woken)
SYS 7 91 -> 0 (bx=40000000 cx=00023000 dx=40000000 si=00023000)             <- munmap(0x40000000, 0x23000): stack #1 recycled
SYS 7 192 -> 1073741824 (bx=00000000 cx=00023000 dx=00000000 si=00000022)   <- mmap2 #2 -> SAME 0x40000000
SYS 7 125 -> 0 (bx=40002000 cx=00021000 dx=00000003 si=00021000)            <- mprotect #2
SYS 7 120 -> 102 (bx=007d0f00 cx=40022f60 dx=40022fa8 si=dffffbcc)          <- clone B: SAME newsp 0x40022f60, SAME cleartid word
SYS 7 238 -> 0 (bx=00000066 cx=00000021 dx=00000066 si=dffffbc0)            <- pthread_cancel(B): tkill(tid 102, SIGCANCEL 33)
SYS 7 238 -> 0 (bx=0000000b cx=00000021 dx=08052fe8 si=40022f90)            <- B's cancel_handler re-raise: tkill(self, 33)
SYS 7 173 -> 0 (bx=007d0f00 cx=40022f60 dx=40022fa8 si=dffffbcc)            <- B's rt_sigreturn: restores GARBAGE (sc zeroed, below)
i686rt: interp: guest fault (host) pid=7 at eip=0x00000000, fault_addr=0x00000000
i686rt: interp: guest fault (host) at eip=0x00000000 (op:0), esp=0x40022f84
```

So the recycle itself is a clean create -> exit -> join -> munmap ->
mmap(same) -> mprotect -> clone sequence — the overlap is temporal:
**generation 1's host thread is still running its `thread_entry` tail
(registry remove, robust walk, cleartid write at 0x40022fb0, dual
futex wake) while generation 2 already interprets on the recycled
range.**

## The corruption (I686RT_SIGTRACE=1, same run shape)

Generation 1 (thread A) and generation 2 (thread B) signal frames land
at overlapping addresses on the recycled stack:

```
SIG tid=12 sig=33 ... esp=40022f30 frame=40022bb4 ...     <- A's SIGCANCEL frame (0x40022bb4..0x40022cc0)
SIG tid=13 sig=33 ... esp=40022f60 frame=40022be4 ...     <- B's SIGCANCEL frame (0x40022be4..0x40022cf0), same stack
SIGRET rt=1 esp=40022be8 frame=40022be4 rec=40022be4 ax=00000000 bp=00000000 eip=00000000
i686rt: interp: guest fault (host) pid=7 at eip=0x00000000, fault_addr=0x00000000
```

B's frame sc (at 0x40022c88..) is ZERO by the time B's sigreturn reads
it: the restored state is eax=ebp=eip=0 and the next guest fetch is the
`eip=0` fault.  A's frame from the previous generation sat exactly over
that range; A's host thread outlives its guest exit (thread_entry tail)
and the region was munmap'd + re-mapped underneath both.

B's delivery point is deterministic: the SIGCANCEL arrives 2
instructions into B's life (clone-child resume at __clone+0x30,
`eip=0804e132`, eax=0), before `start_single` executes.

## Final region map at the fault

```
MAP 08048000-08049000 r-- /w/_build/libc-test/src/functional/pthread_cancel-static.exe
MAP 08049000-08050000 r-x /w/_build/libc-test/src/functional/pthread_cancel-static.exe
MAP 08050000-08052000 r-- /w/_build/libc-test/src/functional/pthread_cancel-static.exe
MAP 08052000-08054000 rw- /w/_build/libc-test/src/functional/pthread_cancel-static.exe
MAP 40000000-40002000 --- [mmap]
MAP 40002000-40023000 rw- [mmap]
MAP df7ff000-df800000 r-x [vdso]
MAP df800000-e0000000 rw- [stack]
```

(the second-generation stack: guard + rw, exactly as requested; the
region bookkeeping matches what musl asked for at death.)

## Working hypotheses for the fix (coordinator's file)

1. `rt32_vm_munmap`/`rt32_vm_mmap2` host-mapping lifecycle across the
   recycle: if the munmap tears the host pages out of the window
   mapping and the re-mmap re-lays them, any translator-side write
   (or A-tail write through a stale host pointer) between the two can
   land in a freshly-zeroed page — B's sc was written by the delivery
   and read back zeroed.
2. Generation-1's `thread_entry` tail writes guest memory (cleartid 0
   at 0x40022fb0, plus the robust-walk cmpxchg and futex wakes) with
   no ordering against generation 2's interpreter — a watchpoint on
   0x40022c88..0x40022ce0 across the create/clone boundary will pin
   the writer (both files involved — `clone.c` tail ordering and
   `rt32_vm.c` — are coordinator-owned; this lane can apply the fix on
   request).

## What this lane already changed that is NOT this defect

The cluster's original livelocks ARE fixed on this branch (delivery
core pending semantics, futex val2/PI re-encode, robust exit walk,
blocked-target wake, cleartid dual wake, sigframe mask semantics):
`functional/pthread_cond` and `functional/pthread_robust` PASS in the
acceptance run, and the C2 dual-oracle fixtures (futex PI vs host
oracle, cancel, masked raise, robust exit) all pass under i686rt.
