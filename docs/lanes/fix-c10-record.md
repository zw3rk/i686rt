# Fix campaign C10 record — formal dynamic-glibc RC4 rerun

Card L-C10 (docs/lanes/fix-campaign.md), 2026-10-23, worktree
`../i686rt-c10`, branch `lane/fix-c10`.  Verification-only lane: no
`src/` or `tools/` files were changed.

## Verdict

**FAIL — the gate run did not print PASS.**  The dynamic glibc-i386
test binary loads and runs to its final phase under i686rt (dynamic
loader, glibc 2.44 startup, SIGFPE handler + siglongjmp, pthread
create/join clone path, guest child thread execution all traced
working), but the process then blocks forever in a host futex right
after the guest child thread exits, and the 30-minute wall-clock bound
fired without a PASS line.  This closes nothing: the RC4 glibc
deviation stays open and needs a translator-side fix (escalated; see
"Diagnosis" below).  Per the card, no source change was made.

## glibc sysroot (deb filename + stamp)

Built on the host (macOS) with the campaign procedure: the shared deb
pool from the main checkout was copied into this worktree's
(gitignored) `_sysroot/pool`, then `python3 tools/setup_sysroot.py`
was run in the worktree (same pattern as RC7b ran setup-wine32.sh on
the host).  Output:

    setup_sysroot: libc6: newest pool version 2.44-3 (libc6_2.44-3_i386.deb)
    setup_sysroot: cached libc6_2.44-3_i386.deb
    setup_sysroot: extracted libc6_2.44-3 (39 entries)
    setup_sysroot: created usrmerge compat symlink lib -> usr/lib
    setup_sysroot: ld-linux.so.2 -> lib/i386-linux-gnu/ld-linux.so.2 (ELF32/EM_386 ok)
    setup_sysroot: libc.so.6 -> lib/i386-linux-gnu/libc.so.6 (ELF32/EM_386 ok)
    setup_sysroot: stamp written: .../_sysroot/debian-i386/.stamp
    L4B OK

Packages (pool/main/g/glibc/, sha256):

- `libc6_2.44-3_i386.deb`
  `84993d459cf69ef0a5e099e35a9eb1569f354b88bd49396b994af63b39ae0c30`
  (extracted by tools/setup_sysroot.py; recorded in the stamp)
- `libc6-dev_2.44-3_i386.deb`
  `1f8b8d04b49cdf84056d4e74ca6eeed188ba14aaa22da500d47349073495096f`
  (added post-stamp: libc6 ships no headers/crt1.o/libc_nonshared.a,
  which the card's `--sysroot` compile step requires; extracted with
  the script's own documented fallback engine, docker linux/386
  alpine + dpkg-deb -x)
- `libgcc-s1_14.2.0-19_i386.deb`
  `a4c71fd856d2a48a7505a087b4186e3cca23f94603c05e3fb7c799b27e72f761`
  (runtime libgcc_s.so.1, reused from the shared pool)

The host `_sysroot` was never written to; everything landed in the
worktree-local gitignored copy.

## i686rt build

    make build CC=/nix/store/cs8q52va4acssg38pivn7f9kyvk9lzjd-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc

(product: `_build/i686rt`, "ELF 64-bit LSB pie executable, ARM aarch64,
static-pie linked").

## Exact compile command (docker linux/386 alpine:3.20)

Worktree mounted at /w; inside the container after `apk add gcc
musl-dev`:

    gcc -O2 -o /w/_build/test_p4_glibc /w/tests/test_p4_glibc.c \
      --sysroot=/w/_sysroot/debian-i386 \
      -isystem /w/_sysroot/debian-i386/usr/include/i386-linux-gnu \
      -B/w/_sysroot/debian-i386/usr/lib/i386-linux-gnu/ \
      -L/w/_sysroot/debian-i386/usr/lib/i386-linux-gnu \
      -Wl,--dynamic-linker=/lib/ld-linux.so.2 \
      -Wl,-rpath-link,/w/_sysroot/debian-i386/usr/lib/i386-linux-gnu \
      -pthread

(`-isystem .../usr/include/i386-linux-gnu` is needed because Debian
keeps the arch-specific `bits/`, `gnu/` headers in the multiarch
include dir; `-B`/`-L` point startfile and library search at the
multiarch lib dir.  NOT -static — the musl pattern was deliberately
not used.)

Resulting binary (tests/test_p4_glibc.c unmodified):

    ELF 32-bit LSB pie executable, Intel 80386, dynamically linked,
    interpreter /lib/ld-linux.so.2 ... for GNU/Linux 3.2.0

DT_NEEDED: `libc.so.6` (nothing else).

## Exact gate run (arm64 alpine:3.20, run ONCE)

    docker run --rm --platform linux/arm64 \
      --name i686rt-c10-gate-20681 --cidfile /tmp/c10-gate-56922-cid.txt \
      -v <worktree>:/w --memory=2g --cpus=2 alpine:3.20 \
      timeout 1790 sh -c '
        echo "GATE_START $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        /w/_build/i686rt --sysroot /w/_sysroot/debian-i386 -- /w/_build/test_p4_glibc
        rc=$?
        echo "I686RT_RC=$rc"
        echo "GATE_END $(date -u +%Y-%m-%dT%H:%M:%SZ)"'

Verbatim output tail (complete output):

    GATE_START 2026-10-23T13:44:25Z
    DOCKER_EXIT=124

No PASS/FAIL line was ever printed; `DOCKER_EXIT=124` is the 30-minute
wall-clock bound.  The bound (host `timeout` plus in-container
`timeout 1790`) fired on time, but signal propagation did not reach
the blocked translator process, so the container survived its bound
and was stopped explicitly by identity (`docker stop` on
i686rt-c10-gate-20681) and removal was verified via `docker ps -a` —
the same orphan-survival class recorded in docs/lanes/phase-4.md
"Diagnostic cleanup (2026-10-22)".

## Diagnosis (one bounded I686RT_SYSTRACE=1 rerun, not a gate re-run)

Host-side observation of the blocked gate process
(`/proc/<pid>/syscall` inside the container):

    98 0x40a4bd60 0x109 0x2 0x0 0x0 0xffffffff ...

= futex(uaddr, WAIT_BITSET|CLOCK_REALTIME, val=2, timeout=NULL,
bitset=ANY), process in state S with exactly 1 host thread, 0 CPU
time.  The translator is parked, not spinning.

The SYSTRACE tail (I686RT_SYSTRACE=1 I686RT_SIGTRACE=1; 78 lines
total, verbatim tail):

    SIG tid=8 sig=8 trapno=0 eip=004011b8 cr2=00000000 esp=dffffdb0 frame=dffffad0 gs=0033/40001580 ret=dffffe1c sys=df7ff330 tcb=40001580 40001a78 40001580 00000000
    SYS 8 175 -> 0 (bx=00000002 cx=0040407c dx=00000000 si=00000008)
    SYS 8 174 -> 0 (bx=00000021 cx=dffffb44 dx=00000000 si=00000008)
    SYS 8 175 -> 0 (bx=00000001 cx=dffffcf4 dx=00000000 si=00000008)
    SYS 8 192 -> 1076146176 (bx=00000000 cx=00801000 dx=00000003 si=00020022)
    SYS 8 219 -> 0 (bx=4024b000 cx=00001000 dx=00000066 si=40a4bb40)
    SYS 8 45 -> 4214784 (bx=00000000 cx=4023fe34 dx=00000000 si=40240740)
    SYS 8 45 -> 4349952 (bx=00426000 cx=4023fe34 dx=00426000 si=40240740)
    SYS 8 45 -> 4354048 (bx=00427000 cx=4023fe34 dx=00427000 si=40240740)
    SYS 8 175 -> 0 (bx=00000000 cx=401cda2c dx=dffffce8 si=00000008)
    SYS 8 435 -> -38 (bx=dffffbf0 cx=00000058 dx=400955c0 si=40a4bb40)
    CLN tid=8 flags=003d0f00 newsp=40a4b424 tls=dffffc4c gs_sel=0033 gs_base=40001580 eip=40132cc4
    TLSSET tid=8 entry=6 base=40a4bb40
    CLNCHILD gs_sel=0033 gs_base=40a4bb40 eip=40132cc4 esp=40a4b424 parent_sys=df7ff330
    SYS 8 120 -> 101 (bx=003d0f00 cx=40a4b424 dx=40a4bba8 si=dffffc4c)
    SYS 8 175 -> 0 (bx=00000002 cx=dffffce8 dx=00000000 si=00000008)
    SYS 8 311 -> -38 (bx=40a4bbac cx=0000000c dx=00000000 si=4023fe34)
    SYS 8 175 -> 0 (bx=00000002 cx=40a4bfbc dx=00000000 si=00000008)
    SYS 8 175 -> 0 (bx=00000000 cx=40a4bfbc dx=00000000 si=00000008)
    SYS 8 219 -> 0 (bx=4024b000 cx=007fc000 dx=00000004 si=00801000)
    SYS 8 1 -> 0 (bx=00000000 cx=4023fe34 dx=00000000 si=00801000)

Reading:

- glibc 2.44 startup completes: `statx` (383), `set_robust_list` (311)
  and `rseq` (386) all return -ENOSYS (-38) and glibc tolerates all
  three; `set_thread_area` (243) and `set_tid_address` (258) succeed.
- SIGFPE (sig 8) is delivered to the guest (`SIG tid=8 sig=8`), the
  handler runs, siglongjmp recovers, and main proceeds — matching the
  RC4 interp fixes.
- pthread_create: glibc first tries `clone3` (435, -ENOSYS), then the
  fallback `clone` (120) with flags 0x3d0f00
  (CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|
  CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID) returns child
  tid 101; the child host thread is spawned with the correct TLS/GS.
- The child runs to completion and exits via guest syscall 1 — plain
  `exit(0)`, which on real Linux terminates only that task (this is
  glibc's normal thread-exit path, `__exit_thread`).  That is the last
  traced syscall; the parent's pthread_join futex wait never returns.

Working hypothesis for the follow-up fix (NOT applied — verification
lane): the CHILD_CLEARTID clear+FUTEX_WAKE at guest thread exit (the
RC4-era fix) does not fire on this path — most likely because the
`exit(1)`-as-thread-exit route (or the clone3->clone(120) fallback
registration of child_tidptr, whose `di` argument is not visible in
the SYS trace lines) never clears/wakes the child's tid futex word, so
glibc's joiner waits forever.  Secondary observation: the blocked wait
uses op 0x109 (WAIT_BITSET|CLOCK_REALTIME, no PRIVATE flag) with
val=2, which does not match a plain musl-internal lock wait and looks
like the forwarded guest futex; confirming the exact guest-side glibc
site needs the translator-side owner.

The 386 TCG oracle (running the same binary natively under
qemu-i386/TCG inside docker linux/386) could not serve as a control:
two bounded attempts segfaulted under qemu user-emulation (explicit
ld-linux.so.2 invocation, then qemu-i386 -L).  This matches the oracle
flakiness already recorded in docs/lanes/phase-4.md ("The rebuilt
oracle binary hangs under the debian:386 TCG container (env issue)").
The RC4 oracle precedent used a musl binary; no glibc-oracle PASS was
ever demonstrated on this host, so this remains an environmental gap,
not new translator evidence.

## Cleanup

Every container was run with a unique name + --cidfile, memory/CPU
limits, and wall-clock bounds; after each completion, failure, or
manual stop, `docker ps -a` filtered on the c10 names was empty
(i686rt-c10-extract-*, i686rt-c10-compile-*, i686rt-c10-oracle-*,
i686rt-c10-gate-20681, i686rt-c10-sysdiag-15952).  No c10 containers
or host wrapper processes survive.

## Escalation

1. The gate needs a translator-side fix (thread-exit wakeup /
   CHILD_CLEARTID path after clone3 fallback) — outside this lane's
   ownership; per the card this is the stop-and-report path.
2. The bound-enforcement gap (blocked processes survive both the host
   `timeout` and the in-container `timeout`) recurs; the lifecycle
   rule "verify with docker ps and stop by identity" is what kept the
   host clean here.
