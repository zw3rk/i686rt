# C3 trace — RC7b gate under engine=dbt (lane fix-c3, 2026-10-23)

Verification-only record for Card L-C3 (docs/lanes/fix-campaign.md):
re-run of the RC7b gate with `I686RT_ENGINE=dbt` after H1 (the DBT loop
now installs+arms the host-fault checkpoint; docs/lanes/phase-h.md H1
record).  Worktree `../i686rt-c3`, branch `lane/fix-c3` at 2061d1c;
build `_build/i686rt` (static-PIE aarch64, 494016 B; only the
pre-existing `sse_emit_prefetch` unused-parameter warning).  Sysroot:
host `_sysroot` (668 MB) mounted read-only, verified with
`tools/setup-wine32.sh --verify` -> `WINE32-SYSROOT-OK` (rc=0) before
the runs.  arm64 alpine:3.20 container per run (unique name + cidfile,
--memory 4g --cpus 4), fresh WINEPREFIX on a mounted scratch dir per
run, host-side `timeout 1920` around `docker run`, in-container gate
bound `timeout -k 10 1800`.  Both containers verified removed
(`docker ps -a` on the names empty / `no such object` for the cid).

## Gate command (both runs, verbatim; only SYSTRACE differs in run 2)

    export HOME=/tmp/whome WINEPREFIX=/wscratch/wprefix WINEDEBUG=-all
    export WINEDLLPATH=/w/_sysroot/debian-wine32-i386/usr/lib/i386-linux-gnu/wine
    rm -rf "$WINEPREFIX"
    timeout -k 10 1800 env I686RT_ENGINE=dbt /w/_build/i686rt \
        --sysroot /w/_sysroot/debian-wine32-i386 -- \
        /w/_sysroot/debian-wine32-i386/usr/bin/wine cmd /c "echo ok"

(The RC7b invocation from docs/lanes/phase-7.md RC7b record, with the
sysroot at its shared-cache path and WINEPREFIX on the mounted scratch
dir per the C3 card.  RC7b did not interp-boot the prefix first; the
prefix is created by the single command, as recorded.)

## Run 1 — gate as prescribed (stdout+stderr merged), 2026-10-23T13:19:27Z

Verdict: FAIL — guest exit 53, stdout EMPTY (no `ok`), elapsed 330 s
(self-terminated; nowhere near the 30-min bound).  Full verbatim
output (the FreeType warnings are expected: no FreeType in the
sysroot, interp runs print them too):

    === RC7b gate, engine=dbt, 2026-10-23T13:19:27Z ===
    wine: created the configuration directory '/wscratch/wprefix'
    Wine cannot find the FreeType font library.  To enable Wine to
    use TrueType fonts please install a version of FreeType greater than
    or equal to 2.0.5.
    http://www.freetype.org
    [... 3 more identical FreeType blocks ...]
    wine: Unhandled division by zero at address 00000000 (thread 005c), starting debugger...
    wine: Unhandled division by zero at address 7BD907B6 (thread 007c), starting debugger...
    wine client error:70: write: Bad file descriptor
    Wine cannot find the FreeType font library.  To enable Wine to
    use TrueType fonts please install a version of FreeType greater than
    or equal to 2.0.5.
    http://www.freetype.org
    GATE-RC=53
    === end 2026-10-23T13:24:55Z ===

Prefix inventory after run 1: 518 files under drive_c/windows/system32,
`kernel32.dll` present (1848546 B), 398 MB total — the wineboot
fake-dll install COMPLETED, yet the chain still exited 53.  Two guest
#DE events: thread 005c at 0x00000000, thread 007c at 0x7BD907B6
(0x7b000000-class = the wine PE kernel32 load region), plus one
wineserver client write EBADF.  Under the interp engine (RC7b record)
the identical chain prints `ok` rc=0 and the only stderr noise is the
3x winevdm DOS-application line — no division-by-zero events.

## Run 2 — single prescribed diagnostic re-run, I686RT_SYSTRACE=1

2026-10-23T13:27:12Z, fresh WINEPREFIX, same gate command, bounded 316 s,
rc=53 again (deterministic), stdout empty.  SYSTRACE: 326,204 lines
(21 MB, kept untracked at `_scratch/c3-systrace-20261023-222711.err`;
NOT committed).  No retry-loop stall anywhere: every phase advances;
the chain self-terminates.

Failure sequence (verbatim trace excerpts; NUL bytes stripped):

1. Mid-boot #DE kills the wineboot install early (prefix reaches only
   278 files / 221 MB; NO system32/kernel32.dll, NO system32/ntdll.dll):

       SYS 21 3 -> 64 (bx=00000004 cx=0021ebc0 dx=00000040 si=00000000)
       SYS 21 175 -> 0 (bx=00000002 cx=0021ec30 dx=00000000 si=00000008)
       wine: Unhandled division by zero at address 682CE9A2 (thread 0064), starting debugger...
       SYS 17 4 -> 89 (bx=00000002 cx=7ff63404 dx=00000059 si=00000000)
       SYS 21 175 -> 0 (bx=00000000 cx=68322240 dx=0021fbb0 si=00000008)
       SYS 17 175 -> 0 (bx=00000000 cx=68322240 dx=019cef60 si=00000008)

   0x682CE9A2 is in the i386-unix ntdll.so mapping region (cf. T4:
   load-base class 0x6828C000 -> ~ntdll.so+0x429A2 for this run).

2. The wine loader's boot-event wait then expires into the kernel32
   search cascade — prefix search paths, all absent — and exits:

       STAT /wscratch/wprefix2/dosdevices/c:/windows/system32/kernel32.dll
       STAT /wscratch/wprefix2/dosdevices/c:/windows/system32/kernel32.dll
       STAT /wscratch/wprefix2/dosdevices/c:/windows/system/kernel32.dll
       STAT /wscratch/wprefix2/dosdevices/c:/windows/kernel32.dll
       STAT /wscratch/wprefix2/dosdevices/unix
       STAT /kernel32.dll
       wine: could not load kernel32.dll, status c0000135
       SYS 9 252 -> -1073741515 (bx=c0000135 cx=ffffffd0 dx=00000001 si=0021fcf0)

   (exit_group with 0xC0000135 = STATUS_DLL_NOT_FOUND; the 53 on the
   process is the documented NTSTATUS truncation.)

## Verdict and escalation

C3 is NOT closed.  Verdict: FAIL (deterministic guest exit 53, `ok`
never printed).  Not a STALL — no retry loop, both runs self-terminate
at ~5.3 min; the RC7b-era DBT stall ("2 files copied in 7 min") is
gone, which confirms the H1 checkpoint fix unblocked DBT progression
to full multi-process boot and a partially/fully populated prefix.
Not a translator CRASH — no i686rt fatal-region dump in either run.

Escalation evidence for the coordinator (DBT-specific, interp clean on
the identical chain per the RC7b record):

- Guest #DE (divide error) events appear ONLY under engine=dbt, at
  three distinct sites across two runs (0x00000000, 0x7BD907B6 in the
  PE kernel32 region, 0x682CE9A2 in the unix ntdll.so region) — run-2's
  aborts wineboot's INF/fake-dll install at 278/518 files, so
  system32/kernel32.dll is missing when the loader resumes; run-1's
  prefix is complete yet the chain still exits 53 (silently, no
  "could not load" line), i.e. at least one further DBT divergence
  downstream of the install phase.
- Working artifacts (untracked): run-1 log
  `_scratch/c3-rc7b-dbt-20261023-221925.log`, run-2 raw SYSTRACE
  `_scratch/c3-systrace-20261023-222711.{out,err}`, both prefixes under
  `_scratch/wprefix{,2}` for post-mortem.
