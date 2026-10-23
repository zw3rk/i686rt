# Fix campaign C9 — winevdm "winedevice.exe is a DOS application" diagnosis

Lane L-C9 (`lane/fix-c9`, worktree `../i686rt-c9`), READ-ONLY forensics.
Card: docs/lanes/fix-campaign.md "Card L-C9"; context: docs/lanes/
phase-7.md (T4c launch-vs-slow-copy hypothesis, RC7b record), residual
row in docs/FINAL-REPORT.md.

## Verdict (short)

**TRANSLATOR-SIDE.** The stderr lines are not a launch-vs-copy race.
Wine's prefix-update pass writes the installed
`C:\windows\system32\winedevice.exe` 96 bytes forward because our
translator returns **-ENOSYS for `_llseek` (140)** (unregistered; the
dispatch default "every other number returns -ENOSYS", src/os/
syscalls.c): the pass reads a 96-byte header probe (moving the file
offset to 96), its `_llseek(fd, 0, SEEK_SET)` fails with -ENOSYS, and
the following full 142896-byte rewrite lands at offset 96. The file ends
up 142992 bytes with its first 96 bytes duplicated, so `e_lfanew` (0x80)
points at zeros instead of `PE\0\0`; every subsequent PE-load verdict
fails, kernel32 hands the image to winevdm, and winevdm prints one
"winedevice.exe is a DOS application" line per launch attempt. The file
is permanently corrupt on disk — nothing transient. The linux/386 oracle
is silent because its `_llseek` exists, the rewind succeeds, and the
installed file stays a valid 142896-byte builtin PE.

Minimal fix (proposed here, NOT implemented — file map says "nothing
until coordinator sign-off"): implement `_llseek` (140) kernel-ABI
exact, which is verbatim the first item of fix-campaign card L-C1a
(ebx=fd, ecx=off_hi, edx=off_lo, esi=guest `loff_t*` result, edi=whence;
merge the 64-bit offset, host `lseek`, write the 64-bit result through
the guest pointer, return 0 / -errno). Per the card, a follow-up card
re-runs the RC7b gate for the stderr-empty criterion after C1a lands.

## Method

Build (worktree, cached toolchain):

    make build CC=/nix/store/cs8q52va4acssg38pivn7f9kyvk9lzjd-aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/aarch64-unknown-linux-musl-gcc

→ `_build/i686rt`: ELF 64-bit LSB pie executable, ARM aarch64,
static-pie linked (zero new warnings; the emit_sse.c
sse_emit_prefetch unused-parameter warning pre-exists per T4b/T4c/T4d).

Two bounded runs, each a fresh WINEPREFIX, RC7b env exactly as recorded
in phase-7.md (HOME/WINEPREFIX/WINEDEBUG=-all/WINEDLLPATH), shared
sysroot mounted read-only, unique container name + --cidfile,
--memory 4g --cpus 4, in-container `timeout`, host `timeout 1850`,
verified `docker ps -a` cleanup after completion, timeout, and stop.

### Run A — repro (container c9-repro, prefix on the mounted scratch dir)

    docker run --name c9-repro --rm --platform linux/arm64 --memory 4g --cpus 4 \
      --cidfile .../_scratch/c9-repro.cid \
      -v /Users/angerman/Projects/zw3rk/i686rt-c9:/w \
      -v /Users/angerman/Projects/zw3rk/i686rt/_sysroot:/w/_sysroot:ro \
      alpine:3.20 sh /w/_scratch/runA.sh
      # inside: SYS=/w/_sysroot/debian-wine32-i386
      #   HOME=/w/_scratch/whome WINEPREFIX=/w/_scratch/wprefix WINEDEBUG=-all
      #   WINEDLLPATH=$SYS/usr/lib/i386-linux-gnu/wine
      #   rm -rf $WINEPREFIX
      #   timeout 1700 /w/_build/i686rt --sysroot $SYS -- \
      #     $SYS/usr/bin/wine cmd /c "echo ok"

stderr captured live through a FIFO with per-line `date '+%H:%M:%S'`
stamps (second resolution; busybox `date` has no %N). Chain behaviour:
stdout `ok` printed; DOS lines at 13:26:30 and 13:26:46; at 13:26:49 a
boot child aborted with the guest-glibc heap-corruption message
("corrupted double-linked list" → interp guest-hlt diag) — the T4c-era
pathology resurfacing under the I/O-bound VirtioFS-hosted prefix, out of
C9 scope (escalation note below). The run then outlived its in-container
timeout without exiting (translator survives SIGTERM while stuck, the
documented T4b pathology) and was stopped by container identity; the
stop also killed the stderr stamp reader mid-buffer, which is why only
2 of the 3 RC7b-era lines are in run A's capture. rc not observed.

### Run B — correlate (container c9-trace, THE SYSTRACE run)

Identical chain with `I686RT_SYSTRACE=1`; WINEPREFIX on a VM-local
docker volume (still not container /tmp; matches the RC7b gate's I/O
profile, which run A's VirtioFS prefix did not). Full syscall trace to
`/s/c9-sys.log` (~1.3M lines by the DOS phase; per-syscall
`SYS <pid> <nr> -> <ret> (bx= cx= dx= si=)` lines plus the handler-side
`OPENAT`/`READLINK`/`STAT` path lines); the DOS lines epoch-stamped by
the trace reader. Chain behaviour: stdout `ok`; FIVE DOS lines
(14:00:48 … 14:01:12); the process tree did not exit within the bound
(the trace FIFO's write end is held by surviving translator children,
so the reader never saw EOF — the same documented survivor pathology);
container stopped by identity, cleanup verified, volume removed after
extraction.

## Verbatim stderr (the residual, full text of each line)

Run B (`/s/c9-dos.ts`, epoch + line; boot started 13:56:51 UTC):

    1792764048 winevdm: C:\windows\system32\winedevice.exe is a DOS application, you need to install DOSBox.
    1792764051 winevdm: C:\windows\system32\winedevice.exe is a DOS application, you need to install DOSBox.
    1792764064 winevdm: C:\windows\system32\winedevice.exe is a DOS application, you need to install DOSBox.
    1792764069 winevdm: C:\windows\system32\winedevice.exe is a DOS application, you need to install DOSBox.
    1792764072 winevdm: C:\windows\system32\winedevice.exe is a DOS application, you need to install DOSBox.

(= 14:00:48, 14:00:51, 14:01:04, 14:01:09, 14:01:12 UTC.)

Run A (VirtioFS prefix, HH:MM:SS stamps):

    13:26:30 winevdm: C:\windows\system32\winedevice.exe is a DOS application, you need to install DOSBox.
    13:26:46 winevdm: C:\windows\system32\winedevice.exe is a DOS application, you need to install DOSBox.

The message string lives in the winevdm PE builtin
(`i386-windows/winevdm.exe`: `winevdm: %s is a DOS application, you
need to install DOSBox.`). RC7b recorded 3 lines, this run 5: the count
is the number of winedevice service launches services.exe attempts
before the boot moves on — timing-dependent, and irrelevant to the
mechanism. stdout was `ok` in both runs.

## Correlation (SYSTRACE, run B)

### 1. The installed file is complete but corrupt — not missing/partial

After the boot, the prefix volume holds:

    -rwxr-xr-x 1 root root 142992 ... drive_c/windows/system32/winedevice.exe
    (builtin source: .../i386-windows/winedevice.exe = 142896 bytes)

142992 = 96 + 142896. Byte dump of the installed file:

    000000 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ, e_lfanew=0x80
    000040 57 69 6e 65 20 62 75 69 6c 74 69 6e 20 44 4c 4c   "Wine builtin DLL"
    000060 4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ AGAIN
    0000a0 57 69 6e 65 20 62 75 69 6c 74 69 6e 20 44 4c 4c   "Wine builtin DLL" AGAIN
    0000c0 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20   (builtin stub tail)
    000080 00 00 00 00 ...                                   <- e_lfanew points HERE: zeros, no "PE\0\0"

i.e. `builtin[0..95]` duplicated in front of the full builtin. The
loader reads `e_lfanew = 0x80` from the first DOS header and finds
zeros where `PE\0\0` must be → "not PE, not NE" → kernel32's
CreateProcess hands the path to winevdm → the message. Verified against
the on-disk layout: every launch attempt (pid 17 = services.exe side:
`OPENAT .../system32/winedevice.exe`, `dx=00008800` O_RDONLY, fstat via
300 after statx 383 → -ENOSYS fallback, wineserver request/reply, close)
ends in the winevdm spawn and the message. Nothing races the copy: the
launches at 14:00:48+ all postdate the file's last write (mtime
13:58:46). **T4c's launch-vs-slow-copy hypothesis is refuted** — the
interpreter's slowness only changes how many launch attempts pile up
(3 vs 5), not the verdict.

### 2. The SYSTRACE excerpt: the corrupting write (update pass, pid 39)

Sequence around trace line 609391-609413 (verbatim; fd 10 is the
update-pass handle on the TARGET, received over the wineserver
socketpair via SCM_RIGHTS — fd passing is invisible to SYSTRACE, which
is why the pre-write `read` below has no adjacent OPENAT):

    SYS 39 180 -> 23 (bx=0000000a cx=0021fa20 dx=00000017 si=00000000)
        pread64(fd10, buf, 23, 0) -> 23        header sniff, offset untouched
    SYS 39 3 -> 96 (bx=0000000a cx=0062cfe8 dx=00000060 si=00000000)
        read(fd10, buf, 96) -> 96              THE OFFSET IS NOW 96
    SYS 39 140 -> -38 (bx=0000000a cx=00000000 dx=00000000 si=0021fc30)
        _llseek(fd10, off_hi=0, off_lo=0, result*, whence) -> -ENOSYS
    SYS 39 140 -> -38 (bx=0000000a cx=00000000 dx=00000000 si=0021fc10)
        _llseek retry -> -ENOSYS
    SYS 39 4 -> 142896 (bx=0000000a cx=00cb0000 dx=00022e30 si=00000000)
        write(fd10, builtin-image, 142896) -> 142896   LANDED AT OFFSET 96

where 0x22e30 = 142896 = the builtin size (read into 0x00cb0000
earlier in the same pass via `read` 4096 + 138800 = 142896 on the
builtin handle). On a real kernel the `_llseek` rewinds to 0, the
rewrite overwrites the file in place, and the file stays a valid
142896-byte PE. Under i686rt the rewind fails, the write appends after
the 96-byte probe, and the file becomes the 142992-byte duplicated-
header image of section 1 — matching the on-disk bytes exactly
(installed[0x60+k] == builtin[k] for k in 0..95, verified by od).
An earlier full copy of the same target (trace line ~84204-84332: pid
17 `OPENAT .../winedevice.exe` with `dx=000088c2`
O_RDWR|O_CREAT|O_EXCL, then a 142896-byte write at offset 0) produced a
valid file — the corruption is introduced by the later update pass
only; all five DOS lines postdate it.

### 3. Reader-side verdict excerpt (first DOS line, trace line 1099163)

    OPENAT /s/wprefixB/dosdevices/c:/windows/system32/winedevice.exe
    SYS 17 295 -> 157 (bx=ffffff9c cx=00974560 dx=00008800 si=00000000)   O_RDONLY
    SYS 17 383 -> -38 (bx=0000009d ...)      statx -> ENOSYS (glibc falls back to 300)
    SYS 17 300 -> 0  (bx=0000009d ...)       fstatat64 OK
    ... wineserver exchange, repeated open/fstat/close cycles ...
    SYS 17 194 -> -38 (bx=0000009d cx=00000000 dx=00000000 si=00975a80)   ftruncate64 -> ENOSYS
    SYS 17 6 -> 0 (bx=0000009d ...)          close
    STAT /s/wprefixB/drive_c/windows/cfg966d.tmp
    SYS 17 10 -> 0 (...)                     unlink temp
    winevdm: C:\windows\system32\winedevice.exe is a DOS application, you need to install DOSBox.
    SYS 68 4 -> 94 (bx=00000002 cx=7ffc3404 dx=0000005e si=00000000)      winevdm writes 94 B to stderr

Every launch attempt in the run ends identically (lines 1099163,
1123589, 1157751, 1189373, 1221985). The verdict is deterministic
against the corrupt file; no syscall in the READ path returns anything
wrong — openat/fstat return faithful results; the failure is baked into
the file content by section 2.

## Faithfulness audit (translator innocence check on the other syscalls)

- `read`/`write` are direct host passthroughs into the 1:1 guest
  window (src/os/syscalls.c sys_read/sys_write): the short `read(fd,
  96)` and the full 142896-byte `write` are host truths.
- openat flags pass through translated (`i686_open_flags_to_host`);
  the O_EXCL create, O_RDONLY loader opens and O_RDWR update handle all
  return kernel-shaped results.
- statx (383) → -ENOSYS with fstatat64 (300) fallback — the documented
  C1a gap, harmless here (glibc retries via 300, which succeeds).
- ftruncate64 (194) → -ENOSYS also appears in the launch path — a
  second L-C1a item hit by the same wine code; it does not change the
  C9 verdict (the file is already corrupt), but C1a's landing should
  close it too.
- The oracle (linux/386, RC7b record) runs the identical wine code and
  is silent: with a working `_llseek` the update pass rewrites the file
  in place and every launch succeeds.

## Verdict

TRANSLATOR-SIDE — our syscall layer injects a wrong result (missing
`_llseek` (140) → -ENOSYS) that makes wine's prefix-update pass corrupt
`system32/winedevice.exe` on disk (96-byte offset shift, duplicated
header block); wine's loader then correctly refuses the damaged PE and
kernel32/winevdm print the "DOS application" line per launch attempt.
It is not a wine-side race and not an interpreter-speed artifact.
Minimal fix: implement `_llseek` (140) per the kernel ABI — already
specified verbatim as card L-C1a's first item (with 194 ftruncate64 in
the same list, also hit by this flow). No src/ file was touched by
this lane. Follow-up: after C1a merges, a follow-up card re-runs the
RC7b gate for the stderr-empty criterion (the mechanism predicts:
silent stderr, unchanged stdout/rc).

## Escalation notes (out of C9 scope, for the coordinator)

1. Under the VirtioFS-hosted prefix (run A) a boot child aborted at
   13:26:49 with guest-glibc "corrupted double-linked list" → interp
   guest-hlt diag; the RC7b-era T4c heap-corruption pathology
   resurfaces under slow I/O. Not exercised by the volume-backed run.
2. Both runs' process trees outlived `timeout` (SIGTERM then SIGKILL
   not fully reaping translator children — the documented T4b
   survivor), and in run B the surviving children held the trace FIFO
   open, hanging the capture script's reader. Bounded-run harnesses
   for this chain should `docker stop` by container identity and not
   rely on the in-container timeout alone (done here).

## Evidence files

Extracted under `_scratch/` in this worktree (git-ignored, not
committed): `c9-dos.ts` (stamped DOS lines, run B), `repro.stderr.ts`
(stamped stderr, run A), `c9-systrace.stdout`, `exc-create.txt` /
`exc-firstopen.txt` / `exc-services.txt` / `exc-dos1.txt` (raw SYSTRACE
windows). The run scripts are `runA.sh` / `runB.sh` in the same place.
