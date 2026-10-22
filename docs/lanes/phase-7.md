# Phase 7 — Wine-style LDT (L7a → S7/RC7; L7b wine smoke → RC7b)

SPEC §4 7.1–7.3, §2 D8, E09 verdict ( Wine uses modify_ldt func 0x11 +
set_thread_area only; LDT 8192, entries 0..31 reserved; free = all-zero
not-present entry; far transfers and fault surfaces as listed ).

## Coordinator freeze (7.1 — binding for the fan-out)

- src/interp/seg.h is FROZEN (committed with the ctx tail extension:
  cs_d, v86, v86state appended; `ctx->ldt` now holds `i686_segstate_t*`).
  Lanes implement against it and never edit it.
- Effective addressing with segments: linear32 = (uint32_t)
  (seg_base[seg] + offset) — segment base added AFTER the 16/32-bit
  offset computation, wrapping in 32 bits (D4/D7); the window base xG
  is added after that as today. Default segment per opcode class per
  SDM (SS for ESP-based, DS otherwise); override prefixes select
  es/cs/ss/ds/fs/gs.
- Decode defaults: operand/address defaults come from ctx->cs_d
  (1 = 32-bit, set at process start for flat CS). Prefixes 66/67
  invert per instruction as today. vm86 (Phase 8) reuses this by
  setting cs_d=0 while active.
- Engines (D8): non-flat CS, LDT selector in CS, or v86 active →
  interpreter only. Guard: engine dispatch checks
  i686_seg_flat_cs(ctx) && !ctx->v86 before running/caching blocks;
  flat processes are unaffected.
- Fault surface: #GP trapno 13 / #NP trapno 11 / #SS trapno 12 with
  error code = selector bits, delivered through the existing sync
  fault path (signals_i386.c), guest IP at the faulting instruction.
  Privileged instructions in 16-bit code (cli/sti/in/out/hlt/mov
  cr/dr) fault the same way (E09 gap list). int NN (NN != 0x80) in
  non-flat code = resolvable fault (E09), IP at the int.
- Sigcontext round-trip via i686_seg_sc_encode/sc_decode; wiring into
  signals_i386.c happens at S7 merge (coordinator) to keep file
  ownership exclusive.
- Syscall registration (123 modify_ldt, 243/244 set/get_thread_area):
  handler functions land in src/os/ldt.c; the 3-line dispatch wiring
  into the syscall table is done by the coordinator at S7 merge — the
  lane documents the exact snippet in its record.

## Card L7a — descriptor model implementation (grunt lane)

- Scope: implement seg.h completely: src/interp/seg.c (lookup/load/
  flat defaults/generation), src/interp/h_seg.c (segment-register
  moves 8C/8E, pops 07/17/1F, les/lds/lss/lfs/lgs C4/C5/0F B2/B4/B5,
  far call/jmp 9A/EA, lret CB incl. 0x66 cross-size, non-v86 iret CF,
  int NN fault path, privileged-instruction faults), src/os/ldt.c
  (modify_ldt funcs 0/1/0x11/2, set/get_thread_area with -1
  auto-alloc), tests/test_p7_ldt.c + fixture. Bounded edits: decode.c
  (far-op operands m16:16/m16:32, cs_d defaults, segment-override EA
  plumbing), engine.c (flat/v86 guard), flags on far transfers.
  16-bit operand/address execution uses existing handlers — widths
  already parameterised; defaults come from cs_d.
- Worktree ../i686rt-l7a, branch lane/7-l7a. Files owned (exclusive):
  src/interp/seg.c, src/interp/h_seg.c, src/os/ldt.c,
  tests/test_p7_ldt.c. Bounded: src/x86/decode.c, src/dbt/engine.c,
  Makefile (objects), tests/golden untouched.
- Fixture (SPEC 7.2): install LDT data + 16-bit code descriptors via
  modify_ldt 0x11; load %fs/%es from LDT; far call into 16-bit code
  and back (m16:16); access memory via %fs base; fault on limit
  overrun (expect SIGSEGV trapno 13); set_thread_area -1 alloc +
  %gs load. Print PASS at the end (pattern: test_p4 fixtures).
- Acceptance check (single command, arm64 docker):
  build fixture with tools/build_fixture.sh, then
  `/w/i686rt -- /w/test_p7_ldt` → last line `PASS`
  (engine=interp default is fine; DBT must stay eligible-flat only).
- Escalate after 2 failed attempts / any frozen-interface change
  (seg.h, i686rt.h) / ambiguity. No scope widening; never push; no AI
  mentions in commits.

## Card L7b — Wine32 sysroot smoke (dispatched after S7)

tools/setup-wine32.sh fetching Debian i386 wine (non-wow64) per the
setup_sysroot.py pattern; triage list for RC7b. Owned: the script +
docs/lanes/phase-7.md L7b record only.

## L7a record

Implemented seg.h completely (files owned): `src/interp/seg.c`
(segstate alloc + flat defaults, selector lookup null/GDT-flat/TLS/LDT,
validated segment loads with SDM DPL/RPL/type checks, cs_d maintenance,
`i686_seg_flat_cs`, LDT data-limit enforcement along the decode EA path,
`i686_seg_sc_encode/sc_decode`), `src/interp/h_seg.c` (MOV sreg 8E,
pops 07/17/1F/0F A1/0F A9 via i686_seg_load, les/lds/lss/lfs/lgs, far
call/jmp 9A/EA, lret CB incl. 0x66 cross-size, non-v86 iret CF, int NN
resolvable fault in non-flat code, privileged cli/sti/hlt + synthetic
IN/OUT/MOV CR,DR faults in 16-bit code), `src/os/ldt.c` (modify_ldt
funcs 0/1/0x11/2, set/get_thread_area 243/244 with entry_number -1
auto-alloc, seg_not_present frees, v1-compat GS auto-load), fixture
`tests/test_p7_ldt.c`. Bounded edits: `src/x86/decode.c` (CS-relative
instruction fetch, cs_d-driven defaults normalized into
pfx_opsize/pfx_addrsize so every frozen handler keeps its
`pfx ? 16 : 32` convention, 16-bit EA wrap mod 64K before the segment
base, LDT limit check in x86_rm_read/x86_rm_write, far-op operand
decode m16:16/m16:32 into synthetic registry ids 350–359 handled by
h_seg.c, lazy idempotent `i686_interp_seg_init()` call), `src/dbt/
engine.c` (per-dispatch guard `i686_seg_flat_cs(ctx) && !ctx->v86`).
Makefile needed no edit (SRCS wildcards pick the new TUs up).

**Syscall registration snippet for the coordinator (S7)** — in
`i686_syscalls_init_once` (src/os/syscalls.c), after the existing
registrations, add:

```c
    {
        extern void i686_syscalls_ldt_init(void);
        i686_syscalls_ldt_init();   /* 123 modify_ldt, 243/244 set/get_thread_area */
    }
```

(already callable: ldt.c defines it idempotently; until wired it is
invoked lazily from the Phase-7 interp registration. Note the v1
syscalls.c init re-registers 243 at the first syscall, so it wins for
set_thread_area until this moves here; 123/244 are served by ldt.c
either way.)

Also at S7 (already implemented, awaiting wiring, coordinator-owned
files):
- `src/os/signals_i386.c`: call `i686_seg_sc_encode(ctx, sc.gs..ss)`
  when building sigcontexts and `i686_seg_sc_decode(ctx, in)` from
  `i686_sigreturn`; and preserve the lane's trapno in `i686_deliver_sync`
  (limit/segment/int-NN faults raise `ctx->exit_arg` = 13/11/12 with the
  error code stashed in `ctx->exit_dest`; the current delivery overwrites
  exit_arg to 14 — until wired, guest trapno reads 14 for all SIGSEGVs).
- `src/interp/interp.c` (optional symmetry): move the
  `i686_interp_seg_init()` call from decode.c into `i686_interp_init_all()`.

Deviations / notes (all within card bounds):
- Fault delivery uses the existing sync channel: handlers return
  I686_EXIT_FAULT with exit_arg = trapno; the guest IP stays at the
  faulting instruction (resumable). Limit faults additionally raise a
  deterministic host SIGSEGV by touching the offending guest address
  first (exact cr2 when the page is PROT_NONE — the fixture's overrun
  at 0xF0001000), falling back to the always-unmapped guest VA 0.
- The fixture cannot exercise the privileged-instruction fault from
  inside 16-bit code end-to-end yet: signal delivery enters the handler
  with the interrupted CS (16-bit) and sigreturn does not restore
  segments until the sc_encode/sc_decode wiring above; the h_seg
  handlers and the decode path are in place and covered by the record.
- Limit enforcement covers the modrm/moffs EA path for LDT (TI=1)
  selectors only; flat/GDT selectors are never limit-checked (v1
  compatibility, D8 DBT-eligibility unchanged). 16-bit addressing now
  wraps the offset mod 64K before the segment base is added (SDM
  correct; flat 67-prefix behaviour change noted).
- No vm86 paths touched (ctx->v86 guard only).
- FROZEN-HEADER HAZARD for the coordinator (no change required this
  phase, worked around lane-side): seg.h re-spells the FAULT codes
  I686_SEG_OK/GP/NP/SS over i686rt.h's segment-register index macros —
  I686_SEG_SS is 3 (fault) vs 2U (SS register index). Files including
  both pre-clear the macro (#undef before including seg.h so the frozen
  #define is fresh) and use collision-free SEG_F_* locals; seg.h should
  rename its fault codes (e.g. I686_SEGF_*) at the next sanctioned
  header touch.
- execve leaves ctx->cs_d stale if the execing context ran with D=0
  (the kernel drops the LDT on exec; the coordinator may reset
  ctx->ldt/cs_d in r_execve at S7).

Acceptance check (single run, 2026-10-22):

    tools/build_fixture.sh tests/test_p7_ldt.c _build/test_p7_ldt
      -> build_fixture.sh: _build/test_p7_ldt: ELF 32-bit LSB executable,
         Intel 80386, version 1 (SYSV), statically linked, not stripped
    nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.buildPackages.gcc \
      -c make build CC=aarch64-unknown-linux-musl-gcc        (zero warnings)
    docker run --name l7a-check --rm --platform linux/arm64 \
      -v "$PWD/_build/p7stage":/w alpine:3.20 sh -c 'timeout 60 /w/i686rt -- /w/test_p7_ldt'

Output, verbatim (last line exactly PASS; exit 0; container gone —
`docker ps -a --filter name=l7a-check` empty after the run):

    PASS

(The fixture also passes under I686RT_ENGINE=dbt in pre-flight: the
engine guard keeps DBT to flat blocks and single-steps the far ops
through the interpreter, D8.)

## S7/RC7 (coordinator)

Merge L7a (--no-ff), wire syscall registration + sigframe sc_encode/
sc_decode + far-int fault delivery, run RC7: `test_p7_ldt` prints PASS
(lima stand-in: arm64 docker container — recorded deviation as in
RC1–RC5). RC7b after L7b: `wine cmd /c echo ok`.

## S7/RC7 record (2026-10-22) — PASSED

L7a merged --no-ff (11321cd); coordinator wiring committed: ldt.c
syscalls registered last-wins (123/243/244; full set_thread_area
supersedes the flat v1 stub), sigframe segment round-trip via
i686_seg_sc_decode + segment-fault trapno preservation (#GP 13/#NP
11/#SS 12 with the error code in sc.err instead of the #PF-14
overwrite), i686_interp_seg_init in init_all, r_execve cs_d reset,
seg.h fault codes renamed I686_SEG_F_*.  RC7 evidence (arm64 docker
alpine:3.20, staging /tmp/rc3): `timeout 60 /w/i686rt -- /w/test_p7_ldt`
→ rc=0, last line PASS.  Deviations: lima stand-in as in RC1–RC5.
Noted behavior change (SDM-correct): 16-bit EA wrap mod 64K for
67-prefixed flat code.

## L7b record (2026-10-22)

`tools/setup-wine32.sh` (POSIX sh, difftest.sh header style) fetches
the minimal non-wow64 Wine32 sysroot into `_sysroot/debian-wine32-i386/`
(separate from setup_sysroot.py's `_sysroot/debian-i386/`; both share
the `_sysroot/pool` deb cache — gitignored, not committed).  Pool
listing → newest-version derivation per package (sort -V) with
upstream-version coherence across the wine set (epoch/debian-revision
stripped), bounded curl transfers (--max-time 60 listing / 900 s per
deb, --retry 2), ar-magic check on cached and downloaded debs,
`ar p` + `tar -xJf/xzf -` streaming extraction (data.tar.xz/.gz;
zstd rejected with a clear message — not needed for the current
archive), member path check (no `..`), idempotent `.stamp`
(package urls + sha256s, key-file hashes) with short-circuit rerun and
`--force` to re-fetch.  `--verify` prints `WINE32-SYSROOT-OK` (exit 0)
iff usr/bin/wine (or wine-stable) is executable, the wine32 loader
tree (wine/wine, wine/wineserver, i386-unix/ntdll.so, PE
ntdll/kernel32/cmd.exe, wine.inf, fonts) and the glibc loader/libc are
present; non-zero otherwise.

Package closure (determined from the archive; wine 10.0~repack era,
trixie, main i386) — total download 99,909,696 bytes (95.3 MiB):

    libc6            2.44-3           1,767,384 B   pool/main/g/glibc/
    libwine          10.0~repack-12+b1    96,294,912 B   pool/main/w/wine/
    wine32           10.0~repack-12+b1       304,240 B   "
    wine32-preloader 10.0~repack-12+b1        35,264 B   "
    wine             10.0~repack-12          139,612 B   "
    wine-common      10.0~repack-12        1,368,284 B   "

(libc6-i686 is no longer shipped for this suite; skipped as in
setup_sysroot.py.)  Closure rationale: wine (all) Depends
wine64 | wine32; wine32 Depends libc6 + libwine (=); libwine Depends
wine-common + libc6 + a large optional set (X11/wayland/pulse/gstreamer/
avcodec/fontconfig/freetype/...).  That optional set is Debian's
everything-enabled build being dlopened per subsystem with graceful
fallback — NOT loader requirements: the loader-side DT_NEEDED of
wine/wine, wine/wineserver, i386-unix/ntdll.so and i386-unix/win32u.so
is exactly { libc.so.6, libm.so.6, ntdll.so } (objdump -p evidence),
so no graphics packages are fetched and RC7b's text-mode `wine cmd`
needs none.  wine32-tools / libwine-dev / fonts-wine (external TTFs)
are not needed for `cmd /c echo` and are not fetched.

Extracted layout (preserved paths; i686rt --sysroot resolver handles
the usr/lib/i386-linux-gnu multiarch paths):

    usr/bin/wine -> wine-stable          (alternatives replicas, see below)
    usr/bin/wine32 -> wine32-stable
    usr/bin/wineboot -> wineboot-stable
    usr/bin/*-stable                     shell wrappers (wine deb)
    usr/libexec/wine/apploader           app.exe-style wrapper script
    usr/lib/i386-linux-gnu/wine/wine         the real ELF32 loader
    usr/lib/i386-linux-gnu/wine/wineserver
    usr/lib/i386-linux-gnu/wine/wine-preloader{,.static}
    usr/lib/i386-linux-gnu/wine/i386-unix/*.so      (36 unix-side modules)
    usr/lib/i386-linux-gnu/wine/i386-windows/*      (810 PE builtins incl.
                                          ntdll.dll, kernel32.dll, cmd.exe)
    usr/lib/i386-linux-gnu/wine/x86_64-windows/*    wow64-side PEs shipped
                                          inside the i386 libwine deb;
                                          unused non-wow64, extracted as-is
    usr/share/wine/wine.inf              needed by wineboot prefix creation
    usr/share/wine/fonts/                wine builtin fonts (wine-common)
    lib -> usr/lib                       usrmerge compat symlink (added
                                         when the debs shipped no lib/)

Special paths / fixups documented for RC7b:

- Debian creates usr/bin/wine, usr/bin/wine32 and usr/bin/wineboot as
  update-alternatives links (libwine postinst slave links at priority
  70) pointing at the -stable wrappers; maintainer scripts do not run
  on plain extraction, so the script recreates the three links as
  symlinks (usr/bin/wine -> wine-stable -> ... -> wine32-stable -> exec
  usr/lib/i386-linux-gnu/wine/wine).  Launch chain for RC7b:
  usr/bin/wine → wine-stable (needs usr/bin/wine32 present — provided).
- wineboot needs usr/share/wine/wine.inf (libwine) + the builtin fonts
  (wine-common); both are in the closure.
- libwine's postinst also patches zlib1.dll out of libz-mingw-w64 into
  i386-windows/; skipped (apt-level, not needed by cmd; would drag the
  mingw zip runtime in).
- wine 10 removed libwine.so.1 (folded into i386-unix/ntdll.so); the
  only DT_NEEDED outside the wine tree is glibc (ld-linux.so.2,
  libc.so.6, libm.so.6 — from the libc6 deb, same derivation as
  setup_sysroot.py).

Acceptance check (single run, 2026-10-22, macOS host):

    tools/setup-wine32.sh && tools/setup-wine32.sh --verify

Output, verbatim (exit 0; last line exactly WINE32-SYSROOT-OK):

    setup-wine32.sh: wine set: newest libwine libwine_10.0~repack-12+b1_i386.deb (upstream 10.0~repack)
    setup-wine32.sh:   wine32_10.0~repack-12+b1_i386.deb
    setup-wine32.sh:   wine32-preloader_10.0~repack-12+b1_i386.deb
    setup-wine32.sh:   wine_10.0~repack-12_all.deb
    setup-wine32.sh:   wine-common_10.0~repack-12_all.deb
    setup-wine32.sh: glibc: newest libc6_2.44-3_i386.deb
    setup-wine32.sh: libc6-i686: not shipped for this suite (skipping; modern Debian i386 glibc is i686-optimized in libc6 itself)
    setup-wine32.sh: cached libc6_2.44-3_i386.deb
    setup-wine32.sh: cached libwine_10.0~repack-12+b1_i386.deb
    setup-wine32.sh: cached wine32_10.0~repack-12+b1_i386.deb
    setup-wine32.sh: cached wine32-preloader_10.0~repack-12+b1_i386.deb
    setup-wine32.sh: cached wine_10.0~repack-12_all.deb
    setup-wine32.sh: cached wine-common_10.0~repack-12_all.deb
    setup-wine32.sh: extracting libc6_2.44-3_i386.deb
    setup-wine32.sh: extracting libwine_10.0~repack-12+b1_i386.deb
    setup-wine32.sh: extracting wine32_10.0~repack-12+b1_i386.deb
    setup-wine32.sh: extracting wine32-preloader_10.0~repack-12+b1_i386.deb
    setup-wine32.sh: extracting wine_10.0~repack-12_all.deb
    setup-wine32.sh: extracting wine-common_10.0~repack-12_all.deb
    setup-wine32.sh: created usrmerge compat symlink lib -> usr/lib
    setup-wine32.sh: alternatives replica: usr/bin/wine -> wine-stable
    setup-wine32.sh: alternatives replica: usr/bin/wine32 -> wine32-stable
    setup-wine32.sh: alternatives replica: usr/bin/wineboot -> wineboot-stable
    setup-wine32.sh: stamp written: .../_sysroot/debian-wine32-i386/.stamp (total download 99909696 bytes)
    setup-wine32.sh: ok loader: usr/bin/wine (executable)
    setup-wine32.sh: ok wine32 loader: usr/lib/i386-linux-gnu/wine/wine
    setup-wine32.sh: ok wine32 wineserver: usr/lib/i386-linux-gnu/wine/wineserver
    setup-wine32.sh: ok wine32 unix ntdll: usr/lib/i386-linux-gnu/wine/i386-unix/ntdll.so
    setup-wine32.sh: ok wine32 PE ntdll: usr/lib/i386-linux-gnu/wine/i386-windows/ntdll.dll
    setup-wine32.sh: ok wine32 PE kernel32: usr/lib/i386-linux-gnu/wine/i386-windows/kernel32.dll
    setup-wine32.sh: ok wine32 PE cmd: usr/lib/i386-linux-gnu/wine/i386-windows/cmd.exe
    setup-wine32.sh: ok wine.inf: usr/share/wine/wine.inf
    setup-wine32.sh: ok wine fonts: usr/share/wine/fonts/courer.fon
    setup-wine32.sh: ok glibc loader: lib/ld-linux.so.2
    setup-wine32.sh: ok glibc libc: usr/lib/i386-linux-gnu/libc.so.6
    WINE32-SYSROOT-OK

Deviations / notes:

- The six debs were downloaded into `_sysroot/pool` by the lane while
  resolving the closure from the archive (same URLs the script derives,
  sha256s recorded in `.stamp`); the acceptance run therefore reports
  "cached" instead of re-downloading 95.3 MiB.  A cold-cache run uses
  the identical derivation (the two scripts/scrape paths were compared
  during authoring).  A pre-flight run against a throwaway tree
  preceded the single official acceptance run above (tree wiped before
  it; the check above ran on the final script version only).
- Extracted tree is ~572 MB on disk (dominated by the i386 PE builtins
  plus the wow64-side x86_64-windows tree that Debian ships inside the
  i386 libwine deb; extracted as-is for dpkg-deb -x fidelity).
- Requires curl, ar, tar (xz), sort -V, sha256sum|shasum (all present
  on the macOS host class setup_sysroot.py targets; no zstd debs in
  this closure — wine/glibc ship data.tar.xz).
- RC7b itself (running `wine cmd /c echo ok` under i686rt --sysroot
  against this tree) is the coordinator's card, not this lane's.

## RC7b triage T1 record (2026-10-22) — PASSED

Lane T1 (`lane/7b-t1`, worktree `../i686rt-t1`): sanctioned instruction
union extension (docs/lanes/phase-7.md RC7b context) so the Debian i386
glibc 2.44 SSE2 paths run.  Worktree/branch sanity: clean on start,
nothing pushed, no AI identity in the commit.

### A. Sweep (capstone 5.0.7; linear sweep of every PT_LOAD PF_X segment
plus a recursive pass from e_entry + every STT_FUNC symbol; instruction
bytes classified by mandatory-prefix class (plain/66/F3/F2) against the
parsed i686_insn_tab_0f rows)

Sweep target files (staging sysroot, read-only):

    usr/bin/dash                                   (149,332 B)
    lib/i386-linux-gnu/ld-linux.so.2               (240,976 B)
    usr/lib/i386-linux-gnu/libc.so.6             (2,366,024 B)

Rows currently mapped I686_OP_INVALID that appear in the binaries
(lin = linear-sweep hits, rec = recursive-pass hits; rec=0 means the
bounded recursive pass did not reach the site, not unreachability --
linear presence plus containing-function identity governs the
classification; CPUID under i686rt advertises exactly
FPU/TSC/CX8/CMOV/MMX/FXSR/SSE/SSE2, ECX=0, so SSSE3+/OSXSAVE-gated
variants are never selected by glibc IFUNC):

    bytes     forms                                  lin    rec  classify
    0F 66 6F  MOVDQA load                             2302     4  IMPLEMENT
    0F F3 6F  MOVDQU load                              697    77  IMPLEMENT
    0F 66 7F  MOVDQA store                             957     0  IMPLEMENT
    0F F3 7F  MOVDQU store                             497     0  IMPLEMENT
    0F 66 D6  MOVQ m64/xmm-low <- xmm                  292     0  IMPLEMENT
    0F 66 E7  MOVNTDQ (NT memset large path)           130     0  IMPLEMENT
    0F 66 73  PSRLDQ/PSLLDQ                            184     0  IMPLEMENT
    0F 66 74  PCMPEQB (strlen/strchr family)          1508     0  IMPLEMENT
    0F 66 76  PCMPEQD                                  144   109  IMPLEMENT
    0F 66 D7  PMOVMSKB                                1352    56  IMPLEMENT
    0F 66 DA  PMINUB                                   351     0  IMPLEMENT
    0F 66 DE  PMAXUB                                    18     0  IMPLEMENT
    0F 66 F8  PSUBB                                    237    53  IMPLEMENT
    0F 66 64  PCMPGTB                                  408     0  IMPLEMENT
    0F 18     PREFETCHh (hint-NOP, same NT paths)      126     0  IMPLEMENT
    0F AE /7  SFENCE (8 sites after NT-store blocks)    --     0  IMPLEMENT
              (group slot; objdump-verified sites 0x19292b et al.)
    0F 38/3A  pshufb/ptest/palignr/pcmpistri           1789    0  leave (3-byte maps; SSSE3/SSE4 CPUID-gated off)
    0F 01     rdpkru/wrpkru/xgetbv                        5    0  leave (system class, OSXSAVE-gated)
    0F C7     xsavec                                      2    0  leave (XSAVE family)
    0F AE /4  xsave (ld-linux, OSXSAVE branch)            2    0  leave (XSAVE family)
    0F AE /5-/6  lfence/mfence                       (absent -- objdump finds none)  leave
    0F 75     PCMPEQW                               (absent everywhere)          leave

Not present at all (plain or prefixed): 0F 6F/7F MMX MOVQ forms,
0F 71/72 shift groups, 0F 75 PCMPEQW, MIN/MAX 5D/5F, SQRT 51-53,
F2 0F xx of every row above (only three mid-instruction desync
artifacts `f2 0f 00/03/f1`, not real instructions).  dash's own code
and ld-linux carry none of the implemented forms (only the CPUID-gated
xsave/xgetbv in ld-linux).

### B. Implementation (one id per 0F byte, prefix variants in-handler)

- tools/gen_insn_tab.py: +13 contract ids (MOVDQA, MOVQ2DQ, MOVNTDQ,
  PCMPGTB, PSRLDQ, PCMPEQB, PCMPEQD, PMINUB, PMAXUB, PSUBB, PMOVMSKB,
  PREFETCH, SFENCE); union 345 -> 358 ids, I686_OP_COUNT 359.  Rows:
  6F load ("R32","RM32") / 7F store ("RM32","R32") share I686_OP_MOVDQA;
  D6/E7 store-direction rows; 73 carries I8 (handler sub-dispatches
  /2 /3 under 66, /2 /6 plain MMX); 18 PREFETCH (modrm-sized, no
  access); SFENCE binds the 0F AE group /7 slot (opnd NONE).  Header
  notes updated (RC7b T1 bullet + INVALID list).
- src/x86/insn_tab.h regenerated; tools/test_insn_tab.py expectations
  extended (13 ids, 14 spot rows, 0F AE group row); also chmod +x on
  both tools so the acceptance chain runs verbatim.
- src/interp/h_sse.c: handlers per existing conventions (src128/
  int_vec_* / mm_rd/mm_wr, sse_done; sse_ea for the alignment check).
  MOVDQA (66 0F 6F/7F) and MOVNTDQ/MOVNTQ (0F E7) raise #GP(0) on
  misaligned EAs via the seg-fault channel (exit_arg=13, exit_dest=0,
  fault_addr=EA, eip unadvanced, resumable); MOVAPS keeps its documented
  v1 no-fault behavior.  PMOVMSKB rejects mod!=3 as UNDEF (#UD); plain
  MMX variants of every row implemented as the correctness oracle.
- src/dbt/emit_sse.c: emitters for the 66/F3 forms of every implemented
  row (NEON, ctx-scratch conventions; new verified raw words: EXT,
  CMEQ .16B/.4S, CMGT .16B, UMIN/UMAX .16B, SUB .16B, UMOV B-lane --
  all checked against the cross assembler).  MOVDQA/MOVDQU emit plain
  Q moves (alignment check is interpreter-only -- v1 MOVAPS-class
  deviation, documented); MOVNTDQ emits a plain Q store; SFENCE and
  PREFETCH emit nothing; MMX (plain) forms and F2 on 6F/7F decline to
  the D2 oracle.
- OUT-OF-SCOPE COORDINATION EDIT (disclosed, needs coordinator review):
  the union growth collided with the Phase-7 synthetic registry ids
  350..359 hard-coded in src/x86/decode.c AND src/interp/h_seg.c (the
  h_seg.c _Static_assert fired, by design).  Both identical tables moved
  lockstep to 460..469 (registry holds 512 slots; 91 headroom under the
  cap, 100 above the enum).  Behavior-preserving: private registry
  indices only; no seg/h_seg logic touched.

### C. Acceptance check (single run, 2026-10-22)

    tools/test_insn_tab.py && make build CC=<aarch64-unknown-linux-musl-gcc> \
      && docker run --rm --name t1-check --platform linux/arm64 --memory 2g \
         --cpus 2 -v /tmp/t1-check-stage:/w alpine:3.20 sh -c \
         'export HOME=/tmp/h; mkdir -p /tmp/h; timeout 90 /w/i686rt \
          --sysroot /w/sysroot -- /w/sysroot/usr/bin/sh -c "echo dash-ok"'

Output, verbatim (rc=0; container gone -- `docker ps -a --filter
name=t1-check` empty after the run):

    L1A OK
    BUILD-OK
    dash-ok

(check-chain rc=0, first attempt; build log zero warnings.  Pre-flight
runs against throwaway trees preceded it: default engine and
I686RT_ENGINE=dbt both print dash-ok.)

Deviations / notes:
- The h_seg.c/decode.c synthetic-id renumber above is the only
  out-of-scope touch; everything else is inside the card (tools/,
  insn_tab.h, h_sse.c, emit_sse.c, decode.c, phase-7.md).  src/os/*,
  src/main.c, seg.c, tests/golden/* untouched (golden outputs
  unverified-by-construction: no fixture rerun, no generator output
  change on any previously-ratified row).
- MOVDQA alignment #GP is interpreter-only; DBT emits unaligned-capable
  Q moves (same class as the ratified v1 MOVAPS deviation).  A guest
  that takes the fault under DBT silently proceeds instead of #GP.
- The sweep counts are static-analysis evidence (both passes bounded);
  reachability under the v1 CPUID argued per row above, not proven by
  execution for rec=0 rows.

