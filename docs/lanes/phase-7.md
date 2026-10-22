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


## RC7b triage T2 record (2026-10-22) — PASSED

Card: root-cause the guest-side string-function misbehavior behind the
wine cmd /c echo ok blocker (T1 sweep follow-up: single opcodes matched
the oracle, so a longer SEQUENCE had to diverge).  Lane worktree
i686rt-t2, branch lane/7b-t2; engine under test: interp (default).

### A. Fixture (tests/probe_strfuncs.c, freestanding i386)

tests/probe_strfuncs.c embeds the REAL glibc 2.44 i386 SSE2 string
function bodies, byte-exact, extracted from the sysroot libc.so.6, plus
hand-written raw-.byte probes for the strchr idioms and every T1-added
opcode with edge vectors/alignments and the 64-bit MMX forms:

- glibc blobs (S cases; identities from the IFUNC resolver target
  arithmetic, anchor 0x23de34, confirmed behaviorally on the oracle):
  __strchr_sse2 0xc0c70, __strrchr_sse2 0xc0d80, __memchr_sse2 0xc0f70,
  __strlen_sse2 0xafc80.  Note: glibc i386 has NO SSE2 strchrnul; the
  public strchrnul@@GLIBC_2.1.1 (0xa9e70) is a plain C implementation.
  An earlier draft mislabeled 0xc0c70/0xc0d80/0xc0f70 as
  chrnul/strchr/strlen from their map positions; the oracle run exposed
  that (chr got the LAST match = strrchr semantics; "strlen" took
  (s, c, n) = memchr) and the identities were corrected.
- case matrix: alignment offsets 0..63 over a 64-byte aligned buffer
  (fast path p&0x3f <= 0x30 and unaligned path), needles at
  0/1/5/15/16/31/33/47/63, absent needles, NUL needles
  (strchr(s,0)), needle-after-NUL (chr stops, memchr does not),
  16/32/64/128-boundary needles, memchr n=0/n<pos/n>len, >64-byte
  multi-loop strings, and the literal failing "/usr/bin/sh".
- P probes (raw .byte, pinned regs, no -msse needed): P1 glibc
  prologue idiom (movd + punpcklbw x2 + pshufd broadcast + movdqu +
  pcmpeqb x2 + pmovmskb, the NUL trick); P2 PSRLDQ/PSLLDQ
  (66 0F 73 /3 /7) imm 0/1/15/16/255 on 0102.. and all-ones + packed
  PSRLQ/PSLLQ (/2 /6); P3 MOVDQA + pcmpeqb-vs-zero edge vectors;
  P4 PCMPEQB/PCMPGTB (0x80 vs 0x7F signed); P5 PCMPEQD; P6 PMOVMSKB
  sign-bit patterns; P7 PMINUB/PMAXUB; P8 PSUBB wrap both directions;
  P9 MOVQ row (66 0F D6 m64 store + reg-reg, F3 0F 7E m64 load,
  F3 0F D6 MOVQ2DQ, F2 0F D6 MOVDQ2Q); P10 MOVD zero-extension;
  P11 MOVNTDQ aligned; P12 PREFETCHh /0../3 + SFENCE; P14 por;
  P15 MMX plain forms (movq mm, psubb/pcmpeqb/pcmpgtb/pcmpeqd/
  pminub/pmaxub mm, pmovmskb mm, psrlq/psllq mm, EMMS).

Build: docker --platform linux/386 alpine:3.20 gcc,
  cc -std=gnu11 -ffreestanding -static -nostdlib -O2 -march=i686
     -mno-mmx -fno-pie -fno-stack-protector
(all SSE/MMX as raw bytes; gcc rejects xmm clobbers with SSE disabled
and never allocates those registers, so the asm omits them).
Run oracle: qemu-i386 (alpine arm64 qemu-i386 package) over the same
static binary — deterministic; the --platform linux/386 container
(Rosetta/QEMU) agreed everywhere it was spot-checked.

### B. Divergences found and root causes (all in the T1-added rows)

1. h_movdqa (0F 6F/7F row) — THE dash blocker.  The plain/MMX MOVQ
   branch tested `pfx_rep == 0`, but the 66 prefix rides pfx_opsize,
   NOT pfx_rep, so 66-prefixed MOVDQA/MOVDQA-stores also took the
   8-byte MMX path: loads/stores went through the x87_st (MMX) slot,
   the real XMM destination stayed stale, and the misalignment #GP
   check was skipped.  glibc's aligned main loops (movdqa) therefore
   scanned stale data; __strchr_sse2 returned NULL for "/usr/bin/sh"
   -> dash shellexec PATH-searched the absolute path ->
   "exec: /usr/bin/sh: not found" 127.  Fix: plain-form test is now
   `pfx_opsize == 0U && pfx_rep == 0U`.
2. h_pshiftdq (0F 73 row) — group semantics.  0F 73 is the
   shift-by-imm8 GROUP: modrm_reg carries the /digit and the register
   operand is modrm_rm.  The T1 handler (a) wrote the result to the
   digit-indexed register (XMM3/XMM6) leaving the real destination
   stale, and (b) used the wrong digit map: real map is /2 PSRLQ,
   /3 PSRLDQ, /6 PSLLQ, /7 PSLLDQ (66 forms; the old code had
   /2 "PSRLDQ", /3 "PSLLDQ", /6 /7 -> UNDEF).  Rewritten: /3 byte
   shift out[j]=s[j+imm], /7 out[j]=s[j-imm], /2 /6 packed 64-bit BIT
   shifts (both quadwords, count masked to 6 bits); operand = rm in
   both the 66 and plain (MMX PSRLQ /2, PSLLQ /6) branches.
3. h_movq2dq (0F D6 row) — 66 reg-reg form.  Legacy MOVQ is the store
   form (reg field = source, rm = destination) and CLEARS bits 127:64
   of a register destination; the handler preserved the dest upper.
   Oracle-verified on both qemu backends; fixed to clear.
4. h_movq_xmm (0F 6E/7E row) — F3 0F 7E MOVQ xmm, xmm2/m64 clears
   dest[127:64]; the handler preserved it.  Fixed to clear (the DBT
   emitter already zeroed).
5. src/dbt/emit_sse.c — same fixes on the DBT side: sse_emit_psrldq
   now fires its byte-shift branches on /3 /7 (was /2 /3), stores to
   modrm_rm (was the digit), and declines /2 /6 (packed PSRLQ/PSLLQ)
   to the interpreter; sse_emit_movq2dq 66 reg-reg zeroes bits 127:64.
   NOTE (pre-existing, NOT introduced by this lane, verified by
   stashing the fixes): I686RT_ENGINE=dbt segfaults on the first
   66 0F 73 instruction (psrldq_min and the fixture both die at the
   same point; the interp engine handles the same binaries fine).
   Evidence: _build/probe_dbt.txt (truncated at PR p1 o=13, rc=139).
   Needs a coordinator-owned DBT look at the 0F 73 emission path.

### C. Acceptance check (single run, 2026-10-22)

Oracle (qemu-i386, alpine arm64 container, static fixture):

    DONE 1274 FAIL 0

i686rt (default interp engine, arm64 alpine container):

    DONE 1274 FAIL 0
    rc=0

    diff _build/probe_oracle.txt _build/probe_i686rt.txt   -> identical

Both outputs printed in full to the lane artifacts (kept at
_build/probe_oracle.txt and _build/probe_i686rt.txt; byte-identical,
1274 case lines each).  The reexec repro after the fix:

    /w/i686rt --sysroot /w/sysroot -- /w/sysroot/usr/bin/sh -c
      "exec /usr/bin/sh -c \"echo reexec-ok\""

no longer prints "exec: /usr/bin/sh: not found" — dash execve's the
absolute path correctly (the string-function blocker is gone).  The
chain now fails FURTHER DOWN at a non-opcode issue (see D).

First acceptance attempt passed (pre-flight iterations against the
fixture only; the check chain ran once).

### D. Wine-chain progress (evidence; further blockers are non-opcode)

- wine --version (direct loader, WINEDLLPATH set): STILL PASSES after
  the fixes — "wine-10.0 (debian 10.0~repack-12+b1)" rc=0 (no
  regression from the T2 opcode fixes).
- Full wrapper chain /usr/bin/wine (dash script): FAILS at the script's
  `test -x /usr/bin/wine32` — i686rt syscall 307 faccessat returns
  -EINVAL (real kernels: 0/-EACCES); faccessat2 (439) correctly returns
  -ENOSYS and glibc falls back to 307.  Evidence (I686RT_SYSTRACE):
    SYS 439 -> -38 (faccessat2, ENOSYS)
    SYS 307 -> -22 (faccessat, EINVAL)  <- the gap
  `test -d /usr/bin` passes, so this is the access-mode path for
  regular files.  Wrapper output: "error: unable to find wine
  executable, this shouldn't happen." rc=1.
- Re-exec'd program entry (blocks everything that execve's a dynamic
  PIE, incl. the reexec repro's second sh): the r_execve path enters
  the program at ITS OWN entry without transferring control to the
  PT_INTERP interpreter.  Trace: /usr/bin/sh is PIE, entry 0x2920,
  loaded at 0x400000; execution starts at 0x402920 (= entry) with
  ld-linux.so.2 mapped but libc.so.6 absent; the first PLT call
  (`jmp *0x24(%ebx)` at 0x402090) jumps to the unrelocated GOT value
  0x2096 -> guest fault.  The direct-launch path handles PT_INTERP
  correctly (wine --version works), so the gap is specific to the
  guest execve reload path.  Both items are coordinator-owned
  (src/os/syscalls.c / rt32 exec paths — outside this lane's file
  list).  Per the card, chasing stopped here.

Deviations / notes:
- src/x86/insn_tab.h line ~613 row comment still documents the OLD
  wrong digit map ("66 /2=PSRLDQ /3=PSLLDQ"); the file is outside this
  lane's list, so only the handlers were fixed — the comment needs a
  one-line coordinator touch.
- The fixture is self-checking (scalar C expectations) AND required to
  be byte-identical between oracle and i686rt; P2's first-cut
  expectations encoded the MMX PSRLQ semantics for the 66 form and a
  flat all-ones model — corrected against the oracle (both qemu
  backends agree: 66 PSRLQ/PSLLQ shift BOTH quadwords).
- p9rr pins the 66 0F D6 reg-reg form: legacy MOVQ clears the dest
  upper; i686rt now matches.  F3 0F 7E load likewise clears.

## RC7b triage T3 record (2026-10-22) — PASSED (with disclosed out-of-scope fix)

Card: verify the "empty -c operand string inside dash" hypothesis
(dash's parse/heap clobbered the test -x operand via glibc
memmove/strcpy/stpcpy/memcpy SSE2 sequences).  Lane worktree i686rt-t2
on lane/7b-t2, continued from c6b9e99; merged master 2100f7d (triage-3
stat/access + exec-entry fixes) into the lane branch first.

### A. Hypothesis verification — REFUTED

Method as prescribed: resolved every relevant IFUNC target in the
sysroot libc.so.6 (shared resolver anchor 0x23de34):
memmove -> 0xc2210/0x198030/0x19c260/0x1938a0, strcpy -> 0xc2840/
0xafdc0/0xb8660, stpcpy -> 0xc2be0/0xb4180/0xb9c80, memcpy ->
0x19a290/0xc2190/0x193260/0x194050, mempcpy -> 0x19b270/0xc2280/
0x193580/0x196050, memset -> 0x192cd0/0xc22c0/0x192650.  Then traced
the actual failing run (I686RT_TRACE, 212990 lines): libc loads at
0x40020000 and the SSE2 string bodies execute ZERO times — direct
eip greps for every candidate at its based address (0x400c2210,
0x400c0c70, 0x400afdc0, 0x401bxxxx, ...) all count 0; the busiest
libc pages are malloc/stdio/locale (page histogram symbolized:
0x84000-0x87000 W/T, 0xa4000 T, ...).  The glibc string-function
hypothesis is dead: none of those bodies run in this workload, so the
fixture was NOT extended with memmove/strcpy blobs (no tests for
demonstratedly-unexecuted code paths).

### B. Actual root cause: faccessat(307) reads a nonexistent 4th arg

Behavioral bisection first:
  test -f /etc/hostname -> FOK, test -d /bin -> DOK (stat path fine)
  test -x /bin          -> rc=1 (fails for a DIRECTORY)
  p=/usr/bin/wine32; test -x $p -> rc=1
  for a in test -x /usr/bin/wine32 -> [test] [-x] [/usr/bin/wine32]
The operand strings are INTACT (variable expansion and the argument
stack print verbatim) — there is no string corruption at all; `-x`
(X_OK) fails while `-d`/`-f` pass.  SYSTRACE:

    SYS 439 -> -38 (faccessat2, ENOSYS — glibc falls back)
    SYS 307 -> -22 (bx=ffffff9c cx=004266d4 dx=00000001 si=ffffffd0)

src/os/sys_pass.c sys_faccessat (triage-3) read a FOURTH argument
(flags) from ESI — but the legacy faccessat syscall takes exactly
three (dirfd, path, mode); ESI holds guest garbage (0xffffffd0).  The
handler forwarded it to the host faccessat (musl in the oracle
container): unknown flag bits -> EINVAL (-22).  `test -d`/`-f` only
worked because glibc's faccessat2->ENOSYS fallback for those ops goes
through fstatat64 (300), not 307.

Fix (DISCLOSED OUT-OF-SCOPE TOUCH — src/os/sys_pass.c is outside the
lane's file list; 3-line ABI fix, coordinator review requested):
sys_faccessat drops the flags parameter and passes flags=0 to the
host — the exact kernel ABI for syscall 307 (glibc only falls back to
307 for flags == 0 || AT_EACCESS, and 307 is the effective-uid check
by definition).  faccessat2 (439) remains unimplemented/-ENOSYS.

### C. Acceptance check (single chain, 2026-10-22)

    === 1. fixture (interp)
    rc=0
    DONE 1274 FAIL 0
    FIXTURE-IDENTICAL            (vs _build/probe_oracle.txt)
    === 2. reexec
    reexec-ok
    rc=0
    === 3. dash repro
    XOK
    rc=0
    === 4. wine --version
    wine-10.0 (debian 10.0~repack-12+b1)
    rc=0

First acceptance attempt passed (the earlier runs were diagnosis, not
check attempts).

### D. Wine wrapper chain progress (evidence)

The full wrapper chain /usr/bin/wine now executes PAST the script's
`test -x /usr/bin/wine32` (T2's blocker), execs wine32-stable ->
../libexec/wine/apploader -> the real wine loader.  53 path ops
(READLINK /proc/8/exe, OPENAT /etc/nsswitch.conf, /etc/passwd,
/lib/i386-linux-gnu/libc.so.6 all succeed) before dying at:

    SYS 243 -> -3          (set_thread_area: unimplemented)
    Fatal glibc error: Cannot allocate TLS block
    SYS 252 -> 127         (exit_group)

Next blocker (coordinator-owned, src/os syscall layer): i386
set_thread_area (243) — glibc i386 TLS requires it; also observed
one garbled READLINK path print (/proc/8/<binary>) worth a look when
that layer is next touched.  Per the card, chasing stopped here.
