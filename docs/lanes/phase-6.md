# Phase 6 — hl integration (L6a/L6b → S6/RC6)

SPEC §4 Phase 6, §4.C row 6, D14/D15, E03 (verdict: Rosetta can never
serve EM_386; hl needs explicit dispatch). The a32 integration IS on the
local hyper-linux master (src/a32.c f15d4b1+); the SPEC §6 dependency is
satisfied locally. hl changes are allowed from Phase 6 (D13/D15) but ONLY
on a local worktree branch of hyper-linux (`../i686rt-l6a`, branch
`lane/6-l6a`); the shared `../hyper-linux` checkout stays untouched,
nothing is ever pushed.

## Coordinator freeze (this is the frozen interface for the fan-out)

i686rt side (verified present, no lane work): `/dev/a32host` handshake
vendored in src/rt32/rt32_host.c (D14, I686RT_HOST=none opts out),
I686RT_WINDOW consumed by vm init (offset mode G=4 GiB when hl exports
0x100000000), CLI `--sysroot/--cache/--` all accepted, guest binary
opened by path.

hl side shape (mirrors a32.c exactly, D15 table `{EM_ARM→a32rt,
EM_386→i686rt}`):

- src/i686.h + src/i686.c (new):
  - `int  i686_probe_elf32(const char *path, uint16_t *out_type);`
    ELFCLASS32 + ELFDATA2LSB + EM_386, ET_EXEC/ET_DYN.
  - `void i686_set_path(const char *path);`
  - `int  i686_resolve_path(char *out, size_t out_sz);`
    `--i686rt` > `HL_I686RT` > `../i686rt/_build/i686rt` >
    `../i686rt/result/bin/i686rt`.
  - `typedef struct { char i686rt_path[LINUX_PATH_MAX]; elf_info_t
    i686rt_info; uint64_t load_base; uint64_t entry_point; }
    i686_result_t;`
  - `int i686_prepare(guest_t*, const char *binary_path, mem_region_t*,
    int*, int max, int verbose, i686_result_t*);` — load i686rt
    (static-PIE aarch64 ELF) via elf_load/elf_map_segments, 2MB-aligned
    placement below interp_base, icache invalidate, vDSO + segment
    regions (clone of a32_prepare).
  - `int i686_finalize(guest_t*, const char *binary_path, int guest_argc,
    const char **guest_argv, const i686_result_t*, int verbose,
    int *out_argc, const char ***out_argv, uint64_t *out_vdso_addr,
    int *out_execfd);` — vDSO, proc maps, argv
    `[i686rt_path, ("--sysroot", S)?, ("--cache", C)?, "--",
    guest_argv...]` with S from HL_SYSROOT/I686RT_SYSROOT and C from
    HL_I686_CACHE/I686RT_CACHE (no --auto-aot/--stats: i686rt has
    neither), `setenv("I686RT_WINDOW", HL_I686RT_WINDOW ||
    I686RT_WINDOW || "0x100000000", 1)`, pre-open binary → fd_alloc →
    out_execfd (AT_EXECFD auxv; i686rt currently opens by path —
    execfd is forward-compat only).
- src/translator.h (new): classification table
  `hl_translators[] = { {EM_ARM,"a32rt",a32_probe_elf32,a32_set_path,
  a32_resolve_path}, {EM_386,"i686rt",i686_probe_elf32,i686_set_path,
  i686_resolve_path} }` + lookup helper; hl.c/syscall_exec.c classify
  through it (need_a32/need_i686 stay distinct locals; prepare/finalize
  branch by translator with typed results — no void* refactoring of
  a32 call sites).
- src/hl.c: `--i686rt` / `--i686rt=` arg parse (both forms, mirroring
  --a32rt at :476); `need_i686` classification at the a32 site (:871)
  via the table; personality label "i686"; prepare/finalize branches at
  :1324/:1986; all `!need_a32` gates extended to `!need_i686` where
  they gate ELF64 assumptions.
- src/syscall_exec.c: guest-execve branch mirroring the a32 path
  (:233 classification, :985 prepare, matching finalize) for EM_386.
- Makefile: add i686.o to the hl build.
- /dev/a32host (device.c:173) is already registered and SHARED (D14) —
  no change.

**Deviation recorded at freeze:** SPEC 6.1 "flake input i686rt" —
hyper-linux's flake.nix has no translator-input mechanism at all (a32rt
is consumed via `--a32rt`/`HL_A32RT`/sibling `_build` fallback, never
via flake input). The i686 entry mirrors the a32rt mechanism; a flake
input would be a new, unused layer. Recorded here instead of built.

## Card L6a — hl translator dispatch for EM_386 (grunt lane)

- Scope: implement the frozen hl-side contract above, in the
  hyper-linux worktree `../i686rt-l6a` (branch `lane/6-l6a`, created
  from hyper-linux master by the coordinator). Copy-first from
  src/a32.c/a32.h with i686 names; do NOT refactor a32 code beyond the
  classification table; do NOT touch rosetta paths; never write into
  ../hyper-linux itself; never push; no AI mentions in commits; author
  Moritz Angermann <moritz@zw3rk.com>.
- Files owned (exclusive): src/i686.c, src/i686.h, src/translator.h.
  Bounded edits only in: src/hl.c, src/syscall_exec.c, Makefile.
- Build: `make hl` in the worktree (same as the existing _build/hl).
- Acceptance check (run once, from /tmp so the sibling-build fallback
  cannot fire):
  `cd /tmp && <worktree>/_build/hl /tmp/rc3/busybox-i686 sh -c 'echo ok';
  echo rc=$?`
  Expected: stderr contains `i686rt translator` (clean one-line
  diagnostic + non-zero rc per the E03 error-surface note), rc=1 —
  plus `make hl` in the worktree succeeded. Full `echo ok` through the
  VM is RC6 (coordinator).
- Escalate after 2 failed check attempts, any frozen-interface change,
  or ambiguity. Output: branch `lane/6-l6a` + this file's L6a record.

## Card L6b — `make test-pN-hl` targets (grunt lane)

- Scope: in the i686rt worktree `../i686rt-l6b` (branch `lane/6-l6b`),
  add `test-p1-hl … test-p5-hl` Makefile targets mirroring the
  test-pN-lima pattern, plus `tools/hl-smoke.sh` (POSIX sh, bounded by
  `timeout`, exit non-zero on missing hl/i686rt/busybox) that runs
  `timeout 120 "$HL" --i686rt "$I686RT" "$BUSYBOX" sh -c 'echo ok'`.
  Variables: `HL_BIN ?= ../hyper-linux/_build/hl`,
  `I686RT_BIN ?= $(abspath $(BUILD_DIR)/i686rt)`,
  `BUSYBOX_I686 ?= $(BUILD_DIR)/busybox-i686`. help stays the default
  goal; `all/test/check/clean` semantics unchanged.
- Files owned (exclusive): Makefile (target block only), tools/hl-smoke.sh.
- Acceptance check (single command):
  `make -n test-p2-hl test-p5-hl >/dev/null && sh -n tools/hl-smoke.sh && echo L6B-OK`
  Expected output: `L6B-OK`. Real execution is RC6 (coordinator).
- Same escalation/hygiene rules as L6a. Output: branch `lane/6-l6b`.

## S6/RC6 (coordinator)

Merge L6a (hl worktree branch stays local; hyper-linux master NOT
updated) and L6b; build hl from the L6a worktree; RC6:
`hl ./busybox-i686 sh -c 'echo ok'` → `ok` on macOS Apple Silicon with
offset mode G=4 GiB (hl exports I686RT_WINDOW=0x100000000 by default).
Record evidence here.
