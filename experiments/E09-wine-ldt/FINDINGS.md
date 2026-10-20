# E09 FINDINGS — wine-ldt

VERDICT: ANSWER: funcs=modify_ldt(123) func 0x11 write-one-user_desc ONLY (funcs 0/1/2 unused by every Wine since 0.9.x) + set_thread_area(243) for the GDT %fs path (alloc with entry_number=-1, then per-thread rewrite); descriptors=TEB %fs RW data 32-bit (base=TEB, limit=4095, D=1, G=0), flat CS32 (type 0x1b) and DS32 (0x13) aliases incl. the CallTo16 glue selector, Win16 code segs type 0x1b D=0 and data segs type 0x13 D=0, DPMI raw LDT_ENTRY via int31 0x000b/0x000c, free = write all-zero not-present entry; instructions=mov/pop es..gs, les/lds/lss/lfs/lgs, lcall 0x9a, ljmp 0xea, lret 0xcb/0xc3 and 0x66 lret, iret 0xcf (16-bit frames), int 0xcd (fault-emulated), cli/sti/in/out/mov cr,dr (fault-emulated), sigcontext+syscall-frame %fs/%gs round-trip and %gs fault fixup; gaps-vs-D8=set_thread_area entry_number=-1 auto-alloc, guest sigframe/CONTEXT segment-register round-trip, SS from LDT with D=0 (SP) + #SS on stack-limit, 0x66-prefixed far-ret cross-size transfer rules, resumable fault for int NN (NN!=0x80), fault mapping for privileged instructions in 16-bit code, #NP on loading not-present descriptors (D8 lists funcs 0/1/2 — none needed by Wine)

All `file:line` citations below are at wine-mirror/wine commit
`840a939ee526137639665ff5f587224d6a36403f` (dev HEAD) unless a tag is
named. `signal_i386.c` = `dlls/ntdll/unix/signal_i386.c`,
`virtual.c` = `dlls/ntdll/unix/virtual.c`,
`unix_private.h` = `dlls/ntdll/unix/unix_private.h`, `selector.c` /
`int31.c` / `instr.c` = under `dlls/krnl386.exe16/`.

## (a) modify_ldt operations used

- The only `modify_ldt` function Wine ever calls on Linux is **0x11**
  (write one `struct modify_ldt_s` = kernel `user_desc`), issued as raw
  `syscall(123, func, ptr, count)`:
  - wrapper `signal_i386.c:177-180`; the single call site
    `ldt_set_entry` at `signal_i386.c:2265-2275`
    (`if (modify_ldt( 0x11, &ldt_info, sizeof(ldt_info) ) < 0)`).
  - identical at `wine-10.0`/`wine-8.0` (`signal_i386.c:2173` at the
    wine-8.0 tag, commit `6677c044abb711f423fadfb61f2c9a37da6ff686`), and
    in the classic `libs/wine/ldt.c` at wine-5.0 (`:181`), wine-3.0
    (`:180`), wine-2.0 (`:180`), wine-0.9.37 (`:204`).
- **funcs 0 (read), 1 (old-format write), 2 (read_default) are never
  used** — not by any released Wine back to at least 0.9.37 (2006). Wine
  maintains a write-only shadow of everything it installs:
  `struct ldt_copy` (`virtual.c:3864-3872`) updated in
  `ldt_update_entry` (`virtual.c:3895-3919`); reads for
  `NtQueryInformationThread(ThreadDescriptorInformation)` /
  `GetThreadSelectorEntry` are served from that shadow
  (`ldt_get_entry` `virtual.c:3924-3967`, `get_thread_ldt_entry`
  `signal_i386.c:2320-2355`), including cross-process reads via
  `NtReadVirtualMemory` of the peer's `peb->SpareUlongs[0]` pointer
  (`virtual.c:3943-3962`). No `modify_ldt` read, no read_default cache.
- The LDT-side API surface for Win16/DPMI is `NtSetLdtEntries`
  (`virtual.c:3975-3998`) → `ldt_update_entry` → `ldt_set_entry` →
  `modify_ldt(0x11)`; the 16-bit kernel calls it from
  `selector.c:151-155`.

Allocation policy: `LDT_SIZE` 8192 (`unix_private.h:656`); a bitmap with
the **first word pre-marked used** (`ldt_bitmap = { ~0u }`,
`virtual.c:3890` — entries 0..31 reserved), first-free allocation
(`ldt_alloc_entry` `unix_private.h:701-711`, selectors returned as
`(idx << 3) | 7` = RPL 3, TI 1; krnl386 side `alloc_entries`
`selector.c:176-179` via `RtlFindClearBitsAndSet`). krnl386 additionally
reserves entries below `first_ldt_entry = 32`, plus 512 more if `%gs` is
an LDT selector and 512 more if `%fs` is (libc TLS on LDT-using
kernels): `selector.c:41,93-98`; ntdll mirrors the `%gs` case at
`signal_i386.c:2414`. Because the LDT is per-process (per-mm) while each
thread needs its own TEB, the LDT-%fs fallback allocates **one fresh LDT
entry per thread** (`signal_alloc_thread`, `signal_i386.c:2361-2374`).
Freeing = writing the all-zero `null_entry` (→ `seg_not_present=1`,
base=0, limit=0) and clearing the bitmap bit (`selector.c:183-190`,
`unix_private.h:713-717`).

## (b) descriptor kinds installed (with user_desc flag usage)

`struct modify_ldt_s` = kernel `user_desc`
(`signal_i386.c:163-172`). `ldt_set_entry` maps LDT_ENTRY → user_desc
(`signal_i386.c:2265-2275`; identical `fill_modify_ldt_struct` in the
wine-8.0 classic file):

- `entry_number = sel >> 3`; `base_addr`; raw 20-bit `limit` +
  `limit_in_pages = Granularity`; `seg_32bit = Default_Big`;
  `contents = (Type >> 2) & 3`; `read_exec_only = !(Type & 2)`;
  `seg_not_present = !Pres`; `usable = Sys`; `garbage` ignored.
- Wine's own descriptors always have DPL=3, Pres=1, Sys=0
  (`ldt_make_entry`, `unix_private.h:679-695`; krnl386 twin
  `selector.c:62-85`), so `usable=0` in practice except the GDT
  allocation below.

Kinds:

1. **TEB %fs data segment**: base = TEB, limit = `page_size-1` (4095),
   D=1, G=0, RW data (type 0x13) — `ldt_make_fs32_entry`
   `unix_private.h:729-732`; installed per thread by
   `signal_alloc_thread` (`signal_i386.c:2368`) when the GDT path is
   unavailable, and loaded via `ldt_set_fs`/`init_syscall_frame`
   (`signal_i386.c:2305-2318,2455-2470`).
2. **Flat CS32 code alias**: base 0, limit ~0 (`ldt_set_limit` sets
   granularity automatically when limit ≥ 0x100000,
   `unix_private.h:667-676`), type 0x1b D=1 (`ldt_make_cs32_entry`
   `unix_private.h:719-722`). Used to alias ntdll's CallTo16 glue so
   16-bit stubs can `lcall __FLATCS__:glue`
   (`wowthunk.c:74-81`, `kernel16_private.h:124-133`, `ne_module.c:94`).
3. **Flat DS32 data alias**: type 0x13 D=1 (`ldt_make_ds32_entry`
   `unix_private.h:724-727`), synthesized for
   `GetThreadSelectorEntry` queries of GDT selectors
   (`get_thread_ldt_entry`, `signal_i386.c:2340-2352`).
4. **Win16 code segments**: type 0x1b, **D=0**
   (`code16_segment`, `kernel16_private.h:241`), installed per NE
   segment (`ne_segment.c:1006`), task PDB/CS aliases
   (`task.c:198,336`), snoop and DOSMEM code blocks (`snoop.c:111,230`,
   `dosmem.c:307`).
5. **Win16 data segments**: type 0x13, **D=0** (`data_segment`,
   `kernel16_private.h:239` — note krnl386's variant clears
   `default_big`, unlike ntdll's). 16-bit offsets mask to 16 bits
   (`ldt_get_ptr`, `selector.c:122-126`). Big allocations alias through
   selector pairs (`local.c:1777-1778`) and CS↔DS aliases via
   `AllocCStoDSAlias16` / `PrestoChangoSelector16` (`selector.c:336-344`).
6. **DPMI descriptors**: `int 31h` 0x0000 alloc array, 0x0001 free,
   0x0002 real-mode alias, 0x0006/0x0007 base get/set, 0x0008 limit,
   0x0009 access rights, 0x000a CS alias, 0x000b/0x000c get/set
   **raw client-supplied `LDT_ENTRY`** (only a selector-range check
   `ldt_is_system`, no content filtering — `int31.c:192-345`,
   esp. `:326-337`). So Wine will push arbitrary DPMI descriptors
   (16/32-bit, expand-down, conforming, ...) through `modify_ldt(0x11)`
   and lets the kernel be the gatekeeper.

user_desc flag combos i686rt must accept from Wine:
`{seg_32bit∈{0,1}, contents∈{0,1,2,3}, read_exec_only∈{0,1},
limit_in_pages∈{0,1}, seg_not_present∈{0,1}, usable=0}` — i.e. the full
data/code space with S=0, DPL forced 3 by construction; plus the
all-zero descriptor (free) with `seg_not_present=1`. Wine never sets
`usable=1` on LDT writes.

## (c) instruction surface touching LDT selectors

Wine (≥5.18 model) executes Win16/DPMI code **natively** on the CPU
through LDT descriptors; its own generated stubs and fault emulator
define the full surface:

- Segment loads: `mov sreg, r/m` (0x8e, `instr.c:723-765`), `pop
  es/ss/ds` (0x07/0x17/0x1f, `instr.c:494-496`), `pop fs/gs`
  (0x0f 0xa1/0xa9, `instr.c:586-601`), `les/lds` (0xc4/0xc5,
  `instr.c:765-772`), `lss/lfs/lgs` (0x0f 0xb2/0xb4/0xb5,
  `instr.c:610-612`). These execute natively when the selector is valid;
  the emulator path exists for faults, guarded by
  `INSTR_ReplaceSelector` (`instr.c:91-100`, the bimodal 0x40 BIOS
  selector trick).
- Far transfers through LDT code descriptors, emitted as real code:
  `lcall` 0x9a (`snoop.c:143,189,236`; task dispatcher `task.c:301`;
  the CALLFROM16 `lcall __FLATCS__:glue` glue `kernel16_private.h:128`;
  `thunk.c:1055` jmpf), `ljmp` 0xea (`task.c:884`, `utthunk.c:185`),
  `lret` 0xcb (`thunk.c:1610`, `relay.c:250,301,405`) and near `0xc3`
  (`thunk.c:202`), **`0x66 lret`** (32-bit far ret from 16-bit code,
  `thunk.c:690-692`, detected as `0xcb66`/`0xca66` at `ne_module.c:90`),
  `lretl` + `lssl` 16-bit stack switches (`wowthunk.c:50-66`).
- `iret` 0xcf: emulated only when CS is a 16-bit LDT selector
  (`instr.c:781-800`; 16-bit vs 32-bit stack frames per operand size).
- `int 0xcd`: always faults in PM; dispatched to
  `DOSVM_EmulateInterruptPM` (`instr.c:775-779`, DPMI `int31.c:185+`).
- Privileged ops in 16-bit code fault and are emulated: `cli/sti`
  (`instr.c:853-857`), `in/out` (`instr.c:623-626,801-858`), `mov
  cr/dr` (`instr.c:514-585`). The whole emulator hangs off a vectored
  exception handler registered when the process is 16-bit
  (`kernel.c:105`, guard `instr.c:871-883`: system CS +
  ACCESS_VIOLATION/PRIV_INSTRUCTION).
- Segment registers in signal/exception state: save/restore of
  SegFs/SegGs into and out of sigcontext (`signal_i386.c:788-789,
  905-906`), restore on handler entry/exit (`signal_i386.c:665-666,
  711-712`), syscall frames carry fs/gs (`signal_i386:1021-1022,
  1112-1113,1538-1539`), and `check_invalid_gs` fixes a stale `%gs`
  prefix fault by rewriting `GS_sig` (`signal_i386.c:1327-1358`).
  `get/set_fs`, `get/set_gs` are plain `mov` asm (`signal_i386.c:540-543`).
- Limit semantics: Wine relies on the **CPU** to enforce segment limits
  of the descriptors it installs (that is the point of installing real
  LDT entries); its own segv path does no LDT limit arithmetic, only the
  %gs fixup above and ATL-thunk decoding. Not-present entries fault on
  load (#NP) — that is how freed selectors behave.

## (d) GDT TLS (set_thread_area) side by side

- At process start Wine **prefers a GDT entry** for the TEB %fs:
  `signal_init_process` calls `set_thread_area` with
  **`entry_number = -1`, `seg_32bit = 1`, `usable = 1`** and takes
  whatever slot the kernel assigns: `gdt_fs_sel = (entry_number << 3) |
  3` (`signal_i386.c:2402-2412`). Only if that fails (or the preloader
  left %fs as an LDT selector) does it fall back to per-thread LDT
  entries (see (b).1). `usable=1` is required: the kernel only
  auto-allocates AVL-usable descriptors.
- Per-thread, the GDT path rewrites **the same GDT entry's base** to the
  new TEB via `set_thread_area` (entry_number = sel>>3, base=TEB,
  limit=4095, seg_32bit=1) and then loads %fs
  (`ldt_set_fs`, `signal_i386.c:2305-2318`; thread start
  `init_syscall_frame` `signal_i386.c:2455-2470`).
- `get_thread_area` is never used; GDT descriptors for
  cs/ds/fs are **synthesized** in user space for
  `GetThreadSelectorEntry` (`signal_i386.c:2340-2352`).
- wow64 aside (out of card scope): old-style wow64 implements
  `modify_ldt` by hand-rolling `syscall 0x7b` on a 32-bit stack
  (`signal_x86_64.c:113-160`) and uses LDT fs32/cs32 entries
  (`signal_x86_64.c:2731,2826`).
- vm86: current Wine has **no vm86 code at all** (rg "vm86" over
  ntdll/krnl386 = no hits) — DOS support is 16-bit PM + DPMI only.

## Live trace

Attempted per card procedure step 4 and abandoned for cause: Docker
Desktop `--platform linux/386` runs via binfmt qemu-user-static, where
`ptrace(PTRACE_TRACEME)` returns ENOSYS, so `strace` cannot attach at
all (wine32 8.0~repack-4 itself installed and ran fine in the
container). No syscall counts were collected; the source-level answer
above does not depend on it.

## Gaps vs SPEC D8 (things Wine needs that D8 does not state today)

1. **`set_thread_area` with `entry_number = -1`** (auto-allocate a GDT
   slot, honor the back-filled number) — D8 fixes "3 entries,
   0x33/0x3b/0x43" but never states the -1 allocation request Wine's
   startup makes (`signal_i386.c:2405-2409`).
2. **Segment-register round-trip through the guest signal path**:
   i386 sigcontext/ss + CONTEXT SegCs..SegGs must survive signal
   delivery, `rt_sigreturn`, and `NtSet/GetContextThread` (wine suspend
   writes SegFs/SegGs mid-thread, `signal_i386.c:905-906,1112-1113`).
   D8 is silent; cross-ref §3.4/§3.5 layouts.
3. **SS loaded from LDT with D=0**: 16-bit SP stack (address-size 16 on
   push/pop/call), stack-limit violations → #SS; D8 only says "limit
   checks → SIGSEGV" for data segments and treats SS as flat.
4. **Cross-size far-transfer rules**: `0x66 lret` and mixed D=0/D=1
   far call/jmp/ret/iret — operand-size prefix selects 16/32-bit
   IP/SP/flags width independent of both CS D-bits (wine's thunks depend
   on exactly this, `thunk.c:690-692`). D8's "switches the decoder's
   default operand/address size" should be refined to spell out the
   prefix-vs-D-bit matrix and EIP/ESP truncation.
5. **`int NN` (NN != 0x80) must fault resumably** with the faulting
   context (GP-style SIGSEGV, EIP at the int), because Wine's DOSVM /
   DPMI / INSTR emulation is driven by that fault (`instr.c:775-779`).
   Not in D8; belongs in the Phase 7 card.
6. **Fault mapping for privileged instructions in 16-bit code**
   (cli/sti/in/out/mov cr,dr → wine expects EXCEPTION_PRIV_INSTRUCTION,
   i.e. a distinguishable guest signal with resumable context) —
   D5/D6 adjacent, unstated in D8.
7. **#NP on loading not-present LDT descriptors** (wine frees by writing
   seg_not_present=1 and DPMI/Win16 code may attempt to load them) —
   D8 mentions only limit checks.
8. Inverse note (over-spec, not a gap): D8 lists modify_ldt funcs
   0/1/2/0x11; Wine needs **only 0x11**. Funcs 0/1/2 can stay in scope
   for other guests (DOSEMU-style DPMI) but are not Wine-load-bearing;
   "read_default caching" is specifically unnecessary — Wine never
   reads the LDT back.

## Consequence for SPEC

- **D8 refinement (RC-E)**: add the seven gap items above; relax the
  modify_ldt func list to "0x11 mandatory, 0 optional, 1/2
  lowest-priority"; state the Wine allocation contract explicitly
  (8192 entries, first-free, entries 0..31 and 512-blocks below a
  libc-LDT %gs/%fs reserved, per-thread LDT %fs fallback when
  set_thread_area(-1) fails; selectors carry `|7`).
- **Phase 7 card contents** (LDT): (1) modify_ldt 0x11 write with full
  user_desc validation as in (b); (2) segment loads incl. SS with D-bit,
  limit and #NP/#SS fault semantics; (3) far transfers incl. the
  0x66-cross-size matrix of item 4; (4) int-NN resumable fault +
  privileged-op fault mapping (with D5/D6); (5) set_thread_area(-1)
  allocation; (6) sigframe/CONTEXT segment round-trip conformance test
  against wine32's `ntdll` startup (the lima oracle can run the real
  binary: source study predicts per wine32 process start:
  1 set_thread_area(-1) attempt; when it fails under i686rt's planned
  3-slot GDT, per-thread modify_ldt(0x11) writes instead).
- **Phase 8 note**: vm86 is Wine-irrelevant today (no vm86 in modern
  wine); only DOSEMU-era guests would need it — useful prioritization
  input for the vm86 card (E10).
