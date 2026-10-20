# i686rt — 32-bit x86 (i686) Linux user-mode translator — SPEC

Status: draft rev 2, 2026-10-20 (rev 2: Phase E experiments gate all implementation; rt32 extraction deferred; x87 64-bit default + `--x87-80`; LDT and vm86 in scope). Sources studied (read-only clones in /workspace):
`zw3rk/a32rt` @ `d84feb3`, `zw3rk/hyper-linux` @ `8048a96` (master), `/workspace/arm32-rosetta/REPORT.md` rev 2.
Tags: **[V]** checked in that source; **[U]** unverified, check before relying on it.

---

## 0. Reference study (what i686rt copies from a32rt / hl)

### 0.1 a32rt (zero-dep Curated C11 + A64 asm, static-PIE aarch64-linux, ~18.9 kLoC) [V]
| Concern | Where | Notes for i686rt |
|---|---|---|
| Entry / invocation (explicit `-- PATH ARGV0`, binfmt P via `a32rt-binfmt-p` argv0 alias, legacy form, `AT_EXECFD`) | `src/main.c:main`, `docs/HOST-CONTRACT.md` §1 | Copy verbatim, rename env prefix `I686RT_*`, alias `i686rt-binfmt-p`. |
| Host syscall floor (aarch64 only) | `docs/HOST-CONTRACT.md` §2 | Same floor. |
| Guest context, ABI-locked offsets with asm | `src/a32rt.h:a32_ctx_t` (`guest_base` @72 `_Static_assert`), `src/trampoline.S:a32_jit_run_block` | Same pattern: `i686_ctx_t` with locked offsets + `_Static_assert`. |
| Guest window `[G,G+4GiB)`; G order: `--window`/`A32RT_WINDOW` > `/dev/a32host` `window_hint` > G=0 > scan 4 GiB-aligned `[4G,64G)` | `src/vm.c:a32_vm_init`, `try_reserve_window`; `a32_guest_ptr()` in `a32rt.h` | Identical. Offset mode (G=4 GiB under hl) = `xG + uxtw(w_ea)` addressing (A32RT.md §3.7). |
| Guest VMA manager (region list, brk emulation, mmap2/mremap/munmap/mprotect, gap finder) | `src/vm.c:a32_vm_mmap2`, `a32_vm_brk`, `a32_vm_mremap`, `vm_find_free_gap_locked` | Reusable almost unchanged (ISA-agnostic). |
| ELF32 loader, PT_INTERP via sysroot, kuser page | `src/elf32.c:a32_elf_load`, `load_elf32_image`, `a32_kuser_setup` | Loader reusable; kuser → replaced by i386 vDSO page. |
| Initial stack / auxv synthesis | `src/stack32.c` | Reuse; i386 auxv: `AT_SYSINFO`, `AT_SYSINFO_EHDR`, `AT_HWCAP`=CPUID.1.EDX, `AT_PLATFORM="i686"`. |
| JIT: block cache, hash table, epochs, chain slots in data pages, IBTC + RAS, batch flush + I-cache, host-pc→guest-pc side tables | `src/jit.c:lookup_or_compile_entry`, `flush_batch_locked`, `try_chain_entries`, `a32_jit_record_pc_map`, `a32_jit_lookup_host_pc`, `a32_jit_invalidate_range`, `g_code_page_bitmap` | Reuse the cache/dispatcher skeleton; replace decoder/emitter front end. |
| A64 emitter | `src/a64_emit.c/.h` | Reuse as-is (host-side). |
| AOT cache (FNV ELF hash, scan, `--auto-aot`) | `src/aot.c:a32_aot_generate`, `compute_elf_hash`, `load_cache_from_path` | Defer (Phase H). |
| Syscall dispatcher, struct marshalling (stat64, statfs64, rusage, itimerspec time32/64, flock, dir-cookie remap, /proc virtualization, path/sysroot resolve, robust-list emulation) | `src/syscalls.c:a32_handle_syscall`, `map_dir_cookie`, `try_open_virtual_proc`, `resolve_guest_path_at`, `handle_fcntl_flock`, `a32_cleanup_robust_list`, `thread_exit_cleanup` | ~60% transferable; numbers and several layouts differ (§3.4). |
| CoW fork under hl: snapshot guest regions, PROT_NONE them, `fork()`, child restores from snapshot (hl's legacy fork IPC does not copy the 4 GiB window) | `src/syscalls.c:fork_with_guest_snapshot` (only when `ctx->has_host_info`) | Reuse unchanged. |
| Signals: host handler, sync (fault → guest PC via side table) vs async (pending bit, safe-point), guest frame build, rt_sigreturn, sigaltstack | `src/signals.c:host_sig_handler`, `deliver_guest_signal`, `a32_signals_deliver_sync`, `a32_signals_check_pending`, `a32_sys_rt_sigreturn` | Reuse machinery; i386 frame layout new. |
| Handshake | `include/a32host.h` (A32H_ABI 1.0, `A32H_GET_INFO`=0x81006101, 256-byte `a32h_info_t`, caps PAGE4K/WX_ENFORCED/ICACHE_TRAP_IALLU/LOW4G_FREE/DIROFF32/…), `src/host.c:a32_host_probe` (`A32RT_HOST=none` opt-out) | Reuse ABI unchanged (§3.9). |
| GDB RSP server | `src/gdb.c` | Defer; i386 target.xml later. |
| Packaging | `flake.nix:mkA32rt` (pkgsCross aarch64-multiplatform-musl, `make build`, installs `bin/a32rt`, `a32rt-binfmt-p` symlink, `include/a32host.h`), `mkA32rtTests` (armv7l musleabihf freestanding fixtures, `-DA32RT_FREESTANDING_TEST`), hydraJobs | Mirror: `mkI686rt`, `mkI686rtTests` with `pkgsCross.musl32`/i686 cross. |
| Tests / Makefile | `Makefile` targets `test-mN-hl` / `test-mN-lima`, `tests/test_m1_isa_fs.c … test_m8_glibc.c`, `tools/setup_m7_sysroot.py` | Same convention: one target per milestone, hl + lima variants. |

### 0.2 hyper-linux (hl) [V unless noted]
- HVF VM runs aarch64-linux guests at EL0 under a tiny EL1 shim (`src/shim.S`); syscalls handled host-side (`src/syscall*.c`), 4 KB stage-1 granule, `AT_PAGESZ=4096` (`hl.c:main`, `stack.c:build_linux_stack`).
- x86_64: `hl.c:main` sets `need_rosetta = (elf_info.e_machine == EM_X86_64)`; `guest_init(&g,0,48,need_rosetta)`; `rosetta.c:rosetta_prepare` (pre page tables: load RosettaLinux, VA alias) + `rosetta_finalize` (kbuf/TTBR1, vDSO, binary pre-opened at fd 3, binfmt argv). `syscall_exec.c:sys_execve` re-detects and toggles `g->is_rosetta`; `fork_ipc.c` disables the shm CoW path when `is_rosetta`.
- `elf.c:elf_load` rejects anything but ELFCLASS64 EM_AARCH64/EM_X86_64 → an i386 ELF fails today.
- **Rosetta cannot help**: RosettaLinux translates x86_64 only; macOS dropped 32-bit x86 entirely (Catalina). [U for RosettaLinux rejecting ELFCLASS32 explicitly — behaviour not tested here.] hl's EM_X86_64 path must not be used for EM_386.
- **Integration status [V, important]**: public hl master `8048a96` contains **no** a32rt integration — no `a32rt` flake input, no `src/a32.c`, no `/dev/a32host`, no ELFCLASS32 probe. A32RT.md §5.4 describes it against hl `d76cd75`, which is not on public master. So "hl consumes a32rt as a flake input" is **planned, not landed** (A32RT.md: runtime lookup `--a32rt PATH` > `$HL_A32RT` > default package path; vendored `src/a32host.h`; `a32_prepare/a32_finalize`; `/dev/a32host` via `device.c:hl_device_register` with PAGE4K|WX_ENFORCED|ICACHE_TRAP_IALLU, `window_hint=0x1_0000_0000`; sub-2MB MAP_FIXED/mprotect L2-split fix in `syscall.c:sys_mmap`; `guest.c:guest_get_used_regions` window support).
- Host-side constraints i686rt inherits: W^X toggling on fault (HVC #9), trapped `IC IVAU`/`DC CVAU` (HVC #12, host does IALLU), `DC ZVA` trapped, `set_robust_list` stubbed, `getdents64` d_off = 64-bit macOS cookie, low VA `<0x400000` owned by hl.

---

## 1. PRD

**Problem.** 64-bit-only hosts cannot run 32-bit x86 Linux binaries: Apple Silicon (no x86 at all; Rosetta does x86_64 only), AArch64 Linux servers/SBCs, and x86_64 kernels built without `CONFIG_IA32_EMULATION` or booted `ia32_emulation=0` (6.7+). Legacy i386 tooling, old static binaries, Steam-runtime-era/Wine32 helpers, and CI artefacts break.

**Product.** `i686rt`: a standalone static-PIE translator with the a32rt host contract. Given an `ELFCLASS32/ELFDATA2LSB/EM_386(3)` binary it runs it using only native 64-bit syscalls.

**Users / entry points.** (1) `hl` on macOS (primary verification), (2) binfmt_misc on aarch64 Linux (lima ground truth), (3) direct CLI, (4) later: x86_64 Linux without ia32.

**Goals (v1).** i686 baseline ISA + CMOV/CX8/MMX/SSE/SSE2/FXSR/x87; static and dynamic musl + glibc i686; threads, signals, fork/exec; busybox i686 passes its applet smoke; musl libc-test and an LTP subset pass at agreed rates; ≥ 30% of native-equivalent A64 throughput on CoreMark (stretch).
**In scope (v1) additionally:** exact 80-bit x87 via `--x87-80`; Wine-style LDT (`modify_ldt`, LDT selectors in segment loads, far calls/jumps/returns through LDT/GDT code descriptors, 16-bit code segments); `vm86`/`vm86old` with a real-mode/v86 interpreter path.
**Non-goals (v1).** AVX+; ptrace emulation; kernel module; AOT cache; host-library thunking; shared rt32 library extraction.

---

## 2. Key design decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Language/packaging = a32rt's**: Curated C11 + minimal A64 asm, zero deps, static-PIE aarch64-linux-musl, flake + self-documenting Makefile, Apache-2.0. | Same toolchain, same review culture, same host contract. |
| D2 | **Two engines**: (a) portable C **interpreter** (`interp/`) — correctness oracle, x86_64-host fallback, single-step/debug; (b) **DBT x86→A64** (`dbt/`) reusing a32rt's cache/dispatcher/emitter. Engine per block selectable (`I686RT_ENGINE=interp|dbt`), interpreter is the fallback for unimplemented opcodes (no asserts on unknown insns: interpret-one then resume). | Explore fast: the interpreter gets busybox running before the DBT, and gives differential testing for free. |
| D3 | **Hosts**: aarch64-linux (bare + hl) = tier 1, DBT. x86_64-linux without ia32 = tier 2, interpreter-only build (same C, `x86_64-unknown-linux-musl`); a native fast path via 32-bit code segment (`USER32_CS`, far jmp) is an **open question** [U: whether ia32_emulation=0 removes the compat CS]. | Keeps tier 2 nearly free. |
| D4 | **Memory**: same window `[G,G+4GiB)` and resolution order as a32rt (`vm.c:a32_vm_init`); offset mode G=4 GiB under hl. All EA math in W regs (natural 32-bit wrap), then `add x, xG, w, uxtw`. Guard: none needed since EA is wrapped before add. Guest user top = `0xFFFFE000` (i386 TASK_SIZE on x86_64 compat is 4 GiB [U exact value]); reserve top page for vDSO-like trampolines? No — vDSO placed by mmap in window. | Proven path. |
| D5 | **Memory ordering**: x86 is TSO; A64 is weak. Default: plain LDR/STR while process has 1 thread; once `clone(CLONE_VM)` happens, flush the code cache and re-translate in **TSO mode** (loads `LDAPR` (FEAT_LRCPC, else `LDAR`), stores `STLR`); LOCK-prefixed RMW → LSE atomics (`CASAL`, `LDADDAL`, `SWPAL`), else LDAXR/STLXR loops. Handshake cap for hardware TSO (Apple ACTLR_EL1.TSO under HVF) is an open question. | Correct first; FEX/Box64 use the same lattice [U for their exact policy]. |
| D6 | **Flags**: lazy. ctx holds `{op, res, src1, src2, cf_in}`; materialize EFLAGS only on read (`pushf`, `lahf`, `jcc` not fusable, `adc`, signal frame). Fast path: fuse `cmp/test/sub/add + jcc/setcc/cmovcc` into A64 NZCV (note C inverted for SUB borrow). PF/AF only computed lazily from `res`/srcs. Block-local backward liveness drops dead flag writes. | Biggest DBT win. |
| D7 | **Registers**: EAX..EDI fixed in w-regs (x19..x26 callee-saved under the trampoline), EIP/EFLAGS-lazy in ctx + scratch; `xG`=guest base, `xCtx`=ctx. 8/16-bit partial regs via `BFI/UBFX`. | Mirrors a32rt's fixed mapping (A32RT.md §3.1). |
| D8 | **Segments/TLS/LDT**: emulate GDT TLS slots (3 entries, `GDT_ENTRY_TLS_MIN=6` → selectors 0x33/0x3b/0x43) + per-thread `seg_base[6]`. `set_thread_area(243)`/`get_thread_area(244)` operate on `struct user_desc` (16 B). `mov gs, r` loads base from slot; `gs:`/`fs:`-prefixed accesses add `seg_base`. CS/DS/ES/SS flat (base 0). Full per-process emulated LDT (8192 descriptors, `modify_ldt` funcs 0/1/2/0x11, read/write/read_default): segment loads with TI=1 resolve base/limit/D-bit from the LDT; non-flat CS (far `jmp/call/ret/iret`, `lcall` through code descriptors) switches the decoder's default operand/address size (16/32) and adds CS base to EIP; limit checks → SIGSEGV (interpreter enforces; DBT assumes flat, guarded by a per-block segment-state key). Non-flat CS/DS blocks run in the interpreter first (DBT for them is Phase H). | glibc/musl use `%gs`; Wine32 uses LDT selectors for `%fs` TEB and 16-bit code. |
| D9 | **x87**: two modes, both in scope. Default: 64-bit double per ST(i) + tag word + TOP in ctx, FPU CW honoured for rounding (not precision). `--x87-80` (also `I686RT_X87=80`): exact 80-bit extended semantics (soft-float, precision control, denormals, exceptions/SW flags, exact `fld/fstp m80`), implemented in DBT via helper calls; chosen at startup, fixed per process (inherited across fork/exec via env). `fld/fstp m80` convert. MMX aliases x87 mantissa bits (store MMX as 64-bit in the ST slot raw bits). | Matches common practice; exactness opt-in. |
| D10 | **SSE/SSE2** → NEON 1:1 on `v` regs held in ctx (`xmm0..7`), MXCSR rounding → FPCR; DAZ/FTZ map to FPCR.FZ. Unaligned `movups` free on A64. CPUID advertises: FPU,TSC,CX8,CMOV,MMX,FXSR,SSE,SSE2 (no SSE3+ in v1), vendor "GenuineIntel", family 6. | Deterministic feature set. |
| D11 | **SMC**: x86 requires coherent self-modifying code. Reuse `g_code_page_bitmap`: after translating from a writable page, mprotect it RO (in-window); SIGSEGV write fault → `a32_jit_invalidate_range`-equivalent for the page, restore RW, re-execute. Same-block SMC (write into current block): end block after the store if target page is code; check generation counter at block exit. | Works under hl W^X too (window pages are data from hl's view). |
| D12 | **Syscall entry**: `int 0x80` (CD 80) direct; `sysenter`/`syscall` treated as int 0x80. Provide a synthetic **i386 vDSO** (tiny ELF32 image built at compile time, embedded) exporting `__kernel_vsyscall` (`int $0x80; ret`), `__kernel_sigreturn`, `__kernel_rt_sigreturn`, `__vdso_clock_gettime/gettimeofday/time/clock_gettime64` (trap into a fast in-process hypercall opcode, e.g. reserved `ud2`+magic → host clock_gettime). Pass `AT_SYSINFO` + `AT_SYSINFO_EHDR`. | glibc calls `*%gs:0x10` (SYSINFO) [U offset]. |
| D13 | **Sharing with a32rt**: **copy-first, extraction explicitly deferred**. Phase 0 copies a32rt's ISA-agnostic files into `src/rt32/` with `rt32_` prefix (vm, elf32 loader, stack32, host probe, a64_emit, jit cache core, signals core, syscall marshalling helpers). No change to a32rt. **No shared-library extraction anywhere in this plan**; revisit only after sufficient production experience with both i686rt and a32rt. | Don't destabilize a32rt; avoid premature abstraction. |
| D14 | **Handshake**: reuse `/dev/a32host` + A32H_ABI 1.0 **unchanged** (vendored `include/a32host.h`). i686-specific caps later via minor bump (e.g. `A32H_CAP_HW_TSO`). `I686RT_HOST=none` opt-out. | hl needs one device for both translators. |
| D15 | **hl integration** (separate PR in hl, after a32 integration lands): generalize the planned `a32_prepare/a32_finalize` into a translator table `{EM_ARM→a32rt, EM_386→i686rt}`; `elf_probe_file` accepts ELFCLASS32 EM_386; `--i686rt PATH` > `$HL_I686RT` > default package path; i686rt added as hl flake input alongside a32rt. | Rosetta path stays EM_X86_64 only. |

---

## 3. Technical spec

### 3.1 Repo layout
```
i686rt/
  flake.nix  Makefile  README.md  AGENTS.md  LICENSE  docs/HOST-CONTRACT.md (references a32rt's, deltas only)
  include/a32host.h                (vendored, byte-identical to a32rt)
  src/rt32/  vm.c elf32.c stack32.c host.c a64_emit.[ch] jitcore.c signals_core.c marshal.c   (from a32rt)
  src/x86/   decode.c (prefixes, ModRM/SIB, opcode tables) insn_tab.h (generated) cpuid.c
  src/interp/ interp.c x87.c x87_80.c (softfloat extended) sse.c flags.c seg.c (LDT/GDT descriptors, far transfers) v86.c (real-mode/v86 interpreter)
  src/dbt/    translate.c emit_alu.c emit_mem.c emit_x87.c emit_sse.c flags_lazy.c tso.c
  src/os/     ldt.c (modify_ldt) vm86.c (vm86/vm86old) syscalls.c (i386 table) structs_i386.h signals_i386.c tls.c vdso_i386.S vdso_blob.c proc.c
  src/main.c  src/i686rt.h  src/trampoline.S
  tests/      hello.c test_p1_isa.c test_p3_libc.c test_p4_threads_signals.c test_p5_fpu_sse.c ... bench_coremark.c
  experiments/ E01..E10/ (procedure + FINDINGS.md each)
  tools/      gen_insn_tab.py  gen_syscall_tab.py  setup_sysroot.py
```

### 3.2 Decoder
Table-driven: legacy prefixes (66, 67, F0, F2, F3, 2E/36/3E/26/64/65), 1-byte and 0F map, 0F38/0F3A only for SSSE3+ (later). Output a `x86_insn_t` {opcode id, operand kinds, ModRM decoded EA {base,index,scale,disp,seg}, imm, len}. Tables generated (`tools/gen_insn_tab.py`) — Flash work. 0x67 (16-bit addressing) supported in the interpreter only.

### 3.3 DBT
Block = straight line until branch/`int`/`hlt`/unknown/page end, max N insns. Reuse jitcore: hash on guest EIP (no T bit), chain slots, IBTC for `jmp r/m`, RAS for `call/ret` (push guest ret, compare on `ret`). Side table host-pc→(EIP, insn boundary) for precise faults. REP string ops: loop in emitted code with safe-point check every K iterations. Division by zero → synthesize SIGFPE (A64 udiv doesn't trap: explicit check). `ud2`/unknown → interpreter single-step fallback.

### 3.4 i386 syscall ABI (number in EAX, args EBX,ECX,EDX,ESI,EDI,EBP; return EAX)
- Table from kernel `arch/x86/entry/syscalls/syscall_32.tbl` (generated, Flash). 64-bit args split lo/hi in consecutive regs **without** ARM's even-pair alignment (e.g. `pread64(fd,buf,count,lo,hi)`, `fadvise64_64`, `ftruncate64`, `truncate64`, `sync_file_range`, `fallocate`).
- Multiplexers: `socketcall(102)` (args array in guest mem), `ipc(117)` (sem/msg/shm with `version`), old `mmap(90)` takes `struct mmap_arg_struct*`; `mmap2(192)` pgoff in 4K units; `select(82)` old struct form; `sigreturn(119)`/`rt_sigreturn(173)`.
- Layouts differing from arm EABI (i386 aligns u64 to 4): `stat64` (96 B, `__st_ino` + `st_ino` u64 at end), `statfs64` (84 B, packed), `epoll_event` (12 B on i386 vs 16 B on aarch64), `flock64` (24 B), `msghdr/cmsghdr`, `sigaction` (`sa_handler,sa_flags,sa_restorer,sa_mask` — differs from rt? same order as arm), `user_desc`, `rlimit` (u32), `sysinfo`, `timex`, `semid_ds`/`shmid_ds`/`msqid_ds` ipc64 variants, `struct linux_dirent` (old getdents 141). time32 + time64 syscalls (403–414 etc., shared numbering with all 32-bit arches) both supported. `ioctl`: whitelist translation (termios TCGETS etc. identical layout; others passthrough only if layout-neutral).
- `uname` machine = "i686"; `personality`; `/proc/cpuinfo` synthesized x86 (vendor, flags from D10); `/proc/self/{exe,maps,auxv,cmdline}` virtualized (reuse `try_open_virtual_proc`).

### 3.5 Signals
i386 frames: non-RT `struct sigframe {pretcode, sig, sigcontext, fpstate, extramask, retcode[8]}` and `rt_sigframe {pretcode, sig, pinfo, puc, siginfo(128), ucontext, retcode}`; `sigcontext` gs,fs,es,ds,edi..esp,ebx..eax,trapno,err,eip,cs,eflags,esp_at_signal,ss,fpstate*,oldmask,cr2; fpstate = `_fpstate_32` (x87 env + 8×10-byte regs + FXSR area + magic 0x46505853 [U]). Restorer: `sa_restorer` if SA_RESTORER, else vDSO `__kernel_(rt_)sigreturn`. Fault mapping: SIGSEGV with `cr2`, trapno 14 / err; SIGFPE from div; SIGILL from undecodable; SIGTRAP from `int3`. Async via safe points (a32rt model).

### 3.6 Threads / clone
i386 clone order: `clone(flags, newsp, parent_tidptr, tls, child_tidptr)` (EBX,ECX,EDX,ESI,EDI) where **tls is a `struct user_desc*`** (CLONE_SETTLS installs GDT TLS slot for the child). Host thread gets fresh host stack + cloned ctx (a32rt `thread_exit_cleanup`, robust-list emulation `a32_cleanup_robust_list` — i386 robust_list_head layout = 32-bit). `vfork`/fork → `fork_with_guest_snapshot` under hl. `futex` passthrough (32-bit words identical); `futex_time64`. `set_tid_address` kept guest-side for CLONE_CHILD_CLEARTID.

### 3.7 mmap in the 4 GiB window
Reuse `rt32/vm.c` verbatim: guest mmap2 bottom-up cursor above brk, `MAP_FIXED` validated in-window, `MAP_32BIT` ignored, top limit `0xFFFFE000`. Host prot: guest PROT_EXEC is never host-exec (window is data); translated code lives outside window. Write-protect for SMC layered on top (D11).

### 3.8 Tests
1. Freestanding static fixtures (`-m32 -march=i686 -nostdlib -static`, `-DI686RT_FREESTANDING_TEST`, own `_start` with `int $0x80`), built via flake (`pkgsCross.musl32` / clang `--target=i686-linux-musl`) [U attr name].
2. Static musl busybox i686 (Alpine x86 `busybox-static` apk) — applet smoke script.
3. Dynamic: Alpine x86 sysroot (musl) + Debian i386 glibc sysroot via `tools/setup_sysroot.py` → `--sysroot`.
4. Suites: musl `libc-test`, LTP syscalls subset, a hand x87/SSE vector test compared against **golden outputs generated on a real i386/ia32 Linux** (x86_64 CI box with ia32) — checked into `tests/golden/`.
5. Differential: `I686RT_ENGINE=interp` vs `dbt` trace compare on fixtures (regs at block boundaries).
Targets: `make test-pN-lima` (aarch64 Linux via limactl, ground truth) and `make test-pN-hl` (after Phase 6).

---

## 4. Phased plan

Rules: explore fast first (break internal APIs freely, one vertical slice per phase), harden after. **Exactly one acceptance check per task/phase; never re-run a passed check; no tests nobody asked for.** Owners: **[GLM-5.3]** = coordination, architecture, ABI-locked structs, review; **[GLM-5.3-Flash]** = boilerplate, tables, fixtures, repetitive code. A **Review checkpoint (RC)** is GLM-5.3 reading Flash's diff against this spec before the phase's check is run; failures go back to Flash with a concrete list.

### Phase E — Experiments (before any implementation)
Each experiment lives in `experiments/Enn-<slug>/` with `README.md` (hypothesis, procedure) and `FINDINGS.md` (one-line verdict `PASS|FAIL|ANSWER: …`, evidence, consequence for the spec). Procedures are minimal (one probe program or one source lookup). Flash runs them; **GLM-5.3 reviews every conclusion (RC-E)** and patches SPEC.md (decisions + §5/§6). Gate: a phase that depends on an experiment (column "Gates") may not start until that experiment's FINDINGS.md is reviewed.

| ID | Question | Hypothesis | Minimal procedure | Output | Owner | Gates |
|---|---|---|---|---|---|---|
| E01 | Apple HW strong-ordering (TSO) per vCPU via Hypervisor.framework | Not settable from HVF public API (ACTLR_EL1 TSO bit not exposed/ignored) | Tiny hl patch/probe: `hv_vcpu_set_sys_reg(ACTLR_EL1)` with TSO bit, read back; run a message-passing litmus test (store-buffer / MP) 10^7 iterations with and without | PASS = TSO settable and litmus shows no reordering; else FAIL | GLM-5.3-Flash, RC GLM-5.3 | D5, Phase 4, Phase 6 |
| E02 | Does `ia32_emulation=0` remove the 32-bit user CS? | 6.7+ with `ia32_emulation=0` keeps `__USER32_CS` in GDT but blocks int 0x80/sysenter entry | x86_64 VM, kernel ≥6.7, boot `ia32_emulation=0`; probe: far-jmp to selector 0x23, run `nop; far ret` and also `int 0x80` | ANSWER: CS usable yes/no; int 0x80 → SIGSEGV/ENOSYS | GLM-5.3-Flash, RC GLM-5.3 | D3, H4 |
| E03 | RosettaLinux on a 32-bit ELF | Rejects with an error message, no execution | In a Linux VM with Rosetta mounted: `rosetta ./hello-i386-static`; capture exit code/stderr | ANSWER: exact behaviour | GLM-5.3-Flash, RC GLM-5.3 | D15 (hl dispatch) |
| E04 | Top of i386 user address space | 32-bit task on x86_64: TASK_SIZE = 0xFFFFE000 (IA32_PAGE_OFFSET) [vs 0xC0000000 on native 3G/1G] | Kernel source lookup (`arch/x86/include/asm/page_64_types.h`, `processor.h`) + if E02 VM has ia32: `mmap` probe loop / read `/proc/self/maps` of an i386 binary | ANSWER: value + source line | GLM-5.3-Flash, RC GLM-5.3 | D4, Phase 2 |
| E05 | i386 FPU signal-frame magic | `_fpstate_32.magic` = 0x0000 for FXSR, `FP_XSTATE_MAGIC1`=0x46505853 in sw_reserved | Read `arch/x86/include/uapi/asm/sigcontext.h`; on ia32 host dump a real frame from a handler | ANSWER: layout offsets + magic values | GLM-5.3-Flash, RC GLM-5.3 | Phase 4 signals |
| E06 | nixpkgs i686 cross attr names | `pkgsCross.musl32` (i686-unknown-linux-musl) and `pkgsi686Linux` / `pkgsCross.gnu32` exist | `nix eval nixpkgs#pkgsCross.musl32.stdenv.hostPlatform.config` etc.; build hello for each | ANSWER: attr list that builds | GLM-5.3-Flash, RC GLM-5.3 | Phase 0 |
| E07 | glibc i686 vDSO symbol versions + `%gs` SYSINFO offset | glibc looks up `LINUX_2.6` `__vdso_clock_gettime`, `__vdso_gettimeofday`, `__vdso_time`, `__vdso_clock_gettime64`, `__vdso_clock_getres`; `__kernel_vsyscall` via AT_SYSINFO stored at `%gs:0x10` (`tcbhead_t.sysinfo`) | Grep glibc `sysdeps/unix/sysv/linux/i386/` (`dl-vdso`, `sysdep.h`, `tls.h`) + `readelf -V` of a real i386 vDSO dump (kernel `vdso32.so`) | ANSWER: symbol/version table + offset | GLM-5.3-Flash, RC GLM-5.3 | D12, Phase 2 |
| E08 | How FEX and Box86 handle x86 memory ordering | FEX: TSO by default via LDAPR/STLR (+ "half-barrier" and option to disable), HW TSO when available; Box86: no TSO by default, strong-mem opt-in (`BOX86_DYNAREC_STRONGMEM`) | Source/docs read of FEX-Emu and box86 (config options + emitter); note policies and multithread triggers | ANSWER: comparison table | GLM-5.3-Flash, RC GLM-5.3 | D5, Phase 4 |
| E09 | How Wine uses the LDT | Wine32 (WoW, non-wow64 mode) allocates LDT entries via `modify_ldt` for TEB `%fs`, 16-bit code/data (Win16, DPMI), and does far calls into 16-bit thunks | Read Wine `dlls/ntdll/unix/signal_i386.c`, `ldt` code (`ldt_set_entry`, `wine_ldt_*`); list syscalls/funcs/flags used; trace `strace -e modify_ldt wine notepad` on ia32 host if available | ANSWER: required modify_ldt funcs, descriptor kinds, instructions touching LDT selectors | GLM-5.3-Flash, RC GLM-5.3 | Phase 7 |
| E10 | vm86 feasibility | vm86/vm86old (113/166) can be fully emulated in-process: v86 is an interpreter mode over a 1 MiB guest region at linear 0 (needs window G low 1 MiB mappable; under hl low VA is host-owned but guest window offset mode makes guest 0 = G) with return-to-32-bit on GP-class events | Read kernel `arch/x86/kernel/vm86_32.c` + `struct vm86plus_struct`; check users (dosemu1, `v86d`, X11 int10/x86emu fallback); prototype: interpreter runs a 20-byte real-mode program in guest [0,1MiB) and returns via `int` revectoring | PASS = prototype returns correct regs + VM86_INTx code | GLM-5.3-Flash, RC GLM-5.3 | Phase 8 |

- RC-E [GLM-5.3]: review all FINDINGS.md, update D3/D4/D5/D8/D12/D15, §3, §5, §6. **Accept:** every E01–E10 has a reviewed FINDINGS.md with a verdict line, and §6 has no item without an Exx reference.

### Phase 0 — Scaffold (explore)  
- 0.1 [GLM-5.3] Write `src/i686rt.h` (`i686_ctx_t`, locked offsets + `_Static_assert`s), module boundaries per §3.1, AGENTS.md.
- 0.2 [GLM-5.3-Flash] Vendor a32rt files into `src/rt32/` with `rt32_` rename; flake.nix (`mkI686rt`, `mkI686rtTests`), Makefile skeleton (help, build, test-p0-lima), vendored `include/a32host.h`.
- RC0 [GLM-5.3]. **Accept:** `nix build .#i686rt` produces a static-PIE aarch64 ELF; `file` says static-pie.

### Phase 1 — Interpreter hello (explore)
- 1.1 [GLM-5.3-Flash] `tools/gen_insn_tab.py` + `src/x86/insn_tab.h` (1-byte + 0F maps, i686 integer set).
- 1.2 [GLM-5.3] Decoder core (prefixes, ModRM/SIB, EA), interpreter loop, flags semantics (`flags.c` reference impl).
- 1.3 [GLM-5.3-Flash] Interpreter handlers for ALU/MOV/stack/string/branch/CMOV/SETcc/BT*/shifts/MUL/DIV; syscall table generation `gen_syscall_tab.py`; minimal syscalls (write, exit_group, brk, mmap2, set_thread_area, uname).
- 1.4 [GLM-5.3-Flash] `tests/hello.c`, `tests/test_p1_isa.c` freestanding fixtures.
- RC1 [GLM-5.3]. **Accept:** `make test-p1-lima` → test_p1_isa prints PASS under `I686RT_ENGINE=interp`.

### Phase 2 — Static libc + busybox (explore)
- 2.1 [GLM-5.3] Syscall marshalling for §3.4 struct set (stat64, statfs64, getdents64 + cookie remap, socketcall, ipc, old mmap, time32/time64), `/proc` virtualization, auxv (`AT_SYSINFO*`), embedded i386 vDSO.
- 2.2 [GLM-5.3-Flash] Fill remaining layout-neutral passthrough syscalls from the generated table; struct definitions in `structs_i386.h` with `_Static_assert(sizeof)`s against kernel values.
- RC2 [GLM-5.3]. **Accept:** static i686 busybox runs `sh -c 'ls / && echo ok'` → `ok` (interp, lima).

### Phase 3 — DBT core (explore)
- 3.1 [GLM-5.3] Adapt jitcore (EIP key, chain, IBTC, RAS, side tables), trampoline.S, register map D7, lazy flags D6 with cmp/jcc fusion, interpreter fallback per insn.
- 3.2 [GLM-5.3-Flash] Emitters for ALU/MOV/LEA/stack/branch/string ops following 3.1 patterns.
- 3.3 [GLM-5.3-Flash] Differential trace harness (interp vs dbt) for fixtures.
- RC3 [GLM-5.3]. **Accept:** `make test-p3-lima` → differential harness reports 0 mismatches on test_p1_isa and busybox smoke passes under `dbt`.

### Phase 4 — Dynamic linking, threads, signals
- 4.1 [GLM-5.3] clone/CLONE_SETTLS with user_desc, TSO switch (D5) + LOCK → LSE, futex, robust lists; i386 sigframes + sigreturn; sync fault mapping.
- 4.2 [GLM-5.3-Flash] `tests/test_p4_threads_signals.c` (pthreads, sigaction/SA_SIGINFO, sigaltstack, SIGSEGV recovery, fork+wait); sysroot setup script.
- RC4 [GLM-5.3]. **Accept:** dynamic glibc-i686 `test_p4` prints PASS under lima.

### Phase 5 — x87 / MMX / SSE / SSE2
- 5.1 [GLM-5.3] x87 model D9 (stack, tags, CW/SW, m80 convert), MXCSR↔FPCR, SSE register file.
- 5.2 [GLM-5.3-Flash] Emitters + interpreter handlers for SSE/SSE2 packed/scalar ops and x87 arithmetic/transcendentals (via libm-style helpers); golden vector tests.
- 5.3 [GLM-5.3] `--x87-80` design: softfloat extended core API, CW precision/rounding, SW exception flags, DBT helper-call ABI.
- 5.4 [GLM-5.3-Flash] `x87_80.c` softfloat ops (add/sub/mul/div/sqrt/compare/convert/round, fprem/fscale/fxtract, transcendentals via extended-precision routines), wire flag parsing (`--x87-80`, `I686RT_X87=80`).
- RC5 [GLM-5.3]. **Accept:** `test_p5_fpu_sse` matches `tests/golden/p5.txt` (default mode, x87-exact cases excluded) **and** with `--x87-80` matches `tests/golden/p5_x87_80.txt` including exact cases (one check: script runs both modes, single PASS line).

### Phase 6 — hl integration (separate hl PR; depends on a32 integration in hl)
- 6.1 [GLM-5.3] hl: translator table generalising `a32_prepare/a32_finalize`; `elf_probe_file` EM_386; execve branch; flake input `i686rt`; `/dev/a32host` shared.
- 6.2 [GLM-5.3-Flash] `make test-pN-hl` targets.
- RC6 [GLM-5.3]. **Accept:** on macOS Apple Silicon `hl ./busybox-i686 sh -c 'echo ok'` → `ok` (offset mode G=4 GiB).

### Phase 7 — Wine-style LDT (gated on E09)
- 7.1 [GLM-5.3] Descriptor model (`seg.c`): LDT/GDT lookup, segment-state key in DBT block cache, 16/32-bit default size switching, far `jmp/call/ret/retf/iret` and `lcall` through code descriptors, limit/type checks → SIGSEGV with correct `trapno/err`; sigcontext segment regs saved/restored.
- 7.2 [GLM-5.3-Flash] `ldt.c`: `modify_ldt` funcs 0 (read), 1/0x11 (write, `user_desc` flags: seg_32bit, contents, read_exec_only, limit_in_pages, seg_not_present, useable), 2 (read_default); 16-bit operand/addressing handlers in the interpreter; fixtures `tests/test_p7_ldt.c` (install LDT data + 16-bit code descriptors, load `%fs`/`%es` from LDT, far call into 16-bit code and back, fault on limit).
- RC7 [GLM-5.3]. **Accept:** `test_p7_ldt` prints PASS under lima (interp for non-flat segments).
- 7.3 [GLM-5.3-Flash] Wine32 smoke: Debian i386 wine (non-wow64) sysroot via setup script. [GLM-5.3] triages failures into ≤5 tasks.
- RC7b [GLM-5.3]. **Accept:** `wine cmd /c echo ok` → `ok` under lima.

### Phase 8 — vm86 (gated on E10)
- 8.1 [GLM-5.3] v86 execution model: `vm86plus_struct`/`vm86_struct` state, real-mode linear addressing (seg<<4 + off, 20-bit wrap / A20 off), interpreter-only v86 path (`v86.c`), exit conditions (`VM86_SIGNAL`, `VM86_UNKNOWN`, `VM86_INTx`, `VM86_STI`, `VM86_PICRETURN`, `VM86_TRAP`), `int_revectored`/`int21_revectored` bitmaps, VIF/VIP virtual interrupt flag, return to 32-bit context.
- 8.2 [GLM-5.3-Flash] `vm86.c` syscalls `vm86old(113)`, `vm86(166)` (VM86_ENTER, VM86_ENTER_NO_BYPASS, VM86_PLUS_INSTALL_CHECK, VM86_FREE_IRQ/REQUEST_IRQ → -EINVAL/ENOSYS stub), struct marshalling, 16-bit real-mode handlers reused from Phase 7; fixture `tests/test_p8_vm86.c` (run real-mode code at 0x7c00, `int 0x10` revectored → returns VM86_INTx(0x10), check regs).
- RC8 [GLM-5.3]. **Accept:** `test_p8_vm86` prints PASS under lima.

### Phase H — Hardening (only after Phase 8)
- H1 [GLM-5.3] SMC protection D11 + self-modifying fixture.  **Accept:** SMC fixture PASS.
- H2 [GLM-5.3-Flash] musl libc-test + LTP subset runners; triage list. **Accept:** pass-rate report committed; GLM-5.3 sets thresholds.
- H3 [GLM-5.3] Performance: dead-flag elimination across blocks, block linking stats, CoreMark. **Accept:** CoreMark score recorded vs interp and qemu-i386.
- H4 [GLM-5.3] x86_64-host interpreter build (D3 tier 2, per E02). (rt32 extraction is out of scope, see D13.) **Accept:** `nix build .#i686rt-x86_64` runs hello on an x86_64 kernel with `ia32_emulation=0`.
- H5 [GLM-5.3-Flash] AOT cache port from `aot.c` (optional).
- H6 [GLM-5.3] DBT for non-flat/16-bit segments (keyed by segment state) if Phase 7 profiling shows need. **Accept:** `test_p7_ldt` PASS under `I686RT_ENGINE=dbt`.

---

### 4.C Concurrency plan
GLM-5.3 = single coordinator: owns the DAG, freezes interfaces (headers, struct layouts, signatures, file ownership) before every fan-out, writes one task card per lane, batch-reviews, merges locally, handles escalations; no grunt work. GLM-5.3-Flash lanes run in parallel, one git worktree/branch each (`lane/<phase>-<lane>`), exclusive file ownership, one acceptance check per card. Escalate after 2 failed check attempts, on any interface change, or on spec ambiguity. **S** = sync point (GLM-5.3 batch review + merge + phase check once). Never push.

| Phase | Freeze first (GLM-5.3) | Parallel Flash lanes | Sync |
|---|---|---|---|
| E | experiment card template, FINDINGS.md format | E01 … E10 (10 lanes, independent) | S-E: RC-E review, SPEC.md patched |
| 0 | `src/i686rt.h` (`i686_ctx_t` offsets), module/file ownership map | L0a copy a32rt → `src/rt32/` · L0b flake.nix · L0c Makefile skeleton + vendored `a32host.h` | S0: RC0 |
| 1 | `x86_insn_t`, decoder API, interp handler signature, syscall-table format | L1a `gen_insn_tab.py`+`insn_tab.h` · L1b ALU handlers · L1c MOV/stack/string · L1d branch/CMOV/SETcc/BT · L1e MUL/DIV/shifts · L1f `gen_syscall_tab.py` · L1g fixtures | S1: RC1 (after GLM-5.3 decoder core lands) |
| 2 | `structs_i386.h` index (names + sizes), marshal helper API, vDSO symbol list (from E07) | L2a stat/statfs/dirent · L2b socketcall+msghdr/cmsg · L2c ipc · L2d time32/time64 · L2e epoll/flock/rlimit/sysinfo · L2f passthrough fill · L2g vDSO blob · L2h /proc + auxv | S2: RC2 |
| 3 | jitcore adaptation, emitter helper API, reg map, lazy-flags ABI | L3a ALU emit · L3b MOV/LEA/stack emit · L3c branch/string emit · L3d differential harness | S3: RC3 |
| 4 | clone/TLS + TSO contracts, sigframe structs (from E05/E08) | L4a threads/signals fixtures · L4b sysroot setup · L4c LOCK→LSE emitters | S4: RC4 |
| 5 | x87 state layout, SSE reg file, `--x87-80` helper-call ABI | L5a SSE/SSE2 emit · L5b SSE interp · L5c x87 64-bit · L5d `x87_80.c` softfloat · L5e golden vectors (both modes) | S5: RC5 |
| 6 | hl translator-table contract (from E03) | L6a hl `elf_probe_file`/dispatch (local branch only) · L6b `test-pN-hl` targets | S6: RC6 |
| 7 ∥ 8 | descriptor model + 16-bit decoder mode (shared, frozen once, from E09/E10) | L7a `ldt.c` · L7b 16-bit interp handlers · L7c LDT fixtures · L7d Wine sysroot ∥ L8a `vm86.c` syscalls/marshalling · L8b `v86.c` addressing/exits · L8c vm86 fixtures | S7: RC7/RC7b; S8: RC8 |
| H | per-task cards | H1 SMC · H2 suite runners · H3 perf · H4 x86_64 build · H5 AOT · H6 segmented DBT (independent lanes) | S-H: each H check once |

Cross-phase overlap allowed only where no dependency exists: fixtures/golden vectors for phase N+1 may start during phase N; Phases 7 and 8 run concurrently after the shared descriptor/16-bit freeze; Phase 6 waits on the hl a32 integration branch (§6).

## 5. Open design questions (after rev 2)
Resolved by decision: x87 default (64-bit + `--x87-80`, D9); LDT/vm86 scope (in, Phases 7–8); rt32 extraction (deferred beyond this plan, D13).
To be answered by Phase E (then closed or turned into decisions by RC-E):
1. HW TSO via HVF per vCPU → `A32H_CAP_HW_TSO`? (E01)
2. x86_64 tier-2 host: interpreter-only vs native compat-CS execution (E02).
3. hl dispatch for EM_386 — any RosettaLinux fallback viable? (E03; expected no)
4. Guest top-of-window value (E04); FPU frame layout (E05); glibc vDSO/SYSINFO contract (E07); TSO policy vs FEX/Box86 (E08); Wine LDT surface (E09); vm86 placement in the window under hl offset mode (E10).
Still open (not experiment-shaped):
5. hl: rename shared device to neutral `/dev/rt32host` before hl ships `/dev/a32host`?
6. DBT support for non-flat/16-bit segments (H6) — needed or interpreter enough?
7. vm86 IRQ passing (`VM86_REQUEST_IRQ`): stub vs emulate — depends on real users (dosemu1) found in E10.

## 6. Unverified items (each mapped to an experiment)
- hl a32rt integration (flake input, `src/a32.c`, `/dev/a32host`) not on public hl master `8048a96`; A32RT.md cites hl `d76cd75`, absent upstream. (Not an experiment: ask Moritz for the branch; Phase 6 blocked on it.)
- RosettaLinux on ELFCLASS32 → E03. i386 TASK_SIZE → E04. `_fpstate` magic → E05. nixpkgs i686 cross attrs → E06. glibc SYSINFO offset + vDSO versions → E07. FEX/Box86 TSO policies → E08. Apple HW TSO under HVF → E01. ia32_emulation=0 compat CS → E02. Wine LDT usage → E09. vm86 feasibility → E10.
