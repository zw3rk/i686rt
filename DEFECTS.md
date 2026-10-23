# Defects

Reviewed `master` `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82` (`Phase 3: record audit D3 fix`). `c3be9e83504706551d0a31a0ab066a3821d5a4b5` is an ancestor. Entries that cite an ancestor were read at that commit.
D1–D3 cite `f1e6610566384ce81b582f0a4ef117a80f7f1b19`, where that wording is still visible. The D1 and D2 comments were corrected in `3febc37d`. Commit `14e3e7c6` changed the D3 GE mask; see D3 and D29.
Further entries are appended only after a second read agrees. This file is not a claim that the rest of the tree is clean.
Each entry below was checked by a second read that was given the location and a question, not the first conclusion.

## D1. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `f1e6610566384ce81b582f0a4ef117a80f7f1b19`
- Path: `tests/unit/test_l4c.c`
- Lines: 12–14
- Symbol: file header

The header said a natively emitted LOCK is shown by the first block exit being `UNDEF` with `arg == 1` (only the 1-byte HLT declined).
`run_case` does the opposite check: `fr == I686_EXIT_HLT && fa == 0 && fd == CASE_EIP + clen + 1` (`tests/unit/test_l4c.c` around line 299).
The comment immediately above that check already says the stream exits `HLT` at the post-HLT EIP, and that a declined LOCK would be `UNDEF` with the LOCK's own length.
The header now matches that check. No check was changed.
Second read: `blind/blind-read-i686-unit-tests.md`.

## D2. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `f1e6610566384ce81b582f0a4ef117a80f7f1b19`
- Path: `tests/unit/test_l3c.c`
- Line: 515
- Symbol: SETcc sample in `main`

The comment said the SETcc sample covers E, GE, and A in both directions.
For condition 13 (GE), `setcc_t[1]` is `0` and `setcc_f[1]` is `I686_EF_SF | I686_EF_OF`.
`src/interp/flags.c` case `0xd` sets the condition when SF and OF are equal. Both flags set is the taken polarity, the same as neither flag set.
The Jcc row for GE in this file uses `ef_false = I686_EF_SF` only, which is the not-taken polarity, and that row is checked with `want_f == 0`. The SETcc loop has no such check.
Commit `3febc37d` changed that comment so it said GE's f mask is also taken. The flag masks were not changed in that commit. See D3. Commit `14e3e7c6` later changed the GE f mask to SF only, and D29 updates the comment to match that mask.
Second read: `blind/blind-read-i686-unit-tests.md`, plus `src/interp/flags.c:174`.

## D3. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `f1e6610566384ce81b582f0a4ef117a80f7f1b19`
- Path: `tests/unit/test_l3c.c`
- Line: 522
- Symbol: `setcc_f` for condition 13

At `f1e6610566384ce81b582f0a4ef117a80f7f1b19` and at ancestor `c3be9e83504706551d0a31a0ab066a3821d5a4b5`, `setcc_f[1]` is `I686_EF_SF | I686_EF_OF`, and the case is named `setcc_cc13_f`.
GE (`i686_flags_cc` case `0xd`) is true when SF equals OF, so that mask does not make SETGE write AL=0.
A translator that sets AL=1 for every SETGE still passes `setcc_cc13_f` at those commits. The not-taken GE case there is only in the Jcc table (`ef_false = I686_EF_SF`).
Commit `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82` changed `setcc_f[1]` to `I686_EF_SF`. That commit is the user's audit fix. This entry does not revert it. The comment above the array still said the f mask was `SF|OF` after that commit; D29 corrects the comment only.
Second read: `blind/blind-read-i686-unit-tests.md`, plus `src/interp/flags.c:174`. The current mask was re-read at `14e3e7c6` in `tests/unit/test_l3c.c`.

The D1 and D2 comment corrections are in commit `3febc37d`, which is an ancestor of current `master` `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`. The false text is still the text at `f1e6610566384ce81b582f0a4ef117a80f7f1b19`. Those two hunks are not in the working-tree diff.

## D4. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/dbt/emit.h`
- Lines: 55–57
- Symbol: `i686_emit_ea`

The declaration comment said the function computes `xG + ea` into `x21` and clobbers `x21..x23`.
`i686_emit_ea` in `src/dbt/emit_exit.c` writes the 32-bit guest offset `disp + base + (index << scale)` into `w21`, wraps it with `UXTW`, and adds a segment base in `w21` only when `add_seg` is set. It writes `w22` for that base. It does not mention `x20`, `xG`, or `x23`.
The file header of `emit_exit.c` already says the result is a 32-bit guest offset in `w21` and that callers use `[x20, w21, uxtw]`. Clobbers are `w21..w22`.
The declaration comment now says that. The function was not changed.
Second read: `blind/blind-read-i686-emit-ea-and-tso.md`.

## D5. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/dbt/emit_alu.c`
- Line: 122
- Symbol: `emit_guest_load`

The comment on the `e->tso` arm said `tso is only enabled post-clone`.
`i686_emit_begin` `memset`s the context and then sets `buf`, `ctx`, `guest_eip`, and `block_open`. It does not assign `e->tso`. No other `.c` or `.h` file assigns that field, so the LDAR arm is not emitted.
The comment now says the flag stays false. The branch and the encodings were not changed.
Second read: `blind/blind-read-i686-emit-ea-and-tso.md`.

## D6. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/dbt/emit_atomic.c`
- Lines: 78–79
- Symbol: file header

The header said the LSE AL variants are correct in both plain single-threaded and post-clone TSO modes.
Nothing in the translator sets `e->tso` after `i686_emit_begin`, so there is no post-clone TSO mode in this tree. The AL encodings do not read `e->tso`.
The sentence now says the flag is left false and is not read here. No encoding was changed.
Second read: `blind/blind-read-i686-emit-ea-and-tso.md`.

## D7. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/interp/sse.h`
- Lines: 9–11
- Symbol: file header

The header said MXCSR rounding control is bits 14–15 and, in the next sentence, that FTZ is bit 15. Those ranges both claim bit 15. No `.c` file shifts `ctx->mxcsr`. x87's own header in `src/interp/x87.h` puts the x87 RC field in bits 10–11, which is a different register. MXCSR's RC field is bits 13–14, so it does not overlap FTZ at bit 15, and those two bits still move to FPCR bits 22–23 with the same encoding.
The comment now says `RC(13-14)`. No code was added.
Second read: `blind/blind-read-sse-mxcsr.md`.

## D8. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/interp/x87_80.h`
- Line: 4
- Symbol: copyright

The copyright line said `moritz@zw3erk.com`. The sibling header `src/interp/x87.h` and the other sources use `moritz@zw3rk.com`.
The address is corrected. No code was changed.
Second read: `blind/blind-read-sse-mxcsr.md`.

## D9. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/x86/insn_tab.h`
- Lines: 43–47 (before the comment edit)
- Symbol: one-byte table preamble

The preamble said `69/6B` are left `INVALID` because `IMUL Gv,Ev,Iz/Ib` has no contract id.
The enum defines `I686_OP_IMUL_GvEvIz` and `I686_OP_IMUL_GvEvIb`, and the `0x69` and `0x6B` rows map to those ops.
The preamble now says those rows are mapped. The rows were not changed.
Second read: `blind/blind-read-i686-decode-facts.md`.

## D10. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/x86/insn_tab.h`
- Lines: 377 and 378
- Symbol: opcodes `0xD4` and `0xD5`

The `0xD4` row was labeled `DAA`. `DAA` is `0x27`, which already says `DAA`. `0xD4` is `AAM`.
The `0xD5` row was labeled `AAA`. `AAA` is `0x37`. `0xD5` is `AAD`.
Both rows stay `I686_OP_INVALID`. Only the names in the comments changed.
Second read: `blind/blind-read-i686-decode-facts.md`.

## D11. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/x86/insn_tab.h`
- Lines: 131 and 488–503
- Symbol: `I686_OP_CMOVcc_Gv` rows

The enum note and every `0F 40–4F` row said the CMOVcc condition is carried in `modrm_reg`.
`x86_decode` stores that nibble in `imm` (`src/x86/decode.c`, `I686_OP_CMOVcc_Gv` arm) and leaves `modrm_reg` as the destination.
Jcc and SETcc do use `modrm_reg`. Those comments were left as they were.
The CMOVcc comments now say `imm`. The decoder was not changed.
Second read: `blind/blind-read-i686-decode-facts.md`.

## D12. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/x86/insn_tab.h`
- Lines: 31–34 and the `0x98` row
- Symbol: `I686_OP_CWDE` / `I686_OP_CBW`

The preamble and the `0x98` row said the decoder rewrites `CWDE` to `I686_OP_CBW` when `66` is present.
`I686_OP_CBW` is only the enum name. `x86_decode` never assigns it. `66` sets `pfx_opsize` and leaves the id as `I686_OP_CWDE`.
The comments now say that. The decoder was not changed.
Second read: `blind/blind-read-i686-decode-facts.md`.

## D13. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/x86/decode.c`
- Lines: 364–374
- Symbol: moffs `A0–A3`

The displacement width is `out->pfx_opsize ? 2U : 4U`.
`A0–A3` take an address-size offset: `67` selects 16 bits, and `66` does not. `A0`/`A2` move a byte, so an operand-size prefix must not shorten the offset.
A `66` prefix consumes two offset bytes and leaves the rest of the instruction in the stream. A `67` prefix consumes four.
The width expression was not changed.
Second read: `blind/blind-read-i686-decode-facts.md`.

## D14. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `src/x86/decode.c`
- Lines: 71–85
- Symbol: `ea_default_seg`

SS is chosen only when `modrm_mod != 0`.
32-bit `[esp]` is `mod==0`, `rm==4`, SIB base 4, and `ea_base` is `I686_REG_ESP` (`decode.c` around line 199). That form gets DS.
16-bit `mod==0`, `rm==2` or `rm==3` (`[bp+si]`, `[bp+di]`) sets `ea_base` to `I686_REG_EBP` (`base16` at line 217) and also gets DS.
When `SS` and `DS` bases differ, `x86_ea_compute` adds the wrong base.
The function was not changed.
Second read: `blind/blind-read-i686-decode-facts.md`. The `ea_base` assignments were re-read with that note.

## D15. comment

- Repo: `i686rt`
- Ref: `lane/5-l5e`
- Commit: `927e696bd25efba4a5620912dbe74ecb7538c75c`
- Path: `tests/test_p5_fpu_sse.c`
- Line: 211
- Symbol: `g_cw_ch`

The comment says `PC=53-bit, RC=chop` for `0x0C7F`.
`src/interp/x87.h` says PC is bits 8–9 (`0` = 24-bit, `2` = 53-bit) and RC is bits 10–11 (`3` = trunc).
`0x0C7F` has bits 10 and 11 set and bits 8 and 9 clear, so PC is 24-bit and RC is chop.
The 53-bit nearest word in the same file is `g_cw_d = 0x027F`, which sets bit 9.
This file is only on `lane/5-l5e`. It was not edited.
Second read: `blind/blind-read-x87-chop.md`.

## D16. other

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `SPEC.md`
- Line: 66
- Symbol: decision D7

D7 says `EAX..EDI` are fixed in `x19..x26`.
`src/dbt/emit.h` and `src/trampoline.S` keep those GPRs in `w0..w7`, with `x19` as the context pointer and `x20` as the guest base.
`SPEC.md` was not edited.
Second read: `blind/blind-read-i686-docs-vs-code.md`.

## D17. other

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `AGENTS.md`
- Lines: 52–53
- Symbol: TSO invariant

The invariant says plain loads and stores while single-threaded, then re-translate after `clone(CLONE_VM)`.
`SPEC.md` D5 and `src/os/threads.h` say static GPR TSO from the first block and no clone re-translation.
`i686_emit_begin` memsets the emit context and never sets `e->tso`, so the ordered-load arm stays off. See D5.
`AGENTS.md` was not edited.
Second read: `blind/blind-read-i686-docs-vs-code.md`.

## D18. other

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `docs/lanes/phase-2.md`
- Lines: 115–119
- Symbol: L2g vDSO bodies

The card says the vDSO time helpers are `mov $NR, %eax; int $0x80; ret` with arguments already in the syscall registers.
`src/os/vdso32/vdso32.S` loads arg1 from `4(%esp)` into `%ebx` and, for the two-argument helpers, arg2 from `8(%esp)` into `%ecx` before `int $0x80`.
The lane card was not edited.
Second read: `blind/blind-read-i686-docs-vs-code.md`.

## D19. other

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `SPEC.md`
- Line: 109
- Symbol: `FP_X_STATE_MAGIC1`

The line spells the xstate magic `FP_X_STATE_MAGIC1`.
`experiments/E05-fpstate/sources/uapi-sigcontext.h` and `src/os/sigframe_i386.h` spell it `FP_XSTATE_MAGIC1`. The value `0x46505853` matches.
`SPEC.md` line 140 already uses the header spelling. Line 109 was not edited.
Second read: `blind/blind-read-i686-docs-vs-code.md`.

## D20. other

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `experiments/E08-fex-box86-tso/FINDINGS.md`
- Line: 52
- Symbol: box86 LOCK citation

Line 52 says box86 uses `LDREX/STLXR`.
Line 22 of the same file cites `LDREX/STREX` loops in `src/dynarec/dynarec_arm_f0.c`. `STLXR` is the A64 mnemonic used in the box64 cell.
The findings file was not edited.
Second read: `blind/blind-read-i686-docs-vs-code.md`.

## D21. other

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `experiments/E06-nixpkgs-attrs/FINDINGS.md`
- Line: 90
- Symbol: docker linux/386 row

The table calls that run `i686 (real ia32 kernel mode)`.
The same file says the container is Docker Desktop's Linux VM via QEMU TCG, about 18× a native arm64 run, and that `uname -m` prints `i686`.
The findings file was not edited.
Second read: `blind/blind-read-i686-docs-vs-code.md`.

## D22. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `c3be9e83504706551d0a31a0ab066a3821d5a4b5`
- Path: `tests/unit/test_l1c.c`
- Lines: 91–97
- Symbol: `x86_reg_read` stand-in

This stand-in treats `width == 1` as a byte and `width == 2` as a word, and any other width as the full register.
`src/interp/h_mov.c` passes `8U` into `x86_reg_read` and comments that width is in bits (`8/16/32`). `tests/unit/test_l1d.c` compares `width == 8` and `width == 16`.
A bit-width call into this stand-in takes the full-register arm. Byte and word results in this file do not match the accessor the interpreter calls.
The comparisons were not changed.
Second read: `blind/blind-read-vfp-and-l1c-comments.md`.

## D23. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_pass.c`
- Lines: 69–71
- Symbol: file-header futex paragraph

The header said futex was a v1 stopgap: `FUTEX_WAKE` returns 0, `FUTEX_WAIT` returns `-EAGAIN` when `*uaddr != val` and otherwise 0, never blocks, and other ops return `-ENOSYS`.
`sys_futex` calls `syscall(SYS_futex, ...)` (`src/os/sys_pass.c` around line 1076). `FUTEX_WAIT` can block in that host call. The return is the host result, or `-errno`, with `EWOULDBLOCK` mapped to `-EAGAIN`.
The header now describes that call. The syscall was not changed.
Second read: `blind/quote-i686-futex-exec.md`.

## D24. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_pass.c`
- Lines: 1055–1056
- Symbol: `sys_futex` timeout comment

The comment said the timeout is "arg5 on i386: a guest timespec*".
The next use is `timeout_va = ctx->gpr[I686_REG_EBP]`. On i386, syscall arguments are `ebx, ecx, edx, esi, edi, ebp`. `futex(uaddr, op, val, timeout, uaddr2, val3)` puts the timespec in arg4 (`esi`) and `val3` in arg6 (`ebp`).
The comment now says the pointer is read from `EBP`. The register read was not changed. See D25.
Second read: `blind/quote-i686-futex-exec.md`.

## D25. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_pass.c`
- Line: 1066
- Symbol: `sys_futex`

`sys_futex` takes `uaddr`, `op`, and `val` from its parameters and, for `FUTEX_WAIT`, loads the timeout guest pointer from `ctx->gpr[I686_REG_EBP]`.
i386 arg4 is `esi`. That is the `timeout` pointer. `ebp` is arg6, `val3`. A guest `FUTEX_WAIT` with a non-NULL timespec in `esi` and `ebp == 0` waits forever. A non-zero `ebp` is treated as a timespec pointer.
The `EBP` read was not changed.
Second read: `blind/quote-i686-futex-exec.md`.

## D26. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/syscalls.c`
- Line: 490
- Symbol: `r_execve`

`r_execve` declares `char path[4096]` and later does `ctx->exec_path = path`.
`rt32_stack_setup` reads `ctx->exec_path` before `r_execve` returns (`src/rt32/rt32_stack32.c` line 102), so the auxv string is copied while the array is live.
`proc` "exe" reads `ctx->exec_path` on a later call (`src/os/proc.c` lines 282–290) and passes it to `open`. After `r_execve` returns, that pointer addresses the dead stack array.
The initial process load in `main` sets `ctx.exec_path = argv[path_idx]` (line 282), which is not this stack array. The assignment in `r_execve` was not changed.
Second read: `blind/quote-i686-futex-exec.md`.

## D27. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_pass.c`
- Lines: 1258–1279 and 1511–1514
- Symbol: `r_fchmodat`, `r_faccessat`

`NR_fchmodat` is 306 and `NR_faccessat` is 307. Both handlers pass `ctx->gpr[I686_REG_ESI]` as the flags argument of `sys_fchmodat` / `sys_faccessat`, which forward it to the host `fchmodat` / `faccessat`.
i386 syscall 306 `fchmodat` and 307 `faccessat` take three arguments (`dirfd`, `path`, `mode`). The flagged forms are `fchmodat2` (i386 452) and `faccessat2` (i386 439). Go's linux/386 wrappers call `SYS_FCHMODAT` and `SYS_FACCESSAT` with three registers; musl added `__NR_fchmodat2` because the older `fchmodat` syscall has no flags argument (Linux commit `09da082b07bb`, "fs: Add fchmodat2()").
A guest that leaves a non-zero `esi` makes the host reject the call, or honor `AT_*` bits the i386 syscall does not have. `esi` is still passed. The handlers were not changed.
Second read: `blind/quote-i686-futex-exec.md`.

## D28. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/main.c`
- Lines: 108–110 and 135–139
- Symbol: `--x87-64`, `apply_env`

`--x87-64` sets `ctx->x87_80 = false`. `--x87-80` sets `ctx->x87_80 = true`.
`apply_env` applies `I686RT_X87` only when `!ctx->x87_80`. After `--x87-64`, the field is false, so the environment variable still assigns `ctx->x87_80`. After `--x87-80`, the field is true and the environment variable is ignored.
`--x87-64` does not stick when `I686RT_X87` requests 80-bit. The flag and the environment check were not changed.
Second read: `blind/quote-i686-futex-exec.md`.

## D29. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `tests/unit/test_l3c.c`
- Lines: 515–517
- Symbol: SETcc sample comment

After commit `14e3e7c6`, `setcc_f[1]` is `I686_EF_SF`. The comment above that array still said "GE's f mask is SF|OF; GE is SF==OF, so that mask is taken too."
`i686_flags_cc` case `0xd` is true when SF equals OF. SF set and OF clear is the not-taken polarity, so the SF-only mask is a not-taken sample, not a taken one.
The comment now says the GE not-taken mask is SF only. The mask was not changed.
Second read: `blind/quote-i686-setcc-ge.md` quotes the `14e3e7c6` blob comment "GE's f mask is SF|OF" against `setcc_f[1] = I686_EF_SF`, and `flags.c` case `0xd` (`SF == OF`). The working-tree arrays match the blob. See D3.

## D30. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_pass.c`
- Lines: 1034–1035
- Symbol: `sys_set_tid_address`

The comment said the kernel returns the previous `clear_child_tid`, and that the first call returns 0.
The function returns `prev`, the previous `ctx->clear_child_tid`, after storing `tidptr_va`. Linux man-pages 6.19 `set_tid_address(2)` says `set_tid_address()` always returns the caller's thread ID. The comment attributed the kernel's return value to this previous-pointer behavior.
The comment now says the handler returns the previous stored pointer and that Linux returns the caller's thread id. The return was not changed. See D31.
Second read: `blind/quote-i686-futex-exec.md`. Man page: https://man7.org/linux/man-pages/man2/set_tid_address.2.html (man-pages 6.19, RETURN VALUE).

## D31. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_pass.c`
- Lines: 1032–1038
- Symbol: `sys_set_tid_address`

`sys_set_tid_address` stores `tidptr_va` into `ctx->clear_child_tid` and returns the previous pointer as `long`. `r_set_tid_address` passes only `ctx->gpr[I686_REG_EBX]` (i386 arg1). Number 258 is registered to that handler.
Linux `set_tid_address(2)` (man-pages 6.19) says the call always returns the caller's thread ID. A guest that branches on the return value as a tid observes 0 on the first call and a guest pointer afterwards.
The return expression was not changed.
Second read: `blind/quote-i686-futex-exec.md`, plus the man page RETURN VALUE sentence quoted above.

## D32. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sigframe_i386.h`
- Line: 25
- Symbol: `i686_sigcontext_t.edi`

The field comment said `edi` is at `0x1c`. The four packed segment pairs occupy bytes `0x00..0x0f`, so `edi` is at `0x10`. `esp` is the field at `0x1c`. `fpstate` at `0x4c` matches the same layout, and `sizeof` is asserted 88.
The comment now says `0x10`. The field order was not changed.
Second read: `blind/quote-i686-sigframe.md`.

## D33. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sigframe_i386.h`
- Line: 61
- Symbol: `i686_fpstate_32_t.xmm_space`

The comment said `xmm_space` runs "to 0x188". Counting the packed fields before it puts the array at `0x90`. Thirty-two `uint32_t`s are 128 bytes, so it ends at `0x110`.
The comment now says that. The array was not moved.
Second read: `blind/quote-i686-sigframe.md`.

## D34. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/signals_i386.c`
- Line: 78
- Symbol: `i686_sigframe_build`

`st_space` is `uint32_t[20]` (80 bytes). `ctx->x87_st` is `uint8_t[8][16]` (128 bytes). The builder does `memcpy(&fp.st_space, ctx->x87_st, sizeof(ctx->x87_st))` after `fp.mxcsr = ctx->mxcsr`.
The copy runs 48 bytes past `st_space`, through `__pad0`, the FXSAVE header, and `mxcsr` / `mxcsr_mask`, and 12 bytes into `xmm_space`. The `mxcsr` store on the previous line is overwritten.
The memcpy was not changed.
Second read: `blind/quote-i686-sigframe.md`.

## D35. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sigframe_i386.h`
- Lines: 98–99
- Symbol: `i686_sigframe_build`

The declaration comment said the function returns the new guest ESP.
The function returns `0` on success and `-1` for `SIG_DFL` / `SIG_IGN`. `i686_deliver_sync` returns that value and documents it as 0 or -1. The new ESP is `ctx->gpr[I686_REG_ESP] = frame_va`.
The comment now says that. The returns were not changed.
Second read: `blind/quote-i686-sigframe.md`.

## D36. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/signals_i386.c`
- Line: 84
- Symbol: `i686_sigframe_build`

The comment said `sp &= ~0xF` makes the handler ESP 16-aligned.
`push_bytes` subtracts the length, and it runs after that mask. `_Static_assert(sizeof(i686_rt_sigframe_t) == 268)`. `268 % 16` is 12, so the rt handler ESP is 4 mod 16. The non-rt frame is 112 bytes and stays 16-aligned.
The comment now says the rt frame leaves ESP 4 mod 16. The mask was not changed. See D37.
Second read: `blind/quote-i686-sigframe.md` for the old comment, and `blind/_raw/quote-i686-rest.md` for `push_bytes` (`*sp -= (uint32_t)n`) and `_Static_assert(sizeof(i686_rt_sigframe_t) == 268)`.

## D37. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/signals_i386.c`
- Lines: 84–91
- Symbol: `i686_sigframe_build`

The rt path aligns `sp` down to 16 and then pushes `sizeof(i686_rt_sigframe_t)` (268) bytes. The handler ESP is that pointer (`ctx->gpr[I686_REG_ESP] = frame_va`). It is 4 mod 16, not 0 mod 16 and not the i386 ABI's 12 mod 16.
The align and the push were not changed.
Second read: `blind/_raw/quote-i686-rest.md` quotes `push_bytes`, the 268-byte assert, `frame_va = push_bytes(..., sizeof(rt))`, and `ctx->gpr[I686_REG_ESP] = frame_va`.

## D38. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/clone.c`
- Lines: 7–8
- Symbol: file header

The header said `CLONE_THREAD` without `CLONE_VM` returns `-EINVAL`.
`r_clone` forks when `CLONE_VM` is clear, including `CLONE_THREAD` without `CLONE_VM`. It returns `-EINVAL` only for `CLONE_VM` without `CLONE_THREAD`.
The header now says that. The flag tests were not changed.
Second read: `blind/quote-i686-sigframe.md`.

## D39. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/clone.c`
- Lines: 98–112
- Symbol: `i686_tls_install`

The auto-alloc arm runs when `entry_number` is `0xFFFFFFFF` or `entry_number > 2`. The else arm computes `slot = entry_number - 6` and returns `-EINVAL` unless that slot is in `0..2`.
Every `entry_number <= 2` therefore returns `-EINVAL`. Every explicit TLS index `6`, `7`, or `8` is greater than 2, so it takes the auto-alloc arm, picks a free slot, and overwrites `entry_number`. A later `CLONE_SETTLS` that passes the index just written (6, 7, or 8) allocates again.
The test was not changed.
Second read: `blind/quote-i686-sigframe.md`.

## D40. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_time.c`
- Line: 595
- Symbol: `sys_settimeofday`

The comment said the aarch64 timezone layout is identical to the guest's.
The buffer beside that comment is `long htz[2]`. On aarch64 `long` is 8 bytes, so the buffer is 16 bytes. `i686_timezone_t` is asserted 8 bytes. The comment now says the kernel reads `htz[0]` only. The array was not changed. See D41.
Second read: `blind/quote-i686-syscalls.md`.

## D41. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_time.c`
- Lines: 597–611
- Symbol: `sys_settimeofday`

`htz[0]` holds `tz_minuteswest` and `htz[1]` holds `tz_dsttime`, each in a host `long`. `SYS_settimeofday` is passed `&htz`. Linux `struct timezone` is two `int`s (8 bytes). On little-endian aarch64 the first 8 bytes are only `htz[0]`, so `tz_dsttime` is not in the bytes the kernel copies.
The array was not changed. `sys_gettimeofday` uses `i686_timezone_t`, which is 8 bytes.
Second read: `blind/quote-i686-syscalls.md`.

## D42. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_stat.c`
- Lines: 311–312
- Symbol: d_off cookie remap

The comment said the i386 ABI only has a 32-bit `d_off`.
`i686_linux_dirent64_t.d_off` is `int64_t` at offset 8, and the file header says getdents64's wire `d_off` is `s64`. The old `linux_dirent` `d_off` is the 32-bit field.
The comment now says getdents64 `d_off` is 64-bit and that this remap still folds large cookies. The remap was not changed. See D43.
Second read: `blind/quote-i686-syscalls.md`.

## D43. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_stat.c`
- Lines: 354–370
- Symbol: getdents64 cookie remap

The function comment says it rewrites `d_off` of every getdents64 record. Offsets at or above `L2A_DIR_COOKIE_BASE` (`0x70000000`) are stored back into the 64-bit field as a cookie in that 32-bit-sized space.
i386 getdents64 `d_off` is 64-bit. A host cookie at or above that base is not returned as itself.
The remap was not changed.
Second read: `blind/_raw/quote-i686-rest.md` quotes `map_dir_cookie` and `i686_dirent64_remap_offs`. `L2A_DIR_COOKIE_BASE` is `0x70000000ULL`.

## D47. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_misc.c`
- Lines: 471–493
- Symbol: `i686_oflags_h2g`

The comment above the helper says aarch64 `O_DIRECTORY` is `0x4000` and `O_DIRECT` is `0x10000` (the same split `sys_pass.c` records). `i686_oflags_h2g` masks with `I686_O_KNOWN`, then rewrites only `I686_HO_DIRECT_` (`0x10000`) and `I686_HO_NOFOLLOW_` (`0x8000`).
Host `O_DIRECTORY` (`0x4000`) is inside `I686_O_KNOWN` because guest `O_DIRECT` is `0x4000`. It is returned unchanged, so the guest sees `O_DIRECT`. `F_GETFL` returns `i686_oflags_h2g`.
The helper was not changed. `i686_open_flags_to_host` is a different function and does swap directory on the open path.
Second read: `blind/quote-i686-syscalls.md` quotes the helper. `blind/_raw/quote-i686-rest.md` quotes `I686_GO_DIRECT` `0x004000`, `I686_GO_DIRECTORY` `0x010000`, `I686_HO_DIRECT_` `0x10000`, `I686_HO_NOFOLLOW_` `0x8000`, and the S2 comment `O_DIRECTORY 0x10000 <-> 0x4000`.

## D48. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/rt32/rt32_stack32.c`
- Line: 132
- Symbol: `aux_args.phent`

The comment said `phent` is 56 because `sizeof(Elf32_Phdr)` is 56.
`elf32_phdr_t` is eight `uint32_t` fields (32 bytes). `load_elf32_image` rejects `e_phentsize != sizeof(elf32_phdr_t)`. Elf64 program headers are 56 bytes.
The comment now says 32. The assignment was not changed.
Second read: `blind/quote-i686-syscalls.md`.

## D49. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `tests/hello.c`
- Lines: 4–5
- Symbol: file header

The header said the fixture writes `"hello\n"` and also that `edx` is 5.
`msg` is `static const char msg[6] = "hello\n"`. The write loads `edx` with 5, so the newline is not sent.
The header now says that. The immediate was not changed.
Second read: `blind/quote-i686-syscalls.md`.

## D50. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `tests/test_p1_isa.c`
- Lines: 18–19
- Symbol: file header

The header said AF after shifts is masked out of the comparisons.
`F_CC` is `F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF`. `f_shl` returns `f & F_CC`. `shl2_f` expects exactly `F_CF | F_OF`.
The header now says AF is still inside `F_CC`. The expected masks were not changed. See D51.
Second read: `blind/_raw/quote-i686-rest.md` quotes `#define F_CC (F_CF | F_PF | F_AF | F_ZF | F_SF | F_OF)`.

## D51. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `tests/test_p1_isa.c`
- Lines: 258–270 and 540
- Symbol: `f_shl`, `shl2_f`

`f_shl` returns the host flags masked by `F_CC`, which includes `F_AF`. `shl2_f` requires the result to equal `F_CF | F_OF`. AF after a shift is undefined. A host or translator that sets AF fails `shl2_f` even when CF and OF match.
The comparison was not changed.
Second read: `blind/_raw/quote-i686-rest.md` quotes `F_CC` including `F_AF` and `TEST("shl2_f", f, F_CF | F_OF)`.

## D52. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_pass.c`
- Lines: 1093–1104
- Symbol: `r_openat`

`guest_ptr_bad` returns true for a guest pointer below `0x1000`. `r_openat` loads the pathname with `i686_fetch_cstr`. That function takes `i686_guest_ptr(ctx, va + i)` and reads the byte. It does not call `guest_ptr_bad`.
A pathname in the unmapped low page is dereferenced instead of returning `-EFAULT`.
The load was not changed.
Second read: `blind/_raw/quote-i686-rest.md` quotes `i686_fetch_cstr` reading `*p` from `i686_guest_ptr` and `guest_ptr_bad` returning true for `va < 0x1000`.

D44, D45, and D46 were removed. Their kernel overflow and host-size claims were not in the first syscall quote. D45 stays out: `fixup_compat_flock` is not in Linux v6.12 `fs/locks.c`. See `blind/rejected-unquoted-kernel.md`.

## D53. correctness

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_stat.c`
- Lines: 209–218
- Symbol: `i686_statfs_from_host`

`f_blocks`, `f_bfree`, `f_bavail`, `f_files`, and `f_ffree` are assigned with a `uint32_t` cast. The comment on `f_blocks` says "32-bit compat truncation". There is no range check.
Linux v6.12 `put_compat_statfs` (`fs/statfs.c`) returns `-EOVERFLOW` when `f_blocks`, `f_bfree`, `f_bavail`, `f_bsize`, or `f_frsize` has bits above 32, and the same for `f_files` and `f_ffree` unless the value is `0xffffffffffffffff`. A host filesystem larger than 32 bits is stored as the low 32 bits.
The casts were not changed.
Second read: `blind/quote-i686-syscalls.md` quotes the casts. `blind/_raw/quote-kernel-compat.md` quotes `put_compat_statfs` from https://raw.githubusercontent.com/torvalds/linux/v6.12/fs/statfs.c.

## D54. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_ipc.c`
- Lines: 265–266 and 902
- Symbol: `i686_msginfo_t`

The comments said the packed local struct is layout-identical on i386 and aarch64.
Linux v6.12 `include/uapi/linux/msg.h` `struct msginfo` is 7 `int`s plus an `unsigned short`, and it has no packed attribute. The local type is `__attribute__((packed))`.
The comments now say the uapi struct is not packed. The struct and the `msgctl` call were not changed.
Second read: `blind/quote-i686-syscalls.md` quotes the packed typedef and the old comment. `blind/_raw/quote-kernel-compat.md` quotes the uapi struct.

## D55. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `tests/test_p4_glibc.c`
- Line: 51
- Symbol: `main`

The comment said `fork + wait4`. The call is `waitpid(p, &st, 0)`.
The comment now says `waitpid`. The call was not changed.
Second read: `blind/_raw/quote-i686-rest.md`.

## D56. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `tests/test_p4_threads_signals.c`
- Lines: 29–32 and 426–427
- Symbol: `fpe_handler`

Paragraph (2) and the `fpe_handler` comment said the SIGFPE path returns through `sigreturn`.
The SIGFPE setup assigns `sa.flags = SA_SIGINFO_ | SA_RESTORER_` and `sa.restorer = (u32)l4a_restore_rt`. `l4a_restore_rt` is `mov $173,%eax; int $0x80`. Paragraph (1a) names that stub `rt_sigreturn`. Paragraph (1b) reserves `sigreturn(119)` for the non-RT retcode.
The two SIGFPE comments now say `rt_sigreturn`. The restorer bytes and the handler body were not changed.
Second read: `blind/_raw/quote-rvrt-runtime-main-and-i686-fpe.md`.

D57–D61 were read on `lane/5-l5b` at `a2fe547253da4236e055ad1c838d0902ed1c6499`. D62–D73 were read on `lane/5-l5c` at `05a31200de5e8042ac47d8165f0d21ad0c13145e`. Both worktrees were clean. Neither worktree was edited. The same text is not on `master`.

## D57. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5b`
- Commit: `a2fe547253da4236e055ad1c838d0902ed1c6499`
- Path: `src/interp/h_sse.c`
- Lines: 642–650
- Symbol: `h_movups`

A memory `MOVSS` (`pfx_rep == 1`, 4 bytes) or `MOVSD` (`pfx_rep == 2`, 8 bytes) load fills `dst` with `sse_get_xmm` of the destination, then calls `sse_ld(ctx, insn, dst, size)`.
The register form next to it copies only `size` bytes and comments that the upper lanes stay. `sse_ld` (`h_sse.c` 569–572) `memcpy`s exactly `n` bytes and does not clear the tail.
Intel memory scalar loads zero the lanes above the scalar. This path leaves them equal to the old destination.
The register-form comment is right for `modrm_mod == 3` only. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5b.md`. The `sse_ld` body was re-read beside that note.

## D58. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5b`
- Commit: `a2fe547253da4236e055ad1c838d0902ed1c6499`
- Path: `src/interp/h_sse.c`
- Lines: 279–291
- Symbol: `sse_round_f64_to_f32`

The comment says a normal inexact value is moved one ulp only when host nearest rounded against the MXCSR rounding mode.
For every such value with `rc != 0`, toward-zero always sets `bump = -1` and executes `mag -= 1`. There is no test of which way nearest already rounded.
`1 + 2^-25` rounds to `1.0f` under nearest and under toward-zero. This arm sees `(double)f != d` and steps to the float one ulp below `1.0`.
The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5b.md`.

## D59. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5b`
- Commit: `a2fe547253da4236e055ad1c838d0902ed1c6499`
- Path: `src/interp/h_sse.c`
- Lines: 360–366 and 418–424
- Symbol: `sse_f32_op`, `sse_f64_op`

Both divide arms test `db == 0.0` before the infinity checks. A zero dividend returns the indefinite and sets `MXCSR_IE`. Every other dividend, including an infinity, sets `MXCSR_ZE` and returns a signed infinity.
Intel `#Z` for `DIVSS` / `DIVSD` is a finite non-zero dividend divided by zero. Infinity divided by zero is not `#Z`.
`0/0` does not also set `#Z`, because that arm returns first. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5b.md`.

## D60. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5b`
- Commit: `a2fe547253da4236e055ad1c838d0902ed1c6499`
- Path: `src/interp/h_sse.c`
- Lines: 473–475
- Symbol: `sse_cvtt_f2i`

The guard is `!(d >= -2147483648.0 && d < 2147483648.0)`. Values that fail it set `MXCSR_IE` and return `0x80000000`.
Truncation toward zero of a value in `(-2147483649, -2147483648)` is `-2147483648`, which fits in `int32_t`. Those inputs should return `INT_MIN` and set `MXCSR_PE` only.
`-2147483648.0` itself passes the comparison. `-2147483649.0` does not fit and is correctly invalid. The open interval between them is not. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5b.md`.

## D61. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5b`
- Commit: `a2fe547253da4236e055ad1c838d0902ed1c6499`
- Path: `src/interp/h_sse.c`
- Lines: 706–708 and 733–735
- Symbol: `h_movlps`, `h_movhps`

The load side of each handler treats `modrm_mod == 3` as `MOVHLPS` / `MOVLHPS`, or as `#UD` when the operand-size prefix is set.
The store side does not test `modrm_mod`. It always calls `sse_st`. Register encodings of the `MOVLPS` / `MOVHPS` store opcodes are `#UD`.
The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5b.md`.

## D62. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/x87.c`
- Lines: 408–424 and 445–471
- Symbol: `ext80_parts_to_i64`, `ext80_to_i64`

`ext80_to_i64` builds `eff` as `-16382` or `e - 16383`, then decrements it until significand bit 63 is set. A finite fraction has negative `eff`.
`ext80_parts_to_i64` returns early only when `eff >= 63`. Otherwise `drop = (unsigned)(63 - eff)` is at least 64, and the function evaluates `1ULL << drop` and `m >> drop`. A shift of a `uint64_t` by 64 or more is undefined.
`x87_get_int` calls `ext80_to_i64` when `ctx->x87_80` is set (`x87.c` 515–516). The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`. The `x87_get_int` call was re-read beside that note.

## D63. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 927–941
- Symbol: `op_frndint`

When `ctx->x87_80` is set, every finite value is passed through `x87_80_to_i64` and then `x87_80_from_i64`. `FRNDINT` has to round inside the extended format.
The only definition of `x87_80_to_i64` is `tests/unit/x87_80_stub.c` 715–730. A rounded magnitude outside the int64 range stores `INT64_MIN`, returns `X87_EXC_IE`, and `x87_80_from_i64` (666–669) writes that value back as `-2^63`.
A rounded value greater than or equal to `2^63`, or less than `-2^63`, is replaced by `-2^63` and invalid is raised. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md` quotes the handler calls. The stub body was re-read beside that note.

## D64. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 1983–1984, 1807–1808, and 1889–1890
- Symbol: `do_fcomi`, `h_fld_m80`, `h_fild_m64`

`do_fcomi` sets `SW_IE` for every unordered result. The comment says `FCOMI` raises invalid on a quiet NaN.
`h_fld_m80` with `modrm_mod == 3` is commented `FUCOMI` and calls `do_fcomi` with pop 0. `h_fild_m64` with `modrm_mod == 3` is commented `FUCOMIP` and calls it with pop 1.
`FUCOMI` / `FUCOMIP` must not raise invalid on a quiet NaN. This function has no quiet-NaN test, so those entries do. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`.

## D65. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 1140–1142
- Symbol: `op_fyl2x`

On the non-80-bit path, `a` is `ST(0)` and `b` is `ST(1)`. `a == 0` stores `signbit(b) ? -HUGE_VAL : HUGE_VAL` and sets `SW_ZE`.
`log2(0) * y` is `-infinity` when `y` is positive and finite, and `+infinity` when `y` is negative and finite. The stored sign is the other way.
`tests/unit/x87_80_stub.c` `x87_80_fyl2x` (line 552) stores `signbit(y) ? INFINITY : -INFINITY`, which is the sign of `(-infinity) * y`. That stub was not edited, and it is not a second defect. The `h_x87.c` arm was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`.

## D66. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 1038–1043 and 1072–1075
- Symbol: `op_fxsave`, `op_fxrstor`

`op_fxsave` sets abridged bit `p` when full tag field `p` is 3, and comments `1 = empty`. `op_fxrstor` writes tag field 3, commented `empty`, when that bit is set.
`tag_of` in `x87.c` documents field 3 as empty. Intel's FXSAVE abridged tag is 0 for empty and 1 for non-empty. Save and restore agree with each other and disagree with that image.
`tests/unit/test_l5c.c` line 876 expects `img[4] == 0x3f` and comments that slots 6 and 7 are non-empty. `0x3f` has bits 6 and 7 clear, which is non-empty only under the inverted polarity. Intel for those two live slots is `0xC0`. The test was not edited. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`. `tag_of`'s comment was re-read beside that note.

## D67. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Line: 1070
- Symbol: `op_fxrstor`

The restore does `ctx->mxcsr = img_rd32(img, 24) & 0xffbfU` and comments that bit 6 is reserved.
MXCSR bit 6 is DAZ. `0xffbf` clears that bit and leaves the flag bits, the masks, RC, and FTZ. A saved DAZ bit does not come back. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`.

## D68. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 1071–1078
- Symbol: `op_fxrstor`, `x87_set_ext80`

`op_fxrstor` writes empty tag fields from abridged byte `img[4]`, then calls `x87_set_ext80` for every stack slot.
`x87_set_ext80` (`x87.c` 338–353) ends in `set_tag(ctx, p, classify(ctx, p))`. `classify` (`x87.c` 115–143) returns 0, 1, or 2, and its comment says emptiness lives only in the tag word.
The empty fields just written do not survive. A zero image slot becomes tag 1 (zero), not tag 3. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md` quotes the call. `classify` was re-read beside that note.

## D69. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 275–280
- Symbol: `d_div`

When `b == 0` and `a` is not a NaN, `d_div` always sets `SW_ZE`, then also sets `SW_IE` if `a == 0` or `a` is infinite.
x87 `0/0` is invalid only. Infinity divided by zero is neither divide-by-zero nor invalid; the result is a signed infinity.
A finite non-zero dividend divided by zero sets `SW_ZE` only, which matches. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`.

## D70. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 221–235
- Symbol: `d_exc`

If the result is a NaN, `d_exc` sets `SW_IE` only when an input is a NaN, then returns. Infinity minus infinity is a NaN with non-NaN inputs, so invalid is not set. `d_div` reaches the same return for infinity divided by infinity: that case is not one of the early returns in `d_div`.
The underflow test sets `SW_UE` when `s != 0`, the result is finite, `err != 0`, and `fabs(s) < (double)FLT_MIN`. `FLT_MIN` is the single-precision minimum, far above `DBL_MIN`. An inexact double with `DBL_MIN < |s| < FLT_MIN` therefore is flagged. That magnitude is a normal double, so the flag is a false underflow. A zero result is the one that skips the test, because `s != 0` fails.
Directed-rounding overflow is a different function and is not part of this entry. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`.

## D71. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 617–630
- Symbol: `st_int`

On a 16-bit overflow `st_int` stores `0x8000`. On a 32-bit overflow it stores `0x80000000`. The 64-bit arm stores the raw value. None of those arms calls `x87_set_exc`.
Intel `FIST` / `FISTP` overflow is an invalid operation. The comment describes the integer indefinite and does not mention the flag. The stores were not changed. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`.

## D72. correctness

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Line: 1255
- Symbol: `op_fscale`

The non-80-bit path executes `scalbn(a, (int)trunc(b))` with no range test on `b`.
When `trunc(b)` is a NaN, an infinity, or a value outside the `int` range, the conversion to `int` is undefined. The worktree was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`.

## D73. comment

- Repo: `i686rt`
- Ref: `lane/5-l5c`
- Commit: `05a31200de5e8042ac47d8165f0d21ad0c13145e`
- Path: `src/interp/h_x87.c`
- Lines: 1304–1308
- Symbol: `op_fprem`

The comment says the low 3 quotient bits are safe for huge quotients.
`q` is `nearbyint(a / b)` or `trunc(a / b)`, a double. A double integer is not exact once `|a / b| > 2^53`, so those low bits are not the true low 3 bits of a huge quotient.
The comment is on the branch only and was not edited.
Second read: `blind/_raw/quote-i686-l5c.md`.

## D74. comment

- Repo: `i686rt`
- Ref: `master`
- Commit: `14e3e7c6e4587b91f8bb3e6deb3321bc4cbe7a82`
- Path: `src/os/sys_misc.c`
- Lines: 463–465
- Symbol: `i686_oflags_g2h`

The comment above `i686_oflags_g2h` said host-to-guest is the identity over the known mask.
`i686_oflags_h2g` starts from `h & I686_O_KNOWN`, then replaces `I686_HO_DIRECT_` (`0x10000`) with `I686_GO_DIRECT` (`0x4000`) and `I686_HO_NOFOLLOW_` (`0x8000`) with `I686_GO_NOFOLLOW` (`0x20000`). That is not an identity.
`i686_oflags_g2h` itself only does `g & I686_O_KNOWN & ~I686_GO_LARGEFILE`. D47 is the separate finding that `i686_oflags_h2g` still does not translate host `O_DIRECTORY`. This entry is only the false identity sentence.
The comment now says `g2h` keeps `I686_O_KNOWN`, drops `O_LARGEFILE`, and does not swap `DIRECTORY`, `DIRECT`, or `NOFOLLOW`, and that `h2g` rewrites host `DIRECT` and `NOFOLLOW` only. The functions were not changed.
Second read: `blind/_raw/quote-i686-oflags-g2h.md`.

---

# Open campaign defects (final report inventory, 2026-10-23)

Section owner: the implementation campaign (coordinator record), not the
blind-audit protocol above — C-numbered to keep the D-series untouched.
Status legend: OPEN (known-broken), VERIFY (fix in, evidence missing),
UPSTREAM (owned outside this repo), MEASURE (measurement gap).
Each entry lists the fix sites, a verification command, and lane
suitability for the parallel fix campaign (GOAL-DEFECTS.md).

Fix-campaign close-out (2026-10-24): every entry below now carries a
`Close-out:` line with its terminal state.  Commits cited: freeze
2061d1c, C5 f4336d0, C4 7e5d7a2+d5a3f45, C1b merge (lane/fix-c1b),
C1a f24db6e, C7, C11 59da1ef, C6a, C6b, C6c, C2 merge, fix batch
ba4e54f, LTP harness b316069.

## C1. correctness/coverage — eight unimplemented syscalls (CLOSED: FIXED)

Close-out: FIXED.  C1a (_llseek 140, readv 145, msync 144,
ftruncate64 194, statx 383; f24db6e) and C1b (tkill 238, tgkill 270,
sched_getaffinity 242, set/get_robust_list 311/312, plus set_tid_address
258 superseded to return the caller tid and gettid 224; lane/fix-c1b)
merged.  Verification: the C1a fd fixture passes under both engines;
the C1b fixture prints its tkill/tgkill/affinity/robust PASS line;
`tools/run-libctest.sh` = 135/343 (H2 floor 125/343, no regression);
the LTP rerun after harness repair b316069 reaches test bodies:
25 pass / 19 fail / 1 timeout / 72 skip (TCONF) / 117 — zero framework
setup deaths; residual fails are body-level (fcntl lease family fails
on overlayfs, fork stress under interpreter speed, fcntl31/32 ENOSYS
class) and routed to SPEC §7.

## C1. correctness/coverage — eight unimplemented syscalls (OPEN, P0)

Per-syscall detail (i386 numbers, kernel ABI, known consumers):

- `_llseek` (140): fd, offset_hi:offset_lo (EDX:EAX), whence (ESI);
  returns off64 in EDX:EAX. Breaks glibc stdio `fseeko/ftello` (H2:
  `_llseek off_t at 0x7fffffff` failing case). Site: new handler in
  src/os/sys_pass.c (host lseek64); guest 64-bit split/merge helpers
  exist in the fcntl family.
- `readv` (145): fd, iov, iovcnt — writev(146) exists; mirror it.
  Consumers: coreutils, libc-test.
- `msync` (144): addr, len, flags — trivial passthrough
  (vm_invalidate_jit not required; window is host-mapped).
- `ftruncate64` (194): fd, length_hi:length_lo (i386 two-register
  split). LTP framework `SAFE_FTRUNCATE` dies here — the single
  biggest LTP blocker.
- `tkill` (238): tid, sig — needed by `raise()` and
  `pthread_cancel` routing (see C2). Site: sys_pass.c signal family
  (pending-bit + host tgkill of the owning pthread).
- `sched_getaffinity` (242): pid, len, mask u32[] — return a single
  CPU mask sized to the guest's view (LTP SAFE macro).  Optional
  sibling: sched_setaffinity(241) -ENOSYS tolerated.
- `set_robust_list` (311) / `get_robust_list` (312): head, len.
  glibc/PI mutexes need at least acceptance-then-ENOSYS semantics;
  full robust-list processing is C2 scope.
- `statx` (383): dirfd, path, flags, mask, statx buf — glibc falls
  back to fstatat64 today (works); implementing it removes the
  fallback and the -38 noise.  Optional sibling: faccessat2 (439).

Verification: `tools/run-libctest.sh && tools/run-ltp.sh && make
h2-report` — LTP must reach test bodies (framework deaths = 0) and the
libctest count must not regress; fseek/ftello tests flip to pass.
Lane-suitable: two parallel lanes (C1a: file-descriptor class — 140,
145, 144, 194, 383; C1b: thread/sched class — 238, 242, 311, 312).

## C2. correctness — pthread cancel/cond/robust/once timeouts (CLOSED: PARTIALLY FIXED, remainder root-caused)

Close-out: the delivery/futex cluster is fixed and the cluster left the
timeout class for 8 of 19 (lane/fix-c2 + fix batch ba4e54f): futex
val2/requeue + PI re-encode (host-oracle-identical PI fixture), kernel
pending-signal semantics, robust exit walk, blocked-target wake, dual
cleartid wake (fixes the C10 join route), FPREM indefinite C2 (the 11
math timeouts).  Rerun disposition: pass=8 fail=5 timeout=6.  Remaining,
each root-caused: (1) fmodl/remainderl/remquo family completes with
wrong quotient-bit state — the D73 fprem partial-remainder class, routed
there; (2) functional/pthread_cancel, regression/pthread_once-deadlock,
regression/raise-race — second-generation cancellation still restores a
zeroed sigcontext (eip=0) after the teardown-race fix ba4e54f; the
overlap evidence (docs/lanes/fix-c2-rt32-evidence.md) and the narrowed
signature are committed; (3) clocale_mbfuncs/crypt pass unbounded
(71s/42s) — the fixed 30s wall bound under host load, not a defect;
(4) tls_get_new-dtv — the pre-existing dlopen DSO-not-built class.


## C3. verification — wine chain under engine=dbt (CLOSED: VERIFIED with a documented residual)

Close-out: the RC7b-era stall is confirmed FIXED by H1's host-fault
checkpoint (lane/fix-c3 record: full wine boot, prefix install
completes under dbt).  The gate then exposed deterministic guest #DE
misdeliveries — root-caused by lane/fix-c3f as stale-ctx->exit_arg
classification in i686_deliver_sync (the DBT writes exit_arg=0 on
every BRANCH exit, so plain page faults arrived as divide errors at
stale block-start EIPs) — FIXED in ba4e54f.  Residual (open, SPEC §7):
the gate now fails earlier, inside wine's dash wrapper discovery
("unable to find wine executable") after an empty-path STATX probe
sequence — a dash-under-dbt divergence isolated with SYSTRACE
(docs/lanes/fix-c3-trace.md, _build/fix-c3-raw/).  The interp chain
prints ok rc=0.  Full wine-on-dbt remains H5/H6-class DBT maturity
work.

## C4. correctness — round_pack80 directed-rounding deep-tiny (CLOSED: FIXED)

Close-out: FIXED (merged 7e5d7a2).  round_pack80's eff<0 branch now
rounds a nonzero tiny inexact value of matching sign to the minimum
extended subnormal under toward-infinity; nearest, toward-zero, and
opposite-sign keep the signed zero (mirrors e31dccc).  56 directed
vectors below/around 2^-16446 added to test_l5d; the RC5 golden
comparison reports 0 diff in both modes.  The lane's escalation also
exposed a Makefile defect (test-p5-lima stripped X87ONLY from the
golden side only, making the default compare unwinnable) — fixed in
d5a3f45.

## C5. correctness/SSE — MOVDQA alignment #GP interpreter-only (CLOSED: RATIFIED)

Close-out: RATIFIED (f4336d0).  The whole aligned-SSE-move class
(MOVAPS/MOVAPD/MOVDQA/MOVNTDQ/MOVNTQ) is defined to raise no #GP(0)
on misaligned EAs in v1, identically in both engines; the
interpreter-only checks were dropped, SPEC D10 records the rationale,
and tests/probe_sse_align.c asserts the semantics (SSE-ALIGN-OK,
exit 0, interp + dbt; a native i386 CPU faults where i686rt
succeeds).

## C6. performance — DBT 3x slower than the interpreter (CLOSED: RE-SCOPED, coordinator rationale)

Close-out: RE-SCOPED with this written rationale.  Both H3-named
mechanisms are implemented and verified: dead-flag elimination (C6a —
consumers dispatch on the frozen flags_src seam; fused paths elide the
park/sync/rebuild round-trip, flags_elided=5496 on a busybox run) and
block linking (C6b — IBTC slots filled/severed, trampoline dispatch
loop, 64.3% of executions chaining in asm).  The coordinator-ratified
C6c levers removed the per-dispatch sigsetjmp syscall storm
(rt_sigprocmask 1110 -> 2) and heal collided IBTC slots.  CoreMark
moved dbt 21 -> 24 against interp 63-69 (CRCs intact throughout); the
remaining ~3x gap is the v1 block-granular translation model itself —
per-block RWX mmap/munmap churn (~5.6k-8.5k pairs per CoreMark
iteration) and ~31k dispatches/iteration (no superblocks) — which
belongs to the H5 (AOT) / H6-class DBT maturity roadmap, not to a
defect-fix campaign.  Evidence: tests/hardening/h3-coremark.md
addenda; I686RT_STATS counters in the lane records.

## C7. hygiene — SMC dead-mark reclamation (CLOSED: FIXED)

Close-out: FIXED (merged lane/fix-c7).  Dead-marked blocks park
{code, cap} in a bounded 256-entry graveyard (oldest munmapped on
overflow); drain runs only at the frozen safe points (dispatch-loop
top, flush_all); the dead-mark site empties the slot so eviction and
flush_all cannot double-free.  Acceptance: test_h1_smc PASS both
engines; the 10,200-event SMC RSS fixture grows 248 KiB vs 2964 KiB
against the un-fixed build (negative control).

## C8. upstream — hl guest_env ordering breaks A32RT_WINDOW (CLOSED: UPSTREAM)

Close-out: UPSTREAM, terminal as recorded.  The gap is documented in
SPEC §7 (item 2, final report) and here: hl materialises guest_env
before translator finalize's setenv; the i686 launch carries the
explicit window hint on the local hl branch lane/6-l6a, the a32 path
retains the gap behind a32rt's scan fallback.  Owned by Moritz; the
verification step for a patched hl (a32rt guest + HL_A32RT_WINDOW)
stays as written.  Nothing to change in this repo.

## C9. hygiene — winevdm "winedevice.exe is a DOS application" x3 (CLOSED: FIXED via C1)

Close-out: FIXED, root-caused by lane/fix-c9 forensics
(docs/lanes/fix-c9-diagnosis.md): the lines were not a launch-vs-copy
race — wine's update pass read 96 bytes, failed to rewind (the then-
missing _llseek(140) returned -ENOSYS), and rewrote the 142896-byte
builtin at offset 96, permanently corrupting the installed
winedevice.exe so every launch verdict failed.  T4c's hypothesis is
refuted; interpreter slowness only varies the launch count.  With C1a
landed, the acceptance rerun (fresh WINEPREFIX, interp, RC7b chain)
prints ok rc=0 with ZERO DOS lines and an intact winedevice.exe
(142896 bytes, PE\0\0 at e_lfanew).  The remaining FreeType stderr
notices are expected minimal-sysroot noise (no freetype deb in the
RC7b closure).

## C10. gate hygiene — formal dynamic-glibc rerun of RC4 (CLOSED: PARTIALLY FIXED, residual root-caused)

Close-out: the C10 lane compiled tests/test_p4_glibc as a true dynamic
glibc 2.44 i386 PIE (ld-linux.so.2, DT_NEEDED libc.so.6) and ran the
gate: it initially blocked forever at pthread_join — the clone-fallback
thread exit missed the CHILD_CLEARTID wake; FIXED by C2's dual
private+shared cleartid wake and verified with a dynamic-glibc join
fixture ("PASS t4 join-returned").  The coordinator gate rerun
post-fix: glibc startup, TLS, robust lists, clone3->clone fallback,
threads, fork/wait (child reaped, exit 42) and statx now all work, and
the run dies later at a guest indirect jump to eip=0x00000001 (a
corrupted code pointer, SYSTRACE committed in docs/lanes/fix-c10-
record.md addendum rerun).  Full PASS remains open — root cause is a
deeper dynamic-glibc divergence of the same class the wine chain
anchors (SPEC §7); musl RC4's original gate criteria remain met by
the static fixtures.

## C11. measurement — H2 math under --x87-80 (CLOSED: MEASURED)

Close-out: MEASURED (merged 59da1ef).  `H2_X87_80=1` knob (default
path byte-identical), the 80-bit TAP log, and the two-mode table in
tests/hardening/h2-report.md.  Signal: the remainder/exactness
families flip to pass in 80-bit mode and 12 timeouts resolve, but a
distinct 80-bit rounding/signed-zero cluster flips 22 math tests to
fail (ceil(-0) -> +0 etc.) — recorded as measured; the cluster is the
x87_80-mode evidence for the D63/D73-class fix lanes.

## C12. hygiene — quarantine stashes + open D-series reconciliation (OPEN, P3)

Two quarantine stashes from the Phase 5 lane leaks remain on master
(`git stash list`); content largely superseded by committed fixes.
Reconcile: drop or port anything still relevant, then re-read the
open correctness entries of the D-series above and route still-live
ones into this campaign's triage.
