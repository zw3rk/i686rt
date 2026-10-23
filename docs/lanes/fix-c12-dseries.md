# L-C12 — D-series re-read against current master (2026-10-23)

Card L-C12, task 2.  Lane `lane/fix-c12`, master base `ba4e54f`.  Every
entry was classified by reading the CURRENT master code at the cited
site (not the D-entry's cited commit), with fixing commits identified
via `git log -S` / merge history.  Classes: FIXED-on-master,
STILL-LIVE (defect's code unchanged), MOOT (code gone/restructured).

Scope per dispatch: D13, D14, D25, D26, D27, D28, D31, D34, D37, D39,
D41, D43, D47, D51, D52, D53, plus the three branch-only spot checks
D57, D60, D63.

## Disposition table

| Entry | Site (current master) | Verdict | Evidence |
|---|---|---|---|
| D13 | src/x86/decode.c, moffs A0-A3 (~552-566) | FIXED-on-master | Width is now `out->pfx_addrsize ? 2U : 4U` with the "follows the ADDRESS-size attribute" comment; the `pfx_opsize` expression is gone. Fix: `4a1bbae` ("Phases 7-8 S7/S8 wiring: ... moffs fix") |
| D14 | src/x86/decode.c:124-137 `ea_default_seg` | STILL-LIVE | SS still gated on `modrm_mod != 0`: 16-bit mod==0 rm==2/3 gets `ea_base = I686_REG_EBP` (base16 table at 300-302, assign at 313) and returns DS; 32-bit `[esp]` SIB mod==0 likewise. Wrong base whenever SS != DS |
| D25 | src/os/sys_pass.c:1329 `sys_futex` | FIXED-on-master | `utime_va = ctx->gpr[I686_REG_ESI]` (i386 arg4); the T4d body documents the per-command marshalling (timeout_cmds/val2_cmds). Fix: `1bb5c1b` (RC7b triage T4d) |
| D26 | src/os/syscalls.c:590, 677 `r_execve` | STILL-LIVE | `char path[4096]` local; `ctx->exec_path = path;` (677) still stores the stack array; `proc.c:282-283` reads `ctx->exec_path` on later calls after `r_execve` returned |
| D27 | src/os/sys_pass.c:805-813 `sys_fchmodat`, 856-886 `sys_faccessat` | STILL-LIVE (half-fixed) | faccessat(307) arm fixed by `ca83f68` (RC7b T3: three-argument ABI, no flags read). fchmodat(306) arm unchanged: `r_fchmodat` (1633-1637) still passes `gpr[ESI]` as flags into host `fchmodat` |
| D28 | src/main.c:135 `apply_env` | STILL-LIVE | `if (!ctx->x87_80 && getenv("I686RT_X87"))` unchanged: after `--x87-64` the env still assigns `x87_80`; after `--x87-80` the env is ignored |
| D31 | src/os/sys_thread.c:219-223 `sys_set_tid_address` | FIXED-on-master | C1b handler returns `i686_thread_registry_self_tid(ctx)`; registered at thread-init (syscalls.c:774), which runs after pass-init (773) and shadows the stale sys_pass.c:1269 handler. Fix: `a708b15` + `007807a`, merged via `ed6a8e4` (Merge lane/fix-c1b) |
| D34 | src/os/signals_i386.c:127 `i686_sigframe_build` | STILL-LIVE | `memcpy(&fp.st_space, ctx->x87_st, sizeof(ctx->x87_st))` still copies 128 B into `st_space[20]` (80 B, sigframe_i386.h:49): 48 B run past it over `__pad0`, the FXSAVE header words (fctrl..fpu_ds2), `mxcsr` and `mxcsr_mask` (set correctly at 122, then clobbered), and into `xmm_space` (re-fixed by the next memcpy at 128). Every fpstate-bearing signal delivery writes a corrupted image |
| D37 | src/os/signals_i386.c:133-136 `i686_sigframe_build` | STILL-LIVE | `sp &= ~0xFU` then a 268-byte rt-frame push still leaves handler ESP = 4 mod 16 (not the i386 ABI's 12 mod 16). Only D36's comment correction landed (the line-133 comment now says "leaves ESP 4 mod 16") |
| D39 | src/os/clone.c:495-499 `i686_tls_install` | MOOT | The entry_number slot logic is gone; the function delegates to `i686_ldt_clone_settls` (src/os/ldt.c:356), which validates the GDT index 6..8 kernel-faithfully and rejects everything else with -EINVAL — the described auto-alloc misbehavior no longer exists. Restructure: `911eaa3` (RC7b T4c) |
| D41 | src/os/sys_time.c:600-607 `sys_settimeofday` | STILL-LIVE | Still passes `long htz[2]` (16 B on aarch64) to SYS_settimeofday; the kernel reads only the first 8 B, so `tz_dsttime` (`htz[1]`) is still not transmitted. The comment now openly says "the kernel reads htz[0] only" (that is D40's landed correction) |
| D43 | src/os/sys_stat.c:324-361 cookie remap | STILL-LIVE | `L2A_DIR_COOKIE_BASE 0x70000000` fold (`map_dir_cookie` / `i686_dirent64_remap_offs`) unchanged: host d_off cookies at or above the base are still remapped instead of returned as themselves in the 64-bit i386 getdents64 field |
| D47 | src/os/sys_misc.c:494-508 `i686_oflags_h2g` | STILL-LIVE | Still rewrites only `I686_HO_DIRECT_` (0x10000) and `I686_HO_NOFOLLOW_` (0x8000); host `O_DIRECTORY` (0x4000) survives `I686_O_KNOWN` (guest O_DIRECT = 0x4000) and is returned unchanged, so F_GETFL still reports guest O_DIRECT on directories |
| D51 | tests/test_p1_isa.c:111, 542 | STILL-LIVE | `F_CC` still includes `F_AF`; `f_shl` returns `f & F_CC`; `TEST("shl2_f", f, F_CF | F_OF)` still demands exact equality, failing any host/translator that sets the (undefined-after-shift) AF bit |
| D52 | src/os/marshal.c:43-58 `i686_fetch_cstr` | STILL-LIVE | Still dereferences `*p` from `i686_guest_ptr(ctx, va + i)` per byte with no `guest_ptr_bad`/low-page check; a pathname in the unmapped low page is read instead of returning -EFAULT |
| D53 | src/os/sys_stat.c `i686_statfs_from_host` | STILL-LIVE | The five `(uint32_t)` casts (f_blocks/f_bfree/f_bavail/f_files/f_ffree) are unchanged, no -EOVERFLOW range check (kernel `put_compat_statfs` behavior); the "32-bit compat truncation" comment is still there |

## Branch-only spot checks (D57/D60/D63)

DEFECTS.md notes D57–D61 were read on `lane/5-l5b` (worktree
`../i686rt-l5b`, untouched) and D62–D73 on `lane/5-l5c`
(`../i686rt-l5c`).  The defect TEXT is branch-only, but the CODE landed
on master: h_sse.c via `8a48431` (Merge lane/5-l5b), h_x87.c via
`1b94c8c` (Merge lane/5-l5c), the real x87_80 core via `bf578ae`
(lane/5-l5d).  All three defects are alive on master:

| Entry | Site (current master) | Verdict | Evidence |
|---|---|---|---|
| D57 | src/interp/h_sse.c:642-668 `h_movups` | STILL-LIVE (text branch-only) | Memory scalar load still seeds `dst` from the old destination (`sse_get_xmm`, 650) and `sse_ld` (656) memcpys only 4/8 B, so lanes above MOVSS/MOVSD keep the OLD destination value; Intel zero-extends memory scalar loads. The reg-form arm's "upper lanes preserved" is correct for mod==3 only |
| D60 | src/interp/h_sse.c:475-490 `sse_cvtt_f2i` | STILL-LIVE (text branch-only) | Guard unchanged: `!(d >= -2147483648.0 && d < 2147483648.0)` raises IE + returns 0x80000000 for d in (-2^31-1, -2^31), whose truncation is INT_MIN and should be PE-only |
| D63 | src/interp/h_x87.c:946-967 `op_frndint` | STILL-LIVE (text branch-only) | The --x87-80 arm still round-trips every finite value through `x87_80_to_i64`/`x87_80_from_i64` (958-960). The cited stub is no longer the only definition — `x87_80.c:2788` (to_int_core) clamps anything at/above 2^63 to the integer indefinite, so FRNDINT(2^63) or larger still returns -2^63 with IE instead of rounding inside the extended format. Only the stub's UB-shift aspect (a D62-family issue) is resolved by the real core; the stub (tests/unit/x87_80_stub.c:715) keeps the same clamp for unit builds |

## Counts

19 entries classified:

- FIXED-on-master: 3 — D13 (`4a1bbae`), D25 (`1bb5c1b`), D31 (`a708b15`/`007807a` via `ed6a8e4`).
- MOOT: 1 — D39 (restructured by `911eaa3`).
- STILL-LIVE: 15 — D14, D26, D27 (fchmodat arm; faccessat arm fixed by `ca83f68`), D28, D34, D37, D41, D43, D47, D51, D52, D53, plus branch-only D57, D60, D63.

## Headline still-live finding

D34 (src/os/signals_i386.c:127): the sigframe fpstate builder memcpys
the full 128-byte x87 register file into the 80-byte `st_space` field,
clobbering the FXSAVE image's environment words, `mxcsr` and
`mxcsr_mask` with register-file bytes on EVERY fpstate-bearing signal
delivery.  A guest handler that fxrstors (or reads MXCSR from) the
delivered frame sees corrupted state.  One-line-shaped fix (copy
`sizeof(fp.st_space)`), hot path, and it silently corrupts x87/SSE
state under both engines.

## Extra observations for the coordinator (no edits made)

- FRESH STALE COMMENT: src/os/sys_pass.c:71-72 (file header, D24's
  landed correction) says the futex timeout pointer is "read from EBP
  (i386 arg6 / val3)" and that ESI "is not read here" — the T4d body
  (1bb5c1b) now reads `utime_va` from ESI (1329) and EBP is val3.  The
  header paragraph contradicts the implementation since T4d.
- D31's old sys_pass.c handler (1269-1277, returns the previous
  pointer, with the pre-C1b comment) is dead-but-registered code
  shadowed by the thread seam; a candidate for deletion whenever
  sys_pass.c is next touched.
- The stash set (see fix-c12-stashes.md) is the same D4-D12 audit text;
  after the insn_tab.h port lands, both stashes can be dropped.
