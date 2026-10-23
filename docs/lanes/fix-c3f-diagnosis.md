# C3f diagnosis — the DBT #DE divergence (lane fix-c3f, 2026-10-23)

Root-cause record for Card L-C3f (docs/lanes/fix-c3-trace.md escalation):
why `I686RT_ENGINE=dbt` hits deterministic guest divide-error events that
the interpreter never produces on the identical RC7b wine chain.
DIAGNOSIS-ONLY lane: no src/ files were written or committed. Worktree
`../i686rt-c3f`, branch `lane/fix-c3f` from master a8d79fd.

## Verdict in one line

The three #DE events are not divisions. They are the DBT host-fault
checkpoint misdelivering ordinary guest page faults as SIGFPE/trapno 0
("division by zero") at a stale EIP, because the sync-fault classifier
keys on the *stale* `ctx->exit_arg` — which the DBT leaves at 0 after
every block-ending BRANCH exit — and records `sc.eip = ctx->eip`, which
during translated execution holds the current block's start (or a
garbage dispatch target), never the faulting instruction. Wine cannot
handle a #DE, so every such delivery kills the thread; the wineboot
install dies mid-way and the loader cascades to `c0000135` → exit 53.
One root cause, one delivery path, many trigger sites.

## The mechanism (source, master a8d79fd; signals_i386.c is byte-identical
## to the C3-era 92787d1 tree — md5 8ebd72a33783680fa6ab85dae3b270ac both)

1. Emitted DBT code accesses guest memory through raw window loads with
   no per-access check (`i686_emit_ea` + `[x20, w21, uxtw]`, emit_exit.c);
   an access to an uncommitted/PROT_NONE window page raises a host
   SIGSEGV. The host handler (src/interp/interp.c `host_fault_handler`,
   installed for SIGSEGV/SIGBUS/SIGILL/SIGFPE) filters the D11 SMC
   write-fault case and otherwise `siglongjmp`s to the engine checkpoint
   with `s_fault_addr` recorded. The ORIGINAL host signal number is
   stored in `s_fault_sig` — and never consulted afterwards.
2. The DBT checkpoint (src/dbt/engine.c `i686_dbt_run`, the
   `sigsetjmp(fj,1)` block) calls
   `i686_deliver_sync(ctx, I686_EXIT_FAULT)` — hard-coding the FAULT
   reason for *every* host fault.
3. `i686_deliver_sync` (src/os/signals_i386.c) classifies:
   `sig = (ctx->exit_arg == 0U) ? 8 : 11; /* div0 -> SIGFPE */`.
   `ctx->exit_arg` is stale global state: the interp raises a genuine
   #DE exactly this way (h_muldiv.c `md_divide_fault` sets
   `exit_reason=FAULT, exit_arg=0`), so exit_arg==0 is the #DE convention.
   But under the DBT every block-ending BRANCH exit writes
   `exit_arg = 0` as a *side field* (`i686_emit_exit(..., I686_EXIT_BRANCH,
   0U, pc)` in translate.c; the same 0 in emit_branch.c `l3c_exit_const`
   for both the taken and fall-through arms of every Jcc, and for
   JMP/RET). At any mid-block host fault the last exit was a BRANCH, so
   exit_arg is 0 → **the fault is delivered as a guest divide error**.
   (The interp loop leaves exit_arg mostly untouched across normal
   instructions, so at the interpreter's fault sites it happened to be
   non-zero — hence interp deliveries came out as sig=11; the classifier
   itself is engine-independent and latently exposed there too.)
4. The sigframe records `sc.eip = ctx->eip` and `sc.trapno =
   ctx->exit_arg` = 0, si_code = FPE_INTDIV (signals_i386.c). Under the
   DBT `ctx->eip` is written only by exit sequences (`l3c_exit_seq`
   stores dest into eip for every exit) and by the engine's
   BRANCH/UNDEF handling — during block execution it holds the CURRENT
   BLOCK'S START. The guest handler therefore sees a divide error at an
   address that is not the faulting instruction and usually cannot fault
   at all. For faults at dispatch/translate time (branch to a non-code
   address) the recorded eip is that non-code address itself.
5. Wine's ntdll SIGFPE handler converts trapno 0 to
   EXCEPTION_INT_DIVIDE_BY_ZERO and, finding no guest #DE handler,
   prints `wine: Unhandled division by zero at address XXXXXXXX`,
   tries the debugger, and the thread/process dies with
   STATUS_INTEGER_DIVIDE_BY_ZERO (0xC0000094). Everything downstream
   (missing fake dlls, `could not load kernel32.dll, status c0000135`,
   exit 53) is cascade.

Why the DBT takes these host faults at all is a separate, upstream
matter (see "Upstream divergence anchors"); the fatal *classification
and imprecision* is the #DE divergence, and it converts faults that the
interpreter delivers survivably (wine handles guest #PF/SIGSEGV) into
uniformly fatal #DEs.

## Live discrimination (bounded containers; this lane's runs)

Method: worktree build, arm64 `alpine:3.20` container per run (unique
name + `--cidfile`, `--memory 4g --cpus 4`, host-side `timeout 1920`,
in-container `timeout -k 10 1800`), sysroot mounted read-only,
fresh WINEPREFIX on a mounted scratch, gate command per C3's record.
All three containers verified removed (`docker ps -a --filter
name=c3f-diag` empty after each run); cidfiles deleted.

Build (C3-era sources, see "Note on master" below):

    make build CC=/nix/store/cs8q52va4acssg38pivn7f9kyvk9lzjd-\
      aarch64-unknown-linux-musl-gcc-wrapper-15.2.0/bin/\
      aarch64-unknown-linux-musl-gcc
    → _build/i686rt (495544 B, only the pre-existing
      sse_emit_prefetch unused-parameter warning)

Run 2 (dbt, `I686RT_ENGINE=dbt I686RT_SYSTRACE=1 I686RT_SIGTRACE=1`,
container c3f-diag2, ~5 min, self-terminated): GATE-RC=53, stdout empty,
7 SIG deliveries — 3 misdelivered #DEs plus 4 correctly-classified
sig=11s — verbatim SIG lines (NULs stripped; full trace kept at
`_scratch/c3f-run2.err`, untracked):

    SIG tid=26 sig=11 trapno=14 eip=685a09ee cr2=00000000 ...  (handled, boot continues)
    SIG tid=23 sig=8  trapno=0  eip=681051ef cr2=00000100 ...  <- #DE #1 (libc)
    SIG tid=23 sig=11 trapno=14 eip=0021fca2 cr2=ffffff8c ...  (wine's #DE handler crashing, sigreturn into a stack EIP)
    wine: Unhandled division by zero at address 681051EF (thread 004c), starting debugger...
    SIG tid=23 sig=11 trapno=14 eip=0021fca2 cr2=fffffffc ...  (second handler crash)
    SIG tid=23 sig=8  trapno=0  eip=7bda852a cr2=a803c000 ...  <- #DE #2 (garbage-region EIP)
    SIG tid=30 sig=11 trapno=14 eip=df7fa330 cr2=a6a3b000 ...  (handled: #PF inside the vDSO gateway)
    SIG tid=30 sig=8  trapno=0  eip=680d8736 cr2=00000008 ...  <- #DE #3 (gs=0000/00000000, no handler)
    i686rt: dbt: guest fault (host) pid=17 at eip=0x680d8736, fault_addr=0x00000008
    SYS 23 252 -> -1073741676 (bx=c0000094 ...)   <- pid 23 exits STATUS_INTEGER_DIVIDE_BY_ZERO
    wine: could not load kernel32.dll, status c0000135
    SYS 9  252 -> -1073741515 (bx=c0000135 ...)   <- chain exit 53

`pid=23 252 -> -1073741676` (0xC0000094) is the same death certificate
C3's run 2 recorded for pid 17 (fix-c3-raw line 89006) — the misdelivered
#DE is what kills the install-phase process and triggers the cascade.

Run 3 (interp contrast, same binary and gate, default engine, container
c3f-diag3, ~3.5 min): **GATE-RC=0, stdout `ok`** — and the ENTIRE SIG
population of the whole boot is:

    SIG tid=40 sig=11 trapno=14 eip=682c551e cr2=00000000 ...  (handled)
    SIG tid=40 sig=11 trapno=14 eip=00000000 cr2=00000000 ...  (handled)
    SIG tid=12 sig=6  trapno=0  eip=40097acf ...               (loader abort noise, unrelated)

Zero sig=8 deliveries. Note the second interp line: the interpreter
delivers a SIGSEGV/#PF **at eip=0x00000000** and wine handles it and the
chain completes — the exact guest state of C3's site A. The same class
of event under dbt is the fatal `division by zero at address 00000000`.
This is the discrimination in its purest form: identical fault
machinery, identical guest-level fault population, opposite signal
class, opposite outcome.

## Per-site verdicts

Load bases are deterministic for this chain and were verified from the
traces themselves (run 2 SYSTRACE mmap2s: unix ntdll.so RX at
0x68292000 = base 0x6828C000 + 0x6000, plus the +0x65000/+0x93000
segments; libc.so.6 base 0x68043000 via RX at 0x68067000; PE ntdll.dll
ImageBase 0x7bc00000 SizeOfImage 0x2ae000 per its PE header;
kernel32.dll ImageBase 0x7b800000).

### Site A — `wine: Unhandled division by zero at address 00000000`
### (thread 005c, C3 run 1)

Verdict: misdelivered non-division fault at stale EIP 0; NOT a wrong
branch exit and NOT a division. Two independent facts:

- A genuine #DE can never be recorded at EIP 0: one-operand DIV/IDIV are
  declined by the DBT (emit_alu.c: "one-operand MUL/IMUL/DIV/IDIV ...
  declined" → D2 interpreter path), and the interpreter's
  md_divide_fault leaves the guest IP at the faulting DIV — a real
  instruction. A dispatch at guest VA 0 would also have to first get
  there (guest VA [0, 0x10000) is the PROT_NONE low guard,
  rt32_vm.c/I686_LOW_GUARD_SIZE).
- The interp contrast run shows the chain legitimately produces
  `eip=00000000` fault contexts mid-boot (wine's own handler-recovery
  path sigreturns into a NULL context; the second tid=40 SIG line) and
  survives them as SIGSEGV/#PF. Under dbt the same event class is
  #DE-classified (stale exit_arg 0) and fatal. EIP 0 at delivery needs
  no wrong-branch divergence — the guest walks there itself; only the
  classification differs per engine.

### Site B — `wine: Unhandled division by zero at address 7BD907B6`
### (thread 007c, C3 run 1)

Verdict: misdelivered fault; the recorded EIP is not code at all —
0x7BD907B6 is RVA 0x1907B6 of the PE ntdll.dll image (0x7bc00000), which
lands inside the `.debug_info` section (DWARF data, section table:
.text ends at RVA 0x6e160; .debug_info spans 0xb9000-0x1cb5da). No
instruction exists there; a genuine #DE cannot be recorded there.
Mechanically, `ctx->eip` can hold such a value only after a
BRANCH/UNDEF exit dest pointed there and the engine dispatched
(dbt_get_or_compile decodes whatever bytes are present; the resulting
garbage block faults on first access → checkpoint → #DE at that EIP).
This lane's dbt run caught the same flavor live: tid=23's #DE #2 at
eip=7bda852a (PE ntdll .debug_info RVA 0x1a852a) with return address
7bd61fa2 also inside .debug_info — i.e. guest control flow was executing
garbage blocks by then. In that trace the garbage execution is
downstream of the earlier misdelivered #DE on the same thread (the
handler crash-loop sigreturns into corrupted contexts, eip=0x0021fca2 on
the guest stack), so site-B-class events are consistent with being a
late symptom of the same delivery defect. Whether EVERY garbage-target
transfer is downstream of a misdelivery (or some are upstream codegen
divergences) is not decidable from run 1's log-less evidence; see the
anchors below.

### Site C — `wine: Unhandled division by zero at address 682CE9A2`
### (thread 0064, pid 17, C3 run 2 — the event that aborted the
### wineboot install at 278/518 files)

Verdict: misdelivered page fault at a stale block-start EIP; NOT a
division. Base verified from C3's own trace: ntdll.so at 0x6828C000 →
0x682CE9A2 = ntdll.so + 0x429A2, in the r-x PT_LOAD. The instruction at
that boundary is `mov eax, 0xc000000d` (STATUS_INVALID_PARAMETER
materialization, capstone disassembly of the sysroot
i386-unix/ntdll.so) — reachable code, but an instruction that cannot
fault, preceded by `test edx,edx / je`. It is a textbook block start;
the faulting access was somewhere later inside the translated block, and
the recorded EIP never advanced. C3 run 2's pid 17 exits
STATUS_INTEGER_DIVIDE_BY_ZERO (fix-c3-raw line 89006) — the identical
certificate this lane's run produced for pid 23. This lane's tid=23
#DE #1 (eip=681051ef = libc+0xC21EF, a `movsw` tail inside glibc's i386
memcpy at 0xc2190, cr2=0x100) is the same shape: block-start EIP,
non-faulting boundary instruction.

## Root cause (single)

`i686_deliver_sync` (src/os/signals_i386.c) classifies sync FAULT exits
by the stale `ctx->exit_arg == 0 → SIGFPE/trapno 0`, and both engine
checkpoints feed it `I686_EXIT_FAULT` for every host fault with
`sc.eip = ctx->eip` (stale under the DBT). The DBT's branch-exit
convention (exit_arg = 0 on every block-ending BRANCH) makes the
misclassification deterministic: any host fault taken in translated code
— a plain guest page fault the guest would handle, or the consequences
of an upstream divergence — is delivered to wine as an unhandleable
divide error at a wrong EIP. The interpreter survives the same chain
because its stale exit_arg was non-zero at every fault site (deliveries
came out sig=11/trapno=14, which wine handles), not because the interp
classifier is correct. There are NOT three distinct causes; sites A, B
and C are three trigger instances of one delivery defect.

## Prescription (for the coordinator to route to a fix lane)

Primary fix — classify by the recorded host signal, not stale exit_arg:

- File: `src/os/signals_i386.c`, function `i686_deliver_sync` (used by
  BOTH engines, so one fix covers interp.c and engine.c checkpoints).
- Change: for `I686_EXIT_FAULT` raised from the host-fault checkpoint,
  derive the guest signal from `i686_fault_sig()` (already recorded in
  interp.c's `s_fault_sig`, currently never read):
  SIGSEGV/SIGBUS → sig 11, trapno 14 (#PF, cr2 = fault_addr);
  SIGILL → sig 4, trapno 6 (#UD); SIGFPE → sig 8, trapno 0 (#DE).
  Concretely: give the checkpoint path a way to say "host fault of kind
  X" — e.g. set `ctx->exit_arg` to the kernel trapno before delivery
  (14/6/0 from `i686_fault_sig()`) and make `i686_deliver_sync`
  distinguish "checkpoint-raised" from "interpreter-raised" (a distinct
  exit reason or a flag), since exit_arg==0 must remain the interp's
  genuine-#DE convention (md_divide_fault). The seg-fault channel
  (exit_arg 11/12/13 with error code in exit_dest) is untouched.

Secondary (same fix lane, strongly recommended, cheap):

- Reset `ctx->exit_arg` to a non-#DE sentinel at the top of the DBT
  dispatch loop (next to `ctx->exit_reason = I686_EXIT_NONE`,
  engine.c) so a stale 0 from a BRANCH can never be misread as #DE even
  before the classifier fix lands.
- Known residual after the fix, to be measured not assumed: the DBT
  still resumes a handled fault at the STALE block-start EIP (re-running
  already-executed instructions of the block). Wine handled interp-era
  #PF deliveries at precise EIPs; block-granularity resume may surface
  re-execution side effects. Full precision needs per-access guest-pc
  tracking in the emitters — out of scope for the classification fix;
  flag any remaining divergence after it separately.

Not in this prescription (separate hunt, evidence below): why translated
code takes those host faults at all — near-NULL/garbage pointers and
garbage-region control flow that the interpreter does not produce. That
is the "at least one further DBT divergence downstream" C3 already
escalated, and it persists (in mutated form) after the delivery fix.

## Upstream divergence anchors (for the follow-up lane; not root-caused
## here)

From this lane's dbt run (trace `_scratch/c3f-run2.err`):

- tid=23: guest memcpy writes to cr2=0x100 (libc+0xC21EF block start) —
  a near-NULL destination pointer the interpreter never produces on this
  chain (interp runs `ok`).
- tid=30: a wine child thread faulting `mov edx, dword ptr gs:[8]`
  (libc+0x95736) with `gs=0000/00000000` (cr2=0x8) — GS/TCB not
  installed where the interp's TLS dance (T4c) always succeeds. Note
  this thread had already taken a HANDLED #PF inside the vDSO gateway
  (eip=df7fa330, cr2=a6a3b000), so the gs=0 state may be downstream
  corruption rather than a clone/SETTLS regression — undetermined.
- tid=23 late: execution inside PE ntdll `.debug_info` (eip and ret both
  in 0x7bd90000-class RVAs) — garbage-block execution, downstream of the
  handler crash-loop in this trace.
- C3 run-1 site B (0x7BD907B6) shows the garbage-target flavor existed
  pre-C6a/C6b (2061d1c predates both merges), so it is not attributable
  to the new flags-seam or IBTC code alone; but C6a (cond map polarity)
  and C6b (IBTC linking) are the prime NEW suspects for any
  pointer/branch divergence that remains after the delivery fix, and the
  difftest harness (tools/difftrace) is the right instrument.

Suggested first step for that lane: rerun the gate under dbt with the
delivery fix plus `I686RT_SIGTRACE=1` and classify every surviving
delivery's (eip, cr2) against module maps — the misdeliveries currently
drown out the underlying divergences.

## Note on master (regression found en route, blocking RC7b on a8d79fd)

Building master (a8d79fd) as-is, the chain dies BEFORE any #DE site, at
the wine wrapper's `test -x`:

    SYS 9 439 -> -38 (faccessat2 ENOSYS)
    SYS 9 307 -> -2 (bx=ffffff9c cx=4024d444 dx=00000001 si=ffffffd0)
    error: unable to find wine executable, this shouldn't happen.

and `statx` (383), newly implemented on master by the C1a merge
(f24db6e "fd-syscall class (_llseek, readv, msync, ftruncate64, statx)"),
returns `-2` for `/etc/ld.so.cache` (present in the sysroot; the C3-era
build returned -38 ENOSYS and glibc's fstatat64 fallback succeeded):

    STATX /etc/ld.so.cache
    SYS 9 383 -> -2 (bx=ffffff9c cx=3f02aac0 dx=00000800 si=000007ff)

The C3-era statx ENOSYS also silently changed glibc's fallback behavior
everywhere (C3's run-2 trace shows 383 -> -38 + STAT/fstatat64 pairs
where this lane's master run shows 383 -> -2 alone). Suspicion: the new
statx handler does not apply the sysroot path translation that
fstatat64/stat/access use (triage-3). Reproduction: `make build` on
master + the C3 gate command in an arm64 alpine container → GATE-RC=1
before wineboot. All diagnosis above was performed against the C3-era
tree (92787d1 checkout of src/ inside this worktree, restored to master
afterwards; signals_i386.c and interp.c are byte-identical between the
two, so the analysis applies to master unchanged).

## Commands and bounds (this lane's runs, verbatim gate body)

    export HOME=/tmp/whome WINEPREFIX=/wscratch/wprefix WINEDEBUG=-all
    export WINEDLLPATH=/w/_sysroot/debian-wine32-i386/usr/lib/i386-linux-gnu/wine
    export I686RT_ENGINE=dbt I686RT_SYSTRACE=1 I686RT_SIGTRACE=1   # run 2
    rm -rf "$WINEPREFIX"
    timeout -k 10 1800 /w/_build/i686rt \
        --sysroot /w/_sysroot/debian-wine32-i386 -- \
        /w/_sysroot/debian-wine32-i386/usr/bin/wine cmd /c "echo ok"
    # run 2 (c3f-diag2): GATE-RC=53, stdout empty, 3 sig=8 deliveries
    # run 3 (c3f-diag3, interp: engine env unset): GATE-RC=0, stdout "ok"

Containers: `c3f-diag1` (master build, early statx failure), `c3f-diag2`
(dbt + SIGTRACE), `c3f-diag3` (interp contrast) — each
`--platform linux/arm64 --memory 4g --cpus 4`, host `timeout 1920`,
`--rm` + `--cidfile`; all verified absent afterwards. Working traces
kept untracked under the worktree `_scratch/` (c3f-run1.err,
c3f-run2.{out,err}, c3f-interp.{out,err}); nothing pushed, no AI
identity in any commit.
