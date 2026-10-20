# Phase E — experiment task cards (frozen by the coordinator before fan-out)

Common rules for every E-lane (restated in each card prompt):

- Work ONLY inside your worktree `/Users/angerman/Projects/zw3rk/i686rt-e<NN>`
  (branch `lane/e-e<NN>`, already created from `master`). Never touch the main
  checkout, `master`, other lanes, `../a32rt`, or the `../hyper-linux` checkout.
  Never `git push` (the repo has no remote; never add one).
- Each experiment lives in `experiments/E<NN>-<slug>/` with `README.md`
  (hypothesis, procedure) and `FINDINGS.md`. `FINDINGS.md` must contain exactly
  one verdict line matching `^VERDICT: (PASS|FAIL|ANSWER: .+)$` as its first
  content line after the `# ` title, then **Evidence** (commands + observed
  output / source citations with file:line) and **Consequence for SPEC**.
- One acceptance check per card: `grep -m1 -E '^VERDICT: (PASS|FAIL|ANSWER: )' experiments/E<NN>-<slug>/FINDINGS.md`
  in your worktree must print the verdict line. Probe/build artifacts needed to
  produce the verdict belong under the experiment dir and are committed.
- Escalate (stop, commit what exists with an `ESCALATION:` note in FINDINGS.md,
  and report in your final message) when: the check fails twice, you need a file
  you don't own, or the card is ambiguous. Never widen scope.
- Commits: repository identity is already configured (Moritz Angermann
  <moritz@zw3rk.com>). Commit messages must not mention any AI agent/model/tool
  (no Cursor, Zcode, GLM, Claude, "generated with", etc.). One commit is enough.
- Environment: macOS arm64 (Apple Silicon), nix 2.35.3 with external-builders
  for `aarch64-linux` and `x86_64-linux`, docker Desktop (aarch64; can
  `docker run --platform linux/386|linux/amd64` via QEMU TCG), network access
  (curl / WebFetch). Reference repos (read-only): `../a32rt` @ d84feb3,
  `../hyper-linux` (master, built at `_build/hl`).

Cards:

- **E01-hvf-tso** — Can HVF set ACTLR_EL1 (Apple TSO bit) per vCPU?
  Primary probe: patched hl calls `hv_vcpu_get_sys_reg`/`hv_vcpu_set_sys_reg`
  on `HV_SYS_REG_ACTLR_EL1`, logs before/write-rc/after. Litmus only if
  writable. hl patch lives in a hyper-linux *worktree* `../hyper-linux-e01`
  (branch `exp/e01-tso`); archive the patch as
  `experiments/E01-hvf-tso/hl-tso-probe.patch`.
- **E02-ia32-cs** — Does `ia32_emulation=0` keep the 32-bit user CS? QEMU TCG
  x86_64 VM, kernel ≥ 6.7 with `CONFIG_IA32_EMULATION=y`, boot default vs
  `ia32_emulation=0`; probes: far-jmp into selector 0x23 + far-ret, `int $0x80`,
  and an i386 static ELF (baseline). Kernel from Alpine netboot `vmlinuz-virt`
  or nixpkgs cross-built via the x86_64-linux builder (verify `.config`).
- **E03-rosetta-elf32** — RosettaLinux behaviour on ELFCLASS32/EM_386. Boot an
  hl x86_64-linux guest (Rosetta path proven by
  `hyper-linux-examples#xmms.x86_64-linux`), exec a generated i386 static ELF
  (raw bytes, `mov eax,1; mov ebx,42; int 0x80`), capture exit code + stderr.
- **E04-task-size** — i386 compat TASK_SIZE on x86_64 kernels. Kernel source
  lookup (`arch/x86/include/asm/{page_64_types,processor,elf}.h` etc.), value +
  file:line citation.
- **E05-fpstate** — `_fpstate_32` layout + magic values. Kernel
  `arch/x86/include/uapi/asm/sigcontext.h` + glibc i386 usage.
- **E06-nixpkgs-attrs** — i686 cross attr names in nixpkgs (`pkgsCross.musl32`,
  `pkgsCross.gnu32`, `pkgsi686Linux`, …): eval + build attempts, plus which
  local path can produce/run i386 artifacts (nix builder vs docker 386).
- **E07-vdso-sysinfo** — glibc i386 vDSO symbol/version table + `%gs` SYSINFO
  offset. glibc `sysdeps/unix/sysv/linux/i386/*` + kernel
  `arch/x86/entry/vdso32/*`.
- **E08-fex-box86-tso** — FEX-Emu and Box86/Box64 x86 memory-ordering policies
  (source read; shallow/partial clones). Comparison table.
- **E09-wine-ldt** — Wine's LDT usage surface (partial clone of wine-mirror,
  `dlls/ntdll/unix/*signal_i386*`, ldt code): modify_ldt funcs, descriptor
  kinds, instructions touching LDT selectors.
- **E10-vm86** — vm86 feasibility: kernel `vm86_32.c` + `vm86.h` study, user
  survey (dosemu2/v86d/x86emu), plus a standalone C prototype interpreter that
  runs a 20-byte real-mode program at guest linear 0 and returns
  `VM86_INTx`; PASS = prototype returns correct regs + exit code.
