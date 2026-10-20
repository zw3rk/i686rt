# E01 — hvf-tso findings

VERDICT: PASS

The hypothesis (expected FAIL) is refuted on this host: the Apple TSO bit
`ACTLR_EL1.EnTSO` (bit 1, `0x2`) IS settable from the HVF public API via
`hv_vcpu_set_sys_reg` (returns `HV_SUCCESS`, not ignored, no `HV_ERROR`),
the value sticks on read-back, the vCPU stays healthy, and Apple's SDK
documentation states the bit is honored as a TSO memory model for the
vCPU. The behavioral half (2-vCPU store-buffer litmus) was not run per
the card and is marked [U] below.

## Evidence

Primary probe (patched hl, log `probe-run.err`; `0` == `HV_SUCCESS` for
every `hv_return_t`):

```
E01-PROBE: get ACTLR_EL1 rc=0 before=0x0
E01-PROBE: set ACTLR_EL1|EnTSO rc=0 wrote=0x2
E01-PROBE: get ACTLR_EL1 rc=0 after=0x2 entso_stuck=1
```

(`probe-run.err`, quoted verbatim; every rc is `hv_return_t` `0` == `HV_SUCCESS`)

- `hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ACTLR_EL1, &v)` -> `HV_SUCCESS`,
  initial value `0x0` (EnTSO clear on a fresh vCPU).
- `hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_ACTLR_EL1, 0x0 | 0x2)` ->
  `HV_SUCCESS` (rc=0). The write is neither rejected nor errored.
- Re-read returns `0x2`: the bit sticks.
- The guest (freestanding aarch64 hello, `test/hello.S`) ran to completion
  afterwards: stdout `hello`, hl exit code 0 (`probe-run.log`). The write
  did not break the vCPU.
- Host: Apple M5 (Mac17,3), macOS 26.5.2 (25F84), Darwin 25.5.0 arm64.

TSO bit encoding and sources:

- `ACTLR_EL1.EnTSO` = bit index 1, value `0x2`.
- Apple SDK `Hypervisor.framework/Headers/hv_vcpu_types.h`:
  `HV_SYS_REG_ACTLR_EL1 = 0xc081`, `API_AVAILABLE(macos(15.0))`, with the
  doc comment: "This only allows getting / setting of the
  ACTLR_EL1.EnTSO bit (index 1). Setting this bit to 1 will cause the
  vcpu to use a TSO memory model, whereas clearing it will cause the
  vcpu to use the default ARM64 memory model (weakly ordered loads /
  stores)." This is Apple's authoritative statement that the value is
  honored (only this one bit is settable through the HVF view of the
  register).
- AsahiLinux docs (`AsahiLinux/docs`, `docs/hw/cpu/system-registers.md`):
  "#### ACTLR_EL1 (ARM standard-not-standard) ... * [1] Enable TSO".
  (Related Apple-internal knobs exist in `SYS_APL_HID9_EL1[16]` "TSO
  Enable"; not reachable via the HVF public API.)
- Prior art in-repo: hyper-linux `src/syscall.c:4223` already reads this
  bit via `hv_vcpu_get_sys_reg` for `PR_GET_MEM_MODEL`; FEX-Emu enables
  hardware TSO only through kernel-mediated paths (their
  `FEXUnixLib` `SetHardwareTSOControl`, and KVM on Asahi), i.e. no
  userspace/HVF direct-write prior art contradicts this result.

Version caveat:

- `HV_SYS_REG_ACTLR_EL1` is `API_AVAILABLE(macos(15.0))`. On this
  macOS 26.5 host it exists and works. On HVF hosts older than macOS
  15.0 the register ID does not exist and the write cannot be attempted;
  any consumer must gate on the host OS version (or a capability bit).
- `sysctl hw.optional.arm.FEAT_TSO` returns nothing on this host, so
  that sysctl cannot be used as a host-side feature gate; the SDK
  availability macro is the gate.

Secondary (behavioral confirmation) — [U], not run:

- A message-passing (store-buffer/MP) litmus needs 2 vCPUs running the
  TSO memory model. The probe sets EnTSO only on hl's primary vCPU
  (`src/hl.c` `hv_vcpu_create`, ~line 1918); per the card, multi-vCPU
  hl was not implemented. Note for a future follow-up: hl does create
  additional per-thread vCPUs in `src/fork_ipc.c` (lines ~2190, ~2624,
  ~2951), so a threaded guest plus EnTSO writes at those creation sites
  would be the natural 2-vCPU litmus vehicle. Until then, "honored"
  rests on the value round-trip plus Apple's documented semantics, not
  on an observed ordering change.

## Consequence for SPEC (D5, A32H_CAP_HW_TSO open question #1)

- Open question #1 ("can hl/hvf turn on Apple HW TSO per vCPU?") is
  answered YES on Apple Silicon with macOS >= 15.0: one
  `hv_vcpu_set_sys_reg(HV_SYS_REG_ACTLR_EL1, old | 0x2)` call per vCPU
  before first `hv_vcpu_run`, `HV_SUCCESS`, bit sticks, guest unaffected.
- D5's software TSO baseline is still required and must not be dropped:
  - i686rt's own translator code (static musl aarch64-linux user-mode
    process) executes as plain EL0 code; `ACTLR_EL1` is not writable
    from EL0. HW TSO applies only when the runtime runs as an hl guest
    (Phase 6+, a32rt host contract) AND hl sets the bit on every vCPU,
    including the per-thread vCPUs created on `clone(CLONE_VM)`.
  - lima (ground-truth oracle) and any non-Apple ARM64 host have no
    such bit; portability demands the LDAPR/STLR + LSE software path
    stays the default.
  - TSO fixes load/store ordering only; LOCK-prefixed RMW still needs
    LSE atomics regardless. `--x87-80`, EFLAGS and sigframe semantics
    are unaffected by this bit.
- Practical shape if pursued later (Phase 6+ territory, D15 gating): hl
  exposes an `A32H_CAP_HW_TSO` capability over the existing
  `/dev/a32host` + `A32H_ABI 1.0` contract, and i686rt then may use
  plain loads/stores while single-threaded, keeping the TSO-mode
  re-translation path for hosts without the capability. This is an hl
  change and is out of scope before Phase 6; no SPEC/GOAL/docs were
  modified by this lane.
