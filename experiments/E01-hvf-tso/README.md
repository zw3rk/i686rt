# E01 — hvf-tso: Apple HW strong-ordering (TSO) per vCPU via Hypervisor.framework

Hypothesis (expected FAIL): the TSO bit of `ACTLR_EL1` is not settable from
the HVF public API (`hv_vcpu_set_sys_reg` write ignored or `HV_ERROR`), so
software TSO (LDAPR/STLR + LSE atomics) remains mandatory for the i686rt DBT.

Question: can a guest vCPU's `ACTLR_EL1` (Apple TSO bit) be written via
`hv_vcpu_set_sys_reg`, and is the value honored?

## TSO bit encoding (research, pre-run)

- `ACTLR_EL1.EnTSO` is **bit 1** (value `0x2`).
- Apple SDK, `Hypervisor.framework/Headers/hv_vcpu_types.h`:

  ```
  /*!
   @abstract The ACTLR_EL1 register
   @discussion
      This only allows getting / setting of the ACTLR_EL1.EnTSO bit (index 1). Setting this bit to 1
      will cause the vcpu to use a TSO memory model, whereas clearing it will cause the vcpu to use
      the default ARM64 memory model (weakly ordered loads / stores).
  */
  HV_SYS_REG_ACTLR_EL1 API_AVAILABLE(macos(15.0)) = 0xc081,
  ```

- AsahiLinux docs, `docs/hw/cpu/system-registers.md` (repo
  `AsahiLinux/docs`, branch `main`):

  ```
  #### ACTLR_EL1 (ARM standard-not-standard)

  * [1] Enable TSO
  ```

- Cross-check: hyper-linux `src/syscall.h` (PR_SET/GET_MEM_MODEL, "From
  Asahi Linux: include/uapi/linux/prctl.h") and `src/syscall.c:4223`
  already *read* `HV_SYS_REG_ACTLR_EL1` bit 1 via `hv_vcpu_get_sys_reg`
  for `PR_GET_MEM_MODEL`; the write path was untested before this probe.

Note: the HVF sysreg ID is `API_AVAILABLE(macos(15.0))`. This probe ran on
macOS 26.5.2 where it exists; on hosts older than macOS 15.0 the register
ID itself is unavailable.

## Procedure

1. Create an isolated hyper-linux worktree (main checkout untouched):

   ```
   git -C /Users/angerman/Projects/zw3rk/hyper-linux worktree add \
       /Users/angerman/Projects/zw3rk/hyper-linux-e01 -b exp/e01-tso
   ```

2. Patch `src/hl.c` immediately after the vCPU-creation block at
   `hv_vcpu_create` (~line 1918): read `HV_SYS_REG_ACTLR_EL1`, write
   `old | (1ULL << 1)` via `hv_vcpu_set_sys_reg`, log the `hv_return_t`,
   re-read. All logging to stderr with the `E01-PROBE:` prefix. The exact
   patch is archived as `hl-tso-probe.patch` (26 inserted lines, no other
   changes).

3. Build the way the repo builds hl, inside the worktree only. The `ci`
   dev shell (`nix develop .#ci`) provides clang + GNU objcopy + xxd
   without the remote Linux builder. One wrinkle: the nix apple-sdk clang
   does not find `zlib.h` (hl links `-lz`), so pass nixpkgs zlib via
   clang's env include/lib search paths — the Makefile is not modified:

   ```
   cd /Users/angerman/Projects/zw3rk/hyper-linux-e01
   nix develop .#ci --command bash -c '
     ZLIB=$(nix build --no-link --print-out-paths nixpkgs#zlib)
     ZLIBDEV=$(nix build --no-link --print-out-paths nixpkgs#zlib.dev)
     export CPATH="$ZLIBDEV/include" LIBRARY_PATH="$ZLIB/lib:$ZLIBDEV/lib"
     make hl'
   ```

   This compiles with the repo's Curated C11 flags and ad-hoc signs with
   `entitlements.plist` (Hypervisor entitlement), exactly like the normal
   `make hl` flow.

4. Run the patched hl far enough to create a vCPU — a full Linux boot is
   unnecessary; any guest ELF reaches vCPU creation first. Used the
   freestanding aarch64 asm hello-world from the main checkout's prebuilt
   `_build` (read-only reference), with cwd inside this experiments dir:

   ```
   cd /Users/angerman/Projects/zw3rk/i686rt-e01/experiments/E01-hvf-tso
   cp /Users/angerman/Projects/zw3rk/hyper-linux/_build/test-hello \
      ./test-hello-guest
   timeout 60 /Users/angerman/Projects/zw3rk/hyper-linux-e01/_build/hl \
       ./test-hello-guest > probe-run.log 2> probe-run.err
   ```

   Guest output `hello` on stdout, exit 0 (see `probe-run.log`,
   `probe-run.err`): the EnTSO write did not break the vCPU; the guest
   executed to completion with the bit set.

5. Secondary (2-vCPU store-buffer/MP litmus): not run, per the card.
   Marked [U] in FINDINGS.md.

6. Archived the patch: `git -C .../hyper-linux-e01 diff master >
   .../experiments/E01-hvf-tso/hl-tso-probe.patch`, then removed the
   worktree (`git worktree remove`).

## Host

Apple M5 (Mac17,3), macOS 26.5.2 (Build 25F84), Darwin 25.5.0 arm64.

## Files

- `hl-tso-probe.patch` — the exact hl.c probe patch (against
  hyper-linux master = 20b78b1).
- `probe-run.err` — probe stderr (the answer).
- `probe-run.log` — guest stdout (`hello`).
- `FINDINGS.md` — verdict, evidence, consequence for SPEC.
