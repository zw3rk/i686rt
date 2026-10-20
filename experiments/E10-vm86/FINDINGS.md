# E10 — vm86/vm86old in-process emulation feasibility

VERDICT: PASS

Hypothesis confirmed: the vm86()/vm86old() contract is a pure guest-state
machine (real-mode interpreter over the low 1 MiB of the guest window plus a
set of well-defined exit conditions) and needs nothing from a host kernel's
vm86 implementation. The only host-coupled corner — hardware IRQ passing via
`VM86_REQUEST_IRQ` — has no user that reaches it when running under a
translator (dosemu2 only calls it from its native i386-kernel backend;
v86d and X11 x86emu never do), so stubbing it per SPEC §4 Phase 8.2 is
sufficient. The prototype below executes the card's fixed real-mode program
and exits with the kernel-exact `VM86_INTx(0x10)` packing.

## 1. Kernel ABI (torvalds/linux master, read 2026-10-20)

Files: `arch/x86/include/uapi/asm/vm86.h` (note: the uapi header lives under
`arch/x86/`, not `include/uapi/asm/`), `arch/x86/kernel/vm86_32.c`,
`arch/x86/kernel/signal.c`, `arch/x86/kernel/traps.c`. vm86_32.c is built
only for 32-bit x86 kernels — on x86_64 the syscalls do not exist, which is
why every 64-bit user already runs v86 workloads on userspace interpreters
(§2).

### 1.1 Syscall surface

- `vm86old` = `SYSCALL_DEFINE1(vm86old, struct vm86_struct *)`
  (vm86_32.c:170-173) → `do_sys_vm86(..., plus=false)`.
- `vm86` = `SYSCALL_DEFINE2(vm86, cmd, arg)` (vm86_32.c:176-196):
  - `VM86_REQUEST_IRQ` / `VM86_FREE_IRQ` / `VM86_GET_IRQ_BITS` /
    `VM86_GET_AND_RESET_IRQ` → `do_vm86_irq_handling` (:179-183);
  - `VM86_PLUS_INSTALL_CHECK` → returns 0 (:184-191; the historical
    access_ok-as-address trick is documented in the comment);
  - `VM86_ENTER` / `VM86_ENTER_NO_BYPASS` → `do_sys_vm86(..., plus=true)`
    (:194-195). i386 syscall numbers: vm86old=113, vm86=166.
- Entry marshalling (do_sys_vm86, :199-291): `copy_from_user` splits at
  `offsetof(struct vm86_struct, int_revectored)` (:242-243), then the two
  bitmaps (:276-283), then `vm86plus` only when `plus` — and `is_vm86pus`
  is set kernel-side (:284-291). Registers are read field-by-field
  (:256-271); `__null_ds..gs` and `orig_eax` are ignored on entry.
  `VM86_SCREEN_BITMAP` → `-EINVAL` (:247-252).
- Exit marshalling (save_v86_state, :96-165): writes all registers back to
  the user struct (:119-134), deliberately never writes `screen_bitmap`
  (:136-139), restores the 32-bit context, and returns the exit code in
  `eax` (:156) — i.e. the syscall return value *is* the packed exit code.
- Flags sanitize on entry: `VEFLAGS = user flags`; real flags =
  `(user & SAFE_MASK) | (pm flags & ~SAFE_MASK) | VM` (:296-304);
  `SAFE_MASK = 0xDD5`, `RETURN_MASK = 0xDFF` (:93-94). `cpu_type` selects
  `veflags_mask` (286→0, 386→NT|IOPL, 486→+AC, else +ID; :308-321).
- `security_mmap_addr(0)` guard → `-EPERM` when the task may not map VA 0
  (:208-232; the comment names DOSEMU and vbetool). **Irrelevant for
  i686rt**: guest linear 0 lives at window base G inside `[G, G+4 GiB)`;
  under hl offset mode G = 4 GiB, so the emulator never maps host VA 0.

### 1.2 Structs (vm86.h)

- `struct vm86_regs` (:63-91): ebx, ecx, edx, esi, edi, ebp, eax,
  `__null_ds/es/fs/gs`, orig_eax, eip, `cs` (u16 + pad halfword), eflags,
  esp, `ss` (u16 + pad), then the v86-specific `es/ds/fs/gs` (u16 + pad
  each). Halfword paddings are observable ABI (mismatched copies are
  EFAULT-grade bugs).
- `struct revectored_struct` (:93-95): `unsigned long __map[8]` = 256 bits,
  bit `n` set = interrupt n revectored.
- `struct vm86_struct` (:97-104): regs, flags, screen_bitmap (unused,
  preserved on exit), cpu_type, int_revectored, int21_revectored.
- `struct vm86plus_info_struct` (:111-118): bitfields
  `force_return_for_pic`, `vm86dbg_active`, `vm86dbg_TFpendig`, `unused:28`,
  `is_vm86pus`, plus `vm86dbg_intxxtab[32]`.
- `struct vm86plus_struct` (:119-127): vm86_struct + vm86plus.

### 1.3 Exit codes (vm86.h:30-44) and their generation sites

Packing: `VM86_TYPE(r) = r & 0xff`, `VM86_ARG(r) = r >> 8` (:30-31).

| code | value | generated at |
| --- | --- | --- |
| `VM86_SIGNAL` | 0 | signal.c:261 `save_v86_state(regs, VM86_SIGNAL)` when a signal must be delivered |
| `VM86_UNKNOWN` | 1 | handle_vm86_fault default (vm86_32.c:680-681) and simulate_sigsegv (:702-713) |
| `VM86_INTx` | 2 | do_int cannot_handle `VM86_INTx + (i << 8)` (:524); vm86dbg intxxtab hit (:624-628) |
| `VM86_STI` | 3 | check_vip: VIF and VIP both set after popf/iret/sti (:686-691) |
| `VM86_PICRETURN` | 4 | force_return_for_pic and IF set at fault return (:693-697) |
| `VM86_TRAP` | 6 | int1/int3 while is_vm86pus: `VM86_TRAP + (trapno << 8)` (:531-534) |

There is no exit code 5 (vm86.h:44 jumps 4 → 6).

### 1.4 The revectored-int protocol (do_int, vm86_32.c:494-525)

`cannot_handle` (→ `VM86_INTx + (i << 8)`, guest regs otherwise intact,
IP already past the `int` byte(s)) when any of: `cs == BIOSSEG` (0xf000,
:501); bit i set in `int_revectored` (:503); i == 0x21 and AH set in
`int21_revectored` (:505); IVT entry at linear `i*4` unreadable (:507-509);
IVT target segment == BIOSSEG (:510-511). Otherwise the kernel vectors
in-guest: pushes vflags/cs/ip on ss:sp (:512-514), jumps through the IVT
(:515-517), clears TF/IF/AC (:518-520). Emulating exactly this protocol in
`src/os/vm86.c` + `src/interp/v86.c` reproduces the ABI users depend on.

### 1.5 v86 faults, traps, VIF/VIP

- In v86 mode the IOPL-sensitive instructions fault #GP; handle_vm86_fault
  (vm86_32.c:547-714, entered from traps.c:927) interprets a prefix stream
  (0x66/0x67/segment/rep, :569-583) then pushf(0x9c), popf(0x9d),
  int(0xcd), iret(0xcf), cli(0xfa), sti(0xfb); anything else →
  VM86_UNKNOWN. `hlt` therefore surfaces as VM86_UNKNOWN via the default
  case — the prototype mirrors this.
- Traps 0,1,3,4,5 are forwarded to handle_vm86_trap (traps.c:285-289);
  with is_vm86pus, 1/3 → VM86_TRAP, others → do_int (vm86_32.c:531-537);
  without it, trap 1 → SIGTRAP to the guest (:539-544). TF single-step at
  fault return → DB trap (:698-699, traps.c:1347).
- IF is virtual: set_IF/clear_IF write VEFLAGS.VIF (:345-353); get_vflags
  composes the architected view — real flags minus IF, IF from VIF, IOPL
  forced on, cpu_type bits merged (:397-405).

### 1.6 IRQ passing (vm86_32.c:716-830) — the only host-coupled piece

`VM86_REQUEST_IRQ` requires CAP_SYS_ADMIN (:811) and binds a *real host
IRQ line* via `request_irq` (:815); delivery is one of the allowed signals
(0/USR1/USR2/IO/URG/UNUSED, :728-730) and the line stays disabled until
`VM86_GET_AND_RESET_IRQ` re-arms it (:732-755, :777-795). This cannot be
emulated by a user-mode translator (there is no host IRQ line to borrow,
and under hl the host owns the IRQ domain). It is also not needed: see §2.

### 1.7 A20

vm86_32.c contains no A20 gate code (no `a20` matches); the 20-bit wrap of
`seg<<4 + off` is architectural CPU behavior, and the guest-visible gate
(port 0x92 / PS/2) is serviced by guest BIOS code, not by the vm86 layer.
i686rt models A20-off as the default (mask to 0xFFFFF in the linear
computation); the window is 4 GiB so an A20-on model simply drops the mask.

## 2. User survey

- **dosemu2** (master snapshot 2026-10-17, depth-1 clone):
  - `src/base/emu-i386/do_vm86.c:445` — native backend calls
    `vm86_plus(VM86_ENTER, &x->vm86compat)` ("need to use vm86_plus for now
    as otherwise dosdebug doesn't work"); :447-452 documents the VM86_STI /
    VIP nuance against kernel commit 5ed92a8ab (4.3-rc1).
  - `do_vm86.c:479-497` — three interchangeable engines behind the same
    `vm86_struct` contract: `e_vm86` (simx86 userspace interpreter),
    `kvm_vm86`, `true_vm86` (native i386 only; on x86_64 without
    emu/KVM it just exits).
  - `do_vm86.c:533-572` — consumes all six exit types (UNKNOWN, STI, INTx,
    TRAP, PICRETURN, SIGNAL).
  - `src/base/emu-i386/cpu.c:593-596` — probes `VM86_PLUS_INSTALL_CHECK`
    both old-style and via `vm86_plus`.
  - `src/arch/linux/async/signal.c:426` —
    `vm86_plus(VM86_REQUEST_IRQ, (SIGIO << 8) | irq)` **only in the native
    backend**; the interpreter and KVM backends never issue it.
  - `src/base/emu-i386/simx86/cpu-emu.c:932-957,988` — its own
    `handle_vm86_fault` and a comment "This emulates VM86_ENTER":
    dosemu2 already reimplements the whole vm86 contract in userspace when
    no kernel vm86 exists. `src/base/emu-i386/kvm.c:1042-1055` does the
    same for KVM ("works like handle_vm86_fault in the Linux kernel").
  - `src/include/vm86_compat.h` — a verbatim ABI replica for
    non-i386/64-bit builds.
  - Verdict: needs VM86_ENTER + the full exit-code set + both revectored
    bitmaps + `force_return_for_pic`; vm86plus (not just vm86_struct);
    IRQ subfunctions only in the native backend, which cannot run under a
    translator anyway.
- **v86d 0.1.10** (orig tarball from the Debian pool; the upstream repos
  the card names are gone — github.com/mrpont/v86d and lkundrak/v86d both
  404 as of 2026-10-20): runs v86 code for kernel drivers (VESA/int10 at
  boot) as a netlink daemon (`README:4-8`). It maps the low megabyte
  (IVT/BDA, VRAM, VBIOS, SBIOS) from `/dev/mem` (`v86_mem.c:222-315`) and
  has two backends: LRMI/vm86 on 32-bit x86 (`v86_lrmi.c`) and a pure
  x86emu interpreter (`v86_x86emu.c`). `README` §3.2:39 — "On other arches
  or 64-bit systems, the code is always run by x86emu."
- **X11 x86emu** (freedesktop xserver master; the wildwildwest/x86emu repo
  the card names is gone — 404): the xserver vendors the "Realmode X86
  Emulator Library" (SciTech 1996-1999) at `hw/xfree86/x86emu/x86emu.h`.
  The int10 module's own docs (`hw/xfree86/int10/INT10.HOWTO:72-78`) state
  it executes BIOS code "in vm86 mode of a real x86 CPU" or via "the x86emu
  real mode emulator"; `meson_options.txt:64-66` makes the backend a combo
  with default "usually x86emu", and the x86emu backend builds
  `generic.c + xf86x86emu.c + x86emu.c` (`hw/xfree86/int10/meson.build`).
  The X server's int10/VBE path — the flagship non-DOS vm86 user —
  defaults to a pure interpreter.

Survey conclusion: every serious user either is already interpreter-only
(v86d on non-i386, X11 x86emu) or has a userspace-interpreter fallback
(dosemu2 simx86/KVM). The kernel-syscall parts they need are
VM86_ENTER/PLUS_INSTALL_CHECK, the six exit codes, the revectored-int
protocol, and vm86plus bits — all pure guest-state emulation.

## 3. Prototype

`proto.c` (this directory): standalone Curated C11, no dependencies,
builds and runs natively on macOS:

```
clang -std=c11 -Wall -Wextra -Werror=vla -pedantic -o proto proto.c && ./proto
```

It models the 1 MiB guest window, real-mode `seg<<4+off` addressing with
20-bit wrap (A20 off), the v86 register set with VIF/VIP/TF/DF eflags
stubs, a fetch/decode/execute interpreter (prefix stream per
vm86_32.c:569-583; B8+r mov r16,imm16; 89 /r reg-reg; CD int; F4 hlt; any
unimplemented opcode → VM86_UNKNOWN), and the full do_int protocol of §1.4
(BIOSSEG checks, int21_revectored AH match, IVT vectoring with
flags/cs/ip push, or VM86_INTx exit). Output (observed):

```
vm86 exit: type=2 arg=0x10 (raw=0x1002)
AX=0x1234 BX=0x5678 CX=0x1234 DX=0x0000
SI=0x0000 DI=0x0000 BP=0x0000 SP=0xfffe
CS=0x0000 IP=0x7c0a SS=0x0000 eflags=0x00000002 (VIF=0 VIP=0 TF=0 DF=0)
PROTO: PASS
```

(type=2=VM86_INTx, arg=0x10, regs exactly as expected — note IP=0x7c0a is
*past* the `int 0x10` instruction, matching the kernel's cannot_handle
path; exit status 0.) The header comment block maps every piece to the
planned i686rt artifacts (`src/interp/v86.c`, `src/os/vm86.c` marshalling,
window/G offset-mode placement).

## 4. Blockers

None found for the emulation core. The single host-coupled element —
`VM86_REQUEST_IRQ`/`FREE_IRQ`/`GET_IRQ_BITS`/`GET_AND_RESET_IRQ` (real
host IRQ lines + CAP_SYS_ADMIN) — cannot and need not be emulated: no
surveyed user reaches it without a 32-bit host kernel vm86, and such users
already have interpreter fallbacks.

## 5. Consequence for SPEC

- Phase 8.1/8.2 shape confirmed as written; the exit-condition list is
  exactly the six codes of §1.3 (no code 5) and the interpreter path is
  sufficient (D8). Encode the §1.4 do_int protocol verbatim (including
  BIOSSEG checks and int21_revectored AH matching) in `src/os/vm86.c`.
- Marshalling details worth pinning in 8.2: entry copy splits at
  `offsetof(vm86_struct, int_revectored)`; `is_vm86pus` is kernel-side;
  `screen_bitmap` is preserved on exit; exit code is returned in eax;
  `__null_*`/`orig_eax` ignored on entry.
- **Open question #7 resolved: stub the IRQ subfunctions** (return
  -EINVAL/-ENOSYS per SPEC 8.2's existing plan). Rationale in §2/§4.
- Window placement (SPEC §5 item 4): guest low 1 MiB at window base G;
  under hl offset mode G = 4 GiB so guest 0 never collides with the
  host-owned low VA — the kernel's mmap_min_addr concern (§1.1) does not
  apply to i686rt.
- A20-off 20-bit wrap is the default linear-addressing rule for v86
  (§1.7); expose A20 state later only if a guest toggles the gate.
