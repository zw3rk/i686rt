# E04 findings — top of the 32-bit compat user address space (TASK_SIZE) for i386 tasks on x86_64 kernels

VERDICT: ANSWER: TASK_SIZE(i386 compat on x86_64) = 0xFFFFE000 (kernel master f47d223627f8 [post-v7.3/7.4-rc, fetched 2026-10-20] and unchanged in every version checked back to v2.6.12, arch/x86/include/asm/page_64_types.h:59-65; conditional exception: 0xC0000000 with ADDR_LIMIT_3GB personality)

## Answer

- **Default** for a 32-bit compat task (`TIF_ADDR32` set, personality without
  `ADDR_LIMIT_3GB`): **`TASK_SIZE` = `IA32_PAGE_OFFSET` = `0xFFFFE000` =
  4 GiB − 8 KiB (2 pages)**. This bounds `TASK_SIZE`, `TASK_SIZE_LOW`,
  `TASK_SIZE_OF`, and `STACK_TOP` for the task.
- **Opt-in 3 GB variant**: with the `ADDR_LIMIT_3GB` personality bit
  (`PER_LINUX32_3GB` = `0x0008 | 0x8000000`), `IA32_PAGE_OFFSET` — and hence
  `TASK_SIZE`/`STACK_TOP` — becomes `0xC0000000`.
- **Native i386 kernel (contrast)**: `TASK_SIZE = __PAGE_OFFSET =
  CONFIG_PAGE_OFFSET`, default `0xC0000000` (`CONFIG_VMSPLIT_3G`; selectable
  down to `0x40000000`). Mainline has no `CONFIG_X86_4G`; the 4G/4G split was a
  2.4-era vendor/out-of-tree patch set. So `0xC0000000` is *not* the compat
  value on x86_64 — the card's hypothesis is **confirmed**, with the
  `ADDR_LIMIT_3GB` nuance above.

The exact source spelling of the constant is mixed-case `0xFFFFe000`.

## Evidence (definition chain, master f47d223627f8 unless noted; quotes verbatim)

1. **Who is a compat task.** `arch/x86/include/asm/thread_info.h:103`:
   `#define TIF_ADDR32 27 /* 32-bit address space on 64 bits */`. It is set at
   exec of an ELFCLASS32 binary: `arch/x86/include/asm/elf.h:176-177`
   `#define COMPAT_SET_PERSONALITY(ex) set_personality_ia32((ex).e_machine == EM_X86_64)`
   → `arch/x86/kernel/process_64.c:773-782`:

       void set_personality_ia32(bool x32)
       {
       	/* Make sure to be in 32bit mode */
       	set_thread_flag(TIF_ADDR32);
       	...
       }

   (`COMPAT_ELF_PLATFORM` is `"i686"`, elf.h:179. The x32 ABI also sets
   `TIF_ADDR32` — consistent, since x32 pointers are 32-bit too.)

2. **TASK_SIZE selection.** `arch/x86/include/asm/page_64_types.h:64-65`:

       #define TASK_SIZE		(test_thread_flag(TIF_ADDR32) ? \
       					IA32_PAGE_OFFSET : TASK_SIZE_MAX)

   with `TASK_SIZE_OF(child)` (66-67), `TASK_SIZE_LOW` (62-63, else-branch
   `DEFAULT_MAP_WINDOW = (1UL << 47) - PAGE_SIZE`), `STACK_TOP = TASK_SIZE_LOW`
   (69), `STACK_TOP_MAX = TASK_SIZE_MAX` (70). 64-bit `TASK_SIZE_MAX` is
   `task_size_max()` (line 53; `page_64.h:138`, 47-bit, or 56-bit with LA57) —
   irrelevant for compat.

3. **IA32_PAGE_OFFSET value.** `page_64_types.h:59-60`:

       #define IA32_PAGE_OFFSET	((current->personality & ADDR_LIMIT_3GB) ? \
       					0xc0000000 : 0xFFFFe000)

   `ADDR_LIMIT_3GB = 0x8000000` and `PER_LINUX32_3GB = 0x0008 | ADDR_LIMIT_3GB`
   (`include/uapi/linux/personality.h:24, 56-57`). **Default = `0xFFFFe000`.**

4. **Native i386 (32-bit kernel).** `arch/x86/include/asm/page_32_types.h:47-48`:
   `#define IA32_PAGE_OFFSET __PAGE_OFFSET`, `#define TASK_SIZE __PAGE_OFFSET`
   (comment line 45: "User space process size: 3GB (default)"), where
   `__PAGE_OFFSET = CONFIG_PAGE_OFFSET` (lines 17-18); `arch/x86/Kconfig:1446-1455`:
   `default 0xC0000000` with VMSPLIT_2G/2G_OPT/1G/3G_OPT variants. No
   `CONFIG_X86_4G` in mainline.

5. **mmap enforcement — hints, fixed mappings, search top.**
   - Generic: `mm/mmap.c:839` (`__get_unmapped_area`): `if (len > TASK_SIZE)
     return -ENOMEM;` and `mm/mmap.c:872`: `if (addr > TASK_SIZE - len) return
     -ENOMEM;` — the latter applies after `get_area`, so **`MAP_FIXED` at/above
     `0xFFFFE000` fails with `ENOMEM`** in a 32-bit task (for `MAP_FIXED` the
     arch performs "No address checking", `sys_x86_64.c:186-188`).
   - Non-fixed hint above the limit: `mmap_address_hint_valid()`
     (`arch/x86/mm/mmap.c:197-202`; doc at 163-165: "On 32bit this only checks
     whether @addr + @len is <= TASK_SIZE") returns false → the hint is
     *ignored*, not fatal, and the search continues below the compat mmap base.
   - Search top for a 32-bit syscall: `arch/x86/kernel/sys_x86_64.c:99-120`
     (`find_start_end`): `if (in_32bit_syscall()) *end = task_size_32bit();`
     where `arch/x86/mm/mmap.c:31-34`:

         unsigned long task_size_32bit(void)
         {
         	return IA32_PAGE_OFFSET;
         }

     i.e. the bottom-up unmapped-area search top is exactly `0xFFFFE000`
     (default). The topdown `high_limit` bump into the full address space is
     gated by `!in_32bit_syscall()` (`sys_x86_64.c:226-228`), so it never
     applies to ia32 tasks. The compat mmap bases themselves are laid out from
     `task_size_32bit()` (`arch/x86/mm/mmap.c:133-143`), and
     `TASK_UNMAPPED_BASE = PAGE_ALIGN(TASK_SIZE_LOW / 3)`
     (`arch/x86/include/asm/processor.h:695-696`).
   - `mremap`: `mm/mremap.c:1903` `if (vrm->new_len > TASK_SIZE) return
     -EINVAL;` and `:1911` `if (vrm->new_addr > TASK_SIZE - vrm->new_len)
     return -EINVAL;`.
   - Since ia32 `mmap`/`mmap2` syscall arguments are 32-bit, hints cannot
     exceed `0xFFFFFFFF` anyway; the only reachable "above" band is
     `[0xFFFFE000, 0xFFFFFFFF]`, and it is unobtainable (fixed → `ENOMEM`,
     hint → relocated).

6. **Stack placement / guard gap (cheap citations).** Compat `STACK_TOP` =
   `TASK_SIZE_LOW` = `IA32_PAGE_OFFSET` = `0xFFFFE000` (default); stack
   randomization for 32-bit is `__STACK_RND_MASK(true) = 0x7ff` pages
   (`elf.h:322-323`), i.e. the initial stack top lands up to ~8 MiB below
   `0xFFFFE000`. The stack guard gap is `mm/mmap.c:955`:
   `unsigned long stack_guard_gap = 256UL<<PAGE_SHIFT;` (1 MiB default,
   `stack_guard_gap=` boot param at 957-968); `arch/x86/mm/mmap.c:86` adds
   `stack_maxrandom_size() + stack_guard_gap` padding when picking
   `mmap_base` below the stack.

7. **Cross-version stability** (all `0xc0000000 : 0xFFFFe000`, default
   `0xFFFFE000`; see sources.txt §14 for full quotes):
   - v2.6.12 (2005, first git commit): `include/asm-x86_64/processor.h:168` —
     ternary already present (then used directly by ia32 compat syscall paths).
   - v3.17: `arch/x86/include/asm/processor.h:903-907` (keyed `TIF_IA32`).
   - v4.19: `processor.h:891-897` (keyed `TIF_ADDR32`).
   - v5.15 and v6.12 (LTS): `page_64_types.h:70-76`.
   - master f47d223627f8 (post-v7.3, 2026-10-20): `page_64_types.h:59-65`.

8. **Runtime corroboration attempt (documented as distorted).** Docker Desktop
   on this Apple Silicon host is `linux/arm64` (server 29.8.2); `--platform
   linux/386 alpine cat /proc/self/maps` runs under qemu-user, which
   *virtualizes* `/proc/self/maps` into guest-side entries in qemu's own
   synthetic layout (observed top `0x408ac000`, `[stack]` at `0x40001000`,
   guest musl-i386 libs). The aarch64 host kernel has no ia32 compat mode at
   all, so this cannot corroborate an **x86_64** kernel's compat `TASK_SIZE`.
   Discarded; kernel source is the ground truth (exactly the failure mode the
   card anticipated).

## Consequence for SPEC

- **D4 confirmed and now exact.** SPEC D4 currently says: "Guest user top =
  `0xFFFFE000` (i386 TASK_SIZE on x86_64 compat is 4 GiB [U exact value])".
  The `[U]` is resolved: the mappable guest user range for an i386 compat task
  on x86_64 is `[0, 0xFFFFE000)` = **4 GiB − 8 KiB**; the top 8 KiB
  (`[0xFFFFE000, 0x100000000)`) can never be mapped by a real compat task.
  Patch D4's parenthetical to "i386 TASK_SIZE on x86_64 compat = 0xFFFFE000
  (E04)".
- **rt32 VMA manager bounds.** The copied `rt32_vm_*` gap finder and the
  `mmap2/mmap/mremap/munmap/mprotect` emulation must enforce guest
  `addr + len <= 0xFFFFE000`: fixed placements above → `ENOMEM` (mmap) /
  `EINVAL` (mremap), oversized `len` → `ENOMEM`; a non-fixed hint above the
  limit must be *ignored and relocated* (kernel behaviour, Evidence 5), not
  rejected. Effective-address wrap (D4/D7) already keeps guest EAs ≤
  `0xFFFFFFFF`; additionally keep `[0xFFFFE000, 0x100000000)` permanently
  unmapped in the window so stray accesses fault like native.
- **personality(2) emulation.** i686rt must track `ADDR_LIMIT_3GB`
  (`PER_LINUX32_3GB`): when set, guest `TASK_SIZE`/`STACK_TOP`/mmap-rejection
  top become `0xC0000000`. (Also relevant: `ADDR_COMPAT_LAYOUT` selects the
  legacy bottom-up mmap base; `ELF_ET_DYN_BASE` = `0x400000` for ia32 —
  `elf.h:233-234`.)
- **Stack/vDSO placement.** Initial guest stack should mirror native: top
  just below `0xFFFFE000` minus up to ~8 MiB randomization; the compat vDSO
  lives in the normally mappable region below the stack, so D4's "No — vDSO
  placed by mmap in window" stands; no top-page reservation is needed.
- **vm86 (Phase 8).** The v86 address space is the low 1 MiB (plus a return
  trampoline), far below both `0xC0000000` and `0xFFFFE000`; the compat top
  limit does not constrain vm86. The relevant reservation there is the low
  window `[0x0, 0x100000)`; a real kernel enters v86 mode from a `TIF_ADDR32`
  task without touching `TASK_SIZE` selection.
- No escalation needed: sources agree with the card across all versions
  checked (v2.6.12 → master); the only refinement is the `ADDR_LIMIT_3GB`
  opt-in to `0xC0000000`, which is an opt-in personality, not the default
  compat value.

## Caveats

- `x86_64` `TASK_SIZE_MAX` depends on LA57 (47 vs 56 bits) — never applies to
  `TIF_ADDR32` tasks.
- Line numbers are for the exact refs fetched 2026-10-20; they drift between
  releases (v5.15/v6.12 vs master), values do not.
- No live x86_64 Linux host was available for a genuine compat-task
  `/proc/self/maps`; the Docker/arm64 attempt was qemu-distorted (Evidence 8).
  The i686rt lima oracle is aarch64 and likewise cannot check this; a future
  x86_64 tier-2 host could.
