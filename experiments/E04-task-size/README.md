# E04 — TASK_SIZE for i386 compat tasks on x86_64 Linux kernels

Experiment card E04 (task-size), Phase E. Lane `lane/e-e04`, worktree
`../i686rt-e04`.

## Hypothesis

`TASK_SIZE` for a 32-bit (compat, `TIF_ADDR32`) task on an x86_64 kernel is
`0xFFFFE000` (= 4 GiB − 8 KiB), via the `IA32_PAGE_OFFSET` definitions — not
`0xC0000000`, which is the native-i386 3G/1G split value.

## Method

Kernel-source lookup (no implementation code; Phase E gate):

- Primary source: torvalds/linux master `f47d223627f80cb7a1eb14c585fe6cb35de5e984`
  (fetched 2026-10-20; post-v7.3, 7.4-rc cycle). Current stable at fetch time:
  7.2.11; longterm 6.12.113.
- Trace the full definition chain: who sets `TIF_ADDR32` at exec, how
  `TASK_SIZE`/`TASK_SIZE_LOW`/`STACK_TOP` select on it, what
  `IA32_PAGE_OFFSET` evaluates to (including the `ADDR_LIMIT_3GB` personality
  variant), the native-i386 contrast (`page_32_types.h` + `CONFIG_PAGE_OFFSET`),
  and every enforcement site (mmap hint/fixed, unmapped-area search top,
  mremap) plus `stack_guard_gap`.
- Cross-version stability: tags v2.6.12 (first git commit), v3.17, v4.19,
  v5.15, v6.12 (LTS).
- Optional runtime corroboration via Docker `--platform linux/386` (documented;
  turned out distorted, see FINDINGS).

Fetch commands (all 2026-10-20):

    curl -s https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/page_64_types.h
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/page_32_types.h
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/processor.h
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/include/asm/elf.h
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/mm/mmap.c
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/kernel/sys_x86_64.c
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/kernel/process_64.c
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/mm/mmap.c
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/mm/mremap.c
    curl -s https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/personality.h
    curl -s https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/x86/include/asm/page_64_types.h
    ... (v5.15, v4.19, v3.17, v2.6.12 variants; see sources.txt)

## Deliverables

- `FINDINGS.md` — verdict, quoted evidence chain, consequences for SPEC D4.
- `sources.txt` — curated excerpts with file:line citations for every claim.

## Result (one line)

ANSWER: default `TASK_SIZE(i386 compat on x86_64)` = `0xFFFFE000` (4 GiB − 8 KiB);
`0xC0000000` only with the `ADDR_LIMIT_3GB`/`PER_LINUX32_3GB` personality; see
`FINDINGS.md`.

## Acceptance check

    grep -m1 -E '^VERDICT: (PASS|FAIL|ANSWER: )' experiments/E04-task-size/FINDINGS.md
