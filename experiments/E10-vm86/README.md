# E10 — vm86 feasibility experiment

Card E10: is `vm86`/`vm86old` fully emulatable in-process by i686rt?

- `FINDINGS.md` — verdict, kernel ABI summary (structs, exit codes, the
  revectored-int protocol, VIF/VIP, IRQ corner), user survey (dosemu2,
  v86d, X11 x86emu), and the consequence for SPEC Phase 8 and open
  question #7.
- `proto.c` — standalone Curated C11 prototype: a real-mode interpreter
  over a 1 MiB guest window that runs `mov ax,0x1234 ; mov bx,0x5678 ;
  mov cx,ax ; int 0x10 ; hlt` at 0x7c00 and returns the kernel-exact
  `VM86_INTx + (0x10 << 8)` exit with intact registers.

Build and run (macOS-native, zero dependencies):

```
clang -std=c11 -Wall -Wextra -Werror=vla -pedantic -o proto proto.c && ./proto
```

Expected last line: `PROTO: PASS` (exit status 0).
