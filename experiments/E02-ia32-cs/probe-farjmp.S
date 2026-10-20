/*
 * probe-farjmp.S — E02 ia32-cs probe.
 *
 * Question: with ia32_emulation=0 (kernel 6.7+), does the __USER32_CS
 * descriptor (selector 0x23) remain in the GDT such that a far jump into
 * it still executes 32-bit code?
 *
 * Method (freestanding static non-PIE x86-64, linked at VA < 4 GiB so a
 * 32-bit lret can restore the zero-extended 64-bit RIP and so compat-mode
 * ESP addressing hits the same pages as the 64-bit RSP):
 *
 *   1. print the current CS (expected 0x33 = __USER_CS);
 *   2. push the 64-bit far-return frame (RIP=ret64, CS=0x33);
 *   3. ljmp *fptr -> loads CS=0x23, EIP=stub32, i.e. enters 32-bit
 *      compat mode inside this 64-bit process;
 *   4. stub32 does `mov $0x5A5A,%eax; lret` -> back to 64-bit mode;
 *   5. print FARJMP:OK iff eax == 0x5A5A.
 *
 * If selector 0x23 is unmapped/absent the ljmp raises #GP -> SIGSEGV and
 * the guest init script reports exit status 139; the stage message
 * "FARJMP: attempting ..." is printed before the attempt so the faulting
 * instruction is unambiguous.
 */

    .text
    .globl _start

/* wr: write(1, rsi, rdx); clobbers rax, rdi, rcx, r11 */
wr:
    mov $1, %eax
    mov $1, %edi
    syscall
    ret

/* phex16: print "0x" + 4 hex digits of %di + "\n";
 * clobbers rax, rcx, rdx, rsi, r8 */
phex16:
    sub $16, %rsp
    lea hexd(%rip), %rsi
    movb $'0', 0(%rsp)
    movb $'x', 1(%rsp)
    movl %edi, %edx
    movl $2, %ecx                /* buffer position 2..5 */
    movl $4, %r8d                /* four nibbles */
.Lnib:
    rolw $4, %dx                 /* next nibble (high first) into bits 3..0 */
    movzwl %dx, %eax
    andl $0xF, %eax
    movzbl (%rsi,%rax), %eax
    movb %al, (%rsp,%rcx)
    incl %ecx
    decl %r8d
    jnz .Lnib
    movb $'\n', 6(%rsp)
    mov %rsp, %rsi
    mov $7, %edx
    call wr
    add $16, %rsp
    ret

/* exit(rdi) */
exit_:
    mov $60, %eax
    syscall
    hlt
    jmp exit_

_start:
    /* Move to a low (< 4 GiB) stack: in 32-bit compat mode stack
     * references use SS:ESP, so ESP must address the same pages. */
    leaq lostk+LOSTKSZ(%rip), %rsp
    andq $-16, %rsp

    leaq m_banner(%rip), %rsi
    movq $MBANNER, %rdx
    call wr

    movl %cs, %eax                /* also record the 64-bit CS we run in */
    movzwl %ax, %r8d              /* stash: wr clobbers rdi */
    leaq m_cs(%rip), %rsi
    movq $MCS, %rdx
    call wr
    movl %r8d, %edi
    call phex16

    leaq m_try(%rip), %rsi
    movq $MTRY, %rdx
    call wr

    /* Far-return frame for the 32-bit lret: the frame must be two
     * 32-bit words [ret64][__USER_CS=0x33], NOT two 64-bit pushes —
     * a 32-bit lret pops EIP at (%rsp) and CS at 4(%rsp). */
    subq $8, %rsp
    movl $ret64, %eax
    movl %eax, (%rsp)
    movl $0x33, 4(%rsp)
    ljmp *fptr(%rip)              /* CS=0x23 (__USER32_CS), EIP=stub32 */

    .code32
stub32:
    movl $0x5A5A, %eax
    lret                          /* pops EIP=ret64, CS=0x33 -> 64-bit mode */
    .code64

ret64:
    leaq lostk+LOSTKSZ(%rip), %rsp
    andq $-16, %rsp

    cmpl $0x5A5A, %eax
    jne .Lfail

    leaq m_ok(%rip), %rsi
    movq $MOK, %rdx
    call wr
    xorl %edi, %edi
    jmp .Lexit

.Lfail:
    leaq m_fail(%rip), %rsi
    movq $MFAIL, %rdx
    call wr
    movl %eax, %edi
    call phex16
    movl $1, %edi

.Lexit:
    call exit_

    .section .rodata
hexd:   .ascii "0123456789abcdef"
m_banner: .ascii "FARJMP: start (static non-PIE, low VA)\n"
    .set MBANNER, . - m_banner
m_cs:  .ascii "FARJMP: current cs="
    .set MCS, . - m_cs
m_try: .ascii "FARJMP: attempting ljmp to selector 0x23 (__USER32_CS)\n"
    .set MTRY, . - m_try
m_ok:  .ascii "FARJMP:OK eax=0x5a5a after lret to cs=0x33\n"
    .set MOK, . - m_ok
m_fail: .ascii "FARJMP:FAIL unexpected eax="
    .set MFAIL, . - m_fail

    .data
    .balign 4
fptr:  .long stub32                /* 32-bit offset (VA < 4 GiB) */
       .value 0x23                 /* __USER32_CS */

    .balign 16
lostk: .space 4096
    .set LOSTKSZ, . - lostk
