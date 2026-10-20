/*
 * src/os/vdso32/vdso32.S — synthetic i386 vDSO bodies (SPEC D12, E07)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Built by tools/mkvdso32.sh: `as --32` + `ld -m elf_i386 -shared -T
 * vdso32.lds` under docker linux/386 alpine, producing vdso32.so, which
 * is embedded as src/os/vdso32_blob.c.  Syscall numbers below are the
 * authoritative src/os/syscalls_i386.h values (verified 2026-10-20):
 * 13 time, 78 gettimeofday, 119 sigreturn, 173 rt_sigreturn,
 * 265 clock_gettime, 266 clock_getres, 403 clock_gettime64.
 *
 * Exported set (frozen contract src/os/vdso.h; E07 FINDINGS):
 *   LINUX_2.5: __kernel_vsyscall (= e_entry), __kernel_sigreturn,
 *              __kernel_rt_sigreturn
 *   LINUX_2.6: __vdso_clock_gettime, __vdso_clock_gettime64,
 *              __vdso_gettimeofday, __vdso_time, __vdso_clock_getres
 *
 * Calling conventions — decision recorded after checking the kernel and
 * qemu sources (E07 pins the symbol/version table; the bodies follow
 * the kernel's, which qemu's linux-user/i386/vdso.S replicates):
 *
 * __kernel_vsyscall is the vsyscall GATEWAY, i.e. the raw i386 syscall
 * ABI: nr in %eax, args in %ebx,%ecx,%edx,%esi,%edi,%ebp, result in
 * %eax.  glibc's ENTER_KERNEL reaches it via `call *%gs:0x10` (E07 (3))
 * and cleans up its own argument pushes, so the gateway returns with a
 * plain `ret`.  int $0x80 preserves every register except %eax, which
 * is exactly what the interpreter's syscall exit provides.
 *
 * __kernel_sigreturn/__kernel_rt_sigreturn are signal-frame restorers
 * that never return.  The bodies mirror the kernel's
 * arch/x86/entry/vdso/vdso32/sigreturn.S behavior, including the
 * `popl %eax` that discards the signal number pushed for the handler
 * (qemu's vdso.S documents it as "pop sig") before the syscall number
 * is loaded into the same register.
 *
 * __vdso_* are NOT gateway-style: glibc calls them as ordinary C
 * function pointers.  dl_vdso_vsym (E07 (1)) yields a pointer invoked
 * by INLINE_VSYSCALL as a normal call, and the kernel builds its own
 * vdso32 with `-mregparm=0` (arch/x86/entry/vdso/vdso32/Makefile) —
 * the i386 psABI cdecl convention: arguments at 4(%esp), 8(%esp), ...,
 * plain `ret` with caller-side stack cleanup, %ebx/%esi/%edi/%ebp
 * callee-saved.  So each body reads its arguments from the stack,
 * parks callee-saved %ebx in %edx while loading the i386 syscall
 * register arguments (%ebx arg1, %ecx arg2), traps into int $0x80,
 * restores %ebx, and returns the raw syscall result in %eax (-errno on
 * failure — the contract INLINE_VSYSCALL checks).  `ret $n` (callee
 * pops) would make a cdecl caller adjust %esp a second time and
 * corrupt its stack, so plain `ret` is required.
 */

	.text

/* --- LINUX_2.5: kernel ABI symbols -------------------------------------- */

	.globl	__kernel_vsyscall
	.type	__kernel_vsyscall, @function
__kernel_vsyscall:
	int	$0x80
	ret
	.size	__kernel_vsyscall, . - __kernel_vsyscall

	.globl	__kernel_sigreturn
	.type	__kernel_sigreturn, @function
__kernel_sigreturn:
	popl	%eax			/* pop sig (kernel vdso32/sigreturn.S) */
	movl	$119, %eax		/* __NR_sigreturn */
	int	$0x80
	.size	__kernel_sigreturn, . - __kernel_sigreturn

	.globl	__kernel_rt_sigreturn
	.type	__kernel_rt_sigreturn, @function
__kernel_rt_sigreturn:
	movl	$173, %eax		/* __NR_rt_sigreturn */
	int	$0x80
	.size	__kernel_rt_sigreturn, . - __kernel_rt_sigreturn

/* --- LINUX_2.6: glibc cdecl fast paths ---------------------------------- */

/*
 * vdso_syscall1 name, nr — f(arg1): %ebx = arg1 from the stack.
 */
.macro	vdso_syscall1 name, nr
	.globl	\name
	.type	\name, @function
\name:
	movl	%ebx, %edx		/* save callee-saved %ebx (int80 keeps %edx) */
	movl	4(%esp), %ebx		/* arg1 */
	movl	$\nr, %eax
	int	$0x80
	movl	%edx, %ebx
	ret				/* cdecl: caller pops the argument */
	.size	\name, . - \name
.endm

/*
 * vdso_syscall2 name, nr — f(arg1, arg2): %ebx/%ecx from the stack
 * (%ecx is caller-saved, no save needed).
 */
.macro	vdso_syscall2 name, nr
	.globl	\name
	.type	\name, @function
\name:
	movl	%ebx, %edx		/* save callee-saved %ebx (int80 keeps %edx) */
	movl	4(%esp), %ebx		/* arg1 */
	movl	8(%esp), %ecx		/* arg2 */
	movl	$\nr, %eax
	int	$0x80
	movl	%edx, %ebx
	ret				/* cdecl: caller pops the arguments */
	.size	\name, . - \name
.endm

	vdso_syscall2	__vdso_clock_gettime,   265	/* (clockid_t, struct old_timespec32 *)        */
	vdso_syscall2	__vdso_clock_gettime64, 403	/* (clockid_t, struct __kernel_timespec *)     */
	vdso_syscall2	__vdso_gettimeofday,     78	/* (struct old_timeval *, struct timezone *)   */
	vdso_syscall1	__vdso_time,             13	/* (time_t *)                                  */
	vdso_syscall2	__vdso_clock_getres,    266	/* (clockid_t, struct old_timespec32 *)        */

	.section .note.GNU-stack,"",@progbits
