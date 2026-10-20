/*
 * src/os/vdso32/vdso32.lds — linker script for the synthetic i386 vDSO
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Mirrors the kernel's arch/x86/entry/vdso/vdso32/vdso32.lds.S shape:
 * a single read-only PT_LOAD (r-x) that carries the ELF and program
 * headers (FILEHDR PHDRS), the dynamic tables (.hash, .dynsym,
 * .dynstr, .gnu.version, .dynamic) and .text, so the whole image is
 * one contiguous mapping starting at vaddr 0; PT_DYNAMIC points at
 * .dynamic.  e_entry = __kernel_vsyscall, so AT_SYSINFO can be taken
 * as vdso_base + e_entry (E07 (2)).  The exported symbol set is fixed
 * by the inline VERSION block: LINUX_2.5 carries the kernel ABI
 * symbols, LINUX_2.6 the glibc fast-path symbols, everything else is
 * local — exactly the kernel's split (binutils emits DT_VERDEF and
 * DT_VERSYM from this block; the .so is linked --hash-style=sysv so
 * DT_HASH is present for the loader's bounded .dynsym walk).
 */

OUTPUT_FORMAT(elf32-i386)
OUTPUT_ARCH(i386)

ENTRY(__kernel_vsyscall)

PHDRS
{
	text		PT_LOAD		FILEHDR PHDRS FLAGS(5);	/* r-x */
	dynamic		PT_DYNAMIC	FLAGS(4);		/* r-- */
}

SECTIONS
{
	. = SIZEOF_HEADERS;

	.hash		: { *(.hash) }			:text
	.dynsym		: { *(.dynsym) }		:text
	.dynstr		: { *(.dynstr) }		:text
	.gnu.version	: { *(.gnu.version) }		:text
	.gnu.version_d	: { *(.gnu.version_d) }	:text
	.gnu.version_r	: { *(.gnu.version_r) }	:text

	.dynamic	: { *(.dynamic) }		:text	:dynamic

	.text		: { *(.text .text.*) }		:text	=0x90909090

	.note.GNU-stack	: { *(.note.GNU-stack) }

	/DISCARD/ : {
		*(.comment)
		*(.eh_frame*)
	}
}

VERSION
{
	LINUX_2.6 {
	global:
		__vdso_clock_gettime;
		__vdso_clock_gettime64;
		__vdso_gettimeofday;
		__vdso_time;
		__vdso_clock_getres;
	};

	LINUX_2.5 {
	global:
		__kernel_vsyscall;
		__kernel_sigreturn;
		__kernel_rt_sigreturn;
	local: *;
	};
}
