/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd. */
/*
 * E10 prototype: proves the vm86()/vm86old() contract is fully emulatable
 * in-process by a real-mode interpreter over the low 1 MiB of the guest
 * window.  Kernel references cite torvalds/linux master (2026-10 snapshot):
 *   arch/x86/include/uapi/asm/vm86.h
 *   arch/x86/kernel/vm86_32.c
 *
 * Prototype -> i686rt artifact mapping (Phase 8):
 *  1. win (malloc'd 1 MiB)    -> guest window [G, G+1 MiB); under hl offset
 *     mode guest linear 0 sits at G, never at host VA 0, so the kernel's
 *     mmap_min_addr guard (vm86_32.c:208-232) cannot bite i686rt.
 *  2. lin(seg,off) 20-bit wrap -> src/interp/v86.c real-mode addressing;
 *     A20 is off by default, addresses wrap at the 1 MiB top.
 *  3. struct v86_regs subset  -> vm86_regs marshalling in src/os/vm86.c
 *     for sys_vm86old(113) / sys_vm86(166) (vm86_32.c:170-196).
 *  4. revectored bitmaps      -> int_revectored / int21_revectored copied
 *     from the user vm86(_plus)_struct (vm86_32.c:276-283).
 *  5. do_int()                -> kernel semantics verbatim (vm86_32.c:494-525):
 *     revectored (or BIOS-segment) => VM86_INTx + (n << 8), else vector
 *     through the IVT at linear n*4 with flags/cs/ip pushed on the v86 stack.
 *  6. packed exit codes       -> vm86(166) return value: VM86_TYPE = retval
 *     & 0xff, VM86_ARG = retval >> 8 (vm86.h:30-44; vm86_32.c:156).
 *  7. step() fetch/decode/execute -> the src/interp/v86.c interpreter loop;
 *     unknown opcodes exit VM86_UNKNOWN, never assert (D2; vm86_32.c:680-681).
 *  8. VIF/VIP eflags stubs    -> get_vflags()/clear_IF() composition
 *     (vm86_32.c:345-405); both set => VM86_STI (vm86_32.c:686-691).
 *  9. fault on bad memory     -> VM86_UNKNOWN, mirroring simulate_sigsegv
 *     (vm86_32.c:702-713).
 * 10. hlt stops the loop      -> in v86, hlt #GPs into the fault handler's
 *     default case => VM86_UNKNOWN (vm86_32.c:680-681); terminal safety stop.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define WIN_SZ ((uint32_t)1024u * 1024u) /* low 1 MiB of the guest window */

/* Return codes / packing, verbatim from vm86.h:30-44. */
#define VM86_TYPE(r) ((r) & 0xff)
#define VM86_ARG(r) ((r) >> 8)
#define VM86_SIGNAL 0  /* return due to signal (signal.c:261) */
#define VM86_UNKNOWN 1 /* unhandled GP fault - IO-instruction or similar */
#define VM86_INTx 2    /* int3/int x instruction (ARG = x) */
#define VM86_STI 3     /* sti/popf/iret enabled virtual interrupts */
#define VM86_PICRETURN 4 /* return due to pending PIC request */
#define VM86_TRAP 6    /* return due to DOS-debugger request (no code 5) */

#define BIOSSEG 0x0f000u /* vm86.h:18 */

/* eflags subset (arch/x86/include/asm/processor-flags.h numbering). */
#define F_CF 0x0001u
#define F_TF 0x0100u
#define F_IF 0x0200u
#define F_DF 0x0400u
#define F_AC 0x00040000u
#define F_VIF 0x00080000u /* virtual interrupt flag (vm86.h:5-13) */
#define F_VIP 0x00100000u /* virtual interrupt pending */

#define STEP_CONT (-1) /* internal: keep interpreting */

/* Subset of struct vm86_regs (vm86.h:63-91). */
typedef struct {
	uint32_t eax, ebx, ecx, edx, esi, edi, ebp;
	uint32_t eip, esp, eflags;
	uint16_t cs, ss, ds, es, fs, gs;
} v86_regs;

/* struct revectored_struct (vm86.h:93-95): 256 bits. */
typedef struct {
	uint32_t map[8];
} revectored;

typedef struct {
	v86_regs r;
	revectored int_revectored;
	revectored int21_revectored;
	uint8_t *win; /* stands in for the guest window [G, G+1 MiB) */
	int fault;    /* bad guest memory access -> VM86_UNKNOWN */
} v86_ctx;

static v86_ctx M;

static int is_revectored(unsigned nr, const revectored *rv) /* vm86_32.c:407-410 */
{
	if (nr >= 256u)
		return 0;
	return (int)((rv->map[nr >> 5] >> (nr & 31u)) & 1u);
}

static void revect(revectored *rv, unsigned nr)
{
	if (nr < 256u)
		rv->map[nr >> 5] |= 1u << (nr & 31u);
}

/* Real-mode linear address: seg<<4 + off, wrapping at 1 MiB (A20 off).
 * With A20 on, bit 20 would not be masked; the window is 4 GiB so an
 * A20-on model would simply drop the mask. */
static uint32_t lin(uint16_t seg, uint16_t off)
{
	return (((uint32_t)seg << 4) + (uint32_t)off) & 0xFFFFFu;
}

static uint8_t rd8(uint32_t a)
{
	if (a >= WIN_SZ) {
		M.fault = 1;
		return 0;
	}
	return M.win[a];
}

static void wr8(uint32_t a, uint8_t v)
{
	if (a >= WIN_SZ) {
		M.fault = 1;
		return;
	}
	M.win[a] = v;
}

static uint32_t rd32(uint32_t a)
{
	uint32_t v = (uint32_t)rd8(a);
	v |= (uint32_t)rd8((a + 1u) & 0xFFFFFu) << 8;
	v |= (uint32_t)rd8((a + 2u) & 0xFFFFFu) << 16;
	v |= (uint32_t)rd8((a + 3u) & 0xFFFFFu) << 24;
	return v;
}

/* Compose the flags a v86 PUSHF/IVT push would observe: real flags minus IF,
 * IF synthesized from VIF, IOPL forced on (vm86_32.c:397-405). */
static uint32_t get_vflags(void)
{
	uint32_t f = M.r.eflags & 0x0DFFu; /* RETURN_MASK, vm86_32.c:94 */
	if ((M.r.eflags & F_VIF) != 0u)
		f |= F_IF;
	f |= 0x3000u; /* IOPL */
	return f;
}

static uint8_t fetch8(void)
{
	uint8_t b = rd8(lin(M.r.cs, (uint16_t)M.r.eip));
	M.r.eip = (M.r.eip + 1u) & 0xffffu; /* 16-bit IP wrap */
	return b;
}

static uint16_t fetch16(void)
{
	uint16_t lo = fetch8();
	uint16_t hi = fetch8();
	return (uint16_t)(lo | (uint16_t)(hi << 8));
}

/* pushw over ss:sp, mirroring vm86_32.c:422-431; a fault leaves M.fault set
 * and the caller returns VM86_UNKNOWN (simulate_sigsegv, vm86_32.c:702-713). */
static void pushw(uint16_t v)
{
	uint32_t base = (uint32_t)M.r.ss << 4;
	uint16_t sp = (uint16_t)(M.r.esp - 1u);
	wr8(base + sp, (uint8_t)(v >> 8));
	sp = (uint16_t)(sp - 1u);
	wr8(base + sp, (uint8_t)v);
	M.r.esp = sp;
}

/* int gate, kernel semantics verbatim (vm86_32.c:494-525).  Returns
 * STEP_CONT when the interrupt was vectored through the IVT, or the packed
 * VM86_INTx + (i << 8) exit when it cannot be handled in guest context. */
static int do_int(unsigned i)
{
	uint32_t segoffs;

	if (M.r.cs == BIOSSEG) /* vm86_32.c:501 */
		goto cannot_handle;
	if (is_revectored(i, &M.int_revectored)) /* vm86_32.c:503 */
		goto cannot_handle;
	if (i == 0x21u && is_revectored((M.r.eax >> 8) & 0xffu,
					   &M.int21_revectored)) /* vm86_32.c:505 */
		goto cannot_handle;
	segoffs = rd32((uint32_t)i << 2); /* IVT entry at linear i*4 */
	if (M.fault || (segoffs >> 16) == BIOSSEG) /* vm86_32.c:507-511 */
		goto cannot_handle;
	pushw((uint16_t)get_vflags()); /* vm86_32.c:512-514 */
	pushw(M.r.cs);
	pushw((uint16_t)M.r.eip);
	if (M.fault)
		goto cannot_handle;
	M.r.cs = (uint16_t)(segoffs >> 16);
	M.r.eip = segoffs & 0xffffu;
	M.r.eflags &= ~(F_TF | F_VIF | F_AC); /* clear_TF/IF/AC, :518-520 */
	return STEP_CONT;
cannot_handle:
	return VM86_INTx + ((int)i << 8); /* vm86_32.c:524, regs intact */
}

/* 16-bit register file order: ax cx dx bx sp bp si di (x86 encoding). */
static uint32_t *gpr(unsigned r)
{
	switch (r) {
	case 0:
		return &M.r.eax;
	case 1:
		return &M.r.ecx;
	case 2:
		return &M.r.edx;
	case 3:
		return &M.r.ebx;
	case 4:
		return &M.r.esp;
	case 5:
		return &M.r.ebp;
	case 6:
		return &M.r.esi;
	case 7:
		return &M.r.edi;
	default:
		return NULL; /* unreachable: 3-bit field */
	}
}

/* One fetch/decode/execute step.  Returns STEP_CONT or a packed VM86_*
 * exit; unknown opcodes exit VM86_UNKNOWN, never assert (D2). */
static int step(void)
{
	uint8_t op, modrm;
	int data32 = 0;
	int pref_done = 0;

	/* Prefix loop, mirroring handle_vm86_fault (vm86_32.c:569-583). */
	do {
		op = fetch8();
		if (M.fault)
			return VM86_UNKNOWN;
		switch (op) {
		case 0x66: /* 32-bit data */
			data32 = 1;
			break;
		case 0x67: /* 32-bit address */
		case 0x2e: /* CS */
		case 0x3e: /* DS */
		case 0x26: /* ES */
		case 0x36: /* SS */
		case 0x65: /* GS */
		case 0x64: /* FS */
		case 0xf2: /* repnz */
		case 0xf3: /* rep */
			break;
		default:
			pref_done = 1;
		}
	} while (!pref_done);

	switch (op) {
	case 0xb8: /* B8+r: mov r16, imm16 */
	case 0xb9:
	case 0xba:
	case 0xbb:
	case 0xbc:
	case 0xbd:
	case 0xbe:
	case 0xbf: {
		uint32_t *dst;
		uint16_t imm = fetch16();
		if (M.fault || data32)
			return VM86_UNKNOWN; /* 32-bit operand form not modeled */
		dst = gpr((unsigned)(op - 0xb8));
		if (dst == NULL)
			return VM86_UNKNOWN;
		*dst = imm; /* 16-bit write zero-extends (386 semantics) */
		return STEP_CONT;
	}
	case 0x89: { /* 89 /r: mov r/m16, r16 (register form) */
		uint32_t *src, *dst;
		modrm = fetch8();
		if (M.fault || data32)
			return VM86_UNKNOWN;
		if ((modrm >> 6) != 3u) /* only mod == 11 (reg-reg) modeled */
			return VM86_UNKNOWN;
		src = gpr((modrm >> 3) & 7u);
		dst = gpr(modrm & 7u);
		if (src == NULL || dst == NULL)
			return VM86_UNKNOWN;
		*dst = *src & 0xffffu;
		return STEP_CONT;
	}
	case 0xcd: { /* CD ib: int n */
		unsigned n = fetch8();
		if (M.fault)
			return VM86_UNKNOWN;
		return do_int(n); /* vm86_32.c:620-631 */
	}
	case 0xf4: /* hlt: #GP in v86 -> default case -> VM86_UNKNOWN */
		return VM86_UNKNOWN;
	default: /* unimplemented opcode -> VM86_UNKNOWN (vm86_32.c:680-681) */
		return VM86_UNKNOWN;
	}
}

static int vm86_run(void)
{
	unsigned long guard = 0;
	for (;;) {
		int rc = step();
		if (rc != STEP_CONT)
			return rc;
		if (++guard == 1000000u) /* runaway safety bound */
			return VM86_UNKNOWN;
	}
}

int main(void)
{
	/* 20-byte program at 0x7c00 (11 bytes + hlt padding):
	 *   mov ax, 0x1234 ; mov bx, 0x5678 ; mov cx, ax ; int 0x10 ; hlt */
	static const uint8_t prog[20] = {
		0xb8, 0x34, 0x12, /* mov ax, 0x1234 */
		0xbb, 0x78, 0x56, /* mov bx, 0x5678 */
		0x89, 0xc1, /* mov cx, ax */
		0xcd, 0x10, /* int 0x10 */
		0xf4, 0xf4, 0xf4, 0xf4, 0xf4, /* hlt padding to 20 bytes */
		0xf4, 0xf4, 0xf4, 0xf4,
	};
	const uint16_t want_ax = 0x1234u, want_bx = 0x5678u, want_cx = 0x1234u;
	const unsigned want_type = (unsigned)VM86_INTx, want_arg = 0x10u;
	int ret, ok;

	M.win = malloc(WIN_SZ);
	if (M.win == NULL) {
		fprintf(stderr, "proto: out of memory\n");
		return EXIT_FAILURE;
	}
	memset(M.win, 0, WIN_SZ);
	if (WIN_SZ - 0x7c00u < sizeof prog) { /* bounds check the copy */
		fprintf(stderr, "proto: program does not fit window\n");
		free(M.win);
		return EXIT_FAILURE;
	}
	memcpy(&M.win[0x7c00], prog, sizeof prog);

	/* Boot state: real mode at 0:0x7c00, flat zero segments; eflags
	 * has only the always-one bit 1 set (interrupt state is virtual). */
	M.r.cs = 0;
	M.r.eip = 0x7c00u;
	M.r.ss = 0;
	M.r.esp = 0xfffeu;
	M.r.ds = 0;
	M.r.es = 0;
	M.r.fs = 0;
	M.r.gs = 0;
	M.r.eflags = 0x2u;
	revect(&M.int_revectored, 0x10u); /* int_revectored = {0x10} */

	ret = vm86_run();

	printf("vm86 exit: type=%d arg=0x%02x (raw=0x%04x)\n",
	    VM86_TYPE(ret) & 0xff, VM86_ARG(ret), ret & 0xffff);
	printf("AX=0x%04x BX=0x%04x CX=0x%04x DX=0x%04x\n",
	    (unsigned)(M.r.eax & 0xffffu), (unsigned)(M.r.ebx & 0xffffu),
	    (unsigned)(M.r.ecx & 0xffffu), (unsigned)(M.r.edx & 0xffffu));
	printf("SI=0x%04x DI=0x%04x BP=0x%04x SP=0x%04x\n",
	    (unsigned)(M.r.esi & 0xffffu), (unsigned)(M.r.edi & 0xffffu),
	    (unsigned)(M.r.ebp & 0xffffu), (unsigned)(M.r.esp & 0xffffu));
	printf("CS=0x%04x IP=0x%04x SS=0x%04x eflags=0x%08x "
	       "(VIF=%u VIP=%u TF=%u DF=%u)\n",
	    (unsigned)M.r.cs, (unsigned)(M.r.eip & 0xffffu), (unsigned)M.r.ss,
	    (unsigned)M.r.eflags, (unsigned)((M.r.eflags & F_VIF) != 0u),
	    (unsigned)((M.r.eflags & F_VIP) != 0u),
	    (unsigned)((M.r.eflags & F_TF) != 0u),
	    (unsigned)((M.r.eflags & F_DF) != 0u));

	ok = (M.r.eax & 0xffffu) == want_ax && (M.r.ebx & 0xffffu) == want_bx &&
	    (M.r.ecx & 0xffffu) == want_cx &&
	    (unsigned)VM86_TYPE(ret) == want_type &&
	    (unsigned)VM86_ARG(ret) == want_arg;
	printf("PROTO: %s\n", ok ? "PASS" : "FAIL");

	free(M.win);
	return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
