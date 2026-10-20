/*
 * E05 probe: byte-offset tables for the i386 sigframe structs.
 *
 * k-sigcontext.h is arch/x86/include/uapi/asm/sigcontext.h (torvalds/linux
 * master) with the two kernel-internal #include lines stubbed by typedefs;
 * every struct definition below the includes is untouched. The frame and
 * ucontext structs mirror arch/x86/include/asm/sigframe.h and
 * include/uapi/asm-generic/ucontext.h with i386 type widths
 * (unsigned long = pointer = 4 bytes).
 *
 * Build: gcc -m32 -std=c11 -o layout_probe layout_probe.c && ./layout_probe
 */
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include "k-sigcontext.h"

/* ---- i386 frame structs (arch/x86/include/asm/sigframe.h) ---- */

typedef int32_t  s32;
typedef uint32_t kernel_ulong_t;

struct stack_t_32 {
	uint32_t ss_sp;		/* void * */
	int32_t  ss_flags;
	uint32_t ss_size;
};

/* include/uapi/asm-generic/ucontext.h with i386 widths */
struct ucontext_ia32 {
	uint32_t           uc_flags;
	uint32_t           uc_link;	/* struct ucontext * */
	struct stack_t_32  uc_stack;
	struct sigcontext_32 uc_mcontext;
	uint32_t           uc_sigmask[2];	/* kernel sigset_t: 64 bit */
};

struct sigframe_ia32 {
	uint32_t pretcode;
	int32_t  sig;
	struct sigcontext_32 sc;
	struct _fpstate_32 fpstate_unused;
	uint32_t extramask[1];
	char retcode[8];
	/* fp state follows here */
};

struct compat_siginfo_32 {
	int32_t si_signo;
	int32_t si_errno;
	int32_t si_code;
	uint8_t payload[128 - 12];	/* ABI: 128 bytes total, align 4 */
};

struct rt_sigframe_ia32 {
	uint32_t pretcode;
	int32_t  sig;
	uint32_t pinfo;
	uint32_t puc;
	struct compat_siginfo_32 info;
	struct ucontext_ia32 uc;
	char retcode[8];
	/* fp state follows here */
};

/* ---- helpers ---- */

#define O(t, f)  printf("  %-22s %#06zx  %zu\n", #f, offsetof(t, f), sizeof(((t *)0)->f))
#define SZ(t)    printf("%-28s size %#06zx (%zu) align %zu\n", #t, sizeof(t), sizeof(t), _Alignof(t))

int main(void)
{
	SZ(struct sigcontext_32);
	O(struct sigcontext_32, gs);  O(struct sigcontext_32, __gsh);
	O(struct sigcontext_32, fs);  O(struct sigcontext_32, __fsh);
	O(struct sigcontext_32, es);  O(struct sigcontext_32, __esh);
	O(struct sigcontext_32, ds);  O(struct sigcontext_32, __dsh);
	O(struct sigcontext_32, di);  O(struct sigcontext_32, si);
	O(struct sigcontext_32, bp);  O(struct sigcontext_32, sp);
	O(struct sigcontext_32, bx);  O(struct sigcontext_32, dx);
	O(struct sigcontext_32, cx);  O(struct sigcontext_32, ax);
	O(struct sigcontext_32, trapno); O(struct sigcontext_32, err);
	O(struct sigcontext_32, ip);
	O(struct sigcontext_32, cs);  O(struct sigcontext_32, __csh);
	O(struct sigcontext_32, flags);
	O(struct sigcontext_32, sp_at_signal);
	O(struct sigcontext_32, ss);  O(struct sigcontext_32, __ssh);
	O(struct sigcontext_32, fpstate);
	O(struct sigcontext_32, oldmask);
	O(struct sigcontext_32, cr2);

	SZ(struct _fpstate_32);
	O(struct _fpstate_32, cw);  O(struct _fpstate_32, sw);
	O(struct _fpstate_32, tag); O(struct _fpstate_32, ipoff);
	O(struct _fpstate_32, cssel); O(struct _fpstate_32, dataoff);
	O(struct _fpstate_32, datasel);
	O(struct _fpstate_32, _st);
	O(struct _fpstate_32, status);
	O(struct _fpstate_32, magic);
	O(struct _fpstate_32, _fxsr_env);
	O(struct _fpstate_32, mxcsr);
	O(struct _fpstate_32, reserved);
	O(struct _fpstate_32, _fxsr_st);
	O(struct _fpstate_32, _xmm);
	O(struct _fpstate_32, padding1);
	O(struct _fpstate_32, padding2);	/* union with sw_reserved */
	printf("  (union sw_reserved)    %#06zx  %zu\n",
	       offsetof(struct _fpstate_32, padding2), sizeof(struct _fpx_sw_bytes));

	SZ(struct _fpx_sw_bytes);
	O(struct _fpx_sw_bytes, magic1);
	O(struct _fpx_sw_bytes, extended_size);
	O(struct _fpx_sw_bytes, xfeatures);
	O(struct _fpx_sw_bytes, xstate_size);
	O(struct _fpx_sw_bytes, padding);

	SZ(struct ucontext_ia32);
	O(struct ucontext_ia32, uc_flags);
	O(struct ucontext_ia32, uc_link);
	O(struct ucontext_ia32, uc_stack);
	O(struct ucontext_ia32, uc_mcontext);
	O(struct ucontext_ia32, uc_sigmask);

	SZ(struct sigframe_ia32);
	O(struct sigframe_ia32, pretcode);
	O(struct sigframe_ia32, sig);
	O(struct sigframe_ia32, sc);
	O(struct sigframe_ia32, fpstate_unused);
	O(struct sigframe_ia32, extramask);
	O(struct sigframe_ia32, retcode);

	SZ(struct rt_sigframe_ia32);
	O(struct rt_sigframe_ia32, pretcode);
	O(struct rt_sigframe_ia32, sig);
	O(struct rt_sigframe_ia32, pinfo);
	O(struct rt_sigframe_ia32, puc);
	O(struct rt_sigframe_ia32, info);
	O(struct rt_sigframe_ia32, uc);
	O(struct rt_sigframe_ia32, retcode);

	/* Cross-checks against the kernel's own invariants. */
	printf("checks:\n");
	printf("  sizeof(_fpstate_32) == 624 : %s\n",
	       sizeof(struct _fpstate_32) == 624 ? "ok" : "FAIL");
	printf("  sw_reserved offset 0x240 == 112 (fregs_state) + 464 (fxsave sw area) : %s\n",
	       offsetof(struct _fpstate_32, padding2) == 112 + 464 ? "ok" : "FAIL");
	printf("  mxcsr at 0x88 == 112 + 24 (FXSAVE MXCSR offset) : %s\n",
	       offsetof(struct _fpstate_32, mxcsr) == 112 + 24 ? "ok" : "FAIL");
	printf("  _xmm at 0x110 == 112 + 160 (FXSAVE XMM offset) : %s\n",
	       offsetof(struct _fpstate_32, _xmm) == 112 + 160 ? "ok" : "FAIL");
	printf("  sizeof(sigcontext_32) == 88 : %s\n",
	       sizeof(struct sigcontext_32) == 88 ? "ok" : "FAIL");
	return 0;
}
