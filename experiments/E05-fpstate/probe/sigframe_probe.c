/*
 * E05 probe: dump the real i386 RT sigframe FPU layout from inside a
 * signal handler and check the _fpstate_32 magic constants.
 *
 * Build (in an i386 Linux container):  gcc -static -o sigframe_probe sigframe_probe.c
 * Expected (kernel arch/x86/include/uapi/asm/sigcontext.h):
 *   _fpstate_32.magic      @ fpstate+0x6e (u16) = X86_FXSR_MAGIC    = 0x0000
 *   sw_reserved.magic1     @ fpstate+0x240 (u32) = FP_XSTATE_MAGIC1 = 0x46505853
 *   magic2                 @ buf_fx + xstate_size = FP_XSTATE_MAGIC2 = 0x46505845
 *   buf_fx (the 64-byte-aligned fxsave/xsave image) = fpstate + 112
 *     (112 = sizeof(struct fregs_state), the fsave header in front of buf_fx)
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ucontext.h>

#define FP_XSTATE_MAGIC1 0x46505853u
#define FP_XSTATE_MAGIC2 0x46505845u
#define X86_FXSR_MAGIC   0x0000u

static volatile sig_atomic_t done;

static void handler(int sig, siginfo_t *si, void *uc_)
{
	ucontext_t *uc = uc_;
	unsigned char *fp = (unsigned char *)uc->uc_mcontext.fpregs;
	uint16_t magic;
	uint32_t m1, ext_sz, xs_sz, m2;
	uint64_t xf;
	int i;

	printf("fpstate                 = %p\n", (void *)fp);
	printf("fpstate %% 64            = %lu\n", (unsigned long)(uintptr_t)fp % 64);
	if (!fp) {
		printf("fpstate is NULL (no FP state in frame)\n");
		done = 1;
		return;
	}

	/* Legacy fsave-format header (kernel writes via convert_from_fxsr): */
	printf("cw=%08x sw=%08x tag=%08x\n",
	       *(uint32_t *)(fp + 0x00), *(uint32_t *)(fp + 0x04),
	       *(uint32_t *)(fp + 0x08));

	magic = *(uint16_t *)(fp + 0x6e);
	printf("fpstate[0x6e].magic     = 0x%04x (expect 0x%04x = X86_FXSR_MAGIC)\n",
	       magic, X86_FXSR_MAGIC);

	/* sw_reserved at fpstate+0x240 ( = 112 + 464 into the fxsave/xsave image): */
	m1     = *(uint32_t *)(fp + 0x240);
	ext_sz = *(uint32_t *)(fp + 0x244);
	xf     = *(uint64_t *)(fp + 0x248);
	xs_sz  = *(uint32_t *)(fp + 0x250);
	printf("sw_reserved.magic1      = 0x%08x (expect 0x%08x = FP_XSTATE_MAGIC1)\n",
	       m1, FP_XSTATE_MAGIC1);
	printf("sw_reserved.extended_size = %u\n", ext_sz);
	printf("sw_reserved.xfeatures     = 0x%016llx\n", (unsigned long long)xf);
	printf("sw_reserved.xstate_size   = %u\n", xs_sz);

	/* buf_fx: the 64-byte aligned [f]xsave image sits 112 bytes above fpstate. */
	printf("fpstate+112 %% 64        = %lu (expect 0)\n",
	       (unsigned long)((uintptr_t)fp + 112) % 64);

	/* magic2 terminates the xsave area: at buf_fx + xstate_size. */
	m2 = *(uint32_t *)(fp + 112 + xs_sz);
	printf("magic2 @ +112+xstate_size = 0x%08x (expect 0x%08x = FP_XSTATE_MAGIC2)\n",
	       m2, FP_XSTATE_MAGIC2);

	/* A few bytes of raw frame for eyeballing. */
	fputs("fpstate[0..15]          =", stdout);
	for (i = 0; i < 16; i++)
		printf(" %02x", fp[i]);
	fputs("\n", stdout);

	done = 1;
}

int main(void)
{
	struct sigaction sa;
	volatile double d = 1.0;
	uint32_t cw;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGUSR1, &sa, NULL)) {
		perror("sigaction");
		return 2;
	}

	/* Dirty the x87 and SSE state so the frame must carry FP state. */
	__asm__ volatile ("fnstcw %0" : "=m"(cw));
	__asm__ volatile (
		"xorps %%xmm0, %%xmm0\n\t"
		"addsd %1, %0\n\t"
		: "+x"(d) : "m"(d));

	raise(SIGUSR1);
	while (!done)
		;

	printf("probe done: d=%f cw=0x%04x\n", (double)d, cw & 0xffff);
	return 0;
}
