/*
 * src/i686rt.h — Core context, constants, and module interfaces for i686rt
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 0 freeze (SPEC §4 0.1): the layout of the first 35304 bytes of
 * i686_ctx_t is ABI-locked for the future DBT trampoline (Phase 3) and the
 * a64 emitter.  Fields after the IBTC array are C-only and may be extended
 * at the tail between phases; never inside the locked prefix.
 */

#ifndef I686RT_H
#define I686RT_H

#include <sched.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "a32host.h" /* vendored, byte-identical to a32rt's (D14) */

/* x86 GPR indices in hardware encoding order (ModRM reg/rm numbering). */
#define I686_REG_EAX 0U
#define I686_REG_ECX 1U
#define I686_REG_EDX 2U
#define I686_REG_EBX 3U
#define I686_REG_ESP 4U
#define I686_REG_EBP 5U
#define I686_REG_ESI 6U
#define I686_REG_EDI 7U

/* x86 segment register indices in hardware encoding order (sreg field). */
#define I686_SEG_ES 0U
#define I686_SEG_CS 1U
#define I686_SEG_SS 2U
#define I686_SEG_DS 3U
#define I686_SEG_FS 4U
#define I686_SEG_GS 5U
#define I686_SEG_COUNT 6U

/* EFLAGS bits (architectural; SPEC D6 keeps materialization lazy). */
#define I686_EF_CF   (1U << 0)
#define I686_EF_PF   (1U << 2)
#define I686_EF_AF   (1U << 4)
#define I686_EF_ZF   (1U << 6)
#define I686_EF_SF   (1U << 7)
#define I686_EF_TF   (1U << 8)
#define I686_EF_IF   (1U << 9)
#define I686_EF_DF   (1U << 10)
#define I686_EF_OF   (1U << 11)
#define I686_EF_IOPL (3U << 12)
#define I686_EF_NT   (1U << 14)
#define I686_EF_RF   (1U << 16)
#define I686_EF_VM   (1U << 17)
#define I686_EF_AC   (1U << 18)
#define I686_EF_VIF  (1U << 19)
#define I686_EF_VIP  (1U << 20)
#define I686_EF_ID   (1U << 21)
#define I686_EF_ARITH_MASK \
    (I686_EF_CF | I686_EF_PF | I686_EF_AF | I686_EF_ZF | I686_EF_SF | I686_EF_OF)

/* Block exit reasons (engines return to the dispatcher via ctx->exit_reason). */
#define I686_EXIT_NONE    0U
#define I686_EXIT_BRANCH  1U /* jcc/jmp/call/ret/loop taken to ctx->exit_dest */
#define I686_EXIT_SYSCALL 2U /* int 0x80, sysenter, syscall, or vDSO vsyscall */
#define I686_EXIT_UNDEF   3U /* undecodable insn: interpreter single-step (D2) */
#define I686_EXIT_FAULT   4U /* guest memory fault; ctx->fault_addr set */
#define I686_EXIT_TRAP    5U /* int3/int1 debug trap */
#define I686_EXIT_HLT     6U /* guest executed hlt (diagnostic stop) */

/* Architectural limits, cache capacities, page/window constants (D4, E04). */
#define I686_MAX_REGIONS     512U
#define I686_RAS_SIZE        64U
#define I686_IBTC_SIZE       1024U
#define I686_PAGE_SIZE       4096U
#define I686_TASK_SIZE_TOP   0xFFFFE000U /* i386 compat TASK_SIZE (E04) */
#define I686_ADDR_LIMIT_3GB  0xC0000000U /* personality ADDR_LIMIT_3GB top (E04) */
#define I686_LOW_GUARD_SIZE  0x00010000U
#define I686_LDT_MAX_ENTRIES 8192U       /* full per-process LDT (D8) */

/*
 * Lazy-flags descriptor (D6): engines keep EFLAGS arith bits derivable from
 * {op, res, src1, src2, cf_in} and materialize ctx->eflags only on reads
 * (pushf, lahf, jcc when not fused, adc/sbb, signal frames).  I686_FOP_NONE
 * means ctx->eflags is authoritative as-is.
 */
enum {
    I686_FOP_NONE = 0,
    I686_FOP_ADD,   /* res = src1 + src2        (CF,ZF,SF,OF,PF,AF) */
    I686_FOP_ADC,   /* res = src1 + src2 + cf_in                   */
    I686_FOP_SUB,   /* res = src1 - src2        (CF = borrow)      */
    I686_FOP_SBB,   /* res = src1 - src2 - cf_in                   */
    I686_FOP_LOGIC, /* and/or/xor/test: CF=OF=0                    */
    I686_FOP_INC,
    I686_FOP_DEC,
    I686_FOP_NEG
};

typedef struct i686_region {
    uint32_t start;
    uint32_t end;
    uint32_t prot;
    uint32_t flags;
    char     name[64];
} i686_region_t;

typedef struct i686_ibtc_entry {
    uint32_t    key;       /* guest EIP (no T bit, SPEC §3.3) */
    uint32_t    epoch;
    const void *host_code;
    void       *entry;
    uint64_t    pad;
} i686_ibtc_entry_t;

_Static_assert(sizeof(i686_ibtc_entry_t) == 32, "i686_ibtc_entry_t must be 32 bytes");

/* Engine selection (I686RT_ENGINE, --engine). */
enum {
    I686_ENGINE_INTERP = 0, /* portable C interpreter: correctness oracle (D2) */
    I686_ENGINE_DBT    = 1  /* x86->A64 dynamic binary translator            */
};

/*
 * Architectural + runtime state for a 32-bit x86 guest thread.
 *
 * ABI-locked prefix (offsets 0..35303) shared with the Phase 3 trampoline:
 *   0x000 gpr[8]         EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI (w0..w7 under DBT
 *                        when live; callee-saved w19..w26 hold them across
 *                        the trampoline per D7)
 *   0x020 eip, 0x024 eflags
 *   0x028 seg_base[6]    ES,CS,SS,DS,FS,GS linear bases (D8; flat = 0)
 *   0x040 seg_sel[6]     selectors incl. LDT TI=1 entries
 *   0x04c lazy flags descriptor (see enum above)
 *   0x070 guest_base     host base G of the [G, G+4GiB) window (D4)
 *   0x078 exit_reason / exit_arg (int/syscall nr or insn index)
 *   0x080 fault_addr, 0x084 exit_dest
 *   0x088 x87_st[8][16]  per-slot raw storage: default mode keeps the double
 *                        in the low 8 bytes, --x87-80 keeps the full 80-bit
 *                        value, MMX aliases the low 8 bytes (D9)
 *   0x108 xmm[8][16], 0x188 x87 env, 0x198 mxcsr (D10)
 *   0x1a0 fast-dispatch fields mirroring a32rt's trampoline contract
 *   0x1e8 ras[64], 0x9e8 ibtc[1024]
 */
typedef struct i686_ctx {
    uint32_t gpr[8];                    /* 0x000 */
    uint32_t eip;                       /* 0x020 */
    uint32_t eflags;                    /* 0x024 */
    uint32_t seg_base[I686_SEG_COUNT];  /* 0x028 */
    uint16_t seg_sel[I686_SEG_COUNT];   /* 0x040 */
    uint32_t lazy_op;                   /* 0x04c */
    uint32_t lazy_res;                  /* 0x050 */
    uint32_t lazy_src1;                 /* 0x054 */
    uint32_t lazy_src2;                 /* 0x058 */
    uint32_t lazy_cf_in;                /* 0x05c */
    uint32_t exit_target;               /* 0x060 trampoline/dbt scratch */
    uint32_t x87_top;                   /* 0x064 fast TOP (0..7; fstat mirrors) */
    uint32_t pad_lock0;                 /* 0x068 */
    uint64_t guest_base;                /* 0x070 */
    uint32_t exit_reason;               /* 0x078 */
    uint32_t exit_arg;                  /* 0x07c */
    uint32_t fault_addr;                /* 0x080 */
    uint32_t exit_dest;                 /* 0x084 */
    uint8_t  x87_st[8][16];             /* 0x088 */
    uint8_t  xmm[8][16];                /* 0x108 */
    uint16_t fctrl;                     /* 0x188 x87 control word */
    uint16_t fstat;                     /* 0x18a x87 status word */
    uint16_t ftag;                      /* 0x18c packed tag word */
    uint16_t fop;                       /* 0x18e last opcode */
    uint32_t fpu_ip;                    /* 0x190 last x87 instruction pointer */
    uint32_t fpu_dp;                    /* 0x194 last x87 data pointer */
    uint32_t mxcsr;                     /* 0x198 */
    uint32_t mxcsr_mask;                /* 0x19c */
    uint64_t          sig_mask;         /* 0x1a0 */
    volatile uint64_t pending_signals;  /* 0x1a8 */
    bool              trace_enabled;    /* 0x1b0 */
    bool              gdb_enabled;      /* 0x1b1 */
    bool              single_step;      /* 0x1b2 */
    volatile bool     sync_sig_delivered; /* 0x1b3 */
    uint32_t          pad_lock1;        /* 0x1b4 */
    uint64_t          blocks_executed;  /* 0x1b8 */
    uint64_t          chain_hits;       /* 0x1c0 */
    void             *last_exec_entry;  /* 0x1c8 */
    uint64_t          ibtc_hits;        /* 0x1d0 */
    uint64_t          ras_hits;         /* 0x1d8 */
    uint32_t          ras_top;          /* 0x1e0 */
    uint32_t          pad_lock2;        /* 0x1e4 */
    i686_ibtc_entry_t ras[I686_RAS_SIZE];   /* 0x1e8 */
    i686_ibtc_entry_t ibtc[I686_IBTC_SIZE]; /* 0x9e8 */

    /* ---- C-only tail (no asm offset dependencies; extend at end only) ---- */

    /* Guest memory layout & allocator inside [G, G + 4GiB) */
    uint32_t brk_base;
    uint32_t brk_curr;
    uint32_t mmap_cursor;       /* bottom-up cursor for guest mmap2 (§3.7) */
    uint32_t interp_base;
    uint32_t elf_base;
    uint32_t elf_entry;
    uint32_t stack_top;
    uint32_t stack_base;
    uint32_t vdso_base;         /* synthetic i386 vDSO (D12, Phase 2) */

    /* Host handshake (D14: /dev/a32host, A32H_ABI 1.0, unchanged) */
    a32h_info_t host_info;
    bool        has_host_info;

    /* Tracked guest regions (sorted by start) for /proc/self/maps + gaps */
    i686_region_t regions[I686_MAX_REGIONS];
    size_t        region_count;

    /* Emulated descriptor tables (D8, Phases 7) */
    void    *ldt;               /* array of I686_LDT_MAX_ENTRIES descriptors */
    uint32_t ldt_entries;
    uint32_t gdt_tls_slots[3];  /* GDT_ENTRY_TLS_MIN..+2 bases */

    /* Thread, futex, and signal state */
    uint32_t clear_child_tid;
    uint32_t robust_list_head;
    uint32_t robust_list_len;
    uint32_t altstack_sp;
    uint32_t altstack_size;
    uint32_t altstack_flags;
    int      host_tid;
    bool     is_thread_clone;

    /* Guest startup metadata for /proc/self/{cmdline,auxv,exe} */
    int      guest_argc;
    char   **guest_argv;
    char   **host_envp;
    uint32_t auxv_data[64];
    size_t   auxv_bytes;

    /* Configuration & engine selection */
    const char *sysroot;
    const char *exec_path;
    const char *cache_dir;
    int         engine;         /* I686_ENGINE_* */
    bool        x87_80;         /* --x87-80 / I686RT_X87=80 (D9) */
    bool        stats_enabled;
    int         gdb_port;

    /* Instrumentation counters */
    uint64_t blocks_compiled;
    uint64_t syscalls_executed;
    uint64_t icache_flushes;
    uint64_t wx_transitions;
    uint64_t flags_elided;
} i686_ctx_t;

/* ABI-locked offsets (src/trampoline.S, Phase 3, must agree). */
#define I686_CTX_X87_OFFSET  0x088U
#define I686_CTX_XMM_OFFSET  0x108U
#define I686_CTX_MXCSR_OFFSET 0x198U

_Static_assert(offsetof(i686_ctx_t, gpr) == 0, "gpr must be at offset 0");
_Static_assert(offsetof(i686_ctx_t, eip) == 32, "eip must be at offset 32");
_Static_assert(offsetof(i686_ctx_t, eflags) == 36, "eflags must be at offset 36");
_Static_assert(offsetof(i686_ctx_t, seg_base) == 40, "seg_base must be at offset 40");
_Static_assert(offsetof(i686_ctx_t, seg_sel) == 64, "seg_sel must be at offset 64");
_Static_assert(offsetof(i686_ctx_t, lazy_op) == 76, "lazy_op must be at offset 76");
_Static_assert(offsetof(i686_ctx_t, guest_base) == 112, "guest_base must be at offset 112");
_Static_assert(offsetof(i686_ctx_t, exit_reason) == 120, "exit_reason must be at offset 120");
_Static_assert(offsetof(i686_ctx_t, exit_arg) == 124, "exit_arg must be at offset 124");
_Static_assert(offsetof(i686_ctx_t, fault_addr) == 128, "fault_addr must be at offset 128");
_Static_assert(offsetof(i686_ctx_t, exit_dest) == 132, "exit_dest must be at offset 132");
_Static_assert(offsetof(i686_ctx_t, x87_st) == 136, "x87_st must be at offset 136 (0x88)");
_Static_assert(offsetof(i686_ctx_t, xmm) == 264, "xmm must be at offset 264 (0x108)");
_Static_assert(offsetof(i686_ctx_t, fctrl) == 392, "fctrl must be at offset 392 (0x188)");
_Static_assert(offsetof(i686_ctx_t, mxcsr) == 408, "mxcsr must be at offset 408 (0x198)");
_Static_assert(offsetof(i686_ctx_t, sig_mask) == 416, "sig_mask must be at offset 416 (0x1a0)");
_Static_assert(offsetof(i686_ctx_t, pending_signals) == 424, "pending_signals must be at offset 424");
_Static_assert(offsetof(i686_ctx_t, trace_enabled) == 432, "trace_enabled must be at offset 432");
_Static_assert(offsetof(i686_ctx_t, gdb_enabled) == 433, "gdb_enabled must be at offset 433");
_Static_assert(offsetof(i686_ctx_t, single_step) == 434, "single_step must be at offset 434");
_Static_assert(offsetof(i686_ctx_t, sync_sig_delivered) == 435, "sync_sig_delivered must be at offset 435");
_Static_assert(offsetof(i686_ctx_t, blocks_executed) == 440, "blocks_executed must be at offset 440");
_Static_assert(offsetof(i686_ctx_t, chain_hits) == 448, "chain_hits must be at offset 448");
_Static_assert(offsetof(i686_ctx_t, last_exec_entry) == 456, "last_exec_entry must be at offset 456");
_Static_assert(offsetof(i686_ctx_t, ibtc_hits) == 464, "ibtc_hits must be at offset 464");
_Static_assert(offsetof(i686_ctx_t, ras_hits) == 472, "ras_hits must be at offset 472");
_Static_assert(offsetof(i686_ctx_t, ras_top) == 480, "ras_top must be at offset 480");
_Static_assert(offsetof(i686_ctx_t, ras) == 488, "ras must be at offset 488 (0x1e8)");
_Static_assert(offsetof(i686_ctx_t, ibtc) == 2536, "ibtc must be at offset 2536 (0x9e8)");
_Static_assert(sizeof(i686_ibtc_entry_t) * I686_IBTC_SIZE == 32768,
               "IBTC array must span offsets 2536..35303");

static inline void i686_spin_lock(_Atomic uint32_t *lock)
{
    while (atomic_exchange_explicit(lock, 1U, memory_order_acquire) != 0U) {
        sched_yield();
    }
}

static inline void i686_spin_unlock(_Atomic uint32_t *lock)
{
    atomic_store_explicit(lock, 0U, memory_order_release);
}

/* Guest VA -> host pointer.  va is u32: never sign-extend or truncate (D4/D7). */
static inline void *i686_guest_ptr(const i686_ctx_t *ctx, uint32_t guest_va)
{
    return (void *)(uintptr_t)(ctx->guest_base + (uint64_t)guest_va);
}

static inline uint32_t i686_page_down(uint32_t x)
{
    return x & ~(I686_PAGE_SIZE - 1U);
}

static inline uint32_t i686_page_up(uint32_t x)
{
    return (x + (I686_PAGE_SIZE - 1U)) & ~(I686_PAGE_SIZE - 1U);
}

/* Cache keys hash on guest EIP only — no T bit (SPEC §3.3). */
static inline uint32_t i686_make_key(uint32_t eip)
{
    return eip;
}

static inline uint32_t i686_ibtc_hash(uint32_t eip)
{
    return (eip >> 2U) & (I686_IBTC_SIZE - 1U);
}

/*
 * Guest prot -> host prot for window mappings.  Guest PROT_EXEC is never
 * host-exec (window is data; translated code lives outside the window,
 * §3.7), which also dissolves any W^X conflict; SMC write-protection is
 * layered on top by the JIT (D11), not here.
 */
static inline int i686_host_prot(const i686_ctx_t *ctx, uint32_t guest_prot)
{
    (void)ctx;
    uint32_t p = guest_prot & 0x7U;
    if ((p & 0x4U) != 0U) {
        p |= 0x1U; /* PROT_EXEC implies PROT_READ on host */
        p &= ~0x4U;
    }
    return (int)p;
}

#endif /* I686RT_H */
