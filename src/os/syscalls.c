/*
 * src/os/syscalls.c — minimal i386 (int 0x80) syscall layer (Phase 1, L1f)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * i386 syscall ABI (SPEC §3.4): the syscall number travels in EAX and the
 * six arguments in EBX, ECX, EDX, ESI, EDI, EBP (in that order).  The
 * result goes back to EAX: success values and guest addresses as unsigned
 * 32-bit patterns, errors as negative errno (-38 = -ENOSYS), i.e. the
 * kernel's -4095..-1 window that guest libcs probe with IS_ERR_VALUE().
 *
 * Implemented in Phase 1 (smoke set): read(3), write(4), exit(1),
 * exit_group(252), brk(45), mmap2(192), set_thread_area(243), uname(122),
 * getpid(20).  Every other number returns -ENOSYS in EAX.
 *
 * Exit contract (for the engine loop in src/interp/interp.c): exit(1) and
 * exit_group(252) never return to the guest.  The loop checks
 * i686_syscall_is_exit(nr) — nr taken from EAX before dispatch (or from
 * ctx->exit_arg where the dispatcher parks the syscall number) — and
 * treats the dispatch as terminal instead of resuming at EIP.  The guest
 * exit status (first argument, EBX) is returned from i686_handle_syscall
 * and mirrored into EAX, so the loop can propagate it to the host exit
 * status.  i686_syscall_name(nr) is provided for tracing/diagnostics.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include "i686rt.h"
#include "os/syscalls_i386.h"
#include "rt32/rt32.h"

/* i386 GDT TLS entries GDT_ENTRY_TLS_MIN..+2 (6..8); selectors with RPL 3,
 * so entry 6 -> selector 0x33, entry 7 -> 0x3b, entry 8 -> 0x43. */
#define I686_GDT_ENTRY_TLS_MIN 6U
#define I686_TLS_SLOTS         3U
#define I686_TLS_SELECTOR(entry) ((uint16_t)((((uint32_t)(entry)) << 3) | 3U))

/* struct utsname (i386): six NUL-padded fields of 65 bytes each. */
#define I686_UTS_FIELD  65U
#define I686_UTS_FIELDS 6U
#define I686_UTS_TOTAL  (I686_UTS_FIELD * I686_UTS_FIELDS)

/* Guest memory is little-endian x86; decode exactly rather than casting. */
static uint32_t guest_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void guest_store_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFU);
    p[1] = (uint8_t)((v >> 8) & 0xFFU);
    p[2] = (uint8_t)((v >> 16) & 0xFFU);
    p[3] = (uint8_t)((v >> 24) & 0xFFU);
}

/* Host syscall result -> guest convention: negative errno, else the value.
 * Short (partial) read/write counts are genuine syscall results. */
static long host_ret(ssize_t n)
{
    return (n < 0) ? -(long)errno : (long)n;
}

/* Guest u32 result as the kernel would leave it in EAX: vm_mmap2 returns
 * addresses and (uint32_t)-errno in one u32; sign-extend so errors read as
 * negative errno here, and the EAX truncation at the bottom of
 * i686_handle_syscall restores the exact 32-bit pattern either way. */
static long ret_guest_u32(uint32_t v)
{
    return (long)(int32_t)v;
}

static long sys_read(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    return host_ret(read((int)fd, i686_guest_ptr(ctx, buf_va), (size_t)count));
}

static long sys_write(i686_ctx_t *ctx, uint32_t fd, uint32_t buf_va, uint32_t count)
{
    if (count > 0U && buf_va < 0x1000U) {
        return -EFAULT;
    }
    return host_ret(write((int)fd, i686_guest_ptr(ctx, buf_va), (size_t)count));
}

static long sys_brk(i686_ctx_t *ctx, uint32_t new_brk)
{
    /* rt32_vm_brk: new_brk == 0 reads out the current break; otherwise it
     * grows/shrinks the guest heap and returns the new break (the old one
     * when the request is invalid), matching Linux brk semantics. */
    return ret_guest_u32(rt32_vm_brk(ctx, new_brk));
}

static long sys_mmap2(i686_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                      uint32_t flags, uint32_t fd, uint32_t pgoff)
{
    /* i386 mmap2(addr, len, prot, flags, fd, pgoff): fd in EDI, the page
     * offset (not bytes) in EBP; (int)fd keeps -1 anonymous maps. */
    uint32_t r = rt32_vm_mmap2(ctx, addr, len, prot, flags, (int)fd, pgoff);
    return ret_guest_u32(r);
}

static long sys_getpid(const i686_ctx_t *ctx)
{
    return (ctx->host_tid > 0) ? (long)ctx->host_tid : 1000L;
}

static long sys_uname(i686_ctx_t *ctx, uint32_t buf_va)
{
    static const char *const uts_fields[I686_UTS_FIELDS] = {
        "Linux", "i686rt", "6.1.0", "#1 SMP i686rt", "i686", "(none)",
    };

    if (buf_va > UINT32_MAX - (I686_UTS_TOTAL - 1U)) {
        return -EFAULT; /* struct would wrap the 32-bit guest space */
    }
    uint8_t *buf = (uint8_t *)i686_guest_ptr(ctx, buf_va);
    for (size_t i = 0U; i < I686_UTS_FIELDS; i++) {
        uint8_t *field = buf + i * I686_UTS_FIELD;
        memset(field, 0, I686_UTS_FIELD);
        for (size_t j = 0U; uts_fields[i][j] != '\0' && j < I686_UTS_FIELD - 1U; j++) {
            field[j] = (uint8_t)uts_fields[i][j];
        }
    }
    return 0;
}

/*
 * set_thread_area(243): install a GDT TLS descriptor for the flat-model
 * v1 runtime.  The guest hands us a 16-byte struct user_desc (u32
 * entry_number, u32 base_addr, u32 limit, u32 flags); entry_number == -1
 * asks for the lowest free TLS entry, which is handed back through the
 * same guest field.  Bookkeeping is single-thread-minimal:
 * ctx->gdt_tls_slots[i] holds the installed base of GDT entry 6+i and 0
 * means free (a legitimate base of exactly 0 would be re-allocatable —
 * fine for one thread; revisit together with clone()).
 */
static long sys_set_thread_area(i686_ctx_t *ctx, uint32_t ud_va)
{
    if (ud_va > UINT32_MAX - 15U) {
        return -EFAULT; /* user_desc would wrap the 32-bit guest space */
    }
    uint8_t *ud    = (uint8_t *)i686_guest_ptr(ctx, ud_va);
    uint32_t entry = guest_le32(ud);
    uint32_t base  = guest_le32(ud + 4U);

    uint32_t slot;
    if (entry == 0xFFFFFFFFU) {
        slot = I686_TLS_SLOTS;
        for (uint32_t i = 0U; i < I686_TLS_SLOTS; i++) {
            if (ctx->gdt_tls_slots[i] == 0U) {
                slot = i;
                break;
            }
        }
        if (slot == I686_TLS_SLOTS) {
            return -ESRCH; /* all three TLS entries are in use */
        }
    } else {
        if (entry < I686_GDT_ENTRY_TLS_MIN ||
            entry >= I686_GDT_ENTRY_TLS_MIN + I686_TLS_SLOTS) {
            return -EINVAL;
        }
        slot = entry - I686_GDT_ENTRY_TLS_MIN;
    }

    ctx->gdt_tls_slots[slot]   = base;
    ctx->seg_base[I686_SEG_GS] = base;
    ctx->seg_sel[I686_SEG_GS]  = I686_TLS_SELECTOR(I686_GDT_ENTRY_TLS_MIN + slot);
    guest_store_le32(ud, I686_GDT_ENTRY_TLS_MIN + slot);
    return 0;
}

int i686_syscall_is_exit(long nr)
{
    return (nr == (long)I686__NR_exit || nr == (long)I686__NR_exit_group) ? 1 : 0;
}

const char *i686_syscall_name(long nr)
{
    if (nr < 0L || nr >= (long)I686_NR_MAX) {
        return NULL;
    }
    return i686_sysent[(size_t)nr].name;
}

long i686_handle_syscall(i686_ctx_t *ctx)
{
    uint32_t nr = ctx->gpr[I686_REG_EAX];
    uint32_t a0 = ctx->gpr[I686_REG_EBX];
    uint32_t a1 = ctx->gpr[I686_REG_ECX];
    uint32_t a2 = ctx->gpr[I686_REG_EDX];
    uint32_t a3 = ctx->gpr[I686_REG_ESI];
    uint32_t a4 = ctx->gpr[I686_REG_EDI];
    uint32_t a5 = ctx->gpr[I686_REG_EBP];

    ctx->syscalls_executed++;

    long ret;
    switch (nr) {
    case I686__NR_read:
        ret = sys_read(ctx, a0, a1, a2);
        break;
    case I686__NR_write:
        ret = sys_write(ctx, a0, a1, a2);
        break;
    case I686__NR_exit:
    case I686__NR_exit_group:
        /* Terminal: the engine loop stops via i686_syscall_is_exit();
         * the guest exit status rides back in EAX and our return value. */
        ret = (long)(int32_t)a0;
        break;
    case I686__NR_brk:
        ret = sys_brk(ctx, a0);
        break;
    case I686__NR_mmap2:
        ret = sys_mmap2(ctx, a0, a1, a2, a3, a4, a5);
        break;
    case I686__NR_set_thread_area:
        ret = sys_set_thread_area(ctx, a0);
        break;
    case I686__NR_uname:
        ret = sys_uname(ctx, a1);
        break;
    case I686__NR_getpid:
        ret = sys_getpid(ctx);
        break;
    default:
        ret = -ENOSYS; /* guest sees -38 = -ENOSYS in EAX */
        break;
    }

    ctx->gpr[I686_REG_EAX] = (uint32_t)ret;
    return ret;
}
