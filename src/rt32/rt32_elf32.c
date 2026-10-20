/*
 * src/rt32/rt32_elf32.c — ELFCLASS32 (EM_386) loader
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from a32rt/src/elf32.c @ d84feb3 (D13): renamed a32_→rt32_,
 * retyped on i686_ctx_t, EM_ARM→EM_386, ARM kuser page and Thumb entry
 * heuristics dropped (the i386 vDSO replaces kuser in Phase 2, D12).
 */

#define _GNU_SOURCE
#include "rt32.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define EI_NIDENT   16U
#define ELFCLASS32  1U
#define ELFDATA2LSB 1U
#define ET_EXEC     2U
#define ET_DYN      3U
#define EM_386      3U

#define PT_LOAD   1U
#define PT_INTERP 3U
#define PT_PHDR   6U

#define PF_X 0x1U
#define PF_W 0x2U
#define PF_R 0x4U

typedef struct elf32_ehdr {
    uint8_t  e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} elf32_ehdr_t;

typedef struct elf32_phdr {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
} elf32_phdr_t;

int rt32_open_guest_ro(const i686_ctx_t *ctx, const char *guest_path)
{
    if (guest_path == NULL || guest_path[0] == '\0') {
        return -1;
    }
    /* a32rt resolved via a32_resolve_guest_path() (syscalls.c, not vendored):
     * resolve absolute guest paths against the sysroot here; the full resolver
     * (relative paths, /proc magic) arrives with the Phase 2 syscall marshal. */
    if (ctx != NULL && guest_path[0] == '/' &&
        ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        char resolved[PATH_MAX];
        int n = snprintf(resolved, sizeof(resolved), "%s%s", ctx->sysroot, guest_path);
        if (n > 0 && (size_t)n < sizeof(resolved)) {
            int fd = open(resolved, O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                return fd;
            }
        }
    }
    return open(guest_path, O_RDONLY | O_CLOEXEC);
}

static int pread_full(int fd, void *buf, size_t count, off_t offset)
{
    uint8_t *p = (uint8_t *)buf;
    size_t total = 0;
    while (total < count) {
        ssize_t n = pread(fd, p + total, count - total, offset + (off_t)total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

static int protect_and_record_seg(i686_ctx_t *ctx, uint32_t start, uint32_t end,
                                  uint32_t guest_prot, const char *label)
{
    if (mprotect(i686_guest_ptr(ctx, start), end - start, i686_host_prot(ctx, guest_prot)) != 0) {
        fprintf(stderr, "i686rt: %s: mprotect failed on [0x%x, 0x%x): %s\n",
                label, start, end, strerror(errno));
        return -1;
    }
    rt32_vm_record_region(ctx, start, end, guest_prot, 0x12U, label);
    return 0;
}

static int load_elf32_image(i686_ctx_t *ctx, int fd, uint32_t default_pie_base,
                            const char *label, rt32_elf_info_t *out)
{
    elf32_ehdr_t ehdr;
    if (pread_full(fd, &ehdr, sizeof(ehdr), 0) != 0) {
        fprintf(stderr, "i686rt: %s: failed to read ELF header\n", label);
        return -1;
    }

    if (ehdr.e_ident[0] != 0x7fU || ehdr.e_ident[1] != 'E' ||
        ehdr.e_ident[2] != 'L'  || ehdr.e_ident[3] != 'F') {
        fprintf(stderr, "i686rt: %s: not an ELF file\n", label);
        return -1;
    }
    if (ehdr.e_ident[4] != ELFCLASS32 || ehdr.e_ident[5] != ELFDATA2LSB ||
        ehdr.e_machine != EM_386) {
        fprintf(stderr, "i686rt: %s: not a 32-bit little-endian x86 (EM_386) ELF\n", label);
        return -1;
    }
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN) {
        fprintf(stderr, "i686rt: %s: unsupported ELF type %u\n", label, ehdr.e_type);
        return -1;
    }
    if (ehdr.e_phentsize != sizeof(elf32_phdr_t) || ehdr.e_phnum == 0U || ehdr.e_phnum > 64U) {
        fprintf(stderr, "i686rt: %s: invalid program header table\n", label);
        return -1;
    }

    elf32_phdr_t phdrs[64];
    size_t phdr_bytes = (size_t)ehdr.e_phnum * sizeof(elf32_phdr_t);
    if (pread_full(fd, phdrs, phdr_bytes, (off_t)ehdr.e_phoff) != 0) {
        fprintf(stderr, "i686rt: %s: failed to read program headers\n", label);
        return -1;
    }

    uint32_t min_vaddr = UINT32_MAX;
    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_memsz > 0U) {
            if (phdrs[i].p_vaddr < min_vaddr) {
                min_vaddr = phdrs[i].p_vaddr;
            }
        }
    }
    if (min_vaddr == UINT32_MAX) {
        fprintf(stderr, "i686rt: %s: no PT_LOAD segments\n", label);
        return -1;
    }

    uint32_t load_bias = 0U;
    if (ehdr.e_type == ET_DYN && min_vaddr < 0x10000U) {
        load_bias = default_pie_base;
    }

    if (ehdr.e_entry == 0U) {
        /* a32rt tolerated e_entry == 0 for AOT-loaded DSOs; i686rt has no AOT mode. */
        fprintf(stderr, "i686rt: %s: missing entry point (e_entry == 0)\n", label);
        return -1;
    }

    uint64_t entry64 = 0ULL;
    if (ehdr.e_entry != 0U) {
        entry64 = (uint64_t)ehdr.e_entry + (uint64_t)load_bias;
        if (entry64 < 0x10000ULL || entry64 >= (uint64_t)I686_TASK_SIZE_TOP) {
            fprintf(stderr, "i686rt: %s: entry point 0x%llx out of guest bounds\n",
                    label, (unsigned long long)entry64);
            return -1;
        }
    }

    memset(out, 0, sizeof(*out));
    out->load_bias = load_bias + i686_page_down(min_vaddr);
    out->entry     = (uint32_t)entry64;
    out->phent     = ehdr.e_phentsize;
    out->phnum     = ehdr.e_phnum;
    /* a32rt's misaligned-ARM-entry check was dropped: x86 entries are arbitrary byte addresses. */

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const elf32_phdr_t *ph = &phdrs[i];
        if (ph->p_type == PT_PHDR) {
            uint64_t phdr_va64 = (uint64_t)load_bias + (uint64_t)ph->p_vaddr;
            if (phdr_va64 + phdr_bytes <= (uint64_t)I686_TASK_SIZE_TOP) {
                out->phdr_vaddr = (uint32_t)phdr_va64;
            }
        } else if (ph->p_type == PT_INTERP) {
            if (ph->p_filesz == 0U || ph->p_filesz >= sizeof(out->interp_path)) {
                fprintf(stderr, "i686rt: %s: invalid PT_INTERP filesz %u\n", label, ph->p_filesz);
                return -1;
            }
            if (pread_full(fd, out->interp_path, ph->p_filesz, (off_t)ph->p_offset) != 0) {
                return -1;
            }
            out->interp_path[ph->p_filesz] = '\0';
            if (out->interp_path[0] == '\0') {
                return -1;
            }
        }
    }

    uint32_t highest_mapped_end  = 0U;
    uint32_t highest_mapped_prot = 0U;
    uint32_t prev_seg_end        = 0U;
    uint32_t fallback_phdr_vaddr = 0U;
    bool     entry_in_load       = false;
    bool     phdr_in_load        = false;

    for (uint16_t i = 0; i < ehdr.e_phnum; i++) {
        const elf32_phdr_t *ph = &phdrs[i];
        if (ph->p_type != PT_LOAD || ph->p_memsz == 0U) {
            continue;
        }
        if (ph->p_filesz > ph->p_memsz) {
            fprintf(stderr, "i686rt: %s: invalid segment filesz (0x%x) > memsz (0x%x)\n",
                    label, ph->p_filesz, ph->p_memsz);
            return -1;
        }

        uint64_t seg_vaddr64 = (uint64_t)load_bias + (uint64_t)ph->p_vaddr;
        uint64_t memsz       = (uint64_t)ph->p_memsz;
        if (seg_vaddr64 >= (uint64_t)I686_TASK_SIZE_TOP ||
            seg_vaddr64 + memsz > (uint64_t)I686_TASK_SIZE_TOP) {
            fprintf(stderr, "i686rt: %s: segment [0x%llx, 0x%llx) out of guest bounds\n",
                    label, (unsigned long long)seg_vaddr64,
                    (unsigned long long)(seg_vaddr64 + memsz));
            return -1;
        }

        uint32_t seg_vaddr = (uint32_t)seg_vaddr64;
        uint64_t seg_end64 = seg_vaddr64 + memsz;
        if (seg_vaddr < prev_seg_end) {
            fprintf(stderr, "i686rt: %s: overlapping or out-of-order PT_LOAD segment at 0x%x\n",
                    label, seg_vaddr);
            return -1;
        }
        prev_seg_end = (uint32_t)seg_end64;

        if (out->entry != 0U) {
            /* x86: entry is a plain byte address (no Thumb bit), min insn length 1 */
            uint32_t entry_pc      = out->entry;
            uint32_t entry_min_len = 1U;
            if ((ph->p_flags & PF_X) != 0U &&
                entry_pc >= seg_vaddr &&
                (uint64_t)entry_pc + entry_min_len <= seg_vaddr64 + memsz) {
                entry_in_load = true;
            }
        }
        uint32_t page_start = i686_page_down(seg_vaddr);
        uint64_t map_end64  = (seg_end64 + 0xFFFULL) & ~0xFFFULL;
        if (page_start < 0x10000U || map_end64 > (uint64_t)I686_TASK_SIZE_TOP) {
            fprintf(stderr, "i686rt: %s: segment [0x%x, 0x%llx) out of guest bounds\n",
                    label, page_start, (unsigned long long)map_end64);
            return -1;
        }
        uint32_t map_end   = (uint32_t)map_end64;
        uint32_t map_start = (page_start < highest_mapped_end) ? highest_mapped_end : page_start;
        for (size_t r = 0U; r < ctx->region_count; r++) {
            if (map_start < ctx->regions[r].end && map_end > ctx->regions[r].start) {
                fprintf(stderr, "i686rt: %s: segment [0x%x, 0x%x) overlaps existing region\n",
                        label, map_start, map_end);
                return -1;
            }
        }

        uint32_t guest_prot = ((ph->p_flags & PF_R) ? (uint32_t)PROT_READ : 0U) |
                              ((ph->p_flags & PF_W) ? (uint32_t)PROT_WRITE : 0U) |
                              ((ph->p_flags & PF_X) ? (uint32_t)PROT_EXEC : 0U);

        uint32_t shared_end  = (map_end < map_start) ? map_end : map_start;
        uint32_t merged_prot = highest_mapped_prot | guest_prot;
        if (page_start < map_start) {
            if (mprotect(i686_guest_ptr(ctx, page_start), shared_end - page_start,
                         PROT_READ | PROT_WRITE) != 0) {
                fprintf(stderr, "i686rt: %s: mprotect RW failed on shared page [0x%x, 0x%x): %s\n",
                        label, page_start, shared_end, strerror(errno));
                return -1;
            }
        }

        if (map_end > map_start) {
            void *res = mmap(i686_guest_ptr(ctx, map_start), map_end - map_start,
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
            if (res == MAP_FAILED) {
                fprintf(stderr, "i686rt: %s: failed to map segment [0x%x, 0x%x): %s\n",
                        label, map_start, map_end, strerror(errno));
                return -1;
            }
        }

        uint32_t read_file_off = ph->p_offset;
        uint32_t read_file_len = ph->p_filesz;
        if (ph->p_filesz > 0U) {
            uint32_t page_off = ph->p_vaddr & 0xFFFU;
            uint32_t dst_va   = seg_vaddr;
            if (page_start == map_start && page_off != 0U && ph->p_offset >= page_off) {
                read_file_off = ph->p_offset - page_off;
                read_file_len = ph->p_filesz + page_off;
                dst_va        = map_start;
            }
            if (pread_full(fd, i686_guest_ptr(ctx, dst_va), read_file_len,
                           (off_t)read_file_off) != 0) {
                fprintf(stderr, "i686rt: %s: failed to read segment payload\n", label);
                return -1;
            }
        }

        if (ph->p_memsz > ph->p_filesz) {
            memset(i686_guest_ptr(ctx, seg_vaddr + ph->p_filesz), 0,
                   (size_t)(ph->p_memsz - ph->p_filesz));
        }

        if (page_start < map_start) {
            if (protect_and_record_seg(ctx, page_start, shared_end, merged_prot, label) != 0) {
                return -1;
            }
            highest_mapped_prot = merged_prot;
        }
        if (map_end > map_start) {
            if (protect_and_record_seg(ctx, map_start, map_end, guest_prot, label) != 0) {
                return -1;
            }
            highest_mapped_end  = map_end;
            highest_mapped_prot = guest_prot;
        }

        if (ph->p_flags & PF_X) {
            if (out->text_start == 0U || seg_vaddr < out->text_start) {
                out->text_start = seg_vaddr;
            }
            if (seg_vaddr + ph->p_memsz > out->text_end) {
                out->text_end = seg_vaddr + ph->p_memsz;
            }
        }

        uint32_t base_va = (read_file_off < ph->p_offset) ? page_start : seg_vaddr;
        if (out->phdr_vaddr != 0U &&
            out->phdr_vaddr >= base_va &&
            (uint64_t)out->phdr_vaddr + phdr_bytes <= (uint64_t)base_va + (uint64_t)read_file_len) {
            phdr_in_load = true;
        }
        if (fallback_phdr_vaddr == 0U && read_file_off <= ehdr.e_phoff &&
            (uint64_t)ehdr.e_phoff + phdr_bytes <= (uint64_t)read_file_off + (uint64_t)read_file_len) {
            fallback_phdr_vaddr = base_va + (ehdr.e_phoff - read_file_off);
        }

        if (map_end > out->max_vaddr) {
            out->max_vaddr = map_end;
        }
    }

    if (!phdr_in_load) {
        out->phdr_vaddr = 0U;
    }
    if (out->phdr_vaddr == 0U) {
        out->phdr_vaddr = fallback_phdr_vaddr;
    }

    /* a32rt's Thumb-vs-ARM prologue scan for e_entry == 0 images was dropped:
     * e_entry == 0 is rejected above and x86 has no dual instruction set. */

    if (!entry_in_load) {
        fprintf(stderr, "i686rt: %s: entry point 0x%x is not within any PT_LOAD segment\n",
                label, out->entry);
        return -1;
    }

    return 0;
}

int rt32_elf_load(i686_ctx_t *ctx, int exec_fd, const char *path, rt32_elf_info_t *out_info)
{
    if (!ctx || !out_info) {
        return -1;
    }

    int fd = exec_fd;
    if (fd < 0) {
        if (!path) {
            return -1;
        }
        fd = rt32_open_guest_ro(ctx, path);
        if (fd < 0) {
            fprintf(stderr, "i686rt: cannot open '%s': %s\n", path, strerror(errno));
            return -1;
        }
    }

    int rc = load_elf32_image(ctx, fd, 0x00400000U, path ? path : "[guest]", out_info);
    close(fd);
    if (rc != 0) {
        return -1;
    }

    ctx->elf_base  = out_info->load_bias;
    ctx->elf_entry = out_info->entry;
    ctx->brk_base  = i686_page_up(out_info->max_vaddr);
    ctx->brk_curr  = ctx->brk_base;

    /* Load PT_INTERP if present */
    if (out_info->interp_path[0] != '\0') {
        int ifd = rt32_open_guest_ro(ctx, out_info->interp_path);
        if (ifd < 0) {
            fprintf(stderr, "i686rt: cannot open interpreter '%s': %s\n",
                    out_info->interp_path, strerror(errno));
            return -1;
        }

        rt32_elf_info_t interp_info;
        uint32_t interp_base = (ctx->brk_base > 0x3F000000U) ? ctx->brk_base : 0x3F000000U;
        int irc = load_elf32_image(ctx, ifd, interp_base, out_info->interp_path, &interp_info);
        close(ifd);
        if (irc != 0) {
            return -1;
        }
        out_info->interp_base = interp_info.load_bias;
        ctx->interp_base      = interp_info.load_bias;
        ctx->elf_entry        = interp_info.entry;
        uint32_t interp_end   = i686_page_up(interp_info.max_vaddr);
        if (ctx->brk_base >= interp_info.load_bias && ctx->brk_base < interp_end) {
            ctx->brk_base = interp_end;
            ctx->brk_curr = ctx->brk_base;
        }
    }

    return 0;
}

/* a32rt's a32_kuser_setup() (ARM kuser helper page at 0xffff0000) was dropped
 * entirely: i386 guests use the synthetic vDSO instead (Phase 2, SPEC D12). */
