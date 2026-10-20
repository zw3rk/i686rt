/* gen_hello386.c — emit a minimal ELF32 LSB EM_386 static executable
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * E03 test-vector generator: builds hello-i386 without any cross
 * toolchain. The image is one PT_LOAD segment covering header, program
 * header and code; the entry point lands on the first code byte:
 *
 *   mov $1, %eax      b8 01 00 00 00   (SYS_exit for i386)
 *   mov $42, %ebx     bb 2a 00 00 00   (exit status 42)
 *   int $0x80         cd 80
 *
 * p_offset and p_vaddr are congruent modulo the 4 KiB page size, so the
 * non-page-aligned file layout is a valid Linux mapping.
 */
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BASE_VADDR   0x08048000u
#define EHDR_SIZE    52u
#define PHDR_SIZE    32u
#define CODE_OFF     (EHDR_SIZE + PHDR_SIZE)
#define IMG_SIZE     512u

/* The 11-byte exit(42) sequence. */
static const uint8_t code[] = {
    0xb8, 0x01, 0x00, 0x00, 0x00,   /* mov $1, %eax  */
    0xbb, 0x2a, 0x00, 0x00, 0x00,   /* mov $42, %ebx */
    0xcd, 0x80                      /* int $0x80     */
};

static void put_u16(uint8_t *p, size_t off, uint16_t v) {
    p[off + 0] = (uint8_t)(v & 0xffu);
    p[off + 1] = (uint8_t)((v >> 8) & 0xffu);
}

static void put_u32(uint8_t *p, size_t off, uint32_t v) {
    p[off + 0] = (uint8_t)(v & 0xffu);
    p[off + 1] = (uint8_t)((v >> 8) & 0xffu);
    p[off + 2] = (uint8_t)((v >> 16) & 0xffu);
    p[off + 3] = (uint8_t)((v >> 24) & 0xffu);
}

int main(void) {
    uint8_t img[IMG_SIZE];
    memset(img, 0, sizeof(img));

    if (CODE_OFF + sizeof(code) > sizeof(img)) {
        fprintf(stderr, "gen_hello386: image buffer too small\n");
        return 1;
    }

    /* ---- Elf32_Ehdr ---- */
    img[0] = 0x7f;
    img[1] = 'E';
    img[2] = 'L';
    img[3] = 'F';
    img[4] = 1;                      /* ELFCLASS32 */
    img[5] = 1;                      /* ELFDATA2LSB */
    img[6] = 1;                      /* EV_CURRENT */
    img[7] = 0;                      /* ELFOSABI_NONE */
    put_u16(img, 16, 2);             /* e_type = ET_EXEC */
    put_u16(img, 18, 3);             /* e_machine = EM_386 */
    put_u32(img, 20, 1);             /* e_version */
    put_u32(img, 24, BASE_VADDR + (uint32_t)CODE_OFF); /* e_entry */
    put_u32(img, 28, EHDR_SIZE);     /* e_phoff */
    put_u32(img, 32, 0);             /* e_shoff */
    put_u32(img, 36, 0);             /* e_flags */
    put_u16(img, 40, EHDR_SIZE);     /* e_ehsize */
    put_u16(img, 42, PHDR_SIZE);     /* e_phentsize */
    put_u16(img, 44, 1);             /* e_phnum */
    put_u16(img, 46, 40);            /* e_shentsize (nominal) */
    put_u16(img, 48, 0);             /* e_shnum */
    put_u16(img, 50, 0);             /* e_shstrndx */

    /* ---- Elf32_Phdr: one RWX-free R+X PT_LOAD over the whole file ---- */
    put_u32(img, EHDR_SIZE + 0, 1);                       /* p_type = PT_LOAD */
    put_u32(img, EHDR_SIZE + 4, 0);                       /* p_offset */
    put_u32(img, EHDR_SIZE + 8, BASE_VADDR);              /* p_vaddr */
    put_u32(img, EHDR_SIZE + 12, BASE_VADDR);             /* p_paddr */
    put_u32(img, EHDR_SIZE + 16,
            (uint32_t)CODE_OFF + (uint32_t)sizeof(code)); /* p_filesz */
    put_u32(img, EHDR_SIZE + 20,
            (uint32_t)CODE_OFF + (uint32_t)sizeof(code)); /* p_memsz */
    put_u32(img, EHDR_SIZE + 24, 5);                      /* p_flags = R|X */
    put_u32(img, EHDR_SIZE + 28, 0x1000u);                /* p_align */

    /* ---- Code ---- */
    memcpy(img + CODE_OFF, code, sizeof(code));

    const char *out_path = "hello-i386";
    FILE *f = fopen(out_path, "wb");
    if (f == NULL) {
        fprintf(stderr, "gen_hello386: fopen %s failed: %s\n",
                out_path, strerror(errno));
        return 1;
    }
    size_t total = CODE_OFF + sizeof(code);
    if (fwrite(img, 1, total, f) != total) {
        fprintf(stderr, "gen_hello386: fwrite %s failed: %s\n",
                out_path, strerror(errno));
        fclose(f);
        return 1;
    }
    if (fclose(f) != 0) {
        fprintf(stderr, "gen_hello386: fclose %s failed: %s\n",
                out_path, strerror(errno));
        return 1;
    }
    if (chmod(out_path, 0755) != 0) {
        fprintf(stderr, "gen_hello386: chmod %s failed: %s\n",
                out_path, strerror(errno));
        return 1;
    }
    printf("gen_hello386: wrote %s (%zu bytes, entry 0x%08x)\n",
           out_path, total, BASE_VADDR + (uint32_t)CODE_OFF);
    return 0;
}
