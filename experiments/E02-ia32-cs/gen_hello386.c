/*
 * gen_hello386.c — E02: emit a 32-bit i386 static ELF hello binary
 * without any cross toolchain. The host (any POSIX C11) compiles this
 * generator, which writes the ELF file byte-by-byte:
 *
 *   ELF header (ELFCLASS32, ELFDATA2LSB, EM_386, ET_EXEC)
 *   + one PT_LOAD program header (vaddr 0x08048000, R+X, offset 0)
 *   + 12 bytes of code:
 *       b8 01 00 00 00   mov $1, %eax     (__NR_exit, i386)
 *       bb 2a 00 00 00   mov $42, %ebx    (status 42)
 *       cd 80            int $0x80
 *
 * The program therefore exits with status 42 when int 0x80 works, dies
 * with SIGSEGV (139) when compat entry is blocked, and never runs when
 * execve refuses the ELFCLASS32 file (ENOEXEC, reported by run-exe).
 *
 * Usage: gen_hello386 <output-file>
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BASE_VADDR 0x08048000u
#define EHSZ 52u    /* Elf32_Ehdr */
#define PHSZ 32u    /* Elf32_Phdr */
#define CODESZ 12u
#define NPHDR 2u    /* PT_LOAD + PT_GNU_STACK */
#define PADSZ 4096u /* pad file to one page (avoids beyond-EOF faults) */

static void put8(unsigned char *p, uint32_t off, uint8_t v)
{
    p[off] = v;
}

static void put16le(unsigned char *p, uint32_t off, uint16_t v)
{
    p[off] = (unsigned char)(v & 0xFFu);
    p[off + 1u] = (unsigned char)((v >> 8) & 0xFFu);
}

static void put32le(unsigned char *p, uint32_t off, uint32_t v)
{
    p[off] = (unsigned char)(v & 0xFFu);
    p[off + 1u] = (unsigned char)((v >> 8) & 0xFFu);
    p[off + 2u] = (unsigned char)((v >> 16) & 0xFFu);
    p[off + 3u] = (unsigned char)((v >> 24) & 0xFFu);
}

static int write_all(FILE *f, const unsigned char *buf, uint32_t n)
{
    size_t off = 0u;

    while (off < (size_t)n) {
        size_t w = fwrite(buf + off, 1u, (size_t)n - off, f);

        if (w == 0u) {
            return -1;
        }
        off += w;
    }
    return 0;
}

int main(int argc, char **argv)
{
    static unsigned char img[PADSZ];
    const uint32_t code_off = EHSZ + NPHDR * PHSZ;
    const uint32_t filesz = EHSZ + NPHDR * PHSZ + CODESZ;
    FILE *f;

    if (argc != 2) {
        (void)fprintf(stderr, "usage: %s <output-file>\n", argv[0]);
        return 2;
    }

    /* --- Elf32_Ehdr --- */
    put8(img, 0, 0x7F);                 /* e_ident[EI_MAG0] */
    put8(img, 1, 'E');
    put8(img, 2, 'L');
    put8(img, 3, 'F');
    put8(img, 4, 1);                     /* ELFCLASS32 */
    put8(img, 5, 1);                     /* ELFDATA2LSB */
    put8(img, 6, 1);                     /* EV_CURRENT */
    put8(img, 7, 0);                     /* ELFOSABI_NONE */
    put8(img, 8, 0);                     /* EI_ABIVERSION */
    put16le(img, 16, 2);                 /* e_type = ET_EXEC */
    put16le(img, 18, 3);                 /* e_machine = EM_386 */
    put32le(img, 20, 1);                 /* e_version */
    put32le(img, 24, BASE_VADDR + code_off); /* e_entry */
    put32le(img, 28, EHSZ);              /* e_phoff */
    put32le(img, 32, 0);                 /* e_shoff = none */
    put32le(img, 36, 0);                 /* e_flags */
    put16le(img, 40, EHSZ);              /* e_ehsize */
    put16le(img, 42, PHSZ);              /* e_phentsize */
    put16le(img, 44, NPHDR);             /* e_phnum */
    put16le(img, 46, 0);                 /* e_shentsize */
    put16le(img, 48, 0);                 /* e_shnum */
    put16le(img, 50, 0);                 /* e_shstrndx */

    /* --- Elf32_Phdr[0]: single loadable R+X segment at file offset 0 --- */
    put32le(img, EHSZ + 0, 1);           /* p_type = PT_LOAD */
    put32le(img, EHSZ + 4, 0);           /* p_offset = 0 (!) */
    put32le(img, EHSZ + 8, BASE_VADDR);  /* p_vaddr */
    put32le(img, EHSZ + 12, BASE_VADDR); /* p_paddr */
    put32le(img, EHSZ + 16, filesz);     /* p_filesz */
    put32le(img, EHSZ + 20, filesz);     /* p_memsz */
    put32le(img, EHSZ + 24, 5);          /* p_flags = PF_R | PF_X */
    put32le(img, EHSZ + 28, 0x1000);     /* p_align */

    /* --- Elf32_Phdr[1]: PT_GNU_STACK (non-executable stack) --- */
    put32le(img, EHSZ + PHSZ + 0, 0x6474E551u); /* p_type = PT_GNU_STACK */
    put32le(img, EHSZ + PHSZ + 4, 0);    /* p_offset */
    put32le(img, EHSZ + PHSZ + 8, 0);    /* p_vaddr */
    put32le(img, EHSZ + PHSZ + 12, 0);   /* p_paddr */
    put32le(img, EHSZ + PHSZ + 16, 0);   /* p_filesz */
    put32le(img, EHSZ + PHSZ + 20, 0);   /* p_memsz */
    put32le(img, EHSZ + PHSZ + 24, 6);   /* p_flags = PF_R | PF_W */
    put32le(img, EHSZ + PHSZ + 28, 0x10);/* p_align */

    /* --- code: mov $1,%eax; mov $42,%ebx; int $0x80 --- */
    put8(img, code_off + 0, 0xB8);
    put32le(img, code_off + 1, 1u);      /* __NR_exit (i386) */
    put8(img, code_off + 5, 0xBB);
    put32le(img, code_off + 6, 42u);     /* exit status */
    put8(img, code_off + 10, 0xCD);
    put8(img, code_off + 11, 0x80);

    f = fopen(argv[1], "wb");
    if (f == NULL) {
        (void)fprintf(stderr, "%s: cannot open %s for writing\n",
                      argv[0], argv[1]);
        return 1;
    }
    if (write_all(f, img, PADSZ) != 0) {
        (void)fprintf(stderr, "%s: short write to %s\n", argv[0], argv[1]);
        (void)fclose(f);
        return 1;
    }
    if (fclose(f) != 0) {
        (void)fprintf(stderr, "%s: close failed on %s\n", argv[0], argv[1]);
        return 1;
    }
    return 0;
}
