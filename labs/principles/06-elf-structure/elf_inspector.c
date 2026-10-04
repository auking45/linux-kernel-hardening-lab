/**
 * Linux Kernel Hardening Lab - Principles Track 4: Compilation & ELF Architecture
 * labs/principles/06-elf-structure/elf_inspector.c
 *
 * Directly inspects and parses 64-bit ELF headers:
 * 1. ELF Header (Elf64_Ehdr): Magic bytes, architecture, entry point.
 * 2. Program Headers (Elf64_Phdr): Segments loaded by kernel (PT_LOAD, PT_INTERP).
 * 3. Section Headers (Elf64_Shdr): Sections used by linker (.text, .rodata, .data, .bss).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <elf.h>

static const char *get_segment_type_name(uint32_t type)
{
    switch (type) {
    case PT_NULL:         return "PT_NULL";
    case PT_LOAD:         return "PT_LOAD";
    case PT_DYNAMIC:      return "PT_DYNAMIC";
    case PT_INTERP:       return "PT_INTERP";
    case PT_NOTE:         return "PT_NOTE";
    case PT_SHLIB:        return "PT_SHLIB";
    case PT_PHDR:         return "PT_PHDR";
    case PT_TLS:          return "PT_TLS";
    case PT_GNU_EH_FRAME: return "PT_GNU_EH_FRAME";
    case PT_GNU_STACK:    return "PT_GNU_STACK";
    case PT_GNU_RELRO:    return "PT_GNU_RELRO";
    default:              return "PT_OTHER";
    }
}

static const char *get_section_type_name(uint32_t type)
{
    switch (type) {
    case SHT_NULL:     return "SHT_NULL";
    case SHT_PROGBITS: return "SHT_PROGBITS";
    case SHT_SYMTAB:   return "SHT_SYMTAB";
    case SHT_STRTAB:   return "SHT_STRTAB";
    case SHT_RELA:     return "SHT_RELA";
    case SHT_HASH:     return "SHT_HASH";
    case SHT_DYNAMIC:  return "SHT_DYNAMIC";
    case SHT_NOTE:     return "SHT_NOTE";
    case SHT_NOBITS:   return "SHT_NOBITS (BSS)";
    case SHT_REL:      return "SHT_REL";
    case SHT_DYNSYM:   return "SHT_DYNSYM";
    default:           return "SHT_OTHER";
    }
}

int inspect_elf(const char *filename)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("[-] Failed to open file");
        return 1;
    }

    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr)) {
        perror("[-] Failed to read ELF header");
        close(fd);
        return 1;
    }

    /* Verify ELF Magic bytes: \x7f E L F */
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "[-] Not a valid ELF file: %s\n", filename);
        close(fd);
        return 1;
    }

    printf("============================================================\n");
    printf(" 64-bit ELF Header Inspection: %s\n", filename);
    printf("============================================================\n");
    printf("[1] Magic Bytes      : %02x %02x %02x %02x (ASCII: \\x7f%c%c%c)\n",
           ehdr.e_ident[0], ehdr.e_ident[1], ehdr.e_ident[2], ehdr.e_ident[3],
           ehdr.e_ident[1], ehdr.e_ident[2], ehdr.e_ident[3]);
    printf("[2] Architecture     : %s\n",
           ehdr.e_ident[EI_CLASS] == ELFCLASS64 ? "ELF64 (64-bit)" : "ELF32 (32-bit)");
    printf("[3] Data Encoding    : %s\n",
           ehdr.e_ident[EI_DATA] == ELFDATA2LSB ? "2's complement, Little Endian" : "Big Endian");
    printf("[4] Entry Point      : 0x%lx\n", (unsigned long)ehdr.e_entry);
    printf("[5] Program Headers  : Offset 0x%lx (%d entries, size %d bytes)\n",
           (unsigned long)ehdr.e_phoff, ehdr.e_phnum, ehdr.e_phentsize);
    printf("[6] Section Headers  : Offset 0x%lx (%d entries, size %d bytes)\n",
           (unsigned long)ehdr.e_shoff, ehdr.e_shnum, ehdr.e_shentsize);
    printf("============================================================\n\n");

    /* Read Program Headers (Execution View) */
    printf("=== [Execution View] Program Headers (Segments) ===\n");
    printf("%-18s %-10s %-18s %-10s %-6s\n", "Type", "Offset", "VirtAddr", "MemSize", "Flags");
    printf("-----------------------------------------------------------------\n");

    lseek(fd, ehdr.e_phoff, SEEK_SET);
    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        if (read(fd, &phdr, sizeof(phdr)) != sizeof(phdr)) break;

        char flags_str[4] = "---";
        if (phdr.p_flags & PF_R) flags_str[0] = 'R';
        if (phdr.p_flags & PF_W) flags_str[1] = 'W';
        if (phdr.p_flags & PF_X) flags_str[2] = 'E';

        printf("%-18s 0x%-8lx 0x%-16lx 0x%-8lx %s\n",
               get_segment_type_name(phdr.p_type),
               (unsigned long)phdr.p_offset,
               (unsigned long)phdr.p_vaddr,
               (unsigned long)phdr.p_memsz,
               flags_str);
    }
    printf("\n");

    /* Read Section String Table for Section Names */
    Elf64_Shdr shstrtab_hdr;
    lseek(fd, ehdr.e_shoff + ehdr.e_shstrndx * sizeof(Elf64_Shdr), SEEK_SET);
    read(fd, &shstrtab_hdr, sizeof(shstrtab_hdr));

    char *shstrtab = (char *)malloc(shstrtab_hdr.sh_size);
    lseek(fd, shstrtab_hdr.sh_offset, SEEK_SET);
    read(fd, shstrtab, shstrtab_hdr.sh_size);

    /* Read Section Headers (Linking View) */
    printf("=== [Linking View] Section Headers (Sections) ===\n");
    printf("%-20s %-16s %-18s %-10s\n", "Name", "Type", "Address", "Size");
    printf("-----------------------------------------------------------------\n");

    lseek(fd, ehdr.e_shoff, SEEK_SET);
    for (int i = 0; i < ehdr.e_shnum; i++) {
        Elf64_Shdr shdr;
        if (read(fd, &shdr, sizeof(shdr)) != sizeof(shdr)) break;

        const char *name = (shdr.sh_name < shstrtab_hdr.sh_size) ?
                           &shstrtab[shdr.sh_name] : "<unknown>";

        printf("%-20s %-16s 0x%-16lx 0x%-8lx\n",
               name,
               get_section_type_name(shdr.sh_type),
               (unsigned long)shdr.sh_addr,
               (unsigned long)shdr.sh_size);
    }
    printf("============================================================\n");

    free(shstrtab);
    close(fd);
    return 0;
}

int main(int argc, char *argv[])
{
    const char *target = (argc > 1) ? argv[1] : argv[0];
    return inspect_elf(target);
}
