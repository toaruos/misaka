/**
 * @file kernel/misc/elf64.c
 * @brief Elf64 parsing tools for modules and static userspace binaries.
 */

#include <kernel/types.h>
#include <kernel/symboltable.h>
#include <kernel/printf.h>

struct Elf64_Header {
	uint8_t  e_ident[16];
	uint16_t e_type;
	uint16_t e_machine;
	uint32_t e_version;
	uint64_t e_entry;
	uint64_t e_phoff;
	uint64_t e_shoff;
	uint32_t e_flags;
	uint16_t e_ehsize;
	uint16_t e_phentsize;
	uint16_t e_phnum;
	uint16_t e_shentsize;
	uint16_t e_shnum;
	uint16_t e_shstrndx;
};

struct Elf64_Shdr {
	uint32_t sh_name;
	uint32_t sh_type;
	uint64_t sh_flags;
	uint64_t sh_addr;
	uint64_t sh_offset;
	uint64_t sh_size;
	uint32_t sh_link;
	uint32_t sh_info;
	uint64_t sh_addralign;
	uint64_t sh_entsize;
};

struct Elf64_Phdr {
	uint32_t p_type;
	uint32_t p_flags;
	uint64_t p_offset;
	uint64_t p_vaddr;
	uint64_t p_paddr;
	uint64_t p_filesz;
	uint64_t p_memsz;
	uint64_t p_align;
};

void elf_parseFromMemory(void * atAddress) {
	struct Elf64_Header * elfHeader = atAddress;

	printf("Identifier: %c %c %c %c %c %c %c %c\n",
		elfHeader->e_ident[0],
		elfHeader->e_ident[1],
		elfHeader->e_ident[2],
		elfHeader->e_ident[3],
		elfHeader->e_ident[4],
		elfHeader->e_ident[5],
		elfHeader->e_ident[6],
		elfHeader->e_ident[7]);
	printf("            %c %c %c %c %c %c %c %c\n",
		elfHeader->e_ident[8],
		elfHeader->e_ident[9],
		elfHeader->e_ident[10],
		elfHeader->e_ident[11],
		elfHeader->e_ident[12],
		elfHeader->e_ident[13],
		elfHeader->e_ident[14],
		elfHeader->e_ident[15]);

}
