/**
 * @file kernel/misc/elf64.c
 * @brief Elf64 parsing tools for modules and static userspace binaries.
 */

#include <kernel/types.h>
#include <kernel/symboltable.h>
#include <kernel/printf.h>
#include <kernel/string.h>
#include <kernel/elf.h>

static Elf64_Shdr * elf_getSection(Elf64_Header * this, Elf64_Word index) {
	return (Elf64_Shdr*)((uintptr_t)this + this->e_shoff + index * this->e_shentsize);
}

void elf_parseFromMemory(void * atAddress) {
	struct Elf64_Header * elfHeader = atAddress;

	if (elfHeader->e_ident[0] != ELFMAG0 ||
	    elfHeader->e_ident[1] != ELFMAG1 ||
	    elfHeader->e_ident[2] != ELFMAG2 ||
	    elfHeader->e_ident[3] != ELFMAG3) {
		printf("(Not an elf)\n");
		return;
	}
	if (elfHeader->e_ident[EI_CLASS] != ELFCLASS64) {
		printf("(Wrong Elf class)\n");
		return;
	}
	if (elfHeader->e_type != ET_REL) {
		printf("(Not a relocatable object)\n");
		return;
	}

	/**
	 * In order to load a module, we need to link it as an object
	 * into the running kernel using the symbol table we integrated
	 * into our binary.
	 */
	//char * shrstrtab = (char*)elfHeader + elf_getSection(elfHeader, elfHeader->e_shstrndx)->sh_offset;

	/**
	 * First, we're going to check sections and update their addresses.
	 */
	for (unsigned int i = 0; i < elfHeader->e_shnum; ++i) {
		Elf64_Shdr * shdr = elf_getSection(elfHeader, i);
		if (shdr->sh_type == SHT_NOBITS) {
			if (shdr->sh_size) {
				printf("Warning: Module needs %lu bytes for BSS, we don't have an allocator.\n",
					shdr->sh_size);
			}
			/* otherwise, skip bss */
		} else {
			shdr->sh_addr = (uintptr_t)atAddress + shdr->sh_offset;
		}
	}


}
