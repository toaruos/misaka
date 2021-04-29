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

void elf_parseModuleFromMemory(void * atAddress) {
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

#include <kernel/arch/x86_64/regs.h>

static struct regs ret = {0};

/**
 * @brief (temporary) Load an ELF Executable as a userspace program and jump to its entry point.
 *
 * Basic ELF64 parsing for LOAD PHDRs and the necessary hooks to jump to CPL3.
 */
void elf_parseFromMemory(void * atAddress) {
	struct Elf64_Header * elfHeader = atAddress;

	/* Sanity check the ELF header... */
	if (elfHeader->e_ident[0] != ELFMAG0 ||
	    elfHeader->e_ident[1] != ELFMAG1 ||
	    elfHeader->e_ident[2] != ELFMAG2 ||
	    elfHeader->e_ident[3] != ELFMAG3) {
		printf("(Not an elf)\n");
		return;
	}

	/* We do not support 32-bit ELFs. */
	if (elfHeader->e_ident[EI_CLASS] != ELFCLASS64) {
		printf("(Wrong Elf class)\n");
		return;
	}

	/* This loader can only handle basic executables. */
	if (elfHeader->e_type != ET_EXEC) {
		printf("(Not an executable)\n");
		return;
	}

	/** Load any LOAD PHDRs */
	for (int i = 0; i < elfHeader->e_phnum; ++i) {
		Elf64_Phdr * phdr = (void*)((uintptr_t)elfHeader + elfHeader->e_phoff + i * elfHeader->e_phentsize);
		if (phdr->p_type == PT_LOAD) {
			memcpy((void*)phdr->p_vaddr, (void*)((uintptr_t)elfHeader + phdr->p_offset), phdr->p_filesz);
			for (size_t i = phdr->p_filesz; i < phdr->p_memsz; ++i) {
				*(char*)(phdr->p_vaddr + i) = 0;
			}
		}
		/* TODO: Should also be setting up TLS PHDRs. */
	}

	/**
	 * Userspace segment descriptors
	 */
	ret.cs = 0x18 | 0x03;
	ret.ss = 0x20 | 0x03;
	ret.rip = elfHeader->e_entry;

	/* This should really be mapped at the top the userspace region when we set up
	 * proper page allocation... */
	ret.rsp = 0x3FFFF000;

	/**
	 * Temporary stuff for startup environment loaded at bottom of stack.
	 * TODO: I think the placement of these is defined in the SysV ABI.
	 */
	uintptr_t * userStack = (uintptr_t*)ret.rsp;
	userStack[0] = 1;
	userStack[1] = (uintptr_t)&userStack[2];
	userStack[2] = (uintptr_t)&userStack[6];
	userStack[3] = 0;
	userStack[4] = 0; /* env */
	userStack[5] = 0; /* auxv */

	/* TODO: argv from exec... */
	char * c = (char*)&userStack[6];
	snprintf(c, 10, "argv[0]");

	ret.rflags = (1 << 21);
	asm volatile (
		"pushq %0\n"
		"pushq %1\n"
		"pushq %2\n"
		"pushq %3\n"
		"pushq %4\n"
		"iretq"
	: :"r"(ret.ss), "r"(ret.rsp), "r"(ret.rflags), "r"(ret.cs), "r"(ret.rip));
}
