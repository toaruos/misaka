/**
 * @file kernel/misc/elf64.c
 * @brief Elf64 parsing tools for modules and static userspace binaries.
 */

#include <kernel/types.h>
#include <kernel/symboltable.h>
#include <kernel/printf.h>
#include <kernel/string.h>
#include <kernel/elf.h>
#include <kernel/vfs.h>

#include <kernel/arch/x86_64/mmu.h>

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

#if 0
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
	userStack[0] = 2;
	userStack[1] = (uintptr_t)&userStack[2];
	userStack[2] = (uintptr_t)&userStack[7];
	userStack[4] = 0;

	userStack[5] = 0; /* env */
	userStack[6] = 0; /* auxv */

	/* TODO: argv from exec... */
	char * c = (char*)&userStack[7];
	c += snprintf(c, 30, "/lib/ld.so") + 1;
	userStack[3] = (uintptr_t)c;
	snprintf(c, 30, "/bin/demo");

	ret.rflags = (1 << 21);
	asm volatile (
		"pushq %0\n"
		"pushq %1\n"
		"pushq %2\n"
		"pushq %3\n"
		"pushq %4\n"
		"iretq"
	: : "m"(ret.ss), "m"(ret.rsp), "m"(ret.rflags), "m"(ret.cs), "m"(ret.rip),
	    "a"(2), "b"(&userStack[1]), "c"(NULL));
}
#endif

void elf_loadFromFile(const char * filePath) {
	Elf64_Header header;

	fs_node_t * file = kopen(filePath, 0);
	if (!file) {
		printf("Unable to load file.\n");
		return;
	}

	read_fs(file, 0, sizeof(Elf64_Header), (uint8_t*)&header);

	if (header.e_ident[0] != ELFMAG0 ||
	    header.e_ident[1] != ELFMAG1 ||
	    header.e_ident[2] != ELFMAG2 ||
	    header.e_ident[3] != ELFMAG3) {
		printf("Invalid file: Bad header.\n");
		close_fs(file);
		return;
	}

	if (header.e_ident[EI_CLASS] != ELFCLASS64) {
		printf("(Wrong Elf class)\n");
		return;
	}

	/* This loader can only handle basic executables. */
	if (header.e_type != ET_EXEC) {
		printf("(Not an executable)\n");
		return;
	}

	for (int i = 0; i < header.e_phnum; ++i) {
		Elf64_Phdr phdr;
		read_fs(file, header.e_phoff + header.e_phentsize * i, sizeof(Elf64_Phdr), (uint8_t*)&phdr);
		if (phdr.p_type == PT_LOAD) {
			for (uintptr_t i = phdr.p_vaddr; i < phdr.p_vaddr + phdr.p_memsz; i += 0x1000) {
				union PML * page = mmu_get_page(i, MMU_GET_MAKE);
				mmu_frame_allocate(page, MMU_FLAG_WRITABLE);
			}

			read_fs(file, phdr.p_offset, phdr.p_filesz, (void*)phdr.p_vaddr);
			for (size_t i = phdr.p_filesz; i < phdr.p_memsz; ++i) {
				*(char*)(phdr.p_vaddr + i) = 0;
			}
		}
		/* TODO: Should also be setting up TLS PHDRs. */
	}

	/**
	 * Userspace segment descriptors
	 */
	ret.cs = 0x18 | 0x03;
	ret.ss = 0x20 | 0x03;
	ret.rip = header.e_entry;

	/* This should really be mapped at the top the userspace region when we set up
	 * proper page allocation... */
	ret.rsp = 0x60000000 - 32 * 0x400;

	/* Map stack space */
	for (uintptr_t i = 0x60000000 - 64 * 0x400; i < 0x60000000; i += 0x1000) {
		union PML * page = mmu_get_page(i, MMU_GET_MAKE);
		mmu_frame_allocate(page, MMU_FLAG_WRITABLE);
	}

	/**
	 * Temporary stuff for startup environment loaded at bottom of stack.
	 * TODO: I think the placement of these is defined in the SysV ABI.
	 */
	uintptr_t * userStack = (uintptr_t*)ret.rsp;
	userStack[0] = 3;
	userStack[1] = (uintptr_t)&userStack[2];
	userStack[2] = (uintptr_t)&userStack[8];
	userStack[5] = 0;

	userStack[6] = 0; /* env */
	userStack[7] = 0; /* auxv */

	/* TODO: argv from exec... */
	char * c = (char*)&userStack[8];
	c += snprintf(c, 30, "/lib/ld.so") + 1;
	userStack[3] = (uintptr_t)c;
	c += snprintf(c, 30, "/bin/kuroko") + 1;
	userStack[4] = (uintptr_t)c;
	c += snprintf(c, 30, "/bin/demo.krk") + 1;

	ret.rflags = (1 << 21);
	asm volatile (
		"pushq %0\n"
		"pushq %1\n"
		"pushq %2\n"
		"pushq %3\n"
		"pushq %4\n"
		"iretq"
	: : "m"(ret.ss), "m"(ret.rsp), "m"(ret.rflags), "m"(ret.cs), "m"(ret.rip),
	    "D"(userStack[0]), "S"(userStack[1]), "d"(NULL));

}
