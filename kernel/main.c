#include <types.h>
#include <multiboot.h>
#include <version.h>
#include <symboltable.h>
#include <string.h>

extern int printf(char *fmt, ...);
extern void init_video();

int kmain(struct multiboot * mboot, uint32_t mboot_mag, void* esp) {
	init_video();

#if 0
	kernel_symbol_t * k = (kernel_symbol_t *)&kernel_symbols_start;
	while ((uintptr_t)k < (uintptr_t)&kernel_symbols_end) {
		printf("%s: 0x%x\n", k->name, k->addr);
		k = (kernel_symbol_t *)((uintptr_t)k + sizeof *k + strlen(k->name) + 1);
	}
#endif

	printf("%s %s ", __kernel_name, __kernel_arch);
	printf(__kernel_version_format,
			__kernel_version_major,
			__kernel_version_minor,
			__kernel_version_lower,
			__kernel_version_suffix);
	printf(" %s %s %s",
			__kernel_version_codename,
			__kernel_build_date,
			__kernel_build_time);
	printf("\n");

	printf("Built with %s\n", __kernel_compiler_version);

	printf("0x%8x\n", esp);
	printf("0x%8x\n", mboot_mag);
	printf("0x%8x\n", mboot);
	printf("flags: 0x%8x\n", mboot->flags);
	printf("mem_lower:   0x%8x mem_upper: 0x%8x\n", (uint64_t)mboot->mem_lower, (uint64_t)mboot->mem_upper);
	printf("cmdline: %s\n", mboot->cmdline);
	printf("mmap_length: 0x%8x mmap_addr: 0x%8x\n", (uint64_t)mboot->mmap_length, (uint64_t)mboot->mmap_addr);

#if 0
	for (unsigned int i = 0; i < sizeof(struct multiboot); ++i) {
		printf("%2x ", ((uint8_t *)mboot)[i]);
		if ((i + 1) % 24 == 0) printf("\n");
	}

	for (unsigned int i = sizeof(struct multiboot); i < 0x000200; ++i) {
		printf("%2x ", ((uint8_t *)mboot)[i]);
		if ((i + 1) % 24 == 0) printf("\n");
	}
#endif

	return 42;
}
