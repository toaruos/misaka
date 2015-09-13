#include <types.h>
#include <multiboot.h>
#include <version.h>
#include <symboltable.h>
#include <string.h>

extern int printf(char *fmt, ...);
extern void init_video();

int kmain(struct multiboot *mboot, uint32_t mboot_mag) {
	init_video();

	kernel_symbol_t * k = (kernel_symbol_t *)&kernel_symbols_start;

	while ((uintptr_t)k < (uintptr_t)&kernel_symbols_end) {
		printf("%s: 0x%x\n", k->name, k->addr);
		k = (kernel_symbol_t *)((uintptr_t)k + sizeof *k + strlen(k->name) + 1);
	}

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

	return 42;
}
