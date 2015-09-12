#include <types.h>
#include <multiboot.h>
#include <version.h>

extern int printf(char *fmt, ...);
extern void init_video();

int kmain(struct multiboot *mboot, uint32_t mboot_mag) {
	init_video();

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
