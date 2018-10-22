#include <kernel/types.h>
#include <kernel/multiboot.h>
#include <kernel/version.h>
#include <kernel/symboltable.h>
#include <kernel/string.h>

#include <kernel/arch/x86_64/ports.h>
#include <kernel/arch/x86_64/acpi.h>

extern int printf(const char *fmt, ...);
extern size_t (*printf_output)(size_t, uint8_t *);
extern void init_video();

#define EARLY_LOG_DEVICE 0x3F8
static size_t _early_log_write(size_t size, uint8_t *buffer) {
	for (unsigned int i = 0; i < size; ++i) {
		outportb(EARLY_LOG_DEVICE, buffer[i]);
	}
	return size;
}

typedef struct {
	uint16_t base_low;
	uint16_t sel;
	uint8_t zero;
	uint8_t flags;
	uint16_t base_high;
	uint32_t base_higher;
	uint32_t reserved;
} __attribute__((packed)) idt_entry_t;

int kmain(struct multiboot * mboot, uint32_t mboot_mag, void* esp) {
	init_video();
	printf_output = &_early_log_write;

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

	printf("Command line: %s\n", mboot->cmdline);

	printf("%d module%s starting 0x%8x\n", mboot->mods_count, (mboot->mods_count == 1 ) ? "" : "s", mboot->mods_addr);

	mboot_mod_t * mods = (mboot_mod_t *)(uintptr_t)mboot->mods_addr;
	for (unsigned int i = 0; i < mboot->mods_count; ++i) {
		printf("  module %s at [0x%8x:0x%8x]\n", mods->cmdline, mods->mod_start, mods->mod_end);
		mods++;
	}

	printf("Memory map:\n");
	printf("  Lower mem: %dkB\n", (uint64_t)mboot->mem_lower);
	printf("  Upper mem: %dkB\n", (uint64_t)mboot->mem_upper);
	mboot_memmap_t * mmap = (void *)(uintptr_t)mboot->mmap_addr;
	while ((uintptr_t)mmap < mboot->mmap_addr + mboot->mmap_length) {
		printf("  0x%16x:0x%16x %d (%s)\n", mmap->base_addr, mmap->length, mmap->type,
				mmap->type == 1 ? "available" : (mmap->type == 2 ? "reserved" : "unknown")
				);
		mmap = (mboot_memmap_t *) ((uintptr_t)mmap + mmap->size + sizeof(uint32_t));
	}

	printf("Kernel symbol table:\n");
	kernel_symbol_t * k = (kernel_symbol_t *)&kernel_symbols_start;
	while ((uintptr_t)k < (uintptr_t)&kernel_symbols_end) {
		printf("  0x%x - %s\n", k->addr, k->name);
		k = (kernel_symbol_t *)((uintptr_t)k + sizeof *k + strlen(k->name) + 1);
	}

	/* ACPI */

	uintptr_t scan;
	int good = 0;
	for (scan = 0x000E0000; scan < 0x00100000; scan += 16) {
		char * _scan = (char *)scan;
		if (_scan[0] == 'R' &&
			_scan[1] == 'S' &&
			_scan[2] == 'D' &&
			_scan[3] == ' ' &&
			_scan[4] == 'P' &&
			_scan[5] == 'T' &&
			_scan[6] == 'R') {
			good = 1;
			break;
		}
	}

	if (good) {
		struct rsdp_descriptor * rsdp = (struct rsdp_descriptor *)scan;
		printf("ACPI RSDP found at 0x%16x\n", scan);
		printf("  ACPI revision %d.0\n", rsdp->revision + 1);

		uint8_t check = 0;
		uint8_t * tmp;
		for (tmp = (uint8_t *)scan; (uintptr_t)tmp < scan + sizeof(struct rsdp_descriptor); tmp++) {
			check += *tmp;
		}
		if (check != 0) {
			printf("  Bad checksum? %d\n", check);
		}

		printf("  OEMID: %c%c%c%c%c%c\n",
				rsdp->oemid[0],
				rsdp->oemid[1],
				rsdp->oemid[2],
				rsdp->oemid[3],
				rsdp->oemid[4],
				rsdp->oemid[5]);

		printf("  RSDT address: 0x%8x\n", rsdp->rsdt_address);

#if 0
		struct rsdt * rsdt = (struct rsdt *)(uintptr_t)rsdp->rsdt_address;
		printf("  RSDT length: %d\n", rsdt->header.length);
		printf("  RSDT checksum %s\n", acpi_checksum((struct acpi_sdt_header *)rsdt) ? "passed" : "failed");
#endif

	}




	return 42;
}
