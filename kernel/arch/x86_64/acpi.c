#include <stdint.h>
#include <kernel/string.h>
#include <kernel/printf.h>
#include <kernel/arch/x86_64/acpi.h>
#include <kernel/arch/x86_64/mmu.h>

void __ap_bootstrap(void) {
	asm volatile (
		".global _ap_bootstrap_start\n"
		"_ap_bootstrap_start:\n"
		".code16\n"
		"1:\n"
		"cli\n"
		"hlt\n"
		"jmp 1b\n"
		".org 0x1000\n"
		"movb  $0xF8,%%al\n"
		"movb  $0x03,%%ah\n"
		"mov   %%ax,%%dx\n"
		"mov $'h',%%al\n"
		"outb %%al,%%dx\n"
		"mov $'e',%%al\n"
		"outb %%al,%%dx\n"
		"mov $'l',%%al\n"
		"outb %%al,%%dx\n"
		"outb %%al,%%dx\n"
		"mov $'o',%%al\n"
		"outb %%al,%%dx\n"
		"mov $' ',%%al\n"
		"outb %%al,%%dx\n"
		"mov $'w',%%al\n"
		"outb %%al,%%dx\n"
		"mov $'o',%%al\n"
		"outb %%al,%%dx\n"
		"mov $'r',%%al\n"
		"outb %%al,%%dx\n"
		"mov $'l',%%al\n"
		"outb %%al,%%dx\n"
		"mov $'d',%%al\n"
		"outb %%al,%%dx\n"
		"mov $'\n',%%al\n"
		"outb %%al,%%dx\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		"hlt\n"
		".global _ap_bootstrap_end\n"
		"_ap_bootstrap_end:\n"
		".code64\n"
		: : : "memory"
	);
}

extern char _ap_bootstrap_start[];
extern char _ap_bootstrap_end[];

static inline uint64_t read_tsc(void) {
	uint32_t lo, hi;
	asm volatile ( "rdtsc" : "=a"(lo), "=d"(hi) );
	return ((uint64_t)hi << 32) | (uint64_t)lo;
}

void acpi_initialize(void) {
	/* ACPI */
	uintptr_t scan;
	int good = 0;
	for (scan = 0x000E0000; scan < 0x00100000; scan += 16) {
		char * _scan = mmu_map_from_physical(scan);
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

	if (!good) return;

	struct rsdp_descriptor * rsdp = (struct rsdp_descriptor *)scan;
	printf("ACPI RSDP found at 0x%016lx; ", scan);
	printf("ACPI revision %d.0; ", rsdp->revision + 1);

	uint8_t check = 0;
	uint8_t * tmp;
	for (tmp = (uint8_t *)scan; (uintptr_t)tmp < scan + sizeof(struct rsdp_descriptor); tmp++) {
		check += *tmp;
	}
	if (check != 0) {
		printf("Bad checksum? %d\n", check);
	}

	printf("OEMID: %c%c%c%c%c%c; ",
			rsdp->oemid[0],
			rsdp->oemid[1],
			rsdp->oemid[2],
			rsdp->oemid[3],
			rsdp->oemid[4],
			rsdp->oemid[5]);

	printf("RSDT address: 0x%08x; ", rsdp->rsdt_address);

	struct rsdt * rsdt = (struct rsdt *)((uintptr_t)rsdp->rsdt_address | 0xFFFFffff00000000UL);
	printf("RSDT length: %d; ", rsdt->header.length);
	printf("RSDT checksum %s\n", acpi_checksum((struct acpi_sdt_header *)rsdt) ? "passed" : "failed");

	int cores = 0;
	uintptr_t lapic_base = 0x0;

	printf("Tables:\n");
	for (unsigned int i = 0; i < (rsdt->header.length - 36) / 4; ++i) {
		uint8_t * table = (uint8_t*)((uintptr_t)rsdt->pointers[i] | 0xFFFFffff00000000UL);
		printf("%2d (%#x) - %c%c%c%c\n",
			i, rsdt->pointers[i], table[0], table[1], table[2], table[3]);
		if (table[0] == 'A' && table[1] == 'P' && table[2] == 'I' && table[3] == 'C') {
			/* APIC table! Let's find some CPUs! */
			struct madt * madt = (void*)table;
			printf("lapic base: %#x\n", madt->lapic_addr);
			lapic_base = (uintptr_t)madt->lapic_addr | 0xFFFFffff00000000UL;
			printf("flags: %#x\n", madt->flags);
			for (uint8_t * entry = madt->entries; entry < table + madt->header.length; entry += entry[1]) {
				switch (entry[0]) {
					case 0:
						if (entry[4] & 0x01) {
							cores++;
						}
						printf("lapic id (flags=%#x, %#x)\n", entry[4], entry[3]);
						break;
					case 1: printf("ioapic ptr %#x\n", *((uint32_t*)(entry+4))); break;
					case 2: printf("int source override\n"); break;
					case 4: printf("nmi info\n"); break;
					case 5: printf("64-bit lapic ptr\n"); break;
					default: printf("unknown type? (%d)\n", entry[0]); break;
				}
			}
		}
	}

	printf("%d core%s\n", cores, (cores==1)?"":"s");

	asm volatile ("wrmsr" : : "c"(0x1B), "d"(0), "a"(0xFEE00000));

	printf("Shoving %#zx into 0x1000\n", (uintptr_t)&_ap_bootstrap_start);
	memcpy((void*)0xFFFFffff00001000, &_ap_bootstrap_start, (uintptr_t)&_ap_bootstrap_end - (uintptr_t)&_ap_bootstrap_start);

	uint32_t ebx;
	asm volatile ("cpuid" : "=b"(ebx) : "a"(0x1));
	printf("local apic id = %u\n", ebx >> 24);

	printf("Telling APs to INIT by writing crap to %#zx\n", lapic_base);
	for (int i = 1; i < 4; ++i) {

		*((volatile uint32_t*)(lapic_base + 0x310)) = (i << 24);
		asm volatile ("":::"memory");
		*((volatile uint32_t*)(lapic_base + 0x300)) = 0x004500;
		do { asm volatile ("pause" : : : "memory"); } while (*((volatile uint32_t*)(lapic_base + 0x300)) & (1 << 12));

		/* wait a bit */
		uint64_t clock = read_tsc();

		while (read_tsc() < clock + 34150000UL);

		for (int j = 0; j < 2; j++) {
			*((volatile uint32_t*)(lapic_base + 0x310)) = (i << 24);
			asm volatile ("":::"memory");
			*((volatile uint32_t*)(lapic_base + 0x300)) = 0x004601;
			asm volatile ("":::"memory");
			uint64_t clock = read_tsc();
			while (read_tsc() < clock + 683000UL);
			do { asm volatile ("pause" : : : "memory"); } while (*((volatile uint32_t*)(lapic_base + 0x300)) & (1 << 12));
		}
	}

	printf("Done sending startup.\n");


}

