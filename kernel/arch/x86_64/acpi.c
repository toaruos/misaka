#include <stdint.h>
#include <kernel/string.h>
#include <kernel/process.h>
#include <kernel/printf.h>
#include <kernel/arch/x86_64/acpi.h>
#include <kernel/arch/x86_64/mmu.h>

void __ap_bootstrap(void) {
	asm volatile (
		".code16\n"
		".org 0x0\n"
		".global _ap_bootstrap_start\n"
		"_ap_bootstrap_start:\n"

		/* Enable PAE, paging */
		"mov $0xA0, %%eax\n"
		"mov %%eax, %%cr4\n"

		/* Kernel base PML4 */
		".global init_page_region\n"
		"mov $init_page_region, %%edx\n"
		"mov %%edx, %%cr3\n"

		/* Set LME */
		"mov $0xc0000080, %%ecx\n"
		"rdmsr\n"
		"or $0x100, %%eax\n"
		"wrmsr\n"

		/* Enable long mode */
		"mov $0x80000011, %%ebx\n"
		"mov  %%ebx, %%cr0\n"

		/* Set up basic GDT */
		"addr32 lgdtl %%cs:_ap_bootstrap_gdtp-_ap_bootstrap_start\n"

		/* Jump... */
		"data32 jmp $0x08,$ap_premain\n"

		".global _ap_bootstrap_gdtp\n"
		".align 16\n"
		"_ap_bootstrap_gdtp:\n"
		".word 0\n"
		".quad 0\n"

		".code64\n"
		".align 16\n"
		"ap_premain:\n"
		"mov $0x10, %%ax\n"
		"mov %%ax, %%ds\n"
		"mov %%ax, %%ss\n"
		".extern _ap_stack_base\n"
		"mov _ap_stack_base,%%esp\n"
		".extern ap_main\n"
		"callq ap_main\n"

		".global _ap_bootstrap_end\n"
		"_ap_bootstrap_end:\n"
		: : : "memory"
	);
}

extern char _ap_bootstrap_start[];
extern char _ap_bootstrap_end[];
extern char _ap_bootstrap_gdtp[];
extern size_t arch_cpu_mhz(void);
extern void gdt_copy_to_trampoline(int ap, char * trampoline);
extern void arch_set_core_base(uintptr_t base);
extern void fpu_initialize(void);
extern void idt_install(void);
extern process_t * spawn_kidle(void);
extern union PML init_page_region[];

uintptr_t _ap_stack_base = 0;
static volatile int _ap_startup_flag = 0;

/* For timing delays on IPIs */
static inline uint64_t read_tsc(void) {
	uint32_t lo, hi;
	asm volatile ( "rdtsc" : "=a"(lo), "=d"(hi) );
	return ((uint64_t)hi << 32) | (uint64_t)lo;
}

static void short_delay(unsigned long amount) {
	uint64_t clock = read_tsc();
	while (read_tsc() < clock + amount * arch_cpu_mhz());
}

/* C entrypoint for APs */
void ap_main(void) {
	uint32_t ebx;
	asm volatile ("cpuid" : "=b"(ebx) : "a"(0x1));
	arch_set_core_base((uintptr_t)&processor_local_data[ebx >> 24]);
	printf("Hello, world! I am AP %d; my gsbase is %p\n", ebx >> 24, (void*)&processor_local_data[ebx >> 24]);

	/* Load the IDT */
	idt_install();
	fpu_initialize();

	/* Set our pml pointers */
	this_core->current_pml = &init_page_region[0];

	/* Spawn our kidle, make it our current process. */
	this_core->kernel_idle_task = spawn_kidle();
	this_core->current_process = this_core->kernel_idle_task;

	printf("Ready?\n");

	/* Inform BSP it can continue. */
	_ap_startup_flag = 1;

	switch_next();
}

static void lapic_send_ipi(uintptr_t lapic_final, int i, uint32_t val) {
	*((volatile uint32_t*)(lapic_final + 0x310)) = (i << 24);
	asm volatile ("":::"memory");
	*((volatile uint32_t*)(lapic_final + 0x300)) = val;
	do { asm volatile ("pause" : : : "memory"); } while (*((volatile uint32_t*)(lapic_final + 0x300)) & (1 << 12));
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
	uint8_t check = 0;
	uint8_t * tmp;
	for (tmp = (uint8_t *)scan; (uintptr_t)tmp < scan + sizeof(struct rsdp_descriptor); tmp++) {
		check += *tmp;
	}
	if (check != 0) {
		return; /* bad checksum */
	}

	struct rsdt * rsdt = mmu_map_from_physical(rsdp->rsdt_address);

	int cores = 0;
	uintptr_t lapic_base = 0x0;
	for (unsigned int i = 0; i < (rsdt->header.length - 36) / 4; ++i) {
		uint8_t * table = mmu_map_from_physical(rsdt->pointers[i]);
		if (table[0] == 'A' && table[1] == 'P' && table[2] == 'I' && table[3] == 'C') {
			/* APIC table! Let's find some CPUs! */
			struct madt * madt = (void*)table;
			lapic_base = madt->lapic_addr;
			for (uint8_t * entry = madt->entries; entry < table + madt->header.length; entry += entry[1]) {
				switch (entry[0]) {
					case 0:
						if (entry[4] & 0x01) cores++;
						break;
					/* TODO: Other entries */
				}
			}
		}
	}

	if (!lapic_base || cores <= 1) return;

	/* Allocate a virtual address with which we can poke the lapic */
	uintptr_t lapic_final = 0xffffff1fd0000000;
	union PML * p = mmu_get_page(lapic_final, MMU_GET_MAKE);
	mmu_frame_map_address(p, MMU_FLAG_KERNEL | MMU_FLAG_WRITABLE | MMU_FLAG_NOCACHE | MMU_FLAG_WRITETHROUGH, lapic_base);
	mmu_invalidate(lapic_final);

	/* Map the bootstrap code */
	memcpy(mmu_map_from_physical(0x1000), &_ap_bootstrap_start, (uintptr_t)&_ap_bootstrap_end - (uintptr_t)&_ap_bootstrap_start);

	for (int i = 1; i < cores; ++i) {
		_ap_startup_flag = 0;

		/* Set gdt pointer value */
		gdt_copy_to_trampoline(i, (char*)mmu_map_from_physical(0x1000) + ((uintptr_t)&_ap_bootstrap_gdtp - (uintptr_t)&_ap_bootstrap_start));

		/* Make an initial stack for this AP */
		_ap_stack_base = (uintptr_t)valloc(KERNEL_STACK_SIZE)+ KERNEL_STACK_SIZE;

		/* Send INIT */
		lapic_send_ipi(lapic_final, i, 0x4500);
		short_delay(5000UL);

		/* Send SIPI */
		lapic_send_ipi(lapic_final, i, 0x4601);

		/* Wait for AP to signal it is ready before starting next AP */
		do { asm volatile ("pause" : : : "memory"); } while (!_ap_startup_flag);
	}
}

