/**
 * @file kernel/arch/x86_64/gdt.c
 * @author K. Lange
 * @brief x86-64 GDT
 */

#include <kernel/printf.h>

/**
 * @brief 64-bit TSS
 */
typedef struct tss_entry {
	uint32_t reserved_0;
	uint64_t rsp[3];
	uint64_t reserved_1;
	uint64_t ist[7];
	uint64_t reserved_2;
	uint16_t reserved_3;
	uint16_t iomap_base;
} __attribute__ ((packed)) tss_entry_t;

typedef struct {
	uint16_t limit_low;
	uint16_t base_low;
	uint8_t base_middle;
	uint8_t access;
	uint8_t granularity;
	uint8_t base_high;
} __attribute__((packed)) gdt_entry_t;

typedef struct {
	uint32_t base_highest;
	uint32_t reserved0;
} __attribute__((packed)) gdt_entry_high_t;

typedef struct {
	uint16_t limit;
	uintptr_t base;
} __attribute__((packed)) gdt_pointer_t;

struct {
	gdt_entry_t entries[6];
	gdt_entry_high_t tss_extra;
	gdt_pointer_t pointer;
	tss_entry_t tss;
} __attribute__((packed)) gdt __attribute__((used)) = {
	{
		{0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00},
		{0xFFFF, 0x0000, 0x00, 0x9A, (1 << 5) | (1 << 7) | 0x0F, 0x00},
		{0xFFFF, 0x0000, 0x00, 0x92, (1 << 5) | (1 << 7) | 0x0F, 0x00},
		{0xFFFF, 0x0000, 0x00, 0xFA, (1 << 5) | (1 << 7) | 0x0F, 0x00},
		{0xFFFF, 0x0000, 0x00, 0xF2, (1 << 5) | (1 << 7) | 0x0F, 0x00},
		{0x0067, 0x0000, 0x00, 0xE9, 0x00, 0x00},
	},
	{0x00000000, 0x00000000},
	{0x0000, 0x0000000000000000},
	{0,{0,0,0},0,{0,0,0,0,0,0,0},0,0,0},
};

void gdt_install(void) {
	gdt.pointer.limit = sizeof(gdt.entries)+sizeof(gdt.tss_extra)-1;
	gdt.pointer.base  = (uintptr_t)&gdt.entries;

	uintptr_t addr = (uintptr_t)&gdt.tss;
	gdt.entries[5].limit_low = sizeof(gdt.tss);
	gdt.entries[5].base_low = (addr & 0xFFFF);
	gdt.entries[5].base_middle = (addr >> 16) & 0xFF;
	gdt.entries[5].base_high = (addr >> 24) & 0xFF;
	gdt.tss_extra.base_highest = (addr >> 32) & 0xFFFFFFFF;

	extern void * stack_top;
	gdt.tss.rsp[0] = (uintptr_t)&stack_top;

	asm volatile (
		"mov %0, %%rdi\n"
		"lgdt (%%rdi)\n"
		"mov $0x10, %%ax\n"
		"mov %%ax, %%ds\n"
		"mov %%ax, %%es\n"
		"mov %%ax, %%ss\n"
		"mov $0x2b, %%ax\n"
		"ltr %%ax\n"
		: : "r"(&gdt.pointer)
	);
}
