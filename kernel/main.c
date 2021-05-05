#include <kernel/types.h>
#include <kernel/multiboot.h>
#include <kernel/version.h>
#include <kernel/symboltable.h>
#include <kernel/string.h>
#include <kernel/printf.h>
#include <kernel/pci.h>
#include <kernel/hashmap.h>
#include <kernel/vfs.h>
#include <kernel/process.h>

#include <kernel/arch/x86_64/ports.h>
#include <kernel/arch/x86_64/idt.h>
#include <kernel/arch/x86_64/acpi.h>
#include <kernel/arch/x86_64/cmos.h>
#include <kernel/arch/x86_64/pml.h>

#include "terminal-font.h"

static char * heapStart = NULL;

void * sbrk(size_t bytes) {
	if (!heapStart) {
		printf("Heap is not yet available, but sbrk() was called.\n");
		return NULL;
	}

	void * out = heapStart;
	heapStart += bytes;
	return out;
}

uint32_t * framebuffer = (uint32_t*)0xfd000000;

static void scan_find_framebuffer(uint32_t device, uint16_t v, uint16_t d, void * extra) {
	if ((v == 0x1234 && d == 0x1111) ||
	    (v == 0x80EE && d == 0xBEEF) ||
	    (v == 0x10de && d == 0x0a20))  {
		uintptr_t t = pci_read_field(device, PCI_BAR0, 4);
		framebuffer = (uint32_t*)t;
	}
}

/**
 * @brief Bochs LFB setup.
 */
static void _setup_framebuffer(uint16_t x, uint16_t y) {
	pci_scan(&scan_find_framebuffer, -1, NULL);
	/* Turn display off */
	outports(0x1CE, 0x04);
	outports(0x1CF, 0x00);
	/* Horizontal resolution */
	outports(0x1CE, 0x01);
	outports(0x1CF, x);
	/* Vertical resolution */
	outports(0x1CE, 0x02);
	outports(0x1CF, y);
	/* Set bpp to 32 */
	outports(0x1CE, 0x03);
	outports(0x1CF, 32);
	/* Virtual height */
	outports(0x1CE, 0x07);
	outports(0x1CF, 4096);
	/* Turn it back on */
	outports(0x1CE, 0x04);
	outports(0x1CF, 0x41);
}

static int width = 1440, height = 900;

#define char_height 20
#define char_width  9

#define BG_COLOR 0xFF050505
#define FG_COLOR 0xFFCCCCCC
#define EX_COLOR 0xFF999999

static void set_point(int x, int y, uint32_t value) {
	framebuffer[y * width + x] = value;
}

static void write_char(int x, int y, int val, uint32_t color) {
	if (val > 128) {
		val = 4;
	}
	uint16_t * c = large_font[val];
	for (uint8_t i = 0; i < char_height; ++i) {
		for (uint8_t j = 0; j < char_width; ++j) {
			if (c[i] & (1 << (15-j))) {
				set_point(x+j,y+i,color);
			} else {
				set_point(x+j,y+i,BG_COLOR);
			}
		}
	}
}

#define LEFT_PAD 1
static int x = LEFT_PAD;
static int y = 0;

static void process_char(char ch) {
	write_char(x,y,' ',BG_COLOR);
	switch (ch) {
		case '\n':
			x = LEFT_PAD;
			y += char_height;
			break;
		case '\r':
			x = LEFT_PAD;
			break;
		default:
			write_char(x,y,ch,FG_COLOR);
			x += char_width;
			break;
	}
	if (x > width) {
		y += char_height;
		x = LEFT_PAD;
	}
	if (y > height - char_height) {
		y -= char_height;
		/* scroll everything?*/
		memmove(framebuffer, framebuffer + width * char_height, (height - char_height) * width * 4);
		memset(framebuffer + (height - char_height) * width, 0x05, char_height * width * 4);
	}
	write_char(x,y,'_',EX_COLOR);
}

#define EARLY_LOG_DEVICE 0x3F8
static size_t _early_log_write(size_t size, uint8_t *buffer) {
	if (!buffer) return 0;
	for (unsigned int i = 0; i < size; ++i) {
		outportb(EARLY_LOG_DEVICE, buffer[i]);
		process_char(buffer[i]);
	}
	return size;
}

static uint64_t _early_log_write_fs(fs_node_t * self, uint64_t offset, uint64_t size, uint8_t * buffer) {
	return _early_log_write(size,buffer);
}

#define SERIAL_PORT_A 0x3F8
static int serial_rcvd(int device) {
	return inportb(device + 5) & 1;
}

static char serial_recv(int device) {
	while (serial_rcvd(device) == 0) ;
	return inportb(device);
}

/**
 * Implements some quick-and-dirty line buffering.
 */
static uint64_t _early_log_read_fs(fs_node_t * self, uint64_t offset, uint64_t size, uint8_t * buffer) {
	uint64_t bytesRead = 0;
	while (bytesRead < size) {
		while (serial_rcvd(SERIAL_PORT_A) == 0);
		char c = serial_recv(SERIAL_PORT_A);
		if (c == '\r') c = '\n';
		if (c == 127) {
			if (bytesRead) {
				bytesRead--;
				buffer[bytesRead] = '\0';
				printf("\b \b");
			}
			continue;
		}
		buffer[bytesRead++] = c;
		printf("%c", c);
		if (c == '\n') break;
	}
	return bytesRead;
}

static fs_node_t _early_log = { .write = &_early_log_write_fs, .read = &_early_log_read_fs };

static void setup_serial(void) {
	int port = SERIAL_PORT_A;
	outportb(port + 1, 0x00); /* Disable interrupts */
	outportb(port + 3, 0x80); /* Enable divisor mode */
	outportb(port + 0, 0x01); /* Div Low:  01 Set the port to 115200 bps */
	outportb(port + 1, 0x00); /* Div High: 00 */
	outportb(port + 3, 0x03); /* Disable divisor mode, set parity */
	outportb(port + 2, 0xC7); /* Enable FIFO and clear */
	//outportb(port + 4, 0x0B); /* Enable interrupts */
	//outportb(port + 1, 0x01); /* Enable interrupts */
}

static void startup_initializeFramebuffer(void) {
	printf_output = &_early_log_write;

	setup_serial();
	current_process->fds->entries[0] = &_early_log;
	current_process->fds->entries[1] = &_early_log;
	current_process->fds->entries[2] = &_early_log;

	_setup_framebuffer(1440,900);
	memset(framebuffer, 0x05, width * height * 4);
}

static void startup_printVersion(void) {
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
	printf(" [%s]\n", __kernel_compiler_version);
}

static void startup_processMultiboot(struct multiboot * mboot) {
	printf("mboot struct is at at %p\n", mboot);
#if 1
	printf("Command line: %s\n", mboot->cmdline);
	printf("%d module%s starting 0x%08x\n", mboot->mods_count, (mboot->mods_count == 1 ) ? "" : "s", mboot->mods_addr);
#endif
	mboot_mod_t * mods = (mboot_mod_t *)(uintptr_t)mboot->mods_addr;
	for (unsigned int i = 0; i < mboot->mods_count; ++i) {
		printf("  module %s at [0x%08x:0x%08x]\n", mods[i].cmdline, mods[i].mod_start, mods[i].mod_end);
		heapStart = (char*)((uintptr_t)mods[i].mod_start + mods[i].mod_end);
	}

	if ((uintptr_t)heapStart & 0xFFF) {
		heapStart += 0x1000 - ((uintptr_t)heapStart & 0xFFF);
	}

#if 1
	printf("Memory map:");
	printf("  Lower mem: %dkB", (uint64_t)mboot->mem_lower);
	printf("  Upper mem: %dkB\n", (uint64_t)mboot->mem_upper);
	mboot_memmap_t * mmap = (void *)(uintptr_t)mboot->mmap_addr;
	while ((uintptr_t)mmap < mboot->mmap_addr + mboot->mmap_length) {
		printf("  0x%016x:0x%016x %d (%s)\n", mmap->base_addr, mmap->length, mmap->type,
				mmap->type == 1 ? "available" : (mmap->type == 2 ? "reserved" : "unknown")
				);
		mmap = (mboot_memmap_t *) ((uintptr_t)mmap + mmap->size + sizeof(uint32_t));
	}
#endif
}

static hashmap_t * kernelSymbols = NULL;

static void startup_processSymbols(void) {
	kernelSymbols = hashmap_create(10);
	kernel_symbol_t * k = (kernel_symbol_t *)&kernel_symbols_start;
	while ((uintptr_t)k < (uintptr_t)&kernel_symbols_end) {
		hashmap_set(kernelSymbols, k->name, (void*)k->addr);
		k = (kernel_symbol_t *)((uintptr_t)k + sizeof *k + strlen(k->name) + 1);
	}
}

static void startup_printSymbols(void) {
	printf("Kernel symbol table:\n");
	kernel_symbol_t * k = (kernel_symbol_t *)&kernel_symbols_start;
	int column = 0;
	while ((uintptr_t)k < (uintptr_t)&kernel_symbols_end) {
		int count = printf("  0x%x - %s", k->addr, k->name);
		k = (kernel_symbol_t *)((uintptr_t)k + sizeof *k + strlen(k->name) + 1);
		while (count < 38) {
			count += printf(" ");
		}
		column++;
		if (column == 4) {
			printf("\n");
			column = 0;
		}
	}
	if (column != 0) printf("\n");
}

static void startup_scanAcpi(void) {
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
		printf("ACPI RSDP found at 0x%016x; ", scan);
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

		struct rsdt * rsdt = (struct rsdt *)(uintptr_t)rsdp->rsdt_address;
		printf("RSDT length: %d; ", rsdt->header.length);
		printf("RSDT checksum %s\n", acpi_checksum((struct acpi_sdt_header *)rsdt) ? "passed" : "failed");
	}
}

static void scan_hit_list(uint32_t device, uint16_t vendorid, uint16_t deviceid, void * extra) {
	printf("%02x:%02x.%d (%04x, %04x:%04x)",
			(int)pci_extract_bus(device),
			(int)pci_extract_slot(device),
			(int)pci_extract_func(device),
			(int)pci_find_type(device),
			vendorid,
			deviceid);

	printf(" BAR0: 0x%08x", pci_read_field(device, PCI_BAR0, 4));
	printf(" BAR1: 0x%08x", pci_read_field(device, PCI_BAR1, 4));
	printf(" BAR2: 0x%08x", pci_read_field(device, PCI_BAR2, 4));
	printf(" BAR3: 0x%08x", pci_read_field(device, PCI_BAR3, 4));
	printf(" BAR4: 0x%08x", pci_read_field(device, PCI_BAR4, 4));
	printf(" BAR5: 0x%08x", pci_read_field(device, PCI_BAR5, 4));

	printf(" IRQ: %2d", pci_read_field(device, 0x3C, 1));
	printf(" %2d", pci_read_field(device, 0x3D, 1));
	printf(" Int: %2d", pci_get_interrupt(device));
	printf(" Stat: 0x%04x\n", pci_read_field(device, PCI_STATUS, 2));
}

static void startup_scanPci(void) {
	pci_scan(&scan_hit_list, -1, NULL);
}

static void startup_initializePat(void) {
	asm volatile (
		"mov $0x277, %%ecx\n" /* IA32_MSR_PAT */
		"rdmsr\n"
		"or $0x1000000, %%edx\n" /* set bit 56 */
		"and $0xf9ffffff, %%edx\n" /* unset bits 57, 58 */
		"wrmsr\n"
		: : : "ecx", "edx", "eax"
	);
}

extern void gdt_install(void);
extern void idt_install(void);

static void enable_fpu(void) {
	asm volatile (
		"clts\n"
		"mov %%cr0, %%rax\n"
		"and $0xFFFD, %%ax\n"
		"or $0x10, %%ax\n"
		"mov %%rax, %%cr0\n"
		"fninit\n"
		"mov %%cr0, %%rax\n"
		"and $0xfffb, %%ax\n"
		"or  $0x0002, %%ax\n"
		"mov %%rax, %%cr0\n"
		"mov %%cr4, %%rax\n"
		"or $0x600, %%rax\n"
		"mov %%rax, %%cr4\n"
		"push $0x1F80\n"
		"ldmxcsr (%%rsp)\n"
		"addq $8, %%rsp\n"
	: : : "rax");
}

extern fs_node_t * ramdisk_mount(uintptr_t, size_t);
extern void tarfs_register_init(void);
extern void tmpfs_register_init(void);
extern void elf_parseFromMemory(void * atAddress);
extern void elf_loadFromFile(const char * filePath);
extern void mmu_init(void);
extern void arch_clock_initialize(void);

int kmain(struct multiboot * mboot, uint32_t mboot_mag, void* esp) {
	startup_initializeFramebuffer(); /* TODO: lfbvideo module */
	startup_printVersion();          /* TODO: move to generic kernel/misc/version.c? */
	startup_processMultiboot(mboot);
	startup_processSymbols();        /* TODO: move to generic kernel/misc/symbols.c and/or ditch when we switch to an ELF with a DYN table? */
	startup_initializePat();         /* TODO: arch/x86-64/mem.c? */

	arch_clock_initialize();

	mmu_init();

	startup_printSymbols();
	//startup_scanAcpi();
	//startup_scanPci();

	gdt_install();
	idt_install();
	enable_fpu();

	vfs_install();
	tarfs_register_init();
	tmpfs_register_init();
	map_vfs_directory("/dev");

	/* Assume first module is ramdisk? */
	mboot_mod_t * mods = (mboot_mod_t *)(uintptr_t)mboot->mods_addr;
	ramdisk_mount(mods[0].mod_start, mods[0].mod_end - mods[0].mod_start);

	vfs_mount_type("tar","/dev/ram0","/");
	vfs_mount_type("tmpfs","tmp,777","/tmp");
	vfs_mount_type("tmpfs","var,555","/var");


#if 0
	/* Let's take an aside here to look at a module */
	printf("Parsing %s (starts at 0x%08x)\n", mods[1].cmdline, mods[1].mod_start);
	elf_parseFromMemory((void*)(uintptr_t)mods[1].mod_start);
#endif

#if 1
	/* Load elf from file */
	elf_loadFromFile("/lib/ld.so");
#endif

	while (1);

	return 42;
}
