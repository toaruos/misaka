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
#include <kernel/mmu.h>

#include <kernel/arch/x86_64/ports.h>
#include <kernel/arch/x86_64/idt.h>
#include <kernel/arch/x86_64/cmos.h>
#include <kernel/arch/x86_64/pml.h>

#include <sys/ioctl.h>
#include <sys/termios.h>
#include <errno.h>

static char * heapStart = NULL;

void * sbrk(size_t bytes) {
	if (!heapStart) {
		printf("Heap is not yet available, but sbrk() was called.\n");
		return NULL;
	}

	void * out = heapStart;
	if (heapStart >= 0x800000000) {
		for (uintptr_t p = (uintptr_t)out; p < (uintptr_t)out + bytes; p += 0x1000) {
			union PML * page = mmu_get_page(p, MMU_GET_MAKE);
			mmu_frame_allocate(page, MMU_FLAG_WRITABLE | MMU_FLAG_KERNEL);
		}
	}

	heapStart += bytes;
	return out;
}

extern size_t fbterm_width, fbterm_height;
extern size_t fbterm_write(size_t,uint8_t*);
extern size_t fbterm_initialize(void);

#define EARLY_LOG_DEVICE 0x3F8
size_t _early_log_write(size_t size, uint8_t *buffer) {
	if (!buffer) return 0;
	fbterm_write(size,buffer);
	for (unsigned int i = 0; i < size; ++i) {
		outportb(EARLY_LOG_DEVICE, buffer[i]);
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
		if (0) {
			if (c == '\r') c = '\n';
			if (c == 127) {
				if (bytesRead) {
					bytesRead--;
					buffer[bytesRead] = '\0';
					printf("\b \b");
				}
				continue;
			}
			if (c == 0x17) /* ^W */ {
				while (bytesRead && buffer[bytesRead-1] == ' ') {
					bytesRead--;
					buffer[bytesRead] = '\0';
					printf("\b \b");
				}
				while (bytesRead && buffer[bytesRead-1] != ' ') {
					bytesRead--;
					buffer[bytesRead] = '\0';
					printf("\b \b");
				}
				continue;
			}
			buffer[bytesRead++] = c;
			printf("%c", c);
			if (c == '\n') break;
		} else {
			buffer[0] = c;
			return 1;
		}
	}
	return bytesRead;
}

static int _early_log_ioctl(fs_node_t * node, int request, void * argp) {
	switch (request) {
		case IOCTLDTYPE:
			return IOCTL_DTYPE_TTY;
		case TIOCGWINSZ:
			if (!argp) return -EINVAL;
			((struct winsize*)argp)->ws_row = fbterm_height;
			((struct winsize*)argp)->ws_col = fbterm_width;
			return 0;
	}
	return -EINVAL;
}

static fs_node_t _early_log = {
	.write = &_early_log_write_fs,
	.read = &_early_log_read_fs,
	.ioctl = &_early_log_ioctl,
};

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

	fbterm_initialize();
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
	mboot_mod_t * mods = (mboot_mod_t *)(uintptr_t)mboot->mods_addr;
	for (unsigned int i = 0; i < mboot->mods_count; ++i) {
		heapStart = (char*)((uintptr_t)mods[i].mod_start + mods[i].mod_end);
	}
	if ((uintptr_t)heapStart & 0xFFF) {
		heapStart += 0x1000 - ((uintptr_t)heapStart & 0xFFF);
	}
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
extern int system(const char * path, int argc, const char ** argv, const char ** envin);
extern void mmu_init(void);
extern void arch_clock_initialize(void);
extern void pit_initialize(void);
extern fs_node_t * lfb_device;
extern void acpi_initialize(void);
extern void tasking_start(void);
extern void packetfs_initialize(void);
extern void portio_initialize(void);
extern void zero_initialize(void);
extern void procfs_initialize(void);
extern void shm_install(void);
extern void keyboard_install(void);
extern void mouse_install(void);

int kmain(struct multiboot * mboot, uint32_t mboot_mag, void* esp) {
	startup_processMultiboot(mboot);
	mmu_init();

	/* Set up PAT entries */
	startup_initializePat();

	/* Start the kernel heap from a special high memory region. */
	heapStart = (char*)0xffffff0000000000;

	/* Initialize lfbvideo core and set up a quick-and-dirty terminal emulatory. */
	startup_initializeFramebuffer();

	startup_printVersion();

	/* Process the symbol table. */
	startup_processSymbols();

	/* Turn on the clock timers */
	arch_clock_initialize();

	//startup_printSymbols();
	//acpi_initialize();
	//startup_scanPci();

	gdt_install();
	idt_install();
	enable_fpu();
	initialize_process_tree();
	shm_install();

	vfs_install();
	tarfs_register_init();
	tmpfs_register_init();
	map_vfs_directory("/dev");
	vfs_mount("/dev/fb0", lfb_device);

	/* Assume first module is ramdisk? */
	mboot_mod_t * mods = (mboot_mod_t *)(uintptr_t)mboot->mods_addr;
	ramdisk_mount(mods[0].mod_start, mods[0].mod_end - mods[0].mod_start);

	vfs_mount_type("tar","/dev/ram0","/");
	//vfs_mount_type("tmpfs","tmp,777","/tmp");
	//vfs_mount_type("tmpfs","var,555","/var");
	packetfs_initialize();
	portio_initialize();
	zero_initialize();
	procfs_initialize();

	tasking_start();
	pit_initialize();
	keyboard_install();
	mouse_install();

	vfs_mount("/dev/fblog", &_early_log);

	/* XXX Set actual process file descriptors (this is temporary; init should do this) */
	#if 0
	current_process->fds->modes[process_append_fd((process_t*)current_process, &_early_log)] = 1;
	current_process->fds->modes[process_append_fd((process_t*)current_process, &_early_log)] = 2;
	current_process->fds->modes[process_append_fd((process_t*)current_process, &_early_log)] = 2;
	#endif


#if 0
	/* Let's take an aside here to look at a module */
	printf("Parsing %s (starts at 0x%08x)\n", mods[1].cmdline, mods[1].mod_start);
	elf_parseFromMemory((void*)(uintptr_t)mods[1].mod_start);
#endif

#if 1
	/* Load elf from file */
	const char * boot_app = "/bin/init";
	const char * argv[] = {
		boot_app,
		NULL
	};
	int argc = 0;
	while (argv[argc]) argc++;
	system(argv[0], argc, argv, NULL);
#endif

	while (1);

	return 42;
}
