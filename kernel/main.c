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
#include <kernel/args.h>
#include <kernel/video.h>

#include <kernel/arch/x86_64/ports.h>
#include <kernel/arch/x86_64/idt.h>
#include <kernel/arch/x86_64/cmos.h>
#include <kernel/arch/x86_64/pml.h>

#include <errno.h>

#define EARLY_LOG_DEVICE 0x3F8
static size_t _early_log_write(size_t size, uint8_t * buffer) {
	for (unsigned int i = 0; i < size; ++i) {
		outportb(EARLY_LOG_DEVICE, buffer[i]);
	}
	return size;
}

static void startup_initializeLog(void) {
	printf_output = &_early_log_write;
}

static void startup_processMultiboot(struct multiboot * mboot) {
	mboot_mod_t * mods = (mboot_mod_t *)(uintptr_t)mboot->mods_addr;
	for (unsigned int i = 0; i < mboot->mods_count; ++i) {
		mmu_set_kernel_heap(((uintptr_t)mods[i].mod_start + mods[i].mod_end));
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

static void startup_initializeFPU(void) {
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

extern void gdt_install(void);
extern void idt_install(void);
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
extern void random_initialize(void);
extern void vmware_initialize(void);

static struct multiboot * mboot_struct = NULL;

const char * arch_get_cmdline(void) {
	return (char*)((0xFFFFFFFF00000000UL) | mboot_struct->cmdline);
}

const char * arch_get_loader(void) {
	if (mboot_struct->flags & MULTIBOOT_FLAG_LOADER) {
		return (char*)((0xFFFFFFFF00000000UL) | mboot_struct->boot_loader_name);
	} else {
		return "(unknown)";
	}
}

int kmain(struct multiboot * mboot, uint32_t mboot_mag, void* esp) {
	mboot_struct = mboot;
	startup_processMultiboot(mboot);
	mmu_init();
	startup_initializePat();
	mmu_set_kernel_heap(0xFFFFff0000000000);
	startup_initializeLog();
	framebuffer_initialize();
	startup_processSymbols();
	arch_clock_initialize();

	//acpi_initialize();

	gdt_install();
	idt_install();
	startup_initializeFPU();
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

	packetfs_initialize();
	portio_initialize();
	zero_initialize();
	procfs_initialize();
	random_initialize();

	/* Most of this is generic from here on... */
	args_parse(arch_get_cmdline());

	tasking_start();
	pit_initialize();
	keyboard_install();
	mouse_install();
	vmware_initialize();

	if (args_present("root")) {
		const char * root_type = "tar";
		if (args_present("root_type")) {
			root_type = args_value("root_type");
		}
		vfs_mount_type(root_type,args_value("root"),"/");
	}

	const char * boot_arg = NULL;

	if (args_present("args")) {
		boot_arg = strdup(args_value("args"));
	}

	const char * boot_app = "/bin/init";
	if (args_present("init")) {
		boot_app = args_value("init");
	}

	const char * argv[] = {
		boot_app,
		boot_arg,
		NULL
	};
	int argc = 0;
	while (argv[argc]) argc++;
	system(argv[0], argc, argv, NULL);

	printf("Failed to execute %s.\n", boot_app);
	switch_task(0);
	return 0;
}
