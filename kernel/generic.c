#include <kernel/generic.h>
#include <kernel/args.h>
#include <kernel/process.h>
#include <kernel/string.h>
#include <kernel/printf.h>

extern const char * arch_get_cmdline(void);
extern void tarfs_register_init(void);
extern void tmpfs_register_init(void);
extern void tasking_start(void);
extern void packetfs_initialize(void);
extern void zero_initialize(void);
extern void procfs_initialize(void);
extern void shm_install(void);
extern void random_initialize(void);
extern int system(const char * path, int argc, const char ** argv, const char ** envin);

void generic_startup(void) {
	initialize_process_tree();
	shm_install();
	vfs_install();
	tarfs_register_init();
	tmpfs_register_init();
	map_vfs_directory("/dev");
	packetfs_initialize();
	zero_initialize();
	procfs_initialize();
	random_initialize();
	args_parse(arch_get_cmdline());
	tasking_start();
}

int generic_main(void) {
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
