#include <errno.h>
#include <kernel/vfs.h>
#include <kernel/printf.h>
#include <kernel/process.h>
#include <kernel/string.h>
#include <kernel/arch/x86_64/mmu.h>
#include <sys/time.h>

extern int elf_exec(const char * path, fs_node_t * file, int argc, char *const argv[], char *const env[], int interp);
int exec(const char * path, int argc, char *const argv[], char *const env[], int interp_depth) {
	fs_node_t * file = kopen(path, 0);
	if (!file) return -ENOENT;
	if (!has_permission(file, 01)) return -EACCES;

	current_process->name = strdup(path);
	gettimeofday((struct timeval*)&current_process->start, NULL);

	return elf_exec(path,file,argc,argv,env,interp_depth);
}

int system(const char * path, int argc, char *const argv[], char *const envin[]) {
	char ** argv_ = malloc(sizeof(char*) * (argc + 1));
	for (int j = 0; j < argc; ++j) {
		argv_[j] = malloc((strlen(argv[j]) + 1));
		memcpy((void*)argv_[j], argv[j], strlen(argv[j]) + 1);
	}
	argv_[argc] = NULL;
	char * env[] = {NULL};
	current_process->thread.directory = mmu_clone(NULL); /* base PML? for exec? */
	mmu_set_directory(current_process->thread.directory);
	current_process->cmdline = (char**)argv_;
	exec(path,argc,argv_,envin ? envin : env,0);
	printf("Uh oh?");
	return -EINVAL;
}
