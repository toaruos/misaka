#include <errno.h>
#include <kernel/vfs.h>
#include <kernel/printf.h>
#include <kernel/process.h>
#include <kernel/string.h>
#include <kernel/arch/x86_64/mmu.h>
#include <kernel/elf.h>
#include <sys/time.h>

extern int elf_exec(const char * path, fs_node_t * file, int argc, char *const argv[], char *const env[], int interp);
int exec(const char * path, int argc, char *const argv[], char *const env[], int interp_depth);

int exec_shebang(const char * path, fs_node_t * file, int argc, char *const argv[], char *const env[], int interp) {
	if (interp > 4) /* sounds good to me */ {
		return -ELOOP;
	}
	/* Read MAX_LINE... */
	char tmp[100];
	read_fs(file, 0, 100, (unsigned char *)tmp); close_fs(file);
	char * cmd = (char *)&tmp[2];
	if (*cmd == ' ') cmd++; /* Handle a leading space */
	char * space_or_linefeed = strpbrk(cmd, " \n");
	char * arg = NULL;

	if (!space_or_linefeed) {
		return -ENOEXEC;
	}

	if (*space_or_linefeed == ' ') {
		/* Oh lovely, an argument */
		*space_or_linefeed = '\0';
		space_or_linefeed++;
		arg = space_or_linefeed;
		space_or_linefeed = strpbrk(space_or_linefeed, "\n");
		if (!space_or_linefeed) {
			return -ENOEXEC;
		}
	}
	*space_or_linefeed = '\0';

	char script[strlen(path)+1];
	memcpy(script, path, strlen(path)+1);

	unsigned int nargc = argc + (arg ? 2 : 1);
	char * args[nargc + 2];
	args[0] = cmd;
	args[1] = arg ? arg : script;
	args[2] = arg ? script : NULL;
	args[3] = NULL;

	int j = arg ? 3 : 2;
	for (int i = 1; i < argc; ++i, ++j) {
		args[j] = argv[i];
	}
	args[j] = NULL;

	return exec(cmd, nargc, args, env, interp+1);
}

/* Consider exposing this and making it a list so it can be extended ... */
typedef int (*exec_func)(const char * path, fs_node_t * file, int argc, char *const argv[], char *const env[], int interp);
typedef struct {
	exec_func func;
	unsigned char bytes[4];
	unsigned int  match;
	const char * name;
} exec_def_t;

exec_def_t fmts[] = {
	{elf_exec, {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3}, 4, "ELF"},
	{exec_shebang, {'#', '!', 0, 0}, 2, "#!"},
};

static int matches(unsigned char * a, unsigned char * b, unsigned int len) {
	for (unsigned int i = 0; i < len; ++i) {
		if (a[i] != b[i]) return 0;
	}
	return 1;
}

int exec(const char * path, int argc, char *const argv[], char *const env[], int interp_depth) {
	fs_node_t * file = kopen(path, 0);
	if (!file) return -ENOENT;
	if (!has_permission(file, 01)) return -EACCES;

	unsigned char head[4];
	read_fs(file, 0, 4, head);

	current_process->name = strdup(path);
	gettimeofday((struct timeval*)&current_process->start, NULL);

	for (unsigned int i = 0; i < sizeof(fmts) / sizeof(exec_def_t); ++i) {
		if (matches(fmts[i].bytes, head, fmts[i].match)) {
			return fmts[i].func(path, file, argc, argv, env, interp_depth);
		}
	}
	return -ENOEXEC;
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
	return -EINVAL;
}
