#pragma once

#include <stdint.h>
#include <kernel/types.h>
#include <kernel/vfs.h>
#include <kernel/tree.h>
#include <sys/types.h>
#include <sys/time.h>

typedef struct thread {
	uintptr_t sp;
	uintptr_t bp;
	uintptr_t ip;
	uintptr_t tls_base;
	unsigned int flags;
	uint8_t fp_regs[512];
} thread_t;

typedef struct image {
	size_t    size;
	uintptr_t entry;
	uintptr_t heap;
	uintptr_t heap_actual;
	uintptr_t stack;
	uintptr_t user_stack;
	uintptr_t start;
	uintptr_t shm_heap;
	volatile int lock[2];
} image_t;

typedef struct file_descriptors {
	fs_node_t ** entries;
	uint64_t * offsets;
	int * modes;
	size_t length;
	size_t capacity;
	size_t refs;
} fd_table_t;

typedef struct process {
	pid_t id;    /* PID */
	pid_t group; /* thread group */
	pid_t job;   /* tty job */
	pid_t session; /* tty session */
	int status; /* status code */
	unsigned int flags; /* finished, started, running, isTasklet */

	uid_t user;
	uid_t real_user;
	unsigned int mask;

	char * name;
	char * description;
	char ** cmdline;

	char * wd_name;
	fs_node_t * wd_node;
	fd_table_t *  fds;               /* File descriptor table */

	thread_t thread;
	thread_t signal_state;

	image_t image;

	tree_node_t * tree_entry;
	struct regs * syscall_registers;
	list_t * wait_queue;
	list_t * shm_mappings;
	list_t * node_waits;
	list_t * signal_queue;
	char * signal_kstack;

	node_t sched_node;
	node_t sleep_node;
	node_t * timed_sleep_node;
	node_t * timeout_node;

	struct timeval start;
	int awoken_index;
} process_t;

typedef struct {
	uint64_t end_tick;
	uint64_t end_subtick;
	process_t * process;
	unsigned int flags; /* is_fswait */
} sleeper_t;

extern volatile process_t * current_process;
extern unsigned long process_append_fd(process_t * proc, fs_node_t * node);
extern long process_move_fd(process_t * proc, long src, long dest);
extern void initialize_process_tree(void);
extern process_t * process_from_pid(pid_t pid);

#define USER_ROOT_UID 0
