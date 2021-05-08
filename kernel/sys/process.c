#include <errno.h>
#include <kernel/process.h>
#include <kernel/printf.h>
#include <kernel/string.h>
#include <kernel/vfs.h>
#include <kernel/spinlock.h>
#include <kernel/tree.h>
#include <kernel/list.h>
#include <kernel/mmu.h>
#include <kernel/signal.h>
#include <kernel/arch/x86_64/regs.h>
#include <sys/wait.h>
#include <sys/signal_defs.h>

extern void arch_enter_critical(void);
extern void arch_exit_critical(void);

static fs_node_t * _entries[24] = {
	(fs_node_t *)1, (fs_node_t *)1, (fs_node_t *)1,
	NULL,
};

static uint64_t _offsets[24] = {0};
static int _modes[24] = {1, 2, 2, 0};

static fd_table_t _fake_fds = {
	_entries,
	_offsets,
	_modes,
	3,
	24,
	1,
};

static process_t _fake_process = {
	.user = 0,
	.real_user = 0,
	.wd_name = "/",
	.fds = &_fake_fds,
};

tree_t * process_tree;  /* Parent->Children tree */
list_t * process_list;  /* Flat storage */
list_t * process_queue; /* Ready queue */
list_t * sleep_queue;
volatile process_t * current_process = &_fake_process;
static process_t * kernel_idle_task = NULL;
static spin_lock_t tree_lock = { 0 };
static spin_lock_t process_queue_lock = { 0 };
static spin_lock_t wait_lock_tmp = { 0 };
static spin_lock_t sleep_lock = { 0 };

/* Tasking stuff here */

struct arch_thread_state {
	uintptr_t sp;
	uintptr_t bp;
	uintptr_t ip;
};

extern void arch_set_kernel_stack(uintptr_t stack);

/* TODO: this should be part of arch_(restore/save)_context... */
static uint8_t saves[512] __attribute__((aligned(16)));
void restore_fpu(process_t * proc) {
	memcpy(&saves,(uint8_t *)&proc->thread.fp_regs,512);
	asm volatile ("fxrstor (%0)" :: "r"(saves));
}

void save_fpu(process_t * proc) {
	asm volatile ("fxsave (%0)" :: "r"(saves));
	memcpy((uint8_t *)&proc->thread.fp_regs,&saves,512);
}

extern __attribute__((noreturn)) void arch_restore_context(volatile thread_t * buf);
extern __attribute__((returns_twice)) int arch_save_context(volatile thread_t * buf);

void switch_next(void) {
	current_process = next_ready_process();
	restore_fpu((process_t*)current_process);
	if (current_process->flags & PROC_FLAG_FINISHED) {
		switch_next();
		__builtin_unreachable();
	}
	mmu_set_directory(current_process->thread.page_directory->directory);

	//printf("setting kernel stack to %p\n", current_process->image.stack);
	arch_set_kernel_stack(current_process->image.stack);

	if (current_process->flags & PROC_FLAG_STARTED) {
		if (!current_process->signal_kstack) {
			if (current_process->signal_queue->length > 0) {
				current_process->signal_kstack = malloc(KERNEL_STACK_SIZE);
				current_process->signal_state.sp = current_process->thread.sp;
				current_process->signal_state.bp = current_process->thread.bp;
				current_process->signal_state.ip = current_process->thread.ip;
				memcpy(current_process->signal_kstack, (void*)(current_process->image.stack - KERNEL_STACK_SIZE), KERNEL_STACK_SIZE);
			}
		}
	} else {
		current_process->flags |= PROC_FLAG_STARTED;
	}
	current_process->flags |= PROC_FLAG_RUNNING;

	arch_restore_context(&current_process->thread);
	__builtin_unreachable();
}

__attribute__((noreturn))
__attribute__((naked))
void arch_resume_user(void) {
	asm volatile (
		"pop %r15\n"
		"pop %r14\n"
		"pop %r13\n"
		"pop %r12\n"
		"pop %r11\n"
		"pop %r10\n"
		"pop %r9\n"
		"pop %r8\n"
		"pop %rbp\n"
		"pop %rdi\n"
		"pop %rsi\n"
		"pop %rdx\n"
		"pop %rcx\n"
		"pop %rbx\n"
		"pop %rax\n"
		"add $16, %rsp\n"
		"iretq\n"
	);
	__builtin_unreachable();
}


void switch_task(uint8_t reschedule) {
	if (!current_process) return;
	if (!(current_process->flags & PROC_FLAG_RUNNING)) {
		switch_next();
	}

	if (arch_save_context(&current_process->thread) == 1) {
		fix_signal_stacks();
		if (!(current_process->flags & PROC_FLAG_FINISHED)) {
			if (current_process->signal_queue->length > 0) {
				node_t * node = list_dequeue(current_process->signal_queue);
				signal_t * sig = node->value;
				free(node);
				handle_signal((process_t*)current_process,sig);
			}
		}
		return;
	}

	current_process->flags &= ~(PROC_FLAG_RUNNING);
	save_fpu((process_t*)current_process);

	if (reschedule && current_process != kernel_idle_task) {
		make_process_ready((process_t*)current_process);
	}

	switch_next();
}

uint8_t process_compare(void * proc_v, void * pid_v) {
	pid_t pid = (*(pid_t *)pid_v);
	process_t * proc = (process_t *)proc_v;

	return (uint8_t)(proc->id == pid);
}

void initialize_process_tree(void) {
	process_tree = tree_create();
	process_list = list_create();
	process_queue = list_create();
	sleep_queue = list_create();

	/* TODO: PID bitset? */
}

int is_valid_process(process_t * process) {
	foreach(lnode, process_list) {
		if (lnode->value == process) {
			return 1;
		}
	}

	return 0;
}

unsigned long process_append_fd(process_t * proc, fs_node_t * node) {
	/* Fill gaps */
	for (unsigned long i = 0; i < proc->fds->length; ++i) {
		if (!proc->fds->entries[i]) {
			proc->fds->entries[i] = node;
			/* modes, offsets must be set by caller */
			proc->fds->modes[i] = 0;
			proc->fds->offsets[i] = 0;
			return i;
		}
	}
	/* No gaps, expand */
	if (proc->fds->length == proc->fds->capacity) {
		proc->fds->capacity *= 2;
		proc->fds->entries = realloc(proc->fds->entries, sizeof(fs_node_t *) * proc->fds->capacity);
		proc->fds->modes   = realloc(proc->fds->modes,   sizeof(int) * proc->fds->capacity);
		proc->fds->offsets = realloc(proc->fds->offsets, sizeof(uint64_t) * proc->fds->capacity);
	}
	proc->fds->entries[proc->fds->length] = node;
	/* modes, offsets must be set by caller */
	proc->fds->modes[proc->fds->length] = 0;
	proc->fds->offsets[proc->fds->length] = 0;
	proc->fds->length++;
	return proc->fds->length-1;
}

pid_t get_next_pid(void) {
	static pid_t _next_pid = 2;
	return _next_pid++;
}

extern union PML * current_pml;

static void _kidle(void) {
	while (1) {
		/* FIXME: arch_pause()? */
		asm volatile (
			"sti\n"
			"hlt\n"
		);
	}
}

void process_release_directory(page_directory_t * dir) {
	dir->refcount--;
	if (dir->refcount < 1) {
		mmu_free(dir->directory);
		free(dir);
	}
}

process_t * spawn_kidle(void) {
	process_t * idle = calloc(1,sizeof(process_t));
	idle->id = -1;
	idle->name = strdup("[kidle]");
	idle->flags = PROC_FLAG_IS_TASKLET | PROC_FLAG_STARTED | PROC_FLAG_RUNNING;
	idle->image.stack = (uintptr_t)valloc(KERNEL_STACK_SIZE) + KERNEL_STACK_SIZE;
	idle->thread.ip = (uintptr_t)&_kidle;
	idle->thread.sp = idle->image.stack;
	idle->thread.bp = idle->image.stack;
	idle->wait_queue = list_create();
	idle->shm_mappings = list_create();
	idle->signal_queue = list_create();
	gettimeofday(&idle->start, NULL);
	idle->thread.page_directory = malloc(sizeof(page_directory_t));
	idle->thread.page_directory->refcount = 1;
	idle->thread.page_directory->directory = mmu_clone(current_pml);
	return idle;
}

process_t * spawn_init(void) {
	process_t * init = calloc(1,sizeof(process_t));
	tree_set_root(process_tree, (void*)init);

	init->tree_entry = process_tree->root;
	init->id         = 1;
	init->group      = 0;
	init->job        = 1;
	init->session    = 1;
	init->name       = strdup("init");
	init->cmdline    = NULL;
	init->user       = USER_ROOT_UID;
	init->real_user  = USER_ROOT_UID;
	init->mask       = 022;
	init->status     = 0;

	init->fds           = malloc(sizeof(fd_table_t));
	init->fds->refs     = 1;
	init->fds->length   = 0;
	init->fds->capacity = 4;
	init->fds->entries  = malloc(init->fds->capacity * sizeof(fs_node_t *));
	init->fds->modes    = malloc(init->fds->capacity * sizeof(int));
	init->fds->offsets  = malloc(init->fds->capacity * sizeof(uint64_t));

	init->wd_node = clone_fs(fs_root);
	init->wd_name = strdup("/");

	init->image.entry       = 0;
	init->image.heap        = 0;
	init->image.heap_actual = 0;
	//init->image.stack       = (uintptr_t)&stack_top;
	init->image.stack = (uintptr_t)valloc(KERNEL_STACK_SIZE) + KERNEL_STACK_SIZE;
	init->image.user_stack  = 0;
	init->image.size        = 0;
	init->image.shm_heap    = 0x200000000; /* That's 8GiB? That should work fine... */

	init->flags         = PROC_FLAG_STARTED | PROC_FLAG_RUNNING;
	init->wait_queue    = list_create();
	init->shm_mappings  = list_create();
	init->signal_queue  = list_create();
	init->signal_kstack = NULL; /* Initialized later */

	init->sched_node.prev = NULL;
	init->sched_node.next = NULL;
	init->sched_node.value = init;

	init->sleep_node.prev = NULL;
	init->sleep_node.next = NULL;
	init->sleep_node.value = init;

	init->timed_sleep_node = NULL;

	init->thread.page_directory = malloc(sizeof(page_directory_t));
	init->thread.page_directory->refcount = 1;
	init->thread.page_directory->directory = current_pml;
	init->description = strdup("[init]");
	list_insert(process_list, (void*)init);

	return init;
}

process_t * spawn_process(volatile process_t * parent, int flags) {
	process_t * proc = calloc(1,sizeof(process_t));

	proc->id          = get_next_pid();
	proc->group       = proc->id;
	proc->name        = strdup(parent->name);
	proc->description = NULL;
	proc->cmdline     = parent->cmdline; /* FIXME dup it? */

	proc->user        = parent->user;
	proc->real_user   = parent->real_user;
	proc->mask        = parent->mask;
	proc->job         = parent->job;
	proc->session     = parent->session;

	proc->thread.sp = 0;
	proc->thread.bp = 0;
	proc->thread.ip = 0;
	proc->thread.flags = 0;
	memcpy((void*)proc->thread.fp_regs, (void*)parent->thread.fp_regs, 512);

	proc->image.entry       = parent->image.entry;
	proc->image.heap        = parent->image.heap;
	proc->image.heap_actual = parent->image.heap_actual; /* XXX is this used? */
	proc->image.size        = parent->image.size; /* XXX same ^^ */
	proc->image.stack       = (uintptr_t)valloc(KERNEL_STACK_SIZE) + KERNEL_STACK_SIZE;
	proc->image.user_stack  = parent->image.user_stack;
	proc->image.shm_heap    = 0x200000000;

	if (flags & PROC_REUSE_FDS) {
		proc->fds = parent->fds;
		proc->fds->refs++; /* FIXME lock? */
	} else {
		proc->fds = malloc(sizeof(fd_table_t));
		proc->fds->refs = 1;
		proc->fds->length = parent->fds->length;
		proc->fds->capacity = parent->fds->capacity;
		proc->fds->entries = malloc(proc->fds->capacity * sizeof(fs_node_t *));
		proc->fds->modes   = malloc(proc->fds->capacity * sizeof(int));
		proc->fds->offsets = malloc(proc->fds->capacity * sizeof(uint64_t));
		for (uint32_t i = 0; i < parent->fds->length; ++i) {
			proc->fds->entries[i] = clone_fs(parent->fds->entries[i]);
			proc->fds->modes[i]   = parent->fds->modes[i];
			proc->fds->offsets[i] = parent->fds->offsets[i];
		}
	}

	proc->wd_node = clone_fs(parent->wd_node);
	proc->wd_name = strdup(parent->wd_name);

	proc->wait_queue   = list_create();
	proc->shm_mappings = list_create();
	proc->signal_queue = list_create();

	proc->sched_node.value = proc;
	proc->sleep_node.value = proc;

	gettimeofday(&proc->start, NULL);
	tree_node_t * entry = tree_node_create(proc);
	proc->tree_entry = entry;

	spin_lock(tree_lock);
	tree_node_insert_child_node(process_tree, parent->tree_entry, entry);
	list_insert(process_list, (void*)proc);
	spin_unlock(tree_lock);
	return proc;
}

void process_disown(process_t * proc) {
	tree_node_t * entry = proc->tree_entry;
	spin_lock(tree_lock);
	tree_break_off(process_tree, entry);
	tree_node_insert_child(process_tree, process_tree->root, entry);
	spin_unlock(tree_lock);
}

extern void tree_remove_reparent_root(tree_t * tree, tree_node_t * node);
void process_delete(process_t * proc) {
	tree_node_t * entry = proc->tree_entry;
	if (!entry) return;
	if (process_tree->root == entry) {
		return;
	}
	spin_lock(tree_lock);
	int has_children = entry->children->length;
	tree_remove_reparent_root(process_tree, entry);
	list_delete(process_list, list_find(process_list, proc));
	spin_unlock(tree_lock);
	if (has_children) {
		process_t * init = process_tree->root->value;
		wakeup_queue(init->wait_queue);
	}
	// FIXME bitset_clear(&pid_set, proc->id);
	proc->tree_entry = NULL;
	free(proc);
}

void make_process_ready(volatile process_t * proc) {
	if (proc->sleep_node.owner != NULL) {
		if (proc->sleep_node.owner == sleep_queue) {
			if (proc->timed_sleep_node) {
				arch_enter_critical();
				spin_lock(sleep_lock);
				list_delete(sleep_queue, proc->timed_sleep_node);
				spin_unlock(sleep_lock);
				arch_exit_critical();
				proc->sleep_node.owner = NULL;
				free(proc->timed_sleep_node->value);
			}
		} else {
			proc->flags |= PROC_FLAG_SLEEP_INT;
			spin_lock(wait_lock_tmp);
			list_delete((list_t*)proc->sleep_node.owner, (node_t*)&proc->sleep_node);
			spin_unlock(wait_lock_tmp);
		}
	}
	if (proc->sched_node.owner) {
		printf("Can't make process ready without removing it from owner list: %d\n", proc->id);
		printf("  (This is a bug) Current owner list is %p (ready queue is %p)\n", proc->sched_node.owner, process_queue);
		return;
	}
	spin_lock(process_queue_lock);
	list_append(process_queue, (node_t*)&proc->sched_node);
	spin_unlock(process_queue_lock);
}

int process_available(void) {
	return (process_queue->head != NULL);
}

process_t * next_ready_process(void) {
	if (!process_available()) {
		return kernel_idle_task;
	}
	if (process_queue->head->owner != process_queue) {
		printf("Uh oh.\n");
	}
	node_t * np = list_dequeue(process_queue);
	process_t * next = np->value;
	return next;
}

int wakeup_queue(list_t * queue) {
	int awoken_processes = 0;
	while (queue->length > 0) {
		spin_lock(wait_lock_tmp);
		node_t * node = list_pop(queue);
		spin_unlock(wait_lock_tmp);
		if (!(((process_t *)node->value)->flags & PROC_FLAG_FINISHED)) {
			make_process_ready(node->value);
		}
		awoken_processes++;
	}
	return awoken_processes;
}

int wakeup_queue_interrupted(list_t * queue) {
	int awoken_processes = 0;
	while (queue->length > 0) {
		spin_lock(wait_lock_tmp);
		node_t * node = list_pop(queue);
		spin_unlock(wait_lock_tmp);
		if (!(((process_t *)node->value)->flags & PROC_FLAG_FINISHED)) {
			process_t * proc = node->value;
			proc->flags |= PROC_FLAG_SLEEP_INT;
			make_process_ready(proc);
		}
		awoken_processes++;
	}
	return awoken_processes;
}

int sleep_on(list_t * queue) {
	if (current_process->sleep_node.owner) {
		switch_task(0);
		return 0;
	}
	current_process->flags &= ~(PROC_FLAG_SLEEP_INT);
	spin_lock(wait_lock_tmp);
	list_append(queue, (node_t*)&current_process->sleep_node);
	spin_unlock(wait_lock_tmp);
	switch_task(0);
	return !!(current_process->flags & PROC_FLAG_SLEEP_INT);
}

int process_is_ready(process_t * proc) {
	return (proc->sched_node.owner != NULL);
}

void wakeup_sleepers(unsigned long seconds, unsigned long subseconds) {
	arch_enter_critical();
	spin_lock(sleep_lock);
	if (sleep_queue->length) {
		sleeper_t * proc = ((sleeper_t *)sleep_queue->head->value);
		while (proc && (proc->end_tick < seconds || (proc->end_tick == seconds && proc->end_subtick <= subseconds))) {

			if (proc->is_fswait) {
				proc->is_fswait = -1;
				process_alert_node(proc->process,proc);
			} else {
				process_t * process = proc->process;
				process->sleep_node.owner = NULL;
				process->timed_sleep_node = NULL;
				if (!process_is_ready(process)) {
					make_process_ready(process);
				}
			}
			free(proc);
			free(list_dequeue(sleep_queue));
			if (sleep_queue->length) {
				proc = ((sleeper_t *)sleep_queue->head->value);
			} else {
				break;
			}
		}
	}
	spin_unlock(sleep_lock);
	arch_exit_critical();
}

void sleep_until(process_t * process, unsigned long seconds, unsigned long subseconds) {
	if (current_process->sleep_node.owner) {
		/* Can't sleep, sleeping already */
		return;
	}
	process->sleep_node.owner = sleep_queue;

	arch_enter_critical();
	spin_lock(sleep_lock);
	node_t * before = NULL;
	foreach(node, sleep_queue) {
		sleeper_t * candidate = ((sleeper_t *)node->value);
		if (!candidate) {
			printf("null candidate?\n");
			continue;
		}
		if (candidate->end_tick > seconds || (candidate->end_tick == seconds && candidate->end_subtick > subseconds)) {
			break;
		}
		before = node;
	}
	sleeper_t * proc = malloc(sizeof(sleeper_t));
	proc->process     = process;
	proc->end_tick    = seconds;
	proc->end_subtick = subseconds;
	proc->is_fswait = 0;
	process->timed_sleep_node = list_insert_after(sleep_queue, before, proc);
	spin_unlock(sleep_lock);
	arch_exit_critical();
}

process_t * process_from_pid(pid_t pid) {
	if (pid < 0) return NULL;

	spin_lock(tree_lock);
	tree_node_t * entry = tree_find(process_tree,&pid,process_compare);
	spin_unlock(tree_lock);
	if (entry) {
		return (process_t *)entry->value;
	}
	return NULL;
}


long process_move_fd(process_t * proc, long src, long dest) {
	if ((size_t)src >= proc->fds->length || (dest != -1 && (size_t)dest >= proc->fds->length)) {
		return -1;
	}
	if (dest == -1) {
		dest = process_append_fd(proc, NULL);
	}
	if (proc->fds->entries[dest] != proc->fds->entries[src]) {
		close_fs(proc->fds->entries[dest]);
		proc->fds->entries[dest] = proc->fds->entries[src];
		proc->fds->modes[dest] = proc->fds->modes[src];
		proc->fds->offsets[dest] = proc->fds->offsets[src];
		open_fs(proc->fds->entries[dest], 0);
	}
	return dest;
}

void tasking_start(void) {
	current_process = spawn_init();
	kernel_idle_task = spawn_kidle();
}

static int wait_candidate(volatile process_t * parent, int pid, int options, volatile process_t * proc) {
	if (!proc) return 0;

	if (options & WNOKERN) {
		/* Skip kernel processes */
		if (proc->flags & PROC_FLAG_IS_TASKLET) return 0;
	}

	if (pid < -1) {
		if (proc->job == -pid || proc->id == -pid) return 1;
	} else if (pid == 0) {
		/* Matches our group ID */
		if (proc->job == parent->id) return 1;
	} else if (pid > 0) {
		/* Specific pid */
		if (proc->id == pid) return 1;
	} else {
		return 1;
	}
	return 0;
}

void reap_process(process_t * proc) {
	//printf("reaping %p\n", proc);
	free(proc->name);
	process_delete(proc);
}

int waitpid(int pid, int * status, int options) {
	volatile process_t * volatile proc = (process_t*)current_process;
	if (proc->group) {
		proc = process_from_pid(proc->group);
	}

	do {
		volatile process_t * candidate = NULL;
		int has_children = 0;

		/* First, find out if there is anyone to reap */
		foreach(node, proc->tree_entry->children) {
			if (!node->value) {
				continue;
			}
			volatile process_t * volatile child = ((tree_node_t *)node->value)->value;

			if (wait_candidate(proc, pid, options, child)) {
				has_children = 1;
				if (child->flags & PROC_FLAG_FINISHED) {
					candidate = child;
					break;
				}
				if ((options & WSTOPPED) && child->flags & PROC_FLAG_SUSPENDED) {
					candidate = child;
					break;
				}
			}
		}

		if (!has_children) {
			/* No valid children matching this description */
			return -ECHILD;
		}

		if (candidate) {
			if (status) {
				*status = candidate->status;
			}
			int pid = candidate->id;
			if (candidate->flags & PROC_FLAG_FINISHED) {
				reap_process((process_t*)candidate);
			}
			return pid;
		} else {
			if (options & WNOHANG) {
				return 0;
			}
			/* Wait */
			if (sleep_on(proc->wait_queue) != 0) {
				return -EINTR;
			}
		}
	} while (1);
}

extern void relative_time(unsigned long seconds, unsigned long subseconds, unsigned long * out_seconds, unsigned long * out_subseconds);

int process_wait_nodes(process_t * process,fs_node_t * nodes[], int timeout) {
	fs_node_t ** n = nodes;
	int index = 0;
	if (*n) {
		do {
			int result = selectcheck_fs(*n);
			if (result < 0) {
				return -1;
			}
			if (result == 0) {
				return index;
			}
			n++;
			index++;
		} while (*n);
	}

	if (timeout == 0) {
		return -2;
	}

	n = nodes;

	process->node_waits = list_create();
	if (*n) {
		do {
			if (selectwait_fs(*n, process) < 0) {
				printf("bad selectwait?\n");
			}
			n++;
		} while (*n);
	}

	if (timeout > 0) {
		unsigned long s, ss;
		relative_time(0, timeout * 1000, &s, &ss);

		arch_enter_critical();
		spin_lock(sleep_lock);
		node_t * before = NULL;
		foreach(node, sleep_queue) {
			sleeper_t * candidate = ((sleeper_t *)node->value);
			if (candidate->end_tick > s || (candidate->end_tick == s && candidate->end_subtick > ss)) {
				break;
			}
			before = node;
		}
		sleeper_t * proc = malloc(sizeof(sleeper_t));
		proc->process     = process;
		proc->end_tick    = s;
		proc->end_subtick = ss;
		proc->is_fswait = 1;
		list_insert(((process_t *)process)->node_waits, proc);
		process->timeout_node = list_insert_after(sleep_queue, before, proc);
		spin_unlock(sleep_lock);
		arch_exit_critical();
	} else {
		process->timeout_node = NULL;
	}

	process->awoken_index = -1;
	/* Wait. */
	switch_task(0);

	return process->awoken_index;
}

int process_awaken_from_fswait(process_t * process, int index) {
	process->awoken_index = index;
	list_free(process->node_waits);
	free(process->node_waits);
	process->node_waits = NULL;
	if (process->timeout_node && process->timeout_node->owner == sleep_queue) {
		sleeper_t * proc = process->timeout_node->value;
		if (proc->is_fswait != -1) {
			list_delete(sleep_queue, process->timeout_node);
			free(process->timeout_node->value);
			free(process->timeout_node);
		}
	}
	process->timeout_node = NULL;
	make_process_ready(process);
	return 0;
}

int process_alert_node(process_t * process, void * value) {

	if (!is_valid_process(process)) {
		printf("invalid process\n");
		return 0;
	}

	if (!process->node_waits) {
		return 0; /* Possibly already returned. Wait for another call. */
	}

	int index = 0;
	foreach(node, process->node_waits) {
		if (value == node->value) {
			return process_awaken_from_fswait(process, index);
		}
		index++;
	}

	return -1;
}

process_t * process_get_parent(process_t * process) {
	process_t * result = NULL;
	spin_lock(tree_lock);

	tree_node_t * entry = process->tree_entry;

	if (entry->parent) {
		result = entry->parent->value;
	}

	spin_unlock(tree_lock);
	return result;
}

extern void shm_release_all (process_t * proc);
void task_exit(int retval) {
	current_process->status = retval;
	current_process->flags |= PROC_FLAG_FINISHED;
	list_free(current_process->wait_queue);
	free(current_process->wait_queue);
	list_free(current_process->signal_queue);
	free(current_process->signal_queue);
	free(current_process->wd_name);
	if (current_process->node_waits) {
		list_free(current_process->node_waits);
		free(current_process->node_waits);
		current_process->node_waits = NULL;
	}
	shm_release_all(current_process);
	free(current_process->shm_mappings);

	if (current_process->signal_kstack) {
		free(current_process->signal_kstack);
	}

	process_release_directory(current_process->thread.page_directory);

	if (current_process->fds) {
		current_process->fds->refs--;
		if (current_process->fds->refs == 0) {
			for (uint32_t i = 0; i < current_process->fds->length; ++i) {
				if (current_process->fds->entries[i]) {
					close_fs(current_process->fds->entries[i]);
					current_process->fds->entries[i] = NULL;
				}
			}
			free(current_process->fds->entries);
			free(current_process->fds->offsets);
			free(current_process->fds->modes);
			free(current_process->fds);
			current_process->fds = NULL;
			free((void *)(current_process->image.stack - KERNEL_STACK_SIZE));
		}
	}

	process_t * parent = process_get_parent((process_t *)current_process);
	if (parent && !(parent->flags & PROC_FLAG_FINISHED)) {
		send_signal(parent->group, SIGCHLD, 1);
		wakeup_queue(parent->wait_queue);
	}
	switch_next();
}

#define PUSH(stack, type, item) stack -= sizeof(type); \
							*((type *) stack) = item

pid_t fork(void) {
	arch_enter_critical();
	uintptr_t sp, bp;
	process_t * parent = (process_t*)current_process;
	union PML * directory = mmu_clone(parent->thread.page_directory->directory);
	process_t * new_proc = spawn_process(parent, 0);
	new_proc->thread.page_directory = malloc(sizeof(page_directory_t));
	new_proc->thread.page_directory->refcount = 1;
	new_proc->thread.page_directory->directory = directory;

	struct regs r;
	memcpy(&r, parent->syscall_registers, sizeof(struct regs));
	new_proc->syscall_registers = &r; /* what why here */
	sp = new_proc->image.stack;
	bp = sp;

	/* This is all very arch specific... */
	r.rax = 0; /* make fork return 0 */
	PUSH(sp, struct regs, r);
	new_proc->thread.sp = sp;
	new_proc->thread.bp = bp;
	new_proc->thread.tls_base = parent->thread.tls_base;
	new_proc->thread.ip = (uintptr_t)&arch_resume_user;
	if (parent->flags & PROC_FLAG_IS_TASKLET) new_proc->flags |= PROC_FLAG_IS_TASKLET;
	make_process_ready(new_proc);
	arch_exit_critical();
	return new_proc->id;
}

pid_t clone(uintptr_t new_stack, uintptr_t thread_func, uintptr_t arg) {
	arch_enter_critical();
	uintptr_t sp, bp;
	process_t * parent = (process_t *)current_process;
	process_t * new_proc = spawn_process(current_process, 1);
	new_proc->thread.page_directory = current_process->thread.page_directory;
	new_proc->thread.page_directory->refcount++;

	struct regs r;
	memcpy(&r, current_process->syscall_registers, sizeof(struct regs));
	new_proc->syscall_registers = &r;
	sp = new_proc->image.stack;
	bp = sp;

	/* Set the gid */
	if (current_process->group) {
		new_proc->group = current_process->group;
	} else {
		/* We are the session leader */
		new_proc->group = current_process->id;
	}


	/* different calling convention */
	r.rdi = arg;
	PUSH(new_stack, uintptr_t, (uintptr_t)0xFFFFB00F);
	new_proc->syscall_registers->rsp = new_stack;
	new_proc->syscall_registers->rbp = new_stack;
	new_proc->syscall_registers->rip = thread_func;
	PUSH(sp, struct regs, r);
	new_proc->thread.sp = sp;
	new_proc->thread.bp = bp;
	//new_proc->thread.gsbase = current_process->thread.gsbase;
	new_proc->thread.ip = (uintptr_t)&arch_resume_user;
	if (parent->flags & PROC_FLAG_IS_TASKLET) new_proc->flags |= PROC_FLAG_IS_TASKLET;
	make_process_ready(new_proc);
	arch_exit_critical();
	return new_proc->id;
}
