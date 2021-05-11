/**
 * @file   kernel/sys/process.c
 * @brief  Task switch and thread scheduling.
 *
 * Implements the primary scheduling primitives for the kernel.
 *
 * Generally, what the kernel refers to as a "process" is an individual thread.
 * The POSIX concept of a "process" is represented in Misaka as a collection of
 * threads and their shared paging, signal, and file descriptor tables.
 *
 * Kernel threads are also "processes", referred to as "tasklets".
 *
 * Misaka allows nested kernel preemption, and task switching involves saving
 * kernel state in a manner similar to setjmp/longjmp, as well as saving the
 * outer context in the case of a nested task switch.
 *
 * @copyright This file is part of ToaruOS and is released under the terms
 *            of the NCSA / University of Illinois License - see LICENSE.md
 * @author    2011-2021 K. Lange
 * @author    2012 Markus Schober
 * @author    2015 Dale Weiler
 */
#include <errno.h>
#include <kernel/process.h>
#include <kernel/printf.h>
#include <kernel/string.h>
#include <kernel/vfs.h>
#include <kernel/spinlock.h>
#include <kernel/tree.h>
#include <kernel/list.h>
#include <kernel/mmu.h>
#include <kernel/shm.h>
#include <kernel/signal.h>
#include <kernel/arch/x86_64/regs.h>
#include <sys/wait.h>
#include <sys/signal_defs.h>

extern void arch_enter_critical(void);
extern void arch_exit_critical(void);
extern __attribute__((noreturn)) void arch_resume_user(void);
extern __attribute__((noreturn)) void arch_restore_context(volatile thread_t * buf);
extern __attribute__((returns_twice)) int arch_save_context(volatile thread_t * buf);
extern void arch_set_kernel_stack(uintptr_t stack);
extern void arch_restore_floating(process_t * proc);
extern void arch_save_floating(process_t * proc);
extern void arch_pause(void);
extern void arch_fatal(void);

tree_t * process_tree;  /* Stores the parent-child process relationships; the root of this graph is 'init'. */
list_t * process_list;  /* Stores all existing processes. Mostly used for sanity checking or for places where iterating over all processes is useful. */
list_t * process_queue; /* Scheduler ready queue. This the round-robin source. The head is the next process to run. */
list_t * sleep_queue;   /* Ordered list of processes waiting to be awoken by timeouts. The head is the earliest thread to awaken. */

/**
 * @brief The running process on this core.
 *
 * The current_process is a pointer to the process struct for
 * the process, userspace-thread, or kernel tasklet currently
 * executing. Once the scheduler is active, this should always
 * be set. If a core is not currently doing, its current_process
 * should be the core's idle task.
 *
 * Because a process's data can be modified by nested interrupt
 * contexts, we mark them as volatile to avoid making assumptions
 * based on register-stored cached values.
 */
volatile process_t * current_process = NULL;

/**
 * @brief Idle loop.
 *
 * This is a special kernel tasklet that sits in a loop
 * waiting for an interrupt from a preemption source or hardware
 * device. Its context should never be saved, it should never
 * be added to a sleep queue, and it should be scheduled whenever
 * there is nothing else to do.
 */
process_t * kernel_idle_task = NULL;

/* The following locks protect access to the process tree, scheduler queue,
 * sleeping, and the very special wait queue... */
static spin_lock_t tree_lock = { 0 };
static spin_lock_t process_queue_lock = { 0 };
static spin_lock_t wait_lock_tmp = { 0 };
static spin_lock_t sleep_lock = { 0 };

/**
 * @brief Restore the context of the next available process's kernel thread.
 *
 * Loads the next ready process from the scheduler queue and resumes it.
 *
 * If no processes are available, the local idle task will be run from the beginning
 * of its function entry.
 *
 * If the next process in the queue has been marked as finished, it will be discard
 * until a non-finished process is found.
 *
 * If the next process is new, it will be marked as started, and its entry point
 * jumped to.
 *
 * For all other cases, the process's stored kernel thread state will be restored
 * and execution will contain in @ref switch_task with a return value of 1.
 *
 * Note that switch_next does not return and should be called only when the current
 * process has been properly added to a scheduling queue, or marked as awaiting cleanup,
 * otherwise its return state if resumed is undefined and generally whatever the state
 * was when that process last entered switch_task.
 *
 * @returns never.
 */
void switch_next(void) {

	/* Get the next available process, discarded anything in the queue
	 * marked as finished. */
	do {
		current_process = next_ready_process();
	} while (current_process->flags & PROC_FLAG_FINISHED);

	/* Restore paging and task switch context. */
	mmu_set_directory(current_process->thread.page_directory->directory);
	arch_set_kernel_stack(current_process->image.stack);

	if (current_process->flags & PROC_FLAG_STARTED) {
		/* If this process has a signal pending, we save its current context - including
		 * the entire kernel stack - before resuming switch_task. */
		if (!current_process->signal_kstack) {
			if (current_process->signal_queue->length > 0) {
				current_process->signal_kstack = malloc(KERNEL_STACK_SIZE);
				memcpy(current_process->signal_kstack, (void*)(current_process->image.stack - KERNEL_STACK_SIZE), KERNEL_STACK_SIZE);
				memcpy((thread_t*)&current_process->signal_state, (thread_t*)&current_process->thread, sizeof(thread_t));
			}
		}
	}

	/* Mark the process as running and started. */
	current_process->flags |= PROC_FLAG_RUNNING | PROC_FLAG_STARTED;

	/* Restore the execution context of this process's kernel thread. */
	arch_restore_context(&current_process->thread);
	__builtin_unreachable();
}

extern void * _ret_from_preempt_source;

/**
 * @brief Yield the processor to the next available task.
 *
 * Yields the current process, allowing the next to run. Can be called both as
 * part of general preemption or from blocking tasks; in the latter case,
 * the process should be added to a scheduler queue to be awakoen later when the
 * blocking operation is completed and @p reschedule should be set to 0.
 *
 * @param reschedule Non-zero if this process should be added to the ready queue.
 */
void switch_task(uint8_t reschedule) {

	/* switch_task() called but the scheduler isn't enabled? Resume... this is probably a bug. */
	if (!current_process) return;

	/* We don't want to be interrupted in the middle of a task switch, so block interrupts
	 * until we get back from arch_save_context the second time around. */
	arch_enter_critical();

	if (current_process == kernel_idle_task && __builtin_return_address(0) != &_ret_from_preempt_source) {
		printf("Context switch from kernel_idle_task triggered from somewhere other than pre-emption source. Halting.\n");
		printf("This generally means that a driver responding to interrupts has attempted to yield in its interrupt context.\n");
		printf("Ensure that all device drivers which respond to interrupts do so with non-blocking data structures.\n");
		printf("   Return address of switch_task: %p\n", __builtin_return_address(0));
		arch_fatal();
	}

	/* If a process got to switch_task but was not marked as running, it must be exiting and we don't
	 * want to waste time saving context for it. Also, kidle is always resumed from the top of its
	 * loop function, so we don't save any context for it either. */
	if (!(current_process->flags & PROC_FLAG_RUNNING) || (current_process == kernel_idle_task)) {
		switch_next();
		return;
	}

	arch_save_floating((process_t*)current_process);

	/* 'setjmp' - save the execution context. When this call returns '1' we are back
	 * from a task switch and have been awoken if we were sleeping. */
	if (arch_save_context(&current_process->thread) == 1) {
		arch_restore_floating((process_t*)current_process);

		fix_signal_stacks();
		if (!(current_process->flags & PROC_FLAG_FINISHED)) {
			if (current_process->signal_queue->length > 0) {
				node_t * node = list_dequeue(current_process->signal_queue);
				signal_t * sig = node->value;
				free(node);
				handle_signal((process_t*)current_process,sig);
			}
		}

		/* Re-enable interrupts before returning to outer context */
		arch_exit_critical();
		return;
	}

	/* We mark the thread as not running so it shows as such in `ps`, mostly. */
	current_process->flags &= ~(PROC_FLAG_RUNNING);

	/* If this is a normal yield, we reschedule.
	 * XXX: Is this going to work okay with SMP? I think this whole thing
	 *      needs to be wrapped in a lock, but also what if we put the
	 *      thread into a schedule queue previously but a different core
	 *      picks it up before we saved the thread context or the FPU state... */
	if (reschedule) {
		make_process_ready((process_t*)current_process);
	}

	/* @ref switch_next() does not return. */
	switch_next();
}

/**
 * @brief Initial scheduler datastructures.
 *
 * Called by early system startup to allocate trees and lists
 * the schedule uses to track processes.
 */
void initialize_process_tree(void) {
	process_tree = tree_create();
	process_list = list_create();
	process_queue = list_create();
	sleep_queue = list_create();

	/* TODO: PID bitset? */
}

/**
 * @brief Determines if a process is alive and valid.
 *
 * Scans @ref process_list to see if @p process is a valid
 * process object or not.
 *
 * XXX This is horribly inefficient, and its very existence
 *     is likely indicative of bugs whereever it needed to
 *     be called...
 *
 * @param process Process object to check.
 * @returns 1 if the process is valid, 0 if it is not.
 */
int is_valid_process(process_t * process) {
	foreach(lnode, process_list) {
		if (lnode->value == process) {
			return 1;
		}
	}

	return 0;
}

/**
 * @brief Allocate a new file descriptor.
 *
 * Adds a new entry to the file descriptor table for @p proc
 * pointing to the file @p node. The file descriptor's offset
 * and file modes must be set by the caller afterwards.
 *
 * @param proc Process whose file descriptor should be modified.
 * @param node VFS object to add a reference to.
 * @returns the new file descriptor index
 */
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

/**
 * @brief Allocate a process identifier.
 *
 * Obtains the next available process identifier.
 *
 * FIXME This used to use a bitset in Toaru32 so it could
 *       handle overflow of the pid counter. We need to
 *       bring that back.
 *
 * FIXME This defintely needs a lock for SMP, and probably
 *       just in general... or at least an atomic increment...
 */
pid_t get_next_pid(void) {
	static pid_t _next_pid = 2;
	return _next_pid++;
}

extern union PML * current_pml;

/**
 * @brief The idle task.
 *
 * Sits in a loop forever. Scheduled whenever there is nothing
 * else to do. Actually always enters from the top of the function
 * whenever scheduled, as we don't both to save its state.
 */
static void _kidle(void) {
	while (1) {
		arch_pause();
	}
}

/**
 * @brief Release a process's paging data.
 *
 * If this is a thread in a POSIX process with other
 * living threads, the directory is not actually released
 * but the reference count for it is decremented.
 *
 * XXX There's probably no reason for this to take an argument;
 *     we only ever free directories in two places: on exec, or
 *     when a thread exits, and that's always the current thread.
 */
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
	idle->image.stack = (uintptr_t)valloc(KERNEL_STACK_SIZE)+ KERNEL_STACK_SIZE;

	/* TODO arch_initialize_context(uintptr_t) ? */
	idle->thread.context.ip = (uintptr_t)&_kidle;
	idle->thread.context.sp = idle->image.stack;
	idle->thread.context.bp = idle->image.stack;

	/* FIXME Why does the idle thread have wait queues and shm mappings?
	 *       Can we make sure these are never referenced and not allocate them? */
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

	init->image.entry    = 0;
	init->image.heap     = 0;
	init->image.stack    = (uintptr_t)valloc(KERNEL_STACK_SIZE) + KERNEL_STACK_SIZE;
	init->image.shm_heap = 0x200000000; /* That's 8GiB? That should work fine... */

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

	proc->thread.context.sp = 0;
	proc->thread.context.bp = 0;
	proc->thread.context.ip = 0;
	memcpy((void*)proc->thread.fp_regs, (void*)parent->thread.fp_regs, 512);

	/* Entry is only stored for reference. */
	proc->image.entry       = parent->image.entry;
	proc->image.heap        = parent->image.heap;
	proc->image.stack       = (uintptr_t)valloc(KERNEL_STACK_SIZE) + KERNEL_STACK_SIZE;
	proc->image.shm_heap    = 0x200000000; /* FIXME this should be a macro def */

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

extern void tree_remove_reparent_root(tree_t * tree, tree_node_t * node);

/**
 * @brief Remove a process from the valid process list.
 *
 * Deletes a process from both the valid list and the process tree.
 * Any the process has any children, they become orphaned and are
 * moved under 'init', which is awoken if it was blocked on 'waitpid'.
 *
 * Finally, the process is freed.
 */
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

/**
 * @brief Place an available process in the ready queue.
 *
 * Marks a process as available for general scheduling.
 * If the process was currently in a sleep queue, it is
 * marked as having been interrupted and removed from its
 * owning queue before being moved.
 *
 * The process must not otherwise have been in a scheduling
 * queue before it is placed in the ready queue.
 */
void make_process_ready(volatile process_t * proc) {
	if (proc->sleep_node.owner != NULL) {
		if (proc->sleep_node.owner == sleep_queue) {
			/* The sleep queue is slightly special... */
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
			/* This was blocked on a semaphore we can interrupt. */
			proc->flags |= PROC_FLAG_SLEEP_INT;
			spin_lock(wait_lock_tmp);
			list_delete((list_t*)proc->sleep_node.owner, (node_t*)&proc->sleep_node);
			spin_unlock(wait_lock_tmp);
		}
	}

	if (proc->sched_node.owner) {
		/* There's only one ready queue, so this means the process was already ready, which
		 * is indicative of a bug somewhere as we shouldn't be added processes to the ready
		 * queue multiple times. */
		printf("Can't make process ready without removing it from owner list: %d\n", proc->id);
		printf("  (This is a bug) Current owner list is %p (ready queue is %p)\n", proc->sched_node.owner, process_queue);
		return;
	}

	spin_lock(process_queue_lock);
	list_append(process_queue, (node_t*)&proc->sched_node);
	spin_unlock(process_queue_lock);
}

/**
 * @brief Pop the next available process from the queue.
 *
 * Gets the next available process from the round-robin scheduling
 * queue. If there is no process to run, the idle task is returned.
 *
 * TODO This needs more locking for SMP...
 */
process_t * next_ready_process(void) {
	if (!process_queue->head) {
		return kernel_idle_task;
	}

	if (process_queue->head->owner != process_queue) {
		/* I haven't actually seen this happen since the kernel context
		 * switching was fixed, so it may not be a thing anymore... */
		printf("Uh oh.\n");
	}

	node_t * np = list_dequeue(process_queue);
	process_t * next = np->value;
	return next;
}

/**
 * @brief Signal a semaphore.
 *
 * Okay, so toaru32 used these general-purpose lists of processes
 * as a sort of sempahore system, so often when you see 'queue' it
 * can be read as 'semaphore' and be equally valid (outside of the
 * 'ready queue', I guess). This will awaken all processes currently
 * in the semaphore @p queue, unless they were marked as finished in
 * which case they will be discarded.
 *
 * Note that these "semaphore queues" are binary semaphores - simple
 * locks, but with smarter logic than the "spin_lock" primitive also
 * used throughout the kernel, as that just blindly switches tasks
 * until its atomic swap succeeds.
 *
 * @param queue The semaphore to signal
 * @returns the number of processes successfully awoken
 */
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

/**
 * @brief Signal a semaphore, exceptionally.
 *
 * Wake up everything in the semaphore @p queue but mark every
 * waiter as having been interrupted, rather than gracefully awoken.
 * Generally that means the event they were waiting for did not
 * happen and may never happen.
 *
 * Otherwise, same semantics as @ref wakeup_queue.
 */
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

/**
 * @brief Wait for a binary semaphore.
 *
 * Wait for an event with everyone else in @p queue.
 *
 * @returns 1 if the wait was interrupted (eg. the event did not occur); 0 otherwise.
 */
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

/**
 * @brief Indicates whether a process is ready to be run but not currently running.
 */
int process_is_ready(process_t * proc) {
	return (proc->sched_node.owner != NULL);
}

/**
 * @brief Wake up processes that were sleeping on timers.
 *
 * Reschedule all processes whose timed waits have expired as of
 * the time indicated by @p seconds and @p subseconds. If the sleep
 * was part of an fswait system call timing out, the call is marked
 * as timed out before the process is rescheduled.
 */
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

/**
 * @brief Wait until a given time.
 *
 * Suspends the current process until the given time. The process may
 * still be resumed by a signal or other mechanism, in which case the
 * sleep will not be resumed by the kernel.
 */
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

uint8_t process_compare(void * proc_v, void * pid_v) {
	pid_t pid = (*(pid_t *)pid_v);
	process_t * proc = (process_t *)proc_v;

	return (uint8_t)(proc->id == pid);
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
	shm_release_all((process_t*)current_process);
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
	/* arch_setup_fork_return? */
	r.rax = 0; /* make fork return 0 */
	PUSH(sp, struct regs, r);
	new_proc->thread.context.sp = sp;
	new_proc->thread.context.bp = bp;
	new_proc->thread.context.tls_base = parent->thread.context.tls_base;
	new_proc->thread.context.ip = (uintptr_t)&arch_resume_user;
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
	new_proc->thread.context.sp = sp;
	new_proc->thread.context.bp = bp;
	new_proc->thread.context.tls_base = current_process->thread.context.tls_base;
	new_proc->thread.context.ip = (uintptr_t)&arch_resume_user;
	if (parent->flags & PROC_FLAG_IS_TASKLET) new_proc->flags |= PROC_FLAG_IS_TASKLET;
	make_process_ready(new_proc);
	arch_exit_critical();
	return new_proc->id;
}
