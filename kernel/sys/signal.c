/* vim: tabstop=4 shiftwidth=4 noexpandtab
 * This file is part of ToaruOS and is released under the terms
 * of the NCSA / University of Illinois License - see LICENSE.md
 * Copyright (C) 2012-2018 K. Lange
 *
 * Signal Handling
 */
#include <errno.h>
#include <stdint.h>
#include <sys/signal.h>
#include <sys/signal_defs.h>
#include <kernel/printf.h>
#include <kernel/string.h>
#include <kernel/process.h>
#include <kernel/signal.h>
#include <kernel/spinlock.h>

__attribute__((noreturn))
extern void arch_enter_signal_handler(uintptr_t,int);

static spin_lock_t sig_lock;
static spin_lock_t sig_lock_b;

char isdeadly[] = {
	0, /* 0? */
	[SIGHUP     ] = 1,
	[SIGINT     ] = 1,
	[SIGQUIT    ] = 2,
	[SIGILL     ] = 2,
	[SIGTRAP    ] = 2,
	[SIGABRT    ] = 2,
	[SIGEMT     ] = 2,
	[SIGFPE     ] = 2,
	[SIGKILL    ] = 1,
	[SIGBUS     ] = 2,
	[SIGSEGV    ] = 2,
	[SIGSYS     ] = 2,
	[SIGPIPE    ] = 1,
	[SIGALRM    ] = 1,
	[SIGTERM    ] = 1,
	[SIGUSR1    ] = 1,
	[SIGUSR2    ] = 1,
	[SIGCHLD    ] = 0,
	[SIGPWR     ] = 0,
	[SIGWINCH   ] = 0,
	[SIGURG     ] = 0,
	[SIGPOLL    ] = 0,
	[SIGSTOP    ] = 3,
	[SIGTSTP    ] = 3,
	[SIGCONT    ] = 4,
	[SIGTTIN    ] = 3,
	[SIGTTOUT   ] = 3,
	[SIGVTALRM  ] = 1,
	[SIGPROF    ] = 1,
	[SIGXCPU    ] = 2,
	[SIGXFSZ    ] = 2,
	[SIGWAITING ] = 0,
	[SIGDIAF    ] = 1,
	[SIGHATE    ] = 0,
	[SIGWINEVENT] = 0,
	[SIGCAT     ] = 0,
};

void handle_signal(process_t * proc, signal_t * sig) {
	uintptr_t handler = sig->handler;
	uintptr_t signum  = sig->signum;
	free(sig);

	if (proc->flags & PROC_FLAG_FINISHED) {
		return;
	}

	if (signum == 0 || signum >= NUMSIGNALS) {
		/* Ignore */
		return;
	}

	if (!handler) {
		char dowhat = isdeadly[signum];
		if (dowhat == 1 || dowhat == 2) {
			task_exit(((128 + signum) << 8) | signum);
			__builtin_unreachable();
		} else if (dowhat == 3) {
			current_process->flags |= PROC_FLAG_SUSPENDED;
			current_process->status = 0x7F;

			process_t * parent = process_get_parent((process_t *)current_process);

			if (parent && !(parent->flags & PROC_FLAG_FINISHED)) {
				wakeup_queue(parent->wait_queue);
			}

			switch_task(0);
		} else if (dowhat == 4) {
			switch_task(1);
			return;
		}
		/* XXX dowhat == 2: should dump core */
		/* XXX dowhat == 3: stop */
		return;
	}

	if (handler == 1) /* Ignore */ {
		return;
	}

	arch_enter_signal_handler(handler, signum);
}

list_t * rets_from_sig;

void return_from_signal_handler(void) {
	if (__builtin_expect(!rets_from_sig, 0)) {
		rets_from_sig = list_create();
	}

	spin_lock(sig_lock);
	list_insert(rets_from_sig, (process_t *)current_process);
	spin_unlock(sig_lock);

	switch_next();
}

void fix_signal_stacks(void) {
	uint8_t redo_me = 0;
	if (rets_from_sig) {
		spin_lock(sig_lock_b);
		while (rets_from_sig->head) {
			spin_lock(sig_lock);
			node_t * n = list_dequeue(rets_from_sig);
			spin_unlock(sig_lock);
			if (!n) {
				continue;
			}
			process_t * p = n->value;
			free(n);
			if (p == current_process) {
				redo_me = 1;
				continue;
			}
			/* TODO arch_copy_context? */
			p->thread.sp = p->signal_state.sp;
			p->thread.ip = p->signal_state.ip;
			p->thread.bp = p->signal_state.bp;
			if (!p->signal_kstack) {
				printf("Cannot restore signal stack for pid=%d - unset?\n", p->id);
			} else {
				memcpy((void *)(p->image.stack - KERNEL_STACK_SIZE), p->signal_kstack, KERNEL_STACK_SIZE);
				free(p->signal_kstack);
				p->signal_kstack = NULL;
			}
			make_process_ready(p);
		}
		spin_unlock(sig_lock_b);
	}
	if (redo_me) {
		spin_lock(sig_lock);
		list_insert(rets_from_sig, (process_t *)current_process);
		spin_unlock(sig_lock);
		switch_next();
	}
}

int send_signal(pid_t process, int signal, int force_root) {
	process_t * receiver = process_from_pid(process);

	if (!receiver) {
		/* Invalid pid */
		return -ESRCH;
	}

	if (!force_root && receiver->user != current_process->user && current_process->user != USER_ROOT_UID) {
		if (!(signal == SIGCONT && receiver->session == current_process->session)) {
			return -EPERM;
		}
	}

	if (signal > NUMSIGNALS) {
		/* Invalid signal */
		return -EINVAL;
	}

	if (receiver->flags & PROC_FLAG_FINISHED) {
		/* Can't send signals to finished processes */
		return -EINVAL;
	}

	if (!receiver->signals[signal] && !isdeadly[signal]) {
		/* If we're blocking a signal and it's not going to kill us, don't deliver it */
		return 0;
	}

	if (isdeadly[signal] == 4) {
		if (!(receiver->flags & PROC_FLAG_SUSPENDED)) {
			return -EINVAL;
		} else {
			receiver->flags &= ~(PROC_FLAG_SUSPENDED);
			receiver->status = 0;
		}
	}

	/* Append signal to list */
	signal_t * sig = malloc(sizeof(signal_t));
	sig->handler = (uintptr_t)receiver->signals[signal];
	sig->signum  = signal;
	memset(&sig->registers_before, 0x00, sizeof(struct regs));

	if (receiver->node_waits) {
		process_awaken_from_fswait(receiver, -1);
	}
	if (!process_is_ready(receiver)) {
		make_process_ready(receiver);
	}

	list_insert(receiver->signal_queue, sig);

	if (receiver == current_process) {
		/* Forces us to be rescheduled and enter signal handler */
		if (receiver->signal_kstack) {
			switch_next();
		} else {
			switch_task(0);
		}
	}

	return 0;
}

int group_send_signal(pid_t group, int signal, int force_root) {

	int kill_self = 0;
	int killed_something = 0;

	foreach(node, process_list) {
		process_t * proc = node->value;
		if (proc->group == proc->id && proc->job == group) {
			/* Only thread group leaders */
			if (proc->group == current_process->group) {
				kill_self = 1;
			} else {
				if (send_signal(proc->group, signal, force_root) == 0) {
					killed_something = 1;
				}
			}
		}
	}

	if (kill_self) {
		if (send_signal(current_process->group, signal, force_root) == 0) {
			killed_something = 1;
		}
	}

	return !!killed_something;
}

