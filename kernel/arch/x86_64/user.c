#include <stdint.h>
#include <kernel/process.h>
#include <kernel/string.h>
#include <kernel/arch/x86_64/regs.h>

void arch_enter_user(uintptr_t entrypoint, int argc, char * argv[], char * envp[], uintptr_t stack) {
	struct regs ret;
	ret.cs = 0x18 | 0x03;
	ret.ss = 0x20 | 0x03;
	ret.rip = entrypoint;
	ret.rflags = (1 << 21) | (1 << 9);
	ret.rsp = stack;

	asm volatile (
		"pushq %0\n"
		"pushq %1\n"
		"pushq %2\n"
		"pushq %3\n"
		"pushq %4\n"
		"iretq"
	: : "m"(ret.ss), "m"(ret.rsp), "m"(ret.rflags), "m"(ret.cs), "m"(ret.rip),
	    "D"(argc), "S"(argv), "d"(envp));
}

void arch_enter_signal_handler(uintptr_t entrypoint, int signum) {
	struct regs ret;
	ret.cs = 0x18 | 0x03;
	ret.ss = 0x20 | 0x03;
	ret.rip = entrypoint;
	ret.rflags = (1 << 21) | (1 << 9);
	ret.rsp = (current_process->syscall_registers->rsp - 128 - 8) & 0xFFFFFFFFFFFFFFF0; /* ensure considerable alignment */
	*(uintptr_t*)ret.rsp = 0x00000008DEADBEEF; /* arbitrarily chosen stack return sentinel IP */

	asm volatile(
		"pushq %0\n"
		"pushq %1\n"
		"pushq %2\n"
		"pushq %3\n"
		"pushq %4\n"
		"iretq"
	: : "m"(ret.ss), "m"(ret.rsp), "m"(ret.rflags), "m"(ret.cs), "m"(ret.rip),
	    "D"(signum));
}

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

static uint8_t saves[512] __attribute__((aligned(16)));
void arch_restore_floating(process_t * proc) {
	memcpy(&saves,(uint8_t *)&proc->thread.fp_regs,512);
	asm volatile ("fxrstor (%0)" :: "r"(saves));
}

void arch_save_floating(process_t * proc) {
	asm volatile ("fxsave (%0)" :: "r"(saves));
	memcpy((uint8_t *)&proc->thread.fp_regs,&saves,512);
}

void arch_pause(void) {
	asm volatile (
		"sti\n"
		"hlt\n"
	);
}
