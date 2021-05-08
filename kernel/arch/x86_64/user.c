#include <stdint.h>
#include <kernel/process.h>
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
