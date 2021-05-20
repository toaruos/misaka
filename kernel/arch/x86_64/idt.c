#include <kernel/types.h>
#include <kernel/string.h>
#include <kernel/printf.h>
#include <kernel/vfs.h>
#include <kernel/version.h>
#include <kernel/process.h>
#include <kernel/signal.h>
#include <kernel/misc.h>

#include <sys/time.h>
#include <sys/utsname.h>
#include <kernel/arch/x86_64/mmu.h>
#include <kernel/arch/x86_64/ports.h>
#include <kernel/arch/x86_64/pml.h>
#include <kernel/arch/x86_64/regs.h>
#include <kernel/arch/x86_64/irq.h>

static struct idt_pointer idtp;
static idt_entry_t idt[256];

void idt_set_gate(uint8_t num, interrupt_handler_t handler, uint16_t selector, uint8_t flags) {
	uintptr_t base = (uintptr_t)handler;
	idt[num].base_low  = (base & 0xFFFF);
	idt[num].base_mid  = (base >> 16) & 0xFFFF;
	idt[num].base_high = (base >> 32) & 0xFFFFFFFF;
	idt[num].selector = selector;
	idt[num].zero = 0;
	idt[num].pad = 0;
	idt[num].flags = flags | 0x60;
}

void idt_install(void) {
	idtp.limit = sizeof(idt);
	idtp.base  = (uintptr_t)&idt;

	/** ISRs */
	idt_set_gate(0, _isr0, 0x08, 0x8E);
	idt_set_gate(1, _isr1, 0x08, 0x8E);
	idt_set_gate(2, _isr2, 0x08, 0x8E);
	idt_set_gate(3, _isr3, 0x08, 0x8E);
	idt_set_gate(4, _isr4, 0x08, 0x8E);
	idt_set_gate(5, _isr5, 0x08, 0x8E);
	idt_set_gate(6, _isr6, 0x08, 0x8E);
	idt_set_gate(7, _isr7, 0x08, 0x8E);
	idt_set_gate(8, _isr8, 0x08, 0x8E);
	idt_set_gate(9, _isr9, 0x08, 0x8E);
	idt_set_gate(10, _isr10, 0x08, 0x8E);
	idt_set_gate(11, _isr11, 0x08, 0x8E);
	idt_set_gate(12, _isr12, 0x08, 0x8E);
	idt_set_gate(13, _isr13, 0x08, 0x8E);
	idt_set_gate(14, _isr14, 0x08, 0x8E);
	idt_set_gate(15, _isr15, 0x08, 0x8E);
	idt_set_gate(16, _isr16, 0x08, 0x8E);
	idt_set_gate(17, _isr17, 0x08, 0x8E);
	idt_set_gate(18, _isr18, 0x08, 0x8E);
	idt_set_gate(19, _isr19, 0x08, 0x8E);
	idt_set_gate(20, _isr20, 0x08, 0x8E);
	idt_set_gate(21, _isr21, 0x08, 0x8E);
	idt_set_gate(22, _isr22, 0x08, 0x8E);
	idt_set_gate(23, _isr23, 0x08, 0x8E);
	idt_set_gate(24, _isr24, 0x08, 0x8E);
	idt_set_gate(25, _isr25, 0x08, 0x8E);
	idt_set_gate(26, _isr26, 0x08, 0x8E);
	idt_set_gate(27, _isr27, 0x08, 0x8E);
	idt_set_gate(28, _isr28, 0x08, 0x8E);
	idt_set_gate(29, _isr29, 0x08, 0x8E);
	idt_set_gate(30, _isr30, 0x08, 0x8E);
	idt_set_gate(31, _isr31, 0x08, 0x8E);

	idt_set_gate(32, _irq0, 0x08, 0x8E);
	idt_set_gate(33, _irq1, 0x08, 0x8E);
	idt_set_gate(34, _irq2, 0x08, 0x8E);
	idt_set_gate(35, _irq3, 0x08, 0x8E);
	idt_set_gate(36, _irq4, 0x08, 0x8E);
	idt_set_gate(37, _irq5, 0x08, 0x8E);
	idt_set_gate(38, _irq6, 0x08, 0x8E);
	idt_set_gate(39, _irq7, 0x08, 0x8E);
	idt_set_gate(40, _irq8, 0x08, 0x8E);
	idt_set_gate(41, _irq9, 0x08, 0x8E);
	idt_set_gate(42, _irq10, 0x08, 0x8E);
	idt_set_gate(43, _irq11, 0x08, 0x8E);
	idt_set_gate(44, _irq12, 0x08, 0x8E);
	idt_set_gate(45, _irq13, 0x08, 0x8E);
	idt_set_gate(46, _irq14, 0x08, 0x8E);
	idt_set_gate(47, _irq15, 0x08, 0x8E);
	idt_set_gate(127, _isr127, 0x08, 0x8E);

	asm volatile (
		"lidt %0"
		: : "m"(idtp)
	);
}

static void dump_regs(struct regs * r) {
	printf(
		"Registers at interrupt:\n"
		"  $rip=0x%016lx\n"
		"  $rsi=0x%016lx,$rdi=0x%016lx,$rbp=0x%016lx,$rsp=0x%016lx\n"
		"  $rax=0x%016lx,$rbx=0x%016lx,$rcx=0x%016lx,$rdx=0x%016lx\n"
		"  $r8= 0x%016lx,$r9= 0x%016lx,$r10=0x%016lx,$r11=0x%016lx\n"
		"  $r12=0x%016lx,$r13=0x%016lx,$r14=0x%016lx,$r15=0x%016lx\n"
		"  cs=0x%016lx  ss=0x%016lx rflags=0x%016lx int=0x%02lx err=0x%02lx\n",
		r->rip,
		r->rsi, r->rdi, r->rbp, r->rsp,
		r->rax, r->rbx, r->rcx, r->rdx,
		r->r8, r->r9, r->r10, r->r11,
		r->r12, r->r13, r->r14, r->r15,
		r->cs, r->ss, r->rflags, r->int_no, r->err_code
	);
}

extern void syscall_handler(struct regs *);

static const char *exception_messages[32] = {
	"Division by zero",
	"Debug",
	"Non-maskable interrupt",
	"Breakpoint",
	"Detected overflow",
	"Out-of-bounds",
	"Invalid opcode",
	"No coprocessor",
	"Double fault",
	"Coprocessor segment overrun",
	"Bad TSS",
	"Segment not present",
	"Stack fault",
	"General protection fault",
	"Page fault",
	"Unknown interrupt",
	"Coprocessor fault",
	"Alignment check",
	"Machine check",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved"
};

#define IRQ_CHAIN_SIZE  16
#define IRQ_CHAIN_DEPTH 4
static irq_handler_chain_t irq_routines[IRQ_CHAIN_SIZE * IRQ_CHAIN_DEPTH] = { NULL };
static const char * _irq_handler_descriptions[IRQ_CHAIN_SIZE * IRQ_CHAIN_DEPTH] = { NULL };

const char * get_irq_handler(int irq, int chain) {
	if (irq >= IRQ_CHAIN_SIZE) return NULL;
	if (chain >= IRQ_CHAIN_DEPTH) return NULL;
	return _irq_handler_descriptions[IRQ_CHAIN_SIZE * chain + irq];
}

void irq_install_handler(size_t irq, irq_handler_chain_t handler, const char * desc) {
	arch_enter_critical();
	for (size_t i = 0; i < IRQ_CHAIN_DEPTH; i++) {
		if (irq_routines[i * IRQ_CHAIN_SIZE + irq])
			continue;
		irq_routines[i * IRQ_CHAIN_SIZE + irq] = handler;
		_irq_handler_descriptions[i * IRQ_CHAIN_SIZE + irq ] = desc;
		break;
	}
	arch_exit_critical();
}

void irq_uninstall_handler(size_t irq) {
	arch_enter_critical();
	for (size_t i = 0; i < IRQ_CHAIN_DEPTH; i++)
		irq_routines[i * IRQ_CHAIN_SIZE + irq] = NULL;
	arch_exit_critical();
}

struct regs * isr_handler(struct regs * r) {
	this_core->current_process->interrupt_registers = r;
	switch (r->int_no) {
		case 14: /* Page fault */ {
			uintptr_t faulting_address;
			asm volatile("mov %%cr2, %0" : "=r"(faulting_address));
			if (!this_core->current_process) {
				printf("Page fault in early startup at %#zx\n", faulting_address);
				dump_regs(r);
				break;
			}
			if (faulting_address == 0xFFFFB00F) {
				/* Thread exit */
				task_exit(0);
				break;
			}
			if (faulting_address == 0x8DEADBEEF) {
				return_from_signal_handler();
				break;
			}
			printf("Page fault in pid=%d (%s) at %#zx\n", (int)this_core->current_process->id, this_core->current_process->name, faulting_address);
			dump_regs(r);
			if (this_core->current_process->flags & PROC_FLAG_IS_TASKLET) {
				printf("Segmentation fault in kernel worker thread, halting.\n");
				arch_fatal();
			}
			send_signal(this_core->current_process->id, SIGSEGV, 1);
			break;
		}
		case 13: /* GPF */ {
			if (!this_core->current_process) {
				printf("GPF in early startup\n");
				dump_regs(r);
				break;
			}
			send_signal(this_core->current_process->id, SIGSEGV, 1);
			break;
		}
		case 8: /* Double fault */ {
			printf("Double fault?\n");
			uintptr_t faulting_address;
			asm volatile("mov %%cr2, %0" : "=r"(faulting_address));
			printf("cr2: 0x%016lx\n", faulting_address);
			dump_regs(r);
			break;
		}
		case 127: /* syscall */ {
			syscall_handler(r);
			asm volatile("sti");
			return r;
		}
		case 39: {
			/* Spurious interrupt */
			break;
		}
		default: {
			if (r->int_no < 32) {
				if (!this_core->current_process) {
					printf("Unhandled exception: %s\n", exception_messages[r->int_no]);
					break;
				}
				printf("Killing %d from unhandled %s\n", this_core->current_process->id, exception_messages[r->int_no]);
				send_signal(this_core->current_process->id, SIGILL, 1);
			} else {
				for (size_t i = 0; i < IRQ_CHAIN_DEPTH; i++) {
					irq_handler_chain_t handler = irq_routines[i * IRQ_CHAIN_SIZE + (r->int_no - 32)];
					if (!handler) break;
					if (handler(r)) {
						goto done;
					}
				}
				irq_ack(r->int_no - 32);
				#if 0
				printf("Unhandled interrupt: %lu\n", r->int_no - 32);
				dump_regs(r);
				#endif
				break;
			}
		}
	}

done:

	if (this_core->current_process == this_core->kernel_idle_task && process_queue->head) {
		/* If this is kidle and we got here, instead of finishing the interrupt
		 * we can just switch task and there will probably be something else
		 * to run that was awoken by the interrupt. */
		switch_next();
	}

	return r;
}

