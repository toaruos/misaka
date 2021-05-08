#include <kernel/types.h>
#include <kernel/string.h>
#include <kernel/printf.h>
#include <kernel/vfs.h>
#include <kernel/pipe.h>
#include <kernel/version.h>
#include <kernel/process.h>
#include <kernel/signal.h>

#include <sys/time.h>
#include <sys/utsname.h>
#include <kernel/arch/x86_64/mmu.h>
#include <kernel/arch/x86_64/ports.h>
#include <kernel/arch/x86_64/pml.h>
#include <kernel/arch/x86_64/regs.h>

/**
 * Interrupt descriptor table
 */
typedef struct {
	uint16_t base_low;
	uint16_t selector;

	uint8_t zero;
	uint8_t flags;

	uint16_t base_mid;
	uint32_t base_high;
	uint32_t pad;
} __attribute__((packed)) idt_entry_t;

struct idt_pointer {
	uint16_t  limit;
	uintptr_t base;
} __attribute__((packed));

static struct idt_pointer idtp;
static idt_entry_t idt[256];

extern void arch_enter_critical(void);
extern void arch_exit_critical(void);
extern void idt_load(void *);

typedef struct regs * (*interrupt_handler_t)(struct regs *);

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

extern struct regs * _isr0(struct regs*);
extern struct regs * _isr1(struct regs*);
extern struct regs * _isr2(struct regs*);
extern struct regs * _isr3(struct regs*);
extern struct regs * _isr4(struct regs*);
extern struct regs * _isr5(struct regs*);
extern struct regs * _isr6(struct regs*);
extern struct regs * _isr7(struct regs*);
extern struct regs * _isr8(struct regs*);
extern struct regs * _isr9(struct regs*);
extern struct regs * _isr10(struct regs*);
extern struct regs * _isr11(struct regs*);
extern struct regs * _isr12(struct regs*);
extern struct regs * _isr13(struct regs*);
extern struct regs * _isr14(struct regs*);
extern struct regs * _isr15(struct regs*);
extern struct regs * _isr16(struct regs*);
extern struct regs * _isr17(struct regs*);
extern struct regs * _isr18(struct regs*);
extern struct regs * _isr19(struct regs*);
extern struct regs * _isr20(struct regs*);
extern struct regs * _isr21(struct regs*);
extern struct regs * _isr22(struct regs*);
extern struct regs * _isr23(struct regs*);
extern struct regs * _isr24(struct regs*);
extern struct regs * _isr25(struct regs*);
extern struct regs * _isr26(struct regs*);
extern struct regs * _isr27(struct regs*);
extern struct regs * _isr28(struct regs*);
extern struct regs * _isr29(struct regs*);
extern struct regs * _isr30(struct regs*);
extern struct regs * _isr31(struct regs*);
extern struct regs * _irq0(struct regs*);
extern struct regs * _irq1(struct regs*);
extern struct regs * _irq2(struct regs*);
extern struct regs * _irq3(struct regs*);
extern struct regs * _irq4(struct regs*);
extern struct regs * _irq5(struct regs*);
extern struct regs * _irq6(struct regs*);
extern struct regs * _irq7(struct regs*);
extern struct regs * _irq8(struct regs*);
extern struct regs * _irq9(struct regs*);
extern struct regs * _irq10(struct regs*);
extern struct regs * _irq11(struct regs*);
extern struct regs * _irq12(struct regs*);
extern struct regs * _irq13(struct regs*);
extern struct regs * _irq14(struct regs*);
extern struct regs * _irq15(struct regs*);
extern struct regs * _isr127(struct regs*);

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
		"  rax=0x%016lx rbx=0x%016lx rcx=0x%016lx rdx=0x%016lx\n"
		"  rsi=0x%016lx rdi=0x%016lx rbp=0x%016lx\n"
		"   r8=0x%016lx  r9=0x%016lx r10=0x%016lx r11=0x%016lx\n"
		"  r12=0x%016lx r13=0x%016lx r14=0x%016lx r15=0x%016lx\n"
		"  rip=0x%016lx  cs=0x%016lx rsp=0x%016lx  ss=0x%016lx\n"
		"  rflags=0x%016lx int=0x%02lx err=0x%02lx\n",
		r->rax, r->rbx, r->rcx, r->rdx,
		r->rsi, r->rdi, r->rbp,
		r->r8, r->r9, r->r10, r->r11,
		r->r12, r->r13, r->r14, r->r15,
		r->rip, r->cs, r->rsp, r->ss,
		r->rflags, r->int_no, r->err_code
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

extern void irq_ack(size_t irq_no);
extern void cmos_time_stuff(void);

#define KEY_DEVICE  0x60
#define KEY_PENDING 0x64
#define KEY_IRQ     1

static fs_node_t * keyboard_pipe;
static void keyboard_wait(void) {
	while(inportb(KEY_PENDING) & 2);
}
static int keyboard_handler(struct regs *r) {
	unsigned char scancode;
	if (inportb(KEY_PENDING) & 0x01) {
		scancode = inportb(KEY_DEVICE);

		write_fs(keyboard_pipe, 0, 1, (uint8_t []){scancode});
	}

	irq_ack(KEY_IRQ);
	return 1;
}

void keyboard_install(void) {
	keyboard_pipe = make_pipe(128);
	keyboard_pipe->flags = FS_CHARDEVICE;
	vfs_mount("/dev/kbd", keyboard_pipe);
}

extern void task_exit(int);

struct regs * isr_handler(struct regs * r) {
	current_process->interrupt_registers = r;
	switch (r->int_no) {
		case 14: /* Page fault */ {
			uintptr_t faulting_address;
			asm volatile("mov %%cr2, %0" : "=r"(faulting_address));
			if (faulting_address == 0xFFFFB00F) {
				/* Thread exit */
				task_exit(0);
				break;
			}
			if (faulting_address == 0x8DEADBEEF) {
				return_from_signal_handler();
				break;
			}
			printf("Page fault in %p\n", current_process); //pid=%d (%s)\n", (int)current_process->id, current_process->name);
			printf("cr2: 0x%016lx\n", faulting_address);
			dump_regs(r);
			printf("Stack is at ~%p\n", r);
			arch_enter_critical();
			while (1) { asm volatile ("hlt"); }
			//task_exit(1);
			break;
		}
		case 13: /* GPF */ {
			printf("General Protection Fault in pid=%d (%s)\n", (int)current_process->id, current_process->name);
			dump_regs(r);
			arch_enter_critical();
			while (1) { asm volatile ("hlt"); }
			//task_exit(1);
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
		case 6: /* Invalid opcode */ {
			printf("Invalid opcode\n");
			dump_regs(r);
			while (1) {};
			break;
		}
		case 127: /* syscall */ {
			syscall_handler(r);
			asm volatile("sti");
			return r;
		}
		case 32: /* Generally the PIT */
			/* FIXME:
			 *    We need to port over the IRQ chaining stuff from toaru32
			 *    for quite a lot of our hardware to work
			 **/
			irq_ack(0);
			cmos_time_stuff();
			break;
		case 33: {
			keyboard_handler(r);
			break;
		}
		case 44: {
			extern int mouse_handler(struct regs *r);
			mouse_handler(r);
			irq_ack(12);
			break;
		}
		default: {
			printf("In pid=%d (%s):\n", current_process->id, current_process->name);
			if (r->int_no < 32) {
				printf("Unhandled exception: %s\n", exception_messages[r->int_no]);
			} else {
				printf("Unhandled interrupt: %d\n", r->int_no - 32);
				irq_ack(r->int_no - 32);
			}
			dump_regs(r);
		}
	}

	asm volatile("sti");
	return r;
}

