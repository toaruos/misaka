#include <kernel/printf.h>
#include <kernel/arch/x86_64/ports.h>

/* Programmable interrupt controller */
#define PIC1           0x20
#define PIC1_COMMAND   PIC1
#define PIC1_OFFSET    0x20
#define PIC1_DATA      (PIC1+1)

#define PIC2           0xA0
#define PIC2_COMMAND   PIC2
#define PIC2_OFFSET    0x28
#define PIC2_DATA      (PIC2+1)

#define PIC_EOI        0x20

#define ICW1_ICW4      0x01
#define ICW1_INIT      0x10

#define PIC_WAIT() \
	do { \
		/* May be fragile */ \
		asm volatile("jmp 1f\n\t" \
		             "1:\n\t" \
		             "    jmp 2f\n\t" \
		             "2:"); \
	} while (0)

static volatile int sync_depth = 0;

#define SYNC_CLI() asm volatile("cli")
#define SYNC_STI() asm volatile("sti")

void arch_enter_critical(void) {
	uint64_t rflags;
	asm volatile (
		"pushfq\n"
		"popq %0\n"
		: "=A"(rflags)
	);
	SYNC_CLI();
	if (rflags & (1 << 9)) {
		/* FIXME: This needs to be per-cpu, so it should ref %gs? */
		sync_depth = 1;
	} else {
		sync_depth++;
	}
}

void arch_enable_interrupts(void) {
	SYNC_STI();
}

void arch_exit_critical(void) {
	if (sync_depth <= 1) {
		SYNC_STI();
		sync_depth = 0;
		return;
	}
	sync_depth--;
}


static void irq_remap(void) {
	/* Cascade initialization */
	outportb(PIC1_COMMAND, ICW1_INIT|ICW1_ICW4); PIC_WAIT();
	outportb(PIC2_COMMAND, ICW1_INIT|ICW1_ICW4); PIC_WAIT();

	/* Remap */
	outportb(PIC1_DATA, PIC1_OFFSET); PIC_WAIT();
	outportb(PIC2_DATA, PIC2_OFFSET); PIC_WAIT();

	/* Cascade identity with slave PIC at IRQ2 */
	outportb(PIC1_DATA, 0x04); PIC_WAIT();
	outportb(PIC2_DATA, 0x02); PIC_WAIT();

	/* Request 8086 mode on each PIC */
	outportb(PIC1_DATA, 0x01); PIC_WAIT();
	outportb(PIC2_DATA, 0x01); PIC_WAIT();
}

void irq_ack(size_t irq_no) {
	if (irq_no >= 8) {
		outportb(PIC2_COMMAND, PIC_EOI);
	}
	outportb(PIC1_COMMAND, PIC_EOI);
}


/* Programmable interval timer */
#define PIT_A 0x40
#define PIT_B 0x41
#define PIT_C 0x42
#define PIT_CONTROL 0x43

#define PIT_MASK 0xFF
#define PIT_SCALE 1193180
#define PIT_SET 0x34

#define TIMER_IRQ 0

#define RESYNC_TIME 1

static void pit_set_timer_phase(long hz) {
	long divisor = PIT_SCALE / hz;
	outportb(PIT_CONTROL, PIT_SET);
	outportb(PIT_A, divisor & PIT_MASK);
	outportb(PIT_A, (divisor >> 8) & PIT_MASK);
}

void pit_initialize(void) {
	irq_remap();

	/* ELCR? */
	uint8_t val = inportb(0x4D1);
	outportb(0x4D1, val | (1 << (10-8)) | (1 << (11-8)));

	/* Enable PIT */
	pit_set_timer_phase(1000); /* 1000 Hz */

	SYNC_STI();
}
