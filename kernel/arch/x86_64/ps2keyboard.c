#include <kernel/vfs.h>
#include <kernel/pipe.h>

#include <kernel/arch/x86_64/irq.h>
#include <kernel/arch/x86_64/ports.h>

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
	irq_install_handler(1, keyboard_handler, "ps2kbd");
}

