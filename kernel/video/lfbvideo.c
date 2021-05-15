#include <errno.h>
#include <kernel/types.h>
#include <kernel/vfs.h>
#include <kernel/printf.h>
#include <kernel/pci.h>
#include <kernel/video.h>
#include <kernel/process.h>
#include <kernel/string.h>
#include <kernel/signal.h>
#include <kernel/tokenize.h>
#include <kernel/multiboot.h>
#include <kernel/procfs.h>
#include <kernel/mmu.h>

/* FIXME: Not sure what to do with this; ifdef around it? */
#include <kernel/arch/x86_64/ports.h>

#define PREFERRED_W  1024
#define PREFERRED_H  768
#define PREFERRED_VY 4096
#define PREFERRED_B 32

/* Exported to other modules */
uint16_t lfb_resolution_x = 0;
uint16_t lfb_resolution_y = 0;
uint16_t lfb_resolution_b = 0;
uint32_t lfb_resolution_s = 0;
uint8_t * lfb_vid_memory = (uint8_t *)0xE0000000;
size_t lfb_memsize = 0xFF0000;
const char * lfb_driver_name = NULL;

fs_node_t * lfb_device = NULL;
static int lfb_init(const char * c);

/* Where to send display size change signals */
static pid_t display_change_recipient = 0;

/* Driver-specific modesetting function */
static void (*lfb_resolution_impl)(uint16_t,uint16_t) = NULL;

/* Called by ioctl on /dev/fb0 */
void lfb_set_resolution(uint16_t x, uint16_t y) {
	if (lfb_resolution_impl) {
		lfb_resolution_impl(x,y);
		if (display_change_recipient) {
			send_signal(display_change_recipient, SIGWINEVENT, 1);
		}
	}
}

extern void ptr_validate(void * ptr, const char * syscall);
#define validate(o) ptr_validate(o,"ioctl")

/**
 * Framebuffer control ioctls.
 * Used by the compositor to get display sizes and by the
 * resolution changer to initiate modesetting.
 */
static int ioctl_vid(fs_node_t * node, int request, void * argp) {
	switch (request) {
		case IO_VID_WIDTH:
			/* Get framebuffer width */
			validate(argp);
			*((size_t *)argp) = lfb_resolution_x;
			return 0;
		case IO_VID_HEIGHT:
			/* Get framebuffer height */
			validate(argp);
			*((size_t *)argp) = lfb_resolution_y;
			return 0;
		case IO_VID_DEPTH:
			/* Get framebuffer bit depth */
			validate(argp);
			*((size_t *)argp) = lfb_resolution_b;
			return 0;
		case IO_VID_STRIDE:
			/* Get framebuffer scanline stride */
			validate(argp);
			*((size_t *)argp) = lfb_resolution_s;
			return 0;
		case IO_VID_ADDR:
			/* Get framebuffer address - TODO: map the framebuffer? */
			validate(argp);
			{
				uintptr_t lfb_user_offset;
				if (*(uintptr_t*)argp == 0) {
					/* Pick an address and map it */
					lfb_user_offset = 0x100000000; /* at 4GiB seems good */
				} else {
					validate((void*)(*(uintptr_t*)argp));
					lfb_user_offset = *(uintptr_t*)argp;
				}
				for (uintptr_t i = 0; i < lfb_memsize; i += 0x1000) {
					union PML * page = mmu_get_page(lfb_user_offset + i, MMU_GET_MAKE);
					mmu_frame_map_address(page,MMU_FLAG_WRITABLE,((uintptr_t)(lfb_vid_memory) & 0xFFFFFFFF) + i);
				}
				*((uintptr_t *)argp) = lfb_user_offset;
			}
			return 0;
		case IO_VID_SIGNAL:
			/* ioctl to register for a signal (vid device change? idk) on display change */
			display_change_recipient = current_process->id;
			return 0;
		case IO_VID_SET:
			/* Initiate mode setting */
			validate(argp);
			lfb_set_resolution(((struct vid_size *)argp)->width, ((struct vid_size *)argp)->height);
			return 0;
		case IO_VID_DRIVER:
			validate(argp);
			memcpy(argp, lfb_driver_name, strlen(lfb_driver_name));
			return 0;
		case IO_VID_REINIT:
			if (current_process->user != 0) {
				return -EPERM;
			}
			validate(argp);
			return lfb_init(argp);
		default:
			return -EINVAL;
	}
	return -EINVAL;
}

/* Framebuffer device file initializer */
static fs_node_t * lfb_video_device_create(void /* TODO */) {
	fs_node_t * fnode = malloc(sizeof(fs_node_t));
	memset(fnode, 0x00, sizeof(fs_node_t));
	snprintf(fnode->name, 100, "fb0"); /* TODO */
	fnode->length  = 0;
	fnode->flags   = FS_BLOCKDEVICE; /* Framebuffers are block devices */
	fnode->mask    = 0660; /* Only accessible to root user/group */
	fnode->ioctl   = ioctl_vid; /* control function defined above */
	return fnode;
}

static uint64_t framebuffer_func(fs_node_t * node, uint64_t offset, uint64_t size, uint8_t * buffer) {
	char * buf = malloc(4096);

	if (lfb_driver_name) {
		snprintf(buf, 4095,
			"Driver:\t%s\n"
			"XRes:\t%d\n"
			"YRes:\t%d\n"
			"BitsPerPixel:\t%d\n"
			"Stride:\t%d\n"
			"Address:\t%p\n",
			lfb_driver_name,
			lfb_resolution_x,
			lfb_resolution_y,
			lfb_resolution_b,
			lfb_resolution_s,
			lfb_vid_memory);
	} else {
		snprintf(buf, 20, "Driver:\tnone\n");
	}

	size_t _bsize = strlen(buf);
	if (offset > _bsize) {
		free(buf);
		return 0;
	}
	if (size > _bsize - offset) size = _bsize - offset;

	memcpy(buffer, buf + offset, size);
	free(buf);
	return size;
}

static struct procfs_entry framebuffer_entry = {
	0,
	"framebuffer",
	framebuffer_func,
};

/* Install framebuffer device */
static void finalize_graphics(const char * driver) {
	lfb_driver_name = driver;
	lfb_device->length  = lfb_resolution_s * lfb_resolution_y; /* Size is framebuffer size in bytes */
#if 0
	debug_video_crash = lfb_video_panic;
#endif

	procfs_install(&framebuffer_entry);
}

/* Bochs support {{{ */
static void bochs_scan_pci(uint32_t device, uint16_t v, uint16_t d, void * extra) {
	if ((v == 0x1234 && d == 0x1111) ||
	    (v == 0x80EE && d == 0xBEEF) ||
	    (v == 0x10de && d == 0x0a20))  {
		uintptr_t t = pci_read_field(device, PCI_BAR0, 4);
		if (t > 0) {
			*((uint8_t **)extra) = (uint8_t *)((uintptr_t)(t & 0xFFFFFFF0) | 0xFFFFFFFF00000000);
		}
	}
}

static void bochs_set_resolution(uint16_t x, uint16_t y) {
	outports(0x1CE, 0x04);
	outports(0x1CF, 0x00);
	/* Uh oh, here we go. */
	outports(0x1CE, 0x01);
	outports(0x1CF, x);
	/* Set Y resolution to 768 */
	outports(0x1CE, 0x02);
	outports(0x1CF, y);
	/* Set bpp to 32 */
	outports(0x1CE, 0x03);
	outports(0x1CF, PREFERRED_B);
	/* Set Virtual Height to stuff */
	outports(0x1CE, 0x07);
	outports(0x1CF, PREFERRED_VY);
	/* Turn it back on */
	outports(0x1CE, 0x04);
	outports(0x1CF, 0x41);

	/* Read X to see if it's something else */
	outports(0x1CE, 0x01);
	uint16_t new_x = inports(0x1CF);
	if (x != new_x) {
		x = new_x;
	}

	lfb_resolution_x = x;
	lfb_resolution_s = x * 4;
	lfb_resolution_y = y;
	lfb_resolution_b = 32;
}

static void graphics_install_bochs(uint16_t resolution_x, uint16_t resolution_y) {

	outports(0x1CE, 0x00);
	uint16_t i = inports(0x1CF);
	if (i < 0xB0C0 || i > 0xB0C6) {
		return;
	}
	outports(0x1CF, 0xB0C4);
	i = inports(0x1CF);
	bochs_set_resolution(resolution_x, resolution_y);
	resolution_x = lfb_resolution_x; /* may have changed */

	pci_scan(bochs_scan_pci, -1, &lfb_vid_memory);

	lfb_resolution_impl = &bochs_set_resolution;

	if (!lfb_vid_memory) {
		printf("failed to locate video memory\n");
		return;
	}

	/* Enable the higher memory */
#if 0
	uintptr_t fb_offset = (uintptr_t)lfb_vid_memory;
	for (uintptr_t i = fb_offset; i <= fb_offset + 0xFF0000; i += 0x1000) {
		page_t * p = get_page(i, 1, kernel_directory);
		dma_frame(p, 0, 1, i);
		p->pat = 1;
		p->writethrough = 1;
		p->cachedisable = 1;
	}
#endif

	outports(0x1CE, 0x0a);
	i = inports(0x1CF);
	if (i > 1) {
		lfb_memsize = (uint32_t)i * 64 * 1024;
	} else {
		lfb_memsize = inportl(0x1CF);
	}
#if 0
	for (uintptr_t i = (uintptr_t)lfb_vid_memory; i <= (uintptr_t)lfb_vid_memory + lfb_memsize; i += 0x1000) {
		dma_frame(get_page(i, 1, kernel_directory), 0, 1, i);
	}
#endif

	finalize_graphics("bochs");
}

struct multiboot * mboot_ptr = NULL;

static void graphics_install_preset(uint16_t w, uint16_t h) {
	/* Extract framebuffer information from multiboot */
	lfb_vid_memory = (void *)((uintptr_t)mboot_ptr->framebuffer_addr | 0xFFFFFFFF00000000);
	lfb_resolution_x = mboot_ptr->framebuffer_width;
	lfb_resolution_y = mboot_ptr->framebuffer_height;
	lfb_resolution_s = mboot_ptr->framebuffer_pitch;
	lfb_resolution_b = 32;

	//debug_print(WARNING, "Mode was set by bootloader: %dx%d bpp should be 32, framebuffer is at 0x%x", w, h, (uintptr_t)lfb_vid_memory);

	#if 0
	for (uintptr_t i = (uintptr_t)lfb_vid_memory; i <= (uintptr_t)lfb_vid_memory + w * h * 4; i += 0x1000) {
		page_t * p = get_page(i, 1, kernel_directory);
		dma_frame(p, 0, 1, i);
		p->pat = 1;
		p->writethrough = 1;
		p->cachedisable = 1;
	}
	#endif
	finalize_graphics("preset");
}

#if 0
static void graphics_install_kludge(uint16_t w, uint16_t h) {
	uint32_t * herp = (uint32_t *)0xA0000;
	herp[0] = 0xA5ADFACE;
	herp[1] = 0xFAF42943;

	for (int i = 2; i < 1000; i += 2) {
		herp[i]   = 0xFF00FF00;
		herp[i+1] = 0x00FF00FF;
	}

	for (uintptr_t fb_offset = 0xE0000000; fb_offset < 0xFF000000; fb_offset += 0x01000000) {
		/* Enable the higher memory */
		for (uintptr_t i = fb_offset; i <= fb_offset + 0xFF0000; i += 0x1000) {
			dma_frame(get_page(i, 1, kernel_directory), 0, 1, i);
		}

		/* Go find it */
		for (uintptr_t x = fb_offset; x < fb_offset + 0xFF0000; x += 0x1000) {
			if (((uintptr_t *)x)[0] == 0xA5ADFACE && ((uintptr_t *)x)[1] == 0xFAF42943) {
				lfb_vid_memory = (uint8_t *)x;
				debug_print(INFO, "Had to futz around, but found video memory at 0x%x", lfb_vid_memory);
				goto mem_found;
			}
		}
	}
mem_found:
	lfb_resolution_x = w;
	lfb_resolution_y = h;
	lfb_resolution_s = w * 4;
	lfb_resolution_b = 32;

	for (uintptr_t i = (uintptr_t)lfb_vid_memory; i <= (uintptr_t)lfb_vid_memory + w * h * 4; i += 0x1000) {
		page_t * p = get_page(i, 1, kernel_directory);
		dma_frame(p, 0, 1, i);
		p->pat = 1;
		p->writethrough = 1;
		p->cachedisable = 1;
	}
	finalize_graphics("kludge");
}
#endif

#define SVGA_IO_BASE (vmware_io)
#define SVGA_IO_MUL 1
#define SVGA_INDEX_PORT 0
#define SVGA_VALUE_PORT 1

#define SVGA_REG_ID 0
#define SVGA_REG_ENABLE 1
#define SVGA_REG_WIDTH 2
#define SVGA_REG_HEIGHT 3
#define SVGA_REG_BITS_PER_PIXEL 7
#define SVGA_REG_BYTES_PER_LINE 12
#define SVGA_REG_FB_START 13

static uint32_t vmware_io = 0;

static void vmware_scan_pci(uint32_t device, uint16_t v, uint16_t d, void * extra) {
	if ((v == 0x15ad && d == 0x0405)) {
		uintptr_t t = pci_read_field(device, PCI_BAR0, 4);
		if (t > 0) {
			*((uint8_t **)extra) = (uint8_t *)(t & 0xFFFFFFF0);
		}
	}
}

static void vmware_write(int reg, int value) {
	outportl(SVGA_IO_MUL * SVGA_INDEX_PORT + SVGA_IO_BASE, reg);
	outportl(SVGA_IO_MUL * SVGA_VALUE_PORT + SVGA_IO_BASE, value);
}

static uint32_t vmware_read(int reg) {
	outportl(SVGA_IO_MUL * SVGA_INDEX_PORT + SVGA_IO_BASE, reg);
	return inportl(SVGA_IO_MUL * SVGA_VALUE_PORT + SVGA_IO_BASE);
}

static void vmware_set_resolution(uint16_t w, uint16_t h) {
	vmware_write(SVGA_REG_ENABLE, 0);
	vmware_write(SVGA_REG_ID, 0);
	vmware_write(SVGA_REG_WIDTH, w);
	vmware_write(SVGA_REG_HEIGHT, h);
	vmware_write(SVGA_REG_BITS_PER_PIXEL, 32);
	vmware_write(SVGA_REG_ENABLE, 1);

	uint32_t bpl = vmware_read(SVGA_REG_BYTES_PER_LINE);

	lfb_resolution_x = w;
	lfb_resolution_s = bpl;
	lfb_resolution_y = h;
	lfb_resolution_b = 32;
}

static void graphics_install_vmware(uint16_t w, uint16_t h) {
	pci_scan(vmware_scan_pci, -1, &vmware_io);

	if (!vmware_io) {
		printf("vmware video, but no device found?\n");
		return;
	} else {
		printf("vmware io base: %p\n", (void*)(uintptr_t)vmware_io);
	}

	vmware_set_resolution(w,h);
	lfb_resolution_impl = &vmware_set_resolution;

	uintptr_t fb_addr = vmware_read(SVGA_REG_FB_START);
	printf("vmware fb address: %p\n", (void*)fb_addr);

	size_t fb_size = vmware_read(15);

	printf("vmware fb size: 0x%lx\n", fb_size);

	lfb_vid_memory = (uint8_t *)((uintptr_t)fb_addr | 0xFFFFFFFF00000000);

	uintptr_t fb_offset = (uintptr_t)lfb_vid_memory;
	for (uintptr_t i = fb_offset; i <= fb_offset + fb_size; i += 0x1000) {
		#if 0
		page_t * p = get_page(i, 1, kernel_directory);
		dma_frame(p, 0, 1, i);
		p->pat = 1;
		p->writethrough = 1;
		p->cachedisable = 1;
		#endif
	}

	finalize_graphics("vmware");
}

struct disp_mode {
	int16_t x;
	int16_t y;
	int set;
};

static void auto_scan_pci(uint32_t device, uint16_t v, uint16_t d, void * extra) {
	struct disp_mode * mode = extra;
	if (mode->set) return;
	if ((v == 0x1234 && d == 0x1111) ||
	    (v == 0x80EE && d == 0xBEEF) ||
	    (v == 0x10de && d == 0x0a20))  {
		mode->set = 1;
		graphics_install_bochs(mode->x, mode->y);
	} else if ((v == 0x15ad && d == 0x0405)) {
		mode->set = 1;
		graphics_install_vmware(mode->x, mode->y);
	}
}

static int lfb_init(const char * c) {
	char * arg = strdup(c);
	char * argv[10];
	int argc = tokenize(arg, ",", argv);

	uint16_t x, y;
	if (argc < 3) {
		x = PREFERRED_W;
		y = PREFERRED_H;
	} else {
		x = atoi(argv[1]);
		y = atoi(argv[2]);
	}

	int ret_val = 0;
	if (!strcmp(argv[0], "auto")) {
		/* Attempt autodetection */
		struct disp_mode mode = {x,y,0};
		pci_scan(auto_scan_pci, -1, &mode);
		if (!mode.set) {
			graphics_install_preset(x,y);
		}
	} else if (!strcmp(argv[0], "qemu")) {
		/* Bochs / Qemu Video Device */
		graphics_install_bochs(x,y);
	} else if (!strcmp(argv[0],"vmware")) {
		/* VMware SVGA */
		graphics_install_vmware(x,y);
#if 0
	} else if (!strcmp(argv[0],"preset")) {
		/* Set by bootloader (UEFI) */
		graphics_install_preset(x,y);
	} else if (!strcmp(argv[0],"kludge")) {
		/* Old hack to find vid memory from the VGA window */
		graphics_install_kludge(x,y);
#endif
	} else {
		ret_val = 1;
	}

	free(arg);
	return ret_val;
}

int framebuffer_initialize(void) {
	lfb_device = lfb_video_device_create();
	lfb_init("auto,1440,900");
	vfs_mount("/dev/fb0", lfb_device);

#if 0
	char * c;
	if ((c = args_value("vid"))) {
		debug_print(NOTICE, "Video mode requested: %s", c);
		lfb_init(c);
	}
#endif

	return 0;
}

