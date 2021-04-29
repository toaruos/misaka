#include <kernel/types.h>
#include <kernel/string.h>
#include <kernel/printf.h>
#include <kernel/arch/x86_64/pml.h>
#include <kernel/arch/x86_64/regs.h>
#include <kernel/vfs.h>

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

#include <syscall_nums.h>
static const char * syscallNames[] = {
#define _(o) [o] = #o,
_(SYS_EXT)
_(SYS_GETEUID)
_(SYS_OPEN)
_(SYS_READ)
_(SYS_WRITE)
_(SYS_CLOSE)
_(SYS_GETTIMEOFDAY)
_(SYS_EXECVE)
_(SYS_FORK)
_(SYS_GETPID)
_(SYS_SBRK)
_(SYS_UNAME)
_(SYS_OPENPTY)
_(SYS_SEEK)
_(SYS_STAT)
_(SYS_MKPIPE)
_(SYS_DUP2)
_(SYS_GETUID)
_(SYS_SETUID)
_(SYS_REBOOT)
_(SYS_READDIR)
_(SYS_CHDIR)
_(SYS_GETCWD)
_(SYS_CLONE)
_(SYS_SETHOSTNAME)
_(SYS_GETHOSTNAME)
_(SYS_MKDIR)
_(SYS_SHM_OBTAIN)
_(SYS_SHM_RELEASE)
_(SYS_KILL)
_(SYS_SIGNAL)
_(SYS_GETTID)
_(SYS_YIELD)
_(SYS_SYSFUNC)
_(SYS_SLEEPABS)
_(SYS_SLEEP)
_(SYS_IOCTL)
_(SYS_ACCESS)
_(SYS_STATF)
_(SYS_CHMOD)
_(SYS_UMASK)
_(SYS_UNLINK)
_(SYS_WAITPID)
_(SYS_PIPE)
_(SYS_MOUNT)
_(SYS_SYMLINK)
_(SYS_READLINK)
_(SYS_LSTAT)
_(SYS_FSWAIT)
_(SYS_FSWAIT2)
_(SYS_CHOWN)
_(SYS_SETSID)
_(SYS_SETPGID)
_(SYS_GETPGID)
_(SYS_FSWAIT3)
};

static uintptr_t sbrk_address = 0x20000000;

static int stat_node(fs_node_t * fn, uintptr_t st) {
	struct stat * f = (struct stat *)st;

	//PTR_VALIDATE(f);

	if (!fn) {
		memset(f, 0x00, sizeof(struct stat));
		printf("nope\n");
		return -1; //-ENOENT;
	}
	f->st_dev   = (uint16_t)(((uint64_t)fn->device & 0xFFFF0) >> 8);
	f->st_ino   = fn->inode;

	uint32_t flags = 0;
	if (fn->flags & FS_FILE)        { flags |= _IFREG; }
	if (fn->flags & FS_DIRECTORY)   { flags |= _IFDIR; }
	if (fn->flags & FS_CHARDEVICE)  { flags |= _IFCHR; }
	if (fn->flags & FS_BLOCKDEVICE) { flags |= _IFBLK; }
	if (fn->flags & FS_PIPE)        { flags |= _IFIFO; }
	if (fn->flags & FS_SYMLINK)     { flags |= _IFLNK; }

	f->st_mode  = fn->mask | flags;
	f->st_nlink = fn->nlink;
	f->st_uid   = fn->uid;
	f->st_gid   = fn->gid;
	f->st_rdev  = 0;
	f->st_size  = fn->length;

	f->st_atime = fn->atime;
	f->st_mtime = fn->mtime;
	f->st_ctime = fn->ctime;
	f->st_blksize = 512; /* whatever */

	if (fn->get_size) {
		f->st_size = fn->get_size(fn);
	}

	return 0;
}

static int __fd = 3;
static fs_node_t * __fd_nodes[10] = {NULL};
static size_t __fd_offsets[10] = {0};

struct regs * isr_handler(struct regs * r) {
	/* XXX for demo purposes */
	if (r->int_no == 14) {
		printf("Page fault\n");
		uintptr_t faulting_address;
		asm volatile("mov %%cr2, %0" : "=r"(faulting_address));
		printf("cr2: 0x%016lx\n", faulting_address);
		dump_regs(r);
		printf("Stack is at ~%p\n", r);
		printf("(halting)\n");
		while (1) {};
	} else if (r->int_no == 13) {
		/* GPF */
		printf("General Protection Fault\n");
		dump_regs(r);
		while (1) {};
	} else if (r->int_no == 8) {
		printf("Double fault?\n");
		uintptr_t faulting_address;
		asm volatile("mov %%cr2, %0" : "=r"(faulting_address));
		printf("cr2: 0x%016lx\n", faulting_address);
		dump_regs(r);
	} else if (r->int_no == 6) {
		printf("Invalid opcode\n");
		dump_regs(r);
		while (1) {};
	} else if (r->int_no == 127) {
		if (r->rax > SYS_FSWAIT) {
			printf("Invalid system call: %lu\n", r->rax);
			r->rax = (size_t)-1;
			return r;
		}

		switch (r->rax) {
			case SYS_SYSFUNC:
				{
					char ** args = (char**)r->rcx;
					switch (r->rbx) {
						case 0x0E:
							printf("Set TLS/fsbase to %p\n", args[0]);
							break;
						default:
							printf("unsupported sysfunc called (%lu)\n", r->rbx);
							break;
					}
					r->rax = (size_t)-1;
				}
				break;
			case SYS_SBRK:
				r->rax = sbrk_address;
				sbrk_address += r->rbx;
				break;
			case SYS_EXT:
				printf("(halting)\n");
				while (1) {};
				break;
			case SYS_WRITE:
				if (r->rbx == 1 || r->rbx == 2) {
					printf("%.*s", (int)r->rdx, (char*)r->rcx);
				} else {
					printf("invalid write (fd=%ld)\n", r->rbx);
				}
				r->rax = r->rdx;
				break;
			case SYS_STATF: {
				fs_node_t * fn = kopen((char*)r->rbx, 0);
				int result = stat_node(fn, r->rcx);
				r->rax = result;
				break;
			}
			case SYS_OPEN: {
				fs_node_t * node = kopen((char*)r->rbx, (int)r->rcx);
				if (!node) {
					r->rax = -1;
					break;
				}
				int fd = __fd++;
				__fd_nodes[fd] = node;
				__fd_offsets[fd] = 0;
				r->rax = fd;
				printf("Completed open for '%s' as fd=%d\n", (char*)r->rbx, fd);
				break;
			}
			case SYS_SEEK: {
				int fd = r->rbx;
				if (fd < 3) {
					r->rax = -1;
					break;
				}
				int offset = r->rcx;
				int whence = r->rdx;

				if (whence == 0) {
					__fd_offsets[fd] = offset;
				} else if (whence == 1) {
					__fd_offsets[fd] += offset;
				} else if (whence == 2) {
					__fd_offsets[fd] = __fd_nodes[fd]->length + offset;
				}
				r->rax = __fd_offsets[fd];
				break;
			}
			case SYS_READ: {
				int fd = r->rbx;
				if (fd < 3 || !__fd_nodes[fd]) {
					r->rax = -1;
					break;
				}
				r->rax = read_fs(__fd_nodes[fd], __fd_offsets[fd], r->rdx, (uint8_t*)r->rcx);
				__fd_offsets[fd] += r->rax;
				break;
			}
			default:
				printf("Unsupported system call (%s)\n", syscallNames[r->rax]);
				r->rax = (size_t)-1;
				break;
		}
	} else {
		printf("Unhandled interrupt: %ld\n", r->int_no);
		dump_regs(r);
	}

	return r;
}

