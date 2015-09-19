/*
    This is primarily adapted from Toaru's 32-bit mulitboot bootstrap.
    Instead of jumping straight to our C entry point, however, we need
    to (obviously) get ourselves set up for long mode first by setting
    up initial page tables, etc.

    We use a multiboot "1.0" header and build the whole kernel into an
    elf32 binary so that we can safely load with qemu's -kernel mode.
*/
.section .multiboot
.code32
.align 4

.set MB_MAGIC,              0x1BADB002
.set MB_FLAG_PAGE_ALIGN,    1 << 0
.set MB_FLAG_MEMORY_INFO,   1 << 1
.set MB_FLAG_GRAPHICS,      1 << 2
.set MB_FLAGS,              MB_FLAG_PAGE_ALIGN | MB_FLAG_MEMORY_INFO | MB_FLAG_GRAPHICS
.set MB_CHECKSUM,           -(MB_MAGIC + MB_FLAGS)

.extern bss_start
.extern end

/* Multiboot section */
.long MB_MAGIC
.long MB_FLAGS
.long MB_CHECKSUM
.long 0x00100000 /* header_addr */
.long 0x00100000 /* load_addr */
.long bss_start /* load_end_addr */
.long end /* bss_end_addr */
.long start /* entry_addr */

/* Request linear graphics mode */
.long 0x00000000
.long 1024
.long 768
.long 32

/* .stack resides in .bss */
.section .stack, "aw", @nobits
stack_bottom:
.skip 16384 /* 16KiB */
stack_top:

.section .bootstrap
.code32
.align 4

.extern jmp_to_long
.type jmp_to_long, @function

.extern kmain
.type kmain, @function

.global start
.type start, @function

start:
    /* Setup our stack */
    mov $stack_top, %esp

    /* Make sure our stack is 16-byte aligned */
    and $-16, %esp

    pushl $0
    pushl %esp
    pushl $0
    pushl %eax /* Multiboot header magic */
    pushl $0
    pushl %ebx /* Multiboot header pointer */

    jmp jmp_to_long


