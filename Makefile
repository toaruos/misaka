include util/util.mk
include build/arch.mk

KERNEL_TARGET=${ARCH}-elf

CC = ${KERNEL_TARGET}-gcc
NM = ${KERNEL_TARGET}-nm
CXX= ${KERNEL_TARGET}-g++
AR = ${KERNEL_TARGET}-ar
AS = ${KERNEL_TARGET}-as
OC = ${KERNEL_TARGET}-objcopy
YA = yasm

KERNEL_CFLAGS  = -ffreestanding -O2 -std=c99 -g
# Arch-specific arguments
KERNEL_CFLAGS += -mcmodel=large -mno-red-zone -fno-omit-frame-pointer
KERNEL_CFLAGS += -mno-mmx -mno-sse -mno-sse2
# Warnings
KERNEL_CFLAGS += -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-format
KERNEL_CFLAGS += -pedantic
# Defined constants for the kernel
KERNEL_CFLAGS += -D_KERNEL_ -DKERNEL_ARCH=${ARCH}
KERNEL_CFLAGS += -DKERNEL_GIT_TAG=`util/make-version`

KERNEL_OBJS =  $(patsubst %.c,%.o,$(wildcard kernel/*.c))
KERNEL_OBJS += $(patsubst %.c,%.o,$(wildcard kernel/*/*.c))
KERNEL_OBJS += $(patsubst %.c,%.o,$(wildcard kernel/${ARCH}/*/*.c))

KERNEL_ASMOBJS  = $(filter-out kernel/symbols.o,$(patsubst %.S,%.o,$(wildcard kernel/arch/${ARCH}/*.S)))
KERNEL_YASMOBJS = $(filter-out kernel/symbols.o,$(patsubst %.s,%.o,$(wildcard kernel/arch/${ARCH}/*.s)))

KERNEL_SOURCES  = $(wildcard kernel/*.c) $(wildcard kernel/*/*.c) $(wildcard kernel/${ARCH}/*/*.c)
KERNEL_SOURCES += $(wildcard kernel/arch/${ARCH}/*.S) $(wildcard kernel/arch/${ARCH}/*.s)

EMU = qemu-system-x86_64
EMU_ARGS  = -kernel misaka-kernel
EMU_ARGS += -m 1024
EMU_ARGS += -smp 4
EMU_ARGS += -vga std
EMU_ARGS += -serial stdio
EMU_ARGS += -k en-us
EMU_ARGS += -no-frame
EMU_ARGS += -rtc base=localtime
EMU_ARGS += -net nic,model=rtl8139 -net user -net dump
EMU_ARGS += -soundhw pcspk,ac97
EMU_ARGS += -no-kvm-irqchip
#EMU_ARGS += -hda toaruos-disk.img
EMU_KVM   = -enable-kvm

.PHONY: all system clean run kvm

all: system
system: misaka-kernel

run: system
	${EMU} ${EMU_ARGS}

kvm: system
	${EMU} ${EMU_ARGS} ${EMU_KVM} -append "cmdline arguments heeeeeeeeeeerererererere" -initrd README.md,Makefile

# TODO: build/symbols.o as a replacement for toaru kernel/symbols.o
#       (symbol table generator needs x86_64 support)
misaka-kernel: ${KERNEL_ASMOBJS} ${KERNEL_YASMOBJS} ${KERNEL_OBJS} kernel/symbols.o
	@${BEG} "CC" "$@"
	@${CC} -T kernel/arch/${ARCH}/link.ld ${KERNEL_CFLAGS} -z max-page-size=0x1000 -nostdlib -o $@.64 ${KERNEL_ASMOBJS} ${KERNEL_YASMOBJS} ${KERNEL_OBJS} kernel/symbols.o -lgcc ${ERRORS}
	@${OC} -I elf64-x86-64 -O elf32-i386 $@.64 $@
	@${KERNEL_TARGET}-strip $@
	@${END} "CC" "$@"
	@${INFO} "--" "Kernel is ready!"

kernel/sys/version.o: ${KERNEL_SOURCES}

kernel/symbols.o: ${KERNEL_ASMOBJS} ${KERNEL_YASMOBJS} ${KERNEL_OBJS} util/generate_symbols.py
	@-rm -f kernel/symbols.o
	@${BEG} "NM" "Generating symbol list..."
	@${CC} -T kernel/arch/${ARCH}/link.ld ${KERNEL_CFLAGS} -z max-page-size=0x1000 -nostdlib -o misaka-kernel.64 ${KERNEL_ASMOBJS} ${KERNEL_YASMOBJS} ${KERNEL_OBJS} -lgcc ${ERRORS}
	@${NM} misaka-kernel.64 -g | python2 util/generate_symbols.py > kernel/symbols.S
	@${END} "NM" "Generated symbol list."
	@${BEG} "AS" "kernel/symbols.S"
	@${AS} kernel/symbols.S -o $@ ${ERRORS}
	@${END} "AS" "kernel/symbols.S"

kernel/%.o: kernel/%.S
	@${BEG} "AS" "$<"
	@${AS} $< -o $@ ${ERRORS}
	@${END} "AS" "$<"

kernel/%.o: kernel/%.s
	@${BEG} "AS" "$<"
	@${YA} -f elf64 -w $< -o $@ ${ERRORS}
	@${END} "AS" "$<"

kernel/%.o: kernel/%.c ${HEADERS}
	@${BEG} "CC" "$<"
	@${CC} ${KERNEL_CFLAGS} -nostdlib -g -I./kernel/include -c -o $@ $< ${ERRORS}
	@${END} "CC" "$<"

clean:
	@${BEGRM} "RM" "Cleaning kernel objects..."
	@-rm -f ${KERNEL_ASMOBJS}
	@-rm -f ${KERNEL_YASMOBJS}
	@-rm -f ${KERNEL_OBJS}
	@-rm -f kernel/symbols.o
	@-rm -f misaka-kernel
	@-rm -f misaka-kernel.64
	@${ENDRM} "RM" "Cleaned kernel objects"
