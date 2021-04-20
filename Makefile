TOOLCHAIN=../x86_64-toaru
BASE=$(TOOLCHAIN)/base
export PATH := $(shell $(TOOLCHAIN)/activate.sh)
include util/util.mk
include build/arch.mk

KERNEL_TARGET=x86_64-pc-toaru
#${ARCH}-elf

CC = ${KERNEL_TARGET}-gcc
NM = ${KERNEL_TARGET}-nm
CXX= ${KERNEL_TARGET}-g++
AR = ${KERNEL_TARGET}-ar
AS = ${KERNEL_TARGET}-as
OC = ${KERNEL_TARGET}-objcopy

KERNEL_CFLAGS  = -ffreestanding -O2 -std=c11 -g -static

# Arch-specific arguments
KERNEL_CFLAGS += -mcmodel=large -mno-red-zone -fno-omit-frame-pointer
KERNEL_CFLAGS += -mno-mmx -mno-sse -mno-sse2

# Warnings
KERNEL_CFLAGS += -Wall -Wextra -Wno-unused-function -Wno-unused-parameter
KERNEL_CFLAGS += -pedantic -Wwrite-strings

# Defined constants for the kernel
KERNEL_CFLAGS += -D_KERNEL_ -DKERNEL_ARCH=${ARCH}
KERNEL_CFLAGS += -DKERNEL_GIT_TAG=`util/make-version`

KERNEL_OBJS =  $(patsubst %.c,%.o,$(wildcard kernel/*.c))
KERNEL_OBJS += $(patsubst %.c,%.o,$(wildcard kernel/*/*.c))
KERNEL_OBJS += $(patsubst %.c,%.o,$(wildcard kernel/arch/${ARCH}/*.c))

KERNEL_ASMOBJS  = $(filter-out kernel/symbols.o,$(patsubst %.S,%.o,$(wildcard kernel/arch/${ARCH}/*.S)))

KERNEL_SOURCES  = $(wildcard kernel/*.c) $(wildcard kernel/*/*.c) $(wildcard kernel/${ARCH}/*/*.c)
KERNEL_SOURCES += $(wildcard kernel/arch/${ARCH}/*.S)

EMU = qemu-system-x86_64
EMU_ARGS  = -kernel misaka-kernel
EMU_ARGS += -m 1G
EMU_ARGS += -smp 4
EMU_ARGS += -no-reboot
EMU_ARGS += -display none
EMU_ARGS += -serial mon:stdio
EMU_ARGS += -rtc base=localtime
EMU_ARGS += -soundhw pcspk,ac97
#EMU_ARGS += -hda toaruos-disk.img
EMU_KVM   = -enable-kvm

.PHONY: all system clean run

all: system
system: misaka-kernel

run: system
	${EMU} ${EMU_ARGS} ${EMU_KVM} -append "cmdline arguments heeeeeeeeeeerererererere" -initrd README.md,Makefile

misaka-kernel: ${KERNEL_ASMOBJS} ${KERNEL_OBJS} kernel/symbols.o
	${CC} -T kernel/arch/${ARCH}/link.ld ${KERNEL_CFLAGS} -z max-page-size=0x1000 -nostdlib -o $@.64 ${KERNEL_ASMOBJS} ${KERNEL_OBJS} kernel/symbols.o -lgcc
	${OC} -I elf64-x86-64 -O elf32-i386 $@.64 $@

kernel/sys/version.o: ${KERNEL_SOURCES}

kernel/symbols.o: ${KERNEL_ASMOBJS} ${KERNEL_OBJS} util/generate_symbols.py
	-rm -f kernel/symbols.o
	${CC} -T kernel/arch/${ARCH}/link.ld ${KERNEL_CFLAGS} -z max-page-size=0x1000 -nostdlib -o misaka-kernel.64 ${KERNEL_ASMOBJS} ${KERNEL_OBJS} -lgcc
	${NM} misaka-kernel.64 -g | python2 util/generate_symbols.py > kernel/symbols.S
	${CC} -c kernel/symbols.S -o $@

kernel/%.o: kernel/%.S
	echo ${PATH}
	${CC} -c $< -o $@

kernel/%.o: kernel/%.c ${HEADERS}
	${CC} ${KERNEL_CFLAGS} -nostdlib -g -Iinclude -c -o $@ $<

clean:
	-rm -f ${KERNEL_ASMOBJS}
	-rm -f ${KERNEL_OBJS}
	-rm -f kernel/symbols.o
	-rm -f misaka-kernel
	-rm -f misaka-kernel.64

LIBC_OBJS  = $(patsubst %.c,%.o,$(wildcard libc/*.c))
LIBC_OBJS += $(patsubst %.c,%.o,$(wildcard libc/*/*.c))

libc/%.o: libc/%.c
	$(CC) -fPIC -c -o $@ $<

libc.a: ${LIBC_OBJS} | crts
	$(AR) cr $@ $^

libc.so: ${LIBC_OBJS} | crts
	${CC} -nodefaultlibs -shared -fPIC -o $@ $^ -lgcc

apps/test: apps/test.c
	${CC} -o $@ $<

crts: $(BASE)/lib/crt0.o $(BASE)/lib/crti.o $(BASE)/lib/crtn.o

$(BASE)/lib/crt%.o: libc/crt%.S
	${AS} -o $@ $<

