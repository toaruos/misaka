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
KERNEL_CFLAGS += -mcmodel=large -mno-red-zone
KERNEL_CFLAGS += -mno-mmx -mno-sse -mno-sse2
KERNEL_CFLAGS += -Wall -Wextra -Wno-unused-function -Wno-unused-parameter -Wno-format
KERNEL_CFLAGS += -pedantic -fno-omit-frame-pointer
KERNEL_CFLAGS += -D_KERNEL_ -DKERNEL_ARCH=${ARCH}
KERNEL_CFLAGS += -DKERNEL_GIT_TAG=`util/make-version`

KERNEL_OBJS =  $(patsubst %.c,%.o,$(wildcard kernel/*.c))
KERNEL_OBJS += $(patsubst %.c,%.o,$(wildcard kernel/*/*.c))
KERNEL_OBJS += $(patsubst %.c,%.o,$(wildcard kernel/${ARCH}/*/*.c))

KERNEL_ASMOBJS = $(filter-out kernel/symbols.o,$(patsubst %.S,%.o,$(wildcard kernel/arch/${ARCH}/*.S)))
KERNEL_YASMOBJS = $(filter-out kernel/symbols.o,$(patsubst %.s,%.o,$(wildcard kernel/arch/${ARCH}/*.s)))

KERNEL_SOURCES  = $(wildcard kernel/*.c) $(wildcard kernel/*/*.c) $(wildcard kernel/${ARCH}/*/*.c)
KERNEL_SOURCES += $(wildcard kernel/arch/${ARCH}/*.S) $(wildcard kernel/arch/${ARCH}/*.s)

.PHONY: all system

all: system
system: misaka-kernel

# TODO: build/symbols.o as a replacement for toaru kernel/symbols.o
#       (symbol table generator needs x86_64 support)
misaka-kernel: ${KERNEL_ASMOBJS} ${KERNEL_YASMOBJS} ${KERNEL_OBJS}
	@${BEG} "CC" "$@"
	@${CC} -T kernel/arch/${ARCH}/link.ld ${KERNEL_CFLAGS} -z max-page-size=0x1000 -nostdlib -o $@.64 ${KERNEL_ASMOBJS} ${KERNEL_YASMOBJS} ${KERNEL_OBJS} -lgcc ${ERRORS}
	@${OC} -I elf64-x86-64 -O elf32-i386 $@.64 $@
	@${END} "CC" "$@"
	@${INFO} "--" "Kernel is ready!"

kernel/sys/version.o: ${KERNEL_SOURCES}

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

