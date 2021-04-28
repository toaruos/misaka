TOOLCHAIN=util
BASE=base
export PATH := $(shell $(TOOLCHAIN)/activate.sh)
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
KERNEL_CFLAGS += -mno-mmx -mno-sse -mno-sse2  -z max-page-size=0x1000 -nostdlib

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

MODULES = $(patsubst %.c,%.ko,$(wildcard modules/*.c))

EMU = qemu-system-x86_64
EMU_ARGS  = -kernel misaka-kernel
EMU_ARGS += -m 3G
EMU_ARGS += -smp 4
EMU_ARGS += -no-reboot
#EMU_ARGS += -display none
EMU_ARGS += -serial mon:stdio
EMU_ARGS += -rtc base=localtime
EMU_ARGS += -soundhw pcspk,ac97
#EMU_ARGS += -hda toaruos-disk.img
EMU_KVM   = -enable-kvm

.PHONY: all system clean run

all: system
system: misaka-kernel $(MODULES)

%.ko: %.c
	${CC} -c ${KERNEL_CFLAGS} -o $@ $<

run: system
	${EMU} ${EMU_ARGS} ${EMU_KVM} -append "foo bar baz" -initrd demo

misaka-kernel: ${KERNEL_ASMOBJS} ${KERNEL_OBJS} kernel/symbols.o
	${CC} -g -T kernel/arch/${ARCH}/link.ld ${KERNEL_CFLAGS} -o $@.64 ${KERNEL_ASMOBJS} ${KERNEL_OBJS} kernel/symbols.o -lgcc
	${OC} -I elf64-x86-64 -O elf32-i386 $@.64 $@

kernel/sys/version.o: ${KERNEL_SOURCES}

kernel/symbols.o: ${KERNEL_ASMOBJS} ${KERNEL_OBJS} util/gensym.krk
	-rm -f kernel/symbols.o
	${CC} -T kernel/arch/${ARCH}/link.ld ${KERNEL_CFLAGS} -o misaka-kernel.64 ${KERNEL_ASMOBJS} ${KERNEL_OBJS} -lgcc
	${NM} misaka-kernel.64 -g | kuroko util/gensym.krk > kernel/symbols.S
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

.PHONY: libc
libc: $(BASE)/lib/libc.a $(BASE)/lib/libc.so

$(BASE)/lib/libc.a: ${LIBC_OBJS} | crts
	$(AR) cr $@ $^

$(BASE)/lib/libc.so: ${LIBC_OBJS} | crts
	${CC} -nodefaultlibs -shared -fPIC -o $@ $^ -lgcc

.PHONY: crts
crts: $(BASE)/lib/crt0.o $(BASE)/lib/crti.o $(BASE)/lib/crtn.o

$(BASE)/lib/crt%.o: libc/crt%.S
	${AS} -o $@ $<

base/dev:
	mkdir -p $@
base/tmp:
	mkdir -p $@
base/proc:
	mkdir -p $@
base/bin:
	mkdir -p $@
base/lib:
	mkdir -p $@
base/cdrom:
	mkdir -p $@
base/var:
	mkdir -p $@
base/lib/kuroko:
	mkdir -p $@
fatbase/efi/boot:
	mkdir -p $@
cdrom:
	mkdir -p $@
.make:
	mkdir -p .make
dirs: base/dev base/tmp base/proc base/bin base/lib base/cdrom base/lib/kuroko cdrom base/var fatbase/efi/boot .make

APPS=$(patsubst apps/%.c,%,$(wildcard apps/*.c))
APPS_X=$(foreach app,$(APPS),base/bin/$(app))
APPS_Y=$(foreach app,$(APPS),.make/$(app).mak)
APPS_SH=$(patsubst apps/%.sh,%.sh,$(wildcard apps/*.sh))
APPS_SH_X=$(foreach app,$(APPS_SH),base/bin/$(app))
APPS_KRK=$(patsubst apps/%.krk,%.krk,$(wildcard apps/*.krk))
APPS_KRK_X=$(foreach app,$(APPS_KRK),base/bin/$(app))

LIBS=$(patsubst lib/%.c,%,$(wildcard lib/*.c))
LIBS_X=$(foreach lib,$(LIBS),base/lib/libtoaru_$(lib).so)
LIBS_Y=$(foreach lib,$(LIBS),.make/$(lib).lmak)

CFLAGS= -O2 -s -std=gnu11 -I. -Iapps -fplan9-extensions -Wall -Wextra -Wno-unused-parameter

ifeq (,$(findstring clean,$(MAKECMDGOALS)))
-include ${APPS_Y}
endif

ifeq (,$(findstring clean,$(MAKECMDGOALS)))
-include ${LIBS_Y}
endif

.make/%.lmak: lib/%.c util/auto-dep.krk | dirs crts
	kuroko util/auto-dep.krk --makelib $< > $@

.make/%.mak: apps/%.c util/auto-dep.krk | dirs crts
	kuroko util/auto-dep.krk --make $< > $@

base/bin/%.sh: apps/%.sh
	cp $< $@
	chmod +x $@

base/bin/%.krk: apps/%.krk
	cp $< $@
	chmod +x $@

.PHONY: libs
libs: $(LIBS_X)

.PHONY: apps
apps: $(APPS_X)

