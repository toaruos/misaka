# Misaka

**Misaka** is an experimental `x86_64` kernel.

The primary goal for Misaka is to replace the kernel from [ToaruOS](https://github.com/klange/toaruos) while maintaining general compatibility with the userspace at a source level, porting to x86-64, and supporting SMP. Misaka is named after the main character of A Certain Scientific Railgun (とある科学の超電磁砲) in the same way that ToaruOS itself is named after the series and its predecessor, A Certain Magical Index (とある魔術の禁書目録).

## Goals

Misaka aims to support several pieces of functionality from the original Toaru kernel, including:

- Loadable modules as ELF relocatable objects (replacing ELF32 with ELF64)
- Extensible VFS, with the same basic interface as its predecessor
- Robust build system

While supporting these, Misaka will be built from the ground up to support:

- x86-64, with a better focus on portability than the original
- SMP, with better synchronization and scheduling primitives
- Event-based IPC for VFS and many other kernel interactions
- An updated toolchain (gcc 5, especially)

Some specific pain points in the current Toaru kernel that we hope to address with these goals include:

- `select`/`poll` were essentially impossible with the current VFS model.
- Essentially none of our synchronization/scheduling supported timeouts, besides `sleep`.
- Much of the toaru32 kernel was built with the assumption that the kernel was running with interrupts disabled, though spinlocks around many critical sections were included for potential future SMP support.

## Timeline

As Misaka is a hobby project, there are no specific dates for when any part of this timeline will be completed, but there is a general ordering to what elements we will work on:

- x86-64 paging and interrupts
- Porting the memory management layers from toaru32 (heap, shared memory)
- Module loading infrastructure (ELF64 parsing, other elements from toaru32)
- Processes / threads / kernel tasklets / multitasking
- New synchronization primitives
- VFS (mostly ported from toaru32, updated interfaces for 64-bit offsets / sizes)
- Initial pass at porting existing drivers from toaru32
- Userspace toolchain (newlib / musl)
- Second pass at porting drivers
- Port userspace
- Drop toaru32 from the ToaruOS project
