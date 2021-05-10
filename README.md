# Misaka (ToaruOS 2.0)

Misaka is the "next-generation" (x86-64) kernel for [ToaruOS](https://github.com/klange/toaruos).

This repository contains most of the same content as the upstream repository, including the userspace applications and libraries and toolchain scripts.

Note that Misaka is still considered a _work in progress_. While most of the OS is functioning, there are still several subsystems which have not been completed.

![screenshot](https://klange.dev/s/Screenshot%20from%202021-05-07%2017-03-38.png)

## Completed Work

- The Toaru kernel has been ported to x86-64.
- Considerable changes have been made to make the kernel more portable to other architectures.
- Userspace fixes have been implemented to run on the new kernel.
- Some drivers have been ported.

## Roadmap

- SMP support is the next key target for the project.
- Some subsystems are being rewritten from scratch, such as the network stack.
- Ports have not been made/tested yet; current plan is to have everything from the 1.10.x package series available again for x86-64.
- aarch64 and riscv64 ports are on the long-term roadmap.
- All of this will eventually be merged upstream.

