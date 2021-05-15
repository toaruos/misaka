# Misaka (ToaruOS 2.0)

Misaka is the "next-generation" (x86-64) kernel for [ToaruOS](https://github.com/klange/toaruos).

This repository contains most of the same content as the upstream repository, including the userspace applications, libraries, and toolchain scripts. The bootloaders are not included.

Note that Misaka is still considered a _work in progress_. While most of the OS is functioning, third-party ports are not ready and the network stack is being redesigned.

![screenshot](https://klange.dev/s/Screenshot%20from%202021-05-15%2011-05-51.png)

## Completed Work

- The Toaru kernel has been ported to x86-64.
- Considerable changes have been made to make the kernel more portable to other architectures.
- Userspace fixes have been implemented to run on the new kernel.
- Some drivers have been ported (AC'97, serial, vmware mouse)

## Roadmap

- SMP support is the next key target for the project.
- Some subsystems are being rewritten from scratch, such as the network stack.
- Third-party ports have not been made/tested yet; current plan is to have everything from the 1.10.x package series available again for x86-64.
- aarch64 and riscv64 ports are on the long-term roadmap.
- All of this will eventually be merged upstream.

## Building

```bash
git clone https://github.com/toaruos/misaka
cd misaka
git submodule update --init kuroko
docker pull toaruos/build-tools:1.99.x
docker run -v `pwd`:/root/misaka -w /root/misaka -e LANG=C.UTF-8 -t toaruos/build-tools:1.99.x util/build-in-docker.sh
```

## Running

```bash
qemu-system-x86_64 -kernel misaka-kernel -initrd ramdisk.tar -append "root=/dev/ram0 start=live-session migrate" -enable-kvm -m 1G
```
