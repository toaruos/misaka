# Misaka (toaru-64)

Misaka is an experimental replacement kernel for [ToaruOS](https://github.com/klange/toaruos), alternatively known as "Toaru 2.0" or "Toaru-64".

This repository contains both Misaka as well as a modified ToaruOS userspace and the infrastructure needed to build a toolchain.

As Misaka is still _experimental_, it is missing many critical features and is not intended to used quite yet.

![screenshot](https://klange.dev/s/Screenshot%20from%202021-05-07%2017-03-38.png)

_Misaka can launch the graphical environment, but is missing important drivers and subsystems to make the OS usable._

## Goals

- Make an initial port of the Toaru kernel to x86-64.
- Cleanup the kernel to support porting to other architectures.
- Eventually, add support for SMP, by fixing resource locking.
