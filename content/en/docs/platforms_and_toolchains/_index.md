---
title: Platforms and Toolchains
linkTitle: Platforms and Toolchains
menu: {main: {weight: 30}}
weight: 30
---

{{% pageinfo %}}
Code is built by a toolchain (compiler, linker) to run on a platform (e.g., a pixel 7a cellphone).
{{% /pageinfo %}}

This project adopts the Bazel framework for building importable exemplars.  [Platforms](https://bazel.build/extending/platforms)
describe the foundation on which code will run.  [Toolchains](https://bazel.build/extending/toolchains) compile and link code for different
platforms.  Bazel builds are [hermetic](https://bazel.build/basics/hermeticity), which for our purposes means that platforms and toolchains
are all versioned and importable, so build results are the same no matter where the build host may be.

## Example of RISCV-64 platforms and toolchains

The directory RISCV64/toolchain defines these platforms:

* `//platforms:riscv_userspace` for a generic RISCV-64 Linux appliance with the usual libc and libstdio APIs
* `//platforms:riscv_vector` for a more specialized RISCV-64 Linux appliance with vector extensions supported
* `//platforms:riscv_custom` for a highly specialized RISCV-64 Linux appliance with vector and vendor-specific extensions supported

>Note: The current binutils and gcc show more vendor-specific instruction set extensions from THead, so we will arbitrarily use that
>      as an exemplar platform.

This directory defines these toolchains:

* `//toolchains:riscv64-default` - a gcc-13 stable RISCV compiler, linker, loader, and sysroot of related include files and libraries
* `//toolchains:riscv64-next` - a gcc-14 unreleased but feature-frozen RISCV compiler, linker, loader, and sysroot of related include files
  and libraries
* `//toolchains:riscv64-custom` a variant of  `//toolchains:riscv64-next` with multiple standard and vendor-specific ISA extensions enabled
  by default

Exemplars are built by naming the platform for each build.  Bazel then finds a compatible toolchain to complete the build.

```console
# compile for the riscv_userspace platform, automatically selecting the riscv64-default toolchain with gcc-13.
bazel build -s --platforms=//platforms:riscv_userspace gcc_vectorization:helloworld_challenge
# compile for the riscv_vector platform, automatically selecting the riscv64-next toolchain with gcc-14.
bazel build -s --platforms=//platforms:riscv_vector gcc_vectorization:helloworld_challenge
```

## Toolchain details

Toolchains generally include several components that can affect the generated binaries:

* the gcc compiler, built from source and configured for a specific target architecture and language set
* binutils utilities, including a `gas` assembler with support for various instruction set extensions
  and disassembler tools like `objdump` that provide reference handling of newer instructions.
* linker and linker scripts
* a `sysroot` holding files the above subsystems would normally expect to find under `/usr`, for instance
    `/usr/include` files supplied by the kernel and standard libraries
* libc, libstdc++, etc.
* default compiler options and include directories

The toolchain prepared for building a kernel module won't be the same as a toolchain built for userspace programs,
even if the compilers are identical.

See [adding toolchains]({{< relref "adding_toolchains" >}}) for an example of adding a new toolchain to this project.