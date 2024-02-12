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
* `//platforms:riscv_local` for toolchain debugging, using a local file system toolchain under `/opt/riscvx`

>Note: The current binutils and gcc show more vendor-specific instruction set extensions from THead, so we will arbitrarily use that
>      as the exemplar custom platform.

This directory defines these toolchains:

* `//toolchains:riscv64-default` - a gcc-13 stable RISCV compiler, linker, loader, and sysroot of related include files and libraries
* `//toolchains:riscv64-next` - a gcc-14 unreleased but feature-frozen RISCV compiler, linker, loader, and sysroot of related include files
  and libraries
* `//toolchains:riscv64-custom` - a variant of  `//toolchains:riscv64-next` with multiple standard and vendor-specific ISA extensions enabled
  by default
* `//toolchains:riscv64-local` - a toolchain executing out of `/opt/riscvx` instead of a portable tarball.  Generally useful only when
  debugging the generation of a fully portable and hermetic toolchain tarball.

Exemplars are built by naming the platform for each build.  Bazel then finds a compatible toolchain to complete the build.

```console
# compile for the riscv_userspace platform, automatically selecting the riscv64-default toolchain with gcc-13.
bazel build -s --platforms=//platforms:riscv_userspace gcc_vectorization:helloworld_challenge
# compile for the riscv_vector platform, automatically selecting the riscv64-next toolchain with gcc-14.
bazel build -s --platforms=//platforms:riscv_vector gcc_vectorization:helloworld_challenge
```

This table shows relationships between platforms, constraints, toolchains, and default options:

| platform                    | cpu constraint         | toolchain                    | default options              | added optimized options |
| --------------------------- | ---------------------- | ---------------------------- | ---------------------------- | ----------------------- |
| //platforms:riscv_userspace | //toolchains:riscv64   | //toolchains:riscv64-default |                              | -O3                     |
| //platforms:riscv_vector    | //toolchains:riscv64-v | //toolchains:riscv64-next    | -march=rv64gcv               | -O3                     |
| //platforms:riscv_custom    | //toolchains:riscv64-c | //toolchains:riscv64-custom  | -march=rv64gcv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbc_xtheadba_xtheadbb_xtheadbs_xtheadcmo_xtheadcondmov_xtheadmac_xtheadfmemidx_xtheadmempair_xtheadsync | -O3 |
| //platforms:riscv_local     | //toolchains:riscv64-l | //toolchains:riscv64-local   |                              | -O3                      |

Notes:
 * The `-O3` option is likely too aggressive. The `-O2` option would be more common in broadly released software.
 * `//toolchains:riscv64-default` currently uses a gcc-13 toolchain suite
 * the other toolchains use various developmental snapshots of the gcc-14 toolchain suite
 * vector extensions version 1.0 are default on `//toolchains:riscv64-next` and `//toolchains:riscv64-custom`
 * `//toolchains:riscv64-custom` adds bit manipulation and many of the THead extensions supported by binutils.

 >Warning: C options can be added by the toolchain, within a BUILD file, and on the command line.  For options like `-O` and `-march`, only
 >         the last instance of the option affects the build.  

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