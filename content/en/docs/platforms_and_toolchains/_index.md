---
title: Platforms and Toolchains
linkTitle: Platforms and Toolchains
weight: 50
---

{{% pageinfo %}}
Code is built by a toolchain (compiler, linker) to run on a platform (e.g., a pixel 7a cellphone).
{{% /pageinfo %}}

This project adopts the Bazel framework for building importable exemplars.  [Platforms](https://bazel.build/extending/platforms)
describe the foundation on which code will run.  [Toolchains](https://bazel.build/extending/toolchains) compile and link code for different
platforms.  Compiler suites assemble `gcc`, `binutils`, and `glibc` packages for different architectures.
Bazel builds are (ideally) [hermetic](https://bazel.build/basics/hermeticity), which for our purposes means that platforms and toolchains
are all versioned and importable, so build results are the same no matter the build host environment.

## Example of RISCV-64 platforms and toolchains

The currently configured platforms and toolchains can be shown with the `show_toolchains.sh` script:

```console
$ ./show_toolchains.sh
Show RISCV64 platforms, cpu constraints, and available toolchains
Available platforms:
//riscv64/generated/platforms:riscv64_default
//riscv64/generated/platforms:riscv64_rva23
//riscv64/generated/platforms:riscv64_thead
//riscv64/generated/platforms:x86_64
CPU constraints:
//riscv64/generated/toolchains/riscv:riscv64
//riscv64/generated/toolchains/riscv:riscv64-rva23-supported
//riscv64/generated/toolchains/riscv:riscv64-thead-supported
Registered Toolchain Configurations:
//riscv64/generated/toolchains/riscv:riscv64-gc-gcc-config
//riscv64/generated/toolchains/riscv:riscv64-rva23-gcc-config
//riscv64/generated/toolchains/riscv:riscv64-thead-gcc-config
```

* `//riscv64/generated/platforms:riscv64_default` might be specified for a generic RISCV-64 Linux appliance with the usual libc and libstdio support
  and a CPU machine architecture like rv64gc - general purpose extensions plus compressed (16 bit) instructions only.
* `//riscv64/generated/platforms:riscv64_rva23` for a more specialized RISCV-64 Linux appliance where all of the extensions defined in
   the RISCV RVA23 profile are fully implemented.
* `//riscv64/generated/platforms:riscv64_thead` for a highly specialized RISCV-64 Linux appliance implementing the THead vendor-specific instruction extensions
* `//riscv64/generated/platforms:x86_64` for local unit testing on x86_64 developer or continuous integration hosts.

>Note: The current binutils and gcc show more vendor-specific instruction set extensions from THead, so we will arbitrarily use that
>      as the exemplar custom platform.

Code built for the //riscv64/generated/platforms:riscv64_rva23 platform would likely not run on a generic RISCV-64 processor since it would likely include
unsupported instructions.  Code built for the //riscv64/generated/platforms:riscv64_default platform would likely run on a RISCV CPU supporting the
more advanced RVA23 instructions.  Bazel captures these relationships in CPU constraints like `//riscv64/generated/toolchains/riscv:riscv64-rva23-supported`.
Those platform constraints are matched against toolchain compatibility rules.

Current toolchain configurations include:

* `//riscv64/generated/toolchains/riscv:riscv64-gc-gcc-config` - a current gcc stable RISCV compiler, linker, loader,
   and sysroot of related include files and libraries.  The default machine architecture is `rv64gc`.
* `//riscv64/generated/toolchains/riscv:riscv64-rva23-gcc-config` - a variant of `//riscv64/generated/toolchains/riscv:riscv64-gc-gcc-config` with many of the rva23
  instruction extensions enabled.
* `//riscv64/generated/toolchains/riscv:riscv64-thead-gcc-config` - a variant of `//riscv64/generated/toolchains/riscv:riscv64-gc-gcc-config` with many of the
  THead instruction extensions enabled.

Exemplars are built by naming the platform for each build.  Bazel then finds a compatible toolchain to complete the build.

```console
# compile for the riscv_default platform, automatically selecting the riscv64-default toolchain.
bazel build -s --platforms=//riscv64/generated/platforms:riscv64_default riscv64/generated/userSpaceSamples:helloworld
...
# inspect the binary to see which RISCV architecture it was built for
$ readelf -A bazel-bin/riscv64/generated/userSpaceSamples/helloworld
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0_zmmul1p0_zaamo1p0_zalrsc1p0_zca1p0_zcd1p0"

# compile for the riscv_vector platform, automatically selecting the riscv64_rva23_ toolchain
$ bazel build -s --platforms=//riscv64/generated/platforms:riscv64_rva23 riscv64/generated/userSpaceSamples:helloworld
...
$ readelf -A bazel-bin/riscv64/generated/userSpaceSamples/helloworld
Attribute Section: riscv
File Attributes
  Tag_RISCV_stack_align: 16-bytes
  Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicsr2p0_zifencei2p0_zmmul1p0_zaamo1p0_zalrsc1p0_zfa1p0_zca1p0_zcb1p0_zcd1p0_zba1p0_zbb1p0_zbc1p0_zbkb1p0_zbkc1p0_zbkx1p0_zvbb1p0_zvbc1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvkb1p0_zvkg1p0_zvkn1p0_zvknc1p0_zvkned1p0_zvkng1p0_zvknhb1p0_zvks1p0_zvksc1p0_zvksed1p0_zvksg1p0_zvksh1p0_zvkt1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0"
```

Toolchain configuration tells Bazel how to construct the compilation and linking command lines.  You might see something like this (annotated for clarity):

```console
$ bazel build -s --platforms=//riscv64/generated/platforms:riscv64_rva23 riscv64/generated/userSpaceSamples:helloworld
...
SUBCOMMAND: # //riscv64/generated/userSpaceSamples:helloworld [action 'Compiling riscv64/generated/userSpaceSamples/helloworld.c', configuration: 355341da4b372fe5596450d81d75e9e44e0ed1782c3a6df05a54fdb1b4caf782, execution platform: @@platforms//host:host, mnemonic: CppCompile]
(cd /run/user/1000/bazel/execroot/_main && \
  exec env - \
    ...
    PWD=/proc/self/cwd \
  riscv64/generated/toolchains/riscv/gcc/wrappers/gcc \
    -isystem/run/user/1000/bazel/external/gcc_riscv_suite+/lib/gcc/riscv64-unknown-linux-gnu/15.0.1/include-fixed \
    -isystem/run/user/1000/bazel/external/gcc_riscv_suite+/lib/gcc/riscv64-unknown-linux-gnu/15.0.1/include \
    -isystem/run/user/1000/bazel/external/gcc_riscv_suite+/riscv64-unknown-linux-gnu/include/c++/15.0.1 \
    -isystem/run/user/1000/bazel/external/gcc_riscv_suite+/usr/include \
    -isystem/run/user/1000/bazel/external/gcc_riscv_suite+/include \
    '-march=rv64gcv_zba_zbb_zbc_zbkb_zbkc_zbkx_zvbb_zvbc_zvkng_zvksg_zvkt_zcb_zfa' \
    -no-canonical-prefixes \
    -fno-canonical-system-headers \
    -Wno-builtin-macro-redefined \
    '-D__DATE__="redacted"' \
    '-D__TIMESTAMP__="redacted"' \
    '-D__TIME__="redacted"' \
    -fstack-protector \
    -Wall -Wunused-but-set-parameter -Wno-free-nonheap-object -fno-omit-frame-pointer \
    -MD -MF bazel-out/k8-fastbuild/bin/riscv64/generated/userSpaceSamples/_objs/helloworld/helloworld.pic.d \
    '-frandom-seed=bazel-out/k8-fastbuild/bin/riscv64/generated/userSpaceSamples/_objs/helloworld/helloworld.pic.o' \
    -fPIC \
    -iquote . \
    -iquote bazel-out/k8-fastbuild/bin \
    -iquote external/bazel_tools \
    -iquote bazel-out/k8-fastbuild/bin/external/bazel_tools \
    -c riscv64/generated/userSpaceSamples/helloworld.c \
    -o bazel-out/k8-fastbuild/bin/riscv64/generated/userSpaceSamples/_objs/helloworld/helloworld.pic.o)
...
SUBCOMMAND: # //riscv64/generated/userSpaceSamples:helloworld [action 'Linking riscv64/generated/userSpaceSamples/helloworld', configuration: 355341da4b372fe5596450d81d75e9e44e0ed1782c3a6df05a54fdb1b4caf782, execution platform: @@platforms//host:host, mnemonic: CppLink]
(cd /run/user/1000/bazel/execroot/_main && \
  exec env - \
    ...
    PWD=/proc/self/cwd \
  riscv64/generated/toolchains/riscv/gcc/wrappers/gcc \
  -o bazel-out/k8-fastbuild/bin/riscv64/generated/userSpaceSamples/helloworld \
  bazel-out/k8-fastbuild/bin/riscv64/generated/userSpaceSamples/_objs/helloworld/helloworld.pic.o \
  -Wl,-S \
  -Wl,-Triscv64/generated/toolchains/riscv/gcc/elf64lriscv.xc \
  -Wl,-lstdc++ \
  -Wl,-lm \
  -Wl,-z,relro,-z,now \
  -no-canonical-prefixes \
  -pass-exit-codes)
# Configuration: 355341da4b372fe5596450d81d75e9e44e0ed1782c3a6df05a54fdb1b4caf782
# Execution platform: @@platforms//host:host
INFO: Found 1 target...
Target //riscv64/generated/userSpaceSamples:helloworld up-to-date:
  bazel-bin/riscv64/generated/userSpaceSamples/helloworld
```

## Compiler Suites

Compiler suites generally include several components that can affect the generated binaries:

* the gcc compiler or cross-compiler, built from source and configured for a specific target architecture and language set
* binutils utilities, including a `gas` assembler with support for various instruction set extensions
  and disassembler tools like `objdump` that provide reference handling of newer instructions.
* linker and linker scripts
* a `sysroot` holding files the above subsystems would normally expect to find under `/usr`, for instance
    `/usr/include` files supplied by the kernel and standard libraries
* libc, libstdc++, etc.
* default compiler options and include directories

Compiler suites are generated externally and imported into the workspace as Bazel modules using lines like this in `MODULE.bazel`:

```py
bazel_dep(name="gcc_riscv_suite", version="15.0.1.0")
bazel_dep(name="gcc_x86_64_suite", version="15.0.1.0")
```

>Note: any single workspace can only import a single version of any given module
