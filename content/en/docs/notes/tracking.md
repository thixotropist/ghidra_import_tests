---
title: Tracking Convergence
linkTitle: Tracking
weight: 50
---

{{% pageinfo %}}
We can track external events to plan future integration test effort.
{{% /pageinfo %}}

This project gets more relevant when RISCV-64 processors start appearing in appliances with more instruction set extensions and
with code compiled by newer compiler toolchains.

The project results get easier to integrate if and when more development effort is applied to specific Ghidra components.

This page collects external sites to track for convergence.

## Toolchains and platforms

### binutils

New instruction extensions often appear here as the first public implementation.  Check out the opcodes, aliases, and disassembly
patterns found in the test suite.

* track the [source](https://sourceware.org/git/binutils-gdb.git)
* inspect `git log include/opcode/|grep riscv|head`
* inspect `git log gas/testsuite/gas/riscv`

#### sample log

* 28 Feb 2024 - jiawei@iscas.ac.cn added support for Zabha riscv extension (atomic byte and half-word memory ops)
* 4 Jan 2024 - jinma@linux.alibaba.com fixed th.vsetvli for T-Head extensions

### compilers

* track the [source](git://gcc.gnu.org/git/gcc.git)
* inspect `git log gcc/testsuite/gcc.target/riscv`

#### log

Look for commits indicating the stability of vectorization or new compound loop types that now allow auto vectorization.

### libraries

* track the [source](git://sourceware.org/git/glibc.git)
* track the [source](https://github.com/openssl/openssl)

#### log

* glibc
    * Not much specific to RISC-V
* openssl (in master, not released as of openssl 3.2)
    * phoebe.chen@sifive.com added vector crypto implementations of AES-CBC mode,  AES-128/192/256-CTR, AES-128/256-XTS
    * jerry.shih@sifive.com added Zvksh support for sm3

### kernels

* track the [source](https://github.com/torvalds/linux.git)
* inspect `git log arch/riscv`

### system images

* Fedora
* Ubuntu

### cloud instances

* [Scaleway risc-v servers](https://www.scaleway.com/en/news/scaleway-launches-its-risc-v-servers-in-the-cloud-a-world-first-and-a-firm-commitment-to-technological-independence/)
    * with the T-HEAD TH1520 SoC, 16GB RAM and 128GB

## ISA Extensions

* profiles and individual standards-tracked extensions
* vendor-specific extensions
* gcc intrinsics

## applications

* track [source](https://github.com/ggerganov/whisper.cpp.git)
* Look for use of riscv intrinsics with arm/Neon and avx2 eqiuvalents as opposed to allowing compiler autovectorization.
* Watch for standardization of 16 bit floating point

## Ghidra

### similar vector instruction suites

`Ghidra/Processors/AARCH64/data/languages/AARCH64sve.sinc` defines the instructions used by the AARCH64 Scalable Vector Extensions package.
This suite is similar to the RISCV vector suite in that it is vector register length agnostic.  It was added in March of 2019 and not updated since.

### pcode extensions

`Ghidra/Features/Decompiler/src/decompile/cpp` holds much of the existing Ghidra code for system and user defined pcodes.
`userop.h` and `userop.cc` look relevant, with `caheckman` a common contributor.

## Community

* [RISCV Organization](https://riscv.org/)
* [reddit discussion group](https://www.reddit.com/r/RISCV/)
    * new RISCV products are often discussed here.
