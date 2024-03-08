---
title: Testbed Internals
linkTitle: Testbed Internals
weight: 90
---

{{% pageinfo %}}
This testbed uses several open source components that need descriptions and reference links.
{{% /pageinfo %}}

## Ghidra development sources

We track the [Ghidra repository](https://github.com/NationalSecurityAgency/ghidra) for released Ghidra packages, currently Ghidra 11.0.
A [Ghidra fork](https://github.com/thixotropist/ghidra/tree/isa_ext) is also used here which adds proposed RISCV instruction set
extension support.
The host environment for this project is currently a Fedora 39 workstation with an AMD Ryzen 9 5900HX and 32 GB of RAM.

## Toolchain sources

### binutils

* source repo: https://sourceware.org/git/binutils-gdb.git
* commit 2c73aeb8d2e02de7b69cbcb13361cfbca9d76a4e (HEAD, tag: binutils-2_41), 30 July 2023.
* local source directory `/home2/vendor/binutils-gdb`

### gcc, stdlib

* source repo: git://gcc.gnu.org/git/gcc.git
* commit ac9c81dd76cfc34ed53402049021689a61c6d6e7 (HEAD -> master, origin/trunk, origin/master, origin/HEAD),
  Date:   Mon Dec 18 21:40:00 2023 +0800
* local source directory `/home2/vendor/gcc`

### glibc

* source repo: git@github.com:bminor/glibc.git
* commit e957308723ac2e55dad360d602298632980bbd38 (HEAD -> master, origin/master, origin/HEAD)
  Date:   Fri Dec 15 12:04:05 2023 -0800
* local source directory `/home2/vendor/glibc`

### Bazel

* release repo https://github.com/bazelbuild/bazel
* release 7.0 currently used

## website sources

* hugo v0.120.4, installed as a Fedora snap package
* docsy v0.8.0 
