---
title: Glossary
linkTitle: Glossary
weight: 100
---

{{% pageinfo %}}
Some of the commonly used terms in this project
{{% /pageinfo %}}

exemplar
: An example of a binary file one might expect Ghidra to accept as input.  This might be an ELF executable, an ELF object file or library of object files, a kernel load module,
or a kernel vmlinux image.  Ideally it should be relatively small and easy to screen for hidden malware.  Not all features demonstrated by the exemplar need be supported
by the current Ghidra release.

platform
: The technology base one or more exemplars are used on.  A kernel exemplar expects to be run on top of a bootloader platform.  A Linux application exemplar may consider
the Linux kernel plus system libraries as its platform.  System libraries like libc.so can then be both exemplars and platform elements.

compiler suite
: A compiler suite includes a compiler or cross compiler plus all of the supporting tools and libraries to build executables for a range of
platforms.  This generally includes a versioned C and C++ compiler, preprocessor, assembler, linker, linker scripts, and core libraries like libgcc.  Compiler suites often support many architecture variants, such as 32 or 64 bit word size and a host of microarchitecture or instruction set
options.  Compiler suites can be customized by selecting specific configurations and options, becoming `toolchains`.

cross compiler
: A compiler capable of generating code for a processor other than the one it is running on.  An x86_64 gcc-14 compiler configured to generate RISCV-64 object files would be a cross-compiler.
Cross-compilers run on either the local host platform or on a Continuous Integration test server platform.

linker
: A tool that takes one or more object files and resolves those runtime linkages internal to those object files.  Usually `ld` on a Linux system.  Often generates an ELF file
or a kernel image.

loader
: A tool - often integrated with the kernel - that loads an Elf file into RAM.  The loader finalizes runtime linkages with external objects.  The loader will often rewrite
code (aka `relaxation`) to optimize memory references and so performance.

sysroot
: The system root directories provide the interface between platform (kernel and system libraries) and user code.
This can be as simple as `/usr/include` or as complicated as a `sysroot/lib/ldscripts` holding
over 250 ld scripts detailing how a linker should generate code the kernel loader can fully process.
Cross-compiler toolchains often need to import a sysroot to build for a given kernel.  This can make for a circular dependency.

toolchain
: A toolchain is an assembly of cross-compiler, linker, loader, and sysroot, plus a default set of options and switches for each component.
Different toolchains might share a gcc compiler suite, but be configured for different platforms - building a kernel image, building `libc.so`, or building an executable application.  Note: the word `toolchain` is often used in this project where `compiler suite` is intended.

workspace
: An environment that provides mappings between platforms and toolchains.  If you want to build an executable for a given platform, just name that platform on the command line
and the build tool will select a compatible toolchain and a *default* set of options.  You can still override those options.

hermetic
: Build artifacts are not affected by any local host files other than those imported with the toolchain.  A hermetic build on a Fedora platform will generate exactly the same
binary output as if built on an Ubuntu platform.  This allows remote build servers to cache build artifacts and CI/CD servers to use exactly the same build environment as a diverse
development team.
