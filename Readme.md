# Ghidra binary import tests

Ghidra is a wonderful tool for analysis of executable binaries. This project attempts to collect
elements of a testing framework for the binary import process - loading something with executable
code into a Ghidra project.  The basic Concept of Operations is:

1. Identify one or more external executable packages containing binary code exemplars.  Avoid holding
   individual executable binaries as test resources, as these may include malware.
2. Break these binary code exemplars down into exemplar categories:
    1. user space executables
    2. user space system libraries
    3. kernel loadable modules and device drivers
    4. kernel code
3. For each exemplar category, import the exemplars into Ghidra using the headless analyzer
   with a dedicated pre-analysis Ghidra script.  This script adds structure and context to
   highlight the Ghidra import elements under test.
4. For each exemplar, bundle import assertion tests into a post-analysis Ghidra script.

Additional exemplars are generated from source and a cross-platform toolchain.

This project starts with a narrowly defined objective, hopefully within a test framework that
allows expansion:

1. The only processor considered is the RISCV-64 Little Endian processor with a common instruction set base.
   32 bit RISCV systems are ignored.  The first toolchain considered is a Linux gcc/g++
   toolchain.
2. The first external package considered is a Fedora 37 system image built on a Linux 6.0 kernel.  The kernel included in
   this package appears to be tuned for an SiFive system development kit.
3. Exemplars are chosen from common networking components, with a bias towards components demonstrating - or stressing -
   RISCV-64 concurrency management.
4. Initial tests deal with Ghidra's import handling of RISCV-64 relocation codes.  This is fairly easy
   for Linux executables but more involved for position independent code like kernel load modules.

## Running Tests

Edit the `Makefile` to identify the Ghidra package to be tested and the cache location for imported packages.
Make sure that any imported binaries are either erased after Ghidra import or isolated in systems approved for
external executables.  The existing code avoids privileged operations, depending instead on the `guestmount` utility.

Execute the tests in this top level directory with:

```console
$ make all_imports
```

Review log files of the form `riscv64/*/*.log` to identify errors and warnings.

To test or retest a single exemplar import like the kernel import, simply delete the associated import log file:

```console
$ rm riscv64/kernel/vmlinux.log
$ make all_imports
```

## Caveats

These are not regression tests.  A test failure or regression is not necessarily a Ghidra release blocker.
Test failures and successes should only be considered as indicators of how well currently Ghidra handles specific
import edge cases.  Discussion of how well Ghidra *should* handle those cases is out of scope for this repository.

With a single Fedora 37 import example we have poor sample diversity.  An Ubuntu system image is also available,
with a somewhat older kernel. We could add the Ubuntu image to this test framework.  It's not clear whether
the Ubuntu image was built with a different toolchain or even by a different development team.  It is possible that
the development team modified the toolchain or used unusual build and link options in assembling the image.

The RISCV-64 instruction set architecture is mutable.  We can expect to see hardware implementations with vector, crypto,
and transactional code extensions at some time in the near future.

The RISCV-64 ISA and toolchain use more link-time optimization, resulting in more ELF relocation codes and more work
for Ghidra in ELF relocation handling.  We don't know whether this is a trend that may be seen in other processor families.
We do know that this first package includes binaries with multiple relocation codes at a single address and relocation codes that
can only be resolved indirectly by searching for a related relocation code entry.  We also see symbol names containing non-printing
ASCII characters, like `.L0^B1`.

## TODO

* [ ] Unify tests run via Ghidra postAnalysis scripts with toolchain tests run in Python.  Failure detection during external exemplar
      import currently depends on visual inspection of the import logs.  Instead, the postAnalysis scripts should generate json test summary
      files that the toolchain Python integration test processes.  In general, we need to make regressions harder to miss.
* [ ] Experiment with a migration from gcc-12 to gcc-13 and from binutils 2-40 to binutils 2-41.  This *should* introduce RISCV vector instructions.
      This is also an opportunity to use other toolchains.
* [ ] Search for inadequate disassembly or decompilation of RISCV-64 instructions.  Do `fence` instruction variations need specific mnemonics?
      Are crypto ISA instructions found in newer kernel or libssl binaries?
* [ ] Clarify the terms `loader`, `linker`, `sysroot`, `toolchain` and `crosscompiler`.  Specifically clarify the ways a kernel loader can modify
      compiled code just before execution.  This includes well-known things like shared object linkages as well as code relaxation and link time optimization.

## Backburner goals

* An early project goal was to help Ghidra identify race conditions in critical network code.  RISCV exemplars use at least 10 different memory barrier
  or `fence` instructions - would Ghidra help locate places where the wrong fence instruction is used? Probably yes, but it would help in so few contexts that
  it isn't a timely thing to add to Ghidra.
