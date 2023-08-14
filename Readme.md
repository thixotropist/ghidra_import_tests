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

This project starts with a narrowly defined objective, hopefully within a test framework that
allows expansion:

1. The only processor considered is the RISCV-64 Little Endian processor with a common instruction set base.
   32 bit RISCV systems are ignored.  The only toolchain considered is a Linux gcc/g++ plus binutils
   toolchain.
2. The first external package considered is a Fedora 37 system image built on a Linux 6.0 kernel.  The kernel included in
   this package *may* be tuned for an SiFive system development kit.
3. Exemplars are chosen from common networking components, with a bias towards components demonstrating - or stressing -
   RISCV-64 concurrency management and memory barrier implementations.
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
Test failures and successes should only be considered as indicators of how well Ghidra handles specific
import edge cases.

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

* [X] Consider loading the Fedora 37 RISCV kernel at 0xffffffff80000000 instead of 0x0000000080000000.  This will
      make 64 bit absolute pointers align better, but may not materially affect Ghidra import testing except to stress
      signed versus unsigned address offset calculations.
* [ ] Add pre- and post- analysis import scripts for the kernel load module exemplar.  The post-analysis script should
      verify all non-debug relocation types found in the exemplar load module.  Tests can be free-form, reporting results
      using the existing GhidraScript error logging framework.
* [ ] Look for ways to evolve post-analysis GhidraScript tests to look more like the existing Ghidra gradle integration test framework.
      Some of the tests will be very slow.
* [ ] Search for inadequate disassembly or decompilation of RISCV-64 instructions.  Do `fence` instruction variations need specific mnemonics?
      are crypto ISA instructions found in newer kernel or libssl binaries? 
