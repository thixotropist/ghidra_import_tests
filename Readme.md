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

Additional exemplars are generated from source and a cross-platform gcc toolchain.

This project starts with a narrowly defined objective, hopefully within a test framework that
allows expansion:

1. The only processor considered is the RISCV-64 Little Endian processor with a common instruction set base.
   32 bit RISCV systems are ignored.  The first toolchains considered are a Linux gcc/g++
   toolchains with a binutils assembler.
2. The first external package considered was a Fedora 37 system image built on a Linux 6.0 kernel.  The kernel included in
   this package appears to be tuned for an SiFive system development kit.  The current external package is a Fedora 39 system image
   built with gcc-13 and binutils 2.40 or 2.41.
3. Exemplars are chosen from common networking components, with a bias towards components demonstrating - or stressing -
   RISCV-64 concurrency management.
4. Initial tests deal with Ghidra's import handling of RISCV-64 relocation codes.  This is fairly easy
   for Linux executables but more involved for position independent code like kernel load modules.
5. Current tests focus on RISCV instruction set extensions likely to impact Ghidra users in the future.
   This started with RISCV vector instructions, then added common bit manipulation and crypto instructions.
   Selected vendor-specific instruction additions are included now, if only to explore Ghidra design-space
   options for support of vendor-specific RISCV designs.

## Running Tests

Edit the `Makefile` to identify the Ghidra package to be tested and the cache location for imported packages.
Make sure that any imported binaries are either erased after Ghidra import or isolated in systems approved for
external executables.  The existing code avoids privileged operations, depending instead on the `guestmount` utility.

Execute the tests in this top level directory with:

```console
$ make all_imports
```

Review log files of the form `riscv64/*/*.log` to visually identify errors and warnings.

Run `integrationTest.py` in the top level directory to process json test results in `testResults`.  At present
only the igc.ko kernel module import generates json and discrete test results.

To test or retest a single exemplar import like the kernel import, simply delete the associated import log file:

```console
$ rm riscv64/kernel/vmlinux.log
$ make all_imports
```

Additional tests use a local toolchain to compile short source files into exemplar binary object and executable files.
These tests have their own dependencies.  For example to run integration tests on generated RISCV-64 exemplars with verbose output:

```console
$ cd riscv64/toolchain
$ python integrationTest.py -v
test00VerifyToolchainResolution (__main__.T0ToolchainTest.test00VerifyToolchainResolution)
Verify that workspace .bazelrc exists and enables toolchain resolution. ... ok
test01LocalCHelloWorld (__main__.T0ToolchainTest.test01LocalCHelloWorld)
local host toolchain (x86_64) build of helloworld, ... ok
test02InitializeToolchain (__main__.T0ToolchainTest.test02InitializeToolchain)
Try a continuous integration (x86_64) build, mostly to make sure bazel imports the toolchain ... ok
test03RiscV64Build (__main__.T0ToolchainTest.test03RiscV64Build)
riscV64 C build of helloworld, with checks to see if the right toolchain was ... ok
test04RiscV64AssemblyBuild (__main__.T0ToolchainTest.test04RiscV64AssemblyBuild)
riscV64 assembly build with synthetic relocations, with checks to see if the right toolchain was ... ok
test04RiscV64CppBuild (__main__.T0ToolchainTest.test04RiscV64CppBuild)
riscV64 C++ build of helloworld++, with checks to see if the right toolchain was ... ok
test01HelloWorld (__main__.T1ImportTests.test01HelloWorld)
build a riscv-64 helloworld binary and import the executable and object files into Ghidra. ... ok
test01ValidateImports (__main__.T2RelocationTests.test01ValidateImports)
Check the return codes on all Bazel build and Ghidra imports for success ... ok
test02GccPcRelRelocations (__main__.T2RelocationTests.test02GccPcRelRelocations)
Build and import a Gnu C binary that exercises many of the RISC-V 64 bit relocations generated by binutils 2-40. ... ok
test03GccTpRelRelocations (__main__.T2RelocationTests.test03GccTpRelRelocations)
Does Ghidra import thread-local data sections?  The decompiler may need work. ... skipped 'Relocations to thread Local storage needs support'
test04GasPcRelRelocations (__main__.T2RelocationTests.test04GasPcRelRelocations)
Build and import a short assembly program similar to relocationTest_pie, where ... ok

----------------------------------------------------------------------
Ran 11 tests in 26.609s

OK (skipped=1)
```

## ISA extensions

The RISCV community has a rich set of extensions to the base Instruction Set Architecture.  That means a diverse set
of new binary import targets to test against.  This work-in-progress is collected in the `riscv64/toolchain/assemblySamples` directory.
The basic idea is to compare current Ghidra disassembly with current binutils `objdump` disassembly, using object files
assembled from the binutils `gas` testsuite.  For example:

* `riscv64/toolchain/assemblySamples/h-ext-64.S` was copied from the binutils gas testsuite.  It contains unit test instructions for
  hypervisor support extensions like `hfence.vvma` and `hlv.w`.
* `riscv64/exemplars/h-ext-64.o` is the object file produced by a *current snapshot* of the binutils 2-41 assembler.  The associated listing
  is `riscv64/exemplars/h-ext-64.list`.
* `riscv64/exemplars/h-ext-64.objdump` is the output from disassembling `riscv64/exemplars/h-ext-64.o` using the current snapshot of the binutils 2-41
  `objdump`.

So we want to open Ghidra, import `riscv64/exemplars/h-ext-64.o`, and compare the disassembly window to `riscv64/exemplars/h-ext-64.objdump`, then triage
any variances.

Some variances are trivial.  The `h-ext-64.S` tests include instructions that assemble into a single 4 byte sequence.  Disassembly will only give a single
instruction, perhaps the simplest one of the given aliases.

Other variances are harder - it looks like Ghidra expects to see an earlier and deprecated set of vector instructions than one currently approved set.

`riscv64/toolchain/assemblySamples/TODO.md` collects some of the variances noted so far.

One big question is what kind of pcode should Ghidra generate for some of these instructions - and how many Ghidra users will care about that pcode.
The short term answer is to treat extension instructions as pcode function calls.  The longer term answer may be to wait until GCC14 comes out with support for
vector extensions, then see what kind of C source is conventionally used when invoking those extensions.  The `memcpy` inline function from `libc` is a likely
place to find early use of vector instructions.

Also, what can we safely ignore for now?  The proposed vendor-specific T-Head extension instruction
[`th.l2cache.iall`](https://github.com/T-head-Semi/thead-extension-spec/blob/master/xtheadcmo/l2cache_iall.adoc) won't be seen by most Ghidra users.
On the other hand, the encoding rules published with those T-Head extensions look like a good example to follow.

The Fedora 39 kernel includes virtual machine cache management instructions that are not necessarily supported by binutils - they are 'assembled' with gcc macros
before reaching the binutils assembler.  We will ignore those instruction extensions for now, and only consider instruction extensions supported by binutils.

## Caveats

These are not regression tests.  A test failure or regression is not necessarily a Ghidra release blocker.
Test failures and successes should only be considered as indicators of how well Ghidra handles specific
import edge cases.  Discussion of how well Ghidra *should* handle those cases is out of scope for this repository.

With a single Fedora import example we have poor sample diversity.  An Ubuntu system image is also available,
with a somewhat older kernel. We could add the Ubuntu image to this test framework.  It's not clear whether
the Ubuntu image was built with a different toolchain or even by a different development team.  It is possible that
the development team modified the toolchain or used unusual build and link options in assembling the image.

The RISCV-64 instruction set architecture is mutable.  We can expect to see hardware implementations with vector, crypto,
and transactional code extensions at some time in the near future.

## TODO

* [ ] Clarify the toolchains we are using.  At present we are using the base gcc-12 toolchain https://github.com/riscv/riscv-gnu-toolchain,
  a patched variant of that to invoke gcc-13, and a standalone binutils 2-41 daily snapshot.
* [ ] Collect technical debt, such as the lack of Ghidra support for thread-local and cpu-local storage and the relocation codes used to
  identify and support that storage class.  This is likely not just a RISCV issue for Ghidra.
* [ ] Identify a workflow starting with ISA extensions added to the binutils gas testsuite and ending with PR updates to Ghidra's RISCV
  sleigh files.  There are a number of out-of-date entries within `Ghidra/Processors/RISCV/data/languages`.
* [ ] Identify the methods the RISCV community and binutils developers manage vendor-specific instruction set extensions, then compare
  with the methods Ghidra uses to recommend a processor 'language' on import of any given binary.  For example, which GCC versions encode
  extension requirements into ELF files?

## Backburner goals

* An early project goal was to help Ghidra identify race conditions in critical network code.  RISCV exemplars use at least 10 different memory barrier
  or `fence` instructions - would Ghidra help locate places where the wrong fence instruction is used? Probably yes, but it would help in so few contexts that
  it isn't a timely thing to add to Ghidra.
