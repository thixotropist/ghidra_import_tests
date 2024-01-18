---
title: Overview
linkTitle: Overview
menu: {main: {weight: 1}}
weight: 1
---

{{% pageinfo %}}
We can help Ghidra import newer binaries by collecting samples of those binaries.
{{% /pageinfo %}}

>Note: This proof-of-concept project focuses on a single processor family, RISCV.
>      Some results are checked against equivalent x86_64 processors, to see if pending
>      issues are limited in scope or likely to hit a larger community

This project collects files that may stress - in a good way - Ghidra's import capabilities.
Others are doing a great job extending Ghidra's ability to import
and recognize C++ structures and classes, so we will focus on lower level objects
like instruction sets, relocation codes, and pending toolchain improvements.
The primary CPU family will be based on
the RISCV-64 processor.  This processor is relatively new and easily modified, so
it will likely show lots of new features early.  Not all of these new features will
make it into common use or arenas in which Ghidra is necessary, so we don't really
know how much effort is worth spending on any given feature.

There are two key goals here:

1. Experiment with Ghidra import integration tests that can detect Ghidra regressions.  This involves collecting
   a number of processor and toolchain binary exemplars to be imported plus analysis scripts to verify those import results
   remain valid.  Example: verify that ELF relocation codes are properly handled when importing a RISCV-64 kernel
   module.  These integration tests should always pass after changes to Ghidra's source code.
2. Collect feature-specific binary exemplars that might highlight emergent gaps in
   Ghidra's import processes.  Ghidra will usually
   fail to properly import these exemplars, allowing the Ghidra development team to triage the gap and evaluate options for closing
   it.  Example: pass the RISCV instruction set extension testsuite from `binutils/gas` into Ghidra to test whether Ghidra can
   recognize all of the new instructions `gas` can generate.

The initial scope focuses on RISCV 64 bit processors capable of running a full linux network stack, likely implementing
the [2023 standard profile](https://github.com/riscv/riscv-profiles/blob/main/rva23-profile.adoc).

We want to track recent additions to standard RISCV-64 toolchains (like `binutils` and `gcc`) to
see how they might make life interesting for Ghidra developers.  At present, that includes
newly frozen or ratified instruction set architecture (ISA) changes and compiler autovectorization
optimizations.  Some vendor-specific instruction set extensions will be included if they are accepted into
the `binutils` main branch.

## Running integration tests

The first two steps collect binary exemplars for Ghidra to import.  Large binaries are extracted from public disk images,
such as the latest Fedora RISCV-64 system disk image.  Small binaries are generated locally from minimal C or C++ source
files and gcc toolchains.

The large binaries are downloaded and extracted using `acquireExternalExemplars.py`.  This script is built on the python `unittest` framework
to either verify the existence of previously extracted exemplars or regenerate those if missing.

```console
$ ./acquireExternalExemplars.py 
...........
----------------------------------------------------------------------
Ran 11 tests in 0.003s

OK
```

>TODO: add the script example for `generateInternalExemplars.py`

>TODO: add the script example for `importExemplars.py`

```console
$ ./integrationTest.py 
inspecting the R_RISCV_BRANCH relocation test
inspecting the R_RISCV_JAL test
inspecting the R_RISCV_PCREL_HI20 1/2 test
inspecting the R_RISCV_PCREL_HI20 2/2 test
inspecting the R_RISCV_PCREL_LO12_I test
inspecting the R_RISCV_64 test
inspecting the R_RISCV_RVC_BRANCH test
inspecting the R_ADD_32 test
inspecting the R_RISCV_ADD64 test
inspecting the R_SUB_32 test
inspecting the R_RISCV_ADD64 test
inspecting the R_RISCV_RVC_JUMP test
.
----------------------------------------------------------------------
Ran 1 test in 0.000s
```
