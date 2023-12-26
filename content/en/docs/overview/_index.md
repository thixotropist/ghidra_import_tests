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
2. Collect feature-specific binary exemplars that might highlight gaps in Ghidra's import processes.  Ghidra will usually
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

>Note: These tests often run Ghidra in a headless mode.  There should be no other Ghidra
processes currently locking the `riscv64/exemplars` project, or the tests will fail.

These tests retrieve open source binaries - typically disk images - then break them down
into kernel, kernel module, system library, and user process exemplars to be imported into Ghidra.

Runs `make all_imports` then imports a kernel module exemplar into Ghidra, validating proper 
Ghidra handling of RISCV relocation codes found in that exemplar.

After the external binaries are processed, any object files found in `riscv64/exemplars` are imported into Ghidra
for manaual analysis

```console
$ make clean_imports
$ ./integrationTest.py
./integrationTest.py 
Running: make all_imports
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
Ran 1 test in 537.806s

OK
```

The imported binaries with their Ghidra import log files can include:

```text
riscv64/kernel/vmlinux-6.5.4-300.0.riscv64.fc39.riscv64
riscv64/kernel/vmlinux.log
riscv64/kernel_mod/igc.ko
riscv64/kernel_mod/igc.log
riscv64/system_lib/libc.so.6
riscv64/system_lib/libc.log
riscv64/system_lib/libssl.so.3.0.8
riscv64/system_lib/libssl.log
riscv64/system_executable/ssh
riscv64/system_executable/ssh.log
```

Locally compiled binaries (without explicit Ghidra import logs) can include:

```text
b-ext-64.o
b-ext.o
h-ext-64.o
relocationTest.o
rvv_index.pic.o
rvv_matmul.pic.o
rvv_memcpy.pic.o
rvv_reduce.pic.o
rvv_strncpy.pic.o
semantics.o
syntheticRelocations.o
vector.o
x-thead-ba.o
x-thead-bb.o
x-thead-bs.o
x-thead-cmo.o
x-thead-condmov.o
x-thead-fmemidx.o
x-thead-mac.o
x-thead-memidx.o
x-thead-mempair.o
x-thead-sync.o
zbkb-64.o
zbkc.o
zbkx.o
zca.o
zcb.o
zknd-64.o
zkne-64.o
zknh-64.o
zksed.o
zksh.o
zvbb.o
zvbc.o
zvkng.o
zvksg.o
```

The matching source code for these binary exemplars can be found in [exemplars]({{< relref "/exemplars" >}})

All of these binaries should be available in the Ghidra local repository `riscv/exemplars`