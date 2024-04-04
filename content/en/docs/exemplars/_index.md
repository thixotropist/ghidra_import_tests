---
title: Exemplars
linkTitle: Exemplars
weight: 10
---

{{% pageinfo %}}
List the current importable and buildable exemplars, their origins, and the Ghidra features they are intended to validate or stress.
{{% /pageinfo %}}

## Overview

Exemplars suitable for Ghidra import are generally collected by platform architecture, such as `riscv64/exemplars` or `x86_64/exemplars`.
Some are imported from system disk images.  Others are locally built from small source code files and an appropriate compiler toolchain.
The initial scope includes Linux-capable RISCV 64 bit systems that might be found in network appliances or ML inference engines.  That makes for a local
bias towards privileged code, concurrency management, and performance optimization.  That scope expands slightly to x86_64 exemplars that
may help triage issues that show up first in RISCV 64 exemplars.

You can get decent exemplar coverage with this set of exemplars:

* from a general purpose RISCV-64 disk image:
    * kernel - a RISCV-64 kernel built with a recent Linux release
    * kernel load module - an ELF binary intended to be loaded into a running kernel
    * system library - libc.so or libssl.so copied from a generic Linux disk image
    * system application - a user application linking against system libraries and running over a Linux kernel
* built from source, with the development tip of the gcc toolchain and many explicit ISA extensions:
    * binutils assembly test suite - ISA extensions usually show up here first, along with preferred disassembly patterns
    * memcpy and other libc replacements coded with RISCV-64 ISA intrinsic extensions
    * `libssl.so` and `libcrypt.so` built from source and configured for all standard and frozen crypto, vector, and bit manipulation
      instruction extensions.
    * DPDK network appliance source code, `l3fwd` and `l2fwd`.

In general, visual inspection of these exemplars after importing into Ghidra should show:

* no failed constructors, so all instructions are recognized by Ghidra during disassembly
* no missing pcode
* all vector vset* instructions are unwrapped to show selected element width, multiplier, tail and mask handling

Ghidra will in a few cases disassemble an instruction differently than binutils' `objdump`.  That's fine, if it is due to a limitation
of Ghidra's SLEIGH language. If alignment to `objdump` is possible, that's preferable.

## Imported exemplars

Most of the imported large binary exemplars are broken out of current Fedora disk images.  The top level `acquireExternalExemplars.py`
script controls this process, sometimes with some manual intervention to handle image mounting.  Selection of the imported disk image
is controlled with text like:

```py
LOGLEVEL = logging.WARN
FEDORA_RISCV_SITE = "http://fedora.riscv.rocks/kojifiles/work/tasks/6900/1466900"
FEDORA_RISCV_IMAGE = "Fedora-Developer-39-20230927.n.0-sda.raw"
FEDORA_KERNEL = "vmlinuz-6.5.4-300.0.riscv64.fc39.riscv64"
FEDORA_KERNEL_OFFSET = 40056
FEDORA_KERNEL_DECOMPRESSED = "vmlinux-6.5.4-300.0.riscv64.fc39.riscv64"
FEDORA_SYSMAP = "System.map-6.5.4-300.0.riscv64.fc39.riscv64"

```
### Fedora kernel

This exemplar kernel is not an ELF file, so analysis of the import process will need
help.

* The import process explicitly sets the processor on the command line: `-processor RISCV:LE:64:RV64IC`.
  This will likely be the same as the processor determined from imported kernel load modules.
* Ghidra recognizes three sections, one text and two data.  All three need to be moved
  to the offset suggested in the associated `System.map` file.  For example, `.text` moves from
  0x1000 to 0x80001000.  Test this by verifying function start addresses identified in `System.map`
  look like actual RISCV-64 kernel functions.  Most begin with 16 bytes of no-op instructions
  to support debugging and tracing operations.
* Mark `.text` as code by selecting from 0x80001000 to 0x80dfffff and hitting the `D` key.

#### Verification

Verify that kernel code correctly references data:

1. locate the address of `panic` in `System.map`: ffffffff80b6b188
2. go to 0x80b6b188 in Ghidra and verify that this is a function
3. display references to `panic` and examine the decompiler window.

```c
 /* WARNING: Subroutine does not return */
  panic(s_Fatal_exception_in_interrupt_813f84f8);
```

#### Notes

This kernel includes 149 strings including `sifive`, most of which appear in `System.map`.  It's not immediately clear whether these
indicate kernel mods by SiFive or an SiFive SDK kernel module compiled into the kernel.

The kernel currently includes a few RISCV instruction set extensions not handled by Ghidra, and possibly not even by `binutils` and the `gas`
RISCV assembler.  Current Linux kernels can bypass the standard assembler to insert custom or obscure privileged instructions.

This Linux kernel explicitly includes ISA extension code for processors that support those extensions.  For example, if the kernel boots
up on a processor supporting the `_zbb` bit manipulation instruction extensions, then the vanilla `strlen`, `strcmp`, and `strncmp` kernel
functions are patched out to invoke `strlen_zbb`, `strcmp_zbb`, and `strncmp_zbb` respectively.

This kernel can support up to 64 discrete ISA extensions, of which about 30 are currently defined.  It has some support for hybrid processors,
where each of the hardware threads (aka 'harts') can support a different mix of ISA extensions.

>Note: The combination of instruction set extensions and self-modifying privileged code makes for a fertile ground for Ghidra research.
>      We can expect vector variants of `memcpy` inline expansion sometime in 2024, significantly complicating cyberanalysis of
>      even the simplest programs.

### Fedora kernel modules

Kernel modules are typically ELF files compiled as Position Independent Code, often using more varied Elf relocation types
for dynamically loading and linking into kernel memory space.  This study looks at the `igc.ko` kernel module for a type
of Intel network interface device.  Network device drivers can have some of the most time-critical and race-condition-rich
behavior, making this class of driver a good exemplar.

RISCV relocation types found in this exemplar include:

  R_RISCV_64(2), R_RISCV_BRANCH(16), R_RISCV_JAL(17), R_RISCV_CALL(18), R_RISCV_PCREL_HI20(23), R_RISCV_PCREL_LO12_I(24),
  R_RISCV_ADD32(35), R_RISCV_ADD64(36), R_RISCV_SUB32(39), R_RISCV_SUB64(40), R_RISCV_RVC_BRANCH(44), and R_RISCV_RVC_JUMP(45)

#### Verification

Open Ghidra's Relocation Table window and verify that all relocations were applied.

Go to `igc_poll`, open a decompiler window, and export the function as `igc_poll.c`.  Compare this file with the
provided `igc_poll_decompiled.c` in the visual difftool of your choice (e.g. `meld`) and check for the presence of lines
like:

```c
netdev_printk(&_LC7,*(undefined8 *)(lVar33 + 8),"Unknown Tx buffer type\n");
```

This statement generates - and provides tests for - at least four relocation types.

#### Notes

The decompiler translates *all* fence instructions as `fence()`.  This kernel module uses 8 distinct `fence` instructions
to request memory barriers.  The sleigh files should probably be extended to show either `fence(1,5)` or the Linux macro names
given in `linux/arch/riscv/include/asm/barrier.h`.

### Fedora system libraries

System libraries like `libc.so` and `libssl.so` typically link to versioned shareable object libraries like `libc.so.6` and `libssl.so.3.0.5`.  Ghidra imports
RISCV system libraries well.

Relocation types observed include:

  R_RISCV_64(2), R_RISCV_RELATIVE(3), R_RISCV_JUMP_SLOT(5), and R_RISCV_TLS_TPREL64(11)

R_RISCV_TLS_TPREL64 is currently unsupported by Ghidra, appearing in the `libc.so.6` .got section about 15 times.  This relocation type does not appear
in `libssl.so.3.0.5`.  It appears in multithreaded applications that use thread-local storage.

### Fedora system executables

The `ssh` utility imports cleanly into Ghidra.

Relocation types observed include:

  R_RISCV_64(2), R_RISCV_RELATIVE(3), R_RISCV_JUMP_SLOT(5)

Function thunks referencing external library functions do not automatically get the name of the external function propagated into the name of the thunk.

## Locally built exemplars

Imported binaries are generally locked into a single platform and a single toolchain.  The imported binaries above are built for an SiFive
development board, a 64 bit RISCV processor with support for Integer and Compressed instruction sets, and a gcc-13 toolchain.  If we want some
variation on that, say to look ahead at challenges a gcc-14 toolchain might throw our way, we need to build our own exemplars.

Open source test suites can be a good source for feature-focused importable exemplars.  If we want to test Ghidra's ability to import RISCV instruction
set extensions, we want to import many of the files from [binutils-gdb/gas/testsuite/gas/riscv](https://sourceware.org/git?p=binutils-gdb.git;a=tree;f=gas/testsuite/gas/riscv;hb=HEAD).

For example, most of the ratified set of RISCV vector instructions are used in `vector-insns.s`.
If we assemble this with a `gas` assembler compatible with the `-march=rv32ifv` architecture
we get an importable binary exemplar for those instructions.
Even better, we can disassemble that exemplar with a compatible `objdump` and get the reference disassembly to compare against Ghidra's disassembly.
This gives us three kinds of insights into Ghidra's import capabilities:

1. When new instructions appear in the `binutils` `gas` main branch, they are good candidates for implementation in Ghidra within the next 12 months.
   This currently includes vector, bit manipulation, cache management, and crypto approved extensions plus about a dozen vendor-specific extensions
   from AliBaba's THead RISCV server initiative.
2. These exemplars drive extension of Ghidra's RISCV sleigh files, both as new instruction definitions and as pcode semantics for display in the decompiler window.
3. Disassembly of those exemplars with a current `binutils` `objdump` utility gives us a reference disassembly to compare with Ghidra's.
   We can minimize arbitrary or erroneous Ghidra disassembly by comparing the two disassembler views.
   Ghidra and `objdump` have different goals, so we don't need strict alignment of Ghidra with `objdump`.

Most exemplars appear as four related files.  We can use the `vector` exemplar as an example.

* The source file is `riscv64/toolchain/assemblySamples/vector.S`, copied from `binutils-gdb/gas/testsuite/gas/riscv/vector-insns.s`.
* `vector.S` is assembled into `riscv64/exemplars/vector.o`
* That assembly run generates the assembly output listing `riscv64/exemplars/vector.log`.
* `riscv64/exemplars/vector.o` is finally processed by `binutils` `objdump` to generate the reference disassembly `riscv64/exemplars/vector.objdump`.

The `riscv64/exemplars/vector.o` is then imported into the Ghidra `exemplars` project, where we can evaluate the import and disassembly results.

Assembly language exemplars usually don't have any sensible decompilation.  C or C++ language exemplars usually do, so that gives the test analyst more to work with.

Another example shows Ghidra's difficulty with vector optimized code.  Compile this C code for the `rv64gcv` architecture (RISCV-64 with vector extensions), using the
gcc-14 toolchain due for mid 2024 release.

```c
#include <stdio.h>
int main(int argc, char** argv){
    const int N = 1320;
    char s[N];
    for (int i = 0; i < N - 1; ++i)
        s[i] = i + 1;
    s[N - 1] = '\0';
    printf(s);
}
```
Ghidra's 11.0 release decompiles this into:

```text
/* WARNING: Control flow encountered unimplemented instructions */

void main(void)

{
  gp = &__global_pointer$;
                    /* WARNING: Unimplemented instruction - Truncating control flow here */
  halt_unimplemented();
}
```

Try the import again with the `isa_ext` experimental branch of Ghidra:

```text
undefined8 main(void)

{
  undefined auVar1 [64];
  undefined8 uVar2;
  undefined (*pauVar3) [64];
  long lVar4;
  long lVar5;
  undefined auVar6 [256];
  undefined auVar7 [256];
  char local_540 [1319];
  undefined uStack_19;
  
  gp = &__global_pointer$;
  pauVar3 = (undefined (*) [64])local_540;
  lVar4 = 0x527;
  vsetvli_e32m1tama(0);
  auVar7 = vid_v();
  do {
    lVar5 = vsetvli(lVar4,0xcf);
    auVar6 = vmv1r_v(auVar7);
    lVar4 = lVar4 - lVar5;
    auVar6 = vncvt_xxw(auVar6);
    vsetvli(0,0xc6);
    auVar6 = vncvt_xxw(auVar6);
    auVar6 = vadd_vi(auVar6,1);
    auVar1 = vse8_v(auVar6);
    *pauVar3 = auVar1;
    uVar2 = vsetvli_e32m1tama(0);
    pauVar3 = (undefined (*) [64])(*pauVar3 + lVar5);
    auVar6 = vmv_v_x(lVar5);
    auVar7 = vadd_vv(auVar7,auVar6);
  } while (lVar4 != 0);
  uStack_19 = 0;
  printf(local_540,uVar2);
  return 0;
}
```

That Ghidra branch decompiles, but the decompilation listing only resembles the C source code if you are familiar with RISCV vector extension instructions.

Repeat the example, this time building with a gcc-13 toolchain.  Ghidra 11.0 does a fine job of decompiling this.

```c
undefined8 main(void)
{
  long lVar1;
  char acStack_541 [1320];
  undefined uStack_19;
    gp = &__global_pointer$;
  lVar1 = 1;
  do {
    acStack_541[lVar1] = (char)lVar1;
    lVar1 = lVar1 + 1;
  } while (lVar1 != 0x528);
  uStack_19 = 0;
  printf(acStack_541 + 1);
  return 0;
}
```

### x86_64 exemplars

A few x86_64 exemplars exist to explore the scope of issues raised by RISCV exemplars.  The `x86_64/exemplars` directory
shows how optimizing gcc-14 compilations handle simple loops and built-ins like `memcpy` for various microarchitectures.

Intel microarchitectures can be grouped into common profiles like `x86-64-v2`, `x86-64-v3`, and `x86-64-v4`.  Each has its own set of
instruction set extensions, so an optimizing compiler like gcc-14 will autovectorize loops and built-ins differently for each microarchitecture.

The `memcpy` exemplar set includes source code and three executables compiled from that source code with `-march=x86-64-v2`, `-march=x86-64-v3`, and
`-march=x86-64-v4`.  The binutils-2.41 `objdump` disassembly is provided for each executable, for comparison with Ghidra's disassembly window.

```console
x86_64/exemplars$ ls memcpy*
memcpy.c  memcpy_x86-64-v2  memcpy_x86-64-v2.objdump  memcpy_x86-64-v3  memcpy_x86-64-v3.objdump  memcpy_x86-64-v4  memcpy_x86-64-v4.objdump
```

These exemplars suggest several Ghidra issues:

* Ghidra's disassembler is generally unable to recognize many vector instructions generated by gcc-14 with `-march=x86-64-v4` and `-O3`.
* Ghidra's decompiler provides the user little help in recognizing the semantics of `memcpy` or many simple loops with `-march=x86-64-v2` or `-march=x86-64-v3`.
* Ghidra users should be prepared for wide variety in vector optimized instruction sequences.  Pattern recognition will be difficult.
