---
title: Issues
linkTitle: Issues
weight: 20
---
{{% pageinfo %}}
Summarize Ghidra import issues here to promote discussion on relative priority and possible solutions. 
{{% /pageinfo %}}

## Thread local storage class handling

[Thread local storage](https://gcc.gnu.org/onlinedocs/gcc/Thread-Local.html) provides one instance of the variable per extant thread.
GCC supports this feature as:

```c
__thread char threadLocalString[4096];
```

Binaries built with this feature will often include ELF relocation codes like `R_RISCV_TLS_TPREL64`.  This relocation code is not recognized by
Ghidra, nor is it clear how TLS storage should be handled itself within Ghidra - perhaps as a memory section akin to BSS?

To reproduce, import `libc.so.6` and look for lines like `Elf Relocation Warning: Type = R_RISCV_TLS_TPREL64`.
Alternatively, compile, link, and import `riscv64/toolchain/userSpaceSamples/relocationTest.c`.

## Vector instruction support

Newer C compiler releases can replace simple loops and standard C library invocations with processor-specific vector instructions.  These vector
instructions can be handled poorly by Ghidra's disassembler and worse by Ghidra's decompiler.  See [autovectorization]({{< relref "autovectorization" >}})
and [vector_intrinsics]({{< relref "vector_intrinsics" >}}) for examples.