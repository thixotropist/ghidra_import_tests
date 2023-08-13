# Kernel import test

This exemplar kernel is not an ELF file, so analysis of the import process will need
help.

* The import Makefile explicitly sets the processor on the command line: `-processor RISCV:LE:64:RV64IC`.
  This will likely be the same as the processor determined from imported kernel load modules.
* Ghidra recognizes three sections, one text and two data.  All three need to be manually moved
  to the offset suggested in the associated `System.map` file.  For example, `.text` moves from
  0x1000 to 0x80001000.  Test this by verifying function start addresses identified in `System.map`
  look like actual RISCV-64 kernel functions.  Most begin with 16 bytes of no-op instructions
  to support debugging and tracing operations.
* Mark `.text` as code by selecting from 0x80001000 to 0x80dfffff and hitting the `D` key.

## Verification

Verify that kernel code correctly references data:

1. locate the address of `panic` in `System.map`: ffffffff80b6b188
2. go to 0x80b6b188 in Ghidra and verify that this is a function
3. display references to `panic` and examine the decompiler window.

```c
 /* WARNING: Subroutine does not return */
  panic(s_Fatal_exception_in_interrupt_813f84f8);
```

Note that the disassembler window does not recognize the string parameter reference - perhaps we needed
to move .text and .data *before* the analysis phase.

## Notes

This kernel includes 149 strings including `sifive`, most of which appear in `System.map`.  It's not immediately clear whether these
indicate kernel mods by SiFive or an SDK kernel module compiled into the kernel.
