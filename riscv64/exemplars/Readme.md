# Exemplars

This directory holds binary objects extracted from external disk images or compiled locally by other parts of this project.
They are cached here as a convenience.

## igc.ko

This is a Fedora 37 kernel load module for an Intel ethernet interface.  It demonstrates several concurrency controls as well as features
enabling load-time code rewriting and optimization.

## relocationTest.o

This is a very short object file compiled from C with gcc-12 and binutils 2-40.  The compilation option is `-fpie`, generating RISCV relocation
codes found in much larger kernel load modules.

## syntheticRelocations.o

This is a very short object file compiled from RISCV assembly code with gcc-12 and binutils 2-40.  The source code is similar to that used for relocationTest.o,
with the addition of assembler local label back-references.  It represents small inline assembly sequences found in kernel C code, generating labels like `.L1^B1`.