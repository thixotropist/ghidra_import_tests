# Kernel module import test

Kernel modules are typically ELF files compiled as Position Independent Code, often using more varied Elf relocation types
for dynamically loading and linking into kernel memory space.  This study looks at the `igc.ko` kernel module for a type
of Intel network interface device.  Network device drivers can have some of the most time-critical and race-condition-rich
behavior, making this class of driver a good exemplar.

RISCV relocation types found in this exemplar include:

  R_RISCV_64(2), R_RISCV_BRANCH(16), R_RISCV_JAL(17), R_RISCV_CALL(18), R_RISCV_PCREL_HI20(23), R_RISCV_PCREL_LO12_I(24),
  R_RISCV_ADD32(35), R_RISCV_ADD64(36), R_RISCV_SUB32(39), R_RISCV_SUB64(40), R_RISCV_RVC_BRANCH(44), and R_RISCV_RVC_JUMP(45)


## Verification

Importing `igc.ko` generates several warnings similar to:

    ERROR Failed to process GOT at 00100028: Insufficent memory

These are likely due to `.got` and `.plt` sections being 1 byte long and unused.

Importing `igc.ko` generates other errors when processing symbols with names like `.L0^B1`.  These local symbols are
generated for  processing `R_RISCV_PCREL_HI20` and `R_RISCV_PCREL_LO12_I` relocations.  The symbol *name* is not
used in that processing, and Ghidra accepts the symbol anyway.  Ghidra should probably suppress these errors:

* by accepting all C strings regardless of the presence of traditional ASCII control characters, or
* by translating bytes like "\x01" into strings like "^B" during import, or
* by silently trimming symbol labels at the first control character

### Verification steps

Open Ghidra's Relocation Table window and verify that all relocations were applied.

Go to `igc_poll`, open a decompiler window, and export the function as `igc_poll_decompiled.c`.  Compare this file with the
provided `igc_poll.c` in the visual difftool of your choice (e.g. `meld`) and check for the presence of lines
like:

```c
netdev_printk(&_LC7,*(undefined8 *)(lVar33 + 8),"Unknown Tx buffer type\n");
```

This statement generates - and provides tests for - at least four relocation types.

## Notes

The decompiler translates *all* fence instructions as `fence()`.  This kernel module uses 8 distinct `fence` instructions
to request memory barriers.  The sleigh files should probably be extended to show either `fence(1,5)` or the linux macro names
given in `linux/arch/riscv/include/asm/barrier.h`.
