# System Libraries

System libraries like `libc.so` and `libssl.so` typically link to versioned sharable object libraries like `libc.so.6` and `libssl.so.3.0.5`.  Ghidra imports
RISCV system libraries well.

Relocation types observed include:

  R_RISCV_64(2), R_RISCV_RELATIVE(3), R_RISCV_JUMP_SLOT(5), and R_RISCV_TLS_TPREL64(11)

R_RISCV_TLS_TPREL64 is currently unsupported by Ghidra, appearing in the `libc.so.6` .got section about 15 times.  This relocation type does not appear
in `libssl.so.3.0.5`.