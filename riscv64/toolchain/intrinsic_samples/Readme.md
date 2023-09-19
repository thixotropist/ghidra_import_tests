# RISCV Intrinsics

Examples here come from https://github.com/riscv-non-isa/rvv-intrinsic-doc/blob/main/examples,
with draft documentation found at https://github.com/riscv-non-isa/rvv-intrinsic-doc/releases.

Note that the number of instrinsics defined is very large, and that `#include <riscv_vector.h>` doesn't contain their signatures.
Instead, it contains a gcc pragma telling the compiler to include a preparsed symbol table bundled with gcc.  This implies an exhaustive set of Ghidra pcope ops based on riscv vector instrinsics is not likely anytime soon.