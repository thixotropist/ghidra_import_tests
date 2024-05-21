---
title: testing pcode semantics
weight: 50
---

{{% pageinfo %}}
Ghidra processor semantics needs tests
{{% /pageinfo %}}

Procesor instructions known to Ghidra are defined in Sleigh pcode or semanitc sections.
Adding new instructions - such as instruction set extensions to an existing processor -
requires a pcode description of what that instruction does.  That pcode drives both the decompiler
process and any emulator or debugger processes.

This generates a conflict in testing.  Should we test for maximum clarity for semantics rendered
in the decompiler window or maximum fidelity in any Ghidra emulator?  For example,
should a divide instruction include pcode to test against a divide-by-zero?  Should floating point
instructions guard against NaN (Not a Number) inputs?

We assume here that decompiler fidelity is more important than emulator fidelity.  That implies:

* ignore any exception-generating cases, including divide-by-zero, NaN, memory access and memory alignment.
* pcode must allow for normal C implicit type conversions, such as between different integer and
  floating point lengths.
    * this implies pcode must pay attention to Ghidra's type inference system.

## Concept of Operations

Individual instructions are wrapped in C and exercised within a Google Test C++ framework.
The test framework is then executed within a qemu static emulation environment.

For example, let's examine two riscv-64 instructions: `fcvt.w.s` and `fmv.x.w`


* `fcvt.w.s` converts a ﬂoating-point number in ﬂoating-point register rs1 to a signed
  32-bit or 64-bit integer, respectively, in integer register rd.
* `fmv.x.w` moves the single-precision value in floating-point register rs1 represented in
  IEEE 754-2008 encoding to the lower 32 bits of integer register rd. For RV64,
  the higher 32 bits of the destination register are filled with copies of the floating-point
  number’s sign bit.

These two instructions have similar signatures but very different semantics.  `fcvt.w.s` performs
a float to int type conversion, so the `float 1.0` can be converted to `int 1`.  `fmv.x.w` moves the
raw bits between float and int registers without any type coversion.

We can generate simple exemplars of both instructions with this C code:

```c
int fcvt_w_s(float* x) {
    return (int)*x;
}

int fmv_x_w(float* x) {
    int val;
    float src = *x;

    __asm__ __volatile__ (
        "fmv.x.w  %0, %1" \
        : "=r" (val) \
        : "f" (src));
    return val;
}
```

Ghidra's 11.2-DEV decompiler renders these as:

```c
long fcvt_w_s(float *param_1)
{
  return (long)(int)param_1;
}
long fmv_x_w(float *param_1)
{
  return (long)(int)param_1;
}
```

Both of these are wrong - they are both missing a dereference operation.  The `fmv_x_w` version is also implying an
implicit type conversion when none is actually performed.

## Running tests

The draft test harness can be built and run from the top level workspace directory.

```console
$ bazel build --platforms=//riscv64/generated/platforms:riscv_userspace riscv64/generated/emulator_tests:testSemantics
Starting local Bazel server and connecting to it...
INFO: Analyzed target //riscv64/generated/emulator_tests:testSemantics (74 packages loaded, 1902 targets configured).
...
INFO: From Executing genrule //riscv64/generated/emulator_tests:testSemantics:
...
INFO: Found 1 target...
Target //riscv64/generated/emulator_tests:testSemantics up-to-date:
  bazel-bin/riscv64/generated/emulator_tests/results
INFO: Elapsed time: 4.172s, Critical Path: 1.93s
INFO: 4 processes: 1 internal, 3 linux-sandbox.
INFO: Build completed successfully, 4 total actions

$ cat bazel-bin/riscv64/generated/emulator_tests/results
[==========] Running 4 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 4 tests from FP
[ RUN      ] FP.testharness
[       OK ] FP.testharness (3 ms)
[ RUN      ] FP.fcvt
[       OK ] FP.fcvt (10 ms)
[ RUN      ] FP.fmv
[       OK ] FP.fmv (1 ms)
[ RUN      ] FP.fp16
[       OK ] FP.fp16 (0 ms)
[----------] 4 tests from FP (15 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test suite ran. (19 ms total)
[  PASSED  ] 4 tests.

$ file bazel-bin/riscv64/generated/emulator_tests/libfloatOperations.so
bazel-bin/riscv64/generated/emulator_tests/libfloatOperations.so: ELF 64-bit LSB shared object, UCB RISC-V, RVC, double-float ABI, version 1 (SYSV), dynamically linked, not stripped

```

