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
  return (long)(int)*param_1;
}
long fmv_x_w(float *param_1)
{
  return (long)(int)param_1;
}
```

`fmv_x_w` was missing a dereference operation.  The `fmv_x_w` version was also implying an
implicit type conversion when none is actually performed.  Let's trace how to use these test
results to improve the decompiler output.

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

## Test parameters

What version of Ghidra are we testing against?

* Ghidra as released, e.g., 11.1
* [Ghidra master](https://github.com/NationalSecurityAgency/ghidra), currently 11.2-DEV
* Our [isa_ext](https://github.com/thixotropist/ghidra/tree/isa_ext) fork
* [jobermayr's clang fork](https://github.com/jobermayr/ghidra/tree/clang)
* One of the many [Sleigh-InSPECtor](https://github.com/Sleigh-InSPECtor/ghidra) RISCV Ghidra pull requests

What do we do with Ghidra patches that improve the decompilation results?

* If the patched instructions only exist within the [isa_ext](https://github.com/thixotropist/ghidra/tree/isa_ext)
  fork, we will make the changes to that fork and [PR](https://github.com/NationalSecurityAgency/ghidra/pull/5778)
* If the patches come from unmerged PRs we may cherry-pick them into
  [isa_ext](https://github.com/thixotropist/ghidra/tree/isa_ext).  This includes some of the `fcvt` and `fmv`
  patches from other sources.

## Test example

Use `meld` to compare the original C source file `floatOperations.c` with the exported C decompiler view from Ghidra 11.2-DEV. A quick inspection shows some errors to address:

| Original | Ghidra |
| -------- | ------ |
| float fcvt_s_wu(uint32_t* i) {return (float)*i;} | float fcvt_s_wu(uint *param_1){return (float)ZEXT416(*param_1);} |
| double fcvt_d_wu(uint32_t* j){return (double)*j;} | double fcvt_d_wu(uint *param_1){return (double)ZEXT416(*param_1);} |
|  | long fmv_x_w(float *param_1){return (long)(int)*param_1;} |
|  | long fmv_x_d(double *param_1){return (long)(int)*param_1;} |
|  | long fcvt_h_w(int param_1){return (long)param_1;} |
|  | long fcvt_h_wu(int param_1){return (long)param_1;} |
|  | ulong fcvt_h_d(ulong *param_1){return *param_1 & 0xffffffff;} |

The errors include:

* spurious `ZEXT416` in two places
* `fmv` instructions appear to force an implicit type conversion where none is wanted
* missing dereference operation in `fcvt_h_w` and `fcvt_h_wu`
* bad mask operation in `fcvt_h_d`

## Next steps

Testing semantics for the `zfh` half-precision floating point instructions is more complicated
than usual.  Ghidra's semantics and pcode system has no known provision for half-precision floating point,
so emulation won't work well.  The current `zfh` implementation makes these _fp16 objects look
like 32 bit floats in registers and like 16 bit shorts in memory operations, making Ghidra type inferencing
even more confusing.

Let's look at a more limited scope, the definition of the Ghidra `trunc` pcode op.

The documentation says `trunc` produces a signed integer obtained by truncating its argument.
* how does `trunc` set its result type?
* does `trunc` expect only a floating point double?
* what would it take to define `trunk_u` to generate an unsigned integer
* what would it take to accept a half-precision floating point value as an argument?

The documentation also says that `float2float` 'copies a floating-point number with more or less precision',
so its implementation may tell us something about type inferencing.

* `Ghidra/Features/Decompiler/src/decompile/cpp/pcodeparse.cc` binds `float2float` to `OP_FLOAT2FLOAT`
* this leads to `CPUI_FLOAT_FLOAT2FLOAT` and to several files under `Ghidra/Features/Decompiler/src/decompile/cpp`.
* functions like `FloatFormat::opFloat2Float` and `FloatFormat::opTrunc` look relevant in `float.hh` and `float.cc`
